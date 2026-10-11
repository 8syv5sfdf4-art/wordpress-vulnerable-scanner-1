//! Local vulnerability database
//!
//! `pull` downloads WPVulnerability records for a set of components into a
//! directory; [`Source::Local`](crate::vulnerability::Source::Local) then lets
//! the scanner work from that directory with no network access.
//!
//! Layout (one raw API response per component, so the files stay identical
//! to what the API returns and can be inspected or diffed):
//!
//! ```text
//! <dir>/wpvuln-db.json            metadata: format, source, last pull
//! <dir>/index.json                per record: when, from where, sha256, uuids
//! <dir>/plugin/<slug>.json
//! <dir>/theme/<slug>.json
//! <dir>/core/<version>.json
//! ```

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::stream::{self, StreamExt};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::http::API_USER_AGENT;
use crate::scanner::ComponentType;
use crate::vulnerability::{RecordKind, api_url, record_kind, record_uuids};

/// Database layout version, bumped on incompatible changes.
/// 1: records only. 2: adds `index.json`; format 1 is migrated on pull.
pub const FORMAT_VERSION: u32 = 2;

const META_FILE: &str = "wpvuln-db.json";
const INDEX_FILE: &str = "index.json";

/// Whether a stored record describes a tracked component
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    /// WPVulnerability knows the component
    Tracked,
    /// WPVulnerability has no entry for it: not checked
    Untracked,
}

/// Provenance of one stored record
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexEntry {
    /// Unix time the body was downloaded
    pub fetched_at: u64,
    /// Unix time it was last confirmed current (download or HTTP 304);
    /// 0 for a rebuilt entry, which was never confirmed
    pub checked_at: u64,
    /// Where it came from
    pub url: String,
    /// HTTP status of the download; `None` for entries rebuilt from files
    pub http_status: Option<u16>,
    /// SHA-256 of the stored file, lowercase hex
    pub sha256: String,
    /// Tracked or untracked
    pub kind: EntryKind,
    /// Number of vulnerability records
    pub records: usize,
    /// Vulnerability uuids, sorted, to tell what changed between versions
    pub uuids: Vec<String>,
    /// `ETag` from the API, for conditional requests
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    /// `Last-Modified` from the API, for conditional requests
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
    /// Rebuilt from a file found without an entry (a format 1 database or
    /// an interrupted pull), so its download details are unknown
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub rebuilt: bool,
}

/// `index.json`: one [`IndexEntry`] per record, keyed `plugin/<slug>`,
/// `theme/<slug>` or `core/<version>`
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Index {
    /// Layout version ([`FORMAT_VERSION`])
    pub format: u32,
    /// Entries by key
    pub records: std::collections::BTreeMap<String, IndexEntry>,
}

/// Index key for one component
pub fn index_key(kind: ComponentType, key: &str) -> String {
    format!("{}/{key}", dir_name(kind))
}

/// SHA-256 as lowercase hex
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Refuse databases written by a newer version of this tool, rather than
/// misreading them
fn check_format(dir: &Path) -> Result<()> {
    let format = std::fs::read_to_string(dir.join(META_FILE))
        .ok()
        .and_then(|s| serde_json::from_str::<DbMeta>(&s).ok())
        .map(|m| m.format);
    match format {
        Some(f) if f > FORMAT_VERSION => Err(Error::Database(format!(
            "{} uses format {f}, but this version of the tool only understands up to \
             {FORMAT_VERSION}. Use a newer wordpress-vulnerable-scanner, or pull into a new \
             directory.",
            dir.display()
        ))),
        _ => Ok(()),
    }
}

/// Read `index.json`; `None` when there is none yet (a new or format 1
/// database)
pub fn read_index(dir: &Path) -> Result<Option<Index>> {
    let path = dir.join(INDEX_FILE);
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::Database(format!("{}: {e}", path.display()))),
    };
    let index: Index = serde_json::from_str(&text).map_err(|e| {
        Error::Database(format!(
            "{}: unreadable ({e}). Delete it and run `db pull` again to rebuild it from the \
             record files.",
            path.display()
        ))
    })?;
    if index.format > FORMAT_VERSION {
        return Err(Error::Database(format!(
            "{}: format {} is newer than this tool understands ({FORMAT_VERSION})",
            path.display(),
            index.format
        )));
    }
    Ok(Some(index))
}

fn write_index(dir: &Path, index: &Index) -> Result<()> {
    let path = dir.join(INDEX_FILE);
    let tmp = dir.join(format!("{INDEX_FILE}.tmp"));
    std::fs::write(&tmp, serde_json::to_string_pretty(index)?)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// Index entry for a stored file that has none, from the file alone.
/// Copying a database resets file times, so they say nothing about when
/// a record was fetched: `fetched_at` is only a guess (file time, capped
/// at the last pull), and `checked_at` is 0 so the record counts as
/// stale and the next pull or update confirms it.
fn rebuild_entry(path: &Path, url: String, last_pull: Option<u64>) -> Option<IndexEntry> {
    let body = std::fs::read_to_string(path).ok()?;
    let kind = record_kind(&body)?;
    let mtime = std::fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|m| m.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs());
    let guess = last_pull.map_or(mtime, |p| p.min(mtime));
    let mut entry = entry_for(&body, kind, url, None, None, None, guess, true);
    entry.checked_at = 0;
    Some(entry)
}

#[allow(clippy::too_many_arguments)]
fn entry_for(
    body: &str,
    kind: RecordKind,
    url: String,
    http_status: Option<u16>,
    etag: Option<String>,
    last_modified: Option<String>,
    at: u64,
    rebuilt: bool,
) -> IndexEntry {
    let (kind, records) = match kind {
        RecordKind::Tracked(n) => (EntryKind::Tracked, n),
        RecordKind::Untracked => (EntryKind::Untracked, 0),
    };
    IndexEntry {
        fetched_at: at,
        checked_at: at,
        url,
        http_status,
        sha256: sha256_hex(body.as_bytes()),
        kind,
        records,
        uuids: record_uuids(body),
        etag,
        last_modified,
        rebuilt,
    }
}

/// Every record file in `dir`, as (kind, key)
fn record_files(dir: &Path) -> Vec<(ComponentType, String)> {
    let mut out = Vec::new();
    for kind in [
        ComponentType::Core,
        ComponentType::Plugin,
        ComponentType::Theme,
    ] {
        let Ok(entries) = std::fs::read_dir(dir.join(dir_name(kind))) else {
            continue;
        };
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if let Some(key) = name.strip_suffix(".json")
                && is_safe_key(key)
            {
                out.push((kind, key.to_string()));
            }
        }
    }
    out.sort_by(|a, b| (dir_name(a.0), &a.1).cmp(&(dir_name(b.0), &b.1)));
    out
}

/// Every record the database holds or indexes, as (kind, key): what
/// `db update` re-checks. Index entries whose file is missing are
/// included, so an update restores them.
pub fn stored(dir: &Path) -> Result<Vec<(ComponentType, String)>> {
    let mut out = record_files(dir);
    if let Some(index) = read_index(dir)? {
        for key in index.records.keys() {
            let Some((kind, name)) = key.split_once('/') else {
                continue;
            };
            let kind = match kind {
                "core" => ComponentType::Core,
                "plugin" => ComponentType::Plugin,
                "theme" => ComponentType::Theme,
                _ => continue,
            };
            let item = (kind, name.to_string());
            if is_safe_key(name) && !out.contains(&item) {
                out.push(item);
            }
        }
    }
    Ok(out)
}

/// The index, with entries rebuilt for any record file that lacks one.
/// This is how a format 1 database is migrated.
fn load_index(dir: &Path, base: &str) -> Result<Index> {
    let mut index = read_index(dir)?.unwrap_or_default();
    index.format = FORMAT_VERSION;
    let last_pull = std::fs::read_to_string(dir.join(META_FILE))
        .ok()
        .and_then(|s| serde_json::from_str::<DbMeta>(&s).ok())
        .map(|m| m.pulled_at);
    for (kind, key) in record_files(dir) {
        let k = index_key(kind, &key);
        if index.records.contains_key(&k) {
            continue;
        }
        let path = dir.join(dir_name(kind)).join(format!("{key}.json"));
        if let Some(entry) = rebuild_entry(&path, api_url(base, kind, &key), last_pull) {
            index.records.insert(k, entry);
        }
    }
    Ok(index)
}

/// Metadata stored at the root of a local database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbMeta {
    /// Layout version
    pub format: u32,
    /// API base URL the records were pulled from
    pub source: String,
    /// Unix time of the last pull
    pub pulled_at: u64,
}

fn dir_name(kind: ComponentType) -> &'static str {
    match kind {
        ComponentType::Core => "core",
        ComponentType::Plugin => "plugin",
        ComponentType::Theme => "theme",
    }
}

/// Slugs and versions become file names, so only allow characters that
/// cannot escape the database directory.
pub fn is_safe_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 200
        && !key.starts_with('.')
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// Path of the record for one component, or `None` for an unsafe key
pub fn record_path(dir: &Path, kind: ComponentType, key: &str) -> Option<PathBuf> {
    is_safe_key(key).then(|| dir.join(dir_name(kind)).join(format!("{key}.json")))
}

/// Options for [`pull`]
#[derive(Debug, Clone)]
pub struct PullOptions {
    /// API base URL
    pub api_url: String,
    /// Requests in flight at once
    pub jobs: usize,
    /// Attempts per component (network errors, 429 and 5xx are retried)
    pub attempts: u32,
    /// Pause before each request, to stay polite to a free API
    pub delay: Duration,
    /// Re-download records that are newer than this; `None` = always
    pub max_age: Option<Duration>,
    /// Like `max_age`, for records of untracked components, which rarely
    /// change; `None` = same as `max_age`
    pub untracked_max_age: Option<Duration>,
}

impl Default for PullOptions {
    fn default() -> Self {
        Self {
            api_url: crate::vulnerability::WPVULN_API.to_string(),
            jobs: 4,
            attempts: 3,
            delay: Duration::from_millis(250),
            max_age: None,
            untracked_max_age: None,
        }
    }
}

/// Outcome for one component
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PullStatus {
    /// Saved; holds the number of vulnerability records
    Saved(usize),
    /// Already present and fresh enough (see [`PullOptions::max_age`])
    Fresh(usize),
    /// Asked again; the API answered "not modified" (HTTP 304), so the
    /// stored record is confirmed current
    Unchanged(usize),
    /// WPVulnerability has no entry for it (404, an API error, or
    /// `data: null`). Common for premium and custom plugins. The response is
    /// stored so offline scans can say "not tracked" instead of "clean"
    NoData,
    /// The slug or version contains characters that are not allowed
    Invalid,
    /// Gave up after all attempts; the previous file (if any) is kept
    Failed(String),
}

/// One finished component, reported to the progress callback
#[derive(Debug, Clone)]
pub struct PullEvent {
    /// Component type
    pub kind: ComponentType,
    /// Slug, or core version
    pub key: String,
    /// What happened
    pub status: PullStatus,
    /// Components finished so far
    pub done: usize,
    /// Total components
    pub total: usize,
}

/// Totals for a pull
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PullSummary {
    /// Components saved (with or without records)
    pub saved: usize,
    /// Skipped because already fresh
    pub fresh: usize,
    /// Confirmed current by the API (HTTP 304)
    pub unchanged: usize,
    /// No data upstream
    pub no_data: usize,
    /// Rejected keys
    pub invalid: usize,
    /// Failed after retries
    pub failed: usize,
    /// Vulnerability records across saved, fresh and unchanged components
    pub records: usize,
    /// What changed in records that were replaced (also appended to
    /// `changes/<date>.json`)
    pub changes: Vec<crate::changes::Change>,
}

/// Stored for a 404, so the file reads as "not tracked" rather than "clean"
const UNTRACKED_RECORD: &str = r#"{"error":0,"message":null,"data":null}"#;

/// Download records for `items` into `dir`.
///
/// Every component is attempted; one failure never stops the rest.
/// `on_event` is called once per component as it finishes.
pub async fn pull(
    dir: &Path,
    items: &[(ComponentType, String)],
    opts: &PullOptions,
    mut on_event: impl FnMut(&PullEvent),
) -> Result<PullSummary> {
    check_format(dir)?;
    for kind in [
        ComponentType::Core,
        ComponentType::Plugin,
        ComponentType::Theme,
    ] {
        std::fs::create_dir_all(dir.join(dir_name(kind)))?;
    }
    let client = Client::builder()
        .user_agent(API_USER_AGENT)
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| Error::HttpClient(e.to_string()))?;

    let mut unique: Vec<(ComponentType, String)> = Vec::new();
    for item in items {
        if !unique.contains(item) {
            unique.push(item.clone());
        }
    }
    let total = unique.len();
    let base = opts.api_url.trim_end_matches('/').to_string();
    let mut index = load_index(dir, &base)?;
    let work: Vec<_> = unique
        .into_iter()
        .map(|(kind, key)| {
            let old = index.records.get(&index_key(kind, &key)).cloned();
            (kind, key, old)
        })
        .collect();

    let mut results = stream::iter(work.into_iter().map(|(kind, key, old)| {
        let client = &client;
        let base = &base;
        async move {
            let (status, entry, changes) =
                pull_one(client, base, dir, kind, &key, old.as_ref(), opts).await;
            (kind, key, status, entry, changes)
        }
    }))
    .buffer_unordered(opts.jobs.max(1));

    let mut summary = PullSummary::default();
    let mut done = 0;
    let mut fresh_entries = Vec::new();
    while let Some((kind, key, status, entry, changes)) = results.next().await {
        done += 1;
        if let Some(entry) = entry {
            fresh_entries.push((index_key(kind, &key), entry));
        }
        summary.changes.extend(changes);
        match &status {
            PullStatus::Saved(n) => {
                summary.saved += 1;
                summary.records += n;
            }
            PullStatus::Fresh(n) => {
                summary.fresh += 1;
                summary.records += n;
            }
            PullStatus::Unchanged(n) => {
                summary.unchanged += 1;
                summary.records += n;
            }
            PullStatus::NoData => summary.no_data += 1,
            PullStatus::Invalid => summary.invalid += 1,
            PullStatus::Failed(_) => summary.failed += 1,
        }
        on_event(&PullEvent {
            kind,
            key,
            status,
            done,
            total,
        });
    }
    drop(results);

    index.records.extend(fresh_entries);
    write_index(dir, &index)?;
    summary
        .changes
        .sort_by(|a, b| (&a.key, a.change as u8).cmp(&(&b.key, b.change as u8)));
    crate::changes::append_log(dir, &summary.changes)?;
    write_meta(
        dir,
        &DbMeta {
            format: FORMAT_VERSION,
            source: base,
            pulled_at: now(),
        },
    )?;
    Ok(summary)
}

/// Seconds since the record was last confirmed current: from the index
/// when it has an entry, otherwise from the file's modification time
fn record_age(path: &Path, old: Option<&IndexEntry>) -> Option<Duration> {
    match old {
        Some(e) => Some(Duration::from_secs(now().saturating_sub(e.checked_at))),
        None => std::fs::metadata(path)
            .ok()?
            .modified()
            .ok()?
            .elapsed()
            .ok(),
    }
}

/// What pulling one record produced: its status, a new index entry when
/// the record was saved or confirmed, and what changed in it
type Outcome = (PullStatus, Option<IndexEntry>, Vec<crate::changes::Change>);

async fn pull_one(
    client: &Client,
    base: &str,
    dir: &Path,
    kind: ComponentType,
    key: &str,
    old: Option<&IndexEntry>,
    opts: &PullOptions,
) -> Outcome {
    let Some(path) = record_path(dir, kind, key) else {
        return (PullStatus::Invalid, None, Vec::new());
    };

    let max_age = match old.map(|e| e.kind) {
        Some(EntryKind::Untracked) => opts.untracked_max_age.or(opts.max_age),
        _ => opts.max_age,
    };
    // The stored file as it was before this pull, if it is still intact:
    // only then may "not modified" confirm it
    let old_body = std::fs::read_to_string(&path).ok();
    let intact = old
        .zip(old_body.as_deref())
        .is_some_and(|(e, body)| sha256_hex(body.as_bytes()) == e.sha256);

    if let Some(max_age) = max_age
        && record_age(&path, old).is_some_and(|age| age < max_age)
        && let Some(kind) = std::fs::read_to_string(&path)
            .ok()
            .as_deref()
            .and_then(record_kind)
    {
        let status = match kind {
            RecordKind::Tracked(n) => PullStatus::Fresh(n),
            RecordKind::Untracked => PullStatus::NoData,
        };
        return (status, None, Vec::new());
    }

    let url = api_url(base, kind, key);
    let entry_key = index_key(kind, key);
    let mut last_error = String::new();
    for attempt in 0..opts.attempts.max(1) {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_secs(1 << (attempt - 1).min(4))).await;
        }
        tokio::time::sleep(opts.delay).await;

        let mut request = client.get(&url);
        if let Some(e) = old.filter(|_| intact) {
            if let Some(ref tag) = e.etag {
                request = request.header(reqwest::header::IF_NONE_MATCH, tag);
            }
            if let Some(ref date) = e.last_modified {
                request = request.header(reqwest::header::IF_MODIFIED_SINCE, date);
            }
        }
        let response = match request.send().await {
            Ok(r) => r,
            Err(e) => {
                last_error = short_error(&e);
                continue;
            }
        };
        let code = response.status();
        let header = |name: reqwest::header::HeaderName| {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        let etag = header(reqwest::header::ETAG);
        let last_modified = header(reqwest::header::LAST_MODIFIED);
        let store = |body: &str, kind: RecordKind, ok: PullStatus| {
            let entry = entry_for(
                body,
                kind,
                url.clone(),
                Some(code.as_u16()),
                etag.clone(),
                last_modified.clone(),
                now(),
                false,
            );
            let changes = match old {
                Some(o) if o.sha256 != entry.sha256 => {
                    crate::changes::diff(&entry_key, o, old_body.as_deref(), &entry, body, now())
                }
                _ => Vec::new(),
            };
            match save(&path, body, ok) {
                ok @ (PullStatus::Saved(_) | PullStatus::NoData) => (ok, Some(entry), changes),
                failed => (failed, None, Vec::new()),
            }
        };
        if code == StatusCode::NOT_MODIFIED
            && let Some(e) = old.filter(|_| intact)
        {
            let confirmed = IndexEntry {
                checked_at: now(),
                ..e.clone()
            };
            let status = match e.kind {
                EntryKind::Tracked => PullStatus::Unchanged(e.records),
                EntryKind::Untracked => PullStatus::NoData,
            };
            return (status, Some(confirmed), Vec::new());
        }
        if code == StatusCode::NOT_FOUND {
            return store(UNTRACKED_RECORD, RecordKind::Untracked, PullStatus::NoData);
        }
        if code == StatusCode::TOO_MANY_REQUESTS || code.is_server_error() {
            last_error = format!("HTTP {}", code.as_u16());
            continue;
        }
        if !code.is_success() {
            return (
                PullStatus::Failed(format!("HTTP {}", code.as_u16())),
                None,
                Vec::new(),
            );
        }
        let body = match response.text().await {
            Ok(b) => b,
            Err(e) => {
                last_error = short_error(&e);
                continue;
            }
        };
        return match record_kind(&body) {
            Some(k @ RecordKind::Tracked(n)) => store(&body, k, PullStatus::Saved(n)),
            Some(k @ RecordKind::Untracked) => store(&body, k, PullStatus::NoData),
            None => {
                last_error = "unexpected response (blocked or rate limited?)".to_string();
                continue;
            }
        };
    }
    (PullStatus::Failed(last_error), None, Vec::new())
}

/// Write via a temp file and rename, so an interrupted pull never leaves
/// a half-written record behind.
fn save(path: &Path, body: &str, ok: PullStatus) -> PullStatus {
    let tmp = path.with_extension("json.tmp");
    match std::fs::write(&tmp, body).and_then(|_| std::fs::rename(&tmp, path)) {
        Ok(()) => ok,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            PullStatus::Failed(format!("write failed: {e}"))
        }
    }
}

fn short_error(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "timed out".to_string()
    } else if e.is_connect() {
        "connection failed".to_string()
    } else {
        e.to_string()
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn write_meta(dir: &Path, meta: &DbMeta) -> Result<()> {
    let json = serde_json::to_string_pretty(meta)?;
    std::fs::write(dir.join(META_FILE), json)?;
    Ok(())
}

/// Contents of a local database
#[derive(Debug, Clone, Default, Serialize)]
pub struct DbStatus {
    /// Metadata, if the directory has been pulled into
    pub meta: Option<DbMeta>,
    /// Stored plugin records
    pub plugins: usize,
    /// Stored theme records
    pub themes: usize,
    /// Stored core records
    pub core: usize,
    /// Of those, components WPVulnerability has no entry for (not checked)
    pub untracked: usize,
    /// Total vulnerability records across all files
    pub records: usize,
    /// Unix time of the oldest record file
    pub oldest: Option<u64>,
    /// Entries in `index.json`; `None` without an index (format 1)
    pub indexed: Option<usize>,
    /// Of those, entries rebuilt from files (download details unknown)
    pub rebuilt: usize,
    /// Unix time of the oldest confirmation among indexed records that
    /// were ever confirmed
    pub oldest_check: Option<u64>,
    /// Indexed records never confirmed (rebuilt from files)
    pub unconfirmed: usize,
    /// The Wordfence feed, if one was pulled
    pub wordfence: Option<crate::wordfence_db::Meta>,
}

/// Inspect a local database directory
pub fn status(dir: &Path) -> Result<DbStatus> {
    let index = read_index(dir)?;
    let mut st = DbStatus {
        meta: std::fs::read_to_string(dir.join(META_FILE))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok()),
        indexed: index.as_ref().map(|i| i.records.len()),
        rebuilt: index
            .as_ref()
            .map_or(0, |i| i.records.values().filter(|e| e.rebuilt).count()),
        oldest_check: index.as_ref().and_then(|i| {
            i.records
                .values()
                .map(|e| e.checked_at)
                .filter(|&t| t > 0)
                .min()
        }),
        unconfirmed: index.map_or(0, |i| {
            i.records.values().filter(|e| e.checked_at == 0).count()
        }),
        wordfence: crate::wordfence_db::read_meta(dir),
        ..Default::default()
    };
    for kind in [
        ComponentType::Core,
        ComponentType::Plugin,
        ComponentType::Theme,
    ] {
        let Ok(entries) = std::fs::read_dir(dir.join(dir_name(kind))) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            match kind {
                ComponentType::Core => st.core += 1,
                ComponentType::Plugin => st.plugins += 1,
                ComponentType::Theme => st.themes += 1,
            }
            match std::fs::read_to_string(&path)
                .ok()
                .as_deref()
                .and_then(record_kind)
            {
                Some(RecordKind::Tracked(n)) => st.records += n,
                Some(RecordKind::Untracked) | None => st.untracked += 1,
            }
            if let Some(t) = entry
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|m| m.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
            {
                st.oldest = Some(st.oldest.map_or(t, |o| o.min(t)));
            }
        }
    }
    Ok(st)
}

/// Append changes found outside a pull (another source) to the change log
pub fn append_changes(dir: &Path, changes: &[crate::changes::Change]) -> Result<()> {
    crate::changes::append_log(dir, changes)
}

/// What a local database knows about one component
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Known {
    /// Tracked, with this many vulnerability records
    Tracked(usize),
    /// Looked up, but WPVulnerability has no entry for it
    Untracked,
    /// Never pulled into this database (or unreadable)
    Missing,
}

/// Look up one component's stored record
pub fn known(dir: &Path, kind: ComponentType, key: &str) -> Known {
    match record_path(dir, kind, key)
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|b| record_kind(&b))
    {
        Some(RecordKind::Tracked(n)) => Known::Tracked(n),
        Some(RecordKind::Untracked) => Known::Untracked,
        None => Known::Missing,
    }
}

/// Result of [`verify`]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Verification {
    /// Record files checked
    pub records: usize,
    /// Of those, untracked components (not a problem: nothing to check)
    pub untracked: usize,
    /// Everything wrong, each with what it means and how to fix it
    pub problems: Vec<String>,
    /// The part of `problems` that concerns the Wordfence feed (also
    /// listed in `problems`). Kept apart so a caller that does not use the
    /// feed can leave those out without guessing from the text.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub feed_problems: Vec<String>,
    /// Lookups the inventory needs that the database lacks
    pub missing: Vec<String>,
}

impl Verification {
    /// Nothing wrong and nothing missing
    pub fn ok(&self) -> bool {
        self.problems.is_empty() && self.missing.is_empty()
    }
}

/// Files allowed at the top of a database
const TOP_LEVEL: [&str; 8] = [
    META_FILE,
    INDEX_FILE,
    "MANIFEST.json",
    "changes",
    "core",
    "plugin",
    "theme",
    crate::wordfence_db::DIR,
];

/// Check a database: format, index, every record against its recorded
/// sha256, stray files, and (with `needed`) coverage of an inventory
pub fn verify(dir: &Path, needed: &[(ComponentType, String)]) -> Verification {
    let mut v = Verification::default();
    let mut problem = |p: String| v.problems.push(p);
    if !dir.is_dir() {
        problem(format!(
            "{}: not a directory. Run `db pull` to create the database, or check the path.",
            dir.display()
        ));
        return v;
    }

    match std::fs::read_to_string(dir.join(META_FILE))
        .ok()
        .map(|s| serde_json::from_str::<DbMeta>(&s))
    {
        None => problem(format!(
            "{META_FILE}: missing, so this is not a database written by `db pull` (or it was \
             only partly copied). Copy the whole directory, or pull again."
        )),
        Some(Err(e)) => problem(format!(
            "{META_FILE}: unreadable ({e}). Pull again into a fresh directory."
        )),
        Some(Ok(m)) if m.format > FORMAT_VERSION => problem(format!(
            "{META_FILE}: format {} is newer than this tool understands ({FORMAT_VERSION}), so \
             nothing else can be checked. Use a newer wordpress-vulnerable-scanner.",
            m.format
        )),
        Some(Ok(_)) => {}
    }
    let index = match read_index(dir) {
        Ok(Some(i)) => Some(i),
        Ok(None) => {
            problem(format!(
                "{INDEX_FILE}: missing, so no record can be checked against what was \
                 downloaded (a format 1 database). Run `db update` to add the index."
            ));
            None
        }
        Err(e) => {
            problem(e.to_string());
            None
        }
    };

    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !TOP_LEVEL.contains(&name.as_str()) {
            problem(format!(
                "{name}: unexpected; this tool never writes it. If it is not yours, it may have \
                 been added after the pull; remove it before relying on this database."
            ));
        }
    }

    let mut seen = std::collections::BTreeSet::new();
    for kind in [
        ComponentType::Core,
        ComponentType::Plugin,
        ComponentType::Theme,
    ] {
        let folder = dir_name(kind);
        for entry in std::fs::read_dir(dir.join(folder))
            .into_iter()
            .flatten()
            .flatten()
        {
            let name = entry.file_name().to_string_lossy().into_owned();
            let shown = format!("{folder}/{name}");
            let key = match name.strip_suffix(".json") {
                Some(k) if is_safe_key(k) && entry.path().is_file() => k,
                _ if name.ends_with(".tmp") => {
                    problem(format!(
                        "{shown}: left over from an interrupted write. It is never read; \
                         delete it."
                    ));
                    continue;
                }
                _ => {
                    problem(format!(
                        "{shown}: not a record file this tool writes. Remove it before relying \
                         on this database."
                    ));
                    continue;
                }
            };
            v.records += 1;
            let k = index_key(kind, key);
            seen.insert(k.clone());
            let body = match std::fs::read(entry.path()) {
                Ok(b) => b,
                Err(e) => {
                    problem(format!(
                        "{shown}: unreadable ({e}). Run `db update` to fetch it again."
                    ));
                    continue;
                }
            };
            match record_kind(&String::from_utf8_lossy(&body)) {
                None => problem(format!(
                    "{shown}: not a valid WPVulnerability response (damaged, or written by \
                     something else), so scans would treat it as missing. Delete it and run \
                     `db update`."
                )),
                Some(RecordKind::Untracked) => v.untracked += 1,
                Some(RecordKind::Tracked(_)) => {}
            }
            let Some(index) = index.as_ref() else {
                continue;
            };
            match index.records.get(&k) {
                None => problem(format!(
                    "{shown}: not in the index, so where it came from is unknown (added by \
                     hand, or a pull was interrupted). Run `db update` to index it."
                )),
                Some(e) if e.sha256 != sha256_hex(&body) => problem(format!(
                    "{shown}: content differs from what was downloaded (sha256 mismatch), so \
                     it was changed afterwards. Do not trust it; run `db update` to download \
                     it again."
                )),
                Some(_) => {}
            }
        }
    }
    if let Some(index) = index.as_ref() {
        for k in index.records.keys().filter(|k| !seen.contains(*k)) {
            problem(format!(
                "{k}: listed in the index but its file is missing, so scans treat it as never \
                 pulled. Run `db update` to fetch it again."
            ));
        }
    }

    for entry in std::fs::read_dir(dir.join("changes"))
        .into_iter()
        .flatten()
        .flatten()
    {
        let name = entry.file_name().to_string_lossy().into_owned();
        let valid = name.ends_with(".json")
            && std::fs::read_to_string(entry.path())
                .ok()
                .and_then(|s| serde_json::from_str::<Vec<crate::changes::Change>>(&s).ok())
                .is_some();
        if !valid {
            problem(format!(
                "changes/{name}: not a change log this tool writes. Scans never read it, but \
                 the history it holds cannot be trusted."
            ));
        }
    }

    let feed = crate::wordfence_db::verify(dir);
    v.problems.extend(feed.iter().cloned());
    v.feed_problems = feed;

    for (kind, key) in needed {
        if !record_path(dir, *kind, key).is_some_and(|p| p.is_file()) {
            v.missing.push(index_key(*kind, key));
        }
    }
    v
}

/// Components from `items` that have no record in `dir`
pub fn missing<'a>(
    dir: &Path,
    items: impl IntoIterator<Item = (ComponentType, &'a str)>,
) -> Vec<&'a str> {
    items
        .into_iter()
        .filter(|(kind, key)| !record_path(dir, *kind, key).is_some_and(|p| p.is_file()))
        .map(|(_, key)| key)
        .collect()
}

/// Components from `items` whose stored record says WPVulnerability has no
/// entry for them: they were looked up, but nothing could be checked
pub fn untracked<'a>(
    dir: &Path,
    items: impl IntoIterator<Item = (ComponentType, &'a str)>,
) -> Vec<&'a str> {
    items
        .into_iter()
        .filter(|(kind, key)| {
            record_path(dir, *kind, key)
                .and_then(|p| std::fs::read_to_string(p).ok())
                .and_then(|b| record_kind(&b))
                == Some(RecordKind::Untracked)
        })
        .map(|(_, key)| key)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_keys() {
        assert!(is_safe_key("woocommerce"));
        assert!(is_safe_key("6.4.3"));
        assert!(is_safe_key("wp_rocket-2"));
        assert!(!is_safe_key(""));
        assert!(!is_safe_key("../etc/passwd"));
        assert!(!is_safe_key("a/b"));
        assert!(!is_safe_key(".hidden"));
        assert!(!is_safe_key("wp-rocket--:x"));
    }

    #[test]
    fn record_paths() {
        let d = Path::new("/db");
        assert_eq!(
            record_path(d, ComponentType::Plugin, "akismet"),
            Some(PathBuf::from("/db/plugin/akismet.json"))
        );
        assert_eq!(
            record_path(d, ComponentType::Core, "6.4.3"),
            Some(PathBuf::from("/db/core/6.4.3.json"))
        );
        assert_eq!(record_path(d, ComponentType::Theme, "../x"), None);
    }
}
