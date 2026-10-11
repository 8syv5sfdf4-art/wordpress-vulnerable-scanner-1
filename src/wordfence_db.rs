//! Keeping a Wordfence feed in the local database
//!
//! `pull` downloads a feed into `<db>/wordfence/`:
//!
//! ```text
//! <db>/wordfence/wordfence.json         the feed, exactly as downloaded
//! <db>/wordfence/wordfence.meta.json    where and when it came from, sha256, counts
//! <db>/wordfence/wordfence.NOTICE.txt   copyright notice the license requires
//! ```
//!
//! A download is streamed to a temporary file, size-capped, then parsed in
//! full; only a valid feed replaces the previous one.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::{Client, StatusCode, header};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::http::API_USER_AGENT;
use crate::wordfence::{InputFormat, Keep, WordfenceIndex};

/// Keyless feed: wpprobe's Wordfence export, rebuilt every few hours
pub const GITHUB_URL: &str =
    "https://github.com/Chocapikk/wpprobe/releases/download/db/wordfence_vulnerabilities.json";

/// Official Wordfence Intelligence v3 feeds (append `/production` or
/// `/scanner`)
pub const API_URL: &str = "https://www.wordfence.com/api/intelligence/v3/vulnerabilities";

/// Shortest wait between two API downloads with one key. Wordfence answers
/// faster repeats with HTTP 429.
pub const API_MIN_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// Largest feed accepted by default
pub const DEFAULT_MAX_BYTES: u64 = 1 << 30;

/// A feed older than this is flagged by `db status`
pub const STALE_AFTER: Duration = Duration::from_secs(7 * 24 * 3600);

/// Folder inside the database
pub const DIR: &str = "wordfence";
const FEED: &str = "wordfence.json";
const META: &str = "wordfence.meta.json";
const NOTICE: &str = "wordfence.NOTICE.txt";

/// Files a `wordfence/` folder may hold
pub const FILES: [&str; 3] = [FEED, META, NOTICE];

/// Stored next to every downloaded feed (Wordfence Intelligence Terms §3.1)
pub const NOTICE_TEXT: &str = "\
Wordfence Intelligence vulnerability data

Copyright (c) Defiant, Inc. All rights reserved.

This data is licensed under the Wordfence Intelligence Terms and Conditions,
section 3.1: a free, perpetual, worldwide license to reproduce and redistribute
it, provided this copyright designation, the license text, and the license of
any disclosed licensor are kept with every copy.
https://www.wordfence.com/wordfence-intelligence-terms-and-conditions/

Records derived from the CVE List: Copyright (c) The MITRE Corporation.
The CVE List is used under its terms of use: https://www.cve.org/Legal/TermsOfUse
";

/// Where to download from
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FeedSource {
    /// wpprobe's keyless export on GitHub (no CVE-less records)
    Github,
    /// The official Intelligence API (needs a free key)
    Api,
}

/// Which Intelligence feed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Feed {
    /// Full, analysed records
    Production,
    /// Detection-only, smaller, includes records still being researched
    Scanner,
}

/// Options for [`pull`]
#[derive(Debug, Clone)]
pub struct PullOptions {
    /// GitHub or API
    pub from: FeedSource,
    /// Production or scanner (API only)
    pub feed: Feed,
    /// Intelligence API key (API only)
    pub api_key: Option<String>,
    /// Override the URL (mirrors, tests)
    pub url: Option<String>,
    /// Ignore the 30-minute guard for API downloads
    pub force: bool,
    /// Refuse feeds larger than this
    pub max_bytes: u64,
}

impl PullOptions {
    fn url(&self) -> String {
        match (&self.url, self.from) {
            (Some(u), _) => u.clone(),
            (None, FeedSource::Github) => GITHUB_URL.to_string(),
            (None, FeedSource::Api) => format!(
                "{API_URL}/{}",
                match self.feed {
                    Feed::Production => "production",
                    Feed::Scanner => "scanner",
                }
            ),
        }
    }
}

/// `wordfence.meta.json`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    /// Meta format
    pub format: u32,
    /// GitHub or API
    pub source: FeedSource,
    /// Download URL
    pub url: String,
    /// Intelligence feed, for API downloads
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feed: Option<Feed>,
    /// Unix time of the last download, or of the last "not modified"
    pub fetched_at: u64,
    /// SHA-256 of the feed file
    pub sha256: String,
    /// Size of the feed file
    pub bytes: u64,
    /// Records in the feed
    pub records: usize,
    /// Distinct software entries in the feed
    pub slugs: usize,
    /// wpprobe or raw feed
    pub input_format: InputFormat,
    /// `ETag`, for conditional requests
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_etag: Option<String>,
    /// `Last-Modified`, for conditional requests
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_last_modified: Option<String>,
}

/// What [`pull`] did
#[derive(Debug, Clone)]
pub enum PullOutcome {
    /// A new feed replaced the old one (if any)
    Updated {
        /// The new feed
        meta: Meta,
        /// The feed it replaced
        previous: Option<Meta>,
    },
    /// The server said the stored feed is current (HTTP 304)
    NotModified(Meta),
    /// An API download within [`API_MIN_INTERVAL`] of the last one, skipped
    TooSoon {
        /// The stored feed
        meta: Meta,
        /// How long until the next download is allowed
        wait: Duration,
    },
}

/// The feed file in a database
pub fn feed_path(db: &Path) -> PathBuf {
    db.join(DIR).join(FEED)
}

/// The stored meta, if a feed was pulled
pub fn read_meta(db: &Path) -> Option<Meta> {
    let text = std::fs::read_to_string(db.join(DIR).join(META)).ok()?;
    serde_json::from_str(&text).ok()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn bad(msg: impl std::fmt::Display) -> Error {
    Error::Wordfence(msg.to_string())
}

/// Attempts for a keyless download; API downloads are never repeated
/// automatically, since each one may count against the key's limit
const GITHUB_ATTEMPTS: u32 = 3;

/// One download attempt's result
enum Fetched {
    NotModified,
    Body {
        bytes: u64,
        sha256: String,
        etag: Option<String>,
        last_modified: Option<String>,
    },
}

/// Why an attempt failed: worth another try, or final
enum Failure {
    Transient(String),
    Final(Error),
}

impl From<std::io::Error> for Failure {
    fn from(e: std::io::Error) -> Self {
        Failure::Final(e.into())
    }
}

/// Download a feed into `<db>/wordfence/`. `on_progress` gets the bytes
/// received so far and the expected total. `before_replace` runs with the
/// validated new file and the old one (if any) just before the swap, which
/// is where a caller can compare the two.
pub async fn pull(
    db: &Path,
    opts: &PullOptions,
    mut on_progress: impl FnMut(u64, Option<u64>),
    before_replace: impl FnOnce(&Path, Option<&Path>),
) -> Result<PullOutcome> {
    let folder = db.join(DIR);
    let previous = read_meta(db).filter(|_| feed_path(db).is_file());

    if opts.from == FeedSource::Api {
        if opts.api_key.as_deref().is_none_or(str::is_empty) {
            return Err(bad(
                "the Intelligence API needs a key: pass --api-key or set WORDFENCE_API_KEY \
                 (wordfence.com > Account > Integrations), or use --from github, which needs none",
            ));
        }
        if let Some(meta) = previous.as_ref().filter(|m| m.source == FeedSource::Api)
            && !opts.force
        {
            let age = Duration::from_secs(now().saturating_sub(meta.fetched_at));
            if age < API_MIN_INTERVAL {
                return Ok(PullOutcome::TooSoon {
                    meta: meta.clone(),
                    wait: API_MIN_INTERVAL - age,
                });
            }
        }
    }

    std::fs::create_dir_all(&folder)?;
    let url = opts.url();
    let client = Client::builder()
        .user_agent(API_USER_AGENT)
        .connect_timeout(Duration::from_secs(30))
        .read_timeout(Duration::from_secs(120))
        .build()
        .map_err(|e| Error::HttpClient(e.to_string()))?;
    // Conditional only when the stored file is intact and came from here
    let conditional = previous
        .as_ref()
        .filter(|m| m.url == url)
        .filter(|m| sha256_file(&feed_path(db)).ok().as_deref() == Some(m.sha256.as_str()));
    let tmp = folder.join(format!("{FEED}.tmp"));
    let attempts = match opts.from {
        FeedSource::Github => GITHUB_ATTEMPTS,
        FeedSource::Api => 1,
    };

    let mut last = String::new();
    let mut fetched = None;
    for attempt in 1..=attempts {
        if attempt > 1 {
            tokio::time::sleep(Duration::from_secs(5 << (attempt - 2))).await;
        }
        match fetch_once(&client, &url, opts, conditional, &tmp, &mut on_progress).await {
            Ok(f) => {
                fetched = Some(f);
                break;
            }
            Err(Failure::Transient(why)) => last = why,
            Err(Failure::Final(e)) => {
                let _ = std::fs::remove_file(&tmp);
                remove_if_empty(&folder);
                return Err(e);
            }
        }
    }
    let Some(fetched) = fetched else {
        let _ = std::fs::remove_file(&tmp);
        remove_if_empty(&folder);
        return Err(bad(format!(
            "{last}{}. Nothing was replaced. If this machine blocks or throttles outbound \
             traffic, pull on one that can reach {} and copy the database over (`db export` / \
             `db import`).",
            if attempts > 1 {
                format!(" (gave up after {attempts} attempts)")
            } else {
                String::new()
            },
            host(&url)
        )));
    };

    let (bytes, sha256, etag, last_modified) = match fetched {
        Fetched::NotModified => {
            let mut meta =
                previous.ok_or_else(|| bad("the server answered 304 but no feed is stored"))?;
            meta.fetched_at = now();
            write_meta(&folder, &meta)?;
            return Ok(PullOutcome::NotModified(meta));
        }
        Fetched::Body {
            bytes,
            sha256,
            etag,
            last_modified,
        } => (bytes, sha256, etag, last_modified),
    };

    let meta = match validate(&tmp) {
        Ok(index) => Meta {
            format: 1,
            source: opts.from,
            url,
            feed: (opts.from == FeedSource::Api).then_some(opts.feed),
            fetched_at: now(),
            sha256,
            bytes,
            records: index.records,
            slugs: index.slugs,
            input_format: index.format.unwrap_or(InputFormat::Wpprobe),
            http_etag: etag,
            http_last_modified: last_modified,
        },
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            remove_if_empty(&folder);
            return Err(bad(format!(
                "the download from {} is not a usable feed, so the stored one was kept: {e}",
                host(&meta_url(opts))
            )));
        }
    };

    let old = feed_path(db);
    before_replace(&tmp, old.is_file().then_some(old.as_path()));
    std::fs::rename(&tmp, &old)?;
    write_meta(&folder, &meta)?;
    std::fs::write(folder.join(NOTICE), NOTICE_TEXT)?;
    Ok(PullOutcome::Updated { meta, previous })
}

/// Leave no empty `wordfence/` behind after a failed first download
fn remove_if_empty(folder: &Path) {
    let _ = std::fs::remove_dir(folder);
}

async fn fetch_once(
    client: &Client,
    url: &str,
    opts: &PullOptions,
    conditional: Option<&Meta>,
    tmp: &Path,
    on_progress: &mut impl FnMut(u64, Option<u64>),
) -> std::result::Result<Fetched, Failure> {
    let mut request = client.get(url);
    if opts.from == FeedSource::Api
        && let Some(ref key) = opts.api_key
    {
        request = request.header(header::AUTHORIZATION, format!("Bearer {key}"));
    }
    if let Some(meta) = conditional {
        if let Some(ref tag) = meta.http_etag {
            request = request.header(header::IF_NONE_MATCH, tag);
        }
        if let Some(ref date) = meta.http_last_modified {
            request = request.header(header::IF_MODIFIED_SINCE, date);
        }
    }

    let mut response = request.send().await.map_err(|e| {
        let why = if e.is_timeout() {
            "timed out"
        } else if e.is_connect() {
            "connection failed"
        } else {
            "request failed"
        };
        Failure::Transient(format!("could not reach {} ({why})", host(url)))
    })?;
    let status = response.status();
    let header_text = |r: &reqwest::Response, name: header::HeaderName| {
        r.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    match status {
        StatusCode::NOT_MODIFIED if conditional.is_some() => return Ok(Fetched::NotModified),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
            return Err(Failure::Final(bad(format!(
                "HTTP {}: the API key was refused. Check that it is a Wordfence Intelligence \
                 key (wordfence.com > Account > Integrations), not a plugin license key, and \
                 that it was copied whole.",
                status.as_u16()
            ))));
        }
        StatusCode::GONE => {
            return Err(Failure::Final(bad(format!(
                "HTTP 410: {url} is retired (the keyless v2 API is gone). Use the v3 API with \
                 a key, or --from github."
            ))));
        }
        StatusCode::TOO_MANY_REQUESTS => {
            let wait = header_text(&response, header::RETRY_AFTER)
                .map(|r| format!(" Retry after: {r} (seconds, or a date)."))
                .unwrap_or_default();
            return Err(Failure::Final(bad(format!(
                "HTTP 429: too many downloads. Wordfence allows about one full download per \
                 {} minutes per key.{wait} The stored feed is unchanged.",
                API_MIN_INTERVAL.as_secs() / 60
            ))));
        }
        s if s.is_server_error() => {
            return Err(Failure::Transient(format!(
                "HTTP {} from {}",
                s.as_u16(),
                host(url)
            )));
        }
        s if !s.is_success() => {
            return Err(Failure::Final(bad(format!(
                "HTTP {} from {}; the stored feed is unchanged",
                s.as_u16(),
                host(url)
            ))));
        }
        _ => {}
    }
    let total = response.content_length();
    if total.is_some_and(|len| len > opts.max_bytes) {
        return Err(Failure::Final(too_big(opts.max_bytes)));
    }
    let etag = header_text(&response, header::ETAG);
    let last_modified = header_text(&response, header::LAST_MODIFIED);

    // Stream to a temporary file, hashing as it comes
    let mut file = std::fs::File::create(tmp)?;
    let mut hasher = Sha256::new();
    let mut bytes = 0u64;
    loop {
        let chunk = match response.chunk().await {
            Ok(Some(c)) => c,
            Ok(None) => break,
            Err(e) => {
                return Err(Failure::Transient(format!(
                    "the connection to {} dropped after {:.1} MB ({})",
                    host(url),
                    bytes as f64 / 1e6,
                    if e.is_timeout() {
                        "no data for 2 minutes"
                    } else {
                        "transfer interrupted"
                    }
                )));
            }
        };
        bytes += chunk.len() as u64;
        if bytes > opts.max_bytes {
            return Err(Failure::Final(too_big(opts.max_bytes)));
        }
        hasher.update(&chunk);
        file.write_all(&chunk)?;
        on_progress(bytes, total);
    }
    file.sync_all()?;
    if total.is_some_and(|t| t != bytes) {
        return Err(Failure::Transient(format!(
            "the download from {} ended early ({bytes} of {} bytes)",
            host(url),
            total.unwrap_or_default()
        )));
    }
    Ok(Fetched::Body {
        bytes,
        sha256: hex(&hasher.finalize()),
        etag,
        last_modified,
    })
}

fn meta_url(opts: &PullOptions) -> String {
    opts.url()
}

/// Copy a feed obtained some other way into the database, after the same
/// validation as a download
pub fn import(db: &Path, file: &Path) -> Result<Meta> {
    let index = validate(file).map_err(|e| bad(format!("{}: {e}", file.display())))?;
    let folder = db.join(DIR);
    std::fs::create_dir_all(&folder)?;
    let tmp = folder.join(format!("{FEED}.tmp"));
    std::fs::copy(file, &tmp)?;
    let meta = Meta {
        format: 1,
        source: match index.format {
            Some(InputFormat::WordfenceRaw) => FeedSource::Api,
            _ => FeedSource::Github,
        },
        url: format!("file://{}", file.display()),
        feed: None,
        fetched_at: now(),
        sha256: sha256_file(&tmp)?,
        bytes: std::fs::metadata(&tmp)?.len(),
        records: index.records,
        slugs: index.slugs,
        input_format: index.format.unwrap_or(InputFormat::Wpprobe),
        http_etag: None,
        http_last_modified: None,
    };
    std::fs::rename(&tmp, feed_path(db))?;
    write_meta(&folder, &meta)?;
    std::fs::write(folder.join(NOTICE), NOTICE_TEXT)?;
    Ok(meta)
}

/// Can the stored feed's content be trusted: its meta is readable and the
/// feed file still has the checksum recorded at download? Stray files and a
/// missing notice are problems for [`verify`] to report, but they say
/// nothing about the content.
pub fn feed_intact(db: &Path) -> bool {
    read_meta(db)
        .and_then(|m| sha256_file(&feed_path(db)).ok().map(|sum| sum == m.sha256))
        .unwrap_or(false)
}

/// Write the license notice back next to a feed whose content is intact but
/// whose notice file is gone. The notice is a constant, so this is safe to
/// repeat; it is what `db wordfence pull` would restore. Returns whether
/// anything was written. A feed that is not intact is left alone.
pub fn restore_notice(db: &Path) -> std::io::Result<bool> {
    let notice = db.join(DIR).join(NOTICE);
    if !feed_intact(db) || std::fs::symlink_metadata(&notice).is_ok() {
        return Ok(false);
    }
    // exclusive creation: never written through a symlink
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&notice)?;
    if let Err(e) = f.write_all(NOTICE_TEXT.as_bytes()) {
        // a truncated notice would pass verify's is_file check
        drop(f);
        let _ = std::fs::remove_file(&notice);
        return Err(e);
    }
    Ok(true)
}

/// Problems with a stored feed, each explained; empty when it is intact
pub fn verify(db: &Path) -> Vec<String> {
    let folder = db.join(DIR);
    match std::fs::read_dir(&folder) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(e) => {
            return vec![format!(
                "{DIR}: cannot be read ({e}), so the stored feed cannot be checked"
            )];
        }
        Ok(mut d) => {
            if d.next().is_none() {
                return Vec::new();
            }
        }
    }
    let mut problems = Vec::new();
    for entry in std::fs::read_dir(&folder).into_iter().flatten().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !FILES.contains(&name.as_str()) {
            problems.push(format!(
                "{DIR}/{name}: unexpected; `db wordfence pull` never writes it{}",
                if name.ends_with(".tmp") {
                    " (left over from an interrupted download; delete it)"
                } else {
                    ""
                }
            ));
        }
    }
    let Some(meta) = read_meta(db) else {
        problems.push(format!(
            "{DIR}/{META}: missing or unreadable, so the feed cannot be checked against its \
             download. Run `db wordfence pull` again."
        ));
        return problems;
    };
    match sha256_file(&feed_path(db)) {
        Err(_) => problems.push(format!(
            "{DIR}/{FEED}: missing, though {META} lists it. Run `db wordfence pull` again."
        )),
        Ok(sum) if sum != meta.sha256 => problems.push(format!(
            "{DIR}/{FEED}: content differs from what was downloaded (sha256 mismatch), so it \
             was changed afterwards. Do not trust it; run `db wordfence pull` again."
        )),
        Ok(_) => {}
    }
    if !folder.join(NOTICE).is_file() {
        problems.push(format!(
            "{DIR}/{NOTICE}: missing. The Wordfence license requires the copyright notice to \
             travel with the data; run `db wordfence pull` again to restore it."
        ));
    }
    problems
}

fn validate(path: &Path) -> Result<WordfenceIndex> {
    WordfenceIndex::load(path, &Keep::Count)
}

fn write_meta(folder: &Path, meta: &Meta) -> Result<()> {
    let tmp = folder.join(format!("{META}.tmp"));
    std::fs::write(&tmp, serde_json::to_string_pretty(meta)?)?;
    std::fs::rename(&tmp, folder.join(META))?;
    Ok(())
}

fn too_big(max: u64) -> Error {
    bad(format!(
        "the feed is larger than {} MiB, so the download was stopped and the stored feed kept. \
         Raise --max-bytes if that is expected.",
        max >> 20
    ))
}

fn host(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| url.to_string())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-256 of a file, streamed
pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        match file.read(&mut buf)? {
            0 => break,
            n => hasher.update(&buf[..n]),
        }
    }
    Ok(hex(&hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wordfence/raw-sample.json")
    }

    fn temp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("wvs-wfdb-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn intact_means_the_content_matches_not_that_nothing_is_stray() {
        let db = temp("intact");
        import(&db, &sample()).unwrap();
        assert!(feed_intact(&db));
        assert!(verify(&db).is_empty());

        // stray file and missing notice: reported, content still trusted
        std::fs::write(db.join(DIR).join("wordfence.json.tmp"), "x").unwrap();
        std::fs::remove_file(db.join(DIR).join(NOTICE)).unwrap();
        assert!(feed_intact(&db));
        assert_eq!(verify(&db).len(), 2);

        // changed content: not intact
        let feed = feed_path(&db);
        let mut bytes = std::fs::read(&feed).unwrap();
        bytes.push(b' ');
        std::fs::write(&feed, bytes).unwrap();
        assert!(!feed_intact(&db));

        // no meta: not intact
        std::fs::remove_file(db.join(DIR).join(META)).unwrap();
        assert!(!feed_intact(&db));
        let _ = std::fs::remove_dir_all(&db);
    }

    #[test]
    fn a_missing_notice_is_restored_for_an_intact_feed_only() {
        let db = temp("notice");
        import(&db, &sample()).unwrap();
        std::fs::remove_file(db.join(DIR).join(NOTICE)).unwrap();
        assert_eq!(verify(&db).len(), 1);
        assert!(restore_notice(&db).unwrap());
        assert!(verify(&db).is_empty());
        assert!(!restore_notice(&db).unwrap(), "nothing left to restore");

        // a changed feed is not blessed by getting its notice back
        std::fs::remove_file(db.join(DIR).join(NOTICE)).unwrap();
        let feed = feed_path(&db);
        let mut bytes = std::fs::read(&feed).unwrap();
        bytes.push(b' ');
        std::fs::write(&feed, bytes).unwrap();
        assert!(!restore_notice(&db).unwrap());
        assert!(!db.join(DIR).join(NOTICE).exists());
        let _ = std::fs::remove_dir_all(&db);
    }

    #[cfg(unix)]
    #[test]
    fn a_dangling_symlink_at_the_notice_is_not_written_through() {
        let db = temp("dangling");
        import(&db, &sample()).unwrap();
        let notice = db.join(DIR).join(NOTICE);
        std::fs::remove_file(&notice).unwrap();
        let target = db.join("elsewhere.txt");
        std::os::unix::fs::symlink(&target, &notice).unwrap();
        assert!(!restore_notice(&db).unwrap());
        assert!(!target.exists(), "must not create the symlink's target");
        let _ = std::fs::remove_dir_all(&db);
    }

    #[cfg(unix)]
    #[test]
    fn an_unlistable_feed_folder_is_a_problem_not_silence() {
        use std::os::unix::fs::PermissionsExt;
        let db = temp("unlistable");
        import(&db, &sample()).unwrap();
        let folder = db.join(DIR);
        std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o000)).unwrap();
        let can_list = std::fs::read_dir(&folder).is_ok();
        let problems = verify(&db);
        std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o755)).unwrap();
        if !can_list {
            assert_eq!(problems.len(), 1, "{problems:?}");
            assert!(problems[0].contains("cannot be read"));
        }
        let _ = std::fs::remove_dir_all(&db);
    }
}
