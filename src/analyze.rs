//! Analysis logic for vulnerability scanning

use crate::aliases::MatchedVia;
use crate::scanner::{ComponentInfo, ComponentType, ScanResult};
use crate::vulnerability::{
    RecordLookup, Severity, SourceKind, Vulnerability, VulnerabilityClient, VulnerabilityReport,
};
use futures::future::join_all;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// What the scan could say about one component. Exactly one applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentState {
    /// Tracked, and the installed version is inside an affected range
    Vulnerable,
    /// Like `Vulnerable`, but found through an alias: premium editions may
    /// number versions differently, so confirm before acting
    AliasMatch,
    /// Tracked, and no affected range contains the installed version
    Clean,
    /// The data source has no entry for it: not checked
    Untracked,
    /// The local database never pulled it: not checked
    NotInDb,
    /// No installed version is known, so ranges cannot be compared: not
    /// checked
    UnknownVersion,
    /// The lookup failed (network error, damaged record): not checked
    Failed,
    /// Deliberately never looked up: a must-use plugin or drop-in is not a
    /// wordpress.org plugin, so no database can be asked about it by name.
    /// Not checked, and to be reviewed by hand.
    NotLookedUp,
}

impl ComponentState {
    /// Whether the component was actually compared with vulnerability data
    pub fn checked(self) -> bool {
        matches!(self, Self::Vulnerable | Self::AliasMatch | Self::Clean)
    }

    /// Short human label
    pub fn label(self) -> &'static str {
        match self {
            Self::Vulnerable => "vulnerable",
            Self::AliasMatch => "vulnerable (via alias, confirm)",
            Self::Clean => "clean",
            Self::Untracked => "not tracked",
            Self::NotInDb => "not in the local database",
            Self::UnknownVersion => "version unknown",
            Self::Failed => "lookup failed",
            Self::NotLookedUp => "not looked up",
        }
    }
}

/// How many components ended in each state
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct StateCounts {
    /// See [`ComponentState::Vulnerable`]
    pub vulnerable: usize,
    /// See [`ComponentState::AliasMatch`]
    pub alias_match: usize,
    /// See [`ComponentState::Clean`]
    pub clean: usize,
    /// See [`ComponentState::Untracked`]
    pub untracked: usize,
    /// See [`ComponentState::NotInDb`]
    pub not_in_db: usize,
    /// See [`ComponentState::UnknownVersion`]
    pub unknown_version: usize,
    /// See [`ComponentState::Failed`]
    pub failed: usize,
    /// See [`ComponentState::NotLookedUp`]
    #[serde(skip_serializing_if = "is_zero")]
    pub not_looked_up: usize,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

impl StateCounts {
    fn add(&mut self, state: ComponentState) {
        use ComponentState::*;
        *match state {
            Vulnerable => &mut self.vulnerable,
            AliasMatch => &mut self.alias_match,
            Clean => &mut self.clean,
            Untracked => &mut self.untracked,
            NotInDb => &mut self.not_in_db,
            UnknownVersion => &mut self.unknown_version,
            Failed => &mut self.failed,
            NotLookedUp => &mut self.not_looked_up,
        } += 1;
    }

    /// Components that were not compared with any data
    pub fn not_checked(&self) -> usize {
        self.untracked + self.not_in_db + self.unknown_version + self.failed + self.not_looked_up
    }
}

/// Vulnerability analysis for a single component
#[derive(Debug, Clone, Serialize)]
pub struct ComponentVulnerabilities {
    /// Component type
    pub component_type: ComponentType,
    /// Component slug
    pub slug: String,
    /// Detected version
    pub version: Option<String>,
    /// Vulnerabilities affecting this component
    pub vulnerabilities: Vec<Vulnerability>,
    /// Highest severity
    pub max_severity: Option<Severity>,
    /// What the scan could say about it
    pub state: ComponentState,
    /// Looked up under its own slug or through an alias
    pub matched_via: MatchedVia,
    /// Installed slug, when looked up through an alias
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installed_as: Option<String>,
    /// Why it was not checked, or what to keep in mind about the result
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// For a component not checked because of its name: the slug the
    /// local database does track, to put in aliases.toml
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_alias: Option<String>,
    /// What each source knew about it, when a scan uses several
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub coverage: BTreeMap<SourceKind, Coverage>,
}

impl ComponentVulnerabilities {
    /// Check if there are any vulnerabilities
    pub fn has_vulnerabilities(&self) -> bool {
        !self.vulnerabilities.is_empty()
    }

    /// Count vulnerabilities
    pub fn vuln_count(&self) -> usize {
        self.vulnerabilities.len()
    }
}

/// Summary of vulnerability counts
#[derive(Debug, Clone, Default, Serialize)]
pub struct VulnerabilitySummary {
    /// Count of critical vulnerabilities
    pub critical: usize,
    /// Count of high severity vulnerabilities
    pub high: usize,
    /// Count of medium severity vulnerabilities
    pub medium: usize,
    /// Count of low severity vulnerabilities
    pub low: usize,
    /// Total count
    pub total: usize,
    /// Components that could not be compared with any data
    pub not_checked: usize,
    /// Components per state
    pub components: StateCounts,
    /// With several sources: components each source had no data for
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub not_checked_by: BTreeMap<SourceKind, usize>,
}

impl VulnerabilitySummary {
    /// Create from a list of vulnerabilities
    pub fn from_vulnerabilities(vulns: &[Vulnerability]) -> Self {
        let mut summary = Self::default();
        for v in vulns {
            summary.add_severity(v.severity);
        }
        summary
    }

    /// Create from a list of vulnerability references (avoids cloning)
    pub fn from_refs(vulns: &[&Vulnerability]) -> Self {
        let mut summary = Self::default();
        for v in vulns {
            summary.add_severity(v.severity);
        }
        summary
    }

    /// Add a severity to the counts
    fn add_severity(&mut self, severity: Severity) {
        match severity {
            Severity::Critical => self.critical += 1,
            Severity::High => self.high += 1,
            Severity::Medium => self.medium += 1,
            Severity::Low => self.low += 1,
        }
        self.total += 1;
    }

    /// Check if there are any critical or high severity vulnerabilities
    pub fn has_critical_or_high(&self) -> bool {
        self.critical > 0 || self.high > 0
    }

    /// Check if there are any vulnerabilities
    pub fn has_any(&self) -> bool {
        self.total > 0
    }

    /// Get the highest severity level
    pub fn max_severity(&self) -> Option<Severity> {
        if self.critical > 0 {
            Some(Severity::Critical)
        } else if self.high > 0 {
            Some(Severity::High)
        } else if self.medium > 0 {
            Some(Severity::Medium)
        } else if self.low > 0 {
            Some(Severity::Low)
        } else {
            None
        }
    }
}

/// Complete vulnerability analysis
#[derive(Debug, Clone, Serialize)]
pub struct Analysis {
    /// Target URL (if scanned from URL)
    pub url: Option<String>,
    /// Scan timestamp
    pub scan_date: String,
    /// Component vulnerability reports
    pub components: Vec<ComponentVulnerabilities>,
    /// Overall summary
    pub summary: VulnerabilitySummary,
    /// Problems with the scan's own setup (aliases, inventory), each saying
    /// what it means and what to do
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// Data sources used, with the attribution their licenses require
    pub sources: Vec<SourceInfo>,
}

impl Analysis {
    /// Get all vulnerabilities across all components
    pub fn all_vulnerabilities(&self) -> Vec<&Vulnerability> {
        self.components
            .iter()
            .flat_map(|c| c.vulnerabilities.iter())
            .collect()
    }

    /// Filter components to only those with vulnerabilities
    pub fn vulnerable_components(&self) -> impl Iterator<Item = &ComponentVulnerabilities> {
        self.components.iter().filter(|c| c.has_vulnerabilities())
    }

    /// The same analysis restricted to one kind of component (core, themes
    /// or plugins), with the summary recomputed so it describes only those
    /// components. Sources, warnings and scan metadata are kept: a per-part
    /// report still has to name where its data came from.
    ///
    /// The result has no components when the scan found none of that kind
    /// (no themes, or no readable core version). That is "nothing was
    /// inventoried", not "clean"; callers that write a report must say so.
    pub fn only(&self, kind: ComponentType) -> Analysis {
        let components: Vec<ComponentVulnerabilities> = self
            .components
            .iter()
            .filter(|c| c.component_type == kind)
            .cloned()
            .collect();
        Analysis {
            url: self.url.clone(),
            scan_date: self.scan_date.clone(),
            summary: summarize(&components),
            components,
            warnings: self.warnings.clone(),
            sources: self.sources.clone(),
        }
    }

    /// Add a component that was deliberately never looked up (a must-use
    /// plugin or drop-in has no entry in any database by name). It is
    /// reported as not checked with `note` saying why, and the summary is
    /// recomputed so the counts include it.
    pub fn add_not_looked_up(
        &mut self,
        component_type: ComponentType,
        slug: &str,
        version: Option<&str>,
        note: &str,
    ) {
        self.components.push(ComponentVulnerabilities {
            component_type,
            slug: slug.to_string(),
            version: version.map(str::to_string),
            vulnerabilities: Vec::new(),
            max_severity: None,
            state: ComponentState::NotLookedUp,
            matched_via: MatchedVia::Slug,
            installed_as: None,
            note: Some(note.to_string()),
            suggested_alias: None,
            coverage: BTreeMap::new(),
        });
        self.summary = summarize(&self.components);
    }

    /// Get components by severity
    pub fn components_by_severity(&self, severity: Severity) -> Vec<&ComponentVulnerabilities> {
        self.components
            .iter()
            .filter(|c| c.max_severity == Some(severity))
            .collect()
    }
}

/// Severity counts, per-state counts and per-source gaps for a set of
/// components
fn summarize(components: &[ComponentVulnerabilities]) -> VulnerabilitySummary {
    let all_vulns: Vec<&Vulnerability> = components
        .iter()
        .flat_map(|c| c.vulnerabilities.iter())
        .collect();

    let mut summary = VulnerabilitySummary::from_refs(&all_vulns);
    for c in components {
        summary.components.add(c.state);
        for (source, cov) in &c.coverage {
            if *cov != Coverage::Tracked {
                *summary.not_checked_by.entry(*source).or_default() += 1;
            }
        }
    }
    summary.not_checked = summary.components.not_checked();
    summary
}

/// What one source said about a component
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Coverage {
    /// The source knows the component
    Tracked,
    /// The source has no entry for it
    Untracked,
    /// A local database that never pulled it
    NotInDb,
    /// The lookup failed
    Failed,
}

/// A data source a scan used, for reports and attribution
#[derive(Debug, Clone, Serialize)]
pub struct SourceInfo {
    /// Which source
    pub source: SourceKind,
    /// Where its data came from (API URL, database, feed file)
    pub detail: String,
    /// Copyright notice to show with its data, when the license requires one
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribution: Option<String>,
}

/// Analyzer for scan results
pub struct Analyzer {
    client: Option<VulnerabilityClient>,
    wordfence: Option<(crate::wordfence::WordfenceIndex, String)>,
    include_informational: bool,
}

impl Analyzer {
    /// Create a new analyzer
    pub fn new() -> crate::error::Result<Self> {
        Self::with_source(crate::vulnerability::Source::default())
    }

    /// Create an analyzer that reads from a specific source
    /// (a mirror of the API, or a local database directory)
    pub fn with_source(source: crate::vulnerability::Source) -> crate::error::Result<Self> {
        Ok(Self {
            client: Some(VulnerabilityClient::with_source(source)?),
            wordfence: None,
            include_informational: false,
        })
    }

    /// An analyzer that uses only Wordfence data: no network at all
    pub fn wordfence_only(index: crate::wordfence::WordfenceIndex, detail: String) -> Self {
        Self {
            client: None,
            wordfence: Some((index, detail)),
            include_informational: false,
        }
    }

    /// Also use Wordfence data, next to WPVulnerability
    pub fn with_wordfence(
        mut self,
        index: crate::wordfence::WordfenceIndex,
        detail: String,
    ) -> Self {
        self.wordfence = Some((index, detail));
        self
    }

    /// Report Wordfence's informational records (as low, marked) instead
    /// of skipping them
    pub fn include_informational(mut self, yes: bool) -> Self {
        self.include_informational = yes;
        self
    }

    /// The sources this analyzer reads, in the order they are consulted
    pub fn sources(&self) -> Vec<SourceInfo> {
        let mut out = Vec::new();
        if let Some(ref client) = self.client {
            out.push(SourceInfo {
                source: SourceKind::WpVulnerability,
                detail: match client.source() {
                    crate::vulnerability::Source::Api(url) => format!("API {url}"),
                    crate::vulnerability::Source::Local(dir) => {
                        format!("local database {}", dir.display())
                    }
                },
                attribution: None,
            });
        }
        if let Some((_, ref detail)) = self.wordfence {
            out.push(SourceInfo {
                source: SourceKind::Wordfence,
                detail: detail.clone(),
                attribution: Some(crate::wordfence::ATTRIBUTION.to_string()),
            });
        }
        out
    }

    /// Analyze scan results for vulnerabilities
    pub async fn analyze(&self, scan: &ScanResult) -> Analysis {
        // Fetch all vulnerability reports in parallel
        let futures: Vec<_> = scan
            .components
            .iter()
            .map(|component| self.analyze_component(component))
            .collect();

        let components: Vec<ComponentVulnerabilities> = join_all(futures).await;

        let summary = summarize(&components);

        Analysis {
            url: if scan.url.is_empty() {
                None
            } else {
                Some(scan.url.clone())
            },
            scan_date: chrono_lite_now(),
            components,
            summary,
            warnings: Vec::new(),
            sources: self.sources(),
        }
    }

    /// Analyze a single component
    async fn analyze_component(&self, component: &ComponentInfo) -> ComponentVulnerabilities {
        let via = if component.installed_as.is_some() {
            MatchedVia::Alias
        } else {
            MatchedVia::Slug
        };
        let kind = component.component_type;
        let several = self.client.is_some() && self.wordfence.is_some();

        // Ask every source; keep what each one knows
        let mut found: Vec<(SourceKind, Vec<Vulnerability>)> = Vec::new();
        let mut misses: Vec<(SourceKind, ComponentState, String)> = Vec::new();
        let mut coverage = BTreeMap::new();
        if let Some(ref client) = self.client {
            let key = match kind {
                ComponentType::Core => component.version.as_deref(),
                _ => Some(component.slug.as_str()),
            };
            let looked = match key {
                Some(key) => client.lookup(kind, key).await,
                // Core is looked up by version, so there is nothing to ask
                None => RecordLookup::Found(Default::default()),
            };
            let source = SourceKind::WpVulnerability;
            match looked {
                RecordLookup::Found(report) => {
                    coverage.insert(source, Coverage::Tracked);
                    found.push((source, report.vulnerabilities));
                }
                RecordLookup::Untracked => {
                    coverage.insert(source, Coverage::Untracked);
                    misses.push((
                        source,
                        ComponentState::Untracked,
                        "the data source has no entry for it (common for premium and custom code)"
                            .into(),
                    ));
                }
                RecordLookup::Missing => {
                    coverage.insert(source, Coverage::NotInDb);
                    misses.push((
                        source,
                        ComponentState::NotInDb,
                        "never pulled into the local database; run `db pull` with the same inputs"
                            .into(),
                    ));
                }
                RecordLookup::Failed(why) => {
                    coverage.insert(source, Coverage::Failed);
                    misses.push((source, ComponentState::Failed, why));
                }
            }
        }
        if let Some((ref index, _)) = self.wordfence {
            let slug = match kind {
                ComponentType::Core => "wordpress",
                _ => component.slug.as_str(),
            };
            let source = SourceKind::Wordfence;
            match index.lookup(kind, slug) {
                Some(list) => {
                    coverage.insert(source, Coverage::Tracked);
                    let list = list
                        .iter()
                        .filter(|v| !v.informational || self.include_informational)
                        .map(|v| {
                            let mut v = v.clone();
                            if v.informational {
                                v.severity = Severity::Low;
                                v.title = format!("[informational] {}", v.title);
                            }
                            v
                        })
                        .collect();
                    found.push((source, list));
                }
                None => {
                    coverage.insert(source, Coverage::Untracked);
                    misses.push((
                        source,
                        ComponentState::Untracked,
                        "Wordfence has no entry for it; it lists only software with known \
                         vulnerabilities, so this is not proof of safety"
                            .into(),
                    ));
                }
            }
        }

        let (state, vulnerabilities, note) = if found.is_empty() {
            // Nothing to compare with: the most actionable reason wins
            let state = [
                ComponentState::Failed,
                ComponentState::NotInDb,
                ComponentState::Untracked,
            ]
            .into_iter()
            .find(|s| misses.iter().any(|(_, m, _)| m == s))
            .unwrap_or(ComponentState::Untracked);
            let note = if several {
                misses
                    .iter()
                    .map(|(source, _, why)| format!("{}: {why}", source_name(*source)))
                    .collect::<Vec<_>>()
                    .join("; ")
            } else {
                misses
                    .first()
                    .map(|(_, _, why)| why.clone())
                    .unwrap_or_default()
            };
            (state, Vec::new(), Some(note))
        } else if let Some(version) = component.version.as_deref() {
            let mut merged: Vec<Vulnerability> = Vec::new();
            for (source, list) in &found {
                let hits = VulnerabilityReport {
                    vulnerabilities: list.clone(),
                }
                .filter_by_version(Some(version))
                .vulnerabilities;
                for hit in hits {
                    merge_finding(&mut merged, hit, *source);
                }
            }
            let state = match (merged.is_empty(), via) {
                (true, _) => ComponentState::Clean,
                (false, MatchedVia::Alias) => ComponentState::AliasMatch,
                (false, MatchedVia::Slug) => ComponentState::Vulnerable,
            };
            let mut notes = Vec::new();
            if via == MatchedVia::Alias {
                notes.push(format!(
                    "installed as {}, looked up as {}; premium editions may number versions \
                     differently",
                    component.installed_as.as_deref().unwrap_or_default(),
                    component.slug
                ));
            }
            if several {
                for (source, _, why) in &misses {
                    notes.push(format!("{}: {why}", source_name(*source)));
                }
            }
            (state, merged, (!notes.is_empty()).then(|| notes.join("; ")))
        } else {
            let mut ids = std::collections::BTreeSet::new();
            for (_, list) in &found {
                for v in list {
                    ids.insert(v.cves.first().cloned().unwrap_or_else(|| v.id.clone()));
                }
            }
            let note = match ids.len() {
                0 => "no version could be read".to_string(),
                n => format!(
                    "no version could be read; {n} known vulnerabilit{} some versions",
                    if n == 1 { "y affects" } else { "ies affect" }
                ),
            };
            (ComponentState::UnknownVersion, Vec::new(), Some(note))
        };

        let (note, suggested_alias) = match state {
            ComponentState::Untracked | ComponentState::NotInDb
                if component.installed_as.is_none() && kind != ComponentType::Core =>
            {
                self.name_hint(component, state, note)
            }
            _ => (note, None),
        };

        let max_severity = vulnerabilities.iter().map(|v| v.severity).max();
        ComponentVulnerabilities {
            component_type: kind,
            slug: component.slug.clone(),
            version: component.version.clone(),
            vulnerabilities,
            max_severity,
            state,
            matched_via: via,
            installed_as: component.installed_as.clone(),
            note,
            suggested_alias,
            coverage: if several { coverage } else { BTreeMap::new() },
        }
    }

    /// Is the component unchecked only because of its name (a renamed,
    /// premium or backup copy)? Name variants are looked up in the local
    /// database and the Wordfence feed; otherwise the note says how to
    /// find out.
    fn name_hint(
        &self,
        component: &ComponentInfo,
        state: ComponentState,
        note: Option<String>,
    ) -> (Option<String>, Option<String>) {
        let variants = crate::aliases::name_variants(&component.slug);
        let table = match component.component_type {
            ComponentType::Theme => "theme",
            _ => "plugin",
        };
        let advice = |variant: &str, who: String, why: &str| {
            Some(format!(
                "probably installed under another name: {who} \"{variant}\" ({why}). If it is \
                 the same {table}, add `\"{}\" = \"{variant}\"` to the [{table}] table of \
                 aliases.toml",
                component.slug
            ))
        };
        for (variant, why) in &variants {
            if let Some(crate::vulnerability::Source::Local(dir)) =
                self.client.as_ref().map(|c| c.source())
                && let crate::db::Known::Tracked(n) =
                    crate::db::known(dir, component.component_type, variant)
            {
                return (
                    advice(
                        variant,
                        "the database tracks".to_string(),
                        &format!("{n} record{}; {why}", if n == 1 { "" } else { "s" }),
                    ),
                    Some(variant.clone()),
                );
            }
            if let Some((ref index, _)) = self.wordfence
                && let Some(list) = index.lookup(component.component_type, variant)
            {
                let n = list.len();
                return (
                    advice(
                        variant,
                        "Wordfence tracks".to_string(),
                        &format!(
                            "{n} vulnerabilit{}; {why}",
                            if n == 1 { "y" } else { "ies" }
                        ),
                    ),
                    Some(variant.clone()),
                );
            }
        }
        match variants.last() {
            Some((variant, _)) => (
                Some(format!(
                    "{}; the name looks like a renamed, premium or backup copy of \"{variant}\": \
                     run `aliases suggest --online` to check",
                    note.unwrap_or_else(|| state.label().to_string())
                )),
                None,
            ),
            None => (note, None),
        }
    }
}

/// Display name of a source
pub fn source_name(source: SourceKind) -> &'static str {
    match source {
        SourceKind::WpVulnerability => "WPVulnerability",
        SourceKind::Wordfence => "Wordfence",
    }
}

/// Add `hit` (found by `source`) to `merged`: the same CVE from another
/// source joins the existing finding, which then lists both sources;
/// findings without a CVE never merge
fn merge_finding(merged: &mut Vec<Vulnerability>, hit: Vulnerability, source: SourceKind) {
    let same = hit.cves.first().and_then(|cve| {
        merged
            .iter_mut()
            .find(|m| m.cves.first() == Some(cve) && !m.sources.contains(&source))
    });
    let Some(existing) = same else {
        merged.push(hit);
        return;
    };
    existing.sources.push(source);
    for r in hit.references {
        if !existing.references.contains(&r) {
            existing.references.push(r);
        }
    }
    for c in hit.cves {
        if !existing.cves.contains(&c) {
            existing.cves.push(c);
        }
    }
    if existing.cvss_vector.is_none() {
        existing.cvss_vector = hit.cvss_vector;
    }
    if existing.cwes.is_empty() {
        existing.cwes = hit.cwes;
    }
    if existing.description.is_none() {
        existing.description = hit.description;
    }
    if existing.auth.is_none() {
        existing.auth = hit.auth;
    }
    if existing.known_exploited != Some(true) && hit.known_exploited.is_some() {
        existing.known_exploited = hit.known_exploited;
    }
    if existing.fixed_in.is_none() {
        existing.fixed_in = hit.fixed_in;
        existing.fixed_branch = hit.fixed_branch;
    }
}

impl Default for Analyzer {
    fn default() -> Self {
        Self::new().expect("Failed to create analyzer")
    }
}

/// Get current timestamp in ISO format (lightweight, no chrono dependency)
pub(crate) fn chrono_lite_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    iso_date(duration.as_secs())
}

/// Unix time as `YYYY-MM-DDTHH:MM:SSZ`
pub(crate) fn iso_date(secs: u64) -> String {
    // Calculate date/time components
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let mins = (time_secs % 3600) / 60;
    let secs = time_secs % 60;

    // Days since 1970-01-01
    let mut year = 1970;
    let mut remaining_days = days;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let days_in_months: [u64; 12] = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1;
    for days_in_month in days_in_months {
        if remaining_days < days_in_month {
            break;
        }
        remaining_days -= days_in_month;
        month += 1;
    }

    let day = remaining_days + 1;

    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{mins:02}:{secs:02}Z")
}

fn is_leap_year(year: u64) -> bool {
    year.is_multiple_of(4) && !year.is_multiple_of(100) || year.is_multiple_of(400)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vuln(severity: &str) -> Vulnerability {
        serde_json::from_value(serde_json::json!({
            "id": "x", "title": "t", "severity": severity, "cvss_score": null,
            "affected_max": null, "fixed_in": null, "references": []
        }))
        .unwrap()
    }

    fn component(
        kind: ComponentType,
        slug: &str,
        state: ComponentState,
        vulns: Vec<Vulnerability>,
    ) -> ComponentVulnerabilities {
        ComponentVulnerabilities {
            component_type: kind,
            slug: slug.into(),
            version: Some("1.0".into()),
            max_severity: vulns.iter().map(|v| v.severity).max(),
            vulnerabilities: vulns,
            state,
            matched_via: MatchedVia::Slug,
            installed_as: None,
            note: None,
            suggested_alias: None,
            coverage: BTreeMap::new(),
        }
    }

    fn with_coverage(
        mut c: ComponentVulnerabilities,
        cov: &[(SourceKind, Coverage)],
    ) -> ComponentVulnerabilities {
        c.coverage = cov.iter().cloned().collect();
        c
    }

    fn analysis() -> Analysis {
        use ComponentState::*;
        let components = vec![
            with_coverage(
                component(
                    ComponentType::Core,
                    "wordpress",
                    Vulnerable,
                    vec![vuln("critical"), vuln("medium")],
                ),
                &[
                    (SourceKind::WpVulnerability, Coverage::Tracked),
                    (SourceKind::Wordfence, Coverage::Tracked),
                ],
            ),
            with_coverage(
                component(
                    ComponentType::Plugin,
                    "akismet",
                    AliasMatch,
                    vec![vuln("high")],
                ),
                &[
                    (SourceKind::WpVulnerability, Coverage::Tracked),
                    (SourceKind::Wordfence, Coverage::Untracked),
                ],
            ),
            with_coverage(
                component(ComponentType::Plugin, "mine", Untracked, vec![]),
                &[
                    (SourceKind::WpVulnerability, Coverage::Untracked),
                    (SourceKind::Wordfence, Coverage::Untracked),
                ],
            ),
            with_coverage(
                component(ComponentType::Plugin, "gone", Failed, vec![]),
                &[(SourceKind::WpVulnerability, Coverage::Failed)],
            ),
            component(ComponentType::Plugin, "new", NotInDb, vec![]),
            component(ComponentType::Plugin, "odd", UnknownVersion, vec![]),
            component(ComponentType::Theme, "astra", Clean, vec![]),
        ];
        Analysis {
            url: None,
            scan_date: "2026-01-01T00:00:00Z".into(),
            summary: summarize(&components),
            components,
            warnings: vec!["w".into()],
            sources: vec![SourceInfo {
                source: SourceKind::Wordfence,
                detail: "feed".into(),
                attribution: Some("Copyright Defiant".into()),
            }],
        }
    }

    #[test]
    fn parts_add_up_to_the_whole() {
        let a = analysis();
        let parts: Vec<Analysis> = [
            ComponentType::Core,
            ComponentType::Plugin,
            ComponentType::Theme,
        ]
        .into_iter()
        .map(|k| a.only(k))
        .collect();
        let sum = |f: &dyn Fn(&VulnerabilitySummary) -> usize| {
            parts.iter().map(|p| f(&p.summary)).sum::<usize>()
        };
        let w = &a.summary;
        assert_eq!(sum(&|s| s.critical), w.critical);
        assert_eq!(sum(&|s| s.high), w.high);
        assert_eq!(sum(&|s| s.medium), w.medium);
        assert_eq!(sum(&|s| s.low), w.low);
        assert_eq!(sum(&|s| s.total), w.total);
        assert_eq!(sum(&|s| s.not_checked), w.not_checked);
        assert_eq!(sum(&|s| s.components.vulnerable), w.components.vulnerable);
        assert_eq!(sum(&|s| s.components.alias_match), w.components.alias_match);
        assert_eq!(sum(&|s| s.components.clean), w.components.clean);
        assert_eq!(sum(&|s| s.components.untracked), w.components.untracked);
        assert_eq!(sum(&|s| s.components.not_in_db), w.components.not_in_db);
        assert_eq!(
            sum(&|s| s.components.unknown_version),
            w.components.unknown_version
        );
        assert_eq!(sum(&|s| s.components.failed), w.components.failed);
        for source in [SourceKind::WpVulnerability, SourceKind::Wordfence] {
            let parts_n: usize = parts
                .iter()
                .map(|p| p.summary.not_checked_by.get(&source).copied().unwrap_or(0))
                .sum();
            assert_eq!(parts_n, w.not_checked_by.get(&source).copied().unwrap_or(0));
        }
    }

    #[test]
    fn only_keeps_one_kind_and_recomputes_the_summary() {
        let a = analysis();
        assert_eq!(a.summary.total, 3);
        assert_eq!(a.summary.not_checked, 4);

        let core = a.only(ComponentType::Core);
        assert_eq!(core.components.len(), 1);
        assert_eq!((core.summary.critical, core.summary.medium), (1, 1));
        assert_eq!(core.summary.total, 2);
        assert_eq!(core.summary.not_checked, 0);
        assert!(core.summary.not_checked_by.is_empty());

        let plugins = a.only(ComponentType::Plugin);
        assert_eq!(plugins.components.len(), 5);
        assert_eq!((plugins.summary.high, plugins.summary.total), (1, 1));
        assert_eq!(plugins.summary.components.alias_match, 1);
        assert_eq!(plugins.summary.not_checked, 4);
        // akismet and mine: Wordfence has no entry; mine and gone: WPVuln
        // has none or failed
        assert_eq!(
            plugins.summary.not_checked_by.get(&SourceKind::Wordfence),
            Some(&2)
        );
        assert_eq!(
            plugins
                .summary
                .not_checked_by
                .get(&SourceKind::WpVulnerability),
            Some(&2)
        );
        assert_eq!(plugins.warnings, a.warnings);
        assert_eq!(plugins.sources.len(), 1);
        assert_eq!(
            plugins.sources[0].attribution.as_deref(),
            Some("Copyright Defiant")
        );

        let themes = a.only(ComponentType::Theme);
        assert_eq!(themes.summary.total, 0);
        assert_eq!(themes.summary.components.clean, 1);
    }

    #[test]
    fn a_kind_with_no_components_gives_an_empty_analysis() {
        let mut a = analysis();
        a.components
            .retain(|c| c.component_type != ComponentType::Theme);
        let themes = a.only(ComponentType::Theme);
        assert!(themes.components.is_empty());
        assert_eq!(themes.summary.total, 0);
        assert_eq!(themes.summary.not_checked, 0);
    }

    #[test]
    fn components_never_looked_up_count_as_not_checked() {
        let mut a = analysis();
        let before = a.summary.not_checked;
        a.add_not_looked_up(
            ComponentType::Plugin,
            "loader",
            None,
            "must-use plugin: review by hand",
        );
        assert_eq!(a.summary.not_checked, before + 1);
        let c = a.components.last().unwrap();
        assert_eq!(c.state, ComponentState::NotLookedUp);
        assert!(!c.state.checked());
        assert_eq!(a.summary.components.not_looked_up, 1);
        assert_eq!(a.only(ComponentType::Plugin).summary.not_checked, 5);
    }
}
