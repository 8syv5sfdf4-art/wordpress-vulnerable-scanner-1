//! The steps of a whole-site audit that do not print anything: take the
//! inventory of a WordPress root, turn it into lookups, and write one set of
//! reports per part (core, themes, plugins).
//!
//! The command line wires these together with the database pull and the
//! scan, so each step stays testable on its own.

use std::path::Path;

use crate::aliases::{self, Aliases, MatchedVia};
use crate::analyze::Analysis;
use crate::dojo::{self, DojoConfig, ManifestFile, SkippedPart};
use crate::error::{Error, Result};
use crate::inventory::{self, Inventory, Kind, Layout};
use crate::output::{OutputConfig, OutputFormat, output_analysis};
use crate::report::md_cell;
use crate::scanner::{ComponentInfo, ComponentType};
use crate::vulnerability::Severity;

/// One of the three things an audit reports on
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Part {
    /// WordPress itself
    Core,
    /// Everything in `themes/`
    Themes,
    /// Plugins, plus must-use plugins and drop-ins (reported as not checked)
    Plugins,
}

impl Part {
    /// All parts, in report order
    pub const ALL: [Part; 3] = [Part::Core, Part::Themes, Part::Plugins];

    /// Name used in file names and the manifest
    pub fn name(self) -> &'static str {
        match self {
            Part::Core => "core",
            Part::Themes => "themes",
            Part::Plugins => "plugins",
        }
    }

    /// The component type its components have
    pub fn kind(self) -> ComponentType {
        match self {
            Part::Core => ComponentType::Core,
            Part::Themes => ComponentType::Theme,
            Part::Plugins => ComponentType::Plugin,
        }
    }
}

/// Components to look up for an inventory, and the warnings that go with
/// it: alias entries that cannot work, then what the inventory itself
/// could not resolve. Core is left out when its version is unknown.
pub fn components_of(inv: &Inventory, aliases: &Aliases) -> (Vec<ComponentInfo>, Vec<String>) {
    let mut warnings = aliases.check(inv);
    warnings.extend(inv.warnings.iter().map(|w| format!("inventory: {w}")));

    let mut out = Vec::new();
    if let Some(version) = inv.core.as_ref().and_then(|c| c.version.clone()) {
        out.push(ComponentInfo {
            component_type: ComponentType::Core,
            slug: "wordpress".to_string(),
            version: Some(version),
            installed_as: None,
        });
    }
    for l in aliases::lookups(inv, aliases) {
        out.push(ComponentInfo {
            component_type: match l.kind {
                Kind::Theme => ComponentType::Theme,
                _ => ComponentType::Plugin,
            },
            installed_as: (l.matched_via == MatchedVia::Alias).then_some(l.installed),
            slug: l.slug,
            version: l.version,
        });
    }
    (out, warnings)
}

/// [`components_of`] for an inventory file, directory or archive
pub fn inventory_components(
    path: &Path,
    aliases: Option<&Path>,
) -> Result<(Vec<ComponentInfo>, Vec<String>)> {
    let inv = inventory::load(path)?;
    let aliases = match aliases {
        Some(p) => Aliases::load(p)?,
        None => Aliases::default(),
    };
    Ok(components_of(&inv, &aliases))
}

/// The database records a set of components needs: core by version,
/// everything else by slug. Core without a version needs none.
pub fn pull_items(components: &[ComponentInfo]) -> Vec<(ComponentType, String)> {
    components
        .iter()
        .filter_map(|c| match c.component_type {
            ComponentType::Core => c.version.clone().map(|v| (ComponentType::Core, v)),
            kind => Some((kind, c.slug.clone())),
        })
        .collect()
}

/// What an audit found out about a site before looking anything up
#[derive(Debug)]
pub struct Recon {
    /// Everything installed
    pub inventory: Inventory,
    /// What to look up. Core is always present: with no readable version it
    /// has `version: None`, so the scan reports it as not checked instead of
    /// the audit silently having no core part.
    pub components: Vec<ComponentInfo>,
    /// Problems with the inventory and the aliases (advice as well as
    /// real gaps; see `unreadable` for the ones that make a report
    /// incomplete)
    pub warnings: Vec<String>,
    /// Folders under `wp-content` that exist but could not be listed.
    /// Whatever is installed there is missing from the inventory, so
    /// reports built from it are incomplete.
    pub unreadable: Vec<String>,
}

/// Plugin, theme and mu-plugin folders (and the folders inside them) that
/// exist but cannot be read
fn unreadable_dirs(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for sub in ["plugins", "themes", "mu-plugins"] {
        let dir = root.join("wp-content").join(sub);
        let shown = format!("wp-content/{sub}");
        match std::fs::read_dir(&dir) {
            Ok(entries) => {
                for e in entries.flatten() {
                    let p = e.path();
                    if p.is_dir() && std::fs::read_dir(&p).is_err() {
                        out.push(format!("{shown}/{}", e.file_name().to_string_lossy()));
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => out.push(shown),
        }
    }
    out.sort();
    out
}

/// The site's name for report folders and the DefectDojo product: the
/// directory name of the WordPress root (`public_html` is looked through
/// to its parent, which is the name that means something), made safe for
/// file names
pub fn site_name(root: &Path) -> String {
    let abs = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    // lossy, not skipped: two sites whose folders differ only in non-UTF-8
    // bytes must not end up with the name of their parent
    let mut names = abs
        .components()
        .rev()
        .map(|c| c.as_os_str().to_string_lossy().into_owned());
    let mut name = names.next().unwrap_or_default();
    if abs.is_file() {
        // an archive is named after itself, without its extension
        let lower = name.to_ascii_lowercase();
        for suffix in [".tar.gz", ".tgz", ".tar", ".zip"] {
            if lower.ends_with(suffix) {
                name.truncate(name.len() - suffix.len());
                break;
            }
        }
    } else if matches!(
        name.as_str(),
        "public_html" | "htdocs" | "www" | "html" | "httpdocs"
    ) && let Some(parent) = names.next()
    {
        name = parent;
    }
    let name: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '-'
            }
        })
        .collect();
    if name.trim_matches(['-', '.']).is_empty() {
        "wordpress".to_string()
    } else {
        name
    }
}

/// Today's UTC date as `YYYY-MM-DD`
pub fn today() -> String {
    crate::analyze::chrono_lite_now()
        .split('T')
        .next()
        .unwrap_or_default()
        .to_string()
}

/// `reports/<site>-<UTC date and time>`, so each run has its own folder
pub fn default_out_dir(root: &Path) -> std::path::PathBuf {
    let stamp = crate::analyze::chrono_lite_now()
        .replace(['-', ':'], "")
        .replace('T', "-")
        .replace('Z', "");
    std::path::PathBuf::from("reports").join(format!("{}-{stamp}", site_name(root)))
}

/// Add the components an audit finds but cannot look up to `analysis`:
/// must-use plugins and drop-ins. They are not wordpress.org plugins, so
/// asking a database for a plugin of the same name could match something
/// unrelated; they are listed as not checked for review by hand instead.
fn add_unlooked(analysis: &mut Analysis, inv: &Inventory) {
    for c in &inv.components {
        let what = match c.kind {
            Kind::MuPlugin => "must-use plugin",
            Kind::Dropin => "drop-in",
            _ => continue,
        };
        let file = if c.main_file.is_empty() {
            String::new()
        } else {
            format!(" ({})", c.main_file)
        };
        analysis.add_not_looked_up(
            ComponentType::Plugin,
            &c.slug,
            c.version.as_deref(),
            &format!(
                "{what}{file}: not a wordpress.org plugin, so no vulnerability database is asked \
                 about it by name"
            ),
        );
    }
}

/// Take the inventory of a WordPress root (the `public_html` directory)
pub fn recon(root: &Path, aliases: Option<&Path>) -> Result<Recon> {
    let inventory = inventory::read(root)?;
    if inventory.source.layout != Layout::Wordpress {
        return Err(Error::Inventory(format!(
            "{} is not a WordPress root: wp-includes/version.php was not found. Give the \
             directory that holds wp-config.php and wp-includes (usually public_html), not \
             wp-content or plugins.",
            root.display()
        )));
    }
    let aliases = match aliases {
        Some(p) => Aliases::load(p)?,
        None => Aliases::default(),
    };
    let (mut components, warnings) = components_of(&inventory, &aliases);
    if !components
        .iter()
        .any(|c| c.component_type == ComponentType::Core)
    {
        components.insert(
            0,
            ComponentInfo {
                component_type: ComponentType::Core,
                slug: "wordpress".to_string(),
                version: None,
                installed_as: None,
            },
        );
    }
    let unreadable = unreadable_dirs(root);
    Ok(Recon {
        inventory,
        components,
        warnings,
        unreadable,
    })
}

/// A readable account of what recon found
pub fn recon_markdown(r: &Recon) -> String {
    use std::fmt::Write;
    let inv = &r.inventory;
    let mut s = String::new();
    let _ = writeln!(s, "# Reconnaissance\n");
    let _ = writeln!(s, "- Path: `{}`", inv.source.path);
    let _ = writeln!(s, "- Taken: {}", inv.generated_at);
    let _ = writeln!(
        s,
        "- WordPress core: {}\n",
        inv.core
            .as_ref()
            .and_then(|c| c.version.as_deref())
            .unwrap_or("version could not be read")
    );

    let section = |s: &mut String, title: &str, kinds: &[Kind]| {
        let rows: Vec<_> = inv
            .components
            .iter()
            .filter(|c| kinds.contains(&c.kind))
            .collect();
        let _ = writeln!(s, "## {title} ({})\n", rows.len());
        if rows.is_empty() {
            let _ = writeln!(s, "None found.\n");
            return;
        }
        let _ = writeln!(s, "| Folder | Name | Version | Notes |\n|---|---|---|---|");
        for c in rows {
            let mut notes = Vec::new();
            if let Some(p) = &c.parent {
                notes.push(format!("child of {p}"));
            }
            if let Some(st) = &c.status {
                notes.push(st.clone());
            }
            if c.kind == Kind::Unloaded {
                notes.push("not loaded by WordPress".into());
            }
            if let Some(l) = &c.lookup_slug {
                notes.push(format!("looked up as {l}"));
            }
            let _ = writeln!(
                s,
                "| {} | {} | {} | {} |",
                md_cell(&c.slug),
                md_cell(&c.name),
                md_cell(c.version.as_deref().unwrap_or("unknown")),
                md_cell(&notes.join(", "))
            );
        }
        let _ = writeln!(s);
    };
    section(&mut s, "Themes", &[Kind::Theme]);
    section(&mut s, "Plugins", &[Kind::Plugin, Kind::Unloaded]);
    section(&mut s, "Must-use plugins", &[Kind::MuPlugin]);
    section(&mut s, "Drop-ins", &[Kind::Dropin]);

    if !r.unreadable.is_empty() {
        let _ = writeln!(
            s,
            "## Folders that could not be read ({})\n\nWhatever is installed in these is missing \
             from this inventory.\n",
            r.unreadable.len()
        );
        for d in &r.unreadable {
            let _ = writeln!(s, "- `{d}`");
        }
        let _ = writeln!(s);
    }
    if !r.warnings.is_empty() {
        let _ = writeln!(s, "## Warnings ({})\n", r.warnings.len());
        for (i, w) in r.warnings.iter().enumerate() {
            let _ = writeln!(s, "{}. {}", i + 1, w.replace('\n', " "));
        }
    }
    s
}

/// What was written for one part
#[derive(Debug, Clone)]
pub struct PartResult {
    /// Which part
    pub part: Part,
    /// Components of this part that were looked up
    pub components: usize,
    /// Findings in its DefectDojo file (not-checked Info findings included)
    pub findings: usize,
    /// DefectDojo file name, when one was written
    pub file: Option<String>,
}

/// The outcome of [`write_reports`]
#[derive(Debug)]
pub struct Written {
    /// One entry per part, in report order
    pub parts: Vec<PartResult>,
    /// The analysis the files were written from: recon's warnings and the
    /// not-looked-up components are in it, so summaries and exit codes
    /// computed from it match the files
    pub analysis: Analysis,
    /// Reasons the files may lack findings (empty: complete)
    pub incomplete_because: Vec<String>,
}

/// Write `bytes` to `dir/name` through a temporary file, so a reader never
/// sees a half-written report. Errors name the file.
pub fn put(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let path = dir.join(name);
    let tmp = dir.join(format!("{name}.tmp"));
    // a leftover (or a planted symlink) at the temporary name is removed,
    // never written through
    let _ = std::fs::remove_file(&tmp);
    let write = || -> std::io::Result<()> {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.write_all(bytes)
    };
    write()
        .and_then(|()| std::fs::rename(&tmp, &path))
        .map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            Error::from(std::io::Error::new(
                e.kind(),
                format!("{}: {e}", path.display()),
            ))
        })
}

/// Remove a file left by an earlier run; a missing one is fine
fn remove_old(dir: &Path, name: &str) -> Result<()> {
    match std::fs::remove_file(dir.join(name)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            Err(std::io::Error::new(e.kind(), format!("{}: {e}", dir.join(name).display())).into())
        }
        _ => Ok(()),
    }
}

/// Marker file that says an audit made (and may clear) a folder
const MARKER: &str = ".wpvuln-audit";

/// Create `out` and remove what an earlier audit left in it: the manifest
/// first (so nothing points at files that are about to change), then the
/// per-part and combined reports. Call it before writing anything else into
/// the folder, so a run that fails halfway leaves no stale results next to
/// its new inventory.
pub fn clear_previous(out: &Path) -> Result<()> {
    clear_previous_checked(out, &|_| Ok(()))
}

/// [`clear_previous`], with `check` run on the folder after it exists and
/// before anything is written or removed in it. When `check` refuses and
/// this call created the folder, the folder is removed again.
pub fn clear_previous_checked(out: &Path, check: &dyn Fn(&Path) -> Result<()>) -> Result<()> {
    let named = |e: std::io::Error| {
        Error::from(std::io::Error::new(
            e.kind(),
            format!("{}: {e}", out.display()),
        ))
    };
    // Only ever clear a folder an audit made: some of the names below
    // (report.json, report.csv) are generic and could be someone's files
    let marker = out.join(MARKER);
    let marked = std::fs::symlink_metadata(&marker).is_ok_and(|m| m.is_file());
    if out.is_dir() && !marked {
        let empty = std::fs::read_dir(out).map_err(named)?.next().is_none();
        if !empty {
            return Err(Error::Config(format!(
                "{} already holds files that this tool did not write. Choose an empty or new \
                 folder with --out so nothing of yours is deleted or overwritten.",
                out.display()
            )));
        }
    }
    // the folders this call is about to create, deepest first, so a refusal
    // can take them away again
    let mut created = Vec::new();
    let mut cur = Some(out);
    while let Some(dir) = cur {
        if dir.exists() || dir.as_os_str().is_empty() {
            break;
        }
        created.push(dir.to_path_buf());
        cur = dir.parent();
    }
    std::fs::create_dir_all(out).map_err(named)?;
    if let Err(e) = check(out) {
        for dir in &created {
            let _ = std::fs::remove_dir(dir);
        }
        return Err(e);
    }
    if !marked {
        std::fs::write(
            &marker,
            "Made by wordpress-vulnerable-scanner audit. Its reports are replaced on each run.\n",
        )
        .map_err(named)?;
    }
    let mut names = vec![
        "dojo-manifest.json".to_string(),
        "report.json".to_string(),
        "report.csv".to_string(),
    ];
    for part in Part::ALL {
        names.push(format!("defectdojo-{}.json", part.name()));
        names.push(format!("report-{}.md", part.name()));
    }
    for name in names {
        remove_old(out, &name)?;
        remove_old(out, &format!("{name}.tmp"))?;
    }
    // written by the command around write_reports, same temporary scheme
    for name in ["inventory.json.tmp", "recon.md.tmp"] {
        remove_old(out, name)?;
    }
    Ok(())
}

/// Write the reports of an audit into `out`: per part a DefectDojo file and
/// a Markdown report, plus the whole analysis as JSON and CSV, and the
/// import manifest.
///
/// `analysis` is what the scan returned for `recon.components`. This
/// function adds what the scan does not know about (recon's warnings, and
/// the must-use plugins and drop-ins as not looked up), so that no caller
/// can write reports without them; the finished analysis is returned.
///
/// - A part with no components gets no files and a `skipped` entry in the
///   manifest. An empty DefectDojo file would read as "checked, nothing
///   found" and, on a reimport that closes old findings, close real ones.
/// - Files from an earlier run in `out` are removed first, so nothing stale
///   sits next to a manifest that no longer lists it, and the manifest is
///   written last.
/// - The DefectDojo files always carry every severity. `min` filters only
///   the human-readable Markdown and CSV; filtering the import would make a
///   vulnerable component look clean and let a reimport close its findings.
/// - `sources_key` names the sources the findings came from
///   (`wordfence-api+wpvulnerability`); without it the analysis's own source
///   names are used. It goes into every test title, so runs with different
///   sources never share a DefectDojo test.
/// - A file is `complete: false` in the manifest when a component of its
///   part was not compared with any data (lookup failed, never pulled,
///   version unknown), or when one of several sources had no answer for it
///   (findings only that source knows are absent). Only a not-checked Info
///   finding stands in for the first kind. The whole manifest is incomplete
///   when a folder could not be read, and `extra_incomplete` adds reasons
///   only the caller knows (a source that was expected but not loaded).
pub fn write_reports(
    analysis: &Analysis,
    recon: &Recon,
    out: &Path,
    min: Severity,
    dojo_cfg: &DojoConfig,
    sources_key: Option<&str>,
    extra_incomplete: &[String],
) -> Result<Written> {
    let mut analysis = analysis.clone();
    for w in &recon.warnings {
        if !analysis.warnings.contains(w) {
            analysis.warnings.push(w.clone());
        }
    }
    add_unlooked(&mut analysis, &recon.inventory);
    let analysis = &analysis;

    clear_previous(out)?;
    let render = |a: &Analysis, format: OutputFormat, min: Severity| -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        output_analysis(a, &OutputConfig::new(format, min), &mut buf)?;
        Ok(buf)
    };

    let sources_key = match sources_key {
        Some(k) => k.to_string(),
        None => {
            let mut names: Vec<String> = analysis
                .sources
                .iter()
                .map(|s| crate::analyze::source_name(s.source).to_ascii_lowercase())
                .collect();
            names.sort();
            names.dedup();
            names.join("+")
        }
    };
    let mut incomplete_because: Vec<String> = recon
        .unreadable
        .iter()
        .map(|d| format!("{d} could not be read, so what is installed there is not in the reports"))
        .collect();
    incomplete_because.extend(extra_incomplete.iter().cloned());
    let mut parts = Vec::new();
    let mut files = Vec::new();
    let mut skipped = Vec::new();
    for part in Part::ALL {
        let a = analysis.only(part.kind());
        if a.components.is_empty() {
            skipped.push(SkippedPart {
                part: part.name().to_string(),
                reason: if recon.unreadable.is_empty() {
                    format!(
                        "no {} were inventoried, so there is nothing to report or to close in \
                         DefectDojo",
                        part.name()
                    )
                } else {
                    format!(
                        "nothing was inventoried for {}, but {} folder(s) could not be read: \
                         this may be an unreadable folder, not an empty site",
                        part.name(),
                        recon.unreadable.len()
                    )
                },
            });
            parts.push(PartResult {
                part,
                components: 0,
                findings: 0,
                file: None,
            });
            continue;
        }

        let json = render(&a, OutputFormat::DefectDojo, Severity::Low)?;
        let findings = serde_json::from_slice::<serde_json::Value>(&json)?["findings"]
            .as_array()
            .map(Vec::len)
            .ok_or_else(|| {
                Error::InvalidOutputFormat("the DefectDojo report has no findings list".into())
            })?;
        let file = format!("defectdojo-{}.json", part.name());
        put(out, &file, &json)?;
        put(
            out,
            &format!("report-{}.md", part.name()),
            &render(&a, OutputFormat::Markdown, min)?,
        )?;

        let c = &a.summary.components;
        let mut why = Vec::new();
        for (n, what) in [
            (c.failed, "lookup failed"),
            (c.not_in_db, "not in the local database"),
            (c.unknown_version, "version unknown"),
        ] {
            if n > 0 {
                why.push(format!(
                    "{n} {} component(s): {what}, so their findings are not in {file}",
                    part.name()
                ));
            }
        }
        // With several sources a component can be "checked" by one while
        // the other failed: what only the failed one knows is missing
        let gaps = a
            .components
            .iter()
            .filter(|c| {
                c.coverage.len() > 1
                    && c.coverage.values().any(|v| {
                        matches!(
                            v,
                            crate::analyze::Coverage::Failed | crate::analyze::Coverage::NotInDb
                        )
                    })
            })
            .count();
        if gaps > 0 {
            why.push(format!(
                "{gaps} {} component(s): one data source had no answer (lookup failed or not \
                 pulled), so findings only that source knows are not in {file}",
                part.name()
            ));
        }
        incomplete_because.extend(why.iter().cloned());
        let mut file_reasons = why;
        file_reasons.extend(
            recon
                .unreadable
                .iter()
                .map(|d| format!("{d} could not be read")),
        );
        file_reasons.extend(extra_incomplete.iter().cloned());
        files.push(ManifestFile {
            part: part.name().to_string(),
            file: file.clone(),
            test_title: dojo_cfg.test_title(part.name(), &sources_key),
            findings,
            complete: file_reasons.is_empty(),
            incomplete_because: file_reasons,
        });
        parts.push(PartResult {
            part,
            components: a.components.len(),
            findings,
            file: Some(file),
        });
    }

    put(
        out,
        "report.json",
        &render(analysis, OutputFormat::Json, min)?,
    )?;
    put(
        out,
        "report.csv",
        &render(analysis, OutputFormat::Csv, min)?,
    )?;
    let manifest = dojo::manifest(
        dojo_cfg,
        &analysis.scan_date,
        files,
        skipped,
        &recon.warnings,
        &incomplete_because,
        &analysis
            .sources
            .iter()
            .map(|s| format!("{}: {}", crate::analyze::source_name(s.source), s.detail))
            .collect::<Vec<_>>(),
    );
    put(
        out,
        "dojo-manifest.json",
        &serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok(Written {
        parts,
        analysis: analysis.clone(),
        incomplete_because,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::{ComponentState, ComponentVulnerabilities};
    use std::path::PathBuf;

    fn fixture() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wp")
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("wvs-pipeline-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A WordPress root with the given pieces
    struct Site {
        root: PathBuf,
    }

    impl Site {
        fn new(name: &str, core: Option<&str>) -> Site {
            let root = temp_dir(name);
            std::fs::create_dir_all(root.join("wp-includes")).unwrap();
            std::fs::create_dir_all(root.join("wp-content")).unwrap();
            let php = match core {
                Some(v) => format!("<?php\n$wp_version = '{v}';\n"),
                None => "<?php\n".to_string(),
            };
            std::fs::write(root.join("wp-includes/version.php"), php).unwrap();
            Site { root }
        }

        fn write(&self, rel: &str, text: &str) -> &Self {
            let p = self.root.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
            self
        }

        fn plugin(&self, slug: &str, version: &str) -> &Self {
            self.write(
                &format!("wp-content/plugins/{slug}/{slug}.php"),
                &format!("<?php\n/*\nPlugin Name: {slug}\nVersion: {version}\n*/\n"),
            )
        }

        fn theme(&self, slug: &str, version: &str) -> &Self {
            self.write(
                &format!("wp-content/themes/{slug}/style.css"),
                &format!("/*\nTheme Name: {slug}\nVersion: {version}\n*/\n"),
            )
        }

        fn mu_plugin(&self, file: &str) -> &Self {
            self.write(
                &format!("wp-content/mu-plugins/{file}"),
                "<?php\n/*\nPlugin Name: MU\nVersion: 1.0\n*/\n",
            )
        }
    }

    impl Drop for Site {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    /// An analysis in which nothing was pulled, so every looked-up
    /// component is not in the database
    async fn unpulled(r: &Recon, db: &Path) -> Analysis {
        let analyzer =
            crate::Analyzer::with_source(crate::Source::Local(db.to_path_buf())).unwrap();
        analyzer
            .analyze(&crate::ScanResult::from_components(r.components.clone()))
            .await
    }

    fn cfg() -> DojoConfig {
        DojoConfig::from_lookup(|_| None, "site", "2026-10-11").unwrap()
    }

    fn json(p: &Path) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
    }

    fn findings(p: &Path) -> Vec<serde_json::Value> {
        json(p)["findings"].as_array().unwrap().clone()
    }

    fn tags(f: &serde_json::Value) -> Vec<String> {
        f["tags"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_str().unwrap().to_string())
            .collect()
    }

    /// An analysis in which one plugin is vulnerable with a Low finding
    fn vulnerable_plugin(r: &Recon) -> Analysis {
        let v: crate::Vulnerability = serde_json::from_value(serde_json::json!({
            "id": "x", "title": "a low issue", "severity": "low", "cvss_score": null,
            "affected_max": null, "fixed_in": null, "references": [], "uuid": "u-low"
        }))
        .unwrap();
        let mut components: Vec<ComponentVulnerabilities> = r
            .components
            .iter()
            .map(|c| ComponentVulnerabilities {
                component_type: c.component_type,
                slug: c.slug.clone(),
                version: c.version.clone(),
                max_severity: None,
                vulnerabilities: Vec::new(),
                state: ComponentState::Clean,
                matched_via: MatchedVia::Slug,
                installed_as: None,
                note: None,
                suggested_alias: None,
                coverage: Default::default(),
            })
            .collect();
        let p = components
            .iter_mut()
            .find(|c| c.component_type == ComponentType::Plugin)
            .unwrap();
        p.vulnerabilities = vec![v];
        p.max_severity = Some(Severity::Low);
        p.state = ComponentState::Vulnerable;
        Analysis {
            url: None,
            scan_date: "2026-10-11T00:00:00Z".into(),
            summary: Default::default(),
            components,
            warnings: Vec::new(),
            sources: Vec::new(),
        }
    }

    #[test]
    fn recon_reads_core_themes_and_plugins() {
        let r = recon(&fixture(), None).unwrap();
        let core = r
            .components
            .iter()
            .find(|c| c.component_type == ComponentType::Core)
            .unwrap();
        assert!(core.version.is_some());
        for kind in [ComponentType::Theme, ComponentType::Plugin] {
            assert!(r.components.iter().any(|c| c.component_type == kind));
        }
        let md = recon_markdown(&r);
        assert!(md.contains("## Themes") && md.contains("## Plugins"));
        assert!(md.contains("storefront"));
    }

    #[test]
    fn recon_refuses_something_that_is_not_a_wordpress_root() {
        let e = recon(&fixture().join("wp-content/plugins"), None)
            .unwrap_err()
            .to_string();
        assert!(e.contains("not a WordPress root"), "{e}");
    }

    #[test]
    fn pull_items_key_core_by_version() {
        let c = |t, slug: &str, v: Option<&str>| ComponentInfo {
            component_type: t,
            slug: slug.into(),
            version: v.map(Into::into),
            installed_as: None,
        };
        let items = pull_items(&[
            c(ComponentType::Core, "wordpress", Some("6.4.3")),
            c(ComponentType::Core, "wordpress", None),
            c(ComponentType::Theme, "astra", Some("1.0")),
            c(ComponentType::Plugin, "akismet", None),
        ]);
        assert_eq!(
            items,
            vec![
                (ComponentType::Core, "6.4.3".to_string()),
                (ComponentType::Theme, "astra".to_string()),
                (ComponentType::Plugin, "akismet".to_string()),
            ]
        );
    }

    #[test]
    fn site_name_looks_through_public_html_and_is_file_safe() {
        let d = temp_dir("names");
        let site = d.join("my shop.example").join("public_html");
        std::fs::create_dir_all(&site).unwrap();
        assert_eq!(site_name(&site), "my-shop.example");
        let plain = d.join("blog");
        std::fs::create_dir_all(&plain).unwrap();
        assert_eq!(site_name(&plain), "blog");
        let out = default_out_dir(&plain);
        let name = out.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with("blog-20"), "{name}");
        assert!(!name.contains(':') && !name.contains('T'), "{name}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn markdown_cells_in_recon_are_escaped() {
        let site = Site::new("pipe", Some("6.4.3"));
        site.write(
            "wp-content/plugins/odd/odd.php",
            "<?php\n/*\nPlugin Name: A|B\nVersion: 1|2\n*/\n",
        );
        let md = recon_markdown(&recon(&site.root, None).unwrap());
        assert!(md.contains("A\\|B") && md.contains("1\\|2"), "{md}");
    }

    #[tokio::test]
    async fn unreadable_core_version_is_a_not_checked_core_finding() {
        let site = Site::new("nover", None);
        site.plugin("akismet", "5.0");
        let r = recon(&site.root, None).unwrap();
        let core: Vec<_> = r
            .components
            .iter()
            .filter(|c| c.component_type == ComponentType::Core)
            .collect();
        assert_eq!((core.len(), core[0].version.as_deref()), (1, None));
        assert!(
            pull_items(&r.components)
                .iter()
                .all(|(k, _)| *k != ComponentType::Core)
        );

        let out = temp_dir("nover-out");
        let a = unpulled(&r, &out.join("no-db")).await;
        let w = write_reports(&a, &r, &out, Severity::Low, &cfg(), None, &[]).unwrap();
        let core_state = w
            .analysis
            .components
            .iter()
            .find(|c| c.component_type == ComponentType::Core)
            .unwrap()
            .state;
        assert_eq!(core_state, ComponentState::UnknownVersion);
        let f = findings(&out.join("defectdojo-core.json"));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0]["severity"], "Info");
        assert!(tags(&f[0]).contains(&"not-checked".to_string()), "{f:?}");
        let _ = std::fs::remove_dir_all(&out);
    }

    #[tokio::test]
    async fn one_report_set_per_part_with_only_its_own_findings() {
        let out = temp_dir("all");
        let r = recon(&fixture(), None).unwrap();
        let a = unpulled(&r, &out.join("no-db")).await;
        let w = write_reports(&a, &r, &out, Severity::Low, &cfg(), None, &[]).unwrap();
        assert_eq!(w.parts.len(), 3);

        for (part, own) in [("core", "core"), ("themes", "theme"), ("plugins", "plugin")] {
            let f = findings(&out.join(format!("defectdojo-{part}.json")));
            assert!(!f.is_empty(), "{part}");
            for finding in &f {
                let t = tags(finding);
                assert!(t.contains(&own.to_string()), "{part}: {t:?}");
                for other in ["core", "theme", "plugin"].iter().filter(|o| **o != own) {
                    assert!(!t.contains(&other.to_string()), "{part}: {t:?}");
                }
            }
            assert!(out.join(format!("report-{part}.md")).is_file());
        }
        for f in ["report.json", "report.csv", "dojo-manifest.json"] {
            assert!(out.join(f).is_file(), "{f}");
        }
        let m = json(&out.join("dojo-manifest.json"));
        assert_eq!(m["files"].as_array().unwrap().len(), 3);
        // nothing was pulled: the manifest must say the files lack findings
        assert_eq!(m["complete"], false);
        assert!(
            m["incomplete_because"]
                .to_string()
                .contains("not in the local database"),
            "{m}"
        );
        let _ = std::fs::remove_dir_all(&out);
    }

    #[tokio::test]
    async fn a_part_with_nothing_inventoried_is_skipped_not_written_empty() {
        let site = Site::new("noth", Some("6.4.3"));
        site.plugin("akismet", "5.0");
        let r = recon(&site.root, None).unwrap();
        let out = temp_dir("noth-out");
        let a = unpulled(&r, &out.join("no-db")).await;
        write_reports(&a, &r, &out, Severity::Low, &cfg(), None, &[]).unwrap();

        assert!(out.join("defectdojo-plugins.json").is_file());
        for absent in ["defectdojo-themes.json", "report-themes.md"] {
            assert!(!out.join(absent).exists(), "{absent}");
        }
        let m = json(&out.join("dojo-manifest.json"));
        let skipped = m["skipped"].as_array().unwrap();
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0]["part"], "themes");
        assert!(
            skipped[0]["reason"]
                .as_str()
                .unwrap()
                .contains("no themes were inventoried"),
            "{skipped:?}"
        );
        let _ = std::fs::remove_dir_all(&out);
    }

    #[test]
    fn severity_filter_never_hides_findings_from_defectdojo() {
        let site = Site::new("sev", Some("6.4.3"));
        site.plugin("akismet", "3.3");
        let r = recon(&site.root, None).unwrap();
        let out = temp_dir("sev-out");
        let a = vulnerable_plugin(&r);
        let w = write_reports(&a, &r, &out, Severity::High, &cfg(), None, &[]).unwrap();

        let f = findings(&out.join("defectdojo-plugins.json"));
        assert_eq!(f.len(), 1);
        assert!(f[0]["title"].as_str().unwrap().contains("a low issue"));
        let plugins = w.parts.iter().find(|p| p.part == Part::Plugins).unwrap();
        assert_eq!(plugins.findings, 1);
        let md = std::fs::read_to_string(out.join("report-plugins.md")).unwrap();
        assert!(md.contains("## Findings"), "{md}");
        assert!(!md.contains("a low issue"), "{md}");
        // a complete, fully looked-up site is complete
        let m = json(&out.join("dojo-manifest.json"));
        assert_eq!(m["complete"], true, "{m}");
        let _ = std::fs::remove_dir_all(&out);
    }

    #[tokio::test]
    async fn rerunning_into_a_directory_leaves_no_stale_files() {
        let site = Site::new("stale", Some("6.4.3"));
        site.plugin("akismet", "5.0").theme("astra", "1.0");
        let out = temp_dir("stale-out");
        let r = recon(&site.root, None).unwrap();
        let a = unpulled(&r, &out.join("no-db")).await;
        write_reports(&a, &r, &out, Severity::Low, &cfg(), None, &[]).unwrap();
        assert!(out.join("defectdojo-themes.json").is_file());
        assert!(out.join("report-themes.md").is_file());
        std::fs::write(out.join("report.json.tmp"), "leftover").unwrap();

        std::fs::remove_dir_all(site.root.join("wp-content/themes")).unwrap();
        let r = recon(&site.root, None).unwrap();
        let a = unpulled(&r, &out.join("no-db")).await;
        write_reports(&a, &r, &out, Severity::Low, &cfg(), None, &[]).unwrap();
        for stale in [
            "defectdojo-themes.json",
            "report-themes.md",
            "report.json.tmp",
        ] {
            assert!(!out.join(stale).exists(), "{stale} is stale");
        }
        let m = json(&out.join("dojo-manifest.json"));
        let listed: Vec<_> = m["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["part"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(listed, ["core", "plugins"]);
        let _ = std::fs::remove_dir_all(&out);
    }

    #[tokio::test]
    async fn mu_plugins_and_dropins_are_not_checked_findings_and_never_looked_up() {
        let site = Site::new("mu", Some("6.4.3"));
        site.mu_plugin("evil.php")
            .write("wp-content/object-cache.php", "<?php\n// Drop-in\n");
        let r = recon(&site.root, None).unwrap();
        for c in &r.components {
            assert!(
                c.slug != "evil" && c.slug != "object-cache",
                "{} would be looked up by name",
                c.slug
            );
        }
        let out = temp_dir("mu-out");
        let a = unpulled(&r, &out.join("no-db")).await;
        let w = write_reports(&a, &r, &out, Severity::Low, &cfg(), None, &[]).unwrap();

        let f = findings(&out.join("defectdojo-plugins.json"));
        for name in ["evil", "object-cache"] {
            let hit = f
                .iter()
                .find(|x| x["component_name"] == name)
                .unwrap_or_else(|| panic!("{name} missing from {f:?}"));
            assert_eq!(hit["severity"], "Info");
            let t = tags(hit);
            assert!(t.contains(&"not-checked".into()) && t.contains(&"not-looked-up".into()));
            assert!(
                hit["description"]
                    .as_str()
                    .unwrap()
                    .contains("Review it by hand")
                    || hit["description"]
                        .as_str()
                        .unwrap()
                        .contains("review it by hand"),
                "{hit}"
            );
            assert!(
                !hit["description"].as_str().unwrap().contains(".."),
                "{hit}"
            );
        }
        assert!(w.analysis.summary.components.not_looked_up >= 2);
        // the Markdown summary table adds up to the "not checked" count
        let md = std::fs::read_to_string(out.join("report-plugins.md")).unwrap();
        assert!(md.contains("never looked up"), "{md}");
        let m = json(&out.join("dojo-manifest.json"));
        assert!(m["files"].to_string().contains("defectdojo-plugins.json"));
        assert_eq!(m["skipped"].as_array().unwrap().len(), 1); // themes only
        let _ = std::fs::remove_dir_all(&out);
    }

    #[tokio::test]
    async fn a_site_with_only_mu_plugins_still_has_a_plugins_part() {
        let site = Site::new("mu-only", Some("6.4.3"));
        site.mu_plugin("evil.php");
        let r = recon(&site.root, None).unwrap();
        let out = temp_dir("mu-only-out");
        let a = unpulled(&r, &out.join("no-db")).await;
        write_reports(&a, &r, &out, Severity::Low, &cfg(), None, &[]).unwrap();
        let f = findings(&out.join("defectdojo-plugins.json"));
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0]["component_name"], "evil");
        let m = json(&out.join("dojo-manifest.json"));
        let parts: Vec<_> = m["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["part"].as_str().unwrap().to_string())
            .collect();
        assert!(parts.contains(&"plugins".to_string()), "{m}");
        let _ = std::fs::remove_dir_all(&out);
    }

    #[tokio::test]
    async fn recon_warnings_reach_every_file_without_the_caller_doing_anything() {
        let site = Site::new("warn", Some("6.4.3"));
        site.plugin("akismet", "5.0");
        site.write("wp-content/plugins/noheader/noheader.php", "<?php\n");
        let r = recon(&site.root, None).unwrap();
        assert!(!r.warnings.is_empty());
        let out = temp_dir("warn-out");
        // an analysis straight from the analyzer: its warnings are empty
        let a = unpulled(&r, &out.join("no-db")).await;
        assert!(a.warnings.is_empty());
        let w = write_reports(&a, &r, &out, Severity::Low, &cfg(), None, &[]).unwrap();
        assert_eq!(w.analysis.warnings.len(), r.warnings.len());

        let first = &r.warnings[0];
        let desc = json(&out.join("defectdojo-plugins.json"))["description"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(desc.contains(first.as_str()), "{desc}");
        let md = std::fs::read_to_string(out.join("report-plugins.md")).unwrap();
        assert!(md.contains(first.as_str()), "{md}");
        let m = json(&out.join("dojo-manifest.json"));
        assert_eq!(m["inventory_warnings"][0], first.as_str());
        let _ = std::fs::remove_dir_all(&out);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn an_unreadable_folder_makes_the_manifest_incomplete() {
        use std::os::unix::fs::PermissionsExt;
        let site = Site::new("unread", Some("6.4.3"));
        site.plugin("akismet", "5.0").theme("astra", "1.0");
        let themes = site.root.join("wp-content/themes");
        std::fs::set_permissions(&themes, std::fs::Permissions::from_mode(0o000)).unwrap();
        // running as root reads it anyway; nothing to test then
        if std::fs::read_dir(&themes).is_ok() {
            std::fs::set_permissions(&themes, std::fs::Permissions::from_mode(0o755)).unwrap();
            return;
        }
        let r = recon(&site.root, None).unwrap();
        std::fs::set_permissions(&themes, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(r.unreadable, vec!["wp-content/themes".to_string()]);

        let out = temp_dir("unread-out");
        let a = unpulled(&r, &out.join("no-db")).await;
        let w = write_reports(&a, &r, &out, Severity::Low, &cfg(), None, &[]).unwrap();
        assert!(
            w.incomplete_because
                .iter()
                .any(|x| x.contains("wp-content/themes"))
        );
        let m = json(&out.join("dojo-manifest.json"));
        assert_eq!(m["complete"], false);
        let themes_skip = &m["skipped"][0];
        assert_eq!(themes_skip["part"], "themes");
        assert!(
            themes_skip["reason"]
                .as_str()
                .unwrap()
                .contains("could not be read"),
            "{themes_skip}"
        );
        assert!(recon_markdown(&r).contains("could not be read"));
        let _ = std::fs::remove_dir_all(&out);
    }

    #[test]
    fn a_failed_source_makes_that_file_incomplete_even_if_another_source_answered() {
        use crate::analyze::Coverage;
        use crate::vulnerability::SourceKind;
        let site = Site::new("gap", Some("6.4.3"));
        site.plugin("akismet", "5.0").plugin("other", "1.0");
        let r = recon(&site.root, None).unwrap();
        let mut a = vulnerable_plugin(&r);
        for c in a.components.iter_mut().filter(|c| c.slug == "akismet") {
            c.coverage = [
                (SourceKind::WpVulnerability, Coverage::Failed),
                (SourceKind::Wordfence, Coverage::Tracked),
            ]
            .into_iter()
            .collect();
        }
        let out = temp_dir("gap-out");
        let w = write_reports(&a, &r, &out, Severity::Low, &cfg(), None, &[]).unwrap();
        let m = json(&out.join("dojo-manifest.json"));
        let by_part = |part: &str| {
            m["files"]
                .as_array()
                .unwrap()
                .iter()
                .find(|f| f["part"] == part)
                .unwrap()
                .clone()
        };
        assert_eq!(by_part("plugins")["complete"], false, "{m}");
        assert!(
            by_part("plugins")["incomplete_because"]
                .to_string()
                .contains("one data source had no answer")
        );
        assert_eq!(by_part("core")["complete"], true, "{m}");
        assert_eq!(m["complete"], false);
        assert!(!w.incomplete_because.is_empty());
        let _ = std::fs::remove_dir_all(&out);
    }

    #[test]
    fn reasons_from_the_caller_make_every_file_incomplete() {
        let site = Site::new("extra", Some("6.4.3"));
        site.plugin("akismet", "5.0");
        let r = recon(&site.root, None).unwrap();
        let a = vulnerable_plugin(&r);
        let out = temp_dir("extra-out");
        let why = vec!["Wordfence was enabled but no feed is stored".to_string()];
        write_reports(&a, &r, &out, Severity::Low, &cfg(), None, &why).unwrap();
        let m = json(&out.join("dojo-manifest.json"));
        assert_eq!(m["complete"], false);
        for f in m["files"].as_array().unwrap() {
            assert_eq!(f["complete"], false, "{f}");
            assert_eq!(f["incomplete_because"][0], why[0].as_str());
        }
        let _ = std::fs::remove_dir_all(&out);
    }

    #[test]
    fn site_name_of_an_archive_is_the_site_not_the_file() {
        let d = temp_dir("arch");
        for (file, want) in [
            ("shop.tar.gz", "shop"),
            ("shop.tgz", "shop"),
            ("shop.zip", "shop"),
        ] {
            let f = d.join(file);
            std::fs::write(&f, "").unwrap();
            assert_eq!(site_name(&f), want);
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn clear_previous_removes_old_results_and_names_the_folder_on_error() {
        let out = temp_dir("clear");
        std::fs::write(out.join(MARKER), "").unwrap();
        for f in [
            "dojo-manifest.json",
            "defectdojo-core.json",
            "report-themes.md",
            "report.csv",
        ] {
            std::fs::write(out.join(f), "old").unwrap();
        }
        std::fs::write(out.join("inventory.json"), "keep").unwrap();
        clear_previous(&out).unwrap();
        assert!(!out.join("dojo-manifest.json").exists());
        assert!(!out.join("defectdojo-core.json").exists());
        assert!(!out.join("report-themes.md").exists());
        assert!(out.join("inventory.json").exists(), "only report files go");

        let file = out.join("inventory.json");
        let e = clear_previous(&file).unwrap_err().to_string();
        assert!(e.contains("inventory.json"), "{e}");
        let _ = std::fs::remove_dir_all(&out);
    }

    #[test]
    fn test_title_names_the_sources_so_runs_with_fewer_never_share_a_test() {
        let site = Site::new("title", Some("6.4.3"));
        site.plugin("akismet", "5.0");
        let r = recon(&site.root, None).unwrap();
        let mut a = vulnerable_plugin(&r);
        a.sources = vec![
            crate::analyze::SourceInfo {
                source: crate::vulnerability::SourceKind::Wordfence,
                detail: "feed".into(),
                attribution: None,
            },
            crate::analyze::SourceInfo {
                source: crate::vulnerability::SourceKind::WpVulnerability,
                detail: "db".into(),
                attribution: None,
            },
        ];
        let out = temp_dir("title-out");
        write_reports(&a, &r, &out, Severity::Low, &cfg(), None, &[]).unwrap();
        let m = json(&out.join("dojo-manifest.json"));
        assert_eq!(
            m["files"][0]["test_title"],
            "site WordPress core (wordfence+wpvulnerability)"
        );
        a.sources.truncate(1);
        a.sources[0].source = crate::vulnerability::SourceKind::WpVulnerability;
        write_reports(&a, &r, &out, Severity::Low, &cfg(), None, &[]).unwrap();
        let m = json(&out.join("dojo-manifest.json"));
        assert_eq!(
            m["files"][0]["test_title"],
            "site WordPress core (wpvulnerability)"
        );
        let _ = std::fs::remove_dir_all(&out);
    }

    #[test]
    fn a_folder_with_foreign_files_is_never_cleared_or_written_into() {
        let out = temp_dir("foreign");
        std::fs::write(out.join("report.csv"), "my own data").unwrap();
        let e = clear_previous(&out).unwrap_err().to_string();
        assert!(e.contains("did not write"), "{e}");
        assert_eq!(
            std::fs::read_to_string(out.join("report.csv")).unwrap(),
            "my own data"
        );
        assert!(!out.join(MARKER).exists());

        // an empty folder is fine, and then recognised as ours
        let fresh = temp_dir("foreign-fresh");
        clear_previous(&fresh).unwrap();
        assert!(fresh.join(MARKER).is_file());
        std::fs::write(fresh.join("report.csv"), "ours").unwrap();
        clear_previous(&fresh).unwrap();
        assert!(!fresh.join("report.csv").exists());
        let _ = std::fs::remove_dir_all(&out);
        let _ = std::fs::remove_dir_all(&fresh);
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_folder_names_do_not_become_the_parents_name() {
        use std::os::unix::ffi::OsStrExt;
        let d = temp_dir("nonutf8");
        let odd = d.join(std::ffi::OsStr::from_bytes(b"caf\xe9-a"));
        std::fs::create_dir_all(&odd).unwrap();
        let name = site_name(&odd);
        assert!(name.starts_with("caf"), "{name}");
        assert_ne!(name, site_name(&d));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn archive_names_are_case_insensitive_and_not_looked_through() {
        let d = temp_dir("arch2");
        let f = d.join("SHOP.ZIP");
        std::fs::write(&f, "").unwrap();
        assert_eq!(site_name(&f), "SHOP");
        let g = d.join("public_html.tar.gz");
        std::fs::write(&g, "").unwrap();
        assert_eq!(site_name(&g), "public_html");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_failed_lookup_in_a_single_source_run_is_reported_once() {
        use crate::analyze::ComponentState;
        let site = Site::new("single", Some("6.4.3"));
        site.plugin("akismet", "5.0");
        let r = recon(&site.root, None).unwrap();
        let mut a = vulnerable_plugin(&r);
        for c in a.components.iter_mut().filter(|c| c.slug == "akismet") {
            c.state = ComponentState::Failed;
            c.vulnerabilities.clear();
            c.coverage = Default::default();
        }
        let out = temp_dir("single-out");
        let w = write_reports(&a, &r, &out, Severity::Low, &cfg(), None, &[]).unwrap();
        assert_eq!(w.incomplete_because.len(), 1, "{:?}", w.incomplete_because);
        assert!(w.incomplete_because[0].contains("lookup failed"));
        let _ = std::fs::remove_dir_all(&out);
    }

    #[test]
    fn a_marker_that_is_a_directory_does_not_make_a_folder_ours() {
        let out = temp_dir("fakemarker");
        std::fs::create_dir_all(out.join(MARKER)).unwrap();
        std::fs::write(out.join("report.csv"), "mine").unwrap();
        assert!(clear_previous(&out).is_err());
        assert_eq!(
            std::fs::read_to_string(out.join("report.csv")).unwrap(),
            "mine"
        );
        let _ = std::fs::remove_dir_all(&out);
    }

    #[test]
    fn a_refused_new_folder_is_removed_again_with_the_parents_it_created() {
        let parent = temp_dir("refused");
        let out = parent.join("a/b/reports");
        let e = clear_previous_checked(&out, &|_| Err(Error::Config("no".into())));
        assert!(e.is_err());
        assert!(!out.exists(), "a folder this call created must not stay");
        assert!(!parent.join("a").exists(), "nor the parents it created");
        assert!(parent.exists(), "but the existing folder stays");
        let _ = std::fs::remove_dir_all(&parent);
    }
}
