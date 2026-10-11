//! WordPress Vulnerable Scanner CLI

use clap::{Args as ClapArgs, Parser, Subcommand, ValueEnum};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use wordpress_vulnerable_scanner::{
    Analyzer, Severity, Source,
    aliases::Aliases,
    changes::{Change, ChangeKind},
    db::{self, PullEvent, PullOptions, PullStatus},
    inventory::{self, Kind},
    output::{OutputConfig, OutputFormat, output_analysis, wrap},
    pipeline::{inventory_components, pull_items},
    scanner::{
        ComponentInfo, ComponentType, ScanResult, Scanner, parse_component, parse_component_list,
    },
    vulnerability::WPVULN_API,
    wordfence::{self, Keep, WordfenceIndex},
    wordfence_db,
};

/// WordPress vulnerability scanner - detects known CVEs in core, plugins, and themes
#[derive(Parser, Debug)]
#[command(name = "wordpress-vulnerable-scanner")]
#[command(version, about, long_about = None)]
#[command(args_conflicts_with_subcommands = true)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    #[command(flatten)]
    scan: ScanArgs,
}

/// Everything a scan takes; the same flags work with and without `scan`
#[derive(ClapArgs, Debug)]
struct ScanArgs {
    /// URL of the WordPress site to scan
    url: Option<String>,

    #[command(flatten)]
    inputs: Inputs,

    /// Read vulnerability data from a local database (see `db pull`) instead of the API
    #[arg(long, env = "WPVULN_DB", value_name = "DIR")]
    db: Option<PathBuf>,

    /// WPVulnerability API base URL (for mirrors)
    #[arg(long, env = "WPVULN_API", value_name = "URL", default_value = WPVULN_API)]
    api_url: String,

    /// Output format
    #[arg(short = 'o', long = "output", default_value = "human", value_enum)]
    output_format: OutputFormatArg,

    /// Minimum severity level to report
    #[arg(long = "severity", default_value = "low", value_enum)]
    min_severity: SeverityArg,

    /// Exit non-zero only for vulnerabilities at or above this severity
    /// (none: never); without it, any vulnerability exits 1 and critical 2
    #[arg(long, value_enum, value_name = "SEVERITY")]
    fail_on: Option<FailOn>,

    /// Also exit 1 when any component could not be checked
    #[arg(long)]
    fail_on_unchecked: bool,

    /// Wordfence feed to use: a file, or `auto` for <db>/wordfence/wordfence.json.
    /// With --db both sources are combined; without it only Wordfence is used,
    /// with no network access
    #[arg(long, env = "WPVULN_WORDFENCE", value_name = "FILE|auto")]
    wordfence: Option<String>,

    /// Report Wordfence's informational records too (as low, marked)
    #[arg(long)]
    include_informational: bool,
}

/// Threshold for `--fail-on`
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum FailOn {
    None,
    Low,
    Medium,
    High,
    Critical,
}

/// Component inputs shared by scanning and `db pull`
#[derive(ClapArgs, Debug, Clone, Default)]
struct Inputs {
    /// Plugins to check (slug:version,slug:version,...)
    #[arg(long, short = 'p')]
    plugins: Option<String>,

    /// File with one plugin per line (slug:version; `wp plugin list --format=csv` also works)
    #[arg(long, value_name = "FILE")]
    plugins_file: Option<PathBuf>,

    /// Themes to check (slug:version,slug:version,...)
    #[arg(long, short = 't')]
    themes: Option<String>,

    /// File with one theme per line (slug:version)
    #[arg(long, value_name = "FILE")]
    themes_file: Option<PathBuf>,

    /// WordPress core version to check
    #[arg(long, short = 'c')]
    core: Option<String>,

    /// JSON manifest file (output from wordpress-audit)
    #[arg(long, short = 'm')]
    manifest: Option<PathBuf>,

    /// Inventory to check: inventory.json, or a directory or archive to inventory
    #[arg(long, value_name = "PATH")]
    inventory: Option<PathBuf>,

    /// Aliases file mapping inventory folder names to wordpress.org slugs
    #[arg(
        long,
        env = "WPVULN_ALIASES",
        value_name = "FILE",
        requires = "inventory"
    )]
    aliases: Option<PathBuf>,
}

// Parsed once per run, so the size difference between variants is irrelevant
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand, Debug)]
enum Command {
    /// Check components for known vulnerabilities (the default when no
    /// subcommand is given)
    Scan(ScanArgs),
    /// Manage a local vulnerability database for offline scans
    #[command(subcommand)]
    Db(DbCommand),
    /// List installed core, plugins and themes from files (no network, no PHP)
    Inventory(InventoryArgs),
    /// Work with slug aliases (installed folder name -> wordpress.org slug)
    #[command(subcommand)]
    Aliases(AliasesCommand),
}

#[derive(Subcommand, Debug)]
enum AliasesCommand {
    /// Propose aliases for an inventory; prints TOML to review, never writes files
    Suggest {
        /// inventory.json, or a directory or archive to inventory first
        input: PathBuf,

        /// Confirm candidates against this local database
        #[arg(long, env = "WPVULN_DB", value_name = "DIR")]
        db: Option<PathBuf>,

        /// Existing aliases file; components it already maps are skipped
        #[arg(long, env = "WPVULN_ALIASES", value_name = "FILE")]
        aliases: Option<PathBuf>,

        /// Ask the API about slugs the local database lacks (nothing is saved)
        #[arg(long)]
        online: bool,

        /// WPVulnerability API base URL, for --online
        #[arg(long, env = "WPVULN_API", value_name = "URL", default_value = WPVULN_API)]
        api_url: String,
    },
}

#[derive(ClapArgs, Debug)]
struct InventoryArgs {
    /// WordPress root, wp-content or plugins directory, or a .tar, .tar.gz or .zip of one
    path: PathBuf,

    /// Write to this file instead of stdout
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    output: Option<PathBuf>,

    /// json: full inventory; list: slug:version lines for --plugins-file / --themes-file
    #[arg(long, default_value = "json", value_enum)]
    format: InventoryFormat,

    /// Which components a list contains
    #[arg(long = "type", default_value = "plugin", value_enum)]
    list_type: ListType,

    /// Also ask WP-CLI (`wp` on PATH) for active/inactive status and available updates
    #[arg(long)]
    with_wp_cli: bool,

    /// WordPress root for WP-CLI (default: PATH, when it is a WordPress root)
    #[arg(long, value_name = "DIR", requires = "with_wp_cli")]
    wp_path: Option<PathBuf>,

    /// Pass --allow-root to WP-CLI
    #[arg(long, requires = "with_wp_cli")]
    allow_root: bool,

    /// Map folder names to wordpress.org slugs (see `aliases suggest`)
    #[arg(long, env = "WPVULN_ALIASES", value_name = "FILE")]
    aliases: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum InventoryFormat {
    Json,
    List,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ListType {
    Plugin,
    Theme,
    Core,
}

#[derive(Subcommand, Debug)]
enum WordfenceCommand {
    /// Download the Wordfence feed into <db>/wordfence/
    Pull {
        /// Database directory
        #[arg(
            long,
            env = "WPVULN_DB",
            value_name = "DIR",
            default_value = "wpvuln-db"
        )]
        db: PathBuf,

        /// github: wpprobe's keyless export; api: the official feed (needs a key).
        /// Default: api when a key is set, else github
        #[arg(long, value_enum)]
        from: Option<FromArg>,

        /// Wordfence Intelligence API key (wordfence.com > Account > Integrations)
        #[arg(
            long,
            env = "WORDFENCE_API_KEY",
            hide_env_values = true,
            value_name = "KEY"
        )]
        api_key: Option<String>,

        /// Intelligence feed, for --from api
        #[arg(long, value_enum, default_value = "production")]
        feed: FeedArg,

        /// Download from this URL instead (mirrors, tests)
        #[arg(long, value_name = "URL")]
        url: Option<String>,

        /// Download from the API even if the last download was under 30 minutes ago
        #[arg(long)]
        force: bool,

        /// Refuse feeds larger than this many MiB
        #[arg(long, value_name = "MIB", default_value_t = wordfence_db::DEFAULT_MAX_BYTES >> 20)]
        max_mib: u64,

        /// Show what changed for the components of this inventory
        #[arg(long, value_name = "PATH")]
        inventory: Option<PathBuf>,

        /// Aliases to apply to the inventory
        #[arg(
            long,
            env = "WPVULN_ALIASES",
            value_name = "FILE",
            requires = "inventory"
        )]
        aliases: Option<PathBuf>,
    },
    /// Use a feed file obtained some other way (validated, then stored with its notice)
    Import {
        /// wpprobe or Wordfence feed JSON file
        file: PathBuf,

        /// Database directory
        #[arg(
            long,
            env = "WPVULN_DB",
            value_name = "DIR",
            default_value = "wpvuln-db"
        )]
        db: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum FromArg {
    Github,
    Api,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum FeedArg {
    Production,
    Scanner,
}

// Parsed once per run, so the size difference between variants is irrelevant
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand, Debug)]
enum DbCommand {
    /// Download records for the given components into a local database
    Pull {
        /// Database directory (created if missing)
        #[arg(
            long,
            env = "WPVULN_DB",
            value_name = "DIR",
            default_value = "wpvuln-db"
        )]
        db: PathBuf,

        #[command(flatten)]
        inputs: Inputs,

        /// WPVulnerability API base URL
        #[arg(long, env = "WPVULN_API", value_name = "URL", default_value = WPVULN_API)]
        api_url: String,

        /// Requests in flight at once (please keep this low; the API is free)
        #[arg(long, short = 'j', default_value_t = 4, value_parser = clap::value_parser!(u64).range(1..=16))]
        jobs: u64,

        /// Skip records downloaded less than this many hours ago (0 = always download)
        #[arg(long, default_value_t = 0, value_name = "HOURS")]
        max_age: u64,
    },
    /// Re-check stored records that are older than their interval, and
    /// report what changed since the last check
    Update {
        /// Database directory
        #[arg(
            long,
            env = "WPVULN_DB",
            value_name = "DIR",
            default_value = "wpvuln-db"
        )]
        db: PathBuf,

        /// WPVulnerability API base URL
        #[arg(long, env = "WPVULN_API", value_name = "URL", default_value = WPVULN_API)]
        api_url: String,

        /// Requests in flight at once (please keep this low; the API is free)
        #[arg(long, short = 'j', default_value_t = 4, value_parser = clap::value_parser!(u64).range(1..=16))]
        jobs: u64,

        /// Re-check records last confirmed more than this many hours ago (0 = all)
        #[arg(long, default_value_t = 24, value_name = "HOURS")]
        max_age: u64,

        /// The same for untracked components, which rarely change
        #[arg(long, default_value_t = 168, value_name = "HOURS")]
        untracked_max_age: u64,
    },
    /// Check a database: format, index, every record's sha256, stray files,
    /// and optionally that it covers an inventory (exit 1 on problems)
    Verify {
        /// Database directory
        #[arg(
            long,
            env = "WPVULN_DB",
            value_name = "DIR",
            default_value = "wpvuln-db"
        )]
        db: PathBuf,

        /// Also check that every lookup this inventory needs is present
        #[arg(long, value_name = "PATH")]
        inventory: Option<PathBuf>,

        /// Aliases to apply to the inventory
        #[arg(
            long,
            env = "WPVULN_ALIASES",
            value_name = "FILE",
            requires = "inventory"
        )]
        aliases: Option<PathBuf>,
    },
    /// Pack a verified database into one file with checksums, for transfer
    Export {
        /// Database directory
        #[arg(
            long,
            env = "WPVULN_DB",
            value_name = "DIR",
            default_value = "wpvuln-db"
        )]
        db: PathBuf,

        /// Bundle to write
        #[arg(
            short = 'o',
            long,
            value_name = "FILE",
            default_value = "wpvuln-db.tar.gz"
        )]
        output: PathBuf,
    },
    /// Replace a database with a bundle from `db export`, after checking it
    Import {
        /// Bundle made by `db export`
        bundle: PathBuf,

        /// Database directory to replace (the old one is kept as a backup)
        #[arg(
            long,
            env = "WPVULN_DB",
            value_name = "DIR",
            default_value = "wpvuln-db"
        )]
        db: PathBuf,
    },
    /// Wordfence Intelligence data as a second source
    #[command(subcommand)]
    Wordfence(WordfenceCommand),
    /// Show what a local database contains
    Status {
        /// Database directory
        #[arg(
            long,
            env = "WPVULN_DB",
            value_name = "DIR",
            default_value = "wpvuln-db"
        )]
        db: PathBuf,

        /// Print as JSON
        #[arg(long)]
        json: bool,
    },
}

/// Output format argument
#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormatArg {
    Human,
    Json,
    Csv,
    Markdown,
    #[value(name = "defectdojo")]
    DefectDojo,
    None,
}

impl From<OutputFormatArg> for OutputFormat {
    fn from(arg: OutputFormatArg) -> Self {
        match arg {
            OutputFormatArg::Human => OutputFormat::Human,
            OutputFormatArg::Json => OutputFormat::Json,
            OutputFormatArg::Csv => OutputFormat::Csv,
            OutputFormatArg::Markdown => OutputFormat::Markdown,
            OutputFormatArg::DefectDojo => OutputFormat::DefectDojo,
            OutputFormatArg::None => OutputFormat::None,
        }
    }
}

/// Severity argument
#[derive(Clone, Copy, Debug, ValueEnum)]
enum SeverityArg {
    Low,
    Medium,
    High,
    Critical,
}

impl From<SeverityArg> for Severity {
    fn from(arg: SeverityArg) -> Self {
        match arg {
            SeverityArg::Low => Severity::Low,
            SeverityArg::Medium => Severity::Medium,
            SeverityArg::High => Severity::High,
            SeverityArg::Critical => Severity::Critical,
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();

    let result = match args.command {
        Some(Command::Db(ref cmd)) => run_db(cmd).await,
        Some(Command::Inventory(ref inv)) => run_inventory(inv),
        Some(Command::Aliases(ref cmd)) => run_aliases(cmd).await,
        Some(Command::Scan(ref scan)) => run_scan(scan).await,
        None => run_scan(&args.scan).await,
    };

    match result {
        Ok(exit_code) => exit_code,
        Err(e) => {
            eprintln!("Error: {}", e);
            ExitCode::from(10)
        }
    }
}

async fn run_scan(args: &ScanArgs) -> wordpress_vulnerable_scanner::Result<ExitCode> {
    // Print banner for human output
    if matches!(args.output_format, OutputFormatArg::Human) {
        print_banner();
    }
    let output_config = &OutputConfig::new(args.output_format.into(), args.min_severity.into())
        .with_color(Style::stdout().0);
    // Build scan result from various input sources
    let (scan_result, warnings) = build_scan_result(args).await?;

    let wordfence = match args.wordfence.as_deref() {
        None => None,
        Some(spec) => Some(load_wordfence(spec, args.db.as_deref(), &scan_result)?),
    };
    let analyzer = match (args.db.as_ref(), wordfence) {
        (Some(dir), wf) => {
            let a = Analyzer::with_source(Source::Local(dir.clone()))?;
            match wf {
                Some((index, detail)) => a.with_wordfence(index, detail),
                None => a,
            }
        }
        // Wordfence alone: no network
        (None, Some((index, detail))) => Analyzer::wordfence_only(index, detail),
        (None, None) => Analyzer::with_source(Source::Api(args.api_url.clone()))?,
    }
    .include_informational(args.include_informational);
    let mut analysis = analyzer.analyze(&scan_result).await;
    analysis.warnings = warnings;

    // Output results
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();
    output_analysis(&analysis, output_config, &mut writer)?;

    Ok(ExitCode::from(exit_code(
        &analysis,
        args.fail_on,
        args.fail_on_unchecked,
    )))
}

/// Load a Wordfence feed for a scan, keeping only what it can use: the
/// scanned slugs, their name variants (for naming hints) and core
fn load_wordfence(
    spec: &str,
    db: Option<&Path>,
    scan: &ScanResult,
) -> wordpress_vulnerable_scanner::Result<(WordfenceIndex, String)> {
    let path = match (spec, db) {
        ("auto", Some(dir)) => wordfence_db::feed_path(dir),
        ("auto", None) => {
            return Err(wordpress_vulnerable_scanner::Error::Wordfence(
                "--wordfence auto means <db>/wordfence/wordfence.json, so it needs --db; \
                 or give the feed file's path"
                    .to_string(),
            ));
        }
        (file, _) => PathBuf::from(file),
    };
    if !path.is_file() {
        return Err(wordpress_vulnerable_scanner::Error::Wordfence(format!(
            "{}: no feed there. Run `db wordfence pull --db <dir>` first, or give the path \
             of a downloaded feed.",
            path.display()
        )));
    }
    let mut keep = std::collections::HashSet::new();
    keep.insert((ComponentType::Core, "wordpress".to_string()));
    for c in &scan.components {
        if c.component_type == ComponentType::Core {
            continue;
        }
        keep.insert((c.component_type, c.slug.to_ascii_lowercase()));
        for (variant, _) in wordpress_vulnerable_scanner::aliases::name_variants(&c.slug) {
            keep.insert((c.component_type, variant));
        }
    }
    let index = WordfenceIndex::load(&path, &Keep::Only(keep))?;
    let detail = match db.and_then(wordfence_db::read_meta) {
        Some(m) if path == wordfence_db::feed_path(db.unwrap_or(Path::new(""))) => format!(
            "{} ({}, pulled {})",
            path.display(),
            match m.source {
                wordfence_db::FeedSource::Github => "GitHub wpprobe export",
                wordfence_db::FeedSource::Api => "Intelligence API",
            },
            ago(m.fetched_at)
        ),
        _ => path.display().to_string(),
    };
    Ok((index, detail))
}

/// 2 for critical, 1 for other vulnerabilities, 0 otherwise. `fail_on`
/// ignores findings below a severity; `fail_unchecked` turns a would-be 0
/// into 1 when anything could not be checked.
fn exit_code(
    analysis: &wordpress_vulnerable_scanner::Analysis,
    fail_on: Option<FailOn>,
    fail_unchecked: bool,
) -> u8 {
    let s = &analysis.summary;
    let threshold = match fail_on {
        None | Some(FailOn::Low) => Some(Severity::Low),
        Some(FailOn::Medium) => Some(Severity::Medium),
        Some(FailOn::High) => Some(Severity::High),
        Some(FailOn::Critical) => Some(Severity::Critical),
        Some(FailOn::None) => None,
    };
    let at_least = |sev: Severity| threshold.is_some_and(|t| sev >= t);
    let count = |sev: Severity| match sev {
        Severity::Critical => s.critical,
        Severity::High => s.high,
        Severity::Medium => s.medium,
        Severity::Low => s.low,
    };
    let failing = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
    ]
    .into_iter()
    .filter(|&sev| at_least(sev))
    .map(count)
    .sum::<usize>();
    if at_least(Severity::Critical) && s.critical > 0 {
        2
    } else if failing > 0 || (fail_unchecked && s.not_checked > 0) {
        1
    } else {
        0
    }
}

async fn build_scan_result(
    args: &ScanArgs,
) -> wordpress_vulnerable_scanner::Result<(ScanResult, Vec<String>)> {
    // URL scan mode
    if let Some(ref url) = args.url {
        // Add http:// if no scheme provided
        let url = if !url.contains("://") {
            format!("http://{}", url)
        } else {
            url.clone()
        };
        let scanner = Scanner::new(&url)?;
        let result = scanner.scan().await?;
        return Ok((result, Vec::new()));
    }

    let (components, warnings) = build_components(&args.inputs)?;
    Ok((ScanResult::from_components(components), warnings))
}

/// Components named by the inputs, and warnings about the inputs
fn build_components(
    inputs: &Inputs,
) -> wordpress_vulnerable_scanner::Result<(Vec<ComponentInfo>, Vec<String>)> {
    let mut warnings = Vec::new();
    let mut components = Vec::new();

    // Manifest file mode
    if let Some(ref manifest_path) = inputs.manifest {
        read_manifest(manifest_path, &mut components)?;
        return Ok((components, warnings));
    }

    // Direct input mode
    if let Some(ref core_version) = inputs.core {
        components.push(ComponentInfo {
            component_type: ComponentType::Core,
            slug: "wordpress".to_string(),
            version: Some(core_version.clone()),
            installed_as: None,
        });
    }

    for (list, file, kind) in [
        (&inputs.plugins, &inputs.plugins_file, ComponentType::Plugin),
        (&inputs.themes, &inputs.themes_file, ComponentType::Theme),
    ] {
        if let Some(list) = list {
            for item in list.split(',') {
                let item = item.trim();
                if !item.is_empty() {
                    components.push(parse_component(item, kind)?);
                }
            }
        }
        if let Some(path) = file {
            let text = std::fs::read_to_string(path).map_err(|e| {
                wordpress_vulnerable_scanner::Error::ManifestRead(format!(
                    "{}: {}",
                    path.display(),
                    e
                ))
            })?;
            components.extend(parse_component_list(&text, kind)?);
        }
    }

    if let Some(ref path) = inputs.inventory {
        let (found, found_warnings) = inventory_components(path, inputs.aliases.as_deref())?;
        components.extend(found);
        warnings = found_warnings;
    }

    // Check we have something to scan
    if components.is_empty() {
        return Err(wordpress_vulnerable_scanner::Error::NoInput);
    }

    Ok((components, warnings))
}

fn read_manifest(
    manifest_path: &Path,
    components: &mut Vec<ComponentInfo>,
) -> wordpress_vulnerable_scanner::Result<()> {
    // Security: Limit manifest file size to 10MB to prevent memory exhaustion
    const MAX_MANIFEST_SIZE: u64 = 10 * 1024 * 1024;

    let metadata = std::fs::metadata(manifest_path)
        .map_err(|e| wordpress_vulnerable_scanner::Error::ManifestRead(e.to_string()))?;

    if metadata.len() > MAX_MANIFEST_SIZE {
        return Err(wordpress_vulnerable_scanner::Error::ManifestRead(format!(
            "file too large ({} bytes, max {} bytes)",
            metadata.len(),
            MAX_MANIFEST_SIZE
        )));
    }

    let contents = std::fs::read_to_string(manifest_path)
        .map_err(|e| wordpress_vulnerable_scanner::Error::ManifestRead(e.to_string()))?;

    // Try to parse as wordpress-audit JSON output
    let manifest: serde_json::Value = serde_json::from_str(&contents)
        .map_err(|e| wordpress_vulnerable_scanner::Error::ManifestParse(e.to_string()))?;

    // Extract WordPress version
    if let Some(wp) = manifest.get("wordpress")
        && let Some(version) = wp.get("version").and_then(|v| v.as_str())
        && version != "-"
    {
        components.push(ComponentInfo {
            component_type: ComponentType::Core,
            slug: "wordpress".to_string(),
            version: Some(version.to_string()),
            installed_as: None,
        });
    }

    // Extract theme
    if let Some(theme) = manifest.get("theme")
        && let Some(name) = theme.get("name").and_then(|v| v.as_str())
    {
        let version = theme
            .get("version")
            .and_then(|v| v.as_str())
            .filter(|v| *v != "-")
            .map(|s| s.to_string());

        components.push(ComponentInfo {
            component_type: ComponentType::Theme,
            slug: name.to_string(),
            version,
            installed_as: None,
        });
    }

    // Extract plugins
    if let Some(plugins) = manifest.get("plugins").and_then(|p| p.as_object()) {
        for (slug, plugin_data) in plugins {
            let version = plugin_data
                .get("version")
                .and_then(|v| v.as_str())
                .filter(|v| *v != "-")
                .map(|s| s.to_string());

            components.push(ComponentInfo {
                component_type: ComponentType::Plugin,
                slug: slug.clone(),
                version,
                installed_as: None,
            });
        }
    }
    Ok(())
}

async fn run_db(cmd: &DbCommand) -> wordpress_vulnerable_scanner::Result<ExitCode> {
    match cmd {
        DbCommand::Pull {
            db: dir,
            inputs,
            api_url,
            jobs,
            max_age,
        } => {
            let (components, warnings) = build_components(inputs)?;
            let items = pull_items(&components);
            let opts = PullOptions {
                api_url: api_url.clone(),
                jobs: *jobs as usize,
                max_age: (*max_age > 0).then(|| Duration::from_secs(max_age * 3600)),
                ..PullOptions::default()
            };
            pull_cli("Pulling", dir, &items, &opts, &warnings).await
        }
        DbCommand::Update {
            db: dir,
            api_url,
            jobs,
            max_age,
            untracked_max_age,
        } => {
            let items = db::stored(dir)?;
            if items.is_empty() {
                return Err(wordpress_vulnerable_scanner::Error::Database(format!(
                    "{} holds no records yet; run `db pull` first",
                    dir.display()
                )));
            }
            let hours = |h: u64| (h > 0).then(|| Duration::from_secs(h * 3600));
            let opts = PullOptions {
                api_url: api_url.clone(),
                jobs: *jobs as usize,
                max_age: hours(*max_age),
                untracked_max_age: hours(*untracked_max_age),
                ..PullOptions::default()
            };
            pull_cli("Updating", dir, &items, &opts, &[]).await
        }
        DbCommand::Verify {
            db: dir,
            inventory,
            aliases,
        } => verify_cli(dir, inventory.as_deref(), aliases.as_deref()),
        DbCommand::Export { db: dir, output } => {
            let m = wordpress_vulnerable_scanner::transfer::export(dir, output)?;
            let s = Style::stdout();
            println!(
                "{} {} files from {} into {}",
                s.bold("Exported"),
                m.files.len(),
                dir.display(),
                output.display()
            );
            println!(
                "Copy it to the offline machine, then: {}",
                s.bold(&format!(
                    "wordpress-vulnerable-scanner db import {}",
                    output
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default()
                ))
            );
            Ok(ExitCode::SUCCESS)
        }
        DbCommand::Import { bundle, db: dir } => {
            let done = wordpress_vulnerable_scanner::transfer::import(bundle, dir)?;
            let s = Style::stdout();
            println!(
                "{} {} files into {}: every file matched the manifest and `db verify` passed",
                s.bold("Imported"),
                done.files,
                dir.display()
            );
            if let Some(b) = done.backup {
                println!("The previous database was moved to {}", b.display());
            }
            Ok(ExitCode::SUCCESS)
        }
        DbCommand::Wordfence(cmd) => wordfence_cli(cmd).await,
        DbCommand::Status { db: dir, json } => {
            let st = db::status(dir)?;
            if *json {
                println!("{}", serde_json::to_string_pretty(&st)?);
                return Ok(ExitCode::SUCCESS);
            }
            let s = Style::stdout();
            println!("{} {}", s.bold("Database"), dir.display());
            match st.meta {
                Some(ref m) => {
                    println!("  source      {}", m.source);
                    println!("  last pull   {}", ago(m.pulled_at));
                    match st.indexed {
                        Some(n) => println!(
                            "  format      {} (index: {n} records{})",
                            m.format,
                            match st.rebuilt {
                                0 => String::new(),
                                r => format!(", {r} rebuilt from files, download details unknown"),
                            }
                        ),
                        None => println!(
                            "  format      {} {}",
                            m.format,
                            s.dim("(no index yet; the next `db pull` adds one)")
                        ),
                    }
                }
                None => println!("  {}", s.yellow("not a database yet; run `db pull` first")),
            }
            println!("  plugins     {}", st.plugins);
            println!("  themes      {}", st.themes);
            println!("  core        {}", st.core);
            if st.untracked > 0 {
                println!(
                    "  untracked   {} {}",
                    st.untracked,
                    s.dim("(no WPVulnerability entry, not checked)")
                );
            }
            println!("  records     {}", st.records);
            print_wordfence_status(&s, st.wordfence.as_ref());
            match (st.indexed, st.oldest_check, st.oldest) {
                (Some(_), Some(t), _) => println!("  oldest check {}", ago(t)),
                (None, _, Some(t)) => println!(
                    "  oldest file {} {}",
                    ago(t),
                    s.dim("(file times reset when a database is copied)")
                ),
                _ => {}
            }
            if st.unconfirmed > 0 {
                println!(
                    "  {} {} never confirmed: rebuilt from files, so when they were fetched is \
                     unknown. `db update` re-checks them.",
                    s.yellow("unconfirmed"),
                    st.unconfirmed
                );
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

async fn pull_cli(
    verb: &str,
    dir: &Path,
    items: &[(ComponentType, String)],
    opts: &PullOptions,
    warnings: &[String],
) -> wordpress_vulnerable_scanner::Result<ExitCode> {
    let s = Style::stdout();
    let total = items.len();
    let width = items
        .iter()
        .map(|(_, k)| k.chars().count())
        .max()
        .unwrap_or(10)
        .min(48);
    let digits = total.to_string().len();
    println!(
        "{} {} component{} from {} into {} ({} parallel)\n",
        s.bold(verb),
        total,
        if total == 1 { "" } else { "s" },
        opts.api_url,
        dir.display(),
        opts.jobs
    );

    let started = Instant::now();
    let mut outcomes: Vec<(ComponentType, String, PullStatus)> = Vec::new();
    let summary = db::pull(dir, items, opts, |e: &PullEvent| {
        outcomes.push((e.kind, e.key.clone(), e.status.clone()));
        let (mark, detail) = match &e.status {
            PullStatus::Saved(0) => (s.green("✓"), s.dim("tracked, no known vulnerabilities")),
            PullStatus::Saved(n) => (
                s.green("✓"),
                format!("{n} record{}", if *n == 1 { "" } else { "s" }),
            ),
            PullStatus::Fresh(n) => (s.dim("="), s.dim(&format!("{n} records, up to date"))),
            PullStatus::Unchanged(n) => (
                s.dim("="),
                s.dim(&format!("{n} records, unchanged (confirmed by the API)")),
            ),
            PullStatus::NoData => (
                s.yellow("?"),
                s.yellow("not tracked by WPVulnerability (not checked)"),
            ),
            PullStatus::Invalid => (s.red("✗"), s.red("invalid slug, skipped")),
            PullStatus::Failed(why) => (
                s.red("✗"),
                s.red(&format!("{why} (after {} attempts)", opts.attempts)),
            ),
        };
        let kind = match e.kind {
            ComponentType::Core => "core ",
            ComponentType::Plugin => "",
            ComponentType::Theme => "theme ",
        };
        println!(
            "  {} {} {}{:<width$}  {}",
            s.dim(&format!("[{:>digits$}/{}]", e.done, e.total)),
            mark,
            kind,
            e.key,
            detail,
        );
    })
    .await?;

    let mut parts = vec![format!(
        "{} saved ({} records)",
        summary.saved, summary.records
    )];
    if summary.fresh > 0 {
        parts.push(format!("{} up to date", summary.fresh));
    }
    if summary.unchanged > 0 {
        parts.push(format!("{} unchanged", summary.unchanged));
    }
    if summary.no_data > 0 {
        parts.push(s.yellow(&format!("{} not tracked", summary.no_data)));
    }
    if summary.invalid > 0 {
        parts.push(s.red(&format!("{} invalid", summary.invalid)));
    }
    if summary.failed > 0 {
        parts.push(s.red(&format!("{} failed", summary.failed)));
    }
    println!(
        "\n{} in {:.0?}: {}",
        s.bold("Done"),
        started.elapsed(),
        parts.join(", ")
    );
    print_changes(&s, dir, &summary.changes, verb == "Updating");
    print_pull_problems(&s, dir, &outcomes, warnings);
    println!(
        "Scan offline with: {}",
        s.bold(&format!(
            "wordpress-vulnerable-scanner --db {} ...",
            dir.display()
        ))
    );

    Ok(if summary.failed > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

fn verify_cli(
    dir: &Path,
    inventory: Option<&Path>,
    aliases: Option<&Path>,
) -> wordpress_vulnerable_scanner::Result<ExitCode> {
    let (components, warnings) = match inventory {
        Some(path) => inventory_components(path, aliases)?,
        None => (Vec::new(), Vec::new()),
    };
    let needed = pull_items(&components);
    let v = db::verify(dir, &needed);
    let s = Style::stdout();
    println!("{} {}", s.bold("Verifying"), dir.display());
    println!("  {} record files checked", v.records);
    if v.untracked > 0 {
        println!(
            "  {} untracked {}",
            v.untracked,
            s.dim(
                "(not a problem: WPVulnerability has no entry for them, so they are not checked)"
            )
        );
    }
    if let Some(path) = inventory {
        println!(
            "  {} lookups needed by {}, {} missing",
            needed.len(),
            path.display(),
            v.missing.len()
        );
    }
    if !v.problems.is_empty() {
        println!("\n{} ({})", s.red("Problems"), v.problems.len());
        let digits = v.problems.len().to_string().len();
        for (i, p) in v.problems.iter().enumerate() {
            let indent = " ".repeat(digits + 4);
            println!(
                "  {} {}",
                s.dim(&format!("{:>digits$}.", i + 1)),
                wrap(p, 96 - indent.len()).join(&format!("\n{indent}"))
            );
        }
    }
    if !v.missing.is_empty() {
        println!(
            "\n{} ({}): {}",
            s.red("Missing for the inventory"),
            v.missing.len(),
            v.missing.join(", ")
        );
        println!(
            "  They were never pulled, so a scan would report them as not checked. Fix with:\n  \
             wordpress-vulnerable-scanner db pull --db {} --inventory {}{}",
            dir.display(),
            inventory
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            aliases
                .map(|a| format!(" --aliases {}", a.display()))
                .unwrap_or_default()
        );
    }
    print_input_warnings(&s, &warnings);
    if v.ok() {
        println!(
            "\n{}",
            s.green("OK: every record matches what was downloaded.")
        );
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(1))
    }
}

/// After a pull: what could not be checked and why, which names look like
/// renamed copies (and whether this database tracks the original), what
/// failed, and any warnings about the inputs, each with what to do
fn print_pull_problems(
    s: &Style,
    dir: &Path,
    outcomes: &[(ComponentType, String, PullStatus)],
    warnings: &[String],
) {
    let kind_label = |k: ComponentType| match k {
        ComponentType::Core => "core ",
        ComponentType::Plugin => "",
        ComponentType::Theme => "theme ",
    };
    let table = |k: ComponentType| match k {
        ComponentType::Theme => "theme",
        _ => "plugin",
    };

    let mut confirmed = Vec::new();
    let mut maybe = Vec::new();
    let mut unknown = Vec::new();
    for (kind, key, status) in outcomes {
        if *status != PullStatus::NoData {
            continue;
        }
        let variants = match kind {
            ComponentType::Core => Vec::new(),
            _ => wordpress_vulnerable_scanner::aliases::name_variants(key),
        };
        let tracked = variants
            .iter()
            .find_map(|(v, _)| match db::known(dir, *kind, v) {
                db::Known::Tracked(n) => Some((v.clone(), n)),
                _ => None,
            });
        match (tracked, variants.is_empty()) {
            (Some((v, n)), _) => confirmed.push(format!(
                "{}{key:<40} \"{key}\" = \"{v}\"   (in [{}]; {n} record{} under \"{v}\")",
                kind_label(*kind),
                table(*kind),
                if n == 1 { "" } else { "s" }
            )),
            (None, false) => maybe.push(format!(
                "{}{key}: maybe {}",
                kind_label(*kind),
                variants
                    .iter()
                    .map(|(v, _)| format!("\"{v}\""))
                    .collect::<Vec<_>>()
                    .join(" or ")
            )),
            (None, true) => unknown.push(format!("{}{key}", kind_label(*kind))),
        }
    }
    let failed: Vec<String> = outcomes
        .iter()
        .filter_map(|(kind, key, status)| match status {
            PullStatus::Failed(why) => Some(format!("{}{key}: {why}", kind_label(*kind))),
            _ => None,
        })
        .collect();
    let invalid: Vec<String> = outcomes
        .iter()
        .filter(|(_, _, status)| *status == PullStatus::Invalid)
        .map(|(kind, key, _)| format!("{}{key:?}", kind_label(*kind)))
        .collect();

    let not_tracked = confirmed.len() + maybe.len() + unknown.len();
    if not_tracked > 0 {
        println!(
            "\n{} ({not_tracked}): WPVulnerability has no entry under these names, so a scan \
             cannot check them",
            s.yellow("Not tracked")
        );
        if !confirmed.is_empty() {
            println!(
                "  {} ({}): this database tracks them under another slug. If they are the same \
                 plugin, add these lines to aliases.toml and pull again:",
                s.bold("probably a naming problem"),
                confirmed.len()
            );
            for line in &confirmed {
                println!("    {line}");
            }
        }
        if !maybe.is_empty() {
            println!(
                "  {} ({}): the name looks like a renamed, premium or backup copy, but the \
                 original is not in this database. To check:\n    \
                 wordpress-vulnerable-scanner aliases suggest <inventory> --db {} --online",
                s.bold("maybe a naming problem"),
                maybe.len(),
                dir.display()
            );
            for line in &maybe {
                println!("    {line}");
            }
        }
        if !unknown.is_empty() {
            println!(
                "  {} ({}): no other name to try. Usually custom or marketplace code that no \
                 database covers; scans will list it as not checked, so review it by hand:\n    {}",
                s.bold("not tracked"),
                unknown.len(),
                unknown.join(", ")
            );
        }
    }
    if !failed.is_empty() {
        println!(
            "\n{} ({}): nothing was saved for these, and scans will list them as not in the \
             database. Re-run the same command to retry; saved records are kept.",
            s.red("Failed"),
            failed.len()
        );
        for line in &failed {
            println!("    {line}");
        }
    }
    if !invalid.is_empty() {
        println!(
            "\n{} ({}): these are not usable slugs (only letters, digits, '-', '_' and '.'), so \
             they were never requested. Fix the name in the input, or map it in aliases.toml:\n    {}",
            s.red("Invalid names"),
            invalid.len(),
            invalid.join(", ")
        );
    }
    print_input_warnings(s, warnings);
}

/// Numbered, wrapped "Warnings about the inputs" section on stdout
fn print_input_warnings(s: &Style, warnings: &[String]) {
    if warnings.is_empty() {
        return;
    }
    println!(
        "\n{} ({})",
        s.yellow("Warnings about the inputs"),
        warnings.len()
    );
    let digits = warnings.len().to_string().len();
    let indent = " ".repeat(digits + 4);
    for (i, w) in warnings.iter().enumerate() {
        println!(
            "  {:>digits$}. {}",
            i + 1,
            wrap(w, 96 - indent.len()).join(&format!("\n{indent}"))
        );
    }
}

fn print_wordfence_status(s: &Style, meta: Option<&wordfence_db::Meta>) {
    let Some(m) = meta else {
        println!(
            "  wordfence   {}",
            s.dim("not pulled (`db wordfence pull` adds a second source)")
        );
        return;
    };
    let age = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
        .saturating_sub(m.fetched_at);
    let source = match (m.source, m.feed) {
        (wordfence_db::FeedSource::Api, Some(wordfence_db::Feed::Scanner)) => {
            "Intelligence API, scanner feed"
        }
        (wordfence_db::FeedSource::Api, _) => "Intelligence API, production feed",
        (wordfence_db::FeedSource::Github, _) => "GitHub (wpprobe export, CVE records only)",
    };
    println!("  wordfence   {source}");
    println!(
        "              {} records, {} slugs, {:.1} MB, pulled {}",
        m.records,
        m.slugs,
        m.bytes as f64 / 1e6,
        ago(m.fetched_at)
    );
    println!("              sha256 {}", &m.sha256);
    if age > wordfence_db::STALE_AFTER.as_secs() {
        println!(
            "              {}",
            s.yellow("older than 7 days: run `db wordfence pull` for current data")
        );
    }
}

async fn wordfence_cli(cmd: &WordfenceCommand) -> wordpress_vulnerable_scanner::Result<ExitCode> {
    let s = Style::stdout();
    match cmd {
        WordfenceCommand::Import { file, db: dir } => {
            let m = wordfence_db::import(dir, file)?;
            println!(
                "{} {} ({} records, {} slugs) into {}",
                s.bold("Imported"),
                file.display(),
                m.records,
                m.slugs,
                wordfence_db::feed_path(dir).display()
            );
            Ok(ExitCode::SUCCESS)
        }
        WordfenceCommand::Pull {
            db: dir,
            from,
            api_key,
            feed,
            url,
            force,
            max_mib,
            inventory,
            aliases,
        } => {
            let has_key = api_key.as_deref().is_some_and(|k| !k.is_empty());
            let (source, why) = match from {
                Some(FromArg::Github) => (wordfence_db::FeedSource::Github, "--from github"),
                Some(FromArg::Api) => (wordfence_db::FeedSource::Api, "--from api"),
                None if has_key => (
                    wordfence_db::FeedSource::Api,
                    "a key is set; pass --from github for the keyless file",
                ),
                None => (
                    wordfence_db::FeedSource::Github,
                    "no key set; WORDFENCE_API_KEY or --api-key selects the official API",
                ),
            };
            let opts = wordfence_db::PullOptions {
                from: source,
                feed: match feed {
                    FeedArg::Production => wordfence_db::Feed::Production,
                    FeedArg::Scanner => wordfence_db::Feed::Scanner,
                },
                api_key: api_key.clone(),
                url: url.clone(),
                force: *force,
                max_bytes: max_mib.saturating_mul(1 << 20),
            };
            println!(
                "{} Wordfence data from {} ({why})",
                s.bold("Pulling"),
                match source {
                    wordfence_db::FeedSource::Github => "GitHub",
                    wordfence_db::FeedSource::Api => "the Intelligence API",
                }
            );

            // With an inventory: what changed for its components
            let keep = match inventory {
                Some(path) => {
                    let (components, warnings) = inventory_components(path, aliases.as_deref())?;
                    print_input_warnings(&s, &warnings);
                    Some(wordfence_keep(&components))
                }
                None => None,
            };
            let mut changes = Vec::new();
            let started = Instant::now();
            let tty = Style::stderr().0;
            let mut shown = 0u64;
            let progress = |bytes: u64, total: Option<u64>| {
                // A line every 2 MB, on a terminal only
                if tty && bytes >= shown + (2 << 20) {
                    shown = bytes;
                    match total {
                        Some(t) => eprint!(
                            "\r  {:.1} of {:.1} MB ({:.0}%)   ",
                            bytes as f64 / 1e6,
                            t as f64 / 1e6,
                            bytes as f64 * 100.0 / t.max(1) as f64
                        ),
                        None => eprint!("\r  {:.1} MB   ", bytes as f64 / 1e6),
                    }
                }
            };
            let outcome = wordfence_db::pull(dir, &opts, progress, |new, old| {
                let (Some(keep), Some(old)) = (keep.as_ref(), old) else {
                    return;
                };
                let load = |p: &Path| WordfenceIndex::load(p, keep).ok();
                if let (Some(a), Some(b)) = (load(old), load(new)) {
                    changes = wordfence_diff(&a, &b);
                }
            })
            .await;
            if tty && shown > 0 {
                eprintln!();
            }
            match outcome? {
                wordfence_db::PullOutcome::TooSoon { meta, wait } => {
                    println!(
                        "{} The last API download was under {} minutes ago, and Wordfence \
                         allows about one per {} minutes per key. Using the stored feed (pulled \
                         {}). Run again in {} minutes, or pass --force.",
                        s.yellow("Skipped."),
                        wordfence_db::API_MIN_INTERVAL.as_secs() / 60,
                        wordfence_db::API_MIN_INTERVAL.as_secs() / 60,
                        ago(meta.fetched_at),
                        wait.as_secs().div_ceil(60)
                    );
                }
                wordfence_db::PullOutcome::NotModified(meta) => {
                    println!(
                        "{} the stored feed is current ({} records), confirmed by the server",
                        s.bold("Not modified:"),
                        meta.records
                    );
                }
                wordfence_db::PullOutcome::Updated { meta, previous } => {
                    println!(
                        "{} in {:.1?}: {} records, {} slugs, {:.1} MB ({})",
                        s.bold("Saved"),
                        started.elapsed(),
                        meta.records,
                        meta.slugs,
                        meta.bytes as f64 / 1e6,
                        match meta.input_format {
                            wordfence::InputFormat::Wpprobe =>
                                "wpprobe format: records with a CVE only",
                            wordfence::InputFormat::WordfenceRaw => "official feed format",
                        }
                    );
                    println!("  {}", wordfence_db::feed_path(dir).display());
                    if let Some(p) = previous {
                        let delta = meta.records as i64 - p.records as i64;
                        println!(
                            "  previous feed: {} records, pulled {} ({delta:+} records)",
                            p.records,
                            ago(p.fetched_at)
                        );
                    }
                    if keep.is_some() {
                        db::append_changes(dir, &changes)?;
                        print_changes(&s, dir, &changes, true);
                    }
                    println!(
                        "{}",
                        s.dim(&format!(
                            "License notice saved next to it ({}/wordfence.NOTICE.txt); keep it \
                             with every copy.",
                            dir.join(wordfence_db::DIR).display()
                        ))
                    );
                }
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// The (type, slug) pairs a Wordfence load should keep for these components
fn wordfence_keep(components: &[ComponentInfo]) -> Keep {
    Keep::Only(
        components
            .iter()
            .map(|c| (c.component_type, c.slug.to_ascii_lowercase()))
            .collect(),
    )
}

fn wordfence_diff(old: &WordfenceIndex, new: &WordfenceIndex) -> Vec<Change> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    wordpress_vulnerable_scanner::changes::diff_snapshots(
        old.entries(),
        new.entries(),
        "wordfence",
        now,
    )
}

/// The "what is new since last time" view of a pull or update
fn print_changes(s: &Style, dir: &Path, changes: &[Change], always: bool) {
    if changes.is_empty() {
        if always {
            println!("\n{}", s.bold("No changes since the last check."));
        }
        return;
    }
    println!("\n{}", s.bold("Changes since the last check"));
    let width = changes
        .iter()
        .map(|c| c.key.chars().count())
        .max()
        .unwrap_or(0)
        .min(48);
    for c in changes {
        let what = c
            .cves
            .first()
            .map(|cve| format!("{cve}: "))
            .unwrap_or_default()
            + c.title.as_deref().or(c.uuid.as_deref()).unwrap_or_default();
        let (mark, text) = match c.change {
            ChangeKind::Added => (s.red("+"), format!("{what} (new vulnerability)")),
            ChangeKind::Removed => (
                s.green("-"),
                format!("{what} (withdrawn or merged upstream)"),
            ),
            ChangeKind::Changed => (
                s.yellow("~"),
                format!("{what} (details changed: affected versions, score or references)"),
            ),
            ChangeKind::NowTracked => (
                s.green("!"),
                "now tracked by WPVulnerability: it is checked from now on".to_string(),
            ),
            ChangeKind::NoLongerTracked => (
                s.red("!"),
                "no longer tracked by WPVulnerability: it is not checked any more".to_string(),
            ),
        };
        println!("  {mark} {:<width$}  {text}", c.key);
    }
    println!(
        "{}",
        s.dim(&format!(
            "Logged in {}",
            dir.join("changes").join("<date>.json").display()
        ))
    );
}

fn run_inventory(args: &InventoryArgs) -> wordpress_vulnerable_scanner::Result<ExitCode> {
    let mut inv = inventory::read(&args.path)?;
    if args.with_wp_cli {
        if inv.source.kind == inventory::SourceKind::Archive {
            return Err(wordpress_vulnerable_scanner::Error::Inventory(
                "--with-wp-cli needs a live WordPress directory, not an archive".to_string(),
            ));
        }
        let path = args.wp_path.clone().or_else(|| {
            (inv.source.layout == inventory::Layout::Wordpress).then(|| args.path.clone())
        });
        let wp = inventory::WpCli {
            path,
            allow_root: args.allow_root,
            ..Default::default()
        };
        inventory::enrich_with_wp_cli(&mut inv, &wp);
    }
    if let Some(ref path) = args.aliases {
        Aliases::load(path)?.apply(&mut inv);
    }
    let text = match args.format {
        InventoryFormat::Json => serde_json::to_string_pretty(&inv)? + "\n",
        InventoryFormat::List => inv.to_list(match args.list_type {
            ListType::Plugin => ComponentType::Plugin,
            ListType::Theme => ComponentType::Theme,
            ListType::Core => ComponentType::Core,
        }),
    };
    match args.output {
        Some(ref path) => std::fs::write(path, text)?,
        None => {
            use std::io::Write;
            std::io::stdout().lock().write_all(text.as_bytes())?;
        }
    }

    // Everything else goes to stderr, so stdout stays a clean file
    let s = Style::stderr();
    let plural = |n: usize, noun: &str| format!("{n} {noun}{}", if n == 1 { "" } else { "s" });
    let count = |kind: Kind| inv.components.iter().filter(|c| c.kind == kind).count();
    let mut parts = vec![
        plural(count(Kind::Plugin), "plugin"),
        plural(count(Kind::Theme), "theme"),
    ];
    for (kind, noun) in [
        (Kind::MuPlugin, "must-use plugin"),
        (Kind::Dropin, "drop-in"),
        (Kind::Unloaded, "unloaded plugin"),
    ] {
        if count(kind) > 0 {
            parts.push(plural(count(kind), noun));
        }
    }
    if let Some(ref core) = inv.core {
        parts.push(format!(
            "core {}",
            core.version.as_deref().unwrap_or("unknown")
        ));
    }
    eprintln!(
        "{} {} ({} layout): {}{}",
        s.bold("Inventory"),
        inv.source.path,
        serde_json::to_value(inv.source.layout)?
            .as_str()
            .unwrap_or_default(),
        parts.join(", "),
        match inv.warnings.len() {
            0 => String::new(),
            n => format!(", {}", s.yellow(&plural(n, "warning"))),
        }
    );
    if !inv.warnings.is_empty() {
        eprintln!("\n{}", s.yellow("Warnings"));
        let digits = inv.warnings.len().to_string().len();
        for (i, w) in inv.warnings.iter().enumerate() {
            let number = format!("{:>digits$}.", i + 1);
            let indent = " ".repeat(digits + 4);
            let lines = wrap(w, 96 - indent.len());
            eprintln!(
                "  {} {}",
                s.dim(&number),
                lines.join(&format!("\n{indent}"))
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

async fn run_aliases(cmd: &AliasesCommand) -> wordpress_vulnerable_scanner::Result<ExitCode> {
    let AliasesCommand::Suggest {
        input,
        db: db_dir,
        aliases,
        online,
        api_url,
    } = cmd;
    let inv = inventory::load(input)?;
    let existing = match aliases {
        Some(path) => Aliases::load(path)?,
        None => Aliases::default(),
    };
    let lookup = |kind: Kind, slug: &str| {
        let kind = match kind {
            Kind::Theme => ComponentType::Theme,
            _ => ComponentType::Plugin,
        };
        db::known(db_dir.as_deref().unwrap_or(Path::new("")), kind, slug)
    };
    let known: Option<wordpress_vulnerable_scanner::aliases::KnownFn> = match db_dir {
        Some(_) => Some(&lookup),
        None => None,
    };
    let s = Style::stderr();
    let (suggestions, failed) = if *online {
        eprintln!(
            "{} candidates at {api_url} (4 requests at a time, nothing is saved)",
            s.bold("Checking")
        );
        let opts = PullOptions {
            api_url: api_url.clone(),
            ..PullOptions::default()
        };
        wordpress_vulnerable_scanner::aliases::suggest_online(
            &inv,
            &existing,
            db_dir.as_deref(),
            &opts,
        )
        .await?
    } else {
        let found = wordpress_vulnerable_scanner::aliases::suggest(&inv, &existing, known);
        (found, Vec::new())
    };
    let checked = match (db_dir, online) {
        (Some(dir), true) => format!("local database {}, then {api_url}", dir.display()),
        (None, true) => api_url.clone(),
        (Some(dir), false) => format!("local database {}", dir.display()),
        (None, false) => "nothing (add --db DIR or --online to confirm them)".to_string(),
    };
    print!(
        "{}",
        wordpress_vulnerable_scanner::aliases::render(&suggestions, &checked)
    );

    if !failed.is_empty() {
        eprintln!(
            "{} {} lookup{} failed, so those slugs read as \"not in the database\"; run again \
             to retry: {}",
            s.yellow("warning:"),
            failed.len(),
            if failed.len() == 1 { "" } else { "s" },
            failed.join(", ")
        );
    }
    let confirmed = suggestions.iter().filter(|x| x.chosen.is_some()).count();
    let without = suggestions
        .iter()
        .filter(|x| x.candidates.is_empty())
        .count();
    eprintln!(
        "{} {} component{}: {confirmed} confirmed, {} to review, {without} without candidates",
        s.bold("Suggestions for"),
        suggestions.len(),
        if suggestions.len() == 1 { "" } else { "s" },
        suggestions.len() - confirmed - without
    );
    Ok(ExitCode::SUCCESS)
}

fn ago(unix: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(unix);
    let secs = now.saturating_sub(unix);
    match secs {
        0..=59 => "just now".to_string(),
        60..=3599 => format!("{} min ago", secs / 60),
        3600..=86_399 => format!("{} h ago", secs / 3600),
        _ => format!("{} days ago", secs / 86_400),
    }
}

/// ANSI styling, only when writing to a terminal and NO_COLOR is unset
struct Style(bool);

impl Style {
    fn stdout() -> Self {
        Style(std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none())
    }
    fn stderr() -> Self {
        Style(std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none())
    }
    fn paint(&self, code: &str, text: &str) -> String {
        if self.0 {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }
    fn bold(&self, t: &str) -> String {
        self.paint("1", t)
    }
    fn dim(&self, t: &str) -> String {
        self.paint("2", t)
    }
    fn red(&self, t: &str) -> String {
        self.paint("31", t)
    }
    fn green(&self, t: &str) -> String {
        self.paint("32", t)
    }
    fn yellow(&self, t: &str) -> String {
        self.paint("33", t)
    }
}

fn print_banner() {
    const VERSION: &str = env!("CARGO_PKG_VERSION");
    println!("WordPress Vulnerable Scanner v{}", VERSION);
    println!("by Robert F. Ecker <robert@robdotec.com>");
    println!();
}
