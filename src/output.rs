//! Output formatting for vulnerability scan results

use crate::analyze::{Analysis, ComponentState, ComponentVulnerabilities, source_name};
use crate::error::{Error, Result};
use crate::vulnerability::Severity;
use comfy_table::{Attribute, Cell, Color, ContentArrangement, Table, presets::UTF8_FULL};
use std::io::Write;
use std::str::FromStr;

/// Output format for results
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    /// Human-readable table output
    #[default]
    Human,
    /// JSON output
    Json,
    /// CSV: one row per finding, and per component without findings
    Csv,
    /// Markdown report for people
    Markdown,
    /// DefectDojo Generic Findings Import JSON
    DefectDojo,
    /// No output (silent mode)
    None,
}

impl FromStr for OutputFormat {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "human" => Ok(Self::Human),
            "json" => Ok(Self::Json),
            "csv" => Ok(Self::Csv),
            "markdown" | "md" => Ok(Self::Markdown),
            "defectdojo" => Ok(Self::DefectDojo),
            "none" => Ok(Self::None),
            _ => Err(Error::InvalidOutputFormat(s.to_string())),
        }
    }
}

/// Configuration for output formatting
#[derive(Debug, Clone)]
pub struct OutputConfig {
    /// Output format
    pub format: OutputFormat,
    /// Minimum severity to display
    pub min_severity: Severity,
    /// Use ANSI colors in human output (turn off when not writing to a
    /// terminal, or when NO_COLOR is set)
    pub color: bool,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: OutputFormat::Human,
            min_severity: Severity::Low,
            color: true,
        }
    }
}

impl OutputConfig {
    /// Create a new output config
    pub fn new(format: OutputFormat, min_severity: Severity) -> Self {
        Self {
            format,
            min_severity,
            color: true,
        }
    }

    /// Turn colors on or off
    pub fn with_color(mut self, color: bool) -> Self {
        self.color = color;
        self
    }
}

/// Output the analysis results
pub fn output_analysis<W: Write>(
    analysis: &Analysis,
    config: &OutputConfig,
    writer: &mut W,
) -> Result<()> {
    match config.format {
        OutputFormat::Human => output_human(analysis, config, writer),
        OutputFormat::Json => output_json(analysis, writer),
        OutputFormat::Csv => crate::report::write_csv(analysis, config.min_severity, writer),
        OutputFormat::Markdown => {
            crate::report::write_markdown(analysis, config.min_severity, writer)
        }
        OutputFormat::DefectDojo => {
            crate::report::write_defectdojo(analysis, config.min_severity, writer)
        }
        OutputFormat::None => Ok(()),
    }
}

/// Output JSON format
fn output_json<W: Write>(analysis: &Analysis, writer: &mut W) -> Result<()> {
    serde_json::to_writer_pretty(&mut *writer, analysis)?;
    writeln!(writer)?;
    Ok(())
}

/// Output human-readable format
fn output_human<W: Write>(
    analysis: &Analysis,
    config: &OutputConfig,
    writer: &mut W,
) -> Result<()> {
    // Print target URL if available
    if let Some(ref url) = analysis.url {
        writeln!(writer, "Target: {}", url)?;
        writeln!(writer)?;
    }

    let summary = &analysis.summary;
    // Check if any vulnerabilities found
    if !summary.has_any() {
        if summary.not_checked == 0 {
            writeln!(writer, "No vulnerabilities found.")?;
            if !analysis.warnings.is_empty() {
                writeln!(writer)?;
                write_warnings(analysis, config.color, writer)?;
            }
            return Ok(());
        }
        writeln!(
            writer,
            "No vulnerabilities found in the {} components that could be checked.\n",
            analysis.components.len() - summary.not_checked
        )?;
        write_not_checked(analysis, config.color, writer)?;
        write_warnings(analysis, config.color, writer)?;
        write_summary(analysis, writer)?;
        return Ok(());
    }

    // Group and display by severity (highest first)
    let severities = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
    ];

    for severity in severities {
        if severity < config.min_severity {
            continue;
        }

        let components: Vec<_> = analysis
            .components
            .iter()
            .filter(|c| c.vulnerabilities.iter().any(|v| v.severity == severity))
            .collect();

        if components.is_empty() {
            continue;
        }

        let count: usize = components
            .iter()
            .map(|c| {
                c.vulnerabilities
                    .iter()
                    .filter(|v| v.severity == severity)
                    .count()
            })
            .sum();

        // Severity header
        let header = format!("{} ({})", severity.to_string().to_uppercase(), count);
        let header_color = severity_color(severity);
        writeln!(writer, "{}", colorize(&header, header_color, config.color))?;

        // Build table for this severity level
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec![
                Cell::new("Component").add_attribute(Attribute::Bold),
                Cell::new("Version").add_attribute(Attribute::Bold),
                Cell::new("Vulnerability").add_attribute(Attribute::Bold),
                Cell::new("Fixed").add_attribute(Attribute::Bold),
            ]);

        for component in &components {
            for vuln in component
                .vulnerabilities
                .iter()
                .filter(|v| v.severity == severity)
            {
                add_vulnerability_row(&mut table, component, vuln);
            }
        }

        writeln!(writer, "{}", table)?;
        writeln!(writer)?;
    }

    write_alias_notes(analysis, config.color, writer)?;
    write_not_checked(analysis, config.color, writer)?;
    write_warnings(analysis, config.color, writer)?;
    write_summary(analysis, writer)?;
    Ok(())
}

/// Name of a component as shown in reports: installed slug, plus what it
/// was looked up as when that differs
fn display_name(c: &ComponentVulnerabilities) -> String {
    let base = match (c.component_type, c.installed_as.as_deref()) {
        (crate::scanner::ComponentType::Core, _) => "WordPress".to_string(),
        (_, Some(installed)) => format!("{installed} (as {})", c.slug),
        (_, None) => c.slug.clone(),
    };
    match c.component_type {
        crate::scanner::ComponentType::Theme => format!("Theme: {base}"),
        _ => base,
    }
}

/// Findings that came through an alias need a human to confirm them
fn write_alias_notes<W: Write>(analysis: &Analysis, color: bool, writer: &mut W) -> Result<()> {
    let via_alias: Vec<_> = analysis
        .components
        .iter()
        .filter(|c| c.state == ComponentState::AliasMatch)
        .collect();
    if via_alias.is_empty() {
        return Ok(());
    }
    writeln!(
        writer,
        "{}",
        colorize(
            "Found through an alias, confirm before acting",
            Color::Yellow,
            color
        )
    )?;
    for c in via_alias {
        writeln!(
            writer,
            "  {} {}: premium editions may number versions differently",
            display_name(c),
            c.version.as_deref().unwrap_or("-")
        )?;
    }
    writeln!(writer)?;
    Ok(())
}

/// Everything that was not compared with any data, grouped by why: these
/// are neither safe nor vulnerable as far as this scan knows
fn write_not_checked<W: Write>(analysis: &Analysis, color: bool, writer: &mut W) -> Result<()> {
    if analysis.summary.not_checked == 0 {
        return Ok(());
    }
    writeln!(
        writer,
        "{}",
        colorize(
            &format!(
                "NOT CHECKED ({}): not known to be safe, review by hand",
                analysis.summary.not_checked
            ),
            Color::Yellow,
            color
        )
    )?;
    let with_version = |c: &ComponentVulnerabilities| {
        format!(
            "{} {}",
            display_name(c),
            c.version.as_deref().unwrap_or("(no version)")
        )
    };

    // Unchecked only because of the name: the fix is one line in aliases.toml
    let renamed: Vec<_> = analysis
        .components
        .iter()
        .filter(|c| c.suggested_alias.is_some())
        .collect();
    if !renamed.is_empty() {
        writeln!(
            writer,
            "  probably a naming problem ({}): the database tracks these under another slug; \
             if they are the same, add the lines to aliases.toml",
            renamed.len()
        )?;
        for c in &renamed {
            let table = match c.component_type {
                crate::scanner::ComponentType::Theme => "theme",
                _ => "plugin",
            };
            writeln!(
                writer,
                "    {:<44} \"{}\" = \"{}\"   (in [{table}])",
                with_version(c),
                c.slug,
                c.suggested_alias.as_deref().unwrap_or_default()
            )?;
        }
    }

    let mut name_hints = !renamed.is_empty();
    for (state, why) in [
        (
            ComponentState::Untracked,
            "the data source has no entry (common for premium and custom code)",
        ),
        (
            ComponentState::NotInDb,
            "never pulled into the local database; run `db pull` with the same inputs",
        ),
        (
            ComponentState::UnknownVersion,
            "no version could be read, so ranges cannot be compared",
        ),
        (
            ComponentState::Failed,
            "the lookup failed; run the scan again",
        ),
        (
            ComponentState::NotLookedUp,
            "not wordpress.org plugins, so no database is asked by name; review them by hand",
        ),
    ] {
        let hits: Vec<_> = analysis
            .components
            .iter()
            .filter(|c| c.state == state && c.suggested_alias.is_none())
            .collect();
        if hits.is_empty() {
            continue;
        }
        writeln!(writer, "  {} ({}): {why}", state.label(), hits.len())?;
        for c in hits {
            let looks_renamed = c
                .note
                .as_deref()
                .is_some_and(|n| n.contains("looks like a renamed"));
            name_hints |= looks_renamed;
            let detail = match state {
                ComponentState::UnknownVersion
                | ComponentState::Failed
                | ComponentState::NotLookedUp => c.note.clone(),
                _ if looks_renamed => c
                    .note
                    .as_deref()
                    .and_then(|n| n.split_once("; the name "))
                    .map(|(_, rest)| format!("the name {rest}")),
                _ => None,
            };
            match detail {
                Some(d) => writeln!(writer, "    {}: {d}", with_version(c))?,
                None => writeln!(writer, "    {}", with_version(c))?,
            }
        }
    }
    if name_hints {
        writeln!(
            writer,
            "  To find the right slugs for renamed or premium copies in one go:\n    \
             wordpress-vulnerable-scanner aliases suggest <inventory.json> --db <db> --online"
        )?;
    }
    writeln!(writer)?;
    Ok(())
}

/// Problems with the scan's own setup, numbered and wrapped
fn write_warnings<W: Write>(analysis: &Analysis, color: bool, writer: &mut W) -> Result<()> {
    if analysis.warnings.is_empty() {
        return Ok(());
    }
    writeln!(
        writer,
        "{}",
        colorize(
            &format!("WARNINGS ({})", analysis.warnings.len()),
            Color::Yellow,
            color
        )
    )?;
    let digits = analysis.warnings.len().to_string().len();
    let indent = " ".repeat(digits + 4);
    for (i, w) in analysis.warnings.iter().enumerate() {
        writeln!(
            writer,
            "  {:>digits$}. {}",
            i + 1,
            wrap(w, 96 - indent.len()).join(&format!("\n{indent}"))
        )?;
    }
    writeln!(writer)?;
    Ok(())
}

/// Greedy word wrap for terminal messages
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = vec![String::new()];
    for word in text.split_whitespace() {
        let line = lines.last_mut().expect("never empty");
        if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > width {
            lines.push(word.to_string());
        } else {
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(word);
        }
    }
    lines
}

fn write_summary<W: Write>(analysis: &Analysis, writer: &mut W) -> Result<()> {
    let s = &analysis.summary;
    let n = &s.components;
    writeln!(
        writer,
        "Summary: {} Critical, {} High, {} Medium, {} Low; {} components: {} vulnerable, {} clean, {} not checked",
        s.critical,
        s.high,
        s.medium,
        s.low,
        analysis.components.len(),
        n.vulnerable + n.alias_match,
        n.clean,
        s.not_checked
    )?;
    if !s.not_checked_by.is_empty() {
        let per: Vec<String> = s
            .not_checked_by
            .iter()
            .map(|(source, n)| format!("{} had no data for {n}", source_name(*source)))
            .collect();
        writeln!(
            writer,
            "Sources: {} (a component counts as not checked only when no source had data)",
            per.join(", ")
        )?;
    }
    write_sources(analysis, writer)?;
    Ok(())
}

/// Which sources the scan used, and the attribution their licenses require
fn write_sources<W: Write>(analysis: &Analysis, writer: &mut W) -> Result<()> {
    let used: Vec<String> = analysis
        .sources
        .iter()
        .map(|s| format!("{} ({})", source_name(s.source), s.detail))
        .collect();
    if analysis.sources.iter().any(|s| s.attribution.is_some()) {
        writeln!(writer, "Data: {}", used.join("; "))?;
        for s in &analysis.sources {
            if let Some(ref a) = s.attribution {
                writeln!(writer, "{a}")?;
            }
        }
    }
    Ok(())
}

/// Add a row for a vulnerability
fn add_vulnerability_row(
    table: &mut Table,
    component: &ComponentVulnerabilities,
    vuln: &crate::vulnerability::Vulnerability,
) {
    let component_name = display_name(component);

    let version = component.version.as_deref().unwrap_or("-");

    let title = truncate_title(&vuln.title);

    let vuln_desc = format!("{}: {}", vuln.id, title);

    let fixed = match (vuln.fixed_in.as_deref(), vuln.affected_max.as_deref()) {
        _ if vuln.unfixed => "no fix yet".to_string(),
        (Some(f), _) => format!(">={}", f), // "< X": X is the first fixed version
        (None, Some(m)) => format!(">{}", m), // "<= X": fixed after X
        _ => "-".to_string(),
    };

    table.add_row(vec![
        Cell::new(component_name),
        Cell::new(version),
        Cell::new(vuln_desc),
        Cell::new(fixed),
    ]);
}

/// Get color for severity level
fn severity_color(severity: Severity) -> Color {
    match severity {
        Severity::Critical => Color::Red,
        Severity::High => Color::Red,
        Severity::Medium => Color::Yellow,
        Severity::Low => Color::DarkYellow,
    }
}

/// Maximum title length before truncation
const MAX_TITLE_LENGTH: usize = 40;

/// Truncate title if too long, adding ellipsis
fn truncate_title(title: &str) -> String {
    // count characters, not bytes, so Persian/CJK titles don't panic
    if title.chars().count() > MAX_TITLE_LENGTH {
        let cut: String = title.chars().take(MAX_TITLE_LENGTH - 3).collect();
        format!("{}...", cut)
    } else {
        title.to_string()
    }
}

/// Apply ANSI color to text
fn colorize(text: &str, color: Color, enabled: bool) -> String {
    if !enabled {
        return text.to_string();
    }
    let code = match color {
        Color::Red => "31",
        Color::Yellow => "33",
        Color::DarkYellow => "33",
        Color::Green => "32",
        _ => "0",
    };
    format!("\x1b[{}m{}\x1b[0m", code, text)
}
