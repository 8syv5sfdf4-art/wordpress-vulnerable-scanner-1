//! DefectDojo settings from a `.env` file and the import manifest written
//! next to the reports.
//!
//! Uploading is a separate step: this module only reads and validates the
//! settings, and describes what is to be imported. The API key is wrapped in
//! [`Secret`], which never prints or serializes its value, so it cannot end
//! up in a log or in the manifest by accident.

use std::collections::HashMap;
use std::path::Path;

use serde::Serialize;

use crate::error::{Error, Result};

/// Import type name DefectDojo uses for the report files this tool writes
pub const SCAN_TYPE: &str = "Generic Findings Import";

/// Every setting this module reads
const KEYS: [&str; 6] = [
    "DEFECTDOJO_URL",
    "DEFECTDOJO_API_KEY",
    "DEFECTDOJO_PRODUCT",
    "DEFECTDOJO_PRODUCT_TYPE",
    "DEFECTDOJO_ENGAGEMENT",
    "DEFECTDOJO_TEST_TITLE_PREFIX",
];

/// A value that must not be shown; `Debug` prints a placeholder and there is
/// no `Serialize`
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// The value, for the one place that sends it (the upload step)
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Parse the text of a `.env` file into `KEY=VALUE` pairs.
///
/// Understands a leading BOM, blank lines, `#` comments, an optional
/// `export` prefix, and values in single or double quotes. A quoted value
/// ends at the closing quote and takes no escapes; only whitespace or a
/// comment may follow it. An unquoted value ends at a `#` that starts the
/// value or follows whitespace, so `KEY= # note` is empty and a URL with
/// `#fragment` is kept. Errors name the line number only, never its
/// content, since it may hold a secret.
pub fn parse_env(text: &str) -> Result<Vec<(String, String)>> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let n = i + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = match line.strip_prefix("export") {
            Some(rest) if rest.starts_with(char::is_whitespace) => rest.trim_start(),
            _ => line,
        };
        let Some((key, value)) = line.split_once('=') else {
            return Err(Error::Config(format!("line {n}: expected KEY=VALUE")));
        };
        let key = key.trim();
        let valid = key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && !key.starts_with(|c: char| c.is_ascii_digit());
        if key.is_empty() || !valid {
            return Err(Error::Config(format!("line {n}: invalid variable name")));
        }
        let value = value.trim_start();
        let value = match value.chars().next() {
            Some(q @ ('"' | '\'')) => {
                let inner = &value[1..];
                let Some(end) = inner.find(q) else {
                    return Err(Error::Config(format!("line {n}: unterminated quote")));
                };
                let rest = inner[end + 1..].trim_start();
                if !rest.is_empty() && !rest.starts_with('#') {
                    return Err(Error::Config(format!(
                        "line {n}: unexpected text after the closing quote (quoted values \
                         have no escapes)"
                    )));
                }
                inner[..end].to_string()
            }
            _ => {
                let mut end = value.len();
                let mut prev_space = true;
                for (idx, c) in value.char_indices() {
                    if c == '#' && prev_space {
                        end = idx;
                        break;
                    }
                    prev_space = c.is_whitespace();
                }
                value[..end].trim_end().to_string()
            }
        };
        out.push((key.to_string(), value));
    }
    Ok(out)
}

/// Read a `.env` file. A missing file is an empty result unless `required`
/// (the user named it explicitly). When a key repeats, the last one wins.
pub fn read_env_file(path: &Path, required: bool) -> Result<HashMap<String, String>> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !required => {
            return Ok(HashMap::new());
        }
        Err(e) => {
            return Err(Error::Config(format!("{}: {e}", path.display())));
        }
    };
    match parse_env(&text) {
        Ok(pairs) => Ok(pairs.into_iter().collect()),
        Err(Error::Config(m)) => Err(Error::Config(format!("{}: {m}", path.display()))),
        Err(e) => Err(e),
    }
}

/// DefectDojo connection and import settings
#[derive(Debug, Clone)]
pub struct DojoConfig {
    /// Base URL of the DefectDojo instance (`DEFECTDOJO_URL`)
    pub url: Option<String>,
    /// API v2 token (`DEFECTDOJO_API_KEY`)
    pub api_key: Option<Secret>,
    /// Product the findings belong to (`DEFECTDOJO_PRODUCT`)
    pub product: String,
    /// Product type, used when the product has to be created
    /// (`DEFECTDOJO_PRODUCT_TYPE`)
    pub product_type: String,
    /// Engagement to import into (`DEFECTDOJO_ENGAGEMENT`)
    pub engagement: String,
    /// Prepended to each test title (`DEFECTDOJO_TEST_TITLE_PREFIX`)
    pub test_title_prefix: String,
}

impl DojoConfig {
    /// Build the settings from a lookup (environment first, then the file;
    /// see [`DojoConfig::load`]). `site` names the product when
    /// `DEFECTDOJO_PRODUCT` is unset, `date` the default engagement.
    pub fn from_lookup(
        get: impl Fn(&str) -> Option<String>,
        site: &str,
        date: &str,
    ) -> Result<Self> {
        let value = |k: &str| {
            get(k)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let url = match value("DEFECTDOJO_URL") {
            Some(u) => {
                let parsed = url::Url::parse(&u).map_err(|e| {
                    Error::Config(format!("DEFECTDOJO_URL is not a valid URL: {e}"))
                })?;
                if !matches!(parsed.scheme(), "http" | "https") || parsed.host().is_none() {
                    return Err(Error::Config(
                        "DEFECTDOJO_URL must be an http:// or https:// URL".into(),
                    ));
                }
                // The URL goes into the manifest, which must hold no secrets
                if !parsed.username().is_empty() || parsed.password().is_some() {
                    return Err(Error::Config(
                        "DEFECTDOJO_URL must not contain a user name or password; the token \
                         belongs in DEFECTDOJO_API_KEY"
                            .into(),
                    ));
                }
                if parsed.query().is_some() || parsed.fragment().is_some() {
                    return Err(Error::Config(
                        "DEFECTDOJO_URL must be the base URL of the instance, without a \
                         query or fragment"
                            .into(),
                    ));
                }
                Some(parsed.as_str().trim_end_matches('/').to_string())
            }
            None => None,
        };
        let product = value("DEFECTDOJO_PRODUCT").unwrap_or_else(|| site.to_string());
        Ok(DojoConfig {
            url,
            api_key: value("DEFECTDOJO_API_KEY").map(Secret),
            engagement: value("DEFECTDOJO_ENGAGEMENT")
                .unwrap_or_else(|| format!("{product} audit {date}")),
            product,
            product_type: value("DEFECTDOJO_PRODUCT_TYPE")
                .unwrap_or_else(|| "Web Application".to_string()),
            test_title_prefix: get("DEFECTDOJO_TEST_TITLE_PREFIX").unwrap_or_default(),
        })
    }

    /// Settings from the process environment and a `.env` file, the
    /// environment winning. A variable that is set but empty counts as unset,
    /// so the file's value is used.
    pub fn load(env_file: &Path, required: bool, site: &str, date: &str) -> Result<Self> {
        for key in KEYS {
            if let Some(v) = std::env::var_os(key)
                && v.to_str().is_none()
            {
                return Err(Error::Config(format!("{key} is not valid UTF-8")));
            }
        }
        Self::load_with(|k| std::env::var(k).ok(), env_file, required, site, date)
    }

    /// [`DojoConfig::load`] with the environment passed in, for tests
    pub fn load_with(
        env: impl Fn(&str) -> Option<String>,
        env_file: &Path,
        required: bool,
        site: &str,
        date: &str,
    ) -> Result<Self> {
        let file = read_env_file(env_file, required)?;
        Self::from_lookup(
            |k| {
                env(k)
                    .filter(|v| !v.trim().is_empty())
                    .or_else(|| file.get(k).cloned())
            },
            site,
            date,
        )
    }

    /// Names of the settings an upload needs and this configuration lacks
    pub fn missing_for_upload(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if self.url.is_none() {
            missing.push("DEFECTDOJO_URL");
        }
        if self.api_key.is_none() {
            missing.push("DEFECTDOJO_API_KEY");
        }
        missing
    }

    /// Title of the DefectDojo test one part is imported as. It names the
    /// sources the findings came from (`wordfence-api+wpvulnerability`): a run
    /// with fewer sources lands in a different test, so it can never close
    /// findings that only another source knew.
    pub fn test_title(&self, part: &str, sources: &str) -> String {
        format!(
            "{}{} WordPress {part} ({sources})",
            self.test_title_prefix, self.product
        )
    }
}

/// One report file in the manifest
#[derive(Debug, Clone, Serialize)]
pub struct ManifestFile {
    /// `core`, `themes` or `plugins`
    pub part: String,
    /// File name, relative to the manifest
    pub file: String,
    /// Title of the DefectDojo test this file is imported as
    pub test_title: String,
    /// Findings in the file (not-checked Info findings included)
    pub findings: usize,
    /// False when something that belongs in this file could not be put
    /// there; see `incomplete_because`
    pub complete: bool,
    /// Why the file may be missing findings
    pub incomplete_because: Vec<String>,
}

/// A part that has no file, and why
#[derive(Debug, Clone, Serialize)]
pub struct SkippedPart {
    /// `core`, `themes` or `plugins`
    pub part: String,
    /// Why nothing was written for it
    pub reason: String,
}

/// The manifest the upload step reads: what to import and where. It never
/// contains the API key.
///
/// `complete` is false when `incomplete_because` has any entry: a folder
/// that could not be read, or components whose lookup failed or was never
/// pulled, whose real findings are therefore absent from the files. An
/// upload must not close old findings on the strength of their absence.
/// `inventory_warnings` is advice (leftovers, missing headers) and does
/// not change `complete`.
pub fn manifest(
    cfg: &DojoConfig,
    scan_date: &str,
    files: Vec<ManifestFile>,
    skipped: Vec<SkippedPart>,
    inventory_warnings: &[String],
    incomplete_because: &[String],
    sources: &[String],
) -> serde_json::Value {
    let missing = cfg.missing_for_upload();
    serde_json::json!({
        "scan_type": SCAN_TYPE,
        "scan_date": scan_date,
        "url": cfg.url,
        "product": cfg.product,
        "product_type": cfg.product_type,
        "engagement": cfg.engagement,
        "upload_ready": missing.is_empty(),
        "missing_settings": missing,
        "complete": incomplete_because.is_empty(),
        "incomplete_because": incomplete_because,
        "inventory_warnings": inventory_warnings,
        "sources": sources,
        "files": files,
        "skipped": skipped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get(pairs: &[(String, String)], k: &str) -> Option<String> {
        pairs
            .iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.clone())
    }

    fn config(url: &str) -> Result<DojoConfig> {
        let url = url.to_string();
        DojoConfig::from_lookup(
            move |k| (k == "DEFECTDOJO_URL").then(|| url.clone()),
            "s",
            "d",
        )
    }

    #[test]
    fn parses_comments_quotes_and_export() {
        let pairs = parse_env(
            "# comment\n\nA=1\nexport B = two # trailing\nC=\"x # y\"\nD='q'\nE=\n\
             F=\"v\" # note\nexport\tG=g\n",
        )
        .unwrap();
        assert_eq!(get(&pairs, "A").as_deref(), Some("1"));
        assert_eq!(get(&pairs, "B").as_deref(), Some("two"));
        assert_eq!(get(&pairs, "C").as_deref(), Some("x # y"));
        assert_eq!(get(&pairs, "D").as_deref(), Some("q"));
        assert_eq!(get(&pairs, "E").as_deref(), Some(""));
        assert_eq!(get(&pairs, "F").as_deref(), Some("v"));
        assert_eq!(get(&pairs, "G").as_deref(), Some("g"));
    }

    #[test]
    fn a_comment_after_an_empty_value_is_not_the_value() {
        let pairs = parse_env("K= # paste the key here\nT=x\t# c\nU=\t#c\n").unwrap();
        assert_eq!(get(&pairs, "K").as_deref(), Some(""));
        assert_eq!(get(&pairs, "T").as_deref(), Some("x"));
        assert_eq!(get(&pairs, "U").as_deref(), Some(""));
    }

    #[test]
    fn hash_without_whitespace_before_it_stays_in_the_value() {
        let pairs = parse_env("U=https://h/p#frag\nP=pa#ss\nV=a=b=c\n").unwrap();
        assert_eq!(get(&pairs, "U").as_deref(), Some("https://h/p#frag"));
        assert_eq!(get(&pairs, "P").as_deref(), Some("pa#ss"));
        assert_eq!(get(&pairs, "V").as_deref(), Some("a=b=c"));
    }

    #[test]
    fn bom_and_crlf_are_handled() {
        let pairs = parse_env("\u{feff}# c\r\nA=1\r\nB=\"2\"\r\n").unwrap();
        assert_eq!(get(&pairs, "A").as_deref(), Some("1"));
        assert_eq!(get(&pairs, "B").as_deref(), Some("2"));
        let pairs = parse_env("\u{feff}A=1\n").unwrap();
        assert_eq!(get(&pairs, "A").as_deref(), Some("1"));
    }

    #[test]
    fn quoted_values_allow_only_a_comment_after_them() {
        let e = parse_env("A=\"abc\"def\n").unwrap_err().to_string();
        assert!(e.contains("line 1"), "{e}");
        assert!(!e.contains("abc") && !e.contains("def"), "{e}");
        assert!(parse_env("A=\"a\\\"b\"\n").is_err());
        let pairs = parse_env("A='x#y'\n").unwrap();
        assert_eq!(get(&pairs, "A").as_deref(), Some("x#y"));
    }

    #[test]
    fn errors_name_the_line_but_never_the_content() {
        for bad in [
            "OK=1\nsecret-without-equals-token\n",
            "K=\"s3cret-token\n",
            "bad s3cret-key=1\n",
            "1S3CRET=x\n",
        ] {
            let text = parse_env(bad).unwrap_err().to_string();
            assert!(text.contains("line "), "{text}");
            assert!(!text.to_lowercase().contains("s3cret"), "{text}");
        }
    }

    #[test]
    fn the_last_duplicate_wins() {
        let file = std::env::temp_dir().join(format!("wvs-dojo-dup-{}", std::process::id()));
        std::fs::write(&file, "A=1\nA=2\n").unwrap();
        let m = read_env_file(&file, true).unwrap();
        assert_eq!(m.get("A").map(String::as_str), Some("2"));
        let _ = std::fs::remove_file(&file);
    }

    #[test]
    fn load_prefers_the_environment_and_skips_empty_values() {
        let file = std::env::temp_dir().join(format!("wvs-dojo-load-{}", std::process::id()));
        std::fs::write(
            &file,
            "DEFECTDOJO_URL=https://file.example\nDEFECTDOJO_PRODUCT=from-file\n\
             DEFECTDOJO_API_KEY=file-key\n",
        )
        .unwrap();
        let env: HashMap<&str, &str> = [
            ("DEFECTDOJO_URL", "https://env.example/"),
            ("DEFECTDOJO_API_KEY", ""),
        ]
        .into();
        let cfg = DojoConfig::load_with(
            |k| env.get(k).map(|v| v.to_string()),
            &file,
            true,
            "site",
            "2026-10-11",
        )
        .unwrap();
        assert_eq!(cfg.url.as_deref(), Some("https://env.example"));
        assert_eq!(cfg.product, "from-file");
        // an exported but empty variable does not hide the file's value
        assert_eq!(cfg.api_key.as_ref().map(Secret::expose), Some("file-key"));
        assert_eq!(cfg.engagement, "from-file audit 2026-10-11");
        let _ = std::fs::remove_file(&file);
    }

    #[test]
    fn defaults_and_validation() {
        let cfg = DojoConfig::from_lookup(|_| None, "mysite", "2026-10-11").unwrap();
        assert_eq!(cfg.product, "mysite");
        assert_eq!(
            cfg.missing_for_upload(),
            vec!["DEFECTDOJO_URL", "DEFECTDOJO_API_KEY"]
        );
        assert!(config("ftp://x").is_err());
        assert!(config("not a url").is_err());
    }

    #[test]
    fn url_must_be_a_plain_base_url_and_is_normalised() {
        assert!(config("https://admin:hunter2@dojo.example/").is_err());
        assert!(config("https://:hunter2@dojo.example/").is_err());
        assert!(config("https://dojo.example/?token=abc").is_err());
        assert!(config("https://dojo.example/#x").is_err());
        let e = config("https://admin:hunter2@dojo.example/")
            .unwrap_err()
            .to_string();
        assert!(!e.contains("hunter2"), "{e}");
        assert_eq!(
            config("https://dojo.example/base/").unwrap().url.as_deref(),
            Some("https://dojo.example/base")
        );
        assert_eq!(
            config("http:/dojo.example").unwrap().url.as_deref(),
            Some("http://dojo.example")
        );
    }

    #[test]
    fn key_is_never_printed_or_in_the_manifest() {
        let cfg = DojoConfig::from_lookup(
            |k| match k {
                "DEFECTDOJO_URL" => Some("https://dojo.example".into()),
                "DEFECTDOJO_API_KEY" => Some("s3cret-token".into()),
                _ => None,
            },
            "site",
            "2026-10-11",
        )
        .unwrap();
        assert!(!format!("{cfg:?}").contains("s3cret-token"));
        assert!(!format!("{:?}", cfg.api_key).contains("s3cret-token"));
        assert!(cfg.missing_for_upload().is_empty());
        let m = manifest(
            &cfg,
            "2026-10-11T00:00:00Z",
            vec![ManifestFile {
                part: "core".into(),
                file: "defectdojo-core.json".into(),
                test_title: cfg.test_title("core", "wpvulnerability"),
                findings: 3,
                complete: true,
                incomplete_because: Vec::new(),
            }],
            Vec::new(),
            &[],
            &[],
            &[],
        );
        let text = m.to_string();
        assert!(!text.contains("s3cret-token"), "{text}");
        assert_eq!(m["upload_ready"], true);
        assert_eq!(m["complete"], true);
        assert_eq!(
            m["files"][0]["test_title"],
            "site WordPress core (wpvulnerability)"
        );
    }

    #[test]
    fn missing_file_is_fine_unless_required() {
        let p = Path::new("/nonexistent/.env");
        assert!(read_env_file(p, false).unwrap().is_empty());
        match read_env_file(p, true) {
            Err(Error::Config(m)) => assert!(m.contains("/nonexistent/.env"), "{m}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn file_errors_name_the_file_once() {
        let file = std::env::temp_dir().join(format!("wvs-dojo-bad-{}", std::process::id()));
        std::fs::write(&file, "nonsense\n").unwrap();
        let e = read_env_file(&file, true).unwrap_err().to_string();
        assert_eq!(e.matches("configuration:").count(), 1, "{e}");
        assert!(e.contains("line 1"), "{e}");
        let _ = std::fs::remove_file(&file);
    }
}
