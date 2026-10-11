//! `audit`: the whole pipeline against a mock API, through the binary.

use std::path::{Path, PathBuf};
use std::process::Command;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const KEY: &str = "tok-s3cret-for-the-test";

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("wvs-audit-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn record(entries: &str) -> String {
    format!(r#"{{"error":0,"message":null,"data":{{"name":"x","vulnerability":[{entries}]}}}}"#)
}

const CORE_VULN: &str = r#"
 {"uuid":"core-1","name":"WordPress < 6.7 - SQL Injection",
  "operator":{"max_version":"6.7","max_operator":"lt"},
  "source":[{"id":"CVE-2026-0001","link":"https://example.org/core"}],
  "impact":{"cvss":{"score":"9.8","vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
            "cwe":[{"cwe":"CWE-89","name":"SQL Injection"}]}}"#;

const PLUGIN_VULN: &str = r#"
 {"uuid":"plug-1","name":"Akismet < 6.0 - XSS",
  "operator":{"max_version":"6.0","max_operator":"lt"},
  "source":[{"id":"CVE-2026-0002"}],
  "impact":{"cvss":{"score":"6.1"},"cwe":[{"cwe":"CWE-79","name":"XSS"}]}}"#;

async fn mount(server: &MockServer, p: &str, status: u16, body: &str) {
    Mock::given(method("GET"))
        .and(path(p))
        .respond_with(ResponseTemplate::new(status).set_body_string(body))
        .mount(server)
        .await;
}

/// Run the binary in an empty folder (so no stray .env or wpvuln-db is
/// picked up) with every setting it reads from the environment removed
fn run(args: Vec<String>) -> std::process::Output {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let cwd = temp(&format!(
        "cwd-{}",
        N.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_wordpress-vulnerable-scanner"));
    cmd.args(args).current_dir(&cwd);
    for var in [
        "WPVULN_DB",
        "WPVULN_API",
        "WPVULN_ALIASES",
        "WPVULN_WORDFENCE",
        "WORDFENCE_API_KEY",
        "DEFECTDOJO_URL",
        "DEFECTDOJO_API_KEY",
        "DEFECTDOJO_PRODUCT",
        "DEFECTDOJO_PRODUCT_TYPE",
        "DEFECTDOJO_ENGAGEMENT",
        "DEFECTDOJO_TEST_TITLE_PREFIX",
    ] {
        cmd.env_remove(var);
    }
    let output = cmd.output().unwrap();
    let _ = std::fs::remove_dir_all(&cwd);
    output
}

fn read_json(p: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

#[tokio::test]
async fn audit_writes_one_defectdojo_file_per_part() {
    let server = MockServer::start().await;
    mount(&server, "/core/6.6.2/", 200, &record(CORE_VULN)).await;
    mount(&server, "/plugin/akismet/", 200, &record(PLUGIN_VULN)).await;
    // everything else (themes, other plugins) is untracked
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let work = temp("parts");
    let env_file = work.join("test.env");
    std::fs::write(
        &env_file,
        format!("DEFECTDOJO_URL=https://dojo.example\nDEFECTDOJO_API_KEY={KEY}\n"),
    )
    .unwrap();
    let site = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wp");
    let out = work.join("out");
    let args: Vec<String> = [
        "audit",
        site.to_str().unwrap(),
        "--db",
        work.join("db").to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--api-url",
        &server.uri(),
        "--no-wordfence",
        "--env",
        env_file.to_str().unwrap(),
    ]
    .map(String::from)
    .to_vec();

    // twice into the same folder: the second run must replace, not mix
    for _ in 0..2 {
        let a = args.clone();
        let output = tokio::task::spawn_blocking(move || run(a)).await.unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(
            output.status.code(),
            Some(2),
            "critical core vulnerability exits 2\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(stdout.contains("[4/4] Reports"), "{stdout}");
    }

    // offline: same database, a dead API address, identical findings
    let before = read_json(&out.join("defectdojo-core.json"));
    let mut offline = args.clone();
    // point the API at a dead address (replacing, not repeating, the flag:
    // clap rejects a repeated flag with exit code 2, the same code as a
    // critical finding)
    let at = offline.iter().position(|a| a == "--api-url").unwrap();
    offline[at + 1] = "http://127.0.0.1:1".to_string();
    offline.extend(["--offline".to_string(), "--max-age".into(), "0".into()]);
    let output = tokio::task::spawn_blocking(move || run(offline))
        .await
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    // --max-age 0 would download everything, so "Pulling" proves it went online
    assert!(
        stdout.contains("offline: using"),
        "{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!stdout.contains("Pulling"), "{stdout}");
    assert!(stdout.contains("[4/4] Reports"), "{stdout}");
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(read_json(&out.join("defectdojo-core.json")), before);

    let core = read_json(&out.join("defectdojo-core.json"));
    let findings = core["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "{core}");
    assert_eq!(findings[0]["cwe"], 89);
    assert_eq!(findings[0]["cve"], "CVE-2026-0001");
    assert!(findings[0]["tags"].to_string().contains("core"));

    let plugins = read_json(&out.join("defectdojo-plugins.json"));
    let text = plugins.to_string();
    assert!(text.contains("CVE-2026-0002"), "{text}");
    assert!(
        !text.contains("CVE-2026-0001"),
        "core finding leaked into plugins"
    );
    // not-checked components stay visible as Info findings
    assert!(text.contains("not-checked"), "{text}");

    let themes = read_json(&out.join("defectdojo-themes.json"));
    assert!(!themes.to_string().contains("CVE-2026"), "{themes}");

    let manifest = read_json(&out.join("dojo-manifest.json"));
    assert_eq!(manifest["upload_ready"], true);
    assert_eq!(manifest["url"], "https://dojo.example");
    assert_eq!(manifest["files"].as_array().unwrap().len(), 3);
    // every lookup was answered (untracked is an answer), so nothing is
    // missing from the files
    assert_eq!(manifest["complete"], true, "{manifest}");

    // Wordfence enabled (the default) but no feed stored: the files must say
    // they may lack findings only Wordfence knows
    let mut with_wf: Vec<String> = args
        .iter()
        .filter(|a| *a != "--no-wordfence")
        .cloned()
        .collect();
    with_wf.push("--offline".to_string());
    let output = tokio::task::spawn_blocking(move || run(with_wf))
        .await
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let m = read_json(&out.join("dojo-manifest.json"));
    assert_eq!(m["complete"], false, "{m}");
    assert!(
        m["incomplete_because"]
            .to_string()
            .contains("no feed is stored"),
        "{m}"
    );
    assert!(
        m["files"][0]["test_title"]
            .as_str()
            .unwrap()
            .ends_with("(wpvulnerability)"),
        "{m}"
    );

    // a record changed on disk after it was pulled: the checksum no longer
    // matches, so the files may be wrong and must say so, online (the fresh
    // record is not downloaded again) and offline alike
    let record = work.join("db/plugin/akismet.json");
    let mut bytes = std::fs::read(&record).unwrap();
    bytes.extend_from_slice(b" ");
    std::fs::write(&record, bytes).unwrap();
    for offline in [false, true] {
        let mut damaged = args.clone();
        if offline {
            damaged.push("--offline".to_string());
        }
        let output = tokio::task::spawn_blocking(move || run(damaged))
            .await
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        assert_eq!(output.status.code(), Some(2), "offline={offline}\n{stdout}");
        assert!(
            stdout.contains("[4/4] Reports"),
            "offline={offline}\n{stdout}"
        );
        assert!(stdout.contains("database:"), "offline={offline}\n{stdout}");
        let m = read_json(&out.join("dojo-manifest.json"));
        assert_eq!(m["complete"], false, "offline={offline} {m}");
        assert!(
            m["incomplete_because"]
                .to_string()
                .contains("database problem"),
            "offline={offline} {m}"
        );
    }

    // the API key is in no file at all
    for entry in std::fs::read_dir(&out).unwrap() {
        let p = entry.unwrap().path();
        let body = std::fs::read_to_string(&p).unwrap();
        assert!(!body.contains(KEY), "{} contains the API key", p.display());
    }
    for f in ["inventory.json", "recon.md", "report.json", "report.csv"] {
        assert!(out.join(f).is_file(), "{f}");
    }
    let _ = std::fs::remove_dir_all(&work);
}

#[test]
fn audit_refuses_a_directory_that_is_not_a_wordpress_root() {
    let plugins =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wp/wp-content/plugins");
    let work = temp("refuse");
    let output = run(vec![
        "audit".into(),
        plugins.to_str().unwrap().into(),
        "--db".into(),
        work.join("db").to_str().unwrap().into(),
        "--offline".into(),
        "--out".into(),
        work.join("out").to_str().unwrap().into(),
    ]);
    assert_eq!(output.status.code(), Some(10));
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(err.contains("not a WordPress root"), "{err}");
    assert!(!work.join("out/defectdojo-core.json").exists());
    let _ = std::fs::remove_dir_all(&work);
}

#[test]
fn a_broken_env_file_stops_the_run_before_anything_is_written() {
    let site = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wp");
    let work = temp("badenv");
    let env_file = work.join("bad.env");
    std::fs::write(&env_file, "DEFECTDOJO_URL=ftp://nope\n").unwrap();
    let out = work.join("out");
    let output = run(vec![
        "audit".into(),
        site.to_str().unwrap().into(),
        "--db".into(),
        work.join("db").to_str().unwrap().into(),
        "--offline".into(),
        "--no-wordfence".into(),
        "--out".into(),
        out.to_str().unwrap().into(),
        "--env".into(),
        env_file.to_str().unwrap().into(),
    ]);
    assert_eq!(output.status.code(), Some(10));
    assert!(!out.exists(), "nothing written for a bad configuration");
    let _ = std::fs::remove_dir_all(&work);
}

#[test]
fn offline_without_a_database_fails_and_leaves_no_stale_manifest() {
    let site = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wp");
    let work = temp("offline-nodb");
    let out = work.join("out");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join(".wpvuln-audit"), "").unwrap();
    std::fs::write(out.join("dojo-manifest.json"), "{\"old\":true}").unwrap();
    std::fs::write(out.join("defectdojo-core.json"), "{\"findings\":[]}").unwrap();

    let output = run(vec![
        "audit".into(),
        site.to_str().unwrap().into(),
        "--db".into(),
        work.join("missing-db").to_str().unwrap().into(),
        "--offline".into(),
        "--no-wordfence".into(),
        "--out".into(),
        out.to_str().unwrap().into(),
    ]);
    assert_eq!(output.status.code(), Some(10));
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(err.contains("not a local database"), "{err}");
    // the failed run cleared the old results instead of leaving them next
    // to the new inventory
    assert!(!out.join("dojo-manifest.json").exists());
    assert!(!out.join("defectdojo-core.json").exists());
    assert!(out.join("inventory.json").is_file());
    let _ = std::fs::remove_dir_all(&work);
}

#[test]
fn reports_and_database_inside_the_site_are_refused() {
    let work = temp("inside");
    let site = work.join("public_html");
    std::fs::create_dir_all(site.join("wp-includes")).unwrap();
    std::fs::write(
        site.join("wp-includes/version.php"),
        "<?php\n$wp_version = '6.4.3';\n",
    )
    .unwrap();
    for args in [
        vec!["--out", site.join("reports").to_str().unwrap()],
        vec![
            "--out",
            work.join("out").to_str().unwrap(),
            "--db",
            site.join("wpvuln-db").to_str().unwrap(),
        ],
    ] {
        let mut a = vec!["audit".to_string(), site.to_str().unwrap().to_string()];
        a.extend(args.iter().map(|s| s.to_string()));
        a.extend(["--offline".to_string(), "--no-wordfence".to_string()]);
        let output = run(a);
        assert_eq!(output.status.code(), Some(10));
        let err = String::from_utf8_lossy(&output.stderr);
        assert!(err.contains("inside the site"), "{err}");
    }
    assert!(!site.join("reports").exists());
    assert!(!site.join("wpvuln-db").exists());
    let _ = std::fs::remove_dir_all(&work);
}

#[test]
fn dot_dot_through_a_missing_folder_cannot_reach_the_site() {
    let work = temp("dotdot");
    let site = work.join("home").join("public_html");
    std::fs::create_dir_all(site.join("wp-includes")).unwrap();
    std::fs::write(
        site.join("wp-includes/version.php"),
        "<?php\n$wp_version = '6.4.3';\n",
    )
    .unwrap();
    // other/missing/../../home/public_html/reports is inside the site
    let sneaky = work
        .join("other")
        .join("missing")
        .join("..")
        .join("..")
        .join("home")
        .join("public_html")
        .join("reports");
    let output = run(vec![
        "audit".into(),
        site.to_str().unwrap().into(),
        "--out".into(),
        sneaky.to_str().unwrap().into(),
        "--db".into(),
        work.join("db").to_str().unwrap().into(),
        "--offline".into(),
        "--no-wordfence".into(),
    ]);
    assert_eq!(output.status.code(), Some(10));
    assert!(String::from_utf8_lossy(&output.stderr).contains("inside the site"));
    assert!(!site.join("reports").exists());
    assert!(!work.join("other").exists());
    let _ = std::fs::remove_dir_all(&work);
}

#[cfg(unix)]
#[test]
fn a_symlink_into_the_site_is_resolved_before_the_check() {
    let work = temp("symlink");
    let site = work.join("public_html");
    std::fs::create_dir_all(site.join("wp-includes")).unwrap();
    std::fs::write(
        site.join("wp-includes/version.php"),
        "<?php\n$wp_version = '6.4.3';\n",
    )
    .unwrap();
    let link = work.join("innocent");
    std::os::unix::fs::symlink(&site, &link).unwrap();
    let output = run(vec![
        "audit".into(),
        site.to_str().unwrap().into(),
        "--out".into(),
        link.join("reports").to_str().unwrap().into(),
        "--db".into(),
        work.join("db").to_str().unwrap().into(),
        "--offline".into(),
        "--no-wordfence".into(),
    ]);
    assert_eq!(output.status.code(), Some(10));
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(err.contains("inside the site"), "{err}");
    assert!(!site.join("reports").exists());
    let _ = std::fs::remove_dir_all(&work);
}

#[test]
fn a_folder_with_someone_elses_files_is_left_alone() {
    let site = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wp");
    let work = temp("foreign");
    let out = work.join("mine");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("report.csv"), "my own data").unwrap();
    std::fs::write(out.join("inventory.json"), "my own inventory").unwrap();
    let output = run(vec![
        "audit".into(),
        site.to_str().unwrap().into(),
        "--out".into(),
        out.to_str().unwrap().into(),
        "--db".into(),
        work.join("db").to_str().unwrap().into(),
        "--offline".into(),
        "--no-wordfence".into(),
    ]);
    assert_eq!(output.status.code(), Some(10));
    assert!(String::from_utf8_lossy(&output.stderr).contains("did not write"));
    assert_eq!(
        std::fs::read_to_string(out.join("report.csv")).unwrap(),
        "my own data"
    );
    assert_eq!(
        std::fs::read_to_string(out.join("inventory.json")).unwrap(),
        "my own inventory"
    );
    let _ = std::fs::remove_dir_all(&work);
}

#[test]
fn out_and_db_may_not_be_the_same_folder() {
    let site = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wp");
    let work = temp("samedir");
    let both = work.join("both");
    let output = run(vec![
        "audit".into(),
        site.to_str().unwrap().into(),
        "--out".into(),
        both.to_str().unwrap().into(),
        "--db".into(),
        both.to_str().unwrap().into(),
        "--offline".into(),
        "--no-wordfence".into(),
    ]);
    assert_eq!(output.status.code(), Some(10));
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(err.contains("same folder"), "{err}");
    let _ = std::fs::remove_dir_all(&work);
}

#[tokio::test]
async fn test_titles_tell_the_wordfence_feeds_apart() {
    let server = MockServer::start().await;
    mount(&server, "/core/6.6.2/", 200, &record(CORE_VULN)).await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    let work = temp("titles");
    let site = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wp");
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wordfence");
    let db = work.join("db");
    let out = work.join("out");
    let audit = |extra: Vec<String>| {
        let mut a: Vec<String> = [
            "audit",
            site.to_str().unwrap(),
            "--db",
            db.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--api-url",
            &server.uri(),
            "--env",
            work.join("none.env").to_str().unwrap(),
        ]
        .map(String::from)
        .to_vec();
        a.extend(extra);
        a
    };
    // --env must exist when named; an empty file means no settings
    std::fs::write(work.join("none.env"), "").unwrap();

    let first = audit(vec!["--no-wordfence".into()]);
    let output = tokio::task::spawn_blocking(move || run(first))
        .await
        .unwrap();
    assert_eq!(output.status.code(), Some(2));

    for (file, want) in [
        ("raw-sample.json", "(wordfence-api+wpvulnerability)"),
        ("wpprobe-sample.json", "(wordfence-github+wpvulnerability)"),
    ] {
        let import = vec![
            "db".to_string(),
            "wordfence".into(),
            "import".into(),
            fixtures.join(file).to_str().unwrap().into(),
            "--db".into(),
            db.to_str().unwrap().into(),
        ];
        let output = tokio::task::spawn_blocking(move || run(import))
            .await
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let again = audit(vec!["--offline".into()]);
        let output = tokio::task::spawn_blocking(move || run(again))
            .await
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        assert!(stdout.contains("[4/4] Reports"), "{stdout}");
        let m = read_json(&out.join("dojo-manifest.json"));
        let title = m["files"][0]["test_title"].as_str().unwrap().to_string();
        assert!(title.ends_with(want), "{file}: {title}");
    }
    let _ = std::fs::remove_dir_all(&work);
}
