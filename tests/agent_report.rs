//! scripts/agent-report.py against a stand-in `freefitty` that records what it was asked: a report reaches the
//! named agent's thread with its owner's DM channel and the summary request, long reports are cut, and an unknown
//! or inactive agent gets nothing.

use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

fn report(dir: &Path, agent: &str, body: &str) -> std::process::Output {
    use std::io::Write;
    let mut child = Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/scripts/agent-report.py"
        ))
        .arg("--registry")
        .arg(dir.join("agents.json"))
        .arg("--rap-state")
        .arg(dir.join("rap-state.json"))
        .arg("--freefitty")
        .arg(dir.join("freefitty"))
        .arg("--log")
        .arg(dir.join("reports.jsonl"))
        .args([
            "--agent",
            agent,
            "--from",
            "nightly-build",
            "--title",
            "build 7",
            "--max-bytes",
            "2000",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("python3 runs the script");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(body.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn a_report_reaches_the_agent_thread_with_the_owner_dm() {
    let dir = std::env::temp_dir().join(format!("buzz-rap-agent-report-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("calls.log");
    let ff = dir.join("freefitty");
    std::fs::write(
        &ff,
        format!(
            "#!/bin/sh\nprintf '%s' \"$*\" | tr '\\n' ' ' >> {0}\necho >> {0}\necho '{{}}'\n",
            log.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&ff, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(
        dir.join("agents.json"),
        json!({"agents": [
            {"id": "a1", "name": "Scout", "status": "active"},
            {"id": "a2", "name": "Gone", "status": "deleted"}]})
        .to_string(),
    )
    .unwrap();
    std::fs::write(
        dir.join("rap-state.json"),
        json!({"subs": [
            {"identity": "a1", "scope": "mentions"},
            {"identity": "a1", "scope": "dms", "dm_channels": ["dm-owner"]},
            {"identity": "a9", "scope": "dms", "dm_channels": ["dm-other"]}]})
        .to_string(),
    )
    .unwrap();

    // by name, case-insensitive: one freefitty call into the agent's thread
    let out = report(&dir, "scout", "Tests passed. Deploy waits for your OK.");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let calls = std::fs::read_to_string(&log).unwrap();
    assert_eq!(calls.lines().count(), 1, "{calls}");
    assert!(calls.contains("say --thread agent-a1"), "{calls}");
    assert!(
        calls.contains("[Report for your owner from nightly-build: build 7]"),
        "{calls}"
    );
    assert!(calls.contains("Deploy waits for your OK."), "{calls}");
    assert!(
        calls.contains("channel dm-owner") && !calls.contains("dm-other"),
        "{calls}"
    );
    assert!(calls.contains("buzz_messages_send"), "{calls}");

    // a long report is cut at --max-bytes
    let out = report(&dir, "Scout", &"x".repeat(5000));
    assert!(out.status.success());
    let last = std::fs::read_to_string(&log)
        .unwrap()
        .lines()
        .last()
        .unwrap()
        .to_owned();
    assert!(
        last.contains("[report cut at 2000 bytes]") && !last.contains(&"x".repeat(2001)),
        "{last}"
    );

    // an unknown or deleted agent: an error and no delivery
    for name in ["Nobody", "Gone"] {
        let out = report(&dir, name, "hello");
        assert!(!out.status.success(), "{name} must fail");
    }
    assert_eq!(std::fs::read_to_string(&log).unwrap().lines().count(), 2);
    let logged = std::fs::read_to_string(dir.join("reports.jsonl")).unwrap();
    assert_eq!(logged.lines().count(), 2, "{logged}");
    let _ = std::fs::remove_dir_all(&dir);
}
