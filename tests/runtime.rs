//! scripts/freefitty-runtime.py against stand-in `freefitty` and `buzz` binaries that record what they were asked:
//! an agent's life (created, unchanged, edited, deleted) maps to the right FreeFitty and Buzz calls, once each.

use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn stand_in(dir: &Path, name: &str, log: &Path) -> PathBuf {
    let p = dir.join(name);
    // one line per call: the brief spans lines, so newlines in the arguments are flattened
    let body = format!(
        "#!/bin/sh\nargs=$(printf '%s' \"$*\" | tr '\\n' ' ')\nprintf '%s|key=%s|tag=%s|%s\\n' \"{name}\" \"$BUZZ_PRIVATE_KEY\" \"$BUZZ_AUTH_TAG\" \"$args\" >> {}\necho '{{}}'\n",
        log.display()
    );
    std::fs::write(&p, body).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

fn sync(dir: &Path, registry: &Path, ff: &Path, buzz: &Path, extra: &str) -> String {
    let out = Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/scripts/freefitty-runtime.py"
        ))
        .arg("--registry")
        .arg(registry)
        .arg("--state")
        .arg(dir.join("runtime-state.json"))
        .arg("--freefitty")
        .arg(ff)
        .arg("--freefitty-config")
        .arg(dir.join("freefitty.toml"))
        .arg("--buzz")
        .arg(buzz)
        .arg(format!("--extra-tools={extra}"))
        .output()
        .expect("python3 runs the runtime script");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn write_registry(path: &Path, agent: &Value) {
    std::fs::write(path, json!({"agents": [agent]}).to_string()).unwrap();
}

#[test]
fn agent_life_maps_to_threads_and_profiles() {
    let dir = std::env::temp_dir().join(format!("buzz-rap-runtime-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("calls.log");
    let (ff, buzz) = (
        stand_in(&dir, "freefitty", &log),
        stand_in(&dir, "buzz", &log),
    );
    let key = dir.join("a1.key");
    std::fs::write(&key, "11".repeat(32)).unwrap();
    let tag = dir.join("a1.auth");
    std::fs::write(&tag, "[\"auth\",\"owner\",\"\",\"sig\"]\n").unwrap();
    let registry = dir.join("agents.json");
    let mut agent = json!({"id": "a1", "pubkey": "p", "name": "Scout", "instructions": "Be brief.",
        "model": "m", "effort": "low", "status": "active", "owner": "o", "idempotency_key": "k",
        "key_file": key, "auth_tag_file": tag, "created_at": 1, "updated_at": 1});
    let calls = || std::fs::read_to_string(&log).unwrap_or_default();

    // created: profile with the agent's key and owner tag, then the thread with the buzz tools and the brief
    write_registry(&registry, &agent);
    sync(&dir, &registry, &ff, &buzz, "");
    let c = calls();
    let lines: Vec<&str> = c.lines().collect();
    assert_eq!(lines.len(), 2, "{c}");
    assert!(
        lines[0].starts_with("buzz|key=1111")
            && lines[0].contains("tag=[\"auth\",\"owner\",\"\",\"sig\"]")
    );
    assert!(lines[0].contains("users set-profile --name=Scout"), "{c}");
    assert!(
        lines[1].contains("say --thread agent-a1 --tools buzz_subscribe,"),
        "{c}"
    );
    assert!(
        lines[1].contains("You are Scout") && lines[1].contains("Be brief."),
        "{c}"
    );
    assert!(
        lines[1].contains("since 1"),
        "subscribe from the agent's creation: {c}"
    );
    assert!(lines[1].contains("plain-text reply reaches no one"), "{c}");
    assert!(
        lines[1].contains("buzz_users_get,routine,hand_off,workspace_read,workspace_list,workspace_write,workspace_delete"),
        "every agent gets FreeFitty's standing tools: {c}"
    );
    assert!(
        lines[1].contains("Standing duties:") && lines[1].contains("my/MEMORY.md") && lines[1].contains("[FreeFitty]"),
        "and the brief teaches them: {c}"
    );

    // unchanged: nothing to do
    sync(&dir, &registry, &ff, &buzz, "");
    assert_eq!(calls().lines().count(), 2, "a second sync is a no-op");

    // edited: the thread hears the new settings; the profile is republished for the new name
    agent["instructions"] = json!("Answer in French.");
    agent["name"] = json!("Scout II");
    write_registry(&registry, &agent);
    sync(&dir, &registry, &ff, &buzz, "");
    let c = calls();
    let new: Vec<&str> = c.lines().skip(2).collect();
    assert_eq!(new.len(), 2, "{c}");
    assert!(new[0].contains("set-profile --name=Scout II"), "{c}");
    assert!(
        new[1].contains("say --thread agent-a1 [From the agent service]")
            && new[1].contains("Answer in French."),
        "{c}"
    );
    assert!(
        !new[1].contains("--tools"),
        "a settings note does not reset the tool list"
    );

    // a new tool for every agent: the thread starts again with it (a thread's tool list is fixed at its start)
    let before = calls().lines().count();
    sync(&dir, &registry, &ff, &buzz, "board_list,board_read");
    let c = calls();
    let new: Vec<&str> = c.lines().skip(before).collect();
    assert_eq!(new.len(), 2, "{c}");
    assert!(new[0].contains(" rm agent-a1"), "{c}");
    assert!(
        new[1].contains("say --thread agent-a1 --tools buzz_subscribe,")
            && new[1].contains(",board_list,board_read"),
        "{c}"
    );
    assert!(
        new[1].contains("board_list, board_read"),
        "the brief names the extra tools: {c}"
    );
    sync(&dir, &registry, &ff, &buzz, "board_list,board_read");
    assert_eq!(
        calls().lines().count(),
        before + 2,
        "same tools again: no-op"
    );

    // an image tool: the brief says how to attach what it makes
    let before = calls().lines().count();
    sync(
        &dir,
        &registry,
        &ff,
        &buzz,
        "board_list,board_read,image_generate",
    );
    let c = calls();
    let new: Vec<&str> = c.lines().skip(before).collect();
    assert_eq!(new.len(), 2, "{c}");
    assert!(
        new[1].contains("files: [\"<path>\"]"),
        "the brief says to attach images with files: {c}"
    );

    // deleted: the thread is removed, once
    let before = calls().lines().count();
    agent["status"] = json!("deleted");
    write_registry(&registry, &agent);
    sync(&dir, &registry, &ff, &buzz, "board_list,board_read");
    sync(&dir, &registry, &ff, &buzz, "board_list,board_read");
    let c = calls();
    let removed: Vec<&str> = c
        .lines()
        .skip(before)
        .filter(|l| l.contains(" rm agent-a1"))
        .collect();
    assert_eq!(removed.len(), 1, "{c}");
    let _ = std::fs::remove_dir_all(&dir);
}


/// A stand-in FreeFitty operator API: GET /output?thread=... hands out the queued replies, oldest first, then 204.
fn fake_output(replies: Vec<Value>) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    use std::io::{Read, Write};
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen2 = seen.clone();
    std::thread::spawn(move || {
        let mut q: std::collections::VecDeque<Value> = replies.into();
        for s in l.incoming() {
            let mut s = s.unwrap();
            let mut buf = [0u8; 4096];
            let n = s.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            seen2.lock().unwrap().push(req.lines().next().unwrap_or("").to_owned() + if req.contains("Bearer optok") { " [token]" } else { "" });
            let resp = match q.pop_front() {
                Some(v) => { let b = v.to_string(); format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}", b.len()) }
                None => "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".to_owned(),
            };
            let _ = s.write_all(resp.as_bytes());
        }
    });
    (addr, seen)
}

#[test]
fn alerts_reach_the_owners_dm_with_the_agents_key_and_plain_replies_are_dropped() {
    let dir = std::env::temp_dir().join(format!("buzz-rap-runtime-alerts-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("calls.log");
    let (ff, buzz) = (stand_in(&dir, "freefitty", &log), stand_in(&dir, "buzz", &log));
    let key = dir.join("a1.key");
    std::fs::write(&key, "22".repeat(32)).unwrap();
    let tag = dir.join("a1.auth");
    std::fs::write(&tag, "[\"auth\",\"owner\",\"\",\"sig\"]\n").unwrap();
    let registry = dir.join("agents.json");
    write_registry(&registry, &json!({"id": "a1", "pubkey": "p", "name": "Cubey", "instructions": "", "model": "m", "effort": "low",
        "status": "active", "owner": "o", "idempotency_key": "k", "key_file": key, "auth_tag_file": tag, "created_at": 1, "updated_at": 1}));
    let (addr, seen) = fake_output(vec![
        json!({"text": "plain words nobody reads", "metadata": {"kind": "text", "thread": "agent-a1"}}),
        json!({"text": "[FreeFitty] Duty check paused: fired 12 times in the last hour", "metadata": {"kind": "alert", "thread": "agent-a1"}}),
    ]);
    std::fs::write(dir.join("freefitty.toml"), format!("listen = \"{addr}\"\noperator_token = \"optok\"\n")).unwrap();
    let rap_state = dir.join("rap-state.json");
    std::fs::write(&rap_state, json!({"subs": [{"identity": "a1", "scope": "dms", "dm_channels": ["dm-chan-1"]}]}).to_string()).unwrap();
    let out = Command::new("python3")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/freefitty-runtime.py"))
        .arg("--registry").arg(&registry)
        .arg("--state").arg(dir.join("runtime-state.json"))
        .arg("--freefitty").arg(&ff)
        .arg("--freefitty-config").arg(dir.join("freefitty.toml"))
        .arg("--buzz").arg(&buzz)
        .arg("--rap-state").arg(&rap_state)
        .output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(out.status.success(), "{}{}", stdout, String::from_utf8_lossy(&out.stderr));
    let calls = std::fs::read_to_string(&log).unwrap();
    let sends: Vec<&str> = calls.lines().filter(|l| l.contains("messages send")).collect();
    assert_eq!(sends.len(), 1, "{calls}");
    assert!(sends[0].starts_with("buzz|key=2222") && sends[0].contains("--channel dm-chan-1 --content [FreeFitty] Duty check paused"), "{calls}");
    assert!(stdout.contains("1 plain-text reply collected"), "{stdout}");
    let seen = seen.lock().unwrap().clone();
    assert!(seen.iter().all(|r| r.starts_with("GET /output?thread=agent-a1&wait=0") && r.ends_with("[token]")), "{seen:?}");
    assert_eq!(seen.len(), 3, "until the 204: {seen:?}");
    let _ = std::fs::remove_dir_all(&dir);
}
