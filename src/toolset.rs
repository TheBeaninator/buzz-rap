//! The toolset, generated from the `buzz` command tree.
//!
//! Each allowed command path (`messages send`, `channels canvas get`, ...) becomes one RAP tool named
//! `buzz_<path>` with `-` and spaces turned into `_`. Its input schema comes from the command's own clap
//! arguments, so the toolset cannot drift from what the CLI accepts, and an invocation is turned back into
//! the exact `buzz` argument vector a person would type.

use anyhow::{bail, Context, Result};
use clap::{ArgAction, Command};
use serde_json::{json, Map, Value};

/// Arguments every command shares (connection, identity, output); the server sets them, the agent never does.
const SERVER_OWNED: [&str; 9] = [
    "relay",
    "private-key",
    "auth-tag",
    "api-token",
    "format",
    "output",
    "help",
    "version",
    "yes",
];

/// Command paths exposed when `--allow` is not given: reading, searching and posting, nothing that deletes,
/// archives, moderates or changes identity.
pub const DEFAULT_ALLOW: [&str; 16] = [
    "messages send",
    "messages get",
    "messages thread",
    "messages search",
    "messages edit",
    "reactions add",
    "reactions get",
    "channels list",
    "channels get",
    "channels search",
    "channels members",
    "canvas get",
    "canvas set",
    "canvas history",
    "feed get",
    "users get",
];

#[derive(Debug, Clone, PartialEq)]
pub enum Kind {
    /// `--flag` with no value
    Flag,
    /// `--name=value`
    Single,
    /// `--name=a --name=b`
    Multi,
    /// a positional value at this index
    Positional,
}

#[derive(Debug, Clone)]
pub struct ArgSpec {
    /// JSON property name (clap id with `-` as `_`)
    pub prop: String,
    /// long flag without dashes; empty for positionals
    pub long: String,
    pub kind: Kind,
}

#[derive(Debug, Clone)]
pub struct ToolSpec {
    pub name: String,
    /// the command path, e.g. ["messages", "send"]
    pub path: Vec<String>,
    pub description: String,
    pub schema: Value,
    pub args: Vec<ArgSpec>,
}

pub fn tool_name(path: &[String]) -> String {
    let joined = path.join("_").replace('-', "_");
    format!("buzz_{joined}")
}

/// Every allowed leaf command under `root`, as tools. An allowed path that names no command is an error, so
/// a typo in the allow list is caught at start instead of silently exposing less.
pub fn build(root: &Command, allow: &[String]) -> Result<Vec<ToolSpec>> {
    let mut tools = Vec::new();
    for entry in allow {
        let path: Vec<String> = entry.split_whitespace().map(str::to_owned).collect();
        if path.is_empty() {
            continue;
        }
        let mut cmd = root;
        for part in &path {
            cmd = cmd.find_subcommand(part).with_context(|| {
                format!("--allow {entry:?}: `buzz` has no command {part:?} there")
            })?;
        }
        if cmd.has_subcommands() {
            bail!("--allow {entry:?} is a command group; name one of its commands");
        }
        tools.push(spec(&path, cmd));
    }
    Ok(tools)
}

fn spec(path: &[String], cmd: &Command) -> ToolSpec {
    let mut props = Map::new();
    let mut required = Vec::new();
    let mut args = Vec::new();
    for a in cmd.get_arguments() {
        let id = a.get_id().as_str();
        if a.is_hide_set() || a.is_global_set() || SERVER_OWNED.contains(&id) {
            continue;
        }
        let long = a.get_long().unwrap_or("").to_owned();
        if SERVER_OWNED.contains(&long.as_str()) {
            continue;
        }
        let kind = if a.is_positional() {
            Kind::Positional
        } else {
            match a.get_action() {
                ArgAction::SetTrue | ArgAction::SetFalse | ArgAction::Count => Kind::Flag,
                ArgAction::Append => Kind::Multi,
                _ if a.get_num_args().is_some_and(|n| n.max_values() > 1) => Kind::Multi,
                _ => Kind::Single,
            }
        };
        let prop = id.replace('-', "_");
        let help = a.get_help().map(|h| h.to_string()).unwrap_or_default();
        let mut p = match kind {
            Kind::Flag => json!({"type": "boolean"}),
            Kind::Multi => json!({"type": "array", "items": {"type": "string"}}),
            Kind::Single | Kind::Positional => json!({"type": "string"}),
        };
        let choices: Vec<String> = a
            .get_possible_values()
            .iter()
            .map(|v| v.get_name().to_owned())
            .collect();
        if !choices.is_empty() && kind != Kind::Flag {
            p["enum"] = json!(choices);
        }
        if !help.is_empty() {
            p["description"] = json!(help);
        }
        if a.is_required_set() {
            required.push(json!(prop));
        }
        props.insert(prop.clone(), p);
        args.push(ArgSpec { prop, long, kind });
    }
    let description = cmd
        .get_about()
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("buzz {}", path.join(" ")));
    ToolSpec {
        name: tool_name(path),
        path: path.to_vec(),
        description,
        schema: json!({"type": "object", "properties": props, "required": required}),
        args,
    }
}

/// The `buzz` argument vector for one invocation. Values are passed as `--name=value`, so a value that
/// starts with `-` is never read as a flag. Unknown properties are refused rather than dropped.
pub fn argv(tool: &ToolSpec, arguments: &Value) -> Result<Vec<String>> {
    let empty = Map::new();
    let given = match arguments {
        Value::Object(m) => m,
        Value::Null => &empty,
        _ => bail!("arguments must be an object"),
    };
    for key in given.keys() {
        if !tool.args.iter().any(|a| &a.prop == key) {
            bail!("{} has no argument {key:?}", tool.name);
        }
    }
    let mut out = tool.path.clone();
    let mut positionals = Vec::new();
    for a in &tool.args {
        let Some(v) = given.get(&a.prop) else {
            continue;
        };
        if v.is_null() {
            continue;
        }
        match a.kind {
            Kind::Flag => {
                if v.as_bool()
                    .with_context(|| format!("{} must be true or false", a.prop))?
                {
                    out.push(format!("--{}", a.long));
                }
            }
            Kind::Single => out.push(format!("--{}={}", a.long, scalar(&a.prop, v)?)),
            Kind::Multi => {
                let items: Vec<&Value> = match v {
                    Value::Array(xs) => xs.iter().collect(),
                    other => vec![other],
                };
                for x in items {
                    out.push(format!("--{}={}", a.long, scalar(&a.prop, x)?));
                }
            }
            Kind::Positional => positionals.push(scalar(&a.prop, v)?),
        }
    }
    if !positionals.is_empty() {
        out.push("--".to_owned());
        out.extend(positionals);
    }
    Ok(out)
}

fn scalar(prop: &str, v: &Value) -> Result<String> {
    Ok(match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => bail!("{prop} must be a string, number or boolean"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(path: &str) -> ToolSpec {
        let allow = vec![path.to_owned()];
        build(&buzz_cli::command(), &allow).unwrap().remove(0)
    }

    #[test]
    fn every_default_path_names_a_command() {
        let allow: Vec<String> = DEFAULT_ALLOW.iter().map(|s| (*s).to_owned()).collect();
        let tools = build(&buzz_cli::command(), &allow).unwrap();
        assert_eq!(tools.len(), DEFAULT_ALLOW.len());
    }

    #[test]
    fn send_schema_follows_the_cli() {
        let t = tool("messages send");
        assert_eq!(t.name, "buzz_messages_send");
        let req = t.schema["required"].as_array().unwrap();
        assert!(
            req.contains(&json!("channel")) && req.contains(&json!("content")),
            "{}",
            t.schema
        );
        assert_eq!(t.schema["properties"]["mentions"]["type"], "array");
        assert_eq!(t.schema["properties"]["broadcast"]["type"], "boolean");
        assert!(t.schema["properties"].get("relay").is_none());
    }

    #[test]
    fn argv_round_trips_and_guards_dashes() {
        let t = tool("messages send");
        let v = argv(&t, &json!({"channel": "c1", "content": "-rf everything", "mentions": ["a", "b"], "broadcast": false})).unwrap();
        assert_eq!(
            v,
            [
                "messages",
                "send",
                "--channel=c1",
                "--content=-rf everything",
                "--mention=a",
                "--mention=b"
            ]
        );
        assert!(argv(
            &t,
            &json!({"channel": "c", "content": "x", "relay": "evil"})
        )
        .is_err());
    }

    #[test]
    fn a_group_or_unknown_path_is_refused() {
        assert!(build(&buzz_cli::command(), &["messages".to_owned()]).is_err());
        assert!(build(&buzz_cli::command(), &["messages nuke".to_owned()]).is_err());
    }
}
