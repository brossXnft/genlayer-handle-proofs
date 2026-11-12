//! Handle Proofs: bind GitHub accounts and web domains to GenLayer addresses.
//!
//! The owner of a handle publishes one token line that names the registry,
//! the handle and the address:
//!
//!   genlayer-handle-proof:v1:<chain>:<registry>:<kind>:<handle>:<address>
//!
//! - github:  in any file of a public gist owned by that GitHub login
//! - domain:  in a DNS TXT record at `_genlayer-proof.<domain>` (method `dns`)
//!            or in `https://<domain>/.well-known/genlayer-proof.txt` (method `well-known`)
//!
//! `claim` makes every validator fetch the proof itself; the binding is stored
//! only if they agree it is there. `recheck` (callable by anyone) removes a
//! binding whose proof was taken down, so the registry does not keep stale claims.
//! Other contracts call `resolve`, `is_bound` or `handles_of`.

use glkit::genlayer_sdk::abi::entry::MessageData;
use glkit::genlayer_sdk::abi::entry::contract_def::{ConsensusStageData, Contract, ContractExt};
use glkit::genlayer_sdk::storage::{DynArray, Root};
use glkit::*;

glkit::genlayer_sdk::record!(State {
    bindings: Records,
    by_address: Records,
    log: DynArray<Vec<u8>>,
});

fn state() -> State {
    Root::<State>::get().contract_instance().get()
}

const UA: &str = "handle-proofs/1.0 (+https://github.com/brossXnft/genlayer-handle-proofs)";
const MAX_HANDLES_PER_ADDRESS: usize = 16;

// ------------------------------------------------------------------ handles

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Github,
    Domain,
}

impl Kind {
    fn parse(s: &str) -> R<Kind> {
        match s {
            "github" => Ok(Kind::Github),
            "domain" => Ok(Kind::Domain),
            _ => Err("kind must be `github` or `domain`".into()),
        }
    }
    fn name(self) -> &'static str {
        match self {
            Kind::Github => "github",
            Kind::Domain => "domain",
        }
    }
}

/// Lowercase and validate a handle.
fn normalize(kind: Kind, handle: &str) -> R<String> {
    let h = handle.trim().to_ascii_lowercase();
    match kind {
        Kind::Github => {
            let ok = !h.is_empty()
                && h.len() <= 39
                && h.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
                && !h.starts_with('-')
                && !h.ends_with('-');
            if !ok {
                return Err("not a valid GitHub login".into());
            }
        }
        Kind::Domain => {
            let h = h.trim_end_matches('.');
            let labels: Vec<&str> = h.split('.').collect();
            let ok = h.len() <= 253
                && labels.len() >= 2
                && labels.iter().all(|l| {
                    !l.is_empty()
                        && l.len() <= 63
                        && l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
                        && !l.starts_with('-')
                        && !l.ends_with('-')
                })
                && !labels.last().unwrap().bytes().all(|c| c.is_ascii_digit());
            if !ok {
                return Err("not a valid domain name".into());
            }
            return Ok(h.to_owned());
        }
    }
    Ok(h)
}

fn key(kind: Kind, handle: &str) -> String {
    format!("{}:{}", kind.name(), handle)
}

fn token(chain: &BigInt, registry: &Address, kind: Kind, handle: &str, owner: &Address) -> String {
    format!(
        "genlayer-handle-proof:v1:{}:{}:{}:{}:{}",
        int_text(chain),
        addr_hex(registry),
        kind.name(),
        handle,
        addr_hex(owner)
    )
}

fn gist_id(proof: &str) -> R<String> {
    let p = proof.trim().trim_end_matches('/');
    let id = p.rsplit('/').next().unwrap_or(p);
    if id.is_empty() || id.len() > 64 || !id.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("proof must be a gist id or gist URL".into());
    }
    Ok(id.to_ascii_lowercase())
}

// ------------------------------------------------------------------ verification (nondet only)

/// What one node sees. Validators compare this whole struct with the leader's.
fn check(kind: Kind, handle: &str, method: &str, proof: &str, tok: &str) -> Value {
    let (found, detail) = match (kind, method) {
        (Kind::Github, _) => check_gist(handle, proof, tok),
        (Kind::Domain, "dns") => check_dns(handle, tok),
        (Kind::Domain, "well-known") => check_well_known(handle, tok),
        _ => (false, "unknown method".to_owned()),
    };
    map([("found", Value::Bool(found)), ("detail", Value::Str(detail))])
}

fn check_gist(login: &str, id: &str, tok: &str) -> (bool, String) {
    let url = format!("https://api.github.com/gists/{id}");
    let j = match get_json(&url, &[("User-Agent", UA), ("Accept", "application/vnd.github+json")]) {
        Ok(j) => j,
        Err(e) if e.starts_with("HTTP 404") => return (false, "gist not found".into()),
        Err(e) => return (false, format!("fetch failed: {e}")),
    };
    let owner = json_path(&j, "owner.login").and_then(|v| v.as_str()).unwrap_or("").to_ascii_lowercase();
    if owner != login {
        return (false, format!("gist owner is `{owner}`, not `{login}`"));
    }
    let Some(files) = json_path(&j, "files").and_then(|v| v.as_object()) else {
        return (false, "gist has no files".into());
    };
    for (_, file) in files {
        let content = file.get("content").and_then(|v| v.as_str()).unwrap_or("");
        if content.lines().any(|l| l.trim() == tok) {
            return (true, "token found in gist".into());
        }
    }
    (false, "token not in gist".into())
}

fn txt_strings(j: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(ans) = json_path(j, "Answer").and_then(|v| v.as_array()) {
        for a in ans {
            if a.get("type").and_then(|t| t.as_u64()) != Some(16) {
                continue;
            }
            // TXT data is one or more quoted strings: "abc" "def" -> abcdef
            let data = a.get("data").and_then(|d| d.as_str()).unwrap_or("");
            let mut joined = String::new();
            let mut inq = false;
            let mut esc = false;
            for ch in data.chars() {
                if esc {
                    joined.push(ch);
                    esc = false;
                } else if ch == '\\' && inq {
                    esc = true;
                } else if ch == '"' {
                    inq = !inq;
                } else if inq {
                    joined.push(ch);
                }
            }
            if joined.is_empty() {
                joined = data.to_owned();
            }
            out.push(joined);
        }
    }
    out
}

fn check_dns(domain: &str, tok: &str) -> (bool, String) {
    let name = format!("_genlayer-proof.{domain}");
    let resolvers = [
        format!("https://dns.google/resolve?name={name}&type=TXT"),
        format!("https://cloudflare-dns.com/dns-query?name={name}&type=TXT"),
    ];
    let mut answered = 0;
    for url in &resolvers {
        let Ok(j) = get_json(url, &[("User-Agent", UA), ("Accept", "application/dns-json")]) else { continue };
        answered += 1;
        if txt_strings(&j).iter().any(|t| t.trim() == tok) {
            return (true, format!("TXT record found via {}", host_of(url)));
        }
    }
    if answered == 0 { (false, "no DNS resolver answered".into()) } else { (false, format!("no matching TXT at {name}")) }
}

fn check_well_known(domain: &str, tok: &str) -> (bool, String) {
    let url = format!("https://{domain}/.well-known/genlayer-proof.txt");
    match http_get(&url, &[("User-Agent", UA)]) {
        Ok(r) if (200..300).contains(&r.status) => {
            let body = String::from_utf8_lossy(&r.body);
            if body.lines().any(|l| l.trim() == tok) {
                (true, "token found in /.well-known/genlayer-proof.txt".into())
            } else {
                (false, "token not in /.well-known/genlayer-proof.txt".into())
            }
        }
        Ok(r) => (false, format!("HTTP {} for /.well-known/genlayer-proof.txt", r.status)),
        Err(e) => (false, format!("fetch failed: {e}")),
    }
}

// ------------------------------------------------------------------ contract

fn log_event(m: &MessageData, ev: &str, k: &str, owner: &Address) {
    let st = state();
    let rec = map([
        ("event", ev.into()),
        ("key", k.into()),
        ("address", Value::Address(*owner)),
        ("at", Value::from(tx_time(m))),
    ]);
    st.log().append_slot().store(&calldata::encode(&rec));
}

fn handles_of(addr: &Address) -> Vec<Value> {
    rec_get(&state().by_address(), &addr_hex(addr)).and_then(|v| v.as_array().map(|a| a.to_vec())).unwrap_or_default()
}

fn set_handles(addr: &Address, list: Vec<Value>) {
    rec_put(&state().by_address(), &addr_hex(addr), &Value::Array(list));
}

fn unbind(k: &str) -> Option<Address> {
    let st = state();
    let b = rec_get(&st.bindings(), k)?;
    let owner = f_addr(&b, "address")?;
    st.bindings().remove(&k.to_owned());
    let list: Vec<Value> = handles_of(&owner).into_iter().filter(|h| h.as_str() != Some(k)).collect();
    set_handles(&owner, list);
    Some(owner)
}

#[derive(Default)]
pub struct HandleProofs;

impl HandleProofs {
    fn verify(&self, kind: Kind, handle: &str, method: &str, proof: &str, owner: &Address) -> R<Value> {
        run_nondet(&map([
            ("op", "check".into()),
            ("kind", kind.name().into()),
            ("handle", handle.into()),
            ("method", method.into()),
            ("proof", proof.into()),
            ("owner", Value::Address(*owner)),
        ]))
    }

    fn claim(&self, m: &MessageData, args: &[Value]) -> R<Value> {
        no_value(m)?;
        let kind = Kind::parse(&arg_str(args, 0, "kind")?)?;
        let handle = normalize(kind, &arg_str(args, 1, "handle")?)?;
        let raw_proof = arg_str(args, 2, "proof")?;
        let (method, proof) = match kind {
            Kind::Github => ("gist".to_owned(), gist_id(&raw_proof)?),
            Kind::Domain => {
                let p = raw_proof.trim().to_ascii_lowercase();
                if p != "dns" && p != "well-known" {
                    return Err("domain proof must be `dns` or `well-known`".into());
                }
                (p.clone(), p)
            }
        };
        let owner = m.sender_address;
        let k = key(kind, &handle);
        let mine = handles_of(&owner);
        if mine.len() >= MAX_HANDLES_PER_ADDRESS && !mine.iter().any(|h| h.as_str() == Some(&k)) {
            return Err(format!("an address can hold at most {MAX_HANDLES_PER_ADDRESS} handles"));
        }
        let res = self.verify(kind, &handle, &method, &proof, &owner)?;
        if !f_bool(&res, "found") {
            return Err(format!("proof not accepted: {}", f_str(&res, "detail")));
        }
        // A fresh valid proof wins: it moves the handle away from any previous owner.
        let previous = unbind(&k);
        let st = state();
        let rec = map([
            ("key", k.clone().into()),
            ("kind", kind.name().into()),
            ("handle", handle.clone().into()),
            ("address", Value::Address(owner)),
            ("method", method.into()),
            ("proof", proof.into()),
            ("detail", Value::Str(f_str(&res, "detail"))),
            ("bound_at", Value::from(tx_time(m))),
            ("checked_at", Value::from(tx_time(m))),
        ]);
        rec_put(&st.bindings(), &k, &rec);
        let mut list = handles_of(&owner);
        list.push(k.clone().into());
        set_handles(&owner, list);
        log_event(m, if previous.is_some() { "rebound" } else { "bound" }, &k, &owner);
        Ok(with(&rec, "previous_owner", previous.map(Value::Address).unwrap_or(Value::Null)))
    }

    fn recheck(&self, m: &MessageData, args: &[Value]) -> R<Value> {
        no_value(m)?;
        let kind = Kind::parse(&arg_str(args, 0, "kind")?)?;
        let handle = normalize(kind, &arg_str(args, 1, "handle")?)?;
        let k = key(kind, &handle);
        let st = state();
        let b = rec_get(&st.bindings(), &k).ok_or_else(|| format!("`{k}` is not bound"))?;
        let owner = f_addr(&b, "address").ok_or("corrupt binding")?;
        let res = self.verify(kind, &handle, &f_str(&b, "method"), &f_str(&b, "proof"), &owner)?;
        if f_bool(&res, "found") {
            let b = with(&b, "checked_at", Value::from(tx_time(m)));
            rec_put(&st.bindings(), &k, &b);
            log_event(m, "rechecked", &k, &owner);
            Ok(map([("key", k.into()), ("status", "valid".into()), ("binding", b)]))
        } else {
            unbind(&k);
            log_event(m, "dropped", &k, &owner);
            Ok(map([("key", k.into()), ("status", "dropped".into()), ("reason", Value::Str(f_str(&res, "detail")))]))
        }
    }
}

impl ContractExt for HandleProofs {
    type Error = String;

    fn handle_deploy(&mut self, _m: MessageData, _a: Vec<Value>, _k: calldata::Map) -> R<Value> {
        Ok(Value::Null)
    }

    fn handle_method(&mut self, m: MessageData, method: String, args: Vec<Value>, _k: calldata::Map) -> R<Value> {
        let st = state();
        match method.as_str() {
            "claim" => self.claim(&m, &args),
            "recheck" => self.recheck(&m, &args),
            "revoke" => {
                no_value(&m)?;
                let kind = Kind::parse(&arg_str(&args, 0, "kind")?)?;
                let k = key(kind, &normalize(kind, &arg_str(&args, 1, "handle")?)?);
                let b = rec_get(&st.bindings(), &k).ok_or_else(|| format!("`{k}` is not bound"))?;
                if f_addr(&b, "address").map(|a| a.raw()) != Some(m.sender_address.raw()) {
                    return Err("only the bound address can revoke".into());
                }
                unbind(&k);
                log_event(&m, "revoked", &k, &m.sender_address);
                Ok(map([("key", k.into()), ("status", "revoked".into())]))
            }
            "statement" => {
                let kind = Kind::parse(&arg_str(&args, 0, "kind")?)?;
                let handle = normalize(kind, &arg_str(&args, 1, "handle")?)?;
                let owner = arg_address(&args, 2, "address")?;
                let tok = token(&m.chain_id, &m.contract_address, kind, &handle, &owner);
                let hint = match kind {
                    Kind::Github => "Put this line in a file of a public gist owned by that login, then claim with the gist id.".to_owned(),
                    Kind::Domain => format!(
                        "Add it as a TXT record at _genlayer-proof.{handle} (claim with `dns`), or as a line in https://{handle}/.well-known/genlayer-proof.txt (claim with `well-known`)."
                    ),
                };
                Ok(map([("token", tok.into()), ("how", hint.into())]))
            }
            "resolve" => {
                let kind = Kind::parse(&arg_str(&args, 0, "kind")?)?;
                let k = key(kind, &normalize(kind, &arg_str(&args, 1, "handle")?)?);
                Ok(rec_get(&st.bindings(), &k).unwrap_or(Value::Null))
            }
            "is_bound" => {
                let kind = Kind::parse(&arg_str(&args, 0, "kind")?)?;
                let k = key(kind, &normalize(kind, &arg_str(&args, 1, "handle")?)?);
                let who = arg_address(&args, 2, "address")?;
                Ok(Value::Bool(
                    rec_get(&st.bindings(), &k).and_then(|b| f_addr(&b, "address")).map(|a| a.raw()) == Some(who.raw()),
                ))
            }
            "handles_of" => {
                let who = arg_address(&args, 0, "address")?;
                let list = handles_of(&who)
                    .into_iter()
                    .filter_map(|k| k.as_str().and_then(|k| rec_get(&st.bindings(), k)))
                    .collect();
                Ok(Value::Array(list))
            }
            "recent" => {
                let n = args.first().and_then(|v| v.as_number()).and_then(|b| u32::try_from(b.clone()).ok()).unwrap_or(20).min(100);
                let log = st.log();
                let len = log.len();
                let mut out = Vec::new();
                let mut i = len;
                while i > 0 && out.len() < n as usize {
                    i -= 1;
                    if let Ok(v) = calldata::decode(&log.index(i).load()) {
                        out.push(v);
                    }
                }
                Ok(Value::Array(out))
            }
            "stats" => Ok(map([("bindings", Value::from(st.bindings().len())), ("events", Value::from(st.log().len()))])),
            "version" => Ok("handle-proofs 1.0.0".into()),
            _ => Err(format!("unknown method: {method}")),
        }
    }
}

impl Contract for HandleProofs {
    fn handle_main(&mut self, message: MessageData, data: bytes::Bytes) -> Result<Value, String> {
        ContractExt::handle_main(self, message, data.to_vec())
    }

    fn handle_sandbox(&mut self, _m: MessageData, _d: bytes::Bytes) -> Result<Vec<u8>, String> {
        Err("sandbox not supported".into())
    }

    fn handle_consensus_stage(&mut self, m: MessageData, data: bytes::Bytes, stage: ConsensusStageData) -> Result<Value, String> {
        let req = calldata::decode(&data).map_err(|e| format!("{e:?}"))?;
        if f_str(&req, "op") != "check" {
            return Err("unknown nondet op".into());
        }
        let kind = Kind::parse(&f_str(&req, "kind"))?;
        let handle = f_str(&req, "handle");
        let owner = f_addr(&req, "owner").ok_or("missing owner")?;
        let tok = token(&m.chain_id, &m.contract_address, kind, &handle, &owner);
        let mine = check(kind, &handle, &f_str(&req, "method"), &f_str(&req, "proof"), &tok);
        match Stage::from(stage) {
            Stage::Leader => Ok(mine),
            // Validators agree on the verdict; the human-readable detail may differ
            // (e.g. which DNS resolver answered), so only `found` is compared.
            Stage::Validator(lr) => Ok(Value::Bool(
                leader_value(&lr).map(|l| f_bool(l, "found") == f_bool(&mine, "found") && f(l, "found").is_some()).unwrap_or(false),
            )),
        }
    }
}

glkit::genlayer_sdk::contract_main!(HandleProofs);
