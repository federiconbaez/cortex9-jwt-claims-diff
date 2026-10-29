//! Runs every case against every verifier in both modes and writes
//! `results/matrix.csv`, `results/details.csv` and `results/summary.json`
//! (paths configurable with --csv, --details, --json).

use jwt_claims_diff::cases::{self, Case};
use jwt_claims_diff::verifiers::{self, Mode, Verifier};
use std::collections::BTreeMap;
use std::fmt::Write as _;

fn arg(name: &str, def: &str) -> String {
    let a: Vec<String> = std::env::args().collect();
    a.iter()
        .position(|x| x == name)
        .and_then(|i| a.get(i + 1).cloned())
        .unwrap_or_else(|| def.to_string())
}

#[derive(Default, serde::Serialize)]
struct Score {
    scored: u32,
    match_rfc: u32,
    undue_accept: Vec<String>,
    spurious_reject: Vec<String>,
    not_configurable: Vec<String>,
    unscored_accepted: Vec<String>,
}

fn verdict(r: &Result<(), String>) -> &'static str {
    if r.is_ok() { "A" } else { "R" }
}

fn main() {
    let csv = arg("--csv", "results/matrix.csv");
    let det = arg("--details", "results/details.csv");
    let js = arg("--json", "results/summary.json");
    std::panic::set_hook(Box::new(|_| {}));
    let cs: Vec<Case> = cases::all(jwt_claims_diff::now());
    let vs: Vec<Verifier> = verifiers::all();
    let mut m = String::from("case,rule,what,expected_default,expected_strict");
    for v in &vs {
        let _ = write!(m, ",{0}_default,{0}_strict", v.name);
    }
    m.push('\n');
    let mut d = String::from("case,verifier,mode,verdict,message\n");
    let mut scores: BTreeMap<String, Score> = BTreeMap::new();
    let mut divergent = 0;
    let e = |x: Option<bool>| match x {
        Some(true) => "A",
        Some(false) => "R",
        None => "-",
    };
    for c in &cs {
        let _ = write!(
            m,
            "{},{},\"{}\",{},{}",
            c.id,
            c.rule,
            c.what,
            e(c.exp_default),
            e(c.exp_strict)
        );
        let mut seen = std::collections::HashSet::new();
        for v in &vs {
            for (mode, exp, mname) in [
                (Mode::Default, c.exp_default, "default"),
                (Mode::Strict, c.exp_strict, "strict"),
            ] {
                let r = verifiers::run(v, &c.token, mode);
                let vd = verdict(&r);
                seen.insert(vd);
                let msg = r
                    .as_ref()
                    .err()
                    .cloned()
                    .unwrap_or_default()
                    .replace(['"', '\n', ','], " ");
                let _ = writeln!(d, "{},{},{},{},\"{}\"", c.id, v.name, mname, vd, msg);
                let nc = mode == Mode::Strict && c.needs.is_some_and(|cap| !v.caps.contains(&cap));
                let s = scores.entry(format!("{}/{}", v.name, mname)).or_default();
                let cell = if nc {
                    format!("{vd}(n/c)")
                } else {
                    vd.to_string()
                };
                let _ = write!(m, ",{cell}");
                match (exp, nc) {
                    (_, true) => s.not_configurable.push(c.id.into()),
                    (None, _) => {
                        if r.is_ok() {
                            s.unscored_accepted.push(c.id.into())
                        }
                    }
                    (Some(want), false) => {
                        s.scored += 1;
                        if want == r.is_ok() {
                            s.match_rfc += 1;
                        } else if r.is_ok() {
                            s.undue_accept.push(c.id.into());
                        } else {
                            s.spurious_reject.push(c.id.into());
                        }
                    }
                }
            }
        }
        if seen.len() > 1 {
            divergent += 1;
        }
        m.push('\n');
    }
    std::fs::write(&csv, m).expect("write matrix");
    std::fs::write(&det, d).expect("write details");
    let summary = serde_json::json!({
        "cases": cs.len(),
        "divergent_cases": divergent,
        "scores": scores,
    });
    std::fs::write(&js, serde_json::to_string_pretty(&summary).unwrap() + "\n")
        .expect("write json");
    println!("cases {} divergent {}", cs.len(), divergent);
    for (k, s) in &scores {
        println!(
            "{k}: match {}/{} undue_accept {:?} spurious_reject {:?} n/c {:?}",
            s.match_rfc, s.scored, s.undue_accept, s.spurious_reject, s.not_configurable
        );
    }
}
