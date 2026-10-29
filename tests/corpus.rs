use jwt_claims_diff::cases::{Case, all};
use jwt_claims_diff::verifiers::{self, Mode};
use jwt_claims_diff::{SigEnc, build, now};

fn corpus() -> Vec<Case> {
    all(now())
}

#[test]
fn ids_unique_and_enough_scored_cases() {
    let c = corpus();
    let mut ids: Vec<_> = c.iter().map(|x| x.id).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), c.len());
    let scored = c
        .iter()
        .filter(|x| x.exp_default.is_some() || x.exp_strict.is_some())
        .count();
    assert!(scored >= 30, "only {scored} scored cases");
}

#[test]
fn positive_control_valid_token_accepted_everywhere() {
    let c = corpus();
    // Strict mode: V01 (all claims). Default mode: V02 (only exp), because a
    // verifier with no audience identity may reject any token carrying aud
    // (RFC 7519 4.1.3).
    for (id, m) in [("V01", Mode::Strict), ("V02", Mode::Default)] {
        let case = c.iter().find(|x| x.id == id).unwrap();
        for v in verifiers::all() {
            let r = verifiers::run(&v, &case.token, m);
            assert!(r.is_ok(), "{} {:?} rejected {}: {:?}", v.name, m, id, r);
        }
    }
}

#[test]
fn negative_control_bad_signature_rejected_everywhere() {
    let c = corpus();
    let v01 = c.iter().find(|x| x.id == "V01").unwrap();
    // Flip one character of the signature.
    let mut t = v01.token.clone().into_bytes();
    let last = t.len() - 2;
    t[last] = if t[last] == b'A' { b'B' } else { b'A' };
    let t = String::from_utf8(t).unwrap();
    for v in verifiers::all() {
        for m in [Mode::Default, Mode::Strict] {
            assert!(
                verifiers::run(&v, &t, m).is_err(),
                "{} {:?} accepted a bad signature",
                v.name,
                m
            );
        }
    }
}

#[test]
fn std_alphabet_case_really_uses_plus_or_slash() {
    let c = corpus();
    let g09 = c.iter().find(|x| x.id == "G09").unwrap();
    let sig = g09.token.rsplit('.').next().unwrap();
    assert!(sig.contains('+') || sig.contains('/'));
}

#[test]
fn builder_shapes() {
    let t = build(r#"{"alg":"HS256"}"#, "{}", SigEnc::Url);
    assert_eq!(t.split('.').count(), 3);
    assert!(build("{}", "{}", SigEnc::Empty).ends_with('.'));
    assert_eq!(
        build("{}", "{}", SigEnc::ExtraSegment).split('.').count(),
        4
    );
    assert!(build("{}", "{}", SigEnc::Padded).ends_with('='));
}
