//! The case corpus. `exp_default` / `exp_strict`: `Some(true)` must accept,
//! `Some(false)` must reject, `None` not scored (the RFCs leave it open).
//! `needs`: the strict-mode policy capability the case depends on.

use crate::{AUD, ISS, SigEnc, build};

/// Strict-mode policy that a crate may or may not be able to express.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Cap {
    RequireExp,
    RequireIss,
    RequireAud,
    RequireTyp,
    Leeway,
    NbfCheck,
}

/// One test case.
#[derive(Clone, Debug)]
pub struct Case {
    pub id: &'static str,
    pub rule: &'static str,
    pub what: &'static str,
    pub token: String,
    pub exp_default: Option<bool>,
    pub exp_strict: Option<bool>,
    pub needs: Option<Cap>,
}

const H: &str = r#"{"alg":"HS256","typ":"JWT"}"#;

fn full(now: i64, extra: &str) -> String {
    format!(
        r#"{{"iss":"{ISS}","aud":"{AUD}","sub":"alice","iat":{},"exp":{}{extra}}}"#,
        now - 10,
        now + 3600
    )
}

#[allow(clippy::too_many_arguments)]
fn c(
    id: &'static str,
    rule: &'static str,
    what: &'static str,
    header: &str,
    payload: &str,
    enc: SigEnc,
    d: Option<bool>,
    s: Option<bool>,
    needs: Option<Cap>,
) -> Case {
    Case {
        id,
        rule,
        what,
        token: build(header, payload, enc),
        exp_default: d,
        exp_strict: s,
        needs,
    }
}

/// Build all cases relative to `now` (Unix seconds).
pub fn all(now: i64) -> Vec<Case> {
    use Cap::*;
    use SigEnc::*;
    let a = Some(true);
    let r = Some(false);
    let o = None;
    let iat = now - 10;
    let base = |exp: &str| {
        format!(r#"{{"iss":"{ISS}","aud":"{AUD}","sub":"alice","iat":{iat},"exp":{exp}}}"#)
    };
    let with_aud = |aud: &str| {
        format!(
            r#"{{"iss":"{ISS}","aud":{aud},"sub":"alice","iat":{iat},"exp":{}}}"#,
            now + 3600
        )
    };
    let with_iss = |iss: &str| {
        format!(
            r#"{{"iss":{iss},"aud":"{AUD}","sub":"alice","iat":{iat},"exp":{}}}"#,
            now + 3600
        )
    };
    let no_aud = format!(
        r#"{{"iss":"{ISS}","sub":"alice","iat":{iat},"exp":{}}}"#,
        now + 3600
    );
    let no_iss = format!(
        r#"{{"aud":"{AUD}","sub":"alice","iat":{iat},"exp":{}}}"#,
        now + 3600
    );
    let no_exp = format!(r#"{{"iss":"{ISS}","aud":"{AUD}","sub":"alice","iat":{iat}}}"#);
    let p = full(now, "");
    vec![
        c(
            "V01",
            "7519 4.1.3",
            "valid token, all claims (default mode has no audience identity)",
            H,
            &p,
            Url,
            o,
            a,
            None,
        ),
        c(
            "V02",
            "7519",
            "valid, only exp (no iss/aud)",
            H,
            &format!(r#"{{"exp":{}}}"#, now + 3600),
            Url,
            o,
            r,
            Some(RequireIss),
        ),
        c(
            "E01",
            "7519 4.1.4",
            "exp 2 h in the past",
            H,
            &base(&(now - 7200).to_string()),
            Url,
            r,
            r,
            None,
        ),
        c(
            "E02",
            "7519 4.1.4",
            "exp 10 min in the past (beyond a few minutes)",
            H,
            &base(&(now - 600).to_string()),
            Url,
            o,
            r,
            Some(Leeway),
        ),
        c(
            "E03",
            "7519 4.1.4",
            "exp 30 s in the past (inside 60 s leeway)",
            H,
            &base(&(now - 30).to_string()),
            Url,
            o,
            a,
            Some(Leeway),
        ),
        c(
            "E04",
            "7519 4.1.4",
            "exp as a JSON string",
            H,
            &base(&format!("\"{}\"", now + 3600)),
            Url,
            r,
            r,
            None,
        ),
        c(
            "E05",
            "7519 2",
            "exp non-integer NumericDate",
            H,
            &base(&format!("{}.5", now + 3600)),
            Url,
            a,
            a,
            None,
        ),
        c(
            "E06",
            "policy: exp required",
            "exp missing",
            H,
            &no_exp,
            Url,
            o,
            r,
            Some(RequireExp),
        ),
        c(
            "E07",
            "7519 4.1.4",
            "exp null",
            H,
            &base("null"),
            Url,
            r,
            r,
            None,
        ),
        c(
            "E08",
            "7519 4.1.4",
            "exp negative",
            H,
            &base("-1"),
            Url,
            r,
            r,
            None,
        ),
        c(
            "N01",
            "7519 4.1.5",
            "nbf 2 h in the future",
            H,
            &full(now, &format!(r#","nbf":{}"#, now + 7200)),
            Url,
            r,
            r,
            Some(NbfCheck),
        ),
        c(
            "N02",
            "7519 4.1.5",
            "nbf 30 s in the future (inside leeway)",
            H,
            &full(now, &format!(r#","nbf":{}"#, now + 30)),
            Url,
            o,
            a,
            Some(Leeway),
        ),
        c(
            "N03",
            "7519 4.1.5",
            "nbf as a JSON string",
            H,
            &full(now, &format!(r#","nbf":"{}""#, now - 60)),
            Url,
            r,
            r,
            Some(NbfCheck),
        ),
        c(
            "I01",
            "7519 4.1.6",
            "iat 2 h in the future",
            H,
            &format!(
                r#"{{"iss":"{ISS}","aud":"{AUD}","iat":{},"exp":{}}}"#,
                now + 7200,
                now + 9000
            ),
            Url,
            o,
            o,
            None,
        ),
        c(
            "I02",
            "7519 4.1.6",
            "iat as a JSON string",
            H,
            &format!(
                r#"{{"iss":"{ISS}","aud":"{AUD}","iat":"{iat}","exp":{}}}"#,
                now + 3600
            ),
            Url,
            o,
            o,
            None,
        ),
        c(
            "A01",
            "7519 4.1.3",
            "aud array containing the expected value",
            H,
            &with_aud(&format!(r#"["other","{AUD}"]"#)),
            Url,
            o,
            a,
            None,
        ),
        c(
            "A02",
            "7519 4.1.3",
            "aud string, other value",
            H,
            &with_aud(r#""api://other""#),
            Url,
            o,
            r,
            None,
        ),
        c(
            "A03",
            "7519 4.1.3",
            "aud array without the expected value",
            H,
            &with_aud(r#"["a","b"]"#),
            Url,
            o,
            r,
            None,
        ),
        c(
            "A04",
            "7519 4.1.3",
            "aud empty array",
            H,
            &with_aud("[]"),
            Url,
            o,
            r,
            None,
        ),
        c(
            "A05",
            "7519 4.1.3",
            "aud as a number",
            H,
            &with_aud("42"),
            Url,
            o,
            r,
            None,
        ),
        c(
            "A06",
            "8725 3.9",
            "aud missing",
            H,
            &no_aud,
            Url,
            o,
            r,
            Some(RequireAud),
        ),
        c(
            "A07",
            "7519 2 StringOrURI",
            "aud differs only in case",
            H,
            &with_aud(&format!("\"{}\"", AUD.to_uppercase())),
            Url,
            o,
            r,
            None,
        ),
        c(
            "S01",
            "7519 4.1.1",
            "iss other value",
            H,
            &with_iss(r#""https://evil.example""#),
            Url,
            o,
            r,
            None,
        ),
        c(
            "S02",
            "8725 3.8",
            "iss missing",
            H,
            &no_iss,
            Url,
            o,
            r,
            Some(RequireIss),
        ),
        c(
            "S03",
            "7519 2 StringOrURI",
            "iss with a trailing slash",
            H,
            &with_iss(&format!("\"{ISS}/\"")),
            Url,
            o,
            r,
            None,
        ),
        c(
            "S04",
            "7519 4.1.1",
            "iss as a number",
            H,
            &with_iss("7"),
            Url,
            o,
            r,
            None,
        ),
        c(
            "C01",
            "7515 4.1.11",
            "crit lists an extension the verifier does not understand",
            r#"{"alg":"HS256","typ":"JWT","crit":["x-cx9"],"x-cx9":1}"#,
            &p,
            Url,
            r,
            r,
            None,
        ),
        c(
            "C02",
            "7515 4.1.11 (recipient MAY)",
            "crit is an empty list",
            r#"{"alg":"HS256","typ":"JWT","crit":[]}"#,
            &p,
            Url,
            r,
            r,
            None,
        ),
        c(
            "C03",
            "7515 4.1.11",
            "crit is a string, not an array",
            r#"{"alg":"HS256","typ":"JWT","crit":"x-cx9","x-cx9":1}"#,
            &p,
            Url,
            r,
            r,
            None,
        ),
        c(
            "T01",
            "8725 3.11",
            "typ of another JWT kind (secevent+jwt)",
            r#"{"alg":"HS256","typ":"secevent+jwt"}"#,
            &p,
            Url,
            o,
            r,
            Some(RequireTyp),
        ),
        c(
            "T02",
            "7519 5.1",
            "typ missing",
            r#"{"alg":"HS256"}"#,
            &p,
            Url,
            a,
            o,
            None,
        ),
        c(
            "G01",
            "8725 3.1",
            "alg none with empty signature",
            r#"{"alg":"none","typ":"JWT"}"#,
            &p,
            Empty,
            r,
            r,
            None,
        ),
        c(
            "G02",
            "8725 3.1",
            "header alg HS384, HS256 signature",
            r#"{"alg":"HS384","typ":"JWT"}"#,
            &p,
            Url,
            r,
            r,
            None,
        ),
        c(
            "G03",
            "7518 3.1",
            "alg in lower case (hs256)",
            r#"{"alg":"hs256","typ":"JWT"}"#,
            &p,
            Url,
            r,
            r,
            None,
        ),
        c(
            "G04",
            "7515 4",
            "header is a JSON array",
            r#"["HS256"]"#,
            &p,
            Url,
            r,
            r,
            None,
        ),
        c(
            "G05",
            "7519 7.2",
            "payload is a JSON array",
            H,
            "[1,2]",
            Url,
            r,
            r,
            None,
        ),
        c(
            "G06",
            "7519 7.2",
            "payload with trailing garbage",
            H,
            &format!("{p}x"),
            Url,
            r,
            r,
            None,
        ),
        c(
            "G07",
            "7515 7.1",
            "four segments",
            H,
            &p,
            ExtraSegment,
            r,
            r,
            None,
        ),
        c(
            "G08",
            "7515 2",
            "signature with = padding",
            H,
            &p,
            Padded,
            r,
            r,
            None,
        ),
        c(
            "G09",
            "7515 2",
            "signature in the standard base64 alphabet",
            H,
            &std_alpha_payload(now),
            StdAlphabet,
            r,
            r,
            None,
        ),
        c(
            "D01",
            "7519 4",
            "duplicate exp: first valid, last expired",
            H,
            &format!(
                r#"{{"iss":"{ISS}","aud":"{AUD}","exp":{},"exp":{}}}"#,
                now + 3600,
                now - 7200
            ),
            Url,
            r,
            r,
            None,
        ),
        c(
            "D02",
            "7519 4",
            "duplicate iss: first expected, last other",
            H,
            &format!(
                r#"{{"iss":"{ISS}","aud":"{AUD}","exp":{},"iss":"https://evil.example"}}"#,
                now + 3600
            ),
            Url,
            o,
            r,
            None,
        ),
        c(
            "D03",
            "7515 4",
            "duplicate alg in header: HS256 then none",
            r#"{"alg":"HS256","typ":"JWT","alg":"none"}"#,
            &p,
            Url,
            r,
            r,
            None,
        ),
    ]
}

/// A full payload whose HS256 tag in standard base64 contains `+` or `/`,
/// so the standard-alphabet case really differs from base64url.
pub fn std_alpha_payload(now: i64) -> String {
    use base64::Engine;
    for n in 0u32.. {
        let p = full(now, &format!(r#","jti":"{n}""#));
        let si = format!(
            "{}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(H),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&p)
        );
        let s = base64::engine::general_purpose::STANDARD.encode(crate::tag(si.as_bytes()));
        if s.contains('+') || s.contains('/') {
            return p;
        }
    }
    unreachable!()
}
