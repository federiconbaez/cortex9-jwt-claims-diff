//! Verifier wrappers. Each returns `Ok(())` if the crate accepted the token
//! or `Err(message)` with the crate's own error text. A panic is caught and
//! reported as `Err("panic")`.

use crate::cases::Cap;
use crate::{AUD, ISS, KEY, STRICT_LEEWAY};

/// Verification mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// The minimal verification call documented by the crate.
    Default,
    /// Expected iss and aud, required claims, 60 s leeway and typ, as far
    /// as the crate's own options allow.
    Strict,
}

/// A crate under test.
pub struct Verifier {
    pub name: &'static str,
    pub verify: fn(&str, Mode) -> Result<(), String>,
    /// Strict-mode policies the crate's own options can express.
    pub caps: &'static [Cap],
}

/// All verifiers, in report order.
pub fn all() -> Vec<Verifier> {
    use Cap::*;
    vec![
        Verifier {
            name: "jsonwebtoken",
            verify: jsonwebtoken_v,
            caps: &[RequireExp, RequireIss, RequireAud, Leeway, NbfCheck],
        },
        Verifier {
            name: "jwt-simple",
            verify: jwt_simple_v,
            caps: &[RequireIss, RequireAud, RequireTyp, Leeway, NbfCheck],
        },
        Verifier {
            name: "josekit",
            verify: josekit_v,
            caps: &[RequireIss, NbfCheck],
        },
    ]
}

/// Run a verifier, turning panics into errors.
pub fn run(v: &Verifier, token: &str, mode: Mode) -> Result<(), String> {
    let f = v.verify;
    let t = token.to_string();
    std::panic::catch_unwind(move || f(&t, mode)).unwrap_or_else(|_| Err("panic".into()))
}

fn jsonwebtoken_v(tok: &str, mode: Mode) -> Result<(), String> {
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
    let key = DecodingKey::from_secret(KEY);
    let mut v = Validation::new(Algorithm::HS256);
    if mode == Mode::Strict {
        v.set_issuer(&[ISS]);
        v.set_audience(&[AUD]);
        v.set_required_spec_claims(&["exp", "iss", "aud"]);
        v.validate_nbf = true;
        v.leeway = STRICT_LEEWAY;
    }
    decode::<serde_json::Value>(tok, &key, &v)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn jwt_simple_v(tok: &str, mode: Mode) -> Result<(), String> {
    use jwt_simple::prelude::*;
    let key = HS256Key::from_bytes(KEY);
    let opts = match mode {
        Mode::Default => None,
        Mode::Strict => Some(VerificationOptions {
            allowed_issuers: Some(HashSet::from_strings(&[ISS])),
            allowed_audiences: Some(HashSet::from_strings(&[AUD])),
            time_tolerance: Some(Duration::from_secs(STRICT_LEEWAY)),
            required_signature_type: Some("JWT".into()),
            ..Default::default()
        }),
    };
    key.verify_token::<NoCustomClaims>(tok, opts)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn josekit_v(tok: &str, mode: Mode) -> Result<(), String> {
    use josekit::jws::HS256;
    use josekit::jwt::{JwtPayloadValidator, decode_with_verifier};
    let verifier = HS256.verifier_from_bytes(KEY).map_err(|e| e.to_string())?;
    let (payload, _header) = decode_with_verifier(tok, &verifier).map_err(|e| e.to_string())?;
    let mut val = JwtPayloadValidator::new();
    if mode == Mode::Strict {
        val.set_issuer(ISS);
        val.set_audience(AUD);
    }
    val.validate(&payload).map_err(|e| e.to_string())
}
