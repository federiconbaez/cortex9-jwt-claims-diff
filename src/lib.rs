//! Differential test of JWT claim validation (RFC 7519, RFC 7515 `crit`,
//! RFC 8725) across three Rust crates, each in a default and a strict mode.
//!
//! Tokens are HS256 and are built from raw JSON text, so malformed and
//! duplicated members can be expressed. Only claim and header semantics
//! differ between cases; the signature is always correct unless the case
//! is about the signature encoding.

pub mod cases;
pub mod verifiers;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Shared HMAC key.
pub const KEY: &[u8; 32] = b"jwt-claims-diff shared hs256 key";
/// Issuer expected in strict mode.
pub const ISS: &str = "https://issuer.example";
/// Audience expected in strict mode.
pub const AUD: &str = "api://cortex9";
/// Leeway configured in strict mode, seconds.
pub const STRICT_LEEWAY: u64 = 60;

/// How the third segment is encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigEnc {
    /// base64url without padding (correct).
    Url,
    /// Empty signature (for `alg: none`).
    Empty,
    /// base64url with `=` padding.
    Padded,
    /// Standard base64 alphabet (`+` `/`).
    StdAlphabet,
    /// Correct token with a fourth segment appended.
    ExtraSegment,
}

/// HMAC-SHA256 tag.
pub fn tag(input: &[u8]) -> Vec<u8> {
    let mut m = Hmac::<Sha256>::new_from_slice(KEY).expect("key");
    m.update(input);
    m.finalize().into_bytes().to_vec()
}

/// Build a compact token from raw header and payload JSON text.
pub fn build(header: &str, payload: &str, enc: SigEnc) -> String {
    let si = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(payload)
    );
    let t = tag(si.as_bytes());
    match enc {
        SigEnc::Url => format!("{si}.{}", URL_SAFE_NO_PAD.encode(&t)),
        SigEnc::Empty => format!("{si}."),
        SigEnc::Padded => format!(
            "{si}.{}",
            STANDARD.encode(&t).replace('+', "-").replace('/', "_")
        ),
        SigEnc::StdAlphabet => format!("{si}.{}", STANDARD.encode(&t).trim_end_matches('=')),
        SigEnc::ExtraSegment => format!("{si}.{}.e30", URL_SAFE_NO_PAD.encode(&t)),
    }
}

/// Current Unix time in seconds.
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs() as i64
}
