// Added for the Line A measurement study: an ML-DSA raw signer, so that the
// C2PA reference implementation can produce a post-quantum manifest.
//
// RFC 9964 ("ML-DSA for JOSE and COSE", Standards Track, May 2026) assigns
// COSE algorithm identifiers -48, -49 and -50 to ML-DSA-44, -65 and -87. The
// COSE layer beneath this crate already knows them; what was missing was a
// signer here and a variant in `SigningAlg`.
//
// Private keys arrive as PKCS#8 PEM, the same shape every other signer in this
// module accepts. For ML-DSA the PKCS#8 private key is the 32-byte seed.

use ml_dsa::{
    MlDsa44, MlDsa65, MlDsa87, SignatureEncoding, Signer as MlDsaSignerTrait, SigningKey,
    pkcs8::DecodePrivateKey,
};

use crate::{RawSigner, RawSignerError, SigningAlg};

/// Signs with ML-DSA at one of the three parameter sets.
///
/// The three sets are distinct types in `ml-dsa`, so they cannot share one
/// field; the enum is what that costs.
pub(crate) enum MlDsaSigner {
    MlDsa44(Box<SigningKey<MlDsa44>>),
    MlDsa65(Box<SigningKey<MlDsa65>>),
    MlDsa87(Box<SigningKey<MlDsa87>>),
}

// The PKCS#8 impls in `ml-dsa` are bounded on a trait the crate does not
// re-export publicly, so a generic helper cannot name that bound from here.
// Three concrete helpers avoid the problem and cost nothing; this macro writes
// them.
/// Accepts a PKCS#8 key as PEM or as raw DER.
///
/// `from_pkcs8_pem` sits behind the `pem` feature of the `pkcs8` crate, and
/// turning that on here pulls in a second major version of `pkcs8` alongside
/// the one `ecdsa` already uses, which breaks the other signers in this
/// module. Stripping the armour by hand is the smaller change, and it keeps
/// this signer's interface identical to its neighbours: callers pass PEM, as
/// they do everywhere else in the crate.
fn pkcs8_der(private_key: &[u8]) -> Result<Vec<u8>, RawSignerError> {
    let bad = |m: &str| RawSignerError::InvalidSigningCredentials(m.to_string());

    let text = match std::str::from_utf8(private_key) {
        Ok(t) if t.contains("-----BEGIN") => t,
        // Not PEM: assume it is already DER and let the decoder judge it.
        _ => return Ok(private_key.to_vec()),
    };

    let body: String = text
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .flat_map(|l| l.chars())
        .filter(|c| !c.is_whitespace())
        .collect();

    // Base64, RFC 4648 alphabet, with the padding that PEM always carries.
    let value = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a') as u32 + 26,
            b'0'..=b'9' => (c - b'0') as u32 + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    };

    let bytes = body.as_bytes();
    if bytes.len() % 4 != 0 {
        return Err(bad("private key is not valid base64"));
    }

    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let pad = chunk.iter().filter(|&&c| c == b'=').count();
        let mut acc = 0u32;
        for &c in chunk {
            acc = (acc << 6) | if c == b'=' { 0 } else {
                value(c).ok_or_else(|| bad("private key is not valid base64"))?
            };
        }
        out.push((acc >> 16) as u8);
        if pad < 2 {
            out.push((acc >> 8) as u8);
        }
        if pad < 1 {
            out.push(acc as u8);
        }
    }
    Ok(out)
}

macro_rules! parse_for {
    ($name:ident, $param:ty) => {
        fn $name(private_key: &[u8]) -> Result<SigningKey<$param>, RawSignerError> {
            let der = pkcs8_der(private_key)?;
            SigningKey::<$param>::from_pkcs8_der(&der).map_err(|e| {
                RawSignerError::InvalidSigningCredentials(format!("invalid private key: {e}"))
            })
        }
    };
}

parse_for!(parse_44, MlDsa44);
parse_for!(parse_65, MlDsa65);
parse_for!(parse_87, MlDsa87);

impl MlDsaSigner {
    pub(crate) fn from_private_key(
        private_key: &[u8],
        alg: SigningAlg,
    ) -> Result<Self, RawSignerError> {
        match alg {
            SigningAlg::MlDsa44 => Ok(Self::MlDsa44(Box::new(parse_44(private_key)?))),
            SigningAlg::MlDsa65 => Ok(Self::MlDsa65(Box::new(parse_65(private_key)?))),
            SigningAlg::MlDsa87 => Ok(Self::MlDsa87(Box::new(parse_87(private_key)?))),
            _ => Err(RawSignerError::InternalError(
                "MlDsaSigner called with a non-ML-DSA algorithm".to_string(),
            )),
        }
    }
}

impl RawSigner for MlDsaSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, RawSignerError> {
        Ok(match self {
            Self::MlDsa44(k) => k.sign(data).to_vec(),
            Self::MlDsa65(k) => k.sign(data).to_vec(),
            Self::MlDsa87(k) => k.sign(data).to_vec(),
        })
    }

    fn alg(&self) -> SigningAlg {
        match self {
            Self::MlDsa44(_) => SigningAlg::MlDsa44,
            Self::MlDsa65(_) => SigningAlg::MlDsa65,
            Self::MlDsa87(_) => SigningAlg::MlDsa87,
        }
    }

    /// ML-DSA signatures are fixed length: 2420, 3309 and 4627 bytes.
    ///
    /// That fixed length matters more here than it looks. C2PA reserves a
    /// block in the manifest before signing and pads to fill it, so a signer
    /// that overstates this figure wastes those bytes in every asset it signs.
    fn max_signature_size(&self) -> usize {
        match self {
            Self::MlDsa44(_) => 2420,
            Self::MlDsa65(_) => 3309,
            Self::MlDsa87(_) => 4627,
        }
    }
}
