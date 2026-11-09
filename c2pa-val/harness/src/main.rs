//! Validation harness for the Line A study: signs JPEGs through the patched
//! c2pa-rs with chosen certificate carriage, time stamp and OCSP staple, and
//! validates them against chosen trust anchors.
//!
//!     lineaval sign   SPEC.json
//!     lineaval verify SPEC.json      (prints one JSON object)
//!
//! Signing goes through the library's own COSE code except in the "direct"
//! modes (thumbprint, no chain, mismatched algorithm header), where this
//! harness builds the COSE_Sign1 itself so that the library's validator sees
//! a structure its signer would never emit.

use std::{
    fs,
    io::Cursor,
    process::Command,
    time::Instant,
};

use anyhow::{anyhow, Context as _, Result};
use c2pa::{Builder, Context, Reader, Settings, Signer, SigningAlg};
use coset::{
    cbor::value::Value, iana, CborSerializable, CoseSign1Builder, HeaderBuilder, Label,
    TaggedCborSerializable,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
struct SignSpec {
    alg: String,
    key: String,
    /// PEM files whose certificates make up x5chain, in order.
    x5chain: Vec<String>,
    input: String,
    output: String,
    /// "good" | "noeku" | "wrongimprint"
    tsa_variant: Option<String>,
    certdir: Option<String>,
    tsa_script: Option<String>,
    python: Option<String>,
    ocsp: Option<String>,
    /// "normal" | "x5t" | "nochain" | "alg:<cose id>"
    mode: Option<String>,
}

#[derive(Deserialize)]
struct VerifySpec {
    input: String,
    anchors: Vec<String>,
    tsa_anchors: Vec<String>,
}

fn pem_to_der_list(pem: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut inside = false;
    for line in pem.lines() {
        if line.starts_with("-----BEGIN CERTIFICATE") {
            inside = true;
            cur.clear();
        } else if line.starts_with("-----END CERTIFICATE") {
            inside = false;
            out.push(b64(&cur));
        } else if inside {
            cur.push_str(line.trim());
        }
    }
    out
}

fn b64(s: &str) -> Vec<u8> {
    let val = |c: u8| -> u32 {
        match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a') as u32 + 26,
            b'0'..=b'9' => (c - b'0') as u32 + 52,
            b'+' => 62,
            b'/' => 63,
            _ => 0,
        }
    };
    let bytes: Vec<u8> = s.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let pad = chunk.iter().filter(|&&c| c == b'=').count();
        let mut acc = 0u32;
        for &c in chunk {
            acc = (acc << 6) | if c == b'=' { 0 } else { val(c) };
        }
        out.push((acc >> 16) as u8);
        if pad < 2 {
            out.push((acc >> 8) as u8);
        }
        if pad < 1 {
            out.push(acc as u8);
        }
    }
    out
}

fn max_sig(alg: SigningAlg) -> usize {
    match alg {
        SigningAlg::Es256 => 132,
        SigningAlg::Ed25519 => 64,
        SigningAlg::MlDsa44 => 2420,
        SigningAlg::MlDsa65 => 3309,
        SigningAlg::MlDsa87 => 4627,
        _ => 1024,
    }
}

struct ValSigner {
    inner: Box<dyn Signer>,
    alg: SigningAlg,
    chain: Vec<Vec<u8>>,
    reserve: usize,
    tsa: Option<(String, String, String, String)>, // python, script, variant, certdir
    ocsp: Option<Vec<u8>>,
    mode: String,
}

impl ValSigner {
    fn direct(&self) -> bool {
        self.mode != "normal"
    }

    /// COSE_Sign1 built by hand for the direct modes, padded to the reserve.
    fn build_cose(&self, claim: &[u8]) -> c2pa::Result<Vec<u8>> {
        let alg_id: i64 = if let Some(id) = self.mode.strip_prefix("alg:") {
            id.parse().map_err(|_| c2pa::Error::BadParam("alg id".into()))?
        } else {
            match self.alg {
                SigningAlg::Ed25519 => -8,
                SigningAlg::MlDsa44 => -48,
                SigningAlg::MlDsa65 => -49,
                SigningAlg::MlDsa87 => -50,
                SigningAlg::Es256 => -7,
                _ => return Err(c2pa::Error::BadParam("alg".into())),
            }
        };
        use coset::iana::EnumI64;
        let alg_iana = iana::Algorithm::from_i64(alg_id)
            .ok_or_else(|| c2pa::Error::BadParam(format!("unknown COSE alg {alg_id}")))?;
        let mut hb = HeaderBuilder::new().algorithm(alg_iana);
        match self.mode.as_str() {
            "x5t" => {
                let thumb = Sha256::digest(&self.chain[0]).to_vec();
                hb = hb.value(
                    34,
                    Value::Array(vec![Value::Integer((-16i64).into()), Value::Bytes(thumb)]),
                );
            }
            "nochain" => {}
            _ => {
                let v = if self.chain.len() == 1 {
                    Value::Bytes(self.chain[0].clone())
                } else {
                    Value::Array(self.chain.iter().cloned().map(Value::Bytes).collect())
                };
                hb = hb.value(33, v);
            }
        }
        let mut err = None;
        let sign1 = CoseSign1Builder::new()
            .protected(hb.build())
            .create_detached_signature(claim, b"", |tbs| match self.inner.sign(tbs) {
                Ok(s) if self.alg == SigningAlg::Es256 => der_to_p1363(&s, 32),
                Ok(s) => s,
                Err(e) => {
                    err = Some(e);
                    Vec::new()
                }
            })
            .build();
        if let Some(e) = err {
            return Err(e);
        }
        pad(sign1, self.reserve)
    }
}

/// ECDSA DER (SEQUENCE of two INTEGERs) to the fixed-length r || s COSE uses.
/// A signature already in that form is returned unchanged.
fn der_to_p1363(der: &[u8], n: usize) -> Vec<u8> {
    if der.len() == 2 * n || der.first() != Some(&0x30) {
        return der.to_vec();
    }
    let mut i = 2;
    if der[1] & 0x80 != 0 {
        i += (der[1] & 0x7f) as usize;
    }
    let mut out = Vec::with_capacity(2 * n);
    for _ in 0..2 {
        let len = der[i + 1] as usize;
        let v = &der[i + 2..i + 2 + len];
        let v = if v.len() > n { &v[v.len() - n..] } else { v };
        out.extend(std::iter::repeat(0u8).take(n - v.len()));
        out.extend_from_slice(v);
        i += 2 + len;
    }
    out
}

/// Pad an unprotected header so the tagged COSE_Sign1 is exactly `end` bytes,
/// as c2pa-rs does for its own signatures.
fn pad(sign1: coset::CoseSign1, end: usize) -> c2pa::Result<Vec<u8>> {
    let base = sign1
        .clone()
        .to_tagged_vec()
        .map_err(|e| c2pa::Error::BadParam(e.to_string()))?;
    if base.len() + 16 > end {
        return Err(c2pa::Error::BadParam("reserve too small".into()));
    }
    let mut guess = end - base.len() - 7;
    for _ in 0..64 {
        let mut s = sign1.clone();
        s.unprotected
            .rest
            .push((Label::Text("pad".into()), Value::Bytes(vec![0u8; guess])));
        let v = s
            .to_tagged_vec()
            .map_err(|e| c2pa::Error::BadParam(e.to_string()))?;
        if v.len() == end {
            return Ok(v);
        }
        if v.len() > end {
            guess -= v.len() - end;
        } else {
            guess += end - v.len();
        }
    }
    // Lengths straddling a CBOR length-prefix boundary need a second pad.
    let mut s = sign1.clone();
    s.unprotected
        .rest
        .push((Label::Text("pad2".into()), Value::Bytes(vec![0u8; 3])));
    pad(s, end)
}

impl Signer for ValSigner {
    fn sign(&self, data: &[u8]) -> c2pa::Result<Vec<u8>> {
        if self.direct() {
            self.build_cose(data)
        } else {
            self.inner.sign(data)
        }
    }
    fn alg(&self) -> SigningAlg {
        self.alg
    }
    fn certs(&self) -> c2pa::Result<Vec<Vec<u8>>> {
        Ok(self.chain.clone())
    }
    fn reserve_size(&self) -> usize {
        self.reserve
    }
    fn send_timestamp_request(&self, message: &[u8]) -> Option<c2pa::Result<Vec<u8>>> {
        let (py, script, variant, certdir) = self.tsa.as_ref()?;
        let body = match self.timestamp_request_body(message) {
            Ok(b) => b,
            Err(e) => return Some(Err(e)),
        };
        let dir = std::env::temp_dir();
        let req = dir.join(format!("lineaval-{}.tsq", std::process::id()));
        let resp = dir.join(format!("lineaval-{}.tsr", std::process::id()));
        if fs::write(&req, &body).is_err() {
            return Some(Err(c2pa::Error::BadParam("tsq write".into())));
        }
        let st = Command::new(py)
            .args([script, variant, certdir])
            .arg(&req)
            .arg(&resp)
            .status();
        match st {
            Ok(s) if s.success() => Some(
                fs::read(&resp).map_err(|_| c2pa::Error::BadParam("tsr read".into())),
            ),
            _ => Some(Err(c2pa::Error::BadParam("tsa script failed".into()))),
        }
    }
    fn ocsp_val(&self) -> Option<Vec<u8>> {
        self.ocsp.clone()
    }
    fn direct_cose_handling(&self) -> bool {
        self.direct()
    }
}

/// The EKU list c2pa-rs ships as its default (sdk/src/crypto/cose/valid_eku_oids.cfg).
/// LINEA_EKUS overrides it, e.g. "1.3.6.1.4.1.62558.2.1" for a claimSigning-only policy.
fn eku_config() -> String {
    std::env::var("LINEA_EKUS").unwrap_or_else(|_| {
        "1.3.6.1.5.5.7.3.4\n1.3.6.1.5.5.7.3.36\n1.3.6.1.5.5.7.3.8\n1.3.6.1.5.5.7.3.9\n\
         1.3.6.1.4.1.311.76.59.1.9\n1.3.6.1.4.1.62558.2.1"
            .to_string()
    })
}

fn settings_toml(anchors: &str, tsa: &str) -> String {
    let mut s = String::from("version = 1\n");
    let ekus = eku_config();
    // The certificate-profile EKU check reads the top-level list, not the
    // per-anchor-set one, so the policy goes in both places.
    s += &format!("[trust]\ntrust_config = \"\"\"\n{ekus}\n\"\"\"\n");
    if !anchors.is_empty() {
        s += &format!(
            "[[trust.anchors]]\ntrust_uri = \"urn:line-a:manifest\"\ntrust_kind = \"manifest\"\ntrust_config = \"\"\"\n{ekus}\n\"\"\"\ntrust_anchors = \"\"\"{anchors}\"\"\"\n"
        );
    }
    if !tsa.is_empty() {
        s += &format!(
            "[[trust.anchors]]\ntrust_uri = \"urn:line-a:tsa\"\ntrust_kind = \"tsa\"\ntrust_config = \"\"\"\n1.3.6.1.5.5.7.3.8\n\"\"\"\ntrust_anchors = \"\"\"{tsa}\"\"\"\n"
        );
    }
    s += "[verify]\nverify_after_reading = true\nverify_after_sign = false\nremote_manifest_fetch = false\nverify_trust = true\nverify_timestamp_trust = true\nocsp_fetch = false\n";
    s
}

fn manifest_json() -> String {
    serde_json::json!({
        "claim_generator_info": [{"name": "line-a-validation", "version": "1"}],
        "title": "line-a.jpg",
        "format": "image/jpeg",
        "assertions": [{
            "label": "c2pa.actions",
            "data": {"actions": [{
                "action": "c2pa.created",
                "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture"
            }]}
        }]
    })
    .to_string()
}

fn cmd_sign(spec: SignSpec) -> Result<()> {
    let alg: SigningAlg = spec.alg.parse().map_err(|_| anyhow!("alg {}", spec.alg))?;
    let key = fs::read(&spec.key)?;
    let mut chain = Vec::new();
    for p in &spec.x5chain {
        chain.extend(pem_to_der_list(&fs::read_to_string(p)?));
    }
    // The inner signer only signs; its certificate is not what travels.
    let leaf_pem = fs::read(&spec.x5chain[0])?;
    let inner = c2pa::create_signer::from_keys(&leaf_pem, &key, alg, None)
        .context("create signer")?;
    let ocsp = match &spec.ocsp {
        Some(p) => Some(fs::read(p)?),
        None => None,
    };
    let chain_len: usize = chain.iter().map(|c| c.len()).sum();
    let reserve = max_sig(alg)
        + chain_len
        + 2048
        // An ES256 token is about 2 kB; an ML-DSA-65 one with its chain about 16 kB.
        + match spec.tsa_variant.as_deref() {
            Some(v) if v.starts_with("pq-") => 24000,
            Some(_) => 10000,
            None => 0,
        }
        + ocsp.as_ref().map_or(0, |o| o.len());
    let tsa = spec.tsa_variant.as_ref().map(|v| {
        (
            spec.python.clone().unwrap_or_else(|| "python3".into()),
            spec.tsa_script.clone().unwrap_or_default(),
            v.clone(),
            spec.certdir.clone().unwrap_or_default(),
        )
    });
    let signer = ValSigner {
        inner,
        alg,
        chain,
        reserve,
        tsa,
        ocsp,
        mode: spec.mode.clone().unwrap_or_else(|| "normal".into()),
    };
    let ctx = Context::new()
        .with_settings(Settings::new().with_toml(&settings_toml("", ""))?)?
        .into_shared();
    let mut builder = Builder::from_shared_context(&ctx).with_definition(manifest_json())?;
    let src = fs::read(&spec.input)?;
    let mut source = Cursor::new(src);
    let mut dest = Cursor::new(Vec::new());
    let t = Instant::now();
    let manifest = builder.sign(&signer, "image/jpeg", &mut source, &mut dest)?;
    let ms = t.elapsed().as_secs_f64() * 1e3;
    fs::write(&spec.output, dest.into_inner())?;
    println!(
        "{}",
        serde_json::json!({"signed": spec.output, "manifest_bytes": manifest.len(),
                           "reserve": reserve, "sign_ms": ms})
    );
    Ok(())
}

fn cmd_verify(spec: VerifySpec) -> Result<()> {
    let mut anchors = String::new();
    for p in &spec.anchors {
        anchors += &fs::read_to_string(p)?;
    }
    let mut tsa = String::new();
    for p in &spec.tsa_anchors {
        tsa += &fs::read_to_string(p)?;
    }
    let toml = settings_toml(&anchors, &tsa);
    let settings = Settings::new().with_toml(&toml)?;
    if std::env::var("LINEA_DEBUG").is_ok() {
        eprintln!("{toml}");
        eprintln!(
            "trust_config set: {:?}; anchor sets: {:?}",
            settings.trust.trust_config.as_ref().map(|s| s.len()),
            settings.trust.anchors.as_ref().map(|a| a.len())
        );
    }
    let ctx = Context::new().with_settings(settings)?.into_shared();
    let bytes = fs::read(&spec.input)?;
    let t = Instant::now();
    let r = Reader::from_shared_context(&ctx).with_stream("image/jpeg", Cursor::new(bytes));
    let ms = t.elapsed().as_secs_f64() * 1e3;
    let out = match r {
        Err(e) => serde_json::json!({"reader_error": e.to_string(), "verify_ms": ms}),
        Ok(reader) => {
            let state = format!("{:?}", reader.validation_state());
            let mut codes = serde_json::json!({"success": [], "informational": [], "failure": []});
            if let Some(vr) = reader.validation_results() {
                if let Some(am) = vr.active_manifest() {
                    let f = |v: &Vec<c2pa::validation_status::ValidationStatus>| -> Vec<serde_json::Value> {
                        v.iter()
                            .map(|s| serde_json::json!({"code": s.code(),
                                                        "explanation": s.explanation()}))
                            .collect()
                    };
                    codes = serde_json::json!({
                        "success": f(am.success()),
                        "informational": f(am.informational()),
                        "failure": f(am.failure()),
                    });
                }
            }
            serde_json::json!({"validation_state": state, "codes": codes, "verify_ms": ms})
        }
    };
    println!("{out}");
    Ok(())
}

#[derive(Deserialize)]
struct CheckSpec {
    /// PEM files, leaf first, then any intermediates carried in the token.
    chain: Vec<String>,
    /// Trust-anchor PEM(s): the C2PA claim-signing list.
    anchors: Vec<String>,
    /// "default" (the shipped EKU list) or "claimsigning_only".
    eku_policy: Option<String>,
}

/// Run a certificate through the library's own certificate-profile and trust
/// checks against the configured anchors, with no signature and no COSE. This
/// is the claim-signer admission test the verifier applies, in isolation.
fn cmd_checkcert(spec: CheckSpec) -> Result<()> {
    use c2pa::crypto::cose::{
        check_end_entity_certificate_profile, CertificateTrustPolicy, TrustAnchorType,
    };
    use c2pa::status_tracker::{ErrorBehavior, StatusTracker};

    let mut chain: Vec<Vec<u8>> = Vec::new();
    for p in &spec.chain {
        chain.extend(pem_to_der_list(&fs::read_to_string(p)?));
    }
    if chain.is_empty() {
        return Err(anyhow!("empty chain"));
    }
    let leaf = chain[0].clone();

    let mut ctp = CertificateTrustPolicy::new();
    for p in &spec.anchors {
        let pem = fs::read(p)?;
        ctp.add_trust_anchors(&pem, "urn:line-a:manifest", TrustAnchorType::Manifest, None)
            .map_err(|e| anyhow!("add_trust_anchors: {e}"))?;
    }
    let policy = spec.eku_policy.clone().unwrap_or_else(|| "default".into());
    match policy.as_str() {
        "claimsigning_only" => ctp.add_valid_ekus(b"1.3.6.1.4.1.62558.2.1"),
        _ => ctp.add_default_valid_ekus(),
    }

    // Certificate-profile and EKU check (no signature).
    let mut log = StatusTracker::with_error_behavior(ErrorBehavior::ContinueWhenPossible);
    let profile = check_end_entity_certificate_profile(&leaf, &ctp, &mut log, None);
    let profile_errors: Vec<_> = log
        .logged_items()
        .iter()
        .filter(|i| i.validation_status.is_some())
        .map(|i| {
            serde_json::json!({"status": i.validation_status.as_deref(),
                               "description": i.description})
        })
        .collect();
    let profile_ok = profile.is_ok() && !log.has_any_error();

    // Trust / path check against the claim-signing anchors (no signature).
    let rest: Vec<Vec<u8>> = chain[1..].to_vec();
    let trust = ctp.check_certificate_trust(&rest, &leaf, None);
    let (trust_ok, trust_anchor, trust_detail) = match &trust {
        Ok((kind, name)) => (true, format!("{kind:?}"), name.clone()),
        Err(e) => (false, String::new(), e.to_string()),
    };

    println!(
        "{}",
        serde_json::json!({
            "chain_certs": chain.len(),
            "eku_policy": policy,
            "profile_ok": profile_ok,
            "profile_errors": profile_errors,
            "trust_ok": trust_ok,
            "trust_anchor_type": trust_anchor,
            "trust_detail": trust_detail,
            "accepts_as_claim_signer": profile_ok && trust_ok,
        })
    );
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        return Err(anyhow!("usage: lineaval sign|verify|checkcert SPEC.json"));
    }
    let spec = fs::read_to_string(&args[2])?;
    match args[1].as_str() {
        "sign" => cmd_sign(serde_json::from_str(&spec)?),
        "verify" => cmd_verify(serde_json::from_str(&spec)?),
        "checkcert" => cmd_checkcert(serde_json::from_str(&spec)?),
        _ => Err(anyhow!("unknown command")),
    }
}
