#!/usr/bin/env python3
"""Port the Line A ML-DSA patch to c2pa_raw_crypto 0.2.0 and c2pa-rs main.

    port.py p1   registrations the original patch needed (signer, validator,
                 ml-dsa dependency): ML-DSA manifests sign and verify, but a
                 certificate signed with ML-DSA cannot be path-validated.
    port.py p2   adds ML-DSA to certificate path validation (which also covers
                 time-stamp signer certificates, through
                 validator_for_sig_and_hash_algs) and to the OCSP response
                 signature check (hash_alg_for_sig_alg).
Idempotent: each edit checks for its marker first.
"""
import pathlib
import re
import sys

V = pathlib.Path.home() / "line-a-experiments" / "c2pa-val"
RC = V / "c2pa_raw_crypto"
SDK = V / "c2pa-rs" / "sdk"
MARK = "Line A"


def edit(path, old, new, count=1):
    p = pathlib.Path(path)
    s = p.read_text()
    if new in s:
        return
    if s.count(old) != count:
        sys.exit(f"{path}: expected {count} of {old[:60]!r}, found {s.count(old)}")
    p.write_text(s.replace(old, new))


def p1():
    cargo = RC / "Cargo.toml"
    s = cargo.read_text()
    if "ml-dsa" not in s:
        s = s.replace('rust_native_crypto = [', 'rust_native_crypto = [\n    "dep:ml-dsa",', 1)
        s = s.replace("[dependencies.pkcs8]",
                      '[dependencies.ml-dsa]\nversion = "0.1"\nfeatures = ["pkcs8"]\noptional = true\n\n[dependencies.pkcs8]', 1)
        cargo.write_text(s)

    sm = RC / "src/rust_native/signers/mod.rs"
    edit(sm, "mod ed25519_signer;\n", "mod ed25519_signer;\nmod mldsa_signer; // Line A\n")
    edit(sm, """        SigningAlg::Es256 | SigningAlg::Es384 | SigningAlg::Es512 => Ok(Box::new(
            ecdsa_signer::EcdsaSigner::from_private_key(private_key, alg)?,
        )),
""", """        SigningAlg::Es256 | SigningAlg::Es384 | SigningAlg::Es512 => Ok(Box::new(
            ecdsa_signer::EcdsaSigner::from_private_key(private_key, alg)?,
        )),

        // Line A: ML-DSA, RFC 9964.
        SigningAlg::MlDsa44 | SigningAlg::MlDsa65 | SigningAlg::MlDsa87 => Ok(Box::new(
            mldsa_signer::MlDsaSigner::from_private_key(private_key, alg)?,
        )),
""")
    vm = RC / "src/rust_native/validators/mod.rs"
    edit(vm, "mod rsa_validator;\npub(crate) use rsa_validator::RsaValidator;\n",
         "mod rsa_validator;\npub(crate) use rsa_validator::RsaValidator;\n\n"
         "mod mldsa_validator; // Line A\npub(crate) use mldsa_validator::MlDsaValidator;\n")
    edit(vm, "        SigningAlg::Es512 => Some(Box::new(EcdsaValidator::Es512)),\n    }\n}",
         "        SigningAlg::Es512 => Some(Box::new(EcdsaValidator::Es512)),\n"
         "        // Line A\n"
         "        SigningAlg::MlDsa44 => Some(Box::new(MlDsaValidator::MlDsa44)),\n"
         "        SigningAlg::MlDsa65 => Some(Box::new(MlDsaValidator::MlDsa65)),\n"
         "        SigningAlg::MlDsa87 => Some(Box::new(MlDsaValidator::MlDsa87)),\n    }\n}")
    print("p1 applied")


def p2():
    oids = RC / "src/oids.rs"
    s = oids.read_text()
    if "ML_DSA_44_OID" not in s:
        s += """
// Line A: ML-DSA, FIPS 204 / RFC 9881. One OID names both the key and the
// signature algorithm.
/// `id-ml-dsa-44` (2.16.840.1.101.3.4.3.17).
pub const ML_DSA_44_OID: Oid<'static> =
    Oid::new(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11]);
/// `id-ml-dsa-65` (2.16.840.1.101.3.4.3.18).
pub const ML_DSA_65_OID: Oid<'static> =
    Oid::new(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12]);
/// `id-ml-dsa-87` (2.16.840.1.101.3.4.3.19).
pub const ML_DSA_87_OID: Oid<'static> =
    Oid::new(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13]);
"""
        oids.write_text(s)
    vm = RC / "src/rust_native/validators/mod.rs"
    edit(vm, """    if sig_alg == ED25519_OID.as_bytes() {
        return Some(Box::new(Ed25519Validator {}));
    }
""", """    if sig_alg == ED25519_OID.as_bytes() {
        return Some(Box::new(Ed25519Validator {}));
    }
    // Line A: pure ML-DSA; the hash OID plays no part.
    if sig_alg == ML_DSA_44_OID.as_bytes() {
        return Some(Box::new(MlDsaValidator::MlDsa44));
    }
    if sig_alg == ML_DSA_65_OID.as_bytes() {
        return Some(Box::new(MlDsaValidator::MlDsa65));
    }
    if sig_alg == ML_DSA_87_OID.as_bytes() {
        return Some(Box::new(MlDsaValidator::MlDsa87));
    }
""")
    rn = SDK / "src/crypto/cose/certificate_trust/rust_native.rs"
    edit(rn, """        "ed25519" => pair(&ED25519_OID, &SHA512_OID),
        _ => None,""", """        "ed25519" => pair(&ED25519_OID, &SHA512_OID),
        // Line A: ML-DSA certificate signatures.
        "mldsa44" => pair(&ML_DSA_44_OID, &SHA512_OID),
        "mldsa65" => pair(&ML_DSA_65_OID, &SHA512_OID),
        "mldsa87" => pair(&ML_DSA_87_OID, &SHA512_OID),
        _ => None,""")
    edit(rn, """    } else if cert_alg == ED25519_OID.as_bytes() {
        Some(SigningAlg::Ed25519.to_string())
    } else {""", """    } else if cert_alg == ED25519_OID.as_bytes() {
        Some(SigningAlg::Ed25519.to_string())
    } else if cert_alg == ML_DSA_44_OID.as_bytes() {
        Some(SigningAlg::MlDsa44.to_string()) // Line A
    } else if cert_alg == ML_DSA_65_OID.as_bytes() {
        Some(SigningAlg::MlDsa65.to_string())
    } else if cert_alg == ML_DSA_87_OID.as_bytes() {
        Some(SigningAlg::MlDsa87.to_string())
    } else {""")
    om = SDK / "src/crypto/ocsp/mod.rs"
    edit(om, """        "1.3.101.112" => Some(bcder::Oid::from_str("2.16.840.1.101.3.4.2.3").ok()?),
        _ => None,""", """        "1.3.101.112" => Some(bcder::Oid::from_str("2.16.840.1.101.3.4.2.3").ok()?),
        // Line A: ML-DSA OCSP responders; pure ML-DSA, the hash OID is unused.
        "2.16.840.1.101.3.4.3.17" | "2.16.840.1.101.3.4.3.18" | "2.16.840.1.101.3.4.3.19" => {
            Some(bcder::Oid::from_str("2.16.840.1.101.3.4.2.3").ok()?)
        }
        _ => None,""")
    print("p2 applied")


if __name__ == "__main__":
    {"p1": p1, "p2": p2}[sys.argv[1]]()
