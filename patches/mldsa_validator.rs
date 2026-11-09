// Added for the Line A measurement study: an ML-DSA raw signature validator.
//
// The public key arrives as a DER SubjectPublicKeyInfo taken from the signer's
// certificate, which is how every other validator in this module receives it.
// The algorithm OID in that SPKI is checked by `ml-dsa` itself when the key is
// decoded, so a key of the wrong parameter set is rejected rather than
// silently mis-verified.

use ml_dsa::{
    MlDsa44, MlDsa65, MlDsa87, Signature, Verifier, VerifyingKey,
    pkcs8::spki::SubjectPublicKeyInfoRef,
};

use crate::{RawSignatureValidationError, RawSignatureValidator};

pub(crate) enum MlDsaValidator {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

// As in the signer, the bound these impls need is not publicly nameable from
// outside `ml-dsa`, so the three parameter sets get three concrete functions.
macro_rules! check_for {
    ($name:ident, $param:ty) => {
        fn $name(
            sig: &[u8],
            data: &[u8],
            public_key: &[u8],
        ) -> Result<(), RawSignatureValidationError> {
            let spki = SubjectPublicKeyInfoRef::try_from(public_key)
                .map_err(|_| RawSignatureValidationError::InvalidPublicKey)?;

            let vk = VerifyingKey::<$param>::try_from(spki)
                .map_err(|_| RawSignatureValidationError::InvalidPublicKey)?;

            let signature = Signature::<$param>::try_from(sig)
                .map_err(|_| RawSignatureValidationError::InvalidSignature)?;

            vk.verify(data, &signature)
                .map_err(|_| RawSignatureValidationError::SignatureMismatch)
        }
    };
}

check_for!(check_44, MlDsa44);
check_for!(check_65, MlDsa65);
check_for!(check_87, MlDsa87);

impl RawSignatureValidator for MlDsaValidator {
    fn validate(
        &self,
        sig: &[u8],
        data: &[u8],
        public_key: &[u8],
    ) -> Result<(), RawSignatureValidationError> {
        match self {
            Self::MlDsa44 => check_44(sig, data, public_key),
            Self::MlDsa65 => check_65(sig, data, public_key),
            Self::MlDsa87 => check_87(sig, data, public_key),
        }
    }
}
