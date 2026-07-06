//! Threshold signature verification for agent guardian approvals.
//!
//! This crate intentionally wraps the upstream Zcash FROST implementation
//! instead of implementing threshold Schnorr signing locally.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ThresholdError {
    #[error("unsupported threshold algorithm")]
    UnsupportedAlgorithm,
    #[error("invalid FROST verifying key")]
    InvalidVerifyingKey,
    #[error("invalid FROST signature")]
    InvalidSignatureEncoding,
    #[error("FROST signature verification failed")]
    VerificationFailed,
}

#[must_use = "discarding threshold verification results is a security bug"]
pub fn verify_frost_ristretto255(
    verifying_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), ThresholdError> {
    let verifying_key: [u8; 32] = verifying_key
        .try_into()
        .map_err(|_| ThresholdError::InvalidVerifyingKey)?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| ThresholdError::InvalidSignatureEncoding)?;
    let verifying_key = frost_ristretto255::VerifyingKey::deserialize(&verifying_key)
        .map_err(|_| ThresholdError::InvalidVerifyingKey)?;
    let signature = frost_ristretto255::Signature::deserialize(&signature)
        .map_err(|_| ThresholdError::InvalidSignatureEncoding)?;
    verifying_key
        .verify(message, &signature)
        .map_err(|_| ThresholdError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use frost_ristretto255::{
        aggregate,
        keys::{generate_with_dealer, IdentifierList, KeyPackage},
        round1, round2, Identifier, SigningPackage,
    };
    use rand::thread_rng;
    use std::collections::BTreeMap;

    fn frost_signature(message: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut rng = thread_rng();
        let identifiers = [
            Identifier::try_from(1).unwrap(),
            Identifier::try_from(2).unwrap(),
            Identifier::try_from(3).unwrap(),
        ];
        let (shares, public_key_package) =
            generate_with_dealer(3, 2, IdentifierList::Custom(&identifiers), &mut rng).unwrap();

        let mut commitments = BTreeMap::new();
        let mut nonces = BTreeMap::new();
        for identifier in identifiers.iter().take(2) {
            let key_package: KeyPackage =
                shares.get(identifier).unwrap().clone().try_into().unwrap();
            let (signing_nonces, signing_commitments) =
                round1::commit(key_package.signing_share(), &mut rng);
            commitments.insert(*identifier, signing_commitments);
            nonces.insert(*identifier, (signing_nonces, key_package));
        }

        let signing_package = SigningPackage::new(commitments, message);
        let mut signature_shares = BTreeMap::new();
        for (identifier, (signing_nonces, key_package)) in nonces {
            let share = round2::sign(&signing_package, &signing_nonces, &key_package).unwrap();
            signature_shares.insert(identifier, share);
        }
        let signature =
            aggregate(&signing_package, &signature_shares, &public_key_package).unwrap();

        (
            public_key_package.verifying_key().serialize().unwrap(),
            signature.serialize().unwrap(),
        )
    }

    #[test]
    fn verifies_valid_frost_signature() {
        let message = b"aether guardian approval";
        let (public_key, signature) = frost_signature(message);
        assert!(verify_frost_ristretto255(&public_key, message, &signature).is_ok());
    }

    #[test]
    fn rejects_wrong_message() {
        let (public_key, signature) = frost_signature(b"approved");
        assert_eq!(
            verify_frost_ristretto255(&public_key, b"tampered", &signature),
            Err(ThresholdError::VerificationFailed)
        );
    }
}
