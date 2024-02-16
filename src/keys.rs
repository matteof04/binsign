/*
 * Copyright (c) 2024 Matteo Franceschini
 * All rights reserved.
 *
 * Use of this source code is governed by BSD-3-Clause-Clear
 * license that can be found in the LICENSE file
 */

use ed25519_dalek::{
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    SigningKey, VerifyingKey,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::{fs, path::Path};

use crate::BinsignError;

/// Expect the path of the private key.\
/// Return the decoded private key and the derived public key.
pub fn read_keypair_from_file<P: AsRef<Path>>(
    path: P,
) -> Result<(SigningKey, VerifyingKey), BinsignError> {
    let private_der = fs::read(path).map_err(BinsignError::FileIO)?;
    let signing_key: SigningKey = SigningKey::from_pkcs8_der(&private_der)
        .map_err(BinsignError::PrivateKeyDeserialization)?;
    let verifying_key: VerifyingKey = signing_key.verifying_key();
    Ok((signing_key, verifying_key))
}

/// Decode the public key at the provided path.
pub fn read_verifying_key_from_file<P: AsRef<Path>>(path: P) -> Result<VerifyingKey, BinsignError> {
    let public_der = fs::read(path).map_err(BinsignError::FileIO)?;
    let verifying_key: VerifyingKey = VerifyingKey::from_public_key_der(&public_der)
        .map_err(BinsignError::PublicKeyDeserialization)?;
    Ok(verifying_key)
}

/// Generate a new keypair and save it at the provided path.\
/// Expect the signing key path first and then the verifying key path.
pub fn generate_keypair<P: AsRef<Path>>(
    signing_key_path: P,
    verifying_key_path: P,
) -> Result<(), BinsignError> {
    let mut csprng = ChaCha20Rng::from_entropy();
    let signing_key: SigningKey = SigningKey::generate(&mut csprng);
    let verifying_key: VerifyingKey = signing_key.verifying_key();
    let private_der = signing_key
        .to_pkcs8_der()
        .map_err(BinsignError::PrivateKeySerialization)?;
    let public_der = verifying_key
        .to_public_key_der()
        .map_err(BinsignError::PublicKeySerialization)?;
    fs::write(signing_key_path, private_der.as_bytes()).map_err(BinsignError::FileIO)?;
    fs::write(verifying_key_path, public_der.as_bytes()).map_err(BinsignError::FileIO)?;
    Ok(())
}
