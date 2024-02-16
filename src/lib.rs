/*
 * Copyright (c) 2024 Matteo Franceschini
 * All rights reserved.
 *
 * Use of this source code is governed by BSD-3-Clause-Clear
 * license that can be found in the LICENSE file
 */

//! # Binsign
//! A tool to sign and encode file, inspired by [minisign](https://github.com/jedisct1/minisign).\
//! Unlike minisign, which output a file with only the signature, leaving the original file untouched, binsign will bundle together the signature and file in a new file.
//! ## Dependencies
//! The [bincode] crate and the [serde_bytes] crate are used for serialization of the files.\
//! For signing and verifying, the [ed25519_dalek] crate is used, in combination with the [blake3] crate: the file is firstly hashed by blake3, and then the hash is signed.\
//! The [rand_chacha] crate is used as cryptographically secure random number generator for key generation.\
//! The [zstd] crate is used for data compression.
//!
//! ## Notes
//! This implementation is not guaranteed to be cryptographically safe. I am not an expert in cryptography.\
//! The main concern is the use of blake3 hasher instead of SHA512, the one used by ed25519_dalek.

use ed25519_dalek::Digest;
use keys::{read_keypair_from_file, read_verifying_key_from_file};
use log::info;
use signed_file::SignedFile;
use std::{
    fs,
    mem::size_of_val,
    path::{Path, PathBuf},
};
use thiserror::Error;

use crate::blake::BlakeHasher;

/// Key manipulation utils
pub mod keys;
/// Signed file model
pub mod signed_file;

mod blake;

/// Sign the provided file with the provided private key.\
/// Expect the path where the file to sign and the key are located, the path of the output bundle and the compression level.\
/// If `None` is passed instead of the output path, the bundle will be saved in the same place where the file to sign is located, using the .sig extension.\
/// The bundle contains the file signature and the file itself.
pub fn sign_file<P: AsRef<Path>>(
    file_path: P,
    signing_key_path: P,
    output_path: Option<P>,
    compression_level: i32,
) -> Result<(), BinsignError> {
    let output_path = match output_path {
        Some(path) => PathBuf::from(path.as_ref()),
        None => {
            let file_path = file_path.as_ref();
            let file_path = file_path.display();
            let path = format!("{file_path}.sig");
            PathBuf::from(&path)
        }
    };
    info!("Reading signing key...");
    let (signing_key, _) = read_keypair_from_file(signing_key_path)?;
    info!("Reading file...");
    let file_content = fs::read(file_path).map_err(BinsignError::FileIO)?;
    let original_file_size = size_of_val(&*file_content);
    info!("Original file size (in bytes): {original_file_size}");
    info!("Hashing file...");
    let file_hash = get_file_hasher(&file_content);
    info!("Signing hash...");
    let signature = signing_key
        .sign_prehashed(file_hash, None)
        .map_err(BinsignError::Signing)?;
    info!("Compressing...");
    let file_content = zstd::bulk::compress(&file_content, compression_level)
        .map_err(BinsignError::ZstdCompression)?;
    let signed_file = SignedFile::new(file_content, signature, original_file_size as u64);
    info!("Encoding file...");
    let encoded_file = signed_file.encode()?;
    info!("Writing file...");
    fs::write(output_path, encoded_file).map_err(BinsignError::FileIO)?;
    Ok(())
}

/// Verify if the provided bundle file is correctly signed using the provided public key.\
/// Expect the path where the file to verify and the key are located and the path of the output decoded file.\
/// If `None` is passed instead of the output path, the decoded file will be saved in the same place where the file to veify is located, using the .ver extension.\
/// The decoded file is just the bundle file without the signature.
pub fn verify_file<P: AsRef<Path>>(
    file_path: P,
    verifying_key_path: P,
    output_path: Option<P>,
) -> Result<(), BinsignError> {
    let output_path = match output_path {
        Some(path) => PathBuf::from(path.as_ref()),
        None => {
            let file_path = file_path.as_ref();
            let file_path = file_path.display();
            let path = format!("{file_path}.ver");
            PathBuf::from(&path)
        }
    };
    info!("Reading verifying key...");
    let verifying_key = read_verifying_key_from_file(verifying_key_path)?;
    info!("Reading file...");
    let file_content = fs::read(file_path).map_err(BinsignError::FileIO)?;
    info!("Decoding file...");
    let signed_file = SignedFile::decode(file_content)?;
    let signature = signed_file.signature;
    let file_content = signed_file.file;
    let original_file_size = signed_file.file_size;
    info!("Decompressing...");
    let file_content = zstd::bulk::decompress(&file_content, original_file_size as usize)
        .map_err(BinsignError::ZstdDecompression)?;
    info!("Hashing file...");
    let file_hasher = get_file_hasher(&file_content);
    info!("Verifying...");
    verifying_key
        .verify_prehashed(file_hasher, None, &signature)
        .map_err(BinsignError::Verification)?;
    info!("Writing decoded file...");
    fs::write(output_path, file_content).map_err(BinsignError::FileIO)?;
    Ok(())
}

fn get_file_hasher(file_data: &[u8]) -> BlakeHasher {
    let mut hasher = BlakeHasher::new();
    hasher.update(file_data);
    hasher
}

/// Errors
#[derive(Debug, Error)]
pub enum BinsignError {
    #[error("An error occurred during file reading or writing. Details: {0}")]
    FileIO(std::io::Error),
    #[error("An error occurred during private key serialization. Details: {0}")]
    PrivateKeySerialization(ed25519_dalek::pkcs8::Error),
    #[error("An error occurred during public key serialization. Details: {0}")]
    PublicKeySerialization(ed25519_dalek::pkcs8::spki::Error),
    #[error(
        "An error occurred during private key deserialization. Make sure to use the DER format for keys. Details: {0}"
    )]
    PrivateKeyDeserialization(ed25519_dalek::pkcs8::Error),
    #[error(
        "An error occurred during public key deserialization. Make sure to use the DER format for keys. Details: {0}"
    )]
    PublicKeyDeserialization(ed25519_dalek::pkcs8::spki::Error),
    #[error("An error occurred during file verification. Details: {0}")]
    Signing(ed25519_dalek::SignatureError),
    #[error("An error occurred during file verification. Details: {0}")]
    Verification(ed25519_dalek::SignatureError),
    #[error("An error occurred during file encoding. Details: {0}")]
    FileEncoding(bincode::Error),
    #[error("An error occurred during file decoding. Details: {0}")]
    FileDecoding(bincode::Error),
    #[error("An error occurred during file compression. Details: {0}")]
    ZstdCompression(std::io::Error),
    #[error("An error occurred during file decompression. Details: {0}")]
    ZstdDecompression(std::io::Error),
}
