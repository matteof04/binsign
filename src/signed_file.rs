/*
 * Copyright (c) 2024 Matteo Franceschini
 * All rights reserved.
 *
 * Use of this source code is governed by BSD-3-Clause-Clear
 * license that can be found in the LICENSE file
 */

use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};

use crate::BinsignError;

/// Representation of a signed file.
#[derive(Serialize, Deserialize)]
pub struct SignedFile {
    pub signature: Signature,
    pub file_size: u64,
    #[serde(with = "serde_bytes")]
    pub file: Vec<u8>,
}

impl SignedFile {
    /// Create a new signed file with the provided binary content, the provided signature and the provided file size
    pub fn new(file: Vec<u8>, signature: Signature, file_size: u64) -> Self {
        SignedFile {
            signature,
            file_size,
            file,
        }
    }
    /// Encode the signed bundle using bincode.\
    /// Take ownership of `Self` and return the encoded file.
    pub fn encode(self) -> Result<Vec<u8>, BinsignError> {
        bincode::serialize(&self).map_err(BinsignError::FileEncoding)
    }
    /// Decode the signed bundle using bincode.\
    /// Expect a `Vec<u8>` with the data to be decoded.
    pub fn decode(data: Vec<u8>) -> Result<Self, BinsignError> {
        bincode::deserialize(&data).map_err(BinsignError::FileDecoding)
    }
}
