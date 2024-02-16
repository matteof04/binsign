/*
 * Copyright (c) 2024 Matteo Franceschini
 * All rights reserved.
 *
 * Use of this source code is governed by BSD-3-Clause-Clear
 * license that can be found in the LICENSE file
 */

use curve25519_dalek::digest::{typenum, FixedOutput, HashMarker, OutputSizeUser, Reset, Update};

#[derive(Default)]
pub struct BlakeHasher {
    hasher: blake3::Hasher,
}

impl Reset for BlakeHasher {
    fn reset(&mut self) {
        self.hasher.reset();
    }
}

impl Update for BlakeHasher {
    fn update(&mut self, data: &[u8]) {
        self.hasher.update_rayon(data);
    }
}

impl HashMarker for BlakeHasher {}

impl OutputSizeUser for BlakeHasher {
    type OutputSize = typenum::U64;
}

impl FixedOutput for BlakeHasher {
    fn finalize_into(self, out: &mut ed25519_dalek::ed25519::signature::digest::Output<Self>) {
        self.hasher.finalize_xof().fill(out.as_mut());
    }
}
