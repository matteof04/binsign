/*
 * Copyright (c) 2024 Matteo Franceschini
 * All rights reserved.
 *
 * Use of this source code is governed by BSD-3-Clause-Clear
 * license that can be found in the LICENSE file
 */

use std::path::PathBuf;

use clap::{command, Args, Parser, Subcommand};
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub(crate) struct Cli {
    /// Verbose flag
    #[arg(short, long)]
    pub(crate) verbose: bool,
    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Sign the given file
    Sign(SignArgs),
    /// Verify if the given file is correcly signed and decodes it
    Verify(VerifyArgs),
    /// Generate a new keypair
    Generate(GenerateArgs),
    /// Build autocomplete scripts for all the shells supported and save them into the complete folder
    BuildComplete,
}

#[derive(Args)]
pub(crate) struct SignArgs {
    /// Set the compression level of the file
    #[arg(short, long, default_value_t = 22)]
    pub(crate) compression_level: i32,
    /// The path of the key to use, the private for signing, the public for verifying
    pub(crate) key_path: PathBuf,
    /// The path of the file to sign
    pub(crate) file_path: PathBuf,
    /// Where to save signed file
    pub(crate) output_file_path: Option<PathBuf>,
}

#[derive(Args)]
pub(crate) struct VerifyArgs {
    /// The path of the key to use, the private for signing, the public for verifying
    pub(crate) key_path: PathBuf,
    /// The path of the file to sign
    pub(crate) file_path: PathBuf,
    /// Where to save signed file
    pub(crate) output_file_path: Option<PathBuf>,
}

#[derive(Args)]
pub(crate) struct GenerateArgs {
    /// Where to save the private key
    pub(crate) private_key_path: PathBuf,
    /// Where to save the public key
    pub(crate) public_key_path: PathBuf,
}
