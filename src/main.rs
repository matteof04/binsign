/*
 * Copyright (c) 2024 Matteo Franceschini
 * All rights reserved.
 *
 * Use of this source code is governed by BSD-3-Clause-Clear
 * license that can be found in the LICENSE file
 */

use binsign::{keys::generate_keypair, sign_file, verify_file, BinsignError};
use clap::{CommandFactory, Parser, ValueEnum};
use clap_complete::Shell;
use cli::Cli;
use log::{error, LevelFilter};
use std::{
    fs::{create_dir, File},
    io::Write,
    path::Path,
    process::exit,
    time::Instant,
};

mod cli;

fn main() {
    let start = Instant::now();
    let cli = Cli::parse();
    if cli.verbose {
        pretty_env_logger::formatted_builder()
            .filter_level(LevelFilter::Info)
            .parse_env("LOG_LEVEL")
            .init();
    } else {
        pretty_env_logger::init_custom_env("LOG_LEVEL");
    }
    match handle_commands(cli.command) {
        Ok(_) => {
            let elapsed = start.elapsed();
            let minutes = elapsed.as_secs() / 60;
            let secs = elapsed.as_secs() % 60;
            let millis = elapsed.as_millis();
            println!("Done in {}m {}s (exactly {}ms)", minutes, secs, millis);
        }
        Err(e) => error!("{e}"),
    }
}

fn handle_commands(command: cli::Commands) -> Result<(), BinsignError> {
    match command {
        cli::Commands::Sign(sign_args) => {
            sign_file(
                sign_args.file_path,
                sign_args.key_path,
                sign_args.output_file_path,
                sign_args.compression_level,
            )?;
        }
        cli::Commands::Verify(verify_args) => {
            verify_file(
                verify_args.file_path,
                verify_args.key_path,
                verify_args.output_file_path,
            )?;
        }
        cli::Commands::Generate(gen_args) => {
            generate_keypair(gen_args.private_key_path, gen_args.public_key_path)?;
        }
        cli::Commands::BuildComplete => build_complete_file(),
    }
    Ok(())
}

fn build_complete_file() {
    const BIN_NAME: &str = env!("CARGO_BIN_NAME");
    let base_dir = Path::new("complete");
    if !base_dir.exists() || !base_dir.is_dir() {
        create_dir(base_dir).unwrap_or_else(|_| {
            error!("Can't create the complete directory!");
            exit(1);
        });
    }
    for shell in Shell::value_variants() {
        let file_name = format!(
            "{}/{BIN_NAME}.{shell}",
            base_dir.file_name().unwrap().to_str().unwrap()
        );
        let file_path = Path::new(&file_name);
        let mut file = File::create(file_path).unwrap_or_else(|_| {
            error!("Can't create the complete file {file_name}!");
            exit(1);
        });
        clap_complete::generate(
            shell.to_owned(),
            &mut cli::Cli::command(),
            BIN_NAME,
            &mut file,
        );
        println!("Generated complete file of {BIN_NAME} for {shell}");
    }
    let load_script = include_str!("../load_script_template");
    let load_script = load_script.replace(
        "COMPLETE_DIR",
        base_dir.file_name().unwrap().to_str().unwrap(),
    );
    let load_script = load_script.replace("BIN_NAME", BIN_NAME);
    let mut file = File::create("load").unwrap_or_else(|_| {
        error!("Can't create the load file!");
        exit(1);
    });
    file.write_all(load_script.as_bytes()).unwrap_or_else(|_| {
        error!("Can't write the load script!");
        exit(1);
    });
    println!("Generated load script");
}
