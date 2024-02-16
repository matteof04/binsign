# Binsign

A tool to sign and encode file, inspired by [minisign](https://github.com/jedisct1/minisign).\
Unlike minisign, which output a file with only the signature, leaving the original file untouched, binsign will bundle together the signature and file in a new file.

## Usage

This program comes with four commands, `sign`, `verify`, `generate` and `build-complete`. The `buld-complete` command build the autocompletition file for your shell to use with this program.
The `generate` command create a new key pair and save the new keys in the specified path.
The `sign` and the `verify` commands are used to sign and verify files.
The command `binsign help sign` will give this output:

```text
Sign the given file

Usage: binsign sign [OPTIONS] <KEY_PATH> <FILE_PATH> [OUTPUT_FILE_PATH]

Arguments:
  <KEY_PATH>          The path of the key to use, the private for signing, the public for verifying
  <FILE_PATH>         The path of the file to sign
  [OUTPUT_FILE_PATH]  Where to save signed file

Options:
  -c, --compression-level <COMPRESSION_LEVEL>  Set the compression level of the file [default: 22]
  -h, --help                                   Print help
  -V, --version                                Print version
```

The `verify` command follow the same syntax, except it does not have the compression level option, as it is figured out automatically.

## Dependencies

The [bincode](https://crates.io/crates/bincode) crate and the [serde_bytes](https://crates.io/crates/serde_bytes) crate are used for serialization of the files.\
For signing and verifying, the [ed25519_dalek](https://crates.io/crates/ed25519_dalek) crate is used, in combination with the [blake3](https://crates.io/crates/blake3) crate: the file is firstly hashed by blake3, and then the hash is signed.\
The [rand_chacha](https://crates.io/crates/rand_chacha) crate is used as cryptographically secure random number generator for key generation.\
The [zstd](https://crates.io/crates/zstd) crate is used for data compression.

## Notes

This implementation is not guaranteed to be cryptographically safe. I am not an expert in cryptography.\
The main concern is the use of blake3 hasher instead of sha512, the one used by ed25519_dalek.
