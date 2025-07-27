# Rust AES Encryption Tool

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/Rust-1.70%2B-blue)](https://www.rust-lang.org)


## Security Notice ⚠️

This implementation currently uses **ECB (Electronic Codebook) mode**, which has significant security limitations:

- 🚫 **Not secure for real-world use** - ECB leaks patterns in plaintext data
- 🔓 **No semantic security** - Identical plaintext blocks produce identical ciphertext
- 📚 **Educational purposes only** - Demonstrates core AES concepts only

**Do not use** for protecting sensitive data. Future versions may implement secure modes like CBC or GCM with proper authentication. Even still this implementation is unlikely to be audited/verified and should not be used on real-world data.

A command-line tool for AES encryption/decryption, written in Rust.

## Features

- 🔒 **AES Encryption**
- 🔑 **Secure Key Generation** using OS random number generator
- 📁 **File & Text Support**
  - Encrypt/decrypt files or direct text input
  - Base64-encoded ciphertext output


## To Run

`cargo run -- *options*`

```text
Options:
  -t, --text <TEXT>      Text to encrypt/decrypt
  -f, --file <FILE>      Input file
  -k, --key <KEY>        Key (text or file path)
  -b, --bits <BITS>      Key size in bits (128/192/256) - encryption only [default: 128]
  -o, --output <OUTPUT>  Output file [default: output.txt]
  -e, --encrypt          Encrypt mode
  -d, --decrypt          Decrypt mode
  -h, --help             Print help
```
For example to run the encryption on the provided example files:

`cargo run -- -e -f example_files/plaintext/bangarang.txt -o encrypted.txt` 

## TODO
```text
// Upcoming Features
- [ ] Add more modes (CBC, GCM, CTR)