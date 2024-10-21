# Encrypt CSV PoC

## Description

A toy C++ application to demonstrate in memory file encryption using a public PGP key. The application reads a dummy CSV file into memory, encrypts it using a PGP public key, and writes the encrypted data to a file.

Uses [gpgme](https://gnupg.org/software/gpgme/index.html) to handle the encryption.

## Requirements

- C++ compiler (GCC, Clang, etc.)
- GPGME development library (provides `gpgme.h` and `libgpgme`)
- Make

## Installation & Usage (*macos*)

### Install GPGME Library

```bash
brew install gpgme
```
### Clone the repo

```bash
git clone https://github.com/mikebradburyflutterintithub.com/encrypt_csv.git
cd encrypt_csv
```
### Usage
Ensure the pgp key and CSV file are in the local directory:
- `test_public_key.asc` 
- `dummy_pan_data.csv`

Build the binary
```bash
make
```
Run the application
```bash
./encrypt_csv
```
