# canopic

Password-derived asymmetric encryption to a self-extracting archive.

[![CI](https://github.com/ivoronin/canopic/actions/workflows/test.yml/badge.svg)](https://github.com/ivoronin/canopic/actions/workflows/test.yml)
[![Release](https://img.shields.io/github/v/release/ivoronin/canopic)](https://github.com/ivoronin/canopic/releases)

## Table of Contents

[Overview](#overview) · [Archive Format](#archive-format) · [Features](#features) · [Installation](#installation) · [Usage](#usage) · [Requirements](#requirements) · [Risks](#risks) · [License](#license)

```bash
canopic genkey -o key.json                                    # passphrase -> public key.json
canopic encrypt -k key.json -i backup.tar.gz -o backup.pyz    # -> self-extracting archive
./backup.pyz -o backup.tar.gz                                 # decrypt with python3 + age
```

## Overview

`genkey`: scrypt(passphrase, salt) -> age X25519 identity. Writes only the recipient, salt,
and scrypt params to `key.json`. Passphrase and identity are never written.

`encrypt`: `age -r <recipient>` over the input, packed into a `.pyz` zipapp (shebang + zip):
ciphertext + KDF params + a stdlib-only decryptor as `__main__.py`.

Decrypt re-derives the identity from the passphrase and runs `age -d`. Same decryptor code
for both paths (embedded self-extractor, installed `canopic decrypt`). Secrets reach `age`
only via an inherited fd, never argv/env/disk; passphrase read from tty.

## Archive Format

A `.pyz` is a Python zip application: a regular ZIP file prefixed with a `python3`
shebang. Python executes its `__main__.py`; ZIP tools still read it as an archive. A
canopic `.pyz` contains the decryptor, `manifest.json` with the salt and scrypt parameters,
and the age ciphertext as `payload.age`. It contains no passphrase or private key.

```bash
unzip -l backup.pyz
```

## Features

- Encrypt needs only public `key.json`; decrypt needs the passphrase.
- No private key file: identity re-derived from passphrase on demand.
- `.pyz` decrypts with `python3` providing `hashlib.scrypt` + `age`, no canopic install.
- Two decrypt paths, one code copy: run the archive, or `canopic decrypt` (does not execute embedded code).
- scrypt N=2^20, r=8 (~1 GiB per guess).
- age (X25519); added crypto is scrypt KDF wiring + bech32 encoding.

## Installation

```bash
uv tool install git+https://github.com/ivoronin/canopic
```

## Usage

stdin/stdout filters unless `-i`/`-o`/`-k` given.

```bash
canopic genkey -o key.json                                    # prompts twice, writes key.json
canopic genkey > key.json

canopic encrypt -k key.json -i secret.txt -o secret.pyz       # -o writes mode 0700
canopic encrypt -k key.json < secret.txt > secret.pyz

./secret.pyz -o secret.txt                                    # self-extract: python3 + age
python3 secret.pyz > secret.txt

canopic decrypt secret.pyz -o secret.txt                      # trusted: no embedded exec
canopic decrypt secret.pyz > secret.txt
```

## Requirements

- `age`, `age-keygen` on `PATH` (`age-keygen` only for `genkey`).
- Python 3.9+; `genkey` and decrypt require `hashlib.scrypt`. LibreSSL-backed Python
  builds may omit it: encryption with an existing `key.json` works, key derivation and
  decryption do not.
- Self-extractor needs `python3` providing `hashlib.scrypt` + `age`.
- ~1 GiB free memory to derive the key.

## Risks

- Passphrase is the only secret. `key.json` and the archive carry salt + scrypt params, so a weak passphrase is brute-forceable offline. scrypt cost slows guesses, does not fix a guessable password.
- Self-extract runs code from the archive. Untrusted archive -> use `canopic decrypt`.
- No sender authentication: anyone with the recipient can build a valid archive.
- Lost passphrase = lost data. No recovery, no key file.

## License

[ISC](LICENSE)
