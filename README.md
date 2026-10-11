# CASK — Container Archival & Secret Keeping

CASK is a command-line companion for EATER containers. It archives container contents while keeping the container's `eater.db` in an encrypted local record store called the *stomach*.

## Status

This project package is prepared from the supplied `cask.c` source file. The source identifies itself as **CASK 1.0.0 (record format v1)**. This package does not claim an independent security audit or production-readiness certification.

## Requirements

- Linux or a compatible POSIX environment
- GCC or another compatible C compiler
- OpenSSL development headers and `libcrypto`
- GNU `tar` and `gzip` available on `PATH`

On Debian/Ubuntu, the build dependencies are commonly installed with:

```sh
sudo apt install build-essential libssl-dev tar gzip
```

## Build

From this directory:

```sh
make
```

Or compile directly:

```sh
gcc -std=c11 -O2 -Wall -Wextra -Wpedantic cask.c -o cask -lcrypto
```

Run the built program's help for the authoritative command syntax:

```sh
./cask --help
./cask --version
```

## Commands

The supplied source advertises these commands:

```text
cask archive <container> <output.tar.gz> [--stomach DIR]
cask stomach [--check] [--stomach DIR]
cask inspect <record-id> [--stomach DIR]
cask find <archive.tar.gz> [--stomach DIR]
cask retrieve <record-id> <output-eater.db> [--force] [--stomach DIR]
cask verify <archive.tar.gz> [--stomach DIR]
cask extract <archive.tar.gz> <output-dir>
cask restore <archive.tar.gz> <output-container> [--stomach DIR]
```

Use `./cask --help` because the compiled program's help is the source of truth for options and behavior.

## Stomach and key handling

By default, the local stomach is stored under:

- `$XDG_DATA_HOME/cask/stomach`, when `XDG_DATA_HOME` is set
- Otherwise, `~/.local/share/cask/stomach`

The source uses a `master.key` in the stomach storage area. Protect this directory and make a secure backup of the key. **If the key is lost, encrypted records may be unrecoverable.** Do not commit the key, database files, EATER containers, archives, or recovered `eater.db` files to Git.

## Safety notes

- Test archive, verification, retrieval, extraction, and restore workflows with disposable sample data before relying on them for important files.
- Keep backups of the original EATER container and the stomach key.
- Treat archives and database files as potentially sensitive.
- Review the source and test behavior in your own environment before using it with valuable data.

## Repository contents

- `cask.c` — supplied C implementation
- `Makefile` — repeatable build and clean targets
- `.gitignore` — excludes common local build artifacts and sensitive data
- `README.md` — build and usage overview

## License

No license is included because none was supplied with the source. Add a license only after deciding which terms you want to apply.
