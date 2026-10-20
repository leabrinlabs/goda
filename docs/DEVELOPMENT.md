# Development

## Repository layout

| Directory | Contents |
| --- | --- |
| `src/` | Launcher, catalog, extraction and runtime code with private headers |
| `src/shortcut/` | Explicit Goda media-shortcut installer |
| `web/` | Embedded browser UI |
| `assets/` | Used artwork, hashes and artwork notes |
| `tools/` | Asset generation, host test runner and publication checks |
| `tests/` | Synthetic host fixtures and regression tests |
| `diagnostics/` | Passive log-reader/collector tooling; private configurations are generated outside Git |
| `vendor/` | Third-party source, license texts and provenance |
| `docs/` | Development and investigation notes |
| `build/` | Generated headers and host test binaries; ignored |
| `dist/` | Compiled artifacts and private development outputs; ignored |

## Build and test

```sh
# Host preview; no console SDK required (C compiler, Python 3 and POSIX host).
make host
./dist/loader-host /path/to/synthetic/library

# Stop the local preview on port 9134 before testing.
# Also needs Node.js, system zlib development files and pthread support.
make test
# Optional independent crypto checks, with Python's cryptography installed:
python3 tools/run_tests.py --crypto

# Console binaries; install the open-source PS5 Payload SDK separately.
make candidate panel PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk
make check-source
```

Generated headers live only in `build/generated/`. `make clean` clears those headers and preserves versioned binaries and private captures. The file layout does not alter console storage paths, ownership markers or title identifiers; those remain compatible with existing installations.

## Releases

Publish versioned ELF binaries and a bundle with quick-start instructions, corresponding-source reference, licenses and SHA256 checksums. Tag the exact source used to build the release. Keep published release assets/tags intact when organizing later development commits. Never include private captures, credentials, game files or proprietary SDK files.
