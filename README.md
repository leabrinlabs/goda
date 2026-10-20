<img src="panel/icon0.png" width="88" alt="Goda icon">

# Goda
**PS4 Folder Launcher for PS5**

Browse and launch extracted PS4 games from folders. Extract supported PKGs directly on the console, with no PC extraction tool or new game PKG required.

## Features
- Cover library, direct Play buttons and a compact sidebar.
- Wider folder explorer with a directory tree, storage Home, breadcrumbs and search. Internal homebrew storage (`/data`) and external disks are listed.
- Game identity read from `sce_sys/param.sfo`; folder names are unrestricted.
- Global launch path with read-only mounts and dynamic module matching; no per-game behavior database.
- Persistent error dialogs with optional codes and technical details.

## Use
1. Start the required jailbreak/kstuff environment and run `goda-v0.6.12.elf` through your ELF loader.
2. In **Settings**, select the parent folder containing your extracted games. Each game needs `eboot.bin` and `sce_sys/param.sfo`.
3. Select a game and press **Play**, or use **PKG’den çıkar** to extract a supported package to a new folder.

On a fresh start, Goda looks for a standard `PS4` folder on supported storage, then an available storage root. Existing valid folder preferences are retained.

Goda does not overwrite source game files or access saves. The launcher must remain running while it manages a folder game.

## Compatibility — alpha 0.6.12
Currently targets **PS5 firmware 13.60**, with limited game testing. Universal game or firmware compatibility is not claimed. Intermittent console shutdowns remain under investigation; automatic system-browser dismissal is unresolved.

Extraction supports **zero-passcode PS4 fPKG base games and updates in supported PFS/PFSC layouts**. PS5 packages, retail/nonzero-passcode packages and DLC are unsupported. Updates are extracted separately, not applied automatically.

Extraction checks structure, identity, safe paths, free space and output SHA256 readback. Existing folders are not overwritten; incomplete outputs are excluded from the library. Sony signatures and signed PFS block authenticity are not verified.

## Build
Install [PS5 Payload SDK v0.44](https://github.com/ps5-payload-dev/sdk), then:

```sh
make PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk
# Optional PC preview, without console launch support:
make host PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk
```

Outputs: `dist/goda-v0.6.12.elf` and `dist/loader-host`. With no live preview using port 9134, run `python3 tests/test_app.py` for host integration checks.

## License
Goda code is GPL-3.0-or-later; third-party files retain their licenses. See [LICENSE](LICENSE) and [third-party notices](THIRD_PARTY_NOTICES.md). Independent homebrew; not affiliated with Sony. No games, game assets or proprietary SDK files are included.

## Security
Local UI only: loopback binding, Host/Origin validation and a random per-run API token. No preset device addresses or access tokens are shipped. Keep generated configs and captures private. See [security boundaries](SECURITY.md). Before publishing, run `python3 tools/check_public_source.py` to check the public source file set for accidental private material.
