# Security boundaries

Goda is experimental privileged homebrew. Source review and tests do not establish that every package or game is safe.

- The UI binds only to `127.0.0.1:9134`. Host and optional Origin are validated before the UI/session token is served; API operations require a fresh random per-run token.
- Game names and paths are rendered as text. Directory access is confined to supported external storage and the internal homebrew area `/data`; `/user`, save directories and system partitions are not exposed by the picker. Traversal, symlink and overwrite checks remain active.
- No fixed access token, personal device address or personal filesystem path is shipped. Generated diagnostic kits contain session credentials and must stay private; their optional transport is not encrypted and is intended for a trusted local network.
- The public fake-package parameters in `vendor/keys.h` come from LibOrbisPkg. They are format-specific public test material, not the user's credentials. Upstream license notices are preserved.
- Package consistency and SHA256 readback checks do not authenticate Sony signatures. Kernel hooks and untrusted input parsers still require care.

Do not place credentials, personal captures, game dumps or proprietary SDK files in the repository. A storage folder is selected at runtime; no title-specific folder is required.
