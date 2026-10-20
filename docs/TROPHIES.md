# PS4 trophy registration

Status: unresolved. `0x80551618` has been observed when launching PS4 folder games. Do not interpret a successful launch as working trophy support.

## Evidence
- The existing console capture contains a trophy registration failure with that exact code. It also contains kstuff failures to resolve/patch `sceNpTrophySystemIsServerAvailable` in ShellUI. The latter concerns server availability; it does not prove the cause of registration failure.
- Goda supplements absent `npbind.dat` and `nptitle.dat` in its registration metadata, compares existing bytes and uses a read-only game view. Adding those files has not established a fix.
- [ShadowMountPlus issue #97](https://github.com/drakmor/ShadowMountPlus/issues/97) reports the same failure for mounted PS4 images. The author suggests differences in PS4 metadata and the native package-backed launch context. These are upstream hypotheses, not a confirmed diagnosis for Goda.
- [PS4pkg_to_ffpfsc issue #3](https://github.com/SadykovIV/PS4pkg_to_ffpfsc/issues/3) remains a corresponding report. A converter or a mount alone is not evidence that trophies work.

## Read-only follow-up

Two currently registered folder games were inspected without launching either one:
- The source `npbind.dat` files pass structural and SHA-1-footer checks using the layout described by [the upstream validator](https://github.com/SadykovIV/PS4pkg_to_ffpfsc/blob/main/tools/ps4ffpsc/ps4ffpsc/npbind.py). This is consistency checking, not Sony signature verification.
- `param.sfo`, `npbind.dat` and `nptitle.dat` match byte-for-byte between the selected source, app registration metadata and public appmeta. Each source Trophy archive also matches its app-registration copy.
- Trophy archive headers and entry ranges also pass structural checks against the [TRP layout](https://github.com/shadps4-emu/shadPS4/blob/main/src/core/file_format/trp.h). Their encrypted configuration payloads were not decrypted, and Sony authenticity was not verified.
- One private appmeta directory is empty. In the other, the three expected files exist, but the management API refuses their contents. That denial must not be treated as a missing-file result or a successful hash comparison.
- Existing title records differ in platform and origin/metadata-path fields. Their meaning and effect need a working native-launch control; changing a DB flag without that evidence would not establish a fix.

These observations make source/copy corruption a less likely explanation for those checked files. They do not identify which configuration/context the native Trophy service actually rejects. Private captures, game identities and file contents are excluded from this repository. No private user Trophy store or save path was accessed.

## Next diagnostic step
Compare registration metadata and the native launch context against a normal working PS4 launch, using read-only captures. Distinguish file availability, configuration validity and service/context failures before choosing a fix. Preserve evidence of the original error.

This release does not patch trophy services, suppress the system warning, delete trophy data, edit saves or apply per-game workarounds. No new console game test was performed for this UI release.
