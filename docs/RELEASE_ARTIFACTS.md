# DWI 1.0.0 Artifact Record

These checksums identify the local Windows 1.0.0 stable artifacts built and smoke-tested
for the release validation record. The binaries remain ignored from source
control; this document records their verified hashes and sizes.

| Artifact | Size (bytes) | SHA-256 |
|---|---:|---|
| `dwi-1.0.0-py3-none-any.whl` | 145,051 | `B50004E1F6F3581CDCEC6B410FBF7962E1377626668522F36EE93E2850232EF2` |
| `dwi-1.0.0.tar.gz` | 124,141 | `2B866A724248402EC02DC89BA6E45D79EF1E517687D8447721BE69D4D4CB3276` |
| `DWI-1.0.0-Desktop.exe` | 11,716,711 | `F1795B1AA554B69F9230A37C23D6FB758B918E4141AF21F41A6562BC1519BCE9` |
| `DWI-1.0.0-windows-x64.zip` | 11,457,685 | `32107EB2AF574FB562CA8DCBF1B9A109BA790B6B143D6774EFCCEB030244AF91` |
| `DWI-1.0.0-Setup.exe` | N/A | `NOT VERIFIED — ISCC unavailable` |

Build tools used in the record were `build 1.5.0`, `setuptools 84.0.0`,
`PyInstaller 6.22.0`, and Inno Setup 7.0.2. The Desktop executable and
installer are unsigned by accepted release policy; Windows SmartScreen may
warn and no trusted certificate claim is made. Inno Setup was used only from
an isolated validation tool directory. Its verified license permits commercial
use and redistribution under its notice/origin/marking conditions; DWI does
not distribute the compiler itself, only compiled installer output.

The portable ZIP is produced by `scripts/build_windows_app.ps1` from a temporary
staging directory and must contain exactly the Desktop executable plus `LICENSE`,
`THIRD-PARTY-NOTICES.md`, and `README.txt` (the latter records the unsigned RC
notice). The ZIP must not be described as release-ready until its contents and
hash are regenerated after a clean, committed source build.

Release provenance rule: the artifact manifest must record the exact source
commit used for the build. A dirty working tree, an untagged `HEAD`, or a source
version that differs from the artifact version is not an acceptable release
provenance state.
