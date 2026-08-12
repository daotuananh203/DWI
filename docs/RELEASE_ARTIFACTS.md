# DWI 1.0.0rc1 Artifact Record

These checksums identify the local Windows RC artifacts built and smoke-tested
for the Batch 2 validation record. The binaries remain ignored from source
control; this document does not publish or authorize a release.

| Artifact | Size (bytes) | SHA-256 |
|---|---:|---|
| `dwi-1.0.0rc1-py3-none-any.whl` | 145,136 | `CFB4900C0D01091F71D925DFA385E81004A9E813E840E3E13527DA87E21C6143` |
| `dwi-1.0.0rc1.tar.gz` | 124,080 | `8DB56E0F9856209C0C63BA70B5A6BEFCC2B63800E8760D734994379AD7AF9496` |
| `DWI-1.0.0rc1-Desktop.exe` | 11,717,550 | `0087B0D7EE60DC352A23829032190A94230E2F0FBB839225E835F17F1083F006` |
| `DWI-1.0.0rc1-windows-x64.zip` | 11,458,905 | `8EC30F462C6F3B7F71096F003AB0FF9A9D2E86885466878CCCCAACDD683D8E5C` |
| `DWI-1.0.0rc1-Setup.exe` | N/A | `NOT VERIFIED — ISCC unavailable` |

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
