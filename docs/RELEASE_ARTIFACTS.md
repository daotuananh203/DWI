# DWI 1.0.0rc1 Artifact Record

These checksums identify the local Windows RC artifacts built and smoke-tested
for the Batch 2 validation record. The binaries remain ignored from source
control; this document does not publish or authorize a release.

| Artifact | Size (bytes) | SHA-256 |
|---|---:|---|
| `dwi-1.0.0rc1-py3-none-any.whl` | 141,575 | `1BC6E1BF2AA7101312BA2829B54922752926EC2DD79AC4904D8AFB97C1783F8C` |
| `dwi-1.0.0rc1.tar.gz` | 119,110 | `23C02DA1870C6F15F6D312E6A2EAB742C548D0CAF62BC3629575A22DBD60E1AA` |
| `DWI-1.0.0rc1-Desktop.exe` | 11,711,801 | `5E4B666794455B9852F8B17B83D26B73409F441512E840D89E0F5D96EB540F95` |
| `DWI-1.0.0rc1-windows-x64.zip` | 11,451,283 | `EF06A78061D9C742C3C8D30ED327686187B9976B44C9F7CC605B6BB4E1C6200D` |
| `DWI-1.0.0rc1-Setup.exe` | 13,551,963 | `2BCBC60E8A2E3CDBDDDB0FD08859644FB6073CF32249AB996B84BE1201FFFCB0` |

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
