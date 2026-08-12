# Developer Workspace Intelligence (DWI)

DWI là hệ thống intelligence cho lưu trữ của developer và cleanup an toàn,
ưu tiên Windows. DWI phát hiện artifact phát triển, giải thích evidence phía
sau từng finding, và cung cấp workflow Quarantine + Journal + Undo có thể khôi
phục thông qua một deterministic engine dùng chung.

> Đây là release candidate `1.0.0rc1`, chưa phải public release cuối cùng
> `1.0.0`. Việc phát hành chính thức cần một vòng audit độc lập riêng.

[Read the English README](README.md)

## DWI cung cấp gì?

- Workspace Intelligence cho artifact Python, Node.js và developer-storage đã
  được phê duyệt.
- System Intelligence với traversal bounded, partial-result rõ ràng và
  network filesystem default-deny.
- Pipeline deterministic: evidence → interpretation → Safety Policy.
- Desktop Tkinter native với resource tiếng Anh/tiếng Việt.
- CLI reporting và cleanup có human confirmation.
- MCP local stdio cho AI agent caller không đáng tin cậy.
- Quarantine + Journal + Undo có thể khôi phục; không có permanent deletion.

Safety engine, không phải AI model, quyết định `RiskLabel`,
`ActionEligibility`, validation và authorization. AI có thể giải thích hoặc
request một quyết định từ engine, nhưng không được tự tạo safety decision.

## Cài đặt release candidate

Wheel đã được kiểm tra với Python 3.11+ trên Windows:

```powershell
python -m pip install dwi-1.0.0rc1-py3-none-any.whl
```

Wheel không có runtime dependency ngoài Python. Có thể dùng source distribution
cho môi trường tự build package. Xem [docs/INSTALLATION.md](docs/INSTALLATION.md)
cho wheel, sdist, Desktop portable và source development. Windows installer đã
được cài và smoke-test trong thư mục tạm disposable trên Windows. EXE và
installer cố ý **chưa ký**; Windows có thể hiện cảnh báo SmartScreen. Hãy kiểm
tra SHA-256 trong [docs/RELEASE_ARTIFACTS.md](docs/RELEASE_ARTIFACTS.md); không
coi artifact là binary đã được trusted code signing.

## Bắt đầu nhanh

```powershell
dwi --version
dwi scan PATH --json
dwi scan-system --root PATH --json
dwi cleanup PATH --json
dwi desktop
dwi-mcp
```

Trong source checkout, thay `dwi` bằng `python -m dwi`. Xem hướng dẫn CLI tại
[docs/CLI.md](docs/CLI.md) và Desktop tại [docs/DESKTOP.md](docs/DESKTOP.md).

Cleanup cần review và confirmation chính xác từ human. Agent không thể cung
cấp arbitrary mutation path. Mỗi item được revalidate ngay trước khi move vào
quarantine; partial result và reconciliation state luôn được giữ rõ ràng.

## Boundary của MCP với agent

Khởi động server local:

```powershell
dwi-mcp
```

Transport chỉ dùng stdin/stdout. 13 tools cung cấp scan read-only, findings,
explanation, cleanup review, trạng thái human confirmation, execution sau
fresh revalidation, recovery status và Undo bằng recovery handle. MCP caller
được xem là untrusted:

- không có tool mutation nhận raw path;
- confirmation phrase từ agent không tạo human consent;
- caller không được gửi risk, validation, authorization hoặc trusted snapshot;
- handle do server sở hữu, có giới hạn, hết hạn và mất hiệu lực khi restart;
- roots, finding selection, message và page đều có hard limit.

Xem đầy đủ tại [docs/MCP.md](docs/MCP.md). DWI offline-first: không telemetry,
analytics, cloud API, hidden update check hoặc network listener mặc định.

## Safety và giới hạn

DWI xử lý conservative khi evidence thiếu, failed, partial, conflicting hoặc
ambiguous. Reachability đã xác nhận và protected root sẽ chặn eligibility.
Link/reparse point không được follow; `.git` chỉ là context/protection, không
phải cleanup candidate; Windows mutation gate chặn protected, network,
reparse, root-escape và alias case.

Cleanup chỉ là Quarantine + Journal + Undo có thể khôi phục. RC không tuyên bố
filesystem transactionality, crash-proof atomicity, automatic cleanup,
permanent deletion, cloud operation hoặc trusted code signing. SmartScreen có
thể cảnh báo vì EXE và installer RC chưa ký. Xem
[docs/SAFETY_INVARIANTS.md](docs/SAFETY_INVARIANTS.md) và
[docs/RELEASE_READINESS.md](docs/RELEASE_READINESS.md).

## Development và validation

```powershell
python -m pip install pytest==9.1.1  # test-only dependency
python -m pytest -q
python -m compileall -q dwi scripts
python scripts\clean_env_smoke.py
python -m dwi evaluate-readonly --max-seconds 5 --max-nodes 2000 --max-files 2000
python -m dwi benchmark
```

Xem [docs/BUILD_WINDOWS.md](docs/BUILD_WINDOWS.md),
[docs/EVALUATION.md](docs/EVALUATION.md), [docs/BENCHMARKS.md](docs/BENCHMARKS.md),
[CONTRIBUTING.md](CONTRIBUTING.md) và [SECURITY.md](SECURITY.md).

Khi repository được public, báo cáo security nhạy cảm qua GitHub Security —
Report a vulnerability / Security Advisories, không mở public Issue. Release
operator phải bật Private Vulnerability Reporting ngay khi repository public;
bug thông thường dùng GitHub Issues.

## Trạng thái và license

RC đang chờ independent public-release audit. RC chưa được publish và không có
nghĩa final `1.0.0` đã được authorize. Project dùng [MIT License](LICENSE).
Lịch sử milestone và ghi chú RC nằm trong [CHANGELOG.md](CHANGELOG.md).
