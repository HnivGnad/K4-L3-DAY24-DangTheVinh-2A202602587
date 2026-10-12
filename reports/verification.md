# Verification — 12/10/2026

- Môi trường: Windows native PowerShell, CPython **3.11.16** trong `.venv`, pytest **9.1.1**, Gitleaks **8.30.1**, pre-commit **4.6.2**. Đã chạy thực tế trên Windows; chưa thử lại trên WSL/macOS/Linux như môi trường khuyến nghị của đề.
- `python -m pytest tests/ -q`: **41 passed**, không skip; 33 test bắt buộc và 8 ca kiểm tra boundary bổ sung. Log: `reports/pytest.log`. Không sửa test bắt buộc.
- PII: gold=118, pred=118, tp=118; **precision=1.000, recall=1.000**. Log: `reports/pii-metrics.log`. Regex chưa được coi là detector tổng quát cho production.
- `agent.check_lure corpus/ticket-90*.md`: **4/4 sẵn sàng**, biến thể 4 được kiểm chung hai file; test bổ sung xác nhận từng phần riêng chưa đủ marker. Log: `reports/lure-check.log`.
- Baseline: đã lưu trước khi hoàn thiện runner; `attack-before.log` chứa hồ sơ synthetic `KH-000999`. Replay riêng từng lure đều 299 byte ở `variant-N-before.log`. Sau pytest đã reset và replay lại query gốc với `dpo`: `attack-after.log` và bốn `variant-N-after.log` **0 byte**. Số liệu: `replay-before.json`, `replay-after.json`.
- Ledger: `verify(reports/ledger.jsonl) = True`; hiện 72 entry (ba lượt DPO query gốc), tất cả có reason, on_behalf_of, agent_id, run_id, expires_at. Dòng 24, 48 và 72 deny `http_post` vì restricted + egress. Hồ sơ được phép đọc vẫn được đọc, support bị deny trước khi mở mapping. Mỗi biến thể có ledger riêng ở `reports/variant-N/ledger.jsonl`.
- Tamper: đổi trường tool ở dòng 2 trong bản sao `reports/tamper-demo.jsonl`, giữ nguyên hash; verify **False**, bản gốc vẫn **True**. Kết quả `reports/tamper-result.json`.
- Dependency: `requirements.lock` sinh thật bằng pip-compile, pin dependency trực tiếp và bắc cầu với SHA256; `pip install --require-hashes -r requirements.lock --force-reinstall` thành công. Log: `reports/lock-generation.log`, `reports/hash-install.log`. Hash chỉ xác nhận gói khớp lock, không chứng minh gói không có lỗ hổng.
- Gitleaks history: **1 finding dự kiến**, exit **1**, commit `1bdd849`, rule `lab24-synthetic-token`; `reports/gitleaks-history.json` đã redact.
- Gitleaks current: **0 finding**, exit **0**, `reports/gitleaks-current.json = []`.
- `pre-commit run --all-files`: **Passed**, exit **0**; log `reports/pre-commit.log`. Pin hook v8.30.1, scan current tree; scan history chạy riêng vì token bài tập còn trong history.
- Kiểm tra cuối CP5: toàn bộ test được chạy lại trước replay; ledger chính và bốn ledger biến thể verify True, bản sao tamper verify False. Hook và scanner được chạy lại; log `reports/cp5-checks.log`.

## Lỗi môi trường đã xử lý

`python` không trong PATH, `py -3.11` không thấy Python: dùng uv với interpreter đã có ở `C:\Users\ADMIN\.local\bin\python3.11.exe` để tạo `.venv`. Cache mặc định ngoài workspace bị từ chối ghi: chuyển cache pip/uv/pre-commit vào các thư mục sinh tự động trong workspace. CLI có tiếng Việt gây `UnicodeEncodeError` khi stdout cp1252: đặt `PYTHONUTF8=1`.

PowerShell `Invoke-WebRequest` tải GitHub gặp lỗi kết nối: tải bằng requests và xác minh SHA256 release. Git schannel báo `SEC_E_NO_CREDENTIALS` lúc pre-commit fetch: override `http.sslBackend=openssl` chỉ trong môi trường tiến trình. Override giữ thêm `safe.directory` đúng workspace để Git sandbox nhận quyền sở hữu; không tắt kiểm chứng TLS và không sửa config Git toàn cục. Scanner tìm mẫu secret trong cache Gitleaks; loại trừ đúng các thư mục tooling sinh tự động, tiếp tục quét toàn bộ mã nguồn/dữ liệu/evidence và lịch sử.

## Chạy lại trên PowerShell

```powershell
$env:PYTHONUTF8 = '1'
$env:PATH = "$PWD\.tools;$PWD\.venv\Scripts;$env:PATH"
$env:PRE_COMMIT_HOME = "$PWD\.pre-commit-cache"
.\.venv\Scripts\python.exe -m pytest tests/ -q
.\.venv\Scripts\python.exe -m agent.check_lure 'corpus/ticket-90*.md'
.\.venv\Scripts\python.exe -m scripts.replay_evidence
.\.venv\Scripts\python.exe -m pre_commit run --all-files
.\.tools\gitleaks.exe git --config .gitleaks.toml --redact .
.\.tools\gitleaks.exe dir --config .gitleaks.toml --redact .
```

Gitleaks history trả 1 là finding giả dự kiến. Script replay tự mở/đóng sink nên cần cổng 10024 đang rảnh. Mỗi lần replay append thêm ledger, không xóa evidence cũ. Chỉ dùng `--baseline` khi chủ động muốn tái hiện đường yếu trên dữ liệu giả của lab.

## Giới hạn và việc người nộp làm sau

Không có lỗi kiểm thử code còn lại. Điều khoản cụ thể của Luật 91/2025 và Luật AI 134/2025 **chưa xác minh**; báo cáo mapping đã ghi đúng giới hạn và nguồn chính thức, không tuyên bố tuân thủ production. Không thực hiện bonus tùy chọn.

Đề trong repo không yêu cầu screenshot hay họ tên/MSSV/email thật; không bổ sung dữ liệu cá nhân. Người nộp tự bổ sung nếu TA có yêu cầu riêng, tự xác nhận deadline/nơi nộp, review code và chạy test để giải thích được từng control. Bài làm được chia thành commit theo nhiệm vụ CP1–CP5; push Git không thay thế bước nộp bài theo thông báo TA. Source commit khi bắt đầu: `52b33b5`; lấy SHA bài nộp cuối bằng `git rev-parse HEAD` sau commit CP5.

Các file evidence bắt buộc bị `.gitignore` mặc định chặn đã được kiểm tra dữ liệu synthetic và đưa vào commit bằng `git add -f`: `reports/attack-before.log`, `reports/attack-after.log`, `reports/ledger.jsonl`. Không đưa `.venv`, cache, `.tools` hoặc `reports/sink.log` vào bài nộp.
