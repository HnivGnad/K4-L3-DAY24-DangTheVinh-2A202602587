# Secret giả trong lịch sử Git — checkpoint 4

Ngày kiểm tra: 12/10/2026. Dữ liệu bài lab là synthetic; không tạo credential thật.

- Scanner: Gitleaks **8.30.1**, tải từ release chính thức; SHA256 gói Windows x64 được đối chiếu checksum release: `d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e`.
- Commit: `1bdd849922156c868a5ee9293d68f5b72e242d2c` (viết tắt `1bdd849`).
- File: `lab-fake-secret.txt:1`; rule: `lab24-synthetic-token`. `reports/gitleaks-history.json` ghi **1 finding**, secret đã redact; exit code **1** là kết quả dự kiến của bài tập, không chứng minh credential thật bị lộ.
- Token đã bị xóa khỏi HEAD, nhưng vẫn tồn tại trong Git history. Không in lại giá trị token vào báo cáo.
- Quét file hiện tại: xem `reports/gitleaks-current.json` và log tương ứng; kết quả cuối phải là `[]`, exit 0.
- Hook `.pre-commit-config.yaml` pin `v8.30.1`, `gitleaks-system`, `pass_filenames: false`, dùng `gitleaks dir` để kiểm tra hiện tại. `gitleaks git` dùng riêng cho finding lịch sử dự kiến.
- Lần quét đầu phát hiện mẫu minh họa trong README công cụ tải về và các fixture của chính Gitleaks ở cache pre-commit. Đã loại trừ đúng bốn thư mục sinh tự động trong `.gitleaks.toml`: `.venv`, `.tools`, `.tool-cache`, `.pre-commit-cache`. Không loại trừ `agent/`, `corpus/`, `data/`, `reports/` hay file token lịch sử.
- Nếu là secret thật: **thu hồi/rotate** tại nhà cung cấp ngay, kiểm tra quyền và log sử dụng, thay credential ở dịch vụ phụ thuộc, đánh giá tác động và xử lý thông báo theo quy trình tổ chức. Xóa file hoặc viết lại Git history không vô hiệu hóa bản sao đã bị lấy.
- Pin dependency và hash lock giảm thay đổi gói không kiểm soát; hook giúp phát hiện trước khi commit. Cả hai không rotate secret, không đảm bảo dependency không có lỗ hổng, và không thay thế kiểm tra quyền hay giám sát production.
