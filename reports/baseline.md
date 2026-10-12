# Baseline — checkpoint 1

1. `_naive_loop()` tại `agent/loop.py:27` chưa tạo identity/TTL cho mỗi run, và không kiểm tra principal dù CLI có tham số `--as`.
2. Chính `_naive_loop()` tin chỉ thị từ tool output (`agent/loop.py:34`), đọc hồ sơ theo ID attacker (`:39`) rồi gọi `http_post` (`:44`); `agent/tools.py` chỉ giới hạn đích localhost, chưa có PEP phân quyền hay kiểm soát mục đích.
3. `reports/attack-before.log:1` chứa request `/reconcile` và CCCD/SĐT/STK synthetic của `KH-000999`; các log `reports/variant-1-before.log` đến `variant-4-before.log` tái hiện riêng từng lure, mỗi file 299 byte.
