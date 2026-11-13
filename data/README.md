# Bộ dữ liệu KLTN: Isolation Forest trên sự kiện của Suricata

Phiên bản 4.0 (10/11/2026). Tác giả: Phạm Lê Hoàng Anh (24TX810002). Giảng viên hướng dẫn: ThS. Nguyễn Thanh Nhã.

Thư mục này là bộ dữ liệu dùng để chạy hai notebook `KLTN_BehaviorIF.ipynb` và `KLTN_WebAppIF.ipynb` của khóa luận. Mã nguồn ở kho GitHub của đề tài, https://github.com/hoanganh-net/KLTN-IsolationForest-Suricata; tải cả thư mục này về rồi đặt vào `data/` của kho.

| Tệp | Dùng cho | Kích thước |
|---|---|---|
| `flow_normal.csv` | Behavior-IF, huấn luyện | 583 MB |
| `flow_test.csv` | Behavior-IF, kiểm thử (lab và CTU-13) | 482 MB |
| `flow_runs.csv` | Nhãn lượt tấn công của tập kiểm thử Behavior-IF | 0,1 MB |
| `web_get_train.csv`, `web_get_test.csv` | Web-App IF, GET | 12 MB, 8,5 MB |
| `web_post_train.csv`, `web_post_test.csv` | Web-App IF, POST | 22 MB, 22 MB |
| `DATASET_CARD.md` | Mô tả nguồn gốc, cách dựng, nhãn, cách chia tập và giới hạn | |
| `SHA256SUMS.txt` | Mã băm SHA-256 để kiểm tra tệp sau khi tải | |

Kiểm tra sau khi tải (Linux): `sha256sum -c SHA256SUMS.txt --ignore-missing`. Trên Windows: `certutil -hashfile <tệp> SHA256` rồi so với dòng tương ứng.

## Điều kiện sử dụng

Bộ dữ liệu phục vụ đánh giá khóa luận, không dùng cho mục đích thương mại. Các dòng lấy từ HTTP Dataset CSIC 2010, ECML/PKDD 2007 và CTU-13 thuộc về nhóm tác giả gốc; nguồn và cách tải lại từng bộ ghi ở mục 8 của `DATASET_CARD.md`.
