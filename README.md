# Isolation Forest phát hiện bất thường từ sự kiện của Suricata

Mã nguồn khóa luận tốt nghiệp **"Nghiên cứu ứng dụng thuật toán Isolation Forest trong phát hiện bất thường từ sự kiện an ninh mạng của Suricata"**.

- Sinh viên: Phạm Lê Hoàng Anh (24TX810002)
- Giảng viên hướng dẫn: ThS. Nguyễn Thanh Nhã

Đề tài xây dựng nhánh phát hiện bất thường chạy song song với nhánh chữ ký của Suricata, gồm hai mô-đun Isolation Forest học không giám sát trên nhật ký `eve.json`:

- **Behavior-IF**: bản ghi `flow`, đơn vị phân tích là cặp máy trong cửa sổ 30 phút, cho cả chiều ra và chiều vào.
- **Web-App IF**: bản ghi `http` và thân POST, đơn vị phân tích là giá trị tham số; gồm Web-Query IF (tham số truy vấn, trường ngắn) và Web-Body IF (văn bản tự do của thân POST). Mô-đun nhắm vào bốn loại tấn công: SQL Injection, XSS, command injection và path traversal, trọng tâm là SQL Injection và XSS.

Cảnh báo được đẩy vào Wazuh, phân loại theo bộ rule riêng, gửi Telegram và có thể chặn nguồn qua Active Response.

## Kết quả trên tập kiểm thử

Mô hình chỉ học trên dữ liệu hợp lệ do đề tài tạo. Ngưỡng của mỗi mô hình được chọn trên tập kiểm định sao cho FPR không vượt 0,2%; tập kiểm thử chỉ dùng để chấm tại ngưỡng đó.

### Behavior-IF

| Chỉ số | Kết quả |
|---|---|
| Lượt và phiên tấn công được phát hiện | 531 / 532 (99,81%) |
| Recall theo cửa sổ | 97,08% |
| FPR chiều ra, tập kiểm định / kiểm thử | 0,141% / 0,146% |
| FPR chiều vào, tập kiểm thử | 0% |
| Cảnh báo nhầm mỗi giờ, kiểm định / kiểm thử | 1,27 / 0,75 |

![Recall của Behavior-IF theo hành vi](docs/behavior_if_recall.png)

![Phân bố điểm của cửa sổ chiều ra trên tập kiểm thử](docs/behavior_if_phan_bo_diem.png)

### Web-App IF

| Chỉ số | GET | POST |
|---|---|---|
| Tấn công gửi tay trên trang thực nghiệm | 99,78% | 97,47% |
| Recall trên tập kiểm thử (bốn loại) | 97,03% | 88,72% |
| Recall riêng SQL Injection và XSS | 99,62% | 96,00% |
| FPR trên request hợp lệ do script duyệt web tạo | 0% | 0% |
| FPR chung trên tập kiểm thử | 0,533% | 0,534% |

![Recall của Web-App IF với SQL Injection và XSS](docs/web_app_if_recall_sqli_xss.png)

![Phân bố điểm của Web-Query IF và Web-Body IF với SQL Injection và XSS](docs/web_app_if_phan_bo_sqli_xss.png)

![Recall của Web-App IF với command injection và path traversal](docs/web_app_if_recall_cmdi_pt.png)

![Phân bố điểm của Web-Query IF và Web-Body IF với command injection và path traversal](docs/web_app_if_phan_bo_cmdi_pt.png)

Mỗi giá trị tham số do đúng một mô hình chấm: query GET và trường ngắn của POST (email, tên, mã số, trường ẩn của form...) do Web-Query IF chấm (nửa trái của hình phân bố điểm); văn bản tự do của POST (bình luận, nội dung tin nhắn, bài viết) do Web-Body IF chấm (nửa phải). Mỗi nửa so phân bố điểm của giá trị hợp lệ với giá trị mang tấn công của nhóm, kèm ngưỡng của mô hình. Một request bị gắn cờ khi có giá trị vượt ngưỡng của mô hình chấm nó; cột ở điểm 1,0 là các giá trị bị bước kiểm tra miền gán điểm 1. SQL Injection và XSS nằm xa ngưỡng ở cả hai mô hình; command injection và path traversal sát ngưỡng hơn, nhất là ở văn bản tự do, và là điểm yếu của mô-đun.

### Kiểm chứng

- Isolation Forest tự cài xếp hạng gần như trùng scikit-learn (tương quan Spearman 0,982 đến 0,994).
- `anomaly.py` chấm lại toàn bộ tập kiểm thử và cho cùng quyết định với bản scikit-learn trong notebook.

## Thực nghiệm trên hệ thống triển khai

Kết quả chạy các kịch bản tấn công trực tiếp trên hệ thống đã triển khai (Chương 4 của báo cáo) sẽ được cập nhật sau. Hình dưới là ví dụ thẻ cảnh báo mà nhánh bất thường gửi qua Telegram, kèm kỹ thuật MITRE ATT&CK và các biện pháp phòng ngừa.

![Ví dụ thẻ cảnh báo gửi qua Telegram](docs/the_canh_bao_telegram.png)

## Hạ tầng thực nghiệm

Ba vùng trên EVE-NG: vùng tấn công, vùng nạn nhân (VLAN 10) và vùng quản trị (VLAN 20). Suricata_IPS đặt nội tuyến, Suricata_IDS nhận bản sao qua SPAN và chạy `anomaly.py`.

![Sơ đồ hạ tầng thực nghiệm](docs/so_do_mang.png)

## Cấu trúc kho

| Thư mục | Nội dung |
|---|---|
| (thư mục gốc) | Hai notebook huấn luyện `KLTN_BehaviorIF.ipynb`, `KLTN_WebAppIF.ipynb`; `isolationforest.py` (Isolation Forest tự cài bằng NumPy); `anomaly.py` (chấm điểm trực tuyến trên `eve.json`) |
| `wazuh/` | Bộ rule Wazuh, script thông báo Telegram, script Active Response, dịch vụ systemd |
| `suricata/` | Rule thu thân POST và cấu hình eve-log trên Suricata_IDS |
| `docs/` | Hình minh họa trong README; các hình kết quả do hai notebook ghi ra |
| `data/` | Đặt bộ dữ liệu vào đây (không đi kèm kho, xem `data/README.md`) |

## Chạy lại

Môi trường: Python 3.13. Ô đầu của mỗi notebook cài đúng phiên bản dùng khi chốt số liệu (numpy 2.5.3, scikit-learn 1.9.1) cùng pandas, scipy, matplotlib, joblib và gdown; khác phiên bản thì cây có thể khác đôi chút. Dữ liệu không đi kèm kho: chép các tệp CSV vào `data/`, hoặc điền `DRIVE_URL` trong ô cấu hình để notebook tự tải thư mục dữ liệu từ Google Drive.

```
python -m venv .venv
.venv\Scripts\pip install jupyter
.venv\Scripts\jupyter nbconvert --to notebook --execute --inplace KLTN_WebAppIF.ipynb
.venv\Scripts\jupyter nbconvert --to notebook --execute --inplace KLTN_BehaviorIF.ipynb
```

Mỗi notebook ghi ra một tệp mô hình để `anomaly.py` nạp khi chạy trực tuyến.
