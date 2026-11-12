# Tích hợp nhánh bất thường vào Wazuh (ingest → rule → leo thang → Telegram + Active Response)

Khớp với hệ thống thật: nhánh **signature** đã có sẵn trên Wazuh (rule `100100`, `100200–100292`, nhóm
`ids,suricata`, đẩy Telegram qua `custom-telegram`). Nhánh **bất thường** được thêm vào song song,
**dải ID riêng `100300–100320`**, **nhóm `anomaly`** (không chứa chuỗi `suricata`) để tách kênh cảnh báo.

## Luồng

```
anomaly.py (host IDS)                 Wazuh agent (IDS)        Wazuh manager
  --live eve.json                       localfile json          decoder json + anomaly_rules.xml
  → anomaly_alerts.jsonl   ── tail ──▶  tách field  ── gửi ──▶  100300-100312 → leo thang mức
                                                                   ├─ 100305/100306/100311 → Telegram (bot anomaly)
                                                                   └─ 100312 (mức 15) → Active Response: suricata-drop @IPS + Telegram "đã chặn"
```

## Thang leo mức (anomaly_rules.xml)

| rule.id | Điều kiện | Mức | Ý nghĩa |
|---|---|---|---|
| 100300 | `module` = `anomaly_(if\|web\|web_body)` | 3 | Rule gốc nhận diện |
| 100301 | `module` = `anomaly_if` | 10 | Hành vi mạng bất thường (cả hai chiều) |
| 100302 | `module` = `anomaly_web` | 10 | Giá trị tham số bất thường (tham số truy vấn hoặc trường ngắn của thân POST) |
| 100303 | `module` = `anomaly_web_body` | 10 | Văn bản tự do của thân POST bất thường |
| 100304 | 100300 + `severity` = `high` | 12 | Một sự kiện điểm cao |
| 100305 | 100304, báo lần đầu (ignore 300 giây) | 12 | Gửi Telegram |
| 100306 | 100302/100303, báo cảnh báo web (ignore 300 giây) | 10 | Gửi Telegram |
| 100311 | ≥5 cảnh báo cùng `srcip` trong 5 phút | 13 | Tái diễn (tần suất) |
| 100312 | ≥10 cảnh báo cùng `srcip` trong 10 phút, không có ignore | **15** | **Kích hoạt Active Response** và gửi thẻ CRITICAL lên Telegram (mỗi lần kích hoạt một thẻ) |
| 100320 | Con của rule Suricata 86601, `alert.signature` = `KLTN POST body capture` | 0 | Ẩn cảnh báo của rule thu thân POST |

Logic: điểm cao (severity) đẩy mức lên 12; tái diễn cùng nguồn (tần suất) lên 13; tái diễn dai dẳng
lên 15. Nhóm `anomaly_event` chỉ gắn cho rule phát hiện (100301–100304) nên hai rule leo thang không tự
đếm lại chính mình. Tương quan theo `srcip` qua `<same_source_ip />`. Rule 100304 là con trực tiếp của 100300
chứ không của 100301/2/3: trên Wazuh 4.12, rule có nhiều rule cha nằm ở nhiều vị trí trên cây rule và mỗi vị trí
ghi cảnh báo thêm một lần vào danh sách đếm của 100311/100312, nên với ba rule cha mỗi cảnh báo điểm cao bị đếm
ba lần (lượt chạy ngày 12/11: 100312 kích hoạt 8 lần trên 32 cảnh báo `anomaly_event`). Mức 12 cao hơn 10 nên
Wazuh xét 100304 trước 100301-100303. Mô phỏng thuật toán đếm của Wazuh (`Search_LastGroups`) trên danh sách cảnh báo của hai lượt chạy ngày 12/11
khớp mọi lần kích hoạt 100311 và 100312: lượt trước khi sửa khi đếm 100304 ba lần, lượt sau khi sửa khi đếm một lần.

Behavior-IF là một mô-đun cho cả hai chiều: anomaly.py chấm mỗi cửa sổ bằng tham chiếu bình thường ứng với bên khởi
tạo (máy nạn nhân hoặc máy bên ngoài), còn cảnh báo của hai chiều đi chung một chuỗi rule. `srcip` luôn là bên khởi tạo
kết nối trong cửa sổ bị gắn cờ: với chiều ra là máy nạn nhân (chặn tại IPS tương đương cô lập tạm máy đó), với chiều vào
là địa chỉ bên ngoài (chặn nguồn). Trường `direction` (`out`/`in`) chỉ để thẻ cảnh báo chọn cách diễn giải, không ảnh
hưởng rule.

**Lưu ý trường IP:** `anomaly.py` nay xuất cảnh báo với `srcip`/`dstip` (quy ước Wazuh) thay cho
`src_ip`/`dest_ip`, để `same_source_ip` và `suricata-drop` đọc đúng nguồn cần chặn.

## Cảnh báo hành vi: chấm cửa sổ đã đóng và gom theo sự cố

Ở chế độ `--live`, Behavior-IF chấm mỗi cửa sổ 30 phút đúng một lần, khi cửa sổ đã đóng và đã chờ thêm
`ANOMALY_FLOW_DELAY_S` (mặc định 360 giây) cho các bản ghi flow ghi trễ, nên cửa sổ được chấm giống cửa sổ mà notebook
đánh giá. Cảnh báo hành vi vì vậy đến sau khi cửa sổ đóng: trên nhật ký của lab, cửa sổ bị gắn cờ đầu tiên của một lượt
tấn công được chấm sau trung vị 18 phút, chậm nhất khoảng 41 phút kể từ lúc lượt bắt đầu. Mỗi lần khởi động lại, cửa sổ đầu
tiên chỉ được chấm sau khoảng 40-50 phút, nên khởi động dịch vụ trước đợt thử ít nhất một giờ.

Các cửa sổ bị gắn cờ được gom theo sự cố của cặp (`srcip`, `dstip`) trước khi ghi ra `anomaly_alerts.jsonl`, để một hành
vi kéo dài không sinh một cảnh báo ở mỗi bucket 30 phút. Một cửa sổ bị gắn cờ chỉ sinh cảnh báo trong các trường hợp sau
(trường `episode_state`):

| `episode_state` | Khi nào sinh cảnh báo |
|---|---|
| `new` | Cửa sổ bị gắn cờ đầu tiên của cặp, hoặc cửa sổ đầu tiên sau khi cặp đã yên lặng quá `ANOMALY_EPISODE_QUIET_MIN` (mặc định 120 phút) |
| `escalated` | Trong sự cố, mức độ tăng từ `medium` lên `high` |
| `new_behavior` | Trong sự cố, đặc trưng lệch nhiều nhất đổi sang một đặc trưng chưa gặp trong sự cố |
| `ongoing` | Sự cố còn tiếp diễn sau `ANOMALY_EPISODE_REMIND_MIN` (mặc định 360 phút) kể từ cảnh báo trước của sự cố; đặt 0 để tắt nhắc lại |

Các cửa sổ bị gắn cờ còn lại chỉ được cộng dồn vào sự cố. Cảnh báo hành vi có thêm `window_start` (thời điểm bắt đầu
cửa sổ), `episode` (mã sự cố), `episode_start` và `episode_windows` (số bucket 30 phút bất thường tính tới lúc đó); thẻ
Telegram hiện các trường này trên một dòng riêng. Khi sự cố đóng, anomaly.py chỉ in một dòng tổng kết ra nhật ký của dịch
vụ (`journalctl -u anomaly-ids`), không ghi vào tệp cảnh báo. Đặt `ANOMALY_EPISODE=0` để quay về cách cũ (mỗi bucket 30
phút một cảnh báo).

Ảnh hưởng tới rule: 100311/100312 đếm theo `srcip` trong 5 và 10 phút. Trước đây, một nguồn có từ 5 cặp bất thường kéo
dài trở lên làm hai rule này kích hoạt lại mỗi khi cửa sổ đóng; nay chúng chủ yếu kích hoạt lúc các sự cố bắt đầu, hoặc
khi nhiều sự cố cùng tăng mức hay nhắc lại. Cảnh báo web không được gom.

## Bước 1: Host IDS (nơi có Suricata_IDS + agent)

Tạo thư mục log và chạy anomaly.py như cũ (xem `agent_ossec.conf.snippet.xml` cho khối `localfile`):
```bash
sudo mkdir -p /var/log/suricata-anomaly
sudo chown root:wazuh /var/log/suricata-anomaly && sudo chmod 750 /var/log/suricata-anomaly
ANOMALY_LOG=/var/log/suricata-anomaly/anomaly_alerts.jsonl \
  python3 anomaly.py --live /var/log/suricata/eve.json
sudo systemctl restart wazuh-agent
```

`--detect` (chấm lại một tệp nhật ký) là chế độ phân tích offline nên mặc định ghi `anomaly_detect.jsonl` ở thư mục hiện
tại (đổi bằng `--out` hoặc `ANOMALY_DETECT_LOG`), không ghi vào tệp Wazuh đọc: trường `time` là giờ chạy, Wazuh sẽ coi
cảnh báo của nhật ký cũ là cảnh báo mới. Chỉ thêm `--to-wazuh` khi thật sự muốn đẩy kết quả lên Wazuh.

## Bước 2: Wazuh manager

1. **Rule:** copy `anomaly_rules.xml` vào `/var/ossec/etc/rules/`. **KHÔNG** dùng file `local_rules.xml`
   phiên bản cũ (100200–100210) vì trùng ID nhánh signature; nếu đã lỡ thả vào `etc/rules/` thì xóa đi.
2. **ossec.conf:** áp 3 thay đổi trong `ossec_anomaly.snippet.xml`:
   - sửa `custom-telegram` (thêm `<group>suricata</group>` → chỉ gửi signature);
   - thêm `custom-telegram-anomaly` (bot thứ 2, `<group>anomaly_notify</group>`: chỉ gửi các rule báo
     100305, 100306, 100311, 100312; các rule đếm 100301–100304 không lên Telegram);
   - Active Response cho rule 100312 trên **agent IPS** dùng `suricata-drop` theo
     `suricata-drop.config.snippet.xml` (điền id agent IPS, lấy bằng `sudo /var/ossec/bin/agent_control -l`).
3. **Script Telegram (hai file, giống `custom-telegram` mặc định):** `custom-telegram-anomaly` là
   wrapper shell (integratord gọi file này), `custom-telegram-anomaly.py` là code; wrapper chạy `.py`
   bằng python bundled của Wazuh.
   ```bash
   sudo cp custom-telegram-anomaly custom-telegram-anomaly.py attack_v20_playbook.json /var/ossec/integrations/
   sudo chmod 750 /var/ossec/integrations/custom-telegram-anomaly /var/ossec/integrations/custom-telegram-anomaly.py
   sudo chmod 640 /var/ossec/integrations/attack_v20_playbook.json
   sudo chown root:wazuh /var/ossec/integrations/custom-telegram-anomaly /var/ossec/integrations/custom-telegram-anomaly.py /var/ossec/integrations/attack_v20_playbook.json
   ```
   `attack_v20_playbook.json` chứa tên, chiến thuật và Mitigations (mã M) của các kỹ thuật mà thẻ
   cảnh báo có thể gợi ý, sinh bằng `build_attack_playbook.py` từ dữ liệu MITRE ATT&CK Enterprise 20.0 (STIX)
   chính thức (kho `mitre-attack/attack-stix-data`). Script thông báo chỉ đọc tệp này, không truy cập Internet
   khi có cảnh báo; thiếu tệp thì thẻ vẫn gửi nhưng chỉ ghi mã kỹ thuật. Thẻ hiện tối đa ba mitigation cho mỗi kỹ thuật
   (bảng `MIT_PICK` trong script, chọn các mục chặn trực tiếp kỹ thuật hoặc loại bỏ điều kiện để nó thành công), các mục còn
   lại xem ở liên kết tới trang kỹ thuật. Khi muốn lên phiên bản ATT&CK mới:
   sửa `URL` và `EXPECTED_VERSION` trong `build_attack_playbook.py`, chạy lại rồi chép tệp mới lên manager.
   Loại hành vi nghi ngờ được suy từ tổ hợp các đặc trưng lệch trong `why` (đặc trưng đặc thù có độ lệch lớn
   nhất, z ≥ 3), có dùng thêm hai trường `zone_other` và `frac_out` mà anomaly.py ghi cho cảnh báo hành vi.
   Cảnh báo hành vi còn có `direction` (`out`: máy nạn nhân khởi tạo, `in`: bên ngoài khởi tạo) và `dport_top`
   (cổng đích nhiều luồng nhất). Khi `direction` = `in`, thẻ dùng các giả thuyết của phía bên ngoài (dò quét T1595,
   dò đăng nhập T1110 nếu `dport_top` là dịch vụ xác thực, làm ngập kết nối T1499).
   Cảnh báo web có thêm dòng 📍 Vị trí: phương thức, đường dẫn (bỏ chuỗi truy vấn) và tên tham số hoặc trường bị
   gắn cờ, lấy từ `method`, `url`, `location`. Giá trị tham số không được đưa lên thẻ vì có thể chứa dữ liệu nhạy cảm.
   KHÔNG cần sửa code: script nhận chat_id/token qua tham số (giống integration custom-telegram mặc định). Trong
   ossec.conf đặt theo quy ước: `<hook_url>` = **BOT TOKEN**, `<api_key>` = **CHAT_ID**
   (xem ossec_anomaly.snippet.xml). Script dùng `requests` (có sẵn trong python bundled của Wazuh) và
   ghi log `/var/ossec/logs/integrations.log` để soi khi lỗi.
4. **Rule 100320:** đặt `post_body_capture_rule.xml` vào `/var/ossec/etc/rules/` để ẩn cảnh báo của rule thu thân POST
   trên Suricata_IDS (thư mục `suricata/`); bỏ qua bước này nếu manager đã có rule 100320.
5. Nạp lại: `sudo systemctl restart wazuh-manager`.

## Kiểm thử rule trước khi nạp

```bash
sudo /var/ossec/bin/wazuh-logtest
```
Dán từng dòng JSON mẫu; mong đợi: cảnh báo `severity` = `high` lên **mức 12** (rule 100304, hoặc 100305 ở lần
báo đầu); cảnh báo web `severity` = `medium` ở **mức 10** (rule 100302/100303, hoặc 100306 ở lần báo đầu). Bắn lặp
cùng một `srcip` để thấy 100311/100312 kích hoạt.

### Alert mẫu
```
{"module": "anomaly_if", "time": "2026-10-20T14:30:00", "ext_ip": "203.0.113.25", "n_conn": 214, "direction": "out", "dport_top": 8443, "zone_other": "ext", "frac_out": 0.962, "location": "cua so 30'", "score": 0.861, "why": "svc_rarity(+18.2), sqrt_mb_out(+12.7), log_n_conn(+4.1)", "severity": "high", "srcip": "192.168.10.60", "dstip": "203.0.113.25"}
{"module": "anomaly_if", "time": "2026-11-10T09:12:40", "ext_ip": "172.16.99.20", "direction": "in", "dport_top": 22, "n_conn": 310, "zone_other": "ext", "frac_out": 0.412, "location": "cua so 30'", "score": 0.731, "why": "svc_rarity(+50.0), log_peak_cpm(+9.6), log_n_conn(+4.0)", "severity": "high", "srcip": "172.16.99.20", "dstip": "192.168.10.20"}
{"module": "anomaly_web", "time": "2026-10-20T14:31:02", "dest_port": 80, "host": "192.168.10.20", "method": "GET", "url": "/product?id=1", "location": "query:id", "score": 0.742, "why": "n_kw(+50.0), n_squote(+6.0)", "severity": "high", "srcip": "172.16.99.10", "dstip": "192.168.10.20"}
{"module": "anomaly_web_body", "time": "2026-10-20T14:32:20", "dest_port": 80, "host": "192.168.10.20", "method": "POST", "url": "/comment", "location": "body:comment", "score": 0.712, "why": "n_kw(+20.8), r_nonalnum(+5.6), max_run_sym(+4.1)", "severity": "medium", "srcip": "172.16.99.10", "dstip": "192.168.10.20"}
```

## Active Response

Rule 100312 (mức 15) kích hoạt `suricata-drop` (khai trong `<command>` của ossec.conf) trên
**agent IPS** (`<location>defined-agent</location>` + `agent_id` của Suricata_IPS). Vì IPS nằm nội
tuyến, chặn `srcip` tại đó cắt được luồng của nguồn. `timeout` đặt mức chặn tạm thời; hết timeout
Wazuh tự gỡ chặn, cảnh báo đã gửi để người trực xử lý dứt điểm.

100312 không có `ignore` để khi lần chặn trước hết hạn mà nguồn vẫn tấn công thì Active Response chặn lại được. Mỗi lần kích hoạt cũng gửi một thẻ CRITICAL, nên khi nguồn tấn công kéo dài, thẻ mức 15 ra theo nhịp chặn (lượt chạy chiều 12/11, sau khi sửa 100304: mỗi lần kích hoạt sau đúng 10 cảnh báo được đếm, khoảng 2,5-3 phút một lần với nhịp của script tấn công). Cách giới hạn thẻ bằng một rule con có `ignore="300"` đã thử và bỏ: trên Wazuh 4.12, cảnh báo vẫn mang mã 100312 kèm nhóm của rule con ở mọi lần kích hoạt, nên `ignore` của rule con không giới hạn được số thẻ.

Với cảnh báo hành vi do máy nạn nhân khởi tạo (`direction` = `out`), `srcip` là host nội bộ nghi bị chiếm quyền → chặn tại IPS tương
đương cô lập tạm host đó. Với cảnh báo hành vi do bên ngoài khởi tạo (`direction` = `in`) và cảnh báo web,
`srcip` là nguồn bên ngoài → chặn nguồn.

## Cần kiểm chứng ở môi trường thật

- Bộ luật đã chạy trên Wazuh 4.12.0 (manager và agent). Khi đổi phiên bản, xác nhận bằng
  `/var/ossec/bin/wazuh-control info | grep VERSION` rồi chạy lại `wazuh-logtest` với các dòng mẫu ở trên.
- Sau khi thêm `<group>suricata</group>` vào `custom-telegram`, kênh này chỉ còn nhận cảnh báo nhóm
  Suricata; nếu trước đây muốn nó gửi cả cảnh báo khác (vuln/SCA...) thì cân nhắc lại filter.
- Quyền đọc `/var/log/suricata-anomaly/` nếu host bật SELinux/AppArmor.
- Chuỗi tấn công lặp ngày 12/11/2026 đã xác nhận mỗi lần 100312 kích hoạt có một thẻ CRITICAL, suricata-drop chặn nguồn
  trên IPS rồi tự gỡ khi hết hạn. Khi đổi hạ tầng, chạy lại phép thử này và đối chiếu
  `sudo cat /var/ossec/logs/active-responses.log` trên agent IPS.
