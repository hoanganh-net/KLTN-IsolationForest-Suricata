# Tích hợp nhánh bất thường vào Wazuh (ingest → rule → leo thang → Telegram + Active Response)

Khớp với hệ thống thật: nhánh **signature** đã có sẵn trên Wazuh (rule `100100`, `100200–100292`, nhóm
`ids,suricata`, đẩy Telegram qua `custom-telegram`). Nhánh **bất thường** được thêm vào song song,
**dải ID riêng `100300–100320`**, **nhóm `anomaly`** (không chứa chuỗi `suricata`) để tách kênh cảnh báo.

## Luồng

```
anomaly.py (host IDS)                 Wazuh agent (IDS)        Wazuh manager
  --live eve.json                       localfile json          decoder json + anomaly_rules.xml
  → anomaly_alerts.jsonl   ── tail ──▶  tách field  ── gửi ──▶  100300-100312 → leo thang mức
                                                                   ├─ 100305/100306/100307/100308/100309/100311 → Telegram (bot anomaly)
                                                                   ├─ 100309 (mức 12, nhãn brute/flood) → Active Response: suricata-drop @IPS
                                                                   └─ 100312 (mức 15) → Active Response: suricata-drop @IPS + Telegram "đã chặn"
```

## Thang leo mức (anomaly_rules.xml)

| rule.id | Điều kiện | Mức | Ý nghĩa |
|---|---|---|---|
| 100300 | `module` = `anomaly_(if\|if_rt\|web\|web_body)` | 3 | Rule gốc nhận diện |
| 100301 | `module` = `anomaly_if` | 10 | Hành vi mạng bất thường, Tầng 2 (cửa sổ 30 phút, cả hai chiều) |
| 100302 | `module` = `anomaly_web` | 10 | Giá trị tham số bất thường (tham số truy vấn hoặc trường ngắn của thân POST) |
| 100303 | `module` = `anomaly_web_body` | 10 | Văn bản tự do của thân POST bất thường |
| 100307 | `module` = `anomaly_if_rt`, không ignore | 10 | Cảnh báo nhanh của Tầng 1 (cửa sổ 2 phút), gửi Telegram |
| 100309 | 100307 + `behavior` = `brute` hoặc `flood` (đặt trước 100308 trong tệp) | 12 | Tầng 1 gán nhãn dò đăng nhập hoặc làm ngập: gửi Telegram và **kích hoạt Active Response** chặn nguồn ngay |
| 100308 | 100307 + `severity` = `high` | 12 | Cảnh báo nhanh điểm cao, gửi Telegram |
| 100304 | 100300 + `module` = `anomaly_(if\|web\|web_body)` + `severity` = `high` | 12 | Một sự kiện điểm cao của Tầng 2 hoặc nhánh web |
| 100305 | 100304, báo lần đầu (ignore 300 giây) | 12 | Gửi Telegram |
| 100306 | 100302/100303, báo cảnh báo web (ignore 300 giây) | 10 | Gửi Telegram |
| 100311 | ≥5 cảnh báo cùng `srcip` trong 5 phút | 13 | Tái diễn (tần suất) |
| 100312 | ≥10 cảnh báo cùng `srcip` trong 10 phút, không có ignore | **15** | **Kích hoạt Active Response** và gửi thẻ CRITICAL lên Telegram (mỗi lần kích hoạt một thẻ) |
| 100320 | Con của rule Suricata 86601, `alert.signature` = `KLTN POST body capture` | 0 | Ẩn cảnh báo của rule thu thân POST |

Logic: điểm cao (severity) đẩy mức lên 12; tái diễn cùng nguồn (tần suất) lên 13; tái diễn dai dẳng
lên 15. Nhóm `anomaly_event` chỉ gắn cho rule phát hiện (100301–100304, 100307–100309) nên hai rule leo thang
không tự đếm lại chính mình. Tương quan theo `srcip` qua `<same_source_ip />`. Rule 100304 là con trực tiếp của 100300
chứ không của 100301/2/3: trên Wazuh 4.12, rule có nhiều rule cha nằm ở nhiều vị trí trên cây rule và mỗi vị trí
ghi cảnh báo thêm một lần vào danh sách đếm của 100311/100312, nên với ba rule cha mỗi cảnh báo điểm cao bị đếm
ba lần (lượt chạy ngày 12/11: 100312 kích hoạt 8 lần trên 32 cảnh báo `anomaly_event`). Mức 12 cao hơn 10 nên
Wazuh xét 100304 trước 100301-100303. Mô phỏng thuật toán đếm của Wazuh (`Search_LastGroups`) trên danh sách cảnh báo của hai lượt chạy ngày 12/11
khớp mọi lần kích hoạt 100311 và 100312: lượt trước khi sửa khi đếm 100304 ba lần, lượt sau khi sửa khi đếm một lần.

Tầng 1 của Behavior-IF (module `anomaly_if_rt`) đi nhánh riêng 100307 → 100309 hoặc 100308 và báo thẳng ra Telegram, không có
`ignore`. anomaly.py đã gom cảnh báo Tầng 1 theo sự cố của cặp máy trước khi ghi: chỉ ghi khi mở sự cố mới, khi mức độ
tăng từ medium lên high hoặc khi đặc trưng lệch nhất đổi sang đặc trưng chưa gặp trong sự cố. Còn `ignore` của Wazuh tính
cho cả rule chứ không theo nguồn, nên nếu đặt sẽ nuốt cảnh báo nhanh của nguồn khác trong cùng 300 giây. Cũng vì lý do đó
100304 chỉ nhận ba module cũ: cảnh báo Tầng 1 điểm cao mà rơi vào 100304 → 100305 sẽ bị `ignore` của 100305 chặn.
100308 và 100309 chỉ có một rule cha (100307) nên mỗi cảnh báo được đếm một lần vào 100311/100312. 100309 đặt trước 100308
trong tệp vì Wazuh xét rule con theo thứ tự trong tệp: cảnh báo mang nhãn `brute` hoặc `flood` vào 100309 ở bất kỳ mức độ nào,
cảnh báo nhãn `scan` hoặc không nhãn mà điểm cao vào 100308.

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
đánh giá. Cảnh báo Tầng 2 vì vậy đến sau khi cửa sổ đóng: trên tập kiểm thử lab, tính theo giờ thật từ luồng đầu tiên của
lượt, Tầng 2 báo sau trung vị 15,1 phút, 90% số lượt không quá 20,9 phút, chậm nhất 49 phút (mục 5 của notebook 1). Mỗi lần
khởi động lại, cửa sổ 30 phút đầu tiên chỉ được chấm sau khoảng 40-50 phút, nên khởi động dịch vụ trước đợt thử ít nhất một
giờ; Tầng 1 (cửa sổ 2 phút) báo được sau vài phút.

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

Khi chạy nền bằng `anomaly-ids.service`, các tệp trong `suricata/anomaly/` (`anomaly.py`, `common.py`, `behavior.py`, `web.py`,
`whitelist.txt`) và hai joblib đặt cùng trong `/opt/ml`; sau mỗi lần chép tệp mới vào đó thì chạy
`sudo systemctl restart anomaly-ids`. Nhật ký khởi động (`journalctl -u anomaly-ids`) phải có dòng `[TẦNG 1 live] cửa sổ 2', ...`
kèm ngưỡng hai chiều; dòng `[TẦNG 1 live] tắt` nghĩa là joblib chưa có khóa `rt`. Muốn ghi số đo hiệu năng (CPU%, RSS, thời
gian chấm) thì thêm `ANOMALY_PERF=1` vào môi trường của dịch vụ: anomaly.py ghi `anomaly_perf.jsonl` cạnh tệp cảnh báo, mặc
định 30 giây một mẫu. Chu kỳ đọc và chấm lại của Tầng 1 lấy theo joblib (10 giây); đặt `ANOMALY_RT_INTERVAL_S=5` để chấm lại
mỗi 5 giây (xem mục Rút ngắn độ trễ Tầng 1). Danh sách loại trừ `whitelist.txt` đặt cạnh anomaly.py (`/opt/ml/whitelist.txt`,
đổi đường dẫn bằng `ANOMALY_WHITELIST`); nhật ký khởi động in dòng `[BEHAVIOR-IF] danh sách loại trừ: N mục` (xem mục Danh
sách loại trừ của nhánh hành vi).

`--detect` (chấm lại một tệp nhật ký) là chế độ phân tích offline nên mặc định ghi `anomaly_detect.jsonl` ở thư mục hiện
tại (đổi bằng `--out` hoặc `ANOMALY_DETECT_LOG`), không ghi vào tệp Wazuh đọc: trường `time` là giờ chạy, Wazuh sẽ coi
cảnh báo của nhật ký cũ là cảnh báo mới. Chỉ thêm `--to-wazuh` khi thật sự muốn đẩy kết quả lên Wazuh.

## Bước 2: Wazuh manager

1. **Rule:** copy `anomaly_rules.xml` vào `/var/ossec/etc/rules/`. **KHÔNG** dùng file `local_rules.xml`
   phiên bản cũ (100200–100210) vì trùng ID nhánh signature; nếu đã lỡ thả vào `etc/rules/` thì xóa đi.
2. **ossec.conf:** áp 3 thay đổi trong `ossec_anomaly.snippet.xml`:
   - sửa `custom-telegram` (thêm `<group>suricata</group>` → chỉ gửi signature);
   - thêm `custom-telegram-anomaly` (bot thứ 2, `<group>anomaly_notify</group>`: chỉ gửi các rule báo
     100305, 100306, 100307, 100308, 100309, 100311, 100312; các rule đếm 100301–100304 không lên Telegram);
   - Active Response cho rule 100309 và 100312 (hai khối `<active-response>` riêng) trên **agent IPS** dùng `suricata-drop` theo
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
   Cảnh báo hành vi còn có `direction` (`out`: máy nạn nhân khởi tạo, `in`: bên ngoài khởi tạo), `dport_top`
   (cổng đích nhiều luồng nhất) và `n_ports` (số cổng đích khác nhau trong cửa sổ). Khi `direction` = `in`, thẻ dùng các
   giả thuyết của phía bên ngoài (dò quét T1595, dò đăng nhập T1110 nếu `dport_top` là dịch vụ xác thực, làm ngập kết nối
   T1499). Khi `n_ports` từ 10 trở lên, thẻ ghi "nhiều cổng, N cổng khác nhau" thay cho một cổng, vì lượt dò chỉ có vài luồng
   mỗi cổng nên cổng nhiều luồng nhất gần như ngẫu nhiên; cảnh báo từ anomaly.py cũ chưa có `n_ports` thì thẻ chỉ ghi "nhiều
   cổng" khi `log_n_ports` chạm trần độ lệch +50.
   Cảnh báo Tầng 1 (`anomaly_if_rt`) có thêm `t_det_s` (đồng hồ live của engine tính từ đầu cửa sổ 2 phút) và `lat_s`
   (giờ phát cảnh báo trừ lúc bắt đầu của luồng sớm nhất trong cửa sổ, tức độ trễ đầu cuối khi chạy live); thẻ hiện
   `lat_s` khi giá trị nằm trong 0-3600 giây, ngoài khoảng đó (ví dụ khi phát lại nhật ký cũ) thì hiện `t_det_s`.
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
báo đầu); cảnh báo web `severity` = `medium` ở **mức 10** (rule 100302/100303, hoặc 100306 ở lần báo đầu); cảnh báo
Tầng 1 (`anomaly_if_rt`) `severity` = `medium` ở **mức 10** (rule 100307) và `high` ở **mức 12** (rule 100308), cả hai
mang nhóm `anomaly_notify` và không được rơi vào 100304/100305; cảnh báo Tầng 1 có `behavior` = `brute` hoặc `flood` ở
**mức 12** (rule 100309) dù `severity` là gì. Bắn lặp cùng một `srcip` để thấy 100311/100312 kích hoạt.

### Alert mẫu
```
{"module": "anomaly_if", "time": "2026-10-20T14:30:00", "ext_ip": "203.0.113.25", "n_conn": 214, "direction": "out", "dport_top": 8443, "zone_other": "ext", "frac_out": 0.962, "location": "cua so 30'", "score": 0.861, "why": "svc_rarity(+18.2), sqrt_mb_out(+12.7), log_n_conn(+4.1)", "severity": "high", "srcip": "192.168.10.60", "dstip": "203.0.113.25"}
{"module": "anomaly_if", "time": "2026-11-10T09:12:40", "ext_ip": "172.16.99.20", "direction": "in", "dport_top": 22, "n_conn": 310, "zone_other": "ext", "frac_out": 0.412, "location": "cua so 30'", "score": 0.731, "why": "svc_rarity(+50.0), log_peak_cpm(+9.6), log_n_conn(+4.0)", "severity": "high", "srcip": "172.16.99.20", "dstip": "192.168.10.20"}
{"module": "anomaly_web", "time": "2026-10-20T14:31:02", "dest_port": 80, "host": "192.168.10.20", "method": "GET", "url": "/product?id=1", "location": "query:id", "score": 0.742, "why": "n_kw(+50.0), n_squote(+6.0)", "severity": "high", "srcip": "172.16.99.10", "dstip": "192.168.10.20"}
{"module": "anomaly_web_body", "time": "2026-10-20T14:32:20", "dest_port": 80, "host": "192.168.10.20", "method": "POST", "url": "/comment", "location": "body:comment", "score": 0.712, "why": "n_kw(+20.8), r_nonalnum(+5.6), max_run_sym(+4.1)", "severity": "medium", "srcip": "172.16.99.10", "dstip": "192.168.10.20"}
{"module": "anomaly_if_rt", "time": "2026-11-14T22:42:24", "ext_ip": "192.168.20.10", "n_conn": 14, "direction": "out", "dport_top": 22, "zone_other": "mgmt", "frac_out": 0.508, "window_start": "2026-10-10T23:32:00+07:00", "location": "cửa sổ 2' (Tầng 1)", "score": 0.7608277874701078, "episode": "192.168.10.22>192.168.20.10@2026-10-10T23:32:00+07:00", "episode_state": "new", "episode_start": "2026-10-10T23:32:00+07:00", "episode_windows": 1, "t_det_s": 86.4, "why": "svc_rarity(+16.2), periodicity(+10.6), uniformity(+5.1)", "severity": "medium", "srcip": "192.168.10.22", "dstip": "192.168.20.10"}
{"module": "anomaly_if_rt", "time": "2026-11-14T22:42:06", "ext_ip": "172.16.99.10", "n_conn": 92, "direction": "in", "dport_top": 5003, "zone_other": "ext", "frac_out": 0.522, "window_start": "2026-09-14T19:41:00+07:00", "location": "cửa sổ 2' (Tầng 1)", "score": 0.7730088321958863, "episode": "172.16.99.10>192.168.10.20@2026-09-14T19:41:00+07:00", "episode_state": "new", "episode_start": "2026-09-14T19:41:00+07:00", "episode_windows": 1, "t_det_s": 88.8, "why": "log_n_ports(+50.0), svc_rarity(+50.0), uniformity(+8.0)", "severity": "high", "srcip": "172.16.99.10", "dstip": "192.168.10.20"}
```
Hai dòng cuối là cảnh báo Tầng 1 thật do anomaly.py ghi khi phát lại eve.json ngày 10/10 (dò SSH sang vùng quản trị, mức
medium) và 14/09 (dò quét từ vùng tấn công vào máy A, mức high).

## Active Response

Hai rule kích hoạt `suricata-drop` (khai trong `<command>` của ossec.conf) trên **agent IPS**
(`<location>defined-agent</location>` + `agent_id` của Suricata_IPS), mỗi rule một khối `<active-response>`: 100312 (mức 15)
chặn nguồn tái diễn, 100309 (mức 12) chặn ngay nguồn mà Tầng 1 gán nhãn `brute` hoặc `flood`. Vì IPS nằm nội
tuyến, chặn `srcip` tại đó cắt được luồng của nguồn. `timeout` đặt mức chặn tạm thời; hết timeout
Wazuh tự gỡ chặn, cảnh báo đã gửi để người trực xử lý dứt điểm.

`suricata-drop` thêm rule `drop ip <srcip>` (SID dải 98xxxxxx) vào tệp rule tùy chỉnh của Suricata_IPS, kèm
`threshold: type limit, track by_src, count 1, seconds 15`: mọi gói của nguồn vẫn bị chặn, nhưng mỗi nguồn chỉ sinh tối đa
một cảnh báo chặn trong 15 giây, để khi nguồn đang làm ngập thì luồng cảnh báo của nhánh signature không bị ngập theo.

100312 không có `ignore` để khi lần chặn trước hết hạn mà nguồn vẫn tấn công thì Active Response chặn lại được. Mỗi lần kích hoạt cũng gửi một thẻ CRITICAL, nên khi nguồn tấn công kéo dài, thẻ mức 15 ra theo nhịp chặn (lượt chạy chiều 12/11, sau khi sửa 100304: mỗi lần kích hoạt sau đúng 10 cảnh báo được đếm, khoảng 2,5-3 phút một lần với nhịp của script tấn công). Cách giới hạn thẻ bằng một rule con có `ignore="300"` đã thử và bỏ: trên Wazuh 4.12, cảnh báo vẫn mang mã 100312 kèm nhóm của rule con ở mọi lần kích hoạt, nên `ignore` của rule con không giới hạn được số thẻ.

Với cảnh báo hành vi do máy nạn nhân khởi tạo (`direction` = `out`), `srcip` là host nội bộ nghi bị chiếm quyền → chặn tại IPS tương
đương cô lập tạm host đó. Với cảnh báo hành vi do bên ngoài khởi tạo (`direction` = `in`) và cảnh báo web,
`srcip` là nguồn bên ngoài → chặn nguồn.

Cảnh báo hành vi của một cặp máy chỉ đi tới Active Response khi Tầng 1 gán nhãn `brute` hoặc `flood` (rule 100309). Hai nhãn
này chỉ gán cho cửa sổ chiều vào, nên địa chỉ bị chặn luôn là bên khởi tạo ở ngoài, không bao giờ là máy nạn nhân. Dò quét
(`scan`) chỉ được cảnh báo và gán kỹ thuật tương ứng, vì một lần chặn ngắn không ngăn được bước trinh sát tiếp theo.

Các cảnh báo hành vi đơn cặp còn lại không đi tới Active Response, và đây là chủ ý thiết kế. Vì anomaly.py gom theo sự cố, một
lượt tấn công đơn cặp chỉ sinh một đến hai cảnh báo Tầng 1 và một đến hai cảnh báo Tầng 2 cách nhau ít nhất 15 phút. Mô phỏng
chính sách gom và cây rule trên từng lượt của tập kiểm thử lab cho thấy không lượt nào có quá 2 cảnh báo `anomaly_event` trong
5 phút, xa ngưỡng tần suất của 100311 (5 trong 5 phút) và 100312 (10 trong 10 phút). Active Response theo tần suất vì vậy chỉ chặn nguồn
tái diễn dai dẳng: chuỗi request web bị gắn cờ (nhánh web không gom), hoặc một nguồn gây bất thường trên nhiều máy đích trong
thời gian ngắn (mỗi cặp là một sự cố riêng). Chặn tự động theo một cảnh báo hành vi đơn lẻ không mang nhãn dễ cô lập nhầm máy hợp lệ: trên tập
kiểm thử, Tầng 1 chiều ra vẫn có 0,49 cảnh báo nhầm/giờ.

## Số thẻ Telegram của một lượt tấn công

Số liệu dưới đây mô phỏng từng lượt của tập kiểm thử lab như khi chạy riêng lẻ (sự cố mới), theo chính sách gom của
anomaly.py và cây rule ở trên. Với timeout luồng mặc định của Suricata, thẻ Tầng 1 đến sau trung vị 72 giây (dò cổng) và
91 giây (dò SSH) theo giờ thật, chủ yếu do Suricata chỉ ghi bản ghi flow khi luồng hết hạn (xem mục Rút ngắn độ trễ Tầng 1);
thẻ Tầng 2 đến sau khoảng 15 phút.

| Lượt | Thẻ Tầng 1 (100307/100308) | Thẻ Tầng 2 (100305) | Tổng thẻ nhánh bất thường |
|---|---|---|---|
| scan_mgmt: dò cổng 1-1024 tới một máy (109 lượt) | 1, mức 12 (2 lượt có 2 thẻ) | 1, mức 12 | 2 (2 lượt: 3) |
| auth_mgmt: 40 lần đăng nhập SSH lỗi (118 lượt) | 1, chủ yếu mức 10 (15 lượt có 2 thẻ) | 1, mức 12 (7 lượt có 2 thẻ) | 2 (22 lượt: 3) |

Nhánh signature gửi thẻ riêng qua bot `custom-telegram`. Quét nhiều máy đích cùng lúc nhân số thẻ theo số cặp; từ 5 cảnh báo
cùng nguồn trong 5 phút có thêm thẻ 100311, từ 10 cảnh báo trong 10 phút thì 100312 chặn nguồn. Trạng thái sự cố nằm trong bộ
nhớ của anomaly.py: lượt lặp lại trên cùng cặp trong vòng 15 phút (Tầng 1) hoặc 2 giờ (Tầng 2) kể từ cửa sổ bất thường cuối được
gộp vào sự cố cũ và không sinh thẻ mới, trừ khi mức độ tăng hoặc đặc trưng lệch nhất đổi. Khi tập dượt trước buổi trình diễn,
dùng cặp máy khác hoặc khởi động lại dịch vụ trước ít nhất một giờ. Trên phần bình thường của tập kiểm thử, nhánh hành vi sinh
khoảng 0,5 thẻ nhầm/giờ, gần như toàn bộ từ Tầng 1 chiều ra; khi dùng danh sách loại trừ ở mục dưới, còn khoảng 0,2 thẻ/giờ.

## Rút ngắn độ trễ Tầng 1

Phần lớn độ trễ của Tầng 1 nằm ở cảm biến: Suricata chỉ ghi bản ghi flow khi luồng hết hạn trong bảng flow. Trên bộ dữ liệu
4.1, 91% số luồng là TCP có độ trễ ghi khoảng 61-70 giây, tức timeout mặc định 60 giây của trạng thái `new` (chưa bắt tay xong)
và `closed`, cộng vài giây của flow manager; luồng TCP còn mở chờ 600 giây (`established`), luồng UDP 30 hoặc 300 giây.
Tệp `suricata/flow-timeouts.snippet.yaml` hạ `tcp.new` xuống 10 giây và `tcp.closed` xuống 5 giây trên Suricata_IDS, dùng
cùng `ANOMALY_RT_INTERVAL_S=5`. `tcp.new` không hạ xuống 5 giây vì SYN được gửi lại với khoảng cách tăng gấp đôi: luồng chưa
bắt tay xong kéo dài từ 15 giây có khoảng nghỉ vượt 5 giây và bị tách thành nhiều bản ghi, chiếm 28,7% số luồng chưa bắt tay
xong của lưu lượng nền, làm lệch đặc trưng so với lúc huấn luyện; với 10 giây tỉ lệ này còn 0,03%.

Mô phỏng trên bộ dữ liệu 4.1, giữ nguyên mô hình và ngưỡng, dời thời điểm ghi của các luồng thuộc cụm 60 giây và giữ phần trễ
thêm của flow manager như đã đo, cho trung vị độ trễ Tầng 1 theo giờ thật (chưa tính chặng Wazuh và Telegram): dò cổng sang
vùng quản trị 9 giây, dò từ vùng tấn công 10 giây, làm ngập 6 giây, dò SSH 32 giây, tấn công web 41 giây. Hai loại sau chậm
hơn chủ yếu vì cửa sổ cần tích lũy đủ số lần thử để điểm vượt ngưỡng. Cảnh báo nhầm của Tầng 1 chiều ra là 0,72/giờ trên tập kiểm định
(trước là 0,71) và 0,52/giờ trên tập kiểm thử (trước là 0,49), chiều vào vẫn 0. Mô phỏng không tái hiện việc tách luồng và
giả định flow manager giữ nhịp như cũ, nên sau khi đổi cấu hình phải đo lại độ trễ (`lat_s` trên thẻ) và cảnh báo nhầm khi
chạy thật. Đo thực trên lab ngày 15/11/2026 (Suricata 7.0.3), cùng lệnh `nmap -sS -sV -Pn` từ vùng tấn công vào máy A, mỗi
cấu hình một lượt: thẻ Tầng 1 báo `lat_s` 66 giây với timeout mặc định và chu kỳ 10 giây, 9 giây sau khi đổi sang `tcp.new`
10 giây, `tcp.closed` 5 giây và chu kỳ 5 giây. Trong 3 phút đầu của đợt chạy sau khi đổi (từ 13:15), Suricata ghi 874 luồng TCP
đã đóng sau trung vị 10,3 giây kể từ lúc kết thúc (90% không quá 14,2 giây) và 35 luồng chưa bắt tay xong sau trung vị 16,8 giây
(90% không quá 19,7 giây): phần trễ thêm của flow manager vẫn khoảng 5-7 giây như trên bộ dữ liệu 4.1, đúng giả định của mô
phỏng.

## Danh sách loại trừ của nhánh hành vi

`whitelist.txt` liệt kê các đích đã xác định là dịch vụ hợp lệ, mỗi dòng một IP hoặc CIDR kèm ghi chú. anomaly.py bỏ mọi luồng
có đầu bên kia vùng nạn nhân thuộc danh sách trước khi gom cửa sổ, ở cả Tầng 1 và Tầng 2; nhánh web không bị ảnh hưởng. Đây là
tinh chỉnh khi vận hành chứ không thuộc mô hình: notebook và mọi số liệu đánh giá ở các mục trên không dùng danh sách này.

Danh sách hiện có năm địa chỉ. Hai địa chỉ đầu thuộc `edge.microsoft.com` (DNS `ax-0002.ax-msedge.net`), dịch vụ của trình duyệt Edge trên hai máy
Windows sinh lưu lượng nền. Edge gọi dịch vụ này qua cả cổng 443 và 80 và nhiều kết nối không hoàn tất bắt tay, nên cửa sổ 2 phút
có hai cổng, nhiều kết nối dở và nhịp đều, giống một lượt dò nhỏ. Mẫu này chiếm 154/226 cảnh báo nhầm Tầng 1 chiều ra trên tập
kiểm định và 174/248 trên tập kiểm thử. Loại hai địa chỉ này thì cảnh báo nhầm của Tầng 1 chiều ra còn 0,23/giờ (kiểm định) và
0,15/giờ (kiểm thử); Tầng 2 gần như không đổi (hai địa chỉ có 0 cảnh báo trên tập kiểm định, 1 trên tập kiểm thử); recall không
đổi vì không lượt tấn công nào dùng hai địa chỉ này. Phát lại 2,5 ngày eve.json của lab (18-20/10/2026) bằng `--detect`: số cảnh
báo Tầng 1 sau khi gom giảm từ 59 xuống 28, và cả 31 cảnh báo bị loại đều là cảnh báo tới hai địa chỉ này.

Ba địa chỉ còn lại cũng là đích của hai máy Windows sinh lưu lượng nền, tên lấy theo SNI và DNS trong eve.json của lab
(18-20/10/2026): `50.19.149.4` và `23.21.189.113` là `autodesk.com` (máy 192.168.10.201), `137.59.44.88` là
`sg1.mobifone.vn.prod.hosts.ooklaserver.net`, máy chủ Speedtest của Ookla đặt tại MobiFone (máy 192.168.10.202). Số cảnh
báo nhầm loại được nhờ ba địa chỉ này chưa đo.

Mỗi mục là một vùng mù của nhánh hành vi, nên chỉ thêm khi đã tra rõ tên TLS/DNS của đích và ghi lý do. Địa chỉ của dịch vụ đám
mây có thể đổi: khi thẻ cảnh báo của một đích quen quay lại, tra lại tên rồi cập nhật tệp và khởi động lại dịch vụ.

## Cần kiểm chứng ở môi trường thật

- Bộ luật đã chạy trên Wazuh 4.12.0 (manager và agent). Khi đổi phiên bản, xác nhận bằng
  `/var/ossec/bin/wazuh-control info | grep VERSION` rồi chạy lại `wazuh-logtest` với các dòng mẫu ở trên.
- Sau khi thêm `<group>suricata</group>` vào `custom-telegram`, kênh này chỉ còn nhận cảnh báo nhóm
  Suricata; nếu trước đây muốn nó gửi cả cảnh báo khác (vuln/SCA...) thì cân nhắc lại filter.
- Quyền đọc `/var/log/suricata-anomaly/` nếu host bật SELinux/AppArmor.
- Chuỗi tấn công lặp ngày 12/11/2026 đã xác nhận mỗi lần 100312 kích hoạt có một thẻ CRITICAL, suricata-drop chặn nguồn
  trên IPS rồi tự gỡ khi hết hạn. Ngày 16/11/2026, brute-force SSH và làm ngập từ vùng tấn công kích hoạt 100309 và chặn
  nguồn; nhánh signature ghi nhận lần chặn qua rule 100205 (Traffic BLOCKED). Khi đổi hạ tầng, chạy lại phép thử này và đối chiếu
  `sudo cat /var/ossec/logs/active-responses.log` trên agent IPS.
