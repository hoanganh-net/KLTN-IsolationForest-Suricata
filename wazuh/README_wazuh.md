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
| 100300 | `module` = `anomaly_(if_rt\|web\|web_body)` | 3 | Rule gốc nhận diện |
| 100302 | `module` = `anomaly_web` | 10 | Giá trị tham số bất thường (tham số truy vấn hoặc trường ngắn của thân POST) |
| 100303 | `module` = `anomaly_web_body` | 10 | Văn bản tự do của thân POST bất thường |
| 100307 | `module` = `anomaly_if_rt`, không ignore | 10 | Cảnh báo của Behavior-IF (cả hai chiều), gửi Telegram |
| 100309 | 100307 + `behavior` = `brute` hoặc `flood` (đặt trước 100308 trong tệp) | 12 | Behavior-IF gán nhãn dò đăng nhập hoặc làm ngập: gửi Telegram và **kích hoạt Active Response** chặn nguồn ngay |
| 100308 | 100307 + `severity` = `high` | 12 | Cảnh báo Behavior-IF điểm cao, gửi Telegram |
| 100304 | 100300 + `module` = `anomaly_(web\|web_body)` + `severity` = `high` | 12 | Một sự kiện điểm cao của nhánh web |
| 100305 | 100304, báo lần đầu (ignore 300 giây) | 12 | Gửi Telegram |
| 100306 | 100302/100303, báo cảnh báo web (ignore 300 giây) | 10 | Gửi Telegram |
| 100311 | ≥5 cảnh báo cùng `srcip` trong 5 phút | 13 | Tái diễn (tần suất) |
| 100312 | ≥10 cảnh báo cùng `srcip` trong 10 phút, không có ignore | **15** | **Kích hoạt Active Response** và gửi thẻ CRITICAL lên Telegram (mỗi lần kích hoạt một thẻ) |
| 100320 | Con của rule Suricata 86601, `alert.signature` = `KLTN POST body capture` | 0 | Ẩn cảnh báo của rule thu thân POST |

Logic: điểm cao (severity) đẩy mức lên 12; tái diễn cùng nguồn (tần suất) lên 13; tái diễn dai dẳng
lên 15. Nhóm `anomaly_event` chỉ gắn cho rule phát hiện (100302–100304, 100307–100309) nên hai rule leo thang
không tự đếm lại chính mình. Tương quan theo `srcip` qua `<same_source_ip />`. Rule 100304 là con trực tiếp của 100300
chứ không của 100302, 100303: trên Wazuh 4.12, rule có nhiều rule cha nằm ở nhiều vị trí trên cây rule và mỗi vị trí
ghi cảnh báo thêm một lần vào danh sách đếm của 100311/100312. Khi 100304 còn là con của ba rule phát hiện, mỗi cảnh báo
điểm cao bị đếm ba lần (lượt chạy ngày 12/11: 100312 kích hoạt 8 lần trên 32 cảnh báo `anomaly_event`). Mức 12 cao hơn 10 nên
Wazuh xét 100304 trước 100302, 100303. Mô phỏng thuật toán đếm của Wazuh (`Search_LastGroups`) trên danh sách cảnh báo của hai lượt chạy ngày 12/11
khớp mọi lần kích hoạt 100311 và 100312: lượt trước khi sửa khi đếm 100304 ba lần, lượt sau khi sửa khi đếm một lần.

Behavior-IF (module `anomaly_if_rt`) đi nhánh riêng 100307 → 100309 hoặc 100308 và báo thẳng ra Telegram, không có
`ignore`. anomaly.py đã gom cảnh báo hành vi theo sự cố của cặp máy trước khi ghi: chỉ ghi khi mở sự cố mới, khi mức độ
tăng từ medium lên high hoặc khi đặc trưng lệch nhất đổi sang đặc trưng chưa gặp trong sự cố. Còn `ignore` của Wazuh tính
cho cả rule chứ không theo nguồn, nên nếu đặt sẽ nuốt cảnh báo của nguồn khác trong cùng 300 giây. Cũng vì lý do đó
100304 chỉ nhận hai module web: cảnh báo Behavior-IF điểm cao mà rơi vào 100304 → 100305 sẽ bị `ignore` của 100305 chặn.
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

## Cảnh báo hành vi: chấm khi cửa sổ còn mở và gom theo sự cố

Ở chế độ `--live`, Behavior-IF gộp luồng của từng cặp máy theo cửa sổ 30 giây, bước 15 giây, dùng chung cho hai chiều.
Sau mỗi lượt đọc `eve.json` (mặc định 10 giây), engine chấm lại các cửa sổ vừa có thêm luồng
và ghi cảnh báo ngay ở lần đầu điểm vượt ngưỡng, không chờ cửa sổ đóng. Mỗi lần chấm chỉ dùng những luồng đã có bản ghi flow,
đúng như khi huấn luyện và chọn ngưỡng. Một cửa sổ được chấm lần cuối khi đồng hồ của engine qua thời điểm cuối cửa sổ 75 giây
(`delay_s` trong joblib), khoảng chờ cho các bản ghi flow ghi trễ. Đồng hồ của engine là thời điểm kết thúc lớn nhất trong
các bản ghi flow đã đọc, nên phát lại nhật ký cũ cho cùng kết quả như khi chạy trực tiếp.

Trên tập kiểm thử, tính theo giờ thật từ luồng đầu tiên của lượt, trung vị độ trễ là 73 giây với dò quét vùng quản trị,
72 giây với dò đăng nhập SSH và 112 đến 114 giây với tải công cụ, exfiltration (mục 4 của notebook 1), chưa cộng
chu kỳ đọc của engine. Phần lớn độ trễ là thời gian chờ Suricata ghi bản ghi flow (xem mục Rút ngắn độ trễ).

Khi khởi động, engine đọc lại phần cuối của `eve.json` (64 MB, đổi bằng `ANOMALY_WARM_MB`, đặt 0 để tắt) và phát lại tối đa
hai giờ gần nhất mà không ghi cảnh báo, để dựng lại các cửa sổ và sự cố đang mở. Thiếu bước này, sự cố đang mở trước lúc khởi động
bị quên và được báo lại như sự cố mới.

Các lần vượt ngưỡng được gom theo sự cố của cặp (`srcip`, `dstip`) trước khi ghi ra `anomaly_alerts.jsonl`, để một hành vi
kéo dài không sinh cảnh báo ở mọi cửa sổ. Một lần vượt ngưỡng chỉ sinh cảnh báo trong các trường hợp sau (trường
`episode_state`):

| `episode_state` | Khi nào sinh cảnh báo |
|---|---|
| `new` | Lần vượt ngưỡng đầu tiên của cặp, hoặc lần đầu sau khi cặp đã yên lặng quá thời gian gom 15 phút. `ANOMALY_RT_QUIET_MIN` đổi thời gian này cho cả hai chiều, nhưng không nhỏ hơn bước trượt |
| `escalated` | Trong sự cố, mức độ tăng từ `medium` lên `high` |
| `new_behavior` | Trong sự cố, đặc trưng lệch nhiều nhất đổi sang một đặc trưng chưa gặp trong sự cố |

Các lần vượt ngưỡng còn lại chỉ được cộng dồn vào sự cố, không nhắc lại định kỳ. Mỗi cửa sổ chỉ báo một lần: cửa sổ đã vượt
ngưỡng không được chấm tiếp. Cảnh báo hành vi có thêm `window_start` (thời điểm bắt đầu cửa sổ), `episode`
(mã sự cố), `episode_start` và `episode_windows` (số cửa sổ bất thường của sự cố tính tới lúc đó); thẻ Telegram hiện các
trường này trên một dòng riêng.

Ảnh hưởng tới rule: 100311/100312 đếm theo `srcip` trong 5 và 10 phút. Vì cảnh báo hành vi đã được gom, hai rule này chủ yếu
kích hoạt khi một nguồn mở sự cố với nhiều máy đích trong thời gian ngắn, hoặc khi nhiều sự cố cùng tăng mức. Cảnh báo web
không được gom.

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
`sudo systemctl restart anomaly-ids`. Nhật ký khởi động (`journalctl -u anomaly-ids`) phải có hai dòng
`[BEHAVIOR-IF live] chiều ra: cửa sổ 30 giây, ...` và `[BEHAVIOR-IF live] chiều vào: cửa sổ 30 giây, ...` kèm ngưỡng của từng chiều, rồi dòng
`[BEHAVIOR-IF live] khởi động ấm: ...` khi nhật ký đã có luồng; dòng `[BEHAVIOR-IF live] tắt` nghĩa là joblib chưa có khóa `rt`. Muốn ghi số đo hiệu năng (CPU%, RSS, thời
gian chấm) thì thêm `ANOMALY_PERF=1` vào môi trường của dịch vụ: anomaly.py ghi `anomaly_perf.jsonl` cạnh tệp cảnh báo, mặc
định 30 giây một mẫu. Chu kỳ đọc và chấm lại của Behavior-IF lấy theo joblib (10 giây); đặt `ANOMALY_RT_INTERVAL_S=5` để chấm lại
mỗi 5 giây (xem mục Rút ngắn độ trễ). Chu kỳ đọc của engine web là 10 giây, đổi bằng `--interval`. Danh sách loại trừ `whitelist.txt` đặt cạnh anomaly.py (`/opt/ml/whitelist.txt`,
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
     100305, 100306, 100307, 100308, 100309, 100311, 100312; các rule đếm 100302–100304 không lên Telegram);
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
   Cảnh báo hành vi có thêm `t_det_s` (đồng hồ của engine tính từ đầu cửa sổ) và `lat_s`
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
Dán từng dòng JSON mẫu; mong đợi: cảnh báo web `severity` = `high` lên **mức 12** (rule 100304, hoặc 100305 ở lần
báo đầu); cảnh báo web `severity` = `medium` ở **mức 10** (rule 100302/100303, hoặc 100306 ở lần báo đầu); cảnh báo
Behavior-IF (`anomaly_if_rt`) `severity` = `medium` ở **mức 10** (rule 100307) và `high` ở **mức 12** (rule 100308), cả hai
mang nhóm `anomaly_notify` và không được rơi vào 100304/100305; cảnh báo Behavior-IF có `behavior` = `brute` hoặc `flood` ở
**mức 12** (rule 100309) dù `severity` là gì. Bắn lặp cùng một `srcip` để thấy 100311/100312 kích hoạt.

### Alert mẫu
```
{"module": "anomaly_if_rt", "time": "2026-11-19T14:55:46", "ext_ip": "192.168.20.20", "n_conn": 35, "direction": "out", "dport_top": 20, "n_ports": 35, "dports": "3,6,7,10,16,20,22,41,43,57", "zone_other": "mgmt", "frac_out": 0.571, "window_start": "2026-10-10T16:00:00+00:00", "location": "cửa sổ 30'", "score": 0.787965302873554, "behavior": "scan", "episode": "192.168.10.20>192.168.20.20@2026-10-10T16:00:00+00:00", "episode_state": "new", "episode_start": "2026-10-10T16:00:00+00:00", "episode_windows": 1, "t_det_s": 288.0, "lat_s": 3451860.3, "why": "log_n_ports(+50.0), svc_rarity(+19.0), log_peak_cpm(+5.8)", "severity": "high", "srcip": "192.168.10.20", "dstip": "192.168.20.20"}
{"module": "anomaly_if_rt", "time": "2026-11-19T14:55:50", "ext_ip": "172.16.99.20", "n_conn": 1, "direction": "out", "dport_top": 9090, "n_ports": 1, "dports": "9090", "zone_other": "ext", "frac_out": 0.965, "window_start": "2026-10-10T17:00:00+00:00", "location": "cửa sổ 30'", "score": 0.7340098796813868, "episode": "192.168.10.22>172.16.99.20@2026-10-10T16:30:00+00:00", "episode_state": "new_behavior", "episode_start": "2026-10-10T16:30:00+00:00", "episode_windows": 3, "t_det_s": 313.0, "lat_s": 3448274.9, "why": "sqrt_mb_out(+26.8), svc_rarity(+19.0), log_throughput(+5.6)", "severity": "high", "srcip": "192.168.10.22", "dstip": "172.16.99.20"}
{"module": "anomaly_if_rt", "time": "2026-11-19T14:55:56", "ext_ip": "172.16.99.11", "n_conn": 9284, "direction": "in", "dport_top": 80, "n_ports": 1, "dports": "80", "zone_other": "ext", "frac_out": 0.472, "window_start": "2026-09-14T13:13:00+00:00", "location": "cửa sổ 2'", "score": 0.7508873136955565, "behavior": "flood", "episode": "172.16.99.11>192.168.10.20@2026-09-14T13:13:00+00:00", "episode_state": "new", "episode_start": "2026-09-14T13:13:00+00:00", "episode_windows": 1, "t_det_s": 98.8, "lat_s": 5708486.9, "why": "log_peak_cpm(+18.2), sqrt_mb_out(+14.3), log_n_conn(+12.9)", "severity": "high", "srcip": "172.16.99.11", "dstip": "192.168.10.20"}
{"module": "anomaly_web", "time": "2026-10-20T14:31:02", "dest_port": 80, "host": "192.168.10.20", "method": "GET", "url": "/product?id=1", "location": "query:id", "score": 0.742, "why": "n_kw(+50.0), n_squote(+6.0)", "severity": "high", "srcip": "172.16.99.10", "dstip": "192.168.10.20"}
{"module": "anomaly_web_body", "time": "2026-10-20T14:32:20", "dest_port": 80, "host": "192.168.10.20", "method": "POST", "url": "/comment", "location": "body:comment", "score": 0.712, "why": "n_kw(+20.8), r_nonalnum(+5.6), max_run_sym(+4.1)", "severity": "medium", "srcip": "172.16.99.10", "dstip": "192.168.10.20"}
```
Ba dòng đầu là cảnh báo Behavior-IF do engine ghi khi phát lại lưu lượng của tập kiểm thử trong môi trường phân tích (giờ
UTC): dò quét vùng quản trị ngày 10/10 (nhãn `scan`, mức high, vào 100308), exfiltration ngày 10/10 (cảnh báo `new_behavior`
của một sự cố đang mở, vào 100308) và làm ngập từ vùng tấn công ngày 14/09 (nhãn `flood`, vào 100309). Hai dòng cuối là mẫu soạn tay
để thử nhánh web của bộ rule, một dòng `high` và một dòng `medium`; điểm trong hai dòng này không lấy từ mô hình.

## Active Response

Hai rule kích hoạt `suricata-drop` (khai trong `<command>` của ossec.conf) trên **agent IPS**
(`<location>defined-agent</location>` + `agent_id` của Suricata_IPS), mỗi rule một khối `<active-response>`: 100312 (mức 15)
chặn nguồn tái diễn, 100309 (mức 12) chặn ngay nguồn mà Behavior-IF gán nhãn `brute` hoặc `flood`. Vì IPS nằm nội
tuyến, chặn `srcip` tại đó cắt được luồng của nguồn. `timeout` đặt mức chặn tạm thời; hết timeout
Wazuh tự gỡ chặn, cảnh báo đã gửi để người trực xử lý dứt điểm.

`suricata-drop` thêm rule `drop ip <srcip>` (SID dải 98xxxxxx) vào tệp rule tùy chỉnh của Suricata_IPS, kèm
`threshold: type limit, track by_src, count 1, seconds 15`: mọi gói của nguồn vẫn bị chặn, nhưng mỗi nguồn chỉ sinh tối đa
một cảnh báo chặn trong 15 giây, để khi nguồn đang làm ngập thì luồng cảnh báo của nhánh signature không bị ngập theo.

100312 không có `ignore` để khi lần chặn trước hết hạn mà nguồn vẫn tấn công thì Active Response chặn lại được. Mỗi lần kích hoạt cũng gửi một thẻ CRITICAL, nên khi nguồn tấn công kéo dài, thẻ mức 15 ra theo nhịp chặn (lượt chạy chiều 12/11, sau khi sửa 100304: mỗi lần kích hoạt sau đúng 10 cảnh báo được đếm, khoảng 2,5-3 phút một lần với nhịp của script tấn công). Cách giới hạn thẻ bằng một rule con có `ignore="300"` đã thử và bỏ: trên Wazuh 4.12, cảnh báo vẫn mang mã 100312 kèm nhóm của rule con ở mọi lần kích hoạt, nên `ignore` của rule con không giới hạn được số thẻ.

Với cảnh báo hành vi do máy nạn nhân khởi tạo (`direction` = `out`), `srcip` là host nội bộ nghi bị chiếm quyền → chặn tại IPS tương
đương cô lập tạm host đó. Với cảnh báo hành vi do bên ngoài khởi tạo (`direction` = `in`) và cảnh báo web,
`srcip` là nguồn bên ngoài → chặn nguồn.

Cảnh báo hành vi của một cặp máy chỉ đi tới Active Response khi Behavior-IF gán nhãn `brute` hoặc `flood` (rule 100309). Hai nhãn
này chỉ gán cho cửa sổ chiều vào, nên địa chỉ bị chặn luôn là bên khởi tạo ở ngoài, không bao giờ là máy nạn nhân. Dò quét
(`scan`) chỉ được cảnh báo và gán kỹ thuật tương ứng, vì một lần chặn ngắn không ngăn được bước trinh sát tiếp theo.

Các cảnh báo hành vi đơn cặp còn lại không đi tới Active Response, và đây là chủ ý thiết kế. Vì anomaly.py gom theo sự cố, một
lượt tấn công đơn cặp của tập kiểm thử chỉ sinh từ một đến ba cảnh báo (bảng ở mục dưới), dưới ngưỡng tần suất của 100311
(5 trong 5 phút) và 100312 (10 trong 10 phút). Active Response theo tần suất vì vậy chỉ chặn nguồn tái diễn dai dẳng: chuỗi
request web bị gắn cờ (nhánh web không gom), hoặc một nguồn gây bất thường trên nhiều máy đích trong thời gian ngắn (mỗi cặp
là một sự cố riêng). Chặn tự động theo một cảnh báo hành vi đơn lẻ không mang nhãn dễ cô lập nhầm máy hợp lệ: trên tập
kiểm thử, chiều ra vẫn có 0,71 cảnh báo nhầm mỗi giờ.

## Số cảnh báo của một lượt tấn công

Bảng dưới đếm số cảnh báo Behavior-IF của từng lượt và phiên trên tập kiểm thử, theo chính sách gom của anomaly.py
(notebook 1). Mỗi cảnh báo là một thẻ Telegram: mức 10 qua rule 100307, mức 12 qua 100308 khi điểm cao hoặc 100309 khi mang
nhãn `brute`, `flood`. Cảnh báo thứ hai trở đi của một lượt là cảnh báo `escalated`, `new_behavior`, hoặc cảnh báo `new` của một cặp máy khác trong cùng lượt.

| Hành vi | Số lượt | Cảnh báo mỗi lượt: trung vị (ít nhất - nhiều nhất) |
|---|---|---|
| scan_mgmt: dò cổng 1-1024 tới một máy | 109 | 1 (1-1) |
| auth_mgmt: 40 lần đăng nhập SSH lỗi | 118 | 2 (1-3) |
| exfil: exfiltration | 85 | 1 (1-1) |
| download: tải công cụ | 101 | 1 (1-2) |
| scan_in: dò quét từ bên ngoài | 2 | 2 (1-2) |
| flood_in: làm ngập từ bên ngoài | 3 | 3 (2-4) |
| web_in: gửi payload web từ bên ngoài | 11 | 1 (1-2) |

Nhánh signature gửi thẻ riêng qua bot `custom-telegram`. Quét nhiều máy đích cùng lúc nhân số thẻ theo số cặp; từ 5 cảnh báo
cùng nguồn trong 5 phút có thêm thẻ 100311, từ 10 cảnh báo trong 10 phút thì 100312 chặn nguồn. Trạng thái sự cố nằm trong bộ
nhớ của anomaly.py: lượt lặp lại trên cùng cặp trong vòng 15 phút kể từ cửa sổ bất thường
cuối được gộp vào sự cố cũ và không sinh thẻ mới, trừ khi mức độ tăng hoặc đặc trưng lệch nhất đổi. Khởi động lại dịch vụ
không xóa trạng thái này, vì engine dựng lại sự cố từ hai giờ cuối của nhật ký. Khi tập dượt trước buổi trình diễn, dùng cặp
máy khác, chờ hết thời gian gom hoặc đặt `ANOMALY_RT_QUIET_MIN` nhỏ hơn. Trên phần bình thường của tập kiểm thử, nhánh hành
vi sinh 0,71 cảnh báo nhầm mỗi giờ, đều ở chiều ra.

## Rút ngắn độ trễ

Phần lớn độ trễ của Behavior-IF nằm ở cảm biến: Suricata chỉ ghi bản ghi flow khi luồng hết hạn trong bảng flow. Trên bộ dữ liệu
4.1, 91% số luồng là TCP có độ trễ ghi khoảng 61-70 giây, tức timeout mặc định 60 giây của trạng thái `new` (chưa bắt tay xong)
và `closed`, cộng vài giây của flow manager; luồng TCP còn mở chờ 600 giây (`established`), luồng UDP 30 hoặc 300 giây.
Tệp `suricata/flow-timeouts.snippet.yaml` hạ `tcp.new` xuống 10 giây và `tcp.closed` xuống 5 giây trên Suricata_IDS, dùng
cùng `ANOMALY_RT_INTERVAL_S=5`. `tcp.new` không hạ xuống 5 giây vì SYN được gửi lại với khoảng cách tăng gấp đôi: luồng chưa
bắt tay xong kéo dài từ 15 giây có khoảng nghỉ vượt 5 giây và bị tách thành nhiều bản ghi, chiếm 28,7% số luồng chưa bắt tay
xong của lưu lượng nền, làm lệch đặc trưng so với lúc huấn luyện; với 10 giây tỷ lệ này còn 0,03%.

Hai phép đo dưới đây làm với mô hình trước ngày 20/11/2026 (chiều vào cửa sổ 2 phút) và chưa được đo lại với mô hình cửa sổ
30 giây. Khi chạy thật ngày 20/11/2026 với cấu hình timeout này, bốn lượt đã chạy (dò quét từ ngoài, dò đăng nhập SSH, làm ngập,
dò quét vùng quản trị) được báo sau 5 đến 25 giây kể từ luồng đầu tiên của cửa sổ.

Mô phỏng trên bộ dữ liệu 4.1, giữ nguyên mô hình và ngưỡng, dời thời điểm ghi của các luồng thuộc cụm 60 giây và giữ phần trễ
thêm của flow manager như đã đo, cho trung vị độ trễ theo giờ thật (chưa tính chặng Wazuh và Telegram): dò từ vùng tấn công
10 giây, làm ngập 6 giây, tấn công web 41 giây. Tấn công web chậm hơn chủ yếu vì cửa sổ cần tích lũy đủ số lần thử để điểm
vượt ngưỡng. Chiều vào vẫn không có cảnh báo nhầm. Mô phỏng không tái hiện việc tách luồng và giả định flow manager giữ nhịp
như cũ, nên sau khi đổi cấu hình phải đo lại độ trễ (`lat_s` trên thẻ) và cảnh báo nhầm khi chạy thật.

Đo thực trên lab ngày 15/11/2026 (Suricata 7.0.3), cùng lệnh `nmap -sS -sV -Pn` từ vùng tấn công vào máy A, mỗi cấu hình một lượt: thẻ báo
`lat_s` 66 giây với timeout mặc định và chu kỳ 10 giây, 9 giây sau khi đổi sang `tcp.new` 10 giây, `tcp.closed` 5 giây và
chu kỳ 5 giây. Trong 3 phút đầu của đợt chạy sau khi đổi (từ 13:15), Suricata ghi 874 luồng TCP
đã đóng sau trung vị 10,3 giây kể từ lúc kết thúc (90% không quá 14,2 giây) và 35 luồng chưa bắt tay xong sau trung vị 16,8 giây
(90% không quá 19,7 giây): phần trễ thêm của flow manager vẫn khoảng 5-7 giây như trên bộ dữ liệu 4.1, đúng giả định của mô
phỏng.

## Danh sách loại trừ của nhánh hành vi

`whitelist.txt` liệt kê các đích đã xác định là dịch vụ hợp lệ, mỗi dòng một IP hoặc CIDR kèm ghi chú. anomaly.py bỏ mọi luồng
có đầu bên kia vùng nạn nhân thuộc danh sách trước khi gom cửa sổ, ở cả hai chiều; nhánh web không bị ảnh hưởng. Đây là
tinh chỉnh khi vận hành chứ không thuộc mô hình: notebook và mọi số liệu đánh giá ở các mục trên không dùng danh sách này.

Danh sách hiện có năm địa chỉ, lập khi chiều ra còn chấm bằng cửa sổ 2 phút. Hai địa chỉ đầu thuộc `edge.microsoft.com`
(DNS `ax-0002.ax-msedge.net`), dịch vụ của trình duyệt Edge trên hai máy Windows sinh lưu lượng nền. Edge gọi dịch vụ này qua
cả cổng 443 và 80 và nhiều kết nối không hoàn tất bắt tay, nên một cửa sổ trông giống một lượt dò nhỏ. Ba địa chỉ còn
lại cũng là đích của hai máy Windows sinh lưu lượng nền, tên lấy theo SNI và DNS trong eve.json của lab (18-20/10/2026):
`50.19.149.4` và `23.21.189.113` là `autodesk.com` (máy 192.168.10.201), `137.59.44.88` là
`sg1.mobifone.vn.prod.hosts.ooklaserver.net`, máy chủ Speedtest của Ookla đặt tại MobiFone (máy 192.168.10.202).

Với mô hình hiện tại (cửa sổ 30 giây, ngưỡng chiều ra 0,6975), hai địa chỉ của Edge vẫn là nguồn tập trung nhất của các cửa sổ
hợp lệ có điểm cao: khoảng một phần tư số cửa sổ huấn luyện có điểm trên 0,64 là tới hai địa chỉ này. Danh sách vì vậy được
giữ nguyên.

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
