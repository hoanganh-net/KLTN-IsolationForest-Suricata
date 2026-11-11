# -*- coding: utf-8 -*-
# custom-telegram-anomaly.py - Wazuh -> Telegram cho NHÁNH BẤT THƯỜNG (anomaly).
# Cùng quy ước với custom-telegram.py của nhánh signature:
#   Wazuh truyền argv[1]=alert_file, argv[2]=chat_id (đặt ở <api_key>), argv[3]=bot_token (đặt ở <hook_url>).
# Dùng parse_mode=HTML (an toàn hơn Markdown vì tên đặc trưng có dấu '_').
#
# Thẻ cảnh báo: Nguồn/Đích -> z-score diễn giải tiếng Việt -> loại hành vi nghi ngờ (suy từ TỔ HỢP các đặc trưng
# lệch trong chuỗi why, không chỉ đặc trưng đứng đầu) -> chiến thuật/kỹ thuật MITRE ATT&CK -> Mitigations (mã M)
# của kỹ thuật theo ATT&CK -> hành động đã thực thi.
# anomaly.py chỉ phát dữ kiện (module, score, why, frac_out, zone_other, direction, dport_top; với web thêm method, url,
# location); phần suy luận nằm Ở ĐÂY. Giá trị tham số KHÔNG đưa lên thẻ (có thể chứa dữ liệu nhạy cảm): thẻ chỉ nêu
# phương thức, đường dẫn không kèm chuỗi truy vấn và tên tham số; giá trị đầy đủ tra trong eve.json theo thời điểm và nguồn.
# Behavior-IF là một mô hình cho cả hai chiều; trường direction (out: máy nạn nhân khởi tạo, in: bên ngoài khởi tạo) chỉ dùng
# để chọn cách diễn giải và kỹ thuật ATT&CK phù hợp với vị trí bên khởi tạo.
#
# Tên, chiến thuật và Mitigations (mã M) của từng kỹ thuật lấy từ attack_v20_playbook.json, do
# build_attack_playbook.py sinh từ dữ liệu ATT&CK Enterprise 20.0 (STIX) chính thức của MITRE. Tệp này đặt cùng
# thư mục với script; script KHÔNG truy cập Internet để tra ATT&CK khi có cảnh báo.

import sys, os, json, re, html, ipaddress
from datetime import datetime
from urllib.parse import urlsplit

try:
    import requests
except ImportError:
    print("Thieu module 'requests'")
    sys.exit(1)

LOG_FILE = "/var/ossec/logs/integrations.log"
ATTACK_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "attack_v20_playbook.json")

def log(msg):
    try:
        with open(LOG_FILE, "a") as f:
            f.write("{0} custom-telegram-anomaly: {1}\n".format(
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg))
    except Exception:
        pass

def load_attack():
    try:
        with open(ATTACK_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception as ex:
        log("Khong doc duoc {0}: {1} -> the chi ghi ma ky thuat, khong co Mitigations".format(ATTACK_FILE, ex))
        return None

ATTACK = load_attack()

# --- Tên mô-đun thân thiện ---
MODULE_NAME = {
    "anomaly_if":       "Hành vi mạng (Behavior-IF)",
    "anomaly_web":      "Giá trị tham số (Web-Query)",
    "anomaly_web_body": "Văn bản tự do POST (Web-Body)",
}

# Trạng thái sự cố do anomaly.py --live ghi cho cảnh báo hành vi (gom các cửa sổ bất thường của cùng một cặp nguồn, đích).
EPISODE_VI = {
    "new":          "mới",
    "escalated":    "tăng mức độ",
    "new_behavior": "hành vi đổi dạng",
    "ongoing":      "vẫn tiếp diễn",
}

def _ts(s):
    """'2026-10-11T00:15:00+07:00' -> '2026-10-11 00:15' (giờ theo múi giờ của máy chạy anomaly.py)."""
    return str(s)[:16].replace("T", " ")

def episode_line(data):
    """Dòng thời điểm cửa sổ và sự cố cho cảnh báo hành vi; rỗng nếu cảnh báo không có các trường này (bản anomaly.py cũ)."""
    ws, st = data.get("window_start"), str(data.get("episode_state") or "")
    parts = []
    if ws:
        parts.append("🕒 <b>Cửa sổ</b> từ {0}".format(e(_ts(ws))))
    if st:
        s = "🔁 <b>Sự cố</b>: {0}".format(e(EPISODE_VI.get(st, st)))
        if st != "new" and data.get("episode_start"):
            s += ", bắt đầu {0}".format(e(_ts(data.get("episode_start"))))
        if data.get("episode_windows"):
            s += ", {0} bucket 30' bất thường".format(e(data.get("episode_windows")))
        parts.append(s)
    return " | ".join(parts)

# --- Từ điển 1: diễn giải z-score sang tiếng Việt (11 đặc trưng hành vi + 13 đặc trưng từ vựng web) ---
ZSCORE_VI = {
    # Behavior-IF (flow)
    "log_n_conn":      "Số kết nối trong cửa sổ tăng bất thường.",
    "sqrt_mb_out":     "Khối lượng byte đẩy ra ngoài (upload) lớn bất thường.",
    "log_bytes_in":    "Khối lượng byte nhận vào bất thường.",
    "frac_out":        "Tỉ lệ byte đi ra chiếm ưu thế (thiên về gửi ra ngoài).",
    "log_throughput":  "Thông lượng (byte/giây) cao bất thường.",
    "log_peak_cpm":    "Kết nối dồn dập nhất trong một phút cao bất thường.",
    "periodicity":     "Giao tiếp lặp lại theo nhịp rất đều (dấu hiệu beacon).",
    "uniformity":      "Kích thước các kết nối gần như giống hệt nhau.",
    "log_n_ports":     "Số cổng đích khác nhau lớn bất thường (dấu hiệu quét).",
    "frac_incomplete": "Tỉ lệ kết nối dang dở (SYN không hoàn tất) cao bất thường.",
    "svc_rarity":      "Truy cập dịch vụ/cổng hiếm gặp so với lưu lượng nền.",
    # Web-App IF (giá trị tham số / văn bản tự do)
    "log_len":         "Độ dài giá trị tham số lớn bất thường.",
    "r_nonalnum":      "Tỉ lệ ký tự không phải chữ-số cao bất thường.",
    "r_digit":         "Tỉ lệ chữ số cao bất thường.",
    "r_upper":         "Tỉ lệ chữ hoa cao bất thường.",
    "entropy":         "Độ hỗn loạn ký tự (entropy) bất thường, nghi mã hóa hoặc làm rối.",
    "n_squote":        "Nhiều dấu nháy đơn ('), dấu hiệu tiêm SQL.",
    "n_dquote":        "Nhiều dấu nháy kép.",
    "n_angle":         "Nhiều dấu ngoặc nhọn (< >), dấu hiệu chèn thẻ/XSS.",
    "n_paren":         "Nhiều dấu ngoặc đơn ( ), dấu hiệu hàm/biểu thức.",
    "n_punct_inj":     "Nhiều ký tự tiêm đặc trưng (; | & ` $ ...).",
    "n_kw":            "Khớp nhiều từ khóa SQL/script độc hại.",
    "n_pct":           "Nhiều chuỗi mã hóa %HH (URL-encoding).",
    "max_run_sym":     "Chuỗi ký tự đặc biệt liền nhau dài bất thường.",
}

# Khi bên khởi tạo là nguồn bên ngoài (direction = in): "byte đi ra" là byte nguồn gửi vào máy chủ, "byte nhận vào" là byte
# máy chủ trả về cho nguồn. Các đặc trưng còn lại giữ nghĩa nhưng mô tả theo góc nhìn nguồn bên ngoài.
ZSCORE_VI_IN = {
    "log_n_conn":      "Số kết nối từ nguồn bên ngoài trong cửa sổ tăng bất thường.",
    "sqrt_mb_out":     "Khối lượng byte nguồn bên ngoài gửi vào máy chủ lớn bất thường.",
    "log_bytes_in":    "Khối lượng byte máy chủ trả về cho nguồn bên ngoài bất thường.",
    "frac_out":        "Tỉ lệ byte do nguồn bên ngoài gửi vào chiếm ưu thế.",
    "log_throughput":  "Thông lượng (byte/giây) của các kết nối cao bất thường.",
    "log_peak_cpm":    "Số kết nối dồn dập nhất trong một phút cao bất thường.",
    "periodicity":     "Kết nối lặp lại theo nhịp rất đều (dấu hiệu công cụ tự động).",
    "uniformity":      "Kích thước các kết nối gần như giống hệt nhau (dấu hiệu công cụ tự động).",
    "log_n_ports":     "Nguồn bên ngoài chạm tới nhiều cổng đích khác nhau (dấu hiệu dò quét).",
    "frac_incomplete": "Nhiều kết nối từ nguồn bên ngoài không hoàn tất bắt tay.",
    "svc_rarity":      "Nguồn bên ngoài truy cập dịch vụ không có trong lưu lượng nền chiều vào.",
}

# --- Suy luận loại hành vi từ TỔ HỢP đặc trưng lệch (dấu vết theo Bảng 2.1 và Bảng 2.3 của báo cáo) ---
SIG = 3.0                                   # chỉ xét độ lệch dương đủ lớn (z >= 3) trong chuỗi why
MGMT_NETS = [ipaddress.ip_network("192.168.20.0/24")]   # dự phòng khi cảnh báo không có trường zone_other

# Behavior-IF: mỗi đặc trưng đặc thù "bầu" cho một giả thuyết; giả thuyết có độ lệch lớn nhất được chọn.
# svc_rarity, log_n_conn, log_throughput chỉ là NGỮ CẢNH, không tự quyết định loại hành vi.
BEH_VOTE = {"periodicity": "c2", "uniformity": "c2", "sqrt_mb_out": "exfil", "frac_out": "exfil",
            "log_bytes_in": "ingress", "log_n_ports": "scan", "frac_incomplete": "scan", "log_peak_cpm": "brute"}
BEH = {   # khóa: (nhãn nghi ngờ, mã kỹ thuật ATT&CK hoặc None)
    "c2":       ("Kênh điều khiển theo nhịp (beacon)", "T1071"),
    "exfil":    ("Rút dữ liệu ra ngoài", "T1048"),
    "ingress":  ("Tải công cụ hoặc mã độc về máy", "T1105"),
    "scan":     ("Dò quét dịch vụ", "T1046"),
    "brute":    ("Dò đăng nhập", "T1110"),
    "auth":     ("Dò đăng nhập vào vùng quản trị", "T1110"),
    "dos":      ("Làm ngập dịch vụ từ máy bị chiếm quyền", "T1498"),
    "internal": ("Truyền dữ liệu bất thường giữa vùng nạn nhân và vùng quản trị", None),
    "unknown":  ("Kết nối bất thường, chưa đủ dấu hiệu để xác định loại hành vi", None),
}

# Bên khởi tạo ở ngoài (direction = in): cùng cách bầu theo đặc trưng lệch nhiều nhất, với các giả thuyết của phía bên ngoài.
# Tần suất kết nối cao tới một dịch vụ xác thực được coi là dò đăng nhập; tới dịch vụ khác thì chưa phân biệt được
# dò đăng nhập, dò nội dung web hay làm ngập chỉ từ bản ghi luồng, nên thẻ nêu các kỹ thuật ứng viên.
AUTH_PORTS = {21, 22, 23, 110, 143, 389, 445, 636, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 5985, 5986}
IN_VOTE = {"log_n_ports": "scan", "frac_incomplete": "scan", "log_peak_cpm": "rate", "log_n_conn": "rate"}
IN = {   # khóa: (nhãn nghi ngờ, mã kỹ thuật / danh sách kỹ thuật ứng viên / None)
    "scan":    ("Dò quét từ bên ngoài", "T1595"),
    "brute":   ("Dò đăng nhập từ bên ngoài", "T1110"),
    "dos":     ("Làm ngập kết nối, phần lớn kết nối không hoàn tất bắt tay", "T1499"),
    "rate":    ("Truy cập dồn dập tới dịch vụ (dò đăng nhập, dò nội dung web hoặc làm ngập)", ["T1110", "T1499"]),
    "newsvc":  ("Truy cập từ bên ngoài tới dịch vụ không có trong lưu lượng nền", None),
    "unknown": ("Hành vi chiều vào bất thường, chưa đủ dấu hiệu để xác định loại hành vi", None),
}

# Web-App IF: mọi cảnh báo ứng với khai thác ứng dụng web (T1190); đặc trưng trội quyết định nhãn chi tiết.
WEB_VOTE = {"n_angle": "xss", "n_squote": "sqli", "n_punct_inj": "cmdi", "n_kw": "inj", "n_paren": "inj"}
WEB = {   # khóa: nhãn nghi ngờ
    "sqli": "Tiêm mã SQL (SQLi)",
    "xss":  "Tiêm mã kịch bản (XSS)",
    "cmdi": "Tiêm lệnh hệ thống",
    "inj":  "Tiêm mã (SQL, lệnh hoặc lùi thư mục)",
    "web":  "Giá trị tham số bất thường",
}
WEB_TECH = "T1190"

# Thẻ hiện tối đa MAX_MIT mitigation cho mỗi kỹ thuật để gọn trên điện thoại; danh sách đầy đủ xem ở liên kết.
# Kỹ thuật có nhiều hơn MAX_MIT mục thì hiện các mục dưới đây, chọn theo tiêu chí: chặn trực tiếp kỹ thuật đã phát hiện
# hoặc loại bỏ điều kiện để nó thành công, thay vì chỉ hạn chế hậu quả sau đó. Mã và tên vẫn lấy từ playbook ATT&CK.
MAX_MIT = 3
MIT_PICK = {
    "T1190": ["M1050", "M1051", "M1016"],   # WAF, cập nhật phần mềm, quét lỗ hổng
    "T1048": ["M1037", "M1031", "M1057"],   # lọc lưu lượng ra, IPS, chống rò rỉ dữ liệu
    "T1110": ["M1036", "M1032", "M1027"],   # khóa tài khoản sau nhiều lần sai, MFA, chính sách mật khẩu
}

_WHY_RE = re.compile(r"([A-Za-z_]+)\(([+-]?\d+(?:\.\d+)?)\)")

def parse_reasons(why):
    """Tách 'n_squote(+50.0), n_kw(+41.0)' -> [('n_squote','+50.0'), ...] theo thứ tự |z| giảm dần."""
    return _WHY_RE.findall(why or "")

def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None

def zone_of(data):
    """Vùng của đầu bên kia với Behavior-IF: ưu tiên trường zone_other do anomaly.py ghi; dự phòng theo dstip."""
    z = str(data.get("zone_other") or "").lower()
    if z in ("ext", "mgmt"):
        return z
    try:
        a = ipaddress.ip_address(data.get("dstip") or data.get("dest_ip") or "")
        return "mgmt" if any(a in n for n in MGMT_NETS) else "ext"
    except ValueError:
        return "ext"

def suspect_in(S, raw, notes, data):
    """Nhánh diễn giải khi bên khởi tạo ở ngoài vùng nạn nhân (direction = in)."""
    if "log_peak_cpm" in S and "frac_incomplete" in S:              # nhiều kết nối/phút, phần lớn dang dở
        key, basis = "dos", ["log_peak_cpm", "frac_incomplete"]
    else:
        key, basis, best = "unknown", [], -1.0
        for f, v in S.items():
            h = IN_VOTE.get(f)
            if h and v > best:
                key, basis, best = h, [f], v
    port = int(_num(data.get("dport_top")) or 0)
    if key == "rate" and port in AUTH_PORTS:                        # dồn dập tới dịch vụ xác thực
        key = "brute"
    if key in ("rate", "brute") and port:
        notes.append("cổng đích chính {0}".format(port))
    if key == "unknown" and "svc_rarity" in S:                      # chỉ lệch ở độ hiếm dịch vụ
        key, basis = "newsvc", ["svc_rarity"]
    label, tech = IN[key]
    return key, label, tech, [(f, raw[f]) for f in basis], "svc_rarity" in S and key != "newsvc", notes

def suspect(module, reasons, data):
    """Trả (khóa, nhãn, mã kỹ thuật hoặc None, đặc trưng làm căn cứ, có ngữ cảnh dịch vụ hiếm, ghi chú)."""
    S, raw, notes = {}, {}, []
    for f, z in reasons:
        v = _num(z)
        if v is not None and v >= SIG and f not in S:
            S[f], raw[f] = v, z
    if module == "anomaly_if" and str(data.get("direction") or "") == "in":
        return suspect_in(S, raw, notes, data)
    if module == "anomaly_if":
        if "log_peak_cpm" in S and "frac_incomplete" in S:          # nhiều kết nối/phút, phần lớn dang dở
            key, basis = "dos", ["log_peak_cpm", "frac_incomplete"]
        else:
            key, basis, best = "unknown", [], -1.0
            for f, v in S.items():
                h = BEH_VOTE.get(f)
                if h and v > best:
                    key, basis, best = h, [f], v
        fo = _num(data.get("frac_out"))
        if key == "exfil" and fo is not None and fo < 0.5:          # byte nhận về nhiều hơn byte gửi đi
            key = "ingress"
            notes.append("tỉ lệ byte đi ra {0:.2f}".format(fo))
        if zone_of(data) == "mgmt":                                 # đích ở vùng quản trị
            if key in ("c2", "brute"):
                key = "auth"
                notes.append("đích thuộc vùng quản trị")
            elif key in ("exfil", "ingress"):
                key = "internal"
                notes.append("đích thuộc vùng quản trị")
        label, tech = BEH[key]
        return key, label, tech, [(f, raw[f]) for f in basis], "svc_rarity" in S, notes
    key, basis, best = "web", [], -1.0
    for f, v in S.items():
        h = WEB_VOTE.get(f)
        if h and v > best:
            key, basis, best = h, [f], v
    label = WEB[key]
    return key, label, WEB_TECH, [(f, raw[f]) for f in basis], False, notes

def pick_mits(tech, mits):
    """Trả (các mitigation hiện trên thẻ, số mục còn lại). Mã trong MIT_PICK không có trong playbook thì bị bỏ qua."""
    if len(mits) <= MAX_MIT:
        return mits, 0
    by_id = {m["id"]: m for m in mits}
    shown = [by_id[i] for i in MIT_PICK.get(tech, []) if i in by_id][:MAX_MIT] or mits[:MAX_MIT]
    return shown, len(mits) - len(shown)

def mit_lines(tech, mits):
    shown, more = pick_mits(tech, mits)
    L = ["• {0} {1}".format(e(m["id"]), e(m["name"])) for m in shown]
    if more:
        L.append("• <i>và {0} mục khác, xem liên kết</i>".format(more))
    return L

def attack_lines(tech):
    """Trả (dòng kỹ thuật, các dòng Mitigations, mỗi mã M một dòng, + liên kết) theo dữ liệu ATT&CK v20 đã đóng gói.
    tech là một mã kỹ thuật, None, hoặc danh sách mã kỹ thuật ứng viên khi bản ghi luồng chưa đủ để chọn một."""
    if tech is None:
        return "🧭 <b>ATT&amp;CK</b>: chưa đủ dấu hiệu để gán kỹ thuật, cần người vận hành xác minh", []
    if isinstance(tech, (list, tuple)):
        T = (ATTACK or {}).get("techniques", {})
        parts, mits, links = [], [], []
        for t in tech:
            x = T.get(t)
            if not x:
                parts.append(e(t)); continue
            tac = ", ".join("{0} {1}".format(a["id"], a["name"]) for a in x.get("tactics", []))
            parts.append("{0} / {1} {2}".format(e(tac), e(t), e(x["name"])))
            if x.get("mitigations"):
                mits.append("<i>{0}</i>:".format(e(t)))
                mits.extend(mit_lines(t, x["mitigations"]))
            links.append(e(x["url"]))
        ver = (ATTACK or {}).get("attack_version", "")
        head = "🧭 <b>ATT&amp;CK v{0} (ứng viên)</b>: ".format(e(ver)) + " | ".join(parts)
        rest = []
        if mits:
            rest.append("🛡 <b>Mitigations (ATT&amp;CK)</b>:")
            rest.extend(mits)
        if links:
            rest.append("🔗 " + " ".join(links))
        return head, rest
    t = (ATTACK or {}).get("techniques", {}).get(tech)
    if not t:
        return "🧭 <b>ATT&amp;CK</b>: {0}".format(e(tech)), []
    ver = ATTACK.get("attack_version", "")
    tac = ", ".join("{0} {1}".format(x["id"], x["name"]) for x in t.get("tactics", []))
    head = "🧭 <b>ATT&amp;CK v{0}</b>: {1} / {2} {3}".format(e(ver), e(tac), e(tech), e(t["name"]))
    rest = []
    mit = t.get("mitigations", [])
    if mit:
        rest.append("🛡 <b>Mitigations (ATT&amp;CK)</b>:")
        rest.extend(mit_lines(tech, mit))
    rest.append("🔗 {0}".format(e(t["url"])))
    return head, rest

def e(s):
    return html.escape(str(s))

def web_location(data):
    """Dòng vị trí cho cảnh báo web: phương thức, đường dẫn (bỏ chuỗi truy vấn vì chứa giá trị) và tên tham số
    hoặc trường bị gắn cờ. location do anomaly.py ghi dạng 'query:<tên>' hoặc 'body:<tên>' (JSON lồng: 'body:a.b')."""
    method = data.get("method") or ""
    try:
        url = urlsplit(str(data.get("url") or "")).path
    except ValueError:
        url = ""
    if len(url) > 120:
        url = url[:117] + "..."
    loc = str(data.get("location") or "")
    part, _, name = loc.partition(":")
    where = {"query": "tham số truy vấn", "body": "trường thân POST"}.get(part, "giá trị")
    s = "📍 <b>Vị trí</b>: {0} {1}".format(e(method), e(url)).rstrip()
    if name:
        s += " | {0} <code>{1}</code>".format(where, e(name))
    return s

def build_message(rule, data):
    level = int(rule.get("level", 0) or 0)
    rid   = rule.get("id", "N/A")
    module   = data.get("module", "anomaly")
    srcip    = data.get("srcip") or data.get("src_ip") or "N/A"
    dstip    = data.get("dstip") or data.get("dest_ip") or ""
    host     = data.get("host", "")
    score    = data.get("score", "")
    severity = data.get("severity", "")
    why      = data.get("why", "")

    critical = level >= 15
    head = "🔴 <b>ANOMALY - CRITICAL</b>" if critical else ("🟠 <b>ANOMALY - HIGH</b>" if level >= 12 else "🟡 <b>ANOMALY</b>")
    L = [head]
    L.append("📝 <b>Rule</b> {0} (level {1}) | {2}".format(e(rid), level, e(MODULE_NAME.get(module, module))))
    inbound = module == "anomaly_if" and str(data.get("direction") or "") == "in"
    extra = ""
    if inbound:
        port = int(_num(data.get("dport_top")) or 0)
        extra = (" | <b>Cổng</b> {0}".format(port) if port else "") + " (bên ngoài khởi tạo)"
    L.append("🌐 <b>Nguồn</b> {0}".format(e(srcip)) + (" ➔ <b>Đích</b> {0}".format(e(dstip)) if dstip else "") + extra
             + (" (Host: {0})".format(e(host)) if host else ""))
    if module in ("anomaly_web", "anomaly_web_body"):
        L.append(web_location(data))
    if score != "":
        try: s = "{0:.3f}".format(float(score))
        except Exception: s = e(score)
        L.append("📊 <b>Điểm</b> {0}".format(s) + (" | <b>Mức độ</b> {0}".format(e(severity)) if severity else ""))
    if module == "anomaly_if":
        ep = episode_line(data)
        if ep: L.append(ep)

    reasons = parse_reasons(why)
    if reasons:
        L.append("🔍 <b>Z-score (nguyên nhân)</b>:")
        for feat, z in reasons:
            vi = (ZSCORE_VI_IN if inbound else ZSCORE_VI).get(feat, "") or ZSCORE_VI.get(feat, "")
            L.append("• <code>{0}</code> ({1}){2}".format(e(feat), e(z), ": " + e(vi) if vi else ""))

    key, label, tech, basis, rare, notes = suspect(module, reasons, data)
    txt = e(label) + (", qua dịch vụ hoặc cổng hiếm gặp so với nền" if rare and key != "unknown" else "")
    cand = ["<code>{0}</code> {1}".format(e(f), e(z)) for f, z in basis] + [e(n) for n in notes]
    if cand:
        txt += " (căn cứ: " + ", ".join(cand) + ")"
    L.append("🎯 <b>Nghi ngờ</b>: " + txt)
    head, rest = attack_lines(tech)
    L.append(head)
    L.extend(rest)

    if critical and inbound:
        L.append("⛔ <b>Action</b>: đã tạm chặn địa chỉ nguồn bên ngoài {0} qua Active Response (suricata-drop) trên IPS, tự gỡ sau 15 giây. Cần xác minh và xử lý dứt điểm.".format(e(srcip)))
    elif critical:
        L.append("⛔ <b>Action</b>: đã tạm cô lập/chặn nguồn {0} qua Active Response (suricata-drop) trên IPS, tự gỡ sau 15 giây. Cần xử lý dứt điểm.".format(e(srcip)))
    return "\n".join(L)

def main():
    log("===== custom-telegram-anomaly duoc goi =====")
    if len(sys.argv) < 4:
        log("Thieu tham so: {0}".format(sys.argv)); sys.exit(1)
    alert_file, chat_id, bot_token = sys.argv[1], sys.argv[2], sys.argv[3]
    try:
        with open(alert_file, "r") as f:
            alert = json.load(f)
    except Exception as ex:
        log("LOI doc/parse alert: {0}".format(ex)); sys.exit(1)

    text = build_message(alert.get("rule", {}) or {}, alert.get("data", {}) or {})
    url = "https://api.telegram.org/bot{0}/sendMessage".format(bot_token)
    payload = {"chat_id": chat_id, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True}
    log("POST -> Telegram (chat_id={0})".format(chat_id))
    try:
        r = requests.post(url, json=payload, timeout=15)
        log("HTTP {0}".format(r.status_code) + ("" if r.status_code == 200 else " : " + r.text[:300]))
    except Exception as ex:
        log("LOI ket noi Telegram: {0}".format(ex)); sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()
