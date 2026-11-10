# -*- coding: utf-8 -*-
"""
anomaly.py: RUNTIME phát hiện bất thường (bản tối giản).

Nạp các mô hình Isolation Forest đã huấn luyện (xuất từ các notebook, định dạng sklearn
cho tốc độ) và chấm điểm trực tiếp trên nhật ký eve.json của Suricata:
    net_if_model.joblib        Behavior-IF  (bản ghi flow; một mô-đun cho cả hai chiều. Tham chiếu chính cho kết nối do
                               máy nạn nhân khởi tạo; khóa "inbound" là tham chiếu cho kết nối từ bên ngoài vào vùng
                               nạn nhân. Tham chiếu được chọn theo bên khởi tạo; cảnh báo, rule và thẻ dùng chung)
    web_app_if_model.joblib    Web-App IF   (MỘT file gồm "query"=Web-Query và "body"=Web-Body; từ v2.0 nhánh query có
                               kiểm tra miền "guard": giá trị tham số lệch trên đặc trưng hằng lúc huấn luyện nhận điểm 1,
                               cảnh báo ghi thêm trường out_of_range)

Dùng:
    python3 anomaly.py --detect eve.json [--last 30]
    python3 anomaly.py --live   eve.json [--interval N]

File này TỰ CHỨA phần trích đặc trưng phục vụ chấm điểm runtime; các notebook huấn luyện định
nghĩa đặc trưng NGAY TRONG notebook. Bản đặc trưng ở đây giữ KHỚP với notebook để số liệu không lệch.
Thuật toán Isolation Forest tự cài nằm ở isolationforest.py (dùng trong notebook để hiểu + kiểm chứng);
file runtime này dùng model sklearn trong joblib cho nhanh.
"""

import sys, os, json, math, time, re, gzip, ipaddress, collections, types, threading, base64, html
from datetime import datetime
from urllib.parse import unquote_plus, urlsplit, parse_qsl
import numpy as np

# Nơi ghi cảnh báo để Wazuh agent đọc (localfile kiểu json). Mặc định trỏ sẵn path khớp ossec.conf
# để chỉ cần chạy `python3 anomaly.py --live`; đặt biến môi trường ANOMALY_LOG=... để ghi đè khi cần.
ALERT_LOG = os.environ.get("ANOMALY_LOG", "/var/log/suricata-anomaly/anomaly_alerts.jsonl")
_alert_dir = os.path.dirname(ALERT_LOG)
if _alert_dir:
    try: os.makedirs(_alert_dir, exist_ok=True)         # tạo thư mục log nếu có quyền; không có thì để _emit báo lỗi rõ
    except Exception: pass

# Lọc hướng cho engine WEB: chỉ chấm http đi VÀO các web server được bảo vệ, để bỏ qua lưu lượng
# duyệt web ĐI RA (telemetry trình duyệt, CDN...) vốn hay có query token dài -> báo nhầm. Đặt biến
# WEB_TARGETS = danh sách IP/CIDR đích, vd: WEB_TARGETS=192.168.10.20,192.168.10.0/24
# Mặc định là vùng nạn nhân 192.168.10.0/24; đặt WEB_TARGETS= (rỗng) để chấm mọi http.
_WEB_TARGETS = []
for _t in os.environ.get("WEB_TARGETS", "192.168.10.0/24").replace(";", ",").split(","):
    _t = _t.strip()
    if _t:
        try: _WEB_TARGETS.append(ipaddress.ip_network(_t, strict=False))
        except Exception: pass
def _in_web_targets(ip):
    if not _WEB_TARGETS: return True
    try: return any(ipaddress.ip_address(ip) in n for n in _WEB_TARGETS)
    except Exception: return False


# File runtime này TỰ CHỨA (chạy trên máy Suricata, không phụ thuộc folder báo cáo).
# zscore/explain lặp lại cùng logic với hàm explain trong isolationforest.py (bên notebook); cố ý lặp lại để runtime độc lập.
def zscore(x, center, scale):
    """Chuẩn hóa: (x - tâm) / thang. Thang ~0 -> 1 để khỏi chia cho 0."""
    scale = np.where(np.asarray(scale, float) < 1e-9, 1.0, scale)
    return (np.asarray(x, float) - center) / scale


def explain(x, center, scale, feature_names, k=3, clip=50.0):
    """VÌ SAO bất thường: k đặc trưng lệch xa nhất theo z = (x - median)/MAD, chặn |z| ở clip.
    Trả [[tên, z]] cho |z|>1 (đưa vào cảnh báo -> Wazuh -> đề xuất xử lý)."""
    z = np.clip(zscore(x, center, scale), -clip, clip)
    order = sorted(range(len(feature_names)), key=lambda j: -abs(z[j]))[:k]
    return [[feature_names[j], round(float(z[j]), 1)] for j in order if abs(z[j]) > 1]


# Chính sách thẻ định dạng được phép trong văn bản tự do (giống hệt notebook Web-App). Danh sách thẻ, thuộc tính và
# giao thức lấy từ joblib (khóa "allowed_tags", "allowed_protocols" của nhánh body), mặc định theo $allowedtags
# (wp-includes/kses.php) và wp_allowed_protocols() (wp-includes/functions.php) của WordPress. Đây là chính sách của ứng
# dụng được bảo vệ, không phải chữ ký tấn công: thẻ nằm trong chính sách thì bỏ phần đánh dấu, giữ chữ bên trong;
# thẻ ngoài chính sách, thuộc tính lạ hoặc liên kết có giao thức không cho phép (javascript:, data:...) giữ nguyên để chấm.
_URI_ATTRS = {"href", "cite"}
_TAG_FULL = re.compile(r"<(/?)([a-zA-Z][a-zA-Z0-9]*)([^<>]*)>")
_ATTR = re.compile(r'\s*([a-zA-Z][-a-zA-Z0-9_:.]*)(?:\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s"\'=<>`]+)))?')


def _uri_ok(v, protocols):
    v = re.sub(r"[\x00-\x20\x7f]", "", html.unescape(v)).lower()
    head = re.split(r"[/?#]", v, maxsplit=1)[0]
    return ":" not in head or head.split(":", 1)[0] in protocols


def the_duoc_phep(m, policy, protocols):
    """Thẻ nằm trong chính sách: tên thẻ, mọi thuộc tính và giao thức của liên kết đều được phép."""
    close, name, rest = m.group(1), m.group(2).lower(), m.group(3)
    if name not in policy: return False
    if close: return rest.strip() == ""
    rest = rest.rstrip()
    if rest.endswith("/"): rest = rest[:-1]
    pos = 0
    while pos < len(rest):
        a = _ATTR.match(rest, pos)
        if not a or a.end() == pos: return False
        key = a.group(1).lower(); val = next((g for g in a.group(2, 3, 4) if g is not None), None)
        if key not in policy[name]: return False
        if key in _URI_ATTRS and (val is None or not _uri_ok(val, protocols)): return False
        pos = a.end()
    return True


_OPEN = re.compile(r"<[a-zA-Z/!?]")   # dấu < mở thẻ theo cách trình duyệt tách thẻ; '<3' hay 'a < b' là chữ thường


def trong_the_chua_dong(s, i):
    """Vị trí i nằm sau một dấu < mở thẻ chưa được đóng bằng '>' (vd. '<B>' trong '<SCRIPT SRC=x?<B>'):
    trình duyệt coi đoạn này là phần của thẻ trước chứ không phải một thẻ định dạng."""
    return _OPEN.search(s, s.rfind(">", 0, i) + 1, i) is not None


def bo_the_duoc_phep(s, policy, protocols):
    """Bỏ phần đánh dấu của thẻ được phép, giữ chữ bên trong; thẻ khác và thẻ nằm trong thẻ chưa đóng giữ nguyên để được chấm."""
    return _TAG_FULL.sub(lambda m: "" if the_duoc_phep(m, policy, protocols) and not trong_the_chua_dong(s, m.start())
                         else m.group(0), s)


def _open(path):
    return gzip.open(path, "rt", errors="ignore") if path.endswith(".gz") else open(path, "r", errors="ignore")


def _tail_lines(path, st):
    """Đọc phần MỚI của eve.json kể từ lần trước (st = {"pos", "tail"}), theo byte.
    - Giữ lại dòng cuối chưa ghi xong (Suricata đang ghi dở) để ghép ở vòng sau, tránh mất sự kiện.
    - Nếu file nhỏ hơn vị trí đã đọc (bị xoay vòng/cắt ngắn) thì đọc lại từ đầu file mới."""
    try:
        if os.path.getsize(path) < st["pos"]:
            st["pos"], st["tail"] = 0, b""
        with open(path, "rb") as f:
            f.seek(st["pos"]); data = f.read(); st["pos"] = f.tell()
    except OSError:
        return []
    parts = (st["tail"] + data).split(b"\n")
    st["tail"] = parts.pop()
    return [x.decode("utf-8", errors="ignore") for x in parts]


def _tail_start(path):
    """Vị trí bắt đầu: CUỐI file hiện tại (chỉ xử lý sự kiện mới khi chạy trực tuyến)."""
    try:
        return {"pos": os.path.getsize(path), "tail": b""}
    except OSError:
        return {"pos": 0, "tail": b""}


def _chon_cot(m, feats, ten):
    """Gắn chỉ số cột cho một mô hình. Từ 05/11/2026 rừng có thể chỉ học trên một tập con đặc trưng:
    'feats' là các cột đưa vào rừng (đúng thứ tự cột của mu/sd), 'feats_all' là bộ đặc trưng runtime tính
    cho mỗi đơn vị (med/scale theo bộ này, dùng để diễn giải). Joblib cũ không có 'feats_all': feats là cả bộ."""
    fm = list(m.get("feats", [])); fa = list(m.get("feats_all", fm))
    if fa != feats or not fm or any(f not in feats for f in fm):
        sys.exit(f"[LỖI] {ten} dùng đặc trưng khác bộ hiện tại. Train lại ở notebook rồi xuất joblib.")
    m["idx"] = [feats.index(f) for f in fm]
    return m


def _load(path, feats):
    import joblib
    return _chon_cot(joblib.load(path), feats, f"model '{path}'")


def _load_web(path, feats):
    """Nạp file Web-App gộp: một joblib chứa {"query": {...}, "body": {...}}.
    Trả (mq, mb); mb có thể None nếu file chưa có nhánh body. Mỗi nhánh kiểm feats cho khớp."""
    import joblib
    blob = joblib.load(path)
    def pick(d, which):
        if d is None: return None
        return _chon_cot(d, feats, f"nhánh '{which}' trong '{path}'")
    mq = pick(blob.get("query"), "query"); mb = pick(blob.get("body"), "body")
    if mb is not None and mb.get("known_values"):          # joblib từ v1.2: giá trị đã biết của trường ngắn ít giá trị
        mb["known_values"] = {f: set(v) for f, v in mb["known_values"].items()}
    if mq is None:
        sys.exit(f"[LỖI] '{path}' thiếu nhánh 'query' (Web-Query). Chạy lại notebook Web-App để xuất đủ.")
    gd = mq.get("guard") or {}
    if gd.get("feats"):                                    # joblib từ v2.0: kiểm tra miền của nhánh query
        mq["guard_idx"] = [feats.index(f) for f in gd["feats"]]
        mq["guard_val"] = np.asarray(gd["values"], float)
    return mq, mb


def _thr_q(m, q):
    """Ngưỡng tại phân vị (1-q) trên phân bố điểm huấn luyện đã lưu (s_sk), dùng để tinh chỉnh độ nhạy khi demo/--live.
    q=None: dùng ngưỡng đã chốt trong model. q càng LỚN -> ngưỡng càng thấp -> càng nhạy (nhiều cảnh báo)."""
    if q is None: return m["thr"]
    sk = m.get("s_sk")
    if sk is None:
        print("[CẢNH BÁO] model chưa lưu phân bố điểm (s_sk), không tinh chỉnh được, dùng ngưỡng đã chốt; chạy lại notebook để bật --score-q.")
        return m["thr"]
    return float(np.quantile(np.asarray(sk, float), 1.0 - q))


def _score(m, X):
    """Điểm bất thường (càng cao càng bất thường) từ model sklearn trong joblib."""
    X = np.asarray(X, float)
    if len(X) == 0:
        return np.empty(0)
    if m.get("idx") is not None:                       # chỉ các cột mô hình đã học (tập con đặc trưng)
        X = X.reshape(len(X), -1)[:, m["idx"]]
    return -m["iso"].score_samples(zscore(X, m["mu"], m["sd"]))


def _ngoai_mien(m, V):
    """Kiểm tra miền (joblib từ v2.0, nhánh query): đơn vị có đặc trưng hằng ở tập huấn luyện khác giá trị hằng đó.
    Isolation Forest không cắt trên đặc trưng hằng nên không tự cô lập được độ lệch này (ví dụ chuỗi còn mã hóa phần
    trăm sau một lần giải mã). Trả mảng bool theo đơn vị, hoặc None nếu mô hình không có kiểm tra miền."""
    j = m.get("guard_idx")
    if not j: return None
    X = np.asarray(V, float).reshape(len(V), -1)
    return (np.abs(X[:, j] - m["guard_val"]) > 1e-12).any(1)


def _emit(alert):
    """In gọn + ghi JSON vào ALERT_LOG (Wazuh agent đọc file này -> rule -> thông báo/đề xuất).
    Thêm 2 trường phục vụ hiển thị, KHÔNG ảnh hưởng quyết định của model:
      why      : chuỗi gọn các đặc trưng lệch xa nhất, để rule/Telegram đọc thẳng (reasons là
                 mảng lồng mảng nên Wazuh tách field khó).
      severity : 'high'/'medium' theo VỊ TRÍ của điểm trên NGƯỠNG RIÊNG của từng engine, không theo
                 một mốc tuyệt đối. Điểm của Behavior-IF và Web-App IF có dải khác nhau (ngưỡng khác
                 nhau) nên dùng frac = (score - thr)/(1 - thr), tức phần đã đi từ ngưỡng phát hiện tới
                 mức tối đa 1.0; frac >= 0.15 coi là 'high'. Mọi alert ở đây đều đã vượt ngưỡng, severity
                 chỉ phân tầng hiển thị. Ngưỡng 'thr' do engine truyền vào và KHÔNG ghi ra JSON."""
    why = ", ".join(f"{f}({z:+.1f})" for f, z in alert.get("reasons", []))
    alert["why"] = why
    alert.pop("reasons", None)       # KHÔNG ghi mảng lồng [tên, z] ra JSON: indexer Wazuh/OpenSearch xung đột
                                     # kiểu field (chuỗi lẫn số) -> rớt document khỏi dashboard; 'why' đã đủ.
    thr = alert.pop("thr", None)
    score = alert.get("score", 0) or 0
    if thr is not None and thr < 1.0:
        frac = (score - thr) / (1.0 - thr)
        alert["severity"] = "high" if frac >= 0.15 else "medium"
    else:
        alert["severity"] = "high" if score >= 0.70 else "medium"   # dự phòng khi engine không truyền ngưỡng
    # Chuẩn hóa tên trường IP theo quy ước Wazuh (srcip/dstip) để tương thích
    # <same_source_ip> trong rule tương quan và script suricata-drop của Active Response.
    if "src_ip" in alert:  alert["srcip"] = alert.pop("src_ip")
    if "dest_ip" in alert: alert["dstip"] = alert.pop("dest_ip")
    print(f"🚨 [{alert['module']}] {alert.get('srcip')} → {alert.get('dstip') or alert.get('host') or ''} "
          f"score={alert['score']:.3f} ({alert.get('location','')})" + (f" vì {why}" if why else ""), flush=True)
    with open(ALERT_LOG, "a") as f:
        f.write(json.dumps(alert, ensure_ascii=False) + "\n")


# #############################################################################
# BEHAVIOR-IF: bản ghi flow
# #############################################################################
def _build_behavior(model_path="net_if_model.joblib"):
    VICTIM_NETS = [ipaddress.ip_network("192.168.10.0/24")]
    MGMT_NETS   = [ipaddress.ip_network("192.168.20.0/24")]
    EXCLUDE_PORTS = {0, 53, 5353, 5355, 137, 138, 123}
    EXCLUDE_SRC = set()
    WINDOW_MIN, WINDOW_HOP_MIN, MIN_CONN = 30, 15, 1
    INCOMPLETE_STATES = {"syn_sent", "syn_recv"}
    FEATS = ["log_n_conn", "sqrt_mb_out", "log_bytes_in", "frac_out", "log_throughput",
             "log_peak_cpm", "periodicity", "uniformity", "log_n_ports", "frac_incomplete", "svc_rarity"]
    # Các trường phụ ghi kèm cảnh báo, chỉ phục vụ khâu thông báo (không ảnh hưởng điểm hay ngưỡng):
    # direction = out (máy nạn nhân khởi tạo) / in (bên ngoài khởi tạo); zone_other = vùng của đầu bên kia (ext/mgmt);
    # frac_out = tỉ lệ byte do bên khởi tạo gửi đi trong cửa sổ; dport_top = cổng đích nhiều luồng nhất trong cửa sổ.
    I_FRAC_OUT = FEATS.index("frac_out")
    _TZ = re.compile(r"([+-]\d{2})(\d{2})$")

    def parse(ts):
        if not ts: return None
        s = str(ts)
        try: return datetime.fromisoformat(s).timestamp()
        except ValueError:
            try: return datetime.fromisoformat(_TZ.sub(r"\1:\2", s)).timestamp()
            except ValueError: return None

    def is_v4(ip):
        try: return ipaddress.ip_address(ip).version == 4
        except (ValueError, TypeError): return False

    def bad_dest(ip):
        try:
            a = ipaddress.ip_address(ip)
            return a.is_multicast or a.is_reserved or a.is_loopback or a.is_link_local or a.is_unspecified
        except (ValueError, TypeError): return True

    def zone(ip):
        try: a = ipaddress.ip_address(ip)
        except (ValueError, TypeError): return "ext"
        if any(a in n for n in VICTIM_NETS): return "victim"
        if any(a in n for n in MGMT_NETS):   return "mgmt"
        return "ext"

    def keep_pair(s, d):
        # Hai chiều cùng được chấm, đặc trưng tính theo bên KHỞI TẠO kết nối:
        #   chiều ra: máy nạn nhân -> bên ngoài hoặc vùng quản trị (tham chiếu chính);
        #   chiều vào: bên ngoài -> vùng nạn nhân (tham chiếu "inbound" trong joblib; không có thì bỏ qua chiều này).
        zs, zd = zone(s), zone(d)
        return (zs == "victim" and zd in ("ext", "mgmt")) or (zs == "ext" and zd == "victim")

    # Giới hạn bộ đệm của chế độ --live để vòng chấm không quá tải khi lưu lượng tăng đột biến (ví dụ bị làm ngập):
    # một cặp đã vượt giới hạn thì cửa sổ của nó đã nằm xa ngoài dải huấn luyện và đã được chấm ở các vòng trước.
    BUF_MAX_ROWS     = int(os.environ.get("ANOMALY_BUF_MAX_ROWS", "400000"))      # tổng số luồng giữ trong bộ đệm
    BUF_MAX_PER_PAIR = int(os.environ.get("ANOMALY_BUF_MAX_PER_PAIR", "50000"))   # số luồng tối đa của một cặp
    BUF_MAX_PAIRS    = int(os.environ.get("ANOMALY_BUF_MAX_PAIRS", "20000"))      # số cặp tối đa theo dõi cùng lúc

    def cap_buffer(buf):
        """Giữ luồng mới nhất khi bộ đệm vượt giới hạn theo tổng, theo cặp và theo số cặp."""
        note = []
        if len(buf) > BUF_MAX_ROWS:
            buf = buf[-BUF_MAX_ROWS:]; note.append(f"tổng > {BUF_MAX_ROWS}")
        cnt = collections.Counter(pk for pk, _ in buf)
        if len(cnt) > BUF_MAX_PAIRS:
            keep = {pk for pk, _ in cnt.most_common(BUF_MAX_PAIRS)}
            buf = [rr for rr in buf if rr[0] in keep]; note.append(f"{len(cnt)} cặp > {BUF_MAX_PAIRS}")
            cnt = collections.Counter(pk for pk, _ in buf)
        over = {pk: c - BUF_MAX_PER_PAIR for pk, c in cnt.items() if c > BUF_MAX_PER_PAIR}
        if over:
            out = []
            for rr in buf:                                     # bỏ các luồng CŨ NHẤT của cặp vượt giới hạn
                if over.get(rr[0], 0) > 0: over[rr[0]] -= 1; continue
                out.append(rr)
            buf = out; note.append("có cặp > %d luồng" % BUF_MAX_PER_PAIR)
        return buf, note

    def ext_ip(s, d):
        return d if zone(s) == "victim" else s

    def svc_key(direction, zone_other, proto, dport):
        return f"{direction}|{zone_other}|{str(proto).upper()}|{int(dport)}"

    def rarity_of(key, rar_counts, rar_total):
        return -math.log10((rar_counts.get(key, 0) + 1) / (rar_total + 1))

    def _cv(x):
        x = np.asarray(x, float)
        if len(x) == 0: return 0.0
        m = x.mean()
        return float(x.std() / m) if m > 0 else 0.0

    def _peak_per_min(starts_sorted):
        st = np.asarray(starts_sorted, float)
        if len(st) == 0: return 0
        hi = np.searchsorted(st, st + 60.0, side="right")
        return int((hi - np.arange(len(st))).max())

    def feature_vector(starts, bts, btc, durs, dports, incomplete, rar_vals):
        o = np.argsort(np.asarray(starts, float), kind="stable")
        st = np.asarray(starts, float)[o]
        bts = np.asarray(bts, float)[o]; btc = np.asarray(btc, float)[o]
        durs = np.asarray(durs, float)[o]
        n = len(st)
        sout, sin_ = float(bts.sum()), float(btc.sum()); stot = sout + sin_; sdur = float(durs.sum())
        tot = bts + btc
        gaps = np.diff(st)
        periodicity = math.log1p(len(gaps)) * max(0.0, 1.0 - _cv(gaps)) if len(gaps) >= 3 else 0.0
        uniformity  = math.log1p(n - 1) * max(0.0, 1.0 - _cv(tot)) if n >= 3 else 0.0
        return [math.log1p(n),
                math.sqrt(sout / 1e6),
                math.log1p(sin_),
                sout / stot if stot > 0 else 0.0,
                math.log1p(stot / sdur) if sdur > 0 else 0.0,
                math.log1p(_peak_per_min(st)),
                periodicity,
                uniformity,
                math.log1p(len(set(int(p) for p in dports))),
                float(np.mean(incomplete)) if n else 0.0,
                float(np.mean(rar_vals)) if n else 0.0]

    def _is_incomplete(o):
        st = ((o.get("tcp") or {}).get("state") or "").lower()
        return 1 if st in INCOMPLETE_STATES else 0

    def flow_row(o, rar_counts, rar_total, rar_in=None):
        """rar_in = (bảng độ hiếm, tổng) của tham chiếu chiều vào; None thì bỏ qua luồng chiều vào."""
        if o.get("event_type") != "flow": return None
        s, d = o.get("src_ip"), o.get("dest_ip")
        if not (is_v4(s) and is_v4(d)): return None
        if not keep_pair(s, d): return None
        if s in EXCLUDE_SRC: return None
        other = ext_ip(s, d)
        if bad_dest(other): return None
        dp = o.get("dest_port") or 0
        if dp in EXCLUDE_PORTS: return None
        direction = "out" if zone(s) == "victim" else "in"
        # Bản ghi ngược chiều: Suricata bắt giữa chừng kết nối do máy nạn nhân mở ra Internet nên coi máy chủ Internet
        # là bên khởi tạo (cổng nguồn < 1024, cổng đích >= 1024, không thấy SYN hoặc không phải TCP). Cùng quy tắc với
        # script dựng bộ dữ liệu (build_flow_dataset.py).
        if direction == "in":
            if rar_in is None: return None
            sp = o.get("src_port") or 0
            if sp < 1024 <= dp and (str(o.get("proto") or "").upper() != "TCP" or not (o.get("tcp") or {}).get("syn")):
                return None
            rar_counts, rar_total = rar_in
        fl = o.get("flow", {}) or {}
        st = parse(fl.get("start"))
        if st is None: return None
        en = parse(fl.get("end")) or st
        key = svc_key(direction, zone(other), o.get("proto") or "", dp)
        return (s, d), (st, fl.get("bytes_toserver", 0) or 0, fl.get("bytes_toclient", 0) or 0,
                        max(0.0, en - st), dp, _is_incomplete(o), rarity_of(key, rar_counts, rar_total))

    def window_offsets():
        return [o * 60 for o in range(0, WINDOW_MIN, WINDOW_HOP_MIN)]

    def read_pairs(path, rc, rt, last_min=None, rar_in=None):
        P = collections.defaultdict(list); tmax = None
        with _open(path) as f:
            for line in f:
                if '"event_type":"flow"' not in line and '"event_type": "flow"' not in line: continue
                try: o = json.loads(line)
                except Exception: continue
                r = flow_row(o, rc, rt, rar_in)
                if r is None: continue
                P[r[0]].append(r[1]); en = r[1][0] + r[1][3]
                if tmax is None or en > tmax: tmax = en
        if last_min and tmax:
            lo = tmax - last_min * 60
            P = {k: [x for x in v if x[0] + x[3] >= lo] for k, v in P.items()}
        return P

    def _windows_from_P(P):
        W = WINDOW_MIN * 60; keys, X = [], []
        for (s, d), rows in P.items():
            for off in window_offsets():
                buckets = collections.defaultdict(list)
                for r in rows: buckets[int((r[0] - off) // W)].append(r)
                for b, rws in buckets.items():
                    if len(rws) < MIN_CONN: continue
                    c = list(zip(*rws))
                    X.append(feature_vector(c[0], c[1], c[2], c[3], c[4], c[5], c[6]))
                    keys.append((s, d, ext_ip(s, d), len(rws), off, b, int(collections.Counter(c[4]).most_common(1)[0][0])))
        return keys, (np.array(X) if X else np.empty((0, len(FEATS))))

    def build_matrix(path, rc, rt, last_min=None, rar_in=None):
        return _windows_from_P(read_pairs(path, rc, rt, last_min, rar_in))

    def _inbound(m):
        mi = m.get("inbound")
        if mi is None: return None
        return _chon_cot(mi, FEATS, "tham chiếu chiều vào trong joblib")

    def score_split(keys, X, m, thr, mi, thr_i):
        """Chấm từng cửa sổ bằng tham chiếu đúng với bên khởi tạo; trả [(i, điểm, mô hình, ngưỡng)]."""
        ra = [i for i, k in enumerate(keys) if zone(k[0]) == "victim"]
        vao = [i for i, k in enumerate(keys) if zone(k[0]) == "ext"]
        out = []
        if ra:
            for i, sc in zip(ra, _score(m, X[ra])): out.append((i, sc, m, thr))
        if vao and mi is not None:
            for i, sc in zip(vao, _score(mi, X[vao])): out.append((i, sc, mi, thr_i))
        return out

    def _emit_beh(key, x, sc, m, thr, loc):
        src, dst, other, n, off, b, top = key
        _emit({"module": "anomaly_if", "time": datetime.now().isoformat(timespec="seconds"),
               "src_ip": src, "dest_ip": dst, "ext_ip": other, "n_conn": int(n),
               "direction": "out" if zone(src) == "victim" else "in", "dport_top": top,
               "zone_other": zone(other), "frac_out": round(float(x[I_FRAC_OUT]), 3),
               "location": loc, "score": float(sc), "thr": thr,
               "reasons": explain(x, m["med"], m["scale"], FEATS)})

    # ---- runtime ----
    def detect(path, last_min=None, score_q=None, score_q_in=None):
        m = _load(model_path, FEATS); thr = _thr_q(m, score_q)
        mi = _inbound(m); thr_i = _thr_q(mi, score_q_in) if mi is not None else None
        if mi is None: print("[BEHAVIOR-IF] chiều vào: bỏ qua (model chưa có khóa 'inbound', chạy mục 9 của notebook).")
        rar_in = (mi["rarity_counts"], mi["rarity_total"]) if mi is not None else None
        keys, X = build_matrix(path, m["rarity_counts"], m["rarity_total"], last_min, rar_in)
        if len(X) == 0:
            print("[BEHAVIOR-IF] không có cặp-cửa-sổ nào để chấm."); return
        fired = {"out": 0, "in": 0}; n = {"out": 0, "in": 0}
        for i, sc, mm, t in score_split(keys, X, m, thr, mi, thr_i):
            d = "in" if mm is mi else "out"; n[d] += 1
            if sc > t:
                fired[d] += 1; _emit_beh(keys[i], X[i], sc, mm, t, f"cửa sổ {WINDOW_MIN}' (off {keys[i][4]//60}')")
        print(f"[BEHAVIOR-IF] chiều ra: {n['out']} cặp-cửa-sổ, {fired['out']} vượt ngưỡng ({thr:.4f})"
              + (f" | chiều vào: {n['in']} cặp-cửa-sổ, {fired['in']} vượt ngưỡng ({thr_i:.4f})" if mi is not None else ""))

    def live(path, interval=None, score_q=None, score_q_in=None):
        # ĐỌC TĂNG DẦN + buffer cuộn: mỗi vòng chỉ đọc phần MỚI của eve.json (seek theo pos) rồi
        # dựng cửa sổ từ các flow gần đây giữ trong bộ nhớ. Tránh đọc lại cả file mỗi vòng (vừa ghim
        # CPU, vừa giữ GIL làm engine web bị bỏ đói). Lần đầu pos=0 nên đọc hết một lần để có lịch sử,
        # sau đó chỉ đọc phần bổ sung.
        m = _load(model_path, FEATS); thr = _thr_q(m, score_q); iv = interval or 30
        rc, rt = m["rarity_counts"], m["rarity_total"]
        print(f"[BEHAVIOR-IF live] model có {len(FEATS)} đặc trưng, cửa sổ {WINDOW_MIN}', ngưỡng={thr:.4f}, mỗi {iv}s", flush=True)
        mi = _inbound(m); thr_i = _thr_q(mi, score_q_in) if mi is not None else None
        rar_in = (mi["rarity_counts"], mi["rarity_total"]) if mi is not None else None
        print("[BEHAVIOR-IF live] chiều vào: " + (f"bật, ngưỡng={thr_i:.4f}" if mi is not None else "tắt (model chưa có khóa 'inbound')"), flush=True)
        seen = set(); buf = []; last_note = 0.0
        st = _tail_start(path)                             # bắt đầu từ CUỐI file: chỉ dựng cửa sổ từ flow MỚI
        KEEP = (WINDOW_MIN + WINDOW_HOP_MIN) * 60          # giữ flow đủ gần để dựng cửa sổ
        while True:
            tmax = None
            for line in _tail_lines(path, st):
                if '"event_type":"flow"' not in line and '"event_type": "flow"' not in line: continue
                try: o = json.loads(line)
                except Exception: continue
                r = flow_row(o, rc, rt, rar_in)
                if r is None: continue
                buf.append(r)                              # r = ((src,dst), row)
                en = r[1][0] + r[1][3]
                if tmax is None or en > tmax: tmax = en
            if tmax is not None:                           # cắt flow quá cũ -> buffer bị chặn
                lo = tmax - KEEP
                buf = [rr for rr in buf if rr[1][0] + rr[1][3] >= lo]
                buf, note = cap_buffer(buf)
                if note and time.time() - last_note > 60:
                    print(f"[BEHAVIOR-IF live] bộ đệm chạm giới hạn ({'; '.join(note)}), chỉ giữ luồng mới nhất", flush=True)
                    last_note = time.time()
                bmin = int((lo - WINDOW_MIN * 60) // (WINDOW_MIN * 60))
                seen = {k for k in seen if k[2] >= bmin}       # bỏ khóa của cửa sổ đã trôi qua
            if buf:
                P = collections.defaultdict(list)
                for (pk, row) in buf: P[pk].append(row)
                keys, X = _windows_from_P(P)
                if len(X):
                    for i, sc, mm, t in score_split(keys, X, m, thr, mi, thr_i):
                        kk = keys[i]; k = (kk[0], kk[1], kk[5])  # (nguồn, đích, bucket)
                        if sc > t and k not in seen:
                            seen.add(k); _emit_beh(kk, X[i], sc, mm, t, f"cửa sổ {WINDOW_MIN}'")
            time.sleep(iv)

    return types.SimpleNamespace(detect=detect, live=live)


# #############################################################################
# WEB-APP IF: bản ghi http (Web-Query cho tham số truy vấn và trường ngắn của thân POST, Web-Body cho văn bản tự do)
# #############################################################################
def _build_web(model_path="web_app_if_model.joblib"):
    FEATS = ["log_len", "r_nonalnum", "r_digit", "r_upper", "entropy", "n_squote", "n_dquote",
             "n_angle", "n_paren", "n_punct_inj", "n_kw", "n_pct", "max_run_sym"]
    # Tên trường văn bản tự do của các ứng dụng được bảo vệ -> luôn đưa sang Web-Body (không phụ thuộc độ dài).
    # Cấu hình theo ứng dụng: comment/message/... (WordPress), mtxMessage (sổ lưu bút DVWA). Mở rộng ở đây khi
    # thêm ứng dụng mới. Trường KHÔNG đăng ký vẫn được xét nếu giá trị đủ dài theo heuristic bên dưới.
    FREE_FIELDS = {"your-message", "content", "comment", "your-subject", "title", "message", "body", "mtxMessage"}
    _FREE_ENV = os.environ.get("WEB_FREE_FIELDS", "")   # cho phép bổ sung lúc chạy: WEB_FREE_FIELDS=f1,f2
    for _f in _FREE_ENV.replace(";", ",").split(","):
        _f = _f.strip()
        if _f: FREE_FIELDS.add(_f)
    _KW = re.compile(
        r"(?:\b(?:select|union|insert|update|delete|drop|from|where|or|and|exec|"
        r"char|concat|benchmark|sleep|script|alert|onerror|onload|iframe|eval|"
        r"javascript|cmd|etc|passwd|boot\.ini)\b)|(?:--)|(?:/\*)|(?:\.\.[\\/])|(?:<\s*/?\s*\w)",
        re.IGNORECASE)
    _PCT = re.compile(r"%[0-9a-fA-F]{2}")
    _INJ = set(";|&`$\\{}")
    _TAG = re.compile(r"</?[a-zA-Z][^<>]{0,300}>|\bon[a-zA-Z]{2,}\s*=\s*\S+", re.IGNORECASE)
    _URL_RE = re.compile(r"^https?://", re.IGNORECASE)
    _HOST_RE = re.compile(r"^[A-Za-z0-9.-]+(?::\d{1,5})?$")
    _PATH_RE = re.compile(r"^/[A-Za-z0-9/_\-.]*$")

    def _entropy(s):
        if not s: return 0.0
        c = collections.Counter(s); n = len(s)
        return float(-sum((v / n) * math.log2(v / n) for v in c.values()))

    def _max_run_symbol(s):
        best = cur = 0
        for ch in s:
            if not ch.isalnum(): cur += 1; best = max(best, cur)
            else: cur = 0
        return best

    def feature_vector(raw):
        s = raw if isinstance(raw, str) else ("" if raw is None else str(raw))
        n = len(s)
        if n == 0: return [0.0] * len(FEATS)
        nonalnum = sum(1 for ch in s if not ch.isalnum())
        digit = sum(1 for ch in s if ch.isdigit())
        upper = sum(1 for ch in s if ch.isupper())
        return [math.log1p(n), nonalnum / n, digit / n, upper / n, _entropy(s),
                float(s.count("'")), float(s.count('"')), float(s.count("<") + s.count(">")),
                float(s.count("(") + s.count(")")), float(sum(s.count(c) for c in _INJ)),
                float(len(_KW.findall(s))), float(len(_PCT.findall(s))), float(_max_run_symbol(s))]

    def decode_once(s):
        # Byte 0 (%00 sau khi giải mã) ghi lại thành chữ %00, giống bộ dữ liệu huấn luyện
        try: return unquote_plus(s).replace("\x00", "%00")
        except Exception: return s

    def is_plain_path(v):
        return bool(_PATH_RE.match(v)) and ".." not in v

    def la_url_hop_le(v):
        # URL http(s) hợp lệ: tên máy hợp lệ, đường dẫn trơn hoặc rỗng, không có phần mảnh '#'. Từ v1.3: trước đó mọi
        # giá trị dạng x:// đều được tách như URL, nên chỉ cần thêm tiền tố (javascript://, php://, http://www.<script>...)
        # là phần còn lại của chuỗi không được chấm.
        if not _URL_RE.match(v) or "#" in v:
            return False
        try:
            u = urlsplit(v)
        except ValueError:
            return False
        return bool(_HOST_RE.match(u.netloc)) and (u.path == "" or is_plain_path(u.path))

    def expand_value(v, known_paths=()):
        # URL hợp lệ: chấm các giá trị tham số bên trong; giá trị khác (kể cả URL không hợp lệ): chấm nguyên giá trị
        if la_url_hop_le(v):
            return [decode_once(x) for _, x in parse_qsl(urlsplit(v).query, keep_blank_values=True) if x]
        if v in known_paths and is_plain_path(v):
            return []
        return [v]

    def _json_string_leaves(s, max_leaves=200):
        try: obj = json.loads(s)
        except Exception: return [("raw", s)]
        out = []
        def walk(o, path):
            if len(out) >= max_leaves: return
            if isinstance(o, str): out.append((path or "root", o))
            elif isinstance(o, dict):
                for k, v in o.items(): walk(v, f"{path}.{k}" if path else str(k))
            elif isinstance(o, (list, tuple)):
                for i, v in enumerate(o): walk(v, f"{path}[{i}]")
        walk(obj, ""); return out

    _MP_HEAD = re.compile(r"^--(\S+)\r?\n")
    _MP_NAME = re.compile(r'name="([^"]*)"')

    def _multipart_fields(s):
        """Thân multipart/form-data -> [(tên trường, giá trị)]; trả None nếu không phải multipart.
        Bỏ qua phần tệp đính kèm (có filename)."""
        m = _MP_HEAD.match(s)
        if not m: return None
        sep = "--" + m.group(1); out = []
        for part in s.split(sep)[1:]:
            if part.startswith("--"): break
            head, ok, val = part.lstrip("\r\n").partition("\r\n\r\n")
            if not ok: head, ok, val = part.lstrip("\n").partition("\n\n")
            nm = _MP_NAME.search(head)
            if not ok or not nm or "filename=" in head: continue
            out.append((nm.group(1), val[:-2] if val.endswith("\r\n") else val.rstrip("\n")))
        return out

    def _raw_units(url, body=None):
        units = []
        if url:
            sp = urlsplit(url if "//" in url else ("//h" + url if url.startswith("/") else url))
            if sp.query:
                pairs = parse_qsl(sp.query, keep_blank_values=True)
                if pairs:
                    for k, v in pairs:
                        if v: units.append((f"query:{k}", decode_once(v)))
                else:
                    units.append(("query", decode_once(sp.query)))
        if body:
            # Tách thân theo đúng cách trích dữ liệu huấn luyện Web-Body: multipart và JSON giữ nguyên giá trị,
            # thân dạng biểu mẫu mã hóa URL thì giải mã như chuỗi truy vấn.
            bs = body.strip()
            mp = _multipart_fields(bs)
            if mp is not None:
                for k, v in mp:
                    if v: units.append((f"body:{k}", v.replace("\x00", "%00")))
            elif bs[:1] in "{[":
                for lab, v in _json_string_leaves(bs): units.append((f"body:{lab}", v.replace("\x00", "%00")))
            elif "=" in bs:
                for k, v in parse_qsl(bs, keep_blank_values=True):
                    if v: units.append((f"body:{k}", decode_once(v)))
            else:
                units.append(("body", decode_once(bs)))
        return units

    def units_text(s):
        """Văn bản tự do -> [nguyên giá trị] + [token thẻ/sự kiện]. Chỉ dùng với joblib cũ (không có tag_units)."""
        return [s] + _TAG.findall(s)

    def _field_name(label):
        return label.split(":", 1)[-1].split(".")[-1].split("[")[0]

    # ---- runtime ----
    # Suricata ghi event "http" cho MỌI giao dịch nhưng KHÔNG kèm thân request; thân POST chỉ xuất hiện
    # trong event "alert" khi bật `http-body: yes` (base64) ở đầu ra EVE của sự kiện alert. Vì vậy
    # runtime đọc hai nguồn:
    #   - event http  -> lấy QUERY (url)                  -> Web-Query (GET + query của POST)
    #   - event alert -> lấy THÂN POST (văn bản)          -> Web-Body
    # Thân chỉ lấy ở event alert nên query của POST không bị chấm trùng (query đã lấy ở event http).
    def _decode_body(h):
        # Ưu tiên http_request_body (base64, bật `http-body: yes` ở đầu ra EVE alert): giải mã đúng UTF-8 nên
        # giữ nguyên chữ tiếng Việt, khớp cách trích dữ liệu huấn luyện. Bản http_request_body_printable thay
        # mọi byte ngoài ASCII bằng '.', chỉ dùng khi không có bản base64.
        b64 = h.get("http_request_body")
        if b64:
            try: return base64.b64decode(b64).decode("utf-8", errors="replace")
            except Exception: pass
        return h.get("http_request_body_printable") or None

    def iter_http(path):
        with _open(path) as f:
            for line in f:
                is_http = '"event_type":"http"' in line or '"event_type": "http"' in line
                is_alert = '"event_type":"alert"' in line or '"event_type": "alert"' in line
                if not (is_http or is_alert): continue
                try: o = json.loads(line)
                except Exception: continue
                h = o.get("http") or {}
                if not h: continue
                base = {"src_ip": o.get("src_ip"), "dest_ip": o.get("dest_ip"),
                        "dest_port": o.get("dest_port"), "host": h.get("hostname"),
                        "method": h.get("http_method")}
                if is_http:
                    yield {**base, "url": h.get("url"), "body": None}          # chỉ query
                else:
                    body = _decode_body(h)
                    if body:
                        ep = urlsplit(h.get("url")).path if h.get("url") else None  # giữ endpoint để hiển thị, bỏ query (tránh chấm trùng)
                        yield {**base, "url": ep, "body": body}                # chỉ thân POST

    def _route_and_score(rec, mq, mb):
        """Định tuyến theo loại giá trị:
        - tham số truy vấn và trường NGẮN của thân POST -> Web-Query IF (mq)
        - trường văn bản tự do của thân POST: trước hết bỏ thẻ định dạng được phép theo chính sách của ứng dụng (joblib
          ghi allowed_tags), rồi nguyên câu -> Web-Body IF (mb); từng đoạn còn lại trông như thẻ HTML hoặc thuộc tính
          sự kiện -> Web-Query IF (chuỗi ngắn có cấu trúc như giá trị tham số; joblib ghi tag_units = "query").
        - joblib từ v1.2 (free_by = "field"): văn bản tự do chỉ xác định theo tên trường, không theo độ dài, để kẻ tấn công
          không chọn được mô hình bằng cách đệm dấu cách; trường ngắn của thân POST có giá trị đã biết (known_values) thì
          bỏ qua giá trị đó, giá trị chưa gặp vẫn chấm bằng Web-Query IF.
        Một giá trị bị gắn cờ khi có đơn vị vượt ngưỡng của chính mô hình chấm nó; cảnh báo lấy đơn vị vượt xa nhất."""
        alerts = []
        for lab, val in _raw_units(rec.get("url"), rec.get("body")):
            is_body = lab.startswith("body")
            field = _field_name(lab)
            theo_ten = mb is not None and mb.get("free_by") == "field"
            free = field in FREE_FIELDS or (not theo_ten and len(val) >= 40 and val.count(" ") >= 4)
            if is_body and free and mb is not None:
                module = "anomaly_web_body"
                if mb.get("tag_units") == "query":
                    v = val
                    if mb.get("allowed_tags"):                 # joblib từ 04/11: bỏ thẻ định dạng được phép trước khi chấm
                        v = bo_the_duoc_phep(val, mb["allowed_tags"], mb.get("allowed_protocols", ()))
                    parts = [(mb, [v], False), (mq, _TAG.findall(v), False)]
                else:                                          # joblib cũ: mọi đơn vị do Web-Body chấm
                    parts = [(mb, units_text(val), False)]
            else:
                if is_body and mb is not None and val in mb.get("known_values", {}).get(field, ()):
                    continue                                   # giá trị đã biết của trường ngắn ít giá trị
                us = expand_value(val, mq.get("known_paths", ()))
                if not us: continue
                module, parts = "anomaly_web", [(mq, us, True)]   # giá trị tham số: có kiểm tra miền (nếu joblib có)
            best = None
            for m, us, kt in parts:
                if not us: continue
                V = [feature_vector(u) for u in us]
                s = _score(m, V); g = _ngoai_mien(m, V) if kt else None
                if g is not None: s = np.where(g, 1.0, s)      # ngoài miền huấn luyện: điểm 1, mức cao nhất
                i = int(np.argmax(s))
                if s[i] > m["thr"] and (best is None or s[i] - m["thr"] > best[0]):
                    oor = ",".join(f for f, j, gv in zip(m["guard"]["feats"], m["guard_idx"], m["guard_val"])
                                   if abs(V[i][j] - gv) > 1e-12) if g is not None and g[i] else ""
                    best = (s[i] - m["thr"], float(s[i]), explain(V[i], m["med"], m["scale"], FEATS), m["thr"], oor)
            if best:
                alerts.append((module, lab, best[1], best[2], best[3], best[4]))
        return alerts

    def detect(path, last_min=None, score_q=None):
        mq, mb = _load_web(model_path, FEATS)
        mq["thr"] = _thr_q(mq, score_q)
        if mb is not None: mb["thr"] = _thr_q(mb, score_q)
        n_req = fired = 0
        for rec in iter_http(path):
            n_req += 1
            if not _in_web_targets(rec.get("dest_ip")): continue
            for module, lab, sc, reasons, thr, oor in _route_and_score(rec, mq, mb):
                fired += 1
                _emit({"module": module, "time": datetime.now().isoformat(timespec="seconds"),
                       "src_ip": rec["src_ip"], "dest_ip": rec["dest_ip"], "dest_port": rec["dest_port"],
                       "host": rec["host"], "method": rec["method"], "url": rec["url"],
                       "location": lab, "score": sc, "thr": thr, "reasons": reasons,
                       **({"out_of_range": oor} if oor else {})})
        print(f"[WEB-APP IF] {n_req} đơn vị quan sát (query http + thân POST) | {fired} đơn vị vượt ngưỡng"
              f"{' (có Web-Body)' if mb is not None else ' (chưa có web_body model)'}")

    def live(path, interval=None, score_q=None):
        mq, mb = _load_web(model_path, FEATS)
        mq["thr"] = _thr_q(mq, score_q)
        if mb is not None: mb["thr"] = _thr_q(mb, score_q)
        iv = interval or 10
        print(f"[WEB-APP IF live] query+body, mỗi {iv}s", flush=True)
        st = _tail_start(path)                             # bắt đầu từ CUỐI file: chỉ xử lý request MỚI
        done = collections.OrderedDict()                   # giao dịch HTTP đã chấm: (flow_id, tx_id, nguồn)
        while True:
            for line in _tail_lines(path, st):
                is_http = '"event_type":"http"' in line or '"event_type": "http"' in line
                is_alert = '"event_type":"alert"' in line or '"event_type": "alert"' in line
                if not (is_http or is_alert): continue
                try: o = json.loads(line)
                except Exception: continue
                h = o.get("http") or {}
                if not h: continue
                # Một yêu cầu POST có thể khớp nhiều luật (luật thu thập + luật chữ ký) -> nhiều event
                # alert cùng mang một thân. Chỉ chấm mỗi giao dịch một lần cho mỗi nguồn (http/alert).
                tx = (o.get("flow_id"), o.get("tx_id"), "alert" if is_alert else "http")
                if tx[0] is not None and tx[1] is not None:
                    if tx in done: continue
                    done[tx] = None
                    if len(done) > 100000: done.popitem(last=False)
                if is_http:                                        # event http: chỉ query (GET + query POST)
                    rec = {"src_ip": o.get("src_ip"), "dest_ip": o.get("dest_ip"), "dest_port": o.get("dest_port"),
                           "host": h.get("hostname"), "method": h.get("http_method"), "url": h.get("url"), "body": None}
                else:                                              # event alert: chỉ thân POST (base64, dự phòng bản printable)
                    body = _decode_body(h)
                    if not body: continue
                    ep = urlsplit(h.get("url")).path if h.get("url") else None  # giữ endpoint để hiển thị, bỏ query (tránh chấm trùng)
                    rec = {"src_ip": o.get("src_ip"), "dest_ip": o.get("dest_ip"), "dest_port": o.get("dest_port"),
                           "host": h.get("hostname"), "method": h.get("http_method"), "url": ep, "body": body}
                if not _in_web_targets(rec["dest_ip"]): continue   # chỉ chấm http đi vào web server bảo vệ
                for module, lab, sc, reasons, thr, oor in _route_and_score(rec, mq, mb):
                    _emit({"module": module, "time": datetime.now().isoformat(timespec="seconds"),
                           "src_ip": rec["src_ip"], "dest_ip": rec["dest_ip"], "host": rec["host"],
                           "method": rec["method"], "url": rec["url"], "location": lab, "score": sc,
                           "thr": thr, "reasons": reasons, **({"out_of_range": oor} if oor else {})})
            time.sleep(iv)

    return types.SimpleNamespace(detect=detect, live=live)


def main(argv):
    # Chạy tối giản: `python3 anomaly.py --live` là đủ, chương trình tự dùng model mặc định ở thư mục hiện tại
    # (net_if_model.joblib + web_app_if_model.joblib) và nguồn log mặc định. Đường dẫn eve.json và
    # model đều có thể ghi đè qua tham số, hoặc đặt biến môi trường EVE_JSON cho đường dẫn log.
    args = argv[1:]
    def opt(flag, d=None):
        if flag in args:
            i = args.index(flag)
            if i + 1 < len(args) and not args[i + 1].startswith("--"): return args[i + 1]
        return d
    def has(flag): return flag in args

    EVE = os.environ.get("EVE_JSON", "/var/log/suricata/eve.json")   # nguồn log mặc định trên host Suricata
    last = int(opt("--last")) if opt("--last") else None
    iv = int(opt("--interval")) if opt("--interval") else None
    q_all = float(opt("--score-q")) if opt("--score-q") else None     # tinh chỉnh độ nhạy khi demo (phân vị, áp cho mọi engine)
    q_net = float(opt("--net-q")) if opt("--net-q") else q_all         # riêng Behavior-IF
    q_web = float(opt("--web-q")) if opt("--web-q") else q_all         # riêng Web-App (cả query lẫn body)
    q_in  = float(opt("--in-q")) if opt("--in-q") else q_all           # riêng tham chiếu chiều vào của Behavior-IF
    net_model = opt("--model-net", "net_if_model.joblib")
    web_model = opt("--model-web", "web_app_if_model.joblib")
    beh = _build_behavior(net_model); web = _build_web(model_path=web_model)

    if has("--detect"):
        path = opt("--detect", EVE)
        print(f"[anomaly] ghi cảnh báo vào {ALERT_LOG}")
        if os.path.exists(net_model): beh.detect(path, last, q_net, q_in)
        else: print(f"[BEHAVIOR-IF] bỏ qua: không thấy {net_model}")
        if os.path.exists(web_model): web.detect(path, last, q_web)
        else: print(f"[WEB-APP IF] bỏ qua: không thấy {web_model}")
        return
    if has("--live"):
        path = opt("--live", EVE)
        # Chỉ cho phép MỘT phiên --live ghi vào cùng tệp cảnh báo: hai phiên chạy song song sẽ ghi
        # mỗi cảnh báo hai lần và làm sai bộ đếm của luật tương quan trên Wazuh.
        import fcntl
        _lock = open(ALERT_LOG + ".lock", "w")
        try:
            fcntl.flock(_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            print(f"[anomaly] đã có một phiên --live khác đang chạy (khóa {ALERT_LOG}.lock). "
                  "Dừng phiên đó trước:  pkill -f 'anomaly.py --live'"); return
        threads = []
        if os.path.exists(net_model):
            threads.append(threading.Thread(target=beh.live, args=(path, iv, q_net, q_in), daemon=True))
        if os.path.exists(web_model):
            threads.append(threading.Thread(target=web.live, args=(path, iv, q_web), daemon=True))
        if not threads:
            print(f"Không thấy model ({net_model} / {web_model}) ở thư mục hiện tại: "
                  "chạy notebook để sinh model trước, hoặc trỏ --model-net/--model-web."); return
        print(f"[anomaly] chạy {len(threads)} engine trên {path} | ghi cảnh báo vào {ALERT_LOG} (Ctrl-C để dừng)")
        for t in threads: t.start()
        try:
            while any(t.is_alive() for t in threads): time.sleep(1)
        except KeyboardInterrupt:
            print("\n[anomaly] dừng.")
        return
    print(f"Dùng: python3 anomaly.py --live [eve.json]    (mặc định log {EVE}; model net_if_model.joblib + web_app_if_model.joblib ở thư mục hiện tại)\n"
          "      python3 anomaly.py --detect [eve.json] [--last N]\n"
          "      Tùy chọn: [--interval N] [--score-q Q | --net-q Q --in-q Q --web-q Q] [--model-net F] [--model-web F]; hoặc EVE_JSON cho đường dẫn log.\n"
          "      Demo: --score-q càng LỚN càng nhạy (nhiều cảnh báo hơn); bỏ trống thì dùng ngưỡng đã chốt trong model.")


if __name__ == "__main__":
    main(sys.argv)
