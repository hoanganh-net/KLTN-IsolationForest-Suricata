"""common.py — hạ tầng dùng chung cho Behavior-IF và Web-App IF. Tách từ anomaly.py, logic nguyên vẹn."""
import sys, os, json, math, time, re, gzip, ipaddress, collections, types, threading, base64, html
from datetime import datetime
from urllib.parse import unquote_plus, urlsplit, parse_qsl
import numpy as np


# Tệp cảnh báo cho Wazuh agent (localfile json); ANOMALY_LOG ghi đè đường dẫn mặc định.
ALERT_LOG = os.environ.get("ANOMALY_LOG", "/var/log/suricata-anomaly/anomaly_alerts.jsonl")
_alert_dir = os.path.dirname(ALERT_LOG)
if _alert_dir:
    try: os.makedirs(_alert_dir, exist_ok=True)         # tạo thư mục log nếu có quyền; không có thì để _emit báo lỗi rõ
    except Exception: pass


# Danh sách loại trừ của nhánh hành vi (ANOMALY_WHITELIST, mặc định whitelist.txt ở thư mục chạy): mỗi dòng một IP hoặc
# CIDR, phần sau # là ghi chú. Luồng có đầu bên kia vùng nạn nhân thuộc danh sách bị bỏ trước khi gom cửa sổ, ở cả hai
# tầng. Đây là tinh chỉnh khi triển khai, notebook không dùng; sửa tệp xong phải khởi động lại dịch vụ.
WHITELIST_PATH = os.environ.get("ANOMALY_WHITELIST", "whitelist.txt")

def _load_whitelist(path):
    ips, nets = set(), []
    if not path or not os.path.exists(path):
        return ips, nets
    with open(path, encoding="utf-8-sig", errors="ignore") as f:          # utf-8-sig: chịu được BOM khi sửa trên Windows
        for i, line in enumerate(f, 1):
            tok = line.split("#", 1)[0].strip()
            if not tok: continue
            try: n = ipaddress.ip_network(tok, strict=False)
            except ValueError:
                print(f"[anomaly] {path}:{i}: bỏ qua dòng không phải IP/CIDR: {tok}", flush=True); continue
            if n.num_addresses == 1: ips.add(str(n.network_address))
            else: nets.append(n)
    return ips, nets


# Đo hiệu năng (ANOMALY_PERF=1): CPU, RAM, thời gian chấm ghi vào tệp riêng, không đụng tệp cảnh báo.
PERF_ON  = os.environ.get("ANOMALY_PERF", "0") not in ("0", "", "false", "False", "no")
PERF_LOG = os.environ.get("ANOMALY_PERF_LOG", os.path.join(_alert_dir or ".", "anomaly_perf.jsonl"))
_perf = {"score_s": 0.0, "score_units": 0}
_perf_lock = threading.Lock()

def _perf_add(**kw):
    if not PERF_ON: return
    try:
        with _perf_lock:
            for k, v in kw.items(): _perf[k] = _perf.get(k, 0) + v
    except Exception: pass

def _perf_write(rec):
    try:
        rec["time"] = datetime.now().isoformat(timespec="seconds")
        with open(PERF_LOG, "a") as f: f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception: pass

def _proc_cpu_rss():
    """CPU giây tích lũy (utime+stime) và RSS (MB) của chính tiến trình, đọc từ /proc; (None, None) nếu không đọc được."""
    try:
        f = open("/proc/self/stat").read().split()
        cpu_s = (int(f[13]) + int(f[14])) / os.sysconf("SC_CLK_TCK")
        rss_mb = None
        for l in open("/proc/self/status"):
            if l.startswith("VmRSS"): rss_mb = int(l.split()[1]) // 1024; break
        return cpu_s, rss_mb
    except Exception:
        return None, None

def _perf_sampler(interval):
    """Luồng nền: mỗi `interval` giây ghi CPU% (so với mẫu trước), RSS và tổng dồn thời gian/đơn vị chấm điểm."""
    interval = max(5, int(interval or 30))
    last_cpu, last_t = _proc_cpu_rss()[0], time.time()
    _perf_write({"kind": "start", "pid": os.getpid(), "interval_s": interval})
    while True:
        time.sleep(interval)
        cpu_s, rss_mb = _proc_cpu_rss(); now = time.time()
        rec = {"kind": "sample", "rss_mb": rss_mb}
        if last_cpu is not None and cpu_s is not None and now > last_t:
            rec["cpu_percent"] = round(100 * (cpu_s - last_cpu) / (now - last_t), 1)
        last_cpu, last_t = cpu_s, now
        with _perf_lock:
            rec["score_time_s"] = round(_perf["score_s"], 3); rec["score_units"] = _perf["score_units"]
        _perf_write(rec)


# Lặp lại zscore/explain của isolationforest.py để runtime tự chứa.
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


def _open(path):
    return gzip.open(path, "rt", errors="ignore") if path.endswith(".gz") else open(path, "r", errors="ignore")


def _tail_lines(path, st):
    """Đọc phần mới của eve.json kể từ lần trước (st = {"pos", "tail"}). Giữ dòng ghi dở để ghép ở vòng sau;
    tệp nhỏ hơn vị trí đã đọc (bị xoay vòng) thì đọc lại từ đầu."""
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


def _tail_warm(path, max_bytes):
    """Đọc lại tối đa max_bytes cuối của eve.json lúc khởi động. Trả (các dòng trọn vẹn, vị trí đọc tiếp cho _tail_lines)."""
    try:
        size = os.path.getsize(path); start = max(0, size - int(max_bytes))
        with open(path, "rb") as f:
            f.seek(start); data = f.read(size - start)
    except OSError:
        return [], {"pos": 0, "tail": b""}
    parts = data.split(b"\n")
    if start > 0:
        parts = parts[1:]                                      # dòng đầu có thể bị cắt giữa chừng
    tail = parts.pop() if parts else b""
    return [x.decode("utf-8", errors="ignore") for x in parts], {"pos": start + len(data), "tail": tail}


def _chon_cot(m, feats, ten):
    """Gắn chỉ số cột cho một mô hình: 'feats' là các cột rừng học (theo thứ tự của mu/sd), 'feats_all' là bộ
    đặc trưng tính cho mỗi đơn vị (med/scale theo bộ này). Joblib cũ không có 'feats_all' thì dùng 'feats'."""
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
    if mb is not None and mb.get("known_values"):  # giá trị đã biết của trường ngắn
        mb["known_values"] = {f: set(v) for f, v in mb["known_values"].items()}
    if mq is None:
        sys.exit(f"[LỖI] '{path}' thiếu nhánh 'query' (Web-Query). Chạy lại notebook Web-App để xuất đủ.")
    gd = mq.get("guard") or {}
    if gd.get("feats"):  # kiểm tra miền của nhánh query
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
    if m.get("idx") is not None:  # cột rừng đã học
        X = X.reshape(len(X), -1)[:, m["idx"]]
    if PERF_ON:
        _t0 = time.perf_counter()
        s = -m["iso"].score_samples(zscore(X, m["mu"], m["sd"]))
        _perf_add(score_s=time.perf_counter() - _t0, score_units=len(X))
        return s
    return -m["iso"].score_samples(zscore(X, m["mu"], m["sd"]))


def _ngoai_mien(m, V):
    """Kiểm tra miền của nhánh query: đơn vị khác giá trị hằng của tập huấn luyện ở một đặc trưng hằng, điều
    rừng không tự cô lập được. Trả mảng bool theo đơn vị, hoặc None nếu mô hình không có kiểm tra miền."""
    j = m.get("guard_idx")
    if not j: return None
    X = np.asarray(V, float).reshape(len(V), -1)
    return (np.abs(X[:, j] - m["guard_val"]) > 1e-12).any(1)


def _severity(score, thr):
    """'high'/'medium' theo vị trí của điểm trên ngưỡng riêng của engine (xem giải thích ở _emit)."""
    if thr is not None and thr < 1.0:
        return "high" if (score - thr) / (1.0 - thr) >= 0.15 else "medium"
    return "high" if score >= 0.70 else "medium"   # dự phòng khi engine không truyền ngưỡng


def _emit(alert):
    """In gọn và ghi một cảnh báo JSON vào ALERT_LOG. Thêm why (các đặc trưng lệch xa nhất) và severity: 'high' khi
    (score - thr) / (1 - thr) >= 0.15, tức đã đi 15% quãng từ ngưỡng của engine tới 1. Ngưỡng không ghi ra JSON."""
    why = ", ".join(f"{f}({z:+.1f})" for f, z in alert.get("reasons", []))
    alert["why"] = why
    alert.pop("reasons", None)  # không ghi mảng lồng [tên, z]: OpenSearch xung đột kiểu field
    thr = alert.pop("thr", None)
    alert["severity"] = _severity(alert.get("score", 0) or 0, thr)
    # srcip/dstip theo quy ước Wazuh, cho <same_source_ip> và Active Response.
    if "src_ip" in alert:  alert["srcip"] = alert.pop("src_ip")
    if "dest_ip" in alert: alert["dstip"] = alert.pop("dest_ip")
    print(f"🚨 [{alert['module']}] {alert.get('srcip')} → {alert.get('dstip') or alert.get('host') or ''} "
          f"score={alert['score']:.3f} ({alert.get('location','')})" + (f" vì {why}" if why else ""), flush=True)
    with open(ALERT_LOG, "a") as f:
        f.write(json.dumps(alert, ensure_ascii=False) + "\n")
