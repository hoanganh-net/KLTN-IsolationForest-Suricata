"""web.py — Web-App IF trên bản ghi http (query + body, chính sách thẻ HTML). Tách từ anomaly.py, logic nguyên vẹn."""
import sys, os, json, math, time, re, gzip, ipaddress, collections, types, threading, base64, html
from datetime import datetime
from urllib.parse import unquote_plus, urlsplit, parse_qsl
import numpy as np
from common import (_emit, _load_web, _ngoai_mien, _open, _score, _thr_q, _tail_lines, _tail_start, explain)


# Engine web chỉ chấm http đi vào máy chủ được bảo vệ (WEB_TARGETS: IP/CIDR; rỗng là chấm mọi http).
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


# Thời gian phát hiện của Web-App IF: giờ phát cảnh báo trừ lúc Suricata ghi nhận request (cùng đồng hồ Suricata_IDS).
_TZ_WEB = re.compile(r"([+-]\d{2})(\d{2})$")
def _epoch_web(ts):
    if not ts: return None
    s = str(ts)
    try: return datetime.fromisoformat(s).timestamp()
    except ValueError:
        try: return datetime.fromisoformat(_TZ_WEB.sub(r"\1:\2", s)).timestamp()
        except ValueError: return None
def _web_time(req_ts):
    """Trường thời gian kèm cảnh báo web: thời điểm request (req_time) và độ trễ phát hiện (lat_s) khi chạy live."""
    out = {}
    if req_ts: out["req_time"] = req_ts
    ep = _epoch_web(req_ts)
    if ep is not None:
        lat = round(time.time() - ep, 1)
        if 0 <= lat <= 3600: out["lat_s"] = lat
    return out


# Thẻ định dạng được phép trong văn bản tự do theo chính sách của ứng dụng (mặc định kses.php của WordPress, joblib
# ghi đè được). Đây là chính sách của ứng dụng, không phải chữ ký tấn công.
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


# ---- Web-App IF: bản ghi http (Web-Query cho tham số và trường ngắn POST, Web-Body cho văn bản tự do) ----
def _build_web(model_path="web_app_if_model.joblib"):
    FEATS = ["log_len", "r_nonalnum", "r_digit", "r_upper", "entropy", "n_squote", "n_dquote",
             "n_angle", "n_paren", "n_punct_inj", "n_kw", "n_pct", "max_run_sym", "n_slash"]
    # Tên trường văn bản tự do của ứng dụng được bảo vệ (WordPress, DVWA), luôn chấm bằng Web-Body.
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
                float(len(_KW.findall(s))), float(len(_PCT.findall(s))), float(_max_run_symbol(s)),
                float(s.count("/") + s.count("\\"))]

    def decode_once(s):
        # Byte 0 (%00 sau khi giải mã) ghi lại thành chữ %00, giống bộ dữ liệu huấn luyện
        try: return unquote_plus(s).replace("\x00", "%00")
        except Exception: return s

    def is_plain_path(v):
        return bool(_PATH_RE.match(v)) and ".." not in v

    def la_url_hop_le(v):
        # URL http(s) hợp lệ: tên máy hợp lệ, đường dẫn trơn hoặc rỗng, không có phần mảnh '#'.
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

    _XML_BODY  = re.compile(r"(?:<\?xml\b|<\s*(?:methodCall|methodResponse)\b|<\s*[\w.-]+:Envelope\b)", re.I)
    _XML_CDATA = re.compile(r"<!\[CDATA\[(.*?)\]\]>", re.S)
    _XML_SKIP  = re.compile(r"<!--.*?-->|<\?.*?\?>|<!DOCTYPE[^>]*>", re.S | re.I)
    _XML_LEAF  = re.compile(r"<([A-Za-z_][\w.:-]*)[^<>]*>([^<]+)")

    def _xml_text_leaves(s, max_leaves=200):
        """Thân XML (XML-RPC, SOAP) -> [(tên thẻ chứa, chuỗi văn bản)], đã giải mã thực thể, bỏ chuỗi chỉ có khoảng trắng.
        Dùng biểu thức chính quy thay cho bộ phân tích XML để không phải xử lý thực thể ngoài hay khai báo DOCTYPE."""
        out = [("cdata", c) for c in _XML_CDATA.findall(s) if c.strip()]
        s = _XML_SKIP.sub("", _XML_CDATA.sub("", s))
        for mt in _XML_LEAF.finditer(s):
            v = html.unescape(mt.group(2)).strip()
            if v: out.append((mt.group(1).split(":")[-1], v))
            if len(out) >= max_leaves: break
        return out[:max_leaves]

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
            # Tách thân như khi trích dữ liệu huấn luyện: multipart, JSON giữ nguyên; biểu mẫu giải mã như chuỗi truy vấn.
            bs = body.strip()
            mp = _multipart_fields(bs)
            if mp is not None:
                for k, v in mp:
                    if v: units.append((f"body:{k}", v.replace("\x00", "%00")))
            elif bs[:1] in "{[":
                for lab, v in _json_string_leaves(bs): units.append((f"body:{lab}", v.replace("\x00", "%00")))
            elif _XML_BODY.match(bs):
                # Thân XML: chấm từng chuỗi văn bản như trường ngắn (bộ dữ liệu không có thân XML).
                for lab, v in _xml_text_leaves(bs): units.append((f"body:{lab}", v.replace("\x00", "%00")))
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
    # Event http mang query (Web-Query); thân POST chỉ có trong event alert khi bật http-body (Web-Body), nên query
    # của POST không bị chấm trùng.
    def _decode_body(h):
        # Ưu tiên http_request_body (base64, giữ đúng UTF-8); bản printable thay byte ngoài ASCII bằng '.', chỉ để dự phòng.
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
        """Định tuyến theo loại giá trị: tham số truy vấn và trường ngắn của thân POST chấm bằng Web-Query IF (mq);
        văn bản tự do (xác định theo tên trường) bỏ thẻ định dạng được phép rồi chấm bằng Web-Body IF (mb), các đoạn còn lại
        trông như thẻ HTML chấm bằng Web-Query IF. Trường ngắn có giá trị đã biết thì bỏ qua. Giá trị bị gắn cờ khi có đơn vị
        vượt ngưỡng của mô hình chấm nó; cảnh báo lấy đơn vị vượt xa nhất."""
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
                    if mb.get("allowed_tags"):  # bỏ thẻ định dạng được phép trước khi chấm
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
                # Một POST khớp nhiều luật sinh nhiều alert cùng thân: mỗi giao dịch chỉ chấm một lần cho mỗi nguồn.
                tx = (o.get("flow_id"), o.get("tx_id"), "alert" if is_alert else "http")
                co_khoa = tx[0] is not None and tx[1] is not None
                if co_khoa and tx in done: continue
                if is_http:                                        # event http: chỉ query (GET + query POST)
                    rec = {"src_ip": o.get("src_ip"), "dest_ip": o.get("dest_ip"), "dest_port": o.get("dest_port"),
                           "host": h.get("hostname"), "method": h.get("http_method"), "url": h.get("url"), "body": None}
                else:                                              # event alert: chỉ thân POST (base64, dự phòng bản printable)
                    body = _decode_body(h)
                    if not body: continue                          # alert chưa mang thân: alert sau của cùng giao dịch vẫn được xét
                    ep = urlsplit(h.get("url")).path if h.get("url") else None  # giữ endpoint để hiển thị, bỏ query (tránh chấm trùng)
                    rec = {"src_ip": o.get("src_ip"), "dest_ip": o.get("dest_ip"), "dest_port": o.get("dest_port"),
                           "host": h.get("hostname"), "method": h.get("http_method"), "url": ep, "body": body}
                if co_khoa:
                    done[tx] = None
                    if len(done) > 100000: done.popitem(last=False)
                if not _in_web_targets(rec["dest_ip"]): continue   # chỉ chấm http đi vào web server bảo vệ
                wt = _web_time(o.get("timestamp"))                 # thời điểm request + độ trễ phát hiện
                for module, lab, sc, reasons, thr, oor in _route_and_score(rec, mq, mb):
                    _emit({"module": module, "time": datetime.now().isoformat(timespec="seconds"),
                           "src_ip": rec["src_ip"], "dest_ip": rec["dest_ip"], "host": rec["host"],
                           "method": rec["method"], "url": rec["url"], "location": lab, "score": sc,
                           "thr": thr, "reasons": reasons, **wt, **({"out_of_range": oor} if oor else {})})
            time.sleep(iv)

    return types.SimpleNamespace(detect=detect, live=live)
