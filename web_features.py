# -*- coding: utf-8 -*-
"""
web_features.py: tách đơn vị, đặc trưng từ vựng, kiểm tra miền, huấn luyện và chọn ngưỡng của Web-App IF.
Module không giữ trạng thái: td (tri thức học từ tập huấn luyện), mod (hai mô hình), sel (ngưỡng) do notebook truyền vào.
"""

import collections
import html
import math
import re
from urllib.parse import parse_qsl, unquote_plus, urlsplit

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest as SkIF

from isolationforest import IsolationForest

# 1. Đặc trưng từ vựng của một đơn vị (chuỗi)
FEATS = ["log_len", "r_nonalnum", "r_digit", "r_upper", "entropy", "n_squote", "n_dquote",
         "n_angle", "n_paren", "n_punct_inj", "n_kw", "n_pct", "max_run_sym"]
# Rừng học trên 11 cột; n_angle và n_pct chỉ dùng để diễn giải và kiểm tra miền
FEATS_Q = ["log_len", "r_nonalnum", "r_digit", "r_upper", "entropy", "n_squote", "n_dquote",
           "n_paren", "n_punct_inj", "n_kw", "max_run_sym"]
FEATS_B = list(FEATS_Q)          # Web-Body IF dùng cùng 11 cột
IDX = {"q": [FEATS.index(f) for f in FEATS_Q], "b": [FEATS.index(f) for f in FEATS_B]}

_KW = re.compile(
    r"(?:\b(?:select|union|insert|update|delete|drop|from|where|or|and|exec|"
    r"char|concat|benchmark|sleep|script|alert|onerror|onload|iframe|eval|"
    r"javascript|cmd|etc|passwd|boot\.ini)\b)|(?:--)|(?:/\*)|(?:\.\.[\\/])|(?:<\s*/?\s*\w)",
    re.IGNORECASE)
_PCT = re.compile(r"%[0-9a-fA-F]{2}")
_INJ = set(";|&`$\\{}")


def _entropy(s):
    if not s:
        return 0.0
    n = len(s)
    return float(-sum((c / n) * math.log2(c / n) for c in collections.Counter(s).values()))


def _max_run_symbol(s):
    best = cur = 0
    for ch in s:
        if ch.isalnum():
            cur = 0
        else:
            cur += 1
            best = max(best, cur)
    return best


def feature_vector(s):
    n = len(s)
    if n == 0:
        return [0.0] * len(FEATS)
    nonalnum = sum(1 for ch in s if not ch.isalnum())
    digit = sum(1 for ch in s if ch.isdigit())
    upper = sum(1 for ch in s if ch.isupper())
    return [math.log1p(n), nonalnum / n, digit / n, upper / n, _entropy(s),
            float(s.count("'")), float(s.count('"')), float(s.count("<") + s.count(">")),
            float(s.count("(") + s.count(")")), float(sum(s.count(c) for c in _INJ)),
            float(len(_KW.findall(s))), float(len(_PCT.findall(s))), float(_max_run_symbol(s))]


_cache = {}      # đệm đặc trưng theo chuỗi


def fv(u):
    if u not in _cache:
        _cache[u] = feature_vector(u)
    return _cache[u]


def ma_tran(units):
    """Ma trận đặc trưng (số đơn vị x 13 cột) của một danh sách đơn vị."""
    return np.array([fv(u) for u in units], float).reshape(len(units), len(FEATS))


# 2. Tách giá trị tham số thành đơn vị
FREE_FIELDS = {"your-message", "content", "comment", "your-subject", "title", "message", "body", "mtxMessage"}

_TAG = re.compile(r"</?[a-zA-Z][^<>]{0,300}>|\bon[a-zA-Z]{2,}\s*=\s*\S+", re.IGNORECASE)
TAG_PATTERN = _TAG.pattern       # lưu vào tệp mô hình cho anomaly.py
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_HOST_RE = re.compile(r"^[A-Za-z0-9.-]+(?::\d{1,5})?$")
_PATH_RE = re.compile(r"^/[A-Za-z0-9/_\-.]*$")


def decode_once(s):
    try:
        return unquote_plus(s).replace("\x00", "%00")
    except Exception:
        return s


def is_plain_path(v):
    return bool(_PATH_RE.match(v)) and ".." not in v


def la_url_hop_le(v):
    """URL http(s) có tên máy hợp lệ, đường dẫn trơn hoặc rỗng, không có phần '#'."""
    if not _URL_RE.match(v) or "#" in v:
        return False
    try:
        u = urlsplit(v)
    except ValueError:
        return False
    return bool(_HOST_RE.match(u.netloc)) and (u.path == "" or is_plain_path(u.path))


def expand_value(v, known_paths=()):
    """Các đơn vị của một giá trị tham số."""
    if la_url_hop_le(v):
        return [decode_once(x) for _, x in parse_qsl(urlsplit(v).query, keep_blank_values=True) if x]
    if v in known_paths and is_plain_path(v):
        return []
    return [v]


def the(s):
    """Các đoạn trông như thẻ HTML hoặc thuộc tính sự kiện trong văn bản tự do."""
    return _TAG.findall(s)


# Thẻ định dạng WordPress cho phép trong bình luận: $allowedtags và wp_allowed_protocols()
ALLOWED_TAGS = {"a": ["href", "title"], "abbr": ["title"], "acronym": ["title"], "b": [], "blockquote": ["cite"],
                "cite": [], "code": [], "del": ["datetime"], "em": [], "i": [], "q": ["cite"], "s": [], "strike": [],
                "strong": []}
ALLOWED_PROTOCOLS = ["http", "https", "ftp", "ftps", "mailto", "news", "irc", "irc6", "ircs", "gopher", "nntp", "feed",
                     "telnet", "mms", "rtsp", "sms", "svn", "tel", "fax", "xmpp", "webcal", "urn"]
_URI_ATTRS = {"href", "cite"}
_TAG_FULL = re.compile(r"<(/?)([a-zA-Z][a-zA-Z0-9]*)([^<>]*)>")
_ATTR = re.compile(r'\s*([a-zA-Z][-a-zA-Z0-9_:.]*)(?:\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s"\'=<>`]+)))?')
_OPEN = re.compile(r"<[a-zA-Z/!?]")


def _uri_ok(v):
    v = re.sub(r"[\x00-\x20\x7f]", "", html.unescape(v)).lower()
    head = re.split(r"[/?#]", v, maxsplit=1)[0]
    return ":" not in head or head.split(":", 1)[0] in ALLOWED_PROTOCOLS


def the_duoc_phep(m):
    """Thẻ có tên, mọi thuộc tính và giao thức liên kết đều nằm trong chính sách."""
    close, name, rest = m.group(1), m.group(2).lower(), m.group(3)
    if name not in ALLOWED_TAGS:
        return False
    if close:
        return rest.strip() == ""
    rest = rest.rstrip()
    if rest.endswith("/"):
        rest = rest[:-1]
    pos = 0
    while pos < len(rest):
        a = _ATTR.match(rest, pos)
        if not a or a.end() == pos:
            return False
        key = a.group(1).lower()
        val = next((g for g in a.group(2, 3, 4) if g is not None), None)
        if key not in ALLOWED_TAGS[name]:
            return False
        if key in _URI_ATTRS and (val is None or not _uri_ok(val)):
            return False
        pos = a.end()
    return True


def trong_the_chua_dong(s, i):
    """Vị trí i nằm sau một dấu < mở thẻ chưa đóng, nên trình duyệt coi là một phần của thẻ trước."""
    return _OPEN.search(s, s.rfind(">", 0, i) + 1, i) is not None


def bo_the_duoc_phep(s):
    """Bỏ phần đánh dấu của thẻ được phép, giữ chữ bên trong; thẻ khác giữ nguyên để được chấm."""
    def thay(m):
        return "" if the_duoc_phep(m) and not trong_the_chua_dong(s, m.start()) else m.group(0)
    return _TAG_FULL.sub(thay, s)


def is_free(field, v):
    """Trường văn bản tự do, chỉ xét theo tên trường."""
    return field in FREE_FIELDS


def don_vi(field, value, method, td):
    """(mô hình phụ trách, [(mô hình, đơn vị), ...]); 'q' là Web-Query IF, 'b' là Web-Body IF."""
    if method == "POST" and is_free(field, value):
        v = bo_the_duoc_phep(value)
        return "b", [("b", v)] + [("q", t) for t in the(v)]
    if method == "POST" and value in td["known_values"].get(field, ()):
        return "q", []
    return "q", [("q", u) for u in expand_value(value, td["known_paths"])]


# 3. Tri thức học từ tập huấn luyện
ENUM_MAX, ENUM_MIN = 10, 100     # trường ngắn có không quá 10 giá trị và xuất hiện ít nhất 100 lần


def duong_dan_da_biet(train_G):
    """Đường dẫn trơn đã thấy trong giá trị GET huấn luyện (không chấm)."""
    return sorted({v for v in train_G["value"] if is_plain_path(v)})


def gia_tri_da_biet(train_P, enum_max=ENUM_MAX, enum_min=ENUM_MIN):
    """Trường ngắn POST có tập giá trị nhỏ và ổn định: {trường: tập giá trị} (không chấm)."""
    ngan = train_P[~train_P["field"].isin(FREE_FIELDS)]
    thong_ke = ngan.groupby("field")["value"].agg(["nunique", "size"])
    it_gia_tri = thong_ke.index[(thong_ke["nunique"] <= enum_max) & (thong_ke["size"] >= enum_min)]
    return {f: set(ngan.loc[ngan["field"] == f, "value"]) for f in it_gia_tri}


def don_vi_huan_luyen(train_G, train_P, known_paths):
    """Đơn vị huấn luyện của Web-Query IF (giá trị GET) và Web-Body IF (văn bản tự do của POST)."""
    Uq = [u for v in train_G["value"] for u in expand_value(v, known_paths)]
    Ub = [v for f, v in zip(train_P["field"], train_P["value"]) if is_free(f, v)]
    return Uq, Ub


def dac_trung_hang(Xq, bat=True):
    """Đặc trưng hằng của Web-Query IF trên tập huấn luyện và giá trị hằng (cho kiểm tra miền)."""
    hang = [j for j in range(len(FEATS)) if np.ptp(Xq[:, j]) == 0] if bat else []
    gia_tri = Xq[0, hang] if hang else np.empty(0)
    return hang, gia_tri


# 4. Kiểm tra miền
def ngoai_mien(X, td):
    """Đơn vị có đặc trưng hằng (ở tập huấn luyện Web-Query) khác giá trị hằng đó."""
    X = np.asarray(X, float).reshape(-1, len(FEATS))
    if not td["hang_q"]:
        return np.zeros(len(X), bool)
    return (np.abs(X[:, td["hang_q"]] - td["gt_hang_q"]) > 1e-12).any(1)


def kiem_mien(field, value, method, td):
    """Chỉ kiểm tra miền cho giá trị tham số, không cho văn bản tự do."""
    return bool(td["hang_q"]) and not (method == "POST" and is_free(field, value))


# 5. Chia dữ liệu
def chia(df, train_frac, seed, pub_sources):
    """Gán 'train' hoặc 'val' cho từng dòng."""
    part = pd.Series("train", index=df.index)
    real = df["source"] == "real_wp"
    t = pd.to_datetime(df.loc[real, "ts"], format="ISO8601")
    part[t.index[t >= t.quantile(train_frac)]] = "val"
    rng = np.random.default_rng(seed)
    nguon = sorted(set(df["source"]) - {"real_wp"}, key=lambda s: (s in pub_sources, s))   # nguồn lab trước
    for s in nguon:
        idx = df.index[df["source"] == s]
        so_val = int(round((1 - train_frac) * len(idx)))
        part[idx[rng.permutation(len(idx))[:so_val]]] = "val"
    return part


def mien(df, pub_sources):
    """Miền của giá trị kiểm định: CSIC (ứng dụng khác) hoặc lab."""
    return np.where(df["source"].isin(pub_sources), "CSIC", "lab")


# 6. Huấn luyện và chấm điểm
def fit_model(X, idx, n_trees, max_samples, seed):
    """Học một mô hình trên X (đủ 13 cột); rừng chỉ nhận các cột idx đã chuẩn hóa."""
    mu = X.mean(0)
    sd = X.std(0)
    sd = np.where(sd < 1e-9, 1.0, sd)
    Z = ((X - mu) / sd)[:, idx]
    own = IsolationForest(n_estimators=n_trees, max_samples=max_samples, random_state=seed).fit(Z)
    sk = SkIF(n_estimators=n_trees, max_samples=min(max_samples, len(Z)), random_state=seed).fit(Z)
    med = np.median(X, 0)
    mad = np.median(np.abs(X - med), 0)
    scale = np.where(mad > 1e-9, 1.4826 * mad, sd)
    return {"own": own, "sk": sk, "mu": mu, "sd": sd, "idx": list(idx), "med": med, "scale": scale,
            "s_tr": own.anomaly_score(Z), "s_sk": -sk.score_samples(Z)}


def diem(m, X, which="own"):
    """Điểm bất thường của các đơn vị X theo mô hình m; which='own' là bản tự cài, 'sk' là scikit-learn."""
    if len(X) == 0:
        return np.empty(0)
    Z = ((np.asarray(X, float) - m["mu"]) / m["sd"])[:, m["idx"]]
    if which == "own":
        return m["own"].anomaly_score(Z)
    return -m["sk"].score_samples(Z)


def diem_gia_tri(df, mod, td, which="own", method="GET"):
    """Điểm cao nhất của mỗi giá trị theo từng mô hình (-1 nếu không có đơn vị) và mô hình phụ trách.
    S["q_rung"] là điểm Web-Query khi chỉ dùng rừng, không kiểm tra miền."""
    S = {"q": np.full(len(df), -1.0), "b": np.full(len(df), -1.0), "q_rung": np.full(len(df), -1.0)}
    mo_hinh = np.empty(len(df), object)
    gom = {"q": ([], [], []), "b": ([], [], [])}          # chỉ số giá trị, đơn vị, có kiểm tra miền
    for i, (f, v) in enumerate(zip(df["field"], df["value"])):
        mo_hinh[i], cac_don_vi = don_vi(f, v, method, td)
        km = kiem_mien(f, v, method, td)
        for m, u in cac_don_vi:
            gom[m][0].append(i)
            gom[m][1].append(u)
            gom[m][2].append(km and m == "q")
    for m, (ii, us, kk) in gom.items():
        if not ii:
            continue
        X = ma_tran(us)
        s = diem(mod[m], X, which)
        ii, kk = np.array(ii), np.array(kk, bool)
        if m == "q":
            np.maximum.at(S["q_rung"], ii, s)
        if kk.any():
            s = np.where(kk & ngoai_mien(X, td), 1.0, s)
        np.maximum.at(S[m], ii, s)
    return S, mo_hinh


def vuot_nguong(S, sel, which="own"):
    """Giá trị bị gắn cờ khi có đơn vị vượt ngưỡng của chính mô hình chấm nó."""
    k = "thr" if which == "own" else "thr_sk"
    return (S["q"] > sel["q"][k]) | (S["b"] > sel["b"][k])


def do_vuot(S, sel, which="own"):
    """Điểm trừ ngưỡng của mô hình chấm, lấy lớn nhất trên hai mô hình; lớn hơn 0 nghĩa là bị gắn cờ."""
    k = "thr" if which == "own" else "thr_sk"
    q = np.where(S["q"] >= 0, S["q"] - sel["q"][k], -np.inf)
    b = np.where(S["b"] >= 0, S["b"] - sel["b"][k], -np.inf)
    return np.maximum(q, b)


def nguon_yeu_cau(x):
    """Nguồn của một yêu cầu: lab_attack được ưu tiên hơn lab_manual."""
    if (x == "lab_attack").any():
        return "lab_attack"
    return next((v for v in x if v.startswith("lab")), x.iloc[0])


def cham_yeu_cau(df, method, mod, td, sel, which="own"):
    """Chấm từng giá trị rồi gộp theo yêu cầu (req_id)."""
    S, md = diem_gia_tri(df, mod, td, which, method)
    k = "thr" if which == "own" else "thr_sk"
    d = df.assign(s=np.maximum(S["q"], S["b"]), m=do_vuot(S, sel, which), mo_hinh=md,
                  vuot=vuot_nguong(S, sel, which),
                  vuot_rung=(S["q_rung"] > sel["q"][k]) | (S["b"] > sel["b"][k]))
    return d.groupby("req_id").agg(label=("label", "first"), source=("source", nguon_yeu_cau),
                                   attack_type=("attack_type", lambda x: next((v for v in x if v), "")),
                                   vuot=("vuot", "any"), vuot_rung=("vuot_rung", "any"),
                                   s=("s", "max"), m=("m", "max"))


def don_vi_noi_bat(rows, method, mod, td, sel):
    """(độ vượt ngưỡng, mô hình, trường, đơn vị) của đơn vị nổi bật nhất trong một yêu cầu."""
    out = []
    for f, v in zip(rows["field"], rows["value"]):
        km = kiem_mien(f, v, method, td)
        for m, u in don_vi(f, v, method, td)[1]:
            X = ma_tran([u])
            s = 1.0 if (km and m == "q" and ngoai_mien(X, td)[0]) else diem(mod[m], X)[0]
            out.append((s - sel[m]["thr"], m, f, u))
    return max(out)


# 7. Chọn ngưỡng trên tập kiểm định
def chon_nguong(model, s_val, d_val, q_grid, fpr_max, truong_ngan=None):
    """Bảng lưới SCORE_Q và ngưỡng chọn được; None nếu không nấc nào đạt fpr_max ở mọi miền."""
    cac_mien = sorted(set(d_val))
    rows = []
    for q in q_grid:
        thr = float(np.quantile(model["s_tr"], 1 - q))
        r = {"SCORE_Q": q, "Ngưỡng": round(thr, 4), "FPR kiểm định (%)": round(100 * (s_val > thr).mean(), 3)}
        if len(cac_mien) > 1:
            for dm in cac_mien:
                r[f"FPR {dm} (%)"] = round(100 * (s_val[d_val == dm] > thr).mean(), 3)
        if truong_ngan is not None:
            r["FPR trường ngắn POST (%)"] = round(100 * (truong_ngan > thr).mean(), 3)
        rows.append(r)
    T = pd.DataFrame(rows)
    cot = [f"FPR {dm} (%)" for dm in cac_mien] if len(cac_mien) > 1 else ["FPR kiểm định (%)"]
    dat = T[(T[cot] <= 100 * fpr_max).all(axis=1)]
    if not len(dat):
        return T, None
    q = float(dat["SCORE_Q"].max())
    return T, {"q": q, "thr": float(np.quantile(model["s_tr"], 1 - q)),
               "thr_sk": float(np.quantile(model["s_sk"], 1 - q))}
