# -*- coding: utf-8 -*-
"""behavior_features.py: cửa sổ cặp máy, đặc trưng hành vi, huấn luyện, chọn ngưỡng và đếm cảnh báo của Behavior-IF.
Module không giữ trạng thái: bảng độ hiếm, tham chiếu và ngưỡng do notebook truyền vào. Tầng 2 dùng cửa sổ 30 phút
trượt 15 phút và các cột FEATS_IF; Tầng 1 (mục 8) dùng cửa sổ 2 phút, chấm theo thời điểm luồng tới engine và các cột
FEATS_RT."""

import math

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest as SkIF

from isolationforest import IsolationForest

# 1. Đọc bản ghi flow
COLS = ["start", "end", "src", "dst", "dport", "proto", "bytes_toserver", "bytes_toclient",
        "tcp_state", "direction", "peer_zone"]
DT = {"proto": str, "tcp_state": str}
EPOCH0 = pd.Timestamp("1970-01-01", tz="UTC")


def epoch(s):
    """Chuỗi thời gian ISO 8601 thành giây kể từ 1970 (UTC)."""
    return (pd.to_datetime(s, format="ISO8601", utc=True) - EPOCH0).dt.total_seconds().values


def doc_luong(path, cols, path_tre):
    """Đọc tệp luồng kèm tệp thời điểm tới cùng thứ tự dòng (kiểm khớp theo flow_id), thêm cột _toi và _ghi (giây). Trả
    (bảng luồng, bảng thu_tu, ghi_us, toi_us của các dòng lab) để dựng gio_that."""
    F = pd.read_csv(path, usecols=cols + ["flow_id"], dtype={**DT, "flow_id": "uint64"}, keep_default_na=False)
    A = pd.read_csv(path_tre, dtype={"flow_id": "UInt64", "thu_tu": "Int64", "ghi_us": "Int64", "toi_us": "Int64"})
    co = A["toi_us"].notna().to_numpy()
    assert len(A) == len(F) and (A["flow_id"][co].to_numpy("uint64") == F["flow_id"].to_numpy()[co]).all(), \
        f"{path_tre} không khớp dòng với {path}"
    F["_toi"] = A["toi_us"].to_numpy("float64", na_value=np.nan) / 1e6
    F["_ghi"] = A["ghi_us"].to_numpy("float64", na_value=np.nan) / 1e6
    return F, A.loc[co, ["thu_tu", "ghi_us", "toi_us"]]


# 2. Độ hiếm dịch vụ
def svc_keys(d):
    """Khóa dịch vụ: chiều|vùng đầu kia|giao thức|cổng."""
    return d["direction"] + "|" + d["peer_zone"] + "|" + d["proto"].str.upper() + "|" + d["dport"].astype(str)


def rarity_of(key, rar_counts, rar_total):
    """Độ hiếm của một khóa dịch vụ, tính trên bảng đếm của tập huấn luyện."""
    return -math.log10((rar_counts.get(key, 0) + 1) / (rar_total + 1))


def rar_of(d, rar_counts, rar_total):
    """Độ hiếm dịch vụ của từng luồng."""
    keys = svc_keys(d)
    table = {k: rarity_of(k, rar_counts, rar_total) for k in keys.unique()}
    return keys.map(table).to_numpy(float)


# 3. Cửa sổ cặp máy và đặc trưng hành vi
WINDOW_MIN, WINDOW_HOP_MIN = 30, 15
INCOMPLETE = {"syn_sent", "syn_recv"}
FEATS = ["log_n_conn", "sqrt_mb_out", "log_bytes_in", "frac_out", "log_throughput",
         "log_peak_cpm", "periodicity", "uniformity", "log_n_ports", "frac_incomplete", "svc_rarity"]
FEATS_IF = ["sqrt_mb_out", "frac_out", "log_throughput", "log_peak_cpm",
            "periodicity", "uniformity", "log_n_ports", "svc_rarity"]
IDX_IF = [FEATS.index(f) for f in FEATS_IF]

# Tầng 1: cửa sổ 2 phút trượt 1 phút, chấm lại mỗi RT_STEP_S giây và báo ngay khi vượt ngưỡng; cửa sổ chốt sau
# cuối cửa sổ RT_DELAY_S giây (luồng chưa thiết lập hoặc đã đóng tới engine trong vòng 70 giây).
RT_WIN_MIN, RT_HOP_MIN, RT_DELAY_S, RT_STEP_S, RT_QUIET_S = 2, 1, 75, 10, 900
FEATS_RT = ["log_peak_cpm", "log_throughput", "log_n_ports", "frac_incomplete", "svc_rarity"]
IDX_RT = [FEATS.index(f) for f in FEATS_RT]
RT_CHOT = RT_WIN_MIN * 60 + RT_DELAY_S                       # lần chấm cuối, tính từ đầu cửa sổ (giây)
RT_TAUS = np.array(list(range(RT_STEP_S, RT_CHOT, RT_STEP_S)) + [RT_CHOT])


def _cv(x):
    """Hệ số biến thiên: độ lệch chuẩn / trung bình."""
    m = x.mean() if len(x) else 0.0
    return float(x.std() / m) if m > 0 else 0.0


def _peak_per_min(st):
    """Số kết nối nhiều nhất trong một khung 60 giây."""
    if len(st) == 0:
        return 0
    hi = np.searchsorted(st, st + 60.0, side="right")
    return int((hi - np.arange(len(st))).max())


def feature_vector(st, bts, btc, dur, dports, inc, rar):
    """11 đặc trưng của một cặp máy trong một cửa sổ; mỗi tham số là một mảng theo luồng."""
    order = np.argsort(st, kind="stable")
    st, bts, btc, dur = st[order], bts[order], btc[order], dur[order]
    n = len(st)
    byte_out, byte_in = float(bts.sum()), float(btc.sum())
    byte_all, dur_all = byte_out + byte_in, float(dur.sum())
    gaps = np.diff(st)
    v = {
        "log_n_conn": math.log1p(n),
        "sqrt_mb_out": math.sqrt(byte_out / 1e6),
        "log_bytes_in": math.log1p(byte_in),
        "frac_out": byte_out / byte_all if byte_all > 0 else 0.0,
        "log_throughput": math.log1p(byte_all / dur_all) if dur_all > 0 else 0.0,
        "log_peak_cpm": math.log1p(_peak_per_min(st)),
        "periodicity": math.log1p(len(gaps)) * max(0.0, 1.0 - _cv(gaps)) if len(gaps) >= 3 else 0.0,
        "uniformity": math.log1p(n - 1) * max(0.0, 1.0 - _cv(bts + btc)) if n >= 3 else 0.0,
        "log_n_ports": math.log1p(len(set(dports.tolist()))),
        "frac_incomplete": float(inc.mean()),
        "svc_rarity": float(rar.mean()),
    }
    return [v[f] for f in FEATS]


def windows(d, rar_counts, rar_total):
    """Gom luồng theo (bên khởi tạo, bên nhận, cửa sổ 30 phút) trên hai lưới lệch nhau 15 phút."""
    start, end = epoch(d["start"]), epoch(d["end"])
    cols = {"st": start,
            "bts": d["bytes_toserver"].to_numpy(float),
            "btc": d["bytes_toclient"].to_numpy(float),
            "dur": np.clip(end - start, 0, None),
            "dport": d["dport"].to_numpy(),
            "inc": d["tcp_state"].str.lower().isin(INCOMPLETE).to_numpy(float),
            "rar": rar_of(d, rar_counts, rar_total)}
    src, dst, dirn = d["src"].to_numpy(), d["dst"].to_numpy(), d["direction"].to_numpy()
    run = d["run_id"].to_numpy() if "run_id" in d else np.full(len(d), "", object)

    keys, feats = [], []
    for off in range(0, WINDOW_MIN * 60, WINDOW_HOP_MIN * 60):
        bucket = ((start - off) // (WINDOW_MIN * 60)).astype("int64")
        gid = pd.factorize(pd.MultiIndex.from_arrays([src, dst, bucket]))[0]
        order = np.argsort(gid, kind="stable")
        g = gid[order]
        lo = np.r_[0, np.flatnonzero(np.diff(g)) + 1]
        hi = np.r_[lo[1:], len(g)]
        for a, z in zip(lo, hi):
            ix = order[a:z]
            feats.append(feature_vector(*(cols[c][ix] for c in ("st", "bts", "btc", "dur", "dport", "inc", "rar"))))
            runs = sorted({r for r in run[ix] if r})
            keys.append((src[ix[0]], dst[ix[0]], dirn[ix[0]], int(bucket[ix[0]]), off, len(ix),
                         float(start[ix].min()), "|".join(runs)))

    K = pd.DataFrame(keys, columns=["src", "dst", "direction", "bucket", "off", "n_conn", "t0", "runs"])
    F = pd.DataFrame(np.array(feats, float).reshape(len(K), -1), columns=FEATS)
    return pd.concat([K, F], axis=1)


# 4. Huấn luyện tham chiếu và chấm điểm
def fit_ref(X, n_trees, max_samples, seed, idx=None):
    """Học một tham chiếu trên X (đủ 11 cột); rừng chỉ nhận các cột idx (mặc định FEATS_IF) đã chuẩn hóa."""
    idx = IDX_IF if idx is None else list(idx)
    mu = X.mean(0)
    sd = X.std(0)
    sd = np.where(sd < 1e-9, 1.0, sd)
    Z = ((X - mu) / sd)[:, idx]
    own = IsolationForest(n_estimators=n_trees, max_samples=max_samples, random_state=seed, n_jobs=-1).fit(Z)
    sk = SkIF(n_estimators=n_trees, max_samples=min(max_samples, len(Z)), random_state=seed).fit(Z)
    med = np.median(X, 0)
    mad = np.median(np.abs(X - med), 0)
    scale = np.where(mad > 1e-9, 1.4826 * mad, sd)
    return {"own": own, "sk": sk, "mu": mu, "sd": sd, "med": med, "scale": scale, "idx": idx,
            "s_tr": own.anomaly_score(Z), "s_sk": -sk.score_samples(Z)}


def score(ref, X, which="own"):
    Z = ((np.asarray(X, float) - ref["mu"]) / ref["sd"])[:, ref.get("idx", IDX_IF)]
    if which == "own":
        return ref["own"].anomaly_score(Z)
    return -ref["sk"].score_samples(Z)


# 5. Chọn ngưỡng trên tập kiểm định
def canh_bao(K, mask):
    """Số cảnh báo: mỗi (bên khởi tạo, bên nhận, khung 30 phút) có cửa sổ bị gắn cờ tính một lần."""
    k = K[np.asarray(mask, bool)]
    khung = (k["t0"] // (WINDOW_MIN * 60)).astype("int64")
    return len(set(zip(k["src"], k["dst"], khung)))


def chon_nguong(ref, V, q_grid, fpr_max):
    """Bảng lưới SCORE_Q, ngưỡng chọn được (None nếu không nấc nào đạt fpr_max) và số giờ kiểm định."""
    s_val = score(ref, V[FEATS].values)
    gio = (V["t0"].max() - V["t0"].min()) / 3600
    rows = []
    for q in q_grid:
        thr = float(np.quantile(ref["s_tr"], 1 - q))
        flag = s_val > thr
        rows.append({"SCORE_Q": q, "Ngưỡng": round(thr, 4), "FPR kiểm định (%)": round(100 * flag.mean(), 3),
                     "Cảnh báo nhầm/giờ": round(canh_bao(V, flag) / gio, 2)})
    T = pd.DataFrame(rows)
    dat = T[T["FPR kiểm định (%)"] <= 100 * fpr_max]
    if not len(dat):
        return T, None, gio
    q = float(dat["SCORE_Q"].max())
    return T, {"q": q, "thr": float(np.quantile(ref["s_tr"], 1 - q)),
               "thr_sk": float(np.quantile(ref["s_sk"], 1 - q))}, gio


# 6. Kiểm thử
def cham(XF, refs, sel, rar_counts, rar_total, dirs=("out", "in")):
    """Gom cửa sổ, chấm bằng tham chiếu của từng chiều và so với ngưỡng."""
    WT = pd.concat([windows(XF[XF["direction"] == d], rar_counts, rar_total) for d in dirs], ignore_index=True)
    WT["score"] = np.nan
    WT["score_sk"] = np.nan
    for d in dirs:
        m = (WT["direction"] == d).values
        WT.loc[m, "score"] = score(refs[d], WT.loc[m, FEATS].values)
        WT.loc[m, "score_sk"] = score(refs[d], WT.loc[m, FEATS].values, "sk")
    WT["thr"] = WT["direction"].map({d: sel[d]["thr"] for d in sel})
    WT["pred"] = WT["score"] > WT["thr"]
    WT["attack"] = WT["runs"] != ""
    return WT


def bang_ket_qua(WT, runs):
    """Recall theo hành vi, tính theo cửa sổ và theo lượt."""
    hit = {r for rs in WT.loc[WT["pred"], "runs"] for r in rs.split("|") if r}
    R = runs.assign(phat_hien=runs["run_id"].isin(hit))
    hanh_vi = dict(zip(runs["run_id"], runs["behavior"]))
    tc = WT[WT["attack"]].assign(behavior=lambda x: x["runs"].str.split("|").str[0].map(hanh_vi))
    B = tc.groupby("behavior").agg(cua_so=("pred", "size"), cua_so_bat=("pred", "sum"))
    B["phu_cua_so_%"] = (100 * B["cua_so_bat"] / B["cua_so"]).round(2)
    L = R.groupby("behavior").agg(luot=("phat_hien", "size"), luot_bat=("phat_hien", "sum"))
    B = B.join(L)
    B["phu_luot_%"] = (100 * B["luot_bat"] / B["luot"]).round(2)
    B.loc["TỔNG"] = [B["cua_so"].sum(), B["cua_so_bat"].sum(), round(100 * B["cua_so_bat"].sum() / B["cua_so"].sum(), 2),
                     B["luot"].sum(), B["luot_bat"].sum(), round(100 * B["luot_bat"].sum() / B["luot"].sum(), 2)]
    return B.astype({"cua_so": int, "cua_so_bat": int, "luot": int, "luot_bat": int}), R


def do_tre(WT, t_dau, win_min, delay_s):
    """Độ trễ phát hiện từng lượt (giây): lúc chấm cửa sổ bị gắn cờ sớm nhất có luồng của lượt (cuối cửa sổ cộng delay_s)
    trừ thời điểm bắt đầu luồng đầu tiên của lượt. t_dau: {run_id: giây}. Lượt không bị gắn cờ không có trong kết quả."""
    f = WT[WT["pred"] & WT["attack"]]
    t_cham = (f["bucket"] + 1) * win_min * 60 + f["off"] + delay_s
    som = {}
    for rs, t in zip(f["runs"], t_cham):
        for r in rs.split("|"):
            if r and (r not in som or t < som[r]):
                som[r] = t
    return pd.Series({r: som[r] - t_dau[r] for r in som if r in t_dau}, dtype=float)


# 7. Mật độ cảnh báo theo máy, đếm như anomaly.py phát cảnh báo
FLOW_DELAY_S = 360                                  # chấm cửa sổ khi đã đóng thêm 6 phút
EPISODE_QUIET_S, EPISODE_REMIND_S = 120 * 60, 360 * 60


def muc_uu_tien(Wx, ref, thr):
    """Đặc trưng lệch nhất (|z| > 1) và mức ưu tiên High/Medium của từng cửa sổ."""
    X = Wx[FEATS].values
    z = np.clip((X - ref["med"]) / np.where(ref["scale"] < 1e-9, 1.0, ref["scale"]), -50, 50)
    top = np.where(np.abs(z).max(1) > 1, np.array(FEATS)[np.argmax(np.abs(z), 1)], "")
    sev = np.where((Wx["score"] - thr) / (1 - thr) >= 0.15, "high", "medium")
    return Wx.assign(top=top, sev=sev)


def canh_bao_may(Wx, may="src"):
    """Cảnh báo phát cho các cửa sổ bị gắn cờ: khóa (máy, đích, bucket), gom theo sự cố của cặp máy;
    cột t_cb là thời điểm phát (cửa sổ đóng cộng FLOW_DELAY_S)."""
    f = Wx[Wx["pred"]].copy()
    f["ws"] = f["bucket"] * WINDOW_MIN * 60 + f["off"]
    f = f.sort_values(["ws", "off"], kind="stable").drop_duplicates(subset=[may, "dst", "bucket"])
    su_co, giu = {}, []
    for r in f.itertuples():
        cap, t = (getattr(r, may), r.dst), r.ws
        e = su_co.get(cap)
        if e is None or t - e["last"] > EPISODE_QUIET_S:          # mở sự cố mới
            su_co[cap] = {"last": t, "emit": t, "sev": r.sev, "tops": {r.top}}
            giu.append(True)
            continue
        e["last"] = max(e["last"], t)
        bao = ((r.sev == "high" and e["sev"] != "high") or (r.top and r.top not in e["tops"])
               or t - e["emit"] >= EPISODE_REMIND_S)
        e["tops"].add(r.top)
        if r.sev == "high":
            e["sev"] = "high"
        if bao:
            e["emit"] = t
        giu.append(bao)
    f = f[np.array(giu, bool)]
    return f.assign(t_cb=f["ws"] + WINDOW_MIN * 60 + FLOW_DELAY_S)


def nhieu_nhat(t, w):
    """Số cảnh báo nhiều nhất trong một khung trượt w giây."""
    t = np.sort(np.asarray(t, float))
    if len(t) == 0:
        return 0
    return int((np.searchsorted(t, t + w, side="right") - np.arange(len(t))).max())


def so_dot(t, n, w):
    """Số đợt đạt n cảnh báo trong khung trượt w giây; sau mỗi đợt bỏ qua w giây."""
    t = np.sort(np.asarray(t, float))
    dot, i, het = 0, 0, -np.inf
    for j in range(len(t)):
        while t[j] - t[i] > w:
            i += 1
        if j - i + 1 >= n and t[j] > het:
            dot += 1
            het = t[j] + w
    return dot


def lan_dau(t, n, w):
    """Thời điểm đầu tiên đạt n cảnh báo trong khung trượt w giây; None nếu không đạt."""
    t = np.sort(np.asarray(t, float))
    j = np.searchsorted(t, t - w, side="left")
    dat = np.flatnonzero(np.arange(len(t)) - j + 1 >= n)
    return float(t[dat[0]]) if len(dat) else None


# 8. Tầng 1: cảnh báo nhanh
def _nhom_mean_std(v, g, G):
    """Trung bình và độ lệch chuẩn (ddof=0) của v theo nhóm g (hai lượt để tránh sai số triệt tiêu)."""
    m = np.bincount(g, minlength=G).astype(float)
    s1 = np.bincount(g, weights=v, minlength=G)
    mean = np.divide(s1, m, out=np.zeros(G), where=m > 0)
    dev2 = np.bincount(g, weights=(v - mean[g]) ** 2, minlength=G)
    std = np.sqrt(np.divide(dev2, m, out=np.zeros(G), where=m > 0))
    return m, mean, std


def _mang_luong(d, rar_counts, rar_total):
    """Các mảng theo luồng dùng để dựng cửa sổ Tầng 1."""
    start, end = epoch(d["start"]), epoch(d["end"])
    M = {"start": start, "bts": d["bytes_toserver"].to_numpy(float), "btc": d["bytes_toclient"].to_numpy(float),
         "dur": np.clip(end - start, 0, None), "dport": d["dport"].to_numpy().astype("int64"),
         "inc": d["tcp_state"].str.lower().isin(INCOMPLETE).to_numpy(float), "rar": rar_of(d, rar_counts, rar_total),
         "src": d["src"].to_numpy(), "dst": d["dst"].to_numpy(), "dirn": d["direction"].to_numpy(),
         "run": d["run_id"].to_numpy() if "run_id" in d else np.full(len(d), "", object)}
    M["pair"] = pd.factorize(pd.MultiIndex.from_arrays([M["src"], M["dst"]]))[0]
    return M


def _cua_so_luoi(M, span, off, bucket, sel):
    """Đặc trưng các cửa sổ trên lưới lệch off giây, chỉ từ các luồng sel (chỉ số tăng dần)."""
    start, bts, btc, dport, run = M["start"], M["bts"], M["btc"], M["dport"], M["run"]
    gid = pd.factorize(pd.MultiIndex.from_arrays([M["pair"][sel], bucket[sel]]))[0]
    o = np.lexsort((start[sel], gid))
    ix, g = sel[o], gid[o]
    G = int(g.max()) + 1
    lo = np.r_[0, np.flatnonzero(np.diff(g)) + 1]
    cnt = np.diff(np.r_[lo, len(g)])
    st = start[ix]
    bo, bi = np.add.reduceat(bts[ix], lo), np.add.reduceat(btc[ix], lo)
    ds = np.add.reduceat(M["dur"][ix], lo)
    ba = bo + bi
    rel = st - np.repeat(st[lo], cnt)                         # đỉnh kết nối mỗi phút trong nhóm
    key = g * (span + 61.0) + rel
    c = np.searchsorted(key, key + 60.0, side="right") - np.arange(len(key))
    peak = np.maximum.reduceat(c, lo)
    same = np.r_[False, g[1:] == g[:-1]]                      # khoảng cách giữa hai lần bắt đầu liền kề trong nhóm
    gaps = np.diff(st, prepend=st[0])[same]
    mg, mean_g, std_g = _nhom_mean_std(gaps, g[same], G)
    cv_g = np.divide(std_g, mean_g, out=np.zeros(G), where=mean_g > 0)
    tot = bts[ix] + btc[ix]
    _, mean_t, std_t = _nhom_mean_std(tot, g, G)
    cv_t = np.divide(std_t, mean_t, out=np.zeros(G), where=mean_t > 0)
    nports = np.bincount(np.unique(g.astype("int64") * 70000 + dport[ix]) // 70000, minlength=G)
    F = pd.DataFrame({
        "log_n_conn": np.log1p(cnt),
        "sqrt_mb_out": np.sqrt(bo / 1e6),
        "log_bytes_in": np.log1p(bi),
        "frac_out": np.divide(bo, ba, out=np.zeros(G), where=ba > 0),
        "log_throughput": np.where(ds > 0, np.log1p(np.divide(ba, ds, out=np.zeros(G), where=ds > 0)), 0.0),
        "log_peak_cpm": np.log1p(peak),
        "periodicity": np.where(mg >= 3, np.log1p(mg) * np.maximum(0.0, 1.0 - cv_g), 0.0),
        "uniformity": np.where(cnt >= 3, np.log1p(cnt - 1) * np.maximum(0.0, 1.0 - cv_t), 0.0),
        "log_n_ports": np.log1p(nports),
        "frac_incomplete": np.add.reduceat(M["inc"][ix], lo) / cnt,
        "svc_rarity": np.add.reduceat(M["rar"][ix], lo) / cnt,
    })[FEATS]
    f0 = ix[lo]
    runs = np.full(G, "", object)
    has = np.flatnonzero(run[ix] != "")
    if len(has):
        rr = pd.DataFrame({"g": g[has], "r": run[ix][has]}).drop_duplicates().sort_values(["g", "r"])
        for gg, s in rr.groupby("g")["r"]:
            runs[gg] = "|".join(s)
    K = pd.DataFrame({"src": M["src"][f0], "dst": M["dst"][f0], "direction": M["dirn"][f0], "bucket": bucket[f0],
                      "off": off, "n_conn": cnt, "t0": st[lo], "runs": runs})
    return pd.concat([K, F], axis=1)


def windows_nhanh(d, rar_counts, rar_total, win_min=RT_WIN_MIN, hop_min=RT_HOP_MIN, arrival=None, delay_s=0):
    """Như windows() nhưng tính đặc trưng bằng phép toán mảng theo nhóm; kết quả trùng feature_vector tới sai số làm
    tròn. arrival, delay_s: chỉ giữ luồng tới không muộn hơn cuối cửa sổ cộng delay_s."""
    M = _mang_luong(d, rar_counts, rar_total)
    span = win_min * 60
    arr = None if arrival is None else np.asarray(arrival, float)
    parts = []
    for off in range(0, span, hop_min * 60):
        bucket = ((M["start"] - off) // span).astype("int64")
        sel = np.arange(len(bucket)) if arr is None else np.flatnonzero(arr <= (bucket + 1) * span + off + delay_s)
        if len(sel):
            parts.append(_cua_so_luoi(M, span, off, bucket, sel))
    return pd.concat(parts, ignore_index=True)


def top_dac_trung(Xw, med, scale, clip=50.0):
    """Đặc trưng lệch xa nhất, đúng như phần tử đầu của explain() trong anomaly.py: |z| lớn nhất theo z = (x - median)/thang,
    chặn ở clip, bằng nhau thì lấy đặc trưng đứng trước; trả chỉ số trong FEATS, -1 khi |z| lớn nhất không quá 1."""
    sc = np.where(np.asarray(scale, float) < 1e-9, 1.0, scale)
    z = np.clip((np.asarray(Xw, float) - med) / sc, -clip, clip)
    if not len(z):
        return np.empty(0, "int8")
    j = np.argmax(np.abs(z), axis=1)
    return np.where(np.abs(z[np.arange(len(z)), j]) > 1, j, -1).astype("int8")


def muc_do(score_, thr):
    """'high' khi điểm vượt ngưỡng từ 15% khoảng còn lại tới 1, như _severity() của anomaly.py; còn lại 'medium'."""
    return np.where((np.asarray(score_, float) - thr) / (1.0 - thr) >= 0.15, "high", "medium")


def chinh_sach(src, dst, ws, batch, sev, top, quiet=RT_QUIET_S):
    """Trạng thái báo của từng cửa sổ nổ theo _su_co_rt() của anomaly.py, theo thứ tự engine gặp (lần đọc rồi đầu
    cửa sổ): 'new', 'escalated', 'new_behavior', hoặc '' khi chỉ cộng dồn vào sự cố."""
    src, dst, ws, batch, sev, top = (np.asarray(a) for a in (src, dst, ws, batch, sev, top))
    st = np.full(len(ws), "", object)
    ep = {}
    for i in np.lexsort((ws, batch)):
        p = (src[i], dst[i])
        e = ep.get(p)
        if e is None or ws[i] - e["last"] > quiet:
            ep[p] = {"last": ws[i], "sev": sev[i], "tops": {top[i]}}
            st[i] = "new"
            continue
        e["last"] = max(e["last"], ws[i])
        if sev[i] == "high" and e["sev"] != "high":
            st[i] = "escalated"
        elif top[i] != -1 and top[i] not in e["tops"]:
            st[i] = "new_behavior"
        e["tops"].add(top[i])
        if sev[i] == "high":
            e["sev"] = "high"
    return st


KEY_RT = ["src", "dst", "bucket", "off"]


def quy_dao(D, ref, rar_counts, rar_total, taus=RT_TAUS):
    """Điểm scikit-learn và đặc trưng lệch nhất của mỗi cửa sổ Tầng 1 ở từng lần chấm tau (giây sau đầu cửa sổ), chỉ
    dùng luồng có _toi không muộn hơn đầu cửa sổ + tau. Mỗi lần chấm chỉ dựng và chấm lại các cửa sổ vừa có thêm luồng,
    cửa sổ khác giữ kết quả của lần chấm trước. Trả (khung cửa sổ, S, K); ô chưa có luồng: S là NaN, K là -1."""
    M = _mang_luong(D, rar_counts, rar_total)
    arr = D["_toi"].to_numpy(float)
    span, taus = RT_WIN_MIN * 60, np.asarray(taus)
    luoi = []
    for off in range(0, span, RT_HOP_MIN * 60):
        bucket = ((M["start"] - off) // span).astype("int64")
        j_toi = np.searchsorted(taus, arr - (bucket * span + off), side="left")     # lần chấm đầu tiên thấy luồng
        gid = pd.factorize(pd.MultiIndex.from_arrays([M["pair"], bucket]))[0]
        luoi.append((off, bucket, j_toi, gid))
    last = pd.concat([_cua_so_luoi(M, span, off, b, np.flatnonzero(j < len(taus))) for off, b, j, _ in luoi],
                     ignore_index=True)
    base = last[KEY_RT + ["direction", "t0", "runs"]].reset_index(drop=True)
    base["runs"] = base["runs"].fillna("")
    so = base[KEY_RT].assign(_r=np.arange(len(base)))
    S = np.full((len(base), len(taus)), np.nan)
    K = np.full((len(base), len(taus)), -1, "int8")
    for j in range(len(taus)):
        if j:
            S[:, j], K[:, j] = S[:, j - 1], K[:, j - 1]
        parts = []
        for off, bucket, j_toi, gid in luoi:
            doi = np.unique(gid[j_toi == j])
            if len(doi):
                parts.append(_cua_so_luoi(M, span, off, bucket, np.flatnonzero(np.isin(gid, doi) & (j_toi <= j))))
        if not parts:
            continue
        w = pd.concat(parts, ignore_index=True)
        r = w[KEY_RT].merge(so, on=KEY_RT, how="left")["_r"]
        assert r.notna().all(), "cửa sổ ở lần chấm sớm phải có ở lần chấm cuối"
        r = r.to_numpy(int)
        v = w[FEATS].values
        S[r, j] = score(ref, v, "sk")
        K[r, j] = top_dac_trung(v, ref["med"], ref["scale"])
    return base, S, K


def no_som(S, K, thr, taus=RT_TAUS):
    """Lần chấm đầu tiên điểm vượt ngưỡng của mỗi cửa sổ: (hàng, tau, điểm, mã đặc trưng lệch nhất)."""
    v = np.nan_to_num(S, nan=-1.0) > thr
    rows = np.flatnonzero(v.any(1))
    j = np.argmax(v[rows], axis=1)
    return rows, np.asarray(taus)[j], S[rows, j], K[rows, j]


def bao_rt(base, rows, tau, sc, top, thr, quiet_s=RT_QUIET_S):
    """Trạng thái báo của các cửa sổ nổ; cửa sổ nổ ở lần chấm cuối được engine xử lý ở lần đọc kế tiếp. Trả
    (trạng thái, đầu cửa sổ)."""
    span = RT_WIN_MIN * 60
    ws = (base["bucket"].to_numpy()[rows] * span + base["off"].to_numpy()[rows]).astype(float)
    batch = ws + np.where(tau == RT_CHOT, (RT_CHOT // RT_STEP_S + 1) * RT_STEP_S, tau)
    st = chinh_sach(base["src"].to_numpy()[rows], base["dst"].to_numpy()[rows], ws, batch, muc_do(sc, thr), top, quiet_s)
    return st, ws


def chon_nguong_rt(ref, base, S, K, q_grid, fa_max, quiet_s=RT_QUIET_S):
    """SCORE_Q lớn nhất có không quá fa_max cảnh báo nhầm mỗi giờ trên tập kiểm định, đếm đủ ba loại cảnh báo
    engine phát. Trả (bảng theo SCORE_Q, lựa chọn hoặc None, số giờ kiểm định)."""
    gio = (base["t0"].max() - base["t0"].min()) / 3600
    rows, sel = [], None
    for q in q_grid:
        t = float(np.quantile(ref["s_sk"], 1 - q))
        r, tau, sc, top = no_som(S, K, t)
        st, _ = bao_rt(base, r, tau, sc, top, t, quiet_s)
        n = pd.Series(st, dtype=object).value_counts()
        moi, tat_ca = int(n.get("new", 0)), int((st != "").sum())
        rows.append({"SCORE_Q": q, "Ngưỡng": round(t, 6), "Cửa sổ nổ": len(r), "Sự cố/giờ": round(moi / gio, 2),
                     "Cảnh báo nhầm/giờ": round(tat_ca / gio, 2), "Tăng mức độ": int(n.get("escalated", 0)),
                     "Đổi dạng": int(n.get("new_behavior", 0))})
        if tat_ca / gio <= fa_max:
            sel = {"q": q, "thr_sk": t, "fa_h": tat_ca / gio}
    return pd.DataFrame(rows), sel, gio


def kiem_thu_rt(Q, thr, t_dau, quiet_s=RT_QUIET_S):
    """Chạy một lần trên tập kiểm thử (Q = {chiều: (khung, S, K)}, thr = {chiều: ngưỡng}). Trả chỉ số cảnh báo
    nhầm theo chiều, độ trễ của từng lượt (lần nổ sớm nhất trừ t_dau, theo đồng hồ live) và số cảnh báo engine phát mỗi lượt."""
    chi_so, nho = {}, []
    for d, (base, S, K) in Q.items():
        r, tau, sc, top = no_som(S, K, thr[d])
        st, ws = bao_rt(base, r, tau, sc, top, thr[d], quiet_s)
        tc = base["runs"].to_numpy() != ""
        rn = ~tc[r]
        st_n, _ = bao_rt(base, r[rn], tau[rn], sc[rn], top[rn], thr[d], quiet_s)
        hl = base[~tc]
        g = (hl["t0"].max() - hl["t0"].min()) / 3600
        chi_so[d] = {"FPR (%)": round(100 * rn.sum() / len(hl), 3), "cảnh báo nhầm/giờ": round((st_n != "").sum() / g, 2),
                     "cửa sổ bình thường": len(hl), "giờ": round(g, 1)}
        ra = np.flatnonzero(tc[r])
        nho.append(pd.DataFrame({"runs": base["runs"].to_numpy()[r[ra]], "t_no": ws[ra] + tau[ra], "state": st[ra]}))
    A = pd.concat(nho, ignore_index=True)
    A = A.assign(run=A["runs"].str.split("|")).explode("run")
    A = A[A["run"] != ""]
    t_dau = pd.Series(t_dau, dtype=float)
    lat = A.groupby("run")["t_no"].min()
    lat = (lat - t_dau.reindex(lat.index)).dropna()
    n_bao = A[A["state"] != ""].groupby("run").size()
    return chi_so, lat, n_bao


def gio_that(*A):
    """Hàm đổi mốc đồng hồ live (giây) sang giờ thật (giây), dựng từ các bảng (thu_tu, ghi_us, toi_us) của doc_luong, gộp
    mọi luồng lab: engine đạt mốc c ở bản ghi đầu tiên làm đồng hồ chạm c, và đọc bản ghi i không sớm hơn timestamp lớn
    nhất của các bản ghi tới i. Chưa cộng chu kỳ đọc của engine."""
    A = pd.concat(A, ignore_index=True).sort_values("thu_tu")
    clock = A["toi_us"].to_numpy("int64") / 1e6
    wall = np.maximum.accumulate(A["ghi_us"].to_numpy("int64")) / 1e6

    def doi(c):
        i = np.searchsorted(clock, np.asarray(c, float), side="left")
        return wall[np.minimum(i, len(wall) - 1)]
    return doi


def tre_gio_that(lat, t_dau, doi):
    """Độ trễ theo đồng hồ live (giây, theo lượt) đổi sang giờ thật."""
    t = t_dau.reindex(lat.index).to_numpy()
    return pd.Series(doi(lat.to_numpy() + t) - t, index=lat.index)


HV_THU_TU = ["scan_mgmt", "auth_mgmt", "scan_in", "flood_in", "web_in", "exfil", "download", "beacon_even",
             "beacon_irregular"]


def bang_do_tre(cot, runs, n_bao):
    """Bảng theo hành vi: mỗi cột của cot (tên -> độ trễ theo lượt) ghi số lượt bắt được, trung vị và tối đa; cột cuối là
    số cảnh báo Tầng 1 mỗi lượt."""
    hv = HV_THU_TU + [b for b in runs["behavior"].unique() if b not in HV_THU_TU]
    hang = []
    for b in hv:
        rr = list(runs.loc[runs["behavior"] == b, "run_id"])
        h = {"Hành vi": b}
        for k, s in cot.items():
            x = s.reindex(rr).dropna()
            h[k] = f"{len(x)}/{len(rr)}, {x.median():.0f} s ({x.max():.0f})" if len(x) else f"0/{len(rr)}"
        nb = n_bao.reindex(rr).dropna()
        h["Cảnh báo Tầng 1 mỗi lượt"] = f"{nb.median():.0f} ({nb.min():.0f}-{nb.max():.0f})" if len(nb) else "-"
        hang.append(h)
    return pd.DataFrame(hang)
