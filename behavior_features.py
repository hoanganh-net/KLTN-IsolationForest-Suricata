# -*- coding: utf-8 -*-
"""
behavior_features.py: cửa sổ cặp máy, đặc trưng hành vi, huấn luyện tham chiếu, chọn ngưỡng và đếm cảnh báo của Behavior-IF.
Module không giữ trạng thái: bảng độ hiếm (rar_counts, rar_total), tham chiếu (ref, refs), ngưỡng (sel) do notebook truyền vào.
"""

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
def fit_ref(X, n_trees, max_samples, seed):
    """Học một tham chiếu trên X (đủ 11 cột); rừng chỉ nhận các cột FEATS_IF đã chuẩn hóa."""
    mu = X.mean(0)
    sd = X.std(0)
    sd = np.where(sd < 1e-9, 1.0, sd)
    Z = ((X - mu) / sd)[:, IDX_IF]
    own = IsolationForest(n_estimators=n_trees, max_samples=max_samples, random_state=seed).fit(Z)
    sk = SkIF(n_estimators=n_trees, max_samples=min(max_samples, len(Z)), random_state=seed).fit(Z)
    med = np.median(X, 0)
    mad = np.median(np.abs(X - med), 0)
    scale = np.where(mad > 1e-9, 1.4826 * mad, sd)
    return {"own": own, "sk": sk, "mu": mu, "sd": sd, "med": med, "scale": scale,
            "s_tr": own.anomaly_score(Z), "s_sk": -sk.score_samples(Z)}


def score(ref, X, which="own"):
    Z = ((np.asarray(X, float) - ref["mu"]) / ref["sd"])[:, IDX_IF]
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
