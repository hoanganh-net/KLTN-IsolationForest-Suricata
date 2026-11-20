# -*- coding: utf-8 -*-
"""behavior_features.py: cửa sổ cặp máy, đặc trưng hành vi, huấn luyện, chọn ngưỡng và kiểm thử của Behavior-IF.
Module không giữ trạng thái: bảng độ hiếm, tham chiếu và ngưỡng do notebook truyền vào. Mỗi chiều có một tham chiếu với độ dài
cửa sổ riêng (CUA_SO), cửa sổ được chấm theo thời điểm luồng tới engine (mục 5) trên các cột FEATS_RT của chiều đó."""

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
INCOMPLETE = {"syn_sent", "syn_recv"}
FEATS = ["log_n_conn", "sqrt_mb_out", "sqrt_mb_in", "frac_out", "log_throughput",
         "log_peak_cpm", "periodicity", "uniformity", "log_n_ports", "frac_incomplete", "svc_rarity"]

# Mỗi chiều một tham chiếu. Cửa sổ được chấm lại mỗi RT_STEP_S giây trên các luồng đã tới và báo ngay khi vượt ngưỡng; cửa sổ
# chốt sau cuối cửa sổ RT_DELAY_S giây (luồng chưa thiết lập hoặc đã đóng tới engine trong vòng 70 giây).
# Chiều vào: cửa sổ 2 phút, vì tấn công từ ngoài vào dồn dập và cần nhãn hành vi theo từng đợt để chọn phản ứng.
# Chiều ra: cửa sổ 30 phút để thấy cả hành vi nhịp thưa (beacon) và luồng dài; cửa sổ đã vượt ngưỡng vẫn được chấm tiếp để
# báo khi mức độ tăng hoặc hành vi đổi dạng.
CUA_SO = {"out": (30, 15), "in": (2, 1)}                     # (độ dài cửa sổ, bước trượt), phút
RT_DELAY_S, RT_STEP_S = 75, 10
RT_QUIET_S = {"out": 1800, "in": 900}                        # sự cố đóng sau chừng này giây không còn cửa sổ vượt ngưỡng
CHAM_TIEP = {"out": True, "in": False}
# Cột rừng học theo từng chiều. Chiều ra dùng 9 đại lượng có tín hiệu đơn biến với ít nhất một hành vi; frac_out và
# frac_incomplete không tách được hành vi chiều ra nào nên chỉ ghi kèm để diễn giải. Chiều vào giữ 5 cột của hành vi dồn dập.
FEATS_RT = {"out": ["log_n_conn", "sqrt_mb_out", "sqrt_mb_in", "log_throughput", "log_peak_cpm", "periodicity", "uniformity",
                    "log_n_ports", "svc_rarity"],
            "in": ["log_peak_cpm", "log_throughput", "log_n_ports", "frac_incomplete", "svc_rarity"]}
IDX_RT = {d: [FEATS.index(f) for f in cot] for d, cot in FEATS_RT.items()}
# Cỡ mẫu con của mỗi cây: phải đủ lớn để mỗi cây thấy vài chục mẫu nằm ngoài phân vị vận hành (psi x SCORE_Q khoảng 30);
# mẫu con nhỏ hơn thì mọi giá trị vượt cực trị của mẫu con nhận cùng một điểm, rừng không xếp hạng được phần đuôi.
PSI = {"out": 65536, "in": 1024}


def taus_cua(huong):
    """Các lần chấm của một cửa sổ, tính bằng giây sau đầu cửa sổ; lần cuối là lúc cửa sổ chốt."""
    chot = CUA_SO[huong][0] * 60 + RT_DELAY_S
    return np.array(list(range(RT_STEP_S, chot, RT_STEP_S)) + [chot])


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
        "sqrt_mb_in": math.sqrt(byte_in / 1e6),
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


# 4. Huấn luyện tham chiếu và chấm điểm
def fit_ref(X, n_trees, max_samples, seed, idx):
    """Học một tham chiếu trên X (đủ 11 cột); rừng chỉ nhận các cột idx đã chuẩn hóa."""
    idx = list(idx)
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
    Z = ((np.asarray(X, float) - ref["mu"]) / ref["sd"])[:, ref["idx"]]
    if which == "own":
        return ref["own"].anomaly_score(Z)
    return -ref["sk"].score_samples(Z)


# 5. Chấm theo thời điểm luồng tới, chọn ngưỡng và kiểm thử
def _nhom_mean_std(v, g, G):
    """Trung bình và độ lệch chuẩn (ddof=0) của v theo nhóm g (hai lượt để tránh sai số triệt tiêu)."""
    m = np.bincount(g, minlength=G).astype(float)
    s1 = np.bincount(g, weights=v, minlength=G)
    mean = np.divide(s1, m, out=np.zeros(G), where=m > 0)
    dev2 = np.bincount(g, weights=(v - mean[g]) ** 2, minlength=G)
    std = np.sqrt(np.divide(dev2, m, out=np.zeros(G), where=m > 0))
    return m, mean, std


def _mang_luong(d, rar_counts, rar_total, tach_luot=False):
    """Các mảng theo luồng dùng để dựng cửa sổ. tach_luot: mỗi lượt tấn công được gom cửa sổ riêng, không trộn luồng của
    lượt khác tới cùng máy đích, để độ phủ và độ trễ không phụ thuộc mật độ lượt của lab."""
    start, end = epoch(d["start"]), epoch(d["end"])
    M = {"start": start, "bts": d["bytes_toserver"].to_numpy(float), "btc": d["bytes_toclient"].to_numpy(float),
         "dur": np.clip(end - start, 0, None), "dport": d["dport"].to_numpy().astype("int64"),
         "inc": d["tcp_state"].str.lower().isin(INCOMPLETE).to_numpy(float), "rar": rar_of(d, rar_counts, rar_total),
         "src": d["src"].to_numpy(), "dst": d["dst"].to_numpy(), "dirn": d["direction"].to_numpy(),
         "run": d["run_id"].to_numpy() if "run_id" in d else np.full(len(d), "", object)}
    M["pair"] = pd.factorize(pd.MultiIndex.from_arrays([M["src"], M["dst"]] + ([M["run"]] if tach_luot else [])))[0]
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
        "sqrt_mb_in": np.sqrt(bi / 1e6),
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
                      "off": off, "n_conn": cnt, "t0": st[lo], "runs": runs, "cap": M["pair"][f0], "f0": f0})
    return pd.concat([K, F], axis=1)


def windows_nhanh(d, rar_counts, rar_total, win_min, hop_min, arrival=None, delay_s=0):
    """Gom luồng theo (bên khởi tạo, bên nhận, cửa sổ win_min phút) trên các lưới lệch nhau hop_min phút; đặc trưng tính
    bằng phép toán mảng theo nhóm, trùng feature_vector tới sai số làm tròn. arrival, delay_s: chỉ giữ luồng tới không
    muộn hơn cuối cửa sổ cộng delay_s."""
    M = _mang_luong(d, rar_counts, rar_total)
    span = win_min * 60
    arr = None if arrival is None else np.asarray(arrival, float)
    parts = []
    for off in range(0, span, hop_min * 60):
        bucket = ((M["start"] - off) // span).astype("int64")
        sel = np.arange(len(bucket)) if arr is None else np.flatnonzero(arr <= (bucket + 1) * span + off + delay_s)
        if len(sel):
            parts.append(_cua_so_luoi(M, span, off, bucket, sel))
    return pd.concat(parts, ignore_index=True).drop(columns=["cap", "f0"])


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


def chinh_sach(cap, ws, batch, sev, top, quiet):
    """Trạng thái báo của từng lần chấm vượt ngưỡng theo _su_co_rt() của anomaly.py, theo thứ tự engine gặp (lần đọc rồi
    đầu cửa sổ): 'new', 'escalated', 'new_behavior', hoặc '' khi chỉ cộng dồn vào sự cố đang mở của cặp máy."""
    cap, ws, batch, sev, top = (np.asarray(a) for a in (cap, ws, batch, sev, top))
    st = np.full(len(ws), "", object)
    ep = {}
    for i in np.lexsort((ws, batch)):
        e = ep.get(cap[i])
        if e is None or ws[i] - e["last"] > quiet:
            ep[cap[i]] = {"last": ws[i], "sev": sev[i], "tops": {top[i]}}
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


def quy_dao(D, rar_counts, rar_total, huong, tach_luot=False):
    """Quỹ đạo chấm sớm của các luồng D theo cửa sổ của chiều huong: với mỗi lần chấm (giây sau đầu cửa sổ), đặc trưng của
    những cửa sổ vừa có thêm luồng, chỉ tính trên luồng có _toi không muộn hơn đầu cửa sổ cộng lần chấm đó. Trả từ điển:
    base (cửa sổ ở trạng thái chốt), taus, các sự kiện sắp theo (cửa sổ, lần chấm) gồm r (hàng trong base), j (chỉ số
    lần chấm), X (11 đặc trưng); lo (sự kiện đầu của mỗi cửa sổ), ws (đầu cửa sổ), cap (mã cặp máy của sự kiện), gio (số
    giờ dữ liệu), dau (lần chấm đầu tiên mỗi lượt có luồng trong từng cửa sổ)."""
    span, hop = CUA_SO[huong][0] * 60, CUA_SO[huong][1] * 60
    taus = taus_cua(huong)
    M = _mang_luong(D, rar_counts, rar_total, tach_luot)
    arr = D["_toi"].to_numpy(float)
    luoi, parts = [], []
    for off in range(0, span, hop):
        bucket = ((M["start"] - off) // span).astype("int64")
        j_toi = np.searchsorted(taus, arr - (bucket * span + off), side="left")       # lần chấm đầu tiên thấy luồng
        gid = pd.factorize(pd.MultiIndex.from_arrays([M["pair"], bucket]))[0]
        luoi.append((off, bucket, j_toi, gid))
        sel = np.flatnonzero(j_toi < len(taus))
        if len(sel):
            parts.append(_cua_so_luoi(M, span, off, bucket, sel).assign(_g=len(luoi) - 1))
    base = pd.concat(parts, ignore_index=True)
    base["runs"] = base["runs"].fillna("")
    hang = []                                                 # hàng trong base của từng cửa sổ, theo lưới
    for g, (off, bucket, j_toi, gid) in enumerate(luoi):
        m = np.full(int(gid.max()) + 1, -1, "int64")
        b = base[base["_g"] == g]
        m[gid[b["f0"].to_numpy()]] = b.index.to_numpy()
        hang.append(m)
    R, J, XX = [], [], []
    for j in range(len(taus)):
        for g, (off, bucket, j_toi, gid) in enumerate(luoi):
            doi = np.unique(gid[j_toi == j])                  # cửa sổ có thêm luồng ở lần chấm này
            if not len(doi):
                continue
            w = _cua_so_luoi(M, span, off, bucket, np.flatnonzero(np.isin(gid, doi) & (j_toi <= j)))
            R.append(hang[g][gid[w["f0"].to_numpy()]])
            J.append(np.full(len(w), j, "int16"))
            XX.append(w[FEATS].to_numpy(float))
    r, jj, X = np.concatenate(R), np.concatenate(J), np.concatenate(XX)
    assert (r >= 0).all(), "cửa sổ ở lần chấm sớm phải có ở lần chấm cuối"
    o = np.lexsort((jj, r))
    r, jj, X = r[o], jj[o], X[o]
    dau = []
    co = np.flatnonzero(M["run"] != "")
    for g, (off, bucket, j_toi, gid) in enumerate(luoi):
        m = co[j_toi[co] < len(taus)]
        if len(m):
            dau.append(pd.DataFrame({"r": hang[g][gid[m]], "run": M["run"][m], "j_dau": j_toi[m]})
                       .groupby(["r", "run"], as_index=False)["j_dau"].min())
    dau = pd.concat(dau, ignore_index=True) if dau else pd.DataFrame({"r": [], "run": [], "j_dau": []})
    ws = (base["bucket"].to_numpy() * span + base["off"].to_numpy()).astype(float)
    return {"base": base.drop(columns=["_g", "f0"]), "taus": taus, "r": r, "j": jj, "X": X,
            "lo": np.r_[0, np.flatnonzero(np.diff(r)) + 1], "ws": ws, "cap": base["cap"].to_numpy(),
            "gio": (base["t0"].max() - base["t0"].min()) / 3600, "dau": dau, "huong": huong}


def cham_quy_dao(Q, ref):
    """Điểm scikit-learn (s) và đặc trưng lệch nhất (k) của từng lần chấm trong quỹ đạo Q theo tham chiếu ref."""
    Q["s"] = score(ref, Q["X"], "sk")
    Q["k"] = top_dac_trung(Q["X"], ref["med"], ref["scale"])
    return Q


def vuot_nguong(Q, thr, cham_tiep):
    """Chỉ số các lần chấm vượt ngưỡng được đưa vào chính sách báo: mọi lần vượt khi cửa sổ đã vượt ngưỡng vẫn được chấm
    tiếp (cham_tiep), còn không thì chỉ lần đầu tiên của mỗi cửa sổ."""
    v = Q["s"] > thr
    if cham_tiep:
        return np.flatnonzero(v)
    dau = np.minimum.reduceat(np.where(v, np.arange(len(v)), len(v)), Q["lo"])
    return dau[dau < len(v)]


def bao_rt(Q, ix, thr):
    """Trạng thái báo của các lần chấm ix. Cửa sổ vượt ngưỡng ở lần chấm cuối được engine xử lý ở lần đọc kế tiếp."""
    r, tau = Q["r"][ix], Q["taus"][Q["j"][ix]].astype(float)
    chot = float(Q["taus"][-1])
    batch = Q["ws"][r] + np.where(tau == chot, (chot // RT_STEP_S + 1) * RT_STEP_S, tau)
    return chinh_sach(Q["cap"][r], Q["ws"][r], batch, muc_do(Q["s"][ix], thr), Q["k"][ix], RT_QUIET_S[Q["huong"]])


def chon_nguong_rt(ref, Q, q_grid, fa_max):
    """SCORE_Q lớn nhất có không quá fa_max cảnh báo nhầm mỗi giờ trên quỹ đạo kiểm định Q (đã chấm), đếm đủ ba loại cảnh
    báo engine phát. Trả (bảng theo SCORE_Q, lựa chọn hoặc None, số giờ kiểm định)."""
    cham_tiep = CHAM_TIEP[Q["huong"]]
    rows, sel = [], None
    for q in q_grid:
        t = float(np.quantile(ref["s_sk"], 1 - q))
        ix = vuot_nguong(Q, t, cham_tiep)
        st = bao_rt(Q, ix, t)
        n = pd.Series(st, dtype=object).value_counts()
        moi, tat_ca = int(n.get("new", 0)), int((st != "").sum())
        rows.append({"SCORE_Q": q, "Ngưỡng": round(t, 6), "Cửa sổ vượt ngưỡng": int(len(np.unique(Q["r"][ix]))),
                     "Sự cố/giờ": round(moi / Q["gio"], 2), "Cảnh báo nhầm/giờ": round(tat_ca / Q["gio"], 2),
                     "Tăng mức độ": int(n.get("escalated", 0)), "Đổi dạng": int(n.get("new_behavior", 0))})
        if tat_ca / Q["gio"] <= fa_max:
            sel = {"q": q, "thr_sk": t, "fa_h": tat_ca / Q["gio"]}
    return pd.DataFrame(rows), sel, Q["gio"]


def chi_so_nen(Q, thr):
    """Báo nhầm trên các cửa sổ không chứa luồng tấn công của quỹ đạo Q: tỷ lệ cửa sổ có lần chấm vượt ngưỡng và số cảnh
    báo engine phát mỗi giờ."""
    nen = (Q["base"]["runs"].to_numpy() == "")
    ix = vuot_nguong(Q, thr, CHAM_TIEP[Q["huong"]])
    ix = ix[nen[Q["r"][ix]]]
    st = bao_rt(Q, ix, thr)
    hl = Q["base"][nen]
    g = (hl["t0"].max() - hl["t0"].min()) / 3600
    n_vuot, n_bao = len(np.unique(Q["r"][ix])), int((st != "").sum())
    gio_nen = len(np.unique(hl["t0"].to_numpy() // 3600))            # số giờ đồng hồ có ít nhất một cửa sổ bình thường
    return {"FPR (%)": round(100 * n_vuot / len(hl), 3), "cảnh báo nhầm/giờ": round(n_bao / g, 2),
            "cửa sổ bình thường": len(hl), "giờ": round(g, 1), "cửa sổ vượt ngưỡng": n_vuot, "cảnh báo nhầm": n_bao,
            "giờ có lưu lượng": gio_nen}


def phat_hien(Q, thr, t_dau):
    """Độ trễ của từng lượt (theo đồng hồ live): lần chấm vượt ngưỡng sớm nhất của một cửa sổ khi lượt đã có luồng trong
    cửa sổ đó, trừ lúc bắt đầu của lượt; và số cảnh báo engine phát cho các cửa sổ của từng lượt."""
    v = np.flatnonzero(Q["s"] > thr)
    d = Q["dau"].merge(pd.DataFrame({"r": Q["r"][v], "j": Q["j"][v]}), on="r")
    d = d[d["j"] >= d["j_dau"]]
    d["t"] = Q["ws"][d["r"].to_numpy()] + Q["taus"][d["j"].to_numpy()]
    lat = d.groupby("run")["t"].min()
    lat = (lat - pd.Series(t_dau, dtype=float).reindex(lat.index)).dropna()
    ix = vuot_nguong(Q, thr, CHAM_TIEP[Q["huong"]])
    st = bao_rt(Q, ix, thr)
    b = pd.DataFrame({"r": Q["r"][ix], "j": Q["j"][ix]})[st != ""].merge(Q["dau"], on="r")
    n_bao = b[b["j"] >= b["j_dau"]].groupby("run").size()
    return lat, n_bao


def tre_khi_dong(Q, thr, t_dau):
    """Độ trễ của từng lượt (theo đồng hồ live) nếu mỗi cửa sổ chỉ được chấm một lần lúc chốt: cửa sổ chốt sớm nhất có luồng
    của lượt và có điểm ở trạng thái chốt vượt ngưỡng, trừ lúc bắt đầu của lượt. Dùng để so với cách chấm khi cửa sổ còn mở."""
    cuoi = np.r_[Q["lo"][1:], len(Q["s"])] - 1                      # lần chấm cuối của mỗi cửa sổ
    r_vuot = Q["r"][cuoi][Q["s"][cuoi] > thr]
    d = Q["dau"][Q["dau"]["r"].isin(r_vuot)]
    t = pd.Series(Q["ws"][d["r"].to_numpy()] + float(Q["taus"][-1]), index=d["run"].to_numpy())
    lat = t.groupby(level=0).min()
    return (lat - pd.Series(t_dau, dtype=float).reindex(lat.index)).dropna()


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
    số cảnh báo engine phát mỗi lượt."""
    hv = HV_THU_TU + [b for b in runs["behavior"].unique() if b not in HV_THU_TU]
    hang = []
    for b in hv:
        rr = list(runs.loc[runs["behavior"] == b, "run_id"])
        h = {"Hành vi": b}
        for k, s in cot.items():
            x = s.reindex(rr).dropna()
            h[k] = f"{len(x)}/{len(rr)}, {x.median():.0f} s ({x.max():.0f})" if len(x) else f"0/{len(rr)}"
        nb = n_bao.reindex(rr).dropna()
        h["Cảnh báo mỗi lượt"] = f"{nb.median():.0f} ({nb.min():.0f}-{nb.max():.0f})" if len(nb) else "-"
        hang.append(h)
    return pd.DataFrame(hang)
