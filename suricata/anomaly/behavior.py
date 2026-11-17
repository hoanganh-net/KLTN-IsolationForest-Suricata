"""behavior.py — Behavior-IF trên bản ghi flow (hai tầng cửa sổ). Tách từ anomaly.py, logic nguyên vẹn."""
import sys, os, json, math, time, re, gzip, ipaddress, collections, types, threading, base64, html
from datetime import datetime
from urllib.parse import unquote_plus, urlsplit, parse_qsl
import numpy as np
from common import (WHITELIST_PATH, _chon_cot, _emit, _load, _load_whitelist, _open, _score,
                    _severity, _tail_lines, _tail_start, _thr_q, explain, zscore)



# ---- Behavior-IF: bản ghi flow ----
def _build_behavior(model_path="net_if_model.joblib"):
    VICTIM_NETS = [ipaddress.ip_network("192.168.10.0/24")]
    MGMT_NETS   = [ipaddress.ip_network("192.168.20.0/24")]
    EXCLUDE_PORTS = {0, 53, 5353, 5355, 137, 138, 123}
    EXCLUDE_SRC = set()
    WINDOW_MIN, WINDOW_HOP_MIN, MIN_CONN = 30, 15, 1
    INCOMPLETE_STATES = {"syn_sent", "syn_recv"}
    FEATS = ["log_n_conn", "sqrt_mb_out", "log_bytes_in", "frac_out", "log_throughput",
             "log_peak_cpm", "periodicity", "uniformity", "log_n_ports", "frac_incomplete", "svc_rarity"]
    # Trường phụ chỉ phục vụ thẻ cảnh báo: direction, zone_other, frac_out, dport_top, n_ports, dports.
    I_FRAC_OUT = FEATS.index("frac_out")
    I_N_PORTS = FEATS.index("log_n_ports")                     # log1p(số cổng đích khác nhau)
    I_PEAK = FEATS.index("log_peak_cpm")                       # tần suất kết nối đỉnh/phút: nhận nguồn dồn dập (brute/flood)
    I_SVC = FEATS.index("svc_rarity")                          # độ hiếm dịch vụ: tách brute (dịch vụ hiếm) khỏi flood (dịch vụ nền)
    DPORTS_MAX = 10                                            # số cổng đích tối đa liệt kê kèm cảnh báo (thẻ chỉ dùng khi ít cổng)
    _TZ = re.compile(r"([+-]\d{2})(\d{2})$")
    WL_IPS, WL_NETS = _load_whitelist(WHITELIST_PATH)
    print(f"[BEHAVIOR-IF] danh sách loại trừ: {len(WL_IPS) + len(WL_NETS)} mục"
          + (f" từ {os.path.abspath(WHITELIST_PATH)}" if WL_IPS or WL_NETS else f" (không thấy {WHITELIST_PATH})"), flush=True)

    def whitelisted(ip):
        if ip in WL_IPS: return True
        if not WL_NETS: return False
        try: a = ipaddress.ip_address(ip)
        except (ValueError, TypeError): return False
        return any(a in n for n in WL_NETS)

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
        # Hai chiều chấm theo bên khởi tạo: chiều ra dùng tham chiếu chính, chiều vào dùng khóa "inbound" (nếu có).
        zs, zd = zone(s), zone(d)
        return (zs == "victim" and zd in ("ext", "mgmt")) or (zs == "ext" and zd == "victim")

    # Giới hạn bộ đệm của --live: cặp vượt giới hạn chỉ mất các luồng cũ nhất.
    BUF_MAX_ROWS     = int(os.environ.get("ANOMALY_BUF_MAX_ROWS", "400000"))      # tổng số luồng giữ trong bộ đệm
    BUF_MAX_PER_PAIR = int(os.environ.get("ANOMALY_BUF_MAX_PER_PAIR", "50000"))   # số luồng tối đa của một cặp
    BUF_MAX_PAIRS    = int(os.environ.get("ANOMALY_BUF_MAX_PAIRS", "20000"))      # số cặp tối đa theo dõi cùng lúc
    # Bản ghi flow đến sau khi luồng kết thúc (lab: 99,4% trong 6 phút, chậm nhất khoảng 10 phút).
    FLOW_DELAY       = int(os.environ.get("ANOMALY_FLOW_DELAY_S", "360"))
    # Gom cảnh báo --live theo sự cố của cặp (nguồn, đích): chỉ báo khi mở sự cố, khi tăng lên high, khi đặc trưng lệch
    # nhất đổi hoặc đã quá EP_REMIND; sự cố đóng sau EP_QUIET yên lặng. ANOMALY_EPISODE=0 tắt việc gom.
    EP_ON     = os.environ.get("ANOMALY_EPISODE", "1") != "0"
    EP_QUIET  = int(float(os.environ.get("ANOMALY_EPISODE_QUIET_MIN", "120")) * 60)
    EP_REMIND = int(float(os.environ.get("ANOMALY_EPISODE_REMIND_MIN", "360")) * 60)   # 0: không nhắc lại

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
        if bad_dest(other) or whitelisted(other): return None
        dp = o.get("dest_port") or 0
        if dp in EXCLUDE_PORTS: return None
        direction = "out" if zone(s) == "victim" else "in"
        # Bản ghi ngược chiều (Suricata bắt giữa chừng kết nối do máy nạn nhân mở): cổng nguồn < 1024 <= cổng đích, không
        # thấy SYN hoặc không phải TCP. Cùng quy tắc với build_flow_dataset.py.
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
                    keys.append((s, d, ext_ip(s, d), len(rws), off, b, int(collections.Counter(c[4]).most_common(1)[0][0]),
                                 sorted({int(p) for p in c[4]})[:DPORTS_MAX]))
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

    def _iso(ts):
        return datetime.fromtimestamp(ts).astimezone().isoformat(timespec="seconds")

    def _emit_beh(key, x, sc, m, thr, loc, reasons=None, extra=None):
        src, dst, other, n, off, b, top = key[:7]
        _emit({"module": "anomaly_if", "time": datetime.now().isoformat(timespec="seconds"),
               "src_ip": src, "dest_ip": dst, "ext_ip": other, "n_conn": int(n),
               "direction": "out" if zone(src) == "victim" else "in", "dport_top": top,
               "n_ports": int(round(math.expm1(float(x[I_N_PORTS])))),
               "dports": ",".join(str(p) for p in key[7]) if len(key) > 7 else "",
               "zone_other": zone(other), "frac_out": round(float(x[I_FRAC_OUT]), 3),
               "window_start": _iso(b * WINDOW_MIN * 60 + off),
               "location": loc, "score": float(sc), "thr": thr,
               "reasons": reasons if reasons is not None else explain(x, m["med"], m["scale"], FEATS),
               **(extra or {})})

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
        # Đọc tăng dần eve.json và giữ flow gần đây trong bộ đệm. Mỗi cửa sổ chấm một lần khi đồng hồ qua cuối cửa sổ cộng
        # FLOW_DELAY và cửa sổ chưa mất luồng (do cắt bộ đệm hay do mới khởi động), nên trùng cửa sổ của notebook.
        m = _load(model_path, FEATS); thr = _thr_q(m, score_q); iv = interval or 30
        rc, rt = m["rarity_counts"], m["rarity_total"]
        print(f"[BEHAVIOR-IF live] model có {len(FEATS)} đặc trưng, cửa sổ {WINDOW_MIN}', ngưỡng={thr:.4f}, mỗi {iv}s", flush=True)
        mi = _inbound(m); thr_i = _thr_q(mi, score_q_in) if mi is not None else None
        rar_in = (mi["rarity_counts"], mi["rarity_total"]) if mi is not None else None
        print("[BEHAVIOR-IF live] chiều vào: " + (f"bật, ngưỡng={thr_i:.4f}" if mi is not None else "tắt (model chưa có khóa 'inbound')"), flush=True)
        if EP_ON:
            print(f"[BEHAVIOR-IF live] gom cảnh báo theo sự cố: đóng sau {EP_QUIET // 60}' yên lặng, nhắc lại sau "
                  + (f"{EP_REMIND // 60}'" if EP_REMIND else "(tắt)"), flush=True)
        else:
            print("[BEHAVIOR-IF live] gom cảnh báo theo sự cố: tắt (mỗi bucket 30' một cảnh báo)", flush=True)
        seen = set(); scored = set(); buf = []; last_note = 0.0
        ep = {}                                            # sự cố đang mở: (nguồn, đích) -> trạng thái
        st = _tail_start(path)                             # bắt đầu từ CUỐI file: chỉ dựng cửa sổ từ flow MỚI
        W = WINDOW_MIN * 60

        def _su_co(kk, sc, t, reasons):
            """Cửa sổ bị gắn cờ kk có sinh cảnh báo không: trả (trạng thái, các trường sự cố); trạng thái None nghĩa là chỉ
            cộng dồn vào sự cố đang mở. Thời gian tính theo thời điểm bắt đầu cửa sổ, không theo giờ máy."""
            p = (kk[0], kk[1]); tw = kk[5] * W + kk[4]
            sev = _severity(sc, t); top = reasons[0][0] if reasons else ""
            e = ep.get(p)
            if e is None or tw - e["last"] > EP_QUIET:
                e = ep[p] = {"id": f"{p[0]}>{p[1]}@{_iso(tw)}", "start": tw, "last": tw, "emit": tw,
                             "sev": sev, "tops": {top}, "n": 1, "n_emit": 0}
                state = "new"
            else:
                e["n"] += 1; e["last"] = max(e["last"], tw)
                if sev == "high" and e["sev"] != "high": state = "escalated"
                elif top and top not in e["tops"]: state = "new_behavior"
                elif EP_REMIND and tw - e["emit"] >= EP_REMIND: state = "ongoing"
                else: state = None
                e["tops"].add(top)
                if sev == "high": e["sev"] = "high"
            if state is not None:
                e["emit"] = tw; e["n_emit"] += 1
            return state, {"episode": e["id"], "episode_state": state, "episode_start": _iso(e["start"]),
                           "episode_windows": e["n"]}
        KEEP = W + WINDOW_HOP_MIN * 60 + FLOW_DELAY        # giữ flow tới khi mọi cửa sổ chứa nó đã được chấm
        clock = None; t_from = None                        # cửa sổ bắt đầu trước t_from có thể thiếu luồng
        while True:
            tmax = None
            for line in _tail_lines(path, st):
                if '"event_type":"flow"' not in line and '"event_type": "flow"' not in line: continue
                try: o = json.loads(line)
                except Exception: continue
                r = flow_row(o, rc, rt, rar_in)
                if r is None: continue
                en = r[1][0] + r[1][3]
                if en > time.time() + 300: continue        # mốc thời gian ở tương lai (đồng hồ lệch): bỏ, để không đẩy đồng hồ đi xa
                buf.append(r)                              # r = ((src,dst), row)
                if tmax is None or en > tmax: tmax = en
            if tmax is not None:
                clock = tmax if clock is None else max(clock, tmax)
                if t_from is None: t_from = clock          # lần đọc đầu: cửa sổ đã mở trước lúc khởi động bị bỏ qua
            if buf and clock is not None:
                P = collections.defaultdict(list)
                for (pk, row) in buf: P[pk].append(row)
                keys, X = _windows_from_P(P)
                chon = [i for i, k in enumerate(keys)
                        if t_from <= k[5] * W + k[4] <= clock - W - FLOW_DELAY and (k[0], k[1], k[4], k[5]) not in scored]
                if chon:
                    keys = [keys[i] for i in chon]; X = X[chon]
                    scored.update((k[0], k[1], k[4], k[5]) for k in keys)
                    gan_co = sorted(((i, sc, mm, t) for i, sc, mm, t in score_split(keys, X, m, thr, mi, thr_i) if sc > t),
                                    key=lambda z: keys[z[0]][5] * W + keys[z[0]][4])   # theo thời điểm bắt đầu cửa sổ
                    for i, sc, mm, t in gan_co:
                        kk = keys[i]; k = (kk[0], kk[1], kk[5])  # (nguồn, đích, bucket): hai lưới lệch 15' gộp một cảnh báo
                        if k in seen: continue
                        seen.add(k)
                        reasons = explain(X[i], mm["med"], mm["scale"], FEATS)
                        extra = None
                        if EP_ON:
                            state, extra = _su_co(kk, sc, t, reasons)
                            if state is None:                  # cộng dồn vào sự cố đang mở: không ghi tệp cảnh báo, chỉ in ra nhật ký
                                print(f"[BEHAVIOR-IF live] cộng dồn vào sự cố {extra['episode']}: cửa sổ từ {_iso(kk[5] * W + kk[4])}, "
                                      f"điểm {sc:.3f}, {extra['episode_windows']} bucket bất thường", flush=True)
                                continue
                        _emit_beh(kk, X[i], sc, mm, t, f"cửa sổ {WINDOW_MIN}'", reasons, extra)
            if clock is not None:                          # cắt flow quá cũ SAU khi đã chấm
                lo = clock - KEEP
                t_from = max(t_from, lo)
                buf = [rr for rr in buf if rr[1][0] + rr[1][3] >= lo]
                buf, note = cap_buffer(buf)
                if note and time.time() - last_note > 60:
                    print(f"[BEHAVIOR-IF live] bộ đệm chạm giới hạn ({'; '.join(note)}), chỉ giữ luồng mới nhất", flush=True)
                    last_note = time.time()
                bmin = int((lo - W) // W)
                seen = {k for k in seen if k[2] >= bmin}       # bỏ khóa của cửa sổ đã trôi qua
                scored = {k for k in scored if k[3] >= bmin}
                if EP_ON:                                  # đóng sự cố đã yên lặng quá EP_QUIET (cửa sổ chưa chấm đều bắt đầu sau han - 15')
                    han = clock - W - FLOW_DELAY
                    for p in [p for p, e in ep.items() if han - e["last"] > EP_QUIET + WINDOW_HOP_MIN * 60]:
                        e = ep.pop(p)
                        print(f"[BEHAVIOR-IF live] đóng sự cố {e['id']}: {e['n']} bucket bất thường, {e['n_emit']} cảnh báo, "
                              f"cửa sổ bất thường cuối bắt đầu {_iso(e['last'])}", flush=True)
            time.sleep(iv)

    # ---- Tầng 1: cảnh báo nhanh ----
    # Mỗi lượt đọc chấm lại các cửa sổ chưa chốt với luồng đã tới và báo ngay khi vượt ngưỡng; cửa sổ chốt khi đồng hồ
    # qua cuối cửa sổ cộng delay_s. Tham số và tham chiếu ở khóa "rt" của joblib; thiếu khóa này thì Tầng 1 tắt.
    def _load_rt():
        import joblib
        rt = joblib.load(model_path).get("rt")
        if not rt:
            return None
        mo = _chon_cot(rt["out"], FEATS, "Tầng 1 chiều ra")
        mi = _chon_cot(rt["inbound"], FEATS, "Tầng 1 chiều vào") if rt.get("inbound") else None
        return mo, mi, rt

    def _nhan_hanh_vi(x, m, direction, zone_src):
        """Đoán hành vi thô để CHỌN phản ứng, không phải phân loại tấn công chuẩn. scan: chạm nhiều cổng (bề rộng)
        -> chỉ quan sát, không chặn. brute: nguồn VÙNG NGOÀI dòm vào một dịch vụ hiếm (vd SSH) -> dò mật khẩu; không
        đòi tần suất cao vì công cụ như hydra chậm (nút cổ chai là xác thực), và chốt vùng ngoài để không chặn quản
        trị viên hợp lệ vốn tới từ vùng mgmt. flood: dịch vụ nền, tần suất cực cao từ một nguồn đơn chiều vào. Chỉ xét
        chiều vào để IP nguồn là bên khởi tạo bên ngoài, không bao giờ tự chặn máy nạn nhân."""
        n_ports = int(round(math.expm1(float(x[I_N_PORTS]))))
        if n_ports >= 6:
            return "scan"
        if direction != "in" or n_ports > 3:
            return ""
        z = zscore(x, m["med"], m["scale"])
        if zone_src == "ext" and float(z[I_SVC]) > 2.0:       # nguồn ngoài dòm dịch vụ hiếm -> dò mật khẩu (bắt cả brute chậm)
            return "brute"
        if float(z[I_PEAK]) > 2.0:                            # dịch vụ nền, tần suất cực cao -> làm ngập
            return "flood"
        return ""

    def _emit_rt(key, x, sc, m, thr, W, extra=None, reasons=None):
        src, dst, other, n, off, b, top = key[:7]
        zs = zone(src)
        direction = "out" if zs == "victim" else "in"
        beh = _nhan_hanh_vi(x, m, direction, zs)
        _emit({"module": "anomaly_if_rt", "time": datetime.now().isoformat(timespec="seconds"),
               "src_ip": src, "dest_ip": dst, "ext_ip": other, "n_conn": int(n),
               "direction": direction, "dport_top": top,
               "n_ports": int(round(math.expm1(float(x[I_N_PORTS])))),
               "dports": ",".join(str(p) for p in key[8]) if len(key) > 8 else "",
               "zone_other": zone(other), "frac_out": round(float(x[I_FRAC_OUT]), 3),
               "window_start": _iso(b * W + off), "location": f"cửa sổ {W // 60}' (Tầng 1)",
               "score": float(sc), "thr": thr,
               **({"behavior": beh} if beh else {}),
               "reasons": reasons if reasons is not None else explain(x, m["med"], m["scale"], FEATS), **(extra or {})})

    def _su_co_rt(ep, p, ws, sc, t, reasons, QUIET):
        """Chính sách báo của Tầng 1, như Tầng 2 nhưng không nhắc lại định kỳ: mở sự cố mới khi cặp đã yên quá QUIET;
        trong sự cố chỉ báo lại khi tăng lên high hoặc đặc trưng lệch nhất đổi sang đặc trưng chưa gặp. Trả (trạng thái hoặc None,
        sự cố)."""
        sev, top = _severity(sc, t), (reasons[0][0] if reasons else "")
        e = ep.get(p)
        if e is None or ws - e["last"] > QUIET:
            e = ep[p] = {"id": f"{p[0]}>{p[1]}@{_iso(ws)}", "start": ws, "last": ws, "n": 1, "sev": sev, "tops": {top}}
            return "new", e
        e["n"] += 1
        e["last"] = max(e["last"], ws)
        if sev == "high" and e["sev"] != "high": state = "escalated"
        elif top and top not in e["tops"]: state = "new_behavior"
        else: state = None
        e["tops"].add(top)
        if sev == "high": e["sev"] = "high"
        return state, e

    def _cua_so_rt(P, W, H, han_fn, bo_qua):
        """Cửa sổ Tầng 1 từ P[(nguồn, đích)] = [(row, thời điểm tới)], chỉ lấy luồng tới không muộn hơn han_fn(ws);
        khóa bị bo_qua loại thì bỏ. Phần tử thứ tám của khóa là lúc bắt đầu của luồng sớm nhất, dùng tính lat_s."""
        keys, X = [], []
        for (s, d), items in P.items():
            for off in range(0, W, H):
                buckets = collections.defaultdict(list)
                for row, toi in items:
                    buckets[int((row[0] - off) // W)].append((row, toi))
                for b, its in buckets.items():
                    ws = b * W + off
                    if bo_qua((s, d, off, b), ws):
                        continue
                    han = han_fn(ws)
                    rws = [row for row, toi in its if toi <= han]
                    if len(rws) < MIN_CONN:
                        continue
                    c = list(zip(*rws))
                    X.append(feature_vector(c[0], c[1], c[2], c[3], c[4], c[5], c[6]))
                    keys.append((s, d, ext_ip(s, d), len(rws), off, b, int(collections.Counter(c[4]).most_common(1)[0][0]),
                                 min(c[0]), sorted({int(p) for p in c[4]})[:DPORTS_MAX]))
        return keys, (np.array(X) if X else np.empty((0, len(FEATS))))

    def _rt_quiet(cfg):
        # ANOMALY_RT_QUIET_MIN đổi thời gian yên lặng của sự cố Tầng 1 khi triển khai (phút; mặc định theo joblib, 15 phút).
        ov = os.environ.get("ANOMALY_RT_QUIET_MIN")
        return float(ov) * 60 if ov else float(cfg.get("quiet_s", 900))

    def tang1(mo, mi, cfg, score_q=None, score_q_in=None, phat=None):
        """Bộ xử lý Tầng 1: doc(dòng) nhận dòng eve.json mới, cập nhật đồng hồ, chấm lại cửa sổ chưa chốt và gọi phat(...)
        cho cửa sổ vượt ngưỡng lần đầu; trạng thái None là cộng dồn vào sự cố đang mở, không báo."""
        W, H = int(cfg["window_min"] * 60), int(cfg["window_hop_min"] * 60)
        D, QUIET = float(cfg["delay_s"]), _rt_quiet(cfg)
        thr_o = _thr_q(mo, score_q)
        thr_i = _thr_q(mi, score_q_in) if mi is not None else None
        rc, rt = mo["rarity_counts"], mo["rarity_total"]
        rar_in = (mi["rarity_counts"], mi["rarity_total"]) if mi is not None else None
        KEEP = W + H + D + 60
        s = types.SimpleNamespace(clock=None, t_from=None, buf=[], fired=set(), done=set(), ep={}, n_alert=0,
                                  W=W, thr_o=thr_o, thr_i=thr_i, last_note=0.0)

        def mac_dinh(kk, x, sc, mm, t, extra, state, reasons):
            if state is not None:
                s.n_alert += 1
                _emit_rt(kk, x, sc, mm, t, W, extra, reasons)

        def doc(lines):
            for line in lines:
                if '"event_type":"flow"' not in line and '"event_type": "flow"' not in line: continue
                try: o = json.loads(line)
                except Exception: continue
                r = flow_row(o, rc, rt, rar_in)
                if r is None: continue
                en = r[1][0] + r[1][3]
                if en > time.time() + 300: continue            # mốc thời gian ở tương lai (đồng hồ lệch): bỏ
                s.clock = en if s.clock is None else max(s.clock, en)
                if s.t_from is None: s.t_from = s.clock          # cửa sổ mở trước lúc khởi động bị bỏ qua
                s.buf.append((r[0], (r[1], s.clock)))            # thời điểm tới = đồng hồ ngay sau khi đọc luồng
            if not s.buf or s.clock is None:
                return
            clock = s.clock
            P = collections.defaultdict(list)
            for pk, item in s.buf: P[pk].append(item)

            def bo_qua(k, ws):
                if ws < s.t_from or k in s.fired or k in s.done:
                    return True
                if clock > ws + W + D:                           # lần chấm cuối của cửa sổ này
                    s.done.add(k)
                return False
            keys, X = _cua_so_rt(P, W, H, lambda ws: min(clock, ws + W + D), bo_qua)
            if len(X):
                gan_co = sorted(((i, sc, mm, t) for i, sc, mm, t in score_split(keys, X, mo, thr_o, mi, thr_i) if sc > t),
                                key=lambda z: keys[z[0]][5] * W + keys[z[0]][4])
                for i, sc, mm, t in gan_co:
                    kk = keys[i]
                    s.fired.add((kk[0], kk[1], kk[4], kk[5]))
                    ws = kk[5] * W + kk[4]
                    reasons = explain(X[i], mm["med"], mm["scale"], FEATS)
                    state, e = _su_co_rt(s.ep, (kk[0], kk[1]), ws, sc, t, reasons, QUIET)
                    extra = {"episode": e["id"], "episode_state": state or "", "episode_start": _iso(e["start"]),
                             "episode_windows": e["n"], "t_det_s": round(clock - ws, 1),
                             "lat_s": round(time.time() - kk[7], 1)}
                    (phat or mac_dinh)(kk, X[i], sc, mm, t, extra, state, reasons)
            lo = clock - KEEP                                    # cắt luồng của các cửa sổ đã chốt
            s.buf = [it for it in s.buf if it[1][0][0] >= lo]
            s.buf, note = cap_buffer(s.buf)
            if note and time.time() - s.last_note > 60:
                print(f"[TẦNG 1 live] bộ đệm chạm giới hạn ({'; '.join(note)}), chỉ giữ luồng mới nhất", flush=True)
                s.last_note = time.time()
            bmin = int((lo - W) // W) - 1
            s.fired = {k for k in s.fired if k[3] >= bmin}
            s.done = {k for k in s.done if k[3] >= bmin}
            for p in [p for p, e in s.ep.items() if clock - e["last"] > QUIET + W + D]:
                s.ep.pop(p)

        s.doc = doc
        return s

    def detect_rt(path, last_min=None, score_q=None, score_q_in=None):
        """Tầng 1 trên một tệp có sẵn: chấm mọi cửa sổ ngắn với đủ luồng, cửa sổ bị gắn cờ đầu tiên của mỗi sự cố phát một
        cảnh báo."""
        blob = _load_rt()
        if blob is None:
            print("[TẦNG 1] bỏ qua: model chưa có khóa 'rt' (chạy mục Tầng 1 của notebook rồi xuất lại joblib)."); return
        mo, mi, cfg = blob
        W, H, QUIET = int(cfg["window_min"] * 60), int(cfg["window_hop_min"] * 60), _rt_quiet(cfg)
        thr_o = _thr_q(mo, score_q)
        thr_i = _thr_q(mi, score_q_in) if mi is not None else None
        rar_in = (mi["rarity_counts"], mi["rarity_total"]) if mi is not None else None
        Pr = read_pairs(path, mo["rarity_counts"], mo["rarity_total"], last_min, rar_in)
        keys, X = _cua_so_rt({k: [(r, 0.0) for r in v] for k, v in Pr.items()}, W, H, lambda ws: np.inf,
                             lambda k, ws: False)
        if not len(X):
            print("[TẦNG 1] không có cửa sổ nào để chấm."); return
        gan_co = sorted(((i, sc, mm, t) for i, sc, mm, t in score_split(keys, X, mo, thr_o, mi, thr_i) if sc > t),
                        key=lambda z: keys[z[0]][5] * W + keys[z[0]][4])
        ep, n = {}, 0
        for i, sc, mm, t in gan_co:
            kk = keys[i]
            ws = kk[5] * W + kk[4]
            reasons = explain(X[i], mm["med"], mm["scale"], FEATS)
            state, e = _su_co_rt(ep, (kk[0], kk[1]), ws, sc, t, reasons, QUIET)
            if state is not None:
                n += 1
                _emit_rt(kk, X[i], sc, mm, t, W, {"episode": e["id"], "episode_state": state,
                                                  "episode_start": _iso(e["start"]), "episode_windows": e["n"]}, reasons)
        print(f"[TẦNG 1] {len(keys)} cửa sổ {W // 60}', {len(gan_co)} vượt ngưỡng (ra {thr_o:.4f}"
              + (f", vào {thr_i:.4f}" if thr_i is not None else "") + f"), {n} cảnh báo sau khi gom sự cố")

    def live_rt(path, interval=None, score_q=None, score_q_in=None):
        blob = _load_rt()
        if blob is None:
            print("[TẦNG 1 live] tắt: model chưa có khóa 'rt' (chạy mục Tầng 1 của notebook rồi xuất lại joblib).", flush=True)
            return
        mo, mi, cfg = blob
        s = tang1(mo, mi, cfg, score_q, score_q_in)
        # ANOMALY_RT_INTERVAL_S đổi chu kỳ đọc và chấm lại khi triển khai (mặc định theo joblib, 10 giây).
        iv = interval or int(os.environ.get("ANOMALY_RT_INTERVAL_S") or cfg.get("interval_s", 10))
        print(f"[TẦNG 1 live] cửa sổ {cfg['window_min']}', trượt {cfg['window_hop_min']}', chấm lại mỗi {iv}s, chốt cửa sổ "
              f"sau {cfg['delay_s']}s | ngưỡng ra {s.thr_o:.4f}" + (f", vào {s.thr_i:.4f}" if s.thr_i is not None else "")
              + f" | gom sự cố {int(_rt_quiet(cfg)) // 60}'", flush=True)
        st = _tail_start(path)
        while True:
            s.doc(_tail_lines(path, st))
            time.sleep(iv)

    return types.SimpleNamespace(detect=detect, live=live, detect_rt=detect_rt, live_rt=live_rt, tang1=tang1,
                                 load_rt=_load_rt)
