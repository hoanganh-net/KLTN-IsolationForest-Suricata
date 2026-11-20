"""behavior.py: Behavior-IF trên bản ghi flow, mỗi chiều một tham chiếu, cửa sổ chấm lại cả khi còn mở (module anomaly_if_rt)."""
import sys, os, json, math, time, re, gzip, ipaddress, collections, types, threading, base64, html
from datetime import datetime
from urllib.parse import unquote_plus, urlsplit, parse_qsl
import numpy as np
from common import (WHITELIST_PATH, _chon_cot, _emit, _load_whitelist, _open, _score,
                    _severity, _tail_lines, _tail_start, _tail_warm, _thr_q, explain, zscore)



# ---- Behavior-IF: bản ghi flow ----
def _build_behavior(model_path="net_if_model.joblib"):
    VICTIM_NETS = [ipaddress.ip_network("192.168.10.0/24")]
    MGMT_NETS   = [ipaddress.ip_network("192.168.20.0/24")]
    EXCLUDE_PORTS = {0, 53, 5353, 5355, 137, 138, 123}
    EXCLUDE_SRC = set()
    MIN_CONN = 1
    INCOMPLETE_STATES = {"syn_sent", "syn_recv"}
    FEATS = ["log_n_conn", "sqrt_mb_out", "sqrt_mb_in", "frac_out", "log_throughput",
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
        # Hai chiều chấm theo bên khởi tạo: chiều ra dùng tham chiếu "out", chiều vào dùng tham chiếu "inbound" (nếu có).
        zs, zd = zone(s), zone(d)
        return (zs == "victim" and zd in ("ext", "mgmt")) or (zs == "ext" and zd == "victim")

    # Giới hạn bộ đệm của --live: cặp vượt giới hạn chỉ mất các luồng cũ nhất.
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
                math.sqrt(sin_ / 1e6),
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

    def _iso(ts):
        return datetime.fromtimestamp(ts).astimezone().isoformat(timespec="seconds")

    # ---- engine chấm sớm ----
    # Mỗi chiều một tham chiếu với độ dài cửa sổ riêng (chiều vào 2 phút, chiều ra 30 phút). Mỗi lượt đọc chấm lại các cửa sổ
    # chưa chốt vừa có thêm luồng và báo ngay khi vượt ngưỡng; cửa sổ chốt khi đồng hồ qua cuối cửa sổ cộng delay_s. Tham số
    # và tham chiếu ở khóa "rt" của joblib; thiếu khóa này thì Behavior-IF tắt.
    def _load_rt():
        import joblib
        rt = joblib.load(model_path).get("rt")
        if not rt:
            return None
        mo = _chon_cot(rt["out"], FEATS, "Behavior-IF chiều ra")
        mi = _chon_cot(rt["inbound"], FEATS, "Behavior-IF chiều vào") if rt.get("inbound") else None
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
               "window_start": _iso(b * W + off), "location": f"cửa sổ {W // 60}'",
               "score": float(sc), "thr": thr,
               **({"behavior": beh} if beh else {}),
               "reasons": reasons if reasons is not None else explain(x, m["med"], m["scale"], FEATS), **(extra or {})})

    def _su_co_rt(ep, p, ws, sc, t, reasons, QUIET, cua_so_moi=True):
        """Chính sách báo: mở sự cố mới khi cặp đã yên quá QUIET; trong sự cố chỉ báo lại khi tăng lên high hoặc đặc trưng
        lệch nhất đổi sang đặc trưng chưa gặp, không nhắc lại định kỳ. Trả (trạng thái hoặc None, sự cố)."""
        sev, top = _severity(sc, t), (reasons[0][0] if reasons else "")
        e = ep.get(p)
        if e is None or ws - e["last"] > QUIET:
            e = ep[p] = {"id": f"{p[0]}>{p[1]}@{_iso(ws)}", "start": ws, "last": ws, "n": 1, "sev": sev, "tops": {top}}
            return "new", e
        if cua_so_moi: e["n"] += 1
        e["last"] = max(e["last"], ws)
        if sev == "high" and e["sev"] != "high": state = "escalated"
        elif top and top not in e["tops"]: state = "new_behavior"
        else: state = None
        e["tops"].add(top)
        if sev == "high": e["sev"] = "high"
        return state, e

    def _cua_so_rt(P, W, H, han_fn, bo_qua, da_thay=None):
        """Cửa sổ từ P[(nguồn, đích)] = [(row, thời điểm tới)], chỉ lấy luồng tới không muộn hơn han_fn(ws);
        khóa bị bo_qua loại thì bỏ. da_thay (từ điển khóa -> số luồng ở lần chấm trước): cửa sổ không có thêm luồng thì
        không dựng lại. Phần tử thứ tám của khóa là lúc bắt đầu của luồng sớm nhất, dùng tính lat_s."""
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
                    if da_thay is not None:
                        dau_vet = (len(rws), rws[-1][0])
                        if da_thay.get((s, d, off, b)) == dau_vet:
                            continue
                        da_thay[(s, d, off, b)] = dau_vet
                    c = list(zip(*rws))
                    X.append(feature_vector(c[0], c[1], c[2], c[3], c[4], c[5], c[6]))
                    keys.append((s, d, ext_ip(s, d), len(rws), off, b, int(collections.Counter(c[4]).most_common(1)[0][0]),
                                 min(c[0]), sorted({int(p) for p in c[4]})[:DPORTS_MAX]))
        return keys, (np.array(X) if X else np.empty((0, len(FEATS))))

    def _tham_so(m, rt, score_q=None):
        """Tham số cửa sổ của một tham chiếu; joblib cũ ghi chung ở khóa "rt". ANOMALY_RT_QUIET_MIN đổi thời gian yên lặng của
        sự cố khi triển khai (phút). Thời gian yên lặng không nhỏ hơn bước trượt: hai cửa sổ chồng nhau cùng chứa một hành
        vi phải thuộc một sự cố, nếu không chiều ra (bước 15 phút) sẽ báo hai lần cho cùng một hành vi."""
        ov = os.environ.get("ANOMALY_RT_QUIET_MIN")
        W = int(m.get("window_min", rt.get("window_min", 2)) * 60)
        H = int(m.get("window_hop_min", rt.get("window_hop_min", 1)) * 60)
        yen = float(ov) * 60 if ov else float(m.get("quiet_s", rt.get("quiet_s", 900)))
        return types.SimpleNamespace(m=m, W=W, H=H, D=float(rt["delay_s"]), quiet=max(yen, float(H)),
                                     rescore=bool(m.get("rescore", False)), thr=_thr_q(m, score_q),
                                     buf=[], fired=set(), done=set(), seen={}, ep={}, last_note=0.0)

    def rt_engine(mo, mi, rt, score_q=None, score_q_in=None, phat=None):
        """Bộ xử lý: doc(dòng) nhận dòng eve.json mới, cập nhật đồng hồ chung, rồi với từng chiều chấm lại các cửa sổ chưa
        chốt vừa có thêm luồng và gọi phat(...) cho lần chấm vượt ngưỡng; trạng thái None là cộng dồn vào sự cố đang mở,
        không báo. Cửa sổ đã vượt ngưỡng chỉ được chấm tiếp khi tham chiếu đặt rescore (chiều ra)."""
        C = {"out": _tham_so(mo, rt, score_q)}
        if mi is not None: C["in"] = _tham_so(mi, rt, score_q_in)
        rc, rtot = mo["rarity_counts"], mo["rarity_total"]
        rar_in = (mi["rarity_counts"], mi["rarity_total"]) if mi is not None else None
        s = types.SimpleNamespace(clock=None, t_from=None, n_alert=0, C=C, thr_o=C["out"].thr,
                                  thr_i=C["in"].thr if "in" in C else None, im_lang=False)

        def mac_dinh(kk, x, sc, mm, t, W, extra, state, reasons):
            if state is not None and not s.im_lang:
                s.n_alert += 1
                _emit_rt(kk, x, sc, mm, t, W, extra, reasons)

        def cham(c):
            if not c.buf:
                return
            clock, W, D = s.clock, c.W, c.D
            P = collections.defaultdict(list)
            for pk, item in c.buf: P[pk].append(item)

            def bo_qua(k, ws):
                if ws < s.t_from or k in c.done or (k in c.fired and not c.rescore):
                    return True
                if clock > ws + W + D:                           # lần chấm cuối của cửa sổ này
                    c.done.add(k)
                return False
            keys, X = _cua_so_rt(P, W, c.H, lambda ws: min(clock, ws + W + D), bo_qua, c.seen)
            if len(X):
                diem = _score(c.m, X)
                for i in sorted(np.flatnonzero(diem > c.thr), key=lambda i: keys[i][5] * W + keys[i][4]):
                    kk = keys[i]; k4 = (kk[0], kk[1], kk[4], kk[5]); sc = float(diem[i])
                    moi = k4 not in c.fired
                    c.fired.add(k4)
                    ws = kk[5] * W + kk[4]
                    reasons = explain(X[i], c.m["med"], c.m["scale"], FEATS)
                    state, e = _su_co_rt(c.ep, (kk[0], kk[1]), ws, sc, c.thr, reasons, c.quiet, moi)
                    extra = {"episode": e["id"], "episode_state": state or "", "episode_start": _iso(e["start"]),
                             "episode_windows": e["n"], "t_det_s": round(clock - ws, 1),
                             "lat_s": round(time.time() - kk[7], 1)}
                    (phat or mac_dinh)(kk, X[i], sc, c.m, c.thr, W, extra, state, reasons)
            lo = clock - (W + c.H + D + 60)                      # cắt luồng của các cửa sổ đã chốt
            c.buf = [it for it in c.buf if it[1][0][0] >= lo]
            c.buf, note = cap_buffer(c.buf)
            if note and time.time() - c.last_note > 60:
                print(f"[BEHAVIOR-IF live] bộ đệm chạm giới hạn ({'; '.join(note)}), chỉ giữ luồng mới nhất", flush=True)
                c.last_note = time.time()
            bmin = int((lo - W) // W) - 1
            c.fired = {k for k in c.fired if k[3] >= bmin}
            c.done = {k for k in c.done if k[3] >= bmin}
            c.seen = {k: v for k, v in c.seen.items() if k[3] >= bmin}
            for p in [p for p, e in c.ep.items() if clock - e["last"] > c.quiet + W + D]:
                c.ep.pop(p)

        def doc(lines):
            for line in lines:
                if '"event_type":"flow"' not in line and '"event_type": "flow"' not in line: continue
                try: o = json.loads(line)
                except Exception: continue
                r = flow_row(o, rc, rtot, rar_in)
                if r is None: continue
                d = "out" if zone(r[0][0]) == "victim" else "in"
                if d not in C: continue
                en = r[1][0] + r[1][3]
                if en > time.time() + 300: continue            # mốc thời gian ở tương lai (đồng hồ lệch): bỏ
                s.clock = en if s.clock is None else max(s.clock, en)
                if s.t_from is None: s.t_from = s.clock          # cửa sổ mở trước lúc khởi động bị bỏ qua
                C[d].buf.append((r[0], (r[1], s.clock)))         # thời điểm tới = đồng hồ ngay sau khi đọc luồng
            if s.clock is None:
                return
            for c in C.values(): cham(c)

        s.doc = doc
        return s

    def detect_rt(path, last_min=None, score_q=None, score_q_in=None):
        """Chấm một tệp có sẵn: mọi cửa sổ với đủ luồng, cửa sổ bị gắn cờ đầu tiên của mỗi sự cố phát một
        cảnh báo."""
        blob = _load_rt()
        if blob is None:
            print("[BEHAVIOR-IF] bỏ qua: model chưa có khóa 'rt' (chạy notebook Behavior-IF rồi xuất lại joblib)."); return
        mo, mi, rt = blob
        rar_in = (mi["rarity_counts"], mi["rarity_total"]) if mi is not None else None
        Pr = read_pairs(path, mo["rarity_counts"], mo["rarity_total"], last_min, rar_in)
        for d, m, sq in (("out", mo, score_q), ("in", mi, score_q_in)):
            if m is None: continue
            c = _tham_so(m, rt, sq)
            P = {k: [(r, 0.0) for r in v] for k, v in Pr.items() if (zone(k[0]) == "victim") == (d == "out")}
            keys, X = _cua_so_rt(P, c.W, c.H, lambda ws: np.inf, lambda k, ws: False)
            if not len(X):
                print(f"[BEHAVIOR-IF] chiều {'ra' if d == 'out' else 'vào'}: không có cửa sổ nào để chấm."); continue
            diem = _score(m, X); n = 0
            gan_co = sorted(np.flatnonzero(diem > c.thr), key=lambda i: keys[i][5] * c.W + keys[i][4])
            for i in gan_co:
                kk = keys[i]; ws = kk[5] * c.W + kk[4]
                reasons = explain(X[i], m["med"], m["scale"], FEATS)
                state, e = _su_co_rt(c.ep, (kk[0], kk[1]), ws, float(diem[i]), c.thr, reasons, c.quiet)
                if state is not None:
                    n += 1
                    _emit_rt(kk, X[i], float(diem[i]), m, c.thr, c.W, {"episode": e["id"], "episode_state": state,
                             "episode_start": _iso(e["start"]), "episode_windows": e["n"]}, reasons)
            print(f"[BEHAVIOR-IF] chiều {'ra' if d == 'out' else 'vào'}: {len(keys)} cửa sổ {c.W // 60}', {len(gan_co)} vượt ngưỡng "
                  f"({c.thr:.4f}), {n} cảnh báo sau khi gom sự cố")

    _END = re.compile(r'"end"\s*:\s*"([^"]+)"')

    def khoi_dong_am(s, path, buoc=10.0, giu_s=7200.0):
        """Đọc lại phần cuối eve.json để dựng lại các cửa sổ và sự cố đang mở (cửa sổ chiều ra dài 30 phút; không đọc lại thì
        sau mỗi lần khởi động chiều ra phải chờ tới mốc 15 phút kế tiếp mới có cửa sổ trọn vẹn). Hai giờ gần nhất của nhật ký
        được phát lại theo từng bước đồng hồ như khi chạy, nên trạng thái sự cố giống một engine chạy liên tục; phần đọc lại
        không phát cảnh báo. ANOMALY_WARM_MB đổi dung lượng đọc lại (mặc định 64 MB, 0 là tắt). Trả vị trí đọc tiếp."""
        mb = float(os.environ.get("ANOMALY_WARM_MB") or 64)
        if mb <= 0:
            return _tail_start(path)
        lines, st = _tail_warm(path, mb * 1e6)
        luong, dong_ho = [], None
        for line in lines:
            if '"event_type":"flow"' not in line and '"event_type": "flow"' not in line: continue
            m = _END.search(line)
            t = parse(m.group(1)) if m else None
            if t is None: continue
            dong_ho = t if dong_ho is None else max(dong_ho, t)
            luong.append((dong_ho, line))
        if not luong:
            return st
        luong = [x for x in luong if x[0] >= dong_ho - giu_s]
        s.im_lang = True
        try:
            nhom, moc = [], math.ceil(luong[0][0] / buoc) * buoc
            for t, line in luong:
                if t > moc:
                    s.doc(nhom); nhom, moc = [], math.ceil(t / buoc) * buoc
                nhom.append(line)
            s.doc(nhom)
        finally:
            s.im_lang = False
        print(f"[BEHAVIOR-IF live] khởi động ấm: phát lại {len(luong)} luồng của {min(giu_s, dong_ho - luong[0][0]) / 60:.0f} phút gần nhất để dựng lại "
              f"cửa sổ đang mở, không phát cảnh báo cho phần này", flush=True)
        return st

    def live_rt(path, interval=None, score_q=None, score_q_in=None):
        blob = _load_rt()
        if blob is None:
            print("[BEHAVIOR-IF live] tắt: model chưa có khóa 'rt' (chạy notebook Behavior-IF rồi xuất lại joblib).", flush=True)
            return
        mo, mi, rt = blob
        s = rt_engine(mo, mi, rt, score_q, score_q_in)
        # ANOMALY_RT_INTERVAL_S đổi chu kỳ đọc và chấm lại khi triển khai (mặc định theo joblib, 10 giây).
        iv = interval or int(os.environ.get("ANOMALY_RT_INTERVAL_S") or rt.get("interval_s", 10))
        for d, c in s.C.items():
            print(f"[BEHAVIOR-IF live] chiều {'ra' if d == 'out' else 'vào'}: cửa sổ {c.W // 60}', trượt {c.H // 60}', chốt sau "
                  f"{c.D:.0f}s | ngưỡng {c.thr:.4f} | gom sự cố {int(c.quiet) // 60}'"
                  + (" | chấm tiếp cửa sổ đã vượt ngưỡng" if c.rescore else ""), flush=True)
        print(f"[BEHAVIOR-IF live] chấm lại mỗi {iv}s", flush=True)
        st = khoi_dong_am(s, path, float(iv))
        while True:
            s.doc(_tail_lines(path, st))
            time.sleep(iv)

    return types.SimpleNamespace(detect=detect_rt, live=live_rt, rt_engine=rt_engine, load_rt=_load_rt, warm=khoi_dong_am)
