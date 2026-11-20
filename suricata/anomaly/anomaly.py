"""anomaly.py: runtime phát hiện bất thường trên nhật ký eve.json của Suricata.

Nạp các mô hình Isolation Forest (scikit-learn) do hai notebook xuất ra và chấm trực tiếp trên eve.json:
    net_if_model.joblib        Behavior-IF trên bản ghi flow: mỗi chiều một tham chiếu (khóa "rt": chiều ra "out" cửa sổ
                               30 phút, chiều vào "inbound" cửa sổ 2 phút), cửa sổ được chấm lại cả khi còn mở
    web_app_if_model.joblib    Web-App IF trên bản ghi http: "query" (Web-Query) và "body" (Web-Body)

Dùng:
    python3 anomaly.py --detect eve.json [--last 30] [--out F | --to-wazuh]
    python3 anomaly.py --live   eve.json [--interval N]

Phần trích đặc trưng giữ khớp với behavior_features.py và web_features.py để số liệu không lệch."""
import sys, os, json, math, time, re, gzip, ipaddress, collections, types, threading, base64, html
from datetime import datetime
from urllib.parse import unquote_plus, urlsplit, parse_qsl
import numpy as np
import common
from behavior import _build_behavior
from web import _build_web



def main(argv):
    # `python3 anomaly.py --live` dùng model và nhật ký mặc định; tham số hoặc EVE_JSON ghi đè đường dẫn.
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
    q_all = float(opt("--score-q")) if opt("--score-q") else None     # tinh chỉnh độ nhạy của Web-App IF khi demo (phân vị)
    q_web = float(opt("--web-q")) if opt("--web-q") else q_all         # riêng Web-App (cả query lẫn body)
    q_net = opt("--net-q") or opt("--rt-q")                            # Behavior-IF chiều ra (bỏ trống: ngưỡng đã chốt)
    q_net = float(q_net) if q_net else None
    q_in = opt("--in-q") or opt("--rt-in-q")                           # Behavior-IF chiều vào
    q_in = float(q_in) if q_in else None
    net_model = opt("--model-net", "net_if_model.joblib")
    web_model = opt("--model-web", "web_app_if_model.joblib")
    beh = _build_behavior(net_model); web = _build_web(model_path=web_model)

    if has("--detect"):
        path = opt("--detect", EVE)
        # --detect mặc định không ghi vào tệp Wazuh đọc (cảnh báo của nhật ký cũ sẽ bị coi là mới); --to-wazuh để ghi.
        if not has("--to-wazuh"):
            common.ALERT_LOG = opt("--out") or os.environ.get("ANOMALY_DETECT_LOG", "anomaly_detect.jsonl")
        print(f"[anomaly] ghi cảnh báo vào {common.ALERT_LOG}" + ("" if has("--to-wazuh") else " (không phải tệp Wazuh đọc; thêm --to-wazuh nếu cần)"))
        if os.path.exists(net_model):
            beh.detect(path, last, q_net, q_in)
        else: print(f"[BEHAVIOR-IF] bỏ qua: không thấy {net_model}")
        if os.path.exists(web_model): web.detect(path, last, q_web)
        else: print(f"[WEB-APP IF] bỏ qua: không thấy {web_model}")
        return
    if has("--live"):
        path = opt("--live", EVE)
        # Chỉ một phiên --live được ghi vào tệp cảnh báo, tránh ghi trùng làm sai bộ đếm luật tương quan.
        import fcntl
        _lock = open(common.ALERT_LOG + ".lock", "w")
        try:
            fcntl.flock(_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            print(f"[anomaly] đã có một phiên --live khác đang chạy (khóa {common.ALERT_LOG}.lock). "
                  "Dừng phiên đó trước:  pkill -f 'anomaly.py --live'"); return
        threads = []
        if os.path.exists(net_model):
            threads.append(threading.Thread(target=beh.live, args=(path, None, q_net, q_in), daemon=True))
        if os.path.exists(web_model):
            threads.append(threading.Thread(target=web.live, args=(path, iv, q_web), daemon=True))
        if not threads:
            print(f"Không thấy model ({net_model} / {web_model}) ở thư mục hiện tại: "
                  "chạy notebook để sinh model trước, hoặc trỏ --model-net/--model-web."); return
        print(f"[anomaly] chạy {len(threads)} engine trên {path} | ghi cảnh báo vào {common.ALERT_LOG} (Ctrl-C để dừng)")
        for t in threads: t.start()
        if common.PERF_ON:
            threading.Thread(target=common._perf_sampler, args=(iv or 30,), daemon=True).start()
            print(f"[anomaly] đo hiệu năng: BẬT, ghi {common.PERF_LOG} (mỗi {iv or 30}s)", flush=True)
        try:
            while any(t.is_alive() for t in threads): time.sleep(1)
        except KeyboardInterrupt:
            print("\n[anomaly] dừng.")
        return
    print(f"Dùng: python3 anomaly.py --live [eve.json]    (mặc định log {EVE}; model net_if_model.joblib + web_app_if_model.joblib ở thư mục hiện tại)\n"
          "      python3 anomaly.py --detect [eve.json] [--last N] [--out F | --to-wazuh]   (mặc định ghi anomaly_detect.jsonl)\n"
          "      Tùy chọn: [--interval N] [--net-q Q --in-q Q] [--score-q Q | --web-q Q] [--model-net F] [--model-web F]; hoặc EVE_JSON cho đường dẫn log.\n"
          "      --net-q, --in-q: Behavior-IF chiều ra, chiều vào; --score-q, --web-q: Web-App IF. Q càng LỚN càng nhạy (nhiều cảnh báo hơn);\n"
          "      bỏ trống thì dùng ngưỡng đã chốt trong model. Chu kỳ chấm lại của Behavior-IF đặt bằng ANOMALY_RT_INTERVAL_S.")


if __name__ == "__main__":
    main(sys.argv)
