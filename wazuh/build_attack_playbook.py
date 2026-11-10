#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sinh attack_v20_playbook.json cho thẻ cảnh báo của nhánh bất thường.

Nguồn: dữ liệu MITRE ATT&CK Enterprise phiên bản 20.0 (STIX 2.1) do MITRE công bố trong kho
mitre-attack/attack-stix-data trên GitHub. Tệp nguồn được ghim đúng phiên bản (enterprise-attack-20.0.json)
để thẻ cảnh báo luôn dựa trên một bản dữ liệu cố định, tái lập được.

Chạy (một lần, trên máy có Internet):
    python build_attack_playbook.py                         # tự tải bản 20.0 từ GitHub
    python build_attack_playbook.py enterprise-attack-20.0.json   # hoặc dùng tệp đã tải sẵn
Đầu ra: attack_v20_playbook.json, chép lên Wazuh manager cạnh custom-telegram-anomaly.py
(/var/ossec/integrations/). Script thông báo chỉ ĐỌC tệp này, không truy cập Internet khi có cảnh báo.

Với mỗi kỹ thuật mà thẻ cảnh báo có thể gợi ý, tệp ghi: tên chính thức, chiến thuật (mã TA và tên),
đường dẫn trang kỹ thuật, các Mitigations (mã M) kèm hướng dẫn riêng cho kỹ thuật
đó, và các chiến lược phát hiện (detection strategy, mã DET) liên quan.
"""
import json, re, sys, urllib.request
from datetime import date

URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
       "enterprise-attack/enterprise-attack-20.0.json")
EXPECTED_VERSION = "20.0"
# Các kỹ thuật thẻ cảnh báo có thể gợi ý (khớp Bảng 2.1 và Bảng 2.3 của báo cáo); T1595 và T1499 dùng cho
# các giả thuyết của Behavior-IF chiều vào (dò quét từ bên ngoài, làm ngập kết nối).
TECHS = ["T1071", "T1048", "T1105", "T1046", "T1110", "T1498", "T1190", "T1595", "T1499"]
OUT = "attack_v20_playbook.json"


def load(src):
    if src.startswith("http://") or src.startswith("https://"):
        print("Tải", src)
        with urllib.request.urlopen(src, timeout=300) as r:
            return json.load(r)
    with open(src, encoding="utf-8") as f:
        return json.load(f)


def ext_id(o):
    for r in o.get("external_references", []):
        if r.get("source_name") == "mitre-attack":
            return r.get("external_id")
    return None


def alive(o):
    return not o.get("revoked") and not o.get("x_mitre_deprecated")


def clean(s):
    s = re.sub(r"\(Citation:[^)]*\)", "", s or "")            # bỏ chú thích trích dẫn nội bộ của STIX
    s = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", s)             # [chữ](liên kết) -> chữ
    return re.sub(r"\s+", " ", s).strip()


def main(src):
    bundle = load(src)
    objs = bundle["objects"]
    coll = next(o for o in objs if o.get("type") == "x-mitre-collection")
    version = coll.get("x_mitre_version")
    if version != EXPECTED_VERSION:
        sys.exit("Sai phiên bản ATT&CK: {0} (cần {1})".format(version, EXPECTED_VERSION))
    by_id = {o["id"]: o for o in objs}
    tactics = {o.get("x_mitre_shortname"): (ext_id(o), o["name"])
               for o in objs if o.get("type") == "x-mitre-tactic" and alive(o)}
    techs = {ext_id(o): o for o in objs if o.get("type") == "attack-pattern" and alive(o)}
    rels = [o for o in objs if o.get("type") == "relationship" and alive(o)]

    out = {"attack_version": version, "attack_modified": coll.get("modified"), "source": URL,
           "generated": date.today().isoformat(), "techniques": {}}
    for t in TECHS:
        o = techs.get(t)
        if o is None:
            sys.exit("Không tìm thấy kỹ thuật {0} (bị thu hồi hoặc ngừng dùng?)".format(t))
        mit, det = [], []
        for r in rels:
            if r["target_ref"] != o["id"]:
                continue
            s = by_id.get(r["source_ref"])
            if not s or not alive(s):
                continue
            if r["relationship_type"] == "mitigates" and s["type"] == "course-of-action":
                mit.append({"id": ext_id(s), "name": s["name"], "guidance": clean(r.get("description"))})
            elif r["relationship_type"] == "detects" and s["type"] == "x-mitre-detection-strategy":
                det.append({"id": ext_id(s), "name": s["name"]})
        out["techniques"][t] = {
            "name": o["name"],
            "tactics": [{"id": tactics[p["phase_name"]][0], "name": tactics[p["phase_name"]][1]}
                        for p in o.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"],
            "url": "https://attack.mitre.org/techniques/{0}/".format(t),
            "mitigations": sorted(mit, key=lambda m: m["id"]),
            "detection_strategies": sorted(det, key=lambda d: d["id"]),
        }
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print("Đã ghi {0}: ATT&CK {1} ({2}), {3} kỹ thuật".format(OUT, version, coll.get("modified"), len(TECHS)))
    for t, v in out["techniques"].items():
        print("  {0} {1} | {2} | {3}".format(t, v["name"], ", ".join(x["id"] for x in v["tactics"]),
                                             ", ".join(m["id"] for m in v["mitigations"])))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else URL)
