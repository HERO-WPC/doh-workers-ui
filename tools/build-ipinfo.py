# -*- coding: utf-8 -*-
# 从来源 CSV(扫描器导出格式)提取 IP 归属信息,合并进 tools/ip-info.json
# 用法: python tools/build-ipinfo.py 源CSV1 [源CSV2 ...]
import csv
import json
import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(BASE, "ip-info.json")

# org 文本 → (ASN, 服务商)
ORG_MAP = [
    ("alibaba", "AS45102", "阿里云"),
    ("tencent", "AS132203", "腾讯云"),
    ("amazon-02", "AS16509", "AWS"),
    ("amazon.com", "AS16509", "AWS"),
    ("hkt", "AS4760", "HKT 香港电讯"),
    ("pccw", "AS4760", "HKT 香港电讯"),
    ("hkbn", "AS9269", "香港宽频"),
    ("huawei", "AS136907", "华为云"),
    ("zenlayer", "AS21859", "Zenlayer"),
    ("dmit", "AS906", "DMIT"),
    ("ucloud", "AS135377", "UCloud 优刻得"),
    ("google", "AS396982", "Google Cloud"),
    ("microsoft", "AS8075", "Azure"),
    ("cloudflare", "AS13335", "Cloudflare"),
    ("digitalocean", "AS14061", "DigitalOcean"),
    ("vultr", "AS20473", "Vultr"),
    ("linode", "AS63949", "Linode"),
    ("oracle", "AS31898", "Oracle Cloud"),
    ("china mobile", "AS58453", "中国移动国际"),
    ("china telecom", "AS4809", "中国电信"),
    ("chinanet", "AS4809", "中国电信"),
    ("china unicom", "AS4837", "中国联通"),
    ("hgc", "AS9304", "和记环球 HGC"),
]

def org_lookup(org_text):
    low = (org_text or "").lower()
    for key, asn, name in ORG_MAP:
        if key in low:
            return asn, name
    return None, None

def load_csv(path):
    try:
        rows = list(csv.reader(open(path, encoding="utf-8-sig", errors="replace")))
    except OSError:
        return []
    if not rows:
        return []
    if not rows:
        return []
    header = [h.strip().lower() for h in rows[0]]
    if "ip" not in header:
        return []
    ip_i, port_i = header.index("ip"), header.index("port")
    org_i = header.index("org") if "org" in header else None
    cty_i = header.index("country") if "country" in header else None
    city_i = header.index("city") if "city" in header else None
    out = []
    for r in rows[1:]:
        if len(r) <= max(ip_i, port_i):
            continue
        ip = r[ip_i].strip()
        if not ip:
            continue
        org = r[org_i].strip() if org_i is not None and org_i < len(r) else ""
        asn, provider = org_lookup(org)
        region = " ".join(x for x in ([r[cty_i].strip() if cty_i is not None and cty_i < len(r) else "",
                                      r[city_i].strip() if city_i is not None and city_i < len(r) else ""]) if x)
        out.append({"ip": ip, "asn": asn or None, "provider": provider or None, "region": region or None})
    return out

def main():
    info = {}
    if os.path.exists(OUT):
        try:
            info = json.load(open(OUT, encoding="utf-8"))
        except Exception:
            info = {}
    added = updated = 0
    for path in sys.argv[1:]:
        for e in load_csv(path):
            cur = info.get(e["ip"])
            if cur is None:
                info[e["ip"]] = e
                added += 1
            else:
                # 补全缺失字段
                ch = False
                for k in ("asn", "provider", "region"):
                    if not cur.get(k) and e.get(k):
                        cur[k] = e[k]; ch = True
                if ch: updated += 1
    json.dump(info, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"ip-info.json: 新增 {added} | 补全 {updated} | 总计 {len(info)}")

main()
