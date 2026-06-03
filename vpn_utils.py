#!/usr/bin/env python3
"""
工具函数：IP信息批量查询、延迟测试、DNS修复、OpenVPN配置解析
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Any

COUNTRY_TRANSLATIONS: dict[str, str] = {
    "Japan": "日本", "United States": "美国", "Korea": "韩国",
    "South Korea": "韩国", "China": "中国", "Taiwan": "台湾",
    "Hong Kong": "香港", "Singapore": "新加坡", "Thailand": "泰国",
    "Vietnam": "越南", "India": "印度", "Russia": "俄罗斯",
    "Germany": "德国", "France": "法国", "United Kingdom": "英国",
    "Canada": "加拿大", "Australia": "澳大利亚", "Brazil": "巴西",
    "Netherlands": "荷兰", "Sweden": "瑞典", "Switzerland": "瑞士",
    "Italy": "意大利", "Spain": "西班牙", "Poland": "波兰",
    "Turkey": "土耳其", "Indonesia": "印度尼西亚", "Malaysia": "马来西亚",
    "Philippines": "菲律宾", "Mexico": "墨西哥", "Argentina": "阿根廷",
    "Ukraine": "乌克兰", "Romania": "罗马尼亚", "Czech Republic": "捷克",
    "Hungary": "匈牙利", "Finland": "芬兰", "Norway": "挪威",
    "Denmark": "丹麦", "Belgium": "比利时", "Austria": "奥地利",
    "Portugal": "葡萄牙", "Greece": "希腊", "Israel": "以色列",
    "United Arab Emirates": "阿联酋", "Saudi Arabia": "沙特阿拉伯",
    "South Africa": "南非", "Egypt": "埃及", "Nigeria": "尼日利亚",
    "New Zealand": "新西兰", "Mongolia": "蒙古", "Kazakhstan": "哈萨克斯坦",
    "Unknown": "未知",
}

_IP_CACHE_FILE = Path(os.environ.get("VPNGATE_DATA_DIR", "vpngate_data")) / "ip_cache.json"
_ip_cache_lock = __import__("threading").Lock()

def _load_ip_cache() -> dict:
    try:
        return json.loads(_IP_CACHE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}

def _save_ip_cache(cache: dict) -> None:
    try:
        _IP_CACHE_FILE.parent.mkdir(exist_ok=True, parents=True)
        _IP_CACHE_FILE.write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass

def _classify_from_batch(item: dict) -> tuple[str, str]:
    if item.get("mobile"):
        return "residential", "移动网络"
    if item.get("proxy"):
        return "proxy", "代理/VPN"
    if item.get("hosting"):
        return "datacenter", "机房IP"
    org = (item.get("org") or "").lower()
    isp = (item.get("isp") or "").lower()
    DC_KEYWORDS = [
        "softether", "vpngate", "cloud", "hosting", "host ", "server",
        "datacenter", "data center", "vps", "virtual", "dedicated",
        "coloc", "cdn", "idc", "amazon", "google", "microsoft", "azure",
        "alibaba", "tencent", "oracle", "linode", "digitalocean", "vultr",
        "ovh", "hetzner", "leaseweb", "choopa", "quadranet", "cogent",
        "hurricane", "ntt ", "sakura", "conoha", "kagoya", "xserver",
        "ablenet", "gmo internet", "softlayer", "rackspace", "psychz",
        "backbone", "telecom research", "research institute",
    ]
    combined = org + " " + isp
    for kw in DC_KEYWORDS:
        if kw in combined:
            return "datacenter", "机房IP"
    def _normalize(s: str) -> str:
        return re.sub(r"\b(corporation|corp|inc|ltd|llc|co\.|gmbh|s\.a\.|plc|ab)\b", "", s).strip()
    org_n = _normalize(org)
    isp_n = _normalize(isp)
    if org_n and isp_n and (org_n in isp_n or isp_n in org_n):
        return "residential", "住宅IP"
    return "residential", "住宅IP"

def enrich_ip_info(nodes: list[dict[str, Any]], timeout: float = 15.0) -> None:
    now = time.time()
    CACHE_TTL = 7 * 24 * 3600
    with _ip_cache_lock:
        cache = _load_ip_cache()
    ips_to_query: list[str] = []
    for node in nodes:
        ip = node.get("ip") or node.get("remote_host") or ""
        if not ip:
            _set_unknown(node)
            continue
        if ip in cache and now - cache[ip].get("cached_at", 0) < CACHE_TTL:
            _apply_cache(node, cache[ip])
        else:
            if ip not in ips_to_query:
                ips_to_query.append(ip)
    if not ips_to_query:
        return
    new_entries: dict[str, dict] = {}
    chunk_size = 100
    for i in range(0, len(ips_to_query), chunk_size):
        chunk = ips_to_query[i:i + chunk_size]
        payload = json.dumps(chunk).encode("utf-8")
        req = urllib.request.Request(
            "http://ip-api.com/batch?lang=zh-CN&fields=status,query,country,countryCode,regionName,city,isp,org,as,asname,proxy,hosting,mobile",
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "vpngate-pro/1.0"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
            for item in data:
                if item.get("status") != "success":
                    continue
                query_ip = item.get("query", "")
                if not query_ip:
                    continue
                ip_type, quality = _classify_from_batch(item)
                country_en = item.get("country", "")
                country_zh = COUNTRY_TRANSLATIONS.get(country_en, country_en)
                loc_parts = [item.get("city", ""), item.get("regionName", "")]
                location = " ".join(p for p in loc_parts if p)
                entry = {
                    "owner":      item.get("org") or item.get("isp") or "",
                    "asn":        item.get("as") or "",
                    "as_name":    item.get("asname") or "",
                    "location":   location,
                    "country_zh": country_zh,
                    "ip_type":    ip_type,
                    "quality":    quality,
                    "cached_at":  now,
                }
                new_entries[query_ip] = entry
        except Exception as e:
            print(f"[enrich_ip_info] 批量查询失败: {e}", flush=True)
    if new_entries:
        with _ip_cache_lock:
            cache = _load_ip_cache()
            cache.update(new_entries)
            _save_ip_cache(cache)
    for node in nodes:
        ip = node.get("ip") or node.get("remote_host") or ""
        if ip in new_entries:
            _apply_cache(node, new_entries[ip])
        elif not node.get("ip_type"):
            _set_unknown(node)

def _apply_cache(node: dict, entry: dict) -> None:
    node["owner"]      = entry.get("owner", "")
    node["asn"]        = entry.get("asn", "")
    node["as_name"]    = entry.get("as_name", "")
    node["location"]   = entry.get("location", "")
    node["country_zh"] = entry.get("country_zh", "")
    node["ip_type"]    = entry.get("ip_type", "unknown")
    node["quality"]    = entry.get("quality", "未知")

def _set_unknown(node: dict) -> None:
    node.setdefault("owner",      "")
    node.setdefault("asn",        "")
    node.setdefault("as_name",    "")
    node.setdefault("location",   "")
    node.setdefault("country_zh", "")
    node.setdefault("ip_type",    "unknown")
    node.setdefault("quality",    "未知")

def parse_remote(config_text: str, fallback_ip: str = "") -> tuple[str, int, str]:
    host, port, proto = fallback_ip, 1194, "udp"
    for line in config_text.splitlines():
        line = line.strip()
        if line.startswith("remote "):
            parts = line.split()
            if len(parts) >= 2:
                host = parts[1]
            if len(parts) >= 3:
                try:
                    port = int(parts[2])
                except ValueError:
                    pass
        elif line.startswith("proto "):
            parts = line.split()
            if len(parts) >= 2:
                proto = parts[1].lower().replace("6", "")
    return host, port, proto

def is_config_tcp(config_text: str) -> bool:
    for line in config_text.splitlines():
        if line.strip().lower().startswith("proto ") and "tcp" in line:
            return True
    return False

def ping_latency_ms(host: str, port: int, proto: str = "tcp",
                    fallback: int = 0, timeout: float = 4.0) -> int:
    """
    延迟测试：TCP节点用TCP连接测试，UDP节点用ICMP ping测试。
    返回毫秒延迟，失败返回fallback（0表示不可达）。
    """
    if proto == "tcp":
        # TCP连接测试
        try:
            t0 = time.monotonic()
            sock = socket.create_connection((host, port), timeout=timeout)
            latency = max(1, int((time.monotonic() - t0) * 1000))
            sock.close()
            return latency
        except Exception:
            pass
        # TCP失败，用ICMP备用
    # ICMP ping测试（UDP节点或TCP失败时）
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(int(timeout)), host],
            capture_output=True, text=True, timeout=timeout + 1
        )
        if result.returncode == 0:
            m = re.search(r"time=(\d+\.?\d*)", result.stdout)
            if m:
                return max(1, int(float(m.group(1))))
    except Exception:
        pass
    return fallback

def check_and_fix_dns() -> None:
    try:
        socket.setdefaulttimeout(3)
        socket.getaddrinfo("www.vpngate.net", 443)
        return
    except Exception:
        pass
    resolv = "/etc/resolv.conf"
    try:
        content = open(resolv).read()
        if "8.8.8.8" not in content:
            with open(resolv, "a") as f:
                f.write("\nnameserver 8.8.8.8\nnameserver 1.1.1.1\n")
            print("[DNS修复] 已添加备用 DNS", flush=True)
    except Exception as e:
        print(f"[DNS修复] 失败: {e}", flush=True)
