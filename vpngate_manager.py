#!/usr/bin/env python3
"""VPNGate Pro - 双节点智能代理网关"""
from __future__ import annotations
import base64, concurrent.futures, csv, hashlib, json, os, queue
import random, re, socket, string, subprocess, threading, time
import urllib.parse, urllib.request, uuid as _uuid_mod
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

_orig_getaddrinfo = socket.getaddrinfo
def _ipv4_only(host, port, family=0, type=0, proto=0, flags=0):
    if family == 0: family = socket.AF_INET
    return _orig_getaddrinfo(host, port, family, type, proto, flags)
socket.getaddrinfo = _ipv4_only

import vpn_utils
import proxy_server as proxy_mod

API_URL   = "https://www.vpngate.net/api/iphone/"
ROOT_DIR  = Path(__file__).resolve().parent
DATA_DIR  = Path(os.environ.get("VPNGATE_DATA_DIR", str(ROOT_DIR / "vpngate_data")))
CONFIG_DIR        = DATA_DIR / "configs"
NODES_FILE        = DATA_DIR / "nodes.json"
CUSTOM_NODES_FILE = DATA_DIR / "custom_nodes.json"
UI_AUTH_FILE      = DATA_DIR / "ui_auth.json"
SLOT_CONFIG_FILE  = DATA_DIR / "slot_config.json"
XRAY_DISPATCH_FILE= DATA_DIR / "xray_dispatch.json"
AUTH_FILE         = DATA_DIR / "vpngate_auth.txt"
LOGS_DIR          = DATA_DIR / "logs"
XRAY_BIN        = Path("/root/agsbx/xray")
XRAY_CFG        = Path("/root/agsbx/xr.json")
XRAY_LOG        = Path("/root/agsbx/xray.log")
XRAY_CONFIG_FILE = XRAY_CFG   # 兼容旧引用

def _restart_xray() -> bool:
    """强制杀死并重启 xray 进程，返回是否成功"""
    # 先尝试优雅退出，再强制kill
    subprocess.run(["pkill", "-f", "xray run"], capture_output=True)
    time.sleep(1)
    subprocess.run(["pkill", "-9", "-f", "xray run"], capture_output=True)
    time.sleep(1)
    if not XRAY_BIN.exists():
        log("ERROR", "xray", f"xray 可执行文件不存在: {XRAY_BIN}")
        return False
    try:
        log_file = open(XRAY_LOG, "a")
        proc = subprocess.Popen(
            [str(XRAY_BIN), "run", "-c", str(XRAY_CFG)],
            stdout=log_file, stderr=log_file,
            start_new_session=True,
        )
        time.sleep(2)
        if proc.poll() is None:
            log("INFO", "xray", f"xray 重启成功，PID={proc.pid}")
            return True
        else:
            log("ERROR", "xray", "xray 启动后立即退出")
            return False
    except Exception as e:
        log("ERROR", "xray", f"xray 启动失败: {e}")
        return False

def xray_watchdog() -> None:
    """守护线程：每30秒检查 xray 是否在运行，崩溃则自动重启"""
    time.sleep(15)  # 启动后等15秒再开始监控
    while True:
        time.sleep(30)
        result = subprocess.run(["pgrep", "-f", "xray run"],
                                capture_output=True, text=True)
        if not result.stdout.strip():
            log("WARNING", "xray", "xray 进程不存在，自动重启...")
            _restart_xray()

OPENVPN_CMD       = os.environ.get("OPENVPN_CMD", "openvpn")
MAX_SCAN_ROWS     = 5000   # VPNGate API 返回几千行，全部扫描
MAX_CONCURRENT_TESTS = 6
OPENVPN_TIMEOUT   = 35

SLOTS = [
    {"id": 0, "tun": "tun10", "table": 110, "proxy_port": 7920},
    {"id": 1, "tun": "tun11", "table": 111, "proxy_port": 7921},
]

lock = threading.RLock()

# ── Slot状态 ─────────────────────────────────────────────────────────
class SlotState:
    def __init__(self, slot_id: int):
        self.slot_id      = slot_id
        self.process: subprocess.Popen | None = None
        self.node_id      = ""
        self.node_type    = ""
        self.is_connecting= False
        self.status_msg   = "未启动"
        self.proxy_ok     = False
        self.proxy_ip     = ""
        self.latency_ms   = 0
        self.tun_ip       = ""   # 当前 tun 本地 IP（用于策略路由清理）
        # 主备节点状态
        self.using_backup = False
        self.primary_id   = ""
        self.backup_ids: list[str] = []

slot_states = {s["id"]: SlotState(s["id"]) for s in SLOTS}

# ── 每槽配置 ─────────────────────────────────────────────────────────
# node_sources: 自动切换来源优先级（无主备模式时使用）
# primary_node_id: 主节点ID
# backup_node_ids: 备用节点ID列表
# recovery_interval: 主节点恢复检测间隔（分钟）
DEFAULT_SLOT_CFG = {
    "auto_switch":        True,
    "node_sources":       ["vpngate_residential", "vpngate_any"],
    "countries":          [],
    "max_latency_ms":     0,
    "prefer_tcp":         True,      # 优先选TCP节点
    "primary_node_id":    "",        # 空=不设主节点，使用自动选择
    "backup_node_ids":    [],        # 备用节点ID列表
    "recovery_interval":  10,        # 主节点恢复检测间隔（分钟）
}

def load_slot_configs() -> dict[str, Any]:
    data = read_json(SLOT_CONFIG_FILE, {})
    result = {}
    for s in SLOTS:
        sid = str(s["id"])
        cfg = dict(DEFAULT_SLOT_CFG)
        cfg.update(data.get(sid, {}))
        result[sid] = cfg
    return result

def save_slot_configs(configs: dict[str, Any]) -> None:
    write_json(SLOT_CONFIG_FILE, configs)

# ── xray出口配置 ─────────────────────────────────────────────────────
def read_xray_inbounds() -> list[dict]:
    """
    从 xr.json 读取所有 inbound 配置，返回列表。
    每项包含：tag、protocol、port
    不依赖硬编码，argosbx 换 UUID/端口后自动适配。
    """
    if not XRAY_CFG.exists():
        return []
    try:
        cfg = json.loads(XRAY_CFG.read_text(encoding="utf-8"))
        result = []
        for ib in cfg.get("inbounds", []):
            tag      = ib.get("tag", "")
            protocol = ib.get("protocol", ib.get("type", ""))
            port     = ib.get("port", ib.get("listen_port", 0))
            if tag:
                result.append({
                    "tag":      tag,
                    "protocol": protocol,
                    "port":     port,
                    "label":    f"{protocol.upper()} :{port}" if port else protocol.upper(),
                })
        return result
    except Exception as e:
        log("WARNING", "xray", f"读取 xr.json 失败: {e}")
        return []

def load_xray_dispatch() -> dict[str, str]:
    """读取已保存的 xray 调度配置，值为 direct/slot0/slot1"""
    return read_json(XRAY_DISPATCH_FILE, {})

def save_xray_dispatch(cfg: dict[str, str]) -> None:
    write_json(XRAY_DISPATCH_FILE, cfg)

def apply_xray_dispatch(cfg: dict[str, str]) -> None:
    """
    更新 xray 配置：每个 inbound tag 独立映射到对应槽端口，热重载 xray。
    slot0 → socks5://127.0.0.1:7920
    slot1 → socks5://127.0.0.1:7921
    direct → freedom outbound
    """
    if not XRAY_CONFIG_FILE.exists():
        log("WARNING", "xray", f"配置文件不存在: {XRAY_CONFIG_FILE}")
        return
    try:
        xray_cfg = json.loads(XRAY_CONFIG_FILE.read_text(encoding="utf-8"))
    except Exception as e:
        log("ERROR", "xray", f"读取配置失败: {e}")
        return

    outbounds = [o for o in xray_cfg.get("outbounds", [])
                 if o.get("tag") not in ("vpngate-slot0", "vpngate-slot1")]

    slots_used = set(v for v in cfg.values() if v != "direct")
    if "slot0" in slots_used:
        outbounds.append({
            "tag": "vpngate-slot0", "protocol": "socks",
            "settings": {"servers": [{"address": "127.0.0.1", "port": 7920}]}
        })
    if "slot1" in slots_used:
        outbounds.append({
            "tag": "vpngate-slot1", "protocol": "socks",
            "settings": {"servers": [{"address": "127.0.0.1", "port": 7921}]}
        })
    xray_cfg["outbounds"] = outbounds

    routing = xray_cfg.get("routing", {})
    rules = [r for r in routing.get("rules", [])
             if not (r.get("outboundTag", "").startswith("vpngate-slot") and r.get("inboundTag"))]

    for tag, slot in cfg.items():
        if slot == "direct":
            continue
        outbound_tag = f"vpngate-{slot}"
        rules.insert(0, {
            "type": "field",
            "inboundTag": [tag],
            "outboundTag": outbound_tag,
        })

    routing["rules"] = rules
    xray_cfg["routing"] = routing

    try:
        XRAY_CFG.write_text(
            json.dumps(xray_cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as e:
        log("ERROR", "xray", f"写入配置失败: {e}")
        return

    # SIGHUP 在 argosbx 环境下无效，直接强制重启
    if _restart_xray():
        log("INFO", "xray", "配置已应用，xray 重启成功")
    else:
        log("ERROR", "xray", "xray 重启失败，请手动检查")

# ── 辅助函数 ─────────────────────────────────────────────────────────
def ensure_dirs() -> None:
    DATA_DIR.mkdir(exist_ok=True, parents=True)
    CONFIG_DIR.mkdir(exist_ok=True, parents=True)
    LOGS_DIR.mkdir(exist_ok=True, parents=True)
    if not AUTH_FILE.exists():
        AUTH_FILE.write_text("vpn\nvpn\n")
        AUTH_FILE.chmod(0o600)

def write_json(path: Path, data: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)

def read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default

def safe_name(v: str) -> str:
    v = re.sub(r"[^A-Za-z0-9_.-]+", "_", v.strip())
    return v.strip("._") or "node"

def parse_int(v: Any) -> int:
    try:
        return int(v)
    except Exception:
        return 0

def log(level: str, module: str, msg: str) -> None:
    entry = {"timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
             "level": level, "module": module, "message": msg}
    try:
        lf = LOGS_DIR / f"{time.strftime('%Y-%m-%d')}.json"
        with open(lf, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass
    print(f"[{level}][{module}] {msg}", flush=True)

# ── UI认证 ───────────────────────────────────────────────────────────
def _rand_str(n: int, alpha_start: bool = False) -> str:
    chars = string.ascii_letters + string.digits
    while True:
        s = "".join(random.choices(chars, k=n))
        if any(c.islower() for c in s) and any(c.isupper() for c in s) and any(c.isdigit() for c in s):
            if not alpha_start or s[0].isalpha():
                return s

def load_ui_config() -> dict[str, Any]:
    cfg: dict[str, Any] = {"username": "", "password": "", "host": "0.0.0.0", "port": 8787}
    if UI_AUTH_FILE.exists():
        try:
            cfg.update(json.loads(UI_AUTH_FILE.read_text()))
        except Exception:
            pass
    changed = False
    if not cfg.get("username"):
        cfg["username"] = _rand_str(12, alpha_start=True); changed = True
    if not cfg.get("password"):
        cfg["password"] = _rand_str(12); changed = True
    if changed:
        UI_AUTH_FILE.write_text(json.dumps(cfg, indent=2))
    return cfg

def save_ui_config(cfg: dict[str, Any]) -> None:
    UI_AUTH_FILE.write_text(json.dumps(cfg, indent=2))

def session_token(username: str, password: str) -> str:
    return hashlib.sha256(f"{username}:{password}:vpngate-pro-2026".encode()).hexdigest()

WEB_SESSIONS: dict[str, float] = {}
SESSION_TTL = 7200

# ── 节点拉取 ─────────────────────────────────────────────────────────
def fetch_candidates() -> list[dict[str, Any]]:
    log("INFO", "Fetch", "开始拉取 VPNGate 节点列表...")
    req = urllib.request.Request(API_URL,
        headers={"User-Agent": "Mozilla/5.0 vpngate-pro/1.0", "Accept": "text/plain,*/*"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        text = resp.read().decode("utf-8", errors="replace")
    lines = [l for l in text.splitlines() if l and not l.startswith("*")]
    if lines and lines[0].startswith("#"):
        lines[0] = lines[0][1:]
    rows = list(csv.DictReader(lines))
    candidates: list[dict[str, Any]] = []
    seen_ips: set[str] = set()
    for row in rows[:MAX_SCAN_ROWS]:
        ip = row.get("IP", "").strip()
        if not ip or ip in seen_ips:
            continue
        encoded = row.get("OpenVPN_ConfigData_Base64", "").strip()
        has_config = bool(encoded)
        config_text = ""
        if has_config:
            try:
                config_text = base64.b64decode(encoded.encode(), validate=False).decode("utf-8", errors="replace")
            except Exception:
                has_config = False

        country_long  = row.get("CountryLong", "")
        country_short = row.get("CountryShort", "")
        country_zh    = vpn_utils.COUNTRY_TRANSLATIONS.get(country_long, country_long)
        remote_host, remote_port, proto = (
            vpn_utils.parse_remote(config_text, ip) if has_config
            else (ip, 1194, "tcp")
        )
        node_id = safe_name("_".join([country_short or "XX", ip, str(remote_port), proto]))
        config_path = CONFIG_DIR / f"{node_id}.ovpn"

        candidates.append({
            "id": node_id, "node_type": "vpngate",
            "country": country_zh, "country_short": country_short, "country_zh": country_zh,
            "host_name": row.get("HostName", ""), "ip": ip,
            "score": parse_int(row.get("Score")), "ping": parse_int(row.get("Ping")),
            "speed": parse_int(row.get("Speed")),
            "config_file": str(config_path),
            "config_text": config_text,
            "has_config":  has_config,   # False = 无 OpenVPN 配置，不可直连
            "proto": proto, "remote_host": remote_host, "remote_port": remote_port,
            "fetched_at": time.time(),
            "probe_status": "not_checked" if has_config else "no_config",
            "probe_message": "" if has_config else "无 OpenVPN 配置",
            "probed_at": 0, "latency_ms": 0,
            "owner": "", "asn": "", "as_name": "", "location": "",
            "ip_type": "unknown", "quality": "未知", "active_slot": -1,
        })
        seen_ips.add(ip)
    log("INFO", "Fetch", f"获取到 {len(candidates)} 个候选节点")
    return candidates

def sort_nodes(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def key(n):
        st = n.get("probe_status", "")
        proto_score = 0 if n.get("proto", "tcp") == "tcp" else 1
        lat = parse_int(n.get("latency_ms")) or 999999
        order = (0 if st == "available" else
                 1 if st == "not_checked" else
                 2 if st == "unavailable" else 3)  # no_config 排最后
        return (order, proto_score, lat, -parse_int(n.get("score")))
    return sorted(nodes, key=key)

# ── OpenVPN ──────────────────────────────────────────────────────────
_openvpn_ver: float | None = None

def get_openvpn_version() -> float:
    global _openvpn_ver
    if _openvpn_ver is not None:
        return _openvpn_ver
    try:
        res = subprocess.run([OPENVPN_CMD, "--version"], capture_output=True, text=True, timeout=3)
        m = re.search(r"OpenVPN\s+(\d+\.\d+)", res.stdout + res.stderr)
        if m:
            _openvpn_ver = float(m.group(1)); return _openvpn_ver
    except Exception:
        pass
    _openvpn_ver = 2.4; return _openvpn_ver

def build_openvpn_cmd(config_file: str, tun_dev: str) -> list[str]:
    cmd = [OPENVPN_CMD, "--config", config_file,
           "--dev", tun_dev, "--dev-type", "tun",
           "--pull-filter", "ignore", "route-ipv6",
           "--pull-filter", "ignore", "ifconfig-ipv6",
           "--route-delay", "2", "--connect-retry-max", "1",
           "--connect-timeout", "15",
           "--auth-user-pass", str(AUTH_FILE), "--auth-nocache",
           "--route-nopull",
           "--tls-cert-profile", "insecure"]  # VPNGate用Let's Encrypt证书，跳过内嵌CA验证
    ver = get_openvpn_version()
    if ver >= 2.5:
        cmd += ["--data-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"]
    else:
        cmd += ["--ncp-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"]
    cmd += ["--verb", "3"]
    return cmd

def run_openvpn(config_file: str, tun_dev: str, keep_alive: bool,
                timeout: int = OPENVPN_TIMEOUT) -> tuple[bool, str, subprocess.Popen | None]:
    try:
        proc = subprocess.Popen(build_openvpn_cmd(config_file, tun_dev),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", cwd=str(ROOT_DIR))
    except FileNotFoundError:
        return False, "openvpn 命令未找到", None
    except OSError as e:
        return False, f"openvpn 启动失败: {e}", None

    lines: queue.Queue[str | None] = queue.Queue()
    done = [False]

    def reader():
        assert proc.stdout
        for line in proc.stdout:
            if not done[0]: lines.put(line.rstrip())
        if not done[0]: lines.put(None)

    threading.Thread(target=reader, daemon=True).start()
    started = time.time()
    ok = False
    msg = "OpenVPN 初始化超时"

    while time.time() - started < timeout:
        try:
            line = lines.get(timeout=0.5)
        except queue.Empty:
            if proc.poll() is not None: break
            continue
        if line is None: break
        if line:
            if keep_alive:
                print(f"[OpenVPN/{tun_dev}] {line}", flush=True)
            lower = line.lower()
            if "initialization sequence completed" in lower:
                ok = True
                msg = f"连接成功，耗时 {int((time.time()-started)*1000)} ms"
                break
            if "auth_failed" in lower or "authentication failed" in lower:
                msg = "AUTH_FAILED"; break
            if "fatal error" in lower:
                msg = line[-200:]; break
    else:
        msg = f"连接超时 ({timeout}s)"

    done[0] = True
    if not ok or not keep_alive:
        _stop_proc(proc); proc = None
    return ok, msg, proc

def _stop_proc(proc: subprocess.Popen | None) -> None:
    if proc is None or proc.poll() is not None: return
    proc.terminate()
    try: proc.wait(timeout=8)
    except subprocess.TimeoutExpired: proc.kill()

def get_tun_local_ip(tun_dev: str) -> str:
    try:
        result = subprocess.run(["ip", "addr", "show", tun_dev],
                                capture_output=True, text=True, timeout=3)
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", result.stdout)
        if m: return m.group(1)
    except Exception:
        pass
    return ""

def setup_policy_routing(tun_dev: str, table_id: int, tun_ip: str) -> None:
    """
    配置策略路由：源IP为 tun_ip 的流量走 tun_dev。
    microsocks 绑定 tun_ip 作为源地址，内核自动路由到 tun 接口。
    """
    # 清理旧规则
    subprocess.run(["ip", "rule", "del", "from", tun_ip, "table", str(table_id)], capture_output=True)
    subprocess.run(["ip", "rule", "del", "fwmark", str(table_id), "table", str(table_id)], capture_output=True)
    subprocess.run(["ip", "route", "flush", "table", str(table_id)], capture_output=True)
    for _ in range(3):
        try:
            subprocess.run(["ip", "route", "add", "default", "dev", tun_dev,
                            "table", str(table_id)], check=True, timeout=3)
            subprocess.run(["ip", "rule", "add", "from", tun_ip,
                            "table", str(table_id)], check=True, timeout=3)
            log("INFO", "Routing", f"策略路由: from {tun_ip} → {tun_dev} → 表{table_id}")
            return
        except Exception as e:
            log("WARNING", "Routing", f"策略路由设置失败: {e}")
            time.sleep(1)

def cleanup_policy_routing(table_id: int, tun_ip: str = "") -> None:
    if tun_ip:
        subprocess.run(["ip", "rule", "del", "from", tun_ip, "table", str(table_id)], capture_output=True)
    subprocess.run(["ip", "rule", "del", "fwmark", str(table_id), "table", str(table_id)], capture_output=True)
    subprocess.run(["ip", "rule", "del", "table", str(table_id)], capture_output=True)
    subprocess.run(["ip", "route", "flush", "table", str(table_id)], capture_output=True)

def kill_slot_openvpn(tun_dev: str) -> None:
    subprocess.run(["pkill", "-f", f"openvpn.*{tun_dev}"], capture_output=True)

# ── 节点测试 ─────────────────────────────────────────────────────────
_test_tuns: set[int] = set()
_test_tuns_lock = threading.Lock()

def _alloc_test_tun() -> int:
    with _test_tuns_lock:
        for i in range(2, 10):
            if i not in _test_tuns:
                _test_tuns.add(i); return i
        return 9

def _free_test_tun(idx: int) -> None:
    with _test_tuns_lock:
        _test_tuns.discard(idx)

def test_node_sync(node: dict[str, Any]) -> dict[str, Any]:
    if not node.get("has_config", True) or not node.get("config_text"):
        return {"probe_status": "no_config", "probe_message": "无 OpenVPN 配置"}
    config_path = Path(node["config_file"])
    CONFIG_DIR.mkdir(exist_ok=True, parents=True)
    config_path.write_text(node.get("config_text", ""), encoding="utf-8")
    proto = node.get("proto", "tcp")
    latency = vpn_utils.ping_latency_ms(
        node.get("remote_host") or node.get("ip"),
        parse_int(node.get("remote_port")),
        proto=proto,
        fallback=parse_int(node.get("ping")),
    )
    tun_idx = _alloc_test_tun()
    # UDP节点使用更长超时
    timeout = 20 if proto == "udp" else 12
    try:
        ok, msg, _ = run_openvpn(str(config_path), f"tun{tun_idx}",
                                  keep_alive=False, timeout=timeout)
    finally:
        _free_test_tun(tun_idx)
    try:
        config_path.unlink(missing_ok=True)
    except Exception:
        pass
    updates: dict[str, Any] = {
        "latency_ms": latency, "proto": proto,
        "probe_status": "available" if ok else "unavailable",
        "probe_message": msg, "probed_at": time.time(),
    }
    if ok:
        tmp = {"ip": node.get("ip"), "remote_host": node.get("remote_host"),
               "owner": "", "asn": "", "as_name": "", "location": "",
               "country_zh": "", "ip_type": "unknown", "quality": "未知"}
        vpn_utils.enrich_ip_info([tmp])
        for k in ("owner","asn","as_name","location","country_zh","ip_type","quality"):
            updates[k] = tmp[k]
    return updates

_batch_test_lock = threading.Lock()
_batch_test_status: dict[str, Any] = {
    "running": False,
    "total": 0,
    "done": 0,
    "current": "",   # 当前正在测试的节点ID
    "results": {},   # node_id -> updates
}

def batch_test_nodes(node_ids: list[str]) -> None:
    global _batch_test_status
    with lock:
        nodes = read_json(NODES_FILE, [])
        to_test = [n for n in nodes if n["id"] in node_ids]

    with _batch_test_lock:
        _batch_test_status.update({
            "running": True, "total": len(to_test),
            "done": 0, "current": "", "results": {},
        })

    def worker(node):
        with _batch_test_lock:
            _batch_test_status["current"] = node["id"]
        result = test_node_sync(node)
        with _batch_test_lock:
            _batch_test_status["done"] += 1
            _batch_test_status["results"][node["id"]] = result
        return node["id"], result

    results: dict[str, dict] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_CONCURRENT_TESTS) as ex:
        futs = {ex.submit(worker, n): n["id"] for n in to_test}
        for fut in concurrent.futures.as_completed(futs):
            try:
                nid, updates = fut.result()
                results[nid] = updates
            except Exception as e:
                results[futs[fut]] = {"probe_status": "unavailable", "probe_message": str(e)}

    with lock:
        nodes = read_json(NODES_FILE, [])
        for n in nodes:
            if n["id"] in results:
                n.update(results[n["id"]])
        write_json(NODES_FILE, sort_nodes(nodes))

    with _batch_test_lock:
        _batch_test_status["running"] = False
        _batch_test_status["current"] = ""

# ── 连接/断开 ─────────────────────────────────────────────────────────
def stop_slot(slot_id: int) -> None:
    slot_cfg = SLOTS[slot_id]
    st = slot_states[slot_id]
    cleanup_policy_routing(slot_cfg["table"], st.tun_ip)
    _stop_proc(st.process)
    kill_slot_openvpn(slot_cfg["tun"])
    # 停止代理（microsocks 或 Python）
    srv = proxy_mod._proxy_slots.get(slot_id)
    if srv: srv.stop()
    st.process = None; st.node_id = ""; st.node_type = ""
    st.proxy_ok = False; st.proxy_ip = ""; st.latency_ms = 0
    st.tun_ip = ""; st.status_msg = "已断开"; st.using_backup = False
    with lock:
        nodes = read_json(NODES_FILE, [])
        for n in nodes:
            if n.get("active_slot") == slot_id: n["active_slot"] = -1
        write_json(NODES_FILE, nodes)

def connect_slot(slot_id: int, node_id: str) -> str:
    slot_cfg = SLOTS[slot_id]
    st = slot_states[slot_id]
    if st.is_connecting: return "正在连接中，请稍候"
    st.is_connecting = True
    st.status_msg = "初始化..."
    try:
        with lock:
            nodes = read_json(NODES_FILE, [])
            node = next((n for n in nodes if n["id"] == node_id), None)
        if not node: raise ValueError(f"节点不存在: {node_id}")
        stop_slot(slot_id)
        config_path = Path(node["config_file"])
        CONFIG_DIR.mkdir(exist_ok=True, parents=True)
        config_path.write_text(node.get("config_text", ""), encoding="utf-8")
        st.status_msg = "启动 OpenVPN..."
        ok, msg, proc = run_openvpn(str(config_path), slot_cfg["tun"], keep_alive=True)
        if not ok or proc is None:
            try: config_path.unlink(missing_ok=True)
            except Exception: pass
            raise RuntimeError(f"OpenVPN 连接失败: {msg}")
        st.process = proc; st.node_id = node_id; st.node_type = "vpngate"
        st.status_msg = "配置路由..."
        # 等待 tun IP 分配（最多5秒）
        tun_ip = ""
        for _ in range(10):
            tun_ip = get_tun_local_ip(slot_cfg["tun"])
            if tun_ip: break
            time.sleep(0.5)
        st.tun_ip = tun_ip
        setup_policy_routing(slot_cfg["tun"], slot_cfg["table"], tun_ip)
        # 启动 microsocks（绑定 tun_ip，流量自动经 tun 出站）
        srv = proxy_mod._proxy_slots.get(slot_id)
        if srv: srv.start_vpngate(tun_ip)
        proto = node.get("proto", "tcp")
        try:
            lat = vpn_utils.ping_latency_ms(
                node.get("ip") or node.get("remote_host"),
                parse_int(node.get("remote_port")), proto=proto,
                fallback=parse_int(node.get("ping")))
            st.latency_ms = lat
        except Exception:
            pass
        with lock:
            nodes = read_json(NODES_FILE, [])
            for n in nodes:
                if n["id"] == node_id: n["active_slot"] = slot_id
                elif n.get("active_slot") == slot_id: n["active_slot"] = -1
            write_json(NODES_FILE, nodes)
        st.status_msg = "检测出口..."
        res = check_slot_proxy(slot_id)
        st.proxy_ok = res["ok"]
        st.proxy_ip = res.get("ip", "")
        st.status_msg = f"已连接 | {st.proxy_ip}" if st.proxy_ok else "已连接 | 出口检测失败"
        log("INFO", f"Slot{slot_id}", f"节点 {node_id} 连接成功，出口: {st.proxy_ip}")
        return f"连接成功: {node_id}"
    except Exception as e:
        st.status_msg = f"连接失败: {e}"
        log("ERROR", f"Slot{slot_id}", str(e))
        stop_slot(slot_id)
        raise
    finally:
        st.is_connecting = False

def connect_custom_socks5(slot_id: int, node: dict) -> str:
    st = slot_states[slot_id]
    if st.is_connecting: return "正在连接中，请稍候"
    st.is_connecting = True
    st.status_msg = "连接自建节点..."
    try:
        stop_slot(slot_id)
        host = node["host"]; port = int(node["port"])
        lat = vpn_utils.ping_latency_ms(host, port)
        if lat == 0: raise RuntimeError(f"无法连接到 {host}:{port}")
        st.latency_ms = lat
        srv = proxy_mod._proxy_slots.get(slot_id)
        if srv:
            srv.set_upstream_socks5({
                "host": host, "port": port,
                "username": node.get("username", ""),
                "password": node.get("password", ""),
            })
        st.node_id = node["id"]; st.node_type = "custom"
        res = check_slot_proxy(slot_id)
        st.proxy_ok = res["ok"]; st.proxy_ip = res.get("ip", "")
        st.status_msg = f"已连接 | {st.proxy_ip}" if st.proxy_ok else "已连接 | 出口检测失败"
        log("INFO", f"Slot{slot_id}", f"自建节点 {node['name']} 连接成功，出口: {st.proxy_ip}")
        return f"连接成功: {node['name']}"
    except Exception as e:
        st.status_msg = f"连接失败: {e}"
        log("ERROR", f"Slot{slot_id}", str(e))
        stop_slot(slot_id)
        raise
    finally:
        st.is_connecting = False

def check_slot_proxy(slot_id: int) -> dict[str, Any]:
    """通过 SOCKS5 代理检测出口 IP（microsocks 是 SOCKS5，不是 HTTP 代理）"""
    proxy_port = SLOTS[slot_id]["proxy_port"]
    try:
        import socket as _socket
        SO_MARK = 36
        # 用 tun IP 作为源地址直连 ipinfo.io（与 microsocks 出口一致）
        tun_ip = slot_states[slot_id].tun_ip
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(12)
        if tun_ip:
            try:
                sock.setsockopt(_socket.SOL_SOCKET, SO_MARK,
                                SLOTS[slot_id]["table"])
                sock.bind((tun_ip, 0))
            except Exception:
                pass
        t0 = time.time()
        sock.connect(("ipinfo.io", 443))
        import ssl
        ctx = ssl.create_default_context()
        ssock = ctx.wrap_socket(sock, server_hostname="ipinfo.io")
        ssock.sendall(b"GET /json HTTP/1.1\r\nHost: ipinfo.io\r\nConnection: close\r\n\r\n")
        resp = b""
        while True:
            chunk = ssock.recv(4096)
            if not chunk: break
            resp += chunk
        ssock.close()
        body = resp.split(b"\r\n\r\n", 1)[-1].decode(errors="replace")
        data = json.loads(body)
        ip = data.get("ip", "")
        return {"ok": bool(ip), "ip": ip, "latency_ms": int((time.time()-t0)*1000)}
    except Exception as e:
        return {"ok": False, "error": str(e)}

# ── 自动切换（主备节点逻辑） ──────────────────────────────────────────
def _get_node_by_id(node_id: str) -> dict | None:
    nodes = read_json(NODES_FILE, [])
    return next((n for n in nodes if n["id"] == node_id), None)

def _try_connect_node(slot_id: int, node_id: str) -> bool:
    """尝试连接节点，返回是否成功且出口可达"""
    try:
        connect_slot(slot_id, node_id)
        return slot_states[slot_id].proxy_ok
    except Exception:
        return False

def auto_switch_slot(slot_id: int) -> None:
    """
    自动切换逻辑：
    1. 有主节点配置时：尝试主节点 → 依次尝试备用节点
    2. 无主节点配置时：从 node_sources 过滤可用节点自动选择
    """
    st = slot_states[slot_id]
    slot_cfgs = load_slot_configs()
    slot_cfg = slot_cfgs.get(str(slot_id), dict(DEFAULT_SLOT_CFG))

    primary_id  = slot_cfg.get("primary_node_id", "")
    backup_ids  = slot_cfg.get("backup_node_ids", [])
    prefer_tcp  = slot_cfg.get("prefer_tcp", True)

    # ── 有主节点配置 ──
    if primary_id:
        # 先尝试主节点
        log("INFO", f"Slot{slot_id}", f"尝试主节点: {primary_id}")
        if _try_connect_node(slot_id, primary_id):
            st.using_backup = False
            st.primary_id = primary_id
            st.backup_ids = backup_ids
            log("INFO", f"Slot{slot_id}", "主节点连接成功")
            return
        # 主节点失败，依次尝试备用节点
        for bid in backup_ids:
            log("INFO", f"Slot{slot_id}", f"主节点失败，尝试备用: {bid}")
            if _try_connect_node(slot_id, bid):
                st.using_backup = True
                st.primary_id = primary_id
                st.backup_ids = backup_ids
                log("INFO", f"Slot{slot_id}", f"备用节点 {bid} 连接成功")
                return
        log("ERROR", f"Slot{slot_id}", "主节点和所有备用节点均失败")
        stop_slot(slot_id)
        return

    # ── 无主节点，自动从 node_sources 选择 ──
    other_node = slot_states[1 - slot_id].node_id
    sources = slot_cfg.get("node_sources", ["vpngate_any"])
    countries = slot_cfg.get("countries", [])
    max_lat = slot_cfg.get("max_latency_ms", 0)
    vpngate_nodes = read_json(NODES_FILE, [])

    candidates = []
    for src in sources:
        cands = [n for n in vpngate_nodes
                 if n.get("probe_status") == "available"
                 and n.get("has_config", True)
                 and n["id"] != other_node]
        if src == "vpngate_residential":
            cands = [n for n in cands if n.get("ip_type") == "residential"]
        elif src == "vpngate_datacenter":
            cands = [n for n in cands if n.get("ip_type") == "datacenter"]
        if countries:
            cands = [n for n in cands if n.get("country_short", "") in countries]
        if max_lat > 0:
            cands = [n for n in cands if parse_int(n.get("latency_ms", 0)) <= max_lat]
        if prefer_tcp:
            tcp_cands = [n for n in cands if n.get("proto", "tcp") == "tcp"]
            cands = tcp_cands if tcp_cands else cands
        cands.sort(key=lambda n: (parse_int(n.get("latency_ms")) or 999999,
                                  -parse_int(n.get("score"))))
        if cands:
            candidates = cands; break

    if not candidates:
        log("ERROR", f"Slot{slot_id}", "没有可用节点")
        stop_slot(slot_id); return

    target = candidates[0]
    log("INFO", f"Slot{slot_id}", f"自动切换 → {target['id']}")
    try:
        connect_slot(slot_id, target["id"])
    except Exception as e:
        log("ERROR", f"Slot{slot_id}", f"自动切换失败: {e}")

# ── 健康监控 ──────────────────────────────────────────────────────────
def _verify_slot_tunnel(slot_id: int) -> bool:
    """用 tun IP 直连 ipinfo.io 验证隧道是否通畅"""
    import socket as _socket, ssl
    SO_MARK = 36
    tun_ip = slot_states[slot_id].tun_ip
    table  = SLOTS[slot_id]["table"]
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(10)
        if tun_ip:
            try:
                sock.setsockopt(_socket.SOL_SOCKET, SO_MARK, table)
                sock.bind((tun_ip, 0))
            except Exception:
                pass
        sock.connect(("ipinfo.io", 443))
        ctx = ssl.create_default_context()
        ssock = ctx.wrap_socket(sock, server_hostname="ipinfo.io")
        ssock.sendall(b"GET /json HTTP/1.1\r\nHost: ipinfo.io\r\nConnection: close\r\n\r\n")
        data = ssock.recv(256)
        ssock.close()
        return b"200" in data
    except Exception:
        return False

def health_monitor() -> None:
    fail_counts = {0: 0, 1: 0}
    FAIL_THRESHOLD = 2
    # 主节点恢复检测：记录上次检测时间
    last_recovery_check = {0: 0.0, 1: 0.0}

    while True:
        time.sleep(30)
        for slot_id in range(2):
            st = slot_states[slot_id]
            if not st.node_id or st.is_connecting:
                fail_counts[slot_id] = 0
                continue

            failed = False
            if st.node_type == "vpngate":
                if st.process is None or st.process.poll() is not None:
                    log("WARNING", f"Slot{slot_id}", "OpenVPN 进程已退出")
                    failed = True
            if not failed:
                if not _verify_slot_tunnel(slot_id):
                    log("WARNING", f"Slot{slot_id}", "隧道连通性检测失败")
                    failed = True
                else:
                    st.proxy_ok = True
                    fail_counts[slot_id] = 0

            if failed:
                fail_counts[slot_id] += 1
                if fail_counts[slot_id] >= FAIL_THRESHOLD:
                    log("WARNING", f"Slot{slot_id}",
                        f"连续 {fail_counts[slot_id]} 次检测失败，触发自动切换")
                    fail_counts[slot_id] = 0
                    st.proxy_ok = False
                    st.status_msg = "连接断开，切换中..."
                    threading.Thread(target=auto_switch_slot, args=(slot_id,), daemon=True).start()
                continue

            # ── 主节点恢复检测 ──
            if not st.using_backup:
                continue
            slot_cfgs = load_slot_configs()
            slot_cfg = slot_cfgs.get(str(slot_id), {})
            recovery_interval = slot_cfg.get("recovery_interval", 10) * 60
            now = time.time()
            if now - last_recovery_check[slot_id] < recovery_interval:
                continue
            last_recovery_check[slot_id] = now
            primary_id = slot_cfg.get("primary_node_id", "")
            if not primary_id:
                continue
            log("INFO", f"Slot{slot_id}", f"检测主节点是否恢复: {primary_id}")
            # 在后台测试主节点
            def _check_primary(sid=slot_id, pid=primary_id):
                updates = test_node_sync(_get_node_by_id(pid) or {"id": pid})
                if updates.get("probe_status") == "available":
                    log("INFO", f"Slot{sid}", f"主节点 {pid} 已恢复，切换回主节点")
                    try:
                        connect_slot(sid, pid)
                        slot_states[sid].using_backup = False
                    except Exception as e:
                        log("ERROR", f"Slot{sid}", f"切换回主节点失败: {e}")
            threading.Thread(target=_check_primary, daemon=True).start()

def refresh_nodes_loop() -> None:
    while True:
        time.sleep(300)  # 每5分钟刷新一次，加快节点积累
        try:
            candidates = fetch_candidates()
            with lock:
                existing = {n["id"]: n for n in read_json(NODES_FILE, [])}
            merged, seen = [], set()
            for c in candidates:
                if c["id"] in existing:
                    ex = existing[c["id"]]
                    ex["config_text"] = c["config_text"]
                    ex["fetched_at"]  = c["fetched_at"]
                    merged.append(ex)
                else:
                    merged.append(c)
                seen.add(c["id"])
            for nid, n in existing.items():
                if nid not in seen: merged.append(n)
            write_json(NODES_FILE, sort_nodes(merged[:5000]))
            log("INFO", "Refresh", f"节点刷新完成，共 {len(merged)} 个")
        except Exception as e:
            log("ERROR", "Refresh", str(e))

# ── Web UI HTML ──────────────────────────────────────────────────────
HTML_PAGE = r"""<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<title>VPNGate Pro</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f1117;color:#e2e8f0;min-height:100vh;font-size:14px}
/* ── 导航 ── */
.nav{background:#1a1d27;border-bottom:1px solid #2d3748;padding:10px 16px;display:flex;align-items:center;gap:10px;position:sticky;top:0;z-index:100}
.nav h1{font-size:16px;font-weight:700;color:#63b3ed;white-space:nowrap}
.badge{background:#2d3748;border-radius:6px;padding:2px 8px;font-size:11px;color:#a0aec0;white-space:nowrap}
/* ── 标签页 ── */
.tabs{display:flex;padding:0 8px;background:#1a1d27;border-bottom:1px solid #2d3748;overflow-x:auto;-webkit-overflow-scrolling:touch;scrollbar-width:none}
.tabs::-webkit-scrollbar{display:none}
.tab{padding:10px 12px;cursor:pointer;font-size:12px;color:#718096;border-bottom:2px solid transparent;white-space:nowrap;flex-shrink:0;user-select:none}
.tab.active{color:#63b3ed;border-bottom-color:#63b3ed}
/* ── 内容区 ── */
.content{padding:12px;max-width:900px;margin:0 auto}
.card{background:#1a1d27;border:1px solid #2d3748;border-radius:10px;padding:14px;margin-bottom:12px}
.card h2{font-size:13px;font-weight:600;color:#a0aec0;margin-bottom:12px}
/* ── 槽卡片 ── */
.slot-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
@media(max-width:600px){.slot-grid{grid-template-columns:1fr}}
.slot-card{background:#141720;border:1px solid #2d3748;border-radius:8px;padding:12px}
.slot-card h3{font-size:12px;font-weight:600;margin-bottom:10px;display:flex;align-items:center;gap:6px}
.dot{width:8px;height:8px;border-radius:50%;display:inline-block;flex-shrink:0}
.dot.green{background:#48bb78}.dot.yellow{background:#ecc94b}.dot.grey{background:#4a5568}
.stat{display:flex;justify-content:space-between;align-items:center;padding:5px 0;border-bottom:1px solid #2d3748;font-size:12px}
.stat:last-child{border:none}
.stat .label{color:#718096;flex-shrink:0}.stat .val{color:#e2e8f0;font-family:monospace;text-align:right;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:55%;font-size:11px}
/* ── 按钮 ── */
.btn{padding:8px 14px;border:none;border-radius:8px;cursor:pointer;font-size:13px;transition:.15s;display:inline-flex;align-items:center;justify-content:center;gap:5px;-webkit-appearance:none}
.btn-primary{background:#3182ce;color:#fff}.btn-primary:active{background:#2b6cb0}
.btn-danger{background:#c53030;color:#fff}.btn-danger:active{background:#9b2c2c}
.btn-success{background:#276749;color:#fff}.btn-success:active{background:#22543d}
.btn-grey{background:#2d3748;color:#a0aec0}.btn-grey:active{background:#4a5568}
.btn-sm{padding:6px 10px;font-size:12px;border-radius:6px}
.btn-xs{padding:4px 8px;font-size:11px;border-radius:5px}
/* ── 表单 ── */
.input{background:#141720;border:1px solid #2d3748;border-radius:8px;padding:10px 12px;color:#e2e8f0;font-size:14px;width:100%;-webkit-appearance:none}
.input:focus{outline:none;border-color:#63b3ed}
.select{background:#141720;border:1px solid #2d3748;border-radius:8px;padding:8px 10px;color:#e2e8f0;font-size:13px;-webkit-appearance:none;appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%23718096' d='M6 8L1 3h10z'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 8px center;padding-right:28px}
/* ── 标签 ── */
.tag{display:inline-block;padding:2px 7px;border-radius:4px;font-size:11px}
.tag.residential{background:#276749;color:#9ae6b4}
.tag.datacenter{background:#2c5282;color:#90cdf4}
.tag.proxy{background:#553c9a;color:#d6bcfa}
.tag.unknown{background:#2d3748;color:#718096}
.tag.available{background:#276749;color:#9ae6b4}
.tag.unavail{background:#742a2a;color:#feb2b2}
.tag.notcheck{background:#2d3748;color:#a0aec0}
.tag.testing{background:#744210;color:#fbd38d}
.tag.tcp{background:#1a365d;color:#90cdf4}
.tag.udp{background:#322659;color:#d6bcfa}
/* ── 节点卡片（移动端） ── */
.node-table{display:none}
.node-cards{display:flex;flex-direction:column;gap:8px}
.node-card{background:#141720;border:1px solid #2d3748;border-radius:8px;padding:10px}
.node-card-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px}
.node-card-info{font-size:11px;color:#718096;display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px}
.node-card-actions{display:flex;gap:6px}
@media(min-width:700px){
  .node-table{display:table;width:100%;border-collapse:collapse;font-size:12px}
  .node-cards{display:none}
  th{text-align:left;padding:8px 10px;color:#718096;font-weight:500;border-bottom:1px solid #2d3748;white-space:nowrap}
  td{padding:8px 10px;border-bottom:1px solid #1a1d27;vertical-align:middle}
  tr:hover td{background:#141720}
}
/* ── 过滤栏 ── */
.filter-row{display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end;margin-bottom:12px}
.filter-group{display:flex;flex-direction:column;gap:4px}
.filter-group label{font-size:11px;color:#718096}
/* ── 进度条 ── */
.progress-wrap{margin-bottom:12px;display:none}
.progress-wrap.active{display:block}
.progress-bar{height:6px;background:#2d3748;border-radius:3px;overflow:hidden}
.progress-fill{height:100%;background:#3182ce;border-radius:3px;transition:width .3s}
.progress-text{font-size:11px;color:#718096;margin-top:4px;display:flex;justify-content:space-between}
/* ── 分页 ── */
.pagination{display:flex;align-items:center;gap:6px;justify-content:center;flex-wrap:wrap;margin-top:12px}
.pg-btn{padding:6px 10px;border-radius:6px;border:1px solid #2d3748;background:#141720;color:#a0aec0;cursor:pointer;font-size:12px}
.pg-btn.active{background:#2b4c7e;border-color:#63b3ed;color:#90cdf4}
.pg-btn:disabled{opacity:.4;cursor:not-allowed}
/* ── 登录 ── */
.login-box{max-width:340px;margin:80px auto;background:#1a1d27;border:1px solid #2d3748;border-radius:12px;padding:24px}
.login-box h2{text-align:center;margin-bottom:20px;color:#63b3ed;font-size:18px}
.form-group{margin-bottom:14px}
.form-group label{display:block;font-size:12px;color:#718096;margin-bottom:6px}
.alert{padding:8px 12px;border-radius:6px;font-size:12px;margin-top:10px}
.alert.error{background:#742a2a33;border:1px solid #c53030;color:#feb2b2}
/* ── Toast ── */
.toast{position:fixed;top:12px;right:12px;left:12px;background:#276749;color:#9ae6b4;padding:10px 14px;border-radius:8px;font-size:13px;z-index:9999;display:none;text-align:center}
@media(min-width:500px){.toast{left:auto;max-width:320px}}
/* ── 工具类 ── */
.flex{display:flex}.gap-2{gap:8px}.items-center{align-items:center}.justify-between{justify-content:space-between}
.mt-2{margin-top:8px}.mt-3{margin-top:12px}
.text-xs{font-size:11px}.text-sm{font-size:12px}.text-grey{color:#718096}
.page{display:none}.page.active{display:block}
.divider{border:none;border-top:1px solid #2d3748;margin:12px 0}
.source-item{display:flex;align-items:center;gap:8px;padding:8px;background:#141720;border:1px solid #2d3748;border-radius:6px;margin-bottom:6px}
.backup-item{display:flex;align-items:center;gap:6px;padding:6px 8px;background:#141720;border:1px solid #2d3748;border-radius:6px;margin-bottom:5px;font-size:12px}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
@media(max-width:500px){.grid-2{grid-template-columns:1fr}}
</style>
</head>
<body>

<div id="loginPage" style="display:none">
  <div class="login-box">
    <h2>🔐 VPNGate Pro</h2>
    <div class="form-group"><label>用户名</label><input class="input" id="loginUser" type="text" autocomplete="username" onkeydown="if(event.key==='Enter')doLogin()"></div>
    <div class="form-group"><label>密码</label><input class="input" id="loginPass" type="password" autocomplete="current-password" onkeydown="if(event.key==='Enter')doLogin()"></div>
    <button class="btn btn-primary" style="width:100%;padding:12px" onclick="doLogin()">登录</button>
    <div id="loginErr" class="alert error" style="display:none"></div>
  </div>
</div>

<div id="mainApp" style="display:none">
  <div class="toast" id="toast"></div>
  <div class="nav">
    <h1>🌐 VPNGate Pro</h1>
    <span class="badge" id="navBadge">…</span>
    <div style="margin-left:auto;display:flex;gap:6px">
      <button class="btn btn-sm btn-grey" onclick="refreshAll()">↺</button>
      <button class="btn btn-sm btn-danger" onclick="doLogout()">退出</button>
    </div>
  </div>
  <div class="tabs" id="tabBar">
    <div class="tab active" onclick="switchTab('dashboard')">📊 控制台</div>
    <div class="tab" onclick="switchTab('nodes')">🗂 节点</div>
    <div class="tab" onclick="switchTab('custom')">🔧 自建</div>
    <div class="tab" onclick="switchTab('autoswitch')">🔁 切换</div>
    <div class="tab" onclick="switchTab('xray')">🚀 xray</div>
    <div class="tab" onclick="switchTab('logs')">📋 日志</div>
    <div class="tab" onclick="switchTab('settings')">⚙️ 设置</div>
  </div>

  <!-- 控制台 -->
  <div class="content page active" id="page-dashboard">
    <div class="slot-grid">
      <div class="slot-card">
        <h3><span class="dot grey" id="s0-dot"></span>槽1 · tun10 · :7920</h3>
        <div class="stat"><span class="label">状态</span><span class="val" id="s0-status">-</span></div>
        <div class="stat"><span class="label">节点</span><span class="val" id="s0-node">-</span></div>
        <div class="stat"><span class="label">出口IP</span><span class="val" id="s0-ip">-</span></div>
        <div class="stat"><span class="label">延迟</span><span class="val" id="s0-lat">-</span></div>
        <div class="stat"><span class="label">主/备</span><span class="val" id="s0-primary">-</span></div>
        <div class="mt-3 flex gap-2" style="flex-wrap:wrap">
          <button class="btn btn-xs btn-danger" onclick="stopSlot(0)">断开</button>
          <button class="btn btn-xs btn-grey" onclick="checkSlot(0)">检测</button>
          <button class="btn btn-xs btn-grey" onclick="switchSlot(0)">切换</button>
        </div>
      </div>
      <div class="slot-card">
        <h3><span class="dot grey" id="s1-dot"></span>槽2 · tun11 · :7921</h3>
        <div class="stat"><span class="label">状态</span><span class="val" id="s1-status">-</span></div>
        <div class="stat"><span class="label">节点</span><span class="val" id="s1-node">-</span></div>
        <div class="stat"><span class="label">出口IP</span><span class="val" id="s1-ip">-</span></div>
        <div class="stat"><span class="label">延迟</span><span class="val" id="s1-lat">-</span></div>
        <div class="stat"><span class="label">主/备</span><span class="val" id="s1-primary">-</span></div>
        <div class="mt-3 flex gap-2" style="flex-wrap:wrap">
          <button class="btn btn-xs btn-danger" onclick="stopSlot(1)">断开</button>
          <button class="btn btn-xs btn-grey" onclick="checkSlot(1)">检测</button>
          <button class="btn btn-xs btn-grey" onclick="switchSlot(1)">切换</button>
        </div>
      </div>
    </div>
    <div class="card mt-3">
      <h2>⚡ 快速连接</h2>
      <div class="flex gap-2 items-center" style="flex-wrap:wrap">
        <select class="select" id="quickNode" style="flex:1;min-width:180px"></select>
        <select class="select" id="quickSlot" style="width:80px">
          <option value="0">槽1</option><option value="1">槽2</option>
        </select>
        <button class="btn btn-primary btn-sm" onclick="quickConnect()">连接</button>
      </div>
    </div>
  </div>

  <!-- 节点列表 -->
  <div class="content page" id="page-nodes">
    <div class="card">
      <div class="flex justify-between items-center">
        <h2>🗂 节点列表</h2>
        <div class="flex gap-2">
          <button class="btn btn-xs btn-grey" onclick="fetchNodes()">拉取</button>
          <button class="btn btn-xs btn-primary" id="testBtn" onclick="testCurrentPage()">测试当前页</button>
        </div>
      </div>
      <!-- 进度条 -->
      <div class="progress-wrap" id="testProgress">
        <div class="progress-bar"><div class="progress-fill" id="progressFill" style="width:0%"></div></div>
        <div class="progress-text">
          <span id="progressText">准备中...</span>
          <span id="progressCount">0/0</span>
        </div>
      </div>
      <div class="filter-row mt-2">
        <div class="filter-group"><label>状态</label>
          <select class="select" id="flStatus" onchange="gotoPage(1)">
            <option value="">全部</option><option value="available">可用</option>
            <option value="not_checked">未测试</option><option value="unavailable">不可用</option>
            <option value="no_config">无配置</option>
          </select>
        </div>
        <div class="filter-group"><label>国家</label>
          <select class="select" id="flCountry" onchange="gotoPage(1)"><option value="">全部</option></select>
        </div>
        <div class="filter-group"><label>类型</label>
          <select class="select" id="flIpType" onchange="gotoPage(1)">
            <option value="">全部</option><option value="residential">住宅</option>
            <option value="datacenter">机房</option>
          </select>
        </div>
        <div class="filter-group"><label>协议</label>
          <select class="select" id="flProto" onchange="gotoPage(1)">
            <option value="">全部</option><option value="tcp">TCP</option><option value="udp">UDP</option>
          </select>
        </div>
        <div class="filter-group"><label>每页</label>
          <select class="select" id="pageSize" onchange="gotoPage(1)">
            <option value="20">20</option><option value="50" selected>50</option><option value="100">100</option>
          </select>
        </div>
      </div>
      <!-- 桌面端表格 -->
      <div style="overflow-x:auto">
        <table class="node-table">
          <thead><tr>
            <th>国家/地区</th><th>IP</th><th>协议</th><th>延迟</th>
            <th>IP类型</th><th>状态</th><th>归属</th><th>操作</th>
          </tr></thead>
          <tbody id="nodeTableBody"></tbody>
        </table>
      </div>
      <!-- 移动端卡片 -->
      <div class="node-cards" id="nodeCards"></div>
      <div class="pagination" id="pagination"></div>
    </div>
  </div>

  <!-- 自建节点 -->
  <div class="content page" id="page-custom">
    <div class="card">
      <h2>➕ 添加自建 SOCKS5 节点</h2>
      <div class="grid-2" style="margin-bottom:12px">
        <div class="filter-group"><label>备注名称 *</label><input class="input" id="cn-name" placeholder="例如：JP住宅节点"></div>
        <div class="filter-group"><label>服务器地址 *</label><input class="input" id="cn-host" placeholder="IP 或域名"></div>
        <div class="filter-group"><label>端口 *</label><input class="input" id="cn-port" type="number" placeholder="1080"></div>
        <div class="filter-group"><label>用户名</label><input class="input" id="cn-user" placeholder="无认证留空"></div>
        <div class="filter-group"><label>密码</label><input class="input" id="cn-pass" type="password" placeholder="无认证留空"></div>
        <div class="filter-group"><label>备注</label><input class="input" id="cn-note" placeholder="可选"></div>
      </div>
      <button class="btn btn-primary" onclick="addCustomNode()">➕ 添加</button>
    </div>
    <div class="card">
      <h2>📋 自建节点</h2>
      <div id="customList"></div>
    </div>
  </div>

  <!-- 自动切换 -->
  <div class="content page" id="page-autoswitch">
    <div id="slotSwitchCards"></div>
    <button class="btn btn-primary mt-3" onclick="saveSlotConfigs()">💾 保存</button>
  </div>

  <!-- xray出口 -->
  <div class="content page" id="page-xray">
    <div class="card">
      <h2>🚀 xray 出口配置</h2>
      <p class="text-xs text-grey" style="margin-bottom:12px">配置各协议出口槽，保存后自动重启 xray。</p>
      <div id="xrayRoutingCards"></div>
      <button class="btn btn-primary mt-3" onclick="saveXrayDispatch()">💾 保存并重启xray</button>
    </div>
  </div>

  <!-- 日志 -->
  <div class="content page" id="page-logs">
    <div class="card">
      <h2>📋 日志</h2>
      <div id="logContent" style="font-family:monospace;font-size:11px;color:#a0aec0;max-height:400px;overflow-y:auto;background:#0f1117;padding:10px;border-radius:6px"></div>
    </div>
  </div>

  <!-- 设置 -->
  <div class="content page" id="page-settings">
    <div class="card">
      <h2>🔐 修改登录信息</h2>
      <div style="max-width:320px">
        <div class="form-group mt-2"><label class="text-xs text-grey">新用户名</label><input class="input mt-2" id="newUser" placeholder="留空不修改"></div>
        <div class="form-group mt-2"><label class="text-xs text-grey">新密码</label><input class="input mt-2" id="newPass" type="password" placeholder="留空不修改"></div>
        <div class="form-group mt-2"><label class="text-xs text-grey">确认密码</label><input class="input mt-2" id="newPass2" type="password"></div>
        <button class="btn btn-primary mt-3" onclick="saveCredentials()">💾 保存</button>
      </div>
    </div>
  </div>
</div>

<script>
let SESSION = localStorage.getItem('vpn_session') || '';
let allNodes = [], slotConfigs = {}, filteredNodes = [], currentPage = 1;
let testingNodes = new Set(), testResults = {};
let testPollTimer = null;

const SOURCE_LABELS = {
  'vpngate_residential':'🏘 住宅IP','vpngate_datacenter':'🏢 机房IP','vpngate_any':'🌐 任意',
};

async function api(path, opts={}) {
  const res = await fetch(path, {
    ...opts, headers: {'X-Session':SESSION,'Content-Type':'application/json',...(opts.headers||{})},
  });
  if (res.status===401){showLogin();return null;}
  return res.json().catch(()=>null);
}

function showToast(msg, isErr=false) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.style.background = isErr?'#742a2a':'#276749';
  t.style.color = isErr?'#feb2b2':'#9ae6b4';
  t.style.display = 'block';
  clearTimeout(t._tid);
  t._tid = setTimeout(()=>t.style.display='none', 3000);
}

function showLogin(){document.getElementById('loginPage').style.display='block';document.getElementById('mainApp').style.display='none';}
function showApp(){document.getElementById('loginPage').style.display='none';document.getElementById('mainApp').style.display='block';}

async function doLogin() {
  const u=document.getElementById('loginUser').value, p=document.getElementById('loginPass').value;
  const r = await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})});
  const d = await r.json();
  if(d.token){SESSION=d.token;localStorage.setItem('vpn_session',SESSION);showApp();refreshAll();}
  else{const el=document.getElementById('loginErr');el.textContent=d.error||'登录失败';el.style.display='block';}
}
function doLogout(){SESSION='';localStorage.removeItem('vpn_session');showLogin();}

function switchTab(name) {
  const pages=['dashboard','nodes','custom','autoswitch','xray','logs','settings'];
  document.querySelectorAll('.tab').forEach((t,i)=>t.classList.toggle('active',pages[i]===name));
  document.querySelectorAll('.page').forEach(p=>p.classList.toggle('active',p.id==='page-'+name));
  if(name==='nodes')loadNodes();
  if(name==='custom')loadCustomNodes();
  if(name==='autoswitch')loadAutoSwitch();
  if(name==='xray')loadXrayDispatch();
  if(name==='logs')loadLogs();
}

async function refreshAll() {
  const d = await api('/api/status');
  if(!d)return;
  document.getElementById('navBadge').textContent=`S1:${d.slots[0].node_id?'✓':'✗'} S2:${d.slots[1].node_id?'✓':'✗'}`;
  for(let i=0;i<2;i++){
    const s=d.slots[i];
    document.getElementById(`s${i}-dot`).className='dot '+(s.proxy_ok?'green':s.node_id?'yellow':'grey');
    document.getElementById(`s${i}-status`).textContent=s.status_msg||'-';
    document.getElementById(`s${i}-node`).textContent=(s.node_id||'-').replace(/^.{0,3}_/,'').substring(0,20);
    document.getElementById(`s${i}-ip`).textContent=s.proxy_ip||'-';
    document.getElementById(`s${i}-lat`).textContent=s.latency_ms?s.latency_ms+'ms':'-';
    document.getElementById(`s${i}-primary`).textContent=s.node_id?(s.using_backup?'⚠️备用':'✅主节点'):'-';
  }
  // 快速连接下拉
  const sel=document.getElementById('quickNode'), cur=sel.value;
  sel.innerHTML='<option value="">-- 选择节点 --</option>';
  (d.nodes||[]).filter(n=>n.probe_status==='available').forEach(n=>{
    const o=document.createElement('option');
    o.value=n.id;
    o.textContent=`${n.country||''} ${n.ip} [${n.proto||'tcp'}] ${n.latency_ms?n.latency_ms+'ms':''}`;
    sel.appendChild(o);
  });
  if(cur)sel.value=cur;
}

// ── 节点列表 ──
async function loadNodes() {
  const d=await api('/api/nodes');
  if(!d)return;
  allNodes=d.nodes||[];
  const cs=document.getElementById('flCountry'),cur=cs.value;
  cs.innerHTML='<option value="">全部</option>';
  [...new Set(allNodes.map(n=>n.country).filter(Boolean))].sort().forEach(c=>{
    const o=document.createElement('option');o.value=c;o.textContent=c;cs.appendChild(o);
  });
  cs.value=cur;
  gotoPage(1);
}

function getFilteredNodes(){
  const sf=document.getElementById('flStatus').value,
        cf=document.getElementById('flCountry').value,
        tf=document.getElementById('flIpType').value,
        pf=document.getElementById('flProto').value;
  let n=allNodes;
  if(sf)n=n.filter(x=>x.probe_status===sf);
  if(cf)n=n.filter(x=>x.country===cf);
  if(tf)n=n.filter(x=>x.ip_type===tf);
  if(pf)n=n.filter(x=>(x.proto||'tcp')===pf);
  return n;
}

function gotoPage(page){
  filteredNodes=getFilteredNodes();
  const ps=parseInt(document.getElementById('pageSize')?.value||'50');
  const total=Math.max(1,Math.ceil(filteredNodes.length/ps));
  currentPage=Math.max(1,Math.min(page,total));
  const start=(currentPage-1)*ps;
  renderNodePage(filteredNodes.slice(start,start+ps),total,ps);
}

const IP_TYPE_MAP={residential:['住宅','residential'],datacenter:['机房','datacenter'],proxy:['代理','proxy'],unknown:['未知','unknown'],mobile:['移动','residential']};
const ST_MAP={available:['可用','available'],unavailable:['不可用','unavail'],not_checked:['未测试','notcheck'],no_config:['无配置','notcheck']};

function getNodeStatus(n){
  if(testingNodes.has(n.id)) return ['测试中','testing'];
  if(testResults[n.id]){
    const r=testResults[n.id];
    return r.probe_status==='available'?['可用','available']:['不可用','unavail'];
  }
  return ST_MAP[n.probe_status]||['未知','notcheck'];
}

function renderNodePage(nodes,totalPages,pageSize){
  // 桌面端表格
  const tbody=document.getElementById('nodeTableBody');
  tbody.innerHTML='';
  nodes.forEach(n=>{
    const geo=[n.country,n.location].filter(Boolean).join('·');
    const [itL,itC]=IP_TYPE_MAP[n.ip_type]||['未知','unknown'];
    const [stL,stC]=getNodeStatus(n);
    const proto=n.proto||'tcp';
    const tr=document.createElement('tr');
    tr.id='tr-'+n.id;
    tr.innerHTML=`
      <td>${geo||'-'} <span style="font-size:10px;color:#4a5568">${n.country_short||''}</span></td>
      <td style="font-family:monospace;font-size:11px">${n.ip||'-'}</td>
      <td><span class="tag ${proto}">${proto.toUpperCase()}</span></td>
      <td>${n.latency_ms?n.latency_ms+'ms':'-'}</td>
      <td><span class="tag ${itC}">${itL}</span></td>
      <td><span class="tag ${stC}" id="st-${n.id}">${stL}</span></td>
      <td style="max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px;color:#718096">${n.as_name||n.owner||'-'}</td>
      <td>
        <button class="btn btn-xs btn-primary" onclick="connectNode('${n.id}',0)">→1</button>
        <button class="btn btn-xs btn-grey" onclick="connectNode('${n.id}',1)">→2</button>
        <button class="btn btn-xs btn-success" id="testbtn-${n.id}" onclick="testOneNode('${n.id}',this)">测</button>
      </td>`;
    tbody.appendChild(tr);
  });
  if(!nodes.length)tbody.innerHTML='<tr><td colspan="8" style="text-align:center;padding:20px;color:#718096">无数据</td></tr>';

  // 移动端卡片
  const cards=document.getElementById('nodeCards');
  cards.innerHTML='';
  nodes.forEach(n=>{
    const geo=[n.country,n.location].filter(Boolean).join(' · ');
    const [itL,itC]=IP_TYPE_MAP[n.ip_type]||['未知','unknown'];
    const [stL,stC]=getNodeStatus(n);
    const proto=n.proto||'tcp';
    const div=document.createElement('div');
    div.className='node-card'; div.id='card-'+n.id;
    div.innerHTML=`
      <div class="node-card-header">
        <span style="font-weight:600;font-size:13px">${geo||n.ip||'-'}</span>
        <span class="tag ${stC}" id="st-m-${n.id}">${stL}</span>
      </div>
      <div class="node-card-info">
        <span style="font-family:monospace">${n.ip||'-'}</span>
        <span class="tag ${proto}" style="font-size:10px">${proto.toUpperCase()}</span>
        <span class="tag ${itC}" style="font-size:10px">${itL}</span>
        ${n.latency_ms?`<span>${n.latency_ms}ms</span>`:''}
        ${n.as_name?`<span style="color:#4a5568">${n.as_name.substring(0,20)}</span>`:''}
      </div>
      <div class="node-card-actions">
        <button class="btn btn-xs btn-primary" onclick="connectNode('${n.id}',0)">→槽1</button>
        <button class="btn btn-xs btn-grey" onclick="connectNode('${n.id}',1)">→槽2</button>
        <button class="btn btn-xs btn-success" id="testbtn-m-${n.id}" onclick="testOneNode('${n.id}',this)">测试</button>
      </div>`;
    cards.appendChild(div);
  });

  // 分页
  const pg=document.getElementById('pagination');
  pg.innerHTML=`<span class="text-xs text-grey">共${filteredNodes.length}个·${currentPage}/${totalPages}页</span>`;
  if(totalPages>1){
    const prev=document.createElement('button');
    prev.className='pg-btn';prev.textContent='‹';prev.disabled=currentPage===1;
    prev.onclick=()=>gotoPage(currentPage-1);pg.appendChild(prev);
    let s=Math.max(1,currentPage-2),e=Math.min(totalPages,s+4);s=Math.max(1,e-4);
    for(let i=s;i<=e;i++){
      const b=document.createElement('button');b.className='pg-btn'+(i===currentPage?' active':'');
      b.textContent=i;b.onclick=(()=>{const p=i;return()=>gotoPage(p)})();pg.appendChild(b);
    }
    const next=document.createElement('button');
    next.className='pg-btn';next.textContent='›';next.disabled=currentPage===totalPages;
    next.onclick=()=>gotoPage(currentPage+1);pg.appendChild(next);
  }
}

// ── 批量测试（带进度显示） ──
async function testCurrentPage(){
  const ps=parseInt(document.getElementById('pageSize')?.value||'50');
  const start=(currentPage-1)*ps;
  const ids=filteredNodes.slice(start,start+ps)
    .filter(n=>n.probe_status!=='no_config'&&n.has_config!==false)
    .map(n=>n.id);
  if(!ids.length)return showToast('当前页无可测试节点',true);
  testingNodes=new Set(ids);
  testResults={};
  showToast(`开始测试 ${ids.length} 个节点...`);
  // 显示进度条
  const pw=document.getElementById('testProgress');
  pw.classList.add('active');
  document.getElementById('progressFill').style.width='0%';
  document.getElementById('progressText').textContent='测试中...';
  document.getElementById('progressCount').textContent=`0/${ids.length}`;
  document.getElementById('testBtn').disabled=true;
  gotoPage(currentPage);
  const r=await api('/api/test_nodes',{method:'POST',body:JSON.stringify({node_ids:ids})});
  if(r&&r.ok) startTestPoll(ids.length);
  else{showToast('启动失败',true);resetTestUI();}
}

function startTestPoll(total){
  if(testPollTimer)clearInterval(testPollTimer);
  testPollTimer=setInterval(async()=>{
    const p=await api('/api/test_progress');
    if(!p)return;
    const done=p.done||0, pct=total?Math.round(done/total*100):0;
    document.getElementById('progressFill').style.width=pct+'%';
    document.getElementById('progressCount').textContent=`${done}/${total}`;
    document.getElementById('progressText').textContent=p.current?`测试中: ${p.current.split('_').pop()}`:'处理中...';
    // 更新已完成节点的状态标签
    const results=p.results||{};
    Object.entries(results).forEach(([id,r])=>{
      testResults[id]=r;
      testingNodes.delete(id);
      const st=r.probe_status==='available'?['可用','available']:['不可用','unavail'];
      ['st-'+id,'st-m-'+id].forEach(eid=>{
        const el=document.getElementById(eid);
        if(el){el.textContent=st[0];el.className='tag '+st[1];}
      });
      // 更新allNodes
      const node=allNodes.find(n=>n.id===id);
      if(node)Object.assign(node,r);
    });
    if(!p.running){
      clearInterval(testPollTimer);testPollTimer=null;
      resetTestUI();
      showToast(`测试完成，${total}个节点`);
      gotoPage(currentPage);
    }
  },2000);
}

function resetTestUI(){
  document.getElementById('testProgress').classList.remove('active');
  document.getElementById('testBtn').disabled=false;
  testingNodes.clear();
}

async function testOneNode(nodeId,btn){
  const orig=btn.textContent;
  btn.textContent='...';btn.disabled=true;
  try{
    const r=await api('/api/test_node',{method:'POST',body:JSON.stringify({node_id:nodeId})});
    if(r&&r.probe_status){
      showToast(`${r.probe_status==='available'?'✅':'❌'} ${r.latency_ms?r.latency_ms+'ms':''} ${r.quality||''}`);
      const node=allNodes.find(n=>n.id===nodeId);
      if(node)Object.assign(node,r);
      gotoPage(currentPage);
    }else showToast((r&&r.error)||'测试失败',true);
  }finally{btn.textContent=orig;btn.disabled=false;}
}

// ── 自建节点 ──
async function loadCustomNodes(){
  const d=await api('/api/custom_nodes');
  if(!d)return;
  const list=document.getElementById('customList');
  if(!d.nodes||!d.nodes.length){list.innerHTML='<p class="text-grey text-sm" style="padding:10px">暂无自建节点</p>';return;}
  list.innerHTML='';
  d.nodes.forEach(n=>{
    const div=document.createElement('div');
    div.style.cssText='display:flex;align-items:center;gap:8px;padding:8px;background:#141720;border:1px solid #2d3748;border-radius:8px;margin-bottom:8px;flex-wrap:wrap';
    div.innerHTML=`
      <div style="flex:1;min-width:120px">
        <div style="font-weight:600;font-size:13px">${n.name}</div>
        <div style="font-size:11px;color:#718096">${n.host}:${n.port} ${n.note?'· '+n.note:''}</div>
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap">
        <button class="btn btn-xs btn-primary" onclick="connectCustom('${n.id}',0)">→槽1</button>
        <button class="btn btn-xs btn-grey" onclick="connectCustom('${n.id}',1)">→槽2</button>
        <button class="btn btn-xs btn-danger" onclick="deleteCustom('${n.id}')">删除</button>
      </div>`;
    list.appendChild(div);
  });
}

async function addCustomNode(){
  const name=document.getElementById('cn-name').value.trim(),host=document.getElementById('cn-host').value.trim(),port=parseInt(document.getElementById('cn-port').value)||0;
  if(!name||!host||!port)return showToast('名称、地址、端口必填',true);
  const r=await api('/api/custom_nodes',{method:'POST',body:JSON.stringify({action:'add',name,host,port,username:document.getElementById('cn-user').value.trim(),password:document.getElementById('cn-pass').value,note:document.getElementById('cn-note').value.trim()})});
  if(r&&r.ok){showToast('已添加');['cn-name','cn-host','cn-port','cn-user','cn-pass','cn-note'].forEach(id=>document.getElementById(id).value='');loadCustomNodes();}
  else showToast((r&&r.error)||'失败',true);
}
async function deleteCustom(id){
  await api('/api/custom_nodes',{method:'POST',body:JSON.stringify({action:'delete',node_id:id})});
  loadCustomNodes();
}
async function connectCustom(id,slot){
  showToast('连接中...');
  const r=await api('/api/connect_custom',{method:'POST',body:JSON.stringify({node_id:id,slot_id:slot})});
  showToast(r&&r.ok?r.message:(r&&r.error)||'失败',!(r&&r.ok));
  setTimeout(refreshAll,2000);
}

// ── 自动切换 ──
async function loadAutoSwitch(){
  const [r,nd]=await Promise.all([api('/api/slot_configs'),api('/api/nodes')]);
  if(!r)return;
  slotConfigs=r.configs;
  const nodeList=(nd&&nd.nodes||[]).filter(n=>n.probe_status==='available'&&n.has_config!==false);
  renderAutoSwitch(nodeList);
}

function renderAutoSwitch(nodeList){
  const wrap=document.getElementById('slotSwitchCards');wrap.innerHTML='';
  const nodeOpts=nodeList.map(n=>`<option value="${n.id}">${n.country||''} ${n.ip} [${n.proto||'tcp'}] ${n.latency_ms?n.latency_ms+'ms':''}</option>`).join('');
  for(let i=0;i<2;i++){
    const cfg=slotConfigs[String(i)]||{};
    const primaryId=cfg.primary_node_id||'',backupIds=cfg.backup_node_ids||[];
    const card=document.createElement('div');card.className='card';
    card.innerHTML=`
      <h2>槽${i+1} 自动切换</h2>
      <div class="flex items-center gap-2 mt-2">
        <input type="checkbox" id="as-en-${i}" ${cfg.auto_switch!==false?'checked':''}>
        <label for="as-en-${i}" style="font-size:13px">启用自动切换</label>
        <input type="checkbox" id="as-tcp-${i}" ${cfg.prefer_tcp!==false?'checked':''} style="margin-left:12px">
        <label for="as-tcp-${i}" style="font-size:13px">优先TCP</label>
      </div>
      <hr class="divider">
      <div style="font-size:13px;font-weight:600;margin-bottom:8px">主节点</div>
      <select class="select" id="primary-${i}" style="width:100%">
        <option value="">不设主节点（自动）</option>${nodeOpts}
      </select>
      <hr class="divider">
      <div style="font-size:13px;font-weight:600;margin-bottom:8px">备用节点</div>
      <div id="backups-${i}"></div>
      <div class="flex gap-2 mt-2">
        <select class="select" id="backup-add-${i}" style="flex:1"><option value="">选择备用节点...</option>${nodeOpts}</select>
        <button class="btn btn-sm btn-success" onclick="addBackup(${i})">➕</button>
      </div>
      <hr class="divider">
      <div class="filter-group mt-2">
        <label>主节点恢复检测间隔（分钟）</label>
        <input class="input" id="recovery-${i}" type="number" min="1" value="${cfg.recovery_interval||10}" style="max-width:100px;margin-top:4px">
      </div>
      <hr class="divider">
      <div style="font-size:13px;font-weight:600;margin-bottom:8px">无主节点时自动来源</div>
      <div id="sources-${i}"></div>
      <div class="flex gap-2 mt-2 flex-wrap">
        ${Object.entries(SOURCE_LABELS).map(([k,v])=>`<button class="btn btn-xs btn-grey" onclick="addSource(${i},'${k}')">${v}</button>`).join('')}
      </div>
      <div class="filter-group mt-3">
        <label>延迟上限(ms，0=不限)</label>
        <input class="input" id="as-lat-${i}" type="number" value="${cfg.max_latency_ms||0}" style="max-width:100px;margin-top:4px">
      </div>`;
    wrap.appendChild(card);
    if(primaryId){const s=document.getElementById(`primary-${i}`);if(s)s.value=primaryId;}
    renderBackups(i,backupIds,nodeList);
    renderSources(i,cfg.node_sources||['vpngate_residential','vpngate_any']);
  }
}

function renderBackups(slotId,ids,nodeList){
  const wrap=document.getElementById(`backups-${slotId}`);if(!wrap)return;
  wrap.innerHTML='';
  if(!ids.length){wrap.innerHTML='<div style="color:#718096;font-size:12px;padding:6px">（无备用节点）</div>';return;}
  ids.forEach((id,idx)=>{
    const node=nodeList&&nodeList.find(n=>n.id===id);
    const label=node?`${node.country||''} ${node.ip} [${node.proto||'tcp'}]`:id;
    const div=document.createElement('div');div.className='backup-item';
    div.innerHTML=`<span style="flex:1">${label}</span>
      ${idx>0?`<button class="btn btn-xs btn-grey" onclick="moveBackup(${slotId},${idx},-1)">↑</button>`:''}
      ${idx<ids.length-1?`<button class="btn btn-xs btn-grey" onclick="moveBackup(${slotId},${idx},1)">↓</button>`:''}
      <button class="btn btn-xs btn-danger" onclick="removeBackup(${slotId},${idx})">×</button>`;
    wrap.appendChild(div);
  });
}

function getBackupIds(slotId){return slotConfigs[String(slotId)]?.backup_node_ids?.slice()||[];}

async function addBackup(slotId){
  const sel=document.getElementById(`backup-add-${slotId}`),id=sel?.value;
  if(!id)return showToast('请选择节点',true);
  const ids=getBackupIds(slotId);
  if(ids.includes(id))return showToast('已存在',true);
  ids.push(id);slotConfigs[String(slotId)]={...(slotConfigs[String(slotId)]||{}),backup_node_ids:ids};
  const nd=await api('/api/nodes');
  renderBackups(slotId,ids,(nd&&nd.nodes||[]).filter(n=>n.probe_status==='available'));
  if(sel)sel.value='';
}

async function removeBackup(slotId,idx){
  const ids=getBackupIds(slotId);ids.splice(idx,1);
  slotConfigs[String(slotId)]={...(slotConfigs[String(slotId)]||{}),backup_node_ids:ids};
  const nd=await api('/api/nodes');
  renderBackups(slotId,ids,(nd&&nd.nodes||[]).filter(n=>n.probe_status==='available'));
}

async function moveBackup(slotId,idx,dir){
  const ids=getBackupIds(slotId),ni=idx+dir;
  if(ni<0||ni>=ids.length)return;
  [ids[idx],ids[ni]]=[ids[ni],ids[idx]];
  slotConfigs[String(slotId)]={...(slotConfigs[String(slotId)]||{}),backup_node_ids:ids};
  const nd=await api('/api/nodes');
  renderBackups(slotId,ids,(nd&&nd.nodes||[]).filter(n=>n.probe_status==='available'));
}

function renderSources(slotId,sources){
  const wrap=document.getElementById(`sources-${slotId}`);if(!wrap)return;
  wrap.innerHTML='';
  if(!sources.length){wrap.innerHTML='<div style="color:#718096;font-size:12px;padding:8px">（无来源）</div>';return;}
  sources.forEach((src,idx)=>{
    const div=document.createElement('div');div.className='source-item';
    div.innerHTML=`<span style="flex:1;font-size:13px">${SOURCE_LABELS[src]||src}</span>
      ${idx>0?`<button class="btn btn-xs btn-grey" onclick="moveSource(${slotId},${idx},-1)">↑</button>`:''}
      ${idx<sources.length-1?`<button class="btn btn-xs btn-grey" onclick="moveSource(${slotId},${idx},1)">↓</button>`:''}
      <button class="btn btn-xs btn-danger" onclick="removeSource(${slotId},${idx})">×</button>`;
    wrap.appendChild(div);
  });
}

function getSources(slotId){
  const wrap=document.getElementById(`sources-${slotId}`);if(!wrap)return[];
  const m=Object.fromEntries(Object.entries(SOURCE_LABELS).map(([k,v])=>[v,k]));
  return [...wrap.querySelectorAll('.source-item span:first-child')].map(el=>m[el.textContent.trim()]||el.textContent.trim());
}

function addSource(slotId,src){const c=getSources(slotId);if(c.includes(src))return showToast('已存在',true);c.push(src);renderSources(slotId,c);}
function removeSource(slotId,idx){const c=getSources(slotId);c.splice(idx,1);renderSources(slotId,c);}
function moveSource(slotId,idx,dir){const c=getSources(slotId),ni=idx+dir;if(ni<0||ni>=c.length)return;[c[idx],c[ni]]=[c[ni],c[idx]];renderSources(slotId,c);}

async function saveSlotConfigs(){
  const configs={};
  for(let i=0;i<2;i++){
    const ps=document.getElementById(`primary-${i}`);
    configs[String(i)]={
      auto_switch:document.getElementById(`as-en-${i}`).checked,
      prefer_tcp:document.getElementById(`as-tcp-${i}`).checked,
      node_sources:getSources(i),
      countries:slotConfigs[String(i)]?.countries||[],
      max_latency_ms:parseInt(document.getElementById(`as-lat-${i}`)?.value)||0,
      primary_node_id:ps?.value||'',
      backup_node_ids:getBackupIds(i),
      recovery_interval:parseInt(document.getElementById(`recovery-${i}`)?.value)||10,
    };
  }
  const r=await api('/api/slot_configs',{method:'POST',body:JSON.stringify({configs})});
  if(r&&r.ok){slotConfigs=configs;showToast('保存成功');}else showToast('失败',true);
}

// ── xray出口 ──
async function loadXrayDispatch(){
  const r=await api('/api/dispatch');if(!r)return;
  const cfg=r.config||{},inbounds=r.inbounds||[];
  const wrap=document.getElementById('xrayRoutingCards');wrap.innerHTML='';
  if(!inbounds.length){wrap.innerHTML='<p class="text-grey text-sm">未检测到 xray inbound，请确认 /root/agsbx/xr.json 存在。</p>';return;}
  inbounds.forEach(ib=>{
    const cur=cfg[ib.tag]||'direct';
    const div=document.createElement('div');
    div.style.cssText='display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid #2d3748;flex-wrap:wrap';
    div.innerHTML=`
      <div style="flex:1;min-width:160px">
        <div style="font-size:13px">${ib.label}</div>
        <div style="font-size:10px;color:#4a5568">${ib.tag}</div>
      </div>
      <select class="select" id="xray-${ib.tag}" style="width:160px">
        <option value="direct" ${cur==='direct'?'selected':''}>直连（原IP）</option>
        <option value="slot0" ${cur==='slot0'?'selected':''}>槽1（:7920）</option>
        <option value="slot1" ${cur==='slot1'?'selected':''}>槽2（:7921）</option>
      </select>`;
    wrap.appendChild(div);
  });
  wrap.dataset.tags=JSON.stringify(inbounds.map(ib=>ib.tag));
}

async function saveXrayDispatch(){
  const wrap=document.getElementById('xrayRoutingCards');
  const tags=JSON.parse(wrap.dataset.tags||'[]');
  const cfg={};tags.forEach(tag=>{const el=document.getElementById(`xray-${tag}`);if(el)cfg[tag]=el.value;});
  const r=await api('/api/dispatch',{method:'POST',body:JSON.stringify({config:cfg})});
  showToast(r&&r.ok?'已保存并重启xray':'失败',!(r&&r.ok));
}

// ── 节点操作 ──
async function fetchNodes(){showToast('拉取中...');const r=await api('/api/fetch_nodes',{method:'POST'});showToast(r&&r.ok?`获取 ${r.count} 个节点`:'失败',!(r&&r.ok));setTimeout(loadNodes,1500);}

async function connectNode(nodeId,slot){
  showToast(`连接到槽${slot+1}...`);
  const r=await api('/api/connect',{method:'POST',body:JSON.stringify({node_id:nodeId,slot_id:slot})});
  showToast(r&&r.ok?r.message:(r&&r.error)||'失败',!(r&&r.ok));
  setTimeout(refreshAll,3000);
}

async function quickConnect(){
  const raw=document.getElementById('quickNode').value,slot=parseInt(document.getElementById('quickSlot').value);
  if(!raw)return showToast('请选择节点',true);
  await connectNode(raw,slot);
}

async function stopSlot(slot){
  const r=await api('/api/stop',{method:'POST',body:JSON.stringify({slot_id:slot})});
  showToast(r&&r.ok?`槽${slot+1}已断开`:'失败',!(r&&r.ok));setTimeout(refreshAll,500);
}

async function checkSlot(slot){
  showToast('检测中...');
  const r=await api('/api/check_proxy',{method:'POST',body:JSON.stringify({slot_id:slot})});
  showToast(r&&r.ok?`出口: ${r.ip}`:'检测失败',!(r&&r.ok));setTimeout(refreshAll,500);
}

async function switchSlot(slot){
  const r=await api('/api/switch_slot',{method:'POST',body:JSON.stringify({slot_id:slot})});
  showToast(r&&r.ok?'切换指令已发送':'失败',!(r&&r.ok));setTimeout(refreshAll,3000);
}

// ── 日志 ──
async function loadLogs(){
  const d=await api('/api/logs');if(!d)return;
  const el=document.getElementById('logContent');
  el.innerHTML=(d.logs||[]).map(l=>`<div style="color:${l.level==='ERROR'?'#fc8181':l.level==='WARNING'?'#ecc94b':'#718096'}">[${l.timestamp.slice(11)}][${l.level}][${l.module}] ${l.message}</div>`).join('');
  el.scrollTop=el.scrollHeight;
}

// ── 设置 ──
async function saveCredentials(){
  const u=document.getElementById('newUser').value.trim(),p=document.getElementById('newPass').value,p2=document.getElementById('newPass2').value;
  if(p&&p!==p2)return showToast('密码不一致',true);
  if(!u&&!p)return showToast('请填写修改内容',true);
  const r=await api('/api/update_credentials',{method:'POST',body:JSON.stringify({username:u||undefined,password:p||undefined})});
  if(r&&r.ok){showToast('已更新，请重新登录');setTimeout(doLogout,1500);}else showToast((r&&r.error)||'失败',true);
}

(async()=>{
  if(SESSION){const d=await api('/api/status');if(d){showApp();refreshAll();}else showLogin();}
  else showLogin();
  setInterval(refreshAll,12000);
})();
</script>
</body>
</html>"""


# ── Web Handler ──────────────────────────────────────────────────────
class WebHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args): pass

    def _send_json(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _check_session(self) -> bool:
        token = self.headers.get("X-Session", "")
        now = time.time()
        if token in WEB_SESSIONS and now - WEB_SESSIONS[token] < SESSION_TTL:
            WEB_SESSIONS[token] = now; return True
        return False

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0: return {}
        try: return json.loads(self.rfile.read(length))
        except Exception: return {}

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path.rstrip("/") or "/"
        if path in ("/", "/index.html"):
            body = HTML_PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if not self._check_session():
            self._send_json({"error": "未授权"}, 401); return
        path_map = {
            "/api/status":        self._handle_status,
            "/api/nodes":         lambda: self._send_json({"nodes": read_json(NODES_FILE, [])}),
            "/api/custom_nodes":  lambda: self._send_json({"nodes": read_json(CUSTOM_NODES_FILE, [])}),
            "/api/slot_configs":  lambda: self._send_json({"configs": load_slot_configs()}),
            "/api/dispatch":      lambda: self._send_json({
                                      "config": load_xray_dispatch(),
                                      "inbounds": read_xray_inbounds(),
                                  }),
            "/api/test_progress": lambda: self._send_json(dict(_batch_test_status)),
            "/api/logs":          self._handle_logs,
            "/api/ui_config":     lambda: self._send_json({"port": load_ui_config().get("port", 8787)}),
        }
        handler = path_map.get(path)
        if handler: handler()
        else: self._send_json({"error": "not found"}, 404)

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/api/login":
            body = self._read_body()
            cfg = load_ui_config()
            if body.get("username") == cfg["username"] and body.get("password") == cfg["password"]:
                token = session_token(cfg["username"], cfg["password"])
                WEB_SESSIONS[token] = time.time()
                self._send_json({"token": token})
            else:
                self._send_json({"error": "用户名或密码错误"}, 401)
            return
        if not self._check_session():
            self._send_json({"error": "未授权"}, 401); return
        body = self._read_body()
        handlers = {
            "/api/connect":             lambda: self._handle_connect(body),
            "/api/connect_custom":      lambda: self._handle_connect_custom(body),
            "/api/stop":                lambda: self._handle_stop(body),
            "/api/switch_slot":         lambda: self._handle_switch_slot(body),
            "/api/fetch_nodes":         lambda: self._handle_fetch_nodes(),
            "/api/test_nodes":          lambda: self._handle_test_nodes(body),
            "/api/test_node":           lambda: self._handle_test_node_sync(body),
            "/api/check_proxy":         lambda: self._handle_check_proxy(body),
            "/api/custom_nodes":        lambda: self._handle_custom_nodes(body),
            "/api/slot_configs":        lambda: self._handle_save_slot_configs(body),
            "/api/dispatch":            lambda: self._handle_save_dispatch(body),
            "/api/update_credentials":  lambda: self._handle_update_credentials(body),
        }
        handler = handlers.get(path)
        if handler: handler()
        else: self._send_json({"error": "not found"}, 404)

    def _handle_status(self):
        slots_info = []
        for s in SLOTS:
            st = slot_states[s["id"]]
            slots_info.append({
                "slot_id": s["id"], "node_id": st.node_id,
                "node_type": st.node_type, "status_msg": st.status_msg,
                "is_connecting": st.is_connecting, "proxy_ok": st.proxy_ok,
                "proxy_ip": st.proxy_ip, "latency_ms": st.latency_ms,
                "using_backup": st.using_backup, "primary_id": st.primary_id,
            })
        nodes = read_json(NODES_FILE, [])
        self._send_json({
            "slots": slots_info,
            "nodes": [n for n in nodes if n.get("probe_status") == "available"][:80],
        })

    def _handle_connect(self, body):
        node_id = body.get("node_id", "")
        slot_id = int(body.get("slot_id", 0))
        if not node_id:
            self._send_json({"error": "缺少 node_id"}, 400); return
        threading.Thread(target=_safe_connect, args=(slot_id, node_id), daemon=True).start()
        self._send_json({"ok": True, "message": f"正在连接 {node_id} → 槽{slot_id+1}"})

    def _handle_connect_custom(self, body):
        node_id = body.get("node_id", "")
        slot_id = int(body.get("slot_id", 0))
        nodes = read_json(CUSTOM_NODES_FILE, [])
        node = next((n for n in nodes if n["id"] == node_id), None)
        if not node:
            self._send_json({"error": "节点不存在"}, 404); return
        threading.Thread(target=_safe_connect_custom, args=(slot_id, node), daemon=True).start()
        self._send_json({"ok": True, "message": f"正在连接 {node['name']} → 槽{slot_id+1}"})

    def _handle_stop(self, body):
        stop_slot(int(body.get("slot_id", 0)))
        self._send_json({"ok": True})

    def _handle_switch_slot(self, body):
        slot_id = int(body.get("slot_id", 0))
        threading.Thread(target=auto_switch_slot, args=(slot_id,), daemon=True).start()
        self._send_json({"ok": True})

    def _handle_fetch_nodes(self):
        def do():
            try:
                candidates = fetch_candidates()
                with lock:
                    existing = {n["id"]: n for n in read_json(NODES_FILE, [])}
                merged, seen = [], set()
                for c in candidates:
                    if c["id"] in existing:
                        ex = existing[c["id"]]
                        ex["config_text"] = c["config_text"]
                        ex["fetched_at"]  = c["fetched_at"]
                        merged.append(ex)
                    else:
                        merged.append(c)
                    seen.add(c["id"])
                for nid, n in existing.items():
                    if nid not in seen: merged.append(n)
                write_json(NODES_FILE, sort_nodes(merged[:5000]))
            except Exception as e:
                log("ERROR", "Fetch", str(e))
        threading.Thread(target=do, daemon=True).start()
        count = len(read_json(NODES_FILE, []))
        self._send_json({"ok": True, "count": count})

    def _handle_test_nodes(self, body):
        node_ids = body.get("node_ids")
        if node_ids:
            ids = node_ids
        else:
            count = int(body.get("count", 10))
            nodes = read_json(NODES_FILE, [])
            ids = [n["id"] for n in nodes if n.get("probe_status") == "not_checked"][:count]
        threading.Thread(target=batch_test_nodes, args=(ids,), daemon=True).start()
        self._send_json({"ok": True, "count": len(ids)})

    def _handle_test_node_sync(self, body):
        node_id = body.get("node_id", "")
        nodes = read_json(NODES_FILE, [])
        node = next((n for n in nodes if n["id"] == node_id), None)
        if not node:
            self._send_json({"error": "节点不存在"}, 404); return
        updates = test_node_sync(node)
        with lock:
            ns = read_json(NODES_FILE, [])
            for n in ns:
                if n["id"] == node_id: n.update(updates)
            write_json(NODES_FILE, sort_nodes(ns))
        self._send_json({"ok": True, **updates})

    def _handle_check_proxy(self, body):
        slot_id = int(body.get("slot_id", 0))
        result = check_slot_proxy(slot_id)
        st = slot_states[slot_id]
        st.proxy_ok = result["ok"]
        st.proxy_ip = result.get("ip", "")
        self._send_json(result)

    def _handle_custom_nodes(self, body):
        action = body.get("action", "")
        if action == "add":
            name = body.get("name", "").strip()
            host = body.get("host", "").strip()
            port = int(body.get("port", 0))
            if not name or not host or not port:
                self._send_json({"error": "名称、地址、端口为必填项"}, 400); return
            node = {
                "id": "custom_" + _uuid_mod.uuid4().hex[:8],
                "node_type": "custom", "name": name, "host": host, "port": port,
                "username": body.get("username", ""), "password": body.get("password", ""),
                "note": body.get("note", ""), "latency_ms": 0, "active_slot": -1,
                "created_at": time.time(),
            }
            nodes = read_json(CUSTOM_NODES_FILE, [])
            nodes.append(node)
            write_json(CUSTOM_NODES_FILE, nodes)
            self._send_json({"ok": True, "node_id": node["id"]})
        elif action == "delete":
            node_id = body.get("node_id", "")
            nodes = [n for n in read_json(CUSTOM_NODES_FILE, []) if n["id"] != node_id]
            write_json(CUSTOM_NODES_FILE, nodes)
            self._send_json({"ok": True})
        else:
            self._send_json({"error": "未知 action"}, 400)

    def _handle_save_slot_configs(self, body):
        save_slot_configs(body.get("configs", {}))
        self._send_json({"ok": True})

    def _handle_save_dispatch(self, body):
        cfg = body.get("config", {})
        save_xray_dispatch(cfg)
        threading.Thread(target=apply_xray_dispatch, args=(cfg,), daemon=True).start()
        self._send_json({"ok": True})

    def _handle_update_credentials(self, body):
        cfg = load_ui_config()
        new_user = body.get("username", "").strip()
        new_pass = body.get("password", "")
        if new_user: cfg["username"] = new_user
        if new_pass: cfg["password"] = new_pass
        if not new_user and not new_pass:
            self._send_json({"error": "未提供修改内容"}, 400); return
        save_ui_config(cfg)
        WEB_SESSIONS.clear()
        self._send_json({"ok": True})

    def _handle_logs(self):
        logs = []
        lf = LOGS_DIR / f"{time.strftime('%Y-%m-%d')}.json"
        if lf.exists():
            for line in lf.read_text(encoding="utf-8").splitlines()[-300:]:
                try: logs.append(json.loads(line))
                except Exception: pass
        self._send_json({"logs": logs[-300:]})


def _safe_connect(slot_id: int, node_id: str) -> None:
    try: connect_slot(slot_id, node_id)
    except Exception as e: log("ERROR", "API", f"connect_slot({slot_id},{node_id}): {e}")

def _safe_connect_custom(slot_id: int, node: dict) -> None:
    try: connect_custom_socks5(slot_id, node)
    except Exception as e: log("ERROR", "API", f"connect_custom({slot_id}): {e}")


def main():
    ensure_dirs()
    log("INFO", "Main", "VPNGate Pro 启动")
    # 清理旧的 iptables 残留规则
    try:
        subprocess.run(["iptables", "-t", "nat", "-F", "OUTPUT"], capture_output=True)
        log("INFO", "Main", "已清理 iptables NAT OUTPUT 规则")
    except Exception:
        pass

    proxy_mod.start_proxy_servers()

    # 启动时恢复 xray 调度配置
    dispatch_cfg = load_xray_dispatch()
    if any(v != "direct" for v in dispatch_cfg.values()):
        threading.Thread(target=apply_xray_dispatch, args=(dispatch_cfg,), daemon=True).start()

    def startup_fetch():
        try:
            candidates = fetch_candidates()
            existing = {n["id"]: n for n in read_json(NODES_FILE, [])}
            merged, seen = [], set()
            for c in candidates:
                merged.append(existing.get(c["id"], c)); seen.add(c["id"])
            for nid, n in existing.items():
                if nid not in seen: merged.append(n)
            write_json(NODES_FILE, sort_nodes(merged[:5000]))
            to_test = [n for n in merged
                       if n.get("probe_status") == "not_checked"
                       and n.get("proto", "tcp") == "tcp"][:6]
            if to_test:
                batch_test_nodes([n["id"] for n in to_test])
        except Exception as e:
            log("ERROR", "Startup", str(e))

    threading.Thread(target=startup_fetch, daemon=True).start()
    threading.Thread(target=health_monitor, daemon=True).start()
    threading.Thread(target=refresh_nodes_loop, daemon=True).start()
    threading.Thread(target=xray_watchdog, daemon=True).start()

    cfg  = load_ui_config()
    host = cfg.get("host", "0.0.0.0")
    port = int(cfg.get("port", 8787))
    server = ThreadingHTTPServer((host, port), WebHandler)
    log("INFO", "WebUI", f"地址: http://{host}:{port}/  用户名: {cfg['username']}  密码: {cfg['password']}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("INFO", "Main", "退出...")
        for sid in range(2): stop_slot(sid)
        proxy_mod.stop_proxy_servers()

if __name__ == "__main__":
    main()

# ── 覆盖 main 函数（内存优化版） ──────────────────────────────────────
def main():
    import gc
    import threading as _threading
    from concurrent.futures import ThreadPoolExecutor

    # 线程栈从默认 8MB 降到 512KB
    _threading.stack_size(1048576)

    # 让 malloc 更积极地归还内存给 OS
    try:
        import ctypes, ctypes.util
        libc = ctypes.CDLL(ctypes.util.find_library("c"))
        libc.mallopt(-3, 65536)   # M_MMAP_THRESHOLD = 64KB
        libc.mallopt(-1, 131072)  # M_TRIM_THRESHOLD = 128KB
    except Exception:
        pass

    ensure_dirs()
    log("INFO", "Main", "VPNGate Pro 启动（内存优化版）")
    try:
        subprocess.run(["iptables", "-t", "nat", "-F", "OUTPUT"], capture_output=True)
    except Exception:
        pass

    proxy_mod.start_proxy_servers()

    dispatch_cfg = load_xray_dispatch()
    if any(v != "direct" for v in dispatch_cfg.values()):
        threading.Thread(target=apply_xray_dispatch, args=(dispatch_cfg,), daemon=True).start()

    def startup_fetch():
        try:
            candidates = fetch_candidates()
            existing = {n["id"]: n for n in read_json(NODES_FILE, [])}
            merged, seen = [], set()
            for c in candidates:
                merged.append(existing.get(c["id"], c)); seen.add(c["id"])
            for nid, n in existing.items():
                if nid not in seen: merged.append(n)
            write_json(NODES_FILE, sort_nodes(merged[:5000]))
            gc.collect()
            to_test = [n for n in merged
                       if n.get("probe_status") == "not_checked"
                       and n.get("has_config", True)
                       and n.get("proto", "tcp") == "tcp"][:6]
            if to_test:
                batch_test_nodes([n["id"] for n in to_test])
            gc.collect()
        except Exception as e:
            log("ERROR", "Startup", str(e))

    def gc_loop():
        """每5分钟强制 GC 并归还堆内存给 OS"""
        while True:
            time.sleep(300)
            gc.collect()
            try:
                import ctypes, ctypes.util
                libc = ctypes.CDLL(ctypes.util.find_library("c"))
                libc.malloc_trim(0)
            except Exception:
                pass

    threading.Thread(target=startup_fetch, daemon=True).start()
    threading.Thread(target=health_monitor, daemon=True).start()
    threading.Thread(target=refresh_nodes_loop, daemon=True).start()
    threading.Thread(target=xray_watchdog, daemon=True).start()
    threading.Thread(target=gc_loop, daemon=True).start()

    cfg  = load_ui_config()
    host = cfg.get("host", "0.0.0.0")
    port = int(cfg.get("port", 8787))

    # 线程池 HTTP 服务器，最多 20 个并发请求
    class PooledHTTPServer(ThreadingHTTPServer):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._pool = ThreadPoolExecutor(max_workers=20)
        def process_request(self, request, client_address):
            self._pool.submit(self._handle, request, client_address)
        def _handle(self, request, client_address):
            try:
                self.finish_request(request, client_address)
            except Exception:
                self.handle_error(request, client_address)
            finally:
                self.shutdown_request(request)

    server = PooledHTTPServer((host, port), WebHandler)
    log("INFO", "WebUI", f"地址: http://{host}:{port}/  用户名: {cfg['username']}  密码: {cfg['password']}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("INFO", "Main", "退出...")
        for sid in range(2): stop_slot(sid)
        proxy_mod.stop_proxy_servers()
