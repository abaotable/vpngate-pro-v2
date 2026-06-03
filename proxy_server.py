#!/usr/bin/env python3
"""
双节点代理服务器
- VPNGate 节点：使用 microsocks（C 原生，极低 CPU）
- 自建节点：使用 Python SOCKS5 代理（支持上游链式转发）
"""
from __future__ import annotations
import select, socket, subprocess, threading
from typing import Any

MICROSOCKS_BIN = "/usr/local/bin/microsocks"


def _microsocks_available() -> bool:
    import os
    return os.path.exists(MICROSOCKS_BIN)


# ── 工具函数 ─────────────────────────────────────────────────────────

def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("连接意外断开")
        data += chunk
    return data


def relay(left: socket.socket, right: socket.socket) -> None:
    sockets = [left, right]
    while True:
        readable, _, errored = select.select(sockets, [], sockets, 120)
        if errored:
            return
        for src in readable:
            dst = right if src is left else left
            data = src.recv(65536)
            if not data:
                return
            dst.sendall(data)


# ── 上游 SOCKS5 连接（自建节点用） ──────────────────────────────────

def connect_via_upstream_socks5(
    target_host: str, target_port: int,
    upstream_host: str, upstream_port: int,
    username: str = "", password: str = "",
    timeout: float = 20.0,
) -> socket.socket:
    sock = socket.create_connection((upstream_host, upstream_port), timeout=timeout)
    try:
        sock.sendall(b"\x05\x02\x00\x02" if username else b"\x05\x01\x00")
        resp = recv_exact(sock, 2)
        if resp[0] != 5:
            raise ConnectionError("上游不是 SOCKS5 服务器")
        method = resp[1]
        if method == 0xFF:
            raise ConnectionError("上游拒绝认证")
        if method == 0x02:
            if not username:
                raise ConnectionError("上游要求认证但未提供凭据")
            u, p = username.encode(), password.encode()
            sock.sendall(bytes([1, len(u)]) + u + bytes([len(p)]) + p)
            if recv_exact(sock, 2)[1] != 0:
                raise ConnectionError("上游认证失败")
        try:
            socket.inet_aton(target_host)
            addr_bytes = b"\x01" + socket.inet_aton(target_host)
        except OSError:
            h = target_host.encode()
            addr_bytes = bytes([3, len(h)]) + h
        sock.sendall(b"\x05\x01\x00" + addr_bytes + target_port.to_bytes(2, "big"))
        resp_header = recv_exact(sock, 4)
        if resp_header[1] != 0:
            raise ConnectionError(f"上游 CONNECT 失败: {resp_header[1]}")
        atype = resp_header[3]
        if atype == 1:
            recv_exact(sock, 6)
        elif atype == 3:
            recv_exact(sock, recv_exact(sock, 1)[0] + 2)
        elif atype == 4:
            recv_exact(sock, 18)
        return sock
    except Exception:
        sock.close()
        raise


# ── 自建节点 Python 代理（仅用于上游 SOCKS5 链式转发） ───────────────

def _handle_custom_client(client: socket.socket, upstream: dict) -> None:
    conn = None
    try:
        client.settimeout(30)
        # 只处理 SOCKS5（xray 和 curl 都支持 SOCKS5）
        first = recv_exact(client, 1)
        if first[0] != 5:
            return
        n = recv_exact(client, 1)[0]
        recv_exact(client, n)
        client.sendall(b"\x05\x00")
        hdr = recv_exact(client, 4)
        if hdr[0] != 5 or hdr[1] != 1:
            client.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
            return
        atype = hdr[3]
        if atype == 1:
            host = socket.inet_ntoa(recv_exact(client, 4))
        elif atype == 3:
            host = recv_exact(client, recv_exact(client, 1)[0]).decode()
        elif atype == 4:
            host = socket.inet6_ntoa(recv_exact(client, 16))
        else:
            client.sendall(b"\x05\x08\x00\x01" + b"\x00" * 6)
            return
        port = int.from_bytes(recv_exact(client, 2), "big")
        try:
            conn = connect_via_upstream_socks5(
                host, port,
                upstream["host"], upstream["port"],
                upstream.get("username", ""), upstream.get("password", ""),
            )
        except Exception:
            client.sendall(b"\x05\x05\x00\x01" + b"\x00" * 6)
            return
        client.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
        relay(client, conn)
    except Exception:
        pass
    finally:
        if conn:
            try: conn.close()
            except Exception: pass
        try: client.close()
        except Exception: pass


class _PythonProxy:
    """最小化 Python SOCKS5 代理，仅用于自建节点上游链式转发"""
    def __init__(self, listen_port: int, upstream: dict):
        self.listen_port = listen_port
        self.upstream = upstream
        self._srv: socket.socket | None = None
        self._running = False

    def start(self) -> None:
        self._running = True
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", self.listen_port))
        self._srv.listen(256)
        threading.Thread(target=self._loop, daemon=True).start()
        print(f"[CustomProxy] 监听 127.0.0.1:{self.listen_port} → "
              f"{self.upstream['host']}:{self.upstream['port']}", flush=True)

    def _loop(self) -> None:
        while self._running:
            try:
                self._srv.settimeout(1.0)
                client, _ = self._srv.accept()
                threading.Thread(
                    target=_handle_custom_client,
                    args=(client, self.upstream),
                    daemon=True,
                ).start()
            except socket.timeout:
                continue
            except Exception:
                if self._running:
                    import traceback; traceback.print_exc()
                break

    def stop(self) -> None:
        self._running = False
        if self._srv:
            try: self._srv.close()
            except Exception: pass


# ── SlotProxyServer ──────────────────────────────────────────────────

class SlotProxyServer:
    """
    单槽代理管理器：
    - VPNGate 节点：启动 microsocks 进程（高性能）
    - 自建节点：启动 Python SOCKS5 代理（支持上游转发）
    """
    def __init__(self, slot_id: int, listen_port: int, tun_dev: str):
        self.slot_id     = slot_id
        self.listen_port = listen_port
        self.tun_dev     = tun_dev
        self.upstream_socks5: dict | None = None
        self._microsocks_proc: subprocess.Popen | None = None
        self._python_proxy: _PythonProxy | None = None

    def start_vpngate(self, tun_ip: str) -> None:
        """用 microsocks 启动 VPNGate 代理，绑定 tun IP 作为出口"""
        self._stop_all()
        if not tun_ip:
            print(f"[Proxy-Slot{self.slot_id}] 无 tun IP，跳过启动", flush=True)
            return
        if not _microsocks_available():
            print(f"[Proxy-Slot{self.slot_id}] microsocks 未安装，跳过", flush=True)
            return
        try:
            self._microsocks_proc = subprocess.Popen(
                [MICROSOCKS_BIN,
                 "-i", "127.0.0.1",
                 "-p", str(self.listen_port),
                 "-b", tun_ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            print(f"[Proxy-Slot{self.slot_id}] microsocks 启动 "
                  f"::{self.listen_port} bind={tun_ip} "
                  f"PID={self._microsocks_proc.pid}", flush=True)
        except Exception as e:
            print(f"[Proxy-Slot{self.slot_id}] microsocks 启动失败: {e}", flush=True)

    def set_upstream_socks5(self, upstream: dict | None) -> None:
        """连接自建节点：用 Python 代理链式转发到上游 SOCKS5"""
        self.upstream_socks5 = upstream
        self._stop_all()
        if upstream:
            self._python_proxy = _PythonProxy(self.listen_port, upstream)
            self._python_proxy.start()

    def _stop_all(self) -> None:
        # 停止 microsocks
        if self._microsocks_proc:
            try:
                self._microsocks_proc.terminate()
                self._microsocks_proc.wait(timeout=3)
            except Exception:
                try: self._microsocks_proc.kill()
                except Exception: pass
            self._microsocks_proc = None
        # 停止 Python 代理
        if self._python_proxy:
            self._python_proxy.stop()
            self._python_proxy = None
        # 清理残留进程
        subprocess.run(
            ["pkill", "-f", f"microsocks.*{self.listen_port}"],
            capture_output=True,
        )

    def stop(self) -> None:
        self._stop_all()
        self.upstream_socks5 = None

    def is_running(self) -> bool:
        if self._microsocks_proc:
            return self._microsocks_proc.poll() is None
        if self._python_proxy:
            return self._python_proxy._running
        return False


# ── 模块级单例 ───────────────────────────────────────────────────────

_proxy_slots: dict[int, SlotProxyServer] = {}

SLOT_CONFIG = [
    {"slot_id": 0, "listen_port": 7920, "tun_dev": "tun10"},
    {"slot_id": 1, "listen_port": 7921, "tun_dev": "tun11"},
]


def start_proxy_servers() -> None:
    # 清理上次残留的 microsocks 进程
    subprocess.run(["pkill", "-f", "microsocks"], capture_output=True)
    for cfg in SLOT_CONFIG:
        sid = cfg["slot_id"]
        if sid not in _proxy_slots:
            _proxy_slots[sid] = SlotProxyServer(
                slot_id=cfg["slot_id"],
                listen_port=cfg["listen_port"],
                tun_dev=cfg["tun_dev"],
            )


def stop_proxy_servers() -> None:
    for srv in _proxy_slots.values():
        srv.stop()
    _proxy_slots.clear()
