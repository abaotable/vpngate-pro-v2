#!/usr/bin/env bash
# VPNGate Pro 一键安装脚本
# 支持：Debian 11/12，Ubuntu 20/22/24
# 用法：bash <(curl -Ls https://raw.githubusercontent.com/YOUR_GITHUB/vpngate-pro/main/install.sh)

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()    { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[✗]${NC} $*"; exit 1; }
section() { echo -e "\n${BLUE}══ $* ══${NC}"; }

# ── 权限检查 ────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "请以 root 权限运行"

# ── 系统检查 ────────────────────────────────────────────────────────
source /etc/os-release 2>/dev/null || true
OS_ID="${ID:-}"
OS_VER="${VERSION_ID:-}"

if [[ "$OS_ID" != "debian" && "$OS_ID" != "ubuntu" ]]; then
    warn "当前系统为 $OS_ID，仅官方支持 Debian/Ubuntu，继续尝试安装..."
fi

section "VPNGate Pro 安装程序"
echo "系统: $OS_ID $OS_VER"
echo "架构: $(uname -m)"

# ── 配置变量 ────────────────────────────────────────────────────────
INSTALL_DIR="/opt/vpngate-pro"
DATA_DIR="/var/lib/vpngate-pro"
SERVICE_NAME="vpngate-pro"
# ↓ 替换为你自己的 GitHub 仓库地址
REPO_RAW="https://raw.githubusercontent.com/YOUR_GITHUB/vpngate-pro/main"

# ── 安装依赖 ────────────────────────────────────────────────────────
section "安装依赖"
apt-get update -qq
apt-get install -y -qq openvpn python3 iproute2 iptables curl ca-certificates gcc make wget
info "依赖安装完成"

# ── 编译安装 microsocks ──────────────────────────────────────────────
section "安装 microsocks"
if ! command -v microsocks &>/dev/null || [ ! -f /usr/local/bin/microsocks ]; then
    cd /tmp
    wget -q https://github.com/rofl0r/microsocks/archive/refs/heads/master.tar.gz \
         -O microsocks.tar.gz 2>/dev/null || \
    curl -sL https://github.com/rofl0r/microsocks/archive/refs/heads/master.tar.gz \
         -o microsocks.tar.gz
    tar xzf microsocks.tar.gz
    cd microsocks-master
    make -s
    cp microsocks /usr/local/bin/
    chmod +x /usr/local/bin/microsocks
    cd /tmp
    rm -rf microsocks-master microsocks.tar.gz
    info "microsocks 编译安装完成"
else
    info "microsocks 已安装，跳过"
fi

# ── 下载项目文件 ─────────────────────────────────────────────────────
section "下载项目文件"
mkdir -p "$INSTALL_DIR"

for f in vpngate_manager.py proxy_server.py vpn_utils.py; do
    curl -fsSL "$REPO_RAW/$f" -o "$INSTALL_DIR/$f"
    info "已下载: $f"
done

chmod +x "$INSTALL_DIR/vpngate_manager.py"

# ── 创建数据目录 ─────────────────────────────────────────────────────
section "创建数据目录"
mkdir -p "$DATA_DIR/configs" "$DATA_DIR/logs"
info "数据目录: $DATA_DIR"

# ── 创建 systemd 服务 ────────────────────────────────────────────────
section "配置系统服务"
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=VPNGate Pro - 双节点智能代理网关
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
Environment="VPNGATE_DATA_DIR=${DATA_DIR}"
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/vpngate_manager.py
Restart=always
RestartSec=10
KillMode=mixed
TimeoutStopSec=30

# 日志限制
StandardOutput=journal
StandardError=journal
SyslogIdentifier=vpngate-pro

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
info "systemd 服务已配置"

# ── 创建 ml 快捷命令 ─────────────────────────────────────────────────
section "创建管理命令"
cat > /usr/local/bin/vg <<'SCRIPT'
#!/usr/bin/env bash
SVC="vpngate-pro"
DATA="/var/lib/vpngate-pro"
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

case "${1:-}" in
  start)   systemctl start $SVC && echo -e "${GREEN}已启动${NC}" ;;
  stop)    systemctl stop  $SVC && echo -e "${YELLOW}已停止${NC}" ;;
  restart) systemctl restart $SVC && echo -e "${GREEN}已重启${NC}" ;;
  logs)    journalctl -u $SVC -f --no-pager ;;
  status)
    echo -e "${GREEN}══ VPNGate Pro 状态 ══${NC}"
    systemctl status $SVC --no-pager -l
    echo ""
    if [[ -f "$DATA/ui_auth.json" ]]; then
      HOST=$(python3 -c "import json;d=json.load(open('$DATA/ui_auth.json'));print(d.get('host','0.0.0.0'))" 2>/dev/null || echo "0.0.0.0")
      PORT=$(python3 -c "import json;d=json.load(open('$DATA/ui_auth.json'));print(d.get('port',8787))" 2>/dev/null || echo "8787")
      USER=$(python3 -c "import json;d=json.load(open('$DATA/ui_auth.json'));print(d.get('username',''))" 2>/dev/null)
      PASS=$(python3 -c "import json;d=json.load(open('$DATA/ui_auth.json'));print(d.get('password',''))" 2>/dev/null)
      IP=$(curl -s --max-time 3 ifconfig.me 2>/dev/null || echo "?")
      echo -e "${GREEN}Web 管理界面:${NC} http://$IP:$PORT/"
      echo -e "${GREEN}用户名:${NC} $USER"
      echo -e "${GREEN}密码:${NC}   $PASS"
    fi
    echo ""
    echo -e "${GREEN}代理端口:${NC}"
    echo "  Slot 1 (tun10): 127.0.0.1:7920"
    echo "  Slot 2 (tun11): 127.0.0.1:7921"
    ;;
  password)
    python3 -c "
import json,string,random,pathlib
chars=string.ascii_letters+string.digits
def rnd(n):
    while True:
        s=''.join(random.choices(chars,k=n))
        if any(c.islower() for c in s) and any(c.isupper() for c in s) and any(c.isdigit() for c in s):
            return s
f=pathlib.Path('$DATA/ui_auth.json')
d=json.loads(f.read_text()) if f.exists() else {}
d['password']=rnd(12)
f.write_text(json.dumps(d,indent=2))
print('新密码:',d['password'])
"
    systemctl restart $SVC
    ;;
  backup)
    BACKUP_DIR="$INST/backup"
    mkdir -p "$BACKUP_DIR"
    cp "$INST"/*.py "$BACKUP_DIR/"
    echo "$(date)" > "$BACKUP_DIR/backup_time.txt"
    echo -e "${GREEN}已备份到 $BACKUP_DIR${NC}"
    ;;
  rollback)
    BACKUP_DIR="$INST/backup"
    if ls "$BACKUP_DIR"/*.py &>/dev/null 2>&1; then
        cp "$BACKUP_DIR"/*.py "$INST/"
        systemctl restart $SVC
        echo -e "${GREEN}已回滚，备份时间: $(cat $BACKUP_DIR/backup_time.txt 2>/dev/null)${NC}"
    else
        echo -e "${RED}未找到备份文件，请先运行 vg backup${NC}"
    fi
    ;;
  uninstall)
    read -p "确认卸载 VPNGate Pro？[y/N] " yn
    [[ "$yn" != "y" && "$yn" != "Y" ]] && exit 0
    systemctl stop $SVC 2>/dev/null; systemctl disable $SVC 2>/dev/null
    rm -f /etc/systemd/system/${SVC}.service
    rm -rf /opt/vpngate-pro
    rm -f /usr/local/bin/vg
    systemctl daemon-reload
    echo -e "${YELLOW}已卸载（数据目录 $DATA 保留）${NC}"
    ;;
  *)
    echo "VPNGate Pro 管理工具"
    echo "用法: vg <命令>"
    echo ""
    echo "  start      启动服务"
    echo "  stop       停止服务"
    echo "  restart    重启服务"
    echo "  status     查看状态（含Web UI地址和密码）"
    echo "  logs       实时日志"
    echo "  password   重置管理密码"
    echo "  backup     备份当前脚本"
    echo "  rollback   回滚到上次备份"
    echo "  uninstall  卸载"
    ;;
esac
SCRIPT

chmod +x /usr/local/bin/vg
info "管理命令已创建：vg"

# ── 防火墙 & iptables 模块 ───────────────────────────────────────────
section "配置 iptables NAT"
modprobe iptable_nat 2>/dev/null || true
modprobe ip_tables   2>/dev/null || true
# 持久化模块加载
echo "iptable_nat" >> /etc/modules 2>/dev/null || true
echo "ip_tables"   >> /etc/modules 2>/dev/null || true
info "iptables NAT 模块已加载"

# ── 开启 IP 转发 ─────────────────────────────────────────────────────
sysctl -w net.ipv4.ip_forward=1 >/dev/null
grep -q "net.ipv4.ip_forward" /etc/sysctl.conf \
  && sed -i 's/#*net.ipv4.ip_forward.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf \
  || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
info "IP 转发已启用"

# ── 启动服务 ────────────────────────────────────────────────────────
section "启动服务"
systemctl start "$SERVICE_NAME"
sleep 3

if systemctl is-active --quiet "$SERVICE_NAME"; then
    info "服务启动成功"
else
    warn "服务启动失败，查看日志："
    journalctl -u "$SERVICE_NAME" -n 20 --no-pager
fi

# ── 安装完成提示 ─────────────────────────────────────────────────────
section "安装完成"
PUBLIC_IP=$(curl -s --max-time 5 ifconfig.me 2>/dev/null || echo "YOUR_VPS_IP")

if [[ -f "$DATA_DIR/ui_auth.json" ]]; then
    UI_USER=$(python3 -c "import json;d=json.load(open('$DATA_DIR/ui_auth.json'));print(d.get('username',''))" 2>/dev/null)
    UI_PASS=$(python3 -c "import json;d=json.load(open('$DATA_DIR/ui_auth.json'));print(d.get('password',''))" 2>/dev/null)
    UI_PORT=$(python3 -c "import json;d=json.load(open('$DATA_DIR/ui_auth.json'));print(d.get('port',8787))" 2>/dev/null)
else
    UI_USER="(初始化中...)"
    UI_PASS="(初始化中...)"
    UI_PORT="8787"
fi

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║       VPNGate Pro 安装成功！             ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║${NC} Web 界面: http://${PUBLIC_IP}:${UI_PORT}/"
echo -e "${GREEN}║${NC} 用户名  : $UI_USER"
echo -e "${GREEN}║${NC} 密  码  : $UI_PASS"
echo -e "${GREEN}╠══════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║${NC} Slot 1 代理: 127.0.0.1:7920 (tun10)"
echo -e "${GREEN}║${NC} Slot 2 代理: 127.0.0.1:7921 (tun11)"
echo -e "${GREEN}╠══════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║${NC} 管理命令: vg status / vg logs / vg restart"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}提示：${NC}"
echo "  1. 打开 Web 界面后，先到「节点列表」拉取并测试节点"
echo "  2. 在「过滤设置」配置国家/IP类型偏好"
echo "  3. 在「协议路由」配置各协议走哪个节点槽"
echo "  4. 将 Xray 的出站代理指向 127.0.0.1:7920 或 :7921"
echo ""
