# VPNGate Pro

双节点智能代理网关，基于 VPNGate 公共节点，为 argosbx（Xray + Sing-box）提供动态出口 IP 切换能力。

## 功能特性

- **双节点槽**：同时维护两个 VPNGate 连接（tun10/tun11），独立出口 IP
- **主备节点**：每槽可配置主节点 + 多个备用节点，断线自动切换，主节点恢复后自动切回
- **xray 出口**：VLESS/VMess/SOCKS5 等协议可独立配置走槽1/槽2/直连
- **高性能代理**：使用 microsocks（C 原生）作为代理层，高流量低 CPU
- **IP 类型识别**：自动识别住宅 IP / 机房 IP / 代理 IP
- **节点分页**：支持分页浏览、按协议/国家/类型过滤、批量测试
- **xray 守护**：自动检测 xray 崩溃并重启
- **Web UI**：内置管理界面，无需命令行操作

## 架构

```
客户端
  └── Xray (VMess/VLESS/SOCKS5)
        └── 调度到 127.0.0.1:7920 或 :7921
              └── microsocks
                    └── 源IP绑定 tun10/tun11
                          └── 策略路由
                                └── OpenVPN → VPNGate 节点
```

## 快速安装

```bash
bash <(curl -Ls https://raw.githubusercontent.com/abaotable/vpngate-pro/main/install.sh)
```

> 安装前确保已修改 `install.sh` 中第35行的 GitHub 仓库地址。

## 依赖

- Debian 11/12 或 Ubuntu 20/22/24
- Python 3.8+
- OpenVPN
- microsocks（安装脚本自动编译）
- argosbx（Xray + Sing-box，已独立运行）

## 管理命令

```bash
vg start      # 启动
vg stop       # 停止
vg restart    # 重启
vg status     # 查看状态和 Web UI 地址
vg logs       # 实时日志
vg backup     # 备份当前脚本
vg rollback   # 回滚到上次备份
vg uninstall  # 卸载
```

## Xray 配置

在 xray 的 `xr.json` 中无需手动修改，通过 Web UI「xray出口」页面配置后自动更新并重启 xray。

## 数据目录

- 安装目录：`/opt/vpngate-pro/`
- 数据目录：`/var/lib/vpngate-pro/`
- xray 配置：`/root/agsbx/xr.json`（自动更新）

## 备用脚本

`backup/` 目录保存了纯 Python 代理版本（不依赖 microsocks），可通过 `vg rollback` 一键切换。
