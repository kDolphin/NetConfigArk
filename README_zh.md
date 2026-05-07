# NetConfigArk

[English](README.md) | [中文](README_zh.md)

网络设备配置备份工具。通过 SSH/Telnet 连接交换机、路由器和防火墙，以**只读**模式获取运行配置（不对设备做任何修改）。

## 支持设备

| 类型 | 设备 | 配置命令 |
|---|---|---|
| `cisco` | Cisco IOS/IOS-XE 交换机/路由器 | `show running-config` |
| `cisco_asa` | Cisco ASA/FTD 防火墙 | `show running-config` |
| `cisco_nxos` | Cisco Nexus 数据中心交换机 | `show running-config` |
| `cisco_xr` | Cisco IOS-XR 路由器 | `show running-config` |
| `huawei` | 华为 VRP 交换机/路由器 | `display current-configuration` |
| `huawei_usg` | 华为 USG 防火墙 | `display current-configuration` |
| `h3c` | H3C Comware 交换机/路由器 | `display current-configuration` |
| `fortinet` | Fortinet FortiGate 防火墙 | `show full-configuration` |
| `juniper` | Juniper JunOS 路由器/交换机/SRX | `show configuration` |
| `paloalto` | Palo Alto PAN-OS 防火墙 | `show config running` |
| `routeros` | MikroTik RouterOS 路由器/交换机 | `export` |

## 功能特性

- **批量或单设备** — CSV 文件批量操作，或命令行参数单台备份
- **设备类型指纹验证** — 预检阶段自动检测并纠正错误的 `device_type`（如 H3C 被标为 Huawei）
- **SSH 自动检测** — SSH 连接时 `device_type` 可留空，通过 SSHDetect 自动识别
- **预检后再备份** — 备份前先验证所有设备可达；`--skip-unreachable` 可跳过不可达设备继续
- **配置完整性验证** — 检查结束标记、分页残留和最少行数
- **连接重试** — 超时自动重试一次，应对间歇性网络问题
- **空输出重试** — 对 prompt 检测异常的设备回退为基于时间的命令执行方式
- **并发执行** — 可配线程数并行备份；`--burst` 模式实现最大并行度
- **配置差异报告** — 对比每台设备最近 N 次备份，生成带颜色编码的 HTML diff 报告；默认过滤自动生成的时间戳
- **配置查看器** — 生成交互式 HTML 页面，带语法高亮浏览每台设备最新配置，支持搜索和深色/浅色主题切换
- **按地点分拆** — `--split` 参数按 location 生成独立 HTML 文件，方便分发给各站点负责人
- **有序输出** — 按地点分组，文件名含 IP/类型/主机名/时间戳
- **只读保证** — 仅发送 show/display/export 命令，绝不进入配置模式

## 环境要求

- Python 3.8+
- 到目标设备的网络可达性（SSH/Telnet）

## 快速开始

```bash
# 安装依赖
pip install -r requirements.txt

# 生成 CSV 模板
python3 backup_config.py --init

# 查看支持的设备类型
python3 backup_config.py --list-types

# 编辑 devices.csv 填入设备信息，然后运行：
python3 backup_config.py -c devices.csv
```

## 使用方法

### CSV 批量模式

```bash
# 基本批量备份
python3 backup_config.py -c devices.csv

# 自定义参数
python3 backup_config.py -c devices.csv -w 4 -t 30 --read-timeout 120 --skip-unreachable

# Burst 模式：每台设备一个线程，全部并行
python3 backup_config.py -c devices.csv --burst
```

### 配置差异模式

```bash
# 对比每台设备最近 5 次备份（默认），生成 HTML 报告
python3 backup_config.py -c devices.csv --diff

# 对比最近 3 次备份
python3 backup_config.py -c devices.csv --diff 3

# 不过滤时间戳（显示所有差异）
python3 backup_config.py -c devices.csv --diff --no-filter
```

差异报告保存为 `backups/diff_report_<时间戳>.html`。用浏览器打开即可查看带颜色编码的配置变更对比。默认自动过滤自动生成的时间戳（RouterOS 导出头、华为/Cisco 时间戳行、`ntp clock-period`）以减少噪音。

### 配置查看模式

```bash
# 生成配置查看器 HTML
python3 backup_config.py -c devices.csv --view
```

查看器保存为 `backups/config_view_<时间戳>.html`。双栏布局：左侧设备列表（按地点分组，可搜索），右侧语法高亮配置面板。支持深色/浅色主题切换。键盘快捷键：`j/k` 或方向键导航设备，`/` 聚焦搜索，`Esc` 清除。

### 按地点分拆

```bash
# 按地点生成独立的差异报告
python3 backup_config.py -c devices.csv --diff --split

# 按地点生成独立的配置查看器
python3 backup_config.py -c devices.csv --view --split
```

在 `--diff` 或 `--view` 后加 `--split`，按 location 生成独立 HTML 文件。文件名格式为 `<类型>_<时间戳>_<地点>.html`，每个文件完全自包含，可独立分发。

### 单设备模式

```bash
# 最简用法（密码交互输入，设备类型自动检测）
python3 backup_config.py -H 192.168.1.1 -u admin

# 完整参数
python3 backup_config.py -H 10.0.0.1 -u admin -p pass123 -d cisco --enable-password en123

# Telnet + 非标准端口
python3 backup_config.py -H 172.16.0.1 -u admin -p pass123 -P telnet --port 2323 -d h3c
```

### 命令行参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `-c, --csv` | `devices.csv` | 设备清单 CSV 文件 |
| `-H, --host` | | 设备 IP（启用单设备模式） |
| `-u, --username` | | 登录用户名 |
| `-p, --password` | | 登录密码（省略则交互输入） |
| `-P, --protocol` | `ssh` | `ssh` 或 `telnet` |
| `-d, --device-type` | | 设备类型（SSH 可选，Telnet 必填） |
| `--enable-password` | | 特权模式密码 |
| `--location` | `default` | 站点/地点名称，用于分组 |
| `-o, --output` | `./backups` | 输出目录 |
| `-w, --workers` | `2` | 并发线程数 |
| `--burst` | 关闭 | 并发数 = 设备数（全部并行） |
| `-t, --timeout` | `20` | 连接超时（秒） |
| `--read-timeout` | `60` | 配置获取超时（秒） |
| `-v, --verbose` | 关闭 | 调试日志 |
| `--skip-unreachable` | 关闭 | 跳过不可达设备，继续备份其余 |
| `--list-types` | | 显示支持的设备类型并退出 |
| `--init` | | 生成 CSV 模板并退出 |
| `--diff [N]` | `5` | 对比最近 N 次备份，生成 HTML 差异报告 |
| `--no-filter` | 关闭 | 差异模式下禁用时间戳过滤 |
| `--view` | 关闭 | 生成带语法高亮的 HTML 配置查看器 |
| `--split` | 关闭 | 将 `--diff`/`--view` 输出按地点拆分为独立文件 |

## CSV 格式

```csv
ip,protocol,port,username,password,device_type,enable_password,hostname,location
192.168.1.1,ssh,,admin,password,huawei,,Core-Switch,DC-East
10.0.0.1,ssh,22,admin,password,cisco,enable123,Router-01,DC-East
172.16.0.1,telnet,23,admin,password,h3c,,Access-SW,Office
```

- `port` — 留空使用默认值（SSH=22, Telnet=23）
- `device_type` — SSH 可选（自动检测），Telnet 必填
- `enable_password` — 可选，用于 Cisco enable / 华为 super
- `hostname` — 可选，用于目录和文件命名
- `location` — 可选，按站点分组备份（默认为 `default`）
- 以 `#` 开头的行为注释

## 输出目录结构

```
backups/
  DC-East/
    192.168.1.1_huawei_Core-Switch/
      192.168.1.1_huawei_Core-Switch_2026-03-10_143000.txt
  default/
    172.16.0.1_h3c/
      172.16.0.1_h3c_2026-03-10_143000.txt
```

## 许可证

MIT
