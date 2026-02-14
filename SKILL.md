# 🦒 Giraffe Guard — 长颈鹿卫士

扫描 OpenClaw skill 目录，检测潜在的供应链投毒和恶意代码。

## 功能

- 17 类安全检测规则，覆盖供应链攻击全链路
- **上下文感知**：区分文档描述和实际可执行代码，降低误报
- 彩色终端输出（红=严重, 黄=警告, 蓝=信息, 绿=安全）
- JSON 格式报告输出
- `--verbose` 模式显示匹配行上下文
- 白名单机制，支持排除已知安全条目
- 兼容 macOS 和 Linux，零外部依赖

## 使用方法

### 扫描 skill 目录

```bash
{baseDir}/scripts/audit.sh /path/to/skills
```

### 详细模式（显示上下文行）

```bash
{baseDir}/scripts/audit.sh --verbose /path/to/skills
```

### 输出 JSON 格式报告

```bash
{baseDir}/scripts/audit.sh --json /path/to/skills
```

### 使用白名单

```bash
{baseDir}/scripts/audit.sh --whitelist whitelist.txt /path/to/skills
```

白名单文件格式（每行一条，# 开头为注释）：
```
# 整个文件加白
path/to/file.sh
# 特定行号加白
path/to/file.sh:42
# 特定规则加白
path/to/file.sh:pipe-execution
```

### 组合使用

```bash
{baseDir}/scripts/audit.sh --verbose --context 3 --whitelist whitelist.txt /path/to/skills
```

## 检测规则（17 条）

### 🔴 严重级别
| 编号 | 规则 | 说明 |
|------|------|------|
| 1 | pipe-execution | 管道执行（curl/wget 管道到 bash/sh/python 等） |
| 2 | base64-decode-pipe | Base64 解码后管道执行 |
| 3 | security-bypass | macOS 安全机制绕过（Gatekeeper/SIP） |
| 5 | tor-onion-address | Tor 暗网地址 |
| 5 | reverse-shell | 反向 shell 模式 |
| 7 | file-type-disguise | 文本扩展名伪装二进制文件（Mach-O/ELF/PE） |
| 8 | ssh-key-exfiltration | SSH 密钥窃取 |
| 8 | cloud-credential-access | 云凭证访问 |
| 8 | env-exfiltration | 通过网络发送环境变量 |
| 9 | anti-sandbox | 反沙盒/反调试（ptrace/DYLD 注入） |
| 10 | covert-downloader | 单行脚本下载器（Python/Node/Ruby/Perl/PowerShell） |
| 11 | persistence-launchagent | macOS 持久化（LaunchAgent 创建） |
| 13 | string-concat-bypass | 字符串拼接绕过检测 |
| 15 | env-file-leak | .env 文件含真实密钥 |
| 16 | typosquat-npm/pip | npm/pip 包名 typosquatting |
| 17 | malicious-postinstall | package.json/setup.py 恶意生命周期脚本 |

### 🟡 警告级别
| 编号 | 规则 | 说明 |
|------|------|------|
| 2 | long-base64-string | 超长 Base64 编码字符串 |
| 4 | dangerous-permissions | 危险权限修改 |
| 5 | suspicious-network-ip | 非本地 IP 直连 |
| 5 | netcat-listener | netcat 监听 |
| 6 | covert-exec-eval | 可疑 eval 调用 |
| 11 | cron-injection | 定时任务注入 |
| 12 | hidden-executable | 隐藏的可执行文件 |
| 13 | hex/unicode-obfuscation | hex/Unicode 转义混淆 |
| 14 | symlink-sensitive | 符号链接指向敏感位置 |
| 16 | custom-registry | 非官方包管理 registry |

## 退出码

- `0` — 安全，无发现
- `1` — 有警告级别发现
- `2` — 有严重级别发现

## 依赖

无外部依赖，仅使用系统自带工具：bash, grep, sed, find, file, awk, readlink
