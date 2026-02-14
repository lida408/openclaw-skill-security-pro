# OpenClaw Skill Security Auditor

[English](#english) | [中文](#中文)

---

<a id="english"></a>
## English

A security scanner for [OpenClaw](https://github.com/openclaw/openclaw) skills -- detect supply chain attacks, malicious code, and suspicious patterns before they compromise your system.

> Born from a real supply chain poisoning incident in the OpenClaw community. Stay safe.

### Features

- **22 detection rules** covering the full supply chain attack surface
- **Context-aware** -- distinguishes documentation from executable code (low false positives)
- **Zero dependencies** -- only uses bash, grep, sed, find, file, awk
- **Cross-platform** -- macOS (BSD) and Linux (GNU) compatible
- **Multiple output formats** -- colored terminal, JSON reports
- **Whitelist support** -- suppress known-safe findings
- **Verbose mode** -- show surrounding context lines for each finding
- **Skip directories** -- exclude directories like node_modules or vendor

### Quick Start

#### As an OpenClaw Skill

```bash
# Clone into your OpenClaw skills directory
git clone https://github.com/lida408/openclaw-skill-security-pro.git \
  ~/.openclaw/workspace/skills/security-pro

# Scan your skills
bash ~/.openclaw/workspace/skills/security-pro/scripts/audit.sh ~/.openclaw/workspace/skills/
```

#### Standalone

```bash
git clone https://github.com/lida408/openclaw-skill-security-pro.git
cd openclaw-skill-security-pro
bash scripts/audit.sh /path/to/scan
```

### Usage

```bash
# Basic scan
bash scripts/audit.sh /path/to/skills

# Verbose mode (show context lines around findings)
bash scripts/audit.sh --verbose /path/to/skills

# JSON output (for CI/CD integration)
bash scripts/audit.sh --json /path/to/skills

# With whitelist
bash scripts/audit.sh --whitelist whitelist.txt /path/to/skills

# Custom context lines (default: 2)
bash scripts/audit.sh --verbose --context 5 /path/to/skills

# Skip directories (repeatable)
bash scripts/audit.sh --skip-dir node_modules --skip-dir vendor /path/to/skills
```

### Detection Rules

#### Critical (immediate action required)

| # | Rule | Description |
|---|------|-------------|
| 1 | pipe-execution | Remote code piped to shell (`curl \| bash`) |
| 2 | base64-decode-pipe | Base64 decoded and executed |
| 3 | security-bypass | macOS Gatekeeper/SIP bypass |
| 5 | tor-onion-address | Tor hidden service addresses |
| 5 | reverse-shell | Reverse shell patterns |
| 7 | file-type-disguise | Binary masquerading as text file |
| 8 | ssh-key-exfiltration | SSH key theft via network |
| 8 | cloud-credential-access | Cloud credential access (AWS/GCP/Azure) |
| 8 | env-exfiltration | Environment variables sent over network |
| 9 | anti-sandbox | Anti-debug/anti-sandbox techniques |
| 10 | covert-downloader | One-liner downloaders (Python/Node/Ruby/Perl/PowerShell) |
| 11 | persistence-launchagent | macOS LaunchAgent persistence |
| 13 | string-concat-bypass | String concatenation to evade detection |
| 15 | env-file-leak | `.env` file containing real secrets |
| 16 | typosquat-npm/pip | Typosquatting package names |
| 17 | malicious-postinstall | Malicious lifecycle scripts |
| 18 | git-hooks | Active git hooks that auto-execute |
| 19 | sensitive-file-leak | Private keys, credentials committed to repo |
| 20 | skillmd-prompt-injection | Prompt injection in SKILL.md |
| 21 | dockerfile-privileged | Privileged Docker containers |
| 22 | zero-width-chars | Hidden zero-width Unicode characters |

#### Warning (manual review recommended)

| # | Rule | Description |
|---|------|-------------|
| 2 | long-base64-string | Suspiciously long Base64 strings |
| 4 | dangerous-permissions | Dangerous permission changes |
| 5 | suspicious-network-ip | Direct IP connections (non-local) |
| 5 | netcat-listener | Netcat listeners |
| 6 | covert-exec-eval | Suspicious eval() calls (includes JS/TS) |
| 6 | covert-exec-python | os.system/subprocess in Python files |
| 11 | cron-injection | Cron/launchctl/systemd injection |
| 12 | hidden-executable | Hidden executable files |
| 13 | hex/unicode-obfuscation | Hex/Unicode escape obfuscation |
| 14 | symlink-sensitive | Symlinks pointing to sensitive locations |
| 16 | custom-registry | Non-official package registries |
| 20 | skillmd-privilege-escalation | Privilege escalation in SKILL.md |
| 21 | dockerfile-sensitive-mount | Sensitive host directory mounts |
| 21 | dockerfile-host-network | Host network mode |

### Whitelist File Format

```txt
# Whitelist entire file
path/to/trusted-file.sh

# Whitelist specific line number
path/to/file.sh:42

# Whitelist specific rule for a file
path/to/file.sh:pipe-execution
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Clean -- no findings |
| 1 | Warnings found |
| 2 | Critical findings |

### CI/CD Integration

```yaml
# GitHub Actions example
- name: Security Audit
  run: |
    bash scripts/audit.sh --json ./skills > audit-report.json
    EXIT_CODE=$?
    if [ $EXIT_CODE -eq 2 ]; then
      echo "::error::Critical security findings detected!"
      exit 1
    fi
```

### Automation with OpenClaw

Add to your `TOOLS.md` to enforce scanning on every skill install:

```markdown
## Skill Security Audit (mandatory)
Every new skill must be scanned before activation:
1. Run: `bash skills/security-pro/scripts/audit.sh <new-skill-path>`
2. Exit 0 -> safe to use
3. Exit 1 -> report warnings to user
4. Exit 2 -> block activation, notify user
```

Schedule daily scans via OpenClaw cron:
```
0 4 * * * bash skills/security-pro/scripts/audit.sh /path/to/skills
```

---

<a id="中文"></a>
## 中文

[OpenClaw](https://github.com/openclaw/openclaw) 技能安全扫描器 -- 在供应链攻击、恶意代码和可疑模式危害你的系统之前将其检测出来。

> 诞生于 OpenClaw 社区中一起真实的供应链投毒事件。保持警惕。

### 特性

- **22 条检测规则**，覆盖供应链攻击全链路
- **上下文感知** -- 自动区分文档描述和可执行代码，大幅降低误报
- **零外部依赖** -- 仅使用 bash、grep、sed、find、file、awk
- **跨平台** -- 兼容 macOS (BSD) 和 Linux (GNU)
- **多种输出格式** -- 彩色终端输出、JSON 报告
- **白名单支持** -- 排除已知安全的条目
- **详细模式** -- 显示匹配行的上下文
- **目录跳过** -- 排除 node_modules、vendor 等目录

### 快速开始

#### 作为 OpenClaw Skill 使用

```bash
# 克隆到 OpenClaw 技能目录
git clone https://github.com/lida408/openclaw-skill-security-pro.git \
  ~/.openclaw/workspace/skills/security-pro

# 扫描你的技能
bash ~/.openclaw/workspace/skills/security-pro/scripts/audit.sh ~/.openclaw/workspace/skills/
```

#### 独立使用

```bash
git clone https://github.com/lida408/openclaw-skill-security-pro.git
cd openclaw-skill-security-pro
bash scripts/audit.sh /要扫描的路径
```

### 使用方法

```bash
# 基本扫描
bash scripts/audit.sh /path/to/skills

# 详细模式（显示匹配行上下文）
bash scripts/audit.sh --verbose /path/to/skills

# JSON 格式输出（适合 CI/CD 集成）
bash scripts/audit.sh --json /path/to/skills

# 指定白名单
bash scripts/audit.sh --whitelist whitelist.txt /path/to/skills

# 自定义上下文行数（默认 2 行）
bash scripts/audit.sh --verbose --context 5 /path/to/skills

# 跳过目录（可重复使用）
bash scripts/audit.sh --skip-dir node_modules --skip-dir vendor /path/to/skills
```

### 检测规则

#### 严重级别（需立即处理）

| 编号 | 规则 | 说明 |
|------|------|------|
| 1 | pipe-execution | 管道执行（curl/wget 管道到 bash/sh/python） |
| 2 | base64-decode-pipe | Base64 解码后管道执行 |
| 3 | security-bypass | macOS 安全机制绕过（Gatekeeper/SIP） |
| 5 | tor-onion-address | Tor 暗网地址 |
| 5 | reverse-shell | 反向 shell 模式 |
| 7 | file-type-disguise | 文本扩展名伪装二进制文件（Mach-O/ELF/PE） |
| 8 | ssh-key-exfiltration | SSH 密钥通过网络外传 |
| 8 | cloud-credential-access | 云服务凭证访问（AWS/GCP/Azure） |
| 8 | env-exfiltration | 环境变量通过网络外传 |
| 9 | anti-sandbox | 反沙盒/反调试技术 |
| 10 | covert-downloader | 单行脚本下载器（Python/Node/Ruby/Perl/PowerShell） |
| 11 | persistence-launchagent | macOS LaunchAgent 持久化 |
| 13 | string-concat-bypass | 字符串拼接绕过检测 |
| 15 | env-file-leak | .env 文件包含真实密钥 |
| 16 | typosquat-npm/pip | npm/pip 包名 typosquatting |
| 17 | malicious-postinstall | 恶意生命周期脚本（postinstall/setup.py） |
| 18 | git-hooks | 活跃的 git hooks（git 操作时自动执行） |
| 19 | sensitive-file-leak | 私钥、凭证文件提交到仓库 |
| 20 | skillmd-prompt-injection | SKILL.md 中的 prompt 注入 |
| 21 | dockerfile-privileged | Docker 特权模式运行 |
| 22 | zero-width-chars | 隐藏的零宽 Unicode 字符 |

#### 警告级别（建议人工复核）

| 编号 | 规则 | 说明 |
|------|------|------|
| 2 | long-base64-string | 超长 Base64 编码字符串 |
| 4 | dangerous-permissions | 危险权限修改 |
| 5 | suspicious-network-ip | 非本地 IP 直连 |
| 5 | netcat-listener | netcat 监听 |
| 6 | covert-exec-eval | 可疑 eval() 调用（含 JS/TS） |
| 6 | covert-exec-python | Python 文件中的 os.system/subprocess |
| 11 | cron-injection | 定时任务注入 |
| 12 | hidden-executable | 隐藏的可执行文件 |
| 13 | hex/unicode-obfuscation | hex/Unicode 转义混淆 |
| 14 | symlink-sensitive | 符号链接指向敏感位置 |
| 16 | custom-registry | 使用非官方包管理 registry |
| 20 | skillmd-privilege-escalation | SKILL.md 中的权限提升 |
| 21 | dockerfile-sensitive-mount | 挂载主机敏感目录 |
| 21 | dockerfile-host-network | 容器使用主机网络模式 |

### 白名单格式

```txt
# 整个文件加白
path/to/trusted-file.sh

# 特定行号加白
path/to/file.sh:42

# 特定规则加白
path/to/file.sh:pipe-execution
```

### 退出码

| 退出码 | 含义 |
|--------|------|
| 0 | 安全 -- 无发现 |
| 1 | 有警告级别发现 |
| 2 | 有严重级别发现 |

### 在 OpenClaw 中自动化

在 `TOOLS.md` 中添加规则，强制每次安装 skill 前扫描：

```markdown
## Skill 安全审计（强制规则）
每个新 skill 必须扫描后才能启用：
1. 运行：`bash skills/security-pro/scripts/audit.sh <新skill路径>`
2. 退出码 0 -> 安全可用
3. 退出码 1 -> 告知用户警告内容
4. 退出码 2 -> 禁止启用，通知用户
```

通过 OpenClaw cron 设置每日自动巡检：
```
0 4 * * * bash skills/security-pro/scripts/audit.sh /path/to/skills
```

---

## License / 许可证

[Apache License 2.0](LICENSE)

## Contributing / 贡献

欢迎提交 Issue 和 PR。添加新检测规则时请：

1. 在 `scripts/audit.sh` 中添加检测函数
2. 在 `scan_file()`（文件级）或 `main()`（目录级）中调用
3. 更新 `SKILL.md` 规则表
4. 用正常 skill 和恶意样本分别测试
5. 确保对 OpenClaw 内置 skill 零误报
