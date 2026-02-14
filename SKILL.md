# security-audit

Scan OpenClaw skill directories for supply chain attacks and malicious code.

## Features

- 22 security detection rules covering the full supply chain attack surface
- **Context-aware**: distinguishes documentation from executable code, reducing false positives
- Colored terminal output (red=critical, yellow=warning, blue=info, green=safe)
- JSON report output
- `--verbose` mode shows matching line context
- Whitelist support for excluding known-safe entries
- `--skip-dir` to exclude directories (e.g. node_modules, vendor)
- Compatible with macOS and Linux, zero external dependencies

## Usage

### Scan a skill directory

```bash
{baseDir}/scripts/audit.sh /path/to/skills
```

### Verbose mode (show context lines)

```bash
{baseDir}/scripts/audit.sh --verbose /path/to/skills
```

### JSON report output

```bash
{baseDir}/scripts/audit.sh --json /path/to/skills
```

### With whitelist

```bash
{baseDir}/scripts/audit.sh --whitelist whitelist.txt /path/to/skills
```

Whitelist file format (one entry per line, # for comments):
```
# Whitelist entire file
path/to/file.sh
# Whitelist specific line number
path/to/file.sh:42
# Whitelist specific rule
path/to/file.sh:pipe-execution
```

### Skip directories

```bash
{baseDir}/scripts/audit.sh --skip-dir node_modules --skip-dir vendor /path/to/skills
```

### Combined usage

```bash
{baseDir}/scripts/audit.sh --verbose --context 3 --whitelist whitelist.txt --skip-dir node_modules /path/to/skills
```

## Detection Rules (22)

### Critical Level
| # | Rule | Description |
|---|------|-------------|
| 1 | pipe-execution | Pipe execution (curl/wget piped to bash/sh/python) |
| 2 | base64-decode-pipe | Base64 decoded and piped to execution |
| 3 | security-bypass | macOS security bypass (Gatekeeper/SIP) |
| 5 | tor-onion-address | Tor hidden service addresses |
| 5 | reverse-shell | Reverse shell patterns |
| 7 | file-type-disguise | Binary disguised with text extension (Mach-O/ELF/PE) |
| 8 | ssh-key-exfiltration | SSH key theft |
| 8 | cloud-credential-access | Cloud credential access |
| 8 | env-exfiltration | Environment variables sent over network |
| 9 | anti-sandbox | Anti-sandbox/anti-debug (ptrace/DYLD injection) |
| 10 | covert-downloader | One-liner downloaders (Python/Node/Ruby/Perl/PowerShell) |
| 11 | persistence-launchagent | macOS persistence (LaunchAgent creation) |
| 13 | string-concat-bypass | String concatenation to evade detection |
| 15 | env-file-leak | .env file containing real secrets |
| 16 | typosquat-npm/pip | npm/pip package typosquatting |
| 17 | malicious-postinstall | Malicious lifecycle scripts (package.json/setup.py) |
| 18 | git-hooks | Active git hooks (auto-execute on git operations) |
| 19 | sensitive-file-leak | Private keys, credentials committed to repo |
| 20 | skillmd-prompt-injection | Prompt injection in SKILL.md |
| 21 | dockerfile-privileged | Docker privileged mode |
| 22 | zero-width-chars | Hidden zero-width Unicode characters |

### Warning Level
| # | Rule | Description |
|---|------|-------------|
| 2 | long-base64-string | Suspiciously long Base64 strings |
| 4 | dangerous-permissions | Dangerous permission changes |
| 5 | suspicious-network-ip | Non-local IP direct connections |
| 5 | netcat-listener | Netcat listeners |
| 6 | covert-exec-eval | Suspicious eval() calls (covers JS/TS) |
| 6 | covert-exec-python | os.system/subprocess in Python files |
| 11 | cron-injection | Scheduled task injection |
| 12 | hidden-executable | Hidden executable files |
| 13 | hex/unicode-obfuscation | Hex/Unicode escape obfuscation |
| 14 | symlink-sensitive | Symlinks pointing to sensitive locations |
| 16 | custom-registry | Non-official package registries |
| 20 | skillmd-privilege-escalation | Privilege escalation in SKILL.md |
| 21 | dockerfile-sensitive-mount | Sensitive host directory mounts |
| 21 | dockerfile-host-network | Host network mode |

## Exit Codes

- `0` -- Clean, no findings
- `1` -- Warning-level findings
- `2` -- Critical-level findings

## Dependencies

No external dependencies. Only uses system tools: bash, grep, sed, find, file, awk, readlink
