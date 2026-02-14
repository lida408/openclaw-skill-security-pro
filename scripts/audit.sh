#!/bin/bash
set -uo pipefail

# ============================================================
# OpenClaw Skill Security Auditor v2.0.0
# 扫描 skill 目录，检测供应链投毒和恶意代码
# 兼容 macOS (BSD) 和 Linux (GNU)
# 零外部依赖：仅使用 bash, grep, sed, find, file, awk, readlink
# ============================================================

VERSION="2.0.0"

# --- 颜色定义 ---
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# --- 参数 ---
VERBOSE=false
JSON_OUTPUT=false
WHITELIST_FILE=""
TARGET_DIR=""
CONTEXT_LINES=2  # --verbose 时显示的上下文行数

SELF_PATH="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"

# 临时文件用于子shell传递计数（避免管道子shell变量丢失）
TMPDIR_AUDIT=$(mktemp -d)
echo 0 > "$TMPDIR_AUDIT/findings"
echo 0 > "$TMPDIR_AUDIT/critical"
echo 0 > "$TMPDIR_AUDIT/warning"
echo 0 > "$TMPDIR_AUDIT/info"
echo 0 > "$TMPDIR_AUDIT/whitelisted"
echo 0 > "$TMPDIR_AUDIT/files"
FINDINGS_FILE="$TMPDIR_AUDIT/findings_json"
touch "$FINDINGS_FILE"
trap 'rm -rf "$TMPDIR_AUDIT"' EXIT

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS] <target-directory>

OpenClaw Skill Security Auditor v${VERSION}
扫描 skill 目录，检测供应链投毒和恶意代码。

Options:
  --verbose       显示详细信息（含匹配行上下文）
  --json          输出 JSON 格式报告
  --whitelist F   指定白名单文件
  --context N     上下文行数（默认 2，配合 --verbose）
  --version       显示版本
  -h, --help      显示帮助

Examples:
  $(basename "$0") /path/to/skills
  $(basename "$0") --verbose --json /path/to/skills
  $(basename "$0") --whitelist whitelist.txt /path/to/skills

Exit codes:
  0  安全（无发现）
  1  有警告级别发现
  2  有严重级别发现
EOF
    exit 0
}

# --- 参数解析 ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --verbose) VERBOSE=true; shift ;;
        --json) JSON_OUTPUT=true; shift ;;
        --whitelist) WHITELIST_FILE="$2"; shift 2 ;;
        --context) CONTEXT_LINES="$2"; shift 2 ;;
        --version) echo "security-audit v${VERSION}"; exit 0 ;;
        -h|--help) usage ;;
        -*) echo "Unknown option: $1"; exit 1 ;;
        *) TARGET_DIR="$1"; shift ;;
    esac
done

if [[ -z "$TARGET_DIR" ]]; then
    echo "Error: 请指定扫描目标目录"
    usage
fi

if [[ ! -d "$TARGET_DIR" ]]; then
    echo "Error: 目录不存在: $TARGET_DIR"
    exit 1
fi

# --- 白名单加载 ---
declare -a WHITELIST_ENTRIES
load_whitelist() {
    if [[ -n "$WHITELIST_FILE" && -f "$WHITELIST_FILE" ]]; then
        while IFS= read -r line; do
            [[ -z "$line" || "$line" == \#* ]] && continue
            WHITELIST_ENTRIES+=("$line")
        done < "$WHITELIST_FILE"
    fi
}

is_whitelisted() {
    local filepath="$1"
    local lineno="$2"
    local rule="$3"
    for entry in "${WHITELIST_ENTRIES[@]+"${WHITELIST_ENTRIES[@]}"}"; do
        if [[ "$entry" == "${filepath}:${lineno}" || "$entry" == "${filepath}:${rule}" || "$entry" == "$filepath" ]]; then
            return 0
        fi
    done
    return 1
}

# --- JSON 辅助 ---
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
}

# --- 上下文获取（--verbose 用）---
get_context() {
    local file="$1"
    local lineno="$2"
    local ctx_lines="$CONTEXT_LINES"
    local start=$((lineno - ctx_lines))
    [[ $start -lt 1 ]] && start=1
    local end=$((lineno + ctx_lines))
    sed -n "${start},${end}p" "$file" 2>/dev/null | while IFS= read -r ctx_line; do
        if [[ $start -eq $lineno ]]; then
            echo "  >>> ${start}: ${ctx_line}"
        else
            echo "      ${start}: ${ctx_line}"
        fi
        start=$((start + 1))
    done
}

# --- 判断是否是文档上下文（降低误报）---
# 返回 0 = 是文档上下文（可能误报），1 = 不是
is_doc_context() {
    local file="$1"
    local lineno="$2"
    local ext="${file##*.}"

    # Markdown/文本文件中的代码块、表格、列表项 — 更可能是文档
    if [[ "$ext" == "md" || "$ext" == "txt" || "$ext" == "rst" ]]; then
        local line
        line=$(sed -n "${lineno}p" "$file" 2>/dev/null)
        # 表格行
        if echo "$line" | grep -qE '^\s*\|'; then
            return 0
        fi
        # 在代码块注释中（行首有 #、// 或在 ``` 块内）
        if echo "$line" | grep -qE '^\s*(#|//|<!--)'; then
            return 0
        fi
        # 纯描述（以 - 开头的列表，且含描述性词汇）
        if echo "$line" | grep -qE '^\s*[-*]\s+.*\b(example|示例|说明|description|e\.g\.|如|用于|for|about)\b'; then
            return 0
        fi
    fi
    return 1
}

# --- 发现记录 ---
add_finding() {
    local level="$1"      # CRITICAL / WARNING / INFO
    local filepath="$2"
    local lineno="$3"
    local rule="$4"
    local content="$5"

    # 白名单检查
    local wl_status=""
    if is_whitelisted "$filepath" "$lineno" "$rule"; then
        wl_status="WHITELISTED"
        echo $(( $(cat "$TMPDIR_AUDIT/whitelisted") + 1 )) > "$TMPDIR_AUDIT/whitelisted"
    else
        echo $(( $(cat "$TMPDIR_AUDIT/findings") + 1 )) > "$TMPDIR_AUDIT/findings"
        case "$level" in
            CRITICAL) echo $(( $(cat "$TMPDIR_AUDIT/critical") + 1 )) > "$TMPDIR_AUDIT/critical" ;;
            WARNING)  echo $(( $(cat "$TMPDIR_AUDIT/warning") + 1 )) > "$TMPDIR_AUDIT/warning" ;;
            INFO)     echo $(( $(cat "$TMPDIR_AUDIT/info") + 1 )) > "$TMPDIR_AUDIT/info" ;;
        esac
    fi

    if [[ "$JSON_OUTPUT" == true ]]; then
        echo "{\"level\":\"$(json_escape "$level")\",\"file\":\"$(json_escape "$filepath")\",\"line\":$lineno,\"rule\":\"$(json_escape "$rule")\",\"content\":\"$(json_escape "$content")\",\"whitelisted\":$([ "$wl_status" = "WHITELISTED" ] && echo true || echo false)}" >> "$FINDINGS_FILE"
    else
        local color icon
        case "$level" in
            CRITICAL) color="$RED"; icon="🔴" ;;
            WARNING)  color="$YELLOW"; icon="🟡" ;;
            INFO)     color="$CYAN"; icon="🔵" ;;
        esac
        if [[ "$wl_status" == "WHITELISTED" ]]; then
            echo -e "  ${DIM}[WHITELISTED] ${icon} ${level} | ${filepath}:${lineno} | ${rule}${NC}"
        else
            echo -e "  ${color}${icon} ${level}${NC} | ${BOLD}${filepath}:${lineno}${NC} | ${CYAN}${rule}${NC}"
            echo -e "     ${DIM}${content}${NC}"
            if [[ "$VERBOSE" == true && "$lineno" != "0" ]]; then
                echo -e "${DIM}$(get_context "$filepath" "$lineno")${NC}"
                echo ""
            fi
        fi
    fi
}

# ============================================================
# 检测规则
# ============================================================

# 规则 1: 管道执行 (CRITICAL)
check_pipe_execution() {
    local file="$1"
    grep -n -E '(curl|wget)\s+.*\|\s*(bash|sh|zsh|dash|ksh|python[23]?|perl|ruby|node)(\s|$)' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        # 如果是文档上下文，降级为 WARNING
        if is_doc_context "$file" "$lineno"; then
            add_finding "WARNING" "$file" "$lineno" "pipe-execution-doc" "$content"
        else
            add_finding "CRITICAL" "$file" "$lineno" "pipe-execution" "$content"
        fi
    done
}

# 规则 2: Base64 混淆 (CRITICAL)
check_base64_obfuscation() {
    local file="$1"
    # base64 -d 后接管道
    grep -n -E 'base64\s+(-d|--decode)\s*\|' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        add_finding "CRITICAL" "$file" "$lineno" "base64-decode-pipe" "$content"
    done
    # echo ... | base64 -d 变体
    grep -n -E 'echo\s+.*\|\s*base64\s+(-d|--decode)' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        add_finding "CRITICAL" "$file" "$lineno" "base64-echo-decode" "$content"
    done
    # 超长 base64 字符串（>100字符的连续 base64）
    grep -n -E '[A-Za-z0-9+/]{100,}={0,2}' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        # 排除合法长字符串（JWT token 示例、SSH key 文档等）
        case "$content" in
            *"ssh-"*|*"BEGIN "*|*"example"*|*"示例"*|*"token"*) continue ;;
        esac
        add_finding "WARNING" "$file" "$lineno" "long-base64-string" "检测到超长 Base64 编码字符串"
    done
}

# 规则 3: 安全机制绕过 (CRITICAL)
check_security_bypass() {
    local file="$1"
    grep -n -E 'xattr\s+-(c|d\s+com\.apple\.quarantine)|spctl\s+--master-disable|csrutil\s+disable' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        if is_doc_context "$file" "$lineno"; then
            add_finding "WARNING" "$file" "$lineno" "security-bypass-doc" "$content"
        else
            add_finding "CRITICAL" "$file" "$lineno" "security-bypass" "$content"
        fi
    done
}

# 规则 4: 危险权限操作 (WARNING)
check_dangerous_permissions() {
    local file="$1"
    grep -n -E 'chmod\s+(777|\+x\s+/tmp|4[0-7]{3}|u\+s)|chown\s+root|chgrp\s+root' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        case "$content" in
            *"chmod +x scripts/"*|*"chmod +x audit"*|*"chmod +x ./"*) continue ;;
        esac
        if is_doc_context "$file" "$lineno"; then continue; fi
        add_finding "WARNING" "$file" "$lineno" "dangerous-permissions" "$content"
    done
}

# 规则 5: 可疑网络行为
check_suspicious_network() {
    local file="$1"
    # IP 直连（排除本地/私有地址）
    grep -n -E 'https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        if echo "$content" | grep -qE '127\.0\.0\.1|0\.0\.0\.0|192\.168\.|10\.[0-9]+\.|172\.(1[6-9]|2[0-9]|3[01])\.'; then
            continue
        fi
        add_finding "WARNING" "$file" "$lineno" "suspicious-network-ip" "$content"
    done
    # .onion 域名
    grep -n -E '[a-z2-7]{16,56}\.onion\b' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        add_finding "CRITICAL" "$file" "$lineno" "tor-onion-address" "$content"
    done
    # 反向 shell 模式
    grep -n -E 'nc\s+(-e|--exec)|ncat\s+(-e|--exec)|bash\s+-i\s+>\&\s*/dev/tcp|/dev/udp/' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        add_finding "CRITICAL" "$file" "$lineno" "reverse-shell" "$content"
    done
    # netcat 监听
    grep -n -E '\bnc\s+-[lp]|\bncat\s+-[lp]|\bnetcat\s+-[lp]' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        if is_doc_context "$file" "$lineno"; then continue; fi
        add_finding "WARNING" "$file" "$lineno" "netcat-listener" "$content"
    done
}

# 规则 6: 隐蔽执行（上下文感知）
check_covert_execution() {
    local file="$1"
    local ext="${file##*.}"

    # Python 危险调用（在非 .py 文件中更可疑）
    if [[ "$ext" != "py" ]]; then
        grep -n -E 'os\.system\s*\(|subprocess\.(call|Popen|run)\s*\(|__import__\s*\(' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
            if is_doc_context "$file" "$lineno"; then continue; fi
            add_finding "WARNING" "$file" "$lineno" "covert-exec-python" "$content"
        done
    fi

    # eval 在 markdown/shell 中
    if [[ "$ext" == "md" || "$ext" == "txt" || "$ext" == "sh" ]]; then
        grep -n -E '\beval\s*\(' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
            # shell 的 eval 命令排除
            if [[ "$ext" == "sh" ]]; then
                case "$content" in
                    *'eval "$(ssh-agent'*|*'eval "$(brew'*|*'eval "$(pyenv'*|*'eval "$(rbenv'*) continue ;;
                esac
            fi
            if is_doc_context "$file" "$lineno"; then continue; fi
            add_finding "WARNING" "$file" "$lineno" "covert-exec-eval" "$content"
        done
    fi

    # child_process 在 markdown 中
    if [[ "$ext" == "md" || "$ext" == "txt" ]]; then
        grep -n -E "require\s*\(\s*['\"]child_process['\"]" "$file" 2>/dev/null | while IFS=: read -r lineno content; do
            add_finding "WARNING" "$file" "$lineno" "covert-exec-child-process" "$content"
        done
    fi
}

# 规则 7: 文件类型伪装 (CRITICAL)
check_file_disguise() {
    local file="$1"
    local ext="${file##*.}"
    if [[ "$ext" == "md" || "$ext" == "txt" || "$ext" == "json" || "$ext" == "yaml" || "$ext" == "yml" || "$ext" == "cfg" || "$ext" == "ini" || "$ext" == "conf" || "$ext" == "csv" || "$ext" == "xml" || "$ext" == "log" ]]; then
        local filetype
        filetype=$(file -b "$file" 2>/dev/null)
        case "$filetype" in
            *"Mach-O"*|*"ELF"*|*"PE32"*|*"shared object"*|*"dynamically linked"*)
                add_finding "CRITICAL" "$file" "0" "file-type-disguise" "扩展名 .$ext 但实际为: ${filetype}"
                ;;
        esac
    fi
}

# 规则 8: 敏感信息窃取（上下文感知）
check_sensitive_data_access() {
    local file="$1"
    local ext="${file##*.}"

    # SSH/密钥文件访问 — 仅在脚本文件中标严重
    grep -n -E '(cat|cp|scp|tar|zip|curl.*-d|POST).*~/\.ssh/|\.ssh/id_(rsa|ed25519|ecdsa)' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        case "$content" in
            *"#"*|*"注意"*|*"warning"*|*"caution"*|*"never"*|*"不要"*|*"do not"*|*"example"*|*"示例"*) continue ;;
        esac
        if [[ "$ext" == "sh" || "$ext" == "py" || "$ext" == "rb" || "$ext" == "js" ]]; then
            add_finding "CRITICAL" "$file" "$lineno" "ssh-key-exfiltration" "$content"
        else
            if is_doc_context "$file" "$lineno"; then continue; fi
            add_finding "WARNING" "$file" "$lineno" "ssh-key-reference" "$content"
        fi
    done

    # AWS/云凭证窃取
    grep -n -E '(cat|cp|curl.*-d|POST).*~/\.(aws|config/gcloud|azure)/' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        if is_doc_context "$file" "$lineno"; then continue; fi
        add_finding "CRITICAL" "$file" "$lineno" "cloud-credential-access" "$content"
    done

    # 环境变量窃取模式（排除正常使用）
    grep -n -E '(curl|wget|nc|http).*\$\{?(GITHUB_TOKEN|GH_TOKEN|AWS_SECRET_ACCESS_KEY|OPENAI_API_KEY|NPM_TOKEN|PRIVATE_KEY|DATABASE_URL)' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        add_finding "CRITICAL" "$file" "$lineno" "env-exfiltration" "通过网络发送环境变量: $content"
    done

    # 批量 env 导出
    grep -n -E '\benv\b\s*\|\s*(curl|wget|nc|base64)|printenv\s*\|\s*(curl|wget|nc)' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        add_finding "CRITICAL" "$file" "$lineno" "env-dump-exfiltration" "$content"
    done
}

# 规则 9: 反沙盒/反调试 (CRITICAL)
check_anti_sandbox() {
    local file="$1"
    grep -n -E 'ptrace\s*\(|PTRACE_TRACEME|DYLD_INSERT_LIBRARIES|DYLD_FORCE_FLAT|LD_PRELOAD\s*=' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        if is_doc_context "$file" "$lineno"; then continue; fi
        add_finding "CRITICAL" "$file" "$lineno" "anti-sandbox" "$content"
    done
}

# 规则 10: 隐蔽下载器 (CRITICAL)
check_covert_downloader() {
    local file="$1"
    # python 单行下载器
    grep -n -E 'python[23]?\s+-c\s+.*\b(urllib|requests\.(get|post)|urlopen|urlretrieve)\b' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        if is_doc_context "$file" "$lineno"; then
            add_finding "WARNING" "$file" "$lineno" "covert-downloader-python-doc" "$content"
        else
            add_finding "CRITICAL" "$file" "$lineno" "covert-downloader-python" "$content"
        fi
    done
    # node 单行下载器
    grep -n -E "node\s+-e\s+.*require\s*\(\s*['\"]https?['\"]" "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        add_finding "CRITICAL" "$file" "$lineno" "covert-downloader-node" "$content"
    done
    # ruby/perl 单行下载器
    grep -n -E '(ruby|perl)\s+-e\s+.*(Net::HTTP|open-uri|LWP|HTTP::Tiny)' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        add_finding "CRITICAL" "$file" "$lineno" "covert-downloader" "$content"
    done
    # PowerShell 下载
    grep -n -iE 'powershell.*downloadstring|iex\s*\(.*webclient|invoke-webrequest.*\|\s*iex' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        add_finding "CRITICAL" "$file" "$lineno" "covert-downloader-powershell" "$content"
    done
}

# 规则 11: 定时任务注入 (WARNING)
check_cron_injection() {
    local file="$1"
    grep -n -E 'crontab\s+(-l|-e|-r|/)|launchctl\s+(load|submit|start|bootstrap)|systemctl\s+(enable|start)\s' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        if is_doc_context "$file" "$lineno"; then continue; fi
        add_finding "WARNING" "$file" "$lineno" "cron-injection" "$content"
    done
    # LaunchAgent/Daemon 创建
    grep -n -E 'LaunchAgents|LaunchDaemons|\.plist' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        if echo "$content" | grep -qE '(cp|mv|tee|cat\s*>|>>)\s.*(LaunchAgents|LaunchDaemons)'; then
            add_finding "CRITICAL" "$file" "$lineno" "persistence-launchagent" "$content"
        fi
    done
}

# 规则 12: 隐藏可执行文件 (WARNING)
check_hidden_executables() {
    local dir="$1"
    local perm_flag="+0111"
    if find --version 2>/dev/null | grep -q "GNU"; then
        perm_flag="/111"
    fi
    find "$dir" -name ".*" -type f -perm $perm_flag 2>/dev/null | while read -r file; do
        local bname
        bname=$(basename "$file")
        case "$bname" in
            .gitignore|.gitkeep|.gitattributes|.editorconfig|.eslintrc*|.prettierrc*|.DS_Store|.env*|.npmrc|.yarnrc*) continue ;;
        esac
        add_finding "WARNING" "$file" "0" "hidden-executable" "隐藏的可执行文件: $bname"
    done
}

# 规则 13 [新]: Hex/Unicode 混淆检测
check_encoding_obfuscation() {
    local file="$1"
    # 大量连续 hex 转义 (\x41\x42...)
    grep -n -E '(\\x[0-9a-fA-F]{2}){6,}' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        add_finding "WARNING" "$file" "$lineno" "hex-obfuscation" "检测到 hex 转义序列"
    done
    # 大量连续 Unicode 转义 (\u0041\u0042...)
    grep -n -E '(\\u[0-9a-fA-F]{4}){4,}' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        add_finding "WARNING" "$file" "$lineno" "unicode-obfuscation" "检测到 Unicode 转义序列"
    done
    # 字符串拼接绕过：变量拼接构造命令（如 c="cu"; c+="rl"）
    grep -n -E '[a-z]+=.*["\x27](cu|ba|we|py|ru|no|pe)["\x27];\s*[a-z]+\+=' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        add_finding "CRITICAL" "$file" "$lineno" "string-concat-bypass" "可疑字符串拼接（可能在构造命令）: $content"
    done
}

# 规则 14 [新]: 符号链接检测
check_symlinks() {
    local dir="$1"
    find "$dir" -type l 2>/dev/null | while read -r link; do
        local target
        # macOS readlink 不支持 -f，用 python 兜底
        target=$(readlink "$link" 2>/dev/null || echo "unknown")

        # 指向系统敏感目录
        case "$target" in
            /etc/passwd|/etc/shadow|*/.ssh/*|*/.gnupg/*|*/.aws/*|/private/etc/*)
                add_finding "CRITICAL" "$link" "0" "symlink-sensitive" "符号链接指向敏感位置: $target"
                ;;
            /tmp/*|/var/tmp/*)
                add_finding "WARNING" "$link" "0" "symlink-tmp" "符号链接指向临时目录: $target"
                ;;
            ../*|../../*)
                # 多层目录穿越
                local depth
                depth=$(echo "$target" | grep -o '\.\.\/' | wc -l)
                if [[ $depth -ge 3 ]]; then
                    add_finding "WARNING" "$link" "0" "symlink-traversal" "符号链接有 ${depth} 层目录穿越: $target"
                fi
                ;;
        esac
    done
}

# 规则 15 [新]: .env 泄露检测
check_env_files() {
    local dir="$1"
    find "$dir" -type f -name ".env*" ! -name ".env.example" ! -name ".env.sample" ! -name ".env.template" 2>/dev/null | while read -r envfile; do
        # 检查是否含实际密钥（非占位符）
        if grep -qE '^[A-Z_]+=.{8,}' "$envfile" 2>/dev/null; then
            if ! grep -qE '(your_|xxx|placeholder|changeme|TODO|REPLACE)' "$envfile" 2>/dev/null; then
                add_finding "CRITICAL" "$envfile" "0" "env-file-leak" ".env 文件可能包含真实密钥"
            fi
        fi
    done
}

# 规则 16 [新]: npm/pip 可疑包名检测
check_suspicious_packages() {
    local file="$1"
    # npm install 含可疑包名（typosquatting 常见模式）
    grep -n -E 'npm\s+i(nstall)?\s+.*--save' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        # 检测看起来像 typosquatting 的包名（含横杠变体或单字母差异的知名包）
        if echo "$content" | grep -qiE '(loadsh|loddash|axois|axio|requets|reqeusts|expresss|reacct|colros|chacl)'; then
            add_finding "CRITICAL" "$file" "$lineno" "typosquat-npm" "可疑 npm 包名（可能是 typosquatting）: $content"
        fi
    done
    # pip install 含可疑包
    grep -n -E 'pip3?\s+install\s' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        if echo "$content" | grep -qiE '(python-sqlite|python3-dateutil|python-mongo|py-requests)'; then
            add_finding "CRITICAL" "$file" "$lineno" "typosquat-pip" "可疑 pip 包名（可能是 typosquatting）: $content"
        fi
    done
    # 从可疑 registry 安装
    grep -n -E 'npm\s.*--registry\s+https?://(?!registry\.npmjs\.org)' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        add_finding "WARNING" "$file" "$lineno" "custom-registry" "使用非官方 npm registry: $content"
    done
    # pip 从可疑源安装
    grep -n -E 'pip3?\s+install\s+.*-i\s+https?://(?!pypi\.org|files\.pythonhosted\.org)' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        add_finding "WARNING" "$file" "$lineno" "custom-pip-source" "使用非官方 pip 源: $content"
    done
}

# 规则 17 [新]: 文件完整性（检测可疑的 post-install 脚本）
check_postinstall_scripts() {
    local file="$1"
    local bname
    bname=$(basename "$file")
    # package.json 中的 scripts 含可疑操作
    if [[ "$bname" == "package.json" ]]; then
        # preinstall/postinstall 含 curl/wget/node -e
        grep -n -E '"(pre|post)install"\s*:\s*".*\b(curl|wget|node\s+-e|python|bash|sh\s+-c)\b' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
            add_finding "CRITICAL" "$file" "$lineno" "malicious-postinstall" "package.json 生命周期脚本含可疑命令: $content"
        done
    fi
    # setup.py/setup.cfg 中的可疑操作
    if [[ "$bname" == "setup.py" ]]; then
        grep -n -E '(os\.system|subprocess|urllib|urlopen)\s*\(' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
            add_finding "CRITICAL" "$file" "$lineno" "malicious-setup-py" "setup.py 含可疑运行时代码: $content"
        done
    fi
}

# ============================================================
# 主扫描逻辑
# ============================================================

print_banner() {
    if [[ "$JSON_OUTPUT" != true ]]; then
        echo ""
        echo -e "${BOLD}╔═══════════════════════════════════════════════╗${NC}"
        echo -e "${BOLD}║   🦒 Giraffe Guard v${VERSION} — 长颈鹿卫士        ║${NC}"
        echo -e "${BOLD}╚═══════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${CYAN}扫描目标:${NC} $TARGET_DIR"
        [[ -n "$WHITELIST_FILE" ]] && echo -e "  ${CYAN}白名单:${NC} $WHITELIST_FILE (${#WHITELIST_ENTRIES[@]} 条规则)"
        [[ "$VERBOSE" == true ]] && echo -e "  ${CYAN}详细模式:${NC} 上下文 ${CONTEXT_LINES} 行"
        echo ""
        echo -e "${BOLD}───────────────────────────────────────────────${NC}"
    fi
}

scan_file() {
    local file="$1"
    # 排除自身
    local realfile
    realfile="$(cd "$(dirname "$file")" && pwd)/$(basename "$file")"
    [[ "$realfile" == "$SELF_PATH" ]] && return 0

    echo $(( $(cat "$TMPDIR_AUDIT/files") + 1 )) > "$TMPDIR_AUDIT/files"

    check_pipe_execution "$file"
    check_base64_obfuscation "$file"
    check_security_bypass "$file"
    check_dangerous_permissions "$file"
    check_suspicious_network "$file"
    check_covert_execution "$file"
    check_file_disguise "$file"
    check_sensitive_data_access "$file"
    check_anti_sandbox "$file"
    check_covert_downloader "$file"
    check_cron_injection "$file"
    check_encoding_obfuscation "$file"
    check_suspicious_packages "$file"
    check_postinstall_scripts "$file"
}

main() {
    load_whitelist
    print_banner

    # 收集所有要扫描的文件
    local file_list
    file_list=$(find "$TARGET_DIR" \
        -type f \
        ! -path "*/.git/*" \
        ! -path "*/__pycache__/*" \
        ! -name "*.png" ! -name "*.jpg" ! -name "*.jpeg" ! -name "*.gif" \
        ! -name "*.ico" ! -name "*.woff" ! -name "*.woff2" ! -name "*.ttf" \
        ! -name "*.zip" ! -name "*.tar" ! -name "*.gz" ! -name "*.bz2" \
        ! -name "*.pyc" ! -name "*.o" ! -name "*.so" ! -name "*.dylib" \
        ! -name "*.mp3" ! -name "*.mp4" ! -name "*.wav" ! -name "*.ogg" \
        2>/dev/null)

    if [[ -z "$file_list" ]]; then
        if [[ "$JSON_OUTPUT" == true ]]; then
            echo '{"version":"'"${VERSION}"'","filesScanned":0,"totalFindings":0,"critical":0,"warning":0,"info":0,"findings":[]}'
        else
            echo "  没有找到可扫描的文件"
        fi
        exit 0
    fi

    # 扫描文本文件
    while IFS= read -r file; do
        local ext="${file##*.}"
        case "$ext" in
            md|txt|json|yaml|yml|sh|bash|zsh|py|rb|js|ts|pl|cfg|ini|conf|toml|xml|html|css|csv|env|makefile|dockerfile|rst|go|rs|c|h|cpp|hpp|java|swift|kt|r|lua|sql|Makefile|Dockerfile)
                scan_file "$file"
                ;;
            *)
                # 无扩展名或不常见扩展名 — 用 file 命令判断
                local ftype
                ftype=$(file -b --mime-type "$file" 2>/dev/null)
                case "$ftype" in
                    text/*|application/json|application/xml|application/javascript|application/x-shellscript|inode/x-empty)
                        scan_file "$file"
                        ;;
                esac
                ;;
        esac
    done <<< "$file_list"

    # 目录级别检测
    check_hidden_executables "$TARGET_DIR"
    check_symlinks "$TARGET_DIR"
    check_env_files "$TARGET_DIR"

    # --- 读取最终计数 ---
    local fc cc wc ic wlc fsc
    fc=$(cat "$TMPDIR_AUDIT/findings")
    cc=$(cat "$TMPDIR_AUDIT/critical")
    wc=$(cat "$TMPDIR_AUDIT/warning")
    ic=$(cat "$TMPDIR_AUDIT/info")
    wlc=$(cat "$TMPDIR_AUDIT/whitelisted")
    fsc=$(cat "$TMPDIR_AUDIT/files")

    # --- 输出结果 ---
    if [[ "$JSON_OUTPUT" == true ]]; then
        echo "{"
        echo "  \"version\": \"${VERSION}\","
        echo "  \"target\": \"$(json_escape "$TARGET_DIR")\","
        echo "  \"filesScanned\": ${fsc},"
        echo "  \"totalFindings\": ${fc},"
        echo "  \"critical\": ${cc},"
        echo "  \"warning\": ${wc},"
        echo "  \"info\": ${ic},"
        echo "  \"whitelisted\": ${wlc},"
        echo "  \"findings\": ["
        if [[ -s "$FINDINGS_FILE" ]]; then
            local first=true
            while IFS= read -r line; do
                if [[ "$first" == true ]]; then
                    echo "    $line"
                    first=false
                else
                    echo "    ,$line"
                fi
            done < "$FINDINGS_FILE"
        fi
        echo "  ]"
        echo "}"
    else
        echo ""
        echo -e "${BOLD}═══════════════════════════════════════════════${NC}"
        echo -e "${BOLD}  📊 扫描报告${NC}"
        echo -e "${BOLD}═══════════════════════════════════════════════${NC}"
        echo -e "  扫描文件数:  ${BOLD}${fsc}${NC}"
        echo -e "  发现总数:    ${BOLD}${fc}${NC}"
        if [[ $cc -gt 0 ]]; then
            echo -e "  🔴 严重:     ${RED}${BOLD}${cc}${NC}"
        else
            echo -e "  🔴 严重:     ${GREEN}0${NC}"
        fi
        if [[ $wc -gt 0 ]]; then
            echo -e "  🟡 警告:     ${YELLOW}${BOLD}${wc}${NC}"
        else
            echo -e "  🟡 警告:     ${GREEN}0${NC}"
        fi
        if [[ $ic -gt 0 ]]; then
            echo -e "  🔵 信息:     ${CYAN}${ic}${NC}"
        fi
        if [[ $wlc -gt 0 ]]; then
            echo -e "  ⬜ 已白名单: ${DIM}${wlc}${NC}"
        fi
        echo ""

        if [[ $fc -eq 0 ]]; then
            echo -e "  ${GREEN}${BOLD}✅ 未发现安全风险，全部安全！${NC}"
        elif [[ $cc -gt 0 ]]; then
            echo -e "  ${RED}${BOLD}⚠️  发现严重安全风险，请立即检查！${NC}"
        elif [[ $wc -gt 0 ]]; then
            echo -e "  ${YELLOW}${BOLD}⚠️  发现潜在风险，建议人工核实。${NC}"
        else
            echo -e "  ${CYAN}ℹ️  仅有信息性发现。${NC}"
        fi
        echo ""
    fi

    # 退出码
    if [[ $cc -gt 0 ]]; then
        exit 2
    elif [[ $wc -gt 0 ]]; then
        exit 1
    else
        exit 0
    fi
}

main
