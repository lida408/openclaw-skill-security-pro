#!/bin/bash
set -uo pipefail

# ============================================================
# OpenClaw Skill Security Auditor v3.0.0
# Scan skill directories for supply chain attacks and malicious code
# Compatible with macOS (BSD) and Linux (GNU)
# Zero dependencies: only uses bash, grep, sed, find, file, awk, readlink
# ============================================================

VERSION="3.0.0"

# --- Color definitions ---
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# --- Parameters ---
VERBOSE=false
JSON_OUTPUT=false
WHITELIST_FILE=""
TARGET_DIR=""
CONTEXT_LINES=2  # context lines for --verbose
declare -a SKIP_DIRS=()

SELF_PATH="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"

# Temp files for counter passing across subshells
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
Scan skill directories for supply chain attacks and malicious code.

Options:
  --verbose       Show detailed findings with context lines
  --json          Output JSON report
  --whitelist F   Specify whitelist file
  --context N     Context lines (default: 2, used with --verbose)
  --skip-dir D    Skip directory name (repeatable, e.g. --skip-dir node_modules)
  --version       Show version
  -h, --help      Show help

Examples:
  $(basename "$0") /path/to/skills
  $(basename "$0") --verbose --json /path/to/skills
  $(basename "$0") --whitelist whitelist.txt /path/to/skills
  $(basename "$0") --skip-dir node_modules --skip-dir vendor /path/to/skills

Exit codes:
  0  Clean (no findings)
  1  Warnings found
  2  Critical findings found
EOF
    exit 0
}

# --- Argument parsing ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --verbose) VERBOSE=true; shift ;;
        --json) JSON_OUTPUT=true; shift ;;
        --whitelist) WHITELIST_FILE="$2"; shift 2 ;;
        --context) CONTEXT_LINES="$2"; shift 2 ;;
        --skip-dir) SKIP_DIRS+=("$2"); shift 2 ;;
        --version) echo "security-audit v${VERSION}"; exit 0 ;;
        -h|--help) usage ;;
        -*) echo "Unknown option: $1"; exit 1 ;;
        *) TARGET_DIR="$1"; shift ;;
    esac
done

if [[ -z "$TARGET_DIR" ]]; then
    echo "Error: Please specify a target directory to scan"
    usage
fi

if [[ ! -d "$TARGET_DIR" ]]; then
    echo "Error: Directory does not exist: $TARGET_DIR"
    exit 1
fi

# --- Whitelist loading ---
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

# --- JSON helpers ---
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
}

# --- Context fetching (for --verbose) ---
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

# --- Doc context detection (reduce false positives) ---
# Returns 0 = doc context (likely false positive), 1 = not doc context
is_doc_context() {
    local file="$1"
    local lineno="$2"
    local ext="${file##*.}"

    # Markdown / text files: tables, comments, list items are likely documentation
    if [[ "$ext" == "md" || "$ext" == "txt" || "$ext" == "rst" ]]; then
        local line
        line=$(sed -n "${lineno}p" "$file" 2>/dev/null)
        # Table row
        if echo "$line" | grep -qE '^\s*\|'; then
            return 0
        fi
        # Comment line (# or // or <!--)
        if echo "$line" | grep -qE '^\s*(#|//|<!--)'; then
            return 0
        fi
        # Descriptive list item
        if echo "$line" | grep -qE '^\s*[-*]\s+.*\b(example|示例|说明|description|e\.g\.|如|用于|for|about)\b'; then
            return 0
        fi
    fi
    return 1
}

# --- Finding recorder ---
add_finding() {
    local level="$1"      # CRITICAL / WARNING / INFO
    local filepath="$2"
    local lineno="$3"
    local rule="$4"
    local content="$5"

    # Whitelist check
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
        local color tag
        case "$level" in
            CRITICAL) color="$RED"; tag="[!!]" ;;
            WARNING)  color="$YELLOW"; tag="[!]" ;;
            INFO)     color="$CYAN"; tag="[i]" ;;
        esac
        if [[ "$wl_status" == "WHITELISTED" ]]; then
            echo -e "  ${DIM}[WHITELISTED] ${tag} ${level} | ${filepath}:${lineno} | ${rule}${NC}"
        else
            echo -e "  ${color}${tag} ${level}${NC} | ${BOLD}${filepath}:${lineno}${NC} | ${CYAN}${rule}${NC}"
            echo -e "     ${DIM}${content}${NC}"
            if [[ "$VERBOSE" == true && "$lineno" != "0" ]]; then
                echo -e "${DIM}$(get_context "$filepath" "$lineno")${NC}"
                echo ""
            fi
        fi
    fi
}

# ============================================================
# Detection Rules
# ============================================================

# Rule 1: Pipe execution (CRITICAL)
check_pipe_execution() {
    local file="$1"
    grep -n -E '(curl|wget)\s+.*\|\s*(bash|sh|zsh|dash|ksh|python[23]?|perl|ruby|node)(\s|$)' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        if is_doc_context "$file" "$lineno"; then
            add_finding "WARNING" "$file" "$lineno" "pipe-execution-doc" "$content"
        else
            add_finding "CRITICAL" "$file" "$lineno" "pipe-execution" "$content"
        fi
    done
}

# Rule 2: Base64 obfuscation (CRITICAL / WARNING)
check_base64_obfuscation() {
    local file="$1"
    # base64 -d piped to execution
    grep -n -E 'base64\s+(-d|--decode)\s*\|' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        add_finding "CRITICAL" "$file" "$lineno" "base64-decode-pipe" "$content"
    done
    # echo ... | base64 -d variant
    grep -n -E 'echo\s+.*\|\s*base64\s+(-d|--decode)' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        add_finding "CRITICAL" "$file" "$lineno" "base64-echo-decode" "$content"
    done
    # Suspiciously long base64 strings (>100 chars)
    grep -n -E '[A-Za-z0-9+/]{100,}={0,2}' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        # Exclude legitimate long strings (JWT examples, SSH keys, etc.)
        case "$content" in
            *"ssh-"*|*"BEGIN "*|*"example"*|*"示例"*|*"token"*) continue ;;
        esac
        add_finding "WARNING" "$file" "$lineno" "long-base64-string" "Suspiciously long Base64 encoded string detected"
    done
}

# Rule 3: Security bypass (CRITICAL)
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

# Rule 4: Dangerous permissions (WARNING)
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

# Rule 5: Suspicious network behavior
check_suspicious_network() {
    local file="$1"
    # Direct IP connection (exclude local/private addresses)
    grep -n -E 'https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        if echo "$content" | grep -qE '127\.0\.0\.1|0\.0\.0\.0|192\.168\.|10\.[0-9]+\.|172\.(1[6-9]|2[0-9]|3[01])\.'; then
            continue
        fi
        add_finding "WARNING" "$file" "$lineno" "suspicious-network-ip" "$content"
    done
    # .onion domain
    grep -n -E '[a-z2-7]{16,56}\.onion\b' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        add_finding "CRITICAL" "$file" "$lineno" "tor-onion-address" "$content"
    done
    # Reverse shell patterns
    grep -n -E 'nc\s+(-e|--exec)|ncat\s+(-e|--exec)|bash\s+-i\s+>\&\s*/dev/tcp|/dev/udp/' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        add_finding "CRITICAL" "$file" "$lineno" "reverse-shell" "$content"
    done
    # Netcat listener
    grep -n -E '\bnc\s+-[lp]|\bncat\s+-[lp]|\bnetcat\s+-[lp]' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        if is_doc_context "$file" "$lineno"; then continue; fi
        add_finding "WARNING" "$file" "$lineno" "netcat-listener" "$content"
    done
}

# Rule 6: Covert execution (context-aware)
check_covert_execution() {
    local file="$1"
    local ext="${file##*.}"

    # Python dangerous calls: WARNING in .py, CRITICAL in other script files
    if [[ "$ext" == "py" ]]; then
        grep -n -E 'os\.system\s*\(|subprocess\.(call|Popen|run)\s*\(|__import__\s*\(' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
            if is_doc_context "$file" "$lineno"; then continue; fi
            add_finding "WARNING" "$file" "$lineno" "covert-exec-python" "$content"
        done
    elif [[ "$ext" != "md" && "$ext" != "txt" && "$ext" != "rst" ]]; then
        grep -n -E 'os\.system\s*\(|subprocess\.(call|Popen|run)\s*\(|__import__\s*\(' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
            if is_doc_context "$file" "$lineno"; then continue; fi
            add_finding "WARNING" "$file" "$lineno" "covert-exec-python" "$content"
        done
    fi

    # eval() in markdown/shell/js/ts files
    if [[ "$ext" == "md" || "$ext" == "txt" || "$ext" == "sh" || "$ext" == "js" || "$ext" == "ts" ]]; then
        grep -n -E '\beval\s*\(' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
            # Exclude common safe shell eval patterns
            if [[ "$ext" == "sh" ]]; then
                case "$content" in
                    *'eval "$(ssh-agent'*|*'eval "$(brew'*|*'eval "$(pyenv'*|*'eval "$(rbenv'*|*'eval "$(nodenv'*|*'eval "$(direnv'*) continue ;;
                esac
            fi
            if is_doc_context "$file" "$lineno"; then continue; fi
            add_finding "WARNING" "$file" "$lineno" "covert-exec-eval" "$content"
        done
    fi

    # child_process in markdown
    if [[ "$ext" == "md" || "$ext" == "txt" ]]; then
        grep -n -E "require\s*\(\s*['\"]child_process['\"]" "$file" 2>/dev/null | while IFS=: read -r lineno content; do
            add_finding "WARNING" "$file" "$lineno" "covert-exec-child-process" "$content"
        done
    fi
}

# Rule 7: File type disguise (CRITICAL)
check_file_disguise() {
    local file="$1"
    local ext="${file##*.}"
    if [[ "$ext" == "md" || "$ext" == "txt" || "$ext" == "json" || "$ext" == "yaml" || "$ext" == "yml" || "$ext" == "cfg" || "$ext" == "ini" || "$ext" == "conf" || "$ext" == "csv" || "$ext" == "xml" || "$ext" == "log" ]]; then
        local filetype
        filetype=$(file -b "$file" 2>/dev/null)
        case "$filetype" in
            *"Mach-O"*|*"ELF"*|*"PE32"*|*"shared object"*|*"dynamically linked"*)
                add_finding "CRITICAL" "$file" "0" "file-type-disguise" "Extension .$ext but actual type: ${filetype}"
                ;;
        esac
    fi
}

# Rule 8: Sensitive data exfiltration (context-aware)
check_sensitive_data_access() {
    local file="$1"
    local ext="${file##*.}"

    # SSH key access - CRITICAL in script files
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

    # AWS/Cloud credential theft
    grep -n -E '(cat|cp|curl.*-d|POST).*~/\.(aws|config/gcloud|azure)/' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        if is_doc_context "$file" "$lineno"; then continue; fi
        add_finding "CRITICAL" "$file" "$lineno" "cloud-credential-access" "$content"
    done

    # Environment variable exfiltration
    grep -n -E '(curl|wget|nc|http).*\$\{?(GITHUB_TOKEN|GH_TOKEN|AWS_SECRET_ACCESS_KEY|OPENAI_API_KEY|NPM_TOKEN|PRIVATE_KEY|DATABASE_URL)' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        add_finding "CRITICAL" "$file" "$lineno" "env-exfiltration" "Sending env vars over network: $content"
    done

    # Bulk env dump
    grep -n -E '\benv\b\s*\|\s*(curl|wget|nc|base64)|printenv\s*\|\s*(curl|wget|nc)' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        add_finding "CRITICAL" "$file" "$lineno" "env-dump-exfiltration" "$content"
    done
}

# Rule 9: Anti-sandbox / Anti-debug (CRITICAL)
check_anti_sandbox() {
    local file="$1"
    grep -n -E 'ptrace\s*\(|PTRACE_TRACEME|DYLD_INSERT_LIBRARIES|DYLD_FORCE_FLAT|LD_PRELOAD\s*=' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        if is_doc_context "$file" "$lineno"; then continue; fi
        add_finding "CRITICAL" "$file" "$lineno" "anti-sandbox" "$content"
    done
}

# Rule 10: Covert downloader (CRITICAL)
check_covert_downloader() {
    local file="$1"
    # Python one-liner downloader
    grep -n -E 'python[23]?\s+-c\s+.*\b(urllib|requests\.(get|post)|urlopen|urlretrieve)\b' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        if is_doc_context "$file" "$lineno"; then
            add_finding "WARNING" "$file" "$lineno" "covert-downloader-python-doc" "$content"
        else
            add_finding "CRITICAL" "$file" "$lineno" "covert-downloader-python" "$content"
        fi
    done
    # Node one-liner downloader
    grep -n -E "node\s+-e\s+.*require\s*\(\s*['\"]https?['\"]" "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        add_finding "CRITICAL" "$file" "$lineno" "covert-downloader-node" "$content"
    done
    # Ruby/Perl one-liner downloader
    grep -n -E '(ruby|perl)\s+-e\s+.*(Net::HTTP|open-uri|LWP|HTTP::Tiny)' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        add_finding "CRITICAL" "$file" "$lineno" "covert-downloader" "$content"
    done
    # PowerShell downloader
    grep -n -iE 'powershell.*downloadstring|iex\s*\(.*webclient|invoke-webrequest.*\|\s*iex' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        add_finding "CRITICAL" "$file" "$lineno" "covert-downloader-powershell" "$content"
    done
}

# Rule 11: Scheduled task injection (WARNING)
check_cron_injection() {
    local file="$1"
    grep -n -E 'crontab\s+(-l|-e|-r|/)|launchctl\s+(load|submit|start|bootstrap)|systemctl\s+(enable|start)\s' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        if is_doc_context "$file" "$lineno"; then continue; fi
        add_finding "WARNING" "$file" "$lineno" "cron-injection" "$content"
    done
    # LaunchAgent/Daemon creation
    grep -n -E 'LaunchAgents|LaunchDaemons|\.plist' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        if echo "$content" | grep -qE '(cp|mv|tee|cat\s*>|>>)\s.*(LaunchAgents|LaunchDaemons)'; then
            add_finding "CRITICAL" "$file" "$lineno" "persistence-launchagent" "$content"
        fi
    done
}

# Rule 12: Hidden executables (WARNING)
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
        add_finding "WARNING" "$file" "0" "hidden-executable" "Hidden executable file: $bname"
    done
}

# Rule 13: Hex/Unicode obfuscation detection
check_encoding_obfuscation() {
    local file="$1"
    # Consecutive hex escapes (\x41\x42...)
    grep -n -E '(\\x[0-9a-fA-F]{2}){6,}' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        add_finding "WARNING" "$file" "$lineno" "hex-obfuscation" "Hex escape sequence detected"
    done
    # Consecutive Unicode escapes (\u0041\u0042...)
    grep -n -E '(\\u[0-9a-fA-F]{4}){4,}' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        add_finding "WARNING" "$file" "$lineno" "unicode-obfuscation" "Unicode escape sequence detected"
    done
    # String concatenation bypass: variable concat to build commands
    grep -n -E '[a-z]+=.*["\\x27](cu|ba|we|py|ru|no|pe)["\\x27];\s*[a-z]+\+=' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        add_finding "CRITICAL" "$file" "$lineno" "string-concat-bypass" "Suspicious string concatenation (may be constructing a command): $content"
    done
}

# Rule 14: Symlink detection
check_symlinks() {
    local dir="$1"
    find "$dir" -type l 2>/dev/null | while read -r link; do
        local target
        target=$(readlink "$link" 2>/dev/null || echo "unknown")

        # Pointing to sensitive system locations
        case "$target" in
            /etc/passwd|/etc/shadow|*/.ssh/*|*/.gnupg/*|*/.aws/*|/private/etc/*)
                add_finding "CRITICAL" "$link" "0" "symlink-sensitive" "Symlink points to sensitive location: $target"
                ;;
            /tmp/*|/var/tmp/*)
                add_finding "WARNING" "$link" "0" "symlink-tmp" "Symlink points to temp directory: $target"
                ;;
            ../*|../../*)
                # Deep directory traversal
                local depth
                depth=$(echo "$target" | grep -o '\.\.\/' | wc -l)
                if [[ $depth -ge 3 ]]; then
                    add_finding "WARNING" "$link" "0" "symlink-traversal" "Symlink has ${depth} levels of directory traversal: $target"
                fi
                ;;
        esac
    done
}

# Rule 15: .env file leak detection (per-line analysis)
check_env_files() {
    local dir="$1"
    find "$dir" -type f -name ".env*" ! -name ".env.example" ! -name ".env.sample" ! -name ".env.template" 2>/dev/null | while read -r envfile; do
        local has_real_secret=false
        while IFS= read -r line; do
            # Skip comments and empty lines
            [[ -z "$line" || "$line" == \#* ]] && continue
            # Check if this line looks like a real secret (KEY=value with 8+ chars, not a placeholder)
            if echo "$line" | grep -qE '^[A-Z_]+=.{8,}'; then
                if ! echo "$line" | grep -qiE '(your_|xxx|placeholder|changeme|TODO|REPLACE|example|sample|<|>)'; then
                    has_real_secret=true
                    break
                fi
            fi
        done < "$envfile"
        if [[ "$has_real_secret" == true ]]; then
            add_finding "CRITICAL" "$envfile" "0" "env-file-leak" ".env file may contain real secrets"
        fi
    done
}

# Rule 16: npm/pip suspicious package name detection
check_suspicious_packages() {
    local file="$1"
    # npm install with suspicious package names (typosquatting)
    grep -n -E 'npm\s+i(nstall)?\s+' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        if echo "$content" | grep -qiE '(loadsh|loddash|axois|axio|requets|reqeusts|expresss|reacct|colros|chacl|coffe-script|crossenv|event-stream|flatmap-stream|eslint-scope|ua-parser-jss|coa-utils)'; then
            add_finding "CRITICAL" "$file" "$lineno" "typosquat-npm" "Suspicious npm package name (possible typosquatting): $content"
        fi
    done
    # pip install with suspicious packages
    grep -n -E 'pip3?\s+install\s' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        if echo "$content" | grep -qiE '(python-sqlite|python3-dateutil|python-mongo|py-requests|python-openssl|python-jwt|python-crypto|python-dateutil-2|djang0|djanGo|requestes)'; then
            add_finding "CRITICAL" "$file" "$lineno" "typosquat-pip" "Suspicious pip package name (possible typosquatting): $content"
        fi
    done
    # Non-official npm registry
    grep -n -E 'npm\s.*--registry\s+https?://(?!registry\.npmjs\.org)' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        add_finding "WARNING" "$file" "$lineno" "custom-registry" "Non-official npm registry: $content"
    done
    # Non-official pip source
    grep -n -E 'pip3?\s+install\s+.*-i\s+https?://(?!pypi\.org|files\.pythonhosted\.org)' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        add_finding "WARNING" "$file" "$lineno" "custom-pip-source" "Non-official pip source: $content"
    done
}

# Rule 17: Malicious post-install scripts
check_postinstall_scripts() {
    local file="$1"
    local bname
    bname=$(basename "$file")
    # package.json lifecycle scripts with suspicious commands
    if [[ "$bname" == "package.json" ]]; then
        grep -n -E '"(pre|post)install"\s*:\s*".*\b(curl|wget|node\s+-e|python|bash|sh\s+-c)\b' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
            add_finding "CRITICAL" "$file" "$lineno" "malicious-postinstall" "Suspicious lifecycle script in package.json: $content"
        done
    fi
    # setup.py with suspicious runtime code
    if [[ "$bname" == "setup.py" ]]; then
        grep -n -E '(os\.system|subprocess|urllib|urlopen)\s*\(' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
            add_finding "CRITICAL" "$file" "$lineno" "malicious-setup-py" "Suspicious runtime code in setup.py: $content"
        done
    fi
}

# Rule 18: Git hooks detection (CRITICAL)
check_git_hooks() {
    local dir="$1"
    find "$dir" -path "*/.git/hooks/*" -type f ! -name "*.sample" 2>/dev/null | while read -r hook; do
        if [[ -x "$hook" ]] || file -b "$hook" 2>/dev/null | grep -qiE '(script|text|executable)'; then
            local bname
            bname=$(basename "$hook")
            add_finding "CRITICAL" "$hook" "0" "git-hooks" "Active git hook detected: $bname (auto-executes on git operations)"
        fi
    done
}

# Rule 19: Sensitive file leak detection (CRITICAL)
check_sensitive_file_leak() {
    local dir="$1"
    # Private keys
    find "$dir" -type f \( -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" -o -name "id_dsa" \) ! -path "*/.git/*" 2>/dev/null | while read -r f; do
        add_finding "CRITICAL" "$f" "0" "sensitive-file-leak" "Private key file found: $(basename "$f")"
    done
    # TLS/SSL private keys
    find "$dir" -type f \( -name "*.pem" -o -name "*.key" -o -name "*.p12" -o -name "*.pfx" -o -name "*.keystore" -o -name "*.jks" \) ! -path "*/.git/*" 2>/dev/null | while read -r f; do
        # Check if it actually contains a private key (not just a cert)
        if grep -qlE 'PRIVATE KEY|ENCRYPTED' "$f" 2>/dev/null; then
            add_finding "CRITICAL" "$f" "0" "sensitive-file-leak" "Private key file found: $(basename "$f")"
        fi
    done
    # Credential files
    find "$dir" -type f \( -name "credentials.json" -o -name "service-account*.json" -o -name ".pypirc" \) ! -path "*/.git/*" 2>/dev/null | while read -r f; do
        add_finding "CRITICAL" "$f" "0" "sensitive-file-leak" "Credential file found: $(basename "$f")"
    done
    # .npmrc with auth token
    find "$dir" -type f -name ".npmrc" ! -path "*/.git/*" 2>/dev/null | while read -r f; do
        if grep -qE '_authToken|_auth\s*=' "$f" 2>/dev/null; then
            add_finding "CRITICAL" "$f" "0" "sensitive-file-leak" ".npmrc contains auth token"
        fi
    done
}

# Rule 20: SKILL.md injection detection (CRITICAL)
check_skillmd_injection() {
    local file="$1"
    local bname
    bname=$(basename "$file")
    [[ "$bname" != "SKILL.md" ]] && return 0

    # Prompt injection patterns
    grep -n -iE '(ignore\s+(previous|above|all)\s+(instructions?|prompts?)|disregard\s+(previous|above|all)|you\s+are\s+now\s+|new\s+instructions?\s*:|system\s+prompt\s*:)' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        add_finding "CRITICAL" "$file" "$lineno" "skillmd-prompt-injection" "Potential prompt injection in SKILL.md: $content"
    done

    # Dangerous tool call patterns (requesting destructive actions)
    grep -n -iE '(rm\s+-rf\s+[/~]|sudo\s+|mkfs\s|dd\s+if=|:\(\)\s*\{\s*:\|:\s*&\s*\};|fork\s*bomb)' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        if is_doc_context "$file" "$lineno"; then continue; fi
        add_finding "CRITICAL" "$file" "$lineno" "skillmd-dangerous-command" "Dangerous command in SKILL.md: $content"
    done

    # Privilege escalation requests
    grep -n -iE '(run\s+as\s+root|requires?\s+sudo|needs?\s+root\s+access|chmod\s+[47][0-7]{2}\s+/)' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        add_finding "WARNING" "$file" "$lineno" "skillmd-privilege-escalation" "Privilege escalation in SKILL.md: $content"
    done
}

# Rule 21: Dockerfile security (WARNING / CRITICAL)
check_dockerfile_security() {
    local file="$1"
    local bname
    bname=$(basename "$file")
    # Only check Dockerfile / docker-compose files
    case "$bname" in
        Dockerfile*|docker-compose*) ;;
        *) return 0 ;;
    esac

    # Privileged mode
    grep -n -iE '\-\-privileged' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        add_finding "CRITICAL" "$file" "$lineno" "dockerfile-privileged" "Container running in privileged mode: $content"
    done

    # Sensitive volume mounts
    grep -n -E '(-v|volumes:)\s*.*\b(/etc|/root|/home|/var/run/docker.sock|/private)\b' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        add_finding "WARNING" "$file" "$lineno" "dockerfile-sensitive-mount" "Sensitive host directory mounted: $content"
    done

    # Host network mode
    grep -n -iE '(--net=host|--network=host|network_mode:\s*host)' "$file" 2>/dev/null | while IFS=: read -r lineno content; do
        add_finding "WARNING" "$file" "$lineno" "dockerfile-host-network" "Container using host network mode: $content"
    done
}

# Rule 22: Zero-width character detection (CRITICAL)
check_zero_width_chars() {
    local file="$1"
    # Detect zero-width characters: U+200B (ZWSP), U+200C (ZWNJ), U+200D (ZWJ),
    # U+FEFF (BOM in middle of file), U+2060 (Word Joiner), U+2062-2064
    # Use hex grep to catch these invisible characters
    if grep -Pn '[\x{200B}\x{200C}\x{200D}\x{2060}\x{2062}\x{2063}\x{2064}]' "$file" 2>/dev/null | head -5 | while IFS=: read -r lineno content; do
        add_finding "CRITICAL" "$file" "$lineno" "zero-width-chars" "Zero-width Unicode characters detected (may hide malicious content)"
    done; then
        :
    fi
    # Check for BOM (U+FEFF) in middle of file (not at position 1)
    # This is a simpler check using od
    if command -v od >/dev/null 2>&1; then
        local fsize
        fsize=$(wc -c < "$file" 2>/dev/null | tr -d ' ')
        if [[ "$fsize" -gt 3 && "$fsize" -lt 1000000 ]]; then
            # Look for FEFF after first 3 bytes (BOM at start is normal for UTF-8-BOM/UTF-16)
            if tail -c +4 "$file" 2>/dev/null | grep -Pq '\xEF\xBB\xBF|\xFE\xFF|\xFF\xFE' 2>/dev/null; then
                add_finding "WARNING" "$file" "0" "embedded-bom" "BOM character found in middle of file (may indicate content splicing)"
            fi
        fi
    fi
}

# ============================================================
# Main Scan Logic
# ============================================================

print_banner() {
    if [[ "$JSON_OUTPUT" != true ]]; then
        echo ""
        echo -e "${BOLD}+===============================================+${NC}"
        echo -e "${BOLD}|   OpenClaw Skill Security Auditor v${VERSION}     |${NC}"
        echo -e "${BOLD}+===============================================+${NC}"
        echo ""
        echo -e "  ${CYAN}Target:${NC} $TARGET_DIR"
        [[ -n "$WHITELIST_FILE" ]] && echo -e "  ${CYAN}Whitelist:${NC} $WHITELIST_FILE (${#WHITELIST_ENTRIES[@]} entries)"
        [[ "$VERBOSE" == true ]] && echo -e "  ${CYAN}Verbose:${NC} context ${CONTEXT_LINES} lines"
        if [[ ${#SKIP_DIRS[@]} -gt 0 ]]; then
            echo -e "  ${CYAN}Skipping:${NC} ${SKIP_DIRS[*]}"
        fi
        echo ""
        echo -e "${BOLD}-----------------------------------------------${NC}"
    fi
}

scan_file() {
    local file="$1"
    # Exclude self
    local realfile
    realfile="$(cd "$(dirname "$file")" && pwd)/$(basename "$file")"
    [[ "$realfile" == "$SELF_PATH" ]] && return 0

    echo $(( $(cat "$TMPDIR_AUDIT/files") + 1 )) > "$TMPDIR_AUDIT/files"

    # Progress indicator (every 50 files)
    if [[ "$JSON_OUTPUT" != true ]]; then
        local fsc
        fsc=$(cat "$TMPDIR_AUDIT/files")
        if [[ $((fsc % 50)) -eq 0 ]]; then
            echo -e "  ${DIM}Scanned ${fsc} files...${NC}"
        fi
    fi

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
    check_skillmd_injection "$file"
    check_dockerfile_security "$file"
    check_zero_width_chars "$file"
}

main() {
    load_whitelist
    print_banner

    # Build find exclude arguments for --skip-dir
    local skip_args=""
    for sd in "${SKIP_DIRS[@]+"${SKIP_DIRS[@]}"}"; do
        skip_args="$skip_args ! -path \"*/${sd}/*\""
    done

    # Collect all scannable files
    local file_list
    file_list=$(eval find "\"$TARGET_DIR\"" \
        -type f \
        ! -path "*/.git/*" \
        ! -path "*/__pycache__/*" \
        ! -name "*.png" ! -name "*.jpg" ! -name "*.jpeg" ! -name "*.gif" \
        ! -name "*.ico" ! -name "*.woff" ! -name "*.woff2" ! -name "*.ttf" \
        ! -name "*.zip" ! -name "*.tar" ! -name "*.gz" ! -name "*.bz2" \
        ! -name "*.pyc" ! -name "*.o" ! -name "*.so" ! -name "*.dylib" \
        ! -name "*.mp3" ! -name "*.mp4" ! -name "*.wav" ! -name "*.ogg" \
        $skip_args \
        2>/dev/null)

    if [[ -z "$file_list" ]]; then
        if [[ "$JSON_OUTPUT" == true ]]; then
            echo '{"version":"'"${VERSION}"'","timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'","filesScanned":0,"totalFindings":0,"critical":0,"warning":0,"info":0,"findings":[]}'
        else
            echo "  No scannable files found"
        fi
        exit 0
    fi

    # Scan text files
    while IFS= read -r file; do
        local ext="${file##*.}"
        case "$ext" in
            md|txt|json|yaml|yml|sh|bash|zsh|py|rb|js|ts|pl|cfg|ini|conf|toml|xml|html|css|csv|env|makefile|dockerfile|rst|go|rs|c|h|cpp|hpp|java|swift|kt|r|lua|sql|Makefile|Dockerfile)
                scan_file "$file"
                ;;
            *)
                # No extension or uncommon extension - use file command
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

    # Directory-level detection
    check_hidden_executables "$TARGET_DIR"
    check_symlinks "$TARGET_DIR"
    check_env_files "$TARGET_DIR"
    check_git_hooks "$TARGET_DIR"
    check_sensitive_file_leak "$TARGET_DIR"

    # --- Read final counters ---
    local fc cc wc ic wlc fsc
    fc=$(cat "$TMPDIR_AUDIT/findings")
    cc=$(cat "$TMPDIR_AUDIT/critical")
    wc=$(cat "$TMPDIR_AUDIT/warning")
    ic=$(cat "$TMPDIR_AUDIT/info")
    wlc=$(cat "$TMPDIR_AUDIT/whitelisted")
    fsc=$(cat "$TMPDIR_AUDIT/files")

    # --- Output results ---
    if [[ "$JSON_OUTPUT" == true ]]; then
        echo "{"
        echo "  \"version\": \"${VERSION}\","
        echo "  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
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
        echo -e "${BOLD}===============================================${NC}"
        echo -e "${BOLD}  Scan Report${NC}"
        echo -e "${BOLD}===============================================${NC}"
        echo -e "  Files scanned: ${BOLD}${fsc}${NC}"
        echo -e "  Total findings: ${BOLD}${fc}${NC}"
        if [[ $cc -gt 0 ]]; then
            echo -e "  [!!] Critical:  ${RED}${BOLD}${cc}${NC}"
        else
            echo -e "  [!!] Critical:  ${GREEN}0${NC}"
        fi
        if [[ $wc -gt 0 ]]; then
            echo -e "  [!]  Warning:   ${YELLOW}${BOLD}${wc}${NC}"
        else
            echo -e "  [!]  Warning:   ${GREEN}0${NC}"
        fi
        if [[ $ic -gt 0 ]]; then
            echo -e "  [i]  Info:      ${CYAN}${ic}${NC}"
        fi
        if [[ $wlc -gt 0 ]]; then
            echo -e "  [w]  Whitelisted: ${DIM}${wlc}${NC}"
        fi
        echo ""

        if [[ $fc -eq 0 ]]; then
            echo -e "  ${GREEN}${BOLD}PASS - No security issues found.${NC}"
        elif [[ $cc -gt 0 ]]; then
            echo -e "  ${RED}${BOLD}FAIL - Critical security issues detected! Immediate review required.${NC}"
        elif [[ $wc -gt 0 ]]; then
            echo -e "  ${YELLOW}${BOLD}WARN - Potential risks found. Manual review recommended.${NC}"
        else
            echo -e "  ${CYAN}INFO - Only informational findings.${NC}"
        fi
        echo ""
    fi

    # Exit codes
    if [[ $cc -gt 0 ]]; then
        exit 2
    elif [[ $wc -gt 0 ]]; then
        exit 1
    else
        exit 0
    fi
}

main
