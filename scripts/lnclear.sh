#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# lnclear.sh — LNClear Client Setup Script
#
# Manages WireGuard VPN tunnel for Lightning node clearnet routing.
# Supports: RaspiBlitz, Umbrel, myNode, RaspiBolt, Start9, Citadel, Bare Metal
# Supports: LND, Core Lightning (CLN), Lightning Terminal (LiT)
#
# Note: Requires root (sudo) for WireGuard/nftables setup, but your Lightning
#       node itself should NOT run as root. The script auto-detects the node
#       user (e.g. bitcoin, lnd, admin) and preserves ownership/permissions.
#
# Usage:
#   wget -O lnclear.sh https://raw.githubusercontent.com/lnclear/lnclear-client/refs/heads/main/scripts/lnclear.sh
#   sudo bash lnclear.sh
#
#   — or —
#
#   sudo bash lnclear.sh                  Interactive setup (recommended)
#   sudo bash lnclear.sh check            Pre-flight compatibility check
#   sudo bash lnclear.sh install          Install (non-interactive, needs WG conf)
#   sudo bash lnclear.sh status           Show tunnel + node status
#   sudo bash lnclear.sh restart          Restart tunnel (stops Lightning first)
#   sudo bash lnclear.sh uninstall        Remove and restore original config
#   sudo bash lnclear.sh update           Pull latest version of this script
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

VERSION="1.4.0"
LNCLEAR_URL="https://lnclear.com"
SCRIPT_URL="https://raw.githubusercontent.com/lnclear/lnclear-client/refs/heads/main/scripts/lnclear.sh"

WG_INTERFACE="lnclear"
CONFIG_DIR="/etc/wireguard"
LNCLEAR_STATE="/etc/lnclear"
BACKUP_SUFFIX=".lnclear-backup"

# ─── State file helper ────────────────────────────────────────────────────────
# Read a single key from state.conf without sourcing (prevents code injection)
_state_get() { grep "^${1}=" "$2" 2>/dev/null | head -1 | cut -d= -f2-; }

# ─── Input validation ─────────────────────────────────────────────────────────
# Abort with error if value doesn't match expected pattern
validate_ipv4() {
    local val=$1 label=$2
    [[ -z "$val" ]] && return 0  # empty is allowed (optional field)
    local IFS=.
    read -ra _octets <<< "$val"
    if [[ ${#_octets[@]} -ne 4 ]]; then
        die "${label}: invalid IPv4 address '${val}'"
    fi
    local _o
    for _o in "${_octets[@]}"; do
        if ! [[ "$_o" =~ ^[0-9]{1,3}$ ]] || (( _o > 255 )); then
            die "${label}: invalid IPv4 address '${val}'"
        fi
    done
}
validate_hostname() {
    local val=$1 label=$2
    [[ -z "$val" ]] && return 0
    if ! [[ "$val" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]{0,253}$ ]]; then
        die "${label}: invalid hostname/IP '${val}'"
    fi
}
validate_port() {
    local val=$1 label=$2
    [[ -z "$val" ]] && return 0
    if ! [[ "$val" =~ ^[0-9]{1,5}$ ]] || (( val < 1 || val > 65535 )); then
        die "${label}: invalid port '${val}'"
    fi
}
validate_service_name() {
    local val=$1 label=$2
    [[ -z "$val" ]] && return 0
    if ! [[ "$val" =~ ^[a-zA-Z0-9@:._-]{1,256}$ ]]; then
        die "${label}: invalid systemd service name '${val}'"
    fi
}

# cgroup split-tunnel constants
CGROUP_NAME="lnclear"
CLASSID="0x00110011"
FWMARK="0x11"
ROUTE_TABLE="211"

# ─── Colours ──────────────────────────────────────────────────────────────────

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

info()  { echo -e "  ${CYAN}[INFO]${RESET}  $*"; }
ok()    { echo -e "  ${GREEN}  ✓${RESET}   $*"; }
warn()  { echo -e "  ${YELLOW}  ⚠${RESET}   $*"; }
err()   { echo -e "  ${RED}  ✗${RESET}   $*" >&2; }
die()   { err "$*"; exit 1; }
blank() { echo ""; }
rule()  { echo -e "  ${DIM}────────────────────────────────────────────────────${RESET}"; }
step()  { blank; echo -e "  ${BOLD}${CYAN}━━━ $* ━━━${RESET}"; blank; }

# ─── Root check ───────────────────────────────────────────────────────────────

[[ $EUID -ne 0 ]] && die "This script must be run as root:  sudo bash lnclear.sh"

# ═══════════════════════════════════════════════════════════════════════════════
# DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

detect_platform() {
    # RaspiBlitz
    if [[ -f /etc/raspiblitz.info ]] || [[ -d /home/admin/config.scripts ]]; then
        echo "raspiblitz"; return
    fi
    # Umbrel (v0.5+ and older)
    if [[ -d /home/umbrel/umbrel ]] || [[ -d /umbrel ]] || \
       [[ -f /usr/bin/umbrel ]] || systemctl is-active --quiet umbrel 2>/dev/null; then
        echo "umbrel"; return
    fi
    # Citadel
    if [[ -d /home/citadel ]] || [[ -f /usr/local/bin/citadel ]]; then
        echo "citadel"; return
    fi
    # myNode
    if [[ -d /usr/share/mynode ]] || [[ -f /usr/bin/mynode_status ]]; then
        echo "mynode"; return
    fi
    # RaspiBolt (lnd user with standard path)
    if id "lnd" &>/dev/null && [[ -f /home/lnd/.lnd/lnd.conf ]]; then
        echo "raspibolt"; return
    fi
    # Start9
    if [[ -f /etc/start9/product.conf ]]; then
        echo "start9"; return
    fi
    echo "barebone"
}

detect_platform_version() {
    local platform=$1
    case "$platform" in
        raspiblitz)
            if [[ -f /etc/raspiblitz.info ]]; then
                grep -m1 "^raspiBlitzVersion=" /etc/raspiblitz.info 2>/dev/null | cut -d= -f2 || echo "unknown"
            else
                echo "unknown"
            fi
            ;;
        umbrel)
            local vf="/home/umbrel/umbrel/info.json"
            [[ -f "$vf" ]] && \
                python3 -c "import json; d=json.load(open('$vf')); print(d.get('version','unknown'))" 2>/dev/null \
                || echo "unknown"
            ;;
        citadel)
            local vf="/home/citadel/citadel/info.json"
            [[ -f "$vf" ]] && \
                python3 -c "import json; d=json.load(open('$vf')); print(d.get('version','unknown'))" 2>/dev/null \
                || echo "unknown"
            ;;
        start9)
            grep "version" /etc/start9/product.conf 2>/dev/null | head -1 | awk '{print $2}' || echo "unknown"
            ;;
        *) echo "" ;;
    esac
}

detect_lightning() {
    # Active systemd services first (most reliable)
    systemctl is-active --quiet lnd         2>/dev/null && echo "lnd" && return
    systemctl is-active --quiet lightningd  2>/dev/null && echo "cln" && return
    systemctl is-active --quiet cln         2>/dev/null && echo "cln" && return
    systemctl is-active --quiet litd        2>/dev/null && echo "lit" && return
    systemctl is-active --quiet lit         2>/dev/null && echo "lit" && return

    # Installed but not running
    [[ -f /etc/systemd/system/lnd.service        ]] && echo "lnd" && return
    [[ -f /etc/systemd/system/lightningd.service ]] && echo "cln" && return
    [[ -f /etc/systemd/system/litd.service       ]] && echo "lit" && return

    # Docker (Umbrel / Citadel)
    if command -v docker &>/dev/null; then
        docker ps 2>/dev/null | grep -iq "lnd"            && echo "lnd" && return
        docker ps 2>/dev/null | grep -iq "core-lightning" && echo "cln" && return
    fi

    # RaspiBlitz info file
    if [[ -f /etc/raspiblitz.info ]]; then
        local _rb_lightning
        _rb_lightning=$(grep -m1 "^lightning=" /etc/raspiblitz.info 2>/dev/null | cut -d= -f2)
        case "${_rb_lightning:-}" in lnd) echo "lnd"; return ;; cl) echo "cln"; return ;; esac
    fi

    # Binary fallback (check root's PATH and sudo caller's PATH)
    command -v lncli         &>/dev/null && echo "lnd" && return
    command -v lightning-cli &>/dev/null && echo "cln" && return
    command -v litcli        &>/dev/null && echo "lit" && return

    # Check sudo caller's environment (binaries may not be in root's PATH)
    if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
        local sudo_home
        sudo_home=$(getent passwd "${SUDO_USER}" | cut -d: -f6)
        for p in "${sudo_home}/go/bin" "${sudo_home}/.local/bin" "${sudo_home}/bin" "/usr/local/bin" "/snap/bin"; do
            [[ -x "${p}/lncli" ]]         && echo "lnd" && return
            [[ -x "${p}/lightning-cli" ]]  && echo "cln" && return
            [[ -x "${p}/litcli" ]]         && echo "lit" && return
        done
        # Check if lnd data directory exists under sudo user's home
        [[ -d "${sudo_home}/.lnd" ]] && echo "lnd" && return
        [[ -d "${sudo_home}/.lightning" ]] && echo "cln" && return
        [[ -d "${sudo_home}/.lit" ]] && echo "lit" && return
    fi

    echo "unknown"
}

detect_node_user() {
    for user in bitcoin lnd admin umbrel citadel pi user; do
        id "$user" &>/dev/null && echo "$user" && return
    done
    # Fallback: the user who invoked sudo (bare-metal / custom installs)
    if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
        id "$SUDO_USER" &>/dev/null && echo "$SUDO_USER" && return
    fi
    echo "root"
}

get_ln_service() {
    local impl=$1
    case "$impl" in
        lnd)
            systemctl list-units --type=service 2>/dev/null | grep -q "^  lnd " && echo "lnd" || echo "lnd"
            ;;
        cln)
            systemctl list-units --type=service 2>/dev/null | grep -q "lightningd" && echo "lightningd" || echo "cln"
            ;;
        lit)
            systemctl list-units --type=service 2>/dev/null | grep -q "litd" && echo "litd" || echo "lit"
            ;;
        *) echo "" ;;
    esac
}

_find_first_existing() {
    for p in "$@"; do
        [[ -n "$p" && -f "$p" ]] && echo "$p" && return
    done
    echo ""
}

get_lnd_conf() {
    local platform=$1 user=$2
    case "$platform" in
        raspiblitz) echo "/mnt/hdd/lnd/lnd.conf" ;;
        umbrel)     echo "/home/umbrel/umbrel/app-data/lightning/data/lnd/lnd.conf" ;;
        citadel)    echo "/home/citadel/citadel/app-data/lnd/data/lnd.conf" ;;
        mynode)     echo "/home/admin/.lnd/lnd.conf" ;;
        raspibolt)  echo "/home/lnd/.lnd/lnd.conf" ;;
        start9)     echo "/embassy-data/package-data/lnd/data/app/lnd.conf" ;;
        *)
            local sudo_home=""
            [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]] && \
                sudo_home=$(getent passwd "${SUDO_USER}" | cut -d: -f6)
            _find_first_existing \
                "/home/${user}/.lnd/lnd.conf" \
                ${sudo_home:+"${sudo_home}/.lnd/lnd.conf"} \
                "/home/bitcoin/.lnd/lnd.conf" \
                "/home/lnd/.lnd/lnd.conf" \
                "/data/lnd/lnd.conf" \
                "/etc/lnd/lnd.conf" \
                "/root/.lnd/lnd.conf"
            ;;
    esac
}

get_cln_conf() {
    local platform=$1 user=$2
    case "$platform" in
        raspiblitz) echo "/mnt/hdd/cln/config" ;;
        umbrel)     echo "/home/umbrel/umbrel/app-data/core-lightning/data/lightningd/bitcoin/config" ;;
        citadel)    echo "/home/citadel/citadel/app-data/core-lightning/data/lightningd/bitcoin/config" ;;
        mynode)     echo "/home/admin/.lightning/config" ;;
        raspibolt)  echo "/home/lightningd/.lightning/config" ;;
        *)
            local sudo_home=""
            [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]] && \
                sudo_home=$(getent passwd "${SUDO_USER}" | cut -d: -f6)
            _find_first_existing \
                "/home/${user}/.lightning/config" \
                ${sudo_home:+"${sudo_home}/.lightning/config"} \
                "/home/bitcoin/.lightning/config" \
                "/etc/lightningd/config" \
                "/root/.lightning/config"
            ;;
    esac
}

get_lit_conf() {
    for svc in /etc/systemd/system/litd.service /etc/systemd/system/lit.service; do
        if [[ -f "$svc" ]]; then
            local extracted
            extracted=$(grep "LIT_CONFIG_FILE" "$svc" 2>/dev/null | \
                sed 's/.*LIT_CONFIG_FILE=//' | tr -d '"' | tr -d "'" | xargs 2>/dev/null || echo "")
            [[ -n "$extracted" && -f "$extracted" ]] && echo "$extracted" && return
        fi
    done
    local sudo_home=""
    [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]] && \
        sudo_home=$(getent passwd "${SUDO_USER}" | cut -d: -f6)
    _find_first_existing \
        "$HOME/.lit/lit.conf" \
        ${sudo_home:+"${sudo_home}/.lit/lit.conf"} \
        "/home/admin/.lit/lit.conf" \
        "/root/.lit/lit.conf"
}

# ─── Composite helpers (used by cmd_setup, cmd_install, cmd_check, cmd_uninstall) ──

parse_wg_config() {
    local wgconf=$1
    WG_SERVER_ENDPOINT=$(grep "^Endpoint" "$wgconf" | awk '{print $3}')
    WG_ASSIGNED_IP=$(grep "^Address" "$wgconf" | awk '{print $3}' | cut -d'/' -f1)
    WG_ASSIGNED_PORT=$(grep -i "^# Your Lightning port:" "$wgconf" | awk '{print $NF}' 2>/dev/null || echo "")
    if [[ -z "$WG_ASSIGNED_PORT" ]]; then
        WG_ASSIGNED_PORT=$(grep "^# LIGHTNING_PORT" "$wgconf" | awk '{print $3}' 2>/dev/null || echo "")
    fi
    WG_SERVER_HOST=$(grep -i "^# Your clearnet IP:" "$wgconf" | awk '{print $NF}' 2>/dev/null || echo "")
    if [[ -z "$WG_SERVER_HOST" ]]; then
        WG_SERVER_HOST=$(echo "$WG_SERVER_ENDPOINT" | cut -d':' -f1)
    fi
}

detect_environment() {
    ENV_PLATFORM=$(detect_platform)
    ENV_PLATFORM_VERSION=$(detect_platform_version "$ENV_PLATFORM")
    ENV_IMPL=$(detect_lightning)
    ENV_NODE_USER=$(detect_node_user)
    ENV_LN_SERVICE=$(get_ln_service "$ENV_IMPL")
    case "$ENV_IMPL" in
        lnd) ENV_LN_CONF=$(get_lnd_conf "$ENV_PLATFORM" "$ENV_NODE_USER") ;;
        cln) ENV_LN_CONF=$(get_cln_conf "$ENV_PLATFORM" "$ENV_NODE_USER") ;;
        lit) ENV_LN_CONF=$(get_lit_conf "$ENV_PLATFORM") ;;
        *)   ENV_LN_CONF="" ;;
    esac
}

detect_bitcoin_core_host() {
    local ln_conf=$1 impl=$2
    local host=""
    [[ -z "$ln_conf" || ! -f "$ln_conf" ]] && echo "" && return

    case "$impl" in
        lnd|lit)
            # Try bitcoind.rpchost=ip or ip:port first
            host=$(grep -iE '^\s*bitcoind\.rpchost\s*=' "$ln_conf" 2>/dev/null | \
                   head -1 | sed 's/.*=\s*//; s/:.*$//' | tr -d ' ')
            # Fallback: parse IP from zmqpubrawblock=tcp://ip:port
            if [[ -z "$host" ]]; then
                host=$(grep -iE '^\s*bitcoind\.zmqpubrawblock\s*=' "$ln_conf" 2>/dev/null | \
                       head -1 | sed 's|.*tcp://||; s/:.*$//' | tr -d ' ')
            fi
            ;;
        cln)
            host=$(grep -iE '^\s*bitcoin-rpcconnect\s*=' "$ln_conf" 2>/dev/null | \
                   head -1 | sed 's/.*=\s*//' | tr -d ' ')
            ;;
    esac

    case "$host" in
        ""|127.0.0.1|localhost|::1) echo "" ;;
        *) echo "$host" ;;
    esac
}

find_wg_config() {
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local candidates=("$script_dir" "./" "/home/admin/" "/home/pi/" \
                      "/home/umbrel/" "/home/citadel/" "/mnt/hdd/" "/root/")
    for dir in "${candidates[@]}"; do
        # Check exact name first, then glob pattern
        [[ -f "${dir}/lnclear.conf" ]] && echo "${dir}/lnclear.conf" && return
        local found
        found=$(find "$dir" -maxdepth 2 -name "lnclear*.conf" -not -path "*/wireguard/*" 2>/dev/null | head -1)
        [[ -n "$found" ]] && echo "$found" && return
    done
    echo ""
}

# ═══════════════════════════════════════════════════════════════════════════════
# INTERACTIVE SETUP (default when no args given)
# ═══════════════════════════════════════════════════════════════════════════════

cmd_setup() {
    clear
    echo ""
    echo -e "  ${BOLD}⚡ LNClear — Lightning Node VPN Setup${RESET}  ${DIM}v${VERSION}${RESET}"
    echo ""
    echo -e "  Get a static clearnet IP for your Lightning node."
    echo -e "  Only port 9735 traffic goes through the VPN — Tor stays live."
    echo ""
    rule

    # ── Step 1: Detect environment ──
    blank
    echo -e "  ${BOLD}Detecting your setup...${RESET}"
    blank

    detect_environment
    local platform="$ENV_PLATFORM" platform_version="$ENV_PLATFORM_VERSION"
    local impl="$ENV_IMPL" node_user="$ENV_NODE_USER"
    local ln_service="$ENV_LN_SERVICE" ln_conf="$ENV_LN_CONF"

    local wgconf btc_host=""
    wgconf=$(find_wg_config)

    # Platform label
    local platform_label
    case "$platform" in
        raspiblitz) platform_label="RaspiBlitz${platform_version:+ ${platform_version}}" ;;
        umbrel)     platform_label="Umbrel${platform_version:+ ${platform_version}}" ;;
        citadel)    platform_label="Citadel${platform_version:+ ${platform_version}}" ;;
        mynode)     platform_label="myNode" ;;
        raspibolt)  platform_label="RaspiBolt" ;;
        start9)     platform_label="Start9" ;;
        barebone)   platform_label="Linux (bare metal)" ;;
        *)          platform_label="$platform" ;;
    esac

    # Lightning label
    local impl_label
    case "$impl" in
        lnd)     impl_label="LND" ;;
        cln)     impl_label="Core Lightning (CLN)" ;;
        lit)     impl_label="Lightning Terminal (LiT)" ;;
        unknown) impl_label="⚠ Not detected" ;;
        *)       impl_label="$impl" ;;
    esac

    # Print detection results
    ok "Platform    :  ${BOLD}${platform_label}${RESET}"
    ok "Lightning   :  ${BOLD}${impl_label}${RESET}${ln_service:+  ${DIM}(service: $ln_service)${RESET}}"
    ok "Node user   :  ${BOLD}${node_user}${RESET}"

    if [[ -n "$ln_conf" && -f "$ln_conf" ]]; then
        ok "LN config   :  ${DIM}${ln_conf}${RESET}"
    elif [[ -n "$ln_conf" ]]; then
        warn "LN config   :  ${DIM}${ln_conf}${RESET}  ${YELLOW}(not found — will need manual edit)${RESET}"
    else
        warn "LN config   :  Could not locate — manual config required"
    fi

    if [[ -n "$wgconf" ]]; then
        ok "WG config   :  ${DIM}${wgconf}${RESET}"
    else
        warn "WG config   :  ${YELLOW}lnclear.conf not found${RESET}"
    fi

    blank; rule; blank

    # ── Abort if Lightning not found ──
    if [[ "$impl" == "unknown" ]]; then
        err "Lightning node not detected. Install LND, CLN, or LiT first."
        blank
        die "Cannot continue."
    fi

    # ── Prompt for WG config if missing ──
    if [[ -z "$wgconf" ]]; then
        echo -e "  ${YELLOW}Your WireGuard config (lnclear.conf) is missing.${RESET}"
        echo ""
        echo -e "  Download it from your dashboard:"
        echo -e "  ${BOLD}${LNCLEAR_URL}/dashboard${RESET}"
        echo ""
        echo -e "  Then copy it to this directory and run again:"
        echo -e "    ${DIM}scp ~/Downloads/lnclear.conf root@your-node:/root/${RESET}"
        blank
        read -rp "  Press Enter to open the dashboard URL, or Ctrl+C to exit: "
        command -v xdg-open &>/dev/null && xdg-open "${LNCLEAR_URL}/dashboard" 2>/dev/null || true
        die "Re-run after placing lnclear.conf alongside this script."
    fi

    # ── Parse config file ──
    parse_wg_config "$wgconf"
    local server_host="$WG_SERVER_HOST" assigned_ip="$WG_ASSIGNED_IP"
    local server_endpoint="$WG_SERVER_ENDPOINT" assigned_port="$WG_ASSIGNED_PORT"

    # ── Bitcoin Core host ──
    btc_host=$(detect_bitcoin_core_host "$ln_conf" "$impl")
    blank
    if [[ -n "$btc_host" ]]; then
        ok "Bitcoin Core (detected): ${BOLD}${btc_host}${RESET}"
        echo -ne "  Confirm or enter a different IP [${btc_host}]:  "
        local btc_input; read -r btc_input
        btc_input=$(echo "$btc_input" | tr -d ' ')
        [[ -n "$btc_input" ]] && btc_host="$btc_input"
        validate_ipv4 "$btc_host" "btc_host"
    else
        echo -e "  ${BOLD}Bitcoin Core on a non-local subnet?${RESET}"
        echo -e "  Local subnet routes bypass the VPN automatically."
        echo -e "  Only needed if Bitcoin Core is on a different VLAN or routed segment."
        echo -ne "  Bitcoin Core IP (or press Enter to skip):  "
        local btc_input; read -r btc_input
        btc_host=$(echo "$btc_input" | tr -d ' ')
        validate_ipv4 "$btc_host" "btc_host"
    fi
    if [[ -n "$btc_host" ]]; then
        ok "Bitcoin Core: ${BOLD}${btc_host}${RESET} — direct route will bypass VPN"
    else
        info "Bitcoin Core: same machine as LND (no extra route needed)"
    fi
    blank; rule; blank

    # ── Platform-specific warnings ──
    if [[ "$platform" == "umbrel" ]]; then
        warn "Umbrel: WireGuard runs on the HOST — not inside Docker containers."
        warn "After install you may also need to enable Hybrid Mode in the Umbrel UI."
        blank
    fi

    if [[ "$platform" == "start9" ]]; then
        warn "Start9: Limited systemd integration — you may need to restart"
        warn "Lightning manually from the Start9 UI after setup."
        blank
    fi

    if [[ "$platform" == "citadel" ]]; then
        warn "Citadel: Similar to Umbrel — WireGuard runs on the host, not in Docker."
        blank
    fi

    # ── Pre-install summary ──
    echo -e "  ${BOLD}What this install will do:${RESET}"
    blank
    echo -e "  ${GREEN}1.${RESET} Install packages: wireguard, nftables, cgroup-tools"
    echo -e "  ${GREEN}2.${RESET} Copy WG config to ${DIM}/etc/wireguard/lnclear.conf${RESET}"
    echo -e "  ${GREEN}3.${RESET} Set up cgroup split-tunnel — ${BOLD}only Lightning goes through VPN${RESET}"
    echo -e "     (your browser, Tor, and other traffic are NOT affected)"
    echo -e "     ${DIM}+ local subnet routes bypass VPN (Bitcoin Core, LAN services)${RESET}"
    [[ -n "$btc_host" ]] && \
        echo -e "     ${DIM}+ explicit route for Bitcoin Core ${btc_host} (non-local subnet)${RESET}"
    echo -e "  ${GREEN}4.${RESET} Route ${BOLD}${ln_service:-Lightning}${RESET} through VPN cgroup"
    echo -e "  ${GREEN}5.${RESET} Enable kill switch — ${BOLD}block port 9735 if VPN drops${RESET}"
    case "$impl" in
        lnd|lit)
            echo -e "  ${GREEN}6.${RESET} Add to ${DIM}lnd.conf${RESET}:"
            echo -e "     ${DIM}• externalhosts=${server_host}:${assigned_port:-YOUR_PORT}${RESET}"
            echo -e "     ${DIM}• listen=0.0.0.0:9735${RESET}"
            echo -e "     ${DIM}• tor.streamisolation=false${RESET}"
            echo -e "     ${DIM}• tor.skip-proxy-for-clearnet-targets=true${RESET}"
            ;;
        cln)
            echo -e "  ${GREEN}6.${RESET} Add to CLN config:"
            echo -e "     ${DIM}• announce-addr=${server_host}:${assigned_port:-YOUR_PORT}${RESET}"
            echo -e "     ${DIM}• bind-addr=0.0.0.0:9735${RESET}"
            echo -e "     ${DIM}• always-use-proxy=false${RESET}"
            ;;
    esac
    if [[ -n "$ln_conf" && -f "$ln_conf" ]]; then
        echo -e "     ${DIM}(backup saved to ${ln_conf}${BACKUP_SUFFIX})${RESET}"
    fi
    echo -e "  ${GREEN}7.${RESET} Enable and start WireGuard interface ${DIM}\"lnclear\"${RESET}"
    echo -e "  ${GREEN}8.${RESET} Restart ${BOLD}${ln_service:-your Lightning service}${RESET}"
    blank
    echo -e "  ${YELLOW}⚠  Your node will be briefly offline (~30 sec) during Lightning restart.${RESET}"
    echo -e "  ${GREEN}✓  Tor stays active the whole time — this does NOT disable Tor.${RESET}"
    blank
    rule
    blank

    # ── Final confirmation ──
    echo -ne "  ${BOLD}Proceed with install?${RESET} [y/N]  "
    local confirm
    read -r confirm
    blank

    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        info "Aborted. No changes were made."
        exit 0
    fi

    # ── Run install ──
    _do_install "$platform" "$impl" "$node_user" "$ln_service" "$ln_conf" "$wgconf" "$server_host" "$assigned_ip" "$server_endpoint" "$assigned_port" "$btc_host"
}

# ═══════════════════════════════════════════════════════════════════════════════
# PRE-FLIGHT CHECK
# ═══════════════════════════════════════════════════════════════════════════════

cmd_check() {
    step "LNClear Pre-flight Check"
    local issues=0

    # OS
    if grep -qiE "ubuntu|debian|raspbian|armbian" /etc/os-release 2>/dev/null; then
        ok "OS: $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)"
    else
        warn "OS: Not Debian/Ubuntu — may have compatibility issues"
    fi

    # Kernel ≥5.10.102
    local kernel; kernel=$(uname -r)
    local kmajor kminor kpatch
    IFS='.-' read -r kmajor kminor kpatch _ <<< "$kernel"
    kpatch=$(echo "${kpatch:-0}" | tr -cd '0-9')
    if (( kmajor > 5 )) || (( kmajor == 5 && kminor > 10 )) || \
       (( kmajor == 5 && kminor == 10 && ${kpatch:-0} >= 102 )); then
        ok "Kernel: $kernel (≥5.10.102 required)"
    else
        err "Kernel: $kernel — need 5.10.102+. Update with: apt-get install --install-recommends linux-generic"
        (( issues++ ))
    fi

    # cgroup v1 (net_cls) required
    if [[ -d /sys/fs/cgroup/net_cls ]] || mount | grep -q "cgroup.*net_cls"; then
        ok "cgroup: v1 net_cls available"
    else
        warn "cgroup: net_cls not found — split-tunnel requires cgroup v1 net_cls"
        warn "  On cgroup v2 systems, run: sudo modprobe cls_cgroup"
        (( issues++ ))
    fi

    # nftables
    if command -v nft &>/dev/null; then
        local nftver; nftver=$(nft -v 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        ok "nftables: v${nftver}"
    else
        warn "nftables: not installed (will be installed automatically)"
    fi

    # Platform
    local platform; platform=$(detect_platform)
    local pver; pver=$(detect_platform_version "$platform")
    ok "Platform: ${platform}${pver:+ ${pver}}"

    # Lightning
    local impl; impl=$(detect_lightning)
    if [[ "$impl" == "unknown" ]]; then
        err "Lightning: not detected — install LND, CLN, or LiT first"
        (( issues++ ))
    else
        local svc; svc=$(get_ln_service "$impl")
        ok "Lightning: $impl (service: $svc)"
    fi

    # WireGuard config
    local wgconf; wgconf=$(find_wg_config)
    if [[ -n "$wgconf" ]]; then
        ok "WG config: $wgconf"
        parse_wg_config "$wgconf"
        [[ -n "$WG_ASSIGNED_PORT" ]] && info "Lightning port: $WG_ASSIGNED_PORT"
    else
        warn "WG config: lnclear.conf not found"
        info "Download from ${LNCLEAR_URL}/dashboard"
        (( issues++ ))
    fi

    blank
    rule
    blank
    if (( issues == 0 )); then
        ok "All checks passed. Ready to install:"
        blank
        echo -e "  ${BOLD}sudo bash lnclear.sh${RESET}   (interactive)"
        echo -e "  ${BOLD}sudo bash lnclear.sh install${RESET}   (non-interactive)"
    else
        warn "${issues} issue(s) need attention (see above)."
    fi
    blank
}

# ═══════════════════════════════════════════════════════════════════════════════
# INSTALL (non-interactive, called from cmd_setup or directly)
# ═══════════════════════════════════════════════════════════════════════════════

cmd_install() {
    local wgconf
    wgconf=$(find_wg_config)
    [[ -z "$wgconf" ]] && die "No lnclear.conf found. Download from ${LNCLEAR_URL}/dashboard"

    detect_environment
    parse_wg_config "$wgconf"

    local btc_host
    btc_host=$(detect_bitcoin_core_host "$ENV_LN_CONF" "$ENV_IMPL")
    [[ -n "$btc_host" ]] && info "Bitcoin Core detected at ${btc_host} — will add direct route"

    _do_install "$ENV_PLATFORM" "$ENV_IMPL" "$ENV_NODE_USER" "$ENV_LN_SERVICE" "$ENV_LN_CONF" "$wgconf" \
                "$WG_SERVER_HOST" "$WG_ASSIGNED_IP" "$WG_SERVER_ENDPOINT" "$WG_ASSIGNED_PORT" "$btc_host"
}

# ═══════════════════════════════════════════════════════════════════════════════
# INTERNAL: PERFORM INSTALL
# ═══════════════════════════════════════════════════════════════════════════════

_do_install() {
    local platform=$1 impl=$2 node_user=$3 ln_service=$4 ln_conf=$5 wgconf=$6
    local server_host=$7 assigned_ip=$8 _server_endpoint=$9 assigned_port=${10:-""} btc_host=${11:-""}

    validate_hostname     "$server_host"  "server_host"
    validate_port         "$assigned_port" "assigned_port"
    validate_ipv4         "$btc_host"     "btc_host"
    validate_service_name "$ln_service"   "ln_service"

    # cgroup v1 (net_cls) required for split-tunnel
    local cgroup_version="v1"
    if ! ([[ -d /sys/fs/cgroup/net_cls ]] || mount | grep -q "cgroup.*net_cls"); then
        warn "cgroup net_cls not found — cgroup-based routing may not work on this kernel"
        warn "  If on a cgroup v2-only kernel, re-mount net_cls or use a v1 kernel"
    fi

    step "Installing LNClear v${VERSION}"

    # ── 0: Clean up artifacts from prior installs ─────────────────────────────
    if [[ -f "${LNCLEAR_STATE}/state.conf" ]]; then
        info "Existing install detected — cleaning up before re-install..."
        # Remove old cgroup service (replaced by lnclear.slice on v2)
        systemctl stop    lnclear-cgroup 2>/dev/null || true
        systemctl disable lnclear-cgroup 2>/dev/null || true
        rm -f /etc/systemd/system/lnclear-cgroup.service
        # Remove old kill switch (will be re-created)
        systemctl stop    lnclear-killswitch 2>/dev/null || true
        systemctl disable lnclear-killswitch 2>/dev/null || true
        rm -f /etc/systemd/system/lnclear-killswitch.service
        nft delete table ip lnclear_killswitch 2>/dev/null || true
        # Remove old cgroup drop-in
        rm -f "/etc/systemd/system/${ln_service}.service.d/lnclear.conf"
        # Remove old slice
        systemctl stop lnclear.slice 2>/dev/null || true
        rm -f /etc/systemd/system/lnclear.slice
        systemctl daemon-reload
        ok "Old artifacts removed"
    fi

    # ── 1: Packages ──────────────────────────────────────────────────────────
    info "[1/7] Installing packages..."
    apt-get update -qq
    apt-get install -y -qq wireguard wireguard-tools nftables cgroup-tools
    ok "Packages: wireguard, nftables, cgroup-tools"

    # ── 2: WireGuard config ──────────────────────────────────────────────────
    info "[2/7] Writing WireGuard config..."
    mkdir -p "$CONFIG_DIR"
    cp "$wgconf" "${CONFIG_DIR}/${WG_INTERFACE}.conf"
    chmod 600 "${CONFIG_DIR}/${WG_INTERFACE}.conf"

    # Prevent wg-quick from hijacking the default route (split-tunnel)
    local wg_conf="${CONFIG_DIR}/${WG_INTERFACE}.conf"
    sed -i '/^Table\s*=/d' "$wg_conf"
    sed -i '/^\[Interface\]/a Table = off' "$wg_conf"

    # Strip all wg-quick hooks and any stale/corrupted lines from prior installs
    sed -i '/^PostUp\s*=/d; /^PostDown\s*=/d; /^PreDown\s*=/d' "$wg_conf"
    sed -i '/resolvconf/d' "$wg_conf"
    sed -i "/^'|/d" "$wg_conf"

    # Detect local gateway and NIC for Bitcoin Core direct routing
    local local_gw local_nic
    local_gw=$(ip route show default 2>/dev/null | awk 'NR==1{for(i=1;i<=NF;i++){if($i=="via")print $(i+1)}}')
    local_nic=$(ip route show default 2>/dev/null | awk 'NR==1{for(i=1;i<=NF;i++){if($i=="dev")print $(i+1)}}')

    python3 - "$wg_conf" "$FWMARK" "$ROUTE_TABLE" "$CLASSID" "$ln_service" "${btc_host:-}" "${local_gw:-}" "${local_nic:-}" << 'PYEOF'
import sys, re
conf, fwmark, table, classid, ln_svc = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
btc_host = sys.argv[6] if len(sys.argv) > 6 else ""
local_gw  = sys.argv[7] if len(sys.argv) > 7 else ""
local_nic = sys.argv[8] if len(sys.argv) > 8 else ""

with open(conf) as f: content = f.read()

# Extract client's WG IP so responses to inbound connections can be routed back
# through the tunnel (src-based routing: from client_ip → table table).
addr_match = re.search(r'^Address\s*=\s*([\d.]+)', content, re.MULTILINE)
client_ip = addr_match.group(1) if addr_match else ""

# Build PostUp: routing rules + full 4-chain nft table
postup = (
    f"PostUp   = ip rule add fwmark {fwmark} table {table} 2>/dev/null || true; "
    + (f"ip rule add from {client_ip} table {table} 2>/dev/null || true; " if client_ip else "")
    + f"ip rule add from all table main suppress_prefixlength 0 2>/dev/null || true; "
    f"ip route add default dev lnclear table {table} 2>/dev/null || true"
)
postup += (
    f"; nft add table ip lnclear 2>/dev/null || true"
    # prerouting: restore conntrack mark on return/reply packets (stateful routing)
    f"; nft add chain ip lnclear prerouting '{{ type filter hook prerouting priority mangle -1; policy accept; }}' 2>/dev/null || true"
    f"; nft add rule ip lnclear prerouting meta mark set ct mark 2>/dev/null || true"
    # output: mark Lightning cgroup packets for VPN routing
    f"; nft add chain ip lnclear output '{{ type route hook output priority mangle -1; policy accept; }}' 2>/dev/null || true"
    f"; nft add rule ip lnclear output meta cgroup {classid} meta mark set {fwmark} 2>/dev/null || true"
    # nat: kill switch (drop Lightning internet traffic on non-VPN) + masquerade
    f"; nft add chain ip lnclear nat '{{ type nat hook postrouting priority srcnat -1; policy accept; }}' 2>/dev/null || true"
    f"; nft add rule ip lnclear nat oifname != lnclear meta mark == {fwmark} ip daddr != {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }} drop 2>/dev/null || true"
    f"; nft add rule ip lnclear nat oifname lnclear masquerade 2>/dev/null || true"
    # input: only allow port 9735 inbound from VPN (drop all other unsolicited inbound)
    f"; nft add chain ip lnclear input '{{ type filter hook input priority filter -1; policy accept; }}' 2>/dev/null || true"
    f"; nft add rule ip lnclear input iifname lnclear ct state established,related accept 2>/dev/null || true"
    f"; nft add rule ip lnclear input iifname lnclear tcp dport != 9735 drop 2>/dev/null || true"
    f"; nft add rule ip lnclear input iifname lnclear udp dport != 9735 drop 2>/dev/null || true"
)

lines = []
lines.append(postup)

# Local network bypass: mirror ALL non-default routes from the main routing
# table into table {table}, stripping proto/src/metric metadata that would
# cause 'ip route add' to fail. This covers:
#   - directly-connected subnets (scope link, non-VLAN and VLAN sub-interfaces)
#   - gateway routes to remote-but-local segments (scope global, different VLANs)
# Both are needed: link-scope covers eth0/eth0.100 subnets; global covers
# routed segments like 172.16.0.0/16 via 172.16.3.1 that are still LAN.
# More-specific subnet routes override the default dev lnclear entry.
lines.append(
    f"PostUp   = ip route show | grep -vE '^default|dev lnclear' | "
    f"awk '{{n=$1; v=\"\"; d=\"\"; for(i=2;i<=NF;i++){{if($i==\"via\")v=\"via \"$(i+1); if($i==\"dev\")d=\"dev \"$(i+1)}}; if(d) print n, v, d}}' | "
    f'while IFS= read -r _r; do ip route add "$_r" table {table} 2>/dev/null || true; done'
)

# Bitcoin Core direct route: for Bitcoin Core on a non-directly-connected subnet
# (e.g. different VLAN, routed segment) where link-scope routes won't cover it.
if btc_host and local_gw and local_nic:
    lines.append(
        f"PostUp   = ip route add {btc_host}/32 via {local_gw} dev {local_nic} table {table} 2>/dev/null || true"
    )

# DNS leak prevention: add VPN-side DNS and route it through tunnel
dns_match = re.search(r'^DNS\s*=\s*([\d.]+)', content, re.MULTILINE)
if dns_match:
    dns_ip = dns_match.group(1)
    lines.append(
        f"PostUp   = ip route add {dns_ip}/32 dev lnclear table {table} 2>/dev/null || true; "
        f"echo 'nameserver {dns_ip}' | resolvconf -a lnclear -m 0 2>/dev/null || true"
    )

# PostUp: restart Lightning after VPN recovery (routing rules are set above)
# Use --no-block to avoid deadlock: lnd Requires=wg-quick which is still in PostUp
lines.append(f"PostUp   = systemctl start --no-block {ln_svc} 2>/dev/null || true")

# PreDown: stop Lightning before tunnel teardown to prevent IP leak
lines.append(f"PreDown  = systemctl stop {ln_svc} 2>/dev/null || true")

# Build PostDown: clean up routing + nft + DNS
postdown = (
    f"PostDown = ip rule del fwmark {fwmark} table {table} 2>/dev/null || true; "
    + (f"ip rule del from {client_ip} table {table} 2>/dev/null || true; " if client_ip else "")
    + f"ip rule del from all table main suppress_prefixlength 0 2>/dev/null || true; "
    f"ip route del default dev lnclear table {table} 2>/dev/null || true; "
    f"nft delete table ip lnclear 2>/dev/null || true; "
    f"resolvconf -d lnclear 2>/dev/null || true"
)
lines.append(postdown)

# Clean up: flush everything we added to table {table} (both link-scope and
# gateway routes). The 'ip route del default' above already removed the VPN
# default; this catches all the mirrored local routes.
lines.append(
    f"PostDown = ip route flush table {table} 2>/dev/null || true"
)

# Bitcoin Core: clean up the direct gateway route on tunnel teardown
if btc_host and local_gw and local_nic:
    lines.append(
        f"PostDown = ip route del {btc_host}/32 via {local_gw} dev {local_nic} table {table} 2>/dev/null || true"
    )

# Insert lines before [Peer] section (or at end of file)
# Using string insertion instead of re.sub to avoid backreference/escape issues
insert_block = "\n".join(lines) + "\n"
peer_pos = content.find("[Peer]")
if peer_pos > 0:
    content = content[:peer_pos] + insert_block + "\n" + content[peer_pos:]
else:
    content = content.rstrip() + "\n" + insert_block

with open(conf, 'w') as f: f.write(content)
PYEOF
    ok "WireGuard config: ${wg_conf}"

    # ── 3: cgroup split-tunnel ───────────────────────────────────────────────
    info "[3/7] Setting up cgroup split-tunnel (net_cls)..."
    cgcreate -g net_cls:${CGROUP_NAME} 2>/dev/null || true
    echo "${CLASSID}" > /sys/fs/cgroup/net_cls/${CGROUP_NAME}/net_cls.classid 2>/dev/null || true

    cat > /etc/systemd/system/lnclear-cgroup.service << EOF
[Unit]
Description=LNClear net_cls cgroup (Lightning split-tunnel)
DefaultDependencies=no
Before=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c "cgcreate -g net_cls:${CGROUP_NAME} && echo ${CLASSID} > /sys/fs/cgroup/net_cls/${CGROUP_NAME}/net_cls.classid"

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now lnclear-cgroup 2>/dev/null || true
    ok "cgroup v1: net_cls:${CGROUP_NAME} (classid=${CLASSID})"

    # Persistent kill switch: blocks Lightning outbound (fwmark ${FWMARK}) on non-VPN
    # interfaces even if wg-quick fails at boot. Runs before network-pre.target.
    cat > /etc/systemd/system/lnclear-killswitch.service << EOF
[Unit]
Description=LNClear kill switch (prevent Lightning IP leak before VPN comes up)
DefaultDependencies=no
Before=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c "nft add table ip lnclear 2>/dev/null || true; nft add chain ip lnclear nat '{ type nat hook postrouting priority srcnat -1; policy accept; }' 2>/dev/null || true; nft add rule ip lnclear nat oifname != lnclear meta mark == ${FWMARK} ip daddr != { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } drop 2>/dev/null || true"
ExecStop=/bin/bash -c "nft delete table ip lnclear 2>/dev/null || true"

[Install]
WantedBy=network-pre.target
EOF
    systemctl daemon-reload
    systemctl enable --now lnclear-killswitch 2>/dev/null || true
    ok "Kill switch: lnclear-killswitch.service (Before=network-pre.target)"

    # ── 4: Place Lightning in cgroup ──────────────────────────────────────────
    info "[4/7] Routing Lightning through VPN cgroup..."
    if [[ -n "$ln_service" ]] && systemctl cat "$ln_service" &>/dev/null; then
        mkdir -p "/etc/systemd/system/${ln_service}.service.d"
        cat > "/etc/systemd/system/${ln_service}.service.d/lnclear.conf" << EOF
[Unit]
After=wg-quick@${WG_INTERFACE}.service
Requires=wg-quick@${WG_INTERFACE}.service

[Service]
ExecStartPost=/bin/bash -c 'sleep 3 && echo \$MAINPID > /sys/fs/cgroup/net_cls/${CGROUP_NAME}/tasks 2>/dev/null || true'
EOF
        systemctl daemon-reload
        ok "${ln_service} → cgroup ${CGROUP_NAME} (all outbound traffic routed through VPN)"
    elif [[ "$platform" == "umbrel" || "$platform" == "citadel" ]]; then
        warn "Docker platform detected — cgroup routing requires manual Docker config."
        warn "The kill switch (step 5) still protects against IP leaks."
    else
        warn "Could not find systemd service '${ln_service}' — cgroup drop-in skipped."
        warn "The kill switch (step 5) still protects against IP leaks."
    fi

    # ── 5: Lightning config ──────────────────────────────────────────────────
    info "[5/7] Updating Lightning config..."

    if [[ -n "$ln_conf" && -f "$ln_conf" ]]; then
        # Only create backup if one doesn't already exist (preserve original on re-run)
        if [[ ! -f "${ln_conf}${BACKUP_SUFFIX}" ]]; then
            cp "$ln_conf" "${ln_conf}${BACKUP_SUFFIX}"
            chmod 600 "${ln_conf}${BACKUP_SUFFIX}"
            ok "Backup: ${ln_conf}${BACKUP_SUFFIX}"
        else
            ok "Backup already exists: ${ln_conf}${BACKUP_SUFFIX} (preserved)"
        fi
        sed -i '/# BEGIN LNCLEAR/,/# END LNCLEAR/d' "$ln_conf"

        case "$impl" in
            lnd|lit)
                # Remove managed keys to prevent duplicates on re-run
                sed -i '/^externalhosts=/d' "$ln_conf"
                sed -i '/^listen=0\.0\.0\.0:9735/d' "$ln_conf"
                sed -i '/^tor\.skip-proxy-for-clearnet-targets=/d' "$ln_conf"
                sed -i '/^tor\.streamisolation=/d' "$ln_conf"
                cat >> "$ln_conf" << EOF

# BEGIN LNCLEAR -- managed by lnclear.sh v${VERSION}
[Application Options]
listen=0.0.0.0:9735
externalhosts=${server_host}:${assigned_port}

[Tor]
tor.streamisolation=false
tor.skip-proxy-for-clearnet-targets=true
# END LNCLEAR
EOF
                ok "lnd.conf: externalhosts + Tor split-routing added"
                ;;
            cln)
                # Remove managed keys to prevent duplicates on re-run
                sed -i '/^bind-addr=0\.0\.0\.0:9735/d' "$ln_conf"
                local _esc_host
                _esc_host=$(printf '%s' "${server_host}" | sed 's/[.[\*^$]/\\&/g')
                sed -i '/^announce-addr='"${_esc_host}"'/d' "$ln_conf"
                sed -i '/^always-use-proxy=/d' "$ln_conf"
                cat >> "$ln_conf" << EOF

# BEGIN LNCLEAR -- managed by lnclear.sh v${VERSION}
bind-addr=0.0.0.0:9735
announce-addr=${server_host}:${assigned_port}
always-use-proxy=false
# END LNCLEAR
EOF
                ok "CLN config: announce-addr + proxy settings added"
                ;;
        esac

        if [[ "$platform" == "umbrel" ]]; then
            blank
            warn "Umbrel: After install, open the Umbrel UI:"
            warn "  Lightning → Settings → Advanced → enable Hybrid Mode"
            blank
        fi
    else
        warn "Could not find Lightning config — add these settings manually:"
        _print_manual_config "$impl" "$server_host" "$assigned_port"
    fi

    # ── 6: State file ────────────────────────────────────────────────────────
    info "[6/7] Saving state..."
    mkdir -p "$LNCLEAR_STATE"
    chmod 700 "$LNCLEAR_STATE"
    cat > "${LNCLEAR_STATE}/state.conf" << EOF
PLATFORM=${platform}
LIGHTNING=${impl}
LN_CONF=${ln_conf:-""}
LN_SERVICE=${ln_service}
WG_CONF=${wg_conf}
SERVER_HOST=${server_host}
ASSIGNED_PORT=${assigned_port}
BITCOIN_CORE_HOST=${btc_host:-""}
INSTALLED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
VERSION=${VERSION}
EOF
    chmod 600 "${LNCLEAR_STATE}/state.conf"
    ok "State: ${LNCLEAR_STATE}/state.conf"

    # ── 7: Start WireGuard + restart Lightning ────────────────────────────────
    info "[7/7] Starting services..."
    systemctl stop wg-quick@${WG_INTERFACE} 2>/dev/null || true
    ip link delete ${WG_INTERFACE} 2>/dev/null || true
    nft delete table ip lnclear 2>/dev/null || true
    systemctl enable wg-quick@${WG_INTERFACE}
    systemctl start wg-quick@${WG_INTERFACE}
    ok "WireGuard interface lnclear: UP"

    if [[ -n "$ln_service" ]]; then
        info "Restarting ${ln_service}..."
        systemctl stop "$ln_service" 2>/dev/null || true
        sleep 2
        systemctl start --no-block "$ln_service" 2>/dev/null || true
        sleep 5
        if systemctl is-active --quiet "$ln_service" 2>/dev/null; then
            ok "${ln_service}: running"
        else
            warn "${ln_service}: still starting up"
            [[ "$impl" == "lnd" || "$impl" == "lit" ]] && \
                info "If wallet unlock is needed, run: ${BOLD}lncli unlock${RESET}"
            info "Check logs: ${DIM}journalctl -u ${ln_service} -n 50${RESET}"
        fi
    fi

    # ── Success banner ────────────────────────────────────────────────────────
    blank; rule; blank
    echo -e "  ${GREEN}${BOLD}✓ LNClear installed successfully!${RESET}"
    blank
    [[ -n "$assigned_port" ]] && echo -e "  Lightning port  :  ${BOLD}${assigned_port}${RESET}"
    echo -e "  VPN server      :  ${BOLD}${server_host}${RESET}"
    echo -e "  Your VPN IP     :  ${BOLD}${assigned_ip}${RESET}"
    [[ -n "$btc_host" ]] && echo -e "  Bitcoin Core    :  ${BOLD}${btc_host}${RESET}  ${DIM}(direct route, bypasses VPN)${RESET}"
    blank
    echo -e "  Check status    :  ${BOLD}sudo bash lnclear.sh status${RESET}"
    echo -e "  Dashboard       :  ${BOLD}${LNCLEAR_URL}/dashboard${RESET}"
    blank

    if [[ "$platform" == "umbrel" ]]; then
        rule; blank
        echo -e "  ${YELLOW}${BOLD}Umbrel extra step:${RESET}"
        echo -e "  Open Umbrel UI → Lightning → Settings → Advanced → enable Hybrid Mode"
        blank
    fi

    rule
    blank
    info "Allow 5–10 minutes for your node to gossip its new address to the network."
    blank
}

_print_manual_config() {
    local impl=$1 host=$2 port=$3
    blank
    case "$impl" in
        lnd|lit)
            echo -e "  ${DIM}[Application Options]"
            echo -e "  listen=0.0.0.0:9735"
            echo -e "  externalhosts=${host}:${port}"
            echo -e ""
            echo -e "  [Tor]"
            echo -e "  tor.streamisolation=false"
            echo -e "  tor.skip-proxy-for-clearnet-targets=true${RESET}"
            ;;
        cln)
            echo -e "  ${DIM}bind-addr=0.0.0.0:9735"
            echo -e "  announce-addr=${host}:${port}"
            echo -e "  always-use-proxy=false${RESET}"
            ;;
    esac
    blank
}

# ═══════════════════════════════════════════════════════════════════════════════
# STATUS
# ═══════════════════════════════════════════════════════════════════════════════

cmd_status() {
    step "LNClear Status"

    local state="${LNCLEAR_STATE}/state.conf"
    if [[ ! -f "$state" ]]; then
        warn "Not installed. Run: sudo bash lnclear.sh"
        return 1
    fi
    PLATFORM=$(          _state_get PLATFORM        "$state")
    LIGHTNING=$(         _state_get LIGHTNING       "$state")
    LN_SERVICE=$(        _state_get LN_SERVICE      "$state")
    LN_CONF=$(           _state_get LN_CONF         "$state")
    SERVER_HOST=$(       _state_get SERVER_HOST      "$state")
    ASSIGNED_PORT=$(     _state_get ASSIGNED_PORT   "$state")
    BITCOIN_CORE_HOST=$( _state_get BITCOIN_CORE_HOST "$state")

    # WireGuard
    echo -e "  ${BOLD}Tunnel (${WG_INTERFACE})${RESET}"
    if wg show "$WG_INTERFACE" &>/dev/null; then
        local handshake
        handshake=$(wg show "$WG_INTERFACE" latest-handshakes 2>/dev/null | awk '{print $2}')
        if [[ -n "$handshake" && "$handshake" != "0" ]]; then
            local ago=$(( $(date +%s) - handshake ))
            ok "Interface UP — last handshake ${ago}s ago"
        else
            warn "Interface UP — no handshake yet (server may be unreachable)"
        fi
        wg show "$WG_INTERFACE" | grep -E "endpoint|transfer|allowed" | sed 's/^/    /'
    else
        err "Interface ${WG_INTERFACE} is DOWN"
        info "Try: sudo systemctl restart wg-quick@lnclear"
    fi

    # Local network bypass
    blank
    echo -e "  ${BOLD}Local network routing (table 211)${RESET}"
    local local_route_count
    local_route_count=$(ip route show table 211 2>/dev/null | grep -v lnclear | grep -v '^default' | wc -l)
    if (( local_route_count > 0 )); then
        ok "${local_route_count} local route(s) bypass VPN:"
        ip route show table 211 2>/dev/null | grep -v lnclear | grep -v '^default' | sed 's/^/    /'
    else
        warn "No local routes in table 211 — LAN traffic (Bitcoin Core, ZMQ) may route through VPN"
        info "Try: sudo systemctl restart wg-quick@lnclear"
    fi
    if [[ -n "${BITCOIN_CORE_HOST:-}" ]]; then
        if ip route show table 211 2>/dev/null | grep -q "${BITCOIN_CORE_HOST}"; then
            ok "Bitcoin Core ${BITCOIN_CORE_HOST}: direct route active"
        else
            warn "Bitcoin Core ${BITCOIN_CORE_HOST}: direct route missing"
        fi
    fi

    # Kill switch
    blank
    echo -e "  ${BOLD}Kill switch${RESET}"
    if nft list table ip lnclear &>/dev/null; then
        ok "Active — integrated in nft lnclear table (NAT chain)"
    else
        warn "nft lnclear table not found — kill switch inactive"
    fi

    # Resolve server IP from live WireGuard endpoint (avoids domain dependency)
    local server_ip
    server_ip=$(wg show "$WG_INTERFACE" endpoints 2>/dev/null | awk '{print $2}' | cut -d':' -f1 | head -1)
    if [[ -z "$server_ip" ]]; then
        # Fallback: DNS resolve SERVER_HOST
        server_ip=$(getent hosts "${SERVER_HOST:-}" 2>/dev/null | awk '{print $1}' | head -1)
    fi
    [[ -z "$server_ip" ]] && server_ip="${SERVER_HOST:-?}"

    # Outbound IP — bind directly to WG interface to bypass cgroup/kill-switch routing
    blank
    echo -e "  ${BOLD}Outbound IP (should match VPN server)${RESET}"
    local outbound
    outbound=$(curl --interface ${WG_INTERFACE} -s --connect-timeout 5 https://api.ipify.org 2>/dev/null || echo "unreachable")
    if [[ "$outbound" == "$server_ip" ]]; then
        ok "$outbound"
    else
        warn "$outbound  ${DIM}(expected ${server_ip})${RESET}"
    fi

    # Inbound port — bind to WG local IP so the probe escapes via the tunnel
    # (suppress_prefixlength 0 blocks the default route for unmark'd root traffic)
    if [[ -n "${ASSIGNED_PORT:-}" && -n "$server_ip" ]]; then
        blank
        echo -e "  ${BOLD}Lightning port ${ASSIGNED_PORT} → ${server_ip}${RESET}"
        local wg_local_ip
        wg_local_ip=$(ip addr show ${WG_INTERFACE} 2>/dev/null | awk '/inet /{print $2}' | cut -d'/' -f1 | head -1)
        local port_reachable=false
        if [[ -n "$wg_local_ip" ]] && python3 -c "
import socket, sys
s = socket.socket()
s.bind(('$wg_local_ip', 0))
s.settimeout(5)
try:
    s.connect(('$server_ip', $ASSIGNED_PORT))
    s.close()
    sys.exit(0)
except Exception:
    sys.exit(1)
" 2>/dev/null; then
            port_reachable=true
        fi
        if $port_reachable; then
            ok "Port ${ASSIGNED_PORT} is reachable from outside ✓"
        else
            warn "Port ${ASSIGNED_PORT} not reachable yet — may need a minute after restart"
        fi
    fi

    # Announced URIs
    blank
    echo -e "  ${BOLD}Lightning announced addresses${RESET}"
    # Derive node user and LN directory from the stored config path
    local _ln_dir _ln_user
    _ln_dir=$(dirname "${LN_CONF:-/dev/null}" 2>/dev/null)
    _ln_user=$(stat -c '%U' "${LN_CONF:-}" 2>/dev/null || echo "")
    case "${LIGHTNING:-lnd}" in
        lnd|lit)
            if command -v lncli &>/dev/null; then
                local _tls="${_ln_dir}/tls.cert"
                local _mac="${_ln_dir}/data/chain/bitcoin/mainnet/admin.macaroon"
                local _lncli_cmd="lncli"
                # Build flags for non-default paths if the files exist
                [[ -f "$_tls" ]] && _lncli_cmd+=" --tlscertpath $_tls"
                [[ -f "$_mac" ]] && _lncli_cmd+=" --macaroonpath $_mac"
                # Run as node user if we're root; otherwise run directly
                local _lncli_out
                if [[ -n "$_ln_user" && "$_ln_user" != "root" ]]; then
                    _lncli_out=$(sudo -u "$_ln_user" bash -c "$_lncli_cmd getinfo" 2>/dev/null || echo "")
                else
                    _lncli_out=$($_lncli_cmd getinfo 2>/dev/null || echo "")
                fi
                echo "$_lncli_out" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    uris=d.get('uris',[])
    [print('    '+u) for u in uris] if uris else print('    (none yet — give it a few minutes)')
except: print('    (lncli not accessible)')
"
            else
                info "lncli not found in PATH"
            fi
            ;;
        cln)
            if command -v lightning-cli &>/dev/null; then
                local _cln_out
                if [[ -n "$_ln_user" && "$_ln_user" != "root" ]]; then
                    _cln_out=$(sudo -u "$_ln_user" lightning-cli getinfo 2>/dev/null || echo "")
                else
                    _cln_out=$(lightning-cli getinfo 2>/dev/null || echo "")
                fi
                echo "$_cln_out" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    addrs=d.get('address',[])
    [print('    {}:{}'.format(a.get('address'),a.get('port'))) for a in addrs] if addrs else print('    (none yet)')
except: print('    (lightning-cli not accessible)')
"
            else
                info "lightning-cli not found in PATH"
            fi
            ;;
    esac

    blank; rule; blank
    ok "v${VERSION} · ${PLATFORM:-unknown} · ${LIGHTNING:-unknown}"
    blank
}

# ═══════════════════════════════════════════════════════════════════════════════
# RESTART
# ═══════════════════════════════════════════════════════════════════════════════

cmd_restart() {
    step "Restarting LNClear"
    local state="${LNCLEAR_STATE}/state.conf"
    if [[ -f "$state" ]]; then
        LN_SERVICE=$(  _state_get LN_SERVICE  "$state")
    fi

    # Re-detect if state file had incomplete values
    if [[ -z "${LN_SERVICE:-}" ]]; then
        local _impl
        _impl=$(detect_lightning)
        LN_SERVICE=$(get_ln_service "$_impl")
    fi

    warn "Stopping ${LN_SERVICE:-lnd} to prevent IP leak during tunnel restart..."
    systemctl stop "${LN_SERVICE:-lnd}" 2>/dev/null || true
    sleep 1

    info "Restarting WireGuard tunnel..."
    systemctl restart wg-quick@${WG_INTERFACE}
    sleep 2

    info "Starting ${LN_SERVICE:-lnd}..."
    systemctl start "${LN_SERVICE:-lnd}"
    ok "Done — run 'sudo bash lnclear.sh status' to verify"
}

# ═══════════════════════════════════════════════════════════════════════════════
# UNINSTALL
# ═══════════════════════════════════════════════════════════════════════════════

cmd_uninstall() {
    step "Uninstall LNClear"

    local state="${LNCLEAR_STATE}/state.conf"
    if [[ -f "$state" ]]; then
        PLATFORM=$(          _state_get PLATFORM        "$state")
        LIGHTNING=$(         _state_get LIGHTNING       "$state")
        LN_SERVICE=$(        _state_get LN_SERVICE      "$state")
        LN_CONF=$(           _state_get LN_CONF         "$state")
        BITCOIN_CORE_HOST=$( _state_get BITCOIN_CORE_HOST "$state")
    fi

    # Re-detect if state file had incomplete values (e.g. install ran with broken sudo detection)
    if [[ -z "${LIGHTNING:-}" || "${LIGHTNING:-}" == "unknown" ]] || \
       [[ -z "${LN_SERVICE:-}" ]] || [[ -z "${LN_CONF:-}" ]]; then
        detect_environment
        if [[ -z "${LIGHTNING:-}" || "${LIGHTNING:-}" == "unknown" ]]; then LIGHTNING="$ENV_IMPL"; fi
        if [[ -z "${LN_SERVICE:-}" ]]; then LN_SERVICE="$ENV_LN_SERVICE"; fi
        if [[ -z "${LN_CONF:-}" ]]; then LN_CONF="$ENV_LN_CONF"; fi
    fi

    blank
    echo -e "  This will:"
    echo -e "   ${RED}✗${RESET} Stop and remove the WireGuard tunnel (${WG_INTERFACE})"
    echo -e "   ${RED}✗${RESET} Remove cgroup split-tunnel, kill switch, and systemd overrides"
    echo -e "   ${GREEN}✓${RESET} Restore your original Lightning config from backup"
    echo -e "   ${GREEN}✓${RESET} Restart Lightning (Tor-only mode)"
    blank

    echo -ne "  ${BOLD}Continue with uninstall?${RESET} [y/N]  "
    local confirm
    read -r confirm
    blank
    [[ "$confirm" != "y" && "$confirm" != "Y" ]] && { info "Aborted."; exit 0; }

    # Stop Lightning
    info "Stopping ${LN_SERVICE:-lnd}..."
    timeout 30 systemctl stop "${LN_SERVICE:-lnd}" 2>/dev/null || true
    ok "Lightning stopped"

    # Stop WireGuard
    info "Stopping WireGuard tunnel..."
    timeout 30 systemctl stop wg-quick@${WG_INTERFACE} 2>/dev/null || true
    systemctl disable wg-quick@${WG_INTERFACE} 2>/dev/null || true
    # Read WG client IP before removing the config (needed for routing cleanup)
    local wg_client_ip
    wg_client_ip=$(grep -i '^Address' "${CONFIG_DIR}/${WG_INTERFACE}.conf" 2>/dev/null | \
        awk '{print $3}' | cut -d'/' -f1 | head -1)

    ip link delete ${WG_INTERFACE} 2>/dev/null || true
    rm -f "${CONFIG_DIR}/${WG_INTERFACE}.conf"
    ok "WireGuard removed"

    # Explicit routing cleanup (safety net if PostDown did not run)
    info "Cleaning up routing rules and table ${ROUTE_TABLE}..."
    ip rule del fwmark ${FWMARK} table ${ROUTE_TABLE} 2>/dev/null || true
    [[ -n "$wg_client_ip" ]] && ip rule del from "$wg_client_ip" table ${ROUTE_TABLE} 2>/dev/null || true
    ip rule del from all table main suppress_prefixlength 0 2>/dev/null || true
    ip route flush table ${ROUTE_TABLE} 2>/dev/null || true
    ok "Routing rules and table ${ROUTE_TABLE} cleared"

    # Remove nft tables (lnclear is torn down by WireGuard PostDown; clean up legacy tables too)
    info "Removing nftables rules..."
    nft delete table ip lnclear 2>/dev/null || true
    nft delete table ip lnclear_killswitch 2>/dev/null || true
    ok "nft tables removed"

    # Remove cgroup service and legacy artifacts
    info "Removing cgroup split-tunnel..."
    systemctl stop    lnclear-cgroup 2>/dev/null || true
    systemctl disable lnclear-cgroup 2>/dev/null || true
    rm -f /etc/systemd/system/lnclear-cgroup.service
    cgdelete -g net_cls:${CGROUP_NAME} 2>/dev/null || true
    # Remove legacy artifacts from older installs
    systemctl stop    lnclear-killswitch 2>/dev/null || true
    systemctl disable lnclear-killswitch 2>/dev/null || true
    rm -f /etc/systemd/system/lnclear-killswitch.service
    systemctl stop lnclear.slice 2>/dev/null || true
    rm -f /etc/systemd/system/lnclear.slice
    ok "cgroup split-tunnel removed"

    # Remove Lightning cgroup drop-in (check all possible service names)
    local ln_svc="${LN_SERVICE:-lnd}"
    for _svc in "$ln_svc" lnd lightningd cln litd lit; do
        rm -f "/etc/systemd/system/${_svc}.service.d/lnclear.conf"
        rmdir "/etc/systemd/system/${_svc}.service.d" 2>/dev/null || true
    done
    systemctl daemon-reload
    ok "Lightning cgroup override removed"

    # Restore Lightning config
    local ln_conf="${LN_CONF:-}"
    if [[ -n "$ln_conf" && -f "${ln_conf}${BACKUP_SUFFIX}" ]]; then
        cp "${ln_conf}${BACKUP_SUFFIX}" "$ln_conf"
        rm -f "${ln_conf}${BACKUP_SUFFIX}"
        ok "Lightning config restored and backup removed: $ln_conf"
    else
        warn "No backup found — remove the # BEGIN LNCLEAR ... # END LNCLEAR block manually"
    fi

    # Remove state
    rm -rf "$LNCLEAR_STATE"

    # Restart Lightning
    systemctl start "${LN_SERVICE:-lnd}" 2>/dev/null || warn "Restart ${LN_SERVICE:-lnd} manually"
    ok "Uninstall complete — node back to Tor-only mode"
    blank
}

# ═══════════════════════════════════════════════════════════════════════════════
# UPDATE SCRIPT
# ═══════════════════════════════════════════════════════════════════════════════

cmd_update() {
    step "Update lnclear.sh"
    warn "Auto-update disabled: downloading and executing unsigned scripts is unsafe."
    blank
    info "To update manually:"
    echo "  1. Download the latest script:"
    echo "     wget -O lnclear-new.sh ${SCRIPT_URL}"
    echo "  2. Verify the checksum matches what's published at ${LNCLEAR_URL}/checksums"
    echo "  3. Replace when satisfied:"
    echo "     chmod +x lnclear-new.sh && sudo mv lnclear-new.sh lnclear.sh"
    blank
}

# ═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

CMD="${1:-setup}"; shift || true

case "$CMD" in
    setup|"")  cmd_setup     "$@" ;;
    check)     cmd_check     "$@" ;;
    install)   cmd_install   "$@" ;;
    status)    cmd_status    "$@" ;;
    restart)   cmd_restart   "$@" ;;
    uninstall) cmd_uninstall "$@" ;;
    update)    cmd_update    "$@" ;;
    *)
        blank
        echo -e "  ${BOLD}lnclear.sh${RESET}  v${VERSION} — LNClear client script"
        blank
        echo "  sudo bash lnclear.sh              Interactive setup (recommended)"
        echo "  sudo bash lnclear.sh check        Pre-flight compatibility check"
        echo "  sudo bash lnclear.sh install      Install (non-interactive)"
        echo "  sudo bash lnclear.sh status       Show tunnel + node status"
        echo "  sudo bash lnclear.sh restart      Restart (safe: stops LN first)"
        echo "  sudo bash lnclear.sh uninstall    Remove and restore config"
        echo "  sudo bash lnclear.sh update       Update this script"
        blank
        echo "  Need your WireGuard config?  ${LNCLEAR_URL}/dashboard"
        blank
        ;;
esac