#!/usr/bin/env bash
# harden-vps.sh — optional post-install VPS hardening for Wattcloud.
#
# The standard install (install.sh → deploy-vps.sh) installs the app only.
# This script is what the operator runs *after* when they want Wattcloud's
# opinionated VPS hardening bundle. Equivalent of the old deploy-vps.sh
# phases A–C + E: SSH lockdown, UFW, fail2ban, unattended-upgrades, R5
# GDPR logging posture, swap sizing, earlyoom, disk-watchdog, AIDE, msmtp.
#
# Invoked via:
#   sudo wattcloud harden             # wizard (tty)
#   sudo wattcloud harden --yes       # accept defaults
#   sudo /opt/wattcloud/current/scripts/harden-vps.sh   # direct path
#
# Phases:
#   A. Collect prompts (tty) or read flags.
#   B. SSH hardening + UFW (with "both ports open until confirmed" safety).
#   C. Dependent hardening (fail2ban, unattended-upgrades, R5, swap, msmtp).
#   E. AIDE baseline.
#   F. Summary.
set -euo pipefail

# ---------------------------------------------------------------------------
# Bootstrap: locate script home + load lib.sh
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib.sh
source "$SCRIPT_DIR/lib.sh"

# ---------------------------------------------------------------------------
# Args & flags
# ---------------------------------------------------------------------------
usage() {
  cat <<'USAGE'
Usage: harden-vps.sh [DOMAIN] [flags]

Optional arg:
  DOMAIN                      FQDN (default: read from /etc/wattcloud/wattcloud.env)

Global flags:
  --email EMAIL               alert email (default: admin@DOMAIN)
  --yes, --non-interactive    accept all hardening defaults without prompting
  --ssh-port PORT             SSH port for hardening (default: 2222)
  --ssh-pubkey FILE|-         appuser authorized_keys contents (file or - for stdin)
  --help

Opt-out flags (all default ON with safety confirmations):
  --no-ufw                    skip UFW configuration
  --no-fail2ban               skip fail2ban installation
  --no-ssh-harden             skip SSH port change + config lockdown
  --no-unattended-upgrades    skip automatic security updates
  --no-r5-logging             skip GDPR logging posture (journald 30d retention, rsyslog off)
  --no-swap                   skip swap file creation
  --no-earlyoom               skip earlyoom install on low-RAM hosts (<8 GB)
  --no-disk-watchdog          skip wattcloud-disk-watchdog timer (root-fs usage alert)

Opt-in flags (default OFF):
  --with-aide                 install AIDE file integrity monitoring
  --with-msmtp SMTP_URL       configure msmtp relay for alerts
USAGE
}

DOMAIN=""
EMAIL=""
SSH_PORT="2222"
SSH_PUBKEY_SOURCE=""
NON_INTERACTIVE=0

OPT_UFW=1
OPT_FAIL2BAN=1
OPT_SSH_HARDEN=1
OPT_UNATTENDED=1
OPT_R5=1
OPT_SWAP=1
OPT_EARLYOOM=1
OPT_DISK_WATCHDOG=1
OPT_AIDE=0
OPT_MSMTP_URL=""
SWAP_SIZE_GB=0

while [ $# -gt 0 ]; do
  case "$1" in
    --email)                EMAIL="$2"; shift 2 ;;
    --ssh-port)             SSH_PORT="$2"; shift 2 ;;
    --ssh-pubkey)           SSH_PUBKEY_SOURCE="$2"; shift 2 ;;
    --yes|--non-interactive) NON_INTERACTIVE=1; shift ;;
    --no-ufw)               OPT_UFW=0; shift ;;
    --no-fail2ban)          OPT_FAIL2BAN=0; shift ;;
    --no-ssh-harden)        OPT_SSH_HARDEN=0; shift ;;
    --no-unattended-upgrades) OPT_UNATTENDED=0; shift ;;
    --no-r5-logging)        OPT_R5=0; shift ;;
    --no-swap)              OPT_SWAP=0; shift ;;
    --no-earlyoom)          OPT_EARLYOOM=0; shift ;;
    --no-disk-watchdog)     OPT_DISK_WATCHDOG=0; shift ;;
    --with-aide)            OPT_AIDE=1; shift ;;
    --with-msmtp)           OPT_MSMTP_URL="$2"; shift 2 ;;
    --help|-h)              usage; exit 0 ;;
    --*)                    warn "unknown flag ignored: $1"; shift ;;
    *)
      if [ -z "$DOMAIN" ]; then DOMAIN="$1"; shift
      else die "unexpected positional argument: $1"
      fi
      ;;
  esac
done

require_root

# Fall back to the installed env file so operators can just run
# `sudo wattcloud harden` with no args after install.sh.
if [ -z "$DOMAIN" ] && [ -f "$WC_ENV_FILE" ]; then
  DOMAIN="$(env_get BYO_DOMAIN "$WC_ENV_FILE")"
fi
[ -n "$DOMAIN" ] || { err "DOMAIN not supplied and BYO_DOMAIN missing from $WC_ENV_FILE"; usage; exit 1; }
[ -z "$EMAIL" ] && EMAIL="admin@$DOMAIN"

# ---------------------------------------------------------------------------
# Phase A: collect prompts (tty only)
# ---------------------------------------------------------------------------
ask_yn() {
  # ask_yn PROMPT DEFAULT(Y|N)  → echoes "Y" or "N"
  local prompt="$1" default="${2:-Y}" ans
  if [ "$NON_INTERACTIVE" -eq 1 ] || [ ! -t 0 ]; then
    echo "$default"; return
  fi
  local hint; [ "$default" = "Y" ] && hint="[Y/n]" || hint="[y/N]"
  printf '  %s %s: ' "$prompt" "$hint" >&2
  read -r ans
  case "${ans,,}" in
    y|yes) echo "Y" ;;
    n|no)  echo "N" ;;
    *)     echo "$default" ;;
  esac
}

ROOT_AUTH_KEYS_HAS_ED25519=0
if [ -f /root/.ssh/authorized_keys ] \
   && grep -qE '^(ssh-ed25519|sk-ssh-ed25519@openssh\.com) ' /root/.ssh/authorized_keys; then
  ROOT_AUTH_KEYS_HAS_ED25519=1
fi

phase_a_collect_prompts() {
  info "Phase A: collecting configuration (tty=${NON_INTERACTIVE})..."
  echo "" >&2

  if [ "$OPT_SSH_HARDEN" -eq 1 ]; then
    if [ "$ROOT_AUTH_KEYS_HAS_ED25519" -eq 0 ] && [ -z "$SSH_PUBKEY_SOURCE" ]; then
      warn "/root/.ssh/authorized_keys has no ed25519 key and --ssh-pubkey not supplied."
      warn "Defaulting SSH hardening to OFF to avoid lockout."
      OPT_SSH_HARDEN=0
    fi
  fi

  if [ "$OPT_UFW" -eq 1 ]; then
    [ "$(ask_yn "Configure UFW firewall (ingress allow-list on ${SSH_PORT}, 80, 443)?" Y)" = "Y" ] || OPT_UFW=0
  fi
  if [ "$OPT_FAIL2BAN" -eq 1 ]; then
    [ "$(ask_yn "Install fail2ban (sshd jail + recidive)?" Y)" = "Y" ] || OPT_FAIL2BAN=0
  fi
  if [ "$OPT_SSH_HARDEN" -eq 1 ]; then
    echo "  SSH hardening will change port from 22 → ${SSH_PORT}, disable root & password auth." >&2
    [ "$(ask_yn "Apply SSH hardening?" Y)" = "Y" ] || OPT_SSH_HARDEN=0
  fi
  if [ "$OPT_UNATTENDED" -eq 1 ]; then
    [ "$(ask_yn "Enable unattended security updates?" Y)" = "Y" ] || OPT_UNATTENDED=0
  fi
  if [ "$OPT_R5" -eq 1 ]; then
    echo "  R5 GDPR posture: journald persistent (500M / 30 days), rsyslog off," >&2
    echo "  fail2ban reads auth events from systemd. Keeps sshd source IPs only" >&2
    echo "  long enough for ban-decay (30 days), nothing else persists them." >&2
    [ "$(ask_yn "Enable R5 GDPR-bounded logging posture?" Y)" = "Y" ] || OPT_R5=0
  fi
  local ram_mb
  ram_mb=$(($(grep MemTotal /proc/meminfo | awk '{print $2}') / 1024))

  if [ "$OPT_SWAP" -eq 1 ]; then
    # Size = min(ceil(ram_gb), 4). Clamp to [1, 4] GB.
    SWAP_SIZE_GB=$(( (ram_mb + 1023) / 1024 ))
    [ "$SWAP_SIZE_GB" -gt 4 ] && SWAP_SIZE_GB=4
    [ "$SWAP_SIZE_GB" -lt 1 ] && SWAP_SIZE_GB=1
    if [ "$ram_mb" -lt 8192 ] && [ ! -f /swapfile ]; then
      [ "$(ask_yn "Create ${SWAP_SIZE_GB}GB swap file + vm.swappiness=10 (RAM=${ram_mb}MB)?" Y)" = "Y" ] || OPT_SWAP=0
    else
      OPT_SWAP=0
    fi
  fi
  if [ "$OPT_EARLYOOM" -eq 1 ]; then
    # Only useful on low-RAM hosts; skip on anything >= 8 GB.
    if [ "$ram_mb" -lt 8192 ] && ! systemctl is-active --quiet systemd-oomd 2>/dev/null; then
      [ "$(ask_yn "Install earlyoom as low-memory safety net (RAM=${ram_mb}MB)?" Y)" = "Y" ] || OPT_EARLYOOM=0
    else
      OPT_EARLYOOM=0
    fi
  fi
  if [ "$OPT_DISK_WATCHDOG" -eq 1 ]; then
    [ "$(ask_yn "Install wattcloud-disk-watchdog timer (alerts at 80% root-fs use)?" Y)" = "Y" ] || OPT_DISK_WATCHDOG=0
  fi
  if [ "$OPT_AIDE" -eq 0 ]; then
    [ "$(ask_yn "Install AIDE file integrity monitoring?" N)" = "Y" ] && OPT_AIDE=1
  fi
  if [ -z "$OPT_MSMTP_URL" ] && [ "$NON_INTERACTIVE" -eq 0 ] && [ -t 0 ]; then
    if [ "$(ask_yn "Configure msmtp relay for alerts?" N)" = "Y" ]; then
      printf '    SMTP URL (smtp[s]://user:pass@host:port): ' >&2
      read -r OPT_MSMTP_URL
    fi
  fi

  echo "" >&2
}

# ---------------------------------------------------------------------------
# Phase B: SSH + UFW safe sequence
# ---------------------------------------------------------------------------
SSHD_BACKUP="/etc/ssh/sshd_config.bak.wattcloud"
SSHD_DROPIN="/etc/ssh/sshd_config.d/99-wattcloud.conf"
SSH_SAFETY_TRIPPED=0

sshd_safety_restore() {
  # Restore previous sshd config and reopen port 22 on failure. Idempotent.
  SSH_SAFETY_TRIPPED=1
  warn "SSH safety net engaged — restoring sshd config and reopening port 22."
  [ -f "$SSHD_DROPIN" ] && rm -f "$SSHD_DROPIN"
  [ -f "$SSHD_BACKUP" ] && cp "$SSHD_BACKUP" /etc/ssh/sshd_config
  systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow 22/tcp >/dev/null 2>&1 || true
  fi
}

phase_b_ssh_ufw() {
  info "Phase B: SSH + UFW safe sequence."

  # Install appuser first (no SSH impact yet).
  if ! id appuser >/dev/null 2>&1; then
    useradd -u 1000 -m -s /bin/bash appuser
    passwd -l appuser >/dev/null
    ok "Created appuser (UID 1000, password locked)."
  else
    ok "appuser already exists."
  fi

  # Resolve pubkey source.
  local pubkey=""
  if [ -n "$SSH_PUBKEY_SOURCE" ]; then
    if [ "$SSH_PUBKEY_SOURCE" = "-" ]; then pubkey="$(cat)"
    elif [ -f "$SSH_PUBKEY_SOURCE" ]; then pubkey="$(cat "$SSH_PUBKEY_SOURCE")"
    else die "--ssh-pubkey: file not found: $SSH_PUBKEY_SOURCE"
    fi
  elif [ "$ROOT_AUTH_KEYS_HAS_ED25519" -eq 1 ]; then
    pubkey="$(grep -E '^(ssh-ed25519|sk-ssh-ed25519@openssh\.com) ' /root/.ssh/authorized_keys)"
    ok "Reusing root's ed25519 key(s) for appuser."
  fi
  if [ -n "$pubkey" ]; then
    install -d -m 0700 -o appuser -g appuser /home/appuser/.ssh
    echo "$pubkey" > /home/appuser/.ssh/authorized_keys
    chmod 600 /home/appuser/.ssh/authorized_keys
    chown appuser:appuser /home/appuser/.ssh/authorized_keys
    ok "appuser authorized_keys installed."
  else
    warn "No SSH pubkey available for appuser — appuser will be inaccessible until you add one."
  fi

  if [ "$OPT_SSH_HARDEN" -eq 0 ] && [ "$OPT_UFW" -eq 0 ]; then
    ok "Both SSH hardening and UFW disabled — skipping Phase B."
    return 0
  fi

  # --- Write sshd config (not applied yet) ---
  if [ "$OPT_SSH_HARDEN" -eq 1 ]; then
    [ -f "$SSHD_BACKUP" ] || cp /etc/ssh/sshd_config "$SSHD_BACKUP"
    sed -i "s/^#\?Port .*/Port $SSH_PORT/" /etc/ssh/sshd_config
    mkdir -p /etc/ssh/sshd_config.d
    cat > "$SSHD_DROPIN" <<SSHD
# Managed by Wattcloud harden-vps.sh — do not edit manually.
PermitRootLogin no
PasswordAuthentication no
PubkeyAcceptedKeyTypes ssh-ed25519,sk-ssh-ed25519@openssh.com
AllowUsers appuser
MaxAuthTries 3
LoginGraceTime 30
PermitEmptyPasswords no
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowAgentForwarding no
SSHD
    if ! sshd -t 2>/dev/null; then
      sshd_safety_restore
      die "sshd config validation failed — aborted before touching UFW."
    fi
    ok "sshd config written + validated (not applied yet)."
  fi

  # --- Install + configure UFW with BOTH 22 and $SSH_PORT open ---
  if [ "$OPT_UFW" -eq 1 ]; then
    apt-get install -y -qq ufw >/dev/null
    trap sshd_safety_restore ERR
    ufw default deny incoming  >/dev/null 2>&1
    ufw default allow outgoing >/dev/null 2>&1
    ufw allow 22/tcp           >/dev/null 2>&1
    ufw allow "$SSH_PORT"/tcp  >/dev/null 2>&1
    ufw allow 80/tcp           >/dev/null 2>&1
    ufw allow 443/tcp          >/dev/null 2>&1
    ufw logging off            >/dev/null 2>&1 || true
    ufw --force enable         >/dev/null 2>&1
    ok "UFW configured with BOTH 22 and $SSH_PORT open (transitional)."
  fi

  # --- Apply sshd config (restart) ---
  if [ "$OPT_SSH_HARDEN" -eq 1 ]; then
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || {
      sshd_safety_restore
      die "sshd restart failed — safety net engaged."
    }
    sleep 1
    if ! ss -Hlntp "( sport = :$SSH_PORT )" 2>/dev/null | grep -q sshd; then
      sshd_safety_restore
      die "sshd is not listening on port $SSH_PORT after restart — safety net engaged."
    fi
    ok "sshd now listening on port $SSH_PORT."
    trap - ERR

    # --- Confirm new port + close 22 ---
    local close_22="N"
    if [ "$NON_INTERACTIVE" -eq 0 ] && [ -t 0 ]; then
      echo "" >&2
      echo "  ** ACTION REQUIRED: open a second terminal and verify:" >&2
      echo "       ssh -p $SSH_PORT appuser@$DOMAIN" >&2
      echo "" >&2
      close_22="$(ask_yn "Does the new port work?" Y)"
    fi
    if [ "$close_22" = "Y" ] && [ "$OPT_UFW" -eq 1 ]; then
      ufw delete allow 22/tcp >/dev/null 2>&1 || true
      ok "Port 22 closed in UFW."
    else
      warn "Port 22 LEFT OPEN in UFW. After verifying port $SSH_PORT works, close it with:"
      warn "  sudo ufw delete allow 22/tcp"
    fi
  fi
}

# ---------------------------------------------------------------------------
# Phase C: dependent hardening
# ---------------------------------------------------------------------------
phase_c_hardening() {
  info "Phase C: dependent hardening."

  timedatectl set-timezone UTC 2>/dev/null || true

  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl gnupg >/dev/null

  if [ "$OPT_UNATTENDED" -eq 1 ]; then
    apt-get install -y -qq unattended-upgrades apt-listchanges >/dev/null
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<AUTO
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
AUTO
    cat > /etc/apt/apt.conf.d/50unattended-upgrades <<AUTO
Unattended-Upgrade::Mail "$EMAIL";
Unattended-Upgrade::MailReport "on-change";
Unattended-Upgrade::Automatic-Reboot "false";
AUTO
    ok "Unattended security updates configured (alerts → $EMAIL)."
  fi

  if [ "$OPT_FAIL2BAN" -eq 1 ]; then
    apt-get install -y -qq fail2ban >/dev/null
    local sender; sender="alerts@$DOMAIN"
    cat > /etc/fail2ban/jail.local <<JAIL
[DEFAULT]
destemail = $EMAIL
sender    = $sender
action    = %(action_mwl)s

[sshd]
enabled  = true
backend  = systemd
port     = $SSH_PORT
filter   = sshd
maxretry = 5
bantime  = 3600
findtime = 600

[recidive]
enabled  = true
logpath  = /var/log/fail2ban.log
maxretry = 3
bantime  = 86400
findtime = 86400
JAIL
    systemctl enable fail2ban >/dev/null 2>&1
    systemctl restart fail2ban
    ok "fail2ban configured (sshd + recidive, alerts → $EMAIL)."
  fi

  if [ "$OPT_R5" -eq 1 ]; then
    # Journald: persistent, 30-day retention, 500M cap. GDPR exposure for
    # IP-bearing sshd auth events is bounded by MaxRetentionSec — which is
    # also what fail2ban's ban window reads against (backend=systemd below).
    mkdir -p /etc/systemd/journald.conf.d
    rm -f /etc/systemd/journald.conf.d/wattcloud-volatile.conf
    cat > /etc/systemd/journald.conf.d/wattcloud-retention.conf <<JOURNAL
[Journal]
Storage=persistent
SystemMaxUse=500M
MaxRetentionSec=30day
ForwardToSyslog=no
JOURNAL
    systemctl restart systemd-journald 2>/dev/null || true

    # Martian-packet log suppression — IP-bearing kernel noise, no value.
    cat > /etc/sysctl.d/99-wattcloud-nolog.conf <<SYSCTL
net.ipv4.conf.all.log_martians = 0
net.ipv4.conf.default.log_martians = 0
SYSCTL
    sysctl --system >/dev/null 2>&1 || true

    # rsyslog stays off; fail2ban reads from systemd journal directly.
    if systemctl is-active rsyslog >/dev/null 2>&1; then
      systemctl disable --now rsyslog >/dev/null 2>&1 || true
    fi
    ok "R5 GDPR posture applied (journald persistent 500M/30d, rsyslog off)."
  fi

  if [ "$OPT_SWAP" -eq 1 ] && [ ! -f /swapfile ]; then
    fallocate -l "${SWAP_SIZE_GB}G" /swapfile \
      || dd if=/dev/zero of=/swapfile bs=1M count=$((SWAP_SIZE_GB * 1024)) status=none
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null
    swapon /swapfile
    grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
    cat > /etc/sysctl.d/99-wattcloud-swap.conf <<SYSCTL
vm.swappiness=10
vm.vfs_cache_pressure=50
SYSCTL
    sysctl -p /etc/sysctl.d/99-wattcloud-swap.conf >/dev/null 2>&1 || true
    ok "${SWAP_SIZE_GB}GB swap file created + swappiness tuned."
  fi

  if [ "$OPT_EARLYOOM" -eq 1 ] && ! command -v earlyoom >/dev/null 2>&1; then
    apt-get install -y -qq earlyoom >/dev/null
    systemctl enable --now earlyoom >/dev/null 2>&1 || true
    ok "earlyoom installed + enabled (kills fattest process at <10% free before kernel OOM)."
  elif [ "$OPT_EARLYOOM" -eq 1 ]; then
    systemctl enable --now earlyoom >/dev/null 2>&1 || true
    ok "earlyoom already installed — enabled."
  fi

  if [ "$OPT_DISK_WATCHDOG" -eq 1 ]; then
    cat > /usr/local/sbin/wattcloud-disk-watchdog.sh <<'WATCH'
#!/bin/bash
# wattcloud-disk-watchdog — installed by harden-vps.sh.
# Logs a daemon.warning to journald/syslog when root-fs exceeds THRESHOLD.
# Operators can tail via:  journalctl -t wattcloud-disk-watchdog -f
THRESHOLD=80
USE=$(df --output=pcent / | tail -1 | tr -dc '0-9')
if [ "${USE:-0}" -ge "$THRESHOLD" ]; then
  logger -p daemon.warning -t wattcloud-disk-watchdog \
    "Root filesystem at ${USE}% (threshold ${THRESHOLD}%)"
  exit 1
fi
exit 0
WATCH
    chmod +x /usr/local/sbin/wattcloud-disk-watchdog.sh
    cat > /etc/systemd/system/wattcloud-disk-watchdog.service <<UNIT
[Unit]
Description=Wattcloud root-fs usage check
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/wattcloud-disk-watchdog.sh
UNIT
    cat > /etc/systemd/system/wattcloud-disk-watchdog.timer <<UNIT
[Unit]
Description=Run wattcloud-disk-watchdog every 10 min

[Timer]
OnBootSec=5min
OnUnitActiveSec=10min
Persistent=true

[Install]
WantedBy=timers.target
UNIT
    systemctl daemon-reload
    systemctl enable --now wattcloud-disk-watchdog.timer >/dev/null 2>&1
    ok "wattcloud-disk-watchdog timer enabled (threshold=80%, every 10 min)."
  fi

  if [ -n "$OPT_MSMTP_URL" ]; then
    apt-get install -y -qq msmtp msmtp-mta bsd-mailx >/dev/null
    # URL → host/port/user/pass/tls
    local proto rest host port user pass
    proto="${OPT_MSMTP_URL%%://*}"
    rest="${OPT_MSMTP_URL#*://}"
    user="${rest%%:*}"; rest="${rest#*:}"
    pass="${rest%%@*}"; rest="${rest#*@}"
    host="${rest%%:*}"; port="${rest##*:}"
    [ "$port" = "$rest" ] && port="587"
    cat > /etc/msmtprc <<MSMTP
defaults
auth on
tls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
account default
host $host
port $port
from $EMAIL
user $user
password $pass
account default : default
MSMTP
    chmod 600 /etc/msmtprc; chown root:root /etc/msmtprc
    ok "msmtp configured (proto=$proto host=$host port=$port)."
  fi
}

# ---------------------------------------------------------------------------
# Phase E: AIDE baseline (run after app is already installed — so
# /var/lib/wattcloud is in the baseline if present).
# ---------------------------------------------------------------------------
phase_e_aide() {
  [ "$OPT_AIDE" -eq 1 ] || return 0
  info "Phase E: AIDE baseline."
  apt-get install -y -qq aide >/dev/null
  if [ ! -f /var/lib/aide/aide.db ]; then
    info "Building AIDE baseline (~5 minutes)..."
    aideinit -y >/dev/null 2>&1 || true
    [ -f /var/lib/aide/aide.db.new ] && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    cp /var/lib/aide/aide.db /var/lib/aide/aide.db.golden 2>/dev/null || true
    ok "AIDE baseline built (includes /opt/wattcloud + /var/lib/wattcloud)."
  else
    ok "AIDE baseline already exists — skipping re-init."
  fi

  cat > /etc/cron.daily/aide-check <<'AIDE'
#!/bin/sh
set -eu
out=$(mktemp); trap 'rm -f "$out"' EXIT
if ! aide --check > "$out" 2>&1; then
  [ -x /usr/bin/mail ] && mail -s "AIDE diff on $(hostname)" root < "$out" || true
fi
AIDE
  chmod 755 /etc/cron.daily/aide-check
  ok "AIDE daily-diff cron installed."
}

# ---------------------------------------------------------------------------
# Phase F: summary
# ---------------------------------------------------------------------------
phase_f_summary() {
  local port22_open=0
  if [ "$OPT_UFW" -eq 1 ] && ufw status 2>/dev/null | grep -qE '^22/tcp\s+ALLOW'; then
    port22_open=1
  fi

  echo "" >&2
  printf '%s\n' "$(_color '0;32' '============================================')" >&2
  printf '%s\n' "$(_color '0;32' ' Wattcloud VPS hardened')" >&2
  printf '%s\n' "$(_color '0;32' '============================================')" >&2
  echo "  domain:           $DOMAIN" >&2
  echo "  SSH port:         $SSH_PORT (hardened=$([ $OPT_SSH_HARDEN -eq 1 ] && echo yes || echo no))" >&2
  echo "  UFW:              $([ $OPT_UFW -eq 1 ] && echo enabled || echo skipped)" >&2
  echo "  fail2ban:         $([ $OPT_FAIL2BAN -eq 1 ] && echo enabled || echo skipped)" >&2
  echo "  unattended-upg:   $([ $OPT_UNATTENDED -eq 1 ] && echo enabled || echo skipped)" >&2
  echo "  R5 logging:       $([ $OPT_R5 -eq 1 ] && echo applied || echo skipped)" >&2
  echo "  swap:             $([ $OPT_SWAP -eq 1 ] && echo "${SWAP_SIZE_GB}G" || echo skipped)" >&2
  echo "  earlyoom:         $([ $OPT_EARLYOOM -eq 1 ] && echo enabled || echo skipped)" >&2
  echo "  disk-watchdog:    $([ $OPT_DISK_WATCHDOG -eq 1 ] && echo enabled || echo skipped)" >&2
  echo "  AIDE:             $([ $OPT_AIDE -eq 1 ] && echo enabled || echo skipped)" >&2
  echo "  msmtp:            $([ -n "$OPT_MSMTP_URL" ] && echo configured || echo skipped)" >&2
  echo "" >&2

  if [ "$port22_open" -eq 1 ]; then
    printf '%s\n' "$(_color '0;31' '  !! Port 22 is still open in UFW. Close it once you have confirmed SSH')" >&2
    printf '%s\n' "$(_color '0;31' "     on port $SSH_PORT works:  sudo ufw delete allow 22/tcp")" >&2
    echo "" >&2
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
info "Wattcloud harden-vps.sh starting — domain=$DOMAIN"

phase_a_collect_prompts
phase_b_ssh_ufw
phase_c_hardening
phase_e_aide
phase_f_summary

ok "Hardening complete."
