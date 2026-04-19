#!/usr/bin/env bash
# =============================================================================
# harden-dev.sh — Harden a dev machine running Ubuntu 22.04 or 24.04
#
# Idempotent: safe to re-run on a machine that is already hardened.
# Also safe to run on a factory-clean Ubuntu image to reach a hardened state.
#
# Usage: sudo bash harden-dev.sh [ALERT_EMAIL] [SSH_PORT] [SSH_PUBKEY]
#
# Env overrides for non-interactive (re-)runs:
#   ALERT_SMTP_HOST, ALERT_SMTP_PORT, ALERT_SMTP_USER, ALERT_SMTP_PASS
#   FORCE_AIDE_REBASELINE=1  — force rebuild of AIDE baseline DB
# =============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*"; }
die()   { err "$@"; exit 1; }

# ---------------------------------------------------------------------------
# Parameters
# ---------------------------------------------------------------------------
ALERT_EMAIL="${1:-}"
SSH_PORT="${2:-2222}"
SSH_PUBKEY="${3:-}"

ALERT_SMTP_HOST="${ALERT_SMTP_HOST:-}"
ALERT_SMTP_PORT="${ALERT_SMTP_PORT:-587}"
ALERT_SMTP_USER="${ALERT_SMTP_USER:-}"
ALERT_SMTP_PASS="${ALERT_SMTP_PASS:-}"
# SPF/DMARC-safe From address for alert mail. Must be a real email on the relay
# domain. Defaults to ALERT_SMTP_USER when it looks like an email; otherwise
# prompted (or set via ALERT_FROM env var for non-interactive runs).
ALERT_FROM="${ALERT_FROM:-}"
FORCE_AIDE_REBASELINE="${FORCE_AIDE_REBASELINE:-0}"

# ---------------------------------------------------------------------------
# Step 1: Preflight — root, Ubuntu version, timezone
# ---------------------------------------------------------------------------
info "Step 1: Preflight checks..."

if [ "$(id -u)" -ne 0 ]; then
  die "This script must be run as root (sudo bash $0)."
fi

CODENAME=$(. /etc/os-release && echo "${VERSION_CODENAME:-unknown}")
if [ "$CODENAME" != "jammy" ] && [ "$CODENAME" != "noble" ]; then
  die "Unsupported OS codename '$CODENAME'. This script supports Ubuntu 22.04 (jammy) and 24.04 (noble)."
fi
ok "OS: Ubuntu $CODENAME"

VIRT=$(systemd-detect-virt 2>/dev/null || echo "none")
info "Virtualisation: $VIRT"

timedatectl set-timezone UTC 2>/dev/null || true
ok "Timezone: UTC"

# Prompt for missing parameters
if [ -z "$ALERT_EMAIL" ] && [ -t 0 ]; then
  printf "Alert email address (for fail2ban/upgrades/AIDE/rkhunter): "
  read -r ALERT_EMAIL
fi
[ -z "$ALERT_EMAIL" ] && die "ALERT_EMAIL is required."

if [ -z "$SSH_PUBKEY" ] && [ -t 0 ]; then
  echo ""
  echo "Paste the ed25519 public key to install for appuser"
  echo "(starts with 'ssh-ed25519' or 'sk-ssh-ed25519@openssh.com'; leave blank to skip):"
  read -r SSH_PUBKEY
fi

# ---------------------------------------------------------------------------
# Step 2: Package updates + unattended-upgrades
# ---------------------------------------------------------------------------
info "Step 2: Package updates..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get upgrade -y -qq
apt-get install -y -qq unattended-upgrades apt-listchanges needrestart ca-certificates curl gnupg git > /dev/null

cat > /etc/apt/apt.conf.d/20auto-upgrades <<'AUTOUPGRADE'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
AUTOUPGRADE

cat > /etc/apt/apt.conf.d/50unattended-upgrades <<AUTOUPGRADE50
Unattended-Upgrade::Mail "$ALERT_EMAIL";
Unattended-Upgrade::MailReport "on-change";
Unattended-Upgrade::Automatic-Reboot "false";
AUTOUPGRADE50
ok "Packages updated; unattended-upgrades configured."

# ---------------------------------------------------------------------------
# Step 3: Docker  [before appuser — creates docker group]
# ---------------------------------------------------------------------------
info "Step 3: Docker..."
if command -v docker &>/dev/null; then
  ok "Docker already installed: $(docker --version)"
else
  install -m 0755 -d /etc/apt/keyrings
  if [ ! -f /etc/apt/keyrings/docker.gpg ]; then
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
  fi
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
    $CODENAME stable" > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin > /dev/null
  ok "Docker installed."
fi

mkdir -p /etc/docker
cat > /etc/docker/daemon.json <<'DAEMON'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
DAEMON

systemctl enable --now docker > /dev/null 2>&1
ok "Docker running with log rotation."

# ---------------------------------------------------------------------------
# Step 4: Create appuser  [after Docker — docker group now exists]
# ---------------------------------------------------------------------------
info "Step 4: appuser setup..."
if id appuser &>/dev/null; then
  ok "appuser already exists."
else
  useradd -u 1000 -m -s /bin/bash appuser
  ok "appuser created (UID 1000)."
fi
passwd -l appuser > /dev/null 2>&1
usermod -aG docker appuser
ok "appuser: password locked, docker group added."

# ---------------------------------------------------------------------------
# Step 5: Install SSH pubkey for appuser
# ---------------------------------------------------------------------------
info "Step 5: appuser SSH pubkey..."
if [ -n "$SSH_PUBKEY" ]; then
  if ! echo "$SSH_PUBKEY" | grep -qE "^(ssh-ed25519|sk-ssh-ed25519@openssh\.com) AAAA"; then
    die "SSH_PUBKEY must be a valid ed25519 public key."
  fi
  install -d -m 700 -o appuser -g appuser /home/appuser/.ssh
  if ! grep -qF "$SSH_PUBKEY" /home/appuser/.ssh/authorized_keys 2>/dev/null; then
    echo "$SSH_PUBKEY" >> /home/appuser/.ssh/authorized_keys
    chown appuser:appuser /home/appuser/.ssh/authorized_keys
    chmod 600 /home/appuser/.ssh/authorized_keys
    ok "SSH pubkey added to authorized_keys."
  else
    ok "SSH pubkey already in authorized_keys."
  fi
else
  warn "No SSH pubkey provided — skipping authorized_keys update."
fi

# ---------------------------------------------------------------------------
# Step 6: UFW  [before sshd restart — opens new port first]
# ---------------------------------------------------------------------------
info "Step 6: UFW..."
apt-get install -y -qq ufw > /dev/null
ufw default deny incoming > /dev/null 2>&1
ufw default allow outgoing > /dev/null 2>&1

# Allow SSH port before enabling (lockout prevention)
ufw allow "$SSH_PORT"/tcp > /dev/null 2>&1
# Keep 80/443 open for test deployments on the dev machine
ufw allow 80/tcp > /dev/null 2>&1
ufw allow 443/tcp > /dev/null 2>&1
ufw logging low > /dev/null 2>&1 || true
ufw --force enable > /dev/null 2>&1
ok "UFW enabled (ports $SSH_PORT, 80, 443; default deny inbound)."

# ---------------------------------------------------------------------------
# Step 7: SSH hardening  [after UFW]
# ---------------------------------------------------------------------------
info "Step 7: SSH hardening (port=$SSH_PORT)..."

if [ ! -f /etc/ssh/sshd_config.bak ]; then
  cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
  ok "sshd_config backed up."
fi

mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/99-dev-hardening.conf <<SSHD
# Managed by harden-dev.sh — do not edit manually
Port $SSH_PORT
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
AllowTcpForwarding local
SSHD

sshd -t || die "sshd config test failed — check /etc/ssh/sshd_config.d/99-dev-hardening.conf"
systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
ok "SSH hardened (port=$SSH_PORT, ed25519-only, appuser-only, no agent forwarding)."

# ---------------------------------------------------------------------------
# Step 8: fail2ban
# ---------------------------------------------------------------------------
info "Step 8: fail2ban..."
apt-get install -y -qq fail2ban > /dev/null

FAIL2BAN_SENDER="${ALERT_SMTP_USER:-root@$(hostname)}"
cat > /etc/fail2ban/jail.local <<JAIL
[DEFAULT]
destemail = $ALERT_EMAIL
sender    = $FAIL2BAN_SENDER
action    = %(action_mwl)s

[sshd]
enabled  = true
port     = $SSH_PORT
filter   = sshd
logpath  = /var/log/auth.log
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

systemctl enable fail2ban > /dev/null 2>&1
systemctl restart fail2ban
ok "fail2ban configured (sshd + recidive; alerts → $ALERT_EMAIL)."

# ---------------------------------------------------------------------------
# Step 9: Kernel hardening
# ---------------------------------------------------------------------------
info "Step 9: Kernel hardening..."
cat > /etc/sysctl.d/99-dev-hardening.conf <<'SYSCTL'
# Kernel info exposure
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2

# ptrace scope: parent-only (2) — blocks malware PTRACE_ATTACH on ssh-agent.
# This is the main mitigation for "active malware on dev machine" threat.
kernel.yama.ptrace_scope = 2

# BPF hardening
kernel.unprivileged_bpf_disabled = 2

# NOTE: kernel.unprivileged_userns_clone is intentionally NOT set to 0.
# Ubuntu 24.04 relies on unprivileged userns for snap confinement, Chrome
# sandbox, bwrap, and container runtimes. Disabling it would break sandbox
# isolation of untrusted code — the opposite of the intended defence.

# Network hardening
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
SYSCTL

sysctl --system > /dev/null 2>&1 || true
ok "Kernel hardening applied."

# ---------------------------------------------------------------------------
# Step 10: auditd
# ---------------------------------------------------------------------------
info "Step 10: auditd..."
apt-get install -y -qq auditd audispd-plugins > /dev/null

cat > /etc/audit/rules.d/dev-hardening.rules <<'AUDITRULES'
# Dev-machine audit rules — managed by harden-dev.sh

# Privileged execution
-a always,exit -F arch=b64 -S execve -F euid=0 -k privileged_exec
-a always,exit -F arch=b32 -S execve -F euid=0 -k privileged_exec

# setuid/setgid
-a always,exit -F arch=b64 -S setuid -S setgid -k setuid_setgid
-a always,exit -F arch=b32 -S setuid -S setgid -k setuid_setgid

# Sensitive file access
-w /etc/shadow -p wa -k shadow
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/sshd_config.d/ -p wa -k sshd_config
-w /var/log/auth.log -p wa -k auth_log

# appuser SSH keys (explicit path — audit watches do not expand ~)
-w /home/appuser/.ssh/ -p wa -k appuser_ssh_keys
AUDITRULES

augenrules --load > /dev/null 2>&1 || true
systemctl enable auditd > /dev/null 2>&1
systemctl restart auditd 2>/dev/null || true
ok "auditd configured with dev-hardening rules."

# ---------------------------------------------------------------------------
# Step 11: AppArmor
# ---------------------------------------------------------------------------
info "Step 11: AppArmor..."
apt-get install -y -qq apparmor-utils > /dev/null

systemctl enable apparmor > /dev/null 2>&1
systemctl start apparmor 2>/dev/null || true
# Log current status only — do NOT enforce all profiles with aa-enforce /etc/apparmor.d/*
# because that promotes intentionally-complain-mode profiles (snap, libvirt, etc.) and
# breaks sandboxes of untrusted code running on this machine.
aa-status --pretty-print 2>/dev/null | head -10 || aa-status 2>/dev/null | head -5 || true
ok "AppArmor running with default profiles."

# ---------------------------------------------------------------------------
# Step 12: AIDE  [file integrity]
# ---------------------------------------------------------------------------
info "Step 12: AIDE..."
apt-get install -y -qq aide > /dev/null

# Store ALERT_EMAIL for cron scripts
cat > /etc/secure-cloud-deploy.conf <<DEPLOYCONF
# Written by harden-dev.sh — used by cron alert scripts
ALERT_EMAIL=$ALERT_EMAIL
DEPLOYCONF
chmod 644 /etc/secure-cloud-deploy.conf

# Daily cron: mail only when aide finds changes (exit non-zero = diff found)
cat > /etc/cron.daily/aide-check <<'AIDECRON'
#!/bin/sh
set -eu
. /etc/secure-cloud-deploy.conf 2>/dev/null || ALERT_EMAIL=root
out=$(mktemp)
trap 'rm -f "$out"' EXIT
if ! aide --check > "$out" 2>&1; then
    mail -s "AIDE diff on $(hostname)" "$ALERT_EMAIL" < "$out"
fi
AIDECRON
chmod 755 /etc/cron.daily/aide-check

# DPkg::Post-Invoke: auto-rebaseline after apt changes to prevent false-positive floods
cat > /etc/apt/apt.conf.d/99-aide-rebaseline <<'AIDEAPT'
DPkg::Post-Invoke { "if [ -x /usr/bin/aide ]; then /usr/bin/aide --update >/dev/null 2>&1 && mv -f /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null || true; fi"; };
AIDEAPT

if [ ! -f /var/lib/aide/aide.db ] || [ "$FORCE_AIDE_REBASELINE" = "1" ]; then
  info "Building AIDE baseline — this takes ~5-15 minutes on a loaded machine..."
  aideinit -y > /dev/null 2>&1 || true
  if [ -f /var/lib/aide/aide.db.new ]; then
    mv -f /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    ok "AIDE baseline built."
  else
    warn "AIDE aideinit produced no DB — run 'aideinit' manually after the script."
  fi
else
  ok "AIDE baseline exists — skipping (set FORCE_AIDE_REBASELINE=1 to rebuild)."
fi

# Golden baseline: snapshot NOT overwritten by DPkg::Post-Invoke auto-rebaseline.
# Daily cron diffs against aide.db (changes since last apt run).
# Weekly cron diffs against golden (cumulative drift + compromised-package blind spot).
# Operator manually refreshes: cp /var/lib/aide/aide.db /var/lib/aide/aide.db.golden
if [ -f /var/lib/aide/aide.db ] && { [ ! -f /var/lib/aide/aide.db.golden ] || [ "$FORCE_AIDE_REBASELINE" = "1" ]; }; then
  cp /var/lib/aide/aide.db /var/lib/aide/aide.db.golden
  ok "AIDE golden baseline saved to aide.db.golden."
fi

cat > /etc/cron.weekly/aide-golden-check <<'AIDEGOLDEN'
#!/bin/sh
set -eu
. /etc/secure-cloud-deploy.conf 2>/dev/null || ALERT_EMAIL=root
[ -f /var/lib/aide/aide.db.golden ] || exit 0
AIDE_CONF=""
for f in /etc/aide/aide.conf /etc/aide.conf; do
    [ -f "$f" ] && AIDE_CONF="$f" && break
done
[ -z "$AIDE_CONF" ] && exit 0
out=$(mktemp)
TMPCONF=$(mktemp)
trap 'rm -f "$out" "$TMPCONF"' EXIT
sed 's|^database=file:.*|database=file:/var/lib/aide/aide.db.golden|' "$AIDE_CONF" > "$TMPCONF"
if ! aide --check --config="$TMPCONF" > "$out" 2>&1; then
    mail -s "AIDE golden-baseline drift on $(hostname)" "$ALERT_EMAIL" < "$out"
fi
AIDEGOLDEN
chmod 755 /etc/cron.weekly/aide-golden-check
ok "AIDE weekly golden-baseline check cron installed."

# ---------------------------------------------------------------------------
# Step 13: rkhunter
# ---------------------------------------------------------------------------
info "Step 13: rkhunter..."
apt-get install -y -qq rkhunter > /dev/null
rkhunter --update > /dev/null 2>&1 || true
rkhunter --propupd > /dev/null 2>&1 || true

if grep -q "^CRON_DAILY_RUN=" /etc/default/rkhunter 2>/dev/null; then
  sed -i 's|^CRON_DAILY_RUN=.*|CRON_DAILY_RUN="true"|' /etc/default/rkhunter
else
  echo 'CRON_DAILY_RUN="true"' >> /etc/default/rkhunter
fi
if grep -q "^REPORT_EMAIL=" /etc/rkhunter.conf 2>/dev/null; then
  sed -i "s|^REPORT_EMAIL=.*|REPORT_EMAIL=$ALERT_EMAIL|" /etc/rkhunter.conf
else
  echo "REPORT_EMAIL=$ALERT_EMAIL" >> /etc/rkhunter.conf
fi
ok "rkhunter configured (daily scan; alerts → $ALERT_EMAIL)."

# ---------------------------------------------------------------------------
# Step 14: chkrootkit
# ---------------------------------------------------------------------------
info "Step 14: chkrootkit..."
apt-get install -y -qq chkrootkit > /dev/null

cat > /etc/cron.daily/chkrootkit-check <<'CHKROOTKIT'
#!/bin/sh
set -eu
. /etc/secure-cloud-deploy.conf 2>/dev/null || ALERT_EMAIL=root
out=$(chkrootkit 2>&1) || true
if echo "$out" | grep -qiE "INFECTED|WARNING"; then
    echo "$out" | mail -s "chkrootkit alert on $(hostname)" "$ALERT_EMAIL"
fi
CHKROOTKIT
chmod 755 /etc/cron.daily/chkrootkit-check
ok "chkrootkit configured (daily; alerts on INFECTED/WARNING)."

# ---------------------------------------------------------------------------
# Step 15: msmtp relay for system alerts
# ---------------------------------------------------------------------------
info "Step 15: msmtp..."
apt-get install -y -qq msmtp msmtp-mta bsd-mailx > /dev/null

MSMTP_CONFIGURED=0
if [ -z "$ALERT_SMTP_HOST" ] && [ -t 0 ]; then
  echo ""
  echo "SMTP relay for system alerts (leave blank to skip):"
  printf "  Host (e.g. smtp.gmail.com): "
  read -r ALERT_SMTP_HOST
  if [ -n "$ALERT_SMTP_HOST" ]; then
    printf "  Port [587]: "
    read -r _port_in
    ALERT_SMTP_PORT="${_port_in:-587}"
    printf "  Username: "
    read -r ALERT_SMTP_USER
    printf "  Password: "
    read -rs ALERT_SMTP_PASS
    echo
  fi
fi

# Resolve SPF/DMARC-safe From address.
# ALERT_SMTP_USER may be a non-email token (e.g. SendGrid "apikey", SES AKID).
if [ -n "$ALERT_SMTP_HOST" ] && [ -n "$ALERT_SMTP_USER" ]; then
  if [ -z "$ALERT_FROM" ]; then
    if echo "$ALERT_SMTP_USER" | grep -q "@"; then
      ALERT_FROM="$ALERT_SMTP_USER"
    elif [ -t 0 ]; then
      printf "  From address for alert mail (e.g. alerts@yourdomain.com): "
      read -r ALERT_FROM
    fi
  fi
  [ -z "$ALERT_FROM" ] && ALERT_FROM="$ALERT_SMTP_USER"
fi

if [ -n "$ALERT_SMTP_HOST" ] && [ -n "$ALERT_SMTP_USER" ]; then
  cat > /etc/msmtprc <<MSMTPRC
defaults
auth           on
tls            on
tls_trust_file /etc/ssl/certs/ca-certificates.crt

account        default
host           $ALERT_SMTP_HOST
port           $ALERT_SMTP_PORT
from           $ALERT_FROM
user           $ALERT_SMTP_USER
password       $ALERT_SMTP_PASS

account default : default
MSMTPRC
  chmod 600 /etc/msmtprc
  chown root:root /etc/msmtprc

  # Update fail2ban sender (must match msmtp From — SPF/DMARC-safe)
  sed -i "s|^sender.*|sender    = $ALERT_FROM|" /etc/fail2ban/jail.local
  systemctl restart fail2ban 2>/dev/null || true

  echo "harden-dev.sh msmtp test on $(hostname) at $(date -u)" \
    | mail -s "SecureCloud dev: msmtp test on $(hostname)" "$ALERT_EMAIL" 2>/dev/null \
    && ok "msmtp configured; test mail sent to $ALERT_EMAIL." \
    || warn "msmtp configured but test mail failed — check /etc/msmtprc."
  MSMTP_CONFIGURED=1
else
  warn "No SMTP relay — system alerts are journal-only."
fi

# ---------------------------------------------------------------------------
# Step 16: Swap  (2 GB if absent)
# ---------------------------------------------------------------------------
info "Step 16: Swap..."
if [ -f /swapfile ]; then
  ok "Swap file already exists."
else
  info "Creating 2GB swap file..."
  fallocate -l 2G /swapfile
  chmod 600 /swapfile
  mkswap /swapfile > /dev/null
  swapon /swapfile
  grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
  ok "Swap created and enabled."
fi

# ---------------------------------------------------------------------------
# Step 17: Journald retention  (persistent, 200 MB, 30 days)
# Unlike the VPS (volatile/zero-logging), the dev machine keeps logs for
# post-incident analysis.
# ---------------------------------------------------------------------------
info "Step 17: Journald retention..."
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/dev-retention.conf <<'JOURNALD'
[Journal]
Storage=persistent
SystemMaxUse=200M
MaxRetentionSec=30day
JOURNALD
systemctl restart systemd-journald 2>/dev/null || true
ok "Journald: persistent storage, 200 MB max, 30-day retention."

# ---------------------------------------------------------------------------
# Step 18: ssh-agent TTL via systemd user unit (5-minute key TTL)
# ---------------------------------------------------------------------------
info "Step 18: ssh-agent TTL (5 min)..."
AGENT_UNIT_DIR=/home/appuser/.config/systemd/user
install -d -m 755 -o appuser -g appuser "$AGENT_UNIT_DIR"

cat > "$AGENT_UNIT_DIR/ssh-agent.service" <<'AGENTUNIT'
[Unit]
Description=SSH agent with 5-minute key TTL

[Service]
Type=simple
ExecStart=/usr/bin/ssh-agent -D -t 300 -a %t/ssh-agent.socket
Restart=on-failure

[Install]
WantedBy=default.target
AGENTUNIT
chown appuser:appuser "$AGENT_UNIT_DIR/ssh-agent.service"

cat > /etc/profile.d/ssh-agent-env.sh <<'AGENTENV'
# ssh-agent socket for appuser systemd user service
if [ "${USER:-}" = "appuser" ] && [ -n "${XDG_RUNTIME_DIR:-}" ]; then
    export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/ssh-agent.socket"
fi
AGENTENV

# Enable linger so user unit runs without an active session
loginctl enable-linger appuser 2>/dev/null || warn "loginctl enable-linger not available — ssh-agent unit will only run during active sessions."

# Reload and enable user unit
sudo -u appuser systemctl --user daemon-reload 2>/dev/null || true
sudo -u appuser systemctl --user enable ssh-agent 2>/dev/null || true
sudo -u appuser systemctl --user start ssh-agent 2>/dev/null || true
ok "ssh-agent systemd user unit installed (5-min TTL on loaded keys)."

# ---------------------------------------------------------------------------
# Step 19: Git commit signing bootstrap
# ---------------------------------------------------------------------------
info "Step 19: Git commit signing..."

GEN_KEY=n
if [ -t 0 ]; then
  printf "Generate ed25519 signing key for appuser? [y/N]: "
  read -r GEN_KEY
fi

if [ "${GEN_KEY,,}" = "y" ]; then
  if [ -f /home/appuser/.ssh/id_ed25519 ]; then
    warn "~appuser/.ssh/id_ed25519 already exists — skipping key generation."
  else
    sudo -u appuser ssh-keygen \
      -t ed25519 -a 100 \
      -f /home/appuser/.ssh/id_ed25519 \
      -C "dev@$(hostname)-$(date +%Y%m%d)"
    ok "ed25519 key generated at ~appuser/.ssh/id_ed25519."
  fi
fi

# Configure git signing for appuser (idempotent)
sudo -u appuser git config --global gpg.format ssh
sudo -u appuser git config --global user.signingkey /home/appuser/.ssh/id_ed25519.pub
sudo -u appuser git config --global commit.gpgsign true
sudo -u appuser git config --global gpg.ssh.allowedSignersFile /home/appuser/.config/git/allowed_signers

install -d -m 755 -o appuser -g appuser /home/appuser/.config/git

# Seed allowed_signers with the generated/existing pubkey
if [ -f /home/appuser/.ssh/id_ed25519.pub ]; then
  PUBKEY=$(cat /home/appuser/.ssh/id_ed25519.pub)
  SIGNERS=/home/appuser/.config/git/allowed_signers
  if [ ! -f "$SIGNERS" ] || ! grep -qF "$PUBKEY" "$SIGNERS" 2>/dev/null; then
    printf "* %s\n" "$PUBKEY" >> "$SIGNERS"
    chown appuser:appuser "$SIGNERS"
    ok "allowed_signers seeded (local git verify-commit works)."
  else
    ok "allowed_signers already contains this pubkey."
  fi
fi

ok "Git signing configured for appuser."

# ---------------------------------------------------------------------------
# Step 20: Shell hygiene
# ---------------------------------------------------------------------------
info "Step 20: Shell hygiene..."
cat > /etc/profile.d/dev-bash-hist.sh <<'HIST'
# Managed by harden-dev.sh
HISTCONTROL=ignoredups:ignorespace
HISTFILESIZE=5000
HISTTIMEFORMAT="%F %T "
HIST
ok "Bash history: dedup, timestamps, 5000 entries."

# ---------------------------------------------------------------------------
# Step 21: PATH — cargo + npm-global
# ---------------------------------------------------------------------------
info "Step 21: PATH persistence..."
cat > /etc/profile.d/dev-paths.sh <<'PATHS'
# Managed by harden-dev.sh
export PATH="$HOME/.cargo/bin:$HOME/.npm-global/bin:$PATH"
PATHS
ok "PATH profile.d entry written (~/.cargo/bin, ~/.npm-global/bin)."

# ---------------------------------------------------------------------------
# Step 22: Final summary
# ---------------------------------------------------------------------------
PUBKEY_OUT=""
[ -f /home/appuser/.ssh/id_ed25519.pub ] && PUBKEY_OUT=$(cat /home/appuser/.ssh/id_ed25519.pub)

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN} Dev machine hardening complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "  OS:           Ubuntu $CODENAME ($VIRT)"
echo "  SSH port:     $SSH_PORT (ed25519-only, appuser-only, no agent forwarding)"
echo "  UFW:          active (deny in / allow out; $SSH_PORT, 80, 443)"
echo "  fail2ban:     sshd + recidive jails (alerts → $ALERT_EMAIL)"
echo "  msmtp:        $([ "$MSMTP_CONFIGURED" -eq 1 ] && echo "configured (from: ${ALERT_FROM})" || echo "NOT configured (journal-only alerts)")"
echo "  AIDE:         $([ -f /var/lib/aide/aide.db ] && echo "baseline ready" || echo "baseline pending — run aideinit")"
echo "  AIDE golden:  $([ -f /var/lib/aide/aide.db.golden ] && echo "saved" || echo "pending")"
echo "  rkhunter:     daily scan (alerts → $ALERT_EMAIL)"
echo "  chkrootkit:   daily scan (alerts on INFECTED/WARNING)"
echo "  AppArmor:     running (default profiles)"
echo "  auditd:       running with dev-hardening rules"
echo "  Kernel:       ptrace_scope=2, BPF disabled, network hardened"
echo "  Journald:     persistent, 200 MB, 30 days"
echo "  ssh-agent:    5-min TTL systemd user unit (appuser)"
echo "  Git signing:  SSH-based (commit.gpgsign=true)"
echo "  Swap:         $([ -f /swapfile ] && echo "2 GB" || echo "n/a")"
echo ""

if [ -n "$PUBKEY_OUT" ]; then
  echo -e "${YELLOW}PUBKEY — paste into the production VPS:${NC}"
  echo ""
  echo "  # On the VPS: append to /home/appuser/.ssh/authorized_keys"
  echo "  echo '$PUBKEY_OUT' >> /home/appuser/.ssh/authorized_keys"
  echo ""
  echo "  # On the VPS: append to /home/appuser/.config/git/allowed_signers"
  echo "  echo '* $PUBKEY_OUT' >> /home/appuser/.config/git/allowed_signers"
  echo ""
fi

echo -e "${YELLOW}Recommended ~/.ssh/config on this machine (for the production VPS):${NC}"
echo ""
cat <<SSHCONFIG
  Host vps
    HostName <VPS-IP>
    Port <VPS-SSH-PORT>
    User appuser
    ForwardAgent no
    IdentitiesOnly yes
    IdentityFile ~/.ssh/id_ed25519
SSHCONFIG
echo ""
echo -e "${RED}SECURITY:${NC} Never set ForwardAgent yes for the vps Host entry."
echo ""
echo -e "${YELLOW}Residual risks:${NC}"
echo "  - No disk encryption (Hetzner Cloud; no vTPM available)."
echo "    Mitigate by trusting Hetzner's encryption-at-rest, or provision a"
echo "    new VM with LUKS + dropbear-initramfs remote unlock."
echo "  - appuser in docker group ≈ root via --privileged bind-mount."
echo "    Accepted: CI/CD requires docker access; compensated by SSH-signed"
echo "    commit gate + origin reconcile stopping upstream compromise."
echo "  - FIDO2 upgrade path: replace id_ed25519 with an ed25519-sk key"
echo "    (ssh-keygen -t ed25519-sk) when a YubiKey or vTPM is available."
echo "    Update VPS authorized_keys + allowed_signers accordingly."
echo ""
