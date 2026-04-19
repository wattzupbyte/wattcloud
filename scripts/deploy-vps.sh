#!/usr/bin/env bash
# =============================================================================
# deploy-vps.sh — Deploy Secure Cloud to a bare Ubuntu 22.04+ VPS
# Idempotent: safe to run multiple times.
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Color helpers
# ---------------------------------------------------------------------------
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
DOMAIN="${1:-}"
EMAIL="${2:-admin@${DOMAIN}}"
SSH_PORT="${3:-2222}"
BYO_DOMAIN="${4:-${DOMAIN}}"
ALERT_EMAIL="${5:-${EMAIL}}"

# Zero-logging hardening (BYO relay — R5 invariant); set BYO_HARDEN=0 to skip.
BYO_HARDEN="${BYO_HARDEN:-1}"

# Managed-mode services (backend/frontend/backup). BYO-only by default.
# MANAGED_SET_BY_ENV=1 when the caller pre-set MANAGED in the environment.
if [ -z "${MANAGED+x}" ]; then
  MANAGED=""
  MANAGED_SET_BY_ENV=0
else
  MANAGED_SET_BY_ENV=1
fi

# ed25519 public key for appuser. Required — pass via env for non-interactive runs.
APPUSER_SSH_PUBKEY="${APPUSER_SSH_PUBKEY:-}"

# SMTP relay credentials for system alerts (fail2ban, unattended-upgrades, AIDE).
# Optional — leave blank to skip; alerts fall back to journal-only.
ALERT_SMTP_HOST="${ALERT_SMTP_HOST:-}"
ALERT_SMTP_PORT="${ALERT_SMTP_PORT:-587}"
ALERT_SMTP_USER="${ALERT_SMTP_USER:-}"
ALERT_SMTP_PASS="${ALERT_SMTP_PASS:-}"
# SPF/DMARC-safe From address. Must be a real email address on the SMTP relay's
# domain. Defaults to ALERT_SMTP_USER when it looks like an email; otherwise
# prompted (or set via ALERT_FROM env var for non-interactive runs).
ALERT_FROM="${ALERT_FROM:-}"

# GitHub repo URL for origin reconcile gate in the CD post-receive hook.
# The bare repo's origin remote is set to this URL so the hook can verify that
# every pushed SHA is already an ancestor of origin/main (upstream PR gate).
ORIGIN_URL="${ORIGIN_URL:-}"

if [ -z "$DOMAIN" ]; then
  echo "Usage: $0 DOMAIN [EMAIL] [SSH_PORT] [BYO_DOMAIN] [ALERT_EMAIL]"
  echo "  DOMAIN       — required (e.g. cloud.example.com)"
  echo "  EMAIL        — for Let's Encrypt (default: admin@DOMAIN)"
  echo "  SSH_PORT     — SSH port (default: 2222)"
  echo "  BYO_DOMAIN   — BYO relay domain (default: DOMAIN)"
  echo "  ALERT_EMAIL  — alert recipient for fail2ban/upgrades/AIDE (default: EMAIL)"
  echo ""
  echo "  Env vars:"
  echo "    APPUSER_SSH_PUBKEY          — ed25519 public key for appuser (prompted if unset)"
  echo "    MANAGED=1                   — also start managed backend/frontend/backup"
  echo "    BYO_HARDEN=0                — skip zero-logging OS hardening"
  echo "    ALERT_SMTP_HOST/PORT/USER/PASS — SMTP relay for alerts (prompted if unset)"
  echo "    ALERT_FROM                  — From: address for alert mail (SPF/DMARC-safe)"
  echo "    ORIGIN_URL                  — GitHub repo URL for CD origin reconcile gate (prompted if unset)"
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  die "This script must be run as root."
fi

# ---------------------------------------------------------------------------
# Mode selection — D1: interactive when TTY; non-interactive defaults to BYO
# ---------------------------------------------------------------------------
if [ "$MANAGED_SET_BY_ENV" -eq 0 ]; then
  if [ -t 0 ]; then
    echo ""
    printf "Deployment mode: [B]YO only / [M]anaged (default: B): "
    read -r _mode_choice
    case "${_mode_choice,,}" in
      m|managed) MANAGED=1 ;;
      *)         MANAGED=0 ;;
    esac
  else
    info "Non-interactive: defaulting to BYO-only mode. Set MANAGED=1 to override."
    MANAGED=0
  fi
fi

# ---------------------------------------------------------------------------
# Prompt for appuser SSH pubkey if not supplied
# ---------------------------------------------------------------------------
if [ -z "$APPUSER_SSH_PUBKEY" ] && [ -t 0 ]; then
  echo ""
  echo "Paste the ed25519 public key for appuser"
  echo "(starts with 'ssh-ed25519' or 'sk-ssh-ed25519@openssh.com'):"
  read -r APPUSER_SSH_PUBKEY
fi

if [ -z "$APPUSER_SSH_PUBKEY" ] || \
   ! echo "$APPUSER_SSH_PUBKEY" | grep -qE "^(ssh-ed25519|sk-ssh-ed25519@openssh\.com) AAAA"; then
  die "APPUSER_SSH_PUBKEY must be a valid ed25519 public key. Got: '${APPUSER_SSH_PUBKEY:-<empty>}'"
fi

APP_DIR="$(cd "$(dirname "$0")/.." && pwd)"
info "App directory: $APP_DIR"
info "Domain:        $DOMAIN"
info "BYO domain:    $BYO_DOMAIN"
info "Email:         $EMAIL"
info "Alert email:   $ALERT_EMAIL"
info "SSH port:      $SSH_PORT"
info "Zero-logging:  $([ "$BYO_HARDEN" = "1" ] && echo enabled || echo disabled)"
info "Managed mode:  $([ "$MANAGED" = "1" ] && echo yes || echo "no (BYO-only)")"
echo ""

# =========================================================================
# 1. OS packages + unattended-upgrades
# =========================================================================
info "Setting timezone to UTC..."
timedatectl set-timezone UTC 2>/dev/null || true
ok "Timezone set."

info "Updating packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get upgrade -y -qq
ok "Packages updated."

info "Installing base packages..."
apt-get install -y -qq ca-certificates curl gnupg git > /dev/null
ok "Base packages installed."

info "Installing unattended-upgrades..."
apt-get install -y -qq unattended-upgrades apt-listchanges > /dev/null
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
ok "Automatic security updates configured (alerts → $ALERT_EMAIL)."

# =========================================================================
# 2. Docker + Docker Compose v2  [must come before appuser — creates docker group]
# =========================================================================
if command -v docker &>/dev/null; then
  ok "Docker already installed: $(docker --version)"
else
  info "Installing Docker..."
  install -m 0755 -d /etc/apt/keyrings
  if [ ! -f /etc/apt/keyrings/docker.gpg ]; then
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
  fi
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin > /dev/null
  ok "Docker installed."
fi

systemctl enable docker > /dev/null 2>&1
systemctl start docker

# =========================================================================
# 3. appuser setup  [after Docker — docker group now exists]
# =========================================================================
info "Setting up appuser (UID 1000)..."
if id appuser &>/dev/null; then
  ok "appuser already exists."
else
  useradd -u 1000 -m -s /bin/bash appuser
  ok "appuser created (UID 1000)."
fi
passwd -l appuser > /dev/null 2>&1
usermod -aG docker appuser
ok "appuser: password locked, docker group added."

install -d -m 700 -o appuser -g appuser /home/appuser/.ssh
echo "$APPUSER_SSH_PUBKEY" > /home/appuser/.ssh/authorized_keys
chmod 600 /home/appuser/.ssh/authorized_keys
chown appuser:appuser /home/appuser/.ssh/authorized_keys
ok "appuser SSH key installed."

# =========================================================================
# 4. UFW — ingress allow-list  [before sshd restart — opens new port first]
# =========================================================================
info "Configuring UFW..."
apt-get install -y -qq ufw > /dev/null
ufw default deny incoming > /dev/null 2>&1
ufw default allow outgoing > /dev/null 2>&1
ufw allow "$SSH_PORT"/tcp > /dev/null 2>&1
ufw allow 80/tcp > /dev/null 2>&1
ufw allow 443/tcp > /dev/null 2>&1
ufw logging off > /dev/null 2>&1 || true
ufw --force enable > /dev/null 2>&1
ok "UFW configured (ports $SSH_PORT, 80, 443; logging off)."

# =========================================================================
# 5. SSH hardening  [after UFW — new port already open before sshd restarts]
# =========================================================================
info "Hardening SSH (port=$SSH_PORT)..."

if [ ! -f /etc/ssh/sshd_config.bak ]; then
  cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
  ok "sshd_config backed up to /etc/ssh/sshd_config.bak"
fi

# Port must be changed in the main file — multiple Port directives are additive,
# so a drop-in Port would cause sshd to listen on both 22 AND $SSH_PORT.
sed -i "s/^#\?Port .*/Port $SSH_PORT/" /etc/ssh/sshd_config

# All other directives live exclusively in the drop-in (survives dist-upgrade).
# PermitRootLogin and PasswordAuthentication are intentionally NOT set via sed
# on the main file — the drop-in wins and there is no stale conflicting value.
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/99-secure-cloud.conf <<SSHD
# Managed by deploy-vps.sh — do not edit manually
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

sshd -t || die "sshd config test failed — check /etc/ssh/sshd_config.d/99-secure-cloud.conf"
systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
ok "SSH hardened (port=$SSH_PORT, ed25519-only, appuser-only)."

if [ -t 0 ]; then
  echo ""
  printf "Root password is kept for Hetzner rescue console break-glass. Change it now? [y/N]: "
  read -r _root_pw_choice
  if [ "${_root_pw_choice,,}" = "y" ]; then
    passwd root
  fi
fi

# =========================================================================
# 6. fail2ban
# =========================================================================
info "Installing fail2ban..."
apt-get install -y -qq fail2ban > /dev/null

# Sender will be updated after msmtp is configured (Section 8).
# Use root@DOMAIN as placeholder; msmtp section overwrites with SMTP user.
FAIL2BAN_SENDER="${ALERT_SMTP_USER:-root@$DOMAIN}"

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
ok "fail2ban configured (sshd + recidive jails; alerts → $ALERT_EMAIL)."

# =========================================================================
# 7. Zero-logging OS hardening (BYO relay — R5 invariant)
#    Prevents the OS from logging relay traffic or client IPs.
# =========================================================================
if [ "$BYO_HARDEN" = "1" ]; then
  info "Applying zero-logging OS hardening..."

  mkdir -p /etc/systemd/journald.conf.d
  cat > /etc/systemd/journald.conf.d/byo-volatile.conf <<'JOURNALD'
[Journal]
Storage=volatile
RuntimeMaxUse=64M
ForwardToSyslog=no
JOURNALD
  systemctl restart systemd-journald 2>/dev/null || true
  ok "journald set to volatile (logs evaporate on reboot)."

  # UFW logging was already disabled in section 4.

  cat > /etc/sysctl.d/99-byo-nolog.conf <<'SYSCTL'
net.ipv4.conf.all.log_martians = 0
net.ipv4.conf.default.log_martians = 0
SYSCTL
  sysctl --system > /dev/null 2>&1 || true
  ok "Kernel martian logging suppressed."

  if systemctl is-active rsyslog &>/dev/null; then
    systemctl disable --now rsyslog 2>/dev/null || true
    ok "rsyslog disabled."
  fi
else
  warn "BYO zero-logging hardening skipped (BYO_HARDEN=0)."
fi

if [ "$BYO_HARDEN" = "1" ]; then
  HARDEN_FAIL=0
  [ -f /etc/systemd/journald.conf.d/byo-volatile.conf ] \
    || { err "journald volatile config missing"; HARDEN_FAIL=1; }
  [ -f /etc/sysctl.d/99-byo-nolog.conf ] \
    || { err "sysctl nolog config missing"; HARDEN_FAIL=1; }
  [ "$HARDEN_FAIL" -eq 1 ] && die "Zero-logging hardening verification failed."
  ok "Zero-logging hardening verified."
fi

# =========================================================================
# 8. msmtp relay for system alerts (fail2ban, unattended-upgrades, AIDE)
# =========================================================================
info "Configuring msmtp relay for system alerts..."
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
# We need a real email address in the From header that matches the relay domain.
if [ -n "$ALERT_SMTP_HOST" ] && [ -n "$ALERT_SMTP_USER" ]; then
  if [ -z "$ALERT_FROM" ]; then
    if echo "$ALERT_SMTP_USER" | grep -q "@"; then
      ALERT_FROM="$ALERT_SMTP_USER"
    elif [ -t 0 ]; then
      echo ""
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

  # Update fail2ban sender (must match the msmtp From address — SPF/DMARC-safe)
  sed -i "s|^sender.*|sender    = $ALERT_FROM|" /etc/fail2ban/jail.local
  systemctl restart fail2ban 2>/dev/null || true

  echo "Secure Cloud alert relay configured on $(hostname) at $(date -u)" \
    | mail -s "SecureCloud: msmtp relay test on $(hostname)" "$ALERT_EMAIL" 2>/dev/null \
    && ok "msmtp configured; test mail sent to $ALERT_EMAIL." \
    || warn "msmtp configured but test mail failed — check relay credentials in /etc/msmtprc."
  MSMTP_CONFIGURED=1
else
  warn "No SMTP relay configured — system alerts are journal-only."
  warn "Re-run with ALERT_SMTP_HOST/USER/PASS env vars to add email alerts."
fi

# =========================================================================
# 9. AIDE + rkhunter (D3: file integrity + rootkit detection)
# =========================================================================
info "Installing AIDE and rkhunter..."
apt-get install -y -qq aide rkhunter > /dev/null

# Store ALERT_EMAIL for use by cron scripts
cat > /etc/secure-cloud-deploy.conf <<DEPLOYCONF
# Written by deploy-vps.sh — used by cron alert scripts
ALERT_EMAIL=$ALERT_EMAIL
DEPLOYCONF
chmod 644 /etc/secure-cloud-deploy.conf

# Daily cron: mail ONLY when aide finds changes (exit non-zero means diff found)
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

# DPkg::Post-Invoke: auto-rebaseline after apt package changes.
# Prevents a flood of "every binary changed" alerts after unattended-upgrades.
# Trade-off: a package compromise between two apt runs would be masked by the
# rebaseline. Acceptable for a single-tenant BYO VPS; document it.
cat > /etc/apt/apt.conf.d/99-aide-rebaseline <<'AIDEAPT'
DPkg::Post-Invoke { "if [ -x /usr/bin/aide ]; then /usr/bin/aide --update >/dev/null 2>&1 && mv -f /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null || true; fi"; };
AIDEAPT

if [ ! -f /var/lib/aide/aide.db ]; then
  info "Building AIDE baseline — this takes ~5 minutes..."
  aideinit -y > /dev/null 2>&1 || true
  if [ -f /var/lib/aide/aide.db.new ]; then
    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    ok "AIDE baseline built."
  else
    warn "AIDE aideinit produced no output — run 'aideinit' manually after deploy."
  fi
else
  ok "AIDE baseline already exists — skipping re-init."
fi

# Golden baseline: a snapshot NOT overwritten by the DPkg::Post-Invoke rebaseline.
# The daily cron diffs against aide.db (catches changes since last apt run).
# The weekly cron diffs against aide.db.golden (catches cumulative drift and
# package compromises between apt runs — the rebaseline trade-off blind spot).
# Operator manually updates golden after reviewing weekly report:
#   cp /var/lib/aide/aide.db /var/lib/aide/aide.db.golden
if [ -f /var/lib/aide/aide.db ] && [ ! -f /var/lib/aide/aide.db.golden ]; then
  cp /var/lib/aide/aide.db /var/lib/aide/aide.db.golden
  ok "AIDE golden baseline saved to aide.db.golden."
fi

cat > /etc/cron.weekly/aide-golden-check <<'AIDEGOLDEN'
#!/bin/sh
set -eu
. /etc/secure-cloud-deploy.conf 2>/dev/null || ALERT_EMAIL=root
[ -f /var/lib/aide/aide.db.golden ] || exit 0
# Find the AIDE config file (location varies by distro)
AIDE_CONF=""
for f in /etc/aide/aide.conf /etc/aide.conf; do
    [ -f "$f" ] && AIDE_CONF="$f" && break
done
[ -z "$AIDE_CONF" ] && exit 0
out=$(mktemp)
TMPCONF=$(mktemp)
trap 'rm -f "$out" "$TMPCONF"' EXIT
# Point database at golden baseline (not the auto-rebaselined daily DB)
sed 's|^database=file:.*|database=file:/var/lib/aide/aide.db.golden|' "$AIDE_CONF" > "$TMPCONF"
if ! aide --check --config="$TMPCONF" > "$out" 2>&1; then
    mail -s "AIDE golden-baseline drift on $(hostname)" "$ALERT_EMAIL" < "$out"
fi
AIDEGOLDEN
chmod 755 /etc/cron.weekly/aide-golden-check
ok "AIDE weekly golden-baseline check cron installed."

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

# =========================================================================
# 10. Bare git repo + post-receive hook for push-to-deploy CD
# =========================================================================
info "Setting up bare git repo for CD at /home/appuser/secure-cloud.git..."
if [ ! -d /home/appuser/secure-cloud.git ]; then
  sudo -u appuser git init --bare /home/appuser/secure-cloud.git
  ok "Bare repo initialised."
else
  ok "Bare repo already exists."
fi
chmod 700 /home/appuser/secure-cloud.git

# Configure git signing infrastructure for appuser — global config
sudo -u appuser git config --global gpg.format ssh
sudo -u appuser git config --global gpg.ssh.allowedSignersFile /home/appuser/.config/git/allowed_signers

# Also set on the bare repo directly so post-receive verify-commit works even if
# appuser's global config is absent or misconfigured (P1-8: GIT_SSH_ALLOWED_SIGNERS
# env var is not recognised by git; repo-level config is authoritative).
git --git-dir=/home/appuser/secure-cloud.git config gpg.format ssh
git --git-dir=/home/appuser/secure-cloud.git config gpg.ssh.allowedSignersFile /home/appuser/.config/git/allowed_signers

install -d -m 755 -o appuser -g appuser /home/appuser/.config/git

ALLOWED_SIGNERS_FILE=/home/appuser/.config/git/allowed_signers
if [ ! -f "$ALLOWED_SIGNERS_FILE" ] || ! grep -qF "$APPUSER_SSH_PUBKEY" "$ALLOWED_SIGNERS_FILE" 2>/dev/null; then
  # Wildcard principal matches any git commit author email
  printf "* %s\n" "$APPUSER_SSH_PUBKEY" >> "$ALLOWED_SIGNERS_FILE"
  chown appuser:appuser "$ALLOWED_SIGNERS_FILE"
  ok "allowed_signers seeded."
fi

# Install post-receive hook if the template exists
HOOK_SRC="$APP_DIR/scripts/post-receive.sh"
HOOK_DST=/home/appuser/secure-cloud.git/hooks/post-receive
if [ -f "$HOOK_SRC" ]; then
  install -m 755 -o appuser -g appuser "$HOOK_SRC" "$HOOK_DST"
  ok "post-receive hook installed."
else
  warn "scripts/post-receive.sh not found — CD hook not installed yet."
  warn "Re-run deploy-vps.sh after adding scripts/post-receive.sh to the repo."
fi

# Write CD config for origin reconcile (configurable; defaults to origin/main)
CD_CONF=/home/appuser/.secure-cloud-cd.conf
if [ ! -f "$CD_CONF" ]; then
  cat > "$CD_CONF" <<'CDCONF'
# CD configuration — edited by operator to point to the upstream remote.
# ORIGIN_REMOTE: pushed SHA must be an ancestor of ORIGIN_REMOTE/ORIGIN_BRANCH.
ORIGIN_REMOTE=origin
# Change to byo-release if using a dedicated BYO-only deploy branch.
ORIGIN_BRANCH=main
CDCONF
  chown appuser:appuser "$CD_CONF"
  ok "CD config written to $CD_CONF."
fi

# Prompt for GitHub origin URL and wire it up on the bare repo (P0-1).
# The post-receive hook fails closed if no origin remote is configured, so this
# is a required step — not optional. Operator can skip by setting ORIGIN_URL=""
# explicitly only if they plan to configure origin manually later.
if [ -z "$ORIGIN_URL" ] && [ -t 0 ]; then
  echo ""
  echo "GitHub repo URL for CD origin reconcile gate (required)."
  echo "The hook verifies every pushed SHA is an ancestor of this remote before deploying."
  printf "  URL (e.g. https://github.com/you/secure-cloud.git): "
  read -r ORIGIN_URL
fi

if [ -n "$ORIGIN_URL" ]; then
  if git --git-dir=/home/appuser/secure-cloud.git remote get-url origin > /dev/null 2>&1; then
    git --git-dir=/home/appuser/secure-cloud.git remote set-url origin "$ORIGIN_URL"
    ok "Bare repo origin updated to $ORIGIN_URL."
  else
    git --git-dir=/home/appuser/secure-cloud.git remote add origin "$ORIGIN_URL"
    ok "Bare repo origin added: $ORIGIN_URL."
  fi
  chown -R appuser:appuser /home/appuser/secure-cloud.git
else
  warn "ORIGIN_URL not set. The post-receive CD hook will fail-closed on every push."
  warn "Add origin manually: git -C /home/appuser/secure-cloud.git remote add origin <URL>"
  warn "Or re-run deploy-vps.sh with ORIGIN_URL env var."
fi

# =========================================================================
# 11. PATH persistence — cargo + wasm-pack for CD hook and appuser sessions
# =========================================================================
cat > /etc/profile.d/secure-cloud.sh <<'PROFILE'
# Added by deploy-vps.sh
export PATH="$HOME/.cargo/bin:/usr/local/bin:$PATH"
PROFILE
ok "PATH profile.d entry written."

# =========================================================================
# 12. Rust toolchain + cargo-audit
# =========================================================================
if command -v cargo &>/dev/null; then
  ok "Rust already installed: $(rustc --version)"
else
  info "Installing Rust toolchain..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
  ok "Rust installed."
fi
export PATH="$HOME/.cargo/bin:$PATH"

if ! command -v cargo-audit &>/dev/null; then
  info "Installing cargo-audit..."
  cargo install cargo-audit
fi

# =========================================================================
# 13. Cargo audit
# =========================================================================
info "Running cargo audit on backend..."
AUDIT_FAIL=0
if [ -f "$APP_DIR/backend/Cargo.lock" ]; then
  AUDIT_OUTPUT=$(cargo audit --file "$APP_DIR/backend/Cargo.lock" 2>&1) || true
  if echo "$AUDIT_OUTPUT" | grep -qi "critical"; then
    err "CRITICAL advisory in backend dependencies!"
    echo "$AUDIT_OUTPUT"
    AUDIT_FAIL=1
  elif echo "$AUDIT_OUTPUT" | grep -qi "warning\|unmaintained\|unsound"; then
    warn "Non-critical advisories in backend (continuing):"
    echo "$AUDIT_OUTPUT" | head -20
  else
    ok "Backend audit clean."
  fi
fi

info "Running cargo audit on SDK..."
if [ -f "$APP_DIR/sdk/Cargo.lock" ]; then
  AUDIT_OUTPUT=$(cargo audit --file "$APP_DIR/sdk/Cargo.lock" 2>&1) || true
  if echo "$AUDIT_OUTPUT" | grep -qi "critical"; then
    err "CRITICAL advisory in SDK dependencies!"
    echo "$AUDIT_OUTPUT"
    AUDIT_FAIL=1
  elif echo "$AUDIT_OUTPUT" | grep -qi "warning\|unmaintained\|unsound"; then
    warn "Non-critical advisories in SDK (continuing):"
    echo "$AUDIT_OUTPUT" | head -20
  else
    ok "SDK audit clean."
  fi
fi

[ "$AUDIT_FAIL" -eq 1 ] && die "Aborting: CRITICAL security advisories. Fix them before deploying."

# =========================================================================
# 14. Generate secrets & create .env
# =========================================================================
ENV_FILE="$APP_DIR/.env"
if [ -f "$ENV_FILE" ]; then
  warn ".env already exists — preserving existing file."
  warn "Delete it manually and re-run if you want fresh secrets."
else
  info "Generating secrets..."

  if [ -f "$APP_DIR/.env.example" ]; then
    cp "$APP_DIR/.env.example" "$ENV_FILE"
  else
    die ".env.example not found at $APP_DIR/.env.example"
  fi

  RELAY_SIGNING_KEY=$(openssl rand -base64 48)
  RELAY_SHARE_SIGNING_KEY=$(openssl rand -base64 48)
  BYO_STATS_HMAC_KEY=$(openssl rand -base64 48)

  sed -i "s|^RELAY_SIGNING_KEY=.*|RELAY_SIGNING_KEY=$RELAY_SIGNING_KEY|" "$ENV_FILE"
  sed -i "s|^RELAY_SHARE_SIGNING_KEY=.*|RELAY_SHARE_SIGNING_KEY=$RELAY_SHARE_SIGNING_KEY|" "$ENV_FILE"
  sed -i "s|^BYO_STATS_HMAC_KEY=.*|BYO_STATS_HMAC_KEY=$BYO_STATS_HMAC_KEY|" "$ENV_FILE"
  sed -i "s|^BYO_DOMAIN=.*|BYO_DOMAIN=$BYO_DOMAIN|"           "$ENV_FILE"
  sed -i "s|^VITE_BYO_BASE_URL=.*|VITE_BYO_BASE_URL=https://$BYO_DOMAIN|" "$ENV_FILE"
  sed -i "s|^ENVIRONMENT=.*|ENVIRONMENT=production|"           "$ENV_FILE"
  sed -i "s|^RUST_LOG=.*|RUST_LOG=warn|"                      "$ENV_FILE"

  if [ "$MANAGED" = "1" ]; then
    info "Generating managed-mode secrets..."
    MASTER_KEY=$(openssl rand -base64 32)
    JWT_SECRET=$(openssl rand -base64 32)
    BACKUP_API_KEY=$(openssl rand -hex 32)
    sed -i "s|^JWT_SECRET=.*|JWT_SECRET=$JWT_SECRET|"               "$ENV_FILE"
    sed -i "s|^MASTER_KEY=.*|MASTER_KEY=$MASTER_KEY|"               "$ENV_FILE"
    sed -i "s|^BACKUP_API_KEY=.*|BACKUP_API_KEY=$BACKUP_API_KEY|"   "$ENV_FILE"
    sed -i "s|^ALLOWED_ORIGINS=.*|ALLOWED_ORIGINS=https://$DOMAIN|" "$ENV_FILE"
    sed -i "s|^APP_BASE_URL=.*|APP_BASE_URL=https://$DOMAIN|"       "$ENV_FILE"
    sed -i "s|^SMTP_FROM=.*|SMTP_FROM=noreply@$DOMAIN|"             "$ENV_FILE"
    ok "Managed secrets generated."
  fi

  chmod 600 "$ENV_FILE"
  ok "Secrets generated and .env created."
  warn "OAuth client IDs not set — fill VITE_BYO_{GDRIVE,DROPBOX,ONEDRIVE}_CLIENT_ID in .env"
  warn "before the BYO SPA is functional. See docs/BYO-DEPLOYMENT.md."
fi

# =========================================================================
# 15. Update Traefik config with domain and email
# =========================================================================
info "Updating Traefik configuration..."
TRAEFIK_STATIC="$APP_DIR/traefik/traefik.yml"
if [ -f "$TRAEFIK_STATIC" ]; then
  sed -i "s|email:.*|email: $EMAIL|" "$TRAEFIK_STATIC"
  ok "Traefik ACME email set to $EMAIL."
fi

COMPOSE_FILE="$APP_DIR/docker-compose.yml"
if [ -f "$COMPOSE_FILE" ]; then
  sed -i "s|routers\.frontend\.rule=Host(\`[^\`]*\`)|routers.frontend.rule=Host(\`$DOMAIN\`)|g" "$COMPOSE_FILE"
  ok "docker-compose.yml managed frontend domain set to $DOMAIN."
fi

ACME_FILE="$APP_DIR/traefik/acme.json"
[ -f "$ACME_FILE" ] || touch "$ACME_FILE"
chmod 600 "$ACME_FILE"

# =========================================================================
# 16. Docker log rotation
# =========================================================================
info "Configuring Docker log rotation..."
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
systemctl restart docker 2>/dev/null || true
ok "Docker daemon log rotation configured."

# =========================================================================
# 17. Swap file (if < 2GB RAM)
# =========================================================================
TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
TOTAL_RAM_MB=$((TOTAL_RAM_KB / 1024))
if [ "$TOTAL_RAM_MB" -lt 2048 ]; then
  if [ -f /swapfile ]; then
    ok "Swap file already exists."
  else
    info "Creating 2GB swap file (RAM: ${TOTAL_RAM_MB}MB)..."
    fallocate -l 2G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile > /dev/null
    swapon /swapfile
    grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
    ok "2GB swap file created and enabled."
  fi
else
  ok "RAM: ${TOTAL_RAM_MB}MB — swap not needed."
fi

# =========================================================================
# 18. Build BYO SPA
# =========================================================================
info "Building BYO SPA..."

if ! command -v node &>/dev/null || ! node --version | grep -q "^v2[0-9]"; then
  info "Installing Node.js 20..."
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash - > /dev/null 2>&1
  apt-get install -y -qq nodejs > /dev/null
  ok "Node.js installed: $(node --version)"
else
  ok "Node.js already installed: $(node --version)"
fi

if ! command -v wasm-pack &>/dev/null; then
  info "Installing wasm-pack..."
  curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh > /dev/null 2>&1
  ok "wasm-pack installed."
fi

WASM_PKG="$APP_DIR/sdk/sdk-wasm/pkg"
WASM_SRC="$APP_DIR/sdk/sdk-wasm/src"
if [ ! -d "$WASM_PKG" ] || [ "$WASM_SRC" -nt "$WASM_PKG" ]; then
  info "Building BYO-only WASM package..."
  (cd "$APP_DIR/sdk/sdk-wasm" && wasm-pack build --target web --release \
    -- --no-default-features --features "crypto byo providers") \
    || die "WASM build failed."
  ok "WASM package built."
else
  ok "WASM package is up-to-date."
fi

# Remove destination first to avoid cp -r nesting on re-run:
# if dst/ already exists, plain `cp -r src/ dst/` copies into dst/src/ instead of dst/.
rm -rf "$APP_DIR/frontend/src/pkg"
cp -r "$WASM_PKG" "$APP_DIR/frontend/src/pkg"

(cd "$APP_DIR/frontend" && npm ci --silent && npm run build:byo) \
  || die "BYO SPA build failed."
ok "BYO SPA built at byo-server/dist/."

if [ -f "$APP_DIR/scripts/verify-byo-bundle.sh" ]; then
  bash "$APP_DIR/scripts/verify-byo-bundle.sh" || die "BYO bundle verification failed."
fi

# =========================================================================
# 19. Build and start BYO Docker image
# =========================================================================
info "Building BYO Docker image..."
cd "$APP_DIR"
BYO_SHA=$(git -C "$APP_DIR" rev-parse --short HEAD 2>/dev/null || echo "local")

BYO_IMAGE="byo-server:$BYO_SHA" \
  docker compose \
    -f "$APP_DIR/docker-compose.yml" \
    -f "$APP_DIR/docker-compose.byo-prod.yml" \
    --profile byo \
    build byo-server
ok "BYO Docker image built (tag: byo-server:$BYO_SHA)."

info "Starting BYO stack (traefik + byo-server)..."
BYO_IMAGE="byo-server:$BYO_SHA" \
  docker compose \
    -f "$APP_DIR/docker-compose.yml" \
    -f "$APP_DIR/docker-compose.byo-prod.yml" \
    --profile byo \
    up -d byo-server
ok "BYO stack started (image: byo-server:$BYO_SHA)."

if [ "$MANAGED" = "1" ]; then
  info "Building and starting managed stack..."
  docker compose --profile managed build backend frontend backup
  docker compose --profile managed up -d
  ok "Managed stack started."
fi

# =========================================================================
# Summary
# =========================================================================
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN} Secure Cloud BYO deployed!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "  BYO domain:   https://$BYO_DOMAIN"
echo "  SSH port:     $SSH_PORT"
echo "  App dir:      $APP_DIR"
echo "  Alert email:  $ALERT_EMAIL"
echo "  msmtp:        $([ "$MSMTP_CONFIGURED" -eq 1 ] && echo "configured (from: ${ALERT_FROM})" || echo "NOT configured (journal-only alerts)")"
echo "  AIDE:         $([ -f /var/lib/aide/aide.db ] && echo "baseline ready" || echo "baseline pending — run aideinit")"
echo "  AIDE golden:  $([ -f /var/lib/aide/aide.db.golden ] && echo "saved" || echo "pending")"
echo "  CD bare repo: /home/appuser/secure-cloud.git"
echo "  CD origin:    $(git --git-dir=/home/appuser/secure-cloud.git remote get-url origin 2>/dev/null || echo "NOT set — hook will fail-closed")"
echo "  CD hook:      $([ -f /home/appuser/secure-cloud.git/hooks/post-receive ] && echo "installed" || echo "NOT installed — re-run after adding scripts/post-receive.sh")"
echo ""
echo -e "${YELLOW}On your dev machine — add the VPS remote:${NC}"
echo "  git remote add vps ssh://appuser@<VPS-IP>:$SSH_PORT/home/appuser/secure-cloud.git"
echo ""
echo -e "${YELLOW}Recommended ~/.ssh/config entry (copy to dev machine):${NC}"
cat <<SSHCONFIG
  Host vps
    HostName <VPS-IP>
    Port $SSH_PORT
    User appuser
    ForwardAgent no
    IdentitiesOnly yes
    IdentityFile ~/.ssh/id_ed25519
SSHCONFIG
echo ""
echo -e "${RED}SECURITY:${NC} Never set ForwardAgent yes for the vps Host entry."
echo ""
echo -e "${YELLOW}Enable commit signing on dev machine (required for CD):${NC}"
echo "  git config --global gpg.format ssh"
echo "  git config --global user.signingkey ~/.ssh/id_ed25519.pub"
echo "  git config --global commit.gpgsign true"
echo "  git config --global gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers"
echo "  mkdir -p ~/.config/git"
echo "  echo \"* \$(cat ~/.ssh/id_ed25519.pub)\" >> ~/.config/git/allowed_signers"
echo ""
echo -e "${YELLOW}Mandatory next steps (external):${NC}"
echo "  1. Point DNS A/AAAA for $BYO_DOMAIN to this server's IP"
echo "  2. Sign Hetzner DPA/AVV — https://accounts.hetzner.com/gdpr"
echo "  3. Register OAuth consent screens — see docs/BYO-DEPLOYMENT.md Section 3"
echo "  4. Verify HTTPS:  curl -I https://$BYO_DOMAIN"
echo "  5. Verify CSP:    curl -sI https://$BYO_DOMAIN | grep content-security-policy"
echo ""
echo "  Logs:     docker compose logs -f"
echo "  Status:   docker compose ps"
echo "  Rollback: BYO_IMAGE=byo-server:<old-sha> docker compose \\"
echo "              -f $APP_DIR/docker-compose.yml \\"
echo "              -f $APP_DIR/docker-compose.byo-prod.yml \\"
echo "              --profile byo up -d byo-server"
echo ""
echo "  Full deployment guide: $APP_DIR/docs/BYO-DEPLOYMENT.md"
echo ""
