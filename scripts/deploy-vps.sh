#!/usr/bin/env bash
# =============================================================================
# deploy-vps.sh — Bootstrap a Wattcloud BYO relay on Ubuntu 22.04+. Idempotent.
# Provisions the VPS, writes /config.json from .env, logs Docker into GHCR, and
# optionally hands off to scripts/update.sh for the first image roll. Does not
# build anything — GitHub Actions owns the image pipeline.
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

BYO_HARDEN="${BYO_HARDEN:-1}"                   # zero-logging R5 hardening; 0 to skip
APPUSER_SSH_PUBKEY="${APPUSER_SSH_PUBKEY:-}"    # ed25519 pubkey for appuser (required)

# SMTP relay for alerts (fail2ban / unattended-upgrades / AIDE). Blank → journal-only.
ALERT_SMTP_HOST="${ALERT_SMTP_HOST:-}"
ALERT_SMTP_PORT="${ALERT_SMTP_PORT:-587}"
ALERT_SMTP_USER="${ALERT_SMTP_USER:-}"
ALERT_SMTP_PASS="${ALERT_SMTP_PASS:-}"
# SPF/DMARC-safe From: must match relay domain. Defaults to ALERT_SMTP_USER if
# it contains "@"; otherwise prompted (or provide ALERT_FROM for non-interactive).
ALERT_FROM="${ALERT_FROM:-}"

# GHCR auth for pulling ghcr.io/wattzupbyte/wattcloud (any read:packages PAT).
GHCR_USER="${GHCR_USER:-}"
GHCR_PAT="${GHCR_PAT:-}"

# Optional first-image roll: INITIAL_DIGEST=ghcr.io/wattzupbyte/wattcloud@sha256:...
INITIAL_DIGEST="${INITIAL_DIGEST:-}"

if [ -z "$DOMAIN" ]; then
  cat <<USAGE
Usage: $0 DOMAIN [EMAIL] [SSH_PORT] [BYO_DOMAIN] [ALERT_EMAIL]
  DOMAIN       required (e.g. cloud.example.com)
  EMAIL        for Let's Encrypt (default: admin@DOMAIN)
  SSH_PORT     SSH port (default: 2222)
  BYO_DOMAIN   BYO relay domain (default: DOMAIN)
  ALERT_EMAIL  alert recipient (default: EMAIL)

  Env vars:
    APPUSER_SSH_PUBKEY              ed25519 public key for appuser (prompted if unset)
    BYO_HARDEN=0                    skip zero-logging OS hardening
    ALERT_SMTP_HOST/PORT/USER/PASS  SMTP relay for alerts (prompted if unset)
    ALERT_FROM                      From: address for alert mail (SPF/DMARC-safe)
    GHCR_USER / GHCR_PAT            GitHub username + read:packages PAT (prompted if unset)
    INITIAL_DIGEST                  ghcr.io/...@sha256:... to roll immediately after provision
USAGE
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  die "This script must be run as root."
fi

# ---------------------------------------------------------------------------
# Prompt for appuser SSH pubkey if not supplied
# ---------------------------------------------------------------------------
if [ -z "$APPUSER_SSH_PUBKEY" ] && [ -t 0 ]; then
  echo "Paste the ed25519 public key for appuser (ssh-ed25519 or sk-ssh-ed25519@openssh.com):"
  read -r APPUSER_SSH_PUBKEY
fi
echo "$APPUSER_SSH_PUBKEY" | grep -qE "^(ssh-ed25519|sk-ssh-ed25519@openssh\.com) AAAA" \
  || die "APPUSER_SSH_PUBKEY must be a valid ed25519 public key. Got: '${APPUSER_SSH_PUBKEY:-<empty>}'"

APP_DIR="$(cd "$(dirname "$0")/.." && pwd)"
info "App=$APP_DIR domain=$DOMAIN byo=$BYO_DOMAIN email=$EMAIL alert=$ALERT_EMAIL ssh=$SSH_PORT harden=$([ "$BYO_HARDEN" = "1" ] && echo on || echo off)"
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
apt-get install -y -qq ca-certificates curl gnupg git jq > /dev/null
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
[ -f /etc/ssh/sshd_config.bak ] || cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
# Port in main file (drop-in Port would be additive); everything else in drop-in.
sed -i "s/^#\?Port .*/Port $SSH_PORT/" /etc/ssh/sshd_config
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/99-wattcloud.conf <<SSHD
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

sshd -t || die "sshd config test failed — check /etc/ssh/sshd_config.d/99-wattcloud.conf"
systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
ok "SSH hardened (port=$SSH_PORT, ed25519-only, appuser-only)."

if [ -t 0 ]; then
  printf "\nRoot password kept for Hetzner rescue-console break-glass. Change it now? [y/N]: "
  read -r _root_pw_choice
  [ "${_root_pw_choice,,}" = "y" ] && passwd root || true
fi

# =========================================================================
# 6. fail2ban
# =========================================================================
info "Installing fail2ban..."
apt-get install -y -qq fail2ban > /dev/null

# Sender updated below once msmtp resolves ALERT_FROM (Section 8 overwrites).
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

  HARDEN_FAIL=0
  [ -f /etc/systemd/journald.conf.d/byo-volatile.conf ] \
    || { err "journald volatile config missing"; HARDEN_FAIL=1; }
  [ -f /etc/sysctl.d/99-byo-nolog.conf ] \
    || { err "sysctl nolog config missing"; HARDEN_FAIL=1; }
  [ "$HARDEN_FAIL" -eq 1 ] && die "Zero-logging hardening verification failed."
  ok "Zero-logging hardening verified."
else
  warn "BYO zero-logging hardening skipped (BYO_HARDEN=0)."
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
  printf "  Host (e.g. smtp.gmail.com): "; read -r ALERT_SMTP_HOST
  if [ -n "$ALERT_SMTP_HOST" ]; then
    printf "  Port [587]: ";    read -r _port_in; ALERT_SMTP_PORT="${_port_in:-587}"
    printf "  Username: ";      read -r ALERT_SMTP_USER
    printf "  Password: ";      read -rs ALERT_SMTP_PASS; echo
  fi
fi

# SPF/DMARC-safe From address — ALERT_SMTP_USER may be a non-email token
# (e.g. SendGrid "apikey", SES AKID); prompt if no email-looking value.
if [ -n "$ALERT_SMTP_HOST" ] && [ -n "$ALERT_SMTP_USER" ] && [ -z "$ALERT_FROM" ]; then
  if echo "$ALERT_SMTP_USER" | grep -q "@"; then
    ALERT_FROM="$ALERT_SMTP_USER"
  elif [ -t 0 ]; then
    printf "  From address for alert mail (e.g. alerts@yourdomain.com): "
    read -r ALERT_FROM
  fi
  [ -z "$ALERT_FROM" ] && ALERT_FROM="$ALERT_SMTP_USER"
fi

if [ -n "$ALERT_SMTP_HOST" ] && [ -n "$ALERT_SMTP_USER" ]; then
  cat > /etc/msmtprc <<MSMTPRC
defaults
auth on
tls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
account default
host $ALERT_SMTP_HOST
port $ALERT_SMTP_PORT
from $ALERT_FROM
user $ALERT_SMTP_USER
password $ALERT_SMTP_PASS
account default : default
MSMTPRC
  chmod 600 /etc/msmtprc; chown root:root /etc/msmtprc
  # fail2ban sender must match msmtp From (SPF/DMARC).
  sed -i "s|^sender.*|sender    = $ALERT_FROM|" /etc/fail2ban/jail.local
  systemctl restart fail2ban 2>/dev/null || true
  echo "Wattcloud alert relay configured on $(hostname) at $(date -u)" \
    | mail -s "Wattcloud: msmtp relay test on $(hostname)" "$ALERT_EMAIL" 2>/dev/null \
    && ok "msmtp configured; test mail sent to $ALERT_EMAIL." \
    || warn "msmtp configured but test mail failed — check /etc/msmtprc."
  MSMTP_CONFIGURED=1
else
  warn "No SMTP relay configured — system alerts are journal-only."
  warn "Re-run with ALERT_SMTP_HOST/USER/PASS env vars to add email alerts."
fi

# =========================================================================
# 9. AIDE + rkhunter (file integrity + rootkit detection)
# =========================================================================
info "Installing AIDE and rkhunter..."
apt-get install -y -qq aide rkhunter > /dev/null

# Store ALERT_EMAIL for cron scripts.
echo "ALERT_EMAIL=$ALERT_EMAIL" > /etc/wattcloud-deploy.conf
chmod 644 /etc/wattcloud-deploy.conf

# Daily cron: mail only when aide --check finds changes (non-zero exit).
cat > /etc/cron.daily/aide-check <<'AIDECRON'
#!/bin/sh
set -eu
. /etc/wattcloud-deploy.conf 2>/dev/null || ALERT_EMAIL=root
out=$(mktemp)
trap 'rm -f "$out"' EXIT
if ! aide --check > "$out" 2>&1; then
    mail -s "AIDE diff on $(hostname)" "$ALERT_EMAIL" < "$out"
fi
AIDECRON
chmod 755 /etc/cron.daily/aide-check

# Auto-rebaseline AIDE after apt changes — trade-off accepted for BYO VPS;
# weekly golden-baseline cron below catches drift between apt runs.
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

# Golden baseline: untouched by the apt auto-rebaseline; weekly cron diffs it.
if [ -f /var/lib/aide/aide.db ] && [ ! -f /var/lib/aide/aide.db.golden ]; then
  cp /var/lib/aide/aide.db /var/lib/aide/aide.db.golden
  ok "AIDE golden baseline saved to aide.db.golden."
fi

cat > /etc/cron.weekly/aide-golden-check <<'AIDEGOLDEN'
#!/bin/sh
set -eu
. /etc/wattcloud-deploy.conf 2>/dev/null || ALERT_EMAIL=root
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

rkhunter --update > /dev/null 2>&1 || true
rkhunter --propupd > /dev/null 2>&1 || true
# Idempotent set-or-append a KEY=VALUE line in a config file.
set_kv() { local f="$1" k="$2" v="$3"
  if grep -q "^${k}=" "$f" 2>/dev/null; then sed -i "s|^${k}=.*|${k}=${v}|" "$f"; else echo "${k}=${v}" >> "$f"; fi
}
set_kv /etc/default/rkhunter CRON_DAILY_RUN '"true"'
set_kv /etc/rkhunter.conf    REPORT_EMAIL   "$ALERT_EMAIL"
ok "rkhunter configured (daily scan; alerts → $ALERT_EMAIL)."

# =========================================================================
# 10. allowed_signers for SSH-signed commits made from the VPS itself.
#     No bare-repo / push-to-deploy — CD runs via GH Actions + GHCR now.
# =========================================================================
install -d -m 755 -o appuser -g appuser /home/appuser/.config/git
ALLOWED_SIGNERS_FILE=/home/appuser/.config/git/allowed_signers
if ! grep -qF "$APPUSER_SSH_PUBKEY" "$ALLOWED_SIGNERS_FILE" 2>/dev/null; then
  printf "* %s\n" "$APPUSER_SSH_PUBKEY" >> "$ALLOWED_SIGNERS_FILE"
  chown appuser:appuser "$ALLOWED_SIGNERS_FILE"
fi
sudo -u appuser git config --global gpg.format ssh
sudo -u appuser git config --global gpg.ssh.allowedSignersFile "$ALLOWED_SIGNERS_FILE"
ok "allowed_signers wired for appuser."

# =========================================================================
# 11. PATH persistence for appuser sessions
# =========================================================================
echo 'export PATH="/usr/local/bin:$PATH"' > /etc/profile.d/wattcloud.sh
ok "PATH profile.d entry written."

# =========================================================================
# 12. GHCR docker login (as appuser — update.sh runs as appuser)
# =========================================================================
info "Configuring GHCR login for appuser..."
if [ -z "$GHCR_USER" ] && [ -t 0 ]; then
  printf "\nGitHub username for GHCR pulls: "; read -r GHCR_USER
fi
if [ -z "$GHCR_PAT" ] && [ -t 0 ]; then
  printf "GitHub PAT with read:packages scope: "; read -rs GHCR_PAT; echo
fi

if [ -n "$GHCR_USER" ] && [ -n "$GHCR_PAT" ]; then
  install -d -m 700 -o appuser -g appuser /home/appuser/.docker
  if printf '%s' "$GHCR_PAT" | sudo -u appuser docker login ghcr.io -u "$GHCR_USER" --password-stdin > /dev/null 2>&1; then
    ok "docker login ghcr.io succeeded (user: $GHCR_USER)."
  else
    die "docker login ghcr.io failed. Check GHCR_USER / GHCR_PAT (needs read:packages)."
  fi
else
  warn "GHCR_USER/GHCR_PAT not provided — run 'docker login ghcr.io' as appuser before update.sh."
fi

# =========================================================================
# 13. Generate secrets & create .env
# =========================================================================
ENV_FILE="$APP_DIR/.env"
if [ -f "$ENV_FILE" ]; then
  warn ".env already exists — preserving. Delete manually and re-run for fresh secrets."
else
  info "Generating secrets..."
  [ -f "$APP_DIR/.env.example" ] || die ".env.example not found at $APP_DIR/.env.example"
  cp "$APP_DIR/.env.example" "$ENV_FILE"

  sed -i "s|^RELAY_SIGNING_KEY=.*|RELAY_SIGNING_KEY=$(openssl rand -base64 48)|"             "$ENV_FILE"
  sed -i "s|^RELAY_SHARE_SIGNING_KEY=.*|RELAY_SHARE_SIGNING_KEY=$(openssl rand -base64 48)|" "$ENV_FILE"
  sed -i "s|^BYO_STATS_HMAC_KEY=.*|BYO_STATS_HMAC_KEY=$(openssl rand -hex 32)|"              "$ENV_FILE"
  sed -i "s|^BYO_DOMAIN=.*|BYO_DOMAIN=$BYO_DOMAIN|"                                          "$ENV_FILE"
  sed -i "s|^BYO_BASE_URL=.*|BYO_BASE_URL=https://$BYO_DOMAIN|"                              "$ENV_FILE"
  sed -i "s|^ENVIRONMENT=.*|ENVIRONMENT=production|"                                         "$ENV_FILE"
  chmod 600 "$ENV_FILE"; chown appuser:appuser "$ENV_FILE"
  ok "Secrets generated and .env created."

  # Warn on operator-supplied OAuth client IDs still empty.
  EMPTY_IDS=()
  for var in BYO_GDRIVE_CLIENT_ID BYO_DROPBOX_CLIENT_ID BYO_ONEDRIVE_CLIENT_ID BYO_BOX_CLIENT_ID BYO_PCLOUD_CLIENT_ID; do
    val=$(grep -E "^${var}=" "$ENV_FILE" | head -1 | cut -d= -f2-)
    [ -z "$val" ] && EMPTY_IDS+=("$var")
  done
  [ "${#EMPTY_IDS[@]}" -gt 0 ] && warn "OAuth IDs empty: ${EMPTY_IDS[*]} — fill $ENV_FILE and re-run to refresh /config.json."
fi

# =========================================================================
# 14. Traefik config update (domain + Let's Encrypt email)
# =========================================================================
info "Updating Traefik configuration..."
TRAEFIK_STATIC="$APP_DIR/traefik/traefik.yml"
if [ -f "$TRAEFIK_STATIC" ]; then
  sed -i "s|email:.*|email: $EMAIL|" "$TRAEFIK_STATIC"
  ok "Traefik ACME email set to $EMAIL."
else
  warn "traefik/traefik.yml not found — skipping (will be populated by the image)."
fi

ACME_FILE="$APP_DIR/traefik/acme.json"
if [ -d "$APP_DIR/traefik" ]; then
  [ -f "$ACME_FILE" ] || touch "$ACME_FILE"
  chmod 600 "$ACME_FILE"
fi

# =========================================================================
# 15. Docker log rotation
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
# 16. Swap file (if < 2GB RAM)
# =========================================================================
TOTAL_RAM_MB=$(($(grep MemTotal /proc/meminfo | awk '{print $2}') / 1024))
if [ "$TOTAL_RAM_MB" -lt 2048 ] && [ ! -f /swapfile ]; then
  info "Creating 2GB swap file (RAM: ${TOTAL_RAM_MB}MB)..."
  fallocate -l 2G /swapfile && chmod 600 /swapfile
  mkswap /swapfile > /dev/null && swapon /swapfile
  grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
  ok "2GB swap file created."
else
  ok "Swap: ${TOTAL_RAM_MB}MB RAM$([ -f /swapfile ] && echo ', /swapfile present' || echo ', no swap needed')."
fi

# =========================================================================
# 17. Write /config.json for the SPA — regenerated every run from .env.
#     TODO(operator): Traefik/byo-server must serve this at /config.json with
#     `Cache-Control: no-store`. The image owns the routing; the VPS only owns
#     the file on disk.
# =========================================================================
info "Writing config.json from .env..."
install -d -m 755 -o appuser -g appuser /var/www/wattcloud
# shellcheck disable=SC1090
set -a; . "$ENV_FILE"; set +a
CONFIG_JSON=/var/www/wattcloud/config.json
cat > "$CONFIG_JSON" <<CONFIG
{
  "baseUrl": "https://${BYO_DOMAIN}",
  "clientIds": {
    "gdrive":   "${BYO_GDRIVE_CLIENT_ID:-}",
    "dropbox":  "${BYO_DROPBOX_CLIENT_ID:-}",
    "onedrive": "${BYO_ONEDRIVE_CLIENT_ID:-}",
    "box":      "${BYO_BOX_CLIENT_ID:-}",
    "pcloud":   "${BYO_PCLOUD_CLIENT_ID:-}"
  }
}
CONFIG
chmod 0644 "$CONFIG_JSON"; chown appuser:appuser "$CONFIG_JSON"
if command -v jq &>/dev/null; then
  jq -e . < "$CONFIG_JSON" > /dev/null || die "Generated $CONFIG_JSON is not valid JSON — check .env quoting."
fi
ok "/config.json written ($CONFIG_JSON)."

# =========================================================================
# 18. Roll the first image via scripts/update.sh, if INITIAL_DIGEST supplied
# =========================================================================
UPDATE_SH="$APP_DIR/scripts/update.sh"
if [ -n "$INITIAL_DIGEST" ]; then
  if [ ! -x "$UPDATE_SH" ]; then
    die "INITIAL_DIGEST provided but $UPDATE_SH missing/not-executable."
  fi
  info "Rolling initial image: $INITIAL_DIGEST"
  sudo -u appuser -H bash -c "cd '$APP_DIR' && '$UPDATE_SH' '$INITIAL_DIGEST'" \
    || die "update.sh failed — check 'docker compose logs byo-server'."
  ok "Initial image deployed."
else
  warn "INITIAL_DIGEST not supplied — byo-server is NOT running yet."
fi

# =========================================================================
# Summary
# =========================================================================
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN} Wattcloud BYO VPS provisioned!${NC}"
echo -e "${GREEN}========================================${NC}"
echo "  BYO domain:   https://$BYO_DOMAIN"
echo "  SSH port:     $SSH_PORT"
echo "  .env:         $ENV_FILE"
echo "  /config.json: $CONFIG_JSON"
echo "  msmtp:        $([ "$MSMTP_CONFIGURED" -eq 1 ] && echo "configured (from: ${ALERT_FROM})" || echo "journal-only")"
echo "  AIDE:         $([ -f /var/lib/aide/aide.db ] && echo "baseline ready" || echo "pending")"
echo ""
if [ -z "$INITIAL_DIGEST" ]; then
  echo -e "${YELLOW}First-time deploy:${NC} push a v*.*.* tag to GitHub; release.yml publishes to"
  echo "  ghcr.io/wattzupbyte/wattcloud and prints the digest. Then on the VPS as appuser:"
  echo "    cd $APP_DIR && ./scripts/update.sh ghcr.io/wattzupbyte/wattcloud@sha256:<digest>"
  echo ""
fi
echo -e "${YELLOW}External next steps:${NC}"
echo "  1. DNS A/AAAA for $BYO_DOMAIN → this server's IP"
echo "  2. Sign Hetzner DPA/AVV (https://accounts.hetzner.com/gdpr)"
echo "  3. Register OAuth consents, fill BYO_*_CLIENT_ID in $ENV_FILE, re-run deploy-vps.sh"
echo "  4. Verify: curl -I https://$BYO_DOMAIN && curl -s https://$BYO_DOMAIN/config.json | jq ."
echo ""
