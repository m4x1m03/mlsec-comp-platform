#!/usr/bin/env bash
# =============================================================================
# CAPE v2 Installation Script
# =============================================================================
# Usage: sudo ./install_cape.sh <username>
#   <username>  The non-root user to configure with KVM/QEMU
#
# This script is resumable. If a reboot is required between stages, simply
# re-run the same command after rebooting and it will pick up where it left off.
# =============================================================================

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ── Logging helpers ───────────────────────────────────────────────────────────
log()     { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
die()     { error "$*"; exit 1; }

# ── State file ────────────────────────────────────────────────────────────────
STATE_FILE="/var/tmp/cape_install_stage"
LOG_DIR="$HOME/cape_install_logs"
mkdir -p "$LOG_DIR"

# ── Argument validation ───────────────────────────────────────────────────────
USERNAME="${1:-}"
[[ -z "$USERNAME" ]] && die "Usage: $0 <username>\n       Supply the non-root user for KVM/QEMU configuration."
id "$USERNAME" &>/dev/null || die "User '$USERNAME' does not exist on this system."

# ── Must run as root ──────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && die "This script must be run as root (use sudo)."

# ── Helper: run a command, log output, retry on failure ──────────────────────
run_cmd() {
    local retries=$1; shift
    local desc=$1;    shift
    local attempt=1

    while (( attempt <= retries )); do
        log "[$attempt/$retries] $desc"
        if "$@" 2>&1 | tee -a "$LOG_DIR/install.log"; then
            success "$desc"
            return 0
        fi
        warn "Attempt $attempt failed for: $desc"
        (( attempt++ ))
        (( attempt <= retries )) && { warn "Retrying in 5 s…"; sleep 5; }
    done

    error "All $retries attempt(s) failed for: $desc"
    return 1
}

# ── Helper: apt-get with retry and broken-package recovery ───────────────────
safe_apt() {
    local desc="apt-get $*"
    local attempt=1 max=3

    while (( attempt <= max )); do
        log "[$attempt/$max] $desc"
        if DEBIAN_FRONTEND=noninteractive apt-get -y \
               -o Dpkg::Options::="--force-confdef" \
               -o Dpkg::Options::="--force-confold" \
               "$@" 2>&1 | tee -a "$LOG_DIR/apt.log"; then
            success "$desc"
            return 0
        fi

        warn "apt-get failed (attempt $attempt). Attempting recovery…"
        dpkg --configure -a 2>&1 | tee -a "$LOG_DIR/apt.log" || true
        apt-get -f install -y     2>&1 | tee -a "$LOG_DIR/apt.log" || true
        (( attempt++ ))
        sleep 5
    done

    die "apt-get $* failed after $max attempts. Check $LOG_DIR/apt.log"
}

# ── Helper: save stage and prompt user to reboot manually ────────────────────
prompt_reboot() {
    local next_stage=$1
    local msg="${2:-Stage complete. A reboot is required before continuing.}"

    log "Saving resume stage → $next_stage"
    echo "$next_stage" > "$STATE_FILE"

    echo ""
    echo -e "${YELLOW}${BOLD}┌─────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${YELLOW}${BOLD}│  REBOOT REQUIRED                                        │${RESET}"
    echo -e "${YELLOW}${BOLD}└─────────────────────────────────────────────────────────┘${RESET}"
    warn "$msg"
    echo ""
    echo -e "  Reboot your system, then resume installation by re-running:"
    echo -e "  ${BOLD}sudo $(realpath "$0") $USERNAME${RESET}"
    echo ""
    exit 0
}

# ── Read current stage ────────────────────────────────────────────────────────
STAGE=$( [[ -f "$STATE_FILE" ]] && cat "$STATE_FILE" || echo "1" )
log "Resuming from stage $STAGE"

# =============================================================================
# STAGE 1 – Update base packages and install git, then prompt reboot
# =============================================================================
if [[ "$STAGE" == "1" ]]; then
    echo -e "\n${BOLD}══ Stage 1: Update base packages ══${RESET}"

    safe_apt update
    safe_apt upgrade
    safe_apt dist-upgrade
    safe_apt install git

    prompt_reboot "2" "Base packages updated. Please reboot before continuing."
fi

# =============================================================================
# STAGE 2 – Clone CAPEv2 and run kvm-qemu.sh, then prompt reboot
# =============================================================================
if [[ "$STAGE" == "2" ]]; then
    echo -e "\n${BOLD}══ Stage 2: Clone CAPEv2 & KVM/QEMU setup ══${RESET}"

    CAPE_DIR="$HOME/Cape"

    if [[ -d "$CAPE_DIR/CAPEv2/.git" ]]; then
        warn "CAPEv2 repo already cloned at $CAPE_DIR/CAPEv2 – skipping clone."
    else
        mkdir -p "$CAPE_DIR"
        run_cmd 3 "Clone CAPEv2 repository" \
            git clone https://github.com/kevoreilly/CAPEv2.git "$CAPE_DIR/CAPEv2" \
            || die "Could not clone CAPEv2. Check network connectivity."
    fi

    INSTALLER_DIR="$CAPE_DIR/CAPEv2/installer"
    [[ -f "$INSTALLER_DIR/kvm-qemu.sh" ]] \
        || die "kvm-qemu.sh not found in $INSTALLER_DIR"

    chmod a+x "$INSTALLER_DIR/kvm-qemu.sh"

    if grep -q '<WOOT>' "$INSTALLER_DIR/kvm-qemu.sh"; then
        sed -i 's/<WOOT>/ABCD/g' "$INSTALLER_DIR/kvm-qemu.sh"
        success "Placeholder <WOOT> replaced with ABCD in kvm-qemu.sh"
    else
        warn "<WOOT> placeholder not found – already replaced or not present."
    fi

    log "Running kvm-qemu.sh (output → $LOG_DIR/kvm-qemu.log)"
    if ! bash "$INSTALLER_DIR/kvm-qemu.sh" all "$USERNAME" \
            2>&1 | tee "$LOG_DIR/kvm-qemu.log"; then
        error "kvm-qemu.sh reported a non-zero exit."
        warn "Review $LOG_DIR/kvm-qemu.log for details."
        warn "Common fixes:"
        warn "  • Ensure VT-x/AMD-V is enabled in BIOS/UEFI."
        warn "  • Ensure the host is not already a VM without nested virt enabled."
        die  "kvm-qemu.sh failed. Correct the issue and re-run this script."
    fi

    prompt_reboot "3" "KVM/QEMU setup complete. Please reboot before continuing."
fi

# =============================================================================
# STAGE 3 – Run cape2.sh, then prompt reboot
# =============================================================================
if [[ "$STAGE" == "3" ]]; then
    echo -e "\n${BOLD}══ Stage 3: CAPE base installation ══${RESET}"

    INSTALLER_DIR="$HOME/Cape/CAPEv2/installer"
    [[ -f "$INSTALLER_DIR/cape2.sh" ]] \
        || die "cape2.sh not found in $INSTALLER_DIR"

    chmod a+x "$INSTALLER_DIR/cape2.sh"

    log "Running cape2.sh base cape (output → $LOG_DIR/cape.log)"
    if ! bash "$INSTALLER_DIR/cape2.sh" base cape \
            2>&1 | tee "$LOG_DIR/cape.log"; then
        error "cape2.sh reported a non-zero exit."
        warn "Review $LOG_DIR/cape.log for details."
        warn "Common fixes:"
        warn "  • Re-run the script; some package installs are flaky on first run."
        warn "  • Check internet connectivity."
        die  "cape2.sh failed. Correct the issue and re-run this script."
    fi

    prompt_reboot "4" "Cape base install done. Please reboot before continuing."
fi

# =============================================================================
# STAGE 4 – Install Poetry and project dependencies
# =============================================================================
if [[ "$STAGE" == "4" ]]; then
    echo -e "\n${BOLD}══ Stage 4: Poetry & Python dependencies ══${RESET}"

    CAPE_OPT="/opt/CAPEv2"
    [[ -d "$CAPE_OPT" ]] \
        || die "/opt/CAPEv2 not found. Did cape2.sh run successfully?"

    safe_apt install python3-poetry

    POETRY_VERSION="2.3.2"
    log "Installing Poetry $POETRY_VERSION for user 'cape'…"
    if ! sudo -u cape bash -c \
        "curl -sSL https://install.python-poetry.org | python3 - --version $POETRY_VERSION" \
        2>&1 | tee -a "$LOG_DIR/poetry.log"; then
        warn "Poetry installer script failed on first attempt. Retrying after clearing pip cache…"
        sudo -u cape bash -c "python3 -m pip cache purge 2>/dev/null || true"
        sudo -u cape bash -c \
            "curl -sSL https://install.python-poetry.org | python3 - --version $POETRY_VERSION" \
            2>&1 | tee -a "$LOG_DIR/poetry.log" \
            || die "Poetry install failed twice. Check $LOG_DIR/poetry.log"
    fi
    success "Poetry $POETRY_VERSION installed for 'cape'."

    EXPORT_LINE='export PATH=/home/cape/.local/bin:$PATH'
    if ! sudo -u cape bash -c "grep -qF '$EXPORT_LINE' /home/cape/.bashrc 2>/dev/null"; then
        sudo -u cape bash -c "echo '$EXPORT_LINE' >> /home/cape/.bashrc"
        success "PATH export added to /home/cape/.bashrc"
    else
        warn "PATH export already present in /home/cape/.bashrc – skipping."
    fi

    if [[ -f /home/cape/.local/bin/poetry ]]; then
        ln -sf /home/cape/.local/bin/poetry /usr/local/bin/poetry
        success "Symlinked poetry → /usr/local/bin/poetry"
    else
        warn "/home/cape/.local/bin/poetry not found after install – symlink skipped."
    fi

    log "Running 'poetry install' in $CAPE_OPT…"
    if ! sudo -u cape bash -c \
        "cd $CAPE_OPT && /home/cape/.local/bin/poetry install" \
        2>&1 | tee -a "$LOG_DIR/poetry_install.log"; then
        warn "poetry install failed. Attempting with --no-cache flag…"
        sudo -u cape bash -c \
            "cd $CAPE_OPT && /home/cape/.local/bin/poetry install --no-cache" \
            2>&1 | tee -a "$LOG_DIR/poetry_install.log" \
            || die "poetry install failed. Check $LOG_DIR/poetry_install.log"
    fi
    success "Python dependencies installed via Poetry."

    # Clean up state file — installation is complete
    rm -f "$STATE_FILE"

    echo ""
    echo -e "${GREEN}${BOLD}╔═════════════════════════════════════════════════╗${RESET}"
    echo -e "${GREEN}${BOLD}║   CAPE v2 installation completed successfully   ║${RESET}"
    echo -e "${GREEN}${BOLD}╚═════════════════════════════════════════════════╝${RESET}"
    echo ""
    log "All logs are in: $LOG_DIR"
    log "Next step: configure /opt/CAPEv2/conf/ and configure Windows Guest VM"
fi