#!/bin/bash
# setup.sh - Configure a Linux VM for the VM File Restore Operator
#
# Usage:
#   sudo ./setup.sh "ssh-ed25519 AAAA...xyz"
#
# filerestore.sh must be in the same directory as this script.
#
# This script:
# - Creates the 'filerestore' user with sudo access
# - Configures SSH key authentication
# - Sets up passwordless sudo for the restore script
# - Installs the filerestore.sh helper script from the same directory

set -e

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root or with sudo"
    echo "Usage: sudo $0 \"ssh-ed25519 AAAA...xyz\""
    exit 1
fi

# Check arguments
if [ $# -ne 1 ]; then
    echo "ERROR: Public key argument required"
    echo "Usage: sudo $0 \"ssh-ed25519 AAAA...xyz\""
    exit 1
fi

PUB_KEY="$1"
STAGED_HELPER="$(dirname "$0")/filerestore.sh"

# Validate public key format (basic check)
if [[ "$PUB_KEY" == *$'\n'* ]]; then
    echo "ERROR: Public key must be a single line"
    exit 1
fi
if [[ ! "$PUB_KEY" =~ ^ssh- ]]; then
    echo "ERROR: Public key must start with 'ssh-' (e.g., ssh-ed25519, ssh-rsa)"
    exit 1
fi

echo "Setting up VM for file restore operator..."

# Detect sudo group (wheel for RHEL/Fedora, sudo for Debian/Ubuntu)
if getent group wheel >/dev/null 2>&1; then
    SUDO_GROUP="wheel"
elif getent group sudo >/dev/null 2>&1; then
    SUDO_GROUP="sudo"
else
    echo "ERROR: Neither 'wheel' nor 'sudo' group found on this system."
    echo "The filerestore user requires sudo access to mount volumes."
    echo "Please install sudo and configure sudoers, then retry."
    exit 1
fi

# Create filerestore user
echo "Creating filerestore user..."
if id -u filerestore >/dev/null 2>&1; then
    echo "  User 'filerestore' already exists, skipping creation"
    if ! id -Gn filerestore | grep -qw "$SUDO_GROUP"; then
        usermod -aG "$SUDO_GROUP" filerestore
        echo "  Added to sudo group: $SUDO_GROUP"
    fi
else
    useradd -m -s /bin/bash -G "$SUDO_GROUP" filerestore
    echo "  Created user with group: $SUDO_GROUP"
fi

# Set up SSH directory
echo "Setting up SSH directory..."
mkdir -p ~filerestore/.ssh
chmod 700 ~filerestore/.ssh

# Add public key with command restriction
echo "Installing SSH public key..."
linuxHelperScript="/usr/local/bin/filerestore.sh"
RESTRICTED_KEY="command=\"$linuxHelperScript\" $PUB_KEY"
# Remove any existing entries for this key (restricted or unrestricted) before adding
# the command-restricted form. An unrestricted entry would allow arbitrary SSH commands,
# bypassing the intended restriction.
if [ -f ~filerestore/.ssh/authorized_keys ]; then
    grep -vF "$PUB_KEY" ~filerestore/.ssh/authorized_keys > ~filerestore/.ssh/authorized_keys.tmp
    mv ~filerestore/.ssh/authorized_keys.tmp ~filerestore/.ssh/authorized_keys
    echo "$RESTRICTED_KEY" >> ~filerestore/.ssh/authorized_keys
    echo "  Key added/updated in authorized_keys (command-restricted)"
else
    echo "$RESTRICTED_KEY" > ~filerestore/.ssh/authorized_keys
    echo "  Key installed in new authorized_keys (command-restricted)"
fi
chmod 600 ~filerestore/.ssh/authorized_keys
chown -R filerestore:filerestore ~filerestore/.ssh
echo "  Key: ${PUB_KEY:0:30}..."

# Configure sudoers
echo "Configuring passwordless sudo..."
echo "filerestore ALL=(ALL) NOPASSWD: /usr/local/bin/filerestore.sh" > /etc/sudoers.d/filerestore
chmod 440 /etc/sudoers.d/filerestore

# Validate sudoers file
if ! visudo -c -f /etc/sudoers.d/filerestore >/dev/null 2>&1; then
    echo "ERROR: Invalid sudoers configuration"
    rm -f /etc/sudoers.d/filerestore
    exit 1
fi
echo "  Sudoers configured: /etc/sudoers.d/filerestore"

# Install helper script from the same directory as this script
echo "Installing filerestore.sh helper script..."
if [ -L "$STAGED_HELPER" ]; then
    echo "ERROR: filerestore.sh must not be a symlink: $STAGED_HELPER"
    exit 1
fi
if [ ! -f "$STAGED_HELPER" ]; then
    echo "ERROR: filerestore.sh not found next to setup.sh: $STAGED_HELPER"
    exit 1
fi
# Reject world-writable or non-root-owned files
staged_uid="$(stat -c '%u' "$STAGED_HELPER" 2>/dev/null || true)"
if [ "$staged_uid" != "0" ]; then
    echo "ERROR: filerestore.sh must be owned by root (uid 0): $STAGED_HELPER"
    exit 1
fi
staged_mode="$(stat -c '%a' "$STAGED_HELPER" 2>/dev/null || true)"
if [ -n "$staged_mode" ] && [ "$((8#$staged_mode & 0022))" -ne 0 ]; then
    echo "ERROR: filerestore.sh must not be group/world-writable: $STAGED_HELPER (mode $staged_mode)"
    exit 1
fi
cp "$STAGED_HELPER" /usr/local/bin/filerestore.sh
chmod +x /usr/local/bin/filerestore.sh
echo "  Installed: /usr/local/bin/filerestore.sh"

# Verify installation
echo ""
echo "Setup complete! Verifying..."
echo "  User: $(id filerestore)"
echo "  SSH key: $(wc -l < ~filerestore/.ssh/authorized_keys) key(s) installed"
echo "  Sudoers: $(grep filerestore /etc/sudoers.d/filerestore)"
if [ -x /usr/local/bin/filerestore.sh ]; then
    echo "  Helper script: /usr/local/bin/filerestore.sh (executable)"
else
    echo "  Helper script: ERROR - not found or not executable"
fi
echo ""
echo "VM is ready for file restore operations!"
