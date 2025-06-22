#!/bin/bash
# Ubuntu VPS Setup Script for Red-DiscordBot Debug Logs Cog
# This script configures the Ubuntu environment for enhanced debug_logs functionality

set -e  # Exit on any error

echo "🚀 Setting up Ubuntu VPS for Red-DiscordBot Debug Logs Cog..."
echo "================================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_error "This script should not be run as root for security reasons."
   print_status "Please run as the user that runs Red-DiscordBot."
   exit 1
fi

# Get the current user
CURRENT_USER=$(whoami)
print_status "Setting up for user: $CURRENT_USER"

# 1. Install required system packages
print_status "Installing required system packages..."
sudo apt update
sudo apt install -y python3-pip python3-dev build-essential

# 2. Install Python packages
print_status "Installing required Python packages..."
pip3 install --user psutil

# 3. Add user to systemd-journal group for journal access
print_status "Adding user to systemd-journal group..."
if groups $CURRENT_USER | grep -q "\bsystemd-journal\b"; then
    print_success "User $CURRENT_USER is already in systemd-journal group"
else
    sudo usermod -a -G systemd-journal $CURRENT_USER
    print_success "Added $CURRENT_USER to systemd-journal group"
    print_warning "You may need to log out and back in for group changes to take effect"
fi

# 4. Create log directories
print_status "Creating log directories..."
LOG_DIRS=(
    "$HOME/.local/share/Red-DiscordBot/logs"
    "$HOME/redbot/logs"
    "/var/log/red-discordbot"
)

for dir in "${LOG_DIRS[@]}"; do
    if [[ "$dir" == "/var/log/red-discordbot" ]]; then
        # System directory - needs sudo
        if [[ ! -d "$dir" ]]; then
            sudo mkdir -p "$dir"
            sudo chown $CURRENT_USER:$CURRENT_USER "$dir"
            print_success "Created system log directory: $dir"
        else
            print_success "System log directory already exists: $dir"
        fi
    else
        # User directory
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir"
            print_success "Created user log directory: $dir"
        else
            print_success "User log directory already exists: $dir"
        fi
    fi
done

# 5. Configure logrotate for Red-DiscordBot logs
print_status "Configuring log rotation..."
LOGROTATE_CONFIG="/etc/logrotate.d/red-discordbot"

sudo tee $LOGROTATE_CONFIG > /dev/null <<EOF
# Red-DiscordBot log rotation configuration
$HOME/.local/share/Red-DiscordBot/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    copytruncate
    su $CURRENT_USER $CURRENT_USER
}

/var/log/red-discordbot/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    copytruncate
    su $CURRENT_USER $CURRENT_USER
}
EOF

print_success "Configured log rotation"

# 6. Create systemd service file template
print_status "Creating systemd service template..."
SERVICE_TEMPLATE="$HOME/red-discordbot.service.template"

cat > $SERVICE_TEMPLATE <<EOF
# Red-DiscordBot systemd service template
# Copy this to /etc/systemd/system/red-discordbot.service and customize

[Unit]
Description=Red-DiscordBot
After=network.target

[Service]
Type=simple
User=$CURRENT_USER
Group=$CURRENT_USER
WorkingDirectory=$HOME
ExecStart=/usr/bin/python3 -m redbot <instance_name>
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=red-discordbot

# Environment variables
Environment=PYTHONPATH=$HOME/.local/lib/python3.*/site-packages

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$HOME/.local/share/Red-DiscordBot
ReadWritePaths=/var/log/red-discordbot

[Install]
WantedBy=multi-user.target
EOF

print_success "Created systemd service template: $SERVICE_TEMPLATE"

# 7. Check journal access
print_status "Testing journal access..."
if journalctl --no-pager -n 1 >/dev/null 2>&1; then
    print_success "Journal access is working"
else
    print_warning "Journal access test failed. You may need to log out and back in."
fi

# 8. Create a test log entry
print_status "Creating test log entry..."
logger -t red-discordbot-test "Debug logs cog setup completed successfully"
print_success "Test log entry created"

# 9. Display system information
print_status "System Information:"
echo "  OS: $(lsb_release -d | cut -f2)"
echo "  Kernel: $(uname -r)"
echo "  Python: $(python3 --version)"
echo "  User: $CURRENT_USER"
echo "  Groups: $(groups $CURRENT_USER)"
echo "  Journal access: $(journalctl --no-pager -n 1 >/dev/null 2>&1 && echo 'OK' || echo 'FAILED')"

# 10. Display next steps
echo ""
echo "================================================"
print_success "Ubuntu VPS setup completed!"
echo ""
print_status "Next steps:"
echo "1. If you saw group change warnings, log out and back in"
echo "2. Install the debug_logs cog in your Red-DiscordBot"
echo "3. Configure the cog with: !debuglogs config service red-discordbot"
echo "4. Enable journal fallback: !debuglogs config journal_fallback true"
echo "5. Test journal access: !debuglogs journal 50"
echo ""
print_status "Optional: Create systemd service"
echo "1. Copy $SERVICE_TEMPLATE to /etc/systemd/system/red-discordbot.service"
echo "2. Edit the service file to match your setup"
echo "3. Run: sudo systemctl enable red-discordbot"
echo "4. Run: sudo systemctl start red-discordbot"
echo ""
print_success "Setup complete! Your Ubuntu VPS is ready for enhanced debug logging."