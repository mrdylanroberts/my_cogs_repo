# Debug Logs Cog - Ubuntu VPS Enhancement Guide

This guide covers the enhanced features specifically designed for Red-DiscordBot running on Ubuntu 22.04 LTS with Google Cloud VPS and systemd journal logging.

## 🚀 Quick Setup

### Automated Setup (Recommended)

For automated setup, use the built-in setup command:

```
!debuglogs ubuntu_setup
```

This command will automatically perform all the steps below and provide real-time feedback on the setup process through Discord. The setup includes:

- Installing required system packages
- Adding your user to the systemd-journal group
- Creating necessary log directories
- Configuring log rotation
- Creating a systemd service template
- Testing journal access

After the setup completes, you may need to restart your bot if group changes were made.

### Manual Setup
If you prefer manual setup, follow the steps in the [Manual Configuration](#manual-configuration) section.

## 🆕 New Ubuntu/VPS Features

### Journal Integration
- **Direct systemd journal access** using `journalctl`
- **Time-based journal filtering** with natural language support
- **Service-specific log filtering** for Red-DiscordBot
- **Streaming support** for large journal logs

### System Monitoring
- **Real-time system resources** (CPU, memory, disk usage)
- **systemd service status** monitoring
- **Load average** and system health checks
- **Permission verification** for Ubuntu VPS features

### Security Enhancements
- **IP-based rate limiting** for VPS security
- **Path traversal protection** enhanced for Ubuntu paths
- **systemd-journal group** permission checking
- **Audit logging** for all command usage

### Performance Optimizations
- **Google Cloud Platform** specific optimizations
- **Log rotation awareness** for Ubuntu logrotate
- **Smart caching** with configurable duration
- **Memory-efficient streaming** for large logs

## 📋 New Commands

### Journal Commands
```
!debuglogs journal [lines]              # Get systemd journal logs
!debuglogs journal_time <time> [lines]  # Get journal logs for specific time period
```

**Examples:**
```
!debuglogs journal 100                  # Last 100 journal entries
!debuglogs journal_time 1h              # Journal logs from last hour
!debuglogs journal_time 30m 50          # Last 50 entries from last 30 minutes
```

### System Monitoring Commands
```
!debuglogs service_status [service]     # Show systemd service status
!debuglogs system_resources             # Display system resource usage
!debuglogs permissions                  # Check Ubuntu VPS permissions
```

**Examples:**
```
!debuglogs service_status red-discordbot    # Check bot service status
!debuglogs service_status                   # Check default service
!debuglogs system_resources                 # Show CPU, memory, disk usage
!debuglogs permissions                      # Verify journal access
```

## ⚙️ New Configuration Options

### Ubuntu/VPS Specific Settings
```
!debuglogs config service <name>            # Set systemd service name
!debuglogs config journal_fallback <bool>   # Enable journal fallback
!debuglogs config gcp_optimization <bool>   # Enable GCP optimizations
!debuglogs config max_journal_lines <num>   # Set max journal lines (100-50000)
!debuglogs config ip_rate_limiting <bool>   # Enable IP-based rate limiting
!debuglogs config stream_large_logs <bool>  # Enable streaming for large logs
```

**Configuration Examples:**
```
!debuglogs config service red-discordbot        # Set service name
!debuglogs config journal_fallback true         # Enable journal fallback
!debuglogs config gcp_optimization true         # Enable GCP optimizations
!debuglogs config max_journal_lines 10000       # Set max journal lines
!debuglogs config ip_rate_limiting true         # Enable IP rate limiting
!debuglogs config stream_large_logs true        # Enable log streaming
```

### View All Settings
```
!debuglogs config show                      # Display all configuration
```

## 🔧 Manual Configuration

### 1. System Requirements
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y python3-pip python3-dev build-essential

# Install Python dependencies
pip3 install --user psutil
```

### 2. User Permissions
```bash
# Add bot user to systemd-journal group
sudo usermod -a -G systemd-journal $(whoami)

# Verify group membership (after re-login)
groups
```

### 3. Log Directories
```bash
# Create log directories
mkdir -p ~/.local/share/Red-DiscordBot/logs
mkdir -p ~/redbot/logs
sudo mkdir -p /var/log/red-discordbot
sudo chown $(whoami):$(whoami) /var/log/red-discordbot
```

### 4. Log Rotation Setup
```bash
# Create logrotate configuration
sudo tee /etc/logrotate.d/red-discordbot > /dev/null <<EOF
~/.local/share/Red-DiscordBot/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    copytruncate
    su $(whoami) $(whoami)
}

/var/log/red-discordbot/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    copytruncate
    su $(whoami) $(whoami)
}
EOF
```

### 5. systemd Service (Optional)
```bash
# Create service file
sudo tee /etc/systemd/system/red-discordbot.service > /dev/null <<EOF
[Unit]
Description=Red-DiscordBot
After=network.target

[Service]
Type=simple
User=$(whoami)
Group=$(whoami)
WorkingDirectory=$HOME
ExecStart=/usr/bin/python3 -m redbot <your_instance_name>
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=red-discordbot

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable red-discordbot
sudo systemctl start red-discordbot
```

## 🔍 Troubleshooting

### Journal Access Issues
```bash
# Test journal access
journalctl --no-pager -n 5

# If access denied, check group membership
groups | grep systemd-journal

# Re-add to group if needed
sudo usermod -a -G systemd-journal $(whoami)
# Then log out and back in
```

### Permission Problems
```bash
# Check file permissions
ls -la ~/.local/share/Red-DiscordBot/logs/
ls -la /var/log/red-discordbot/

# Fix permissions if needed
chmod 755 ~/.local/share/Red-DiscordBot/logs/
sudo chown -R $(whoami):$(whoami) /var/log/red-discordbot/
```

### Service Status Issues
```bash
# Check service status
sudo systemctl status red-discordbot

# View service logs
journalctl -u red-discordbot -f

# Restart service
sudo systemctl restart red-discordbot
```

## 📊 Performance Tips

### For Google Cloud VPS
1. **Enable GCP optimizations**: `!debuglogs config gcp_optimization true`
2. **Use streaming for large logs**: `!debuglogs config stream_large_logs true`
3. **Set appropriate journal limits**: `!debuglogs config max_journal_lines 5000`
4. **Enable IP rate limiting**: `!debuglogs config ip_rate_limiting true`

### Memory Management
- **Cache duration**: Adjust based on available RAM
- **Max file size**: Set limits based on Discord upload limits
- **Journal lines**: Balance between completeness and performance

## 🔐 Security Considerations

### Rate Limiting
- **User-based**: Standard rate limiting per user
- **IP-based**: Additional protection for VPS environments
- **Configurable limits**: Adjust based on server capacity

### Path Security
- **Path traversal protection**: Prevents access to unauthorized files
- **Safe path validation**: Only allows access to designated log directories
- **Permission checking**: Verifies proper access rights

### Audit Logging
- **Command usage tracking**: All commands are logged
- **User identification**: Tracks who used which commands
- **Timestamp recording**: When commands were executed

## 📈 Monitoring and Alerts

### System Resource Monitoring
Use `!debuglogs system_resources` to monitor:
- **CPU usage**: Current and average load
- **Memory usage**: RAM and swap utilization
- **Disk usage**: Available space on all mounts
- **Load average**: System load over time

### Service Health Checks
Use `!debuglogs service_status` to check:
- **Service state**: Active, inactive, failed
- **Uptime**: How long the service has been running
- **Memory usage**: Service-specific memory consumption
- **Recent logs**: Latest service log entries

## 🆘 Support

If you encounter issues:
1. **Check permissions**: Run `!debuglogs permissions`
2. **Verify configuration**: Run `!debuglogs config show`
3. **Test journal access**: Run `!debuglogs journal 5`
4. **Check system resources**: Run `!debuglogs system_resources`
5. **Review service status**: Run `!debuglogs service_status`

## 📝 Changelog

### Ubuntu VPS Enhancements
- ✅ systemd journal integration
- ✅ System resource monitoring
- ✅ Service status checking
- ✅ IP-based rate limiting
- ✅ GCP optimizations
- ✅ Enhanced security features
- ✅ Automated setup script
- ✅ Comprehensive documentation

---

**Note**: These enhancements are specifically designed for Ubuntu 22.04 LTS running on Google Cloud VPS with systemd. Some features may not work on other operating systems or configurations.