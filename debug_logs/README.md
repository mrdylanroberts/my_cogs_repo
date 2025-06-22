# DebugLogs Cog

Advanced log management and retrieval system for Red-DiscordBot with enterprise-grade features.

## Features

### Core Features
- **Multiple log retrieval methods**: Get full logs, recent entries, or filter by specific criteria
- **Smart file handling**: Automatically handles large files with truncation and file uploads
- **Cog-specific filtering**: Filter logs by specific cogs to debug individual components
- **Error and warning isolation**: Quickly find errors and warnings in your logs
- **Time-based filtering**: Get logs from specific time periods (e.g., last 5 minutes, 2 hours)
- **Search functionality**: Search for specific text patterns in logs
- **Combined filtering**: Use multiple filters together (e.g., cog + time, error + time)
- **Configurable settings**: Customize behavior per server
- **Rate limiting**: Prevents spam and abuse
- **Auto-cleanup**: Automatically clean up old temporary files
- **Timezone support**: Display times in your preferred timezone
- **Caching system**: Improves performance for repeated requests
- **Security features**: Path traversal protection and safe file handling

### 🆕 Ubuntu VPS Enhancements
- **systemd journal integration**: Direct access to systemd journal logs using `journalctl`
- **System resource monitoring**: Real-time CPU, memory, and disk usage monitoring
- **Service status checking**: Monitor systemd service health and status
- **IP-based rate limiting**: Enhanced security for VPS environments
- **Google Cloud Platform optimizations**: Specific optimizations for GCP VPS
- **Log rotation awareness**: Integration with Ubuntu's logrotate system
- **Streaming support**: Memory-efficient processing of large journal logs
- **Permission verification**: Automated checking of Ubuntu VPS permissions
- **Automated setup**: One-click Ubuntu VPS configuration script

## Commands

### Basic Commands

- `!debuglogs full` - Get the complete log file
- `!debuglogs recent` - Get logs from the last hour
- `!debuglogs cog <cog_name>` - Get logs specific to a cog

### Filtered Commands

- `!debuglogs errors` - Get only error messages
- `!debuglogs warnings` - Get only warning messages
- `!debuglogs search <search_term>` - Search for specific text in logs

### Time-based Commands

- `!debuglogs last5m` (or `5m`) - Get logs from the last 5 minutes
- `!debuglogs last10m` (or `10m`) - Get logs from the last 10 minutes
- `!debuglogs last15m` (or `15m`) - Get logs from the last 15 minutes
- `!debuglogs last30m` (or `30m`) - Get logs from the last 30 minutes
- `!debuglogs last1h` (or `1h`) - Get logs from the last 1 hour
- `!debuglogs last2h` (or `2h`) - Get logs from the last 2 hours
- `!debuglogs last6h` (or `6h`) - Get logs from the last 6 hours
- `!debuglogs last12h` (or `12h`) - Get logs from the last 12 hours
- `!debuglogs minutes <N>` - Get logs from the last N minutes

### Combined Filtering Commands
```
!debuglogs cogtime <cog> <time> [lines]     # Filter by cog and time
!debuglogs cogerrors <cog> [lines]          # Get errors from specific cog
!debuglogs cogwarnings <cog> [lines]        # Get warnings from specific cog
!debuglogs timeerrors <time> [lines]        # Get errors from time period
!debuglogs timewarnings <time> [lines]      # Get warnings from time period
```

### Flexible Command Chaining

The cog now supports flexible command chaining for even more powerful filtering:

```
# Using the chain command
!debuglogs chain emailnews errors recent 5    # Get emailnews cog errors from last 5 hours
!debuglogs chain admin warnings 30m          # Get admin cog warnings from last 30 minutes
!debuglogs chain errors 1h                   # Get all errors from last hour
!debuglogs chain mycog "connection timeout"   # Search for specific text in mycog logs

# Direct chaining (auto-detected)
!debuglogs emailnews errors recent 5         # Same as above, without 'chain' keyword
!debuglogs admin warnings 30m               # Direct syntax support
```

**Supported Filter Types:**
- **Cog names**: Any cog name (e.g., `emailnews`, `admin`, `modlog`)
- **Log levels**: `errors`, `warnings` (and variations like `error`, `warn`)
- **Time specifications**: `5m`, `30m`, `1h`, `2h`, etc.
- **Recent with count**: `recent` followed by a number (hours)
- **Search terms**: Quoted strings for text search

**Filter Order**: Filters can be specified in any order and will be applied intelligently.

### 🆕 Ubuntu VPS Commands
```
!debuglogs journal [lines]                  # Get systemd journal logs
!debuglogs journal_time <time> [lines]      # Get journal logs for specific time period
!debuglogs service_status [service]         # Show systemd service status
!debuglogs system_resources                 # Display system resource usage
!debuglogs permissions                      # Check Ubuntu VPS permissions
```

### Utility Commands

- `!debuglogs info` - Display log file information
- `!debuglogs tail <lines>` - Get the last N lines from the log

### Configuration Commands
```
!debuglogs config show                      # Show current settings
!debuglogs config channel <channel>         # Set default log channel
!debuglogs config maxsize <size_mb>         # Set max file size (MB)
!debuglogs config timezone <timezone>       # Set timezone (e.g., US/Eastern)
!debuglogs config ratelimit <number>        # Set rate limit per user
!debuglogs config maxresults <number>       # Set max search results
!debuglogs config cacheduration <minutes>   # Set cache duration
!debuglogs config reset                     # Reset all settings
```

### 🆕 Ubuntu VPS Configuration
```
!debuglogs config service <name>            # Set systemd service name
!debuglogs config journal_fallback <bool>   # Enable journal fallback
!debuglogs config gcp_optimization <bool>   # Enable GCP optimizations
!debuglogs config max_journal_lines <num>   # Set max journal lines (100-50000)
!debuglogs config ip_rate_limiting <bool>   # Enable IP-based rate limiting
!debuglogs config stream_large_logs <bool>  # Enable streaming for large logs
```

## Installation

### Standard Installation

1. Add this repository to your Red-DiscordBot:
   ```
   !repo add debug-logs <repository_url>
   ```

2. Install the cog:
   ```
   !cog install debug-logs debug_logs
   ```

3. Load the cog:
   ```
   !load debug_logs
   ```

### 🆕 Ubuntu VPS Setup

For enhanced Ubuntu VPS features, run the automated setup script:

```bash
# Navigate to the cog directory
cd ~/.local/share/Red-DiscordBot/cogs/debug_logs/

# Make the setup script executable
chmod +x ubuntu_setup.sh

# Run the setup script
./ubuntu_setup.sh
```

Or follow the manual setup guide in [README_UBUNTU.md](README_UBUNTU.md).

**Ubuntu VPS Features Include:**
- systemd journal integration
- System resource monitoring
- Service status checking
- Enhanced security features
- Google Cloud Platform optimizations

4. Ensure the bot has proper file system permissions to read log files.

5. Configure default settings (optional):
   ```
   [p]debuglogs config channel #admin-logs
   [p]debuglogs config maxsize 8
   ```

## Log File Detection

The cog automatically searches for Red-DiscordBot log files in common locations:

- `./logs/red.log`
- `./red.log`
- `~/.local/share/Red-DiscordBot/logs/red.log`
- `/var/log/red-discordbot/red.log`
- `C:\Users\Administrator\AppData\Local\Red-DiscordBot\logs\red.log`

If none of these paths exist, it will search for any `.log` files containing "red" in the current directory and `./logs/` directory.

## Permissions Required

- **Basic Commands**: Manage Guild permission or Moderator role
- **Configuration Commands**: Administrator permission

## File Size Handling

- Discord has file upload limits (8MB for regular users, 50MB for Nitro)
- Large files are automatically truncated with a warning
- Configurable maximum file size per guild
- Files are sent with timestamps in the filename for easy organization

## Use Cases

### Real-time Debugging
```
!debuglogs 5m          # Quick check of recent activity
!debuglogs 30m         # Last 30 minutes for broader context
!debuglogs 1h          # Last hour for comprehensive review
!debuglogs 2h          # Extended troubleshooting period
!debuglogs minutes 45  # Custom 45-minute window
```

### Cog-specific Troubleshooting
```
!debuglogs cog modlog     # Check moderation logs
!debuglogs cog economy   # Review economy cog issues
!debuglogs cog automod   # Automod-related problems
```

### Combined Filtering (Advanced) ⭐
```
!debuglogs cogtime admin 5m      # Admin cog issues in last 5 minutes
!debuglogs cogerrors economy     # All economy cog errors
!debuglogs timeerrors 1h         # All errors in the last hour
!debuglogs cogwarnings modlog    # Modlog warnings only
```

### Error Investigation
```
!debuglogs errors        # All recent errors
!debuglogs warnings      # Warning messages
!debuglogs search "timeout"  # Find timeout-related issues
```

### Sending to Specific Channels
```
!debuglogs recent #admin-logs     # Send to admin channel
!debuglogs errors #error-reports  # Route errors to specific channel
```

### Performance Monitoring
```
!debuglogs config cache 300      # Enable 5-minute caching
!debuglogs config ratelimit 3    # Limit to 3 commands per minute
!debuglogs config maxresults 500 # Limit search results
```

## Security & Performance

### Security Features
- **Permission Control**: Only administrators and users with "Manage Guild" permission can use commands
- **Path Traversal Protection**: Prevents access to files outside allowed directories
- **Rate Limiting**: Configurable limits prevent command spam and resource abuse
- **Audit Logging**: All command usage is logged for security monitoring
- **Safe File Handling**: Validates file types and paths before processing
- **Privacy Protection**: Log files sent as attachments, not displayed in chat

### Performance Optimizations
- **Intelligent Caching**: Frequently accessed log data is cached for faster retrieval
- **Smart Truncation**: Large files are intelligently truncated while preserving context
- **Background Processing**: Heavy operations don't block other bot functions
- **Memory Management**: Automatic cleanup of cache and temporary data
- **Efficient Filtering**: Optimized algorithms for fast log processing

### Best Practices
- Enable caching for frequently accessed logs
- Set appropriate rate limits based on server size
- Use combined filters to reduce processing overhead
- Monitor audit logs for unusual usage patterns
- Regular configuration reviews for optimal performance

## Troubleshooting

### Log File Not Found
- Ensure Red-DiscordBot is configured to write logs
- Check that the bot has read permissions for the log directory
- Verify log file locations in your Red installation
- Check the allowed log paths in configuration

### Performance Issues
- Enable caching: `!debuglogs config cache 300`
- Reduce search results: `!debuglogs config maxresults 500`
- Use more specific filters to reduce processing load
- Check rate limiting settings if commands are slow

### Large File Issues
- Adjust the `maxsize` setting if files are too large
- Use time-based filtering to reduce file size
- Consider using `tail` command for recent entries only
- Enable smart truncation for better context preservation

### Rate Limiting Issues
- Check current limits: `!debuglogs config show`
- Adjust limits: `!debuglogs config ratelimit <number>`
- Wait for rate limit reset (1 minute)
- Use caching to reduce repeated requests

### Permission Errors
- Ensure the bot has proper file system permissions
- Check Discord permissions for file uploads in the target channel
- Verify admin permissions for configuration commands

### Cache Issues
- Clear cache: `!debuglogs config cache 0` then re-enable
- Check cache duration settings
- Monitor memory usage if cache is too large

### Timezone Problems
- Set correct timezone: `!debuglogs config timezone <your_timezone>`
- Verify supported timezone list in configuration
- Check log timestamp formats are recognized

## Support

If you encounter issues or have suggestions for improvements, please check the Red-DiscordBot documentation or community resources.