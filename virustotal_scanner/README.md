# VirusTotal Scanner Cog

A comprehensive Discord bot cog that automatically scans URLs and file attachments using the VirusTotal API to detect malicious content and protect your server from scams and malware.

## Features

- 🔍 **Automatic URL Scanning**: Detects and scans URLs in messages
- 📎 **File Attachment Scanning**: Scans uploaded files for malware
- 🛡️ **Real-time Protection**: Automatic scanning with configurable settings
- 📊 **Detailed Reports**: Beautiful embeds with scan results
- ⚠️ **Threat Detection**: Color-coded results (Green=Clean, Orange=Suspicious, Red=Malicious)
- 🗑️ **Auto-deletion**: Optionally delete malicious content automatically
- 📢 **Admin Notifications**: Alert administrators when threats are detected
- ⚙️ **Highly Configurable**: Whitelist/blacklist channels, detection thresholds, and more
- 🔄 **Rate Limited**: Respects VirusTotal API limits (4 requests per minute for free accounts)

## Setup

### 1. Get a VirusTotal API Key

1. Visit [VirusTotal](https://www.virustotal.com/gui/join-us)
2. Create a free account
3. Go to your profile and copy your API key

### 2. Install the Cog

```
[p]load virustotal_scanner
```

### 3. Configure the API Key

```
[p]virustotal apikey YOUR_API_KEY_HERE
```

**Note**: The message containing your API key will be automatically deleted for security.

## Commands

### Admin Commands (Requires Manage Server permission)

- `[p]virustotal` - Show help for VirusTotal commands
- `[p]virustotal apikey <key>` - Set the VirusTotal API key
- `[p]virustotal toggle [true/false]` - Enable/disable automatic scanning
- `[p]virustotal settings` - Show current configuration
- `[p]virustotal scan <url_or_hash>` - Manually scan a URL or file hash

## Configuration Options

The cog stores the following settings per server:

- **API Key**: Your VirusTotal API key
- **Auto Scan**: Enable/disable automatic scanning (default: enabled)
- **Scan URLs**: Scan URLs in messages (default: enabled)
- **Scan Files**: Scan file attachments (default: enabled)
- **Whitelist Channels**: Only scan in these channels (empty = all channels)
- **Blacklist Channels**: Never scan in these channels
- **Min Detections**: Minimum detections to trigger warnings (default: 1)
- **Delete Malicious**: Auto-delete malicious content (default: disabled)
- **Notify Admins**: Send notifications to admins about threats (default: enabled)
- **Scan Delay**: Delay between scans in seconds (default: 2)

## How It Works

### Automatic Scanning

1. **Message Monitoring**: The cog listens to all messages in configured channels
2. **URL Detection**: Uses regex to find URLs in message content
3. **File Detection**: Checks for file attachments
4. **Queue Processing**: Adds scan requests to a queue with rate limiting
5. **API Requests**: Submits URLs/files to VirusTotal for analysis
6. **Result Processing**: Displays results in formatted embeds
7. **Threat Handling**: Takes action based on detection results

### Scan Results

- **✅ Clean**: 0 detections - content is safe
- **⚠️ Suspicious**: 1-4 detections - potentially risky
- **🚨 Malicious**: 5+ detections - likely dangerous

### Rate Limiting

The cog respects VirusTotal's free API limits:
- 4 requests per minute
- 15-second delay between scans
- Queue system to handle multiple requests

## Security Features

### Automatic Protection
- Real-time scanning of all content
- Immediate threat detection
- Optional auto-deletion of malicious content
- Admin notifications for security incidents

### Privacy & Security
- API keys are stored securely in bot config
- Messages containing API keys are auto-deleted
- No sensitive data is logged
- Respects Discord's file size limits (32MB max)

## Usage Examples

### Basic Setup
```
# Set API key
!virustotal apikey vt_api_key_here

# Check settings
!virustotal settings

# Enable auto-scanning
!virustotal toggle true
```

### Manual Scanning
```
# Scan a URL
!virustotal scan https://suspicious-website.com

# Scan a file hash
!virustotal scan d41d8cd98f00b204e9800998ecf8427e
```

### Advanced Configuration
```python
# These settings are stored in the bot's config system
# and can be modified through the Red-DiscordBot config commands

# Example: Set minimum detections to 3
[p]set guild virustotal_scanner min_detections 3

# Example: Enable auto-deletion
[p]set guild virustotal_scanner delete_malicious true
```

## Troubleshooting

### Common Issues

1. **"No API key configured"**
   - Solution: Set your VirusTotal API key using `[p]virustotal apikey`

2. **"Scan failed"**
   - Check your API key is valid
   - Ensure you haven't exceeded rate limits
   - Verify the URL/file is accessible

3. **"No results found"**
   - The file/URL hasn't been scanned before
   - Wait a few minutes and try again
   - Some content may not be scannable

### Rate Limit Issues

If you're hitting rate limits:
- Increase the scan delay in settings
- Consider upgrading to a paid VirusTotal account
- Reduce the number of channels being monitored

## API Limits

### Free Account
- 4 requests per minute
- 500 requests per day
- 15,500 requests per month

### Paid Accounts
Consider upgrading for higher limits if you have a large server.

## Support

If you encounter issues:
1. Check the bot's logs for error messages
2. Verify your API key is correct
3. Ensure the bot has necessary permissions
4. Check VirusTotal's service status

## Permissions Required

The bot needs these Discord permissions:
- Read Messages
- Send Messages
- Embed Links
- Manage Messages (for auto-deletion feature)
- Read Message History

## Privacy Notice

This cog:
- Sends URLs and file hashes to VirusTotal for analysis
- Does not store or log message content
- Automatically deletes API key messages
- Only processes public message content

By using this cog, you acknowledge that URLs and files will be sent to VirusTotal's servers for analysis.