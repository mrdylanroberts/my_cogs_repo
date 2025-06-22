# My Cogs Repository

> A collection of custom cogs for Red-DiscordBot focused on server automation, security, and utility features.

## Available Cogs

| Cog | Description | Author |
|-----|-------------|--------|
| **CommandBatch** | Execute multiple commands in sequence with custom profiles | mrdylanroberts |
| **EmailNews** | Forward emails from specified senders to Discord channels | mrdylanroberts |
| **Glossary** | Interactive cybersecurity glossary with user contributions | mrdylanroberts |
| **HelpDetector** | Detects help-related messages and directs users to the help channel | mrdylanroberts |
| **JoinLeaveThreads** | Sends join/leave messages to threads | mrdylanroberts |
| **RoleCleanup** | Automatically manages roles based on reactions in specified channels | mrdylanroberts |
| **VirusTotalScanner** | Automatically scan URLs and file attachments using VirusTotal API | mrdylanroberts |

## Installation

To add this repository to your Red-DiscordBot:

```
[p]repo add my-cogs-repo https://github.com/mrdylanroberts/my_cogs_repo
```

To install and load a cog:

```
[p]cog install my-cogs-repo <cog_name>
[p]load <cog_name>
```

## Cog Details

### CommandBatch
Execute multiple commands in sequence with custom profiles. Perfect for testing workflows, cog management, and repetitive tasks.

**Features:**
- Create custom command profiles
- Execute multiple commands with a single command
- Ideal for automation and testing

### EmailNews
Securely forward emails from specific senders to designated Discord channels with encrypted credential storage.

**Features:**
- Secure credential storage using encryption
- Forward emails from specific senders
- Configurable email checking interval
- Selective forwarding based on sender addresses
- Secure setup process through DMs

### Glossary
A comprehensive cybersecurity glossary with interactive features and user contributions.

**Features:**
- Browse terms with pagination
- Search for definitions
- User contribution system with moderation
- Alphabetical sorting and Discord UI integration

### HelpDetector
Monitors messages for help-related keywords and automatically directs users to the help channel.

**Features:**
- Automatic help keyword detection
- Configurable response messages
- Cooldown system to prevent spam

### JoinLeaveThreads
Sends customizable join and leave messages to specific Discord threads.

**Features:**
- Customizable messages with placeholders
- Support for existing or new threads
- Configurable thread naming

### RoleCleanup
Automatically manages roles based on user reactions in specified channels.

**Features:**
- Welcome channel reaction handling
- Role selection channel automation
- Fully configurable through Discord commands
- Works with RolesButtons cog for button interactions

### VirusTotalScanner
Real-time protection against malicious content using VirusTotal API.

**Features:**
- Automatic URL and file scanning
- Configurable threat detection
- Detailed security reports
- Server protection from malware and scams

## Support

For detailed setup instructions and troubleshooting, check the individual README files in each cog's folder.

## Requirements

- Red-DiscordBot 3.5.0 or higher
- Some cogs may have additional requirements listed in their individual folders

---

*Made with ❤️ for the Red-DiscordBot community*