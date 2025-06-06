# Help Detector Cog for Red-DiscordBot

This cog automatically detects when users ask for help in chat and directs them to the dedicated help channel.

## Features

- Monitors chat messages for help-related keywords
- Automatically responds with directions to the help channel
- Includes 1-hour cooldown per user to prevent spam
- Ignores bot messages and commands
- Responds without pinging the user

## Installation

```bash
[p]repo add my-cogs <repository_url>
[p]cog install my-cogs help_detector
[p]load help_detector
```

## Usage

Once installed and loaded, the cog will automatically monitor chat messages for help-related keywords such as:
- "i need help"
- "need help"
- "can someone help"
- "help me"
- "help please"
- "anyone help"
- "how do i"
- "how to"

When these keywords are detected, the bot will reply with a message directing the user to the help channel.

## Note

Make sure your server has a channel named "❓・questions-help" or modify the code to match your help channel's name.