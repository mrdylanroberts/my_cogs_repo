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

Once installed and loaded, the cog will automatically monitor chat messages for help-related keywords.

### Setting up the Cog

Before the cog can function, you need to set a help channel. Use the following command:

```
[p]helpdetectorset channel #your-help-channel
```

Replace `#your-help-channel` with the actual channel you want users to be directed to.

### How it Works

When a user sends a message containing one of the configured keywords, the bot will reply with a message directing them to the specified help channel. By default, it listens for keywords like:
- "i need help"
- "need help"
- "can someone help"
- "help me"
- "help please"
- "anyone help"
- "how do i"
- "how to"

You can customize these keywords.

### Commands

The following commands are available to manage the HelpDetector cog (requires admin or manage_guild permissions):

- `[p]helpdetectorset channel <channel>`: Sets the channel where users will be directed for help.
  - Example: `[p]helpdetectorset channel #support`
- `[p]helpdetectorset addkeyword <keyword>`: Adds a new keyword to the detection list.
  - Example: `[p]helpdetectorset addkeyword assistance needed`
- `[p]helpdetectorset removekeyword <keyword>`: Removes a keyword from the detection list.
  - Example: `[p]helpdetectorset removekeyword help me`
- `[p]helpdetectorset listkeywords`: Lists all currently configured keywords.
- `[p]helpdetectorset setreactionmode <mode>`: Sets the emoji reaction mode. 
  - Modes:
    - `cooldown`: Reactions are added, but subject to the user cooldown (default).
    - `always`: Reactions are always added if a keyword is detected (DM cooldown still applies).
    - `off`: No emoji reactions will be added.
  - Example: `[p]helpdetectorset setreactionmode always`
- `[p]helpdetectorset viewsettings`: Shows the current help channel, configured keywords, and reaction mode.