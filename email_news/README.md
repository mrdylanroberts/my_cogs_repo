# Email News Cog for Red-DiscordBot

A secure cog that allows forwarding emails from specific senders to designated Discord channels. Perfect for receiving newsletters, updates, and notifications from trusted email senders directly in your Discord server.

## Features

- 🔒 Secure credential storage using encryption
- 📧 Forward emails from specific senders to designated Discord channels
- ⚙️ Configurable email checking interval
- 🎯 Selective forwarding based on sender email addresses
- 🔐 Secure setup process through DMs

## Installation

1. Add the repository to your bot:
```
!repo add my-cogs-repo <repository-url>
```

2. Install the cog:
```
!cog install my-cogs-repo email_news
```

3. Load the cog:
```
!load email_news
```

## Initial Setup

Before using the cog, you need to set up a secure encryption key. Use the following command to set it:
```
!set api email_news secret,<your-secret-key>
```
Replace `<your-secret-key>` with a strong, random string. Keep this key secure as it's used to encrypt email credentials.

## Commands

### Email Account Setup
```
!emailnews setup <email> <password>
```
- Sets up an email account for monitoring
- Use this command in a server channel (credentials will be deleted and response sent via DM)
- Currently supports Gmail accounts

### Sender Management
```
!emailnews addsender <sender_email> [channel]
```
- Adds a sender email to forward messages from
- Optionally specify a channel (defaults to current channel)

```
!emailnews removesender <sender_email>
```
- Removes a sender email from the forwarding list

```
!emailnews listsenders
```
- Lists all configured sender filters and their target channels

### Configuration
```
!emailnews interval <seconds>
```
- Sets how often to check for new emails
- Minimum interval: 60 seconds

## Security Considerations

1. Email credentials are encrypted using Fernet symmetric encryption
2. Credentials are stored in an encrypted format
3. Setup command automatically deletes the message containing credentials
4. Sensitive responses are sent via DM
5. Only administrators can configure the cog

## Required Permissions

The bot needs the following permissions in channels where it will forward emails:
- Send Messages
- Embed Links
- Attach Files (if you want to forward email attachments)

## Support

If you encounter any issues or need assistance, please create an issue in the repository.

## Note

This cog is designed to work with Gmail accounts. If you're using Gmail, make sure to:
1. Enable "Less secure app access" or
2. Create an App Password if you have 2FA enabled

## Disclaimer

Store email credentials securely and only use dedicated email accounts for this purpose. Never use your primary email account.