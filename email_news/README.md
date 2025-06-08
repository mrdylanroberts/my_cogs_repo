# Email News Cog for Red-DiscordBot

A secure cog that allows forwarding emails from specific senders to designated Discord channels. Perfect for receiving newsletters, updates, and notifications from trusted email senders directly in your Discord server.

## Features

- 🔒 Secure credential storage using encryption
- 📧 Forward emails from specific senders to designated Discord channels
- ⚙️ Configurable email checking interval
- 🎯 Selective forwarding based on sender email addresses
- 🔐 Secure setup process through DMs

## Installation

1. Add this repository to your bot:
```
[p]repo add my_cogs_repo https://github.com/mrdylanroberts/my_cogs_repo.git
```

2. Install the cog:
```
[p]cog install my_cogs_repo email_news
```

3. Load the cog:
```
[p]load email_news
```

## Initial Setup: Encryption Key (Optional but Recommended)

For enhanced security, you can set up a secure **encryption key** to encrypt your email account credentials. This is **optional** but **highly recommended** for production use.

**To enable encryption**, use the following command in Discord (replace `<your-secret-key>` with your chosen secret):
```
[p]set api email_news secret,<your-secret-key>
```
**Important:** There should be **no spaces** around the comma.

**If you don't set an encryption key**, credentials will be stored in plain text in the bot's configuration. This is acceptable for testing but not recommended for production environments.

## Commands

### Email Account Setup

```
[p]emailnews setup <email_address> <password_or_app_password>
```
-   **Purpose:** Configures an email account for the cog to monitor.
-   **Security:** This command automatically deletes your message containing credentials and sends confirmation via DM to protect your credentials.
-   **Supported Accounts:** Primarily designed and tested with Gmail. For Gmail accounts with 2-Factor Authentication (2FA) enabled, you **must** use an [App Password](https://support.google.com/accounts/answer/185833). If 2FA is not enabled, you might need to enable "Less secure app access" (though using an App Password is more secure and recommended).

### Sender Management

**Set Default Channel for Senders:**
```
[p]emailnews setdefaultchannel <#channel>
```
-   **Purpose:** Sets a default Discord channel for the server. Emails from newly added senders (via `addsender` or `loaddefaults`) will be forwarded to this channel if no specific channel is provided during the command.
-   **Example:** `[p]emailnews setdefaultchannel #newsletters`

**Load Default Senders:**
```
[p]emailnews loaddefaults [target_channel]
```
-   **Purpose:** Adds a predefined list of common newsletter senders to your filter list if they aren't already present. The current default list includes:
    - `clint@tldrsec.com`
    - `newsletter@unsupervised-learning.com`
    - `dan@tldrnewsletter.com`
    - `mike@mail.returnnonsecurity.com`
    - `vulnu@vulnu.mattjay.com`
-   **Channel:** Emails from these senders will be forwarded to the `[target_channel]` if specified. If omitted, they will be sent to the default channel set by `setdefaultchannel`. If no default channel is set, they will be sent to the channel where you run the command (the bot will notify you).
-   **Example:** `[p]emailnews loaddefaults #security-updates` or `[p]emailnews loaddefaults`

**Add a Sender Filter:**
```
[p]emailnews addsender <sender_email_address> [target_channel]
```
-   **Purpose:** Specifies that emails from `<sender_email_address>` should be forwarded.
-   **Channel:** If `[target_channel]` is omitted, emails will be sent to the default channel (if set via `setdefaultchannel`). If no default channel is set, they will be sent to the channel where you run the command. You can also specify a different channel (e.g., `#newsletters`).

**Remove a Sender Filter:**
```
[p]emailnews removesender <sender_email_address>
```
-   **Purpose:** Stops forwarding emails from the specified sender.

**List Sender Filters:**
```
[p]emailnews listsenders
```
-   **Purpose:** Shows all currently configured sender email addresses and the Discord channels they forward to.

### Configuration & Manual Check

**Set Check Interval:**
```
[p]emailnews interval <seconds>
```
-   **Purpose:** Defines how frequently the cog automatically checks for new emails.
-   **Minimum:** 3600 seconds (1 hour) to prevent issues with email provider rate limits.
-   **Default:** 21600 seconds (6 hours).

**Manual Email Check:**
```
[p]emailnews checknow
```
-   **Purpose:** Immediately triggers the email checking process. Useful for testing or fetching emails on demand.
-   **Feedback:** The command will report if emails were found and processed. Check your bot's console/logs for detailed activity, especially if troubleshooting.

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

## Gmail Specifics

This cog is primarily designed and tested with Gmail accounts. When using Gmail:

1.  **2-Factor Authentication (2FA) Enabled (Recommended):** You **must** create and use an [App Password](https://support.google.com/accounts/answer/185833) for the `<password_or_app_password>` field in the `[p]emailnews setup` command. This is the most secure method.
2.  **2FA Disabled:** You *may* need to enable "[Less secure app access](https://support.google.com/accounts/answer/6010255)" in your Google account settings. However, this is less secure and using an App Password with 2FA is strongly advised.

## Disclaimer

-   Always use strong, unique passwords or App Passwords for the email account you configure with this cog.
-   It is highly recommended to use a dedicated email account specifically for this cog, rather than your personal or primary email account.
-   The cog includes features to enhance security (encryption, DM for setup), but you are responsible for safeguarding your API secret key and managing access to your bot and server.