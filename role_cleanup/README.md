# Role Cleanup

A Red-DiscordBot cog that automatically manages user roles based on reactions in specific channels.

## Features

- **Welcome Channel Integration**: When users react with ✅ in the welcome channel, they receive a configurable role
- **Role Selection Cleanup**: When users react in the role selection channel, a configurable guest role is automatically removed
- **Fully Configurable**: Set custom channels and roles for your server
- **Debug Logging**: Comprehensive logging for troubleshooting and monitoring

## Installation

1. Make sure you have the downloader cog loaded: `[p]load downloader` (replace `[p]` with your bot's prefix)
2. Add this repository to your bot: `[p]repo add my_cogs_repo <your_repo_url>` (replace `<your_repo_url>` with the actual URL of your `my_cogs_repo` repository)
3. Install the cog: `[p]cog install my_cogs_repo role_cleanup`
4. Load the cog: `[p]load role_cleanup`

## Commands

### Main Command
- `[p]rolecleanup` or `[p]rc` - Shows current configuration settings

### Subcommands
- `[p]rolecleanup welcomechannel <channel>` - Sets the welcome channel where users react with ✅ to get the role selector role
- `[p]rolecleanup roleselectionchannel <channel>` - Sets the role selection channel where reactions remove guest/selector roles
- `[p]rolecleanup selectorrole <role_name>` - Sets the name of the role selector role (default: "ROLE_SELECTOR")
- `[p]rolecleanup guestrole <role_name>` - Sets the name of the guest role (default: "GUEST")

**Aliases**: `rc` can be used instead of `rolecleanup`

## Configuration

### Required Setup Steps

1. **Set Welcome Channel**: Use `[p]rolecleanup welcomechannel #your-welcome-channel`
2. **Set Role Selection Channel**: Use `[p]rolecleanup roleselectionchannel #your-role-selection-channel`
3. **Create Required Roles**: Ensure your server has the roles specified in the configuration (default: "GUEST" and "ROLE_SELECTOR")
4. **Create Welcome Message**: Manually post a welcome message in the welcome channel and add a ✅ reaction to it
5. **Optional**: Customize role names using `selectorrole` and `guestrole` commands if needed

**Important**: This cog does NOT automatically create welcome messages. You must manually create and post your welcome message in the configured welcome channel, then add the ✅ reaction for users to click.

### How It Works

1. **Welcome Process**: When a user reacts with ✅ in the welcome channel, they receive the "ROLE_SELECTOR" role
2. **Role Selection**: When a user reacts to any message in the role selection channel, their "GUEST" and "ROLE_SELECTOR" roles are automatically removed
3. **Error Handling**: The cog will log errors if it lacks permissions or if roles don't exist

## Permissions

Ensure the bot has the following permissions:

- **Manage Roles** - Required to add and remove roles from users
- **Read Message History** - Required to process reactions
- **View Channels** - Required to access the configured channels
- **Add Reactions** - Optional, for bot to add initial reactions to messages

**Important**: The bot's role must be higher in the hierarchy than the roles it manages (GUEST and ROLE_SELECTOR).

## Example Workflow

1. New user joins server and gets "GUEST" role
2. User reads welcome message and reacts with ✅
3. Bot adds "ROLE_SELECTOR" role to user
4. User goes to role selection channel and reacts to get their class role
5. Bot removes "GUEST" and "ROLE_SELECTOR" roles, leaving user with only their selected class role

## Troubleshooting

- **Bot not responding to reactions**: Check that both channels are properly configured
- **Permission errors**: Ensure bot has "Manage Roles" permission and its role is above managed roles
- **Role not found errors**: Verify that the configured role names exist on your server
- **Check configuration**: Use `[p]rolecleanup` to view current settings

## Support

If you have issues or suggestions, please open an issue on the repository where you found this cog.