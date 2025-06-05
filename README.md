# My Custom Cogs for Red-DiscordBot

This repository contains custom cogs for Red-DiscordBot.

## Cogs Available

### RoleCleanup
- **Description**: Automatically manages roles based on reactions in specified channels. When users react in the welcome channel with ✅, they receive a role selector role. When they react in the role selection channel, their guest and selector roles are removed.
- **Features**:
  - Fully configurable through Discord commands
  - Customizable channel IDs and role names
  - Admin-only configuration commands
  - Settings display with Discord embeds

## Installation

1. Add this repository to your Red-DiscordBot instance:
   ```
   !repo add my-cogs-repo https://github.com/mrdylanroberts/my_cogs_repo
   ```

2. Install the RoleCleanup cog:
   ```
   !cog install my-cogs-repo role_cleanup
   ```

3. Load the cog:
   ```
   !load role_cleanup
   ```

## Configuration

After installation, use these commands to configure the cog (requires admin or manage server permission):

1. View current settings:
   ```
   !rolecleanup
   ```

2. Set the welcome channel:
   ```
   !rolecleanup welcomechannel #your-welcome-channel
   ```

3. Set the role selection channel:
   ```
   !rolecleanup roleselectionchannel #your-role-selection-channel
   ```

4. Set the selector role name:
   ```
   !rolecleanup selectorrole ROLE_SELECTOR
   ```

5. Set the guest role name:
   ```
   !rolecleanup guestrole GUEST
   ```

## Important Notes

- The cog requires the following permissions:
  - Manage Roles
  - Read Messages
  - Send Messages
  - Add Reactions
  - Read Message History
- The bot's role must be higher in the hierarchy than the roles it will manage
- Configuration commands can be accessed using `!rolecleanup` or the shorter alias `!rc`
- The cog will not process reactions until both channels are configured