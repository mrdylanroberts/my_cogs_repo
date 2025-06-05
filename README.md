# My Custom Cogs for Red-DiscordBot

This repository contains custom cogs for Red-DiscordBot.

## Cogs Available

### RoleCleanup
- **Description**: Automatically manages roles based on reactions in specified channels. Assigns a 'ROLE_SELECTOR' role upon reaction in a welcome channel, and removes 'GUEST' and 'ROLE_SELECTOR' roles upon reaction in a role selection channel.
- **Setup**: After installation, you will need to modify the `role_cleanup.py` file to set your specific `YOUR_WELCOME_CHANNEL_ID` and `YOUR_ROLE_SELECTION_CHANNEL_ID`. Ideally, these would be configurable via bot commands in a future update.

## Installation

1. Add this repository to your Red-DiscordBot instance:
   ```
   [p]repo add my_cogs_repo <URL_to_this_GitHub_repository>
   ```
   (Replace `[p]` with your bot's prefix and `<URL_to_this_GitHub_repository>` with the actual URL once you host this on GitHub.)

2. Install the desired cog:
   ```
   [p]cog install my_cogs_repo RoleCleanup
   ```

3. Load the cog:
   ```
   [p]load RoleCleanup
   ```

## Important Notes for RoleCleanup Cog

- You **MUST** edit the `role_cleanup.py` file within the cog's directory after installation to set the correct channel IDs for `YOUR_WELCOME_CHANNEL_ID` and `YOUR_ROLE_SELECTION_CHANNEL_ID` for the cog to function correctly.
- The role names `ROLE_SELECTOR` and `GUEST` are currently hardcoded. If your server uses different names, you'll need to adjust these in the `role_cleanup.py` file as well.
- Ensure your bot has the necessary permissions (Manage Roles) and its role is high enough in the hierarchy to manage the roles specified.