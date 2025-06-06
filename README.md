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

## Quick Configuration Commands

For a quick reference, here are the commands to configure the cog after installation. For a more detailed guide, see the "Detailed Setup Walkthrough" section below.

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
- The cog will not process reactions until all four settings (welcome channel, role selection channel, guest role, and selector role) are configured.

## Detailed Setup Walkthrough

This guide provides a comprehensive step-by-step process to set up the `RoleCleanup` cog along with the necessary Discord roles and `roletools` integration for a complete user verification and role selection flow.

**IMPORTANT PRE-REQUISITE:** Ensure you have created the necessary `GUEST` and `ROLE_SELECTOR` (or your chosen names) roles in your Discord Server Settings *before* proceeding with the cog configuration steps below. Refer to **Step 1** for details on creating these roles.

**Assumptions:**
*   You have Red-DiscordBot installed and running.
*   You have admin/server manager permissions on your Discord server.
*   You have the `roletools` cog (or a similar reaction role cog) installed and loaded.

**Step 1: Create Necessary Roles in Discord**

Before configuring the cog, you need to create the roles in your Discord server settings (Server Settings -> Roles -> Create Role):

1.  **Guest Role:**
    *   **Name:** `GUEST` (or any name you prefer, e.g., "Newcomer", "Unverified").
    *   **Purpose:** This role is automatically assigned (or manually assigned) to users when they first join your server. They will keep this role until they react to the welcome message.
    *   **Permissions:** Typically, this role should have very limited permissions, perhaps only able to see your welcome/rules channel.

2.  **Selector Role:**
    *   **Name:** `ROLE_SELECTOR` (or any name you prefer, e.g., "Verified", "MemberPendingSelection").
    *   **Purpose:** This role is temporarily given to users after they react to the welcome message. It grants them access to the role selection channel. `RoleCleanup` will remove this role once they pick their main roles.
    *   **Permissions:** This role should have permission to see the role selection channel but not much else initially.

**Step 2: Install and Load the `RoleCleanup` Cog**

If you haven't already:

1.  Add this repository to your Red-DiscordBot instance:
    ```
    !repo add my-cogs-repo https://github.com/mrdylanroberts/my_cogs_repo
    ```

2.  Install the `RoleCleanup` cog:
    ```
    !cog install my-cogs-repo role_cleanup
    ```

3.  Load the cog:
    ```
    !load role_cleanup
    ```

**Step 3: Configure the `RoleCleanup` Cog**

Use the following commands to tell `RoleCleanup` which roles and channels to use. Replace the example names/channels with your actual ones.

**Note:** Ensure the roles you specify here (e.g., `GUEST`, `ROLE_SELECTOR`) have already been created in your Discord server as detailed in Step 1.

1.  Set the Guest Role (the role new users have):
    ```
    !rolecleanup guestrole GUEST
    ```
    *(Replace `GUEST` if you named your guest role differently in Step 1)*

2.  Set the Selector Role (the role users get to access the role selection channel):
    ```
    !rolecleanup selectorrole ROLE_SELECTOR
    ```
    *(Replace `ROLE_SELECTOR` if you named your selector role differently in Step 1)*

3.  Set the Welcome Channel (where users first react):
    ```
    !rolecleanup welcomechannel #your-welcome-channel
    ```
    *(Replace `#your-welcome-channel` with your actual welcome channel, e.g., `#👋・welcome-rules`)*

4.  Set the Role Selection Channel (where users pick their main roles):
    ```
    !rolecleanup roleselectionchannel #your-role-selection-channel
    ```
    *(Replace `#your-role-selection-channel` with your actual role selection channel, e.g., `#🎭・role-selection`)*

5.  Verify settings:
    ```
    !rolecleanup
    ```
    This will show you the current configuration to ensure everything is set correctly.

**Step 4: Set Up the Welcome Message and Initial Reaction (using `roletools`)**

This step makes users react to a message in your welcome channel to get the `ROLE_SELECTOR` role.

1.  **Create your Welcome Message:**
    *   Post your welcome message in the channel you designated as `welcomechannel`. This can be a simple text message or a more complex embed (e.g., created with `!embed json ...`).
    *   Once the message is sent, you'll need its **Message ID**. To get this, enable Developer Mode in Discord (User Settings -> Advanced -> Developer Mode), then right-click the message and select "Copy ID".

2.  **Add the Reaction Role using `roletools`:**
    *   Use the following `roletools` command. Replace `[MESSAGE_ID]` with the ID you copied, `✅` with your desired emoji, and `ROLE_SELECTOR` with the exact name of the selector role you created in Step 1 and configured in Step 3.
    ```
    !roletools reaction create [MESSAGE_ID] ✅ ROLE_SELECTOR
    ```
    *   Example: `!roletools reaction create 1380241798689062933 ✅ ROLE_SELECTOR`

**Step 5: Configure Channel Permissions (Recommended)**

To ensure the flow works smoothly and channels are visible only to the appropriate users:

1.  **Welcome Channel (e.g., `#your-welcome-channel`):**
    *   **`GUEST` role:**
        *   `View Channel`: ALLOW
        *   `Read Message History`: ALLOW
        *   `Add Reactions`: ALLOW
    *   **`ROLE_SELECTOR` role (and other general member roles):**
        *   `View Channel`: DENY (Optional, if you want to hide this channel after they've reacted and moved on).
    *   **`@everyone` role:**
        *   `View Channel`: DENY (to ensure only guests see it initially).

2.  **Role Selection Channel (e.g., `#your-role-selection-channel`):**
    *   **`ROLE_SELECTOR` role:**
        *   `View Channel`: ALLOW
    *   **`GUEST` role:**
        *   `View Channel`: DENY
    *   **`@everyone` role:**
        *   `View Channel`: DENY (unless you have a different setup where everyone can see it but only `ROLE_SELECTOR` can interact).

**Step 6: Test the Workflow**

1.  Assign the `GUEST` role to a test user (or yourself, by removing other roles and adding `GUEST`).
2.  The test user should only see the welcome channel.
3.  React to the welcome message with the specified emoji (e.g., ✅).
4.  `roletools` should assign the `ROLE_SELECTOR` role.
5.  `RoleCleanup` should then detect the `ROLE_SELECTOR` role and remove the `GUEST` role.
6.  The test user should now lose access to the welcome channel (if configured in Step 5) and gain access to the role selection channel.
7.  Proceed to the role selection channel and react to messages there (assuming you have other `roletools` set up for main role selection). `RoleCleanup` will then remove the `GUEST` (if somehow still present) and `ROLE_SELECTOR` roles once a main role is acquired via reaction in this channel.

## Expected Workflow Summary

1.  A new user joins the server and is assigned the `GUEST` role.
2.  The user sees the Welcome Channel and reacts to the designated welcome message (e.g., with ✅).
3.  `roletools` grants the user the `ROLE_SELECTOR` role.
4.  `RoleCleanup` detects the presence of the `ROLE_SELECTOR` role and automatically removes the `GUEST` role from the user.
5.  The user now has the `ROLE_SELECTOR` role, granting them access to the Role Selection Channel (and potentially hiding the Welcome Channel).
6.  The user navigates to the Role Selection Channel and reacts to a message to choose their main server roles.
7.  Upon reacting in the Role Selection Channel, `RoleCleanup` removes both the `GUEST` role (if it was somehow re-added or not removed) and the `ROLE_SELECTOR` role, leaving the user with their chosen main roles.

This completes the automated flow from new user to a fully role-assigned member.