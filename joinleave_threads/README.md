# JoinLeaveThreads Cog

This cog for Red Discord Bot allows you to send customizable join and leave messages to specific Discord threads.

## Features

-   Send messages when a user joins the server.
-   Send messages when a user leaves the server.
-   Highly customizable messages with placeholders for member and server information.
-   Option to send messages to an existing thread.
-   Option to create a new thread for each join/leave event.
-   Configurable naming format for newly created threads.

## Installation

1.  Make sure you have the downloader cog loaded: `[p]load downloader` (replace `[p]` with your bot's prefix).
2.  Add this repository to your bot: `[p]repo add my_cogs_repo <your_repo_url>` (replace `<your_repo_url>` with the actual URL of your `my_cogs_repo` repository).
3.  Install the cog: `[p]cog install my_cogs_repo joinleave_threads`
4.  Load the cog: `[p]load joinleave_threads`

## Commands

The main command group is `[p]joinleavethreadsset` (aliased as `[p]jltset`).

### General Settings

*   `[p]jltset settings`
    *   Displays the current configuration for join and leave messages.

### Join Message Configuration

*   `[p]jltset join <true|false>`
    *   Enable or disable join messages.
*   `[p]jltset joinmessage <message>`
    *   Set the join message. Placeholders: `{member.mention}`, `{member.name}`, `{member.display_name}`, `{member.id}`, `{server.name}`.
    *   Example: `[p]jltset joinmessage Welcome {member.mention} (aka {member.display_name}) to {server.name} which now has {server.member_count} members!`
*   `[p]jltset jointhread [thread_or_channel_id]`
    *   Set the target thread ID for join messages. If `joinnewthread` is true, this should be the parent channel ID.
    *   Provide no ID to clear.
*   `[p]jltset joinnewthread <true|false>`
    *   Enable or disable creating a new thread for each join. If true, `jointhread` must be a parent channel ID.
*   `[p]jltset jointhreadname <name_format>`
    *   Set the name format for new join threads. Placeholders: `{member.name}`, `{member.id}`, `{server.name}`.
    *   Example: `[p]jltset jointhreadname Welcome {member.name}`

### Leave Message Configuration

*   `[p]jltset leave <true|false>`
    *   Enable or disable leave messages.
*   `[p]jltset leavemessage <message>`
    *   Set the leave message. Placeholders: `{member.name}`, `{member.display_name}`, `{member.id}`, `{server.name}`.
    *   Example: `[p]jltset leavemessage Goodbye {member.name} (aka {member.display_name}). {server.name} now has {server.member_count} members.`
*   `[p]jltset leavethread [thread_or_channel_id]`
    *   Set the target thread ID for leave messages. If `leavenewthread` is true, this should be the parent channel ID.
    *   Provide no ID to clear.
*   `[p]jltset leavenewthread <true|false>`
    *   Enable or disable creating a new thread for each leave. If true, `leavethread` must be a parent channel ID.
*   `[p]jltset leavethreadname <name_format>`
    *   Set the name format for new leave threads. Placeholders: `{member.name}`, `{member.id}`, `{server.name}`.
    *   Example: `[p]jltset leavethreadname Farewell {member.name}`

## Placeholders for Messages and Thread Names

*   `{member}`: The member object.
    *   `{member.name}`: The member's username (e.g., `Red`).
    *   `{member.mention}`: Mentions the member (e.g., `@Red`).
    *   `{member.display_name}`: The member's display name (nickname if set, otherwise username, e.g., `Reddington`).
    *   `{member.id}`: The member's ID (e.g., `123456789012345678`).
*   `{server}`: The server (guild) object.
    *   `{server.name}`: The server's name (e.g., `My Awesome Server`).
    *   `{server.id}`: The server's ID (e.g., `987654321098765432`).
    *   `{server.member_count}`: The server's current member count (e.g., `150`).

## Permissions

Ensure the bot has the following permissions in the relevant channels/threads:

*   View Channel
*   Send Messages
*   Send Messages in Threads
*   Create Public Threads (if `joinnewthread` or `leavenewthread` is enabled)
*   Manage Threads (recommended for managing the threads it creates)

## Support

If you have issues or suggestions, please open an issue on the repository where you found this cog.