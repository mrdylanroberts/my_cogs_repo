# CommandBatch Cog

A Red-DiscordBot cog that allows you to create custom command profiles and execute multiple commands in sequence. Perfect for testing workflows, cog management, and repetitive tasks.

## Features

- 📝 **Create Custom Profiles**: Define sets of commands to run together
- ▶️ **Execute Batches**: Run all commands in a profile with a single command
- 📋 **Profile Management**: List, view, and delete command profiles
- 🔄 **Progress Tracking**: Real-time status updates during execution
- ⚡ **Smart Execution**: Automatic rate limiting and error handling

## Commands

### Main Commands

- `!multicommand` - Show help and available commands
- `!multicommand create <name> <command1>,<command2>,...` - Create a new command profile
- `!multicommand run <name>` - Execute a command profile
- `!multicommand list` - Show all available profiles
- `!multicommand view <name>` - View details of a specific profile
- `!multicommand delete <name>` - Delete a command profile

### Aliases

- `!mcmd` - Short alias for `!multicommand`
- `!batch` - Alternative alias for `!multicommand`

## Usage Examples

### Creating a Profile for Email News Testing

```
!multicommand create testemailnews unload email_news,cog uninstall email_news,repo update,cog install my-cogs-repo email_news,load email_news,set api email_news secret your-encryption-key-here,emailnews setdefaultchannel examplechannel,emailnews setup your-email@example.com your-app-password,emailnews interval 3600,emailnews checknow
```

### Running the Profile

```
!multicommand run testemailnews
```

### Creating a Simple Cog Reload Profile

```
!multicommand create reloadcog unload mycog,load mycog
```

### Viewing All Profiles

```
!multicommand list
```

### Viewing Profile Details

```
!multicommand view testemailnews
```

## Features in Detail

### Smart Command Parsing

- Commands are automatically parsed from comma-separated lists
- The `!` prefix is automatically removed if present
- Whitespace is automatically trimmed

### Execution Features

- **Progress Tracking**: Real-time updates showing current command being executed
- **Error Handling**: Continues execution even if individual commands fail
- **Rate Limiting**: 1-second delay between commands to prevent issues
- **Result Summary**: Shows success/failure count and details for each command

### Profile Management

- **Alphanumeric Names**: Profile names must contain only letters and numbers
- **Persistent Storage**: Profiles are saved and persist across bot restarts
- **Easy Management**: Create, view, list, and delete profiles with simple commands

## Installation

1. Add the cog to your Red-DiscordBot:
   ```
   !cog install my-cogs-repo command_batch
   ```

2. Load the cog:
   ```
   !load command_batch
   ```

3. Start creating command profiles:
   ```
   !multicommand create myprofile command1,command2,command3
   ```

## Permissions

- This cog requires **moderator** or **administrator** permissions to use
- All commands are restricted to moderators and administrators for security
- Users with the "Manage Server" permission can also use these commands

## Tips

- **Don't include the `!` prefix** when creating profiles - it's automatically handled
- **Use descriptive profile names** to easily identify what each profile does
- **Test individual commands first** before adding them to a profile
- **Profile names must be alphanumeric** (letters and numbers only)
- **Commands execute sequentially** with a 1-second delay between each

## Error Handling

The cog includes robust error handling:

- Invalid commands are logged but don't stop execution
- Errors are displayed in the final results summary
- Execution continues even if individual commands fail
- Detailed error messages help with troubleshooting

## Use Cases

- **Cog Testing**: Quickly reload and reconfigure cogs during development
- **Bot Maintenance**: Run maintenance routines with a single command
- **Setup Automation**: Automate complex setup procedures
- **Troubleshooting**: Create profiles for common troubleshooting steps

## Support

If you encounter any issues or have suggestions for improvements, please create an issue in the repository.