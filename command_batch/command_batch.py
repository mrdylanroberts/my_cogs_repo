import asyncio
import logging
from typing import Dict, List, Optional

import discord
from redbot.core import commands, Config, checks
from redbot.core.bot import Red
from redbot.core.utils.chat_formatting import box, pagify

log = logging.getLogger("red.my-cogs-repo.command_batch")

class CommandBatch(commands.Cog):
    """Execute multiple commands in sequence with custom profiles."""
    
    def __init__(self, bot: Red):
        self.bot = bot
        self.config = Config.get_conf(self, identifier=1234567890, force_registration=True)
        
        default_global = {
            "profiles": {}
        }
        
        self.config.register_global(**default_global)
    
    @commands.group(name="multicommand", aliases=["mcmd", "batch"])
    @checks.is_owner()
    async def multicommand(self, ctx: commands.Context):
        """Manage and execute command batches."""
        if ctx.invoked_subcommand is None:
            await self._show_help(ctx)
    
    @multicommand.command(name="create", aliases=["add", "set"])
    async def create_profile(self, ctx: commands.Context, profile_name: str, *, commands_list: str):
        """Create a new command profile.
        
        Commands should be separated by commas.
        Example: `!multicommand create myprofile !unload email_news,!cog uninstall email_news,!repo update`
        """
        if not profile_name.isalnum():
            await ctx.send("❌ Profile name must contain only letters and numbers.")
            return
        
        # Parse commands from the input
        commands_raw = [cmd.strip() for cmd in commands_list.split(',')]
        commands_clean = []
        
        for cmd in commands_raw:
            if cmd.startswith('!'):
                cmd = cmd[1:]  # Remove the ! prefix
            if cmd.strip():
                commands_clean.append(cmd.strip())
        
        if not commands_clean:
            await ctx.send("❌ No valid commands provided.")
            return
        
        async with self.config.profiles() as profiles:
            profiles[profile_name] = commands_clean
        
        commands_display = "\n".join([f"• {cmd}" for cmd in commands_clean])
        embed = discord.Embed(
            title="✅ Profile Created",
            description=f"Profile `{profile_name}` created with {len(commands_clean)} commands:",
            color=discord.Color.green()
        )
        embed.add_field(name="Commands", value=commands_display, inline=False)
        await ctx.send(embed=embed)
    
    @multicommand.command(name="run", aliases=["execute", "exec"])
    async def run_profile(self, ctx: commands.Context, profile_name: str):
        """Execute a command profile.
        
        Example: `!multicommand run testemailnews`
        """
        profiles = await self.config.profiles()
        
        if profile_name not in profiles:
            await ctx.send(f"❌ Profile `{profile_name}` not found. Use `!multicommand list` to see available profiles.")
            return
        
        commands_list = profiles[profile_name]
        
        embed = discord.Embed(
            title="🔄 Executing Command Batch",
            description=f"Running profile `{profile_name}` with {len(commands_list)} commands...",
            color=discord.Color.blue()
        )
        status_msg = await ctx.send(embed=embed)
        
        results = []
        success_count = 0
        
        for i, command in enumerate(commands_list, 1):
            try:
                # Update status
                embed.description = f"Running profile `{profile_name}` ({i}/{len(commands_list)})\n\n**Current:** `{command}`"
                await status_msg.edit(embed=embed)
                
                # Create a fake message to invoke the command
                fake_message = ctx.message
                fake_message.content = f"{ctx.prefix}{command}"
                
                # Process the command
                new_ctx = await self.bot.get_context(fake_message)
                if new_ctx.valid:
                    await self.bot.invoke(new_ctx)
                    results.append(f"✅ `{command}` - Success")
                    success_count += 1
                else:
                    results.append(f"❌ `{command}` - Invalid command")
                
                # Small delay between commands to prevent rate limiting
                await asyncio.sleep(1)
                
            except Exception as e:
                results.append(f"❌ `{command}` - Error: {str(e)[:100]}")
                log.error(f"Error executing command '{command}': {e}")
        
        # Final results
        color = discord.Color.green() if success_count == len(commands_list) else discord.Color.orange()
        final_embed = discord.Embed(
            title="📊 Batch Execution Complete",
            description=f"Profile `{profile_name}` finished\n\n**Success:** {success_count}/{len(commands_list)} commands",
            color=color
        )
        
        # Add results (paginate if too long)
        results_text = "\n".join(results)
        if len(results_text) > 1024:
            # Split into multiple fields if too long
            for page in pagify(results_text, delims=["\n"], page_length=1024):
                final_embed.add_field(name="Results", value=page, inline=False)
        else:
            final_embed.add_field(name="Results", value=results_text, inline=False)
        
        await status_msg.edit(embed=final_embed)
    
    @multicommand.command(name="list", aliases=["show", "profiles"])
    async def list_profiles(self, ctx: commands.Context):
        """List all available command profiles."""
        profiles = await self.config.profiles()
        
        if not profiles:
            await ctx.send("📝 No command profiles found. Use `!multicommand create` to create one.")
            return
        
        embed = discord.Embed(
            title="📋 Command Profiles",
            description=f"Found {len(profiles)} profile(s):",
            color=discord.Color.blue()
        )
        
        for name, commands_list in profiles.items():
            commands_preview = "\n".join([f"• {cmd}" for cmd in commands_list[:3]])
            if len(commands_list) > 3:
                commands_preview += f"\n... and {len(commands_list) - 3} more"
            
            embed.add_field(
                name=f"`{name}` ({len(commands_list)} commands)",
                value=commands_preview,
                inline=False
            )
        
        await ctx.send(embed=embed)
    
    @multicommand.command(name="delete", aliases=["remove", "del"])
    async def delete_profile(self, ctx: commands.Context, profile_name: str):
        """Delete a command profile."""
        profiles = await self.config.profiles()
        
        if profile_name not in profiles:
            await ctx.send(f"❌ Profile `{profile_name}` not found.")
            return
        
        async with self.config.profiles() as profiles:
            del profiles[profile_name]
        
        await ctx.send(f"✅ Profile `{profile_name}` deleted successfully.")
    
    @multicommand.command(name="view", aliases=["info", "details"])
    async def view_profile(self, ctx: commands.Context, profile_name: str):
        """View details of a specific command profile."""
        profiles = await self.config.profiles()
        
        if profile_name not in profiles:
            await ctx.send(f"❌ Profile `{profile_name}` not found.")
            return
        
        commands_list = profiles[profile_name]
        commands_display = "\n".join([f"{i+1}. `{cmd}`" for i, cmd in enumerate(commands_list)])
        
        embed = discord.Embed(
            title=f"📄 Profile: {profile_name}",
            description=f"Contains {len(commands_list)} command(s):",
            color=discord.Color.blue()
        )
        
        # Paginate if too long
        if len(commands_display) > 1024:
            for page in pagify(commands_display, delims=["\n"], page_length=1024):
                embed.add_field(name="Commands", value=page, inline=False)
        else:
            embed.add_field(name="Commands", value=commands_display, inline=False)
        
        await ctx.send(embed=embed)
    
    async def _show_help(self, ctx: commands.Context):
        """Show help information for the multicommand system."""
        embed = discord.Embed(
            title="🔧 Command Batch System",
            description="Execute multiple commands in sequence with custom profiles.",
            color=discord.Color.blue()
        )
        
        embed.add_field(
            name="📝 Create Profile",
            value="`!multicommand create <name> <command1>,<command2>,...`\nExample: `!multicommand create test !unload cog,!load cog`",
            inline=False
        )
        
        embed.add_field(
            name="▶️ Run Profile",
            value="`!multicommand run <name>`\nExample: `!multicommand run test`",
            inline=False
        )
        
        embed.add_field(
            name="📋 Other Commands",
            value="• `!multicommand list` - Show all profiles\n• `!multicommand view <name>` - View profile details\n• `!multicommand delete <name>` - Delete a profile",
            inline=False
        )
        
        embed.add_field(
            name="💡 Tips",
            value="• Commands are executed with a 1-second delay between each\n• Don't include the `!` prefix when creating profiles\n• Profile names must be alphanumeric only",
            inline=False
        )
        
        await ctx.send(embed=embed)