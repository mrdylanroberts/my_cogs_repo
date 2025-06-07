from datetime import datetime, timedelta
from typing import Dict

from redbot.core import commands
from discord.ext import commands as dpy_commands
from discord import Message, TextChannel, Embed
from redbot.core.utils.chat_formatting import box, pagify
from redbot.core import Config, checks

class HelpDetector(commands.Cog):
    """Detects help-related messages and directs users to the help channel."""

    def __init__(self, bot):
        self.bot = bot
        self.cooldowns: Dict[int, datetime] = {}
        self.cooldown_duration = timedelta(hours=1)
        self.config = Config.get_conf(self, identifier=1234567890, force_registration=True)
        default_guild_settings = {
            "help_channel_id": None,
            "help_keywords": [
                'i need help',
                'need help',
                'can someone help',
                'help me',
                'help please',
                'anyone help',
                'how do i',
                'how to'
            ],
            "reaction_mode": "cooldown"  # 'cooldown', 'always', 'off'
        }
        self.config.register_guild(**default_guild_settings)

    @commands.Cog.listener()
    async def on_message(self, message: Message):
        # Ignore DMs and bot messages
        if not message.guild or message.author.bot:
            return

        # Check if the message starts with a command prefix
        prefixes = await self.bot.get_prefix(message)
        is_command = False
        if isinstance(prefixes, str):
            if message.content.startswith(prefixes):
                is_command = True
        elif isinstance(prefixes, (list, tuple)):
            for p in prefixes:
                if message.content.startswith(p):
                    is_command = True
                    break
        
        if is_command:
            return

        # Check if message contains help keywords
        guild_settings = await self.config.guild(message.guild).all()
        help_channel_id = guild_settings.get("help_channel_id")
        current_help_keywords = guild_settings.get("help_keywords", [
            'i need help',
            'need help',
            'can someone help',
            'help me',
            'help please',
            'anyone help',
            'how do i',
            'how to'
        ]) # Use default keywords if none set

        # Debug logging
        print(f"Processing message: {message.content}")
        print(f"Help channel ID: {help_channel_id}")
        print(f"Current keywords: {current_help_keywords}")

        if not help_channel_id:
            return # Don't do anything if help channel is not set

        help_channel = self.bot.get_channel(help_channel_id)
        if not help_channel:
            print(f"Error: Could not find help channel with ID: {help_channel_id}. It might have been deleted or the bot lacks access.")
            return

        msg_content = message.content.lower()
        print(f"Normalized message content for keyword check: '{msg_content}'") # Debug log

        keyword_found = False
        for keyword in current_help_keywords:
            if keyword in msg_content:
                print(f"Keyword '{keyword}' Matched in message: '{msg_content}'") # Debug log
                keyword_found = True
                break

        if keyword_found:
            guild_settings = await self.config.guild(message.guild).all() # Re-fetch for reaction_mode
            reaction_mode = guild_settings.get("reaction_mode", "cooldown")

            user_id = message.author.id
            now = datetime.now()

            # Send help channel reminder (DM)
            # Cooldown for DMs will still apply to prevent spam, regardless of reaction_mode for reactions themselves
            if user_id in self.cooldowns:
                if now - self.cooldowns[user_id] < self.cooldown_duration:
                    # If DM is on cooldown, reactions might also be skipped depending on mode or if they are tied to DM success
                    # For now, let's assume if DM is on cooldown, we also skip reactions to avoid partial responses.
                    print(f"DM for user {user_id} on cooldown. Skipping DM and reactions.")
                    return 
            self.cooldowns[user_id] = now # Update DM cooldown

            try:
                await message.author.send(
                    f"Hi! It looks like you need help. Please check out {help_channel.mention} in the '{message.guild.name}' server, "
                    f"where our community can better assist you!"
                )
                print(f"Sent DM to user {message.author.id} regarding message ID: {message.id}") # Debug log for DM
            except Exception as e:
                print(f"Error sending help DM: {e}") # Log error for debugging

            # Handle reactions based on reaction_mode
            if reaction_mode == "off":
                print(f"Reaction mode is 'off'. Skipping reactions for message ID: {message.id}")
            else: # 'always' or 'cooldown'
                # The main DM cooldown check above already happened.
                # If reaction_mode is 'always', we proceed to add reactions.
                # If reaction_mode is 'cooldown', the DM cooldown effectively acts as the reaction cooldown too.
                # This simplifies logic: if DM was sent, reactions (if not 'off') are attempted.
                try:
                    # Emoji IDs provided by user
                    emoji_icanhelp = self.bot.get_emoji(1375343348562264165)
                    emoji_pmstaff = self.bot.get_emoji(1375343355411562536)

                    if emoji_icanhelp:
                        await message.add_reaction(emoji_icanhelp)
                        print(f"Added icanhelp reaction to message ID: {message.id}")
                    else:
                        print(f"Could not find emoji 0_icanhelp (ID: 1375343348562264165)")
                    
                    if emoji_pmstaff:
                        await message.add_reaction(emoji_pmstaff)
                        print(f"Added pmstaff reaction to message ID: {message.id}")
                    else:
                        print(f"Could not find emoji 0_pmstaff (ID: 1375343355411562536)")

                except Exception as e:
                    print(f"Error adding reactions: {e}")
        else:
            print(f"Keyword match FAILED. No configured keywords found in message: '{msg_content}' with keywords {current_help_keywords}") # Debug log
            return

    @commands.group()
    @checks.admin_or_permissions(manage_guild=True)
    async def helpdetectorset(self, ctx):
        """Manage HelpDetector settings."""
        pass

    @helpdetectorset.command(name="channel")
    async def set_help_channel(self, ctx, channel: TextChannel):
        """Set the channel where users should be directed for help."""
        await self.config.guild(ctx.guild).help_channel_id.set(channel.id)
        await ctx.send(f"Help channel has been set to {channel.mention}")

    @helpdetectorset.command(name="addkeyword")
    async def add_keyword(self, ctx, *, keyword: str):
        """Add a keyword to the list of help-related keywords."""
        keyword = keyword.lower()
        async with self.config.guild(ctx.guild).help_keywords() as keywords:
            if keyword not in keywords:
                keywords.append(keyword)
                await ctx.send(f"Keyword `{keyword}` added.")
            else:
                await ctx.send(f"Keyword `{keyword}` already exists.")

    @helpdetectorset.command(name="removekeyword")
    async def remove_keyword(self, ctx, *, keyword: str):
        """Remove a keyword from the list of help-related keywords."""
        keyword = keyword.lower()
        async with self.config.guild(ctx.guild).help_keywords() as keywords:
            if keyword in keywords:
                keywords.remove(keyword)
                await ctx.send(f"Keyword `{keyword}` removed.")
            else:
                await ctx.send(f"Keyword `{keyword}` not found.")

    @helpdetectorset.command(name="listkeywords")
    async def list_keywords(self, ctx):
        """List the current help-related keywords."""
        keywords = await self.config.guild(ctx.guild).help_keywords()
        if not keywords:
            await ctx.send("No keywords are currently set.")
            return
        keyword_list = "\n".join([f"- `{kw}`" for kw in keywords])
        for page in pagify(f"Current help keywords:\n{keyword_list}"):
            await ctx.send(box(page))

    @helpdetectorset.command(name="setreactionmode")
    async def set_reaction_mode(self, ctx, mode: str):
        """Set the emoji reaction mode.

        Modes:
        - `cooldown`: Reactions are added, but subject to the user cooldown (default).
        - `always`: Reactions are always added, regardless of cooldown (DM still has cooldown).
        - `off`: No reactions are added.
        """
        mode = mode.lower()
        if mode not in ["cooldown", "always", "off"]:
            await ctx.send("Invalid mode. Choose from `cooldown`, `always`, or `off`.")
            return
        await self.config.guild(ctx.guild).reaction_mode.set(mode)
        await ctx.send(f"Reaction mode set to `{mode}`.")

    @helpdetectorset.command(name="viewsettings")
    async def view_settings(self, ctx):
        """View the current settings for HelpDetector."""
        settings = await self.config.guild(ctx.guild).all()
        help_channel_id = settings.get("help_channel_id")
        keywords = settings.get("help_keywords", [])
        reaction_mode = settings.get("reaction_mode", "cooldown")

        help_channel = self.bot.get_channel(help_channel_id) if help_channel_id else "Not set"
        keyword_list = "\n".join([f"- `{kw}`" for kw in keywords]) if keywords else "No keywords set."

        embed = Embed(title="HelpDetector Settings", color=await ctx.embed_color())
        embed.add_field(name="Help Channel", value=help_channel.mention if isinstance(help_channel, TextChannel) else help_channel, inline=False)
        embed.add_field(name="Reaction Mode", value=f"`{reaction_mode}`", inline=False)
        embed.add_field(name="Keywords", value=box(keyword_list) if keywords else "No keywords set.", inline=False)
        
        await ctx.send(embed=embed)