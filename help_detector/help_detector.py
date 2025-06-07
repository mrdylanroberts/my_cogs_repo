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
            ]
        }
        self.config.register_guild(**default_guild_settings)

    @commands.Cog.listener()
    async def on_message(self, message: Message):
        # Ignore DMs and bot messages and commands
        if not message.guild or message.author.bot or message.content.startswith(await self.bot.get_prefix(message)):
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
            # Maybe log this? Channel might have been deleted
            return

        msg_content = message.content.lower()
        if any(keyword in msg_content for keyword in current_help_keywords):
            # Check cooldown
            user_id = message.author.id
            now = datetime.now()
            if user_id in self.cooldowns:
                if now - self.cooldowns[user_id] < self.cooldown_duration:
                    return

            # Update cooldown
            self.cooldowns[user_id] = now

            # Send help channel reminder and add reactions
            try:
                await message.reply(
                    f"Hi! It looks like you need help. Please check out {help_channel.mention} "
                    f"where our community can better assist you!",
                    mention_author=False
                )
                print(f"Replied to message ID: {message.id}") # Debug log for reply
            except Exception as e:
                print(f"Error sending help message: {e}") # Log error for debugging

            try:
                # Emoji IDs provided by user
                emoji_icanhelp = self.bot.get_emoji(1375343348562264165)
                emoji_pmstaff = self.bot.get_emoji(1375343355411562536)

                if emoji_icanhelp:
                    await message.add_reaction(emoji_icanhelp)
                    print(f"Added icanhelp reaction to message ID: {message.id}") # Debug log for reaction
                else:
                    print(f"Could not find emoji 0_icanhelp (ID: 1375343348562264165)")
                
                if emoji_pmstaff:
                    await message.add_reaction(emoji_pmstaff)
                    print(f"Added pmstaff reaction to message ID: {message.id}") # Debug log for reaction
                else:
                    print(f"Could not find emoji 0_pmstaff (ID: 1375343355411562536)")

            except Exception as e:
                print(f"Error adding reactions: {e}") # Log error for reactions

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

    @helpdetectorset.command(name="viewsettings")
    async def view_settings(self, ctx):
        """View the current HelpDetector settings."""
        settings = await self.config.guild(ctx.guild).all()
        help_channel_id = settings.get("help_channel_id")
        keywords = settings.get("help_keywords", [])

        channel_mention = "Not set"
        if help_channel_id:
            channel = self.bot.get_channel(help_channel_id)
            if channel:
                channel_mention = channel.mention
            else:
                channel_mention = f"Channel ID: {help_channel_id} (not found/accessible)"
        
        keyword_str = "\n".join([f"- `{kw}`" for kw in keywords]) if keywords else "None"

        embed = Embed(title="HelpDetector Settings", color=await ctx.embed_color())
        embed.add_field(name="Help Channel", value=channel_mention, inline=False)
        embed.add_field(name="Keywords", value=keyword_str, inline=False)
        await ctx.send(embed=embed)