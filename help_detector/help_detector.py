from datetime import datetime, timedelta
from typing import Dict

from redbot.core import commands
from discord.ext import commands as dpy_commands
from discord import Message

class HelpDetector(commands.Cog):
    """Detects help-related messages and directs users to the help channel."""

    def __init__(self, bot):
        self.bot = bot
        self.cooldowns: Dict[int, datetime] = {}
        self.cooldown_duration = timedelta(hours=1)
        self.help_keywords = [
            'i need help',
            'need help',
            'can someone help',
            'help me',
            'help please',
            'anyone help',
            'how do i',
            'how to'
        ]

    @commands.Cog.listener()
    async def on_message(self, message: Message):
        # Ignore bot messages and commands
        if message.author.bot or message.content.startswith(await self.bot.get_prefix(message)):
            return

        # Check if message contains help keywords
        msg_content = message.content.lower()
        if any(keyword in msg_content for keyword in self.help_keywords):
            # Check cooldown
            user_id = message.author.id
            now = datetime.now()
            if user_id in self.cooldowns:
                if now - self.cooldowns[user_id] < self.cooldown_duration:
                    return

            # Update cooldown
            self.cooldowns[user_id] = now

            # Send help channel reminder
            try:
                await message.reply(
                    "Hi! It looks like you need help. Please check out the ❓・questions-help channel "
                    "where our community can better assist you!",
                    mention_author=False
                )
            except Exception:
                pass  # Silently handle any errors sending the message