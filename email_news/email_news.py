import asyncio
import json
import base64
import email
import email.utils
from typing import Dict, List, Optional
from datetime import datetime, timezone

import discord

import aiofiles
from aioimaplib import aioimaplib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from redbot.core import commands, Config
from redbot.core.bot import Red
from redbot.core.utils.chat_formatting import box

class EmailNews(commands.Cog):
    """Forward emails from specified senders to Discord channels securely."""

    def __init__(self, bot: Red):
        self.bot = bot
        self.config = Config.get_conf(
            self,
            identifier=987654321,
            force_registration=True
        )
        self.encryption_key = None
        self.email_check_task = None
        
        default_guild = {
            "email_accounts": {},  # Encrypted credentials
            "sender_filters": {},  # Sender email -> channel_id mapping
            "check_interval": 21600,  # 6 hours
            "last_check": None,  # Timestamp of last email check
        }
        
        self.config.register_guild(**default_guild)

    def cog_unload(self):
        if self.email_check_task:
            self.email_check_task.cancel()

    async def initialize_encryption(self, guild_id: int) -> None:
        """Initialize encryption key using guild ID as salt."""
        if not self.encryption_key:
            try:
                tokens = await self.bot.get_shared_api_tokens("email_news")
                if "secret" not in tokens:
                    raise ValueError("Email news secret key not set. Use '!set api email_news secret,<your-secret-key>' to set it.")
                
                salt = str(guild_id).encode()
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                key = base64.urlsafe_b64encode(kdf.derive(tokens["secret"].encode()))
                self.encryption_key = Fernet(key)
            except Exception as e:
                raise ValueError(f"Failed to initialize encryption: {str(e)}")

    def encrypt_credentials(self, email: str, password: str) -> Dict[str, str]:
        """Encrypt email credentials."""
        encrypted_email = self.encryption_key.encrypt(email.encode()).decode()
        encrypted_password = self.encryption_key.encrypt(password.encode()).decode()
        return {"email": encrypted_email, "password": encrypted_password}

    def decrypt_credentials(self, encrypted_data: Dict[str, str]) -> Dict[str, str]:
        """Decrypt email credentials."""
        email = self.encryption_key.decrypt(encrypted_data["email"].encode()).decode()
        password = self.encryption_key.decrypt(encrypted_data["password"].encode()).decode()
        return {"email": email, "password": password}

    @commands.group(name="emailnews")
    @commands.guild_only()
    @commands.admin_or_permissions(administrator=True)
    async def emailnews(self, ctx: commands.Context):
        """Email news notification settings."""
        pass

    @emailnews.command(name="setup")
    async def setup_email(self, ctx: commands.Context, email: str, password: str):
        """Set up email account credentials (use in DM for security)."""
        if not ctx.guild:
            await ctx.send("This command must be used in a server channel.")
            return

        if not ctx.author.dm_channel:
            await ctx.author.create_dm()

        # Delete the command message for security
        try:
            await ctx.message.delete()
        except:
            pass

        await self.initialize_encryption(ctx.guild.id)
        
        try:
            # Test connection before saving
            imap_client = aioimaplib.IMAP4_SSL("imap.gmail.com")
            await imap_client.wait_hello_from_server()
            await imap_client.login(email, password)
            await imap_client.logout()

            encrypted_creds = self.encrypt_credentials(email, password)
            async with self.config.guild(ctx.guild).email_accounts() as accounts:
                accounts[email] = encrypted_creds

            await ctx.author.dm_channel.send("✅ Email account configured successfully! Use `!emailnews addsender` to set up email forwarding.")
        except Exception as e:
            await ctx.author.dm_channel.send(f"❌ Failed to configure email account: {str(e)}")

    @emailnews.command(name="addsender")
    async def add_sender(self, ctx: commands.Context, sender_email: str, channel: Optional[discord.TextChannel] = None):
        """Add a sender email address to forward messages from."""
        channel = channel or ctx.channel
        
        async with self.config.guild(ctx.guild).sender_filters() as filters:
            filters[sender_email] = channel.id
        
        await ctx.send(f"✅ Messages from {sender_email} will be forwarded to {channel.mention}")

    @emailnews.command(name="removesender")
    async def remove_sender(self, ctx: commands.Context, sender_email: str):
        """Remove a sender email address from forwarding."""
        async with self.config.guild(ctx.guild).sender_filters() as filters:
            if sender_email in filters:
                del filters[sender_email]
                await ctx.send(f"✅ Removed {sender_email} from forwarding list.")
            else:
                await ctx.send("❌ Sender email not found in forwarding list.")

    @emailnews.command(name="listsenders")
    async def list_senders(self, ctx: commands.Context):
        """List all configured sender filters."""
        filters = await self.config.guild(ctx.guild).sender_filters()
        if not filters:
            await ctx.send("No sender filters configured.")
            return

        output = ["Configured Sender Filters:"]
        for sender, channel_id in filters.items():
            channel = ctx.guild.get_channel(channel_id)
            channel_mention = channel.mention if channel else "[Deleted Channel]"
            output.append(f"• {sender} → {channel_mention}")

        await ctx.send(box("\n".join(output)))

    @emailnews.command(name="interval")
    async def set_interval(self, ctx: commands.Context, seconds: int):
        """Set how often to check for new emails (in seconds, minimum 3600)."""
        if seconds < 3600:
            await ctx.send("❌ Interval must be at least 1 hour (3600 seconds) to prevent rate limiting.")
            return

        await self.config.guild(ctx.guild).check_interval.set(seconds)
        human_readable = f"{seconds//3600} hours" if seconds >= 3600 else f"{seconds//60} minutes"
        await ctx.send(f"✅ Email check interval set to {human_readable}.")

    async def check_emails(self, guild):
        # Check if enough time has passed since last check
        last_check = await self.config.guild(guild).last_check()
        check_interval = await self.config.guild(guild).check_interval()
        
        if last_check is not None:
            now = datetime.now(timezone.utc).timestamp()
            time_since_last_check = now - last_check
            
            if time_since_last_check < check_interval:
                return  # Skip check if interval hasn't elapsed
        
        # Update last check timestamp
        await self.config.guild(guild).last_check.set(datetime.now(timezone.utc).timestamp())
        """Check for new emails and forward them to appropriate channels."""
        await self.initialize_encryption(guild.id)
        
        accounts = await self.config.guild(guild).email_accounts()
        filters = await self.config.guild(guild).sender_filters()

        for email, encrypted_data in accounts.items():
            try:
                creds = self.decrypt_credentials(encrypted_data)
                imap_client = aioimaplib.IMAP4_SSL("imap.gmail.com")
                await imap_client.wait_hello_from_server()
                await imap_client.login(creds["email"], creds["password"])
                await imap_client.select("INBOX")

                # Search for unread emails
                _, messages = await imap_client.search("(UNSEEN)")
                message_numbers = messages[0].split()

                for num in message_numbers:
                    try:
                        # Fetch the full email message
                        _, msg_data = await imap_client.fetch(num, "(RFC822)")
                        email_body = msg_data[0][1]
                        
                        # Parse email headers
                        email_message = email.message_from_bytes(email_body)
                        from_address = email.utils.parseaddr(email_message["From"])[1]
                        subject = email_message["Subject"]
                        date = email_message["Date"]
                        
                        # Check if this sender is in our filters
                        if from_address in filters:
                            channel_id = filters[from_address]
                            channel = guild.get_channel(channel_id)
                            
                            if channel:
                                # Extract email content
                                content = ""
                                if email_message.is_multipart():
                                    for part in email_message.walk():
                                        if part.get_content_type() == "text/plain":
                                            content = part.get_payload(decode=True).decode()
                                            break
                                else:
                                    content = email_message.get_payload(decode=True).decode()
                                
                                # Create and send embed
                                embed = discord.Embed(
                                    title=subject,
                                    description=content[:2000] if content else "No content",
                                    color=discord.Color.blue(),
                                    timestamp=datetime.now(timezone.utc)
                                )
                                embed.add_field(name="From", value=from_address)
                                embed.add_field(name="Date", value=date)
                                
                                await channel.send(embed=embed)
                                
                                # Mark email as read
                                await imap_client.store(num, "+FLAGS", "(\\Seen)")
                    except Exception as e:
                        print(f"Error processing email {num}: {str(e)}")
                        continue

                await imap_client.logout()
            except Exception as e:
                print(f"Error checking emails: {str(e)}")

    async def start_email_checking(self):
        """Start the email checking loop."""
        while True:
            try:
                for guild in self.bot.guilds:
                    try:
                        interval = await self.config.guild(guild).check_interval()
                        await self.check_emails(guild)
                    except Exception as e:
                        print(f"Error checking emails for guild {guild.id}: {str(e)}")
                        continue
                
                # Use a default interval if no guilds are configured
                # Always wait the (last guild's) interval or 300s before next check cycle
                await asyncio.sleep(interval if 'interval' in locals() else 300) # Guild interval is 6 hours by default
            except Exception as e:
                print(f"Error in email checking loop: {str(e)}")
                await asyncio.sleep(60)  # Wait a minute before retrying on error

    async def cog_load(self) -> None:
        """Start email checking when cog loads."""
        self.email_check_task = self.bot.loop.create_task(self.start_email_checking())