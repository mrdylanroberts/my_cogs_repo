import asyncio
import json
import base64
import email as email_parser_module # Alias email to email_parser_module
# email.utils is accessible via email_parser_module.utils
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

import logging

log = logging.getLogger("red.my-cogs-repo.email_news") # Instantiate the logger

# Default list of sender emails

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
            "default_channel_id": None, # Channel to send default sender emails to
        }

        self.DEFAULT_SENDERS_LIST = [
            "clint@tldrsec.com",
            "newsletter@unsupervised-learning.com",
            "dan@tldrnewsletter.com",
            "mike@mail.returnnonsecurity.com",
            "vulnu@vulnu.mattjay.com"
        ]
        
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
        if not channel:
            default_channel_id = await self.config.guild(ctx.guild).default_channel_id()
            if default_channel_id:
                channel = ctx.guild.get_channel(default_channel_id)
            if not channel: # Still no channel, use current or ask
                channel = ctx.channel
                await ctx.send(f"⚠️ No default channel set. Using current channel {channel.mention}. You can set a default with `!emailnews setdefaultchannel`.")
        
        async with self.config.guild(ctx.guild).sender_filters() as filters:
            filters[sender_email] = channel.id
        
        await ctx.send(f"✅ Messages from {sender_email} will be forwarded to {channel.mention}")

    @emailnews.command(name="setdefaultchannel")
    async def set_default_channel(self, ctx: commands.Context, channel: discord.TextChannel):
        """Sets the default channel for new sender filters if not specified."""
        await self.config.guild(ctx.guild).default_channel_id.set(channel.id)
        await ctx.send(f"✅ Default channel for sender filters set to {channel.mention}.")

    @emailnews.command(name="loaddefaults")
    async def load_default_senders(self, ctx: commands.Context, target_channel: Optional[discord.TextChannel] = None):
        """Loads a predefined list of common newsletter senders."""
        if not target_channel:
            default_channel_id = await self.config.guild(ctx.guild).default_channel_id()
            if default_channel_id:
                target_channel = ctx.guild.get_channel(default_channel_id)
            if not target_channel: # Still no channel, use current or error
                target_channel = ctx.channel
                await ctx.send(f"⚠️ No default channel set. Using current channel {target_channel.mention} for these defaults. You can set a default with `!emailnews setdefaultchannel`.")

        if not target_channel:
            await ctx.send("❌ Could not determine a target channel. Please specify one or set a default channel.")
            return

        added_count = 0
        async with self.config.guild(ctx.guild).sender_filters() as filters:
            for sender in self.DEFAULT_SENDERS_LIST:
                if sender not in filters:
                    filters[sender] = target_channel.id
                    added_count += 1
        
        if added_count > 0:
            await ctx.send(f"✅ Added {added_count} default sender(s) to forward to {target_channel.mention}.")
        else:
            await ctx.send("✅ All default senders are already in your filter list for this server.")

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

    @emailnews.command(name="checknow")
    async def check_now(self, ctx: commands.Context):
        """Manually check for new emails and forward them."""
        if not ctx.guild:
            await ctx.send("This command must be used in a server channel.")
            return

        await ctx.send("⏳ Manually triggering email check...")
        try:
            processed_count = await self.check_emails(ctx.guild, manual_trigger=True)
            if processed_count > 0:
                await ctx.send(f"✅ Email check manually triggered. Processed {processed_count} new email(s).")
            else:
                await ctx.send("✅ Email check manually triggered. No new emails found or processed.")
        except Exception as e:
            await ctx.send(f"❌ An error occurred during manual email check: {str(e)}")

    @emailnews.command(name="interval")
    async def set_interval(self, ctx: commands.Context, seconds: int):
        """Set how often to check for new emails (in seconds, minimum 3600)."""
        if seconds < 3600:
            await ctx.send("❌ Interval must be at least 1 hour (3600 seconds) to prevent rate limiting.")
            return

        await self.config.guild(ctx.guild).check_interval.set(seconds)
        human_readable = f"{seconds//3600} hours" if seconds >= 3600 else f"{seconds//60} minutes"
        await ctx.send(f"✅ Email check interval set to {human_readable}.")

    async def check_emails(self, guild, manual_trigger=False):
        print(f"[EmailNews] Starting email check for guild: {guild.name} ({guild.id})")
        # Check if enough time has passed since last check, unless manually triggered
        if not manual_trigger:
            last_check = await self.config.guild(guild).last_check()
            check_interval = await self.config.guild(guild).check_interval()
            print(f"[EmailNews] Last check: {last_check}, Interval: {check_interval}")
            
            if last_check is not None:
                now = datetime.now(timezone.utc).timestamp()
                time_since_last_check = now - last_check
                print(f"[EmailNews] Time since last check: {time_since_last_check} seconds")
                
                if time_since_last_check < check_interval:
                    print("[EmailNews] Interval not elapsed. Skipping check.")
                    return 0 # Skip check if interval hasn't elapsed
            
            # Update last check timestamp only for automated checks
            await self.config.guild(guild).last_check.set(datetime.now(timezone.utc).timestamp())
            print("[EmailNews] Updated last_check timestamp.")
        """Check for new emails and forward them to appropriate channels."""
        await self.initialize_encryption(guild.id)
        
        accounts = await self.config.guild(guild).email_accounts()
        filters = await self.config.guild(guild).sender_filters()
        print(f"[EmailNews] Found {len(accounts)} email account(s) and {len(filters)} sender filter(s).")
        processed_email_count = 0

        for email, encrypted_data in accounts.items():
            try:
                creds = self.decrypt_credentials(encrypted_data)
                imap_client = aioimaplib.IMAP4_SSL("imap.gmail.com")
                await imap_client.wait_hello_from_server()
                print(f"[EmailNews] Logging into: {creds['email']}")
                login_status, login_data = await imap_client.login(creds["email"], creds["password"])
                print(f"[EmailNews] Login attempt status: {login_status}, data: {login_data}")

                if login_status != 'OK':
                    print(f"[EmailNews] Login failed for {creds['email']}. Status: {login_status}, Reason: {login_data}")
                    # Attempt to logout even if login failed, to clean up connection if possible
                    try:
                        await imap_client.logout()
                        print(f"[EmailNews] Logged out (after failed login attempt) from {creds['email']}.")
                    except Exception as logout_err:
                        print(f"[EmailNews] Error during logout after failed login for {creds['email']}: {logout_err}")
                    continue # Skip to the next account

                print(f"[EmailNews] Logged in successfully. Selecting INBOX.")
                await imap_client.select("INBOX")
                print("[EmailNews] INBOX selected.")

                # Search for unread emails
                print("[EmailNews] Searching for unseen and undeleted emails...")
                # Using (UNSEEN UNDELETED) for a more robust search
                status, messages = await imap_client.search("(UNSEEN UNDELETED)")
                if status == 'OK':
                    message_numbers = messages[0].split()
                    print(f"[EmailNews] IMAP search returned: {messages[0]}")
                    print(f"[EmailNews] Found {len(message_numbers)} unseen and undeleted email(s).")
                else:
                    print(f"[EmailNews] IMAP search failed with status: {status}. Response: {messages}")
                    message_numbers = []

                for num in message_numbers:
                    try:
                        print(f"[EmailNews] Processing email number: {num} (type: {type(num)})")
                        # Fetch the full email message - num MUST be a string
                        # num is already bytes. fetch can take bytes.
                        _, msg_data = await imap_client.fetch(num, "(RFC822)")
                        decoded_num_str = num.decode('utf-8', 'ignore') # For logging

                        log.debug(f"Full msg_data for {decoded_num_str}: {msg_data}")
                        log.debug(f"Type of msg_data: {type(msg_data)}")
                        email_body = None # Initialize

                        if not msg_data or not isinstance(msg_data, list) or len(msg_data) == 0:
                            log.error(f"Unexpected or empty msg_data for email {decoded_num_str}: {msg_data}")
                            continue

                        # Check for flat list structure: [b'HEADER_INFO', b'BODY_DATA', ...]
                        if len(msg_data) >= 2 and isinstance(msg_data[0], bytes) and isinstance(msg_data[1], bytes):
                            if b"RFC822" in msg_data[0]: # Simple check for metadata
                                log.debug(f"Detected flat list structure for msg_data. msg_data[0]: {msg_data[0][:100]}, type(msg_data[1]): {type(msg_data[1])}")
                                email_body = msg_data[1]
                        
                        # If not flat list, or if email_body not set, check for tuple structure: [(b'HEADER_INFO', b'BODY_DATA'), b')']
                        if email_body is None and isinstance(msg_data[0], tuple) and len(msg_data[0]) == 2 and isinstance(msg_data[0][1], bytes):
                            log.debug(f"Detected tuple structure for msg_data[0]. msg_data[0][0]: {msg_data[0][0]}, type(msg_data[0][1]): {type(msg_data[0][1])}")
                            email_body = msg_data[0][1]

                        if email_body is None:
                            log.error(f"Could not extract email_body. Unexpected structure for msg_data elements for email {decoded_num_str}. msg_data: {msg_data}")
                            continue

                        print(f"[EmailNews] Fetched email body for {decoded_num_str}.")
                        log.debug(f"Type of initial email_body: {type(email_body)}")
                        log.debug(f"Initial email_body (first 200 chars): {str(email_body)[:200]}")

                        email_body_bytes = None
                        if isinstance(email_body, str): # Should ideally be bytes from IMAP
                            email_body_bytes = email_body.encode('utf-8', errors='replace')
                        elif isinstance(email_body, bytes):
                            email_body_bytes = email_body
                        else:
                            log.error(f"email_body is neither str nor bytes after extraction. Type: {type(email_body)}. Email {decoded_num_str}")
                            try: # Attempt conversion if it's some other weird type
                                email_body_bytes = str(email_body).encode('utf-8', errors='replace')
                            except Exception as e_conv:
                                log.error(f"Could not convert email_body of type {type(email_body)} to bytes: {e_conv}. Email {decoded_num_str}")
                                continue
                        
                        log.debug(f"Type of email_body_bytes before parsing: {type(email_body_bytes)}")
                        log.debug(f"email_body_bytes (first 200 bytes as string if possible): {email_body_bytes[:200].decode('utf-8', 'ignore') if email_body_bytes else 'None'}")

                        if not email_body_bytes: # Check if email_body_bytes is empty or None
                            log.warning(f"Skipping email {decoded_num_str} due to empty or unconvertible body after extraction.")
                            continue
                        
                        email_obj = email_parser_module.message_from_bytes(email_body_bytes)
                            
                        from_address_raw = email_parser_module.utils.parseaddr(email_obj["From"])[1]
                        from_address = from_address_raw.lower()
                        subject = email_obj["Subject"]
                        date = email_obj["Date"]
                        print(f"[EmailNews] Email From (raw): {from_address_raw}, (lower): {from_address}, Subject: {subject}")
                            
                        # Prepare filter keys for case-insensitive comparison
                        lowercase_filters = {k.lower(): v for k, v in filters.items()}
                        print(f"[EmailNews] Checking against lowercase filters: {list(lowercase_filters.keys())}")

                        # Check if this sender is in our filters (case-insensitive)
                        if from_address in lowercase_filters:
                            print(f"[EmailNews] Sender {from_address} (matched from {from_address_raw}) is in lowercase_filters.")
                            channel_id = lowercase_filters[from_address]
                            channel = guild.get_channel(channel_id)
                            
                            if channel:
                                print(f"[EmailNews] Target channel found: {channel.name} ({channel.id})")
                                # Extract email content using email_obj
                                content = ""
                                if email_obj.is_multipart(): # Fixed: email_message -> email_obj
                                    for part in email_obj.walk(): # Fixed: email_message -> email_obj
                                        if part.get_content_type() == "text/plain":
                                            try:
                                                content = part.get_payload(decode=True).decode('utf-8', errors='replace')
                                            except (UnicodeDecodeError, AttributeError):
                                                content = "Could not decode email content."
                                            break
                                else:
                                    try:
                                        content = email_obj.get_payload(decode=True).decode('utf-8', errors='replace') # Fixed: email_message -> email_obj
                                    except (UnicodeDecodeError, AttributeError):
                                        content = "Could not decode email content."
                                
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
                                print(f"[EmailNews] Marked email {num} as Seen.")
                                processed_email_count += 1
                                print(f"[EmailNews] Pausing for 5 seconds before processing next email...")
                                await asyncio.sleep(5)  # Pause for 5 seconds
                    except Exception as e:
                        print(f"[EmailNews] Error processing email {num}: {str(e)}")
                        continue

                await imap_client.logout()
                print(f"[EmailNews] Logged out from {creds['email']}.")
            except Exception as e:
                print(f"[EmailNews] Error checking emails for account {email}: {str(e)}")
        print(f"[EmailNews] Email check finished for guild {guild.name}. Processed {processed_email_count} email(s).")
        return processed_email_count

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