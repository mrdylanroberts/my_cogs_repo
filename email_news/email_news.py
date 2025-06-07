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
        log.info(f"Starting email check for guild: {guild.name} ({guild.id})")
        # Check if enough time has passed since last check, unless manually triggered
        if not manual_trigger:
            last_check = await self.config.guild(guild).last_check()
            check_interval = await self.config.guild(guild).check_interval()
            log.info(f"Last check: {last_check}, Interval: {check_interval}")
            
            if last_check is not None:
                now = datetime.now(timezone.utc).timestamp()
                time_since_last_check = now - last_check
                log.info(f"Time since last check: {time_since_last_check} seconds")
                
                if time_since_last_check < check_interval:
                    log.info("Interval not elapsed. Skipping check.")
                    return 0 # Skip check if interval hasn't elapsed
            
            # Update last check timestamp only for automated checks
            await self.config.guild(guild).last_check.set(datetime.now(timezone.utc).timestamp())
            log.info("Updated last_check timestamp.")
        """Check for new emails and forward them to appropriate channels."""
        await self.initialize_encryption(guild.id)
        
        accounts = await self.config.guild(guild).email_accounts()
        filters = await self.config.guild(guild).sender_filters()
        log.info(f"Found {len(accounts)} email account(s) and {len(filters)} sender filter(s).")
        processed_email_count = 0

        for email_account_address, encrypted_data in accounts.items(): # Renamed 'email' to 'email_account_address' to avoid confusion
            try:
                creds = self.decrypt_credentials(encrypted_data)
                imap_client = aioimaplib.IMAP4_SSL("imap.gmail.com")
                await imap_client.wait_hello_from_server()
                log.info(f"Logging into: {creds['email']}")
                login_status, login_data = await imap_client.login(creds["email"], creds["password"])
                log.info(f"Login attempt status: {login_status}, data: {login_data}")

                if login_status != 'OK':
                    log.error(f"Login failed for {creds['email']}. Status: {login_status}, Reason: {login_data}")
                    try:
                        await imap_client.logout()
                        log.info(f"Logged out (after failed login attempt) from {creds['email']}.")
                    except Exception as logout_err:
                        log.error(f"Error during logout after failed login for {creds['email']}: {logout_err}")
                    continue # Skip to the next account

                log.info(f"Logged in successfully. Selecting INBOX.")
                await imap_client.select("INBOX")
                log.info("INBOX selected.")

                log.info("Searching for all emails...")
                status, messages = await imap_client.search("(ALL)")
                if status == 'OK':
                    message_numbers = messages[0].split()
                    log.info(f"IMAP search returned: {messages[0]}")
                    log.info(f"Found {len(message_numbers)} email(s).")
                else:
                    log.error(f"IMAP search failed with status: {status}. Response: {messages}")
                    message_numbers = []

                for num in message_numbers:
                    decoded_num_str = num.decode('utf-8', 'ignore') if isinstance(num, bytes) else str(num)
                    try:
                        log.info(f"Processing email number: {decoded_num_str} (type: {type(num)})")
                        _, msg_data = await imap_client.fetch(num, "(RFC822)")
                        
                        log.debug(f"Full msg_data for {decoded_num_str}: {str(msg_data)[:1000]}...") # Log first 1000 chars
                        log.debug(f"Type of msg_data: {type(msg_data)}")
                        email_body = None 

                        if not msg_data or not isinstance(msg_data, list) or len(msg_data) == 0:
                            log.error(f"Unexpected or empty msg_data for email {decoded_num_str}. Full msg_data: {str(msg_data)[:1000]}")
                            continue

                        if len(msg_data) >= 2 and isinstance(msg_data[0], bytes) and isinstance(msg_data[1], bytes):
                            if b"RFC822" in msg_data[0]:
                                log.debug(f"Detected flat list structure for {decoded_num_str}. msg_data[0]: {msg_data[0][:100]}, type(msg_data[1]): {type(msg_data[1])}")
                                email_body = msg_data[1]
                        
                        if email_body is None and isinstance(msg_data[0], tuple) and len(msg_data[0]) == 2 and isinstance(msg_data[0][1], bytes):
                            log.debug(f"Detected tuple structure for {decoded_num_str}. msg_data[0][0]: {str(msg_data[0][0])[:100]}, type(msg_data[0][1]): {type(msg_data[0][1])}")
                            email_body = msg_data[0][1]

                        if email_body is None:
                            log.error(f"Failed to extract email_body for {decoded_num_str} using known structures. msg_data (first 1000 chars): {str(msg_data)[:1000]}")
                            continue
                        
                        log.debug(f"Extracted email_body for {decoded_num_str}. Type: {type(email_body)}. Value (first 200): {str(email_body)[:200]}")

                        email_body_bytes = None
                        if isinstance(email_body, bytes):
                            email_body_bytes = email_body
                            log.debug(f"email_body for {decoded_num_str} is bytes. Length: {len(email_body_bytes)}")
                        elif isinstance(email_body, str):
                            log.warning(f"email_body for {decoded_num_str} is str. Converting to bytes. Value (first 200): {email_body[:200]}")
                            email_body_bytes = email_body.encode('utf-8', errors='replace')
                        else:
                            log.error(f"email_body for {decoded_num_str} is UNEXPECTED type: {type(email_body)}. Value: {str(email_body)[:200]}. Attempting str conversion to bytes.")
                            try:
                                email_body_bytes = str(email_body).encode('utf-8', errors='replace')
                            except Exception as e_conv:
                                log.critical(f"Fatal: Could not convert email_body of type {type(email_body)} to bytes for email {decoded_num_str}: {e_conv}", exc_info=True)
                                continue 

                        if not email_body_bytes:
                            log.warning(f"Skipping email {decoded_num_str} because email_body_bytes is empty or None after conversion attempts.")
                            continue
                        
                        log.debug(f"Prepared email_body_bytes for {decoded_num_str}. Type: {type(email_body_bytes)}. Length: {len(email_body_bytes)}. Preview (first 200 as str): {email_body_bytes[:200].decode('utf-8', 'ignore')}")
                        
                        log.debug(f"DEBUG: Type of email_parser_module before use: {type(email_parser_module)}, Value: {str(email_parser_module)[:200]}")
                        if not hasattr(email_parser_module, 'message_from_bytes'):
                            log.critical(f"CRITICAL: email_parser_module (type: {type(email_parser_module)}) does not have 'message_from_bytes'. Value: {str(email_parser_module)[:200]}")
                        
                        email_obj = email_parser_module.message_from_bytes(email_body_bytes)
                            
                        from_address_raw = email_parser_module.utils.parseaddr(email_obj["From"])[1]
                        from_address = from_address_raw.lower()
                        subject = email_obj["Subject"]
                        date = email_obj["Date"]
                        log.info(f"Email From (raw): {from_address_raw}, (lower): {from_address}, Subject: {subject}")
                            
                        lowercase_filters = {k.lower(): v for k, v in filters.items()}
                        log.debug(f"Checking against lowercase filters: {list(lowercase_filters.keys())}")

                        if from_address in lowercase_filters:
                            log.info(f"Sender {from_address} (matched from {from_address_raw}) is in lowercase_filters.")
                            channel_id = lowercase_filters[from_address]
                            channel = guild.get_channel(channel_id)
                            
                            if channel:
                                log.info(f"Target channel found: {channel.name} ({channel.id})")
                                content = ""
                                if email_obj.is_multipart():
                                    for part in email_obj.walk():
                                        if part.get_content_type() == "text/plain":
                                            try:
                                                content = part.get_payload(decode=True).decode('utf-8', errors='replace')
                                            except (UnicodeDecodeError, AttributeError):
                                                content = "Could not decode email content."
                                            break
                                else:
                                    try:
                                        content = email_obj.get_payload(decode=True).decode('utf-8', errors='replace')
                                    except (UnicodeDecodeError, AttributeError):
                                        content = "Could not decode email content."
                                
                                embed = discord.Embed(
                                    title=subject,
                                    description=content[:2000] if content else "No content",
                                    color=discord.Color.blue(),
                                    timestamp=datetime.now(timezone.utc)
                                )
                                embed.add_field(name="From", value=from_address)
                                embed.add_field(name="Date", value=date)
                                
                                await channel.send(embed=embed)
                                
                                await imap_client.store(num, "+FLAGS", "(\\Seen)")
                                log.info(f"Marked email {decoded_num_str} as Seen.")
                                processed_email_count += 1
                                log.info(f"Pausing for 5 seconds before processing next email...")
                                await asyncio.sleep(5)
                    except Exception as e:
                        log.error(f"Error processing email {decoded_num_str}: {str(e)}", exc_info=True)
                        continue

                await imap_client.logout()
                log.info(f"Logged out from {creds['email']}.")
            except Exception as e:
                log.error(f"Error checking emails for account {email_account_address}: {str(e)}", exc_info=True) # Added exc_info
        log.info(f"Email check finished for guild {guild.name}. Processed {processed_email_count} email(s).")
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