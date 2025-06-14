import email
import html
import imaplib
import json
import base64
import email as email_parser_module # Alias email to email_parser_module
# email.utils is accessible via email_parser_module.utils
from email.header import decode_header
from typing import Dict, List, Optional
from datetime import datetime, timezone
import re
import socket
import time
import asyncio

import discord
from redbot.core import commands, Config, bot
from redbot.core.utils.chat_formatting import pagify
from redbot.core.utils.predicates import MessagePredicate
from redbot.core.utils.menus import menu, DEFAULT_CONTROLS
from redbot.core.bot import Red
from redbot.core.data_manager import cog_data_path
from redbot.core.utils.chat_formatting import box

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

import aiofiles
from aioimaplib import aioimaplib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import logging

log = logging.getLogger("red.my-cogs-repo.email_news") # Instantiate the logger

# Default list of sender emails

class EmailPaginationView(discord.ui.View):
    """Persistent pagination view for long email content."""
    
    def __init__(self, embeds: List[discord.Embed], timeout: float = None):
        super().__init__(timeout=timeout)  # None = persistent view
        self.embeds = embeds
        self.current_page = 0
        self.max_pages = len(embeds)
        
        # Only show pagination if there are multiple pages
        if self.max_pages > 1:
            # Previous button
            self.prev_button = discord.ui.Button(
                label='Previous',
                style=discord.ButtonStyle.secondary,
                emoji='⬅️',
                disabled=True,  # Start disabled since we're on page 1
                custom_id=f'email_previous_{id(self)}'
            )
            self.prev_button.callback = self.previous_callback
            self.add_item(self.prev_button)
            
            # Page indicator button (non-clickable)
            self.page_indicator = discord.ui.Button(
                label=f'Page 1/{self.max_pages}',
                style=discord.ButtonStyle.primary,
                disabled=True,  # Non-clickable indicator
                custom_id=f'email_indicator_{id(self)}'
            )
            self.add_item(self.page_indicator)
            
            # Next button
            self.next_button = discord.ui.Button(
                label='Next',
                style=discord.ButtonStyle.secondary,
                emoji='➡️',
                disabled=self.max_pages <= 1,  # Disabled if only one page
                custom_id=f'email_next_{id(self)}'
            )
            self.next_button.callback = self.next_callback
            self.add_item(self.next_button)
    
    async def previous_callback(self, interaction: discord.Interaction):
        try:
            if self.current_page > 0:
                await self.go_to_page(interaction, self.current_page - 1)
            else:
                if not interaction.response.is_done():
                    await interaction.response.defer()
        except Exception as e:
            log.error(f"Error in previous callback: {e}", exc_info=True)
            try:
                if not interaction.response.is_done():
                    await interaction.response.send_message("❌ An error occurred while navigating.", ephemeral=True)
                else:
                    await interaction.followup.send("❌ An error occurred while navigating.", ephemeral=True)
            except Exception:
                pass
    
    async def next_callback(self, interaction: discord.Interaction):
        try:
            if self.current_page < self.max_pages - 1:
                await self.go_to_page(interaction, self.current_page + 1)
            else:
                if not interaction.response.is_done():
                    await interaction.response.defer()
        except Exception as e:
            log.error(f"Error in next callback: {e}", exc_info=True)
            try:
                if not interaction.response.is_done():
                    await interaction.response.send_message("❌ An error occurred while navigating.", ephemeral=True)
                else:
                    await interaction.followup.send("❌ An error occurred while navigating.", ephemeral=True)
            except Exception:
                pass
    
    async def go_to_page(self, interaction: discord.Interaction, page: int):
        try:
            if 0 <= page < self.max_pages:
                self.current_page = page
                
                # Update button states and page indicator
                if self.max_pages > 1:
                    # Update Previous button state
                    self.prev_button.disabled = (page == 0)
                    
                    # Update Next button state
                    self.next_button.disabled = (page == self.max_pages - 1)
                    
                    # Update page indicator
                    self.page_indicator.label = f'Page {page + 1}/{self.max_pages}'
                
                if not interaction.response.is_done():
                    await interaction.response.edit_message(embed=self.embeds[page], view=self)
                else:
                    await interaction.edit_original_response(embed=self.embeds[page], view=self)
        except Exception as e:
            log.error(f"Error in go_to_page for page {page}: {e}", exc_info=True)
            try:
                if not interaction.response.is_done():
                    await interaction.response.send_message("❌ An error occurred while changing pages.", ephemeral=True)
                else:
                    await interaction.followup.send("❌ An error occurred while changing pages.", ephemeral=True)
            except Exception:
                pass
    
    async def on_timeout(self):
        # This won't be called for persistent views (timeout=None)
        try:
            for item in self.children:
                item.disabled = True
        except Exception as e:
            log.error(f"Error in on_timeout: {e}", exc_info=True)

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
            "rate_limit_delay": 2,  # Delay between email processing in seconds
            "connection_timeout": 30,  # IMAP connection timeout in seconds
            "max_content_length": None,  # No content length limit
            "max_emails_per_check": 50  # Maximum emails to process per check
        }

        self.DEFAULT_SENDERS_LIST = [
            "clint@tldrsec.com",
            "newsletter@unsupervised-learning.com",
            "dan@tldrnewsletter.com",
            "mike@mail.returnnonsecurity.com",
            "vulnu@vulnu.mattjay.com"
        ]
        
        self.config.register_guild(**default_guild)
        
        # Rate limiting
        self.last_email_process_time = {}
        
        # Connection pool for reuse
        self.imap_connections = {}

    def is_valid_email_format(self, email_str: str) -> bool:
        """Validate email format."""
        if not email_str:
            return False
        
        # Extract email from "Name <email@domain.com>" format
        email_match = re.search(r'<([^>]+)>', email_str)
        if email_match:
            email_str = email_match.group(1)
        
        # Basic email validation
        email_pattern = re.compile(
            r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        )
        
        return bool(email_pattern.match(email_str.strip()))

    def is_valid_url(self, url: str) -> bool:
        """Validate if a URL has proper format."""
        if not url:
            return False
        
        # Basic URL validation
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+'  # domain...
            r'(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # host...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        
        return bool(url_pattern.match(url))

    def decode_mime_header(self, header_value: str) -> str:
        """Decode MIME-encoded email headers like subjects."""
        if not header_value:
            return ""
        
        try:
            decoded_parts = email_parser_module.header.decode_header(header_value)
            decoded_string = ""
            
            for part, encoding in decoded_parts:
                if isinstance(part, bytes):
                    if encoding:
                        decoded_string += part.decode(encoding, errors='replace')
                    else:
                        decoded_string += part.decode('utf-8', errors='replace')
                else:
                    decoded_string += str(part)
            
            return decoded_string.strip()
        except Exception as e:
            log.warning(f"Failed to decode MIME header '{header_value}': {e}")
            return header_value

    def extract_links_from_content(self, content: str) -> List[str]:
        """Extract URLs from email content."""
        # Pattern to match URLs
        url_pattern = r'https?://[^\s\]\)]+'
        urls = re.findall(url_pattern, content)
        return urls
    
    def convert_html_to_text_with_links(self, html_content: str, max_length: Optional[int] = None) -> str:
        """Convert HTML content to text while preserving inline links and filtering dangerous links."""
        if not html_content:
            return ""
        
        # No early content length limit applied
        
        try:
            if HAS_BS4:
                # Use BeautifulSoup for proper HTML parsing
                soup = BeautifulSoup(html_content, 'html.parser')
                
                # Remove script and style tags
                for script in soup(["script", "style"]):
                    script.decompose()
                
                # Remove hidden elements
                for element in soup.find_all(style=True):
                    style = element.get('style', '')
                    if any(prop in style.lower() for prop in ['display:none', 'display: none', 'max-height:0', 'max-height: 0', 'overflow:hidden', 'overflow: hidden']):
                        element.decompose()
                
                # Filter out dangerous links
                dangerous_patterns = [
                    r'unsubscribe',
                    r'manage.*subscription',
                    r'email.*forward',
                    r'opt.*out',
                    r'utm_',
                    r'tracking',
                    r'analytics',
                    r'pixel',
                    r'beacon',
                    r'email.*track',
                    r'open.*track',
                    r'click.*track',
                    r'mailtrack',
                    r'emailtrack',
                    r'bit\.ly',
                    r'tinyurl',
                    r'short',
                    r'redirect'
                ]
                
                # Convert links to text format with filtering
                for link in soup.find_all('a', href=True):
                    url = link.get('href')
                    text = link.get_text(strip=True)
                    
                    # Validate URL format
                    if not self.is_valid_url(url):
                        link.replace_with(text)
                        continue
                    
                    # Check if URL matches dangerous patterns
                    is_dangerous = any(re.search(pattern, url.lower()) for pattern in dangerous_patterns)
                    
                    # Special case: allow reading time links
                    if 'reading' in url.lower() and 'time' in url.lower():
                        is_dangerous = False
                    
                    if is_dangerous:
                        # Replace dangerous links with just the text
                        link.replace_with(text)
                    else:
                        # Keep safe links in a readable format
                        if text and text != url and len(text) < 100:
                            link.replace_with(f"{text} ({url})")
                        else:
                            link.replace_with(url)
                
                # Get text content
                text = soup.get_text(separator='\n')
                
                # Clean up whitespace
                lines = []
                for line in text.split('\n'):
                    line = line.strip()
                    if line:
                        lines.append(line)
                
                result = '\n'.join(lines)
                
                # No final length limit applied
                
                return result
            else:
                # Fallback regex-based processing
                log.warning("BeautifulSoup not available, using regex fallback")
                
                # Remove script and style tags
                html_content = re.sub(r'<(script|style)[^>]*>.*?</\1>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
                
                # Remove HTML comments
                html_content = re.sub(r'<!--.*?-->', '', html_content, flags=re.DOTALL)
                
                # Process links
                def replace_link(match):
                    full_tag = match.group(0)
                    href_match = re.search(r'href=["\']([^"\'>]+)["\']', full_tag, re.IGNORECASE)
                    text_match = re.search(r'>([^<]*)<', full_tag)
                    
                    if href_match:
                        url = href_match.group(1)
                        text = text_match.group(1).strip() if text_match else url
                        
                        # Validate URL and check for dangerous patterns
                        if not self.is_valid_url(url):
                            return text
                        
                        dangerous_patterns = [
                            r'unsubscribe', r'manage.*subscription', r'email.*forward', r'opt.*out',
                            r'utm_', r'tracking', r'analytics', r'pixel', r'beacon'
                        ]
                        
                        is_dangerous = any(re.search(pattern, url.lower()) for pattern in dangerous_patterns)
                        
                        if 'reading' in url.lower() and 'time' in url.lower():
                            is_dangerous = False
                        
                        if is_dangerous:
                            return text
                        else:
                            return f"{text} ({url})" if text and text != url else url
                    
                    return match.group(0)
                
                # Replace links
                html_content = re.sub(r'<a[^>]*>.*?</a>', replace_link, html_content, flags=re.DOTALL | re.IGNORECASE)
                
                # Remove remaining HTML tags
                text = re.sub(r'<[^>]+>', '', html_content)
                
                # Decode HTML entities
                text = html.unescape(text)
                
                # Clean up whitespace
                lines = []
                for line in text.split('\n'):
                    line = line.strip()
                    if line:
                        lines.append(line)
                
                result = '\n'.join(lines)
                
                # No final length limit applied
                
                return result
                
        except Exception as e:
            log.error(f"Error converting HTML to text: {e}")
            # Emergency fallback: strip all HTML tags
            text = re.sub(r'<[^>]+>', '', html_content)
            text = html.unescape(text)
            
            if max_length and len(text) > max_length:
                text = text[:max_length] + "..."
            
            return text

    def enhance_reading_time_indicators(self, content: str) -> str:
        """Make reading time links more clickable and visible."""
        # Pattern to match reading time indicators
        reading_time_pattern = r'(\d+\s*(?:min|minute|minutes?)\s*read)\s*\(([^)]+)\)'
        
        def replace_reading_time(match):
            time_text = match.group(1)
            url = match.group(2)
            return f"📖 **{time_text}** - {url}"
        
        return re.sub(reading_time_pattern, replace_reading_time, content, flags=re.IGNORECASE)

    def convert_text_links_to_discord_format(self, content: str) -> str:
        """Convert text with URLs in parentheses to Discord markdown links."""
        # Pattern to match "text (url)" format
        link_pattern = r'([^\(\n]+)\s*\(\s*(https?://[^\s\)]+)\s*\)'
        
        def replace_link(match):
            text = match.group(1).strip()
            url = match.group(2).strip()
            
            # Don't convert if text is too long or looks like a URL itself
            if len(text) > 100 or text.startswith(('http://', 'https://')):
                return f"{text} ({url})"
            
            return f"[{text}]({url})"
        
        return re.sub(link_pattern, replace_link, content)

    def clean_email_content(self, content: str) -> str:
        """Clean email content by removing excessive whitespace and common email artifacts."""
        if not content:
            return ""
        
        # Remove excessive line breaks (more than 2 consecutive)
        content = re.sub(r'\n{3,}', '\n\n', content)
        
        # Remove common email artifacts
        artifacts = [
            r'View this email in your browser.*?\n',
            r'If you.*?unsubscribe.*?\n',
            r'This email was sent to.*?\n',
            r'You received this.*?\n',
            r'\[\]\s*\n',  # Empty brackets
            r'^\s*\n',  # Leading empty lines
        ]
        
        for artifact in artifacts:
            content = re.sub(artifact, '', content, flags=re.IGNORECASE | re.MULTILINE)
        
        # Clean up whitespace
        content = content.strip()
        
        return content

    def split_content_for_pagination(self, content: str, max_length: int = 2000) -> List[str]:
        """Split content into chunks suitable for Discord embeds."""
        if len(content) <= max_length:
            return [content]
        
        chunks = []
        current_chunk = ""
        
        # Split by paragraphs first
        paragraphs = content.split('\n\n')
        
        for paragraph in paragraphs:
            # If adding this paragraph would exceed the limit
            if len(current_chunk) + len(paragraph) + 2 > max_length:
                if current_chunk:
                    chunks.append(current_chunk.strip())
                    current_chunk = ""
                
                # If the paragraph itself is too long, split by sentences
                if len(paragraph) > max_length:
                    sentences = re.split(r'(?<=[.!?])\s+', paragraph)
                    for sentence in sentences:
                        if len(current_chunk) + len(sentence) + 1 > max_length:
                            if current_chunk:
                                chunks.append(current_chunk.strip())
                                current_chunk = ""
                        
                        if len(sentence) > max_length:
                            # Force split very long sentences
                            while len(sentence) > max_length:
                                chunks.append(sentence[:max_length].strip())
                                sentence = sentence[max_length:]
                            if sentence:
                                current_chunk = sentence
                        else:
                            current_chunk += sentence + " "
                else:
                    current_chunk = paragraph
            else:
                current_chunk += paragraph + "\n\n"
        
        if current_chunk:
            chunks.append(current_chunk.strip())
        
        return chunks if chunks else [content[:max_length]]

    async def cog_unload(self):
        """Cancel the email checking task when the cog is unloaded."""
        if self.email_check_task:
            self.email_check_task.cancel()

    async def initialize_encryption(self, guild_id: int):
        """Initialize encryption for a guild using the guild ID as salt."""
        try:
            # Check if we have a secret key set
            secret_key = await self.config.guild_from_id(guild_id).get_raw("secret_key", default=None)
            
            if not secret_key:
                log.warning(f"No secret key set for guild {guild_id}. Use `!set api email_news secret,<your-secret-key>` to set one.")
                self.encryption_key = None
                return
            
            # Use guild ID as salt for key derivation
            salt = str(guild_id).encode('utf-8')
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(secret_key.encode('utf-8')))
            self.encryption_key = Fernet(key)
            
        except Exception as e:
            log.error(f"Failed to initialize encryption for guild {guild_id}: {e}")
            self.encryption_key = None

    async def encrypt_credentials(self, guild_id: int, data: str) -> str:
        """Encrypt credentials if encryption is available, otherwise return as-is."""
        if not self.encryption_key:
            await self.initialize_encryption(guild_id)
        
        if self.encryption_key and data:
            try:
                encrypted = self.encryption_key.encrypt(data.encode('utf-8'))
                return base64.urlsafe_b64encode(encrypted).decode('utf-8')
            except Exception as e:
                log.error(f"Failed to encrypt data: {e}")
        
        return data

    async def decrypt_credentials(self, guild_id: int, encrypted_data: str) -> str:
        """Decrypt credentials if encryption is available, otherwise return as-is."""
        if not encrypted_data:
            return ""
        
        if not self.encryption_key:
            await self.initialize_encryption(guild_id)
        
        if self.encryption_key:
            try:
                decoded = base64.urlsafe_b64decode(encrypted_data.encode('utf-8'))
                decrypted = self.encryption_key.decrypt(decoded)
                return decrypted.decode('utf-8')
            except Exception as e:
                log.debug(f"Failed to decrypt data (might be plain text): {e}")
        
        # Return as-is if decryption fails (might be plain text)
        return encrypted_data

    @commands.group(name="emailnews")
    @commands.guild_only()
    async def emailnews(self, ctx):
        """Email news forwarding commands."""
        pass

    @emailnews.command(name="setup")
    @commands.admin_or_permissions(manage_guild=True)
    async def setup_email(self, ctx, email_address: str, password: str, imap_server: str = "imap.gmail.com", account_name: str = "default"):
        """Set up email account credentials (encrypted storage).
        
        Example: `!emailnews setup user@gmail.com mypassword imap.gmail.com`
        
        Note: Use app-specific passwords for Gmail.
        """
        # Validate email format
        if not self.is_valid_email_format(email_address):
            await ctx.send("❌ Invalid email address format.")
            return
        
        try:
            # Test the connection first
            await ctx.send("🔄 Testing email connection...")
            
            # Set socket timeout for connection test
            socket.setdefaulttimeout(30)
            
            try:
                mail = imaplib.IMAP4_SSL(imap_server)
                mail.login(email_address, password)
                mail.select('INBOX')
                mail.close()
                mail.logout()
            except socket.timeout:
                await ctx.send("❌ Connection timeout. Please check your server settings.")
                return
            except imaplib.IMAP4.error as e:
                await ctx.send(f"❌ IMAP connection failed: {e}")
                return
            finally:
                socket.setdefaulttimeout(None)
            
            # Encrypt credentials
            encrypted_email = await self.encrypt_credentials(ctx.guild.id, email_address)
            encrypted_password = await self.encrypt_credentials(ctx.guild.id, password)
            
            # Store account info
            async with self.config.guild(ctx.guild).email_accounts() as accounts:
                accounts[account_name] = {
                    "email": encrypted_email,
                    "password": encrypted_password,
                    "imap_server": imap_server
                }
            
            await ctx.send(f"✅ Email account '{account_name}' configured successfully!")
            log.info(f"Email account '{account_name}' configured for guild {ctx.guild.id}")
            
        except Exception as e:
            await ctx.send(f"❌ Error setting up email account: {e}")
            log.error(f"Error setting up email account: {e}")

    @emailnews.command(name="addsender")
    @commands.admin_or_permissions(manage_guild=True)
    async def add_sender(self, ctx, sender_email: str, channel: discord.TextChannel = None):
        """Add a sender email to forward to a specific channel.
        
        If no channel is specified, uses the default channel.
        """
        # Validate email format
        if not self.is_valid_email_format(sender_email):
            await ctx.send("❌ Invalid email address format.")
            return
        
        if not channel:
            default_channel_id = await self.config.guild(ctx.guild).default_channel_id()
            if not default_channel_id:
                await ctx.send("❌ No channel specified and no default channel set. Use `!emailnews setdefaultchannel` first.")
                return
            channel = ctx.guild.get_channel(default_channel_id)
            if not channel:
                await ctx.send("❌ Default channel not found. Please set a new default channel.")
                return
        
        async with self.config.guild(ctx.guild).sender_filters() as filters:
            filters[sender_email] = channel.id
        
        await ctx.send(f"✅ Added sender `{sender_email}` → {channel.mention}")
        log.info(f"Added sender filter: {sender_email} -> {channel.id} for guild {ctx.guild.id}")

    @emailnews.command(name="setdefaultchannel")
    @commands.admin_or_permissions(manage_guild=True)
    async def set_default_channel(self, ctx, channel: discord.TextChannel):
        """Set the default channel for sender filters."""
        await self.config.guild(ctx.guild).default_channel_id.set(channel.id)
        await ctx.send(f"✅ Default channel set to {channel.mention}")
        log.info(f"Default channel set to {channel.id} for guild {ctx.guild.id}")

    @emailnews.command(name="loaddefaults")
    @commands.admin_or_permissions(manage_guild=True)
    async def load_default_senders(self, ctx, channel: discord.TextChannel = None):
        """Load the default list of security newsletter senders."""
        if not channel:
            default_channel_id = await self.config.guild(ctx.guild).default_channel_id()
            if not default_channel_id:
                await ctx.send("❌ No channel specified and no default channel set.")
                return
            channel = ctx.guild.get_channel(default_channel_id)
            if not channel:
                await ctx.send("❌ Default channel not found.")
                return
        
        async with self.config.guild(ctx.guild).sender_filters() as filters:
            for sender in self.DEFAULT_SENDERS_LIST:
                filters[sender] = channel.id
        
        sender_list = "\n".join([f"• {sender}" for sender in self.DEFAULT_SENDERS_LIST])
        await ctx.send(f"✅ Loaded {len(self.DEFAULT_SENDERS_LIST)} default senders to {channel.mention}:\n```\n{sender_list}\n```")
        log.info(f"Loaded default senders for guild {ctx.guild.id}")

    @emailnews.command(name="removesender")
    @commands.admin_or_permissions(manage_guild=True)
    async def remove_sender(self, ctx, sender_email: str):
        """Remove a sender from the filter list."""
        async with self.config.guild(ctx.guild).sender_filters() as filters:
            if sender_email in filters:
                del filters[sender_email]
                await ctx.send(f"✅ Removed sender `{sender_email}`")
                log.info(f"Removed sender filter: {sender_email} for guild {ctx.guild.id}")
            else:
                await ctx.send(f"❌ Sender `{sender_email}` not found in filters.")

    @emailnews.command(name="listsenders")
    @commands.admin_or_permissions(manage_guild=True)
    async def list_senders(self, ctx):
        """List all configured sender filters."""
        filters = await self.config.guild(ctx.guild).sender_filters()
        
        if not filters:
            await ctx.send("No sender filters configured.")
            return
        
        embed = discord.Embed(title="Configured Sender Filters", color=0x00ff00)
        
        for sender, channel_id in filters.items():
            channel = ctx.guild.get_channel(channel_id)
            channel_name = channel.mention if channel else f"<#{channel_id}> (deleted)"
            embed.add_field(name=sender, value=channel_name, inline=False)
        
        await ctx.send(embed=embed)

    @emailnews.command(name="checknow")
    @commands.admin_or_permissions(manage_guild=True)
    async def check_now(self, ctx):
        """Manually trigger an email check."""
        await ctx.send("🔄 Checking emails...")
        
        try:
            await self.check_emails_for_guild(ctx.guild.id)
            await ctx.send("✅ Email check completed.")
        except Exception as e:
            await ctx.send(f"❌ Error during email check: {e}")
            log.error(f"Manual email check error for guild {ctx.guild.id}: {e}")

    @emailnews.command(name="setinterval")
    @commands.admin_or_permissions(manage_guild=True)
    async def set_interval(self, ctx, hours: int):
        """Set the email check interval in hours (minimum 1 hour)."""
        if hours < 1:
            await ctx.send("❌ Minimum interval is 1 hour.")
            return
        
        interval_seconds = hours * 3600
        await self.config.guild(ctx.guild).check_interval.set(interval_seconds)
        await ctx.send(f"✅ Email check interval set to {hours} hour(s).")
        log.info(f"Email check interval set to {hours} hours for guild {ctx.guild.id}")

    @emailnews.command(name="config")
    @commands.admin_or_permissions(manage_guild=True)
    async def show_config(self, ctx):
        """Show current email news configuration."""
        guild_config = self.config.guild(ctx.guild)
        
        check_interval = await guild_config.check_interval()
        rate_limit_delay = await guild_config.rate_limit_delay()
        connection_timeout = await guild_config.connection_timeout()

        max_emails_per_check = await guild_config.max_emails_per_check()
        
        embed = discord.Embed(
            title="Email News Configuration",
            color=0x00ff00
        )
        
        embed.add_field(
            name="Check Interval",
            value=f"{check_interval} seconds ({check_interval//3600}h {(check_interval%3600)//60}m)",
            inline=True
        )
        embed.add_field(
            name="Rate Limit Delay",
            value=f"{rate_limit_delay} seconds",
            inline=True
        )
        embed.add_field(
            name="Connection Timeout",
            value=f"{connection_timeout} seconds",
            inline=True
        )

        embed.add_field(
            name="Max Emails Per Check",
            value=str(max_emails_per_check),
            inline=True
        )
        
        await ctx.send(embed=embed)

    @emailnews.command(name="setconfig")
    @commands.admin_or_permissions(manage_guild=True)
    async def set_config(self, ctx, setting: str, value: int):
        """Set configuration values. Available settings: rate_limit_delay, connection_timeout, max_emails_per_check"""
        guild_config = self.config.guild(ctx.guild)
        
        valid_settings = {
            'rate_limit_delay': (0, 60),
            'connection_timeout': (10, 300),
            'max_emails_per_check': (1, 200)
        }
        
        if setting not in valid_settings:
            await ctx.send(f"❌ Invalid setting. Valid options: {', '.join(valid_settings.keys())}")
            return
        
        min_val, max_val = valid_settings[setting]
        if not min_val <= value <= max_val:
            await ctx.send(f"❌ Value must be between {min_val} and {max_val}")
            return
        
        await getattr(guild_config, setting).set(value)
        await ctx.send(f"✅ {setting} set to {value}")
        
        log.info(f"{setting} set to {value} for guild {ctx.guild.id}")

    async def check_emails_for_guild(self, guild_id: int):
        """Check emails for a specific guild with enhanced error handling and rate limiting."""
        try:
            guild_config = self.config.guild_from_id(guild_id)
            
            # Get configuration
            email_accounts = await guild_config.email_accounts()
            sender_filters = await guild_config.sender_filters()
            rate_limit_delay = await guild_config.rate_limit_delay()
            connection_timeout = await guild_config.connection_timeout()

            max_emails_per_check = await guild_config.max_emails_per_check()
            
            if not email_accounts:
                log.debug(f"No email accounts configured for guild {guild_id}")
                return
            
            if not sender_filters:
                log.debug(f"No sender filters configured for guild {guild_id}")
                return
            
            # Initialize encryption
            await self.initialize_encryption(guild_id)
            
            # Process each email account
            for account_name, account_info in email_accounts.items():
                try:
                    log.info(f"Checking emails for account {account_name} in guild {guild_id}")
                    
                    # Decrypt credentials
                    email_address = await self.decrypt_credentials(guild_id, account_info.get('email', ''))
                    password = await self.decrypt_credentials(guild_id, account_info.get('password', ''))
                    imap_server = account_info.get('imap_server', 'imap.gmail.com')
                    
                    if not email_address or not password:
                        log.error(f"Missing credentials for account {account_name}")
                        continue
                    
                    # Connect to IMAP server with timeout
                    mail = None
                    try:
                        # Set socket timeout
                        socket.setdefaulttimeout(connection_timeout)
                        
                        mail = imaplib.IMAP4_SSL(imap_server)
                        mail.login(email_address, password)
                        mail.select('INBOX')
                        
                        # Search for unseen emails
                        status, messages = mail.search(None, 'UNSEEN')
                        
                        if status != 'OK':
                            log.error(f"Failed to search emails for {account_name}")
                            continue
                        
                        message_numbers = messages[0].split()
                        
                        # Limit number of emails to process
                        if len(message_numbers) > max_emails_per_check:
                            log.warning(f"Found {len(message_numbers)} emails, limiting to {max_emails_per_check}")
                            message_numbers = message_numbers[:max_emails_per_check]
                        
                        log.info(f"Processing {len(message_numbers)} unseen emails for {account_name}")
                        
                        # Process emails in batches to prevent memory issues
                        batch_size = 10
                        for i in range(0, len(message_numbers), batch_size):
                            batch = message_numbers[i:i + batch_size]
                            
                            for num in batch:
                                try:
                                    # Rate limiting
                                    if guild_id in self.last_email_process_time:
                                        time_since_last = time.time() - self.last_email_process_time[guild_id]
                                        if time_since_last < rate_limit_delay:
                                            await asyncio.sleep(rate_limit_delay - time_since_last)
                                    
                                    self.last_email_process_time[guild_id] = time.time()
                                    
                                    # Fetch email data
                                    status, msg_data = mail.fetch(num, '(RFC822)')
                                    
                                    if status != 'OK':
                                        log.error(f"Failed to fetch email {num}")
                                        continue
                                    
                                    # Extract email body from the response
                                    email_body = None
                                    if isinstance(msg_data, list) and len(msg_data) > 0:
                                        if isinstance(msg_data[0], tuple) and len(msg_data[0]) > 1:
                                            email_body = msg_data[0][1]
                                        elif isinstance(msg_data[0], (bytes, bytearray)):
                                            email_body = msg_data[0]
                                        elif isinstance(msg_data[0], str):
                                            email_body = msg_data[0].encode('utf-8')
                                    
                                    if not email_body:
                                        log.error(f"Could not extract email body for message {num}")
                                        continue
                                    
                                    # Parse email
                                    msg = email.message_from_bytes(email_body)
                                    
                                    # Extract sender and subject
                                    sender = msg.get('From', '')
                                    subject = msg.get('Subject', '')
                                    
                                    # Decode subject
                                    subject = self.decode_mime_header(subject)
                                    
                                    # Validate email format
                                    if not self.is_valid_email_format(sender):
                                        log.warning(f"Invalid sender format: {sender}")
                                        continue
                                    
                                    # Extract sender email address
                                    sender_email = re.search(r'<([^>]+)>', sender)
                                    if sender_email:
                                        sender_email = sender_email.group(1)
                                    else:
                                        sender_email = sender.strip()
                                    
                                    log.info(f"Processing email from {sender_email}: {subject}")
                                    
                                    # Check if sender is in our filters
                                    if sender_email not in sender_filters:
                                        log.debug(f"Sender {sender_email} not in filters, skipping")
                                        continue
                                    
                                    # Get target channel
                                    channel_id = sender_filters[sender_email]
                                    channel = self.bot.get_channel(channel_id)
                                    
                                    if not channel:
                                        log.error(f"Could not find channel {channel_id}")
                                        continue
                                    
                                    # Extract email content
                                    content = ""
                                    html_content = ""
                                    
                                    if msg.is_multipart():
                                        for part in msg.walk():
                                            content_type = part.get_content_type()
                                            if content_type == "text/plain":
                                                payload = part.get_payload(decode=True)
                                                if payload:
                                                    try:
                                                        content = payload.decode('utf-8', errors='ignore')
                                                    except:
                                                        content = str(payload)
                                            elif content_type == "text/html":
                                                payload = part.get_payload(decode=True)
                                                if payload:
                                                    try:
                                                        html_content = payload.decode('utf-8', errors='ignore')
                                                    except:
                                                        html_content = str(payload)
                                    else:
                                        payload = msg.get_payload(decode=True)
                                        if payload:
                                            try:
                                                content = payload.decode('utf-8', errors='ignore')
                                            except:
                                                content = str(payload)
                                    
                                    # Prefer HTML content for processing
                                    if html_content:
                                        content = self.convert_html_to_text_with_links(html_content)
                                    
                                    # Final safety check for any remaining HTML tags
                                    if '<' in content and '>' in content:
                                        # Emergency fallback: strip all HTML tags
                                        content = re.sub(r'<[^>]+>', '', content)
                                        log.warning("Applied emergency HTML tag removal")
                                    
                                    # Enhance reading time indicators
                                    content = self.enhance_reading_time_indicators(content)
                                    
                                    # Convert text links to Discord format
                                    content = self.convert_text_links_to_discord_format(content)
                                    
                                    # Clean the content
                                    content = self.clean_email_content(content)
                                    
                                    if not content.strip():
                                        log.warning(f"Empty content after processing for email {num}")
                                        continue
                                    
                                    # No content length limit applied
                                    
                                    # Split content for pagination if needed
                                    content_chunks = self.split_content_for_pagination(content)
                                    
                                    # Create and send embeds
                                    embeds = []
                                    for i, chunk in enumerate(content_chunks):
                                        embed = discord.Embed(
                                            title=subject if i == 0 else f"{subject} (continued)",
                                            description=chunk,
                                            color=0x00ff00,
                                            timestamp=datetime.now()
                                        )
                                        
                                        if i == 0:  # Add metadata to first embed
                                            embed.add_field(name="From", value=sender_email, inline=True)
                                            embed.add_field(name="Account", value=account_name, inline=True)
                                        
                                        if len(content_chunks) > 1:
                                            embed.set_footer(text=f"Page {i+1}/{len(content_chunks)}")
                                        
                                        embeds.append(embed)
                                    
                                    # Send embeds
                                    if len(embeds) == 1:
                                        await channel.send(embed=embeds[0])
                                    else:
                                        # Use pagination for multiple embeds
                                        view = EmailPaginationView(embeds)
                                        await channel.send(embed=embeds[0], view=view)
                                    
                                    # Mark email as seen
                                    mail.store(num, '+FLAGS', '\\Seen')
                                    
                                    log.info(f"Successfully processed and sent email from {sender_email}")
                                    
                                except Exception as e:
                                    log.error(f"Error processing email {num}: {e}")
                                    continue
                            
                            # Small delay between batches to prevent overwhelming
                            if i + batch_size < len(message_numbers):
                                await asyncio.sleep(1)
                    
                    except socket.timeout:
                        log.error(f"Connection timeout for account {account_name}")
                        continue
                    except imaplib.IMAP4.error as e:
                        log.error(f"IMAP error for account {account_name}: {e}")
                        continue
                    finally:
                        # Always close the connection
                        if mail:
                            try:
                                mail.close()
                                mail.logout()
                            except:
                                pass
                        # Reset socket timeout
                        socket.setdefaulttimeout(None)
                
                except Exception as e:
                    log.error(f"Error checking emails for account {account_name}: {e}")
                    continue
            
        except Exception as e:
            log.error(f"Error in check_emails_for_guild for guild {guild_id}: {e}")

    async def start_email_checking(self):
        """Start the email checking loop."""
        await self.bot.wait_until_ready()
        
        while not self.bot.is_closed():
            try:
                # Check emails for all guilds
                for guild in self.bot.guilds:
                    try:
                        guild_config = self.config.guild(guild)
                        
                        # Check if enough time has passed since last check
                        last_check = await guild_config.last_check()
                        check_interval = await guild_config.check_interval()
                        current_time = datetime.now().timestamp()
                        
                        if last_check is None or (current_time - last_check) >= check_interval:
                            await guild_config.last_check.set(current_time)
                            await self.check_emails_for_guild(guild.id)
                        
                    except Exception as e:
                        log.error(f"Error checking emails for guild {guild.id}: {e}")
                        continue
                
                # Wait before next iteration (minimum 5 minutes)
                await asyncio.sleep(300)
                
            except Exception as e:
                log.error(f"Error in email checking loop: {e}")
                await asyncio.sleep(300)  # Wait 5 minutes before retrying

    async def cog_load(self):
        """Start the email checking task when the cog loads."""
        self.email_check_task = asyncio.create_task(self.start_email_checking())
        log.info("Email news cog loaded and email checking started")

async def setup(bot):
    await bot.add_cog(EmailNews(bot))