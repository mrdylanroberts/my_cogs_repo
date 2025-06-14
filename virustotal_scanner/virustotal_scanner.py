import asyncio
import aiohttp
import discord
import hashlib
import re
import json
from typing import Dict, List, Optional, Union, Tuple
from datetime import datetime, timezone
import base64
import time

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from redbot.core import commands, Config
from redbot.core.bot import Red
from redbot.core.utils.chat_formatting import box, humanize_number

import logging

log = logging.getLogger("red.my-cogs-repo.virustotal_scanner")

class VirusTotalPaginationView(discord.ui.View):
    """Persistent pagination view for VirusTotal scan results."""
    
    def __init__(self, embeds: List[discord.Embed], timeout: float = None):
        super().__init__(timeout=timeout)  # None = persistent view
        self.embeds = embeds
        self.current_page = 0
        self.max_pages = len(embeds)
        
        # Add numbered buttons for pages (up to 5 pages)
        if self.max_pages <= 5:
            for i in range(self.max_pages):
                button = discord.ui.Button(
                    label=str(i + 1),
                    emoji=f"{i + 1}️⃣",
                    style=discord.ButtonStyle.primary if i == 0 else discord.ButtonStyle.secondary,
                    custom_id=f"vt_page_{i}_{id(self)}"
                )
                button.callback = self.create_page_callback(i)
                self.add_item(button)
        else:
            # For more than 5 pages, use previous/next buttons
            prev_button = discord.ui.Button(
                label='Previous',
                style=discord.ButtonStyle.secondary,
                emoji='⬅️',
                custom_id=f'vt_previous_{id(self)}'
            )
            prev_button.callback = self.previous_callback
            self.add_item(prev_button)
            
            next_button = discord.ui.Button(
                label='Next',
                style=discord.ButtonStyle.secondary,
                emoji='➡️',
                custom_id=f'vt_next_{id(self)}'
            )
            next_button.callback = self.next_callback
            self.add_item(next_button)
    
    def create_page_callback(self, page_num: int):
        async def callback(interaction: discord.Interaction):
            try:
                await self.go_to_page(interaction, page_num)
            except Exception as e:
                log.error(f"Error in page callback for page {page_num}: {e}", exc_info=True)
                try:
                    if not interaction.response.is_done():
                        await interaction.response.send_message("❌ An error occurred while changing pages.", ephemeral=True)
                    else:
                        await interaction.followup.send("❌ An error occurred while changing pages.", ephemeral=True)
                except Exception:
                    pass
        return callback
    
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
                
                # Update button styles for numbered buttons
                if self.max_pages <= 5:
                    for i, item in enumerate(self.children):
                        if isinstance(item, discord.ui.Button) and item.custom_id and "vt_page_" in item.custom_id:
                            item.style = discord.ButtonStyle.primary if i == page else discord.ButtonStyle.secondary
                
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

class VirusTotalScanner(commands.Cog):
    """Automatically scan URLs and file attachments using VirusTotal API."""

    def __init__(self, bot: Red):
        self.bot = bot
        self.config = Config.get_conf(
            self,
            identifier=123456789,
            force_registration=True
        )
        self.encryption_key = None
        
        default_guild = {
            "api_key_data": None,  # Encrypted API key data
            "auto_scan": True,
            "scan_urls": True,
            "scan_files": True,
            "whitelist_channels": [],
            "blacklist_channels": [],
            "min_detections": 1,  # Minimum detections to show warning
            "delete_malicious": False,  # Auto-delete malicious content
            "notify_admins": True,  # Notify admins of malicious content
            "admin_channel": None,  # Channel ID for admin notifications
            "scan_delay": 2,  # Delay between scans to respect rate limits
            "pending_file_scans": {},  # Track pending file scans {scan_id: {channel_id, message_id, filename, timestamp}}
        }
        
        self.config.register_guild(**default_guild)
        
        # VirusTotal API endpoints
        self.vt_base_url = "https://www.virustotal.com/vtapi/v2"
        self.vt_url_scan = f"{self.vt_base_url}/url/scan"
        self.vt_url_report = f"{self.vt_base_url}/url/report"
        self.vt_file_scan = f"{self.vt_base_url}/file/scan"
        self.vt_file_report = f"{self.vt_base_url}/file/report"
        
        # URL regex pattern
        self.url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
        
        # Rate limiting
        self.last_scan_time = 0
        self.scan_queue = asyncio.Queue()
        self.scanning = False
        
        # File scan result checking
        self.file_check_task = None

    async def cog_load(self):
        """Start the scan queue processor and file check task when cog loads."""
        if not self.scanning:
            self.bot.loop.create_task(self.process_scan_queue())
            self.scanning = True
        
        if not self.file_check_task:
            self.file_check_task = self.bot.loop.create_task(self.check_pending_file_scans())

    async def cog_unload(self):
        """Stop scanning when cog unloads."""
        self.scanning = False
        
        if self.file_check_task:
            self.file_check_task.cancel()
            self.file_check_task = None

    async def initialize_encryption(self, guild_id: int):
        """Initialize encryption key using guild ID as salt (optional)."""
        if not self.encryption_key:
            try:
                tokens = await self.bot.get_shared_api_tokens("virustotal_scanner")
                if "secret" not in tokens:
                    # No encryption key set - encryption is optional
                    log.info("No encryption key set. API keys will be stored in plain text. Use '!set api virustotal_scanner secret,<your-secret-key>' to enable encryption.")
                    self.encryption_key = None
                    return
                
                salt = str(guild_id).encode()
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                key = base64.urlsafe_b64encode(kdf.derive(tokens["secret"].encode()))
                self.encryption_key = Fernet(key)
                log.info("Encryption initialized successfully.")
            except Exception as e:
                log.error(f"Failed to initialize encryption: {str(e)}")
                self.encryption_key = None

    def encrypt_api_key(self, api_key: str) -> Dict[str, str]:
        """Encrypt API key (if encryption is enabled)."""
        if self.encryption_key:
            encrypted_key = self.encryption_key.encrypt(api_key.encode()).decode()
            return {"api_key": encrypted_key, "encrypted": True}
        else:
            # Store in plain text if no encryption key is set
            log.warning("Storing API key in plain text. Consider setting an encryption key for security.")
            return {"api_key": api_key, "encrypted": False}

    def decrypt_api_key(self, stored_data: Dict[str, str]) -> str:
        """Decrypt API key (if it was encrypted)."""
        if stored_data.get("encrypted", True):  # Default to True for backward compatibility
            if not self.encryption_key:
                raise ValueError("API key is encrypted but no encryption key is available. Set encryption key with '!set api virustotal_scanner secret,<your-secret-key>'")
            return self.encryption_key.decrypt(stored_data["api_key"].encode()).decode()
        else:
            # API key is stored in plain text
            return stored_data["api_key"]

    async def get_api_key(self, guild) -> Optional[str]:
        """Get and decrypt the API key for a guild."""
        await self.initialize_encryption(guild.id)
        api_key_data = await self.config.guild(guild).api_key_data()
        if not api_key_data:
            return None
        try:
            return self.decrypt_api_key(api_key_data)
        except Exception as e:
            log.error(f"Failed to decrypt API key for guild {guild.id}: {e}")
            return None

    async def process_scan_queue(self):
        """Process the scan queue with rate limiting."""
        while self.scanning:
            try:
                if not self.scan_queue.empty():
                    scan_data = await self.scan_queue.get()
                    await self.perform_scan(scan_data)
                    
                    # Rate limiting - VirusTotal free API allows 4 requests per minute
                    await asyncio.sleep(15)  # 15 seconds between requests
                else:
                    await asyncio.sleep(5)
            except Exception as e:
                log.error(f"Error in scan queue processor: {e}", exc_info=True)
                await asyncio.sleep(5)

    async def check_pending_file_scans(self):
        """Periodically check for results of pending file scans."""
        while True:
            try:
                for guild in self.bot.guilds:
                    guild_config = self.config.guild(guild)
                    pending_scans = await guild_config.pending_file_scans()
                    
                    if not pending_scans:
                        continue
                    
                    api_key = await self.get_api_key(guild)
                    if not api_key:
                        continue
                    
                    scans_to_remove = []
                    
                    for scan_id, scan_info in pending_scans.items():
                        # Check if scan is older than 10 minutes (timeout)
                        if time.time() - scan_info.get('timestamp', 0) > 600:
                            scans_to_remove.append(scan_id)
                            continue
                        
                        # Check for scan results
                        async with aiohttp.ClientSession() as session:
                            report_params = {
                                'apikey': api_key,
                                'resource': scan_id
                            }
                            
                            async with session.get(self.vt_file_report, params=report_params) as response:
                                if response.status == 200:
                                    data = await response.json()
                                    if data.get('response_code') == 1:
                                        # Results available, send them
                                        channel = guild.get_channel(scan_info['channel_id'])
                                        if channel:
                                            # Create fake attachment for processing
                                            class FakeAttachment:
                                                def __init__(self, filename, size=0):
                                                    self.filename = filename
                                                    self.size = size
                                            
                                            fake_attachment = FakeAttachment(scan_info['filename'])
                                            
                                            # Create a fake message for context
                                            try:
                                                message = await channel.fetch_message(scan_info['message_id'])
                                                await self.process_file_report(data, fake_attachment, message)
                                            except discord.NotFound:
                                                # Original message was deleted, send to channel anyway
                                                embed = await self.create_file_report_embed(data, fake_attachment)
                                                await channel.send(embed=embed)
                                        
                                        scans_to_remove.append(scan_id)
                    
                    # Remove completed/expired scans
                    if scans_to_remove:
                        for scan_id in scans_to_remove:
                            del pending_scans[scan_id]
                        await guild_config.pending_file_scans.set(pending_scans)
                
                # Wait 30 seconds before checking again
                await asyncio.sleep(30)
                
            except Exception as e:
                log.error(f"Error in file scan checker: {e}", exc_info=True)
                await asyncio.sleep(60)  # Wait longer on error

    @commands.group(name="virustotal", aliases=["vt"])
    @commands.guild_only()
    @commands.admin_or_permissions(manage_guild=True)
    async def virustotal(self, ctx):
        """VirusTotal scanner configuration and commands."""
        if ctx.invoked_subcommand is None:
            await ctx.send_help()

    @virustotal.command(name="apikey")
    async def set_api_key(self, ctx, api_key: str = None):
        """Set the VirusTotal API key for this server.
        
        Get your free API key from: https://www.virustotal.com/gui/join-us
        """
        if api_key is None:
            await ctx.send(
                "Please provide your VirusTotal API key.\n"
                "Get a free API key from: https://www.virustotal.com/gui/join-us\n"
                "Usage: `!virustotal apikey YOUR_API_KEY`"
            )
            return
        
        # Initialize encryption for this guild
        await self.initialize_encryption(ctx.guild.id)
        
        # Encrypt and store the API key
        encrypted_data = self.encrypt_api_key(api_key)
        await self.config.guild(ctx.guild).api_key_data.set(encrypted_data)
        
        # Inform about encryption status
        if encrypted_data["encrypted"]:
            await ctx.send("✅ VirusTotal API key has been encrypted and stored securely!")
        else:
            await ctx.send("✅ VirusTotal API key has been set successfully!\n⚠️ **Security Notice**: API key is stored in plain text. Consider setting an encryption key with `!set api virustotal_scanner secret,<your-secret-key>` for enhanced security.")
        
        # Delete the message containing the API key for security
        try:
            await ctx.message.delete()
        except discord.HTTPException:
            pass

    @virustotal.command(name="toggle")
    async def toggle_auto_scan(self, ctx, enabled: bool = None):
        """Toggle automatic scanning of messages."""
        if enabled is None:
            current = await self.config.guild(ctx.guild).auto_scan()
            await ctx.send(f"Auto-scan is currently **{'enabled' if current else 'disabled'}**.")
            return
            
        await self.config.guild(ctx.guild).auto_scan.set(enabled)
        status = "enabled" if enabled else "disabled"
        await ctx.send(f"✅ Auto-scan has been **{status}**.")

    @virustotal.command(name="scan")
    async def manual_scan(self, ctx, *, target: str):
        """Manually scan a URL or file hash."""
        api_key = await self.get_api_key(ctx.guild)
        if not api_key:
            await ctx.send("❌ No VirusTotal API key configured. Use `!virustotal apikey` to set one.")
            return
            
        # Check if it's a URL or hash
        if self.url_pattern.match(target):
            await self.scan_url_manual(ctx, target, api_key)
        else:
            await self.scan_hash_manual(ctx, target, api_key)

    @virustotal.command(name="settings")
    async def show_settings(self, ctx):
        """Show current VirusTotal scanner settings."""
        guild_config = self.config.guild(ctx.guild)
        
        # Check API key status and encryption
        api_key_data = await guild_config.api_key_data()
        if api_key_data:
            if api_key_data.get("encrypted", True):
                api_key_status = "✅ Set (Encrypted)"
            else:
                api_key_status = "✅ Set (Plain Text)"
        else:
            api_key_status = "❌ Not set"
        
        # Get admin channel info
        admin_channel_id = await guild_config.admin_channel()
        if admin_channel_id:
            admin_channel = ctx.guild.get_channel(admin_channel_id)
            admin_channel_status = f"✅ {admin_channel.mention}" if admin_channel else "❌ Channel not found"
        else:
            admin_channel_status = "📧 DM to server owner"
        
        settings = {
            "API Key": api_key_status,
            "Auto Scan": "✅ Enabled" if await guild_config.auto_scan() else "❌ Disabled",
            "Scan URLs": "✅ Yes" if await guild_config.scan_urls() else "❌ No",
            "Scan Files": "✅ Yes" if await guild_config.scan_files() else "❌ No",
            "Min Detections": await guild_config.min_detections(),
            "Delete Malicious": "✅ Yes" if await guild_config.delete_malicious() else "❌ No",
            "Notify Admins": "✅ Yes" if await guild_config.notify_admins() else "❌ No",
            "Admin Channel": admin_channel_status,
        }
        
        embed = discord.Embed(
            title="🛡️ VirusTotal Scanner Settings",
            color=discord.Color.blue(),
            timestamp=datetime.now(timezone.utc)
        )
        
        for setting, value in settings.items():
            embed.add_field(name=setting, value=value, inline=True)
        
        # Add security notice if not encrypted
        if api_key_data and not api_key_data.get("encrypted", True):
            embed.add_field(
                name="🔒 Security Notice", 
                value="Consider enabling encryption with `!set api virustotal_scanner secret,<your-secret-key>`", 
                inline=False
            )
            
        await ctx.send(embed=embed)

    @virustotal.command(name="adminchannel")
    @commands.admin_or_permissions(manage_guild=True)
    async def set_admin_channel(self, ctx, channel: discord.TextChannel = None):
        """Set the admin notification channel for security alerts.
        
        Usage:
        - `!virustotal adminchannel #admin-logs` - Set admin channel
        - `!virustotal adminchannel` - Clear admin channel (use DMs)
        """
        guild_config = self.config.guild(ctx.guild)
        
        if channel is None:
            await guild_config.admin_channel.set(None)
            await ctx.send("✅ Admin channel cleared. Notifications will be sent via DM to server owner.")
        else:
            # Check if bot has permission to send messages in the channel
            if not channel.permissions_for(ctx.guild.me).send_messages:
                await ctx.send(f"❌ I don't have permission to send messages in {channel.mention}.")
                return
                
            await guild_config.admin_channel.set(channel.id)
            await ctx.send(f"✅ Admin notifications will now be sent to {channel.mention}.")

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        """Automatically scan messages for URLs and attachments."""
        # Skip bot messages and DMs
        if message.author.bot or not message.guild:
            return
            
        guild_config = self.config.guild(message.guild)
        
        # Check if auto-scan is enabled
        if not await guild_config.auto_scan():
            return
            
        # Check if API key is configured
        api_key = await self.get_api_key(message.guild)
        if not api_key:
            return
            
        # Check channel whitelist/blacklist
        whitelist = await guild_config.whitelist_channels()
        blacklist = await guild_config.blacklist_channels()
        
        if whitelist and message.channel.id not in whitelist:
            return
        if blacklist and message.channel.id in blacklist:
            return
            
        # Scan URLs in message content
        if await guild_config.scan_urls():
            urls = self.url_pattern.findall(message.content)
            if urls:
                # Process all URLs from the same message together
                scan_data = {
                    'type': 'url_batch',
                    'target': urls,
                    'message': message,
                    'api_key': api_key
                }
                await self.scan_queue.put(scan_data)
                
        # Scan file attachments
        if await guild_config.scan_files() and message.attachments:
            for attachment in message.attachments:
                # Only scan files under 32MB (VirusTotal limit)
                if attachment.size <= 32 * 1024 * 1024:
                    scan_data = {
                        'type': 'file',
                        'target': attachment,
                        'message': message,
                        'api_key': api_key
                    }
                    await self.scan_queue.put(scan_data)

    async def perform_scan(self, scan_data: Dict):
        """Perform the actual scan based on scan data."""
        try:
            if scan_data['type'] == 'url':
                await self.scan_url(scan_data)
            elif scan_data['type'] == 'url_batch':
                await self.scan_url_batch(scan_data)
            elif scan_data['type'] == 'file':
                await self.scan_file(scan_data)
        except Exception as e:
            log.error(f"Error performing scan: {e}", exc_info=True)

    async def scan_url_batch(self, scan_data: Dict):
        """Scan multiple URLs from the same message using VirusTotal API."""
        urls = scan_data['target']
        message = scan_data['message']
        api_key = scan_data['api_key']
        
        url_results = []
        
        async with aiohttp.ClientSession() as session:
            for url in urls:
                try:
                    # First, submit URL for scanning
                    scan_params = {
                        'apikey': api_key,
                        'url': url
                    }
                    
                    async with session.post(self.vt_url_scan, data=scan_params) as response:
                        if response.status != 200:
                            log.error(f"VirusTotal URL scan failed for {url}: {response.status}")
                            continue
                            
                    # Wait a moment then get the report
                    await asyncio.sleep(5)
                    
                    report_params = {
                        'apikey': api_key,
                        'resource': url
                    }
                    
                    async with session.get(self.vt_url_report, params=report_params) as response:
                        if response.status != 200:
                            log.error(f"VirusTotal URL report failed for {url}: {response.status}")
                            continue
                            
                        data = await response.json()
                        if data.get('response_code') == 1:
                            url_results.append((url, data))
                        
                except Exception as e:
                    log.error(f"Error scanning URL {url}: {e}")
                    continue
        
        # Process all results together with pagination
        if url_results:
            await self.process_url_batch_results(url_results, message)

    async def scan_url(self, scan_data: Dict):
        """Scan a single URL using VirusTotal API (for manual scans)."""
        url = scan_data['target']
        message = scan_data['message']
        api_key = scan_data['api_key']
        
        async with aiohttp.ClientSession() as session:
            # First, submit URL for scanning
            scan_params = {
                'apikey': api_key,
                'url': url
            }
            
            async with session.post(self.vt_url_scan, data=scan_params) as response:
                if response.status != 200:
                    log.error(f"VirusTotal URL scan failed: {response.status}")
                    return
                    
            # Wait a moment then get the report
            await asyncio.sleep(5)
            
            report_params = {
                'apikey': api_key,
                'resource': url
            }
            
            async with session.get(self.vt_url_report, params=report_params) as response:
                if response.status != 200:
                    log.error(f"VirusTotal URL report failed: {response.status}")
                    return
                    
                data = await response.json()
                await self.process_url_report(data, url, message)

    async def process_url_batch_results(self, url_results: List[Tuple[str, Dict]], message: discord.Message):
        """Process and display multiple URL scan results with pagination."""
        embeds = []
        
        # Create summary embed first
        summary_embed = discord.Embed(
            title="🛡️ VirusTotal URL Scan Results Summary",
            color=discord.Color.blue(),
            timestamp=datetime.now(timezone.utc)
        )
        
        total_urls = len(url_results)
        clean_count = 0
        suspicious_count = 0
        malicious_count = 0
        
        summary_text = ""
        for i, (url, data) in enumerate(url_results, 1):
            positives = data.get('positives', 0)
            total = data.get('total', 0)
            
            if positives == 0:
                status_emoji = "✅"
                clean_count += 1
            elif positives < 5:
                status_emoji = "⚠️"
                suspicious_count += 1
            else:
                status_emoji = "🚨"
                malicious_count += 1
            
            url_display = url[:50] + "..." if len(url) > 50 else url
            summary_text += f"{status_emoji} **URL {i}**: `{url_display}` ({positives}/{total})\n"
        
        summary_embed.add_field(
            name=f"Scanned {total_urls} URLs",
            value=summary_text[:1024],  # Discord field limit
            inline=False
        )
        
        # Add statistics
        stats_text = f"✅ Clean: {clean_count}\n⚠️ Suspicious: {suspicious_count}\n🚨 Malicious: {malicious_count}"
        summary_embed.add_field(name="Statistics", value=stats_text, inline=True)
        
        summary_embed.set_footer(text="Powered by VirusTotal • Use navigation buttons for detailed results")
        embeds.append(summary_embed)
        
        # Create detailed embeds for each URL
        for i, (url, data) in enumerate(url_results, 1):
            positives = data.get('positives', 0)
            total = data.get('total', 0)
            scan_date = data.get('scan_date', 'Unknown')
            permalink = data.get('permalink', '')
            scans = data.get('scans', {})
            
            # Determine threat level
            if positives == 0:
                color = discord.Color.green()
                status = "✅ Clean"
            elif positives < 5:
                color = discord.Color.orange()
                status = "⚠️ Suspicious"
            else:
                color = discord.Color.red()
                status = "🚨 Malicious"
            
            # Create detailed embed for this URL
            detail_embed = discord.Embed(
                title=f"🛡️ URL {i} Detailed Results",
                color=color,
                timestamp=datetime.now(timezone.utc)
            )
            
            detail_embed.add_field(name="URL", value=f"```{url[:100]}{'...' if len(url) > 100 else ''}```", inline=False)
            detail_embed.add_field(name="Status", value=status, inline=True)
            detail_embed.add_field(name="Detections", value=f"{positives}/{total}", inline=True)
            detail_embed.add_field(name="Scan Date", value=scan_date, inline=True)
            
            if permalink:
                detail_embed.add_field(name="Full Report", value=f"[View on VirusTotal]({permalink})", inline=False)
            
            # Add detection details if any
            if positives > 0 and scans:
                detected_engines = []
                for engine, result in scans.items():
                    if result.get('detected', False):
                        detected_engines.append(f"**{engine}**: {result.get('result', 'Malicious site')}")
                
                if detected_engines:
                    detection_text = "\n".join(detected_engines[:10])  # Limit to first 10
                    if len(detected_engines) > 10:
                        detection_text += f"\n... and {len(detected_engines) - 10} more"
                    
                    detail_embed.add_field(
                        name=f"Detected by {len(detected_engines)} engines:",
                        value=detection_text[:1024],  # Discord field limit
                        inline=False
                    )
            
            detail_embed.set_footer(text="Powered by VirusTotal")
            embeds.append(detail_embed)
        
        # Send with pagination if multiple embeds
        if len(embeds) > 1:
            view = VirusTotalPaginationView(embeds, timeout=None)
            await message.channel.send(embed=embeds[0], view=view)
        else:
            await message.channel.send(embed=embeds[0])
        
        # Handle malicious content if any
        malicious_urls = [(url, data) for url, data in url_results if data.get('positives', 0) >= await self.config.guild(message.guild).min_detections()]
        if malicious_urls:
            for url, data in malicious_urls:
                await self.handle_malicious_content(message, 'URL', data.get('positives', 0), data.get('total', 0))

    async def scan_file(self, scan_data: Dict):
        """Scan a file attachment using VirusTotal API."""
        attachment = scan_data['target']
        message = scan_data['message']
        api_key = scan_data['api_key']
        
        # Download file content
        file_content = await attachment.read()
        file_hash = hashlib.sha256(file_content).hexdigest()
        
        async with aiohttp.ClientSession() as session:
            # Check if we already have a report for this file hash
            report_params = {
                'apikey': api_key,
                'resource': file_hash
            }
            
            async with session.get(self.vt_file_report, params=report_params) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get('response_code') == 1:
                        # We have a report, use it
                        await self.process_file_report(data, attachment, message)
                        return
            
            # No existing report, submit file for scanning
            scan_data_form = aiohttp.FormData()
            scan_data_form.add_field('apikey', api_key)
            scan_data_form.add_field('file', file_content, filename=attachment.filename)
            
            async with session.post(self.vt_file_scan, data=scan_data_form) as response:
                if response.status != 200:
                    log.error(f"VirusTotal file scan failed: {response.status}")
                    return
                    
                scan_response = await response.json()
                scan_id = scan_response.get('scan_id')
                
                if scan_id:
                    # Store pending scan for later checking
                    guild_config = self.config.guild(message.guild)
                    pending_scans = await guild_config.pending_file_scans()
                    pending_scans[scan_id] = {
                        'channel_id': message.channel.id,
                        'message_id': message.id,
                        'filename': attachment.filename,
                        'timestamp': time.time()
                    }
                    await guild_config.pending_file_scans.set(pending_scans)
                    
                    # File submitted, will need to check later for results
                    embed = discord.Embed(
                        title="🔍 File Scan Submitted",
                        description=f"File `{attachment.filename}` has been submitted to VirusTotal for scanning. Results will be available shortly.",
                        color=discord.Color.orange()
                    )
                    await message.channel.send(embed=embed)
                else:
                    log.error("No scan_id received from VirusTotal file scan")

    async def process_url_report(self, data: Dict, url: str, message: discord.Message):
        """Process and display URL scan results."""
        if data.get('response_code') != 1:
            return  # No report available
            
        positives = data.get('positives', 0)
        total = data.get('total', 0)
        scan_date = data.get('scan_date', 'Unknown')
        permalink = data.get('permalink', '')
        scans = data.get('scans', {})
        
        # Determine threat level
        if positives == 0:
            color = discord.Color.green()
            status = "✅ Clean"
        elif positives < 5:
            color = discord.Color.orange()
            status = "⚠️ Suspicious"
        else:
            color = discord.Color.red()
            status = "🚨 Malicious"
            
        # Create main summary embed
        main_embed = discord.Embed(
            title="🛡️ VirusTotal URL Scan Results",
            color=color,
            timestamp=datetime.now(timezone.utc)
        )
        
        main_embed.add_field(name="URL", value=f"```{url[:100]}{'...' if len(url) > 100 else ''}```", inline=False)
        main_embed.add_field(name="Status", value=status, inline=True)
        main_embed.add_field(name="Detections", value=f"{positives}/{total}", inline=True)
        main_embed.add_field(name="Scan Date", value=scan_date, inline=True)
        
        if permalink:
            main_embed.add_field(name="Full Report", value=f"[View on VirusTotal]({permalink})", inline=False)
            
        main_embed.set_footer(text="Powered by VirusTotal")
        
        embeds = [main_embed]
        
        # If there are detections, create detailed pages
        if positives > 0 and scans:
            detected_engines = []
            clean_engines = []
            
            for engine, result in scans.items():
                if result.get('detected', False):
                    detected_engines.append((engine, result.get('result', 'Malicious site')))
                else:
                    clean_engines.append(engine)
            
            # Create detection details pages
            if detected_engines:
                # Group detections into pages (10 per page)
                detection_pages = [detected_engines[i:i+10] for i in range(0, len(detected_engines), 10)]
                
                for i, page_detections in enumerate(detection_pages):
                    embed = discord.Embed(
                        title=f"🚨 URL Detection Details (Page {i+1}/{len(detection_pages)})",
                        color=discord.Color.red(),
                        timestamp=datetime.now(timezone.utc)
                    )
                    
                    detection_text = ""
                    for engine, result in page_detections:
                        detection_text += f"**{engine}**: {result}\n"
                    
                    embed.add_field(
                        name=f"Detected by {len(page_detections)} engines:",
                        value=detection_text[:1024],  # Discord field limit
                        inline=False
                    )
                    
                    embed.set_footer(text="Powered by VirusTotal")
                    embeds.append(embed)
            
            # Create clean engines page if there are many
            if len(clean_engines) > 20:
                clean_pages = [clean_engines[i:i+30] for i in range(0, len(clean_engines), 30)]
                
                for i, page_engines in enumerate(clean_pages):
                    embed = discord.Embed(
                        title=f"✅ Clean URL Results (Page {i+1}/{len(clean_pages)})",
                        color=discord.Color.green(),
                        timestamp=datetime.now(timezone.utc)
                    )
                    
                    clean_text = ", ".join(page_engines)
                    embed.add_field(
                        name=f"Clean by {len(page_engines)} engines:",
                        value=clean_text[:1024],  # Discord field limit
                        inline=False
                    )
                    
                    embed.set_footer(text="Powered by VirusTotal")
                    embeds.append(embed)
        
        # Send with pagination if multiple embeds
        if len(embeds) > 1:
            view = VirusTotalPaginationView(embeds, timeout=None)
            await message.channel.send(embed=embeds[0], view=view)
        else:
            await message.channel.send(embed=embeds[0])
        
        # Handle malicious content
        if positives >= await self.config.guild(message.guild).min_detections():
            await self.handle_malicious_content(message, 'URL', positives, total)

    async def process_file_report(self, data: Dict, attachment: discord.Attachment, message: discord.Message):
        """Process and display file scan results."""
        positives = data.get('positives', 0)
        total = data.get('total', 0)
        scans = data.get('scans', {})
        
        # Create main summary embed
        main_embed = await self.create_file_report_embed(data, attachment)
        
        embeds = [main_embed]
        
        # If there are detections, create detailed pages
        if positives > 0 and scans:
            detected_engines = []
            clean_engines = []
            
            for engine, result in scans.items():
                if result.get('detected', False):
                    detected_engines.append((engine, result.get('result', 'Malware')))
                else:
                    clean_engines.append(engine)
            
            # Create detection details pages
            if detected_engines:
                # Group detections into pages (10 per page)
                detection_pages = [detected_engines[i:i+10] for i in range(0, len(detected_engines), 10)]
                
                for i, page_detections in enumerate(detection_pages):
                    embed = discord.Embed(
                        title=f"🚨 Detection Details (Page {i+1}/{len(detection_pages)})",
                        color=discord.Color.red(),
                        timestamp=datetime.now(timezone.utc)
                    )
                    
                    detection_text = ""
                    for engine, result in page_detections:
                        detection_text += f"**{engine}**: {result}\n"
                    
                    embed.add_field(
                        name=f"Detected by {len(page_detections)} engines:",
                        value=detection_text[:1024],  # Discord field limit
                        inline=False
                    )
                    
                    embed.set_footer(text="Powered by VirusTotal")
                    embeds.append(embed)
            
            # Create clean engines page if there are many
            if len(clean_engines) > 20:
                clean_pages = [clean_engines[i:i+30] for i in range(0, len(clean_engines), 30)]
                
                for i, page_engines in enumerate(clean_pages):
                    embed = discord.Embed(
                        title=f"✅ Clean Results (Page {i+1}/{len(clean_pages)})",
                        color=discord.Color.green(),
                        timestamp=datetime.now(timezone.utc)
                    )
                    
                    clean_text = ", ".join(page_engines)
                    embed.add_field(
                        name=f"Clean by {len(page_engines)} engines:",
                        value=clean_text[:1024],  # Discord field limit
                        inline=False
                    )
                    
                    embed.set_footer(text="Powered by VirusTotal")
                    embeds.append(embed)
        
        # Send with pagination if multiple embeds
        if len(embeds) > 1:
            view = VirusTotalPaginationView(embeds, timeout=None)
            await message.channel.send(embed=embeds[0], view=view)
        else:
            await message.channel.send(embed=embeds[0])
        
        # Handle malicious content
        if positives >= await self.config.guild(message.guild).min_detections():
            await self.handle_malicious_content(message, 'File', positives, total)

    async def create_file_report_embed(self, data: Dict, attachment) -> discord.Embed:
        """Create a file report embed from scan data."""
        positives = data.get('positives', 0)
        total = data.get('total', 0)
        scan_date = data.get('scan_date', 'Unknown')
        permalink = data.get('permalink', '')
        md5 = data.get('md5', '')
        
        # Determine threat level
        if positives == 0:
            color = discord.Color.green()
            status = "✅ Clean"
        elif positives < 5:
            color = discord.Color.orange()
            status = "⚠️ Suspicious"
        else:
            color = discord.Color.red()
            status = "🚨 Malicious"
            
        embed = discord.Embed(
            title="🛡️ VirusTotal File Scan Results",
            color=color,
            timestamp=datetime.now(timezone.utc)
        )
        
        embed.add_field(name="Filename", value=f"```{attachment.filename}```", inline=False)
        embed.add_field(name="Status", value=status, inline=True)
        embed.add_field(name="Detections", value=f"{positives}/{total}", inline=True)
        if hasattr(attachment, 'size'):
            embed.add_field(name="File Size", value=humanize_number(attachment.size) + " bytes", inline=True)
        embed.add_field(name="MD5 Hash", value=f"```{md5}```", inline=False)
        embed.add_field(name="Scan Date", value=scan_date, inline=True)
        
        if permalink:
            embed.add_field(name="Full Report", value=f"[View on VirusTotal]({permalink})", inline=False)
            
        embed.set_footer(text="Powered by VirusTotal")
        
        return embed

    async def handle_malicious_content(self, message: discord.Message, content_type: str, positives: int, total: int):
        """Handle detection of malicious content."""
        guild_config = self.config.guild(message.guild)
        
        # Delete message if configured
        if await guild_config.delete_malicious():
            try:
                await message.delete()
                
                # Send notification about deletion
                embed = discord.Embed(
                    title="🚨 Malicious Content Deleted",
                    description=f"A message containing a malicious {content_type.lower()} was automatically deleted.",
                    color=discord.Color.red()
                )
                embed.add_field(name="Author", value=message.author.mention, inline=True)
                embed.add_field(name="Detections", value=f"{positives}/{total}", inline=True)
                
                await message.channel.send(embed=embed, delete_after=30)
            except discord.HTTPException:
                pass
                
        # Notify admins if configured
        if await guild_config.notify_admins():
            admin_embed = discord.Embed(
                title="🚨 Malicious Content Detected",
                description=f"Malicious {content_type.lower()} detected in {message.channel.mention}",
                color=discord.Color.red(),
                timestamp=datetime.now(timezone.utc)
            )
            admin_embed.add_field(name="Author", value=f"{message.author} ({message.author.id})", inline=True)
            admin_embed.add_field(name="Channel", value=message.channel.mention, inline=True)
            admin_embed.add_field(name="Detections", value=f"{positives}/{total}", inline=True)
            admin_embed.add_field(name="Message Link", value=f"[Jump to Message]({message.jump_url})", inline=False)
            
            # Send to configured admin channel or fallback to server owner
            admin_channel_id = await guild_config.admin_channel()
            notification_sent = False
            
            if admin_channel_id:
                admin_channel = message.guild.get_channel(admin_channel_id)
                if admin_channel:
                    try:
                        await admin_channel.send(embed=admin_embed)
                        notification_sent = True
                    except discord.HTTPException:
                        pass  # Fall back to DM if channel send fails
            
            # Fallback to DM server owner if no admin channel or channel send failed
            if not notification_sent:
                try:
                    await message.guild.owner.send(embed=admin_embed)
                except discord.HTTPException:
                    # If can't DM owner, try to find an admin channel as last resort
                    for channel in message.guild.text_channels:
                        if 'admin' in channel.name.lower() or 'mod' in channel.name.lower():
                            try:
                                await channel.send(embed=admin_embed)
                                break
                            except discord.HTTPException:
                                continue

    async def scan_url_manual(self, ctx, url: str, api_key: str):
        """Manually scan a URL and return results."""
        embed = discord.Embed(
            title="🔍 Scanning URL...",
            description="Please wait while the URL is being scanned.",
            color=discord.Color.orange()
        )
        status_msg = await ctx.send(embed=embed)
        
        scan_data = {
            'type': 'url',
            'target': url,
            'message': ctx.message,
            'api_key': api_key
        }
        
        await self.perform_scan(scan_data)
        await status_msg.delete()

    async def scan_hash_manual(self, ctx, file_hash: str, api_key: str):
        """Manually scan a file hash and return results."""
        embed = discord.Embed(
            title="🔍 Scanning File Hash...",
            description="Please wait while the file hash is being checked.",
            color=discord.Color.orange()
        )
        status_msg = await ctx.send(embed=embed)
        
        async with aiohttp.ClientSession() as session:
            report_params = {
                'apikey': api_key,
                'resource': file_hash
            }
            
            async with session.get(self.vt_file_report, params=report_params) as response:
                if response.status != 200:
                    await status_msg.edit(embed=discord.Embed(
                        title="❌ Scan Failed",
                        description="Failed to retrieve scan results.",
                        color=discord.Color.red()
                    ))
                    return
                    
                data = await response.json()
                
                if data.get('response_code') != 1:
                    await status_msg.edit(embed=discord.Embed(
                        title="❌ No Results",
                        description="No scan results found for this hash.",
                        color=discord.Color.orange()
                    ))
                    return
                    
                # Create a fake attachment object for the report processor
                class FakeAttachment:
                    def __init__(self, hash_val):
                        self.filename = f"Hash: {hash_val}"
                        self.size = 0
                        
                fake_attachment = FakeAttachment(file_hash)
                await self.process_file_report(data, fake_attachment, ctx.message)
                await status_msg.delete()