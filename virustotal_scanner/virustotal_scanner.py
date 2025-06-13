import asyncio
import aiohttp
import discord
import hashlib
import re
import json
from typing import Dict, List, Optional, Union
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

    async def cog_load(self):
        """Start the scan queue processor when cog loads."""
        if not self.scanning:
            self.bot.loop.create_task(self.process_scan_queue())
            self.scanning = True

    async def cog_unload(self):
        """Stop scanning when cog unloads."""
        self.scanning = False

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
                    await asyncio.sleep(1)
            except Exception as e:
                log.error(f"Error in scan queue processor: {e}", exc_info=True)
                await asyncio.sleep(5)

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
            for url in urls:
                scan_data = {
                    'type': 'url',
                    'target': url,
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
            elif scan_data['type'] == 'file':
                await self.scan_file(scan_data)
        except Exception as e:
            log.error(f"Error performing scan: {e}", exc_info=True)

    async def scan_url(self, scan_data: Dict):
        """Scan a URL using VirusTotal API."""
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
                    
                # File submitted, will need to check later for results
                embed = discord.Embed(
                    title="🔍 File Scan Submitted",
                    description=f"File `{attachment.filename}` has been submitted to VirusTotal for scanning. Results will be available shortly.",
                    color=discord.Color.orange()
                )
                await message.channel.send(embed=embed)

    async def process_url_report(self, data: Dict, url: str, message: discord.Message):
        """Process and display URL scan results."""
        if data.get('response_code') != 1:
            return  # No report available
            
        positives = data.get('positives', 0)
        total = data.get('total', 0)
        scan_date = data.get('scan_date', 'Unknown')
        permalink = data.get('permalink', '')
        
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
            title="🛡️ VirusTotal URL Scan Results",
            color=color,
            timestamp=datetime.now(timezone.utc)
        )
        
        embed.add_field(name="URL", value=f"```{url[:100]}{'...' if len(url) > 100 else ''}```", inline=False)
        embed.add_field(name="Status", value=status, inline=True)
        embed.add_field(name="Detections", value=f"{positives}/{total}", inline=True)
        embed.add_field(name="Scan Date", value=scan_date, inline=True)
        
        if permalink:
            embed.add_field(name="Full Report", value=f"[View on VirusTotal]({permalink})", inline=False)
            
        embed.set_footer(text="Powered by VirusTotal")
        
        await message.channel.send(embed=embed)
        
        # Handle malicious content
        if positives >= await self.config.guild(message.guild).min_detections():
            await self.handle_malicious_content(message, 'URL', positives, total)

    async def process_file_report(self, data: Dict, attachment: discord.Attachment, message: discord.Message):
        """Process and display file scan results."""
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
        embed.add_field(name="File Size", value=humanize_number(attachment.size) + " bytes", inline=True)
        embed.add_field(name="MD5 Hash", value=f"```{md5}```", inline=False)
        embed.add_field(name="Scan Date", value=scan_date, inline=True)
        
        if permalink:
            embed.add_field(name="Full Report", value=f"[View on VirusTotal]({permalink})", inline=False)
            
        embed.set_footer(text="Powered by VirusTotal")
        
        await message.channel.send(embed=embed)
        
        # Handle malicious content
        if positives >= await self.config.guild(message.guild).min_detections():
            await self.handle_malicious_content(message, 'File', positives, total)

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