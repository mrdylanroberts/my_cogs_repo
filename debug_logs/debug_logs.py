import discord
import asyncio
import os
import logging
import re
import subprocess
import shutil
import psutil
from datetime import datetime, timedelta
from typing import Optional, Union, List, Tuple, Dict, Any
from io import StringIO
import time
from pathlib import Path
import json
try:
    import grp
    import pwd
    UNIX_AVAILABLE = True
except ImportError:
    # Windows doesn't have grp/pwd modules
    UNIX_AVAILABLE = False
    grp = None
    pwd = None

import discord
from redbot.core import commands, checks, Config
from redbot.core.bot import Red
from redbot.core.utils.chat_formatting import box, pagify
from redbot.core.utils.predicates import MessagePredicate

class DebugLogs(commands.Cog):
    """
    Advanced log management cog for Red-DiscordBot.
    Allows moderators and administrators to retrieve and send log files to Discord channels.
    """

    def __init__(self, bot: Red):
        self.bot = bot
        self.config = Config.get_conf(self, identifier=1234567890)
        default_guild = {
            "log_channel": None,
            "auto_cleanup": True,
            "max_file_size": 8000000,  # 8MB Discord limit
            "timezone": "UTC",  # For proper timestamp handling
            "log_format": "auto",  # Support different log formats
            "max_search_results": 1000,  # Limit search results
            "rate_limit_per_user": 5,  # Commands per minute per user
            "cache_duration": 300,  # Cache results for 5 minutes
            "allowed_log_paths": [],  # Whitelist of allowed log directories
            "journal_fallback": True,  # Use systemd journal as fallback
            "service_name": "red-discordbot",  # systemd service name
            "gcp_optimization": False,  # Google Cloud Platform optimizations
            "log_rotation_aware": True,  # Handle log rotation
            "ip_rate_limiting": False,  # IP-based rate limiting for VPS
            "stream_large_logs": True,  # Stream processing for large logs
            "max_journal_lines": 10000  # Maximum lines from journal
        }
        self.user_rate_limits = {}  # Track user command usage
        self.log_cache = {}  # Cache for parsed log data
        self.ip_rate_limits = {}  # Track IP-based rate limits
        self.journal_available = self._check_journal_availability()
        self.config.register_guild(**default_guild)

    def _check_journal_availability(self) -> bool:
        """
        Check if systemd journal is available and accessible.
        """
        if not UNIX_AVAILABLE:
            return False
            
        try:
            # Check if journalctl command exists
            result = subprocess.run(['which', 'journalctl'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                return False
            
            # Check if we can access journal (need systemd-journal group)
            try:
                result = subprocess.run(['journalctl', '--lines=1'], 
                                      capture_output=True, text=True, timeout=5)
                return result.returncode == 0
            except subprocess.TimeoutExpired:
                return False
                
        except (subprocess.SubprocessError, FileNotFoundError):
            return False
    
    def _check_system_permissions(self) -> Dict[str, bool]:
        """
        Check system permissions for Ubuntu VPS environment.
        """
        permissions = {
            'journal_access': False,
            'log_directory_read': False,
            'systemd_service_status': False
        }
        
        try:
            # Check journal group membership (Unix/Linux only)
            if UNIX_AVAILABLE:
                current_user = pwd.getpwuid(os.getuid()).pw_name
                try:
                    journal_group = grp.getgrnam('systemd-journal')
                    permissions['journal_access'] = current_user in journal_group.gr_mem
                except KeyError:
                    pass
            else:
                # On Windows, journal access is not available
                permissions['journal_access'] = False
            
            # Check log directory access
            log_dirs = ['/var/log', '/var/log/red-discordbot']
            for log_dir in log_dirs:
                if os.path.exists(log_dir) and os.access(log_dir, os.R_OK):
                    permissions['log_directory_read'] = True
                    break
            
            # Check systemd service access (Unix/Linux only)
            if UNIX_AVAILABLE:
                try:
                    result = subprocess.run(['systemctl', 'is-active', 'red-discordbot'], 
                                          capture_output=True, text=True, timeout=5)
                    permissions['systemd_service_status'] = True
                except (subprocess.SubprocessError, subprocess.TimeoutExpired):
                    pass
            else:
                permissions['systemd_service_status'] = False
                
        except Exception:
            pass
            
        return permissions
    
    def get_log_file_path(self) -> Optional[str]:
        """
        Get the path to the Red-DiscordBot log file with Ubuntu-specific paths and security validation.
        """
        # Ubuntu/Linux specific paths (prioritized for VPS)
        ubuntu_paths = [
            "/var/log/red-discordbot/red.log",
            "/var/log/red-discordbot/bot.log",
            "/home/redbot/.local/share/Red-DiscordBot/logs/red.log",
            "/opt/red-discordbot/logs/red.log",
            "/var/log/redbot.log",
            "/var/log/discord-bot.log"
        ]
        
        # Standard Red-DiscordBot log locations
        standard_paths = [
            os.path.join(os.getcwd(), "logs", "red.log"),
            os.path.join(os.getcwd(), "red.log"),
            os.path.join(os.path.expanduser("~"), ".local", "share", "Red-DiscordBot", "logs", "red.log"),
            "C:\\Users\\Administrator\\AppData\\Local\\Red-DiscordBot\\logs\\red.log"
        ]
        
        # Combine paths with Ubuntu paths first
        possible_paths = ubuntu_paths + standard_paths
        
        for path in possible_paths:
            if self._is_safe_path(path) and os.path.exists(path):
                return path
        
        # If no standard path found, try to find any .log file in common directories
        search_dirs = [os.getcwd(), os.path.join(os.getcwd(), "logs")]
        for search_dir in search_dirs:
            if os.path.exists(search_dir):
                try:
                    for file in os.listdir(search_dir):
                        if file.endswith(".log") and "red" in file.lower():
                            full_path = os.path.join(search_dir, file)
                            if self._is_safe_path(full_path):
                                return full_path
                except (PermissionError, OSError):
                    continue
        
        return None
    
    def _is_safe_path(self, path: str) -> bool:
        """
        Validate that the path is safe and within allowed directories.
        Prevents path traversal attacks.
        """
        try:
            # Resolve the path to prevent traversal
            resolved_path = Path(path).resolve()
            
            # Check if path exists and is a file
            if not resolved_path.exists() or not resolved_path.is_file():
                return True  # Allow checking non-existent paths
            
            # Basic security: ensure it's a .log file
            if not str(resolved_path).endswith('.log'):
                return False
            
            # Additional security checks could be added here
            return True
        except (OSError, ValueError):
            return False
    
    async def _get_journal_logs(self, service_name: str = None, lines: int = 1000, 
                               since: str = None, until: str = None) -> Optional[str]:
        """
        Get logs from systemd journal for Ubuntu VPS.
        """
        if not UNIX_AVAILABLE or not self.journal_available:
            return None
        
        try:
            cmd = ['journalctl', '--no-pager', '--output=short-iso']
            
            if service_name:
                cmd.extend(['--unit', service_name])
            
            if since:
                cmd.extend(['--since', since])
            
            if until:
                cmd.extend(['--until', until])
            
            cmd.extend(['--lines', str(lines)])
            
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=30)
            
            if result.returncode == 0:
                return stdout.decode('utf-8', errors='ignore')
            else:
                logging.error(f"Journal command failed: {stderr.decode()}")
                return None
                
        except (asyncio.TimeoutError, subprocess.SubprocessError) as e:
            logging.error(f"Failed to get journal logs: {e}")
            return None
    
    async def _get_system_resources(self) -> Dict[str, Any]:
        """
        Get system resource information for VPS monitoring.
        """
        try:
            # Memory usage
            memory = psutil.virtual_memory()
            
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Disk usage
            disk = psutil.disk_usage('/')
            
            # Load average (Linux only)
            try:
                load_avg = os.getloadavg()
            except (OSError, AttributeError):
                load_avg = (0, 0, 0)
            
            return {
                'memory': {
                    'total': memory.total,
                    'available': memory.available,
                    'percent': memory.percent,
                    'used': memory.used
                },
                'cpu': {
                    'percent': cpu_percent,
                    'count': psutil.cpu_count()
                },
                'disk': {
                    'total': disk.total,
                    'used': disk.used,
                    'free': disk.free,
                    'percent': (disk.used / disk.total) * 100
                },
                'load_avg': load_avg
            }
        except Exception as e:
            logging.error(f"Failed to get system resources: {e}")
            return {}
    
    async def _get_service_status(self, service_name: str) -> Dict[str, Any]:
        """
        Get systemd service status for Ubuntu VPS.
        """
        if not UNIX_AVAILABLE:
            return {'status': 'unavailable', 'error': 'systemctl not available on Windows'}
            
        try:
            # Get service status
            status_cmd = ['systemctl', 'is-active', service_name]
            status_result = await asyncio.create_subprocess_exec(
                *status_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            status_stdout, _ = await asyncio.wait_for(status_result.communicate(), timeout=10)
            status = status_stdout.decode().strip()
            
            # Get service info
            info_cmd = ['systemctl', 'show', service_name, '--no-page']
            info_result = await asyncio.create_subprocess_exec(
                *info_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            info_stdout, _ = await asyncio.wait_for(info_result.communicate(), timeout=10)
            
            # Parse service info
            service_info = {}
            for line in info_stdout.decode().split('\n'):
                if '=' in line:
                    key, value = line.split('=', 1)
                    service_info[key] = value
            
            return {
                'status': status,
                'main_pid': service_info.get('MainPID', 'unknown'),
                'memory_current': service_info.get('MemoryCurrent', 'unknown'),
                'active_state': service_info.get('ActiveState', 'unknown'),
                'sub_state': service_info.get('SubState', 'unknown'),
                'load_state': service_info.get('LoadState', 'unknown')
            }
            
        except (asyncio.TimeoutError, subprocess.SubprocessError) as e:
            logging.error(f"Failed to get service status: {e}")
            return {'status': 'unknown', 'error': str(e)}

    def parse_log_timestamp(self, line: str) -> Optional[datetime]:
        """
        Enhanced timestamp parsing with multiple format support.
        """
        patterns = [
            (r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', '%Y-%m-%d %H:%M:%S'),  # Standard
            (r'\[(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\]', '%Y-%m-%d %H:%M:%S'),  # Bracketed
            (r'(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})', '%m/%d/%Y %H:%M:%S'),  # US format
            (r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', '%Y-%m-%dT%H:%M:%S'),  # ISO format
        ]
        
        for pattern, fmt in patterns:
            match = re.search(pattern, line)
            if match:
                try:
                    return datetime.strptime(match.group(1), fmt)
                except ValueError:
                    continue
        return None
    
    def filter_logs_by_time(self, log_content: str, hours: int = None, minutes: int = None) -> str:
        """
        Filter log entries to only include those from the last N hours or minutes.
        Enhanced with better timestamp parsing and performance.
        """
        lines = log_content.split('\n')
        filtered_lines = []
        
        # Calculate cutoff time
        if minutes:
            cutoff_time = datetime.now() - timedelta(minutes=minutes)
        elif hours:
            cutoff_time = datetime.now() - timedelta(hours=hours)
        else:
            cutoff_time = datetime.now() - timedelta(hours=1)  # Default 1 hour
        
        for line in lines:
            log_time = self.parse_log_timestamp(line)
            if log_time:
                if log_time >= cutoff_time:
                    filtered_lines.append(line)
            else:
                # If no timestamp found, include the line (might be continuation)
                filtered_lines.append(line)
        
        return '\n'.join(filtered_lines)

    def filter_logs_by_cog(self, log_content: str, cog_name: str) -> str:
        """
        Filter log entries to only include those related to a specific cog.
        Enhanced with better pattern matching and context.
        """
        lines = log_content.split('\n')
        filtered_lines = []
        context_lines = []  # Store lines for context
        
        # Enhanced patterns for cog matching
        patterns = [
            cog_name.lower(),
            f"cogs.{cog_name.lower()}",
            f"{cog_name.lower()}.py",
            f"[{cog_name.lower()}]",
            f"({cog_name.lower()})",
            f"cog:{cog_name.lower()}"
        ]
        
        for i, line in enumerate(lines):
            line_lower = line.lower()
            if any(pattern in line_lower for pattern in patterns):
                # Add context: previous 2 lines and next 2 lines
                start_idx = max(0, i - 2)
                end_idx = min(len(lines), i + 3)
                context_lines.extend(lines[start_idx:end_idx])
                context_lines.append("---")  # Separator
        
        # Remove duplicates while preserving order
        seen = set()
        for line in context_lines:
            if line not in seen:
                filtered_lines.append(line)
                seen.add(line)
        
        return '\n'.join(filtered_lines)

    def filter_logs_by_level(self, log_content: str, level: str) -> str:
        """
        Filter log entries by log level (ERROR, WARNING, INFO, DEBUG).
        """
        lines = log_content.split('\n')
        filtered_lines = []
        
        for line in lines:
            if level.upper() in line:
                filtered_lines.append(line)
        
        return '\n'.join(filtered_lines)

    async def _check_rate_limit(self, ctx) -> bool:
        """
        Check if user is rate limited.
        Supports both user-based and IP-based rate limiting for VPS security.
        """
        user_id = ctx.author.id
        current_time = time.time()
        
        if user_id not in self.user_rate_limits:
            self.user_rate_limits[user_id] = []
        
        # Clean old entries (older than 1 minute)
        self.user_rate_limits[user_id] = [
            timestamp for timestamp in self.user_rate_limits[user_id]
            if current_time - timestamp < 60
        ]
        
        rate_limit = await self.config.guild(ctx.guild).rate_limit_per_user()
        ip_rate_limiting = await self.config.guild(ctx.guild).ip_rate_limiting()
        
        # User-based rate limiting
        if len(self.user_rate_limits[user_id]) >= rate_limit:
            return False
        
        # IP-based rate limiting (if enabled)
        if ip_rate_limiting:
            # Create a pseudo-IP identifier based on user patterns
            # In production, you'd integrate with proper IP tracking
            user_ip = f"ip_user_{user_id % 1000}"  # Simplified IP grouping
            
            if user_ip not in self.ip_rate_limits:
                self.ip_rate_limits[user_ip] = []
            
            # Clean old IP entries
            self.ip_rate_limits[user_ip] = [
                timestamp for timestamp in self.ip_rate_limits[user_ip]
                if current_time - timestamp < 60
            ]
            
            # More lenient IP-based limit (2x user limit)
            if len(self.ip_rate_limits[user_ip]) >= rate_limit * 2:
                return False
            
            self.ip_rate_limits[user_ip].append(current_time)
        
        self.user_rate_limits[user_id].append(current_time)
        return True
    
    async def send_log_file_to_channel(self, channel: discord.TextChannel, content: str, filename: str):
        """
        Send log content as a file to a specific channel.
        """
        if not content.strip():
            return
        
        # Create file-like object
        file_obj = StringIO(content)
        discord_file = discord.File(file_obj, filename=filename)
        
        try:
            # Add file info embed
            lines_count = content.count('\n')
            file_size = len(content.encode('utf-8'))
            
            embed = discord.Embed(
                title="📄 Log File",
                description=f"**Filename:** `{filename}`\n**Lines:** {lines_count:,}\n**Size:** {file_size/1024:.1f} KB",
                color=discord.Color.green()
            )
            
            await channel.send(embed=embed, file=discord_file)
            
        except discord.HTTPException as e:
            logging.error(f"Failed to send log file to channel {channel.id}: {e}")
        except Exception as e:
            logging.error(f"Unexpected error in send_log_file_to_channel: {e}")
    
    async def send_log_file(self, ctx, content: str, filename: str):
        """
        Send log content as a file to the specified channel.
        Enhanced with better error handling and progress indication.
        """
        if not content.strip():
            embed = discord.Embed(
                title="❌ No Results",
                description="No log entries found matching your criteria.",
                color=discord.Color.orange()
            )
            await ctx.send(embed=embed)
            return

        # Check file size
        content_bytes = content.encode('utf-8')
        max_size = await self.config.guild(ctx.guild).max_file_size()
        
        if len(content_bytes) > max_size:
            # Smart truncation: keep beginning and end
            half_size = max_size // 4
            content_lines = content.split('\n')
            total_lines = len(content_lines)
            
            # Calculate how many lines to keep from start and end
            start_content = '\n'.join(content_lines[:total_lines//4])
            end_content = '\n'.join(content_lines[-total_lines//4:])
            
            content = f"{start_content}\n\n[... {total_lines//2} LINES TRUNCATED - File too large for Discord ...]\n\n{end_content}"
            
            embed = discord.Embed(
                title="⚠️ File Truncated",
                description=f"Log file was truncated due to size limits ({len(content_bytes)/1024/1024:.1f}MB > {max_size/1024/1024:.1f}MB)",
                color=discord.Color.yellow()
            )
            await ctx.send(embed=embed)

        # Create file-like object
        file_obj = StringIO(content)
        discord_file = discord.File(file_obj, filename=filename)
        
        try:
            # Add file info embed
            lines_count = content.count('\n')
            file_size = len(content.encode('utf-8'))
            
            embed = discord.Embed(
                title="📄 Log File",
                description=f"**Filename:** `{filename}`\n**Lines:** {lines_count:,}\n**Size:** {file_size/1024:.1f} KB",
                color=discord.Color.green()
            )
            
            await ctx.send(embed=embed, file=discord_file)
            
        except discord.HTTPException as e:
            error_embed = discord.Embed(
                title="❌ Upload Failed",
                description=f"Failed to send log file: {str(e)}",
                color=discord.Color.red()
            )
            await ctx.send(embed=error_embed)
        except Exception as e:
            logging.error(f"Unexpected error in send_log_file: {e}")
            await ctx.send(f"❌ Unexpected error occurred: {str(e)}")

    def filter_logs_combined(self, log_content: str, cog_name: str = None, hours: int = None, minutes: int = None, level: str = None) -> str:
        """
        Apply multiple filters to log content in sequence.
        """
        filtered_content = log_content
        
        # Apply time filter first (most restrictive)
        if hours or minutes:
            filtered_content = self.filter_logs_by_time(filtered_content, hours, minutes)
        
        # Apply cog filter
        if cog_name:
            filtered_content = self.filter_logs_by_cog(filtered_content, cog_name)
        
        # Apply level filter
        if level:
            filtered_content = self.filter_logs_by_level(filtered_content, level)
        
        return filtered_content
    
    async def _send_combined_logs(self, ctx, cog_name: str = None, hours: int = None, minutes: int = None, level: str = None):
        """
        Helper method to send logs with combined filters.
        """
        # Check rate limit
        if not await self._check_rate_limit(ctx):
            embed = discord.Embed(
                title="⏰ Rate Limited",
                description="You're sending commands too quickly. Please wait a moment.",
                color=discord.Color.red()
            )
            await ctx.send(embed=embed)
            return
        
        log_file_path = self.get_log_file_path()
        if not log_file_path:
            embed = discord.Embed(
                title="❌ Log File Not Found",
                description="Could not locate the Red-DiscordBot log file.",
                color=discord.Color.red()
            )
            await ctx.send(embed=embed)
            return
        
        try:
            with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                log_content = f.read()
        except Exception as e:
            embed = discord.Embed(
                title="❌ Error Reading Log",
                description=f"Failed to read log file: {str(e)}",
                color=discord.Color.red()
            )
            await ctx.send(embed=embed)
            return
        
        # Apply combined filters
        filtered_content = self.filter_logs_combined(log_content, cog_name, hours, minutes, level)
        
        # Generate descriptive filename
        filename_parts = ["red"]
        if cog_name:
            filename_parts.append(f"cog-{cog_name}")
        if hours:
            filename_parts.append(f"{hours}h")
        elif minutes:
            filename_parts.append(f"{minutes}m")
        if level:
            filename_parts.append(level.lower())
        
        filename = f"{'_'.join(filename_parts)}_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        await self.send_log_file(ctx, filtered_content, filename)
    
    @commands.group(name="debuglogs", aliases=["dlogs"])
    @checks.mod_or_permissions(manage_guild=True)
    async def debug_logs(self, ctx):
        """
        Debug logs management commands.
        
        Allows moderators and administrators to retrieve and manage Red-DiscordBot logs.
        """
        if ctx.invoked_subcommand is None:
            embed = discord.Embed(
                title="🔍 Debug Logs Commands",
                description="Advanced log retrieval and analysis tools",
                color=discord.Color.blue()
            )
            embed.add_field(
                name="📄 Basic Commands",
                value="`full` - Complete log file\n`recent` - Last hour of logs\n`cog <name>` - Cog-specific logs",
                inline=False
            )
            embed.add_field(
                name="🎯 Filtered Commands",
                value="`errors` - Error messages only\n`warnings` - Warning messages only\n`search <term>` - Search for specific text",
                inline=False
            )
            embed.add_field(
                name="⏰ Time-based Commands",
                value="`5m`, `10m`, `30m`, `1h`, `2h` - Quick time filters\n`minutes <N>` - Custom minute filter",
                inline=False
            )
            embed.add_field(
                name="🔗 Combined Commands",
                value="`cogtime <cog> <time>` - Cog + time filter\n`cogerrors <cog>` - Cog errors only\n`cogwarnings <cog>` - Cog warnings only",
                inline=False
            )
            embed.add_field(
                name="🔄 Flexible Chaining",
                value="`chain <filters...>` - Chain multiple filters\n`<cog> <level> <time> [count]` - Direct chaining\nExample: `emailnews errors recent 5`\nSupports: cog names, errors, warnings, time specs, recent",
                inline=False
            )
            embed.add_field(
                name="⚙️ Utility Commands",
                value="`info` - Log file information\n`tail <lines>` - Last N lines\n`config` - Configuration settings",
                inline=False
            )
            embed.add_field(
                name="🐧 Ubuntu VPS Commands",
                value="`journal [lines] [service]` - systemd journal logs\n`journal_time <time> [service]` - Journal by time\n`service_status [service]` - Service status\n`system_resources` - System monitoring\n`permissions` - Check VPS permissions",
                inline=False
            )
            await ctx.send(embed=embed)

    @debug_logs.command(name="full")
    async def logs_full(self, ctx, channel: Optional[discord.TextChannel] = None):
        """
        Send the complete log file to the specified channel.
        
        If no channel is specified, sends to the current channel.
        """
        target_channel = channel or ctx.channel
        log_path = self.get_log_file_path()
        
        if not log_path:
            await ctx.send("❌ Could not locate the Red-DiscordBot log file.")
            return
        
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"red_full_logs_{timestamp}.txt"
            
            await self.send_log_file(ctx, content, filename)
            
            if target_channel != ctx.channel:
                await ctx.send(f"✅ Full logs sent to {target_channel.mention}")
                
        except Exception as e:
            await ctx.send(f"❌ Error reading log file: {e}")

    @debug_logs.command(name="recent")
    async def logs_recent(self, ctx, hours: int = 1, channel: Optional[discord.TextChannel] = None):
        """
        Send recent log entries from the past N hours.
        
        Default is 1 hour. Maximum is 24 hours.
        """
        if hours < 1 or hours > 24:
            await ctx.send("❌ Hours must be between 1 and 24.")
            return
            
        target_channel = channel or ctx.channel
        log_path = self.get_log_file_path()
        
        if not log_path:
            await ctx.send("❌ Could not locate the Red-DiscordBot log file.")
            return
        
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            filtered_content = self.filter_logs_by_time(content, hours=hours)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"red_recent_{hours}h_logs_{timestamp}.txt"
            
            await self.send_log_file(ctx, filtered_content, filename)
            
            if target_channel != ctx.channel:
                await ctx.send(f"✅ Recent logs ({hours}h) sent to {target_channel.mention}")
                
        except Exception as e:
            await ctx.send(f"❌ Error reading log file: {e}")

    @debug_logs.command(name="last5m", aliases=["5m", "5min"])
    async def logs_last_5_minutes(self, ctx, channel: Optional[discord.TextChannel] = None):
        """
        Send log entries from the last 5 minutes.
        """
        await self._send_time_filtered_logs(ctx, minutes=5, channel=channel)

    @debug_logs.command(name="last10m", aliases=["10m", "10min"])
    async def logs_last_10_minutes(self, ctx, channel: Optional[discord.TextChannel] = None):
        """
        Send log entries from the last 10 minutes.
        """
        await self._send_time_filtered_logs(ctx, minutes=10, channel=channel)

    @debug_logs.command(name="last15m", aliases=["15m", "15min"])
    async def logs_last_15_minutes(self, ctx, channel: Optional[discord.TextChannel] = None):
        """
        Send log entries from the last 15 minutes.
        """
        await self._send_time_filtered_logs(ctx, minutes=15, channel=channel)

    @debug_logs.command(name="last30m", aliases=["30m", "30min"])
    async def logs_last_30_minutes(self, ctx, channel: Optional[discord.TextChannel] = None):
        """
        Send log entries from the last 30 minutes.
        """
        await self._send_time_filtered_logs(ctx, minutes=30, channel=channel)

    @debug_logs.command(name="last1h", aliases=["1h", "1hour"])
    async def logs_last_1_hour(self, ctx, channel: Optional[discord.TextChannel] = None):
        """
        Send log entries from the last 1 hour.
        """
        await self._send_time_filtered_logs(ctx, hours=1, channel=channel)

    @debug_logs.command(name="last2h", aliases=["2h", "2hours"])
    async def logs_last_2_hours(self, ctx, channel: Optional[discord.TextChannel] = None):
        """
        Send log entries from the last 2 hours.
        """
        await self._send_time_filtered_logs(ctx, hours=2, channel=channel)

    @debug_logs.command(name="last6h", aliases=["6h", "6hours"])
    async def logs_last_6_hours(self, ctx, channel: Optional[discord.TextChannel] = None):
        """
        Send log entries from the last 6 hours.
        """
        await self._send_time_filtered_logs(ctx, hours=6, channel=channel)

    @debug_logs.command(name="last12h", aliases=["12h", "12hours"])
    async def logs_last_12_hours(self, ctx, channel: Optional[discord.TextChannel] = None):
        """
        Send log entries from the last 12 hours.
        """
        await self._send_time_filtered_logs(ctx, hours=12, channel=channel)

    @debug_logs.command(name="minutes", aliases=["mins"])
    async def logs_minutes(self, ctx, minutes: int, channel: Optional[discord.TextChannel] = None):
        """
        Send log entries from the last N minutes.
        
        Maximum is 1440 minutes (24 hours).
        """
        if minutes < 1 or minutes > 1440:
            await ctx.send("❌ Minutes must be between 1 and 1440 (24 hours).")
            return
        
        await self._send_time_filtered_logs(ctx, minutes=minutes, channel=channel)
    
    # Combined filtering commands
    @debug_logs.command(name="cogtime", aliases=["ct"])
    async def logs_cog_time(self, ctx, cog_name: str, time_spec: str):
        """
        Get logs for a specific cog within a time range.
        
        Parameters:
        - cog_name: Name of the cog to filter by
        - time_spec: Time specification (e.g., '5m', '1h', '30m')
        
        Examples:
        - `!debuglogs cogtime mycog 5m` - Get mycog logs from last 5 minutes
        - `!debuglogs cogtime admin 1h` - Get admin cog logs from last hour
        """
        # Parse time specification
        hours, minutes = self._parse_time_spec(time_spec)
        if hours is None and minutes is None:
            embed = discord.Embed(
                title="❌ Invalid Time Format",
                description="Please use format like '5m', '1h', '30m', '2h'",
                color=discord.Color.red()
            )
            await ctx.send(embed=embed)
            return
        
        await self._send_combined_logs(ctx, cog_name=cog_name, hours=hours, minutes=minutes)
    
    @debug_logs.command(name="cogerrors", aliases=["ce"])
    async def logs_cog_errors(self, ctx, cog_name: str):
        """
        Get error logs for a specific cog.
        
        Parameters:
        - cog_name: Name of the cog to filter by
        """
        await self._send_combined_logs(ctx, cog_name=cog_name, level="ERROR")
    
    @debug_logs.command(name="cogwarnings", aliases=["cw"])
    async def logs_cog_warnings(self, ctx, cog_name: str):
        """
        Get warning logs for a specific cog.
        
        Parameters:
        - cog_name: Name of the cog to filter by
        """
        await self._send_combined_logs(ctx, cog_name=cog_name, level="WARNING")
    
    @debug_logs.command(name="timeerrors", aliases=["te"])
    async def logs_time_errors(self, ctx, time_spec: str):
        """
        Get error logs within a specific time range.
        
        Parameters:
        - time_spec: Time specification (e.g., '5m', '1h', '30m')
        """
        hours, minutes = self._parse_time_spec(time_spec)
        if hours is None and minutes is None:
            embed = discord.Embed(
                title="❌ Invalid Time Format",
                description="Please use format like '5m', '1h', '30m', '2h'",
                color=discord.Color.red()
            )
            await ctx.send(embed=embed)
            return
        
        await self._send_combined_logs(ctx, hours=hours, minutes=minutes, level="ERROR")
    
    @debug_logs.command(name="timewarnings", aliases=["tw"])
    async def logs_time_warnings(self, ctx, time_spec: str):
        """
        Get warning logs within a specific time range.
        
        Parameters:
        - time_spec: Time specification (e.g., '5m', '1h', '30m')
        """
        hours, minutes = self._parse_time_spec(time_spec)
        if hours is None and minutes is None:
            embed = discord.Embed(
                title="❌ Invalid Time Format",
                description="Please use format like '5m', '1h', '30m', '2h'",
                color=discord.Color.red()
            )
            await ctx.send(embed=embed)
            return
        
        await self._send_combined_logs(ctx, hours=hours, minutes=minutes, level="WARNING")
    
    @debug_logs.command(name="chain")
    async def logs_chain(self, ctx, *filters):
        """
        Chain multiple filters for flexible log retrieval.
        
        Supports combining:
        - Cog names (e.g., 'emailnews', 'admin')
        - Log levels ('errors', 'warnings')
        - Time specifications ('5m', '1h', '30m')
        - Recent with count ('recent', followed by number)
        
        Examples:
        - `!debuglogs chain emailnews errors recent 5`
        - `!debuglogs chain admin warnings 1h`
        - `!debuglogs chain errors 30m`
        """
        await self._handle_flexible_command(ctx, list(filters))
    
    async def _handle_flexible_command(self, ctx, filters: List[str]):
        """
        Handle flexible command parsing for both chain and direct commands.
        """
        if not filters:
            embed = discord.Embed(
                title="❌ No Filters Provided",
                description="Please provide at least one filter.\n\nExample: `!debuglogs chain emailnews errors recent 5`",
                color=discord.Color.red()
            )
            await ctx.send(embed=embed)
            return
        
        # Parse the filter chain
        parsed_filters = self._parse_filter_chain(filters)
        
        if not parsed_filters['valid']:
            embed = discord.Embed(
                title="❌ Invalid Filter Chain",
                description=f"Error: {parsed_filters['error']}\n\nSupported filters: cog names, 'errors', 'warnings', time specs (5m, 1h), 'recent' + number",
                color=discord.Color.red()
            )
            await ctx.send(embed=embed)
            return
        
        # Apply the parsed filters
        await self._send_chained_logs(ctx, parsed_filters)
    
    @debug_logs.command(name="flexible", hidden=True)
    async def logs_flexible(self, ctx, cog_or_filter: str, *additional_filters):
        """
        Hidden flexible command for direct filter chaining.
        
        This allows commands like: !debuglogs emailnews errors recent 5
        """
        all_filters = [cog_or_filter] + list(additional_filters)
        await self._handle_flexible_command(ctx, all_filters)
    
    @commands.Cog.listener()
    async def on_command_error(self, ctx, error):
        """
        Enhanced error handler for flexible command parsing.
        """
        # Only handle CommandNotFound errors for debuglogs commands
        if (isinstance(error, commands.CommandNotFound) and 
            (ctx.message.content.startswith(f"{ctx.prefix}debuglogs ") or 
             ctx.message.content.startswith(f"{ctx.prefix}dlogs "))):
            
            # Extract the full command after debuglogs/dlogs
            content = ctx.message.content
            if "debuglogs " in content:
                args_part = content.split("debuglogs ", 1)[1].strip()
            elif "dlogs " in content:
                args_part = content.split("dlogs ", 1)[1].strip()
            else:
                return
            
            if args_part:
                # Split into individual arguments
                args = args_part.split()
                
                # Try to parse as a flexible command
                parsed_filters = self._parse_filter_chain(args)
                if parsed_filters['valid'] and (parsed_filters['cog_name'] or 
                                               parsed_filters['level'] or 
                                               parsed_filters['hours'] or 
                                               parsed_filters['minutes'] or 
                                               parsed_filters['recent_count'] or 
                                               parsed_filters['search_term']):
                    await self._send_chained_logs(ctx, parsed_filters)
                    return
            
            # If not a valid flexible command, show helpful error
            embed = discord.Embed(
                title="❓ Command Not Found",
                description=f"Unknown command: `{args_part if args_part else 'none'}`\n\n" +
                           "💡 **Did you mean to use flexible chaining?**\n" +
                           "Try: `!debuglogs chain {your filters}`\n" +
                           "Or use: `!debuglogs` to see all available commands",
                color=discord.Color.orange()
            )
            await ctx.send(embed=embed)
            return
    
    def _parse_filter_chain(self, filters: List[str]) -> Dict[str, Any]:
        """
        Parse a chain of filters into structured data.
        
        Returns:
        - Dictionary with parsed filter information
        """
        result = {
            'valid': True,
            'error': None,
            'cog_name': None,
            'level': None,
            'hours': None,
            'minutes': None,
            'recent_count': None,
            'search_term': None
        }
        
        i = 0
        while i < len(filters):
            filter_item = filters[i].lower()
            
            # Check for log levels
            if filter_item in ['errors', 'error']:
                if result['level']:
                    result['valid'] = False
                    result['error'] = "Multiple log levels specified"
                    return result
                result['level'] = 'ERROR'
            elif filter_item in ['warnings', 'warning', 'warns', 'warn']:
                if result['level']:
                    result['valid'] = False
                    result['error'] = "Multiple log levels specified"
                    return result
                result['level'] = 'WARNING'
            
            # Check for time specifications
            elif self._is_time_spec(filter_item):
                hours, minutes = self._parse_time_spec(filter_item)
                if hours or minutes:
                    if result['hours'] or result['minutes']:
                        result['valid'] = False
                        result['error'] = "Multiple time specifications"
                        return result
                    result['hours'] = hours
                    result['minutes'] = minutes
            
            # Check for recent with count
            elif filter_item == 'recent':
                if i + 1 < len(filters) and filters[i + 1].isdigit():
                    result['recent_count'] = int(filters[i + 1])
                    i += 1  # Skip the next item as it's the count
                else:
                    result['recent_count'] = 1  # Default to 1 hour if no count
            
            # Check for search terms (if starts with quotes or contains spaces)
            elif filter_item.startswith('"') or ' ' in ' '.join(filters[i:]):
                # Handle quoted search terms
                if filter_item.startswith('"'):
                    search_parts = [filter_item[1:]]  # Remove opening quote
                    i += 1
                    while i < len(filters) and not filters[i].endswith('"'):
                        search_parts.append(filters[i])
                        i += 1
                    if i < len(filters) and filters[i].endswith('"'):
                        search_parts.append(filters[i][:-1])  # Remove closing quote
                    result['search_term'] = ' '.join(search_parts)
                else:
                    result['search_term'] = filter_item
            
            # Otherwise, assume it's a cog name
            else:
                if result['cog_name']:
                    result['valid'] = False
                    result['error'] = "Multiple cog names specified"
                    return result
                result['cog_name'] = filters[i]  # Keep original case for cog names
            
            i += 1
        
        return result
    
    def _is_time_spec(self, text: str) -> bool:
        """
        Check if a string is a valid time specification.
        """
        text = text.lower().strip()
        if text.endswith('m') or text.endswith('h'):
            try:
                int(text[:-1])
                return True
            except ValueError:
                return False
        return False
    
    async def _send_chained_logs(self, ctx, parsed_filters: Dict[str, Any]):
        """
        Send logs based on chained filters.
        """
        # Check rate limit
        if not await self._check_rate_limit(ctx):
            embed = discord.Embed(
                title="⏰ Rate Limited",
                description="You're sending commands too quickly. Please wait a moment.",
                color=discord.Color.red()
            )
            await ctx.send(embed=embed)
            return
        
        # Get log content
        log_path = self.get_log_file_path()
        if not log_path:
            embed = discord.Embed(
                title="❌ Log File Not Found",
                description="Could not locate the Red-DiscordBot log file.",
                color=discord.Color.red()
            )
            await ctx.send(embed=embed)
            return
        
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            embed = discord.Embed(
                title="❌ Error Reading Log",
                description=f"Failed to read log file: {str(e)}",
                color=discord.Color.red()
            )
            await ctx.send(embed=embed)
            return
        
        # Apply filters in sequence
        filtered_content = content
        
        # Apply time filter first (most restrictive)
        if parsed_filters['hours'] or parsed_filters['minutes']:
            filtered_content = self.filter_logs_by_time(
                filtered_content, 
                parsed_filters['hours'], 
                parsed_filters['minutes']
            )
        elif parsed_filters['recent_count']:
            # Convert recent count to hours (assuming it's hours)
            filtered_content = self.filter_logs_by_time(
                filtered_content, 
                hours=parsed_filters['recent_count']
            )
        
        # Apply cog filter
        if parsed_filters['cog_name']:
            filtered_content = self.filter_logs_by_cog(filtered_content, parsed_filters['cog_name'])
        
        # Apply level filter
        if parsed_filters['level']:
            filtered_content = self.filter_logs_by_level(filtered_content, parsed_filters['level'])
        
        # Apply search filter
        if parsed_filters['search_term']:
            filtered_content = self.filter_logs_by_search(filtered_content, parsed_filters['search_term'])
        
        # Generate descriptive filename
        filename_parts = ["red"]
        if parsed_filters['cog_name']:
            filename_parts.append(f"cog-{parsed_filters['cog_name']}")
        if parsed_filters['level']:
            filename_parts.append(parsed_filters['level'].lower())
        if parsed_filters['hours']:
            filename_parts.append(f"{parsed_filters['hours']}h")
        elif parsed_filters['minutes']:
            filename_parts.append(f"{parsed_filters['minutes']}m")
        elif parsed_filters['recent_count']:
            filename_parts.append(f"recent{parsed_filters['recent_count']}")
        if parsed_filters['search_term']:
            # Sanitize search term for filename
            safe_term = re.sub(r'[^\w\-_]', '_', parsed_filters['search_term'])[:20]
            filename_parts.append(f"search-{safe_term}")
        
        filename = f"{'_'.join(filename_parts)}_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        # Check if we have any results
        if not filtered_content.strip():
            embed = discord.Embed(
                title="📭 No Results Found",
                description="No log entries match the specified filters.",
                color=discord.Color.orange()
            )
            await ctx.send(embed=embed)
            return
        
        await self.send_log_file(ctx, filtered_content, filename)
        
        # Send summary of applied filters
        filter_summary = []
        if parsed_filters['cog_name']:
            filter_summary.append(f"Cog: {parsed_filters['cog_name']}")
        if parsed_filters['level']:
            filter_summary.append(f"Level: {parsed_filters['level']}")
        if parsed_filters['hours']:
            filter_summary.append(f"Time: {parsed_filters['hours']}h")
        elif parsed_filters['minutes']:
            filter_summary.append(f"Time: {parsed_filters['minutes']}m")
        elif parsed_filters['recent_count']:
            filter_summary.append(f"Recent: {parsed_filters['recent_count']}h")
        if parsed_filters['search_term']:
            filter_summary.append(f"Search: '{parsed_filters['search_term']}'")
        
        if filter_summary:
            embed = discord.Embed(
                title="✅ Filters Applied",
                description=" | ".join(filter_summary),
                color=discord.Color.green()
            )
            await ctx.send(embed=embed)
    
    def filter_logs_by_search(self, content: str, search_term: str) -> str:
        """
        Filter logs by search term with context.
        """
        lines = content.split('\n')
        matching_lines = []
        
        for i, line in enumerate(lines):
            if search_term.lower() in line.lower():
                # Include context (2 lines before and after)
                start = max(0, i - 2)
                end = min(len(lines), i + 3)
                context_lines = lines[start:end]
                matching_lines.extend(context_lines)
                matching_lines.append("---")  # Separator
        
        return '\n'.join(matching_lines)
    
    def _parse_time_spec(self, time_spec: str) -> Tuple[Optional[int], Optional[int]]:
        """
        Parse time specification string into hours and minutes.
        
        Returns:
        - Tuple of (hours, minutes) where one will be None
        """
        time_spec = time_spec.lower().strip()
        
        # Match patterns like '5m', '1h', '30m', '2h'
        if time_spec.endswith('m'):
            try:
                minutes = int(time_spec[:-1])
                return None, minutes
            except ValueError:
                return None, None
        elif time_spec.endswith('h'):
            try:
                hours = int(time_spec[:-1])
                return hours, None
            except ValueError:
                return None, None
        
        return None, None

    async def _send_time_filtered_logs(self, ctx, hours: int = None, minutes: int = None, channel: Optional[discord.TextChannel] = None):
        """
        Helper method to send time-filtered logs.
        Enhanced with caching and audit logging.
        """
        # Log command usage for audit
        filters = {"hours": hours, "minutes": minutes, "channel": channel.id if channel else None}
        await self._log_command_usage(ctx, "time_filtered_logs", filters)
        
        # Check rate limit
        if not await self._check_rate_limit(ctx):
            embed = discord.Embed(
                title="⏰ Rate Limited",
                description="You're sending commands too quickly. Please wait a moment.",
                color=discord.Color.red()
            )
            await ctx.send(embed=embed)
            return
        
        # Generate cache key
        cache_key = f"time_{hours or 0}h_{minutes or 0}m_{ctx.guild.id}"
        
        # Try to get cached content first
        log_content = await self._get_cached_log_content(cache_key)
        
        if log_content is None:
            # Cache miss - read from file
            log_file_path = self.get_log_file_path()
            if not log_file_path:
                embed = discord.Embed(
                    title="❌ Log File Not Found",
                    description="Could not locate the Red-DiscordBot log file.",
                    color=discord.Color.red()
                )
                await ctx.send(embed=embed)
                return
            
            try:
                with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    raw_log_content = f.read()
            except Exception as e:
                embed = discord.Embed(
                    title="❌ Error Reading Log",
                    description=f"Failed to read log file: {str(e)}",
                    color=discord.Color.red()
                )
                await ctx.send(embed=embed)
                return
            
            # Filter logs by time
            log_content = self.filter_logs_by_time(raw_log_content, hours, minutes)
            
            # Cache the filtered content
            await self._cache_log_content(cache_key, log_content, ctx.guild.id)
        
        # Generate filename with timestamp
        if minutes:
            time_desc = f"{minutes}m"
        elif hours:
            time_desc = f"{hours}h"
        else:
            time_desc = "1h"
        
        filename = f"red_logs_last_{time_desc}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        # Send to specified channel or current channel
        target_channel = channel or ctx.channel
        
        if target_channel != ctx.channel:
            # Send to different channel, notify in current channel
            await self.send_log_file_to_channel(target_channel, log_content, filename)
            embed = discord.Embed(
                title="✅ Logs Sent",
                description=f"Logs sent to {target_channel.mention}",
                color=discord.Color.green()
            )
            await ctx.send(embed=embed)
        else:
            await self.send_log_file(ctx, log_content, filename)

    @debug_logs.command(name="cog")
    async def logs_cog(self, ctx, cog_name: str, channel: Optional[discord.TextChannel] = None):
        """
        Send log entries related to a specific cog.
        """
        target_channel = channel or ctx.channel
        log_path = self.get_log_file_path()
        
        if not log_path:
            await ctx.send("❌ Could not locate the Red-DiscordBot log file.")
            return
        
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            filtered_content = self.filter_logs_by_cog(content, cog_name)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"red_{cog_name}_logs_{timestamp}.txt"
            
            await self.send_log_file(ctx, filtered_content, filename)
            
            if target_channel != ctx.channel:
                await ctx.send(f"✅ {cog_name} logs sent to {target_channel.mention}")
                
        except Exception as e:
            await ctx.send(f"❌ Error reading log file: {e}")

    @debug_logs.command(name="errors")
    async def logs_errors(self, ctx, channel: Optional[discord.TextChannel] = None):
        """
        Send only error log entries.
        """
        target_channel = channel or ctx.channel
        log_path = self.get_log_file_path()
        
        if not log_path:
            await ctx.send("❌ Could not locate the Red-DiscordBot log file.")
            return
        
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            filtered_content = self.filter_logs_by_level(content, "ERROR")
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"red_errors_{timestamp}.txt"
            
            await self.send_log_file(ctx, filtered_content, filename)
            
            if target_channel != ctx.channel:
                await ctx.send(f"✅ Error logs sent to {target_channel.mention}")
                
        except Exception as e:
            await ctx.send(f"❌ Error reading log file: {e}")

    @debug_logs.command(name="warnings")
    async def logs_warnings(self, ctx, channel: Optional[discord.TextChannel] = None):
        """
        Send only warning log entries.
        """
        target_channel = channel or ctx.channel
        log_path = self.get_log_file_path()
        
        if not log_path:
            await ctx.send("❌ Could not locate the Red-DiscordBot log file.")
            return
        
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            filtered_content = self.filter_logs_by_level(content, "WARNING")
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"red_warnings_{timestamp}.txt"
            
            await self.send_log_file(ctx, filtered_content, filename)
            
            if target_channel != ctx.channel:
                await ctx.send(f"✅ Warning logs sent to {target_channel.mention}")
                
        except Exception as e:
            await ctx.send(f"❌ Error reading log file: {e}")

    @debug_logs.command(name="search")
    async def logs_search(self, ctx, search_term: str, channel: Optional[discord.TextChannel] = None):
        """
        Search for specific terms in the log file.
        """
        target_channel = channel or ctx.channel
        log_path = self.get_log_file_path()
        
        if not log_path:
            await ctx.send("❌ Could not locate the Red-DiscordBot log file.")
            return
        
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # Search for lines containing the search term
            matching_lines = []
            for i, line in enumerate(lines):
                if search_term.lower() in line.lower():
                    # Include some context (previous and next lines)
                    start = max(0, i-2)
                    end = min(len(lines), i+3)
                    context_lines = lines[start:end]
                    matching_lines.extend(context_lines)
                    matching_lines.append("---\n")  # Separator
            
            if not matching_lines:
                await ctx.send(f"❌ No log entries found containing '{search_term}'.")
                return
            
            content = ''.join(matching_lines)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"red_search_{search_term}_{timestamp}.txt"
            
            await self.send_log_file(ctx, content, filename)
            
            if target_channel != ctx.channel:
                await ctx.send(f"✅ Search results for '{search_term}' sent to {target_channel.mention}")
                
        except Exception as e:
            await ctx.send(f"❌ Error searching log file: {e}")

    @debug_logs.command(name="info")
    async def logs_info(self, ctx):
        """
        Display information about the current log file.
        """
        log_path = self.get_log_file_path()
        
        if not log_path:
            await ctx.send("❌ Could not locate the Red-DiscordBot log file.")
            return
        
        try:
            stat = os.stat(log_path)
            size_mb = stat.st_size / (1024 * 1024)
            modified_time = datetime.fromtimestamp(stat.st_mtime)
            
            # Count lines
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                line_count = sum(1 for _ in f)
            
            embed = discord.Embed(
                title="📋 Log File Information",
                color=discord.Color.blue()
            )
            embed.add_field(name="Path", value=f"`{log_path}`", inline=False)
            embed.add_field(name="Size", value=f"{size_mb:.2f} MB", inline=True)
            embed.add_field(name="Lines", value=f"{line_count:,}", inline=True)
            embed.add_field(name="Last Modified", value=modified_time.strftime("%Y-%m-%d %H:%M:%S"), inline=True)
            
            await ctx.send(embed=embed)
            
        except Exception as e:
            await ctx.send(f"❌ Error getting log file info: {e}")

    @debug_logs.command(name="tail")
    async def logs_tail(self, ctx, lines: int = 50):
        """
        Show the last N lines of the log file (like tail command).
        
        Default is 50 lines. Maximum is 200 lines.
        """
        if lines < 1 or lines > 200:
            await ctx.send("❌ Lines must be between 1 and 200.")
            return
            
        log_path = self.get_log_file_path()
        
        if not log_path:
            await ctx.send("❌ Could not locate the Red-DiscordBot log file.")
            return
        
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                all_lines = f.readlines()
            
            # Get last N lines
            tail_lines = all_lines[-lines:]
            content = ''.join(tail_lines)
            
            # If content is short enough, send as code block
            if len(content) < 1900:
                for page in pagify(content, delims=["\n"], page_length=1900):
                    await ctx.send(box(page, lang="log"))
            else:
                # Send as file if too long
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"red_tail_{lines}_{timestamp}.txt"
                await self.send_log_file(ctx, content, filename)
                
        except Exception as e:
            await ctx.send(f"❌ Error reading log file: {e}")

    # Ubuntu/VPS Specific Commands
    @debug_logs.command(name="journal")
    async def logs_journal(self, ctx, lines: int = 100, service: str = None):
        """
        Get logs from systemd journal (Ubuntu VPS).
        
        Args:
            lines: Number of lines to retrieve (default: 100, max: 10000)
            service: Specific service name (default: configured service)
        """
        if not self.journal_available:
            embed = discord.Embed(
                title="❌ Journal Not Available",
                description="systemd journal is not available or accessible. This feature requires:\n• Ubuntu/Linux with systemd\n• Bot user in `systemd-journal` group\n• `journalctl` command available",
                color=discord.Color.red()
            )
            await ctx.send(embed=embed)
            return
        
        # Validate lines parameter
        max_lines = await self.config.guild(ctx.guild).max_journal_lines()
        if lines < 1 or lines > max_lines:
            await ctx.send(f"❌ Lines must be between 1 and {max_lines}.")
            return
        
        # Check rate limit
        if not await self._check_rate_limit(ctx):
            embed = discord.Embed(
                title="⏰ Rate Limited",
                description="You're sending commands too quickly. Please wait a moment.",
                color=discord.Color.red()
            )
            await ctx.send(embed=embed)
            return
        
        # Use configured service name if not specified
        if not service:
            service = await self.config.guild(ctx.guild).service_name()
        
        # Get journal logs
        journal_content = await self._get_journal_logs(service, lines)
        
        if not journal_content:
            embed = discord.Embed(
                title="❌ No Journal Logs",
                description=f"No journal logs found for service: {service}",
                color=discord.Color.orange()
            )
            await ctx.send(embed=embed)
            return
        
        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"journal_{service}_{lines}lines_{timestamp}.txt"
        
        await self.send_log_file(ctx, journal_content, filename)
        
        # Log command usage
        await self._log_command_usage(ctx, "journal", {"lines": lines, "service": service})
    
    @debug_logs.command(name="journal_time")
    async def logs_journal_time(self, ctx, time_spec: str, service: str = None):
        """
        Get journal logs for a specific time period (Ubuntu VPS).
        
        Args:
            time_spec: Time specification (e.g., '5m', '1h', '2d')
            service: Specific service name (default: configured service)
        """
        if not self.journal_available:
            embed = discord.Embed(
                title="❌ Journal Not Available",
                description="systemd journal is not available. See `!debuglogs journal` for requirements.",
                color=discord.Color.red()
            )
            await ctx.send(embed=embed)
            return
        
        # Parse time specification
        try:
            minutes = self._parse_time_spec(time_spec)
            if minutes is None:
                await ctx.send("❌ Invalid time format. Use formats like: 5m, 1h, 2d")
                return
        except ValueError as e:
            await ctx.send(f"❌ {str(e)}")
            return
        
        # Check rate limit
        if not await self._check_rate_limit(ctx):
            embed = discord.Embed(
                title="⏰ Rate Limited",
                description="You're sending commands too quickly. Please wait a moment.",
                color=discord.Color.red()
            )
            await ctx.send(embed=embed)
            return
        
        # Use configured service name if not specified
        if not service:
            service = await self.config.guild(ctx.guild).service_name()
        
        # Calculate since time
        since_time = datetime.now() - timedelta(minutes=minutes)
        since_str = since_time.strftime("%Y-%m-%d %H:%M:%S")
        
        # Get journal logs
        journal_content = await self._get_journal_logs(service, since=since_str)
        
        if not journal_content:
            embed = discord.Embed(
                title="❌ No Journal Logs",
                description=f"No journal logs found for service: {service} in the last {time_spec}",
                color=discord.Color.orange()
            )
            await ctx.send(embed=embed)
            return
        
        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"journal_{service}_{time_spec}_{timestamp}.txt"
        
        await self.send_log_file(ctx, journal_content, filename)
        
        # Log command usage
        await self._log_command_usage(ctx, "journal_time", {"time_spec": time_spec, "service": service})
    
    @debug_logs.command(name="service_status")
    async def logs_service_status(self, ctx, service: str = None):
        """
        Show systemd service status (Ubuntu VPS).
        
        Args:
            service: Service name (default: configured service)
        """
        # Use configured service name if not specified
        if not service:
            service = await self.config.guild(ctx.guild).service_name()
        
        # Get service status
        status_info = await self._get_service_status(service)
        
        if 'error' in status_info:
            embed = discord.Embed(
                title="❌ Service Status Error",
                description=f"Failed to get status for service: {service}\n{status_info['error']}",
                color=discord.Color.red()
            )
            await ctx.send(embed=embed)
            return
        
        # Create status embed
        status = status_info.get('status', 'unknown')
        color = discord.Color.green() if status == 'active' else discord.Color.red()
        
        embed = discord.Embed(
            title=f"🔧 Service Status: {service}",
            color=color
        )
        
        embed.add_field(name="Status", value=status.title(), inline=True)
        embed.add_field(name="Active State", value=status_info.get('active_state', 'unknown'), inline=True)
        embed.add_field(name="Sub State", value=status_info.get('sub_state', 'unknown'), inline=True)
        embed.add_field(name="Main PID", value=status_info.get('main_pid', 'unknown'), inline=True)
        embed.add_field(name="Load State", value=status_info.get('load_state', 'unknown'), inline=True)
        
        memory_current = status_info.get('memory_current', 'unknown')
        if memory_current != 'unknown' and memory_current.isdigit():
            memory_mb = int(memory_current) / 1024 / 1024
            embed.add_field(name="Memory Usage", value=f"{memory_mb:.1f} MB", inline=True)
        else:
            embed.add_field(name="Memory Usage", value=memory_current, inline=True)
        
        await ctx.send(embed=embed)
        
        # Log command usage
        await self._log_command_usage(ctx, "service_status", {"service": service})
    
    @debug_logs.command(name="system_resources")
    async def logs_system_resources(self, ctx):
        """
        Show system resource usage (Ubuntu VPS monitoring).
        """
        # Check rate limit
        if not await self._check_rate_limit(ctx):
            embed = discord.Embed(
                title="⏰ Rate Limited",
                description="You're sending commands too quickly. Please wait a moment.",
                color=discord.Color.red()
            )
            await ctx.send(embed=embed)
            return
        
        # Get system resources
        resources = await self._get_system_resources()
        
        if not resources:
            embed = discord.Embed(
                title="❌ Resource Error",
                description="Failed to get system resource information.",
                color=discord.Color.red()
            )
            await ctx.send(embed=embed)
            return
        
        # Create resource embed
        embed = discord.Embed(
            title="📊 System Resources",
            color=discord.Color.blue()
        )
        
        # Memory information
        memory = resources.get('memory', {})
        if memory:
            total_gb = memory.get('total', 0) / 1024 / 1024 / 1024
            used_gb = memory.get('used', 0) / 1024 / 1024 / 1024
            available_gb = memory.get('available', 0) / 1024 / 1024 / 1024
            percent = memory.get('percent', 0)
            
            embed.add_field(
                name="💾 Memory",
                value=f"**Used:** {used_gb:.1f} GB ({percent:.1f}%)\n**Available:** {available_gb:.1f} GB\n**Total:** {total_gb:.1f} GB",
                inline=True
            )
        
        # CPU information
        cpu = resources.get('cpu', {})
        if cpu:
            cpu_percent = cpu.get('percent', 0)
            cpu_count = cpu.get('count', 0)
            
            embed.add_field(
                name="🖥️ CPU",
                value=f"**Usage:** {cpu_percent:.1f}%\n**Cores:** {cpu_count}",
                inline=True
            )
        
        # Disk information
        disk = resources.get('disk', {})
        if disk:
            total_gb = disk.get('total', 0) / 1024 / 1024 / 1024
            used_gb = disk.get('used', 0) / 1024 / 1024 / 1024
            free_gb = disk.get('free', 0) / 1024 / 1024 / 1024
            percent = disk.get('percent', 0)
            
            embed.add_field(
                name="💽 Disk (/)",
                value=f"**Used:** {used_gb:.1f} GB ({percent:.1f}%)\n**Free:** {free_gb:.1f} GB\n**Total:** {total_gb:.1f} GB",
                inline=True
            )
        
        # Load average
        load_avg = resources.get('load_avg', (0, 0, 0))
        if load_avg and any(load_avg):
            embed.add_field(
                name="⚡ Load Average",
                value=f"**1m:** {load_avg[0]:.2f}\n**5m:** {load_avg[1]:.2f}\n**15m:** {load_avg[2]:.2f}",
                inline=True
            )
        
        embed.set_footer(text=f"Snapshot taken at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        await ctx.send(embed=embed)
        
        # Log command usage
        await self._log_command_usage(ctx, "system_resources", {})
    
    @debug_logs.command(name="permissions")
    async def logs_permissions(self, ctx):
        """
        Check system permissions for Ubuntu VPS features.
        """
        permissions = self._check_system_permissions()
        
        embed = discord.Embed(
            title="🔐 System Permissions Check",
            description="Checking permissions for Ubuntu VPS features",
            color=discord.Color.blue()
        )
        
        # Journal access
        journal_status = "✅ Available" if permissions.get('journal_access') else "❌ No Access"
        embed.add_field(
            name="📋 Journal Access",
            value=f"{journal_status}\n*Requires: systemd-journal group membership*",
            inline=False
        )
        
        # Log directory access
        log_status = "✅ Available" if permissions.get('log_directory_read') else "❌ No Access"
        embed.add_field(
            name="📁 Log Directory",
            value=f"{log_status}\n*Requires: read access to /var/log*",
            inline=False
        )
        
        # Service status access
        service_status = "✅ Available" if permissions.get('systemd_service_status') else "❌ No Access"
        embed.add_field(
            name="🔧 Service Status",
            value=f"{service_status}\n*Requires: systemctl command access*",
            inline=False
        )
        
        # Journal availability
        journal_available = "✅ Available" if self.journal_available else "❌ Not Available"
        embed.add_field(
            name="📖 Journal Commands",
            value=f"{journal_available}\n*Overall journal functionality*",
            inline=False
        )
        
        if not any(permissions.values()):
            embed.add_field(
                name="💡 Setup Help",
                value="To enable Ubuntu VPS features, run:\n```bash\nsudo usermod -a -G systemd-journal $(whoami)\nsudo mkdir -p /var/log/red-discordbot\nsudo chown $(whoami):$(whoami) /var/log/red-discordbot\n```",
                inline=False
            )
        
        await ctx.send(embed=embed)

    @debug_logs.command(name="ubuntu_setup")
    @checks.admin_or_permissions(manage_guild=True)
    async def ubuntu_vps_setup(self, ctx):
        """
        Automated Ubuntu VPS setup for enhanced debug_logs functionality.
        
        This command performs the same setup as the ubuntu_setup.sh script:
        - Installs required system packages
        - Adds user to systemd-journal group
        - Creates log directories
        - Configures log rotation
        - Creates systemd service template
        """
        # Check if running on Linux
        if os.name != 'posix':
            embed = discord.Embed(
                title="❌ Platform Not Supported",
                description="Ubuntu VPS setup is only available on Linux systems.",
                color=discord.Color.red()
            )
            await ctx.send(embed=embed)
            return
        
        # Send initial status
        setup_embed = discord.Embed(
            title="🚀 Ubuntu VPS Setup Starting",
            description="Setting up Ubuntu VPS for enhanced debug_logs functionality...",
            color=discord.Color.blue()
        )
        status_msg = await ctx.send(embed=setup_embed)
        
        setup_results = []
        
        try:
            # 1. Install required system packages
            setup_results.append("📦 Installing system packages...")
            await self._update_setup_status(status_msg, setup_results)
            
            try:
                if not UNIX_AVAILABLE:
                    setup_results.append("⚠️ Package management not available on Windows")
                    await self._update_setup_status(status_msg, setup_results)
                else:
                    # Update package list
                    result = await asyncio.create_subprocess_exec(
                        'sudo', 'apt', 'update',
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    await asyncio.wait_for(result.communicate(), timeout=60)
                    
                    # Install packages
                    result = await asyncio.create_subprocess_exec(
                        'sudo', 'apt', 'install', '-y', 'python3-pip', 'python3-dev', 'build-essential',
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    await asyncio.wait_for(result.communicate(), timeout=120)
                    
                    if result.returncode == 0:
                        setup_results.append("✅ System packages installed successfully")
                    else:
                        setup_results.append("⚠️ System packages installation had issues")
            except asyncio.TimeoutError:
                setup_results.append("⚠️ System packages installation timed out")
            except Exception as e:
                setup_results.append(f"❌ System packages installation failed: {str(e)[:100]}")
            
            # 2. Install Python packages
            setup_results.append("🐍 Installing Python packages...")
            await self._update_setup_status(status_msg, setup_results)
            
            try:
                result = await asyncio.create_subprocess_exec(
                    'pip3', 'install', '--user', 'psutil',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await asyncio.wait_for(result.communicate(), timeout=60)
                
                if result.returncode == 0:
                    setup_results.append("✅ Python packages installed successfully")
                else:
                    setup_results.append("⚠️ Python packages installation had issues")
            except Exception as e:
                setup_results.append(f"❌ Python packages installation failed: {str(e)[:100]}")
            
            # 3. Add user to systemd-journal group
            setup_results.append("👥 Configuring user groups...")
            await self._update_setup_status(status_msg, setup_results)
            
            try:
                if not UNIX_AVAILABLE:
                    setup_results.append("⚠️ Unix user management not available on Windows")
                    await self._update_setup_status(status_msg, setup_results)
                else:
                    # Get current user
                    current_user = pwd.getpwuid(os.getuid()).pw_name
                    
                    # Check if already in group
                    try:
                        journal_group = grp.getgrnam('systemd-journal')
                        if current_user in journal_group.gr_mem:
                            setup_results.append(f"✅ User {current_user} already in systemd-journal group")
                        else:
                            # Add to group
                            result = await asyncio.create_subprocess_exec(
                                'sudo', 'usermod', '-a', '-G', 'systemd-journal', current_user,
                                stdout=asyncio.subprocess.PIPE,
                                stderr=asyncio.subprocess.PIPE
                            )
                        await asyncio.wait_for(result.communicate(), timeout=30)
                        
                        if result.returncode == 0:
                            setup_results.append(f"✅ Added {current_user} to systemd-journal group")
                            setup_results.append("⚠️ You may need to restart the bot for group changes to take effect")
                        else:
                            setup_results.append("❌ Failed to add user to systemd-journal group")
                    except KeyError:
                        setup_results.append("⚠️ systemd-journal group not found")
                except Exception as e:
                    setup_results.append(f"❌ Group configuration failed: {str(e)[:100]}")
            
            # 4. Create log directories
            setup_results.append("📁 Creating log directories...")
            await self._update_setup_status(status_msg, setup_results)
            
            log_dirs = [
                os.path.expanduser("~/.local/share/Red-DiscordBot/logs"),
                os.path.expanduser("~/redbot/logs"),
                "/var/log/red-discordbot"
            ]
            
            for log_dir in log_dirs:
                try:
                    if log_dir == "/var/log/red-discordbot":
                        # System directory - needs sudo (Unix/Linux only)
                        if not os.path.exists(log_dir):
                            if UNIX_AVAILABLE:
                                result = await asyncio.create_subprocess_exec(
                                    'sudo', 'mkdir', '-p', log_dir,
                                    stdout=asyncio.subprocess.PIPE,
                                    stderr=asyncio.subprocess.PIPE
                                )
                                await result.communicate()
                                
                                # Change ownership
                                current_user = pwd.getpwuid(os.getuid()).pw_name
                                result = await asyncio.create_subprocess_exec(
                                    'sudo', 'chown', f'{current_user}:{current_user}', log_dir,
                                    stdout=asyncio.subprocess.PIPE,
                                    stderr=asyncio.subprocess.PIPE
                                )
                                await result.communicate()
                                
                                setup_results.append(f"✅ Created system log directory: {log_dir}")
                            else:
                                # On Windows, create directory without sudo/chown
                                os.makedirs(log_dir, exist_ok=True)
                                setup_results.append(f"✅ Created log directory: {log_dir}")
                        else:
                            setup_results.append(f"✅ System log directory already exists: {log_dir}")
                    else:
                        # User directory
                        if not os.path.exists(log_dir):
                            os.makedirs(log_dir, exist_ok=True)
                            setup_results.append(f"✅ Created user log directory: {log_dir}")
                        else:
                            setup_results.append(f"✅ User log directory already exists: {log_dir}")
                except Exception as e:
                    setup_results.append(f"❌ Failed to create {log_dir}: {str(e)[:100]}")
            
            # 5. Configure log rotation
            setup_results.append("🔄 Configuring log rotation...")
            await self._update_setup_status(status_msg, setup_results)
            
            try:
                if not UNIX_AVAILABLE:
                    setup_results.append("⚠️ Log rotation not available on Windows")
                    await self._update_setup_status(status_msg, setup_results)
                else:
                    current_user = pwd.getpwuid(os.getuid()).pw_name
                    home_dir = os.path.expanduser("~")
                    
                    logrotate_config = f"""# Red-DiscordBot log rotation configuration
{home_dir}/.local/share/Red-DiscordBot/logs/*.log {{
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    copytruncate
    su {current_user} {current_user}
}}

/var/log/red-discordbot/*.log {{
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    copytruncate
    su {current_user} {current_user}
}}"""
                    
                    # Write logrotate config
                    result = await asyncio.create_subprocess_exec(
                        'sudo', 'tee', '/etc/logrotate.d/red-discordbot',
                    input=logrotate_config.encode(),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await result.communicate()
                
                if result.returncode == 0:
                    setup_results.append("✅ Log rotation configured successfully")
                else:
                    setup_results.append("❌ Failed to configure log rotation")
            except Exception as e:
                setup_results.append(f"❌ Log rotation configuration failed: {str(e)[:100]}")
            
            # 6. Create systemd service template
            setup_results.append("🔧 Creating systemd service template...")
            await self._update_setup_status(status_msg, setup_results)
            
            try:
                if not UNIX_AVAILABLE:
                    setup_results.append("⚠️ Systemd service not available on Windows")
                    await self._update_setup_status(status_msg, setup_results)
                else:
                    current_user = pwd.getpwuid(os.getuid()).pw_name
                    home_dir = os.path.expanduser("~")
                
                service_template = f"""# Red-DiscordBot systemd service template
# Copy this to /etc/systemd/system/red-discordbot.service and customize

[Unit]
Description=Red-DiscordBot
After=network.target

[Service]
Type=simple
User={current_user}
Group={current_user}
WorkingDirectory={home_dir}
ExecStart=/usr/bin/python3 -m redbot <instance_name>
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=red-discordbot

# Environment variables
Environment=PYTHONPATH={home_dir}/.local/lib/python3.*/site-packages

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths={home_dir}/.local/share/Red-DiscordBot
ReadWritePaths=/var/log/red-discordbot

[Install]
WantedBy=multi-user.target"""
                
                service_file = os.path.join(home_dir, "red-discordbot.service.template")
                with open(service_file, 'w') as f:
                    f.write(service_template)
                
                setup_results.append(f"✅ Created systemd service template: {service_file}")
            except Exception as e:
                setup_results.append(f"❌ Service template creation failed: {str(e)[:100]}")
            
            # 7. Test journal access
            setup_results.append("🧪 Testing journal access...")
            await self._update_setup_status(status_msg, setup_results)
            
            try:
                result = await asyncio.create_subprocess_exec(
                    'journalctl', '--no-pager', '-n', '1',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await asyncio.wait_for(result.communicate(), timeout=10)
                
                if result.returncode == 0:
                    setup_results.append("✅ Journal access is working")
                else:
                    setup_results.append("⚠️ Journal access test failed - may need to restart bot")
            except Exception as e:
                setup_results.append(f"⚠️ Journal access test failed: {str(e)[:100]}")
            
            # 8. Create test log entry
            try:
                result = await asyncio.create_subprocess_exec(
                    'logger', '-t', 'red-discordbot-test', 'Debug logs cog setup completed successfully',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await result.communicate()
                setup_results.append("✅ Test log entry created")
            except Exception:
                setup_results.append("⚠️ Could not create test log entry")
            
            # Final status
            setup_results.append("")
            setup_results.append("🎉 Ubuntu VPS setup completed!")
            setup_results.append("")
            setup_results.append("📋 Next steps:")
            setup_results.append("1. If you saw group change warnings, restart the bot")
            setup_results.append("2. Configure the cog: `!debuglogs config service red-discordbot`")
            setup_results.append("3. Enable journal fallback: `!debuglogs config journal_fallback true`")
            setup_results.append("4. Test journal access: `!debuglogs journal 50`")
            
            await self._update_setup_status(status_msg, setup_results, final=True)
            
        except Exception as e:
            setup_results.append(f"❌ Setup failed with error: {str(e)}")
            await self._update_setup_status(status_msg, setup_results, final=True)
    
    async def _update_setup_status(self, message, results, final=False):
        """
        Update the setup status message with current progress.
        """
        try:
            title = "🎉 Ubuntu VPS Setup Complete!" if final else "🚀 Ubuntu VPS Setup In Progress"
            color = discord.Color.green() if final else discord.Color.blue()
            
            embed = discord.Embed(
                title=title,
                description="\n".join(results[-20:]),  # Show last 20 lines
                color=color
            )
            
            if not final:
                embed.set_footer(text="Setup in progress... Please wait.")
            
            await message.edit(embed=embed)
        except Exception:
            pass  # Ignore edit failures

    @debug_logs.group(name="config")
    @checks.admin_or_permissions(manage_guild=True)
    async def logs_config(self, ctx):
        """
        Configure debug logs settings.
        """
        if ctx.invoked_subcommand is None:
            await ctx.send_help()

    @logs_config.command(name="show")
    async def config_show(self, ctx):
        """
        Show current configuration settings.
        """
        config = await self.config.guild(ctx.guild).all()
        
        embed = discord.Embed(
            title="⚙️ Debug Logs Configuration",
            color=discord.Color.blue()
        )
        
        # Log channel
        channel_id = config.get("log_channel")
        if channel_id:
            channel = ctx.guild.get_channel(channel_id)
            channel_name = channel.mention if channel else "#deleted-channel"
        else:
            channel_name = "Not set (uses current channel)"
        
        embed.add_field(
            name="📍 Default Log Channel",
            value=channel_name,
            inline=False
        )
        
        embed.add_field(
            name="📁 Max File Size",
            value=f"{config.get('max_file_size', 8000000) / 1024 / 1024:.1f} MB",
            inline=True
        )
        
        embed.add_field(
            name="🧹 Auto Cleanup",
            value="✅ Enabled" if config.get("auto_cleanup", True) else "❌ Disabled",
            inline=True
        )
        
        embed.add_field(
            name="🌍 Timezone",
            value=config.get("timezone", "UTC"),
            inline=True
        )
        
        embed.add_field(
            name="⏱️ Rate Limit",
            value=f"{config.get('rate_limit_per_user', 5)} commands/minute",
            inline=True
        )
        
        embed.add_field(
            name="🔍 Max Search Results",
            value=f"{config.get('max_search_results', 1000):,}",
            inline=True
        )
        
        embed.add_field(
            name="💾 Cache Duration",
            value=f"{config.get('cache_duration', 300)} seconds",
            inline=True
        )
        
        # Ubuntu/VPS specific settings
        embed.add_field(
            name="🐧 Service Name",
            value=config.get('service_name', 'red-discordbot'),
            inline=True
        )
        
        embed.add_field(
            name="📋 Journal Fallback",
            value="✅ Enabled" if config.get('journal_fallback', True) else "❌ Disabled",
            inline=True
        )
        
        embed.add_field(
            name="☁️ GCP Optimization",
            value="✅ Enabled" if config.get('gcp_optimization', False) else "❌ Disabled",
            inline=True
        )
        
        embed.add_field(
            name="📖 Max Journal Lines",
            value=f"{config.get('max_journal_lines', 10000):,}",
            inline=True
        )
        
        embed.add_field(
            name="🔄 Log Rotation Aware",
            value="✅ Enabled" if config.get('log_rotation_aware', True) else "❌ Disabled",
            inline=True
        )
        
        embed.add_field(
            name="🌐 IP Rate Limiting",
            value="✅ Enabled" if config.get('ip_rate_limiting', False) else "❌ Disabled",
            inline=True
        )
        
        embed.set_footer(text="Use subcommands to modify these settings")
        await ctx.send(embed=embed)
    
    @logs_config.command(name="channel")
    async def config_channel(self, ctx, channel: Optional[discord.TextChannel] = None):
        """
        Set the default channel for log outputs.
        """
        if channel is None:
            current = await self.config.guild(ctx.guild).log_channel()
            if current:
                channel_obj = ctx.guild.get_channel(current)
                await ctx.send(f"Current log channel: {channel_obj.mention if channel_obj else 'Unknown'}")
            else:
                await ctx.send("No default log channel set.")
        else:
            await self.config.guild(ctx.guild).log_channel.set(channel.id)
            await ctx.send(f"✅ Default log channel set to {channel.mention}")

    @logs_config.command(name="maxsize")
    async def config_maxsize(self, ctx, size_mb: float):
        """
        Set the maximum file size for log uploads (in MB).
        
        Parameters:
        - size_mb: Maximum file size in megabytes (max 8MB for Discord)
        """
        if size_mb <= 0 or size_mb > 8:
            await ctx.send("❌ File size must be between 0.1 and 8 MB.")
            return
        
        size_bytes = int(size_mb * 1024 * 1024)
        await self.config.guild(ctx.guild).max_file_size.set(size_bytes)
        
        embed = discord.Embed(
            title="✅ Configuration Updated",
            description=f"Maximum file size set to {size_mb:.1f} MB",
            color=discord.Color.green()
        )
        await ctx.send(embed=embed)
    
    @logs_config.command(name="ratelimit")
    async def config_ratelimit(self, ctx, commands_per_minute: int):
        """
        Set the rate limit for log commands per user.
        
        Parameters:
        - commands_per_minute: Number of commands allowed per minute (1-20)
        """
        if commands_per_minute < 1 or commands_per_minute > 20:
            await ctx.send("❌ Rate limit must be between 1 and 20 commands per minute.")
            return
        
        await self.config.guild(ctx.guild).rate_limit_per_user.set(commands_per_minute)
        
        embed = discord.Embed(
            title="✅ Configuration Updated",
            description=f"Rate limit set to {commands_per_minute} commands per minute per user",
            color=discord.Color.green()
        )
        await ctx.send(embed=embed)
    
    @logs_config.command(name="timezone")
    async def config_timezone(self, ctx, timezone: str = "UTC"):
        """
        Set the timezone for log timestamps.
        
        Parameters:
        - timezone: Timezone identifier (e.g., UTC, US/Eastern, Europe/London)
        """
        # Basic timezone validation
        valid_timezones = ["UTC", "US/Eastern", "US/Central", "US/Mountain", "US/Pacific", 
                          "Europe/London", "Europe/Paris", "Europe/Berlin", "Asia/Tokyo", "Australia/Sydney"]
        
        if timezone not in valid_timezones:
            embed = discord.Embed(
                title="❌ Invalid Timezone",
                description=f"Please use one of: {', '.join(valid_timezones)}",
                color=discord.Color.red()
            )
            await ctx.send(embed=embed)
            return
        
        await self.config.guild(ctx.guild).timezone.set(timezone)
        
        embed = discord.Embed(
            title="✅ Configuration Updated",
            description=f"Timezone set to {timezone}",
            color=discord.Color.green()
        )
        await ctx.send(embed=embed)
    
    @logs_config.command(name="maxresults")
    async def config_maxresults(self, ctx, max_results: int):
        """
        Set the maximum number of search results.
        
        Parameters:
        - max_results: Maximum search results (100-10000)
        """
        if max_results < 100 or max_results > 10000:
            await ctx.send("❌ Max results must be between 100 and 10,000.")
            return
        
        await self.config.guild(ctx.guild).max_search_results.set(max_results)
        
        embed = discord.Embed(
            title="✅ Configuration Updated",
            description=f"Maximum search results set to {max_results:,}",
            color=discord.Color.green()
        )
        await ctx.send(embed=embed)
    
    @logs_config.command(name="cache")
    async def config_cache(self, ctx, duration_seconds: int):
        """
        Set the cache duration for log data.
        
        Parameters:
        - duration_seconds: Cache duration in seconds (0-3600, 0 to disable)
        """
        if duration_seconds < 0 or duration_seconds > 3600:
            await ctx.send("❌ Cache duration must be between 0 and 3600 seconds (1 hour).")
            return
        
        await self.config.guild(ctx.guild).cache_duration.set(duration_seconds)
        
        # Clear existing cache
        self.log_cache.clear()
        
        if duration_seconds == 0:
            description = "Log caching disabled"
        else:
            description = f"Cache duration set to {duration_seconds} seconds"
        
        embed = discord.Embed(
            title="✅ Configuration Updated",
            description=description,
            color=discord.Color.green()
        )
        await ctx.send(embed=embed)
    
    @logs_config.command(name="reset")
    async def config_reset(self, ctx):
        """
        Reset all configuration settings to defaults.
        """
        # Ask for confirmation
        embed = discord.Embed(
            title="⚠️ Reset Configuration",
            description="Are you sure you want to reset all debug logs settings to defaults?",
            color=discord.Color.orange()
        )
        
        msg = await ctx.send(embed=embed)
        await msg.add_reaction("✅")
        await msg.add_reaction("❌")
        
        def check(reaction, user):
            return user == ctx.author and str(reaction.emoji) in ["✅", "❌"] and reaction.message.id == msg.id
        
        try:
            reaction, user = await self.bot.wait_for("reaction_add", timeout=30.0, check=check)
            
            if str(reaction.emoji) == "✅":
                await self.config.guild(ctx.guild).clear()
                self.log_cache.clear()
                self.user_rate_limits.clear()
                
                embed = discord.Embed(
                    title="✅ Configuration Reset",
                    description="All settings have been reset to defaults.",
                    color=discord.Color.green()
                )
                await ctx.send(embed=embed)
            else:
                await ctx.send("❌ Configuration reset cancelled.")
                
        except asyncio.TimeoutError:
            await ctx.send("⏰ Configuration reset timed out.")
        
        try:
            await msg.delete()
        except discord.NotFound:
            pass
    
    # Ubuntu/VPS Configuration Commands
    @logs_config.command(name="service")
    async def config_service(self, ctx, service_name: str):
        """
        Set the systemd service name for Ubuntu VPS.
        
        Parameters:
        - service_name: Name of the systemd service (e.g., 'red-discordbot')
        """
        if not service_name or len(service_name) > 50:
            await ctx.send("❌ Service name must be between 1 and 50 characters.")
            return
        
        await self.config.guild(ctx.guild).service_name.set(service_name)
        
        embed = discord.Embed(
            title="✅ Configuration Updated",
            description=f"systemd service name set to: `{service_name}`",
            color=discord.Color.green()
        )
        await ctx.send(embed=embed)
    
    @logs_config.command(name="journal_fallback")
    async def config_journal_fallback(self, ctx, enabled: bool):
        """
        Enable or disable journal fallback for Ubuntu VPS.
        
        Parameters:
        - enabled: True to enable, False to disable
        """
        await self.config.guild(ctx.guild).journal_fallback.set(enabled)
        
        status = "enabled" if enabled else "disabled"
        embed = discord.Embed(
            title="✅ Configuration Updated",
            description=f"Journal fallback {status}",
            color=discord.Color.green()
        )
        await ctx.send(embed=embed)
    
    @logs_config.command(name="gcp_optimization")
    async def config_gcp_optimization(self, ctx, enabled: bool):
        """
        Enable or disable Google Cloud Platform optimizations.
        
        Parameters:
        - enabled: True to enable, False to disable
        """
        await self.config.guild(ctx.guild).gcp_optimization.set(enabled)
        
        status = "enabled" if enabled else "disabled"
        embed = discord.Embed(
            title="✅ Configuration Updated",
            description=f"GCP optimization {status}",
            color=discord.Color.green()
        )
        await ctx.send(embed=embed)
    
    @logs_config.command(name="max_journal_lines")
    async def config_max_journal_lines(self, ctx, max_lines: int):
        """
        Set the maximum number of lines to retrieve from journal.
        
        Parameters:
        - max_lines: Maximum lines (100-50000)
        """
        if max_lines < 100 or max_lines > 50000:
            await ctx.send("❌ Max journal lines must be between 100 and 50,000.")
            return
        
        await self.config.guild(ctx.guild).max_journal_lines.set(max_lines)
        
        embed = discord.Embed(
            title="✅ Configuration Updated",
            description=f"Maximum journal lines set to {max_lines:,}",
            color=discord.Color.green()
        )
        await ctx.send(embed=embed)
    
    @logs_config.command(name="ip_rate_limiting")
    async def config_ip_rate_limiting(self, ctx, enabled: bool):
        """
        Enable or disable IP-based rate limiting for VPS security.
        
        Parameters:
        - enabled: True to enable, False to disable
        """
        await self.config.guild(ctx.guild).ip_rate_limiting.set(enabled)
        
        status = "enabled" if enabled else "disabled"
        embed = discord.Embed(
            title="✅ Configuration Updated",
            description=f"IP-based rate limiting {status}",
            color=discord.Color.green()
        )
        await ctx.send(embed=embed)
    
    @logs_config.command(name="stream_large_logs")
    async def config_stream_large_logs(self, ctx, enabled: bool):
        """
        Enable or disable streaming for large log processing.
        
        Parameters:
        - enabled: True to enable, False to disable
        """
        await self.config.guild(ctx.guild).stream_large_logs.set(enabled)
        
        status = "enabled" if enabled else "disabled"
        embed = discord.Embed(
            title="✅ Configuration Updated",
            description=f"Large log streaming {status}",
            color=discord.Color.green()
        )
        await ctx.send(embed=embed)

    async def _log_command_usage(self, ctx, command_name: str, filters: dict = None):
        """
        Log command usage for audit purposes.
        """
        try:
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "user_id": ctx.author.id,
                "user_name": str(ctx.author),
                "guild_id": ctx.guild.id if ctx.guild else None,
                "guild_name": ctx.guild.name if ctx.guild else None,
                "channel_id": ctx.channel.id,
                "command": command_name,
                "filters": filters or {}
            }
            
            # Log to bot's logger
            logging.info(f"DebugLogs command used: {log_entry}")
            
        except Exception as e:
            logging.error(f"Failed to log command usage: {e}")
    
    async def _get_cached_log_content(self, cache_key: str) -> Optional[str]:
        """
        Get cached log content if available and not expired.
        """
        if cache_key not in self.log_cache:
            return None
        
        cached_data = self.log_cache[cache_key]
        cache_duration = await self.config.guild_from_id(cached_data.get("guild_id", 0)).cache_duration()
        
        if cache_duration == 0:  # Caching disabled
            return None
        
        # Check if cache is expired
        cache_time = cached_data.get("timestamp", 0)
        if time.time() - cache_time > cache_duration:
            del self.log_cache[cache_key]
            return None
        
        return cached_data.get("content")
    
    async def _cache_log_content(self, cache_key: str, content: str, guild_id: int):
        """
        Cache log content for future use.
        """
        cache_duration = await self.config.guild_from_id(guild_id).cache_duration()
        
        if cache_duration == 0:  # Caching disabled
            return
        
        self.log_cache[cache_key] = {
            "content": content,
            "timestamp": time.time(),
            "guild_id": guild_id
        }
        
        # Clean up old cache entries
        current_time = time.time()
        expired_keys = [
            key for key, data in self.log_cache.items()
            if current_time - data.get("timestamp", 0) > cache_duration
        ]
        
        for key in expired_keys:
            del self.log_cache[key]
    
    def cog_unload(self):
        """
        Cleanup when cog is unloaded.
        """
        self.log_cache.clear()
        self.user_rate_limits.clear()
        logging.info("DebugLogs cog unloaded and cleaned up")


def setup(bot):
    bot.add_cog(DebugLogs(bot))