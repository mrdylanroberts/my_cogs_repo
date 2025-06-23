import discord
import aiohttp
import asyncio
import re
import json
import os
from typing import Optional, Dict, Any
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup

from redbot.core import commands, Config, data_manager
from redbot.core.utils.chat_formatting import box, pagify
from redbot.core.bot import Red


class VidTranscribe(commands.Cog):
    """Extract transcripts from Loom and Zoom video recordings."""
    
    def __init__(self, bot: Red):
        self.bot = bot
        self.config = Config.get_conf(self, identifier=1234567890, force_registration=True)
        
        # Default settings
        default_global = {
            "zoom_client_id": "",
            "zoom_client_secret": "",
            "zoom_account_id": ""
        }
        
        self.config.register_global(**default_global)
        self.session = None
        
    async def cog_load(self):
        """Initialize aiohttp session when cog loads."""
        self.session = aiohttp.ClientSession()
        
    async def cog_unload(self):
        """Clean up aiohttp session when cog unloads."""
        if self.session:
            await self.session.close()
    
    def _detect_platform(self, url: str) -> str:
        """Detect if URL is from Loom or Zoom."""
        if "loom.com" in url:
            return "loom"
        elif "zoom.us" in url or "zoom.com" in url:
            return "zoom"
        else:
            return "unknown"
    
    def _extract_loom_id(self, url: str) -> Optional[str]:
        """Extract Loom video ID from URL."""
        # Pattern: https://www.loom.com/share/{video_id}
        match = re.search(r'loom\.com/share/([a-f0-9-]+)', url)
        if match:
            return match.group(1)
        return None
    
    async def _get_loom_transcript(self, video_id: str) -> Optional[str]:
        """Extract transcript from Loom video using multiple methods."""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
            
            # Method 1: Try the main video page and extract transcript data
            video_url = f"https://www.loom.com/share/{video_id}"
            async with self.session.get(video_url, headers=headers) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    # Look for transcript data in various script patterns
                    scripts = soup.find_all('script')
                    for script in scripts:
                        if script.string:
                            script_content = script.string
                            
                            # Pattern 1: Look for transcript in window.__INITIAL_STATE__ or similar
                            if 'transcript' in script_content.lower():
                                # Try multiple transcript extraction patterns
                                patterns = [
                                    r'"transcript":\s*"([^"]+)"',
                                    r'"transcriptText":\s*"([^"]+)"',
                                    r'"transcribed_text":\s*"([^"]+)"',
                                    r'transcript["\']?:\s*["\']([^"\'
]+)["\']',
                                    r'"captions":\s*\[([^\]]+)\]',
                                    r'"transcript_segments":\s*\[([^\]]+)\]'
                                ]
                                
                                for pattern in patterns:
                                    try:
                                        match = re.search(pattern, script_content, re.IGNORECASE)
                                        if match:
                                            transcript = match.group(1)
                                            # Clean up the transcript
                                            transcript = transcript.replace('\\n', '\n')
                                            transcript = transcript.replace('\\t', '\t')
                                            transcript = transcript.replace('\\"', '"')
                                            if len(transcript.strip()) > 10:  # Basic validation
                                                return transcript.strip()
                                    except Exception:
                                        continue
                            
                            # Pattern 2: Look for JSON data with video information
                            if 'videoData' in script_content or 'video' in script_content:
                                try:
                                    # Extract JSON objects that might contain transcript
                                    json_matches = re.findall(r'\{[^{}]*"transcript"[^{}]*\}', script_content)
                                    for json_str in json_matches:
                                        try:
                                            import json
                                            data = json.loads(json_str)
                                            if 'transcript' in data and data['transcript']:
                                                return data['transcript']
                                        except:
                                            continue
                                except Exception:
                                    continue
                    
                    # Method 2: Look for transcript in meta tags or data attributes
                    transcript_elements = soup.find_all(attrs={'data-transcript': True})
                    for element in transcript_elements:
                        transcript = element.get('data-transcript')
                        if transcript and len(transcript.strip()) > 10:
                            return transcript.strip()
                    
                    # Method 3: Look for transcript in specific div classes/ids
                    transcript_containers = soup.find_all(['div', 'span', 'p'], 
                                                         class_=re.compile(r'transcript|caption', re.I))
                    for container in transcript_containers:
                        if container.get_text(strip=True):
                            text = container.get_text(strip=True)
                            if len(text) > 50:  # Likely to be actual transcript content
                                return text
            
            # Method 4: Try alternative API endpoints
            api_endpoints = [
                f"https://www.loom.com/api/campaigns/sessions/{video_id}/transcribed_text",
                f"https://www.loom.com/api/videos/{video_id}/transcript",
                f"https://cdn.loom.com/sessions/{video_id}/transcripts/en-US.vtt"
            ]
            
            for endpoint in api_endpoints:
                try:
                    async with self.session.get(endpoint, headers=headers) as response:
                        if response.status == 200:
                            content_type = response.headers.get('content-type', '').lower()
                            
                            if 'json' in content_type:
                                data = await response.json()
                                # Handle different JSON response formats
                                if isinstance(data, dict):
                                    for key in ['transcribed_text', 'transcript', 'text', 'content']:
                                        if key in data and data[key]:
                                            return data[key]
                                elif isinstance(data, str) and len(data.strip()) > 10:
                                    return data.strip()
                            
                            elif 'vtt' in content_type or 'text' in content_type:
                                text = await response.text()
                                if text and len(text.strip()) > 10:
                                    # Clean VTT format if needed
                                    if 'WEBVTT' in text:
                                        lines = text.split('\n')
                                        transcript_lines = []
                                        for line in lines:
                                            line = line.strip()
                                            if line and not line.startswith('WEBVTT') and '-->' not in line and not line.isdigit():
                                                transcript_lines.append(line)
                                        if transcript_lines:
                                            return '\n'.join(transcript_lines)
                                    else:
                                        return text.strip()
                except Exception:
                    continue
                    
            return None
            
        except Exception as e:
            print(f"Error getting Loom transcript: {e}")
            return None
    
    async def _get_zoom_access_token(self) -> Optional[str]:
        """Get Zoom OAuth access token."""
        try:
            client_id = await self.config.zoom_client_id()
            client_secret = await self.config.zoom_client_secret()
            account_id = await self.config.zoom_account_id()
            
            if not all([client_id, client_secret, account_id]):
                return None
                
            auth_url = "https://zoom.us/oauth/token"
            
            data = {
                'grant_type': 'account_credentials',
                'account_id': account_id
            }
            
            import base64
            credentials = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
            
            headers = {
                'Authorization': f'Basic {credentials}',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            async with self.session.post(auth_url, data=data, headers=headers) as response:
                if response.status == 200:
                    token_data = await response.json()
                    return token_data.get('access_token')
                    
            return None
            
        except Exception as e:
            print(f"Error getting Zoom access token: {e}")
            return None
    
    def _extract_zoom_meeting_id(self, url: str) -> Optional[str]:
        """Extract Zoom meeting ID from URL."""
        # Pattern: https://zoom.us/rec/share/{meeting_id} or similar
        patterns = [
            r'zoom\.us/rec/share/([A-Za-z0-9._-]+)',
            r'zoom\.us/rec/play/([A-Za-z0-9._-]+)',
            r'zoom\.us/j/([0-9]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, url)
            if match:
                return match.group(1)
        return None
    
    async def _get_zoom_transcript(self, meeting_id: str) -> Optional[str]:
        """Extract transcript from Zoom recording."""
        try:
            access_token = await self._get_zoom_access_token()
            if not access_token:
                return None
                
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            # Get recording details
            recordings_url = f"https://api.zoom.us/v2/meetings/{meeting_id}/recordings"
            
            async with self.session.get(recordings_url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    # Look for transcript files
                    recording_files = data.get('recording_files', [])
                    
                    for file_info in recording_files:
                        file_type = file_info.get('file_type', '')
                        
                        # Look for transcript or closed caption files
                        if file_type in ['TRANSCRIPT', 'CC']:
                            download_url = file_info.get('download_url')
                            if download_url:
                                # Download transcript file
                                async with self.session.get(download_url, headers=headers) as transcript_response:
                                    if transcript_response.status == 200:
                                        transcript_content = await transcript_response.text()
                                        return self._parse_zoom_transcript(transcript_content, file_type)
                                        
            return None
            
        except Exception as e:
            print(f"Error getting Zoom transcript: {e}")
            return None
    
    def _parse_zoom_transcript(self, content: str, file_type: str) -> str:
        """Parse Zoom transcript content based on file type."""
        try:
            if file_type == 'TRANSCRIPT':
                # Parse VTT format
                lines = content.split('\n')
                transcript_lines = []
                
                for line in lines:
                    line = line.strip()
                    # Skip VTT headers and timestamp lines
                    if (line and 
                        not line.startswith('WEBVTT') and 
                        not line.startswith('NOTE') and 
                        not '-->' in line and 
                        not line.isdigit()):
                        transcript_lines.append(line)
                        
                return '\n'.join(transcript_lines)
                
            elif file_type == 'CC':
                # Parse closed caption format
                return content
                
        except Exception as e:
            print(f"Error parsing Zoom transcript: {e}")
            
        return content
    
    async def _save_transcript_file(self, transcript: str, platform: str, video_id: str) -> str:
        """Save transcript to a text file and return the file path."""
        try:
            # Create transcripts directory in cog data folder
            data_dir = data_manager.cog_data_path(self)
            transcripts_dir = data_dir / "transcripts"
            transcripts_dir.mkdir(exist_ok=True)
            
            # Generate filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{platform}_{video_id}_{timestamp}.txt"
            file_path = transcripts_dir / filename
            
            # Write transcript to file
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(f"Transcript from {platform.title()} Video\n")
                f.write(f"Video ID: {video_id}\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 50 + "\n\n")
                f.write(transcript)
                
            return str(file_path)
            
        except Exception as e:
            print(f"Error saving transcript file: {e}")
            return None
    
    @commands.command(name="vid_transcribe")
    async def vid_transcribe(self, ctx, url: str):
        """Extract transcript from Loom or Zoom video recording.
        
        Usage: !vid_transcribe <video_url>
        
        Supported platforms:
        - Loom: Public videos with transcripts enabled
        - Zoom: Cloud recordings (requires API configuration)
        """
        
        # Send initial processing message
        processing_msg = await ctx.send("🔄 Processing video URL and extracting transcript...")
        
        try:
            # Detect platform
            platform = self._detect_platform(url)
            
            if platform == "unknown":
                await processing_msg.edit(content="❌ Unsupported platform. Only Loom and Zoom URLs are supported.")
                return
            
            transcript = None
            video_id = None
            error_details = None
            
            if platform == "loom":
                video_id = self._extract_loom_id(url)
                if not video_id:
                    await processing_msg.edit(content="❌ Could not extract Loom video ID from URL.")
                    return
                    
                await processing_msg.edit(content="🔄 Extracting transcript from Loom video...")
                transcript = await self._get_loom_transcript(video_id)
                
                if not transcript:
                    error_details = "Loom transcript extraction failed. This could be because:\n" + \
                                  "• The video creator hasn't enabled transcript access (most common)\n" + \
                                  "• The video is private or requires authentication\n" + \
                                  "• The transcript is still being processed by Loom\n" + \
                                  "• The video doesn't contain speech content\n" + \
                                  "• Loom has changed their transcript access methods\n\n" + \
                                  "**To enable transcripts on Loom:**\n" + \
                                  "1. Go to video Settings → Audience → Transcript\n" + \
                                  "2. Toggle transcript access ON for viewers"
                
            elif platform == "zoom":
                video_id = self._extract_zoom_meeting_id(url)
                if not video_id:
                    await processing_msg.edit(content="❌ Could not extract Zoom meeting ID from URL.")
                    return
                    
                await processing_msg.edit(content="🔄 Extracting transcript from Zoom recording...")
                transcript = await self._get_zoom_transcript(video_id)
                
                if not transcript:
                    error_details = "Zoom transcript extraction failed. This could be because:\n" + \
                                  "• The recording doesn't have transcript/captions enabled\n" + \
                                  "• The meeting ID or URL format is invalid\n" + \
                                  "• The recording is not accessible with current API permissions\n" + \
                                  "• The transcript is still being processed by Zoom"
            
            if not transcript:
                error_msg = (
                    f"❌ Could not extract transcript from {platform.title()} video.\n\n"
                )
                
                if error_details:
                    error_msg += error_details
                else:
                    error_msg += f"**Possible reasons:**\n"
                    if platform == "loom":
                        error_msg += (
                            "• Video creator hasn't enabled transcript access\n"
                            "• Video is private or requires authentication\n"
                            "• Transcript is still being processed\n"
                            "• Video doesn't contain speech"
                        )
                    elif platform == "zoom":
                        error_msg += (
                            "• Zoom API credentials not configured\n"
                            "• Recording doesn't have transcript enabled\n"
                            "• Insufficient API permissions\n"
                            "• Recording is still being processed"
                        )
                    
                await processing_msg.edit(content=error_msg)
                return
            
            # Save transcript to file
            await processing_msg.edit(content="💾 Saving transcript to file...")
            file_path = await self._save_transcript_file(transcript, platform, video_id)
            
            if not file_path:
                await processing_msg.edit(content="❌ Error saving transcript file.")
                return
            
            # Create embed with transcript info
            embed = discord.Embed(
                title="📝 Transcript Extracted Successfully",
                color=0x00ff00,
                timestamp=datetime.now()
            )
            
            embed.add_field(
                name="Platform",
                value=platform.title(),
                inline=True
            )
            
            embed.add_field(
                name="Video ID",
                value=video_id,
                inline=True
            )
            
            embed.add_field(
                name="Transcript Length",
                value=f"{len(transcript)} characters",
                inline=True
            )
            
            # Add preview of transcript (first 500 characters)
            preview = transcript[:500]
            if len(transcript) > 500:
                preview += "..."
                
            embed.add_field(
                name="Preview",
                value=f"```\n{preview}\n```",
                inline=False
            )
            
            embed.set_footer(text="Transcript saved to file")
            
            # Send transcript file
            try:
                with open(file_path, 'rb') as f:
                    file = discord.File(f, filename=os.path.basename(file_path))
                    await processing_msg.edit(content=None, embed=embed, attachments=[file])
            except Exception as e:
                # If file upload fails, send transcript in chunks
                await processing_msg.edit(content=None, embed=embed)
                
                # Send transcript in chunks if it's too long
                for page in pagify(transcript, delims=["\n", " "], page_length=1900):
                    await ctx.send(box(page, lang=""))
                    
        except Exception as e:
            await processing_msg.edit(content=f"❌ An error occurred: {str(e)}")
    
    @commands.group(name="vidtranscribe_config")
    @commands.is_owner()
    async def vidtranscribe_config(self, ctx):
        """Configure VidTranscribe settings."""
        if ctx.invoked_subcommand is None:
            embed = discord.Embed(
                title="VidTranscribe Configuration",
                description="Configure API credentials for video transcript extraction.",
                color=0x0099ff
            )
            
            # Show current config status
            zoom_configured = bool(await self.config.zoom_client_id())
            
            embed.add_field(
                name="Zoom API",
                value="✅ Configured" if zoom_configured else "❌ Not configured",
                inline=False
            )
            
            embed.add_field(
                name="Available Commands",
                value=(
                    "`!vidtranscribe_config zoom <client_id> <client_secret> <account_id>` - Configure Zoom API\n"
                    "`!vidtranscribe_config clear` - Clear all API credentials"
                ),
                inline=False
            )
            
            await ctx.send(embed=embed)
    
    @vidtranscribe_config.command(name="zoom")
    async def config_zoom(self, ctx, client_id: str, client_secret: str, account_id: str):
        """Configure Zoom API credentials.
        
        Get these from your Zoom Server-to-Server OAuth app:
        https://marketplace.zoom.us/develop/create
        """
        await self.config.zoom_client_id.set(client_id)
        await self.config.zoom_client_secret.set(client_secret)
        await self.config.zoom_account_id.set(account_id)
        
        await ctx.send("✅ Zoom API credentials configured successfully!")
    
    @vidtranscribe_config.command(name="clear")
    async def config_clear(self, ctx):
        """Clear all API credentials."""
        await self.config.zoom_client_id.set("")
        await self.config.zoom_client_secret.set("")
        await self.config.zoom_account_id.set("")
        
        await ctx.send("✅ All API credentials cleared.")
    
    @commands.command(name="vid_help")
    async def vid_help(self, ctx):
        """Show help information for VidTranscribe."""
        embed = discord.Embed(
            title="📹 VidTranscribe Help",
            description="Extract transcripts from Loom and Zoom video recordings.",
            color=0x0099ff
        )
        
        embed.add_field(
            name="Basic Usage",
            value="`!vid_transcribe <video_url>`",
            inline=False
        )
        
        embed.add_field(
            name="Supported Platforms",
            value=(
                "🟢 **Loom** - Public videos with transcripts enabled\n"
                "🟡 **Zoom** - Cloud recordings (requires API setup)"
            ),
            inline=False
        )
        
        embed.add_field(
            name="Loom Requirements",
            value=(
                "• Video must be public or shared\n"
                "• Creator must have enabled transcript access\n"
                "• Video must contain speech"
            ),
            inline=True
        )
        
        embed.add_field(
            name="Zoom Requirements",
            value=(
                "• Zoom API credentials configured\n"
                "• Cloud recording with transcript enabled\n"
                "• Proper API permissions"
            ),
            inline=True
        )
        
        embed.add_field(
            name="Example URLs",
            value=(
                "```\n"
                "!vid_transcribe https://www.loom.com/share/abc123\n"
                "!vid_transcribe https://zoom.us/rec/share/xyz789\n"
                "```"
            ),
            inline=False
        )
        
        embed.set_footer(text="Use !vidtranscribe_config to set up API credentials (owner only)")
        
        await ctx.send(embed=embed)