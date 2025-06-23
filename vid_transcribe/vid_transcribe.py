import discord
import re
import aiohttp
import asyncio
import logging
from redbot.core import commands, Config
from redbot.core.bot import Red
from redbot.core.utils.chat_formatting import box, pagify
from typing import Optional
import json
from urllib.parse import urlparse, parse_qs
import os
import tempfile
from datetime import datetime

log = logging.getLogger("red.cogs.vid_transcribe")

class VidTranscribe(commands.Cog):
    """A cog for transcribing videos from various platforms."""
    
    def __init__(self, bot: Red):
        self.bot = bot
        self.config = Config.get_conf(self, identifier=1234567890)
        default_global = {
            "api_keys": {},
            "enabled_platforms": ["loom", "zoom"]
        }
        self.config.register_global(**default_global)
        self.session = None
        
    async def cog_load(self):
        """Initialize the cog."""
        self.session = aiohttp.ClientSession()
        
    async def cog_unload(self):
        """Clean up when the cog is unloaded."""
        if self.session:
            await self.session.close()
    
    def cog_unload(self):
        """Clean up when the cog is unloaded."""
        if self.session:
            asyncio.create_task(self.session.close())
    
    @commands.group(name="vidtranscribe", aliases=["vt"])
    async def vid_transcribe(self, ctx):
        """Video transcription commands."""
        pass
    
    @vid_transcribe.command(name="transcript", aliases=["t"])
    async def get_transcript(self, ctx, url: str):
        """Get transcript from a video URL."""
        try:
            # Determine platform
            platform = self._detect_platform(url)
            if not platform:
                await ctx.send("❌ Unsupported platform. Currently supports: Loom, Zoom")
                return
            
            # Check if platform is enabled
            enabled_platforms = await self.config.enabled_platforms()
            if platform not in enabled_platforms:
                await ctx.send(f"❌ {platform.title()} transcription is currently disabled.")
                return
            
            await ctx.send(f"🔍 Extracting transcript from {platform.title()} video...")
            
            # Get transcript based on platform
            if platform == "loom":
                transcript = await self._get_loom_transcript(url)
            elif platform == "zoom":
                transcript = await self._get_zoom_transcript(url)
            else:
                await ctx.send("❌ Platform not implemented yet.")
                return
            
            if transcript:
                # Split long transcripts into multiple messages
                for page in pagify(transcript, delims=["\n", ". "], page_length=1900):
                    await ctx.send(box(page, lang=""))
            else:
                await ctx.send("❌ Could not extract transcript from this video.")
                
        except Exception as e:
            log.error(f"Error getting transcript: {e}")
            await ctx.send(f"❌ An error occurred: {str(e)}")
    
    def _detect_platform(self, url: str) -> Optional[str]:
        """Detect the video platform from URL."""
        url_lower = url.lower()
        
        if "loom.com" in url_lower:
            return "loom"
        elif "zoom.us" in url_lower:
            return "zoom"
        
        return None
    
    async def _get_loom_transcript(self, url: str) -> Optional[str]:
        """Extract transcript from Loom video."""
        try:
            # Extract video ID from URL
            video_id = self._extract_loom_id(url)
            if not video_id:
                return None
            
            # Try to get transcript from Loom's API or page source
            transcript = await self._fetch_loom_transcript_from_page(url)
            
            return transcript
            
        except Exception as e:
            log.error(f"Error getting Loom transcript: {e}")
            return None
    
    async def _fetch_loom_transcript_from_page(self, url: str) -> Optional[str]:
        """Fetch transcript by parsing the Loom page source."""
        try:
            async with self.session.get(url) as response:
                if response.status != 200:
                    return None
                
                content = await response.text()
                
                # Look for transcript data in the page source
                # Loom often embeds transcript data in JavaScript variables
                transcript_text = self._extract_transcript_from_content(content)
                
                return transcript_text
                
        except Exception as e:
            log.error(f"Error fetching Loom page: {e}")
            return None
    
    def _extract_transcript_from_content(self, content: str) -> Optional[str]:
        """Extract transcript from page content using regex patterns."""
        try:
            # Pattern 1: Look for transcript patterns in JavaScript
            patterns = [
                r'"transcribed_text":\s*"([^"]+)"',
                r'transcript["\']?:\s*["\']([^"\'\
]+)["\']',
                r'"captions":\s*\[([^\]]+)\]',
                r'"transcript_segments":\s*\[([^\]]+)\]'
            ]
            
            for pattern in patterns:
                try:
                    match = re.search(pattern, content, re.IGNORECASE)
                    if match:
                        transcript_data = match.group(1)
                        # Clean up the transcript
                        return self._clean_transcript(transcript_data)
                except Exception as e:
                    log.debug(f"Pattern {pattern} failed: {e}")
                    continue
            
            # Pattern 2: Look for JSON objects containing transcript
            json_pattern = r'\{[^}]*"transcript"[^}]*\}'
            json_matches = re.findall(json_pattern, content, re.IGNORECASE)
            
            for json_match in json_matches:
                try:
                    data = json.loads(json_match)
                    if 'transcript' in data:
                        return self._clean_transcript(data['transcript'])
                except:
                    continue
            
            return None
            
        except Exception as e:
            log.error(f"Error extracting transcript: {e}")
            return None
    
    def _clean_transcript(self, transcript: str) -> str:
        """Clean and format transcript text."""
        if not transcript:
            return ""
        
        # Remove escape characters
        transcript = transcript.replace('\\n', '\n').replace('\\t', ' ')
        
        # Remove extra whitespace
        transcript = re.sub(r'\s+', ' ', transcript)
        
        # Add line breaks for better readability
        transcript = re.sub(r'\. ', '.\n', transcript)
        
        return transcript.strip()
    
    def _extract_loom_id(self, url: str) -> Optional[str]:
        """Extract Loom video ID from URL."""
        # Loom URLs typically look like: https://www.loom.com/share/VIDEO_ID
        match = re.search(r'loom\.com/share/([a-zA-Z0-9]+)', url)
        if match:
            return match.group(1)
        return None
    
    async def _get_zoom_transcript(self, url: str) -> Optional[str]:
        """Extract transcript from Zoom recording."""
        try:
            # Zoom recordings might have transcript files or embedded captions
            async with self.session.get(url) as response:
                if response.status != 200:
                    return None
                
                content = await response.text()
                
                # Look for transcript or caption data
                transcript = self._extract_zoom_transcript(content)
                
                return transcript
                
        except Exception as e:
            log.error(f"Error getting Zoom transcript: {e}")
            return None
    
    def _extract_zoom_transcript(self, content: str) -> Optional[str]:
        """Extract transcript from Zoom page content."""
        try:
            # Look for various patterns that might contain transcript data
            patterns = [
                r'"transcript":\s*"([^"]+)"',
                r'"captions":\s*\[([^\]]+)\]',
                r'"subtitles":\s*"([^"]+)"'
            ]
            
            for pattern in patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    return self._clean_transcript(match.group(1))
            
            return None
            
        except Exception as e:
            log.error(f"Error extracting Zoom transcript: {e}")
            return None
    
    @vid_transcribe.command(name="platforms")
    async def list_platforms(self, ctx):
        """List supported platforms."""
        enabled = await self.config.enabled_platforms()
        all_platforms = ["loom", "zoom"]
        
        embed = discord.Embed(title="Video Transcription Platforms", color=0x00ff00)
        
        enabled_list = "\n".join([f"✅ {p.title()}" for p in enabled])
        disabled_list = "\n".join([f"❌ {p.title()}" for p in all_platforms if p not in enabled])
        
        if enabled_list:
            embed.add_field(name="Enabled", value=enabled_list, inline=True)
        if disabled_list:
            embed.add_field(name="Disabled", value=disabled_list, inline=True)
        
        await ctx.send(embed=embed)
    
    @vid_transcribe.command(name="enable")
    @commands.is_owner()
    async def enable_platform(self, ctx, platform: str):
        """Enable a platform for transcription."""
        platform = platform.lower()
        available_platforms = ["loom", "zoom"]
        
        if platform not in available_platforms:
            await ctx.send(f"❌ Unknown platform. Available: {', '.join(available_platforms)}")
            return
        
        enabled = await self.config.enabled_platforms()
        if platform not in enabled:
            enabled.append(platform)
            await self.config.enabled_platforms.set(enabled)
            await ctx.send(f"✅ {platform.title()} transcription enabled.")
        else:
            await ctx.send(f"ℹ️ {platform.title()} transcription is already enabled.")
    
    @vid_transcribe.command(name="disable")
    @commands.is_owner()
    async def disable_platform(self, ctx, platform: str):
        """Disable a platform for transcription."""
        platform = platform.lower()
        
        enabled = await self.config.enabled_platforms()
        if platform in enabled:
            enabled.remove(platform)
            await self.config.enabled_platforms.set(enabled)
            await ctx.send(f"❌ {platform.title()} transcription disabled.")
        else:
            await ctx.send(f"ℹ️ {platform.title()} transcription is already disabled.")
    
    @vid_transcribe.command(name="test")
    async def test_transcript(self, ctx, url: str = None):
        """Test transcript extraction with a sample URL."""
        if not url:
            # Provide sample URLs for testing
            sample_urls = {
                "Loom": "https://www.loom.com/share/sample-video-id",
                "Zoom": "https://zoom.us/rec/share/sample-recording-id"
            }
            
            embed = discord.Embed(title="Test Transcript Extraction", color=0x0099ff)
            embed.description = "Use `!vidtranscribe test <url>` with one of these sample formats:"
            
            for platform, sample_url in sample_urls.items():
                embed.add_field(name=platform, value=f"`{sample_url}`", inline=False)
            
            await ctx.send(embed=embed)
            return
        
        # Test the provided URL
        platform = self._detect_platform(url)
        if platform:
            await ctx.send(f"🔍 Detected platform: {platform.title()}")
            await self.get_transcript(ctx, url)
        else:
            await ctx.send("❌ Could not detect platform from URL.")
    
    @vid_transcribe.command(name="info")
    async def transcript_info(self, ctx):
        """Show information about the transcript cog."""
        embed = discord.Embed(
            title="Video Transcript Extractor",
            description="Extract transcripts from video platforms",
            color=0x00ff00
        )
        
        embed.add_field(
            name="Supported Platforms",
            value="• Loom\n• Zoom",
            inline=True
        )
        
        embed.add_field(
            name="Commands",
            value="• `transcript <url>` - Get transcript\n• `platforms` - List platforms\n• `test` - Test extraction",
            inline=True
        )
        
        embed.add_field(
            name="Usage",
            value="Simply provide a video URL and the bot will attempt to extract the transcript.",
            inline=False
        )
        
        await ctx.send(embed=embed)
    
    async def _download_transcript_file(self, url: str) -> Optional[str]:
        """Download transcript file if available."""
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    content = await response.text()
                    return content
        except Exception as e:
            log.error(f"Error downloading transcript file: {e}")
        return None
    
    def _parse_vtt_content(self, content: str) -> str:
        """Parse VTT (WebVTT) subtitle content."""
        lines = content.split('\n')
        transcript_lines = []
        
        for line in lines:
            line = line.strip()
            # Skip VTT headers, timestamps, and empty lines
            if (line and 
                not line.startswith('WEBVTT') and 
                not line.startswith('NOTE') and 
                not '-->' in line and 
                not line.isdigit()):
                transcript_lines.append(line)
        
        return ' '.join(transcript_lines)
    
    def _parse_srt_content(self, content: str) -> str:
        """Parse SRT subtitle content."""
        lines = content.split('\n')
        transcript_lines = []
        
        for line in lines:
            line = line.strip()
            # Skip SRT sequence numbers, timestamps, and empty lines
            if (line and 
                not line.isdigit() and 
                not '-->' in line):
                transcript_lines.append(line)
        
        return ' '.join(transcript_lines)
    
    async def _search_for_transcript_urls(self, content: str, base_url: str) -> Optional[str]:
        """Search for transcript file URLs in page content."""
        # Common transcript file extensions and patterns
        transcript_patterns = [
            r'([^"\s]+\.vtt)',
            r'([^"\s]+\.srt)',
            r'([^"\s]+transcript[^"\s]*)',
            r'([^"\s]+caption[^"\s]*)',
            r'([^"\s]+subtitle[^"\s]*)'
        ]
        
        for pattern in transcript_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                # Try to download and parse the file
                if not match.startswith('http'):
                    # Construct full URL
                    from urllib.parse import urljoin
                    match = urljoin(base_url, match)
                
                transcript_content = await self._download_transcript_file(match)
                if transcript_content:
                    if match.endswith('.vtt'):
                        return self._parse_vtt_content(transcript_content)
                    elif match.endswith('.srt'):
                        return self._parse_srt_content(transcript_content)
                    else:
                        return transcript_content
        
        return None
    
    @vid_transcribe.command(name="debug")
    @commands.is_owner()
    async def debug_transcript(self, ctx, url: str):
        """Debug transcript extraction process."""
        try:
            platform = self._detect_platform(url)
            await ctx.send(f"**Platform detected:** {platform or 'Unknown'}")
            
            if not platform:
                return
            
            # Fetch page content
            async with self.session.get(url) as response:
                status = response.status
                content = await response.text()
                
            await ctx.send(f"**HTTP Status:** {status}")
            await ctx.send(f"**Content Length:** {len(content)} characters")
            
            # Show a preview of the content
            preview = content[:500]
            await ctx.send(f"**Content Preview:**\n{box(preview)}")
            
            # Try to extract transcript
            if platform == "loom":
                transcript = self._extract_transcript_from_content(content)
            elif platform == "zoom":
                transcript = self._extract_zoom_transcript(content)
            
            if transcript:
                preview_transcript = transcript[:200]
                await ctx.send(f"**Transcript Found:**\n{box(preview_transcript)}")
            else:
                await ctx.send("**No transcript found**")
                
        except Exception as e:
            await ctx.send(f"**Debug Error:** {str(e)}")

def setup(bot: Red):
    """Load the VidTranscribe cog."""
    bot.add_cog(VidTranscribe(bot))

async def teardown(bot: Red):
    """Unload the VidTranscribe cog."""
    cog = bot.get_cog("VidTranscribe")
    if cog:
        await cog.cog_unload()