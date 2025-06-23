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

# Optional imports for audio transcription
try:
    import yt_dlp
    YT_DLP_AVAILABLE = True
except ImportError:
    YT_DLP_AVAILABLE = False

try:
    import whisper
    WHISPER_AVAILABLE = True
except ImportError:
    WHISPER_AVAILABLE = False

# For automatic dependency installation
try:
    import subprocess
    import sys
    SUBPROCESS_AVAILABLE = True
except ImportError:
    SUBPROCESS_AVAILABLE = False

log = logging.getLogger("red.cogs.vid_transcribe")

class VidTranscribe(commands.Cog):
    """A cog for transcribing videos from various platforms."""
    
    def __init__(self, bot: Red):
        self.bot = bot
        self.config = Config.get_conf(self, identifier=1234567890)
        default_global = {
            "api_keys": {
                "openai": None,
                "google_speech": None,
                "azure_speech": None
            },
            "enabled_platforms": ["loom", "zoom"],
            "transcription_service": "whisper",  # whisper, openai_api, google, azure
            "audio_transcription_enabled": True,
            "max_audio_duration_minutes": 0,  # 0 = no limit, use chunking for long videos
            "chunk_duration_minutes": 30,  # Process in chunks for long videos
            "save_transcripts": True,
            "transcript_directory": "./transcripts/",
            "audio_quality": "worst",  # worst, best - for resource efficiency
            "cleanup_temp_files": True
        }
        self.config.register_global(**default_global)
        self.session = None
        self.whisper_model = None
        
    async def cog_load(self):
        """Initialize the cog."""
        self.session = aiohttp.ClientSession()
        
        # Load Whisper model if available and enabled
        if WHISPER_AVAILABLE and await self.config.audio_transcription_enabled():
            try:
                # Use small model for efficiency
                self.whisper_model = whisper.load_model("base")
                log.info("Whisper model loaded successfully")
            except Exception as e:
                log.warning(f"Failed to load Whisper model: {e}")
        
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
                transcript = await self._get_loom_transcript(ctx, url)
            elif platform == "zoom":
                transcript = await self._get_zoom_transcript(ctx, url)
            else:
                await ctx.send("❌ Platform not implemented yet.")
                return
            
            if transcript:
                # Save transcript if enabled
                if await self.config.save_transcripts():
                    await self._save_transcript_file(transcript, url, platform)
                
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
    
    async def _get_loom_transcript(self, ctx, url: str) -> Optional[str]:
        """Extract transcript from Loom video with fallback to audio transcription."""
        try:
            # Step 1: Try to get embedded transcript
            video_id = self._extract_loom_id(url)
            if not video_id:
                return None
            
            transcript = await self._fetch_loom_transcript_from_page(url)
            
            if transcript:
                return transcript
            
            # Step 2: Fallback to audio transcription if enabled
            if await self.config.audio_transcription_enabled():
                await ctx.send("📝 No embedded transcript found. Attempting audio transcription...")
                return await self._transcribe_audio_from_url(ctx, url)
            
            return None
            
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
                r'transcript["\']?:\s*["\']([^"\']*).*["\']',
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
    
    async def _transcribe_audio_from_url(self, ctx, url: str) -> Optional[str]:
        """Transcribe audio from video URL using efficient methods."""
        if not YT_DLP_AVAILABLE:
            await ctx.send("⚠️ Audio transcription requires yt-dlp. Install with: `pip install yt-dlp`")
            return None
        
        temp_audio_file = None
        try:
            # Get video duration for processing strategy
            duration = await self._get_video_duration(url)
            max_duration = await self.config.max_audio_duration_minutes()
            chunk_duration = await self.config.chunk_duration_minutes()
            
            # Check if we need chunked processing
            if duration and max_duration > 0 and duration > max_duration * 60:
                await ctx.send(f"⚠️ Video too long ({duration//60:.1f} min). Max allowed: {max_duration} min")
                return None
            elif duration and duration > chunk_duration * 60:
                # Use chunked processing for long videos
                return await self._transcribe_audio_chunked(ctx, url, duration)
            
            await ctx.send("🎵 Downloading audio (audio only, not full video)...")
            
            # Download only audio (much more efficient than full video)
            temp_audio_file = await self._download_audio_only(url)
            
            if not temp_audio_file:
                return None
            
            await ctx.send("🤖 Transcribing speech to text...")
            
            # Transcribe using available service
            transcript = await self._transcribe_audio_file(temp_audio_file)
            
            return transcript
            
        except Exception as e:
            log.error(f"Audio transcription failed: {e}")
            await ctx.send(f"❌ Audio transcription failed: {str(e)}")
            return None
        finally:
            # Clean up temp files
            if temp_audio_file and await self.config.cleanup_temp_files():
                try:
                    os.unlink(temp_audio_file)
                except:
                    pass
    
    async def _transcribe_audio_chunked(self, ctx, url: str, total_duration: float) -> Optional[str]:
        """Transcribe long videos by processing them in chunks."""
        try:
            chunk_duration = await self.config.chunk_duration_minutes() * 60  # Convert to seconds
            total_chunks = int((total_duration + chunk_duration - 1) // chunk_duration)  # Ceiling division
            
            await ctx.send(f"📹 Processing long video ({total_duration//60:.1f} min) in {total_chunks} chunks...")
            
            all_transcripts = []
            temp_files = []
            
            try:
                for chunk_num in range(total_chunks):
                    start_time = chunk_num * chunk_duration
                    end_time = min((chunk_num + 1) * chunk_duration, total_duration)
                    
                    # Initial progress
                    overall_progress = (chunk_num / total_chunks) * 100
                    progress_msg = f"🔄 Processing chunk {chunk_num + 1}/{total_chunks} ({start_time//60:.0f}-{end_time//60:.0f} min) - {overall_progress:.0f}% complete"
                    await ctx.send(progress_msg)
                    
                    # Download phase with progress
                    download_progress = overall_progress + (0.3 / total_chunks) * 100  # 30% of chunk for download
                    await ctx.send(f"⬇️ Downloading audio chunk {chunk_num + 1}... ({download_progress:.0f}% overall)")
                    
                    chunk_file = await self._download_audio_chunk(url, start_time, end_time - start_time, ctx)
                    if not chunk_file:
                        await ctx.send(f"⚠️ Failed to download chunk {chunk_num + 1}, skipping...")
                        continue
                    
                    temp_files.append(chunk_file)
                    
                    # Transcription phase with progress
                    transcribe_progress = overall_progress + (0.7 / total_chunks) * 100  # 70% of chunk for transcription
                    await ctx.send(f"🤖 Transcribing chunk {chunk_num + 1}... ({transcribe_progress:.0f}% overall)")
                    
                    chunk_transcript = await self._transcribe_audio_file(chunk_file)
                    if chunk_transcript:
                        # Add timestamp info
                        timestamp_header = f"\n\n--- Chunk {chunk_num + 1} ({start_time//60:.0f}:{start_time%60:02.0f} - {end_time//60:.0f}:{end_time%60:02.0f}) ---\n"
                        all_transcripts.append(timestamp_header + chunk_transcript)
                    
                    # Completion progress
                    completion_progress = ((chunk_num + 1) / total_chunks) * 100
                    await ctx.send(f"✅ Chunk {chunk_num + 1} completed! ({completion_progress:.0f}% done - {total_chunks - chunk_num - 1} chunks remaining)")
                
                if all_transcripts:
                    final_transcript = "\n".join(all_transcripts)
                    await ctx.send(f"🎉 Transcription completed! Processed {len(all_transcripts)} chunks.")
                    return final_transcript
                else:
                    await ctx.send("❌ No chunks were successfully transcribed.")
                    return None
                    
            finally:
                # Clean up all temp chunk files
                if await self.config.cleanup_temp_files():
                    for temp_file in temp_files:
                        try:
                            os.unlink(temp_file)
                        except:
                            pass
                            
        except Exception as e:
            log.error(f"Chunked transcription failed: {e}")
            await ctx.send(f"❌ Chunked transcription failed: {str(e)}")
            return None
    
    async def _download_audio_chunk(self, url: str, start_time: float, duration: float, ctx=None) -> Optional[str]:
        """Download a specific time segment of audio with progress tracking."""
        try:
            temp_dir = tempfile.gettempdir()
            audio_quality = await self.config.audio_quality()
            
            # Generate unique filename for chunk
            chunk_filename = f"chunk_{int(start_time)}_{int(duration)}.m4a"
            output_path = os.path.join(temp_dir, chunk_filename)
            
            # Progress tracking variables
            last_progress = 0
            
            def progress_hook(d):
                nonlocal last_progress
                if d['status'] == 'downloading' and ctx:
                    try:
                        if 'downloaded_bytes' in d and 'total_bytes' in d:
                            progress = (d['downloaded_bytes'] / d['total_bytes']) * 100
                            # Only send updates every 25% to avoid spam
                            if progress - last_progress >= 25:
                                asyncio.create_task(ctx.send(f"📥 Download progress: {progress:.0f}%"))
                                last_progress = progress
                    except:
                        pass  # Ignore progress errors
            
            # Configure yt-dlp for chunk download with time range
            ydl_opts = {
                'format': f'bestaudio[ext=m4a]/{audio_quality}audio',
                'outtmpl': output_path,
                'quiet': True,
                'no_warnings': True,
                'progress_hooks': [progress_hook],
                'postprocessors': [{
                    'key': 'FFmpegExtractAudio',
                    'preferredcodec': 'm4a',
                }],
                'postprocessor_args': [
                    '-ss', str(start_time),
                    '-t', str(duration)
                ]
            }
            
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                ydl.download([url])
                
            if os.path.exists(output_path):
                return output_path
            else:
                return None
                
        except Exception as e:
            log.error(f"Failed to download audio chunk: {e}")
            return None
    
    async def _get_video_duration(self, url: str) -> Optional[float]:
        """Get video duration without downloading."""
        try:
            ydl_opts = {
                'quiet': True,
                'no_warnings': True,
            }
            
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                info = ydl.extract_info(url, download=False)
                return info.get('duration')
        except:
            return None
    
    async def _download_audio_only(self, url: str) -> Optional[str]:
        """Download only audio track (much more efficient than full video)."""
        try:
            temp_dir = tempfile.gettempdir()
            audio_quality = await self.config.audio_quality()
            
            # Configure yt-dlp for audio-only download
            ydl_opts = {
                'format': f'bestaudio[ext=m4a]/{audio_quality}audio',  # Audio only
                'outtmpl': os.path.join(temp_dir, '%(title)s.%(ext)s'),
                'quiet': True,
                'no_warnings': True,
                'extractaudio': True,
                'audioformat': 'wav',  # Convert to WAV for Whisper
                'audioquality': '192K' if audio_quality == 'best' else '96K',
            }
            
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                info = ydl.extract_info(url, download=True)
                
                # Find the downloaded file
                filename = ydl.prepare_filename(info)
                # yt-dlp might change extension to .wav
                wav_filename = os.path.splitext(filename)[0] + '.wav'
                
                if os.path.exists(wav_filename):
                    return wav_filename
                elif os.path.exists(filename):
                    return filename
                
            return None
            
        except Exception as e:
            log.error(f"Audio download failed: {e}")
            return None
    
    async def _transcribe_audio_file(self, audio_file: str) -> Optional[str]:
        """Transcribe audio file using available service."""
        service = await self.config.transcription_service()
        
        if service == "whisper" and WHISPER_AVAILABLE and self.whisper_model:
            return await self._transcribe_with_whisper(audio_file)
        elif service == "openai_api":
            return await self._transcribe_with_openai_api(audio_file)
        else:
            log.error(f"Transcription service '{service}' not available")
            return None
    
    async def _transcribe_with_whisper(self, audio_file: str) -> Optional[str]:
        """Transcribe using local Whisper model."""
        try:
            # Run in executor to avoid blocking
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None, 
                lambda: self.whisper_model.transcribe(audio_file)
            )
            
            return result['text'].strip()
            
        except Exception as e:
            log.error(f"Whisper transcription failed: {e}")
            return None
    
    async def _transcribe_with_openai_api(self, audio_file: str) -> Optional[str]:
        """Transcribe using OpenAI API (requires API key)."""
        try:
            api_key = await self.config.api_keys.openai()
            if not api_key:
                log.error("OpenAI API key not configured")
                return None
            
            # Implementation would go here
            # This is a placeholder for OpenAI API integration
            log.warning("OpenAI API transcription not yet implemented")
            return None
            
        except Exception as e:
            log.error(f"OpenAI API transcription failed: {e}")
            return None
    
    async def _save_transcript_file(self, transcript: str, url: str, platform: str):
        """Save transcript to a .txt file."""
        try:
            transcript_dir = await self.config.transcript_directory()
            os.makedirs(transcript_dir, exist_ok=True)
            
            # Generate filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            video_id = self._extract_video_id(url, platform)
            filename = f"{platform}_{video_id}_{timestamp}.txt"
            filepath = os.path.join(transcript_dir, filename)
            
            # Save transcript
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(f"Video URL: {url}\n")
                f.write(f"Platform: {platform.title()}\n")
                f.write(f"Transcribed: {datetime.now().isoformat()}\n")
                f.write("\n" + "="*50 + "\n\n")
                f.write(transcript)
            
            log.info(f"Transcript saved to: {filepath}")
            
        except Exception as e:
            log.error(f"Failed to save transcript: {e}")
    
    def _extract_video_id(self, url: str, platform: str) -> str:
        """Extract video ID for filename."""
        if platform == "loom":
            return self._extract_loom_id(url) or "unknown"
        elif platform == "zoom":
            # Extract Zoom meeting ID or recording ID
            match = re.search(r'[a-zA-Z0-9._-]+', url.split('/')[-1])
            return match.group(0) if match else "unknown"
        return "unknown"
    
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
    
    async def _get_zoom_transcript(self, ctx, url: str) -> Optional[str]:
        """Extract transcript from Zoom video with fallback to audio transcription."""
        try:
            # Try embedded transcript first
            async with self.session.get(url) as response:
                if response.status != 200:
                    return None
                
                content = await response.text()
                transcript = self._extract_zoom_transcript(content)
                
                if transcript:
                    return transcript
                
                # Fallback to audio transcription if enabled
                if await self.config.audio_transcription_enabled():
                    await ctx.send("📝 No embedded transcript found. Attempting audio transcription...")
                    return await self._transcribe_audio_from_url(ctx, url)
                
                return None
                
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
    
    @vid_transcribe.command(name="config")
    @commands.is_owner()
    async def show_config(self, ctx):
        """Show current transcription configuration."""
        config = await self.config.all()
        
        embed = discord.Embed(title="VidTranscribe Configuration", color=0x0099ff)
        
        # Audio transcription status
        audio_enabled = config['audio_transcription_enabled']
        embed.add_field(
            name="Audio Transcription", 
            value="✅ Enabled" if audio_enabled else "❌ Disabled",
            inline=True
        )
        
        # Available services
        services = []
        if WHISPER_AVAILABLE:
            services.append("Whisper (Local)")
        if config['api_keys']['openai']:
            services.append("OpenAI API")
        
        embed.add_field(
            name="Available Services",
            value="\n".join(services) if services else "None",
            inline=True
        )
        
        # Current service
        embed.add_field(
            name="Current Service",
            value=config['transcription_service'].title(),
            inline=True
        )
        
        # Resource limits
        max_duration = config['max_audio_duration_minutes']
        duration_text = "No limit (chunked processing)" if max_duration == 0 else f"{max_duration} minutes"
        embed.add_field(
            name="Max Duration",
            value=duration_text,
            inline=True
        )
        
        embed.add_field(
            name="Chunk Size",
            value=f"{config['chunk_duration_minutes']} minutes",
            inline=True
        )
        
        embed.add_field(
            name="Audio Quality",
            value=config['audio_quality'].title(),
            inline=True
        )
        
        embed.add_field(
            name="Save Transcripts",
            value="✅ Yes" if config['save_transcripts'] else "❌ No",
            inline=True
        )
        
        await ctx.send(embed=embed)
    
    async def _install_dependency(self, package_name: str) -> bool:
        """Attempt to install a dependency using pip."""
        if not SUBPROCESS_AVAILABLE:
            return False
        
        try:
            # Use the same Python executable that's running the bot
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", package_name],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            return result.returncode == 0
        except Exception as e:
            log.error(f"Failed to install {package_name}: {e}")
            return False
    
    @vid_transcribe.command(name="install")
    @commands.is_owner()
    async def install_dependencies(self, ctx, auto_install: bool = True):
        """Install required dependencies for audio transcription."""
        global YT_DLP_AVAILABLE, WHISPER_AVAILABLE
        
        if not auto_install:
            await ctx.send("❌ Auto-installation disabled. Please install manually:\n"
                          "`pip install yt-dlp openai-whisper`")
            return
        
        if not SUBPROCESS_AVAILABLE:
            await ctx.send("❌ Cannot auto-install dependencies. Please install manually:\n"
                          "`pip install yt-dlp openai-whisper`")
            return
        
        embed = discord.Embed(title="Installing Audio Transcription Dependencies", color=0xffaa00)
        embed.description = "Installing required packages for audio transcription..."
        status_msg = await ctx.send(embed=embed)
        
        # Install yt-dlp
        if not YT_DLP_AVAILABLE:
            embed.add_field(name="📦 Installing yt-dlp", value="⏳ In progress...", inline=False)
            await status_msg.edit(embed=embed)
            
            success = await self._install_dependency("yt-dlp")
            if success:
                embed.set_field_at(-1, name="📦 Installing yt-dlp", value="✅ Installed successfully", inline=False)
                # Try to import after installation
                try:
                    import yt_dlp
                    YT_DLP_AVAILABLE = True
                except ImportError:
                    pass
            else:
                embed.set_field_at(-1, name="📦 Installing yt-dlp", value="❌ Installation failed", inline=False)
            
            await status_msg.edit(embed=embed)
        else:
            embed.add_field(name="📦 yt-dlp", value="✅ Already installed", inline=False)
            await status_msg.edit(embed=embed)
        
        # Install whisper
        if not WHISPER_AVAILABLE:
            embed.add_field(name="🤖 Installing OpenAI Whisper", value="⏳ In progress...", inline=False)
            await status_msg.edit(embed=embed)
            
            success = await self._install_dependency("openai-whisper")
            if success:
                embed.set_field_at(-1, name="🤖 Installing OpenAI Whisper", value="✅ Installed successfully", inline=False)
                # Try to import after installation
                try:
                    import whisper
                    WHISPER_AVAILABLE = True
                    # Load the model
                    self.whisper_model = whisper.load_model("base")
                except ImportError:
                    pass
            else:
                embed.set_field_at(-1, name="🤖 Installing OpenAI Whisper", value="❌ Installation failed", inline=False)
            
            await status_msg.edit(embed=embed)
        else:
            embed.add_field(name="🤖 OpenAI Whisper", value="✅ Already installed", inline=False)
            await status_msg.edit(embed=embed)
        
        # Final status
        if YT_DLP_AVAILABLE and WHISPER_AVAILABLE:
            embed.color = 0x00ff00
            embed.add_field(
                name="🎉 Installation Complete", 
                value="Audio transcription is now available! Use `!vt transcript <url>` to test.", 
                inline=False
            )
            # Enable audio transcription
            await self.config.audio_transcription_enabled.set(True)
        else:
            embed.color = 0xff0000
            embed.add_field(
                name="⚠️ Installation Issues", 
                value="Some dependencies failed to install. Please install manually:\n`pip install yt-dlp openai-whisper`", 
                inline=False
            )
        
        await status_msg.edit(embed=embed)
    
    @vid_transcribe.command(name="setup")
    @commands.is_owner()
    async def setup_transcription(self, ctx):
        """Setup audio transcription capabilities."""
        embed = discord.Embed(title="Audio Transcription Setup", color=0x00ff00)
        
        # Check dependencies
        deps = []
        if YT_DLP_AVAILABLE:
            deps.append("✅ yt-dlp (audio download)")
        else:
            deps.append("❌ yt-dlp - Missing")
        
        if WHISPER_AVAILABLE:
            deps.append("✅ whisper (local transcription)")
        else:
            deps.append("❌ whisper - Missing")
        
        embed.add_field(
            name="Dependencies Status",
            value="\n".join(deps),
            inline=False
        )
        
        # Auto-install option
        if not YT_DLP_AVAILABLE or not WHISPER_AVAILABLE:
            embed.add_field(
                name="🚀 Quick Setup",
                value="Use `!vt install` to automatically install missing dependencies",
                inline=False
            )
        
        # Manual setup instructions
        setup_text = """
        **Manual Installation:**
        ```
        pip install yt-dlp openai-whisper
        ```
        
        **For API-based Transcription:**
        1. Get OpenAI API key
        2. `!vt config openai_key YOUR_KEY`
        3. `!vt config service openai_api`
        """
        
        embed.add_field(
            name="Manual Setup Instructions",
            value=setup_text,
            inline=False
        )
        
        await ctx.send(embed=embed)
    
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
        
        # Add transcription capabilities
        audio_enabled = await self.config.audio_transcription_enabled()
        embed.add_field(
            name="Audio Transcription",
            value="✅ Available" if audio_enabled else "❌ Disabled",
            inline=False
        )
        
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
            description="Extract transcripts from video platforms with audio fallback",
            color=0x00ff00
        )
        
        embed.add_field(
            name="Supported Platforms",
            value="• Loom\n• Zoom",
            inline=True
        )
        
        embed.add_field(
            name="Transcription Methods",
            value="• Embedded transcripts\n• Audio transcription (fallback)",
            inline=True
        )
        
        embed.add_field(
            name="Commands",
            value="• `transcript <url>` - Get transcript\n• `platforms` - List platforms\n• `test` - Test extraction\n• `setup` - Setup guide\n• `install` - Auto-install dependencies",
            inline=False
        )
        
        embed.add_field(
            name="How it works",
            value="1. Tries to find embedded transcript\n2. Falls back to audio transcription\n3. Saves transcript as .txt file",
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
                
                # Show audio transcription availability
                audio_enabled = await self.config.audio_transcription_enabled()
                if audio_enabled and YT_DLP_AVAILABLE:
                    await ctx.send("**Audio transcription available as fallback**")
                else:
                    await ctx.send("**Audio transcription not available**")
                
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