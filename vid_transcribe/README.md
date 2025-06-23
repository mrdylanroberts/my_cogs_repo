# VidTranscribe

A Discord cog that extracts transcripts from Loom and Zoom video recordings and outputs them as downloadable text files.

## Features

- 🎥 **Multi-platform support**: Works with both Loom and Zoom recordings
- 📝 **Automatic transcript extraction**: Extracts closed captions and transcripts
- 💾 **File output**: Saves transcripts as downloadable .txt files
- 🔍 **Smart detection**: Automatically detects video platform from URL
- ⚡ **Easy to use**: Simple command interface
- 🔒 **Secure**: API credentials stored securely in bot config
- 🖥️ **VPS optimized**: Special installation and resource management for limited disk space environments
- 🧹 **Smart cleanup**: Automatic disk space monitoring and cleanup tools
- ⚙️ **Resource management**: Configurable settings for low-resource environments

## Supported Platforms

### Loom
- ✅ Public videos with transcript access enabled
- ✅ Shared videos (if transcript access is enabled)
- ❌ Private videos requiring authentication
- ❌ Videos without speech or transcript disabled

### Zoom
- ✅ Cloud recordings with transcript enabled
- ✅ Recordings with closed captions
- ❌ Local recordings
- ❌ Recordings without transcript/CC enabled

## Commands

### User Commands

- `!vid_transcribe <video_url>` - Extract transcript from video URL
- `!vid_help` - Show help information

### Owner Commands

- `!vidtranscribe_config` - Show configuration status
- `!vidtranscribe_config zoom <client_id> <client_secret> <account_id>` - Configure Zoom API
- `!vidtranscribe_config clear` - Clear all API credentials
- `!vt install` - Install dependencies (standard)
- `!vt install_vps` - Install dependencies (VPS optimized for limited disk space)
- `!vt cleanup` - Clean pip cache and temp files, show disk usage
- `!vt vpsmode <on/off>` - Configure optimal settings for VPS environments

## Setup

### Basic Installation

1. Install the cog:
   ```
   !cog install my-cogs-repo vid_transcribe
   !load vid_transcribe
   ```

2. **Standard Setup:**
   ```
   !vt install
   ```
   This will automatically install required dependencies (`yt-dlp` and `openai-whisper`) for audio transcription.

3. **VPS Setup (Limited Disk Space):**
   ```
   !vt cleanup
   !vt install_vps
   !vt vpsmode on
   ```
   This optimized installation:
   - Clears pip cache and temp files first
   - Installs CPU-only PyTorch (smaller size)
   - Uses minimal dependencies
   - Configures resource-efficient settings

4. The cog will work immediately for Loom videos (no setup required)

### Zoom API Setup (Optional)

To use Zoom transcript extraction, you need to set up a Zoom Server-to-Server OAuth app:

1. **Create a Zoom App**:
   - Go to [Zoom App Marketplace](https://marketplace.zoom.us/develop/create)
   - Click "Develop" → "Build App" → "Server-to-Server OAuth"
   - Fill in app details and activate the app

2. **Configure Scopes**:
   Add these scopes to your app:
   - `cloud_recording:read:list_user_recordings:admin`
   - `cloud_recording:read:list_recording_files:admin`

3. **Get Credentials**:
   - Copy your Account ID, Client ID, and Client Secret

4. **Configure the Bot**:
   ```
   !vidtranscribe_config zoom <client_id> <client_secret> <account_id>
   ```

## Usage Examples

### Loom Video
```
!vid_transcribe https://www.loom.com/share/7a73b4410c6743c6a6eecd98d0276be7
```

### Zoom Recording
```
!vid_transcribe https://zoom.us/rec/share/abc123def456
```

## Requirements

### For Loom Videos
- Video creator must enable transcript access in Loom settings:
  - Settings → Audience → Transcript → Toggle ON
- Video must be public or properly shared
- Video must contain speech

### For Zoom Videos
- Zoom Pro, Business, or Enterprise plan
- Cloud recording enabled (not local recording)
- Audio transcript or closed captions enabled in recording settings
- Zoom API credentials configured in bot

## Output Format

The cog generates clean text files with:
- Video platform and ID
- Generation timestamp
- Clean transcript text
- Automatic file naming with timestamp

## Troubleshooting

### Loom Issues

**"Could not extract transcript"**:
- Check if video creator enabled transcript access
- Verify video is public or properly shared
- Ensure video contains speech
- Try again later (transcripts may still be processing)

### Zoom Issues

**"Could not extract transcript"**:
- Verify Zoom API credentials are configured
- Check if recording has transcript/CC enabled
- Ensure you have proper API permissions
- Verify recording is fully processed

**"Zoom API credentials not configured"**:
- Set up Zoom Server-to-Server OAuth app
- Configure credentials using `!vidtranscribe_config zoom`

## Technical Details

### Dependencies
- `aiohttp` - HTTP requests
- `beautifulsoup4` - HTML parsing
- `requests` - HTTP requests (fallback)
- `yt-dlp` - Audio extraction from videos (auto-installed)
- `openai-whisper` - Audio transcription (auto-installed)
- `torch` - Machine learning backend (CPU-only for VPS)

### Data Storage
- Transcripts saved to `<bot_data>/vid_transcribe/transcripts/`
- API credentials stored in bot config (encrypted)
- Temporary audio chunks (auto-cleaned after processing)
- No permanent user data storage

### Resource Management
- **Disk monitoring**: Automatic tracking of available disk space
- **Smart cleanup**: Immediate removal of processed audio chunks
- **Low resource mode**: Uses smaller Whisper model ("tiny" vs "base")
- **VPS optimization**: CPU-only PyTorch, minimal dependencies
- **Configurable limits**: Max disk usage and chunk duration settings

### API Limitations

#### Loom
- Relies on public transcript access
- May be affected by Loom API changes
- Rate limiting may apply

#### Zoom
- Requires paid Zoom plan
- API rate limits apply
- Transcript processing delays possible

## Privacy & Security

- 🔒 API credentials encrypted in bot config
- 🚫 No permanent storage of user data
- 📁 Transcript files stored locally on bot server
- 🔄 Automatic cleanup of old transcript files (optional)

## Support

For issues or feature requests, please check:
1. Video platform requirements are met
2. API credentials are properly configured
3. Video contains speech and has transcripts enabled

Common issues are usually related to:
- Missing transcript access permissions
- Incorrect API configuration
- Videos still being processed
- Platform-specific limitations