import asyncio
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
        }

        self.DEFAULT_SENDERS_LIST = [
            "clint@tldrsec.com",
            "newsletter@unsupervised-learning.com",
            "dan@tldrnewsletter.com",
            "mike@mail.returnnonsecurity.com",
            "vulnu@vulnu.mattjay.com"
        ]
        
        self.config.register_guild(**default_guild)

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
    
    def extract_real_url_from_tracking(self, tracking_url: str) -> str:
        """Extract the real destination URL from a tracking URL."""
        try:
            # For TLDR tracking URLs, the real URL is encoded in the path
            if 'tracking.tldrnewsletter.com/CL0/' in tracking_url:
                # Extract the encoded URL part
                parts = tracking_url.split('/CL0/')
                if len(parts) > 1:
                    encoded_part = parts[1].split('/')[0]
                    # URL decode the encoded part
                    import urllib.parse
                    decoded_url = urllib.parse.unquote(encoded_part)
                    # Remove any remaining URL encoding
                    decoded_url = urllib.parse.unquote(decoded_url)
                    return decoded_url
            
            # For other tracking URLs with utm_source, try to find the original URL
            if 'utm_source' in tracking_url:
                # Remove UTM parameters
                base_url = tracking_url.split('?')[0]
                return base_url
            
            # If we can't extract, return the original URL
            return tracking_url
        except Exception as e:
            log.warning(f"Failed to extract real URL from tracking URL: {e}")
            return tracking_url

    def convert_html_to_text_with_links(self, html_content: str) -> str:
        """Convert HTML content to text while preserving inline links and filtering dangerous links."""
        if not html_content:
            return ""
        
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
                    r'opt.*out'
                ]
                
                # Convert links to text format with filtering
                for link in soup.find_all('a', href=True):
                    url = link.get('href')
                    text = link.get_text(strip=True)
                    
                    if text and url:
                        # Check if URL contains dangerous patterns
                        is_dangerous = any(re.search(pattern, url, re.IGNORECASE) for pattern in dangerous_patterns)
                        
                        if is_dangerous:
                            link.replace_with(f"{text} [LINK REMOVED FOR SECURITY]")
                        elif re.search(r'tracking\.tldrnewsletter\.com', url, re.IGNORECASE) and re.search(r'\(\d+\s*min(?:ute)?\s*read\)', text, re.IGNORECASE):
                            link.replace_with(f"{text} {url}")
                        else:
                            link.replace_with(f"{text} ({url})")
                    else:
                        link.decompose()
                
                # Handle line breaks for block elements before removing tags
                for br in soup.find_all('br'):
                    br.replace_with('\n')
                
                # Add line breaks after table rows
                for tr in soup.find_all('tr'):
                    tr.insert_after('\n')
                
                # Add spaces after table cells
                for td in soup.find_all(['td', 'th']):
                    td.insert_after(' ')
                
                # Add line breaks after block elements
                for block in soup.find_all(['div', 'p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6']):
                    block.insert_after('\n')
                
                # Get clean text (this automatically removes all HTML tags)
                text = soup.get_text(separator=' ', strip=True)
                
                # Clean up whitespace
                text = re.sub(r'[ \t]+', ' ', text)  # Multiple spaces/tabs to single space
                text = re.sub(r'\n[ \t]*\n', '\n\n', text)  # Clean paragraph breaks
                text = re.sub(r'\n{3,}', '\n\n', text)  # Max 2 consecutive newlines
                text = re.sub(r'^\s+|\s+$', '', text, flags=re.MULTILINE)  # Trim start/end whitespace per line
                
                # Remove zero-width non-joiners and other invisible characters
                text = text.replace('\u200c', '')
                text = text.replace('\u200b', '')  # Zero-width space
                text = text.replace('\ufeff', '')  # Byte order mark
                
                return text.strip()
            
            else:
                # Fallback to regex-based processing if BeautifulSoup is not available
                # Remove CSS styles and script tags completely
                html_content = re.sub(r'<style[^>]*>.*?</style>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
                html_content = re.sub(r'<script[^>]*>.*?</script>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
                
                # Remove HTML comments
                html_content = re.sub(r'<!--.*?-->', '', html_content, flags=re.DOTALL)
                
                # Remove DOCTYPE and HTML structure tags
                html_content = re.sub(r'<!DOCTYPE[^>]*>', '', html_content, flags=re.IGNORECASE)
                html_content = re.sub(r'</?html[^>]*>', '', html_content, flags=re.IGNORECASE)
                html_content = re.sub(r'</?head[^>]*>', '', html_content, flags=re.IGNORECASE)
                html_content = re.sub(r'</?body[^>]*>', '', html_content, flags=re.IGNORECASE)
                
                # Remove meta tags and other head elements
                html_content = re.sub(r'<meta[^>]*>', '', html_content, flags=re.IGNORECASE)
                html_content = re.sub(r'<title[^>]*>.*?</title>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
                
                # Remove hidden content and email artifacts
                html_content = re.sub(r'<div[^>]*display:\s*none[^>]*>.*?</div>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
                html_content = re.sub(r'<div[^>]*max-height:\s*0[^>]*>.*?</div>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
                html_content = re.sub(r'<div[^>]*overflow:\s*hidden[^>]*>.*?</div>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
                
                # Define dangerous patterns for link filtering
                dangerous_patterns = [
                    r'unsubscribe',
                    r'manage.*subscription',
                    r'email.*forward',
                    r'opt.*out'
                ]
                
                # Convert <a href="url">text</a> to Discord markdown format with filtering
                # Handle nested tags within links properly
                def replace_link(match):
                    try:
                        url = match.group(1)
                        inner_content = match.group(2)
                        
                        # Remove HTML tags from inner content
                        clean_text = re.sub(r'<[^>]+>', '', inner_content)
                        clean_text = html.unescape(clean_text.strip())
                        
                        # Check if URL contains dangerous patterns
                        for pattern in dangerous_patterns:
                            if re.search(pattern, url, re.IGNORECASE):
                                return f"{clean_text} [LINK REMOVED FOR SECURITY]"
                        
                        # Handle paginated links with reading time
                        # Pattern: Title (Page X) (Y minute read)
                        page_time_pattern = r'^(.*?)\s*\(Page\s+(\d+)\)\s*\((\d+)\s+minute\s+read\)\s*$'
                        page_time_match = re.match(page_time_pattern, clean_text, re.IGNORECASE)
                        
                        if page_time_match:
                            title = page_time_match.group(1).strip()
                            page_num = page_time_match.group(2)
                            minutes = page_time_match.group(3)
                            
                            # Format as: **[Title (Page X)](URL)** (Y minute read)
                            return f"**[{title} (Page {page_num})]({url})** ({minutes} minute read)"
                        
                        # Handle regular reading time links
                        # Pattern: Title (X minute read)
                        time_pattern = r'^(.*?)\s*\((\d+)\s+minute\s+read\)\s*$'
                        time_match = re.match(time_pattern, clean_text, re.IGNORECASE)
                        
                        if time_match:
                            title = time_match.group(1).strip()
                            minutes = time_match.group(2)
                            
                            # Format as: **[Title](URL)** (X minute read)
                            return f"**[{title}]({url})** ({minutes} minute read)"
                        
                        # Handle tracking URLs - extract the real URL and make them bold
                        if 'tracking.tldrnewsletter.com' in url or 'utm_source' in url:
                            # Extract the real URL from tracking URL
                            real_url = self.extract_real_url_from_tracking(url)
                            return f"**[{clean_text}]({real_url})**"
                        
                        # Regular links
                        return f"[{clean_text}]({url})"
                    except Exception as e:
                        log.warning(f"Error in replace_link function: {e}")
                        # Return original match if there's an error
                        return match.group(0)
                
                html_content = re.sub(r'<a[^>]*href=["\']([^"\'>]+)["\'][^>]*>(.*?)</a>', 
                                    replace_link, html_content, flags=re.IGNORECASE | re.DOTALL)
                
                # Handle table structures - convert to readable text
                # First add line breaks after table rows for better readability
                html_content = re.sub(r'</tr>', '\n', html_content, flags=re.IGNORECASE)
                html_content = re.sub(r'</td>', ' ', html_content, flags=re.IGNORECASE)
                html_content = re.sub(r'</th>', ' ', html_content, flags=re.IGNORECASE)
                
                # Remove all table structure tags completely
                table_tags = ['table', 'tbody', 'thead', 'tfoot', 'tr', 'td', 'th']
                for tag in table_tags:
                    html_content = re.sub(f'</?{tag}[^>]*>', '', html_content, flags=re.IGNORECASE)
                
                # Add line breaks for block elements
                block_elements = ['div', 'p', 'br', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6']
                for element in block_elements:
                    html_content = re.sub(f'</?{element}[^>]*>', '\n', html_content, flags=re.IGNORECASE)
                
                # Remove all remaining HTML tags
                html_content = re.sub(r'<[^>]+>', '', html_content)
                
                # Decode HTML entities
                html_content = html.unescape(html_content)
                
                # Clean up extra whitespace while preserving structure
                # First normalize line breaks
                html_content = re.sub(r'\r\n|\r', '\n', html_content)
                
                # Remove CSS property patterns and inline styles that might leak through
                html_content = re.sub(r'[a-z-]+:\s*[^;\n]+;?', '', html_content, flags=re.IGNORECASE)
                html_content = re.sub(r'\{[^}]*\}', '', html_content)
                html_content = re.sub(r'style="[^"]*"', '', html_content, flags=re.IGNORECASE)
                
                # Remove common email artifacts and metadata
                html_content = re.sub(r'From\s+[^\n]*@[^\n]*', '', html_content)
                html_content = re.sub(r'Date\s+[^\n]*', '', html_content)
                html_content = re.sub(r'Page \d+ of \d+[^\n]*', '', html_content)
                
                # Clean up excessive whitespace but preserve paragraph breaks
                html_content = re.sub(r'[ \t]+', ' ', html_content)  # Multiple spaces/tabs to single space
                html_content = re.sub(r'\n[ \t]*\n', '\n\n', html_content)  # Clean paragraph breaks
                html_content = re.sub(r'\n{3,}', '\n\n', html_content)  # Max 2 consecutive newlines
                html_content = re.sub(r'^\s+|\s+$', '', html_content)  # Trim start/end whitespace
                
                return html_content.strip()
        except Exception as e:
            log.warning(f"Failed to convert HTML to text: {e}")
            return html_content

    def enhance_reading_time_indicators(self, content: str) -> str:
        """Enhance content by making reading time indicators clickable hyperlinks."""
        if not content:
            return content
        
        # Pattern to find reading time indicators with tracking URLs
        # This looks for text with (X min read) followed by a tracking URL
        reading_time_with_url_pattern = r'([^\n]*?)\s*\((\d+)\s*min(?:ute)?\s*read\)\s+(https?://tracking\.tldrnewsletter\.com[^\s]+)'
        
        def enhance_reading_time_with_url(match):
            title = match.group(1).strip()
            minutes = match.group(2)
            url = match.group(3)
            
            # Create a clickable link with proper spacing
            return f'\n\n**{title}** [({minutes} min read)]({url})\n'
        
        # Apply the enhancement for reading time links with URLs
        content = re.sub(reading_time_with_url_pattern, enhance_reading_time_with_url, content, flags=re.IGNORECASE)
        
        # Pattern to find standalone reading time indicators without URLs
        standalone_reading_time_pattern = r'([^\n]*?)\s*\((\d+)\s*min(?:ute)?\s*read\)(?!\s+https?)'
        
        def enhance_standalone_reading_time(match):
            title = match.group(1).strip()
            minutes = match.group(2)
            
            # Format as bold title with plain reading time and proper spacing
            return f'\n\n**{title}** ({minutes} min read)\n'
        
        # Apply the enhancement for standalone reading time indicators
        content = re.sub(standalone_reading_time_pattern, enhance_standalone_reading_time, content, flags=re.IGNORECASE)
        
        return content
    
    def convert_text_links_to_discord_format(self, content: str) -> str:
        """Convert text with URLs to Discord markdown links."""
        if not content:
            return content
        
        # Pattern 1: text followed by URL in parentheses: "text (https://example.com)"
        link_pattern_parens = r'([^\n\(]+?)\s*\(([https?://][^\)\s]+)\)'
        
        # Pattern 2: reading time followed by URL: "(X minute read) https://example.com"
        reading_time_pattern = r'(\([^\)]*minute read\))\s+(https?://[^\s]+)'
        
        # Pattern 3: title followed by reading time and URL: "Title (X minute read) https://example.com"
        title_reading_time_pattern = r'([^\n]*?)\s+(\([^\)]*minute read\))\s+(https?://[^\s]+)'
        
        def convert_reading_time_link(match):
            reading_time = match.group(1).strip()
            url = match.group(2).strip()
            return f'[{reading_time}]({url})'
        
        def convert_title_reading_time_link(match):
            title = match.group(1).strip()
            reading_time = match.group(2).strip()
            url = match.group(3).strip()
            return f'**[{title}]({url})** {reading_time}'
        
        def convert_to_markdown_link(match):
            text = match.group(1).strip()
            url = match.group(2).strip()
            return f'[{text}]({url})'
        
        # Apply conversions in order of specificity
        content = re.sub(title_reading_time_pattern, convert_title_reading_time_link, content)
        content = re.sub(reading_time_pattern, convert_reading_time_link, content)
        content = re.sub(link_pattern_parens, convert_to_markdown_link, content)
        
        return content
    
    def clean_email_content(self, content: str) -> str:
        """Clean and format email content for Discord while preserving inline links."""
        if not content:
            return "No content available"
        
        # Remove excessive whitespace and normalize line breaks
        content = re.sub(r'\n\s*\n\s*\n+', '\n\n', content)
        content = re.sub(r'[ \t]+', ' ', content)
        
        # Remove common email artifacts
        content = re.sub(r'‌+', '', content)  # Remove zero-width non-joiners
        
        # DON'T remove reference numbers like [1], [2] as they may be linked to URLs
        # Instead, preserve them to maintain link context
        
        # Clean up excessive spacing
        content = re.sub(r'\n{3,}', '\n\n', content)
        content = content.strip()
        
        return content

    def split_content_for_pagination(self, content: str, max_length: int = 1900) -> List[str]:
        """Split content into chunks for pagination while preserving readability."""
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
                
                # If the paragraph itself is too long, split it by sentences
                if len(paragraph) > max_length:
                    sentences = re.split(r'(?<=[.!?])\s+', paragraph)
                    for sentence in sentences:
                        if len(current_chunk) + len(sentence) + 1 > max_length:
                            if current_chunk:
                                chunks.append(current_chunk.strip())
                                current_chunk = ""
                        current_chunk += sentence + " "
                else:
                    current_chunk = paragraph
            else:
                if current_chunk:
                    current_chunk += "\n\n" + paragraph
                else:
                    current_chunk = paragraph
        
        if current_chunk:
            chunks.append(current_chunk.strip())
        
        return chunks if chunks else [content[:max_length]]

    def cog_unload(self):
        if self.email_check_task:
            self.email_check_task.cancel()

    async def initialize_encryption(self, guild_id: int) -> None:
        """Initialize encryption key using guild ID as salt (optional)."""
        if not self.encryption_key:
            try:
                tokens = await self.bot.get_shared_api_tokens("email_news")
                if "secret" not in tokens:
                    # No encryption key set - encryption is optional
                    log.info("No encryption key set. Credentials will be stored in plain text. Use '!set api email_news secret,<your-secret-key>' to enable encryption.")
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

    def encrypt_credentials(self, email: str, password: str) -> Dict[str, str]:
        """Encrypt email credentials (if encryption is enabled)."""
        if self.encryption_key:
            encrypted_email = self.encryption_key.encrypt(email.encode()).decode()
            encrypted_password = self.encryption_key.encrypt(password.encode()).decode()
            return {"email": encrypted_email, "password": encrypted_password, "encrypted": True}
        else:
            # Store in plain text if no encryption key is set
            return {"email": email, "password": password, "encrypted": False}

    def decrypt_credentials(self, stored_data: Dict[str, str]) -> Dict[str, str]:
        """Decrypt email credentials (if they were encrypted)."""
        if stored_data.get("encrypted", True):  # Default to True for backward compatibility
            if not self.encryption_key:
                raise ValueError("Credentials are encrypted but no encryption key is available. Set encryption key with '!set api email_news secret,<your-secret-key>'")
            email = self.encryption_key.decrypt(stored_data["email"].encode()).decode()
            password = self.encryption_key.decrypt(stored_data["password"].encode()).decode()
            return {"email": email, "password": password}
        else:
            # Credentials are stored in plain text
            return {"email": stored_data["email"], "password": stored_data["password"]}

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
        """Check for new emails and forward them to appropriate channels."""
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

                log.info("Searching for unseen emails...")
                status, messages = await imap_client.search("(UNSEEN)")
                if status == 'OK':
                    message_numbers = messages[0].split()
                    log.info(f"IMAP search returned: {messages[0]}")
                    log.info(f"Found {len(message_numbers)} email(s).")
                else:
                    log.error(f"IMAP search failed with status: {status}. Response: {messages}")
                    message_numbers = []

                for num in message_numbers:
                    try:
                        # Fetch the email by its ID
                        decoded_num_str = num.decode('utf-8')
                        typ, msg_data = await imap_client.fetch(decoded_num_str, '(RFC822)')
                        
                        log.debug(f"Full msg_data for {decoded_num_str}: {str(msg_data)[:1000]}...") # Log first 1000 chars
                        log.debug(f"Type of msg_data: {type(msg_data)}")
                        email_body = None 

                        if not msg_data or not isinstance(msg_data, list) or len(msg_data) == 0:
                            log.error(f"Unexpected or empty msg_data for email {decoded_num_str}. Full msg_data: {str(msg_data)[:1000]}")
                            continue

                        # Handle flat list structure with bytes or bytearray
                        if len(msg_data) >= 2 and isinstance(msg_data[0], bytes) and isinstance(msg_data[1], (bytes, bytearray)):
                            if b"RFC822" in msg_data[0]:
                                log.debug(f"Detected flat list structure for {decoded_num_str}. msg_data[0]: {msg_data[0][:100]}, type(msg_data[1]): {type(msg_data[1])}")
                                email_body = msg_data[1]
                        
                        # Handle tuple structure with bytes or bytearray
                        if email_body is None and isinstance(msg_data[0], tuple) and len(msg_data[0]) == 2 and isinstance(msg_data[0][1], (bytes, bytearray)):
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
                        elif isinstance(email_body, bytearray):
                            email_body_bytes = bytes(email_body)
                            log.debug(f"email_body for {decoded_num_str} is bytearray. Converted to bytes. Length: {len(email_body_bytes)}")
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
                        
                        # Decode MIME-encoded subject
                        subject_raw = email_obj["Subject"]
                        subject = self.decode_mime_header(subject_raw) if subject_raw else "No Subject"
                        
                        date = email_obj["Date"]
                        log.info(f"Email From (raw): {from_address_raw}, (lower): {from_address}, Subject (decoded): {subject}")
                            
                        lowercase_filters = {k.lower(): v for k, v in filters.items()}
                        log.debug(f"Checking against lowercase filters: {list(lowercase_filters.keys())}")

                        if from_address in lowercase_filters:
                            log.info(f"Sender {from_address} (matched from {from_address_raw}) is in lowercase_filters.")
                            channel_id = lowercase_filters[from_address]
                            channel = guild.get_channel(channel_id)
                            
                            if channel:
                                log.info(f"Target channel found: {channel.name} ({channel.id})")
                                content = ""
                                html_content = ""
                                
                                if email_obj.is_multipart():
                                    for part in email_obj.walk():
                                        if part.get_content_type() == "text/plain":
                                            try:
                                                content = part.get_payload(decode=True).decode('utf-8', errors='replace')
                                            except (UnicodeDecodeError, AttributeError):
                                                content = "Could not decode email content."
                                        elif part.get_content_type() == "text/html":
                                            try:
                                                html_content = part.get_payload(decode=True).decode('utf-8', errors='replace')
                                            except (UnicodeDecodeError, AttributeError):
                                                html_content = ""
                                else:
                                    try:
                                        content = email_obj.get_payload(decode=True).decode('utf-8', errors='replace')
                                    except (UnicodeDecodeError, AttributeError):
                                        content = "Could not decode email content."
                                
                                # If we have HTML content, try to extract better formatted text with inline links
                                if html_content and len(html_content.strip()) > len(content.strip()):
                                    content = self.convert_html_to_text_with_links(html_content)
                                
                                # Convert text links to clickable Discord format
                                content = self.convert_text_links_to_discord_format(content)
                                
                                # Clean and process the content
                                cleaned_content = self.clean_email_content(content)
                                
                                # Split content into chunks for pagination
                                content_chunks = self.split_content_for_pagination(cleaned_content)
                                
                                # Create embeds for each chunk
                                embeds = []
                                for i, chunk in enumerate(content_chunks):
                                    embed = discord.Embed(
                                        title=subject if i == 0 else f"{subject} (Page {i + 1})",
                                        description=chunk,
                                        color=discord.Color.blue(),
                                        timestamp=datetime.now(timezone.utc)
                                    )
                                    
                                    if i == 0:  # Add metadata only to first embed
                                        embed.add_field(name="From", value=from_address, inline=True)
                                        embed.add_field(name="Date", value=date, inline=True)
                                    
                                    if len(content_chunks) > 1:
                                        embed.set_footer(text=f"Page {i + 1} of {len(content_chunks)}")
                                    
                                    embeds.append(embed)
                                
                                # Send the message with pagination if needed
                                if len(embeds) == 1:
                                    await channel.send(embed=embeds[0])
                                else:
                                    view = EmailPaginationView(embeds)
                                    await channel.send(embed=embeds[0], view=view)
                                
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