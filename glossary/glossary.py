import discord
import json
import os
import asyncio
from typing import Dict, List, Optional, Tuple
import discord
from redbot.core import commands, data_manager, Config
from redbot.core.utils.chat_formatting import box, pagify
from redbot.core.utils.predicates import MessagePredicate
from redbot.core.utils.menus import menu, DEFAULT_CONTROLS
from redbot.core.bot import Red
from datetime import datetime
import re


class GlossaryView(discord.ui.View):
    """Discord UI View for glossary pagination and interactions."""
    
    def __init__(self, entries: List[Tuple[str, str]], per_page: int = 10):
        super().__init__(timeout=300)
        self.entries = entries
        self.per_page = per_page
        self.current_page = 0
        self.max_pages = (len(entries) - 1) // per_page + 1 if entries else 1
        # Update button states after initialization
        self.update_buttons()
        
    def get_page_embed(self) -> discord.Embed:
        """Generate embed for current page."""
        start_idx = self.current_page * self.per_page
        end_idx = min(start_idx + self.per_page, len(self.entries))
        
        embed = discord.Embed(
            title="📚 Cybersecurity Glossary",
            description=f"Page {self.current_page + 1}/{self.max_pages} • {len(self.entries)} total terms",
            color=0x00ff00
        )
        
        if not self.entries:
            embed.add_field(
                name="No Terms Found",
                value="The glossary is empty or no terms match your search.",
                inline=False
            )
        else:
            for term, definition in self.entries[start_idx:end_idx]:
                # Format: title (shown) abbreviation define (shown) full description (hidden)
                embed.add_field(
                    name=f"🔹 {term}",
                    value=f"**{term}** - ||{definition}||",
                    inline=False
                )
        
        embed.set_footer(text="Use the buttons below to navigate • Add terms with !glossary add")
        return embed
    
    def update_buttons(self):
        """Update button states and labels based on current page."""
        # Update page indicator
        for item in self.children:
            if hasattr(item, 'label') and 'Page' in str(item.label):
                item.label = f"Page {self.current_page + 1}/{self.max_pages}"
            elif hasattr(item, 'label') and 'Previous' in str(item.label):
                item.disabled = self.current_page == 0
            elif hasattr(item, 'label') and 'Next' in str(item.label):
                item.disabled = self.current_page >= self.max_pages - 1
    
    @discord.ui.button(label="◀️ Previous", style=discord.ButtonStyle.secondary)
    async def previous_page(self, interaction: discord.Interaction, button: discord.ui.Button):
        if self.current_page > 0:
            self.current_page -= 1
            self.update_buttons()
            await interaction.response.edit_message(embed=self.get_page_embed(), view=self)
        else:
            await interaction.response.defer()
    
    @discord.ui.button(label="Page 1/1", style=discord.ButtonStyle.primary, disabled=True)
    async def page_indicator(self, interaction: discord.Interaction, button: discord.ui.Button):
        # This button is just for display, no action needed
        await interaction.response.defer()
    
    @discord.ui.button(label="▶️ Next", style=discord.ButtonStyle.secondary)
    async def next_page(self, interaction: discord.Interaction, button: discord.ui.Button):
        if self.current_page < self.max_pages - 1:
            self.current_page += 1
            self.update_buttons()
            await interaction.response.edit_message(embed=self.get_page_embed(), view=self)
        else:
            await interaction.response.defer()
    
    @discord.ui.button(label="➕ Add", style=discord.ButtonStyle.success)
    async def add_term(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_message(
            "Use `!glossary add <term> <definition>` to add new terms to the glossary!",
            ephemeral=True
        )
    
    @discord.ui.button(label="🔍 Search", style=discord.ButtonStyle.primary)
    async def search_terms(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_message(
            "Use `!glossary search <term>` to search for specific terms!",
            ephemeral=True
        )


class Glossary(commands.Cog):
    """A comprehensive cybersecurity glossary with user contributions and moderation."""
    
    def __init__(self, bot: Red):
        self.bot = bot
        self.config = Config.get_conf(self, identifier=1234567890, force_registration=True)
        
        # Default settings
        default_guild = {
            "terms": {},
            "pending_terms": {},
            "moderator_roles": [],
            "contributor_roles": [],
            "auto_approve": False,
            "max_definition_length": 1000,
            "terms_per_page": 10
        }
        
        self.config.register_guild(**default_guild)
        
        # Initialize with default cybersecurity terms
        self.default_terms = {
            "230": "FTP Response Code - Indicates successful login to an FTP server.",
            "AD": "Active Directory - A directory service developed by Microsoft for managing networked resources.",
            "ADDS": "Active Directory Domain Services - A set of services that store and manage information about network resources.",
            "Anti-Steering": "Policies preventing companies from directing users toward specific payment methods or services.",
            "API": "Application Programming Interface - A set of protocols and tools for building software applications.",
            "Botnet": "A network of compromised computers controlled remotely by cybercriminals.",
            "CIA": "Confidentiality, Integrity, Availability - The foundational model for thinking about information security risks, policies, and controls.",
            "CLI": "Command Line Interface - A text-based interface for interacting with a computer using typed commands.",
            "Common Service": "A widely used network service, such as HTTP, FTP, or DNS.",
            "CSRF": "Cross-Site Request Forgery - An attack that forces users to execute unwanted actions on web applications.",
            "DC": "Domain Controller - A server that manages authentication and security policies in a Windows domain.",
            "DDoS": "Distributed Denial of Service - An attack that overwhelms a target with traffic from multiple sources.",
            "DFIR": "Digital Forensics and Incident Response - A cybersecurity discipline focused on investigating security breaches and cyber incidents.",
            "Dir Busting": "Directory Brute-Forcing - A technique used to check multiple paths on a web server to find hidden pages.",
            "dir / ls": "Directory Listing Commands - Commands used to list files and directories in Windows (dir) and Linux/macOS (ls).",
            "Dynamic Pricing": "A pricing strategy where costs fluctuate based on demand, competition, or user behavior.",
            "E2E": "End-to-End Encryption - A method of encrypting data so only the sender and receiver can access it.",
            "EDR": "Endpoint Detection and Response - A security solution that monitors and responds to threats on endpoint devices.",
            "Encryption": "The process of converting data into a coded format to prevent unauthorized access.",
            "Firewall": "A security system that monitors and controls incoming and outgoing network traffic.",
            "Freemium": "A business model offering basic services for free while charging for premium features.",
            "FTP": "File Transfer Protocol - A standard protocol used to transfer files between a client and a server over a network.",
            "ftp-? anonymous": "Anonymous FTP Access - Allows users to log in to an FTP server without credentials, often using 'anonymous' as the username.",
            "GDPR": "General Data Protection Regulation - A European regulation that governs data privacy and protection.",
            "get": "FTP Command - Used to download a file from an FTP server.",
            "Good Authentication Practices": "Something you have, something you are, something you know—multi-factor authentication principles.",
            "GPO": "Group Policy Object - A collection of settings in Windows that define system configurations for users and computers within a domain.",
            "GUI": "Graphical User Interface - A visual interface allowing users to interact with a system using graphical elements.",
            "Hashing": "A cryptographic function that converts data into a fixed-length string for security.",
            "Honeypot": "A decoy system designed to attract and detect unauthorized access attempts.",
            "ICT": "Information and Communications Technology - The integration of telecommunications, computing, and data management technologies.",
            "IDS": "Intrusion Detection System - A system that monitors network traffic for suspicious activity and potential threats.",
            "info": "Redis Command - Displays server statistics and configuration details in Redis.",
            "IP": "Internet Protocol - The set of rules governing the format of data sent over the internet or local networks.",
            "IPS": "Intrusion Prevention System - A security tool that actively blocks detected threats before they cause harm.",
            "ISO 27001": "An international standard for managing information security.",
            "keys ***": "Redis Command - Lists all keys stored in a Redis database.",
            "KPI": "Key Performance Indicator - A measurable value that indicates how effectively a security strategy is performing.",
            "LAN": "Local Area Network - A network that connects computers within a limited area, such as a home, school, or office.",
            "Malware": "Malicious software designed to damage, disrupt, or gain unauthorized access to systems.",
            "MFA": "Multi-Factor Authentication - A security method requiring multiple forms of verification for access.",
            "nmap": "Network Mapper - A tool used for network discovery and security auditing.",
            "OSI": "Open Systems Interconnection Model - A conceptual framework that standardizes network communication into seven layers.",
            "OWASP": "Open Web Application Security Project - A nonprofit organization focused on improving software security through open-source tools and resources.",
            "Pen Testing": "Penetration Testing - Simulated cyberattacks used to identify vulnerabilities in systems.",
            "Phishing": "A cyberattack where attackers trick users into revealing sensitive information.",
            "ping": "A network utility used to test connectivity between devices.",
            "Ransomware": "Malicious software that encrypts files and demands payment for decryption.",
            "rdp": "Remote Desktop Protocol - A protocol that allows users to connect to and control a remote computer.",
            "redis": "Remote Dictionary Server - An open-source key-value store used as a database, cache, and message broker.",
            "redis-cli": "Redis Command Line Interface - A command-line tool for interacting with a Redis database.",
            "root": "The highest-level administrative user in a Unix/Linux system.",
            "select": "Redis Command - Switches between different Redis databases.",
            "SFTP": "Secure File Transfer Protocol - A secure file transfer protocol operating as an extension of SSH.",
            "SIEM": "Security Information and Event Management - A system that collects and analyzes security data from multiple sources.",
            "SMB": "Server Message Block - A protocol used for network file sharing and communication between devices.",
            "Snake-Oil Security": "Fraudulent or misleading cybersecurity products that fail to deliver real protection.",
            "SOC": "Security Operations Center - A centralized unit that monitors and defends against cybersecurity threats.",
            "SQL Injection": "An attack that inserts malicious SQL code into application queries.",
            "Supply Chain": "The network of suppliers, manufacturers, and distributors involved in delivering a product.",
            "TDS": "Threat Detection System - A security system designed to identify and mitigate cyber threats.",
            "Terminal": "A command-line interface used to interact with an operating system.",
            "TGT": "Ticket Granting Ticket - A credential used in Kerberos authentication to request service tickets.",
            "Tree / Forest": "Active Directory Structure - A hierarchical structure in Active Directory used to organize domains.",
            "Two-Factor Authentication": "A security method requiring two different authentication factors.",
            "UI": "User Interface - The point of interaction between a user and a device or software, impacting usability and security.",
            "UX": "User Experience - The overall experience a user has when interacting with a system, including usability and accessibility.",
            "VPN": "Virtual Private Network - A secure connection that encrypts internet traffic and protects online privacy.",
            "WAN": "Wireless Area Network - A network that spans a large geographical area, often connecting multiple smaller networks.",
            "Zero Trust": "A security model that assumes no user or device is inherently trustworthy.",
            "Zero-Day": "A vulnerability that is unknown to security vendors and has no available patch."
        }
    
    async def initialize_guild_terms(self, guild_id: int):
        """Initialize guild with default terms if empty."""
        current_terms = await self.config.guild_from_id(guild_id).terms()
        if not current_terms:
            await self.config.guild_from_id(guild_id).terms.set(self.default_terms.copy())
    
    @commands.group(name="glossary", aliases=["gloss"])
    async def glossary(self, ctx: commands.Context):
        """Cybersecurity glossary commands."""
        if ctx.invoked_subcommand is None:
            await self.show_glossary(ctx)
    
    async def show_glossary(self, ctx: commands.Context, search_term: str = None):
        """Display the glossary with pagination."""
        await self.initialize_guild_terms(ctx.guild.id)
        
        terms_dict = await self.config.guild(ctx.guild).terms()
        terms_per_page = await self.config.guild(ctx.guild).terms_per_page()
        
        # Filter terms if search is provided
        if search_term:
            search_term = search_term.lower()
            filtered_terms = {
                k: v for k, v in terms_dict.items() 
                if search_term in k.lower() or search_term in v.lower()
            }
        else:
            filtered_terms = terms_dict
        
        # Sort terms alphabetically
        sorted_terms = sorted(filtered_terms.items(), key=lambda x: x[0].lower())
        
        if not sorted_terms:
            embed = discord.Embed(
                title="📚 Cybersecurity Glossary",
                description="No terms found matching your search." if search_term else "The glossary is empty.",
                color=0xff0000
            )
            await ctx.send(embed=embed)
            return
        
        # Create and send view
        view = GlossaryView(sorted_terms, terms_per_page)
        embed = view.get_page_embed()
        
        if search_term:
            embed.title += f" - Search: '{search_term}'"
        
        await ctx.send(embed=embed, view=view)
    
    @glossary.command(name="search")
    async def search_glossary(self, ctx: commands.Context, *, search_term: str):
        """Search for terms in the glossary.
        
        Usage: !glossary search <term>
        """
        await self.show_glossary(ctx, search_term)
    
    @glossary.command(name="add")
    async def add_term(self, ctx: commands.Context, term: str, *, definition: str):
        """Add a new term to the glossary.
        
        Usage: !glossary add "term" definition here
        """
        await self.initialize_guild_terms(ctx.guild.id)
        
        # Check definition length
        max_length = await self.config.guild(ctx.guild).max_definition_length()
        if len(definition) > max_length:
            await ctx.send(f"❌ Definition too long! Maximum {max_length} characters allowed.")
            return
        
        # Clean up term formatting
        term = term.strip().title()
        definition = definition.strip()
        
        # Check if term already exists
        current_terms = await self.config.guild(ctx.guild).terms()
        if term.lower() in [t.lower() for t in current_terms.keys()]:
            await ctx.send(f"❌ Term '{term}' already exists in the glossary!")
            return
        
        # Check if auto-approval is enabled
        auto_approve = await self.config.guild(ctx.guild).auto_approve()
        contributor_roles = await self.config.guild(ctx.guild).contributor_roles()
        
        # Check if user has contributor role
        user_roles = [role.id for role in ctx.author.roles]
        has_contributor_role = any(role_id in user_roles for role_id in contributor_roles)
        
        if auto_approve or has_contributor_role or ctx.author.guild_permissions.manage_messages:
            # Add directly to glossary
            current_terms[term] = definition
            await self.config.guild(ctx.guild).terms.set(current_terms)
            
            embed = discord.Embed(
                title="✅ Term Added",
                description=f"**{term}** has been added to the glossary!",
                color=0x00ff00
            )
            embed.add_field(name="Definition", value=definition, inline=False)
            embed.set_footer(text=f"Added by {ctx.author.display_name}")
            await ctx.send(embed=embed)
        else:
            # Add to pending terms for moderation
            pending_terms = await self.config.guild(ctx.guild).pending_terms()
            pending_terms[term] = {
                "definition": definition,
                "author_id": ctx.author.id,
                "author_name": ctx.author.display_name,
                "timestamp": datetime.now().isoformat()
            }
            await self.config.guild(ctx.guild).pending_terms.set(pending_terms)
            
            embed = discord.Embed(
                title="⏳ Term Submitted for Review",
                description=f"**{term}** has been submitted and is awaiting moderator approval.",
                color=0xffff00
            )
            embed.add_field(name="Definition", value=definition, inline=False)
            await ctx.send(embed=embed)
            
            # Notify moderators
            await self.notify_moderators(ctx.guild, term, definition, ctx.author)
    
    async def notify_moderators(self, guild: discord.Guild, term: str, definition: str, author: discord.Member):
        """Notify moderators of pending term submissions."""
        moderator_roles = await self.config.guild(guild).moderator_roles()
        
        if not moderator_roles:
            return
        
        embed = discord.Embed(
            title="📝 New Glossary Term Pending Approval",
            color=0x0099ff
        )
        embed.add_field(name="Term", value=term, inline=True)
        embed.add_field(name="Submitted by", value=author.mention, inline=True)
        embed.add_field(name="Definition", value=definition, inline=False)
        embed.set_footer(text="Use !glossary pending to review all pending terms")
        
        # Find channels where moderators might be
        for channel in guild.text_channels:
            if channel.permissions_for(guild.me).send_messages:
                # Check if any moderators can see this channel
                for role_id in moderator_roles:
                    role = guild.get_role(role_id)
                    if role and channel.permissions_for(role).read_messages:
                        try:
                            await channel.send(embed=embed)
                            return  # Only send to first available channel
                        except discord.Forbidden:
                            continue
    
    @glossary.command(name="pending")
    @commands.has_permissions(manage_messages=True)
    async def show_pending(self, ctx: commands.Context):
        """Show pending term submissions (Moderators only)."""
        pending_terms = await self.config.guild(ctx.guild).pending_terms()
        
        if not pending_terms:
            await ctx.send("📭 No pending term submissions.")
            return
        
        embed = discord.Embed(
            title="📝 Pending Glossary Terms",
            description=f"{len(pending_terms)} terms awaiting approval",
            color=0xffff00
        )
        
        for term, data in list(pending_terms.items())[:10]:  # Show first 10
            embed.add_field(
                name=f"🔹 {term}",
                value=f"**Definition:** {data['definition'][:100]}{'...' if len(data['definition']) > 100 else ''}\n**By:** {data['author_name']}",
                inline=False
            )
        
        if len(pending_terms) > 10:
            embed.set_footer(text=f"Showing first 10 of {len(pending_terms)} pending terms")
        
        await ctx.send(embed=embed)
    
    @glossary.command(name="approve")
    @commands.has_permissions(manage_messages=True)
    async def approve_term(self, ctx: commands.Context, *, term: str):
        """Approve a pending term submission (Moderators only)."""
        pending_terms = await self.config.guild(ctx.guild).pending_terms()
        
        # Find term (case-insensitive)
        actual_term = None
        for pending_term in pending_terms.keys():
            if pending_term.lower() == term.lower():
                actual_term = pending_term
                break
        
        if not actual_term:
            await ctx.send(f"❌ No pending term found matching '{term}'.")
            return
        
        # Move from pending to approved
        term_data = pending_terms[actual_term]
        current_terms = await self.config.guild(ctx.guild).terms()
        current_terms[actual_term] = term_data['definition']
        
        await self.config.guild(ctx.guild).terms.set(current_terms)
        
        # Remove from pending
        del pending_terms[actual_term]
        await self.config.guild(ctx.guild).pending_terms.set(pending_terms)
        
        embed = discord.Embed(
            title="✅ Term Approved",
            description=f"**{actual_term}** has been approved and added to the glossary!",
            color=0x00ff00
        )
        embed.add_field(name="Definition", value=term_data['definition'], inline=False)
        embed.set_footer(text=f"Originally submitted by {term_data['author_name']}")
        
        await ctx.send(embed=embed)
        
        # Auto-refresh the glossary to show the approved term
        await asyncio.sleep(1)  # Brief pause for better UX
        await self.show_glossary(ctx)
    
    @glossary.command(name="reject")
    @commands.has_permissions(manage_messages=True)
    async def reject_term(self, ctx: commands.Context, *, term: str):
        """Reject a pending term submission (Moderators only)."""
        pending_terms = await self.config.guild(ctx.guild).pending_terms()
        
        # Find term (case-insensitive)
        actual_term = None
        for pending_term in pending_terms.keys():
            if pending_term.lower() == term.lower():
                actual_term = pending_term
                break
        
        if not actual_term:
            await ctx.send(f"❌ No pending term found matching '{term}'.")
            return
        
        # Remove from pending
        term_data = pending_terms[actual_term]
        del pending_terms[actual_term]
        await self.config.guild(ctx.guild).pending_terms.set(pending_terms)
        
        embed = discord.Embed(
            title="❌ Term Rejected",
            description=f"**{actual_term}** has been rejected.",
            color=0xff0000
        )
        embed.set_footer(text=f"Originally submitted by {term_data['author_name']}")
        
        await ctx.send(embed=embed)
    
    @glossary.command(name="remove", aliases=["delete"])
    @commands.has_permissions(manage_messages=True)
    async def remove_term(self, ctx: commands.Context, *, term: str):
        """Remove a term from the glossary (Moderators only)."""
        current_terms = await self.config.guild(ctx.guild).terms()
        
        # Find term (case-insensitive)
        actual_term = None
        for existing_term in current_terms.keys():
            if existing_term.lower() == term.lower():
                actual_term = existing_term
                break
        
        if not actual_term:
            await ctx.send(f"❌ Term '{term}' not found in the glossary.")
            return
        
        # Remove term
        del current_terms[actual_term]
        await self.config.guild(ctx.guild).terms.set(current_terms)
        
        embed = discord.Embed(
            title="🗑️ Term Removed",
            description=f"**{actual_term}** has been removed from the glossary.",
            color=0xff6600
        )
        
        await ctx.send(embed=embed)
    
    @glossary.command(name="config")
    @commands.has_permissions(administrator=True)
    async def configure_glossary(self, ctx: commands.Context):
        """Configure glossary settings (Administrators only)."""
        embed = discord.Embed(
            title="⚙️ Glossary Configuration",
            description="Available configuration commands:",
            color=0x0099ff
        )
        
        embed.add_field(
            name="Auto-Approval",
            value="`!glossary config autoapprove <true/false>`\nAutomatically approve new terms",
            inline=False
        )
        
        embed.add_field(
            name="Moderator Roles",
            value="`!glossary config modroles <add/remove> <@role>`\nManage moderator roles",
            inline=False
        )
        
        embed.add_field(
            name="Contributor Roles",
            value="`!glossary config controles <add/remove> <@role>`\nManage contributor roles (auto-approved)",
            inline=False
        )
        
        embed.add_field(
            name="Terms Per Page",
            value="`!glossary config perpage <number>`\nSet terms displayed per page (1-20)",
            inline=False
        )
        
        embed.add_field(
            name="Reset Glossary",
            value="`!glossary reset`\nReset to default cybersecurity terms (68+ definitions)",
            inline=False
        )
        
        await ctx.send(embed=embed)
    
    @glossary.command(name="stats")
    async def glossary_stats(self, ctx: commands.Context):
        """Show glossary statistics."""
        await self.initialize_guild_terms(ctx.guild.id)
        
        terms = await self.config.guild(ctx.guild).terms()
        pending = await self.config.guild(ctx.guild).pending_terms()
        
        embed = discord.Embed(
            title="📊 Glossary Statistics",
            color=0x00ff00
        )
        
        embed.add_field(name="📚 Total Terms", value=str(len(terms)), inline=True)
        embed.add_field(name="⏳ Pending Terms", value=str(len(pending)), inline=True)
        embed.add_field(name="📖 Average Definition Length", 
                       value=f"{sum(len(d) for d in terms.values()) // len(terms) if terms else 0} chars", 
                       inline=True)
        
        # Most recent additions
        if pending:
            recent_pending = sorted(pending.items(), 
                                  key=lambda x: x[1].get('timestamp', ''), 
                                  reverse=True)[:3]
            recent_text = "\n".join([f"• {term}" for term, _ in recent_pending])
            embed.add_field(name="🆕 Recent Submissions", value=recent_text, inline=False)
        
        await ctx.send(embed=embed)
    
    @glossary.command(name="reset")
    @commands.has_permissions(administrator=True)
    async def reset_glossary(self, ctx: commands.Context):
        """Reset glossary to default terms (Administrators only)."""
        # Reset to default terms
        await self.config.guild(ctx.guild).terms.set(self.default_terms.copy())
        
        embed = discord.Embed(
            title="🔄 Glossary Reset",
            description=f"Successfully reset glossary to default terms!\n\n📚 **{len(self.default_terms)} terms** loaded",
            color=0x00ff00
        )
        
        await ctx.send(embed=embed)
    
    @glossary.command(name="export")
    @commands.has_permissions(manage_messages=True)
    async def export_glossary(self, ctx: commands.Context):
        """Export the glossary as a JSON file (Moderators only)."""
        terms = await self.config.guild(ctx.guild).terms()
        
        if not terms:
            await ctx.send("❌ No terms to export.")
            return
        
        # Create export data
        export_data = {
            "guild_id": ctx.guild.id,
            "guild_name": ctx.guild.name,
            "export_date": datetime.now().isoformat(),
            "total_terms": len(terms),
            "terms": terms
        }
        
        # Create file
        filename = f"glossary_{ctx.guild.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        import io
        file_content = json.dumps(export_data, indent=2, ensure_ascii=False)
        file_obj = io.StringIO(file_content)
        
        await ctx.send(
            "📤 Glossary exported successfully!",
            file=discord.File(file_obj, filename=filename)
        )


async def setup(bot):
    """Setup function for Red-DiscordBot."""
    await bot.add_cog(Glossary(bot))