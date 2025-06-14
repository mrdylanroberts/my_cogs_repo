import discord
import json
import os
import asyncio
from typing import Dict, List, Optional, Tuple
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
                # Truncate long definitions for display
                display_def = definition[:200] + "..." if len(definition) > 200 else definition
                embed.add_field(
                    name=f"🔹 {term}",
                    value=display_def,
                    inline=False
                )
        
        embed.set_footer(text="Use the buttons below to navigate • Add terms with !glossary add")
        return embed
    
    @discord.ui.button(label="◀️ Previous", style=discord.ButtonStyle.secondary)
    async def previous_page(self, interaction: discord.Interaction, button: discord.ui.Button):
        if self.current_page > 0:
            self.current_page -= 1
            await interaction.response.edit_message(embed=self.get_page_embed(), view=self)
        else:
            await interaction.response.defer()
    
    @discord.ui.button(label="▶️ Next", style=discord.ButtonStyle.secondary)
    async def next_page(self, interaction: discord.Interaction, button: discord.ui.Button):
        if self.current_page < self.max_pages - 1:
            self.current_page += 1
            await interaction.response.edit_message(embed=self.get_page_embed(), view=self)
        else:
            await interaction.response.defer()
    
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
            "API": "Application Programming Interface - A set of protocols and tools for building software applications.",
            "Botnet": "A network of compromised computers controlled remotely by cybercriminals.",
            "CSRF": "Cross-Site Request Forgery - An attack that forces users to execute unwanted actions on web applications.",
            "DDoS": "Distributed Denial of Service - An attack that overwhelms a target with traffic from multiple sources.",
            "Encryption": "The process of converting data into a coded format to prevent unauthorized access.",
            "Firewall": "A security system that monitors and controls incoming and outgoing network traffic.",
            "Honeypot": "A decoy system designed to attract and detect unauthorized access attempts.",
            "IDS": "Intrusion Detection System - Monitors network traffic for suspicious activity.",
            "Malware": "Malicious software designed to damage, disrupt, or gain unauthorized access to systems.",
            "Phishing": "A social engineering attack that tricks users into revealing sensitive information.",
            "Ransomware": "Malware that encrypts files and demands payment for decryption.",
            "SQL Injection": "An attack that inserts malicious SQL code into application queries.",
            "Two-Factor Authentication": "A security method requiring two different authentication factors.",
            "VPN": "Virtual Private Network - Creates a secure connection over a public network.",
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