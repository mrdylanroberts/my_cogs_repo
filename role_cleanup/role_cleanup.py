import discord
import discord
from redbot.core import commands, Config
import logging

log = logging.getLogger("red.my-cogs-repo.role_cleanup")

class RoleCleanup(commands.Cog):
    """Manages role assignments based on reactions."""
    def __init__(self, bot):
        self.bot = bot
        self.config = Config.get_conf(self, identifier=1234567890, force_registration=True)
        default_guild_settings = {
            "welcome_channel_id": None,
            "role_selection_channel_id": None,
            "role_selector_id": None,
            "guest_role_id": None
        }
        self.config.register_guild(**default_guild_settings)

    @commands.Cog.listener()
    async def on_interaction(self, interaction: discord.Interaction):
        """Handles button interactions from RolesButtons cog."""
        # Only handle button interactions
        if interaction.type != discord.InteractionType.component:
            return
            
        # Only handle interactions from guild members (not DMs)
        if not interaction.guild or not interaction.user:
            return
            
        # Skip bot interactions
        if interaction.user.bot:
            return
            
        guild = interaction.guild
        member = interaction.user
        
        # Get configured role selection channel
        role_selection_channel_id = await self.config.guild(guild).role_selection_channel_id()
        
        # Debug: Log button interactions in role selection channel
        if interaction.channel_id == role_selection_channel_id:
            log.info(f"DEBUG: Button interaction in role selection channel by {member.name}")
            
            # Remove both guest and role selector roles when user clicks any button in role selection channel
            await self._remove_welcome_roles(guild, member)
    
    @commands.Cog.listener()
    async def on_raw_reaction_add(self, payload: discord.RawReactionActionEvent):
        """Handles raw reaction add events to manage roles."""
        if payload.member.bot:
            return

        guild = self.bot.get_guild(payload.guild_id)
        if not guild:
            return # Bot is not in the guild
        
        member = guild.get_member(payload.user_id)
        if not member:
            return # Member not found

        # Get configured values from Config
        welcome_channel_id = await self.config.guild(guild).welcome_channel_id()
        role_selection_channel_id = await self.config.guild(guild).role_selection_channel_id()
        
        # Debug: Log all reaction events
        log.info(f"DEBUG: Reaction detected - Channel: {payload.channel_id}, User: {member.name}, Emoji: {payload.emoji}")
        log.info(f"DEBUG: Welcome channel ID: {welcome_channel_id}, Role selection channel ID: {role_selection_channel_id}")

        if not all([welcome_channel_id, role_selection_channel_id]):
            log.warning(f"DEBUG: Channels not configured - Welcome: {welcome_channel_id}, Role Selection: {role_selection_channel_id}")
            return  # Channels not configured yet

        if payload.channel_id == welcome_channel_id: 
            if str(payload.emoji) == "✅":
                # Get role selector ID from config
                selector_role_id = await self.config.guild(guild).role_selector_id()
                if selector_role_id:
                    selector_role = guild.get_role(selector_role_id)
                    if selector_role:
                        try:
                            await member.add_roles(selector_role, reason="Reacted in welcome channel.")
                            log.info(f"DEBUG: Added {selector_role.name} role to {member.name}")
                        except discord.Forbidden:
                            log.error(f"Failed to add role {selector_role.name} to {member.name} in {guild.name} - Forbidden")
                        except discord.HTTPException as e:
                            log.error(f"Failed to add role {selector_role.name} to {member.name} in {guild.name} - HTTPException: {e}")
                    else:
                        log.warning(f"Role with ID {selector_role_id} not found in {guild.name}")
                else:
                    log.warning(f"Role selector ID not configured for {guild.name}")

        elif payload.channel_id == role_selection_channel_id:
            # Handle emoji reactions in role selection channel (fallback for non-button reactions)
            log.info(f"DEBUG: Reaction in role selection channel by {member.name}")
            
            # Remove both guest and role selector roles
            await self._remove_welcome_roles(guild, member)
    
    async def _remove_welcome_roles(self, guild: discord.Guild, member: discord.Member):
        """Helper method to remove both guest and role selector roles from a member."""
        # Get guest role ID from config and remove it
        guest_role_id = await self.config.guild(guild).guest_role_id()
        if guest_role_id:
            guest_role = guild.get_role(guest_role_id)
            if guest_role and guest_role in member.roles:
                try:
                    await member.remove_roles(guest_role, reason="Selected class role in role selection channel.")
                    log.info(f"DEBUG: Removed {guest_role.name} role from {member.name}")
                except discord.Forbidden:
                    log.error(f"Failed to remove role {guest_role.name} from {member.name} in {guild.name} - Forbidden")
                except discord.HTTPException as e:
                    log.error(f"Failed to remove role {guest_role.name} from {member.name} in {guild.name} - HTTPException: {e}")
            else:
                if not guest_role:
                    log.warning(f"Guest role with ID {guest_role_id} not found in {guild.name}")
                else:
                    log.info(f"DEBUG: {member.name} doesn't have {guest_role.name} role to remove")
        else:
            log.warning(f"Guest role ID not configured for {guild.name}")
        
        # Get role selector ID from config and remove it
        selector_role_id = await self.config.guild(guild).role_selector_id()
        if selector_role_id:
            selector_role = guild.get_role(selector_role_id)
            if selector_role and selector_role in member.roles:
                try:
                    await member.remove_roles(selector_role, reason="Selected class role in role selection channel.")
                    log.info(f"DEBUG: Removed {selector_role.name} role from {member.name}")
                except discord.Forbidden:
                    log.error(f"Failed to remove role {selector_role.name} from {member.name} in {guild.name} - Forbidden")
                except discord.HTTPException as e:
                    log.error(f"Failed to remove role {selector_role.name} from {member.name} in {guild.name} - HTTPException: {e}")
            else:
                if not selector_role:
                    log.warning(f"Role selector with ID {selector_role_id} not found in {guild.name}")
                else:
                    log.info(f"DEBUG: {member.name} doesn't have {selector_role.name} role to remove")
        else:
            log.warning(f"Role selector ID not configured for {guild.name}")

    @commands.group(name="rolecleanup", aliases=["rc"])
    @commands.guild_only()
    @commands.admin_or_permissions(manage_roles=True)
    async def rolecleanup(self, ctx):
        """Role cleanup configuration commands."""
        pass

    @rolecleanup.command(name="info")
    async def rolecleanup_info(self, ctx):
        """Show current role cleanup configuration."""
        guild = ctx.guild
        welcome_channel_id = await self.config.guild(guild).welcome_channel_id()
        role_selection_channel_id = await self.config.guild(guild).role_selection_channel_id()
        role_selector_id = await self.config.guild(guild).role_selector_id()
        guest_role_id = await self.config.guild(guild).guest_role_id()
        
        welcome_channel = guild.get_channel(welcome_channel_id) if welcome_channel_id else None
        role_selection_channel = guild.get_channel(role_selection_channel_id) if role_selection_channel_id else None
        role_selector = guild.get_role(role_selector_id) if role_selector_id else None
        guest_role = guild.get_role(guest_role_id) if guest_role_id else None
        
        embed = discord.Embed(title="Role Cleanup Configuration", color=0x00ff00)
        embed.add_field(
            name="Welcome Channel", 
            value=welcome_channel.mention if welcome_channel else "Not configured", 
            inline=False
        )
        embed.add_field(
            name="Role Selection Channel", 
            value=role_selection_channel.mention if role_selection_channel else "Not configured", 
            inline=False
        )
        embed.add_field(
            name="Role Selector Role", 
            value=role_selector.mention if role_selector else "Not configured", 
            inline=False
        )
        embed.add_field(
            name="Guest Role", 
            value=guest_role.mention if guest_role else "Not configured", 
            inline=False
        )
        
        await ctx.send(embed=embed)

    @rolecleanup.command(name="welcomechannel")
    async def set_welcome_channel(self, ctx, channel: discord.TextChannel):
        """Sets the welcome channel for reaction role assignment."""
        await self.config.guild(ctx.guild).welcome_channel_id.set(channel.id)
        await ctx.send(f"Welcome channel set to {channel.mention}")

    @rolecleanup.command(name="roleselectionchannel")
    async def set_role_selection_channel(self, ctx, channel: discord.TextChannel):
        """Set the role selection channel."""
        await self.config.guild(ctx.guild).role_selection_channel_id.set(channel.id)
        await ctx.send(f"Role selection channel set to {channel.mention}.")
    
    @rolecleanup.command(name="roleselector")
    async def set_role_selector(self, ctx, role: discord.Role):
        """Set the role selector role (given to users who react in welcome channel)."""
        await self.config.guild(ctx.guild).role_selector_id.set(role.id)
        await ctx.send(f"Role selector role set to {role.mention}.")
    
    @rolecleanup.command(name="guestrole")
    async def set_guest_role(self, ctx, role: discord.Role):
        """Set the guest role (removed when users react in role selection channel)."""
        await self.config.guild(ctx.guild).guest_role_id.set(role.id)
        await ctx.send(f"Guest role set to {role.mention}.")

    async def red_delete_data_for_user(self, *, requester, user_id):
        """Nothing to delete."""
        return

# This is the standard way to load the cog by Red
# It's not strictly needed in this file if you have an __init__.py in the cog's folder
# that calls bot.add_cog, but it's good practice for standalone cog files.
async def setup(bot):
    await bot.add_cog(RoleCleanup(bot))
