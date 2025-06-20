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
        default_guild = {
            "welcome_channel_id": None,
            "role_selection_channel_id": None,
            "role_selector_name": "ROLE_SELECTOR",
            "guest_role_name": "GUEST"
        }
        self.config.register_guild(**default_guild)

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
        role_selector_name = await self.config.guild(guild).role_selector_name()
        guest_role_name = await self.config.guild(guild).guest_role_name()

        if not all([welcome_channel_id, role_selection_channel_id]):
            return  # Channels not configured yet
        # --- End Hardcoded section ---

        if payload.channel_id == welcome_channel_id: 
            if str(payload.emoji) == "✅":
                # Use specific role ID for ROLE_SELECTOR
                selector_role_id = 1380244431256420463  # @ROLE_SELECTOR
                selector_role = guild.get_role(selector_role_id)
                if selector_role:
                    try:
                        await member.add_roles(selector_role, reason="Reacted in welcome channel.")
                    except discord.Forbidden:
                        # Log this or inform an admin, bot lacks permissions
                        log.error(f"Failed to add role {selector_role.name} to {member.name} in {guild.name} - Forbidden")
                    except discord.HTTPException as e:
                        log.error(f"Failed to add role {selector_role.name} to {member.name} in {guild.name} - HTTPException: {e}")
                else:
                    # Log this, role not found
                    log.warning(f"Role with ID {selector_role_id} not found in {guild.name}")

        elif payload.channel_id == role_selection_channel_id:
            # This part assumes any reaction in role_selection_channel_id (except by bots)
            # should lead to removal of GUEST and ROLE_SELECTOR roles.
            # This might need refinement if you have multiple reaction roles in this channel.
            log.info(f"DEBUG: Reaction in role selection channel by {member.name}")
            
            # Use specific role IDs instead of names for reliability
            guest_role_id = 1378417620474138674  # @GUEST
            selector_role_id = 1380244431256420463  # @ROLE_SELECTOR
            
            guest_role = guild.get_role(guest_role_id)
            selector_role = guild.get_role(selector_role_id)
            
            log.info(f"DEBUG: Looking for guest role ID {guest_role_id}: {guest_role}")
            log.info(f"DEBUG: Looking for selector role ID {selector_role_id}: {selector_role}")
            log.info(f"DEBUG: Member {member.name} current roles: {[role.name for role in member.roles]}")

            roles_to_remove = []
            if guest_role and guest_role in member.roles:
                roles_to_remove.append(guest_role)
                log.info(f"DEBUG: Will remove guest role {guest_role.name}")
            if selector_role and selector_role in member.roles:
                roles_to_remove.append(selector_role)
                log.info(f"DEBUG: Will remove selector role {selector_role.name}")
            
            log.info(f"DEBUG: Roles to remove: {[role.name for role in roles_to_remove]}")
            
            if roles_to_remove:
                try:
                    await member.remove_roles(*roles_to_remove, reason="Reacted in role selection channel.")
                    log.info(f"DEBUG: Successfully removed roles from {member.name}")
                except discord.Forbidden:
                    log.error(f"Failed to remove roles from {member.name} in {guild.name} - Forbidden")
                except discord.HTTPException as e:
                    log.error(f"Failed to remove roles from {member.name} in {guild.name} - HTTPException: {e}")
            else:
                log.info(f"DEBUG: No roles to remove for {member.name}")

    @commands.group(name="rolecleanup", aliases=["rc"])
    @commands.admin_or_permissions(manage_guild=True)
    async def rolecleanup(self, ctx):
        """Configure RoleCleanup settings."""
        if ctx.invoked_subcommand is None:
            settings = await self.config.guild(ctx.guild).all()
            welcome_channel = ctx.guild.get_channel(settings["welcome_channel_id"])
            role_selection_channel = ctx.guild.get_channel(settings["role_selection_channel_id"])
            
            embed = discord.Embed(title="RoleCleanup Settings", color=discord.Color.blue())
            embed.add_field(name="Welcome Channel", value=welcome_channel.mention if welcome_channel else "Not set", inline=False)
            embed.add_field(name="Role Selection Channel", value=role_selection_channel.mention if role_selection_channel else "Not set", inline=False)
            embed.add_field(name="Role Selector Name", value=settings["role_selector_name"], inline=False)
            embed.add_field(name="Guest Role Name", value=settings["guest_role_name"], inline=False)
            
            await ctx.send(embed=embed)

    @rolecleanup.command(name="welcomechannel")
    async def set_welcome_channel(self, ctx, channel: discord.TextChannel):
        """Sets the welcome channel for reaction role assignment."""
        await self.config.guild(ctx.guild).welcome_channel_id.set(channel.id)
        await ctx.send(f"Welcome channel set to {channel.mention}")

    @rolecleanup.command(name="roleselectionchannel")
    async def set_roleselection_channel(self, ctx, channel: discord.TextChannel):
        """Sets the role selection channel for role removal."""
        await self.config.guild(ctx.guild).role_selection_channel_id.set(channel.id)
        await ctx.send(f"Role selection channel set to {channel.mention}")

    @rolecleanup.command(name="selectorrole")
    async def set_selector_role(self, ctx, role_name: str):
        """Sets the name of the role selector role."""
        await self.config.guild(ctx.guild).role_selector_name.set(role_name)
        await ctx.send(f"Role selector name set to {role_name}")

    @rolecleanup.command(name="guestrole")
    async def set_guest_role(self, ctx, role_name: str):
        """Sets the name of the guest role."""
        await self.config.guild(ctx.guild).guest_role_name.set(role_name)
        await ctx.send(f"Guest role name set to {role_name}")

    async def red_delete_data_for_user(self, *, requester, user_id):
        """Nothing to delete."""
        return

# This is the standard way to load the cog by Red
# It's not strictly needed in this file if you have an __init__.py in the cog's folder
# that calls bot.add_cog, but it's good practice for standalone cog files.
async def setup(bot):
    await bot.add_cog(RoleCleanup(bot))
