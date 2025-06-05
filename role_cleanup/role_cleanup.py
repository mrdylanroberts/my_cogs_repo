import discord
from redbot.core import commands

class RoleCleanup(commands.Cog):
    """Manages role assignments based on reactions."""
    def __init__(self, bot):
        self.bot = bot
        # It's good practice to define default settings or load them here if needed
        # For this cog, we'll need to store channel IDs. 
        # We'll use Red's config system for this.
        # self.config = Config.get_conf(self, identifier=1234567890, force_registration=True)
        # default_guild = {
        #     "welcome_channel_id": None,
        #     "role_selection_channel_id": None,
        #     "role_selector_name": "ROLE_SELECTOR", # Default name for the selector role
        #     "guest_role_name": "GUEST" # Default name for the guest role
        # }
        # self.config.register_guild(**default_guild)

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

        # TODO: Replace YOUR_WELCOME_CHANNEL_ID and YOUR_ROLE_SELECTION_CHANNEL_ID
        # with actual channel IDs. It's better to make these configurable per server.
        # For now, we'll use placeholders. You should implement a command to set these.
        # welcome_channel_id = await self.config.guild(guild).welcome_channel_id()
        # role_selection_channel_id = await self.config.guild(guild).role_selection_channel_id()
        # role_selector_name = await self.config.guild(guild).role_selector_name()
        # guest_role_name = await self.config.guild(guild).guest_role_name()

        # --- Hardcoded for now, replace with config later --- 
        # These should be set via a command by an admin for each server
        # For example: !rolecleanup set welcomechannel #your-welcome-channel
        # For example: !rolecleanup set roleselectionchannel #your-role-selection-channel
        # For example: !rolecleanup set selectorrole ROLE_SELECTOR
        # For example: !rolecleanup set guestrole GUEST
        # For demonstration, we'll use the names from your prompt.md
        # You MUST replace these with actual IDs or implement config commands.
        YOUR_WELCOME_CHANNEL_ID = 0 # Replace with actual ID
        YOUR_ROLE_SELECTION_CHANNEL_ID = 0 # Replace with actual ID
        ROLE_SELECTOR_NAME = "ROLE_SELECTOR"
        GUEST_ROLE_NAME = "GUEST"
        # --- End Hardcoded section ---

        if payload.channel_id == YOUR_WELCOME_CHANNEL_ID: 
            if str(payload.emoji) == "✅":
                selector_role = discord.utils.get(guild.roles, name=ROLE_SELECTOR_NAME)
                if selector_role:
                    try:
                        await member.add_roles(selector_role, reason="Reacted in welcome channel.")
                    except discord.Forbidden:
                        # Log this or inform an admin, bot lacks permissions
                        print(f"Failed to add role {ROLE_SELECTOR_NAME} to {member.name} in {guild.name} - Forbidden")
                    except discord.HTTPException as e:
                        print(f"Failed to add role {ROLE_SELECTOR_NAME} to {member.name} in {guild.name} - HTTPException: {e}")
                else:
                    # Log this, role not found
                    print(f"Role {ROLE_SELECTOR_NAME} not found in {guild.name}")

        elif payload.channel_id == YOUR_ROLE_SELECTION_CHANNEL_ID:
            # This part assumes any reaction in role_selection_channel_id (except by bots)
            # should lead to removal of GUEST and ROLE_SELECTOR roles.
            # This might need refinement if you have multiple reaction roles in this channel.
            guest_role = discord.utils.get(guild.roles, name=GUEST_ROLE_NAME)
            selector_role = discord.utils.get(guild.roles, name=ROLE_SELECTOR_NAME)

            roles_to_remove = []
            if guest_role and guest_role in member.roles:
                roles_to_remove.append(guest_role)
            if selector_role and selector_role in member.roles:
                roles_to_remove.append(selector_role)
            
            if roles_to_remove:
                try:
                    await member.remove_roles(*roles_to_remove, reason="Reacted in role selection channel.")
                except discord.Forbidden:
                    print(f"Failed to remove roles from {member.name} in {guild.name} - Forbidden")
                except discord.HTTPException as e:
                    print(f"Failed to remove roles from {member.name} in {guild.name} - HTTPException: {e}")

    # It would be good to add setup commands here to set the channel IDs and role names
    # e.g., using @commands.group() and @yourgroup.command()
    # For example:
    # @commands.group(name="rolecleanupset", aliases=["rcset"])
    # @commands.admin_or_permissions(manage_guild=True)
    # async def rolecleanupset(self, ctx):
    #     """Configure RoleCleanup settings."""
    #     pass

    # @rolecleanupset.command(name="welcomechannel")
    # async def set_welcome_channel(self, ctx, channel: discord.TextChannel):
    #     """Sets the welcome channel for reaction role assignment."""
    #     # await self.config.guild(ctx.guild).welcome_channel_id.set(channel.id)
    #     await ctx.send(f"Welcome channel set to {channel.mention}")

    # @rolecleanupset.command(name="roleselectionchannel")
    # async def set_roleselection_channel(self, ctx, channel: discord.TextChannel):
    #     """Sets the role selection channel for GUEST/ROLE_SELECTOR removal."""
    #     # await self.config.guild(ctx.guild).role_selection_channel_id.set(channel.id)
    #     await ctx.send(f"Role selection channel set to {channel.mention}")

    # You would also need to add a setup function if you use Config
    # async def red_delete_data_for_user(self, *, requester, user_id):
    #     # This cog does not store any user data directly in config.
    #     return

# This is the standard way to load the cog by Red
# It's not strictly needed in this file if you have an __init__.py in the cog's folder
# that calls bot.add_cog, but it's good practice for standalone cog files.
# async def setup(bot):
#    await bot.add_cog(RoleCleanup(bot))