import discord
from redbot.core import commands, Config, checks

class JoinLeaveThreads(commands.Cog):
    """Sends join/leave messages to threads."""

    def __init__(self, bot):
        self.bot = bot
        self.config = Config.get_conf(self, identifier=1234567890, force_registration=True)
        default_guild_settings = {
            "join_enabled": False,
            "join_message": "Welcome {member.mention} to {server.name}!",
            "join_thread_id": None,
            "join_create_new_thread": False, # If True, creates a new thread for each join
            "join_thread_name_format": "Welcome {member.name}", # Used if join_create_new_thread is True
            "leave_enabled": False,
            "leave_message": "Goodbye {member.name}!",
            "leave_thread_id": None,
            "leave_create_new_thread": False, # If True, creates a new thread for each leave
            "leave_thread_name_format": "Farewell {member.name}" # Used if leave_create_new_thread is True
        }
        self.config.register_guild(**default_guild_settings)

    async def cog_load(self):
        # Optional: Any setup needed when the cog is loaded
        pass

    async def cog_unload(self):
        # Optional: Any cleanup needed when the cog is unloaded
        pass

    @commands.Cog.listener()
    async def on_member_join(self, member):
        guild = member.guild
        settings = await self.config.guild(guild).all()

        if not settings["join_enabled"]:
            return

        target_channel_id = settings["join_thread_id"]
        if not target_channel_id:
            return

        target_channel = guild.get_thread(target_channel_id)
        if not target_channel:
            # Fallback or error if thread not found by ID (maybe it was a channel ID?)
            # For simplicity, we'll try to get it as a channel if thread lookup fails
            # In a real scenario, you'd want more robust error handling or specific settings for channel vs thread
            parent_channel_for_new_thread = guild.get_channel(target_channel_id)
            if settings["join_create_new_thread"] and parent_channel_for_new_thread and isinstance(parent_channel_for_new_thread, discord.TextChannel):
                try:
                    thread_name = settings["join_thread_name_format"].format(member=member, server=guild)
                    # Ensure thread name is within Discord's limits (1-100 chars)
                    thread_name = thread_name[:100]
                    # Try to create a public thread. For private, use discord.ChannelType.private_thread
                    # Note: Bots might need specific permissions or be part of the thread to send messages.
                    # Creating a thread from a message is often easier for initial message sending.
                    # Here, we'll create an unarchived thread if possible.
                    # Auto_archive_duration can be 60, 1440, 4320, 10080
                    new_thread = await parent_channel_for_new_thread.create_thread(
                        name=thread_name, 
                        auto_archive_duration=1440, # 24 hours
                        type=discord.ChannelType.public_thread
                    )
                    target_channel = new_thread
                except discord.HTTPException as e:
                    print(f"Failed to create join thread for {member.name} in {guild.name}: {e}")
                    return # Failed to create thread
            else:
                # If not creating new thread or parent_channel_for_new_thread is not a TextChannel, log and return
                print(f"Join thread/channel ID {target_channel_id} not found or not a text channel for new thread creation in {guild.name}.")
                return
        
        if not target_channel:
            print(f"Could not find or create target join thread for {guild.name}.")
            return

        join_msg = settings["join_message"].format(member=member, server=guild)
        try:
            await target_channel.send(join_msg)
        except discord.HTTPException as e:
            print(f"Failed to send join message to {target_channel.name} for {member.name}: {e}")

    @commands.Cog.listener()
    async def on_member_remove(self, member):
        guild = member.guild
        settings = await self.config.guild(guild).all()

        if not settings["leave_enabled"]:
            return

        target_channel_id = settings["leave_thread_id"]
        if not target_channel_id:
            return

        target_channel = guild.get_thread(target_channel_id)
        if not target_channel:
            parent_channel_for_new_thread = guild.get_channel(target_channel_id)
            if settings["leave_create_new_thread"] and parent_channel_for_new_thread and isinstance(parent_channel_for_new_thread, discord.TextChannel):
                try:
                    thread_name = settings["leave_thread_name_format"].format(member=member, server=guild)
                    thread_name = thread_name[:100]
                    new_thread = await parent_channel_for_new_thread.create_thread(
                        name=thread_name, 
                        auto_archive_duration=1440, 
                        type=discord.ChannelType.public_thread
                    )
                    target_channel = new_thread
                except discord.HTTPException as e:
                    print(f"Failed to create leave thread for {member.name} in {guild.name}: {e}")
                    return
            else:
                print(f"Leave thread/channel ID {target_channel_id} not found or not a text channel for new thread creation in {guild.name}.")
                return
        
        if not target_channel:
            print(f"Could not find or create target leave thread for {guild.name}.")
            return

        leave_msg = settings["leave_message"].format(member=member, server=guild)
        try:
            await target_channel.send(leave_msg)
        except discord.HTTPException as e:
            print(f"Failed to send leave message to {target_channel.name} for {member.name}: {e}")

    @commands.group(aliases=["jltset"])
    @checks.admin_or_permissions(manage_guild=True)
    async def joinleavethreadsset(self, ctx):
        """Configure JoinLeaveThreads settings."""
        pass

    @joinleavethreadsset.command(name="join")
    async def jltset_join(self, ctx, true_false: bool):
        """Enable or disable join messages.

        Use `true` to enable, `false` to disable.
        """
        await self.config.guild(ctx.guild).join_enabled.set(true_false)
        status = "enabled" if true_false else "disabled"
        await ctx.send(f"Join messages are now {status}.")

    @joinleavethreadsset.command(name="joinmessage")
    async def jltset_joinmessage(self, ctx, *, message: str):
        """Set the join message.

        Use `{member}` for member mention and `{server}` for server name.
        Example: `Welcome {member.mention} to {server.name}!`
        """
        await self.config.guild(ctx.guild).join_message.set(message)
        await ctx.send(f"Join message set to: `{message}`")

    @joinleavethreadsset.command(name="jointhread")
    async def jltset_jointhread(self, ctx, thread_or_channel_id: int = None):
        """Set the thread ID or parent channel ID for join messages.

        If `joinnewthread` is enabled, this should be the ID of the PARENT CHANNEL where new threads will be created.
        Otherwise, this should be the ID of the existing THREAD to send messages to.
        Provide no ID to clear the setting.
        """
        await self.config.guild(ctx.guild).join_thread_id.set(thread_or_channel_id)
        if thread_or_channel_id:
            # Attempt to fetch to give user feedback, but don't require it to exist yet
            fetched_obj = ctx.guild.get_thread(thread_or_channel_id) or ctx.guild.get_channel(thread_or_channel_id)
            obj_type = "Thread/Channel" if fetched_obj else "ID"
            await ctx.send(f"Join message {obj_type} set to `{thread_or_channel_id}`.")
            if not fetched_obj:
                await ctx.send("Note: I couldn't immediately find a thread or channel with this ID. Make sure it's correct and I have permissions.")
        else:
            await ctx.send("Join message thread/channel ID cleared.")

    @joinleavethreadsset.command(name="joinnewthread")
    async def jltset_joinnewthread(self, ctx, true_false: bool):
        """Enable or disable creating a new thread for each join message.

        If enabled, `jointhread` should be set to a parent TEXT CHANNEL ID.
        Use `true` to enable, `false` to disable.
        """
        await self.config.guild(ctx.guild).join_create_new_thread.set(true_false)
        status = "enabled" if true_false else "disabled"
        await ctx.send(f"Creating new threads for joins is now {status}.")
        if true_false:
            await ctx.send("Remember to set `jointhread` to the ID of the PARENT TEXT CHANNEL.")
        else:
            await ctx.send("Remember to set `jointhread` to the ID of an EXISTING THREAD.")

    @joinleavethreadsset.command(name="jointhreadname")
    async def jltset_jointhreadname(self, ctx, *, name_format: str):
        """Set the name format for newly created join threads.

        Only used if `joinnewthread` is enabled.
        Use `{member.name}` for member's name, `{member.id}` for ID, `{server.name}` for server.
        Example: `Welcome {member.name}`
        """
        await self.config.guild(ctx.guild).join_thread_name_format.set(name_format)
        await ctx.send(f"Join thread name format set to: `{name_format}`")

    @joinleavethreadsset.command(name="leave")
    async def jltset_leave(self, ctx, true_false: bool):
        """Enable or disable leave messages.

        Use `true` to enable, `false` to disable.
        """
        await self.config.guild(ctx.guild).leave_enabled.set(true_false)
        status = "enabled" if true_false else "disabled"
        await ctx.send(f"Leave messages are now {status}.")

    @joinleavethreadsset.command(name="leavemessage")
    async def jltset_leavemessage(self, ctx, *, message: str):
        """Set the leave message.

        Use `{member.name}` for member name (mention is not possible as member already left) and `{server.name}` for server name.
        Example: `Goodbye {member.name} from {server.name}!`
        """
        await self.config.guild(ctx.guild).leave_message.set(message)
        await ctx.send(f"Leave message set to: `{message}`")

    @joinleavethreadsset.command(name="leavethread")
    async def jltset_leavethread(self, ctx, thread_or_channel_id: int = None):
        """Set the thread ID or parent channel ID for leave messages.

        If `leavenewthread` is enabled, this should be the ID of the PARENT CHANNEL where new threads will be created.
        Otherwise, this should be the ID of the existing THREAD to send messages to.
        Provide no ID to clear the setting.
        """
        await self.config.guild(ctx.guild).leave_thread_id.set(thread_or_channel_id)
        if thread_or_channel_id:
            fetched_obj = ctx.guild.get_thread(thread_or_channel_id) or ctx.guild.get_channel(thread_or_channel_id)
            obj_type = "Thread/Channel" if fetched_obj else "ID"
            await ctx.send(f"Leave message {obj_type} set to `{thread_or_channel_id}`.")
            if not fetched_obj:
                await ctx.send("Note: I couldn't immediately find a thread or channel with this ID. Make sure it's correct and I have permissions.")
        else:
            await ctx.send("Leave message thread/channel ID cleared.")

    @joinleavethreadsset.command(name="leavenewthread")
    async def jltset_leavenewthread(self, ctx, true_false: bool):
        """Enable or disable creating a new thread for each leave message.

        If enabled, `leavethread` should be set to a parent TEXT CHANNEL ID.
        Use `true` to enable, `false` to disable.
        """
        await self.config.guild(ctx.guild).leave_create_new_thread.set(true_false)
        status = "enabled" if true_false else "disabled"
        await ctx.send(f"Creating new threads for leaves is now {status}.")
        if true_false:
            await ctx.send("Remember to set `leavethread` to the ID of the PARENT TEXT CHANNEL.")
        else:
            await ctx.send("Remember to set `leavethread` to the ID of an EXISTING THREAD.")

    @joinleavethreadsset.command(name="leavethreadname")
    async def jltset_leavethreadname(self, ctx, *, name_format: str):
        """Set the name format for newly created leave threads.

        Only used if `leavenewthread` is enabled.
        Use `{member.name}` for member's name, `{member.id}` for ID, `{server.name}` for server.
        Example: `Farewell {member.name}`
        """
        await self.config.guild(ctx.guild).leave_thread_name_format.set(name_format)
        await ctx.send(f"Leave thread name format set to: `{name_format}`")

    @joinleavethreadsset.command(name="settings")
    async def jltset_settings(self, ctx):
        """Show current JoinLeaveThreads settings."""
        settings = await self.config.guild(ctx.guild).all()
        
        # Helper function to get thread/channel name if possible
        async def get_target_name(id_value):
            if not id_value:
                return "Not set"
            target = ctx.guild.get_thread(id_value) or ctx.guild.get_channel(id_value)
            return f"{target.name} ({id_value})" if target else f"Unknown ({id_value})"

        join_target = await get_target_name(settings["join_thread_id"])
        leave_target = await get_target_name(settings["leave_thread_id"])

        embed = discord.Embed(
            title="JoinLeaveThreads Settings",
            color=await ctx.embed_color(),
            description=f"Settings for {ctx.guild.name}"
        )

        # Join settings
        join_status = "✅ Enabled" if settings["join_enabled"] else "❌ Disabled"
        join_thread_mode = "Create new thread for each join" if settings["join_create_new_thread"] else "Use existing thread"
        embed.add_field(
            name="Join Messages",
            value=(
                f"**Status:** {join_status}\n"
                f"**Mode:** {join_thread_mode}\n"
                f"**Target:** {join_target}\n"
                f"**Message:** {settings['join_message']}\n"
                f"**Thread Name Format:** {settings['join_thread_name_format']}"
            ),
            inline=False
        )

        # Leave settings
        leave_status = "✅ Enabled" if settings["leave_enabled"] else "❌ Disabled"
        leave_thread_mode = "Create new thread for each leave" if settings["leave_create_new_thread"] else "Use existing thread"
        embed.add_field(
            name="Leave Messages",
            value=(
                f"**Status:** {leave_status}\n"
                f"**Mode:** {leave_thread_mode}\n"
                f"**Target:** {leave_target}\n"
                f"**Message:** {settings['leave_message']}\n"
                f"**Thread Name Format:** {settings['leave_thread_name_format']}"
            ),
            inline=False
        )

        await ctx.send(embed=embed)

async def setup(bot):
    await bot.add_cog(JoinLeaveThreads(bot))