from .joinleave_threads import JoinLeaveThreads

async def setup(bot):
    await bot.add_cog(JoinLeaveThreads(bot))