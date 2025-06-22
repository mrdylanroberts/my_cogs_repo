from .debug_logs import DebugLogs

async def setup(bot):
    await bot.add_cog(DebugLogs(bot))
