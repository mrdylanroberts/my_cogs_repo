from .debug_logs import DebugLogs

def setup(bot):
    bot.add_cog(DebugLogs(bot))
