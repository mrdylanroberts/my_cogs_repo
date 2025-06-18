from .help_detector import HelpDetector

async def setup(bot):
    await bot.add_cog(HelpDetector(bot))