from .virustotal_scanner import VirusTotalScanner

async def setup(bot):
    await bot.add_cog(VirusTotalScanner(bot))