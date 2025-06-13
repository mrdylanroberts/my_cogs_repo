import logging
from redbot.core.bot import Red
from .virustotal_scanner import VirusTotalScanner

log = logging.getLogger("red.my-cogs-repo.virustotal_scanner")

async def setup(bot: Red) -> None:
    try:
        await bot.add_cog(VirusTotalScanner(bot))
        log.info("VirusTotalScanner cog loaded successfully")
    except Exception as e:
        log.error(f"Failed to load VirusTotalScanner cog: {e}", exc_info=True)
        raise