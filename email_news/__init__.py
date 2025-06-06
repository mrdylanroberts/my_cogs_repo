import logging
from redbot.core.bot import Red
from .email_news import EmailNews

log = logging.getLogger("red.my-cogs-repo.email_news")

async def setup(bot: Red) -> None:
    try:
        await bot.add_cog(EmailNews(bot))
        log.info("EmailNews cog loaded successfully")
    except Exception as e:
        log.error(f"Failed to load EmailNews cog: {str(e)}")
        raise