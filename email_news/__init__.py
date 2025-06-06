from .email_news import EmailNews

async def setup(bot):
    await bot.add_cog(EmailNews(bot))