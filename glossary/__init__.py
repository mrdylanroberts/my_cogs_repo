from .glossary import Glossary


from .glossary import Glossary

async def setup(bot):
    await bot.add_cog(Glossary(bot))