from .glossary import Glossary


def setup(bot):
    bot.add_cog(Glossary(bot))