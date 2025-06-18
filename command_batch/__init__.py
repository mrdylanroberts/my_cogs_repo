from .command_batch import CommandBatch

def setup(bot):
    bot.add_cog(CommandBatch(bot))