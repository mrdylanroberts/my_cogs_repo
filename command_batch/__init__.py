from .command_batch import CommandBatch

async def setup(bot):
    await bot.add_cog(CommandBatch(bot))
