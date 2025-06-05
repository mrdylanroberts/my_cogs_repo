from .role_cleanup import RoleCleanup

async def setup(bot):
    await bot.add_cog(RoleCleanup(bot))