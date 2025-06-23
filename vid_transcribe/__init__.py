from .vid_transcribe import VidTranscribe


async def setup(bot):
    await bot.add_cog(VidTranscribe(bot))