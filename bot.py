import discord
from discord.ext import commands
import os
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv('DISCORD_TOKEN')
GUILD_ID = int(os.getenv('GUILD_ID'))
ROLE_ID = int(os.getenv('ROLE_ID'))

intents = discord.Intents.default()
intents.members = True

bot = commands.Bot(command_prefix='!', intents=intents)

@bot.event
async def on_ready():
    print(f'✅ Logged in as {bot.user.name}')

@bot.event
async def on_member_join(member):
    if member.guild.id == GUILD_ID:
        role = member.guild.get_role(ROLE_ID)
        if role:
            await member.add_roles(role)
            print(f"🎉 Assigned role to new member: {member.name}")

@bot.command()
async def grantaccess(ctx):
    if ctx.guild.id == GUILD_ID:
        role = ctx.guild.get_role(ROLE_ID)
        if role:
            await ctx.author.add_roles(role)
            await ctx.send(f"{ctx.author.mention}, you've been granted access.")
        else:
            await ctx.send("⚠️ Role misconfigured.")

bot.run(TOKEN)