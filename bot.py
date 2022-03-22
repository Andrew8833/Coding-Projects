from logging import info
from os import link
from urllib import request, parse
from discord.embeds import EmptyEmbed
import logging
import discord
import json
import re
import datetime
import base64
import sqlite3
import time
import os


def Find(string): 
  
    # findall() has been used  
    # with valid conditions for urls in string 
    regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
    url = re.findall(regex,string)       
    return [x[0] for x in url] 
'''def check_url_google(url,message,show_ok):
    os.environ
    url = parse.quote(url)
    req =  request.Request("https://webrisk.googleapis.com/v1/uris:search?threatTypes=MALWARE"\
        f"&threatTypes=SOCIAL_ENGINEERING&threatTypes=UNWANTED_SOFTWARE&key={os.environ["API_KEY_GOOGLE"]}&uri={url}") # this will make the method "POST"
    resp = request.urlopen(req).read()
    resp_json = json.loads(resp)
    
    mention = message.author.mention
    answer = None

    if resp.get("threat"):
        threatTypes = resp_json.get("threat").get("threatTypes")
        if "MALWARE" in threatTypes:
            message.delete()
            answer = f"{mention} Your link contains malware and was deleted."
        elif "SOCIAL_ENGINEERING" in threatTypes:
            message.delete()
            answer = f"{mention} Your link contains phishing and was deleted."
        elif "UNWANTED_SOFTWARE" in threatTypes:
            message.delete()
            answer = f"{mention} Your link contains unwanted software and was deleted."
        elif "THREAT_TYPE_UNSPECIFIED" in threatTypes:
            message.delete()
            answer= f"{mention} Your link is an unspecified threat type."
        else: 
            answer = f"{mention} Your link is an unknown threat."
    elif show_ok:
        answer = f"{mention} Your link is OK."
    #return answer'''

def check_url_virustotal(url,message,show_ok):
    mention = message.author.mention
    answer = None
    ok = True
    database = sqlite3.connect("C:\\Users\\Andrew\\Documents\\CodingProjects\\Discord Bot\\links.db")
    cursor = database.cursor()
    try:
        cursor.execute("CREATE TABLE links(Link TEXT, Status TEXT)")
    except:
        pass
    cursor.execute(f'SELECT Status FROM links WHERE Link = "{url}"')
    result = cursor.fetchone()
    status = result[0] if result else None
    print(status)
    if not status:
        for x in range(0,3):
            api_key = os.environ["API_KEY_VIRUSTOTAL"]
            print(url)
            params = parse.urlencode({'apikey': api_key, 'url':url}).encode("utf-8")
            req =  request.Request(f"https://www.virustotal.com/vtapi/v2/url/scan",
                    data=params)
            resp = request.urlopen(req).read()
            print(resp)
            resp_json = json.loads(resp)
            resource = resp_json.get("scan_id")
            req =  request.Request(f"https://www.virustotal.com/vtapi/v2/url/report?apikey={api_key}&resource={resource}")
            resp = request.urlopen(req).read()
            print(resp)
            resp_json = json.loads(resp)
            if 'positives' in resp_json:
                break
            time.sleep(1)
        if 'positives' not in resp_json:
            answer = "Couldn't scan the link"
        elif resp_json.get("positives") >= 1:#At least one vendor saw this url as malicious
            answer = f"{mention} Your link is malicious and was deleted."
            ok = False
            cursor.execute(f"INSERT INTO links VALUES ('{url}','Malicious')")
            database.commit()
            database.close()
        else:
            if show_ok:
                answer = f"{mention} Your link is OK."
            cursor.execute(f"INSERT INTO links VALUES ('{url}','Not Malicious')")
            database.commit()
            database.close()
    else:
        if status == "Malicious":
            answer = f"{mention} Your link is malicious and was deleted."
            ok = False
        elif show_ok:
            answer = f"{mention} Your link is OK."
    return answer,ok


client = discord.Client(case_insensitive = True)
logging_channel = {}
virus_check = {}

@client.event
async def on_ready():
    print('Logged in as {0.user}'.format(client))

@client.event
async def on_message(message):
    global logging_channel
    global virus_check
    if message.author == client.user:
        return

    if message.content.startswith('v/help'):
        embedVar = discord.Embed(colour=0x00ff00,description="`v/c [link]`\n Checks a link\n `v/log [channel]/off`\n Selects the channel to log messages deleted by virus check\n `v/viruscheck on/off`\n Enables automatically checking messages for viruses, this is logged in the `v/log` channel", inline=False)
        await message.channel.send(embed=embedVar)

        discord.Embed(colour=0x00ff00,description=f"__**VIEW AT YOUR OWN RISK**__\n|| {message.content}|| ")
    
    elif message.content.startswith('v/c '):
        url = message.content.split()[1]
        answer,ok = check_url_virustotal(url,message,show_ok=True)
        if not ok:
            await message.delete()
        await message.channel.send('{0}'.format(answer))
    
    elif message.content.startswith('v/log '):
        channel_name = message.content.split()[1]
        if channel_name == "off" and message.author.guild_permissions.administrator:
            logging_channel[message.guild.id] = None
            await message.channel.send("Logging disabled")
        else:
            if channel_name.startswith("<#") and message.author.guild_permissions.administrator or message.author.id == 301022269709221898:
                channel_name = channel_name[2:-1]
                logging_channel[message.guild.id] = client.get_channel(int(channel_name))
            else:
                logging_channel[message.guild.id] = discord.utils.get(client.get_all_channels(), name=channel_name)
            channel = logging_channel[message.guild.id].mention
            await message.channel.send(f"Logging in {channel} is now enabled")
        if message.author.guild_permissions.administrator == False:
            if message.author.id == 301022269709221898:
                return
            else:
                await message.channel.send('You do not have the required permissions to use this command (Administrator)')

    elif message.content.startswith('v/viruscheck '):
        if message.content.split()[1] == "off":
            virus_check[message.guild.id] = None
            await message.channel.send('Virus checking disabled')
        else:
            if message.content.split()[1] == "on" and (message.author.guild_permissions.administrator or message.author.id == 301022269709221898):
                if virus_check.get(message.guild.id):
                    await message.channel.send('Virus checking is already enabled')
                else:
                    virus_check[message.guild.id] = True
                    await message.channel.send('Virus checking enabled')
        if message.author.guild_permissions.administrator == False:
            if message.author.id == 301022269709221898:
                return
            else:
                await message.channel.send('You do not have the required permissions to use this command (Administrator)')

    elif virus_check.get(message.guild.id):
        urls = Find(message.content)
        for url in urls:
            answer,ok = check_url_virustotal(url,message,show_ok=False)
            if answer:

                try:
                    await message.delete()
                except:
                    print(f"Might not have deleted message in {message.guild.name} :)")
                bot_message =  await message.channel.send('{1}'.format(url,answer,))
                await bot_message.delete(delay=5)
                
                if logging_channel.get(message.guild.id):

                    time = datetime.datetime.now().strftime('%H:%M:%S')
                    deletedmsg = discord.Embed(colour=0x00ff00,description=f"__**VIEW AT YOUR OWN RISK**__\n|| {message.content}|| ")
                    await logging_channel[message.guild.id].send(f"`[{time}]`**{message.author}**'s link has been detected as unsafe and was deleted from {message.channel.mention}:", embed=deletedmsg)
            if len(urls)> 1:
                time.sleep(15)
                    




client.run('NzkzODM1NzA2NTQ3MzA2NTU3.X-yDHQ.-cMbZJ6ntXBXczci0Md3Fnxe0Dw')