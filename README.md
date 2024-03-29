This is a RedBot-Discord Python 3.x (3.5.5) Cog that checks URLs and IPs that are submitted to the Bot's server against VirusTotal
and takes appropriate (defined) action against the user and message.

![image](https://github.com/Grommish/virustotal/assets/4427558/23aac5ec-d25e-4ed2-b21d-7d70de57121e)

![image](https://github.com/Grommish/virustotal/assets/4427558/1dd75e4d-a54d-4a21-b99f-ec270ba2528c)
![image](https://github.com/Grommish/virustotal/assets/4427558/4469bc50-8aab-40a2-8ea1-bac858a33942)



Installation:

On the Host:
Go into your RedBot-Discord data directory `/home/xxxx/RedBot-DiscordBot/<bot_instance>/cogs/CogManager/cogs/` and clone the repo:
- `git clone https://github.com/Grommish/virustotal.git`

This will download the repo into `/home/xxxx/RedBot-DiscordBot/<bot_instance>/cogs/CogManager/cogs/virustotal`

Where `[p]` is RedBot's defined trigger.

Inside Discord:
- `[p]load virustotal`

This will install the cog.

Usage:

`[p]help VirusTotal`
`[p]virustotal` | `[p]vt`
- `[p]vt enable` - This toggles Enable/Disable of link checking (Default: Off)
- `[p]vt reset` - This resets the Cog to the default settings
- `[p]vt set` - Set various configurations for the Cog
  - `[p]vt set api` - Set your VirusTotal API Key
  - `[p]vt set debug` - Toggle Debug Logging into `journalctl` (Default: Off)
  - `[p]vt set punishment` - Set the Punishment Type (Default: Warn)
    - `[p]vt set punishment ban` - Ban the Sender
    - `[p]vt set punishment warn` - Warn the Sender via DM (Not a Server Warn)
    - `[p]vt set punishment punish @<role> #<textchannel>` - Punish the User.  This requires configurating a "Jail" Role and TextChannel to restrict the Sender to
  - `[p]vt set reportschannel` - Set the text channel to send reports to when a bad link is found
  - `[p]vt set threshold` - Set the number of scanners that have to find the link malicious before taking action (Default: 5)
- `[p]vt status` - This shows the current status of the Cog

