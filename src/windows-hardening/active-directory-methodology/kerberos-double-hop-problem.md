# Kerberos Double Hop Problem

{{#include ../../banners/hacktricks-training.md}}


## Introduction

当攻击者尝试通过两个 **hops** 使用 **Kerberos authentication** 时，就会出现 Kerberos "Double Hop" problem，例如使用 **PowerShell**/**WinRM**。

当通过 **Kerberos** 进行 **authentication** 时，**credentials** **不会**缓存到 **memory** 中。因此，即使用户正在运行进程，执行 mimikatz 时也**找不到该用户的 credentials**。

这是因为使用 Kerberos 连接时会执行以下步骤：<sup>[[1]](#references)</sup>

1. User1 提供 credentials，**domain controller** 向 User1 返回 Kerberos **TGT**。
2. User1 使用 **TGT** 请求 **service ticket**，以便 **connect** 到 Server1。
3. User1 **connects** 到 **Server1**，并提供 **service ticket**。
4. **Server1** 不会缓存 User1 的 **credentials** 或 User1 的 **TGT**。因此，当 User1 从 Server1 尝试登录第二台服务器时，他**无法进行 authentication**。

### Unconstrained Delegation

如果 PC 启用了 **unconstrained delegation**，则不会发生这种情况，因为 **Server** 会 **get** 每个访问它的用户的 **TGT**。此外，如果使用 unconstrained delegation，你可能可以从该服务器**攻陷 Domain Controller**。\
[**More info in the unconstrained delegation page**](unconstrained-delegation.md)。

### CredSSP

另一种避免此问题的方法是使用 [**notably insecure**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) 的 **Credential Security Support Provider**。Microsoft 的说明如下：

> CredSSP authentication 会将用户 credentials 从本地计算机委派到远程计算机。这种做法会增加远程操作的安全风险。如果远程计算机遭到 compromise，当 credentials 传递给它时，这些 credentials 可被用于控制 network session。

由于安全问题，强烈建议在 production systems、sensitive networks 及类似环境中禁用 **CredSSP**。要确定是否启用了 **CredSSP**，可以运行 `Get-WSManCredSSP` 命令。该命令可用于**checking of CredSSP status**，并且在启用 **WinRM** 的情况下，甚至可以 remotely 执行。
```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
### Remote Credential Guard（RCG）

**Remote Credential Guard** 会将用户的 TGT 保留在发起连接的工作站上，同时仍允许 RDP 会话在下一跳请求新的 Kerberos service tickets。启用 **Computer Configuration > Administrative Templates > System > Credentials Delegation > Restrict delegation of credentials to remote servers**，并选择 **Require Remote Credential Guard**，然后使用 `mstsc.exe /remoteGuard /v:server1` 进行连接，而不是回退到 CredSSP。

在 Windows 11 22H2+ 上，Microsoft 曾导致 RCG 的 multi-hop 访问失效，直到安装 **April 2024 cumulative updates**（KB5036896/KB5036899/KB5036894）后才修复。请为客户端和中间服务器安装补丁，否则第二跳仍会失败。<sup>[[5]](#references)</sup> 快速检查 hotfix：
```powershell
("KB5036896","KB5036899","KB5036894") | ForEach-Object {
Get-HotFix -Id $_ -ErrorAction SilentlyContinue
}
```
安装这些 build 后，RDP hop 可以满足下游 Kerberos challenges，而无需在第一台 server 上暴露可复用的 secrets。

## 解决方法

### Invoke Command

为解决 double hop 问题，这里介绍一种涉及嵌套 `Invoke-Command` 的方法。它并不能直接解决该问题，但提供了一种无需特殊配置的 workaround。该方法允许通过从初始 attacking machine 执行的 PowerShell 命令，或通过之前与第一台 server 建立的 PS-Session，在 secondary server 上执行命令（`hostname`）。具体如下：<sup>[[2]](#references)</sup>
```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
或者，建议先与第一台服务器建立 PS-Session，然后使用 `$cred` 运行 `Invoke-Command`，以集中执行任务。

### Register PSSession Configuration

绕过 double hop 问题的一种方案是将 `Register-PSSessionConfiguration` 与 `Enter-PSSession` 结合使用。此方法与 `evil-winrm` 所采用的方法不同，并允许建立不受 double hop 限制影响的会话。<sup>[[3]](#references)[[4]](#references)</sup>
```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName TARGET_PC -Credential domain_name\username
klist
```
### PortForwarding

对于中间目标上的本地管理员，端口转发允许将请求发送到最终服务器。使用 `netsh` 可以添加端口转发规则，同时添加 Windows 防火墙规则以允许转发的端口。<sup>[[2]](#references)</sup>
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` 可用于转发 WinRM 请求；如果担心 PowerShell 监控，这可能是一种更难被检测到的选项。<sup>[[2]](#references)</sup> 以下命令演示了其用法：
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

在第一台服务器上安装 OpenSSH 可以为 double-hop 问题提供一种解决方法，尤其适用于 jump box 场景。此方法需要通过 CLI 安装并配置适用于 Windows 的 OpenSSH。配置为 Password Authentication 后，中间服务器便可代表用户获取 TGT。<sup>[[2]](#references)</sup>

#### OpenSSH 安装步骤

1. 下载最新的 OpenSSH release zip，并将其移动到目标服务器。
2. 解压并运行 `Install-sshd.ps1` 脚本。
3. 添加防火墙规则以开放端口 22，并确认 SSH 服务正在运行。

要解决 `Connection reset` 错误，可能需要更新权限，以允许 everyone 对 OpenSSH 目录具有读取和执行权限。
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
### LSA Whisperer CacheLogon (Advanced)

**LSA Whisperer** (2024) 暴露了 `msv1_0!CacheLogon` package call，因此你可以使用已知的 NT hash 为现有的 *network logon* 注入凭据，而不是通过 `LogonUser` 创建全新的 session。将 hash 注入 WinRM/PowerShell 已在 hop #1 上打开的 logon session 后，该主机便可以向 hop #2 进行身份验证，无需存储显式凭据，也不会生成额外的 4624 事件。<sup>[[6]](#references)</sup>

1. 在 LSASS 内部获取代码执行权限（禁用/滥用 PPL，或在你控制的 lab VM 上运行）。
2. 枚举 logon sessions（例如 `lsa.exe sessions`），并获取与你的 remoting context 对应的 LUID。
3. 预先计算 NT hash 并将其传递给 `CacheLogon`，完成后将其清除。
```powershell
lsa.exe cachelogon --session 0x3e4 --domain ta --username redsuit --nthash a7c5480e8c1ef0ffec54e99275e6e0f7
lsa.exe cacheclear --session 0x3e4
```
在 cache seed 之后，从 hop #1 重新运行 `Invoke-Command`/`New-PSSession`：LSASS 将重复使用注入的 hash 来满足第二跳的 Kerberos/NTLM challenges，从而巧妙地绕过 double hop 限制。代价是更重的 telemetry（在 LSASS 中执行代码），因此应将其保留用于禁止使用 CredSSP/RCG 的高摩擦环境。

## References

- [1] [Understanding Kerberos Double Hop - Microsoft Community Hub](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [2] [Kerberos Double-Hop Workarounds](https://posts.slayerlabs.com/double-hop/)
- [3] [Another solution to multi-hop PowerShell remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [4] [Solve the PowerShell multi-hop problem without using CredSSP](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)
- [5] [April 9, 2024—KB5036896 (OS Build 17763.5696)](https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92)
- [6] [LSA Whisperer](https://specterops.io/blog/2024/04/17/lsa-whisperer/)

{{#include ../../banners/hacktricks-training.md}}
