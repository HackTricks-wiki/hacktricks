# Kerberos 双跳问题

{{#include ../../banners/hacktricks-training.md}}


## 介绍

Kerberos "Double Hop" 问题出现在当攻击者尝试使用 **Kerberos 在两个跳点之间的认证** **跳点** 时，例如使用 **PowerShell**/**WinRM**。

当通过 **Kerberos** 发生 **authentication** 时，**credentials** **aren't** 被缓存到 **memory**。因此，如果你运行 mimikatz，即使用户正在运行进程，你也 **won't find credentials** 在该机器上。

这是因为使用 Kerberos 连接时的步骤如下：

1. User1 提供 credentials，**域控制器** 返回 Kerberos **TGT** 给 User1。
2. User1 使用 **TGT** 请求 **service ticket** 以 **connect** 到 Server1。
3. User1 **connects** 到 **Server1** 并提供 **service ticket**。
4. **Server1** **doesn't** 拥有 User1 的 **credentials** 缓存或 User1 的 **TGT**。因此，当 User1 从 Server1 尝试登录到第二台服务器时，他 **not able to authenticate**。

### Unconstrained Delegation

如果在 PC 上启用了 **unconstrained delegation**，则不会发生这种情况，因为 **Server** 会获取每个访问它的用户的 **TGT**。此外，如果使用 unconstrained delegation，你很可能可以从中 **compromise the Domain Controller**。\
[**More info in the unconstrained delegation page**](unconstrained-delegation.md).

### CredSSP

另一种可避免此问题但 [**notably insecure**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) 的方法是 **Credential Security Support Provider**。来自 Microsoft 的说明：

> CredSSP authentication 将用户的 credentials 从本地计算机委派到远程计算机。此做法增加了远程操作的安全风险。如果远程计算机被攻破，当 credentials 被传递到该计算机时，这些 credentials 可以被用来控制网络会话。

强烈建议在生产系统、敏感网络和类似环境中由于安全问题禁用 **CredSSP**。要确定是否启用了 **CredSSP**，可以运行命令 `Get-WSManCredSSP`。该命令可用于 **检查 CredSSP 状态**，并且只要启用了 **WinRM**，甚至可以远程执行。
```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
### Remote Credential Guard (RCG)

**Remote Credential Guard** 会将用户的 TGT 保留在源工作站，同时仍允许 RDP 会话在下一跳请求新的 Kerberos 服务票据。启用 **Computer Configuration > Administrative Templates > System > Credentials Delegation > Restrict delegation of credentials to remote servers** 并选择 **Require Remote Credential Guard**，然后使用 `mstsc.exe /remoteGuard /v:server1` 连接，而不是回退到 CredSSP。

在 Windows 11 22H2+ 上，Microsoft 将 RCG 的 multi-hop 访问破坏，直到 **April 2024 cumulative updates** (KB5036896/KB5036899/KB5036894) 才修复。请修补客户端和中间服务器，否则第二跳仍会失败。快速 hotfix 检查：
```powershell
("KB5036896","KB5036899","KB5036894") | ForEach-Object {
Get-HotFix -Id $_ -ErrorAction SilentlyContinue
}
```
在安装了这些构建后，RDP 跳转可以满足下游 Kerberos 的挑战，而无需在第一台服务器上暴露可重用的凭据。

## Workarounds

### Invoke Command

为了解决双跳问题，这里提出了一种包含嵌套 `Invoke-Command` 的方法。它并不能直接根治该问题，但提供了一种无需特殊配置的变通方案。该方法允许通过从初始攻击机器执行的 PowerShell 命令，或通过与第一台服务器已建立的 PS-Session，在第二台服务器上执行命令（`hostname`）。操作方法如下：
```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
作为替代，建议在第一个服务器上建立一个 PS-Session，并使用 `$cred` 运行 `Invoke-Command` 来集中任务。

### 注册 PSSession 配置

绕过双跳问题的一个解决方案是将 `Register-PSSessionConfiguration` 与 `Enter-PSSession` 结合使用。该方法需要与 evil-winrm 不同的方式，并允许建立不受双跳限制的会话。
```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName TARGET_PC -Credential domain_name\username
klist
```
### PortForwarding

对于中间目标上的本地管理员，port forwarding 允许将请求发送到最终服务器。使用 `netsh`，可以添加一条端口转发规则，同时添加一条 Windows firewall 规则以允许被转发的端口。
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` 可用于转发 WinRM 请求，如果担心 PowerShell 被监控，可能是更难被检测到的选项。下面的命令演示了它的用法：
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

在第一台服务器上安装 OpenSSH 可以作为 double-hop 问题的一个变通方法，尤其适用于 jump box 场景。该方法需要通过 CLI 在 Windows 上安装和配置 OpenSSH。当配置为 Password Authentication 时，这允许中间服务器代表用户获取 TGT。

#### OpenSSH 安装步骤

1. 下载并将最新的 OpenSSH release zip 移到目标服务器。
2. 解压并运行 `Install-sshd.ps1` 脚本。
3. 添加防火墙规则以打开 port 22，并验证 SSH services 是否正在运行。

为了解决 `Connection reset` 错误，可能需要更新权限，允许 everyone 对 OpenSSH directory 具有读取和执行权限。
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
### LSA Whisperer CacheLogon (高级)

**LSA Whisperer** (2024) 暴露了 `msv1_0!CacheLogon` 包调用，让你可以用已知的 NT hash 来预置一个已有的 *network logon*，而不是用 `LogonUser` 创建新的会话。通过将 hash 注入到 WinRM/PowerShell 已经在 hop #1 打开的登录会话中，该主机可以在不存储显式凭据或产生额外 4624 事件的情况下，认证到 hop #2。

1. 在 LSASS 内获得代码执行（要么禁用/滥用 PPL，要么在你可控的实验室 VM 上运行）。
2. 枚举登录会话（例如 `lsa.exe sessions`），并捕获与您的远程上下文对应的 LUID。
3. 预先计算 NT hash 并将其提供给 `CacheLogon`，完成后清除它。
```powershell
lsa.exe cachelogon --session 0x3e4 --domain ta --username redsuit --nthash a7c5480e8c1ef0ffec54e99275e6e0f7
lsa.exe cacheclear --session 0x3e4
```
在完成缓存种子后，从 hop #1 重新运行 `Invoke-Command`/`New-PSSession`：LSASS 会重用注入的哈希来应对第二跳的 Kerberos/NTLM 挑战，巧妙地绕过 double hop 限制。代价是更重的遥测（在 LSASS 中执行代码），因此只在 CredSSP/RCG 被禁止的高摩擦环境中使用。

## 参考资料

- [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
- [https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)
- [https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92](https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92)
- [https://specterops.io/blog/2024/04/17/lsa-whisperer/](https://specterops.io/blog/2024/04/17/lsa-whisperer/)


{{#include ../../banners/hacktricks-training.md}}
