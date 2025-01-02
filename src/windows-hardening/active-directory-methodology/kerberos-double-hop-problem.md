# Kerberos Double Hop Problem

{{#include ../../banners/hacktricks-training.md}}

## Introduction

Kerberos "Double Hop" 问题出现在攻击者试图在两个跳跃中使用 **Kerberos 认证** 时，例如使用 **PowerShell**/**WinRM**。

当通过 **Kerberos** 进行 **认证** 时，**凭据** **不会** 被缓存到 **内存** 中。因此，如果你运行 mimikatz，你 **不会找到用户的凭据** 在机器上，即使他正在运行进程。

这是因为在使用 Kerberos 连接时，步骤如下：

1. User1 提供凭据，**域控制器** 返回一个 Kerberos **TGT** 给 User1。
2. User1 使用 **TGT** 请求一个 **服务票据** 以 **连接** 到 Server1。
3. User1 **连接** 到 **Server1** 并提供 **服务票据**。
4. **Server1** **没有** 缓存 User1 的 **凭据** 或 User1 的 **TGT**。因此，当 User1 从 Server1 尝试登录到第二台服务器时，他 **无法进行认证**。

### Unconstrained Delegation

如果在 PC 上启用了 **unconstrained delegation**，则不会发生这种情况，因为 **Server** 将 **获取** 每个访问它的用户的 **TGT**。此外，如果使用了不受限制的委托，你可能会 **妥协域控制器**。\
[**更多信息请参见不受限制的委托页面**](unconstrained-delegation.md)。

### CredSSP

另一种避免此问题的方法是 [**显著不安全**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) 的 **凭据安全支持提供程序**。来自 Microsoft 的说明：

> CredSSP 认证将用户凭据从本地计算机委托到远程计算机。这种做法增加了远程操作的安全风险。如果远程计算机被攻破，当凭据被传递给它时，这些凭据可以用于控制网络会话。

由于安全问题，强烈建议在生产系统、敏感网络和类似环境中禁用 **CredSSP**。要确定 **CredSSP** 是否启用，可以运行 `Get-WSManCredSSP` 命令。此命令允许 **检查 CredSSP 状态**，并且可以在启用 **WinRM** 的情况下远程执行。
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## 解决方法

### Invoke Command

为了解决双跳问题，提出了一种涉及嵌套 `Invoke-Command` 的方法。这并不能直接解决问题，但提供了一种无需特殊配置的变通方法。该方法允许通过从初始攻击机器执行的 PowerShell 命令或通过与第一服务器之前建立的 PS-Session，在辅助服务器上执行命令（`hostname`）。以下是具体操作步骤：
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
另外，建议与第一个服务器建立 PS-Session 并使用 `$cred` 运行 `Invoke-Command` 来集中任务。

### 注册 PSSession 配置

绕过双跳问题的解决方案涉及使用 `Register-PSSessionConfiguration` 和 `Enter-PSSession`。这种方法需要与 `evil-winrm` 不同的方法，并允许一个不受双跳限制的会话。
```powershell
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### PortForwarding

对于中介目标上的本地管理员，端口转发允许请求发送到最终服务器。使用 `netsh`，可以添加一个端口转发规则，以及一个 Windows 防火墙规则以允许转发的端口。
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` 可用于转发 WinRM 请求，如果 PowerShell 监控是一个问题，它可能是一个不太容易被检测到的选项。下面的命令演示了它的用法：
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

在第一台服务器上安装 OpenSSH 可以为双跳问题提供解决方法，特别适用于跳板机场景。此方法需要在 Windows 上进行 CLI 安装和配置 OpenSSH。当配置为密码认证时，这允许中介服务器代表用户获取 TGT。

#### OpenSSH 安装步骤

1. 下载并将最新的 OpenSSH 发布 zip 移动到目标服务器。
2. 解压并运行 `Install-sshd.ps1` 脚本。
3. 添加防火墙规则以打开 22 端口，并验证 SSH 服务是否正在运行。

要解决 `Connection reset` 错误，可能需要更新权限以允许所有人对 OpenSSH 目录的读取和执行访问。
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## 参考

- [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
- [https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)


{{#include ../../banners/hacktricks-training.md}}
