# Active Directory Web Services (ADWS) Enumeracija i prikriveno prikupljanje

{{#include ../../banners/hacktricks-training.md}}

## Šta je ADWS?

Active Directory Web Services (ADWS) je **omogućen po defaultu na svakom Domain Controller-u od Windows Server 2008 R2** i sluša na TCP **9389**. Uprkos imenu, **nema HTTP-a**. Umesto toga, servis izlaže LDAP-style podatke kroz sloj proprietarnih .NET framing protokola:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Pošto je saobraćaj enkapsuliran unutar ovih binarnih SOAP frejmova i ide preko neuobičajenog porta, **enumeracija preko ADWS-a je znatno manje verovatno da će biti inspektovana, filtrirana ili signature-ovana nego klasični LDAP/389 & 636 saobraćaj**. Za operatore to znači:

* Diskretniji izviđaj – Blue teams često fokusiraju na LDAP upite.
* Mogućnost prikupljanja sa **non-Windows hostova (Linux, macOS)** tunelovanjem 9389/TCP kroz SOCKS proxy.
* Isti podaci koje biste dobili preko LDAP-a (users, groups, ACLs, schema, itd.) i mogućnost izvođenja **write** operacija (npr. `msDs-AllowedToActOnBehalfOfOtherIdentity` za **RBCD**).

ADWS interakcije su implementirane preko WS-Enumeration: svaki upit počinje sa `Enumerate` porukom koja definiše LDAP filter/atribute i vraća `EnumerationContext` GUID, nakon čega sledi jedna ili više `Pull` poruka koje stream-uju do serverom definisanog result window-a. Konteksti isteknu nakon ~30 minuta, pa alati moraju paginirati rezultate ili podeliti filtere (prefiks upiti po CN) da bi se izbegao gubitak stanja. Kada tražite security descriptors, navedite kontrolu `LDAP_SERVER_SD_FLAGS_OID` da izostavite SACLs, inače ADWS jednostavno izostavi atribut `nTSecurityDescriptor` iz svog SOAP odgovora.

> NAPOMENA: ADWS se takođe koristi u mnogim RSAT GUI/PowerShell alatima, pa se saobraćaj može uklopiti u legitimne administratorske aktivnosti.

## SoaPy – Nativni Python klijent

[SoaPy](https://github.com/logangoins/soapy) je **potpuna reimplementacija ADWS protocol stack-a u čistom Python-u**. On sastavlja NBFX/NBFSE/NNS/NMF frejmove bajt-po-bajt, omogućavajući prikupljanje sa Unix-like sistema bez dodirivanja .NET runtime-a.

### Ključne karakteristike

* Podržava **proksiranje preko SOCKS** (korisno iz C2 implantata).
* Fino-granularni search filteri identični LDAP `-q '(objectClass=user)'`.
* Opcione **write** operacije ( `--set` / `--delete` ).
* **BOFHound output mode** za direktan unos u BloodHound.
* `--parse` zastavica za lepše prikazivanje timestamps / `userAccountControl` kada je potrebna čitljivost za ljude.

### Ciljne zastavice za prikupljanje i operacije upisa

SoaPy dolazi sa kuriranim switch-evima koji repliciraju najčešće LDAP hunting zadatke preko ADWS-a: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, plus raw `--query` / `--filter` opcije za custom pulls. Povežite ih sa write primitivima kao što su `--rbcd <source>` (postavlja `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging za ciljani Kerberoasting) i `--asrep` (flip `DONT_REQ_PREAUTH` u `userAccountControl`).

Primer ciljane SPN pretrage koja vraća samo `samAccountName` i `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Koristite isti host/credentials da odmah weaponise findings: dump RBCD-capable objects with `--rbcds`, then apply `--rbcd 'WEBSRV01$' --account 'FILE01$'` to stage a Resource-Based Constrained Delegation chain (see [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) for the full abuse path).

### Instalacija (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Sopa - Praktičan klijent za ADWS u Golangu

Slično kao soapy, [sopa](https://github.com/Macmod/sopa) implementira ADWS protocol stack (MS-NNS + MC-NMF + SOAP) u Golangu, izlažući command-line flags za izdavanje ADWS poziva kao što su:

* **Pretraga i preuzimanje objekata** - `query` / `get`
* **Lifecycle objekta** - `create [user|computer|group|ou|container|custom]` i `delete`
* **Uređivanje atributa** - `attr [add|replace|delete]`
* **Upravljanje nalozima** - `set-password` / `change-password`
* i ostali kao `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, itd.

## SOAPHound – Prikupljanje velikih količina iz ADWS (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) je .NET collector koji drži sve LDAP interakcije unutar ADWS i emituje BloodHound v4-compatible JSON. Napravi kompletan cache `objectSid`, `objectGUID`, `distinguishedName` i `objectClass` jednom (`--buildcache`), zatim ga ponovo koristi za visokopropusne `--bhdump`, `--certdump` (ADCS), ili `--dnsdump` (AD-integrated DNS) prolaze tako da samo ~35 kritičnih atributa ikada napusti DC. AutoSplit (`--autosplit --threshold <N>`) automatski deli upite po CN prefiksu da ostane ispod 30-minutnog EnumerationContext timeout-a u velikim forest-ovima.

Tipičan radni tok na operator VM-u pridruženom domenu:
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
Exported JSON slots directly into SharpHound/BloodHound workflows—see [BloodHound methodology](bloodhound.md) for downstream graphing ideas. AutoSplit makes SOAPHound resilient on multi-million object forests while keeping the query count lower than ADExplorer-style snapshots.

## Stealth AD radni tok prikupljanja

Sledeći radni tok pokazuje kako da izlistate **objekte domena i ADCS** preko ADWS, konvertujete ih u BloodHound JSON i tražite puteve napada zasnovane na sertifikatima — sve sa Linuxa:

1. **Tunelujte 9389/TCP** sa ciljne mreže do vaše mašine (npr. preko Chisel, Meterpreter, SSH dynamic port-forward, itd.). Postavite `export HTTPS_PROXY=socks5://127.0.0.1:1080` ili koristite SoaPy’s `--proxyHost/--proxyPort`.

2. **Prikupite root objekat domena:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Prikupi ADCS-povezane objekte iz Configuration NC:**
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
5. **Upload the ZIP** u BloodHound GUI i pokrenite cypher upite kao što su `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` da biste otkrili puteve eskalacije sertifikata (ESC1, ESC8, itd.).

### Pisanje `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Kombinujte ovo sa `s4u2proxy`/`Rubeus /getticket` da biste ostvarili potpun lanac **Resource-Based Constrained Delegation** (pogledajte [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

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
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
