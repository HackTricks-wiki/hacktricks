# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## Šta je ADWS?

Active Directory Web Services (ADWS) je **podrazumevano omogućen na svakom Domain Controller-u počev od Windows Server 2008 R2** i osluškuje TCP port **9389**.  Uprkos nazivu, **HTTP se ne koristi**.  Umesto toga, servis izlaže podatke u LDAP stilu kroz stek vlasničkih .NET framing protokola:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Pošto je saobraćaj enkapsuliran unutar ovih binarnih SOAP frame-ova i odvija se preko neuobičajenog porta, **enumeration kroz ADWS je mnogo manje verovatno da će biti nadziran, filtriran ili prepoznat potpisom nego klasični LDAP/389 i 636 saobraćaj**.  Za operatore to znači:<sup>[[1]](#references)[[7]](#references)</sup>

* Stealthier recon – Blue timovi se često koncentrišu na LDAP upite.
* Mogućnost prikupljanja podataka sa **non-Windows hostova (Linux, macOS)** tunelovanjem 9389/TCP kroz SOCKS proxy.
* Isti podaci koje biste dobili putem LDAP-a (users, groups, ACLs, schema itd.), kao i mogućnost izvršavanja **write** operacija (npr. `msDs-AllowedToActOnBehalfOfOtherIdentity` za **RBCD**).

ADWS interakcije se implementiraju preko WS-Enumeration-a: svaki query počinje porukom `Enumerate` koja definiše LDAP filter/atribute i vraća GUID za `EnumerationContext`, nakon čega sledi jedna ili više `Pull` poruka koje prosleđuju rezultate do server-defined result window-a.<sup>[[7]](#references)</sup> Contexts ističu nakon približno 30 minuta, pa tooling mora da paginira rezultate ili podeli filtere (prefix queries po CN-u) kako bi se izbegao gubitak stanja.<sup>[[8]](#references)</sup> Prilikom zahtevanja security descriptors-a navedite `LDAP_SERVER_SD_FLAGS_OID` control kako biste izostavili SACL-ove; u suprotnom ADWS jednostavno izostavlja atribut `nTSecurityDescriptor` iz svog SOAP response-a.

> NAPOMENA: ADWS koriste i mnogi RSAT GUI/PowerShell alati, pa se saobraćaj može stopiti sa legitimnom administratorskom aktivnošću.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) je **potpuna reimplementacija ADWS protocol stack-a u čistom Python-u**.  On kreira NBFX/NBFSE/NNS/NMF frame-ove byte-for-byte, omogućavajući collection sa Unix-like sistema bez korišćenja .NET runtime-a.<sup>[[1]](#references)[[2]](#references)</sup>

### Key Features

* Podržava **proxying kroz SOCKS** (korisno iz C2 implant-a).
* Fine-grained search filters identični LDAP-u `-q '(objectClass=user)'`.
* Opcionе **write** operacije ( `--set` / `--delete` ).
* **BOFHound output mode** za direktan unos u BloodHound.
* `--parse` flag za formatiranje timestamps / `userAccountControl` vrednosti radi bolje čitljivosti kada je to potrebno.<sup>[[2]](#references)</sup>

### Targeted collection flags & write operations

SoaPy dolazi sa curated switches koji repliciraju najčešće LDAP hunting zadatke preko ADWS-a: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, kao i raw `--query` / `--filter` opcije za custom pulls.  Uparite ih sa write primitives kao što su `--rbcd <source>` (postavlja `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging za targeted Kerberoasting) i `--asrep` (menja `DONT_REQ_PREAUTH` u `userAccountControl`).<sup>[[2]](#references)</sup>

Primer targeted SPN hunt-a koji vraća samo `samAccountName` i `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Koristi isti host/credentials da odmah operacionalizuješ nalaze: dumpuj objekte koji podržavaju RBCD pomoću `--rbcds`, zatim primeni `--rbcd 'WEBSRV01$' --account 'FILE01$'` da pripremiš lanac Resource-Based Constrained Delegation (pogledaj [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) za kompletan abuse path).

### Instalacija (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump preko ADWS (Linux/Windows)

* Fork `ldapdomaindump` alata koji LDAP upite zamenjuje ADWS pozivima preko TCP/9389 radi smanjenja broja detekcija LDAP potpisa.
* Obavlja početnu proveru dostupnosti porta 9389, osim ako je prosleđen `--force` (preskače proveru ako skeniranja portova generišu mnogo buke ili su filtrirana).
* Testirano sa Microsoft Defender for Endpoint i CrowdStrike Falcon, uz uspešan bypass naveden u README dokumentu.<sup>[[4]](#references)</sup>

### Instalacija
```bash
pipx install .
```
### Upotreba
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
Tipičan izlaz beleži proveru dostupnosti porta 9389, ADWS bind i početak/završetak dump-a:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Praktičan klijent za ADWS u Golangu

Slično kao soapy, [sopa](https://github.com/Macmod/sopa) implementira ADWS protocol stack (MS-NNS + MC-NMF + SOAP) u Golangu, izlažući command-line flags za izdavanje ADWS poziva kao što su:<sup>[[5]](#references)</sup>

* **Pretraga i preuzimanje objekata** - `query` / `get`
* **Životni ciklus objekata** - `create [user|computer|group|ou|container|custom]` i `delete`
* **Uređivanje atributa** - `attr [add|replace|delete]`
* **Upravljanje nalozima** - `set-password` / `change-password`
* i drugi, kao što su `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, itd.

### Najvažnije stavke mapiranja protokola

* LDAP-style pretrage se izvršavaju putem **WS-Enumeration** (`Enumerate` + `Pull`) uz projekciju atributa, kontrolu opsega (Base/OneLevel/Subtree) i pagination.
* Preuzimanje pojedinačnog objekta koristi **WS-Transfer** `Get`; izmene atributa koriste `Put`; brisanja koriste `Delete`.
* Ugrađeno kreiranje objekata koristi **WS-Transfer ResourceFactory**; custom objekti koriste **IMDA AddRequest** kojim upravljaju YAML templates.
* Operacije sa lozinkama su **MS-ADCAP** actions (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Otkrivanje metapodataka bez autentikacije (mex)

ADWS izlaže WS-MetadataExchange bez credentials, što je brz način za proveru izloženosti pre autentikacije:<sup>[[5]](#references)</sup>
```bash
sopa mex --dc <DC>
```
### Beleške o DNS/DC otkrivanju i Kerberos targetiranju

Sopa može da pronađe DC-ove putem SRV-a ako je `--dc` izostavljen, a `--domain` naveden. Upite izvršava ovim redosledom i koristi cilj sa najvišim prioritetom:<sup>[[5]](#references)</sup>
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
Operativno, prednost dajte resolveru kojim upravlja DC da biste izbegli greške u segmentiranim okruženjima:

* Koristite `--dns <DC-IP>` kako bi se **svi** SRV/PTR/forward upiti izvršavali preko DC DNS-a.
* Koristite `--dns-tcp` kada je UDP blokiran ili su SRV odgovori veliki.
* Ako je Kerberos omogućen, a `--dc` je IP adresa, sopa izvršava **reverse PTR** upit da bi dobio FQDN za ispravno SPN/KDC usmeravanje. Ako se Kerberos ne koristi, PTR upit se ne izvršava.

Primer (IP + Kerberos, prisilni DNS preko DC-a):
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### Opcije autentikacionog materijala

Pored plaintext lozinki, sopa podržava **NT hashes**, **Kerberos AES keys**, **ccache** i **PKINIT certificates** (PFX ili PEM) za ADWS auth. Kerberos se podrazumeva kada se koriste `--aes-key`, `-c` (ccache) ili opcije zasnovane na certificates.<sup>[[5]](#references)</sup>
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### Kreiranje prilagođenih objekata putem templates

Za proizvoljne klase objekata, komanda `create custom` koristi YAML template koji se mapira na IMDA `AddRequest`:<sup>[[5]](#references)</sup>

* `parentDN` i `rdn` definišu kontejner i relativni DN.
* `attributes[].name` podržava `cn` ili imenovani prostor `addata:cn`.
* `attributes[].type` prihvata `string|int|bool|base64|hex` ili eksplicitni `xsd:*`.
* Nemojte uključivati `ad:relativeDistinguishedName` ili `ad:container-hierarchy-parent`; sopa ih automatski ubacuje.
* Vrednosti `hex` konvertuju se u `xsd:base64Binary`; koristite `value: ""` za postavljanje praznih stringova.

## SOAPHound – ADWS prikupljanje velikog obima (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) je .NET collector koji sve LDAP interakcije zadržava unutar ADWS-a i generiše JSON kompatibilan sa BloodHound v4. Jednom pravi kompletan keš vrednosti `objectSid`, `objectGUID`, `distinguishedName` i `objectClass` (`--buildcache`), a zatim ga ponovo koristi za `--bhdump`, `--certdump` (ADCS) ili `--dnsdump` (DNS integrisan u AD), tako da samo ~35 kritičnih atributa ikada napusti DC. AutoSplit (`--autosplit --threshold <N>`) automatski deli upite prema CN prefiksu kako bi ostali ispod 30-minutnog ograničenja `EnumerationContext` u velikim forestima.<sup>[[8]](#references)</sup>

Tipičan workflow na operatorskoj VM koja je pridružena domenu:
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
Izvezeni JSON slotovi direktno u SharpHound/BloodHound workflows — pogledajte [BloodHound methodology](bloodhound.md) za ideje o downstream graphing-u. AutoSplit čini SOAPHound otpornim na forest-e sa više miliona objekata, uz održavanje manjeg broja upita nego kod ADExplorer-style snapshot-a.

## Stealth AD Collection Workflow

Sledeći workflow prikazuje kako da enumerišete **domain & ADCS objekte** preko ADWS-a, konvertujete ih u BloodHound JSON i tražite attack paths zasnovane na certificate-ima – sve iz Linux-a:

1. **Tunelujte 9389/TCP** iz target network-a do svoje mašine (npr. preko Chisel-a, Meterpreter-a, SSH dynamic port-forward-a itd.).  Export `export HTTPS_PROXY=socks5://127.0.0.1:1080` ili koristite SoaPy `--proxyHost/--proxyPort`.

2. **Prikupite root domain objekat:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Prikupite objekte povezane sa ADCS-om iz Configuration NC-a:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-dn 'CN=Configuration,DC=ludus,DC=domain' \
-q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
| tee data/adcs.log
```
4. **Pretvorite u BloodHound:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **Otpremite ZIP** u BloodHound GUI i pokrenite cypher upite kao što je `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` da biste otkrili putanje za eskalaciju privilegija putem sertifikata (ESC1, ESC8 itd.).

### Upisivanje `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Kombinujte ovo sa `s4u2proxy`/`Rubeus /getticket` za potpunu **Resource-Based Constrained Delegation** lančanu tehniku (pogledajte [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Sažetak alata

| Namena | Alat | Napomene |
|---------|------|-------|
| ADWS enumeracija | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| ADWS dump velikog obima | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS režimi |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Konvertuje SoaPy/ldapsearch logove |
| Kompromitacija sertifikata | [Certipy](https://github.com/ly4k/Certipy) | Može se proslediti preko istog SOCKS-a |
| ADWS enumeracija i izmene objekata | [sopa](https://github.com/Macmod/sopa) | Generički klijent za interakciju sa poznatim ADWS endpointima - omogućava enumeraciju, kreiranje objekata, izmene atributa i promene lozinki |

## Reference

- [1] [SpecterOps – Uverite se da koristite SOAP(y) – Vodič za operatere za stealthy AD prikupljanje podataka pomoću ADWS-a](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – specifikacije MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Stealthy enumeracija Active Directory okruženja kroz ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – SOAPHound alat za prikupljanje Active Directory podataka putem ADWS-a](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
