# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Pregled

Mnogi arhivski formati (ZIP, RAR, TAR, 7-ZIP itd.) omogućavaju da svaki unos sadrži sopstvenu **internu putanju**. Kada alat za ekstrakciju slepo poštuje tu putanju, kreirano ime datoteke koje sadrži `..` ili **apsolutnu putanju** (npr. `C:\Windows\System32\`) biće zapisano izvan direktorijuma koji je korisnik izabrao.
Ova klasa ranjivosti je opšte poznata kao *Zip-Slip* ili **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Posledice se kreću od prepisivanja proizvoljnih datoteka do direktnog postizanja **remote code execution (RCE)** ubacivanjem payload-a na lokaciju sa **auto-run** funkcijom, kao što je Windows *Startup* folder.

## Osnovni uzrok

1. Napadač kreira arhivu u kojoj jedno ili više zaglavlja datoteka sadrže:
* Relativne traversal sekvence (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Apsolutne putanje (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Ili kreirane **symlink-ove** koji se razrešavaju izvan ciljnog direktorijuma (uobičajeno u ZIP/TAR formatima na *nix* sistemima).
2. Žrtva ekstraktuje arhivu pomoću ranjivog alata koji veruje ugrađenoj putanji (ili prati symlink-ove), umesto da je sanitizuje ili primora ekstrakciju unutar izabranog direktorijuma.
3. Datoteka se zapisuje na lokaciju pod kontrolom napadača i izvršava/učitava sledeći put kada sistem ili korisnik aktivira tu putanju.

### .NET `Path.Combine` + `ZipArchive` traversal

Čest .NET anti-pattern je kombinovanje predviđenog odredišta sa `user-controlled` `ZipArchiveEntry.FullName` vrednošću i ekstrakcija bez normalizacije putanje:<sup>[[4]](#references)[[8]](#references)</sup>
```csharp
using (var zip = ZipFile.OpenRead(zipPath))
{
foreach (var entry in zip.Entries)
{
var dest = Path.Combine(@"C:\samples\queue\", entry.FullName); // drops base if FullName is absolute
entry.ExtractToFile(dest);
}
}
```
- Ako `entry.FullName` počinje sa `..\\`, vrši traversal; ako je **absolute path**, leva komponenta se u potpunosti odbacuje, što dovodi do **arbitrary file write** kao identiteta ekstrakcije.
- Proof-of-concept archive za upisivanje u susedni `app` direktorijum koji nadgleda scheduled scanner:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Ubаcivanje tog ZIP-a u nadzirani inbox rezultuje fajlom `C:\samples\app\0xdf.txt`, čime se dokazuje traversal izvan `C:\samples\queue\` i omogućavaju naknadne primitive (npr. DLL hijacks).

## Primer iz stvarnog sveta – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR za Windows i njegove Windows RAR/UnRAR komponente nisu validirale nazive fajlova tokom ekstrakcije. Propust je koristio NTFS alternate data streams (ADS) za zaobilaženje izabrane putanje za ekstrakciju i upisivanje fajlova na nenamerne lokacije.<sup>[[5]](#references)</sup>
Zlonamerni RAR archive koji sadrži unos kao što je:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
bi završila **izvan** izabranog izlaznog direktorijuma i unutar korisničkog *Startup* foldera. ESET je uočio da su se zlonamerni LNK fajlovi tamo raspakivali i izvršavali pri prijavljivanju korisnika, obezbeđujući persistence i putanju do RCE.<sup>[[5]](#references)</sup>

### Kreiranje PoC arhive (Linux/Mac)

Pošto CVE-2025-8088 koristi traversal putanju u ADS imenu, koristite namenski generator za kreiranje RAR arhive, a zatim testirajte ekstrakciju samo u izolovanoj lab ortam sa ranjivom WinRAR verzijom.<sup>[[5]](#references)</sup>

### Uočena Eksploatacija u Wild

ESET je prijavio spear-phishing kampanje grupe RomCom (Storm-0978/UNC2596) koje su slale RAR arhive koje zloupotrebljavaju CVE-2025-8088 za postavljanje prilagođenih backdoor-a i olakšavanje ransomware operacija.<sup>[[5]](#references)</sup>

## Noviji slučajevi (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Greška**: ZIP unosi koji su **symbolic links** dereferencirali su se tokom ekstrakcije, omogućavajući napadačima da izađu iz odredišnog direktorijuma i prepišu proizvoljne putanje. Interakcija korisnika svodi se samo na *otvaranje/ekstrakciju* arhive.<sup>[[1]](#references)</sup>
* **Pogođeno**: 7-Zip builds pre **25.00**. Greška u obradi symbolic link-ova ispravljena je u verziji **25.00** (jul 2025) i novijim verzijama.<sup>[[1]](#references)[[10]](#references)</sup>
* **Putanja uticaja**: Prepisivanje lokacija `Start Menu/Programs/Startup` ili onih koje pokreću servisi → kod se izvršava pri sledećem prijavljivanju ili ponovnom pokretanju servisa.
* **Brzi fixture za rukovanje symlink-ovima (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Ova arhiva sadrži symlink unos koji pokazuje izvan direktorijuma za ekstrakciju; koristite odredište namenjeno za jednokratnu upotrebu i proverite da extractor ne prati taj link. Test prolaznog upisivanja takođe zahteva regular-file unos ispod symlink-a.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Greška**: `archiver.Unarchive()` prati `../` i symlinkovane ZIP unose, upisujući izvan `outputDir`.<sup>[[2]](#references)</sup>
* **Pogođeno**: `github.com/mholt/archiver` ≤ 3.5.1 (projekat je sada deprecated).
* **Ispravka**: Pređite na `mholt/archives` ≥ 0.1.0 ili implementirajte provere canonical path-a pre upisivanja.
* **Minimalna reprodukcija**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Saveti za detekciju

* **Statička inspekcija** – Izlistajte unose arhive i označite svako ime koje sadrži `../`, `..\\`, *apsolutne putanje* (`/`, `C:`) ili unose tipa *symlink* čije se odredište nalazi izvan direktorijuma za ekstrakciju.
* **Canonicalisation** – Obezbedite da `realpath(join(dest, name))` ostane unutar `realpath(dest)` (upoređujte komponente putanje, a ne samo sirovi string prefix). U suprotnom odbijte unos.<sup>[[3]](#references)</sup>
* **Sandbox ekstrakcija** – Dekompresujte u direktorijum namenjen za jednokratnu upotrebu koristeći extractor sa proverama putanja/symlink-ova (na primer, podrazumevane bezbedne provere bsdtar-a ili 7-Zip ≥ 25.00), a zatim proverite da rezultujuće putanje ostanu unutar direktorijuma.<sup>[[1]](#references)[[9]](#references)</sup>
* **Monitoring endpoint-a** – Upozorite na nove izvršne fajlove upisane u `Startup`/`Run`/`cron` lokacije ubrzo nakon što je arhiva otvorena pomoću WinRAR-a/7-Zip-a/itd.

## Ublažavanje i Hardening

1. **Ažurirajte extractor** – WinRAR 7.13+ i 7-Zip 25.00+ sadrže ispravke za probleme sa d putanjom/symlink-om.<sup>[[1]](#references)[[5]](#references)</sup>
2. Kada je moguće, ekstraktujte arhive uz opciju “**Do not extract paths**” / “**Ignore paths**”.
3. Na Unix-u smanjite privileges i montirajte **chroot/namespace** pre ekstrakcije; na Windows-u koristite **AppContainer** ili sandbox.
4. Ako pišete custom code, normalizujte pomoću `realpath()`/`PathCanonicalize()` **pre** kreiranja/upisivanja i odbijte svaki unos koji izlazi iz odredišta.

## Dodatni pogođeni / istorijski slučajevi

* 2018 – Snyk-ovo obimno *Zip-Slip* obaveštenje koje je uticalo na mnoge Java/Go/JS biblioteke.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal u slug-ovima (ispravljeno u v0.16.3).<sup>[[7]](#references)</sup>
* Svaka custom extraction logika koja pre upisivanja ne pozove `PathCanonicalize` / `realpath`.

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Sprečavanje Zip Slip-a u .NET-u](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack lanac](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Ažurirajte WinRAR tools odmah: RomCom i drugi koriste zero-day ranjivost (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Javno otkrivanje kritične ranjivosti za proizvoljno prepisivanje fajlova: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug je ranjiv na Zip Slip napad (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine Method](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar secure extraction flags](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Prijavljen Proof-of-Concept Exploit za CVE-2025-11001 u 7-Zip-u](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
{{#include ../banners/hacktricks-training.md}}
