# Path Traversal pri ekstrakciji arhiva ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Pregled

Mnogi formati arhiva (ZIP, RAR, TAR, 7-ZIP itd.) omogućavaju da svaki unos sadrži sopstvenu **internu putanju**. Kada alat za ekstrakciju slepo poštuje tu putanju, kreirano ime datoteke koje sadrži `..` ili **apsolutnu putanju** (npr. `C:\Windows\System32\`) biće upisano izvan direktorijuma koji je korisnik izabrao.
Ova klasa ranjivosti je široko poznata kao *Zip-Slip* ili **path traversal pri ekstrakciji arhiva**.<sup>[[6]](#references)</sup>

Posledice se kreću od prepisivanja proizvoljnih datoteka do direktnog ostvarivanja **remote code execution (RCE)** ubacivanjem payload-a na lokaciju koja se **automatski pokreće**, kao što je Windows *Startup* folder.

## Osnovni uzrok

1. Attacker kreira arhivu u kojoj jedno ili više zaglavlja datoteka sadrže:
* Relativne traversal sekvence (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Apsolutne putanje (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Ili kreirane **symlinks** koji se razrešavaju izvan ciljnog direktorijuma (uobičajeno kod ZIP/TAR na *nix* sistemima).
2. Victim raspakuje arhivu pomoću ranjivog alata koji veruje ugrađenoj putanji (ili prati symlinks), umesto da je sanitizuje ili prisili ekstrakciju unutar izabranog direktorijuma.
3. Datoteka se upisuje na lokaciju pod kontrolom attackera i izvršava/učitava sledeći put kada sistem ili korisnik aktivira tu putanju.

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
- Ako `entry.FullName` počinje sa `..\\`, dolazi do traversal-a; ako je **apsolutna putanja**, leva komponenta se u potpunosti odbacuje, što kao identitet ekstrakcije omogućava **proizvoljan upis fajla**.
- Proof-of-concept arhiva za upis u susedni `app` direktorijum koji nadgleda zakazani skener:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Prebacivanje tog ZIP-a u nadzirani inbox rezultira putanjom `C:\samples\app\0xdf.txt`, čime se dokazuje traversal izvan `C:\samples\queue\` i omogućavaju naknadni primitives (npr. DLL hijacks).

## Primer iz stvarnog sveta – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR za Windows i njegove Windows RAR/UnRAR komponente nisu uspevali da validiraju nazive datoteka tokom ekstrakcije. Propust je koristio NTFS alternate data streams (ADS) za zaobilaženje izabrane putanje ekstrakcije i upisivanje datoteka na neželjene lokacije.<sup>[[5]](#references)</sup>
Maliciozni RAR arhiv koji sadrži stavku poput:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
završila bi **izvan** izabranog direktorijuma za izlaz i unutar korisničkog *Startup* foldera. ESET je uočio da su se zlonamerni LNK fajlovi tamo raspakivali i izvršavali prilikom prijavljivanja korisnika, obezbeđujući persistence i putanju do RCE.<sup>[[5]](#references)</sup>

### Kreiranje PoC Archive-a (Linux/Mac)

Pošto CVE-2025-8088 koristi traversal path u ADS imenu, koristite namenski generator za kreiranje RAR-a, a zatim testirajte extraction samo u izolovanoj lab okolini sa ranjivom WinRAR verzijom.<sup>[[5]](#references)</sup>

### Uočena Eksploatacija u the Wild

ESET je prijavio spear-phishing kampanje grupe RomCom (Storm-0978/UNC2596) u kojima su bili priloženi RAR archive-i koji zloupotrebljavaju CVE-2025-8088 za deployment prilagođenih backdoor-a i sprovođenje ransomware operacija.<sup>[[5]](#references)</sup>

## Noviji Slučajevi (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP entries koji su **symbolic links** dereferencirani su tokom extraction-a, što je napadačima omogućavalo da izađu iz odredišnog direktorijuma i prepišu proizvoljne putanje. Interakcija korisnika svodi se samo na *otvaranje/raspakivanje* archive-a.<sup>[[1]](#references)</sup>
* **Affected**: 7-Zip build-ovi pre **25.00**. Greška u obradi symbolic link-ova ispravljena je u verziji **25.00** (jul 2025) i novijim verzijama.<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**: Prepisivanje lokacija `Start Menu/Programs/Startup` ili lokacija iz kojih se pokreću servisi → code se izvršava pri sledećem prijavljivanju ili restartovanju servisa.
* **Quick symlink-handling fixture (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Ovaj archive sadrži symlink entry koji pokazuje izvan extraction direktorijuma; koristite disposable target i proverite da extractor ne prati taj symlink. Test upisivanja kroz symlink takođe zahteva regular-file entry ispod symlink-a.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` prati `../` i symlinked ZIP entries, upisujući izvan `outputDir`.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (projekat je sada deprecated).
* **Fix**: Pređite na `mholt/archives` ≥ 0.1.0 ili implementirajte canonical-path provere pre upisivanja.
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Saveti za Detekciju

* **Static inspection** – Izlistajte archive entries i označite svako ime koje sadrži `../`, `..\\`, *absolute paths* (`/`, `C:`) ili entries tipa *symlink* čiji je target izvan extraction direktorijuma.
* **Canonicalisation** – Uverite se da `realpath(join(dest, name))` ostaje unutar `realpath(dest)` (upoređujte komponente putanje, a ne samo sirovi string prefix). U suprotnom odbacite entry.<sup>[[3]](#references)</sup>
* **Sandbox extraction** – Raspakujte u disposable direktorijum koristeći extractor sa proverama putanja/symlink-ova (na primer, podrazumevane bezbedne provere u bsdtar-u ili 7-Zip ≥ 25.00), a zatim proverite da rezultujuće putanje ostaju unutar direktorijuma.<sup>[[1]](#references)[[9]](#references)</sup>
* **Endpoint monitoring** – Postavite alert za nove executable fajlove upisane u `Startup`/`Run`/`cron` lokacije ubrzo nakon što je archive otvoren pomoću WinRAR-a/7-Zip-a/itd.

## Mitigacija i Hardening

1. **Ažurirajte extractor** – WinRAR 7.13+ i 7-Zip 25.00+ sadrže fix-eve za navedene path/symlink probleme.<sup>[[1]](#references)[[5]](#references)</sup>
2. Kada je moguće, raspakujte archive-e uz opciju “**Do not extract paths**” / “**Ignore paths**”.
3. Na Unix-u smanjite privileges i mount-ujte **chroot/namespace** pre extraction-a; na Windows-u koristite **AppContainer** ili sandbox.
4. Ako pišete custom code, normalizujte pomoću `realpath()`/`PathCanonicalize()` **pre** create/write operacije i odbacite svaki entry koji izlazi iz destination-a.

## Dodatni Pogođeni / Istorijski Slučajevi

* 2018 – Opsežni *Zip-Slip* advisory kompanije Snyk koji je uticao na brojne Java/Go/JS library-je.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal u slug-ovima (ispravljeno u v0.16.3).<sup>[[7]](#references)</sup>
* Svaka custom extraction logika koja ne pozove `PathCanonicalize` / `realpath` pre upisivanja.

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Sprečavanje Zip Slip-a u .NET-u](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Ažurirajte WinRAR tools odmah: RomCom i drugi iskorišćavaju zero-day ranjivost (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Javno otkrivanje kritične ranjivosti za proizvoljno prepisivanje fajlova: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug ranjiv na Zip Slip Attack (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Metod Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar secure extraction flags](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Prijavljen Proof-of-Concept Exploit za CVE-2025-11001 u 7-Zip-u](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
{{#include ../banners/hacktricks-training.md}}
