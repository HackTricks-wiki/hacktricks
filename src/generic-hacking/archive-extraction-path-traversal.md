# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Oorsig

Baie argiefformate (ZIP, RAR, TAR, 7-ZIP, ens.) laat elke inskrywing toe om sy eie **interne pad** te bevat. Wanneer ’n extraction utility daardie pad blindelings eerbiedig, sal ’n vervaardigde lêernaam wat `..` of ’n **absolute pad** (bv. `C:\Windows\System32\`) bevat, buite die gebruiker-gekose gids geskryf word.
Hierdie klas kwesbaarheid staan algemeen bekend as *Zip-Slip* of **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Gevolge wissel van die oorskryf van arbitrêre lêers tot die direkte bereiking van **remote code execution (RCE)** deur ’n payload in ’n **auto-run**-ligging, soos die Windows *Startup*-gids, te plaas.

## Worteloorsaak

1. Aanvaller skep ’n argief waarin een of meer lêerheaders die volgende bevat:
* Relatiewe traversal-sekwense (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paaie (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Of vervaardigde **symlinks** wat buite die teikengids resolve (algemeen in ZIP/TAR op *nix*).
2. Slagoffer onttrek die argief met ’n kwesbare tool wat die ingebedde pad vertrou (of symlinks volg) in plaas daarvan om dit te sanitise of extraction onder die gekose gids af te dwing.
3. Die lêer word in die aanvaller-beheerde ligging geskryf en uitgevoer/gelaai wanneer die stelsel of gebruiker daardie pad volgende keer aktiveer.

### .NET `Path.Combine` + `ZipArchive` traversal

’n Algemene .NET anti-patroon is om die bedoelde bestemming met gebruiker-beheerde `ZipArchiveEntry.FullName` te kombineer en extraction sonder paths normalisation uit te voer:<sup>[[4]](#references)[[8]](#references)</sup>
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
- As `entry.FullName` met `..\\` begin, traverseer dit; as dit ’n **absolute path** is, word die linkerkant-komponent heeltemal verwerp, wat ’n **arbitrary file write** as die extraction identity lewer.
- Proof-of-concept-argief om na ’n naburige `app`-gids te skryf wat deur ’n geskeduleerde skandeerder gemonitor word:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Deur daardie ZIP in die gemonitorde inbox te plaas, lei dit tot `C:\samples\app\0xdf.txt`, wat traversal buite `C:\samples\queue\` bewys en opvolg-primitives moontlik maak (bv. DLL hijacks).

## Werklike Voorbeeld – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR for Windows en sy Windows RAR/UnRAR-komponente het versuim om lêername tydens extraction te valideer. Die flaw het NTFS alternate data streams (ADS) gebruik om die geselekteerde extraction path te omseil en lêers na onbedoelde locations te skryf.<sup>[[5]](#references)</sup>
'n Kwaadwillige RAR-archive wat 'n entry soos die volgende bevat:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
sou **buite** die geselekteerde uitvoergids en binne die gebruiker se *Startup*-gids beland. ESET het waargeneem dat kwaadwillige LNK-lêers daar uitgepak en by gebruikersaanmelding uitgevoer is, wat persistence en ’n pad na RCE verskaf het.<sup>[[5]](#references)</sup>

### Skep van ’n PoC-argief (Linux/Mac)

Omdat CVE-2025-8088 ’n traversal-pad in ’n ADS-naam gebruik, gebruik ’n doelgeboude generator om die RAR te skep, en toets die extraction slegs in ’n geïsoleerde laboratorium met ’n kwesbare WinRAR-build.<sup>[[5]](#references)</sup>

### Waargenome Exploitation in die Wild

ESET het spear-phishing-veldtogte deur RomCom (Storm-0978/UNC2596) gerapporteer wat RAR-argiewe aangeheg het wat CVE-2025-8088 misbruik om aangepaste backdoors te ontplooi en ransomware-bedrywighede te fasiliteer.<sup>[[5]](#references)</sup>

## Nuwer Gevalle (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP-inskrywings wat **symbolic links** was, is tydens extraction gedereferensieer, wat aanvallers toegelaat het om uit die bestemmingsgids te ontsnap en arbitrêre paaie te oorskryf. Gebruikersinteraksie is bloot om die argief *oop te maak/uit te pak*.<sup>[[1]](#references)</sup>
* **Affected**: 7-Zip-builds voor **25.00**. Die fout in symbolic-link-verwerking is in **25.00** (Julie 2025) en later reggestel.<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**: Oorskryf `Start Menu/Programs/Startup` of diens-run-liggings → kode loop by die volgende aanmelding of wanneer die diens herbegin.
* **Quick symlink-handling fixture (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Hierdie argief bevat ’n symlink-inskrywing wat buite die extraction-gids wys; gebruik ’n weggooibare teiken en verifieer dat die extractor dit nie volg nie. ’n Write-through-toets benodig ook ’n gewone-lêer-inskrywing onder die symlink.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` volg `../` en symlinked ZIP-inskrywings, en skryf buite `outputDir`.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (die projek is nou deprecated).
* **Fix**: Skakel oor na `mholt/archives` ≥ 0.1.0 of implementeer canonical-path-kontroles voor daar geskryf word.
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection Tips

* **Static inspection** – Lys argiefinskrywings en merk enige naam wat `../`, `..\\`, *absolute paths* (`/`, `C:`) bevat, of inskrywings van die tipe *symlink* waarvan die teiken buite die extraction-gids is.
* **Canonicalisation** – Verseker dat `realpath(join(dest, name))` binne `realpath(dest)` bly (vergelyk padkomponente, nie slegs ’n rou string-prefix nie). Verwerp dit andersins.<sup>[[3]](#references)</sup>
* **Sandbox extraction** – Decomprimeer na ’n weggooibare gids met ’n extractor wat path/symlink-kontroles gebruik (byvoorbeeld bsdtar se verstek-veilige kontroles of 7-Zip ≥ 25.00), en verifieer dan dat die gevolglike paaie binne die gids bly.<sup>[[1]](#references)[[9]](#references)</sup>
* **Endpoint monitoring** – Genereer ’n alert oor nuwe uitvoerbare lêers wat kort nadat ’n argief deur WinRAR/7-Zip/etc. oopgemaak is, na `Startup`/`Run`/`cron`-liggings geskryf word.

## Mitigation & Hardening

1. **Update the extractor** – WinRAR 7.13+ en 7-Zip 25.00+ bevat regstellings vir die d path/symlink-kwessies.<sup>[[1]](#references)[[5]](#references)</sup>
2. Pak argiewe uit met “**Do not extract paths**” / “**Ignore paths**” waar moontlik.
3. Op Unix, verlaag privileges en mount ’n **chroot/namespace** voor extraction; op Windows, gebruik **AppContainer** of ’n sandbox.
4. Indien jy custom code skryf, normaliseer met `realpath()`/`PathCanonicalize()` **voor** create/write, en verwerp enige inskrywing wat uit die bestemming ontsnap.

## Additional Affected / Historical Cases

* 2018 – Massiewe *Zip-Slip*-advies deur Snyk wat baie Java/Go/JS-libraries geraak het.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp se `go-slug` (CVE-2025-0377) TAR-extraction traversal in slugs (reggestel in v0.16.3).<sup>[[7]](#references)</sup>
* Enige custom extraction-logika wat versuim om `PathCanonicalize` / `realpath` voor die write aan te roep.

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Voorkom Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack-ketting](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Dateer WinRAR-nutsmiddels nou op: RomCom en ander misbruik zero-day-kwesbaarheid (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Openbare bekendmaking van ’n kritieke kwesbaarheid vir arbitrêre lêeroorskrywing: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug kwesbaar vir Zip Slip-aanval (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine-metode](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar-veilige extraction-vlae](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Proof-of-Concept Exploit oor CVE-2025-11001 in 7-Zip gerapporteer](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
{{#include ../banners/hacktricks-training.md}}
