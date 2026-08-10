# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

## Oorsig

Baie argiefformate (ZIP, RAR, TAR, 7-ZIP, ens.) laat elke entry toe om sy eie **interne path** te bevat. Wanneer 'n extraction utility blindelings daardie path eerbiedig, sal 'n vervaardigde lêernaam wat `..` of 'n **absolute path** bevat (bv. `C:\Windows\System32\`) buite die gebruiker-gekose directory geskryf word.
Hierdie klas kwesbaarheid staan algemeen bekend as *Zip-Slip* of **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Gevolge wissel van die oorskryf van arbitrêre lêers tot die direkte verkryging van **remote code execution (RCE)** deur 'n payload in 'n **auto-run**-ligging, soos die Windows *Startup*-folder, te plaas.

## Grondoorsaak

1. Attacker creates an archive where one or more file headers contain:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Or crafted **symlinks** that resolve outside the target dir (common in ZIP/TAR on *nix*).
2. Slagoffer extracts the archive with a vulnerable tool that trusts the embedded path (or follows symlinks) instead of sanitising it or forcing extraction beneath the chosen directory.
3. The file is written in the attacker-controlled location and executed/loaded next time the system or user triggers that path.

### .NET `Path.Combine` + `ZipArchive` traversal

'n Algemene .NET anti-pattern is om die beoogde bestemming met die **user-controlled** `ZipArchiveEntry.FullName` te kombineer en die extraction sonder path-normalisering uit te voer:<sup>[[4]](#references)[[8]](#references)</sup>
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
- As `entry.FullName` met `..\\` begin, deurkruis dit paaie; as dit ’n **absolute path** is, word die linkerkomponent heeltemal verwyder, wat ’n **arbitrêre lêerskrywing** as die onttrekkingsidentiteit tot gevolg het.
- Proof-of-concept-argief om na ’n sibling `app`-gids te skryf wat deur ’n geskeduleerde skandeerder gemonitor word:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Deur daardie ZIP in die gemonitorde inbox te plaas, lei dit tot `C:\samples\app\0xdf.txt`, wat traversal buite `C:\samples\queue\` bewys en opvolgprimitives moontlik maak (bv. DLL hijacks).

## Werklike voorbeeld – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR for Windows en sy Windows RAR/UnRAR-komponente het versuim om lêername tydens extraction te valideer. Die kwesbaarheid het NTFS alternate data streams (ADS) gebruik om die geselekteerde extraction path te omseil en lêers na onbedoelde liggings te skryf.<sup>[[5]](#references)</sup>
'n Kwaadwillige RAR-argief wat 'n entry soos die volgende bevat:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
sou uiteindelik **buite** die geselekteerde uitvoergids en binne die gebruiker se *Startup*-gids beland. ESET het waargeneem dat kwaadwillige LNK-lêers daar uitgepak en tydens gebruikersaanmelding uitgevoer is, wat persistence en ’n pad na RCE verskaf het.<sup>[[5]](#references)</sup>

### Skep van ’n PoC-argief (Linux/Mac)

Omdat CVE-2025-8088 ’n traversal-pad in ’n ADS-naam gebruik, moet jy ’n doelgeboude generator gebruik om die RAR te skep, en dan die onttrekking slegs in ’n geïsoleerde laboratorium met ’n kwesbare WinRAR-build toets.<sup>[[5]](#references)</sup>

### Waargenome Exploitation in die Wild

ESET het RomCom (Storm-0978/UNC2596) spear-phishing-veldtogte gerapporteer wat RAR-argiewe aangeheg het wat CVE-2025-8088 misbruik om aangepaste backdoors te ontplooi en ransomware-bedrywighede te fasiliteer.<sup>[[5]](#references)</sup>

## Nuwer Gevalle (2024–2025)

### 7-Zip ZIP-symlink-traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP-inskrywings wat **symbolic links** was, is tydens onttrekking gedereferensieer, wat aanvallers toegelaat het om uit die bestemmingsgids te ontsnap en arbitrêre paaie te oorskryf. Gebruikersinteraksie is slegs om die argief *oop te maak/te onttrek*.<sup>[[1]](#references)</sup>
* **Affected**: 7-Zip-builds voor **25.00**. Die fout met symbolic-link-verwerking is in **25.00** (Julie 2025) en later reggestel.<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**: Oorskryf `Start Menu/Programs/Startup` of diens-run-liggings → kode loop tydens die volgende aanmelding of wanneer die diens herbegin.
* **Quick symlink-handling fixture (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Hierdie argief bevat ’n symlink-inskrywing wat buite die onttrekkingsgids wys; gebruik ’n weggooibare teiken en verifieer dat die extractor dit nie volg nie. ’n Write-through-toets benodig ook ’n gewone-lêer-inskrywing onder die symlink.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` volg `../` en gesymlinkte ZIP-inskrywings, en skryf buite `outputDir`.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (die projek is nou deprecated).
* **Fix**: Skakel oor na `mholt/archives` ≥ 0.1.0 of implementeer canonical-path-kontroles voordat daar geskryf word.
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection Tips

* **Static inspection** – Lys argief-inskrywings en merk enige naam wat `../`, `..\\`, *absolute paths* (`/`, `C:`) bevat, of inskrywings van die tipe *symlink* waarvan die teiken buite die onttrekkingsgids is.
* **Canonicalisation** – Verseker dat `realpath(join(dest, name))` binne `realpath(dest)` bly (vergelyk padkomponente, nie slegs ’n rou string-prefix nie). Verwerp dit andersins.<sup>[[3]](#references)</sup>
* **Sandbox extraction** – Decomprimeer na ’n weggooibare gids met ’n extractor wat pad-/symlink-kontroles uitvoer (byvoorbeeld bsdtar se verstek veilige kontroles of 7-Zip ≥ 25.00), en verifieer dan dat die resulterende paaie binne die gids bly.<sup>[[1]](#references)[[9]](#references)</sup>
* **Endpoint monitoring** – Genereer ’n waarskuwing wanneer nuwe uitvoerbare lêers kort nadat ’n argief deur WinRAR/7-Zip/ens. oopgemaak is, na `Startup`/`Run`/`cron`-liggings geskryf word.

## Mitigation & Hardening

1. **Dateer die extractor op** – WinRAR 7.13+ en 7-Zip 25.00+ bevat regstellings vir die aangehaalde pad-/symlink-kwessies.<sup>[[1]](#references)[[5]](#references)</sup>
2. Onttrek argiewe met “**Do not extract paths**” / “**Ignore paths**” waar moontlik.
3. Op Unix, verlaag privileges en mount ’n **chroot/namespace** voordat jy onttrek; op Windows, gebruik **AppContainer** of ’n sandbox.
4. As jy custom code skryf, normaliseer met `realpath()`/`PathCanonicalize()` **voordat** jy skep/skryf, en verwerp enige inskrywing wat uit die bestemming ontsnap.

## Additional Affected / Historical Cases

* 2018 – Groot *Zip-Slip*-advies deur Snyk wat baie Java/Go/JS-libraries geraak het.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp se `go-slug` (CVE-2025-0377) TAR-onttrekkingstraversal in slugs (reggestel in v0.16.3).<sup>[[7]](#references)</sup>
* Enige custom extraction logic wat versuim om `PathCanonicalize` / `realpath` voor die skryfaksie aan te roep.

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP-traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Voorkom Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL-hijack-ketting](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Dateer WinRAR-tools nou op: RomCom en ander misbruik zero-day-kwesbaarheid (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Openbare bekendmaking van ’n kritieke arbitrêre lêeroorskryfkwesbaarheid: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug kwesbaar vir Zip Slip-aanval (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine-metode](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar-veilige onttrekkingsvlae](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Proof-of-Concept-exploit vir CVE-2025-11001 in 7-Zip gerapporteer](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
{{#include ../banners/hacktricks-training.md}}
