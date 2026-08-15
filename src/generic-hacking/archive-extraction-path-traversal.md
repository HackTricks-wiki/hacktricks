# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Oorsig

Baie archive-formate (ZIP, RAR, TAR, 7-ZIP, ens.) laat elke entry toe om sy eie **interne pad** te bevat. Wanneer 'n extraction utility daardie pad blindelings eerbiedig, sal 'n vervaardigde lêernaam wat `..` of 'n **absolute pad** bevat (bv. `C:\Windows\System32\`) buite die gebruiker-gekozen directory geskryf word.
Hierdie klas kwesbaarheid staan algemeen bekend as *Zip-Slip* of **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Gevolge wissel van die oorskryf van arbitrêre lêers tot die direkte bereiking van **remote code execution (RCE)** deur 'n payload in 'n **auto-run**-ligging, soos die Windows *Startup*-folder, te plaas.

## Worteloorsaak

1. Aanvaller skep 'n archive waarin een of meer file headers die volgende bevat:
* Relatiewe traversal-sekwense (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paaie (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Of vervaardigde **symlinks** wat buite die target dir resolve (algemeen in ZIP/TAR op *nix*).
2. Slagoffer extract die archive met 'n kwesbare tool wat die ingebedde path vertrou (of symlinks volg) in plaas daarvan om dit te sanitise of extraction onder die gekose directory af te dwing.
3. Die lêer word in die aanvaller-beheerde ligging geskryf en uitgevoer/gelaai wanneer die system of user daardie path volgende keer trigger.

### .NET `Path.Combine` + `ZipArchive` traversal

'n Algemene .NET anti-pattern is om die bedoelde bestemming met user-beheerde `ZipArchiveEntry.FullName` te kombineer en extraction sonder path-normalisering uit te voer:<sup>[[4]](#references)[[8]](#references)</sup>
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
- As `entry.FullName` met `..\\` begin, traverseer dit; indien dit ’n **absolute path** is, word die linkerkantste komponent heeltemal weggegooi, wat ’n **arbitrary file write** as die extraction identity oplewer.
- Proof-of-concept archive om na ’n sibling `app`-gids te skryf wat deur ’n geskeduleerde scanner gemonitor word:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Deur daardie ZIP in die gemonitorde inbox te plaas, lei dit tot `C:\samples\app\0xdf.txt`, wat traversal buite `C:\samples\queue\` bewys en opvolgprimitiewe moontlik maak (bv. DLL hijacks).

## Werklike voorbeeld – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR vir Windows en sy Windows RAR/UnRAR-komponente het versuim om lêername tydens extraction te valideer. Die kwesbaarheid het NTFS alternate data streams (ADS) gebruik om die geselekteerde extraction path te omseil en lêers na onbedoelde liggings te skryf.<sup>[[5]](#references)</sup>
'n Kwaadwillige RAR-argief wat 'n inskrywing soos die volgende bevat:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
sou **buite** die gekose uitvoergids en binne die gebruiker se *Startup*-gids beland. ESET het waargeneem dat kwaadwillige LNK-lêers daar uitgepak en by gebruikersaanmelding uitgevoer is, wat persistence en 'n pad na RCE verskaf het.<sup>[[5]](#references)</sup>

### Skep van 'n PoC-argief (Linux/Mac)

Omdat CVE-2025-8088 'n traversal path in 'n ADS-naam gebruik, gebruik 'n doelgeboude generator om die RAR te skep, en toets ekstraksie slegs in 'n geïsoleerde laboratorium met 'n kwesbare WinRAR-build.<sup>[[5]](#references)</sup>

### Waargenome Exploitation in die Wild

ESET het spear-phishing-veldtogte deur RomCom (Storm-0978/UNC2596) gerapporteer wat RAR-argiewe aangeheg het wat CVE-2025-8088 misbruik om aangepaste backdoors te ontplooi en ransomware-bedrywighede te fasiliteer.<sup>[[5]](#references)</sup>

## Nuwer Gevalle (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP-inskrywings wat **symbolic links** was, is tydens ekstraksie gedereferensieer, wat aanvallers toegelaat het om uit die bestemmingsgids te ontsnap en arbitrêre paths te oorskryf. Gebruikersinteraksie is bloot die *opening/extracting* van die argief.<sup>[[1]](#references)</sup>
* **Geaffekteer**: 7-Zip-builds voor **25.00**. Die fout in symbolic-link-verwerking is in **25.00** (Julie 2025) en later reggestel.<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**: Oorskryf `Start Menu/Programs/Startup` of diens-run-liggings → kode loop by die volgende aanmelding of wanneer die diens herbegin.
* **Vinnige symlink-handling fixture (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Hierdie argief bevat 'n symlink-inskrywing wat buite die ekstraksiegids wys; gebruik 'n weggooibare teiken en verifieer dat die extractor dit nie volg nie. 'n Write-through-toets benodig ook 'n gewone-lêer-inskrywing onder die symlink.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` volg `../` en symlinked ZIP-inskrywings en skryf buite `outputDir`.<sup>[[2]](#references)</sup>
* **Geaffekteer**: `github.com/mholt/archiver` ≤ 3.5.1 (die projek is nou deprecated).
* **Fix**: Skakel oor na `mholt/archives` ≥ 0.1.0 of implementeer canonical-path checks voor skryf.
* **Minimale reproduksie**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection Tips

* **Statiese inspeksie** – Lys argief-inskrywings en merk enige naam wat `../`, `..\\`, *absolute paths* (`/`, `C:`) bevat, of inskrywings van die tipe *symlink* waarvan die teiken buite die ekstraksiegids is.
* **Canonicalisation** – Verseker dat `realpath(join(dest, name))` binne `realpath(dest)` bly (vergelyk path-komponente, nie slegs 'n rou string-prefix nie). Verwerp dit andersins.<sup>[[3]](#references)</sup>
* **Sandbox-ekstraksie** – Decomprimeer na 'n weggooibare gids met 'n extractor wat path/symlink-checks gebruik (byvoorbeeld bsdtar se verstek secure checks of 7-Zip ≥ 25.00), en verifieer daarna dat die resulterende paths binne die gids bly.<sup>[[1]](#references)[[9]](#references)</sup>
* **Endpoint-monitering** – Waarsku oor nuwe uitvoerbare lêers wat na `Startup`/`Run`/`cron`-liggings geskryf word kort nadat 'n argief deur WinRAR/7-Zip/etc. geopen is.

## Mitigation & Hardening

1. **Werk die extractor by** – WinRAR 7.13+ en 7-Zip 25.00+ bevat fixes vir die aangehaalde path/symlink-kwessies.<sup>[[1]](#references)[[5]](#references)</sup>
2. Trek argiewe uit met “**Do not extract paths**” / “**Ignore paths**” waar moontlik.
3. Op Unix, verminder privileges en mount 'n **chroot/namespace** voor ekstraksie; op Windows, gebruik **AppContainer** of 'n sandbox.
4. Indien jy custom code skryf, normaliseer met `realpath()`/`PathCanonicalize()` **voor** create/write, en verwerp enige inskrywing wat uit die bestemming ontsnap.

## Bykomende Geaffekteerde / Historiese Gevalle

* 2018 – Massiewe *Zip-Slip*-advies deur Snyk wat baie Java/Go/JS-libraries geraak het.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR-extraction traversal in slugs (reggestel in v0.16.3).<sup>[[7]](#references)</sup>
* Enige custom extraction logic wat versuim om `PathCanonicalize` / `realpath` voor skryf aan te roep.

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Voorkom Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack-ketting](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Dateer WinRAR-tools nou op: RomCom en anderes buit zero-day-kwesbaarheid uit (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Openbare bekendmaking van 'n kritieke kwesbaarheid vir arbitrêre lêeroorskrywing: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug kwesbaar vir Zip Slip-aanval (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine-metode](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar secure extraction-vlae](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Proof-of-Concept-exploit vir CVE-2025-11001 in 7-Zip gerapporteer](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
{{#include ../banners/hacktricks-training.md}}
