# Archive Extraction Path Traversal ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## Oorsig

Baie archive-formate (ZIP, RAR, TAR, 7-ZIP, ens.) laat elke entry toe om sy eie **interne pad** te bevat. Wanneer 'n extraction utility daardie pad blindelings eerbiedig, sal 'n vervaardigde lêernaam wat `..` of 'n **absolute pad** (bv. `C:\Windows\System32\`) bevat, buite die gebruiker-gekose gids geskryf word.
Hierdie klas kwesbaarheid staan algemeen bekend as *Zip-Slip* of **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Gevolge wissel van die oorskryf van arbitrêre lêers tot die direkte verkryging van **remote code execution (RCE)** deur 'n payload in 'n **auto-run**-ligging, soos die Windows *Startup*-gids, te plaas.

## Worteloorsaak

1. Aanvaller skep 'n archive waarin een of meer lêerheaders die volgende bevat:
* Relatiewe traversal-sekwensies (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paaie (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Of vervaardigde **symlinks** wat buite die teikengids resolve (algemeen in ZIP/TAR op *nix*).
2. Slagoffer trek die archive uit met 'n kwesbare tool wat die ingebedde pad vertrou (of symlinks volg) in plaas daarvan om dit te sanitise of extraction onder die gekose gids af te dwing.
3. Die lêer word in die aanvaller-beheerde ligging geskryf en uitgevoer/gelaai wanneer die stelsel of gebruiker daardie pad volgende keer aktiveer.

### .NET `Path.Combine` + `ZipArchive` traversal

'n Algemene .NET anti-patroon is om die beoogde bestemming met gebruiker-beheerde `ZipArchiveEntry.FullName` te kombineer en extraction uit te voer sonder padnormalisering:<sup>[[4]](#references)[[8]](#references)</sup>
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
- As `entry.FullName` met `..\\` begin, traverseer dit; as dit ’n **absolute path** is, word die linkerkant-komponent heeltemal weggegooi, wat ’n **arbitrary file write** as die extraction identity oplewer.
- Proof-of-concept-argief om na ’n sibling `app`-gids te skryf wat deur ’n geskeduleerde scanner gemonitor word:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Deur daardie ZIP in die gemonitorde inbox te plaas, word `C:\samples\app\0xdf.txt` geskep, wat traversal buite `C:\samples\queue\` bewys en opvolgprimitiewe (bv. DLL hijacks) moontlik maak.

## Gevorderde Archive-Breakout Primitives

Behandel extraction as ’n reeks lêerstelselmutasies, nie as onafhanklike lêernaamkontroles nie. ’n Inskrywing wat veilig is wanneer dit geparse word, kan onveilig word nadat ’n vorige lid ’n link skep of vervang; dieselfde probleem kom voor wanneer ’n extractor ’n gids as veilig cache en die tipe daarvan later verander.<sup>[[11]](#references)</sup>

### Link-pivots en inskrywingbotsings

* **Symlink write-through**: skep `pivot -> /tmp`, en extract dan ’n gewone lid as `pivot/PWNED.txt`. As die extractor die eerste lid volg terwyl dit die tweede materialiseer, ontsnap die skrywing sonder `..` in die tweede naam.
* **Directory-cache/TOCTOU-botsing**: genereer gids `d/sub/`, vervang `d/sub` met ’n symlink na `/tmp`, en genereer dan `d/sub/PWNED.txt`. Dit teiken extractors wat die gids een keer valideer of cache en dit nie weer nagaan voordat die finale skrywing plaasvind nie.
* **Hardlink read/overwrite**: TAR en RAR kan hardlinks voorstel. ’n Hardlink na ’n bestaande host-lêer kan die inhoud daarvan blootlê as ’n latere komponent die geëxtraheerde naam bedien; ’n botsende gewone inskrywing kan eerder die gekoppelde inode oorskryf. Dit word beperk deur reëls vir dieselfde lêerstelsel en OS-hardlink-toestemmings.
* **Pre-existing of cross-archive pivot**: probeer weer met ’n nie-leë bestemming. Een archive kan ’n link plant, waarna ’n latere extraction daardeur kan skryf, selfs al slaag elke archive ’n stateless header-name check.<sup>[[11]](#references)</sup>

### Lêerstelsel-ekwivalensie-botsings

Vergelyk name volgens die semantiek van die lêerstelsel wat dit sal ontvang. Nuttige differensiële gevalle sluit in `LINK` teenoor `link` op hoofletter-onsensitiewe lêerstelsels, NFC teenoor NFD Unicode-spellings, versoenbaarheid-ekwivalente name soos `ﬁle` teenoor `file`, duplikaatlede wat ’n pad van ’n gids na ’n symlink verander, en backslashes wat slegs op Windows as skeiers geïnterpreteer word. Toets ook ADS-bevattende name op NTFS. Hierdie gevalle kan veroorsaak dat die validator twee paaie sien terwyl die lêerstelsel een pad resolve.<sup>[[5]](#references)[[11]](#references)</sup>

’n Kompakte corpus behoort dus geordende kombinasies van **directory → symlink → child**, **symlink → colliding regular file**, **hardlink → colliding regular file**, gemengde `/` en `\`, absolute/rooted name, en compressed wrappers soos `.tar.gz` te toets. Voer dit slegs in ’n weggooibare VM/container uit en monitor beide die bestemming en die bedoelde canary-pad buite die bestemming.<sup>[[11]](#references)</sup>

## Werklike Voorbeeld – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR vir Windows en sy Windows RAR/UnRAR-komponente het versuim om lêername tydens extraction te valideer. Die fout het NTFS alternate data streams (ADS) gebruik om die geselekteerde extraction-pad te omseil en lêers na onbedoelde liggings te skryf.<sup>[[5]](#references)</sup>
’n Kwaadwillige RAR-archive wat ’n inskrywing soos die volgende bevat:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
sou **buite** die geselekteerde uitvoergids en binne die gebruiker se *Startup*-lêergids beland. ESET het waargeneem dat kwaadwillige LNK-lêers daar uitgepak en by gebruikersaanmelding uitgevoer is, wat persistence en ’n pad na RCE verskaf het.<sup>[[5]](#references)</sup>

### Creating a PoC Archive (Linux/Mac)

Omdat CVE-2025-8088 ’n traversal path in ’n ADS-naam gebruik, moet jy ’n doelgemaakte generator gebruik om die RAR te skep, en extraction slegs in ’n geïsoleerde lab met ’n kwesbare WinRAR-build toets.<sup>[[5]](#references)</sup>

### Observed Exploitation in the Wild

ESET het spear-phishing campaigns deur RomCom (Storm-0978/UNC2596) gerapporteer wat RAR-archives aangeheg het wat CVE-2025-8088 misbruik om aangepaste backdoors te ontplooi en ransomware-operasies te fasiliteer.<sup>[[5]](#references)</sup>

## Nuwer Gevalle (2024–2026)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP-entries wat **symbolic links** was, is tydens extraction gedereferensieer, wat aanvallers toegelaat het om die bestemmingsgids te verlaat en arbitrêre paths te oorskryf. Gebruikersinteraksie is slegs om die archive te *open/extract*.<sup>[[1]](#references)</sup>
* **Affected**: 7-Zip-builds voor **25.00**. Die symbolic-link-verwerkingsfout is in **25.00** (Julie 2025) en later reggestel.<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**: Oorskryf `Start Menu/Programs/Startup` of diens-run-liggings → code loop by die volgende aanmelding of wanneer die diens herbegin.
* **Quick symlink-handling fixture (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Hierdie archive bevat ’n symlink-entry wat buite die extraction-gids wys; gebruik ’n weggooibare target en verifieer dat die extractor dit nie volg nie. ’n Write-through-toets benodig ook ’n gewone-lêer-entry onder die symlink.

### Go mholt/archiver `Unarchive()` symlink collision (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` kan ’n ZIP-symlink uitpak en dit daarna dereferensieer wanneer ’n latere gewone member dieselfde naam het, wat ’n oënskynlik in-root write in ’n out-of-root write verander.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (die projek is nou deprecated).<sup>[[2]](#references)</sup>
* **Fix**: Skakel oor na `mholt/archives` ≥ 0.1.0 of verwerp links en resolve elke destination onmiddellik voor dit oopgemaak word.<sup>[[2]](#references)</sup>
* **Minimal collision generator** (roep daarna `archiver.Unarchive("exploit.zip", "/tmp/safe")` aan):<sup>[[2]](#references)</sup>
```python
import zipfile

with zipfile.ZipFile("exploit.zip", "w") as z:
link = zipfile.ZipInfo("./x")
link.create_system = 3
link.external_attr = 0o120777 << 16
z.writestr(link, "../../../tmp/PWNED")
z.writestr("./x", b"owned\n")
```

### CPython filtered TAR extraction bypass (CVE-2026-11940)

Selfs `tarfile.extractall(filter="data")` en `filter="tar"` het link-order-bypasses gehad. In hierdie geval het ’n hardlink verwys na ’n symlink wat by ’n dieper path ge-archiveer is; fallback extraction het die relatiewe symlink by daardie diep ligging gevalideer, maar dit by die hardlink se vlakker ligging herskep, waar dieselfde relatiewe target ontsnap het. Dit is ’n nuttige algemene toets: laat validation en materialisation verskil oor die base directory of die finale member-tipe.<sup>[[12]](#references)</sup>

## Detection Tips

* **Static inspection** – Lys beide member-name en link-targets. Merk `../`, `..\\`, absolute/rooted paths, symlinks, hardlinks, special files, duplicate names, type changes en case/Unicode-equivalent collisions. Behou entry order tydens review, omdat die exploit van vroeëre members kan afhang.<sup>[[11]](#references)</sup>
* **Canonicalisation** – Maak seker dat die resolved parent plus die finale basename onder die resolved destination bly (vergelyk path-komponente, nie ’n rou string-prefix nie). Kontroleer weer ná elke voorafgaande member; ’n eenmalige `realpath(join(dest, name))`-toets is kwesbaar vir link replacement en kan misluk vir ’n leaf wat nog nie geskep is nie.<sup>[[3]](#references)[[11]](#references)</sup>
* **Sandbox extraction** – Decompress na ’n nuwe, weggooibare directory met ’n extractor wat path/symlink-checks uitvoer (byvoorbeeld bsdtar se verstek secure checks of 7-Zip ≥ 25.00), en verifieer daarna dat die resulterende tree geen outward links bevat nie. Isolation moet voorkom dat ’n escape wat reeds ge-trigger is, host paths bereik.<sup>[[1]](#references)[[9]](#references)</sup>
* **Downstream reads matter** – ’n Oorgeblewe symlink of hardlink kan ’n arbitrary-file-read primitive word wanneer ’n previewer, CDN, file browser of package pipeline later die uitgepakte naam oopmaak of bedien, selfs al het extraction self geen buite-lêer geskep nie.<sup>[[11]](#references)</sup>
* **Endpoint monitoring** – Genereer ’n alert wanneer nuwe executables na `Startup`/`Run`/`cron`-liggings geskryf word kort nadat ’n archive deur WinRAR/7-Zip/etc. oopgemaak is.

## Mitigation & Hardening

1. **Update the extractor** – WinRAR 7.13+ en 7-Zip 25.00+ bevat fixes vir die aangehaalde path/symlink-issues.<sup>[[1]](#references)[[5]](#references)</sup>
2. Extract archives met “**Do not extract paths**” / “**Ignore paths**” waar moontlik. Vir untrusted input, verwerp symbolic links, hardlinks, devices en FIFOs tensy die application dit uitdruklik benodig.<sup>[[9]](#references)[[11]](#references)</sup>
3. Extract na ’n **new empty directory**. Moenie untrusted members saamsmelt met ’n tree wat attacker-replaceable paths bevat nie, en moenie ’n directory hergebruik wat deur ’n vorige archive geplant is nie.<sup>[[11]](#references)</sup>
4. Op Unix, laat vaar privileges en isoleer die destination in ’n **chroot/mount namespace**; op Windows, gebruik **AppContainer** of ’n sandbox. ’n Post-extraction scan alleen is onvoldoende omdat ’n escaped write voor die scan plaasvind.<sup>[[11]](#references)</sup>
5. In custom code, pas die target OS se separator/case/Unicode-reëls toe en valideer beide die member en link-target. Resolve en open die destination sonder om links te volg; moenie ’n containment check van ’n latere create/replace-operasie skei nie. Die validator moet presies dieselfde base- en link-emulation-semantiek as die write path gebruik.<sup>[[11]](#references)[[12]](#references)</sup>

## Additional Affected / Historical Cases

* 2018 – Massiewe *Zip-Slip*-advisory deur Snyk wat talle Java/Go/JS-libraries geraak het.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal in slugs (reggestel in v0.16.3).<sup>[[7]](#references)</sup>
* Enige custom extraction logic wat header strings valideer, maar nie link-targets en die finale filesystem path wat vir elke write gebruik word nie.<sup>[[11]](#references)[[12]](#references)</sup>



## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Voorkom Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Dateer WinRAR-tools nou op: RomCom en ander misbruik zero-day-kwesbaarheid (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Openbare bekendmaking van ’n kritieke arbitrêre lêeroorskryfkwesbaarheid: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug kwesbaar vir Zip Slip-aanval (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine-metode](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar secure extraction flags](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Proof-of-Concept-exploit vir CVE-2025-11001 in 7-Zip gerapporteer](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – Hacking fun met zip-slips, tar-slips, symlinks, hardlinks, collisions en meer](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – CVE-2026-11940 tarfile extraction filter bypass](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
{{#include ../banners/hacktricks-training.md}}
