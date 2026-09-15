# Archive Extraction Path Traversal ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## Oorsig

Baie archive-formate (ZIP, RAR, TAR, 7-ZIP, ens.) laat elke entry toe om sy eie **interne path** te bevat. Wanneer ’n extraction utility daardie path blindelings eerbiedig, sal ’n vervaardigde filename wat `..` of ’n **absolute path** (bv. `C:\Windows\System32\`) bevat, buite die user-chosen directory geskryf word.
Hierdie klas kwesbaarheid staan algemeen bekend as *Zip-Slip* of **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Gevolge wissel van die oorskryf van arbitrary files tot die direkte verkryging van **remote code execution (RCE)** deur ’n payload in ’n **auto-run**-ligging, soos die Windows *Startup*-folder, te plaas.

## Oorsaak

1. Attacker skep ’n archive waarin een of meer file headers die volgende bevat:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Of vervaardigde **symlinks** wat buite die target dir resolve (algemeen in ZIP/TAR op *nix*).
2. Victim extract die archive met ’n kwesbare tool wat die embedded path vertrou (of symlinks volg) in plaas daarvan om dit te sanitise of extraction onder die gekose directory af te dwing.
3. Die file word in die attacker-controlled location geskryf en volgende keer uitgevoer/geladen wanneer die system of user daardie path trigger.

### .NET `Path.Combine` + `ZipArchive` traversal

’n Algemene .NET anti-pattern is om die beoogde destination met user-controlled `ZipArchiveEntry.FullName` te kombineer en te extract sonder path normalisation:<sup>[[4]](#references)[[8]](#references)</sup>
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
- As `entry.FullName` met `..\\` begin, traverseer dit; indien dit ’n **absolute path** is, word die linkerkantse komponent heeltemal weggegooi, wat ’n **arbitrary file write** as die extraction identity oplewer.
- Proof-of-concept-argief om na ’n sibling `app`-gids te skryf wat deur ’n geskeduleerde scanner gemonitor word:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Deur daardie ZIP in die gemonitorde inkassie te plaas, lei dit tot `C:\samples\app\0xdf.txt`, wat traversal buite `C:\samples\queue\` bewys en opvolgende primitives moontlik maak (bv. DLL hijacks).

## Gevorderde Archive-Breakout Primitives

Behandel ekstraksie as ’n reeks lêerstelselmutasies, nie as onafhanklike lêernaamkontroles nie. ’n Inskrywing wat veilig is wanneer dit geparse word, kan onveilig word nadat ’n vorige lid ’n skakel skep of vervang; dieselfde probleem ontstaan wanneer ’n extractor ’n gids as veilig cache en die tipe daarvan later verander.<sup>[[11]](#references)</sup>

### Skakelpivots en inskrywingsbotsings

* **Symlink write-through**: skep `pivot -> /tmp`, en ekstraheer dan ’n gewone lid as `pivot/PWNED.txt`. As die extractor die eerste lid volg terwyl die tweede gematerialiseer word, ontsnap die skrywing sonder `..` in die tweede naam.
* **Directory-cache/TOCTOU collision**: genereer gids `d/sub/`, vervang `d/sub` met ’n symlink na `/tmp`, en genereer dan `d/sub/PWNED.txt`. Dit teiken extractors wat die gids een keer valideer of cache en dit nie weer kontroleer voordat die finale skrywing plaasvind nie.
* **Hardlink read/overwrite**: TAR en RAR kan hardlinks voorstel. ’n Hardlink na ’n bestaande gasheerlêer kan die inhoud daarvan blootstel as ’n latere komponent die geëkstraheerde naam bedien; ’n botsende gewone inskrywing kan eerder die gekoppelde inode oorskryf. Dit word beperk deur reëls vir dieselfde lêerstelsel en OS-hardlink-toestemmings.
* **Pre-existing or cross-archive pivot**: probeer weer met ’n nie-leë bestemming. Een argief kan ’n skakel plant, en ’n latere ekstraksie kan daardeur skryf, selfs al slaag elke argief ’n statelose header-name check.<sup>[[11]](#references)</sup>

### Lêerstelsel-ekwivalensiebotsings

Vergelyk name volgens die semantiek van die lêerstelsel wat dit sal ontvang. Nuttige differensiële gevalle sluit in `LINK` teenoor `link` op hoofletter-onsensitiewe lêerstelsels, NFC teenoor NFD Unicode-spellings, kompatibiliteit-ekwivalente name soos `ﬁle` teenoor `file`, duplikaatlede wat ’n pad van ’n gids na ’n symlink verander, en backslashes wat slegs op Windows as skeiers geïnterpreteer word. Toets ook ADS-bevattende name op NTFS. Hierdie gevalle kan veroorsaak dat die validator twee paaie sien terwyl die lêerstelsel een pad resolveer.<sup>[[5]](#references)[[11]](#references)</sup>

’n Kompakte corpus behoort dus geordende kombinasies van **directory → symlink → child**, **symlink → colliding regular file**, **hardlink → colliding regular file**, gemengde `/` en `\`, absolute/rooted names, en saamgeperste wrappers soos `.tar.gz` te toets. Voer dit slegs in ’n weggooibare VM/container uit en monitor sowel die bestemming as die bedoelde canary-pad buite die bestemming.<sup>[[11]](#references)</sup>

ZIP-specific structural ambiguity kan veroorsaak dat ’n pre-scan en die werklike extractor verskillende inskrywingsname of bome waarneem. Sien [Local-header vs central-directory parser confusion](../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md#local-header-vs-central-directory-parser-confusion) eerder as om slegs op die uitvoer van een ZIP-library te vertrou.

## Werklike voorbeeld – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR for Windows en sy Windows RAR/UnRAR-komponente het versuim om lêername tydens ekstraksie te valideer. Die fout het NTFS alternate data streams (ADS) gebruik om die gekose ekstraksiepad te omseil en lêers na onbedoelde liggings te skryf.<sup>[[5]](#references)</sup>
’n Kwaadwillige RAR-argief wat ’n inskrywing soos die volgende bevat:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
sou **buite** die geselekteerde uitvoergids en binne die gebruiker se *Startup*-gids beland. ESET het waargeneem dat kwaadwillige LNK-lêers daar uitgepak en tydens gebruiker-aanmelding uitgevoer is, wat persistence en 'n pad na RCE gebied het.<sup>[[5]](#references)</sup>

### Skep van 'n PoC-argief (Linux/Mac)

Omdat CVE-2025-8088 'n traversal-pad in 'n ADS-naam gebruik, gebruik 'n doelgeboude generator om die RAR te skep, en toets ekstraksie slegs in 'n geïsoleerde lab met 'n kwesbare WinRAR-build.<sup>[[5]](#references)</sup>

### Waargenome Exploitation in die Wild

ESET het RomCom (Storm-0978/UNC2596) spear-phishing-veldtogte gerapporteer wat RAR-argiewe aangeheg het wat CVE-2025-8088 misbruik om aangepaste backdoors te ontplooi en ransomware-bedrywighede te fasiliteer.<sup>[[5]](#references)</sup>

## Newer Cases (2024–2026)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP-inskrywings wat **symboliese skakels** was, is tydens ekstraksie gedereferensieer, wat attackers toegelaat het om uit die bestemmingsgids te ontsnap en arbitrêre paths te oorskryf. Gebruikerinteraksie is bloot *opening/extracting* van die argief.<sup>[[1]](#references)</sup>
* **Affected**: 7-Zip-builds voor **25.00**. Die fout in die verwerking van simboliese skakels is in **25.00** (Julie 2025) en later reggestel.<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**: Oorskryf `Start Menu/Programs/Startup` of service-run-liggings → code loop tydens die volgende aanmelding of diensherbegin.
* **Quick symlink-handling fixture (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Hierdie argief bevat 'n simboliese-skakel-inskrywing wat buite die ekstraksiegids wys; gebruik 'n weggooibare teiken en verifieer dat die extractor dit nie volg nie. 'n Write-through-toets benodig ook 'n gewone-lêer-inskrywing onder die simboliese skakel.

### Go mholt/archiver `Unarchive()` symlink collision (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` kan 'n ZIP-simboliese skakel ekstraheer en dit daarna dereferensieer wanneer 'n latere gewone member dieselfde naam het, wat 'n skynbaar in-root write in 'n out-of-root write verander.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (projek nou deprecated).<sup>[[2]](#references)</sup>
* **Fix**: Skakel oor na `mholt/archives` ≥ 0.1.0 of reject links en resolve elke bestemming onmiddellik voordat dit oopgemaak word.<sup>[[2]](#references)</sup>
* **Minimal collision generator** (roep dan `archiver.Unarchive("exploit.zip", "/tmp/safe")` aan):<sup>[[2]](#references)</sup>
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

Selfs `tarfile.extractall(filter="data")` en `filter="tar"` het link-order-bypasses gehad. In hierdie geval het 'n hardlink verwys na 'n simboliese skakel wat by 'n dieper path ge-archiveer was; fallback extraction het die relatiewe simboliese skakel by daardie diep ligging gevalideer, maar dit by die hardlink se vlakker ligging herskep, waar dieselfde relatiewe target ontsnap het. Dit is 'n nuttige algemene toets: laat validation en materialisation oor die base directory of finale member type verskil.<sup>[[12]](#references)</sup>

### Node `tar` hardlink target escape through a symlink chain (GHSA-83g3-92jg-28cx)

Die Node.js `tar`-package se `tar.extract()` het 'n hardlink aanvaar waarvan die target leksikaal binne die ekstraksie-root gelyk het, maar deur twee vroeëre simboliese skakels buite die ekstraksie-root resolved het. Die aanval werk met die verstek-ekstraksieopsies: destination-parent checks het die hardlink se in-root-naam gedek, terwyl die hardlink-target aan die filesystem gegee is sonder om die volledige chain vir containment te resolve. `tar` ≤ 7.5.7 is affected; 7.5.8 patch die issue.<sup>[[13]](#references)</sup>

Die belangrike test fixture is die **geordende verhouding** tussen members, nie hierdie letterlike name nie:<sup>[[13]](#references)</sup>
```text
a/b/c/up     -> ../..                          (symlink)
a/b/escape   -> c/up/../..                     (symlink)
exfil        => a/b/escape/<path-from-parent>  (hardlink)
```
As ekstraksie slaag, bly `exfil` sigbaar binne die uitvoerboom, maar deel dit ’n inode met die gekose eksterne lêer; die lees daarvan veroorsaak ’n leak van daardie lêer, en die skryf daarvan wysig die oorspronklike. Hierdie omseiling illustreer waarom dit onvoldoende is om slegs die finale padnaam na te gaan, absolute voorvoegsels te verwyder, of `..` in die hardlink-kop te blokkeer: valideer skakelteikens nadat alle voorheen geëkstraheerde lêerstelseltoestand toegepas is.<sup>[[13]](#references)</sup>

## Opsporingswenke

* **Statiese inspeksie** – Lys beide lidname en skakelteikens. Merk `../`, `..\\`, absolute/gewortelde paaie, simlinks, hardlinks, spesiale lêers, duplikaatname, tipeveranderinge en botsings tussen hoofletter-/Unicode-ekwivalente. Behou die inskrywingsvolgorde tydens hersiening, omdat die exploit van vroeëre lede kan afhang.<sup>[[11]](#references)</sup>

```bash
bsdtar -tvf suspect.tar       # ordered TAR members, types and link targets
7z l -slt suspect.7z          # technical metadata, one field per line
zipinfo -v suspect.zip        # ZIP central-directory metadata and offsets
```

* **Kanonisering** – Verseker dat die opgeloste ouer plus die finale basisnaam onder die opgeloste bestemming bly (vergelyk padkomponente, nie ’n rou stringvoorvoegsel nie). Kontroleer weer ná elke voorafgaande lid; ’n eenmalige `realpath(join(dest, name))`-toets is kwesbaar vir skakelvervanging en kan misluk vir ’n blaar wat nog nie geskep is nie.<sup>[[3]](#references)[[11]](#references)</sup>
* **Sandbox-ekstraksie** – Decomprimeer na ’n vars, weggooibare gids deur ’n extractor met pad-/simlinkkontroles te gebruik (byvoorbeeld bsdtar se verstek veilige kontroles of 7-Zip ≥ 25.00), en verifieer dan dat die gevolglike boom geen uitwaartse skakels bevat nie. Isolasie moet voorkom dat ’n reeds-geaktiveerde ontsnapping gasheerpaaie bereik.<sup>[[1]](#references)[[9]](#references)</sup>
* **Daaropvolgende leesbewerkings is belangrik** – ’n Oorlewende simlink of hardlink kan ’n primitief vir die lees van arbitrêre lêers word wanneer ’n voorskouer, CDN, lêerblaaier of pakketpyplyn later die geëkstraheerde naam oopmaak of bedien, selfs al het ekstraksie self geen eksterne lêer geskep nie.<sup>[[11]](#references)</sup>
* **Eindpuntmonitering** – Waarsku oor nuwe uitvoerbare lêers wat kort nadat ’n argief deur WinRAR/7-Zip/etc. oopgemaak is, na `Startup`/`Run`/`cron`-liggings geskryf word.

## Versagting & Versterking

1. **Werk die extractor by** – WinRAR 7.13+, 7-Zip 25.00+ en Node `tar` 7.5.8+ bevat regstellings vir die aangehaalde pad-/simlink-/skakelteikenkwessies.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>
2. Ekstraheer argiewe met “**Do not extract paths**” / “**Ignore paths**” waar moontlik. Vir onbetroubare invoer, verwerp simboliese skakels, hardlinks, toestelle en FIFOs tensy die toepassing dit uitdruklik benodig.<sup>[[9]](#references)[[11]](#references)</sup>
3. Ekstraheer na ’n **nuwe leë gids**. Moenie onbetroubare lede saamsmelt met ’n boom wat paaie bevat wat deur ’n aanvaller vervang kan word nie, en moenie ’n gids hergebruik wat deur ’n vorige argief voorberei is nie.<sup>[[11]](#references)</sup>
4. Op Unix, verlaag voorregte en isoleer die bestemming in ’n **chroot/mount-namespace**; op Windows, gebruik **AppContainer** of ’n sandbox. ’n Skandering ná ekstraksie alleen is onvoldoende, omdat ’n ontsnapte skryfbewerking plaasvind voordat die skandering begin.<sup>[[11]](#references)</sup>
5. Pas in pasgemaakte kode die teiken-OS se skeier-, hoofletter- en Unicode-reëls toe, en valideer beide die lid en die skakelteiken. Los die bestemming op en maak dit oop sonder om skakels te volg; moenie ’n insluitingskontrole van ’n latere skep/vervang-bewerking skei nie. Die valideerder moet presies dieselfde basis- en skakel-emulasiesemantiek as die skryfpad gebruik.<sup>[[11]](#references)[[12]](#references)</sup>

## Bykomende Geaffekteerde / Historiese Gevalle

* 2018 – Massiewe *Zip-Slip*-advies deur Snyk wat baie Java/Go/JS-biblioteke geraak het.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR-ekstraksie-traversal in slugs (reggestel in v0.16.3).<sup>[[7]](#references)</sup>
* Enige pasgemaakte ekstraksielogika wat kopstringe valideer, maar nie skakelteikens en die finale lêerstelselpad wat vir elke skryfbewerking gebruik word nie.<sup>[[11]](#references)[[12]](#references)</sup>





## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip simlink ZIP-traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Voorkom Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL-kapingketting](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Werk WinRAR-nutsgoed nou by: RomCom en ander buit zero-day-kwesbaarheid uit (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Openbare bekendmaking van ’n kritieke kwesbaarheid vir die arbitrêre oorskryf van lêers: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug kwesbaar vir Zip Slip-aanval (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine-metode](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar-vlae vir veilige ekstraksie](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Proof-of-Concept-exploit gerapporteer vir CVE-2025-11001 in 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – Pret met hacking met zip-slips, tar-slips, simlinks, hardlinks, botsings en meer](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – CVE-2026-11940 tarfile-ekstraksiefilter-omseiling](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
- [13] [GitHub Security Advisory – node-tar-hardlink-teikenontsnapping deur simlink-ketting](https://github.com/isaacs/node-tar/security/advisories/GHSA-83g3-92jg-28cx)
{{#include ../banners/hacktricks-training.md}}
