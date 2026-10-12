# Archive Extraction Path Traversal ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## Oorsig

Baie argiefformate (ZIP, RAR, TAR, 7-ZIP, ens.) laat toe dat elke inskrywing sy eie **interne pad** bevat. Wanneer ’n ekstraksiehulpmiddel daardie pad blindelings eerbiedig, word ’n vervalste lêernaam met `..` of ’n **absolute pad** (bv. `C:\Windows\System32\`) buite die gids wat die gebruiker gekies het, geskryf.  
Hierdie kwesbaarheidsklas staan algemeen bekend as *Zip-Slip* of **padtraversering tydens argiefekstraksie**.<sup>[[6]](#references)</sup>

Gevolge wissel van die oorskryf van arbitrêre lêers tot die verkryging van **remote code execution (RCE)** deur ’n payload in ’n **outo-uitvoer**-ligging te plaas, soos die Windows-*Startup*-gids.

## Grondoorsaak

1. Die aanvaller skep ’n argief waarin een of meer lêeropskrifte die volgende bevat:
   * Relatiewe traverseringreekse (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
   * Absolute paaie (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
   * Of vervalste **simboliese skakels** wat buite die teikengids oplos (algemeen in ZIP/TAR op *nix*). 
2. Die slagoffer onttrek die argief met ’n kwesbare hulpmiddel wat die ingebedde pad vertrou (of simboliese skakels volg) eerder as om dit te saniteer of ekstraksie binne die gekose gids af te dwing.
3. Die lêer word op die aanvaller-beheerde plek geskryf en uitgevoer/gelaai wanneer die stelsel of gebruiker daardie pad die volgende keer aktiveer.

### .NET `Path.Combine` + `ZipArchive`-traversering

’n Algemene .NET-antipatroon is om die beoogde bestemming met **gebruikerbeheerde** `ZipArchiveEntry.FullName` te kombineer en te onttrek sonder padnormalisering:<sup>[[4]](#references)[[8]](#references)</sup>

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

- As `entry.FullName` met `..\\` begin, traverseer dit; as dit ’n **absolute path** is, word die komponent aan die linkerkant heeltemal weggegooi, wat ’n **arbitrary file write** as die onttrekkingsidentiteit oplewer.
- Proof-of-concept-argief om na ’n aangrensende `app`-gids te skryf wat deur ’n geskeduleerde skandeerder gemonitor word:

```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
    z.writestr("../app/0xdf.txt", "ABCD")
```

Deur daardie ZIP in die gemonitorde inkassie te plaas, ontstaan `C:\samples\app\0xdf.txt`. Dit bewys traversal buite `C:\samples\queue\` en maak opvolgprimitiewe moontlik (bv. DLL-hijacks).

### Gebruikerbeheerde ekstraksiewortel

Toets ook die **gids wat aan die extractor deurgegee word**, nie net die argief se lede se name nie. ’n Toepassing kan daardie gids aflei van ’n titel, projeknaam of ander versoekveld. ’n Waarde soos `../../../../app/module` kan die ekstraksiewortel buite die oplaai-area verskuif voordat die extractor enige lede verwerk. In daardie geval kan selfs ’n argief wat net die veilige basisnaam `api.py` bevat, toepassingkode oorskryf.<sup>[[14]](#references)[[15]](#references)</sup>

```python
# Vulnerable pattern: the ZIP entries themselves need no ../ components.
extract_root = os.path.join(site_root, "public", "files", user_title)
archive.extractall(extract_root)
```

Dit is ’n aparte insluitingsgrens van klassieke Zip-Slip. Valideer sowel die opgeloste onttrekkingswortel as elke opgeloste lidpad. ’n Wortelkontrole kan padkomponente in plaas van ’n stringvoorvoegsel gebruik:<sup>[[14]](#references)</sup>

```python
base = Path(site_root, "public", "files").resolve()
dest = (base / user_title).resolve()
if not dest.is_relative_to(base):
    raise ValueError("extraction root escapes its base")
```

Vir ’n veilige toets, laai ’n geldige argief met een canary-lêer op en plaas traversal-reekse in elke veld wat die ekstraksiegids kan bepaal. Monitor sowel die bedoelde gids as ’n weggooibare pad buite die gids. As die bestemming toegang tot ’n ingevoerde module het, kan die oorskryf daarvan tot code execution lei wanneer workers herlaai; ’n HTTP 500 of verbindingsherstel tydens daardie herlaai bewys nie dat die skryfaksie misluk het nie.<sup>[[14]](#references)[[15]](#references)</sup> Sien ook die breër [metodologie vir lêeroplaaie](../pentesting-web/file-upload/).

## Gevorderde primitiewe vir argiefontsnapping

Behandel ekstraksie as ’n reeks lêerstelselmutasies, nie as onafhanklike lêernaamkontroles nie. ’n Inskrywing wat veilig is wanneer dit ontleed word, kan onveilig raak nadat ’n vroeëre lid ’n skakel skep of vervang; dieselfde probleem kom voor wanneer ’n extractor ’n gids as veilig kas en die tipe daarvan later verander.<sup>[[11]](#references)</sup>

### Skakelpivots en inskrywingsbotsings

* **Symlink write-through**: skep `pivot -> /tmp`, en ekstraheer dan ’n gewone lid as `pivot/PWNED.txt`. As die extractor die eerste lid volg wanneer die tweede gematerialiseer word, ontsnap die skryfaksie sonder `..` in die tweede naam.
* **Directory-cache/TOCTOU-botsing**: skryf die gids `d/sub/`, vervang `d/sub` met ’n symlink na `/tmp`, en skryf dan `d/sub/PWNED.txt`. Dit teiken extractors wat die gids een keer valideer of kas en dit nie weer nagaan voor die finale skryfaksie nie.
* **Hardlink lees/oor­skryf**: TAR en RAR kan hardlinks voorstel. ’n Hardlink na ’n bestaande lêer op die gasheerstelsel kan die inhoud daarvan blootlê as ’n latere komponent die geëkstraheerde naam bedien; ’n botsende gewone inskrywing kan eerder die gekoppelde inode oorskryf. Dit word beperk deur reëls vir dieselfde lêerstelsel en OS-toestemmings vir hardlinks.
* **Bestaande of kruisargief-pivot**: probeer weer met ’n nie-leë bestemming. Een argief kan ’n skakel plaas en ’n latere ekstraksie kan daardeur skryf, selfs al slaag elke argief ’n staatlose kontrole van die opskrifnaam.<sup>[[11]](#references)</sup>

### Lêerstelsel-ekwivalensiebotsings

Vergelyk name volgens die semantiek van die lêerstelsel wat dit sal ontvang. Nuttige differensiële gevalle sluit in `LINK` teenoor `link` op lêerstelsels wat nie hooflettergevoelig is nie, NFC- teenoor NFD-Unicode-spellings, name wat ekwivalent is volgens versoenbaarheid, soos `ﬁle` teenoor `file`, duplikaatlede wat ’n pad van gids na symlink verander, en terugskuinsstrepe wat slegs op Windows as skeiers geïnterpreteer word. Toets ook name met ADS op NTFS. Hierdie gevalle kan veroorsaak dat die valideerder twee paaie sien terwyl die lêerstelsel een pad oplos.<sup>[[5]](#references)[[11]](#references)</sup>

’n Kompakte toetsversameling behoort dus geordende kombinasies te toets van **gids → symlink → kind**, **symlink → botsende gewone lêer**, **hardlink → botsende gewone lêer**, gemengde `/` en `\`, absolute/gewortelde name, en saamgeperste omhulsels soos `.tar.gz`. Doen dit slegs in ’n weggooibare VM/container en monitor sowel die bestemming as die bedoelde canary-pad buite die gids.<sup>[[11]](#references)</sup>

ZIP-spesifieke strukturele dubbelsinnigheid kan veroorsaak dat ’n voorafskandering en die werklike extractor verskillende inskrywingsname of bome waarneem. Sien [Verwarring tussen ontleder van plaaslike kopskrif en sentrale gids](../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md#local-header-vs-central-directory-parser-confusion) eerder as om die uitvoer van net een ZIP-biblioteek te vertrou.

## Werklike voorbeeld – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR vir Windows en sy Windows RAR/UnRAR-komponente het nagelaat om lêername tydens ekstraksie te valideer. Die fout het NTFS alternate data streams (ADS) gebruik om die geselekteerde ekstraksiepad te omseil en lêers na onbedoelde plekke te skryf.<sup>[[5]](#references)</sup>
’n Kwaadwillige RAR-argief wat ’n inskrywing soos die volgende bevat:

```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```

sou buite die geselekteerde uitvoergids en in die gebruiker se *Startup*-gids beland. ESET het waargeneem dat kwaadwillige LNK-lêers daar uitgepak en tydens die gebruiker se aanmelding uitgevoer is, wat volharding en ’n pad na RCE gebied het.<sup>[[5]](#references)</sup>

### Skep van ’n PoC-argief (Linux/Mac)

Omdat CVE-2025-8088 ’n traversal-pad in ’n ADS-naam gebruik, moet jy ’n doelgemaakte generator gebruik om die RAR te skep. Toets die uitpak daarvan dan slegs in ’n geïsoleerde laboratorium met ’n kwesbare WinRAR-bouweergawe.<sup>[[5]](#references)</sup>

### Waargenome uitbuiting in die natuur

ESET het spear-phishing-veldtogte deur RomCom (Storm-0978/UNC2596) aangemeld waarin RAR-argiewe aangeheg is wat CVE-2025-8088 misbruik het om pasgemaakte backdoors te ontplooi en ransomware-bedrywighede te fasiliteer.<sup>[[5]](#references)</sup>

## Nuwer gevalle (2024–2026)

### 7-Zip ZIP-symlink-traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Fout**: ZIP-inskrywings wat **simboliese skakels** was, is tydens uitpak gevolg, sodat aanvallers buite die bestemmingsgids kon ontsnap en arbitrêre paaie kon oorskryf. Gebruikerinteraksie behels net die *oopmaak/uitpak* van die argief.<sup>[[1]](#references)</sup>
* **Geaffekteer**: 7-Zip-bouweergawes voor **25.00**. Die fout in die verwerking van simboliese skakels is in **25.00** (Julie 2025) en later reggestel.<sup>[[1]](#references)[[10]](#references)</sup>
* **Impakpad**: Oorskryf `Start Menu/Programs/Startup` of plekke waarvandaan dienste uitgevoer word → kode loop tydens die volgende aanmelding of wanneer die diens herbegin.
* **Vinnige toetsopstelling vir symlink-hantering (Linux)**:
  ```bash
  mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
  ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
  cd /tmp/archive-slip-test
  zip -y exploit.zip evil   # -y preserves symlinks
  7z x exploit.zip -o/tmp/archive-slip-target
  ```
  Hierdie argief bevat ’n symlink-inskrywing wat buite die onttrekkingsgids wys; gebruik ’n weggooibare teiken en verifieer dat die onttrekker dit nie volg nie. ’n Deurskryftoets vereis ook ’n gewone lêerinskrywing onder die symlink.

### Go mholt/archiver `Unarchive()`-symlink-botsing (CVE-2025-3445)
* **Fout**: `archiver.Unarchive()` kan ’n ZIP-symlink onttrek en dit dan dereferensieer wanneer ’n latere gewone lêerlid dieselfde naam het, wat ’n skynbaar interne skryfbewerking in ’n skryfbewerking buite die gids verander.<sup>[[2]](#references)</sup>
* **Geaffekteer**: `github.com/mholt/archiver` ≤ 3.5.1 (die projek is nou afgekeur).<sup>[[2]](#references)</sup>
* **Oplossing**: Skakel oor na `mholt/archives` ≥ 0.1.0 of verwerp skakels en los elke bestemming onmiddellik voor dit oopgemaak word weer op.<sup>[[2]](#references)</sup>
* **Minimale botsingsgenerator** (roep daarna `archiver.Unarchive("exploit.zip", "/tmp/safe")` aan):<sup>[[2]](#references)</sup>
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

Selfs `tarfile.extractall(filter="data")` en `filter="tar"` was kwesbaar vir omleidings deur die volgorde van skakels. In hierdie geval het ’n hardlink verwys na ’n symlink wat op ’n dieper pad geargiveer is; die fallback extraction het die relatiewe symlink by daardie dieper ligging gevalideer, maar dit by die hardlink se hoër ligging herskep, waar dieselfde relatiewe teiken buite die bestemming geval het. Dit is ’n nuttige algemene toets: laat validering en materialisering verskil oor die basisgids of die finale lid se tipe.<sup>[[12]](#references)</sup>

### Node `tar`-hardlink-teiken ontsnap deur ’n symlink-ketting (GHSA-83g3-92jg-28cx)

Die Node.js `tar`-pakket se `tar.extract()` het ’n hardlink aanvaar waarvan die teiken tekstueel binne die bestemming gelyk het, maar deur twee vroeëre symlinks buite die extraction-wortel opgelos is. Die aanval werk met die verstek extraction-opsies: kontroles van die bestemmingsouer het die hardlink se naam binne die wortel gedek, terwyl die hardlink-teiken aan die lêerstelsel deurgegee is sonder dat die volledige ketting vir insluiting opgelos is. `tar` ≤ 7.5.7 is geraak; 7.5.8 maak die probleem reg.<sup>[[13]](#references)</sup>

Die belangrike toets-fixture is die **geordende verhouding** tussen lede, nie hierdie letterlike name nie:<sup>[[13]](#references)</sup>

```text
a/b/c/up     -> ../..                          (symlink)
a/b/escape   -> c/up/../..                     (symlink)
exfil        => a/b/escape/<path-from-parent>  (hardlink)
```

As ekstraksie slaag, bly `exfil` sigbaar binne die uitvoerboom, maar deel ’n inode met die gekose lêer buite die boom; om dit te lees, lek daardie lêer, en om daarin te skryf, wysig die oorspronklike. Hierdie omseiling wys waarom dit onvoldoende is om slegs die finale pad na te gaan, absolute voorvoegsels te verwyder of `..` in die hardlink-opskrif te blokkeer: valideer skakelteikens nadat al die voorheen onttrekte lêerstelseltoestand toegepas is.<sup>[[13]](#references)</sup>

## Opsporingswenke

* **Statiese inspeksie** – Lys sowel lede se name as skakelteikens. Merk `../`, `..\\`, absolute/gegronde paaie, symlinks, hardlinks, spesiale lêers, duplikaatname, tipeveranderings en botsings tussen hooflettergevoelige/Unicode-ekwivalente name. Behou die volgorde van inskrywings tydens die hersiening, omdat die uitbuiting van vroeëre lede kan afhang.<sup>[[11]](#references)</sup>

  ```bash
  bsdtar -tvf suspect.tar       # ordered TAR members, types and link targets
  7z l -slt suspect.7z          # technical metadata, one field per line
  zipinfo -v suspect.zip        # ZIP central-directory metadata and offsets
  ```

* **Kanonisering** – Maak seker dat die opgeloste ouergids plus die finale basisnaam binne die opgeloste bestemmingsgids bly (vergelyk padkomponente, nie ’n rou stringvoorvoegsel nie). Kontroleer dit weer ná elke voorafgaande lid; ’n eenmalige `realpath(join(dest, name))`-toets is kwesbaar vir skakelvervanging en kan misluk vir ’n blaarknoop wat nog nie geskep is nie.<sup>[[3]](#references)[[11]](#references)</sup>
* **Sandbox-onttrekking** – Decomprimeer na ’n nuwe, tydelike gids met ’n onttrekker wat pad-/symlink-kontroles uitvoer (byvoorbeeld bsdtar se verstek veilige kontroles of 7-Zip ≥ 25.00), en verifieer dan dat die resulterende boom geen skakels na buite bevat nie. Isolasie moet voorkom dat ’n ontsnapping wat reeds geaktiveer is, gasheerpaadjies bereik.<sup>[[1]](#references)[[9]](#references)</sup>
* **Latere leesaksies is belangrik** – ’n Symlink of hardlink wat agterbly, kan ’n primitief vir die lees van arbitrêre lêers word wanneer ’n voorskouer, CDN, lêerblaaier of pakketpyplyn later die onttrekte naam oopmaak of bedien, selfs al het die onttrekking self geen lêer buite die gids geskep nie.<sup>[[11]](#references)</sup>
* **Monitering van eindpunte** – Stel ’n waarskuwing in vir nuwe uitvoerbare lêers wat kort nadat ’n argief deur WinRAR/7-Zip/ens. oopgemaak is, na `Startup`-/`Run`-/`cron`-liggings geskryf word.

## Versagting en verharding

1. **Dateer die onttrekker op** – WinRAR 7.13+, 7-Zip 25.00+ en Node `tar` 7.5.8+ bevat regstellings vir die aangehaalde probleme met paaie, symlinks en skakelteikens.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>
2. Onttrek argiewe met “**Moenie paaie onttrek nie**” / “**Ignoreer paaie**” waar moontlik. Verwerp simboliese skakels, hardlinks, toestelle en FIFOs vir onvertroude invoer, tensy die toepassing dit uitdruklik nodig het.<sup>[[9]](#references)[[11]](#references)</sup>
3. Onttrek na ’n **nuwe, leë gids**. Moenie onvertroude lede by ’n boom voeg wat paaie bevat wat ’n aanvaller kan vervang nie, en moenie ’n gids hergebruik wat deur ’n vorige argief voorberei is nie.<sup>[[11]](#references)</sup>
4. Op Unix, verlaag die voorregte en isoleer die bestemming in ’n **chroot-/mount-namespace**; gebruik **AppContainer** of ’n sandbox op Windows. ’n Skandering ná onttrekking alleen is onvoldoende, want ’n ontsnapte skryfbewerking vind plaas voordat die skandering begin.<sup>[[11]](#references)</sup>
5. Pas in pasgemaakte kode die teikenbedryfstelsel se skeier-, hoofletter- en Unicode-reëls toe, en valideer beide die lid en die skakelteiken. Los die bestemming op en maak dit oop sonder om skakels te volg; moenie ’n insluitingskontrole skei van ’n latere skep-/vervangbewerking nie. Die valideerder moet presies dieselfde basis- en skakel-emulasiesemantiek as die skryfbewerking gebruik.<sup>[[11]](#references)[[12]](#references)</sup>

## Bykomende geraakte / historiese gevalle

* 2018 – Snyk se groot *Zip-Slip*-advies, wat baie Java-/Go-/JS-biblioteke geraak het.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377): TAR-onttrekkingspadtraversering in slugs (reggestel in v0.16.3).<sup>[[7]](#references)</sup>
* Enige pasgemaakte onttrekkingslogika wat kopstringe valideer, maar nie skakelteikens en die finale lêerstelselpad wat vir elke skryfbewerking gebruik word nie.<sup>[[11]](#references)[[12]](#references)</sup>





## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink-ZIP-traversering (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Voorkom Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL-kapingketting](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Dateer WinRAR-nutsgoed nou op: RomCom en ander buit nuldagkwesbaarheid uit (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Openbare bekendmaking van ’n kritieke kwesbaarheid vir arbitrêre lêeroorskrywing: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug kwesbaar vir Zip Slip-aanval (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine-metode](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar-vlae vir veilige onttrekking](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Bewys-van-konsep-uitbuiting vir CVE-2025-11001 in 7-Zip gerapporteer](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – Pret met zip-slips, tar-slips, symlinks, hardlinks, botsings en meer](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – CVE-2026-11940-omseiling van tarfile-onttrekkingsfilter](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
- [13] [GitHub Security Advisory – node-tar-hardlink-teiken ontsnap deur ’n symlink-ketting](https://github.com/isaacs/node-tar/security/advisories/GHSA-83g3-92jg-28cx)
- [14] [Rhino Security Labs CVE PoC – gebruikerbeheerde SCORM-onttrekkingswortel](https://raw.githubusercontent.com/RhinoSecurityLabs/CVEs/master/CVE-2026-39405/README.md)
- [15] [Rhino Security Labs – Veelvuldige kwesbaarhede in Frappe LMS wat tot afgeleë kode-uitvoering lei](https://rhinosecuritylabs.com/research/multiple-vulnerabilities-in-frappe-lms-leading-to-remote-code-execution/)
{{#include ../banners/hacktricks-training.md}}
