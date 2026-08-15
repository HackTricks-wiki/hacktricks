# Archive Extraction Path Traversal ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## Muhtasari

Miundo mingi ya archive (ZIP, RAR, TAR, 7-ZIP, n.k.) huruhusu kila entry kuwa na **internal path** yake. Zana ya extraction inapofuata path hiyo bila kuikagua, filename iliyoundwa ikiwa na `..` au **absolute path** (kwa mfano `C:\Windows\System32\`) itaandikwa nje ya directory iliyochaguliwa na mtumiaji.
Aina hii ya vulnerability inajulikana sana kama *Zip-Slip* au **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Madhara yanaweza kuanzia kubadilisha faili zozote hadi kupata moja kwa moja **remote code execution (RCE)** kwa kuweka payload katika eneo la **auto-run**, kama vile folder ya Windows *Startup*.

## Chanzo Kikuu

1. Attacker huunda archive ambapo file header moja au zaidi zina:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Au **symlinks** zilizoundwa kwa ustadi ambazo hu-resolve nje ya target dir (jambo la kawaida katika ZIP/TAR kwenye *nix*).
2. Victim hu-extract archive kwa kutumia tool yenye vulnerability inayoamini path iliyowekwa ndani (au kufuata symlinks), badala ya kuisafisha au kulazimisha extraction ifanyike chini ya directory iliyochaguliwa.
3. File huandikwa katika location inayodhibitiwa na attacker na kutekelezwa/kupakiwa wakati mwingine mfumo au mtumiaji anapo-trigger path hiyo.

### .NET `Path.Combine` + `ZipArchive` traversal

Anti-pattern ya kawaida katika .NET ni kuunganisha destination iliyokusudiwa na `ZipArchiveEntry.FullName` inayodhibitiwa na mtumiaji, kisha kufanya extraction bila path normalisation:<sup>[[4]](#references)[[8]](#references)</sup>
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
- Ikiwa `entry.FullName` inaanza na `..\\`, hufanya path traversal; ikiwa ni **absolute path**, sehemu ya upande wa kushoto huondolewa kabisa, na hivyo kusababisha **arbitrary file write** kama extraction identity.
- Archive ya proof-of-concept ya kuandika kwenye directory ya `app` iliyo jirani, inayofuatiliwa na scanner iliyoratibiwa:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Kudondosha ZIP hiyo kwenye inbox inayofuatiliwa husababisha `C:\samples\app\0xdf.txt`, kuthibitisha traversal nje ya `C:\samples\queue\` na kuwezesha primitives za ufuatiliaji (kwa mfano, DLL hijacks).

## Advanced Archive-Breakout Primitives

Chukulia extraction kama mfululizo wa mabadiliko ya filesystem, si kama ukaguzi huru wa majina ya faili. Entry ambayo ni salama inapoparsiwa inaweza kuwa si salama baada ya member wa awali kuunda au kubadilisha link; tatizo hilo hilo hujitokeza extractor inapoweka directory kwenye cache kuwa salama na baadaye kubadilisha aina yake.<sup>[[11]](#references)</sup>

### Link pivots and entry collisions

* **Symlink write-through**: unda `pivot -> /tmp`, kisha extract member wa kawaida kama `pivot/PWNED.txt`. Ikiwa extractor inafuata member wa kwanza wakati wa materialising wa pili, write inatoroka bila `..` kwenye jina la pili.
* **Directory-cache/TOCTOU collision**: toa directory `d/sub/`, badilisha `d/sub` kuwa symlink inayoelekeza `/tmp`, kisha toa `d/sub/PWNED.txt`. Hii inalenga extractors zinazothibitisha au kuweka directory kwenye cache mara moja na hazikague tena kabla ya write ya mwisho.
* **Hardlink read/overwrite**: TAR na RAR zinaweza kuwakilisha hardlinks. Hardlink inayoelekeza faili iliyopo ya host inaweza kufichua yaliyomo ikiwa component ya baadaye itatumia jina lililo-extractiwa; entry ya kawaida inayogongana inaweza badala yake ku-overwrite inode iliyounganishwa. Hii inadhibitiwa na masharti ya same-filesystem na ruhusa za hardlink za OS.
* **Pre-existing or cross-archive pivot**: jaribu tena ukiwa na destination isiyo tupu. Archive moja inaweza kupanda link na extraction ya baadaye ikaandika kupitia hiyo hata kama kila archive imepitisha ukaguzi wa stateless wa header-name.<sup>[[11]](#references)</sup>

### Filesystem-equivalence collisions

Linganisha majina kwa kutumia semantics za filesystem itakayoyapokea. Kesi muhimu za differential zinajumuisha `LINK` dhidi ya `link` kwenye filesystems zisizojali case, tahajia za Unicode za NFC dhidi ya NFD, majina yenye equivalence ya compatibility kama `ﬁle` dhidi ya `file`, members duplicate wanaobadilisha path kutoka directory kuwa symlink, na backslashes zinazotafsiriwa kama separators kwenye Windows pekee. Pia jaribu majina yenye ADS kwenye NTFS. Kesi hizi zinaweza kusababisha validator kuona paths mbili wakati filesystem inatatua path moja.<sup>[[5]](#references)[[11]](#references)</sup>

Kwa hivyo, corpus fupi inapaswa kujaribu mchanganyiko wa mpangilio wa **directory → symlink → child**, **symlink → colliding regular file**, **hardlink → colliding regular file**, mchanganyiko wa `/` na `\`, majina ya absolute/rooted, na wrappers za compression kama `.tar.gz`. Iendeshe tu kwenye VM/container inayoweza kutupwa na ufuatilie destination pamoja na canary path iliyokusudiwa kuwa nje.<sup>[[11]](#references)</sup>

## Real-World Example – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR for Windows pamoja na components zake za Windows RAR/UnRAR zilishindwa kuthibitisha filenames wakati wa extraction. Flaw hiyo ilitumia NTFS alternate data streams (ADS) kupita selected extraction path na kuandika files kwenye locations ambazo hazikukusudiwa.<sup>[[5]](#references)</sup>
Archive hasidi ya RAR iliyo na entry kama:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
ingeishia **nje ya** saraka ya matokeo iliyochaguliwa na ndani ya folda ya *Startup* ya mtumiaji. ESET ilibaini faili hasidi za LNK zikifunguliwa humo na kutekelezwa mtumiaji anapoingia, hivyo kutoa persistence na njia ya RCE.<sup>[[5]](#references)</sup>

### Kutengeneza PoC Archive (Linux/Mac)

Kwa kuwa CVE-2025-8088 hutumia traversal path katika jina la ADS, tumia generator maalum kuunda RAR, kisha jaribu extraction katika lab iliyotengwa pekee, ukiwa na build ya WinRAR iliyo vulnerable.<sup>[[5]](#references)</sup>

### Exploitation Iliyoonekana Inayotokea Hadharani

ESET iliripoti kampeni za spear-phishing za RomCom (Storm-0978/UNC2596) zilizoweka RAR archives zinazoabuse CVE-2025-8088 ili kusambaza backdoors zilizobinafsishwa na kuwezesha ransomware operations.<sup>[[5]](#references)</sup>

## Kesi Mpya Zaidi (2024–2026)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP entries ambazo ni **symbolic links** zilitafutwa wakati wa extraction, hivyo kuwawezesha attackers kutoka kwenye destination directory na ku-overwrite paths kiholela. User interaction ni *kufungua/kuextract* archive tu.<sup>[[1]](#references)</sup>
* **Affected**: 7-Zip builds zilizo kabla ya **25.00**. Hitilafu ya kushughulikia symbolic links ilirekebishwa katika **25.00** (Julai 2025) na matoleo ya baadaye.<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**: Ku-overwrite `Start Menu/Programs/Startup` au maeneo yanayoendeshwa na services → code huendeshwa wakati wa logon inayofuata au service restart.
* **Quick symlink-handling fixture (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Archive hii ina symlink entry inayoelekeza nje ya extraction directory; tumia target inayoweza kufutwa na uthibitishe kuwa extractor haifuati symlink hiyo. Write-through test pia inahitaji regular-file entry iliyo chini ya symlink.

### Go mholt/archiver `Unarchive()` symlink collision (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` inaweza kuextract ZIP symlink na kisha kuifuata wakati member wa kawaida wa baadaye ana jina lilelile, na kubadilisha write inayoonekana kuwa ndani ya root kuwa write iliyo nje ya root.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (project sasa deprecated).<sup>[[2]](#references)</sup>
* **Fix**: Hamia kwenye `mholt/archives` ≥ 0.1.0 au kataa links na u-resolve kila destination upya mara moja kabla ya kuifungua.<sup>[[2]](#references)</sup>
* **Minimal collision generator** (kisha ita `archiver.Unarchive("exploit.zip", "/tmp/safe")`):<sup>[[2]](#references)</sup>
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

Hata `tarfile.extractall(filter="data")` na `filter="tar"` zimewahi kuwa na link-order bypasses. Katika hali hii, hardlink ilirejelea symlink iliyokuwa archived kwenye path ya kina zaidi; fallback extraction ili-validate relative symlink katika eneo hilo la kina lakini ika-create tena kwenye eneo la hardlink lililokuwa fupi, ambapo target ileile ya relative ilitoka nje. Huu ni test ya jumla yenye manufaa: fanya validation na materialisation zitofautiane kuhusu base directory au final member type.<sup>[[12]](#references)</sup>

## Vidokezo vya Detection

* **Static inspection** – Orodhesha member names na link targets zote mbili. Weka alama kwa `../`, `..\\`, absolute/rooted paths, symlinks, hardlinks, special files, duplicate names, type changes, na collisions zinazolingana kwa case/Unicode. Hifadhi entry order wakati wa review kwa sababu exploit inaweza kutegemea members za awali.<sup>[[11]](#references)</sup>
* **Canonicalisation** – Hakikisha parent iliyoresolve pamoja na final basename inabaki chini ya destination iliyoresolve (linganisha path components, si raw string prefix). Fanya re-check baada ya kila member iliyotangulia; test ya mara moja ya `realpath(join(dest, name))` iko vulnerable kwa link replacement na inaweza kushindwa kwa leaf ambayo bado haija-create.<sup>[[3]](#references)[[11]](#references)</sup>
* **Sandbox extraction** – Decompress kwenye directory mpya inayoweza kufutwa, ukitumia extractor yenye path/symlink checks (kwa mfano, secure checks za default za bsdtar au 7-Zip ≥ 25.00), kisha thibitisha kuwa tree inayotokea haina links zinazoelekea nje. Isolation lazima izuie escape iliyokwisha trigger kufikia host paths.<sup>[[1]](#references)[[9]](#references)</sup>
* **Downstream reads matter** – Symlink au hardlink iliyosalia inaweza kuwa primitive ya arbitrary-file-read wakati previewer, CDN, file browser, au package pipeline baadaye inafungua au kuserve jina lililo-extract, hata kama extraction yenyewe haikuunda file nje.<sup>[[11]](#references)</sup>
* **Endpoint monitoring** – Toa alert kwa executables mpya zinazoandikwa kwenye maeneo ya `Startup`/`Run`/`cron` muda mfupi baada ya archive kufunguliwa na WinRAR/7-Zip/etc.

## Mitigation & Hardening

1. **Update the extractor** – WinRAR 7.13+ na 7-Zip 25.00+ zina fixes za path/symlink issues zilizotajwa.<sup>[[1]](#references)[[5]](#references)</sup>
2. Extract archives kwa “**Do not extract paths**” / “**Ignore paths**” inapowezekana. Kwa input isiyoaminika, kataa symbolic links, hardlinks, devices na FIFOs isipokuwa application inazihitaji waziwazi.<sup>[[9]](#references)[[11]](#references)</sup>
3. Extract kwenye **new empty directory**. Usi-merge members zisizoaminika kwenye tree iliyo na paths ambazo attacker anaweza kubadilisha, na usitumie tena directory iliyopandwa na archive ya awali.<sup>[[11]](#references)</sup>
4. Kwenye Unix, shusha privileges na tenga destination ndani ya **chroot/mount namespace**; kwenye Windows, tumia **AppContainer** au sandbox. Post-extraction scan pekee haitoshi kwa sababu write iliyotoroka hutokea kabla ya scan.<sup>[[11]](#references)</sup>
5. Kwenye custom code, tumia separator/case/Unicode rules za target OS na u-validate member pamoja na link target. Resolve na fungua destination bila kufuata links; usitenganishe containment check na create/replace operation ya baadaye. Validator lazima itumie base ileile na link-emulation semantics zilezile zinazotumiwa na write path.<sup>[[11]](#references)[[12]](#references)</sup>

## Additional Affected / Historical Cases

* 2018 – Advisory kubwa ya *Zip-Slip* kutoka Snyk iliyoathiri Java/Go/JS libraries nyingi.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal katika slugs (ilirekebishwa kwenye v0.16.3).<sup>[[7]](#references)</sup>
* Custom extraction logic yoyote inayofanya validation ya header strings lakini si link targets na final filesystem path inayotumiwa kwa kila write.<sup>[[11]](#references)[[12]](#references)</sup>



## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Zuia Zip Slip katika .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Sasisha zana za WinRAR sasa: RomCom na wengine wakitumia zero-day vulnerability (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Ufichuaji wa Umma wa Critical Arbitrary File Overwrite Vulnerability: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug Iko Vulnerable kwa Zip Slip Attack (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine Method](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar secure extraction flags](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Proof-of-Concept Exploit Imeripotiwa kwa CVE-2025-11001 katika 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – Furaha ya hacking na zip-slips, tar-slips, symlinks, hardlinks, collisions, na zaidi](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – CVE-2026-11940 tarfile extraction filter bypass](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
{{#include ../banners/hacktricks-training.md}}
