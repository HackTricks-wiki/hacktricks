# Archive Extraction Path Traversal ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## Muhtasari

Miundo mingi ya archive (ZIP, RAR, TAR, 7-ZIP, n.k.) huruhusu kila entry kubeba **internal path** yake. Utility ya extraction inapofuata path hiyo bila kuichunguza, filename iliyotengenezwa ikiwa na `..` au **absolute path** (kwa mfano `C:\Windows\System32\`) itaandikwa nje ya directory iliyochaguliwa na mtumiaji.
Aina hii ya vulnerability inajulikana sana kama *Zip-Slip* au **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Madhara yanaweza kuanzia overwriting ya files kiholela hadi kufanikisha moja kwa moja **remote code execution (RCE)** kwa kuweka payload kwenye eneo la **auto-run** kama vile folder ya Windows *Startup*.

## Chanzo Kikuu

1. Attacker huunda archive ambapo file headers moja au zaidi zina:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Au **symlinks** zilizotengenezwa ambazo huelekezwa nje ya target dir (jambo la kawaida katika ZIP/TAR kwenye *nix*).
2. Victim hu-extract archive kwa kutumia tool iliyo vulnerable ambayo huamini path iliyo-embed (au hufuata symlinks) badala ya kuisanitize au kulazimisha extraction ifanyike chini ya directory iliyochaguliwa.
3. File huandikwa katika location inayodhibitiwa na attacker na ku-executiwa/loaded wakati mwingine mfumo au mtumiaji anapo-trigger path hiyo.

### .NET `Path.Combine` + `ZipArchive` traversal

Anti-pattern ya kawaida ya .NET ni kuunganisha destination iliyokusudiwa na `ZipArchiveEntry.FullName` inayodhibitiwa na mtumiaji na kufanya extraction bila path normalisation:<sup>[[4]](#references)[[8]](#references)</sup>
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
- Ikiwa `entry.FullName` inaanza na `..\\`, inapita; ikiwa ni **absolute path**, component ya upande wa kushoto hutupwa kabisa, na hivyo kutoa **arbitrary file write** kama utambulisho wa extraction.
- Archive ya proof-of-concept ya kuandika kwenye directory ya `app` iliyo jirani, inayofuatiliwa na scanner iliyoratibiwa:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Kuweka ZIP hiyo kwenye inbox inayofuatiliwa husababisha `C:\samples\app\0xdf.txt`, kuthibitisha traversal nje ya `C:\samples\queue\` na kuwezesha primitives za ufuatiliaji (kwa mfano, DLL hijacks).

## Advanced Archive-Breakout Primitives

Chukulia extraction kama mfululizo wa mabadiliko ya filesystem, si kama ukaguzi huru wa majina ya faili. Entry ambayo ni salama inapochanganuliwa inaweza kuwa si salama baada ya member wa awali kuunda au kubadilisha link; tatizo hilo hilo huonekana extractor inapoweka directory kwenye cache kuwa salama na baadaye kubadilisha aina yake.<sup>[[11]](#references)</sup>

### Link pivots and entry collisions

* **Symlink write-through**: unda `pivot -> /tmp`, kisha extract member ya kawaida kama `pivot/PWNED.txt`. Ikiwa extractor inafuata member ya kwanza wakati inamaterialise ya pili, write itatoka nje bila `..` kwenye jina la pili.
* **Directory-cache/TOCTOU collision**: toa directory `d/sub/`, badilisha `d/sub` iwe symlink inayoelekeza `/tmp`, kisha toa `d/sub/PWNED.txt`. Hii inalenga extractors zinazovalidate au kuweka directory kwenye cache mara moja na hazifanyi ukaguzi tena kabla ya write ya mwisho.
* **Hardlink read/overwrite**: TAR na RAR zinaweza kuwakilisha hardlinks. Hardlink inayoelekeza kwenye host file iliyopo inaweza kufichua contents zake ikiwa component ya baadaye itahudumia jina lililo-extractiwa; entry ya kawaida inayogongana inaweza badala yake ku-overwrite inode iliyounganishwa. Hii inadhibitiwa na sheria za same-filesystem na ruhusa za OS za hardlink.
* **Pre-existing or cross-archive pivot**: jaribu tena kwa destination isiyo tupu. Archive moja inaweza kupanda link na extraction ya baadaye ikaandika kupitia hiyo hata ikiwa kila archive imepita ukaguzi wa stateless wa header-name.<sup>[[11]](#references)</sup>

### Filesystem-equivalence collisions

Linganisha majina kwa kutumia semantics za filesystem itakayoyapokea. Mifano muhimu ya differential ni `LINK` dhidi ya `link` kwenye filesystems zisizo na case-sensitivity, tahajia za Unicode za NFC dhidi ya NFD, majina yaliyo sawa kwa compatibility kama `ﬁle` dhidi ya `file`, members zilizojirudia zinazobadilisha path kutoka directory kuwa symlink, na backslashes zinazotafsiriwa kama separators kwenye Windows pekee. Pia jaribu majina yenye ADS kwenye NTFS. Hali hizi zinaweza kufanya validator ione paths mbili huku filesystem ikitatua moja.<sup>[[5]](#references)[[11]](#references)</sup>

Kwa hiyo corpus fupi inapaswa kujaribu mchanganyiko ulio na mpangilio wa **directory → symlink → child**, **symlink → colliding regular file**, **hardlink → colliding regular file**, mchanganyiko wa `/` na `\`, majina ya absolute/rooted, na wrappers zilizobanwa kama `.tar.gz`. Iendeshe tu kwenye VM/container inayoweza kutupwa na ufuatilie destination pamoja na canary path iliyokusudiwa kuwa nje.<sup>[[11]](#references)</sup>

Utata wa kimuundo mahususi wa ZIP unaweza kufanya pre-scan na extractor halisi zione entry names au trees tofauti. Angalia [Local-header vs central-directory parser confusion](../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md#local-header-vs-central-directory-parser-confusion) badala ya kuamini output ya ZIP library moja pekee.

## Real-World Example – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR ya Windows na components zake za Windows RAR/UnRAR zilishindwa ku-validate filenames wakati wa extraction. Flaw hii ilitumia NTFS alternate data streams (ADS) kupita njia iliyochaguliwa ya extraction na kuandika files kwenye locations zisizokusudiwa.<sup>[[5]](#references)</sup>
RAR archive hasidi iliyokuwa na entry kama:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
ingeishia **nje** ya saraka iliyochaguliwa ya matokeo na ndani ya folda ya *Startup* ya mtumiaji. ESET iliona faili hasidi za LNK zikifunguliwa humo na kutekelezwa mtumiaji anapoingia, hivyo kutoa persistence na njia ya RCE.<sup>[[5]](#references)</sup>

### Kuunda PoC Archive (Linux/Mac)

Kwa sababu CVE-2025-8088 hutumia path ya traversal katika jina la ADS, tumia generator iliyoundwa mahsusi kuunda RAR, kisha fanya extraction katika lab iliyotengwa pekee, ukitumia build ya WinRAR iliyo vulnerable.<sup>[[5]](#references)</sup>

### Exploitation Iliyoonekana Hadharani

ESET iliripoti kampeni za spear-phishing za RomCom (Storm-0978/UNC2596) zilizoweka RAR archives zinazotumia vibaya CVE-2025-8088 ili kusambaza backdoors zilizobinafsishwa na kuwezesha shughuli za ransomware.<sup>[[5]](#references)</sup>

## Kesi Mpya (2024–2026)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP entries ambazo ni **symbolic links** zilifuatwa wakati wa extraction, hivyo kuwawezesha attackers kutoka kwenye destination directory na kuandika paths za kiholela. User interaction ni *kufungua/kufanya extraction* ya archive tu.<sup>[[1]](#references)</sup>
* **Affected**: 7-Zip builds za kabla ya **25.00**. Kasoro ya kushughulikia symbolic links ilirekebishwa katika **25.00** (Julai 2025) na matoleo ya baadaye.<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**: Andika juu ya `Start Menu/Programs/Startup` au maeneo yanayoendeshwa na service → code inaendeshwa mtumiaji anapoingia tena au service inapowashwa upya.
* **Fixture ya haraka ya kushughulikia symlink (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Archive hii ina symlink entry inayoelekeza nje ya extraction directory; tumia target inayoweza kutupwa na uthibitishe kuwa extractor haifuati symlink hiyo. Test ya write-through pia inahitaji regular-file entry iliyo chini ya symlink.

### Go mholt/archiver `Unarchive()` symlink collision (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` inaweza kufanya extraction ya ZIP symlink na kisha kuifuata wakati member ya kawaida ya baadaye ina jina lilelile, na kubadilisha write inayoonekana kuwa ndani ya root kuwa write iliyo nje ya root.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (project sasa ime-deprecated).<sup>[[2]](#references)</sup>
* **Fix**: Hamia kwenye `mholt/archives` ≥ 0.1.0 au kataa links na u-resolve tena kila destination mara moja kabla ya kuifungua.<sup>[[2]](#references)</sup>
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

Hata `tarfile.extractall(filter="data")` na `filter="tar"` zimewahi kuwa na bypasses za link-order. Katika hali hii, hardlink ilirejelea symlink iliyokuwa archived kwenye path ya ndani zaidi; fallback extraction ilivalidate relative symlink katika eneo hilo la ndani, lakini ika-create tena katika eneo la hardlink lililokuwa karibu zaidi, ambapo target ileile ya relative ilitoka nje. Hii ni test ya jumla yenye manufaa: fanya validation na materialisation zitofautiane kuhusu base directory au aina ya mwisho ya member.<sup>[[12]](#references)</sup>

### Node `tar` hardlink target escape kupitia symlink chain (GHSA-83g3-92jg-28cx)

Package ya Node.js `tar` ilikubali hardlink ambayo target yake ilionekana kuwa ndani kwa kuangalia lexical, lakini ika-resolve kuwa nje ya extraction root kupitia symlinks mbili za awali. Attack hii hufanya kazi kwa default extraction options: checks za destination-parent zilifunika jina la hardlink lililokuwa ndani ya root, huku hardlink target ikipitishwa kwenye filesystem bila ku-resolve chain nzima ili kuthibitisha containment. `tar` ≤ 7.5.7 imeathirika; 7.5.8 inarekebisha tatizo hilo.<sup>[[13]](#references)</sup>

Fixture muhimu ya test ni **uhusiano wa mpangilio** kati ya members, si majina haya halisi:<sup>[[13]](#references)</sup>
```text
a/b/c/up     -> ../..                          (symlink)
a/b/escape   -> c/up/../..                     (symlink)
exfil        => a/b/escape/<path-from-parent>  (hardlink)
```
Ikiwa extraction itafaulu, `exfil` itaendelea kuonekana ndani ya mti wa output lakini itashiriki inode na faili iliyochaguliwa iliyo nje; kuisoma kunaleak faili hilo, na kuiandikia kunarekebisha faili la awali. Bypass hii inaonyesha kwa nini kuangalia tu pathname ya mwisho, kuondoa absolute prefixes, au kuzuia `..` kwenye hardlink header hakutoshi: validate link targets baada ya kutumia hali yote ya filesystem iliyotokana na entries zilizotolewa awali.<sup>[[13]](#references)</sup>

## Detection Tips

* **Static inspection** – Orodhesha member names na link targets zote. Weka alama kwa `../`, `..\\`, absolute/rooted paths, symlinks, hardlinks, special files, duplicate names, mabadiliko ya type, na collisions zinazolingana kwa case/Unicode. Hifadhi mpangilio wa entries wakati wa review kwa sababu exploit inaweza kutegemea members zilizotangulia.<sup>[[11]](#references)</sup>

```bash
bsdtar -tvf suspect.tar       # ordered TAR members, types and link targets
7z l -slt suspect.7z          # technical metadata, one field per line
zipinfo -v suspect.zip        # ZIP central-directory metadata and offsets
```

* **Canonicalisation** – Hakikisha parent iliyoresolve pamoja na final basename inabaki chini ya destination iliyoresolve (linganisha path components, si raw string prefix). Fanya ukaguzi tena baada ya kila member iliyotangulia; test ya mara moja ya `realpath(join(dest, name))` iko hatarini kwa link replacement na inaweza kushindwa kwa leaf ambayo bado haijaundwa.<sup>[[3]](#references)[[11]](#references)</sup>
* **Sandbox extraction** – Decompress kwenye directory mpya inayoweza kutupwa, ukitumia extractor yenye path/symlink checks (kwa mfano, secure checks za default za bsdtar au 7-Zip ≥ 25.00), kisha thibitisha kuwa mti unaotokana hauna outward links. Isolation lazima izuie escape ambayo tayari imeshaanzishwa kufikia host paths.<sup>[[1]](#references)[[9]](#references)</sup>
* **Downstream reads matter** – Symlink au hardlink inayosalia inaweza kuwa arbitrary-file-read primitive wakati previewer, CDN, file browser, au package pipeline baadaye inapofungua au kuhudumia extracted name, hata ikiwa extraction yenyewe haikuunda faili lolote nje.<sup>[[11]](#references)</sup>
* **Endpoint monitoring** – Toa alert kuhusu executables mpya zilizoandikwa kwenye locations za `Startup`/`Run`/`cron` muda mfupi baada ya archive kufunguliwa na WinRAR/7-Zip/etc.

## Mitigation & Hardening

1. **Update the extractor** – WinRAR 7.13+, 7-Zip 25.00+, na Node `tar` 7.5.8+ zina fixes za masuala yaliyotajwa ya path/symlink/link-target.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>
2. Extract archives kwa “**Do not extract paths**” / “**Ignore paths**” inapowezekana. Kwa input isiyoaminika, kataa symbolic links, hardlinks, devices na FIFOs isipokuwa application ihitaji hizo waziwazi.<sup>[[9]](#references)[[11]](#references)</sup>
3. Extract kwenye **new empty directory**. Usiunganishe members zisizoaminika kwenye tree yenye paths zinazoweza kubadilishwa na attacker, na usitumie tena directory iliyopandwa na archive ya awali.<sup>[[11]](#references)</sup>
4. Kwenye Unix, ondoa privileges na tenga destination ndani ya **chroot/mount namespace**; kwenye Windows, tumia **AppContainer** au sandbox. Post-extraction scan pekee haitoshi kwa sababu escaped write hutokea kabla ya scan.<sup>[[11]](#references)</sup>
5. Katika custom code, tumia separator/case/Unicode rules za target OS na validate member pamoja na link target. Resolve na open destination bila kufuata links; usitenganishe containment check na create/replace operation ya baadaye. Validator lazima itumie base ileile na link-emulation semantics zilezile zinazotumiwa na write path.<sup>[[11]](#references)[[12]](#references)</sup>

## Additional Affected / Historical Cases

* 2018 – Ushauri mkubwa wa *Zip-Slip* kutoka Snyk ulioathiri Java/Go/JS libraries nyingi.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal kwenye slugs (ilirekebishwa katika v0.16.3).<sup>[[7]](#references)</sup>
* Logic yoyote ya custom extraction inayovalidate header strings lakini si link targets na final filesystem path inayotumiwa kwa kila write.<sup>[[11]](#references)[[12]](#references)</sup>





## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Zuia Zip Slip katika .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Sasisha zana za WinRAR sasa: RomCom na wengine wakitumia zero-day vulnerability (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Ufichuzi wa Umma wa Critical Arbitrary File Overwrite Vulnerability: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug Iko Hatarini kwa Zip Slip Attack (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine Method](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar secure extraction flags](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Proof-of-Concept Exploit Reported for CVE-2025-11001 in 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – Burudani ya hacking na zip-slips, tar-slips, symlinks, hardlinks, collisions, na zaidi](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – CVE-2026-11940 tarfile extraction filter bypass](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
- [13] [GitHub Security Advisory – node-tar hardlink target escape through symlink chain](https://github.com/isaacs/node-tar/security/advisories/GHSA-83g3-92jg-28cx)
{{#include ../banners/hacktricks-training.md}}
