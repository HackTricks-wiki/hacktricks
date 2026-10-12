# Upitiaji wa Njia Wakati wa Kutoa Archive ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## Muhtasari

Miundo mingi ya archive (ZIP, RAR, TAR, 7-ZIP, n.k.) huruhusu kila ingizo kuwa na **njia ya ndani** yake. Zana ya kutoa archive inapofuata njia hiyo bila kuikagua, jina la faili lililoundwa kwa `..` au **njia kamili** (kwa mfano, `C:\Windows\System32\`) litaandikwa nje ya saraka iliyochaguliwa na mtumiaji.  
Aina hii ya udhaifu inajulikana sana kama *Zip-Slip* au **upitiaji wa njia wakati wa kutoa archive**.<sup>[[6]](#references)</sup>

Madhara yake yanaweza kuwa kuanzia kubadilisha faili zozote hadi kufanikisha moja kwa moja **utekelezaji wa msimbo wa mbali (RCE)** kwa kuweka payload katika eneo la **kujiendesha kiotomatiki**, kama vile folda ya *Startup* ya Windows.

## Chanzo Kikuu

1. Mshambuliaji hutengeneza archive ambamo kichwa cha faili kimoja au zaidi kina:
   * Mfuatano wa kupitia saraka za juu (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
   * Njia kamili (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
   * Au **symlinks** zilizoundwa mahsusi zinazoelekeza nje ya saraka lengwa (jambo la kawaida katika ZIP/TAR kwenye *nix*). 
2. Mhasiriwa hutoa archive kwa kutumia zana yenye udhaifu inayoamini njia iliyopachikwa (au kufuata symlinks) badala ya kuisafisha au kulazimisha utoaji kufanyika ndani ya saraka iliyochaguliwa.
3. Faili huandikwa katika eneo linalodhibitiwa na mshambuliaji, kisha hutekelezwa/kupakiwa wakati mwingine mfumo au mtumiaji anapowasha njia hiyo.

### Upitaji wa njia kupitia `Path.Combine` + `ZipArchive` katika .NET

Mojawapo ya mifumo mibaya inayotumika sana katika .NET ni kuchanganya eneo lengwa lililokusudiwa na `ZipArchiveEntry.FullName` inayodhibitiwa na **mtumiaji**, kisha kutoa faili bila kurekebisha njia:<sup>[[4]](#references)[[8]](#references)</sup>

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

- Ikiwa `entry.FullName` inaanza na `..\\`, huvuka njia; ikiwa ni **absolute path**, sehemu ya upande wa kushoto huondolewa kabisa, na hivyo kusababisha **arbitrary file write** kama kitambulisho cha uchimbaji.
- Archive ya **proof-of-concept** ya kuandika kwenye directory ya `app` iliyo jirani, inayofuatiliwa na scanner iliyoratibiwa:

```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
    z.writestr("../app/0xdf.txt", "ABCD")
```

Kuweka ZIP hiyo kwenye kikasha pokezi kinachofuatiliwa husababisha `C:\samples\app\0xdf.txt` kuundwa, jambo linalothibitisha path traversal nje ya `C:\samples\queue\` na kuwezesha primitives za hatua zinazofuata (kwa mfano, DLL hijacks).

### Root ya uchimbaji inayodhibitiwa na mtumiaji

Pia jaribu **directory inayopitishwa kwa extractor**, si majina ya washiriki wa archive pekee. Programu inaweza kupata directory hiyo kutoka kwa kichwa, jina la project au sehemu nyingine ya ombi. Thamani kama `../../../../app/module` inaweza kuhamisha root ya uchimbaji nje ya eneo la upakiaji kabla extractor haijachakata washiriki wowote. Katika hali hiyo, hata archive iliyo na basename salama pekee, `api.py`, inaweza kubatilisha code ya programu.<sup>[[14]](#references)[[15]](#references)</sup>

```python
# Vulnerable pattern: the ZIP entries themselves need no ../ components.
extract_root = os.path.join(site_root, "public", "files", user_title)
archive.extractall(extract_root)
```

Huu ni mpaka tofauti wa containment na classic Zip-Slip. Thibitisha extraction root iliyotatuliwa na kila member path iliyotatuliwa. Ukaguzi wa root unaweza kutumia vipengele vya path badala ya kiambishi awali cha string:<sup>[[14]](#references)</sup>

```python
base = Path(site_root, "public", "files").resolve()
dest = (base / user_title).resolve()
if not dest.is_relative_to(base):
    raise ValueError("extraction root escapes its base")
```

Kwa jaribio salama, pakia archive halali iliyo na faili moja ya canary na uweke mfuatano wa traversal katika kila sehemu inayoweza kuchagua saraka ya kutoa faili. Fuatilia saraka iliyokusudiwa na njia ya nje inayoweza kutupwa. Ikiwa lengwa linaweza kufikia moduli iliyoingizwa, kuandika juu yake kunaweza kusababisha code execution wafanyakazi wanapopakia upya; HTTP 500 au muunganisho kukatika wakati wa upakiaji huo upya hakuthibitishi kuwa uandishi haukufanikiwa.<sup>[[14]](#references)[[15]](#references)</sup> Tazama pia [mbinu pana ya kupakia faili](../pentesting-web/file-upload/).

## Mbinu za Kina za Kuvunja Mipaka ya Archive

Chukulia uchimbuaji kama mfuatano wa mabadiliko kwenye mfumo wa faili, wala si ukaguzi huru wa majina ya faili. Kipengee ambacho ni salama kinapochanganuliwa kinaweza kuwa si salama baada ya mwanachama wa awali kuunda au kubadilisha link; tatizo hilo hilo hutokea wakati extractor inapohifadhi saraka kama salama kisha baadaye kubadilisha aina yake.<sup>[[11]](#references)</sup>

### Link pivots na migongano ya vipengee

* **Uandishi kupitia Symlink**: unda `pivot -> /tmp`, kisha uchimbue mwanachama wa kawaida kama `pivot/PWNED.txt`. Ikiwa extractor itafuata mwanachama wa kwanza inapounda wa pili, uandishi utatoka nje bila `..` kwenye jina la pili.
* **Mgongano wa directory-cache/TOCTOU**: toa saraka `d/sub/`, badilisha `d/sub` iwe symlink inayoelekeza `/tmp`, kisha toa `d/sub/PWNED.txt`. Hii inalenga extractors zinazothibitisha au kuhifadhi saraka mara moja bila kuiangalia tena kabla ya uandishi wa mwisho.
* **Kusoma/kuandika juu ya Hardlink**: TAR na RAR zinaweza kuwakilisha hardlink. Hardlink inayoelekeza faili iliyopo kwenye host inaweza kufichua yaliyomo ikiwa kipengee cha baadaye kitatoa jina lililochimbuliwa; kipengee cha kawaida kinachogongana nacho kinaweza badala yake kuandika juu ya inode iliyounganishwa. Hili huzuiwa na masharti ya mfumo huo huo wa faili na ruhusa za hardlink za OS.
* **Pivot iliyokuwepo awali au ya archive nyingine**: jaribu tena kwa kutumia lengwa lisilo tupu. Archive moja inaweza kuweka link na uchimbuaji wa baadaye ukaandika kupitia link hiyo, hata kama kila archive inapita ukaguzi wa jina la header usiohifadhi hali.<sup>[[11]](#references)</sup>

### Migongano ya usawa wa mfumo wa faili

Linganisha majina kwa kutumia kanuni za mfumo wa faili utakaoyapokea. Kesi muhimu za tofauti ni pamoja na `LINK` dhidi ya `link` kwenye mifumo ya faili isiyotofautisha herufi kubwa na ndogo, tahajia za Unicode za NFC dhidi ya NFD, majina yanayolingana kwa uoanifu kama `ﬁle` dhidi ya `file`, wanachama rudufu wanaobadilisha njia kutoka saraka kuwa symlink, na backslash zinazotafsiriwa kama vitenganishi kwenye Windows pekee. Pia jaribu majina yenye ADS kwenye NTFS. Kesi hizi zinaweza kufanya validator ione njia mbili huku mfumo wa faili ukitatua moja.<sup>[[5]](#references)[[11]](#references)</sup>

Kwa hiyo, mkusanyiko mfupi wa majaribio unapaswa kupima michanganyiko ya mpangilio ya **directory → symlink → child**, **symlink → faili ya kawaida inayogongana**, **hardlink → faili ya kawaida inayogongana**, `/` na `\` zilizochanganywa, majina kamili yanayoanzia kwenye root, na wrappers zilizobanwa kama `.tar.gz`. Iendeshe tu kwenye VM/container inayoweza kutupwa na uangalie lengwa pamoja na njia ya nje ya canary iliyokusudiwa.<sup>[[11]](#references)</sup>

Utata wa kimuundo unaohusu ZIP pekee unaweza kufanya uchanganuzi wa awali na extractor halisi zione majina au miti tofauti ya vipengee. Tazama [mkanganyiko wa parser kati ya local header na central directory](../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md#local-header-vs-central-directory-parser-confusion) badala ya kutegemea matokeo ya maktaba moja tu ya ZIP.

## Mfano Halisi – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR ya Windows na vipengele vyake vya Windows RAR/UnRAR vilishindwa kuthibitisha majina ya faili wakati wa uchimbuaji. Kasoro hiyo ilitumia NTFS alternate data streams (ADS) kukwepa njia iliyochaguliwa ya uchimbuaji na kuandika faili kwenye maeneo yasiyokusudiwa.<sup>[[5]](#references)</sup>
Archive hasidi ya RAR yenye kipengee kama hiki:

```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```

ingeishia **nje** ya saraka teule ya matokeo na ndani ya folda ya *Startup* ya mtumiaji. ESET iliona faili hasidi za LNK zikifunguliwa humo na kutekelezwa mtumiaji anapoingia, hivyo kutoa persistence na njia ya kupata RCE.<sup>[[5]](#references)</sup>

### Kutengeneza Kumbukumbu ya PoC (Linux/Mac)

Kwa kuwa CVE-2025-8088 hutumia path traversal katika jina la ADS, tumia generator iliyoundwa mahsusi kuunda RAR, kisha ujaribu uondoaji wake kwenye maabara iliyotengwa pekee ukitumia build ya WinRAR iliyo hatarini.<sup>[[5]](#references)</sup>

### Matumizi Yaliyoonekana Hadharani

ESET iliripoti kampeni za spear-phishing za RomCom (Storm-0978/UNC2596) zilizokuwa na kumbukumbu za RAR zinazotumia CVE-2025-8088 vibaya ili kusambaza backdoors zilizobinafsishwa na kuwezesha shughuli za ransomware.<sup>[[5]](#references)</sup>

## Kesi Mpya Zaidi (2024–2026)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Hitilafu**: Maingizo ya ZIP yaliyo **symbolic links** yalifuatwa wakati wa uondoaji, na kuwawezesha washambuliaji kutoka kwenye saraka lengwa na kubadilisha njia zozote. Mwingiliano wa mtumiaji ni *kufungua/kutoa* yaliyomo kwenye kumbukumbu tu.<sup>[[1]](#references)</sup>
* **Zilizoathiriwa**: Build za 7-Zip za kabla ya **25.00**. Hitilafu ya uchakataji wa symbolic link ilirekebishwa katika **25.00** (Julai 2025) na matoleo ya baadaye.<sup>[[1]](#references)[[10]](#references)</sup>
* **Njia ya athari**: Badilisha `Start Menu/Programs/Startup` au maeneo yanayoendeshwa na service → code hutekelezwa mtumiaji anapoingia tena au service inapowashwa upya.
* **Mfano wa haraka wa kushughulikia symlink (Linux)**:
  ```bash
  mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
  ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
  cd /tmp/archive-slip-test
  zip -y exploit.zip evil   # -y preserves symlinks
  7z x exploit.zip -o/tmp/archive-slip-target
  ```
  Archive hii ina ingizo la symlink linaloelekeza nje ya saraka ya uchimbuaji; tumia lengwa linaloweza kutupwa na uhakikishe kuwa kichimbuaji hakilifuati. Jaribio la write-through pia linahitaji ingizo la faili ya kawaida chini ya symlink.

### Go mholt/archiver mgongano wa symlink katika `Unarchive()` (CVE-2025-3445)
* **Hitilafu**: `archiver.Unarchive()` inaweza kuchimbua symlink ya ZIP kisha kuifuata wakati ingizo la kawaida linalofuata lina jina sawa, na hivyo kubadilisha uandishi unaoonekana kuwa ndani ya mzizi kuwa uandishi nje ya mzizi.<sup>[[2]](#references)</sup>
* **Zinazoathirika**: `github.com/mholt/archiver` ≤ 3.5.1 (mradi sasa umekatishwa).<sup>[[2]](#references)</sup>
* **Suluhisho**: Hamia kwenye `mholt/archives` ≥ 0.1.0 au kataa links na utatue upya kila lengwa mara moja kabla ya kulifungua.<sup>[[2]](#references)</sup>
* **Kijenzi kidogo cha mgongano** (kisha ita `archiver.Unarchive("exploit.zip", "/tmp/safe")`):<sup>[[2]](#references)</sup>
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

Hata `tarfile.extractall(filter="data")` na `filter="tar"` zimekuwa na bypass za mpangilio wa link. Katika hali hii, hardlink ilirejelea symlink iliyohifadhiwa kwenye njia ya ndani zaidi; fallback extraction ilithibitisha symlink ya relative kwenye eneo hilo la ndani zaidi lakini ikaizalisha upya kwenye eneo lisilo la ndani sana la hardlink, ambapo target ileile ya relative ilitoroka. Huu ni mtihani wa jumla wenye manufaa: hakikisha uthibitishaji na uwekaji halisi havitofautiani kuhusu saraka msingi au aina ya mwisho ya member.<sup>[[12]](#references)</sup>

### Node `tar` hardlink target kutoroka kupitia mnyororo wa symlink (GHSA-83g3-92jg-28cx)

Kifurushi cha Node.js `tar` cha `tar.extract()` kilikubali hardlink ambayo target yake ilionekana kuwa ndani kwa kuangalia maandishi, lakini ilisuluhishwa na kutoroka nje ya root ya extraction kupitia symlink mbili za awali. Shambulio hili hufanya kazi kwa chaguo-msingi za extraction: ukaguzi wa parent wa destination ulihusisha jina la hardlink lililo ndani ya root, lakini target ya hardlink ilipitishwa kwa filesystem bila kusuluhisha mnyororo mzima ili kuthibitisha kuwa iko ndani. `tar` ≤ 7.5.7 imeathirika; toleo la 7.5.8 limerekebisha tatizo hilo.<sup>[[13]](#references)</sup>

Kipengele muhimu cha test fixture ni **uhusiano wa mpangilio** kati ya members, si majina haya halisi:<sup>[[13]](#references)</sup>

```text
a/b/c/up     -> ../..                          (symlink)
a/b/escape   -> c/up/../..                     (symlink)
exfil        => a/b/escape/<path-from-parent>  (hardlink)
```

Ikiwa ufunguaji wa archive utafaulu, `exfil` itaendelea kuonekana ndani ya mti wa matokeo lakini itashiriki inode na faili ya nje iliyochaguliwa; kuisoma kutavuja faili hiyo na kuiandikia kutarekebisha faili asili. Njia hii ya kukwepa inaonyesha kwa nini kukagua tu pathname ya mwisho, kuondoa viambishi awali vya absolute, au kuzuia `..` kwenye hardlink header hakutoshi: thibitisha malengo ya link baada ya kutumia hali yote ya mfumo wa faili iliyoundwa na faili zilizotolewa awali.<sup>[[13]](#references)</sup>

## Vidokezo vya Utambuzi

* **Ukaguzi tuli** – Orodhesha majina ya wanachama na malengo ya link. Weka alama kwenye `../`, `..\\`, njia za absolute/rooted, symlinks, hardlinks, faili maalum, majina yanayojirudia, mabadiliko ya aina, na migongano ya majina yanayolingana kwa herufi kubwa/ndogo au Unicode. Hifadhi mpangilio wa maingizo wakati wa ukaguzi kwa sababu exploit inaweza kutegemea maingizo yaliyotangulia.<sup>[[11]](#references)</sup>

  ```bash
  bsdtar -tvf suspect.tar       # ordered TAR members, types and link targets
  7z l -slt suspect.7z          # technical metadata, one field per line
  zipinfo -v suspect.zip        # ZIP central-directory metadata and offsets
  ```

* **Canonicalisation** – Hakikisha kuwa parent iliyosuluhishwa pamoja na basename ya mwisho inabaki ndani ya destination iliyosuluhishwa (linganisha vipengele vya path, si prefix ghafi ya string). Kagua tena baada ya kila member inayotangulia; jaribio la mara moja la `realpath(join(dest, name))` linaweza kushambuliwa kwa kubadilisha link, na huenda likashindwa ikiwa leaf bado haijaundwa.<sup>[[3]](#references)[[11]](#references)</sup>
* **Sandbox extraction** – Decompress kwenye directory mpya inayoweza kutupwa, ukitumia extractor yenye ukaguzi wa path/symlink (kwa mfano, ukaguzi salama wa kawaida wa bsdtar au 7-Zip ≥ 25.00), kisha thibitisha kuwa tree iliyotokana haina link zinazoelekea nje. Isolation lazima izuie escape ambayo tayari imeanzishwa kufikia path za host.<sup>[[1]](#references)[[9]](#references)</sup>
* **Usomaji wa hatua zinazofuata ni muhimu** – Symlink au hardlink inayosalia inaweza kuwa primitive ya kusoma faili yoyote wakati previewer, CDN, file browser, au package pipeline baadaye inapofungua au kuhudumia jina lililotolewa, hata kama extraction yenyewe haikuunda faili yoyote nje ya directory.<sup>[[11]](#references)</sup>
* **Ufuatiliaji wa endpoint** – Toa tahadhari kuhusu executable mpya zilizoandikwa kwenye maeneo ya `Startup`/`Run`/`cron` muda mfupi baada ya archive kufunguliwa na WinRAR/7-Zip/n.k.

## Mitigation & Hardening

1. **Sasisha extractor** – WinRAR 7.13+, 7-Zip 25.00+, na Node `tar` 7.5.8+ zina marekebisho ya masuala yaliyotajwa ya path/symlink/link-target.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>
2. Extract archives kwa kutumia “**Do not extract paths**” / “**Ignore paths**” inapowezekana. Kwa input isiyoaminika, kataa symbolic links, hardlinks, devices na FIFOs isipokuwa programu inavihitaji waziwazi.<sup>[[9]](#references)[[11]](#references)</sup>
3. Extract kwenye **directory mpya tupu**. Usiunganishe members zisizoaminika kwenye tree yenye path ambazo mshambuliaji anaweza kubadilisha, wala kutumia tena directory iliyopandwa na archive ya awali.<sup>[[11]](#references)</sup>
4. Kwenye Unix, punguza privileges na tenga destination ndani ya **chroot/mount namespace**; kwenye Windows, tumia **AppContainer** au sandbox. Ukaguzi wa baada ya extraction pekee hautoshi, kwa sababu uandishi uliotoroka hutokea kabla ya ukaguzi.<sup>[[11]](#references)</sup>
5. Katika code maalum, tumia kanuni za OS lengwa za separator/case/Unicode na uthibitishe member pamoja na link target. Suluhisha na ufungue destination bila kufuata links; usitenganishe ukaguzi wa containment na operesheni ya baadaye ya create/replace. Validator lazima itumie base na semantics zilezile za uigaji wa link kama write path.<sup>[[11]](#references)[[12]](#references)</sup>

## Additional Affected / Historical Cases

* 2018 – Ushauri mkubwa wa *Zip-Slip* kutoka Snyk ulioathiri libraries nyingi za Java/Go/JS.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377): path traversal wakati wa TAR extraction kwenye slugs (ilisahihishwa katika v0.16.3).<sup>[[7]](#references)</sup>
* Logic yoyote maalum ya extraction inayothibitisha header strings lakini si link targets na filesystem path ya mwisho inayotumiwa kwa kila write.<sup>[[11]](#references)[[12]](#references)</sup>





## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip: path traversal kupitia symlink kwenye ZIP (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [Utafiti wa JFrog – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Kuzuia Zip Slip katika .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – Msururu wa HTB Bruno ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Utafiti wa ESET – Sasisha zana za WinRAR sasa: RomCom na wengine wanatumia udhaifu wa zero-day (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Ufichuzi wa Umma wa Udhaifu Muhimu wa Kubadilisha Faili Yoyote: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug Ina Udhaifu wa Zip Slip Attack (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Mbinu ya Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – Bendera za bsdtar za extraction salama](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Exploit ya Proof-of-Concept Imeripotiwa kwa CVE-2025-11001 katika 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – Burudani ya hacking na zip-slips, tar-slips, symlinks, hardlinks, collisions, na mengine](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – Bypass ya kichujio cha tarfile extraction ya CVE-2026-11940](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
- [13] [GitHub Security Advisory – node-tar: hardlink target escape kupitia msururu wa symlink](https://github.com/isaacs/node-tar/security/advisories/GHSA-83g3-92jg-28cx)
- [14] [Rhino Security Labs CVE PoC – Root ya SCORM extraction inayodhibitiwa na mtumiaji](https://raw.githubusercontent.com/RhinoSecurityLabs/CVEs/master/CVE-2026-39405/README.md)
- [15] [Rhino Security Labs – Udhaifu Mbalimbali katika Frappe LMS Unaosababisha Remote Code Execution](https://rhinosecuritylabs.com/research/multiple-vulnerabilities-in-frappe-lms-leading-to-remote-code-execution/)
{{#include ../banners/hacktricks-training.md}}
