# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Muhtasari

Miundo mingi ya archive (ZIP, RAR, TAR, 7-ZIP, n.k.) huruhusu kila entry kuwa na **internal path** yake. Wakati extraction utility inapotumia path hiyo bila kuikagua, filename iliyoundwa ikiwa na `..` au **absolute path** (kwa mfano `C:\Windows\System32\`) itaandikwa nje ya directory iliyochaguliwa na mtumiaji.
Aina hii ya vulnerability inajulikana sana kama *Zip-Slip* au **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Madhara yanaweza kuanzia overwrite ya arbitrary files hadi kufikia moja kwa moja **remote code execution (RCE)** kwa kuweka payload katika eneo la **auto-run**, kama vile Windows *Startup* folder.

## Chanzo cha Msingi

1. Attacker huunda archive ambamo file headers moja au zaidi zina:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Au **symlinks** zilizoundwa kwa njia inayozifanya zielekeze nje ya target dir (jambo la kawaida katika ZIP/TAR kwenye *nix*).
2. Victim hutoa archive kwa kutumia tool yenye vulnerability inayoamini embedded path (au inayofuata symlinks), badala ya kuisanitise au kulazimisha extraction ifanyike ndani ya directory iliyochaguliwa.
3. File huandikwa katika location inayodhibitiwa na attacker na kutekelezwa/kupakiwa wakati mwingine mfumo au mtumiaji anapo-trigger path hiyo.

### .NET `Path.Combine` + `ZipArchive` traversal

Anti-pattern ya kawaida katika .NET ni kuunganisha destination iliyokusudiwa na `ZipArchiveEntry.FullName` inayodhibitiwa na mtumiaji na kufanya extraction bila path normalisation:<sup>[[4]](#references)[[8]](#references)</sup>
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
- Ikiwa `entry.FullName` inaanza na `..\\`, inafanya traversal; ikiwa ni **absolute path**, sehemu ya kushoto huondolewa kabisa, na hivyo kusababisha **arbitrary file write** kama utambulisho wa extraction.
- Archive ya proof-of-concept ya kuandika kwenye directory ya `app` iliyo jirani, inayofuatiliwa na scanner iliyoratibiwa:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Kuweka ZIP hiyo kwenye inbox inayofuatiliwa husababisha `C:\samples\app\0xdf.txt`, kuthibitisha traversal nje ya `C:\samples\queue\` na kuwezesha primitives za ufuatiliaji (kwa mfano, DLL hijacks).

## Mfano wa Kwenye Ulimwengu Halisi – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR ya Windows pamoja na vipengele vyake vya Windows RAR/UnRAR vilishindwa kuthibitisha majina ya faili wakati wa extraction. Flaw ilitumia NTFS alternate data streams (ADS) kukwepa extraction path iliyochaguliwa na kuandika faili kwenye maeneo ambayo hayakukusudiwa.<sup>[[5]](#references)</sup>
RAR archive hasidi yenye entry kama:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
ingeishia **nje** ya saraka ya matokeo iliyochaguliwa na ndani ya folda ya *Startup* ya mtumiaji. ESET iliona faili hasidi za LNK zikifunguliwa humo na kutekelezwa mtumiaji anapoingia, hivyo kutoa persistence na njia ya RCE.<sup>[[5]](#references)</sup>

### Kutengeneza PoC Archive (Linux/Mac)

Kwa sababu CVE-2025-8088 hutumia traversal path katika jina la ADS, tumia generator maalumu kuunda RAR, kisha jaribu extraction pekee katika lab iliyotengwa kwa kutumia WinRAR build iliyo hatarini.<sup>[[5]](#references)</sup>

### Exploitation Iliyoonekana Porini

ESET iliripoti kampeni za spear-phishing za RomCom (Storm-0978/UNC2596) zilizoweka RAR archives zikitumia vibaya CVE-2025-8088 ili kupeleka backdoors zilizobinafsishwa na kuwezesha shughuli za ransomware.<sup>[[5]](#references)</sup>

## Kesi Mpya Zaidi (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP entries ambazo ni **symbolic links** zilifuatiliwa wakati wa extraction, na kuwawezesha attackers kutoka kwenye saraka lengwa na ku-overwrite paths kiholela. Mwingiliano wa mtumiaji ni *kufungua/kuextract* archive tu.<sup>[[1]](#references)</sup>
* **Affected**: 7-Zip builds za kabla ya **25.00**. Kosa la uchakataji wa symbolic-link lilirekebishwa katika **25.00** (Julai 2025) na matoleo ya baadaye.<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**: Ku-overwrite `Start Menu/Programs/Startup` au maeneo yanayoendeshwa na service → code huendeshwa mtumiaji anapoingia tena au service inapoanzishwa upya.
* **Fixture ya haraka ya kushughulikia symlink (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Archive hii ina symlink entry inayoelekeza nje ya saraka ya extraction; tumia target inayoweza kutupwa na thibitisha kuwa extractor haifuati symlink hiyo. Jaribio la write-through pia linahitaji regular-file entry ndani ya symlink.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` hufuata `../` na symlinked ZIP entries, na kuandika nje ya `outputDir`.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (project sasa imeachwa).
* **Fix**: Hamia kwenye `mholt/archives` ≥ 0.1.0 au tekeleza canonical-path checks kabla ya kuandika.
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Vidokezo vya Detection

* **Static inspection** – Orodhesha archive entries na weka alama kwa jina lolote lenye `../`, `..\\`, *absolute paths* (`/`, `C:`) au entries za aina ya *symlink* ambazo target yake iko nje ya saraka ya extraction.
* **Canonicalisation** – Hakikisha `realpath(join(dest, name))` inabaki ndani ya `realpath(dest)` (linganisha path components, si raw string prefix pekee). Kataa vinginevyo.<sup>[[3]](#references)</sup>
* **Sandbox extraction** – Decompress kwenye saraka inayoweza kutupwa kwa kutumia extractor yenye path/symlink checks (kwa mfano, secure checks za kawaida za bsdtar au 7-Zip ≥ 25.00), kisha thibitisha kuwa paths zinazotokana zinabaki ndani ya saraka hiyo.<sup>[[1]](#references)[[9]](#references)</sup>
* **Endpoint monitoring** – Toa alert kuhusu executables mpya zinazoandikwa kwenye maeneo ya `Startup`/`Run`/`cron` muda mfupi baada ya archive kufunguliwa na WinRAR/7-Zip/n.k.

## Mitigation & Hardening

1. **Update extractor** – WinRAR 7.13+ na 7-Zip 25.00+ zina fixes za masuala ya d path/symlink.<sup>[[1]](#references)[[5]](#references)</sup>
2. Extract archives kwa “**Do not extract paths**” / “**Ignore paths**” inapowezekana.
3. Kwenye Unix, punguza privileges na mount **chroot/namespace** kabla ya extraction; kwenye Windows, tumia **AppContainer** au sandbox.
4. Ukiandika custom code, normalise kwa `realpath()`/`PathCanonicalize()` **kabla** ya create/write, na kataa entry yoyote inayotoka nje ya destination.

## Kesi Nyingine Zilizoathirika / Za Kihistoria

* 2018 – Ushauri mkubwa wa *Zip-Slip* wa Snyk uliowaathiri Java/Go/JS libraries nyingi.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal katika slugs (ilirekebishwa katika v0.16.3).<sup>[[7]](#references)</sup>
* Custom extraction logic yoyote inayoshindwa kuita `PathCanonicalize` / `realpath` kabla ya kuandika.

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [Utafiti wa JFrog – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Kuzuia Zip Slip katika .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Utafiti wa ESET – Sasisha zana za WinRAR sasa: RomCom na wengine wanatumia udhaifu wa zero-day (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Ufichuaji wa Umma wa Udhaifu Muhimu wa Ku-Overwrite Faili Zisizo za Kiholela: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug Iko Hatarini kwa Shambulio la Zip Slip (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Mbinu ya Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bendera za bsdtar za secure extraction](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Proof-of-Concept Exploit Imeripotiwa kwa CVE-2025-11001 katika 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
{{#include ../banners/hacktricks-training.md}}
