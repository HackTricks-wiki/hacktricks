# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

## Muhtasari

Miundo mingi ya archive (ZIP, RAR, TAR, 7-ZIP, n.k.) huruhusu kila entry kuwa na **internal path** yake. Extraction utility inapofuata path hiyo bila ukaguzi, filename iliyotengenezwa ikiwa na `..` au **absolute path** (kwa mfano `C:\Windows\System32\`) itaandikwa nje ya directory iliyochaguliwa na mtumiaji.
Aina hii ya vulnerability inajulikana sana kama *Zip-Slip* au **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Madhara yanaweza kuanzia overwriting ya files kiholela hadi kupata **remote code execution (RCE)** moja kwa moja kwa kuweka payload katika eneo la **auto-run**, kama vile Windows *Startup* folder.

## Chanzo Kikuu

1. Attacker huunda archive ambamo file headers moja au zaidi zina:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Au **symlinks** zilizotengenezwa ambazo hu-resolve nje ya target dir (jambo linalotokea mara nyingi katika ZIP/TAR kwenye *nix*).
2. Victim hu-extract archive kwa kutumia tool yenye vulnerability inayotegemea embedded path (au kufuata symlinks), badala ya kuisanitize au kulazimisha extraction ifanyike chini ya directory iliyochaguliwa.
3. File huandikwa katika location inayodhibitiwa na attacker na ku-execute/load mfumo au mtumiaji anapochochea path hiyo wakati unaofuata.

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
- Ikiwa `entry.FullName` inaanza na `..\\`, hupita nje ya saraka; ikiwa ni **absolute path**, sehemu ya upande wa kushoto huondolewa kabisa, na kusababisha **arbitrary file write** kama utambulisho wa extraction.
- Archive ya proof-of-concept ya kuandika kwenye saraka ya `app` iliyo jirani, inayofuatiliwa na scanner iliyoratibiwa:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Kuweka ZIP hiyo kwenye inbox inayofuatiliwa husababisha `C:\samples\app\0xdf.txt`, kuthibitisha traversal nje ya `C:\samples\queue\` na kuwezesha primitives za ufuatiliaji (kwa mfano, DLL hijacks).

## Mfano wa Ulimwengu Halisi – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR for Windows na components zake za Windows RAR/UnRAR zilishindwa kuthibitisha majina ya mafaili wakati wa extraction. Flaw ilitumia NTFS alternate data streams (ADS) kupita njia ya extraction iliyochaguliwa na kuandika mafaili kwenye maeneo yasiyokusudiwa.<sup>[[5]](#references)</sup>
RAR archive yenye madhara iliyokuwa na entry kama hii:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
ingeishia **nje** ya saraka ya output iliyochaguliwa na ndani ya folda ya *Startup* ya user. ESET iliona faili hasidi za LNK zikifunguliwa humo na kutekelezwa user anapoingia, hivyo kutoa persistence na njia ya RCE.<sup>[[5]](#references)</sup>

### Kutengeneza PoC Archive (Linux/Mac)

Kwa sababu CVE-2025-8088 hutumia traversal path katika jina la ADS, tumia generator iliyoundwa mahsusi kuunda RAR, kisha fanya extraction katika lab iliyotengwa pekee, yenye WinRAR vulnerable build.<sup>[[5]](#references)</sup>

### Exploitation Iliyoonekana Hadharani

ESET iliripoti kampeni za spear-phishing za RomCom (Storm-0978/UNC2596) zilizoweka RAR archives zinazotumia vibaya CVE-2025-8088 ili kusambaza backdoors zilizobinafsishwa na kuwezesha shughuli za ransomware.<sup>[[5]](#references)</sup>

## Kesi Mpya zaidi (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP entries ambazo ni **symbolic links** zilifuatwa wakati wa extraction, hivyo kuwawezesha attackers kutoka kwenye destination directory na kuandika paths holela. User interaction ni *kufungua/kufanya extraction* ya archive pekee.<sup>[[1]](#references)</sup>
* **Affected**: 7-Zip builds za kabla ya **25.00**. Hitilafu ya kushughulikia symbolic links ilirekebishwa katika **25.00** (Julai 2025) na matoleo ya baadaye.<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**: Kuandika juu ya `Start Menu/Programs/Startup` au maeneo ya service-run → code huendeshwa user anapoingia tena au service inapoanzishwa upya.
* **Quick symlink-handling fixture (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Archive hii ina symlink entry inayoelekeza nje ya extraction directory; tumia target ya kutupwa na uhakikishe kuwa extractor haifuatilii symlink hiyo. Write-through test pia inahitaji regular-file entry iliyo chini ya symlink.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` hufuata `../` na ZIP entries zilizo symlink, na kuandika nje ya `outputDir`.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (project sasa imepitwa na wakati).
* **Fix**: Hamia kwenye `mholt/archives` ≥ 0.1.0 au implement canonical-path checks kabla ya write.
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Vidokezo vya Detection

* **Static inspection** – Orodhesha archive entries na flag jina lolote lenye `../`, `..\\`, *absolute paths* (`/`, `C:`) au entries za aina ya *symlink* ambazo target yake iko nje ya extraction dir.
* **Canonicalisation** – Hakikisha `realpath(join(dest, name))` inabaki ndani ya `realpath(dest)` (linganisha path components, si raw string prefix pekee). Kataa vinginevyo.<sup>[[3]](#references)</sup>
* **Sandbox extraction** – Decompress kwenye directory ya kutupwa ukitumia extractor yenye path/symlink checks (kwa mfano secure checks za default za bsdtar au 7-Zip ≥ 25.00), kisha thibitisha kuwa paths zinazosalia ziko ndani ya directory hiyo.<sup>[[1]](#references)[[9]](#references)</sup>
* **Endpoint monitoring** – Toa alert kuhusu executables mpya zinazoandikwa kwenye maeneo ya `Startup`/`Run`/`cron` muda mfupi baada ya archive kufunguliwa na WinRAR/7-Zip/etc.

## Mitigation & Hardening

1. **Update extractor** – WinRAR 7.13+ na 7-Zip 25.00+ zina fixes za path/symlink issues zilizotajwa.<sup>[[1]](#references)[[5]](#references)</sup>
2. Fanya extraction ya archives kwa “**Do not extract paths**” / “**Ignore paths**” inapowezekana.
3. Kwenye Unix, punguza privileges na mount **chroot/namespace** kabla ya extraction; kwenye Windows, tumia **AppContainer** au sandbox.
4. Ukiandika custom code, normalise kwa `realpath()`/`PathCanonicalize()` **kabla** ya create/write, na kataa entry yoyote inayotoka nje ya destination.

## Kesi Nyingine Zilizoathirika / za Kihistoria

* 2018 – Advisory kubwa ya *Zip-Slip* kutoka Snyk iliyoathiri Java/Go/JS libraries nyingi.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal katika slugs (imefanyiwa fix katika v0.16.3).<sup>[[7]](#references)</sup>
* Logic yoyote ya custom extraction inayoshindwa kuita `PathCanonicalize` / `realpath` kabla ya write.

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [Utafiti wa JFrog – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Kuzuia Zip Slip katika .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Utafiti wa ESET – Update WinRAR tools now: RomCom and others exploiting zero-day vulnerability (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Ufichuaji wa Umma wa Critical Arbitrary File Overwrite Vulnerability: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug Vulnerable to Zip Slip Attack (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine Method](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar secure extraction flags](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Proof-of-Concept Exploit Reported for CVE-2025-11001 in 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
{{#include ../banners/hacktricks-training.md}}
