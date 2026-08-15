# Archive Extraction Path Traversal ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## अवलोकन

कई archive formats (ZIP, RAR, TAR, 7-ZIP आदि) प्रत्येक entry को अपना **internal path** रखने की अनुमति देते हैं। जब कोई extraction utility उस path को बिना जांचे स्वीकार कर लेती है, तो `..` या **absolute path** (जैसे `C:\Windows\System32\`) वाला crafted filename user द्वारा चुनी गई directory के बाहर लिख दिया जाएगा।
इस vulnerability class को व्यापक रूप से *Zip-Slip* या **archive extraction path traversal** के नाम से जाना जाता है।<sup>[[6]](#references)</sup>

इसके परिणाम arbitrary files को overwrite करने से लेकर **remote code execution (RCE)** तक हो सकते हैं, जैसे payload को Windows के *Startup* folder जैसी **auto-run** location में डालकर।

## मूल कारण

1. Attacker ऐसा archive बनाता है जिसमें एक या अधिक file headers में निम्न शामिल होते हैं:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* या crafted **symlinks**, जो target dir के बाहर resolve होते हैं (*nix* पर ZIP/TAR में सामान्य)।
2. Victim archive को ऐसे vulnerable tool से extract करता है, जो embedded path पर भरोसा करता है (या symlinks follow करता है), उसे sanitise करने या चुनी गई directory के भीतर extraction को बाध्य करने के बजाय।
3. File attacker-controlled location में लिख दी जाती है और अगली बार system या user द्वारा उस path को trigger करने पर execute/load हो जाती है।

### .NET `Path.Combine` + `ZipArchive` traversal

एक सामान्य .NET anti-pattern में intended destination को **user-controlled** `ZipArchiveEntry.FullName` के साथ combine किया जाता है और path normalisation के बिना extraction की जाती है:<sup>[[4]](#references)[[8]](#references)</sup>
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
- यदि `entry.FullName` `..\\` से शुरू होता है, तो यह traversal करता है; यदि यह **absolute path** है, तो बाईं ओर का component पूरी तरह discard कर दिया जाता है, जिससे extraction identity के रूप में **arbitrary file write** संभव हो जाता है।
- scheduled scanner द्वारा monitored sibling `app` directory में लिखने के लिए proof-of-concept archive:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
उस ZIP को monitored inbox में डालने पर `C:\samples\app\0xdf.txt` बन जाता है, जिससे `C:\samples\queue\` के बाहर traversal सिद्ध होता है और follow-on primitives (जैसे DLL hijacks) सक्षम हो जाते हैं।

## Advanced Archive-Breakout Primitives

Extraction को स्वतंत्र filename checks के बजाय filesystem mutations के क्रम के रूप में देखें। Parsing के समय सुरक्षित दिखने वाला entry तब असुरक्षित बन सकता है, जब कोई पिछला member link बनाए या उसे replace करे; यही समस्या तब भी दिखाई देती है, जब extractor किसी directory को सुरक्षित मानकर cache कर ले और बाद में उसका type बदल जाए।<sup>[[11]](#references)</sup>

### Link pivots और entry collisions

* **Symlink write-through**: `pivot -> /tmp` बनाएं, फिर regular member को `pivot/PWNED.txt` के रूप में extract करें। यदि extractor दूसरे member को materialise करते समय पहले member को follow करता है, तो दूसरे नाम में `..` न होने पर भी write बाहर चली जाती है।
* **Directory-cache/TOCTOU collision**: directory `d/sub/` emit करें, `d/sub` को `/tmp` के symlink से replace करें, फिर `d/sub/PWNED.txt` emit करें। यह उन extractors को target करता है जो directory को एक बार validate या cache करते हैं और final write से पहले उसे दोबारा check नहीं करते।
* **Hardlink read/overwrite**: TAR और RAR hardlinks को represent कर सकते हैं। किसी मौजूदा host file का hardlink उसकी contents को expose कर सकता है, यदि बाद का component extracted name को serve करे; इसके बजाय colliding regular entry linked inode को overwrite कर सकता है। यह same-filesystem और OS hardlink-permission rules से सीमित होता है।
* **Pre-existing या cross-archive pivot**: non-empty destination के साथ दोबारा प्रयास करें। एक archive link plant कर सकता है और बाद का extraction उसके माध्यम से write कर सकता है, भले ही प्रत्येक archive stateless header-name check पास करे।<sup>[[11]](#references)</sup>

### Filesystem-equivalence collisions

Names की तुलना उस filesystem के semantics का उपयोग करके करें, जो उन्हें receive करेगा। उपयोगी differential cases में case-insensitive filesystems पर `LINK` और `link`, Unicode की NFC और NFD spellings, `ﬁle` और `file` जैसे compatibility-equivalent names, ऐसे duplicate members जो किसी path को directory से symlink में बदल दें, और केवल Windows पर separators के रूप में interpret होने वाले backslashes शामिल हैं। NTFS पर ADS-bearing names का भी परीक्षण करें। इन cases के कारण validator को दो paths दिखाई दे सकते हैं, जबकि filesystem एक ही path resolve करता है।<sup>[[5]](#references)[[11]](#references)</sup>

इसलिए एक compact corpus को **directory → symlink → child**, **symlink → colliding regular file**, **hardlink → colliding regular file**, मिश्रित `/` और `\`, absolute/rooted names, और `.tar.gz` जैसे compressed wrappers के ordered combinations का परीक्षण करना चाहिए। इसे केवल disposable VM/container में चलाएं और destination तथा intended outside canary path दोनों पर निगरानी रखें।<sup>[[11]](#references)</sup>

## Real-World Example – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows के लिए WinRAR और उसके Windows RAR/UnRAR components extraction के दौरान filenames validate करने में विफल रहे। इस flaw ने selected extraction path को bypass करने और files को unintended locations पर write करने के लिए NTFS alternate data streams (ADS) का उपयोग किया।<sup>[[5]](#references)</sup>
एक malicious RAR archive, जिसमें इस प्रकार का entry हो:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
selected output directory के **बाहर** और user के *Startup* folder के अंदर पहुंच जाता। ESET ने वहां malicious LNK files को unpack होकर execute होते देखा, जिससे user logon पर persistence और RCE का मार्ग मिलता था।<sup>[[5]](#references)</sup>

### PoC Archive बनाना (Linux/Mac)

क्योंकि CVE-2025-8088 ADS name में traversal path का उपयोग करता है, RAR बनाने के लिए purpose-built generator का उपयोग करें, फिर vulnerable WinRAR build वाले isolated lab में ही extraction test करें।<sup>[[5]](#references)</sup>

### Wild में देखे गए Exploitation

ESET ने RomCom (Storm-0978/UNC2596) के spear-phishing campaigns की रिपोर्ट की, जिनमें CVE-2025-8088 का दुरुपयोग करने वाले RAR archives attach किए गए थे, ताकि customised backdoors deploy किए जा सकें और ransomware operations को सक्षम बनाया जा सके।<sup>[[5]](#references)</sup>

## नए Cases (2024–2026)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: Extraction के दौरान **symbolic links** वाले ZIP entries को dereference किया गया, जिससे attackers destination directory से बाहर निकलकर arbitrary paths को overwrite कर सकते थे। User interaction केवल archive को *खोलना/extract करना* है।<sup>[[1]](#references)</sup>
* **Affected**: **25.00** से पहले के 7-Zip builds। Symbolic-link processing flaw को **25.00** (July 2025) और बाद के versions में fix किया गया।<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**: `Start Menu/Programs/Startup` या service-run locations को overwrite करना → अगली logon या service restart पर code run होता है।
* **Quick symlink-handling fixture (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
इस archive में extraction directory के बाहर point करने वाली symlink entry है; disposable target का उपयोग करें और verify करें कि extractor उसका अनुसरण नहीं करता। Write-through test के लिए symlink के नीचे एक regular-file entry भी आवश्यक है।

### Go mholt/archiver `Unarchive()` symlink collision (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` एक ZIP symlink को extract कर सकता है और बाद में उसी name वाले regular member के आने पर उसे dereference कर सकता है, जिससे apparently in-root write, out-of-root write में बदल जाती है।<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (project अब deprecated है)।<sup>[[2]](#references)</sup>
* **Fix**: `mholt/archives` ≥ 0.1.0 पर switch करें या links को reject करें और हर destination को open करने से ठीक पहले फिर से resolve करें।<sup>[[2]](#references)</sup>
* **Minimal collision generator** (फिर `archiver.Unarchive("exploit.zip", "/tmp/safe")` call करें):<sup>[[2]](#references)</sup>
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

`tarfile.extractall(filter="data")` और `filter="tar"` में भी link-order bypasses देखे गए हैं। इस मामले में, एक hardlink ने deeper path पर archived symlink को reference किया; fallback extraction ने उस deep location पर relative symlink को validate किया, लेकिन उसे hardlink की shallower location पर recreate किया, जहां वही relative target बाहर निकल गया। यह एक उपयोगी general test है: validation और materialisation के base directory या final member type के बारे में अलग-अलग परिणाम आने की स्थिति बनाएं।<sup>[[12]](#references)</sup>

## Detection Tips

* **Static inspection** – Member names और link targets दोनों की सूची बनाएं। `../`, `..\\`, absolute/rooted paths, symlinks, hardlinks, special files, duplicate names, type changes और case/Unicode-equivalent collisions को flag करें। Review के दौरान entry order बनाए रखें, क्योंकि exploit पहले आने वाले members पर निर्भर कर सकता है।<sup>[[11]](#references)</sup>
* **Canonicalisation** – सुनिश्चित करें कि resolved parent और final basename, resolved destination के अंदर ही रहें (raw string prefix की बजाय path components की तुलना करें)। हर preceding member के बाद दोबारा check करें; एक बार किया गया `realpath(join(dest, name))` test link replacement के प्रति vulnerable होता है और अभी तक create न किए गए leaf के लिए fail हो सकता है।<sup>[[3]](#references)[[11]](#references)</sup>
* **Sandbox extraction** – किसी fresh, disposable directory में ऐसे extractor का उपयोग करके decompress करें जिसमें path/symlink checks हों (उदाहरण के लिए, bsdtar के default secure checks या 7-Zip ≥ 25.00), फिर verify करें कि resulting tree में कोई outward links नहीं हैं। Isolation को पहले से trigger हो चुके escape को host paths तक पहुंचने से रोकना चाहिए।<sup>[[1]](#references)[[9]](#references)</sup>
* **Downstream reads matter** – बची हुई symlink या hardlink arbitrary-file-read primitive बन सकती है, जब कोई previewer, CDN, file browser या package pipeline बाद में extracted name को open या serve करे, भले ही extraction ने स्वयं कोई outside file create न की हो।<sup>[[11]](#references)</sup>
* **Endpoint monitoring** – WinRAR/7-Zip आदि द्वारा archive खोले जाने के तुरंत बाद `Startup`/`Run`/`cron` locations में लिखे गए नए executables पर alert करें।

## Mitigation & Hardening

1. **Update the extractor** – WinRAR 7.13+ और 7-Zip 25.00+ में cited path/symlink issues के fixes शामिल हैं।<sup>[[1]](#references)[[5]](#references)</sup>
2. जब संभव हो, archives को “**Do not extract paths**” / “**Ignore paths**” के साथ extract करें। Untrusted input के लिए symbolic links, hardlinks, devices और FIFOs को reject करें, जब तक application को स्पष्ट रूप से इनकी आवश्यकता न हो।<sup>[[9]](#references)[[11]](#references)</sup>
3. Archives को **new empty directory** में extract करें। Untrusted members को ऐसे tree में merge न करें जिसमें attacker-replaceable paths हों, और पहले के archive द्वारा बनाए गए directory को reuse न करें।<sup>[[11]](#references)</sup>
4. Unix पर privileges drop करें और destination को **chroot/mount namespace** में isolate करें; Windows पर **AppContainer** या sandbox का उपयोग करें। केवल post-extraction scan पर्याप्त नहीं है, क्योंकि escaped write scan से पहले हो जाती है।<sup>[[11]](#references)</sup>
5. Custom code में target OS के separator/case/Unicode rules लागू करें और member तथा link target दोनों को validate करें। Links को follow किए बिना destination को resolve और open करें; containment check को बाद के create/replace operation से अलग न रखें। Validator को write path जैसी ही exact base और link-emulation semantics का उपयोग करना चाहिए।<sup>[[11]](#references)[[12]](#references)</sup>

## Additional Affected / Historical Cases

* 2018 – Snyk का Massive *Zip-Slip* advisory, जिसने कई Java/Go/JS libraries को प्रभावित किया।<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) में slugs का TAR extraction traversal (v0.16.3 में fix किया गया)।<sup>[[7]](#references)</sup>
* ऐसा कोई भी custom extraction logic जो header strings को validate करता है, लेकिन link targets और प्रत्येक write के लिए उपयोग किए जाने वाले final filesystem path को validate नहीं करता।<sup>[[11]](#references)[[12]](#references)</sup>



## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – .NET में Zip Slip को रोकना](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – WinRAR tools को अभी update करें: RomCom और अन्य द्वारा zero-day vulnerability का exploitation (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Critical Arbitrary File Overwrite Vulnerability का Public Disclosure: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug Zip Slip Attack के प्रति Vulnerable (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine Method](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar secure extraction flags](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – 7-Zip में CVE-2025-11001 के लिए Proof-of-Concept Exploit की रिपोर्ट](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – zip-slips, tar-slips, symlinks, hardlinks, collisions और अन्य के साथ Hacking fun](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – CVE-2026-11940 tarfile extraction filter bypass](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
{{#include ../banners/hacktricks-training.md}}
