# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## अवलोकन

कई archive formats (ZIP, RAR, TAR, 7-ZIP, आदि) प्रत्येक entry को अपना **internal path** रखने की अनुमति देते हैं। जब कोई extraction utility उस path को बिना जांचे स्वीकार करती है, तो `..` या **absolute path** (जैसे `C:\Windows\System32\`) वाला crafted filename user द्वारा चुनी गई directory के बाहर लिख दिया जाएगा।
इस प्रकार की vulnerability को व्यापक रूप से *Zip-Slip* या **archive extraction path traversal** के नाम से जाना जाता है।<sup>[[6]](#references)</sup>

इसके परिणाम arbitrary files को overwrite करने से लेकर **remote code execution (RCE)** सीधे प्राप्त करने तक हो सकते हैं, यदि payload को Windows के *Startup* folder जैसे **auto-run** location में डाल दिया जाए।

## मूल कारण

1. Attacker एक ऐसा archive बनाता है जिसमें एक या अधिक file headers में निम्न शामिल होते हैं:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* या crafted **symlinks**, जो target dir के बाहर resolve होते हैं (*nix* पर ZIP/TAR में सामान्य)।
2. Victim archive को ऐसे vulnerable tool से extract करता है, जो embedded path पर भरोसा करता है (या symlinks को follow करता है), बजाय उसे sanitise करने या extraction को चुनी गई directory के भीतर सीमित करने के।
3. File attacker-controlled location में लिखी जाती है और अगली बार जब system या user उस path को trigger करता है, तो execute/load हो जाती है।

### .NET `Path.Combine` + `ZipArchive` traversal

एक सामान्य .NET anti-pattern में intended destination को user-controlled `ZipArchiveEntry.FullName` के साथ combine किया जाता है और path normalisation के बिना extract किया जाता है:<sup>[[4]](#references)[[8]](#references)</sup>
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
- यदि `entry.FullName` `..\\` से शुरू होता है, तो यह traverse करता है; यदि यह एक **absolute path** है, तो बाईं ओर वाला component पूरी तरह discard कर दिया जाता है, जिससे extraction identity के रूप में **arbitrary file write** संभव हो जाता है।
- scheduled scanner द्वारा monitored sibling `app` directory में लिखने के लिए proof-of-concept archive:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
उस ZIP को monitored inbox में डालने पर `C:\samples\app\0xdf.txt` बनता है, जो `C:\samples\queue\` के बाहर traversal को साबित करता है और follow-on primitives (जैसे DLL hijacks) सक्षम करता है।

## वास्तविक उदाहरण – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows के लिए WinRAR और उसके Windows RAR/UnRAR components extraction के दौरान filenames को validate करने में विफल रहे। इस flaw ने चयनित extraction path को bypass करने और files को अनपेक्षित locations पर लिखने के लिए NTFS alternate data streams (ADS) का उपयोग किया।<sup>[[5]](#references)</sup>
एक malicious RAR archive में निम्न जैसा entry हो सकता है:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
**बाहर** निकल जाती और user के *Startup* folder के अंदर चली जाती। ESET ने वहां malicious LNK files को unpack होकर user logon पर execute होते देखा, जिससे persistence और RCE का रास्ता मिला।<sup>[[5]](#references)</sup>

### PoC Archive तैयार करना (Linux/Mac)

क्योंकि CVE-2025-8088 ADS name में traversal path का उपयोग करता है, RAR बनाने के लिए purpose-built generator का उपयोग करें, फिर vulnerable WinRAR build वाले isolated lab में ही extraction का परीक्षण करें।<sup>[[5]](#references)</sup>

### वास्तविक मामलों में देखा गया Exploitation

ESET ने RomCom (Storm-0978/UNC2596) की spear-phishing campaigns की रिपोर्ट की, जिनमें CVE-2025-8088 का दुरुपयोग करने वाले RAR archives attach किए गए थे, ताकि customised backdoors deploy किए जा सकें और ransomware operations को facilitate किया जा सके।<sup>[[5]](#references)</sup>

## नए मामले (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: Extraction के दौरान **symbolic links** वाले ZIP entries को dereference किया गया, जिससे attackers destination directory से बाहर निकलकर arbitrary paths को overwrite कर सकते थे। User interaction केवल archive को *opening/extracting* करना है।<sup>[[1]](#references)</sup>
* **Affected**: **25.00** से पहले के 7-Zip builds। Symbolic-link processing flaw को **25.00** (July 2025) और बाद के versions में fix किया गया।<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**: `Start Menu/Programs/Startup` या service-run locations को overwrite करना → अगले logon या service restart पर code run होता है।
* **Quick symlink-handling fixture (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
इस archive में extraction directory के बाहर point करने वाली symlink entry है; disposable target का उपयोग करें और verify करें कि extractor उसका अनुसरण नहीं करता। Write-through test के लिए symlink के नीचे एक regular-file entry भी आवश्यक है।

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` `../` और symlinked ZIP entries का अनुसरण करता है और `outputDir` के बाहर लिखता है।<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (project अब deprecated है)।
* **Fix**: `mholt/archives` ≥ 0.1.0 पर switch करें या write से पहले canonical-path checks implement करें।
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection Tips

* **Static inspection** – Archive entries की सूची बनाएं और ऐसे किसी भी name को flag करें जिसमें `../`, `..\\`, *absolute paths* (`/`, `C:`) हों, या ऐसी *symlink* entries हों जिनका target extraction dir के बाहर हो।
* **Canonicalisation** – सुनिश्चित करें कि `realpath(join(dest, name))`, `realpath(dest)` के अंदर रहे (केवल raw string prefix नहीं, बल्कि path components की तुलना करें)। अन्यथा reject करें।<sup>[[3]](#references)</sup>
* **Sandbox extraction** – Path/symlink checks वाले extractor का उपयोग करके disposable directory में decompress करें (उदाहरण के लिए, bsdtar के default secure checks या 7-Zip ≥ 25.00), फिर verify करें कि resulting paths directory के अंदर ही रहें।<sup>[[1]](#references)[[9]](#references)</sup>
* **Endpoint monitoring** – WinRAR/7-Zip आदि द्वारा archive open किए जाने के तुरंत बाद `Startup`/`Run`/`cron` locations में लिखे गए नए executables पर alert करें।

## Mitigation & Hardening

1. **Extractor को update करें** – WinRAR 7.13+ और 7-Zip 25.00+ में बताए गए path/symlink issues के fixes शामिल हैं।<sup>[[1]](#references)[[5]](#references)</sup>
2. जहां संभव हो, archives को “**Do not extract paths**” / “**Ignore paths**” विकल्प के साथ extract करें।
3. Unix पर extraction से पहले privileges drop करें और **chroot/namespace** mount करें; Windows पर **AppContainer** या sandbox का उपयोग करें।
4. यदि custom code लिख रहे हैं, तो **before** create/write `realpath()`/`PathCanonicalize()` से normalise करें और ऐसे किसी भी entry को reject करें जो destination से बाहर निकलती हो।

## अतिरिक्त Affected / Historical Cases

* 2018 – Snyk की Massive *Zip-Slip* advisory, जिसने कई Java/Go/JS libraries को प्रभावित किया।<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) में slugs के TAR extraction traversal की समस्या (v0.16.3 में fix की गई)।<sup>[[7]](#references)</sup>
* कोई भी custom extraction logic जो write से पहले `PathCanonicalize` / `realpath` call करने में विफल हो।

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – .NET में Zip Slip से बचाव](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – WinRAR tools को अभी update करें: RomCom और अन्य zero-day vulnerability (CVE-2025-8088) का exploitation कर रहे हैं](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – एक Critical Arbitrary File Overwrite Vulnerability का Public Disclosure: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug Zip Slip Attack के लिए Vulnerable (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine Method](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar secure extraction flags](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – 7-Zip में CVE-2025-11001 के लिए Proof-of-Concept Exploit की रिपोर्ट](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
{{#include ../banners/hacktricks-training.md}}
