# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Overview

Many archive formats (ZIP, RAR, TAR, 7-ZIP, etc.) allow each entry to carry its own **internal path**. When an extraction utility blindly honours that path, a crafted filename containing `..` or an **absolute path** (e.g. `C:\Windows\System32\`) will be written outside of the user-chosen directory.
This class of vulnerability is widely known as *Zip-Slip* or **archive extraction path traversal**.

कई archive फ़ॉर्मैट्स (ZIP, RAR, TAR, 7-ZIP, आदि) प्रत्येक entry को अपना **internal path** रखने का विकल्प देते हैं। जब कोई extraction utility उस path को बिना सत्यापित किए मान लेता है, तो एक crafted filename जिसमें `..` या एक **absolute path** (उदा. `C:\Windows\System32\`) शामिल हो, उपयोगकर्ता द्वारा चुनी गई डायरेक्टरी के बाहर लिखा जा सकता है।
इस तरह की vulnerability को व्यापक रूप से *Zip-Slip* या **archive extraction path traversal** कहा जाता है।

## Root Cause

1. Attacker creates an archive where one or more file headers contain:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Or crafted **symlinks** that resolve outside the target dir (common in ZIP/TAR on *nix*).
2. Victim extracts the archive with a vulnerable tool that trusts the embedded path (or follows symlinks) instead of sanitising it or forcing extraction beneath the chosen directory.
3. The file is written in the attacker-controlled location and executed/loaded next time the system or user triggers that path.

1. हमलावर एक archive बनाता है जिसमें एक या अधिक फ़ाइल हेडर में निम्न शामिल होते हैं:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* या crafted **symlinks** जो target dir के बाहर resolve होते हैं (यह ZIP/TAR में *nix* पर आम है)।
2. पीड़ित उस archive को किसी vulnerable टूल से extract करता है जो embedded path पर भरोसा करता है (या symlinks का पालन करता है) बजाय इसके कि वह उसे sanitize करे या चुनी हुई डायरेक्टरी के भीतर extraction को मजबूर करे।
3. फ़ाइल हमलावर-नियंत्रित स्थान पर लिखी जाती है और अगली बार जब सिस्टम या उपयोगकर्ता उस path को ट्रिगर करता है तो वह execute/loaded हो जाती है।

## Real-World Example – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR for Windows (including the `rar` / `unrar` CLI, the DLL and the portable source) failed to validate filenames during extraction.
A malicious RAR archive containing an entry such as:

WinRAR for Windows (including the `rar` / `unrar` CLI, the DLL and the portable source) extraction के दौरान filenames को validate करने में विफल रहा।
एक malicious RAR archive जिसमें ऐसा एक entry हो:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
यह चुनी हुई आउटपुट डायरेक्टरी के **बाहर** और उपयोगकर्ता के *Startup* फ़ोल्डर के अंदर समाप्त हो जाएगा। लॉगऑन के बाद Windows वहाँ मौजूद सभी चीज़ों को स्वचालित रूप से चलाता है, जिससे *persistent* RCE मिलता है।

### PoC Archive तैयार करना (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
इस्तेमाल किए गए विकल्प:
* `-ep`  – store file paths exactly as given (do **not** prune leading `./`).

लक्षित को `evil.rar` दें और उन्हें किसी vulnerable WinRAR build के साथ इसे extract करने का निर्देश दें।

### वास्तविक दुनिया में देखे गए शोषण

ESET ने रिपोर्ट किया कि RomCom (Storm-0978/UNC2596) spear-phishing अभियानों ने CVE-2025-8088 का दुरुपयोग करते हुए RAR आर्काइव संलग्न किए, ताकि कस्टम बैकडोर तैनात किए जा सकें और ransomware ऑपरेशनों की सुविधा हो।

## हाल के मामले (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **बग**: ZIP एंट्रीज़ जो **symbolic links** हैं, extraction के दौरान dereference हो रही थीं, जिससे हमलावर destination directory से बाहर निकलकर arbitrary paths overwrite कर सकते थे। User interaction केवल आर्काइव को *opening/extracting* करना है।
* **प्रभावित**: 7-Zip 21.02–24.09 (Windows & Linux builds). Fixed in **25.00** (July 2025) and later.
* **Impact path**: Overwrite `Start Menu/Programs/Startup` or service-run locations → code runs at next logon or service restart.
* **Quick PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
पैच्ड बिल्ड पर `/etc/cron.d` छेड़ा नहीं जाएगा; symlink /tmp/target के अंदर एक link के रूप में extract होगा।

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **बग**: `archiver.Unarchive()` `../` और symlinked ZIP एंट्रीज़ का पालन करता है, और `outputDir` के बाहर लिखता है।
* **प्रभावित**: `github.com/mholt/archiver` ≤ 3.5.1 (project now deprecated).
* **फिक्स**: `mholt/archives` ≥ 0.1.0 पर स्विच करें या write से पहले canonical-path चेक लागू करें।
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## पहचान के सुझाव

* **Static inspection** – आर्काइव एंट्रीज़ को सूचीबद्ध करें और किसी भी नाम पर फ्लैग लगाएँ जिसमें `../`, `..\\`, *absolute paths* (`/`, `C:`) हो या जिनकी type *symlink* हो और जिनका target extraction dir के बाहर हो।
* **Canonicalisation** – सुनिश्चित करें कि `realpath(join(dest, name))` अभी भी `dest` से शुरू होता है। वरना reject करें।
* **Sandbox extraction** – एक disposable directory में decompress करें using a *safe* extractor (e.g., `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) और सत्यापित करें कि resulting paths डायरेक्टरी के अंदर ही रहें।
* **Endpoint monitoring** – WinRAR/7-Zip/etc. द्वारा आर्काइव खोले जाने के तुरंत बाद `Startup`/`Run`/`cron` लोकेशन्स में लिखे गए नए executables पर अलर्ट करें।

## शमन और हार्डेनिंग

1. **Update the extractor** – WinRAR 7.13+ और 7-Zip 25.00+ path/symlink sanitisation लागू करते हैं। दोनों टूल्स अभी भी auto-update से वंचित हैं।
2. आर्काइव को संभव हो तो “**Do not extract paths**” / “**Ignore paths**” विकल्प के साथ extract करें।
3. Unix पर, extraction से पहले privileges घटाएँ & एक **chroot/namespace** mount करें; Windows पर **AppContainer** या sandbox का उपयोग करें।
4. यदि custom code लिख रहे हैं, तो create/write से **पहले** `realpath()`/`PathCanonicalize()` से normalise करें, और किसी भी एंट्री को अस्वीकार करें जो destination से बाहर निकलती हो।

## अतिरिक्त प्रभावित / ऐतिहासिक मामले

* 2018 – Snyk द्वारा massive *Zip-Slip* advisory जिसने कई Java/Go/JS libraries को प्रभावित किया।
* 2023 – 7-Zip CVE-2023-4011 समान traversal `-ao` merge के दौरान।
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal in slugs (patch in v1.2).
* कोई भी custom extraction logic जो write से पहले `PathCanonicalize` / `realpath` कॉल करने में विफल हो।

## References

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)

{{#include ../banners/hacktricks-training.md}}
