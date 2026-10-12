# Archive Extraction Path Traversal ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## Overview

कई archive formats (ZIP, RAR, TAR, 7-ZIP आदि) हर entry को अपना **internal path** रखने देते हैं। जब कोई extraction utility इस path का बिना सोचे-समझे पालन करती है, तो `..` या **absolute path** (जैसे `C:\Windows\System32\`) वाला crafted filename, user द्वारा चुनी गई directory के बाहर लिखा जाएगा।  
इस तरह की vulnerability को आम तौर पर *Zip-Slip* या **archive extraction path traversal** कहा जाता है।<sup>[[6]](#references)</sup>

इसके परिणाम arbitrary files को overwrite करने से लेकर, Windows *Startup* folder जैसी **auto-run** location में payload डालकर सीधे **remote code execution (RCE)** हासिल करने तक हो सकते हैं।

## Root Cause

1. Attacker ऐसा archive बनाता है जिसके एक या अधिक file headers में ये शामिल हों:
   * Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
   * Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
   * या ऐसे crafted **symlinks** जो target dir के बाहर resolve होते हैं (*nix* पर ZIP/TAR में आम)। 
2. Victim archive को ऐसे vulnerable tool से extract करता है जो embedded path पर भरोसा करता है (या symlinks follow करता है), बजाय इसके कि उसे sanitise करे या extraction को चुनी गई directory के भीतर ही सीमित रखे।
3. File attacker के नियंत्रण वाली location में लिखी जाती है और अगली बार system या user द्वारा उस path को trigger करने पर execute/load होती है।

### .NET `Path.Combine` + `ZipArchive` traversal

एक आम .NET anti-pattern में, intended destination को **user-controlled** `ZipArchiveEntry.FullName` के साथ combine करके path normalisation के बिना extract किया जाता है:<sup>[[4]](#references)[[8]](#references)</sup>

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

- अगर `entry.FullName` की शुरुआत `..\\` से होती है, तो यह directory traversal करता है; अगर यह **absolute path** है, तो बाईं ओर का component पूरी तरह हटा दिया जाता है, जिससे extraction के दौरान **arbitrary file write** संभव हो जाता है।
- scheduled scanner द्वारा मॉनिटर की जाने वाली sibling `app` directory में फ़ाइल लिखने के लिए proof-of-concept archive:

```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
    z.writestr("../app/0xdf.txt", "ABCD")
```

उस ZIP को monitored inbox में डालने से `C:\samples\app\0xdf.txt` बनती है, जो `C:\samples\queue\` के बाहर traversal साबित करता है और आगे के primitives (जैसे DLL hijacks) को सक्षम करता है।

### User-controlled extraction root

केवल archive member names ही नहीं, बल्कि **extractor को दी गई directory** की भी जाँच करें। कोई application इस directory को title, project name या किसी अन्य request field से निर्धारित कर सकती है। `../../../../app/module` जैसी value, extractor द्वारा किसी भी member को process करने से पहले extraction root को upload area के बाहर ले जा सकती है। ऐसे में केवल सुरक्षित basename `api.py` वाली archive भी application code को overwrite कर सकती है।<sup>[[14]](#references)[[15]](#references)</sup>

```python
# Vulnerable pattern: the ZIP entries themselves need no ../ components.
extract_root = os.path.join(site_root, "public", "files", user_title)
archive.extractall(extract_root)
```

यह classic Zip-Slip से अलग containment boundary है। resolved extraction root और हर resolved member path को validate करें। Root check में string prefix के बजाय path components का उपयोग किया जा सकता है:<sup>[[14]](#references)</sup>

```python
base = Path(site_root, "public", "files").resolve()
dest = (base / user_title).resolve()
if not dest.is_relative_to(base):
    raise ValueError("extraction root escapes its base")
```

सुरक्षित परीक्षण के लिए, एक canary file वाला valid archive upload करें और हर उस field में traversal sequences रखें जो extraction directory चुन सकती है। निर्धारित directory और एक disposable बाहरी path, दोनों पर नज़र रखें। अगर destination किसी imported module तक पहुँच सकती है, तो उसे overwrite करने पर workers के reload होने पर code execution हो सकता है; उस reload के दौरान HTTP 500 या connection reset होना इस बात का प्रमाण नहीं है कि write विफल रहा।<sup>[[14]](#references)[[15]](#references)</sup> [file upload methodology](../pentesting-web/file-upload/) भी देखें।

## Advanced Archive-Breakout Primitives

Extraction को स्वतंत्र filename checks के बजाय filesystem mutations के क्रम के रूप में देखें। Parse होने पर सुरक्षित दिखने वाली entry, उससे पहले के किसी member द्वारा link बनाने या बदलने के बाद असुरक्षित हो सकती है; यही समस्या तब भी आती है जब कोई extractor किसी directory को safe के रूप में cache करता है और बाद में उसका type बदल जाता है।<sup>[[11]](#references)</sup>

### Link pivots and entry collisions

* **Symlink write-through**: `pivot -> /tmp` बनाएँ, फिर एक regular member को `pivot/PWNED.txt` के रूप में extract करें। अगर extractor दूसरे member को materialise करते समय पहले member को follow करता है, तो दूसरे name में `..` के बिना ही write बाहर जा सकता है।
* **Directory-cache/TOCTOU collision**: directory `d/sub/` बनाएँ, `d/sub` को `/tmp` की ओर इशारा करने वाले symlink से बदलें, फिर `d/sub/PWNED.txt` बनाएँ। यह उन extractors को निशाना बनाता है जो directory को एक बार validate या cache करते हैं और final write से पहले दोबारा जाँच नहीं करते।
* **Hardlink read/overwrite**: TAR और RAR hardlinks दर्शा सकते हैं। किसी मौजूदा host file का hardlink उसकी सामग्री उजागर कर सकता है, अगर बाद में कोई component extracted name serve करे; colliding regular entry इसके बजाय linked inode को overwrite कर सकती है। यह same-filesystem और OS hardlink-permission नियमों से सीमित है।
* **Pre-existing or cross-archive pivot**: non-empty destination के साथ दोबारा प्रयास करें। एक archive link बना सकता है और बाद का extraction उसके ज़रिए write कर सकता है, भले ही हर archive stateless header-name check पास कर जाए।<sup>[[11]](#references)</sup>

### Filesystem-equivalence collisions

Names की तुलना उस filesystem के semantics के अनुसार करें जहाँ वे लिखे जाएँगे। उपयोगी differential cases में case-insensitive filesystems पर `LINK` और `link`, Unicode के NFC और NFD spellings, compatibility-equivalent names जैसे `ﬁle` और `file`, duplicate members जो किसी path को directory से symlink में बदलते हैं, और backslashes शामिल हैं जिन्हें केवल Windows पर separators माना जाता है। NTFS पर ADS वाले names भी जाँचें। इन मामलों में validator को दो paths दिख सकते हैं, जबकि filesystem उन्हें एक ही path मानता है।<sup>[[5]](#references)[[11]](#references)</sup>

इसलिए एक संक्षिप्त corpus में **directory → symlink → child**, **symlink → colliding regular file**, **hardlink → colliding regular file**, मिश्रित `/` और `\`, absolute/rooted names, और `.tar.gz` जैसे compressed wrappers के क्रमबद्ध combinations जाँचें। इसे केवल disposable VM/container में चलाएँ और destination तथा निर्धारित बाहरी canary path, दोनों पर नज़र रखें।<sup>[[11]](#references)</sup>

ZIP-विशिष्ट structural ambiguity के कारण pre-scan और वास्तविक extractor को अलग-अलग entry names या trees दिख सकते हैं। केवल एक ZIP library के output पर भरोसा करने के बजाय [Local-header vs central-directory parser confusion](../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md#local-header-vs-central-directory-parser-confusion) देखें।

## वास्तविक दुनिया का उदाहरण – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows के लिए WinRAR और उसके Windows RAR/UnRAR components extraction के दौरान filenames validate करने में विफल रहे। इस flaw ने चुने गए extraction path को bypass करके अनचाही locations में files लिखने के लिए NTFS alternate data streams (ADS) का इस्तेमाल किया।<sup>[[5]](#references)</sup>
एक malicious RAR archive जिसमें इस तरह की entry हो:

```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```

अंततः चुनी गई आउटपुट डायरेक्टरी के **बाहर** और उपयोगकर्ता के *Startup* फ़ोल्डर के अंदर पहुँच जाती। ESET ने वहाँ दुर्भावनापूर्ण LNK फ़ाइलें अनपैक किए जाने और उपयोगकर्ता के लॉगिन पर निष्पादित होने की घटनाएँ देखीं, जिससे persistence और RCE का रास्ता मिला।<sup>[[5]](#references)</sup>

### PoC Archive बनाना (Linux/Mac)

क्योंकि CVE-2025-8088 में ADS नाम के भीतर traversal path का इस्तेमाल होता है, RAR बनाने के लिए खास तौर पर तैयार किए गए generator का उपयोग करें। फिर extraction का परीक्षण केवल vulnerable WinRAR build वाले isolated lab में करें।<sup>[[5]](#references)</sup>

### वास्तविक हमलों में देखा गया शोषण

ESET ने RomCom (Storm-0978/UNC2596) के spear-phishing अभियानों की रिपोर्ट दी, जिनमें CVE-2025-8088 का दुरुपयोग करने वाले RAR archives संलग्न थे, ताकि customized backdoors deploy किए जा सकें और ransomware operations को अंजाम देने में मदद मिले।<sup>[[5]](#references)</sup>

## नए मामले (2024–2026)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: Extraction के दौरान ZIP entries के **symbolic links** को dereference किया जाता था, जिससे हमलावर destination directory से बाहर निकलकर मनमाने paths को overwrite कर सकते थे। उपयोगकर्ता को केवल archive *खोलना/extract करना* होता है।<sup>[[1]](#references)</sup>
* **प्रभावित**: **25.00** से पुराने 7-Zip builds। Symbolic-link processing की यह खामी **25.00** (जुलाई 2025) और बाद के संस्करणों में ठीक की गई।<sup>[[1]](#references)[[10]](#references)</sup>
* **प्रभाव का रास्ता**: `Start Menu/Programs/Startup` या service-run locations को overwrite करना → अगले लॉगिन या service restart पर code चलता है।
* **Symlink handling के लिए त्वरित fixture (Linux)**:
  ```bash
  mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
  ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
  cd /tmp/archive-slip-test
  zip -y exploit.zip evil   # -y preserves symlinks
  7z x exploit.zip -o/tmp/archive-slip-target
  ```
  इस archive में extraction directory के बाहर की ओर इंगित करने वाली symlink entry है; disposable target का उपयोग करें और सत्यापित करें कि extractor उसका अनुसरण नहीं करता। Write-through test के लिए symlink के नीचे regular-file entry भी आवश्यक है।

### Go mholt/archiver `Unarchive()` symlink collision (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` एक ZIP symlink को extract कर सकता है और फिर बाद में उसी नाम वाले regular member को extract करते समय उसे dereference कर सकता है, जिससे root के भीतर दिखने वाला write, root के बाहर का write बन जाता है।<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (project अब deprecated है)।<sup>[[2]](#references)</sup>
* **Fix**: `mholt/archives` ≥ 0.1.0 पर स्विच करें या links को reject करें और हर destination को खोलने से ठीक पहले दोबारा resolve करें।<sup>[[2]](#references)</sup>
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

`tarfile.extractall(filter="data")` और `filter="tar"` में भी link-order bypasses हुए हैं। इस मामले में, एक hardlink ने archive में गहरे path पर मौजूद symlink को संदर्भित किया; fallback extraction ने उस गहरी जगह पर relative symlink को validate किया, लेकिन उसे hardlink की कम गहरी जगह पर फिर से बनाया, जहाँ वही relative target बाहर निकल गया। यह एक उपयोगी सामान्य test है: validation और materialisation के बीच base directory या अंतिम member type को लेकर असहमति पैदा करें।<sup>[[12]](#references)</sup>

### Node `tar` hardlink target escape through a symlink chain (GHSA-83g3-92jg-28cx)

Node.js के `tar` package का `tar.extract()` ऐसा hardlink स्वीकार करता था जिसका target देखने में lexical रूप से extraction root के भीतर था, लेकिन पहले के दो symlinks के ज़रिए resolve होने पर बाहर निकल जाता था। यह attack default extraction options के साथ काम करता है: destination-parent checks ने hardlink के in-root नाम को तो कवर किया, लेकिन containment जाँचने के लिए hardlink target को पूरी chain resolve किए बिना filesystem को सौंप दिया गया। `tar` ≤ 7.5.7 प्रभावित है; 7.5.8 में इस issue का patch है।<sup>[[13]](#references)</sup>

महत्वपूर्ण test fixture सदस्यों के बीच **क्रमबद्ध संबंध** है, न कि ये शाब्दिक नाम:<sup>[[13]](#references)</sup>

```text
a/b/c/up     -> ../..                          (symlink)
a/b/escape   -> c/up/../..                     (symlink)
exfil        => a/b/escape/<path-from-parent>  (hardlink)
```

यदि extraction सफल होता है, तो `exfil` output tree में स्पष्ट रूप से मौजूद रहता है, लेकिन चुनी गई बाहरी फ़ाइल के साथ उसका inode साझा होता है; इसे पढ़ने से उस फ़ाइल का data leak होता है और इसमें लिखने से मूल फ़ाइल संशोधित हो जाती है। यह bypass दिखाता है कि केवल अंतिम pathname की जाँच करना, absolute prefixes हटाना या hardlink header में `..` को रोकना पर्याप्त क्यों नहीं है: सभी पहले extract किए गए filesystem state लागू करने के बाद link targets की जाँच करें।<sup>[[13]](#references)</sup>

## Detection Tips

* **Static inspection** – Member names और link targets, दोनों की सूची बनाएँ। `../`, `..\\`, absolute/rooted paths, symlinks, hardlinks, special files, duplicate names, type changes और case/Unicode-equivalent collisions को चिह्नित करें। समीक्षा के दौरान entry order बनाए रखें, क्योंकि exploit पहले के members पर निर्भर हो सकता है।<sup>[[11]](#references)</sup>

  ```bash
  bsdtar -tvf suspect.tar       # ordered TAR members, types and link targets
  7z l -slt suspect.7z          # technical metadata, one field per line
  zipinfo -v suspect.zip        # ZIP central-directory metadata and offsets
  ```

* **Canonicalisation** – सुनिश्चित करें कि resolved parent और अंतिम basename, resolved destination के भीतर ही रहें (raw string prefix के बजाय path components की तुलना करें)। हर पिछले member के बाद फिर से जाँचें; एक बार किया गया `realpath(join(dest, name))` परीक्षण link replacement के प्रति असुरक्षित है और अभी तक न बने leaf के लिए विफल हो सकता है।<sup>[[3]](#references)[[11]](#references)</sup>
* **Sandbox extraction** – ऐसे extractor का उपयोग करके किसी नई, disposable directory में decompress करें जिसमें path/symlink checks हों (उदाहरण के लिए, bsdtar के default secure checks या 7-Zip ≥ 25.00), फिर सत्यापित करें कि resulting tree में बाहर की ओर इंगित करने वाले कोई links नहीं हैं। Isolation यह सुनिश्चित करे कि पहले से हो चुका escape host paths तक न पहुँच सके।<sup>[[1]](#references)[[9]](#references)</sup>
* **बाद में होने वाले reads भी मायने रखते हैं** – बचा हुआ symlink या hardlink arbitrary-file-read primitive बन सकता है, जब कोई previewer, CDN, file browser या package pipeline बाद में extracted name को खोलता या serve करता है—भले ही extraction के दौरान कोई बाहरी file न बनी हो।<sup>[[11]](#references)</sup>
* **Endpoint monitoring** – WinRAR/7-Zip/आदि द्वारा archive खोले जाने के तुरंत बाद `Startup`/`Run`/`cron` locations में लिखे गए नए executables के लिए alert करें।

## Mitigation और Hardening

1. **Extractor को update करें** – WinRAR 7.13+, 7-Zip 25.00+ और Node `tar` 7.5.8+ में उद्धृत path/symlink/link-target समस्याओं के fixes शामिल हैं।<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>
2. जहाँ संभव हो, archives को “**Do not extract paths**” / “**Ignore paths**” के साथ extract करें। Untrusted input के लिए symbolic links, hardlinks, devices और FIFOs को अस्वीकार करें, जब तक application को उनकी स्पष्ट आवश्यकता न हो।<sup>[[9]](#references)[[11]](#references)</sup>
3. **नई खाली directory** में extract करें। Untrusted members को ऐसे tree में merge न करें जिसमें attacker द्वारा बदले जा सकने वाले paths हों, और पहले के archive द्वारा बनाई गई directory का दोबारा उपयोग न करें।<sup>[[11]](#references)</sup>
4. Unix पर privileges drop करें और destination को **chroot/mount namespace** में isolate करें; Windows पर **AppContainer** या sandbox का उपयोग करें। केवल extraction के बाद scan करना पर्याप्त नहीं है, क्योंकि scan से पहले ही escape से write हो सकता है।<sup>[[11]](#references)</sup>
5. Custom code में target OS के separator/case/Unicode rules लागू करें और member तथा link target, दोनों को validate करें। Links follow किए बिना destination को resolve और open करें; containment check को बाद के create/replace operation से अलग न करें। Validator को write path वाले ठीक उसी base और link-emulation semantics का उपयोग करना चाहिए।<sup>[[11]](#references)[[12]](#references)</sup>

## अन्य प्रभावित / ऐतिहासिक मामले

* 2018 – Snyk की व्यापक *Zip-Slip* advisory, जिसने कई Java/Go/JS libraries को प्रभावित किया।<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) में slugs के TAR extraction traversal की समस्या (v0.16.3 में ठीक की गई)।<sup>[[7]](#references)</sup>
* कोई भी custom extraction logic जो header strings को validate करता हो, लेकिन link targets और हर write के लिए उपयोग किए गए अंतिम filesystem path को नहीं।<sup>[[11]](#references)[[12]](#references)</sup>





## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – .NET में Zip Slip से बचाव](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – WinRAR tools अभी update करें: RomCom और अन्य zero-day vulnerability का exploit कर रहे हैं (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Critical Arbitrary File Overwrite Vulnerability का सार्वजनिक खुलासा: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug, Zip Slip Attack (CVE-2025-0377) के प्रति Vulnerable](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine Method](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar के secure extraction flags](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – 7-Zip में CVE-2025-11001 के लिए Proof-of-Concept Exploit की रिपोर्ट](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – zip-slips, tar-slips, symlinks, hardlinks, collisions और अन्य के साथ hacking का मज़ा](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – CVE-2026-11940 tarfile extraction filter bypass](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
- [13] [GitHub Security Advisory – symlink chain के ज़रिए node-tar hardlink target escape](https://github.com/isaacs/node-tar/security/advisories/GHSA-83g3-92jg-28cx)
- [14] [Rhino Security Labs CVE PoC – user-controlled SCORM extraction root](https://raw.githubusercontent.com/RhinoSecurityLabs/CVEs/master/CVE-2026-39405/README.md)
- [15] [Rhino Security Labs – Frappe LMS में कई Vulnerabilities, जिनसे Remote Code Execution संभव होता है](https://rhinosecuritylabs.com/research/multiple-vulnerabilities-in-frappe-lms-leading-to-remote-code-execution/)
{{#include ../banners/hacktricks-training.md}}
