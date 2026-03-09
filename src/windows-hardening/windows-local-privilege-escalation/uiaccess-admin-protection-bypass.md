# Обхід Admin Protection через UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Огляд
- Windows AppInfo відкриває доступ до `RAiLaunchAdminProcess` для запуску UIAccess-процесів (призначено для accessibility). UIAccess обходить більшість фільтрації повідомлень User Interface Privilege Isolation (UIPI), дозволяючи програмам доступності керувати UI з вищим IL.
- Пряме увімкнення UIAccess вимагає `NtSetInformationToken(TokenUIAccess)` з **SeTcbPrivilege**, тому виклики з низькими привілеями покладаються на сервіс. Сервіс виконує три перевірки цільового бінарника перед встановленням UIAccess:
  - Вбудований manifest містить `uiAccess="true"`.
  - Підписаний будь-яким сертифікатом, якому довіряє Local Machine root store (без обов’язкового EKU/Microsoft).
  - Розташований у шляху, доступному тільки адміністраторам, на системному диску (наприклад, `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, за винятком певних підшляхів з правом запису).
- `RAiLaunchAdminProcess` не показує prompt згоди для запусків з UIAccess (інакше інструменти доступності не могли б керувати prompt).

## Формування токена та рівні інтеграції (integrity levels)
- Якщо перевірки пройдені, AppInfo **копіює токен викликуча**, вмикає UIAccess і підвищує Integrity Level (IL):
  - Limited admin user (user is in Administrators but running filtered) ➜ **High IL**.
  - Non-admin user ➜ IL підвищується на **+16 levels** до межі **High** (System IL ніколи не призначається).
- Якщо токен викликуча вже має UIAccess, IL залишається без змін.
- Трик «ratchet»: процес з UIAccess може вимкнути UIAccess для себе, перезапуститися через `RAiLaunchAdminProcess` і отримати ще одне підвищення IL на +16. Medium➜High вимагає 255 перезапусків (шумно, але працює).

## Чому UIAccess дозволяє обійти Admin Protection
- UIAccess дозволяє процесу з нижчим IL надсилати віконні повідомлення вікнам з вищим IL (обхід UIPI-фільтрів). При **рівних IL** класичні UI-примітиви, такі як `SetWindowsHookEx`, **дозволяють ін’єкцію коду/завантаження DLL** у будь-який процес, що володіє вікном (включно з **message-only windows**, які використовує COM).
- Admin Protection запускає UIAccess-процес під особистістю обмеженого користувача, але на **High IL**, приховано. Як тільки в цьому High-IL UIAccess-процесі виконується довільний код, атакуючий може інжектуватися в інші High-IL процеси на робочому столі (навіть належні іншим користувачам), порушуючи заплановане розділення.

## Примітив HWND-to-process handle (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- На Windows 10 1803+ API перемістили в Win32k (`NtUserGetWindowProcessHandle`) і воно може відкрити handle процесу з використанням `DesiredAccess`, який подає викликач. Шлях ядра використовує `ObOpenObjectByPointer(..., KernelMode, ...)`, що обходить звичайні юзер-модові перевірки доступу.
- Передумови на практиці: цільове вікно має бути на тому ж десктопі, і UIPI-перевірки мають пройти. Історично викличач з UIAccess міг обійти UIPI-проблему і все ще отримати kernel-mode handle (виправлено як CVE-2023-41772).
- Наслідок: дескриптор вікна стає **здатністю (capability)** отримати потужний handle процесу (зазвичай `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`), який викличач зазвичай не міг би відкрити. Це дозволяє доступ між сандбоксами і може порушити межі Protected Process / PPL, якщо ціль експонує будь-яке вікно (включно з message-only windows).
- Практичний шлях зловживання: перерахувати або знайти HWNDs (наприклад, `EnumWindows`/`FindWindowEx`), визначити власний PID (`GetWindowThreadProcessId`), викликати `GetProcessHandleFromHwnd`, а потім використати повернений handle для читання/запису пам’яті або примітивів перехоплення коду.
- Після виправлення: UIAccess більше не дає kernel-mode відкриттів при UIPI-фейлі й дозволені права доступу обмежено до набору для legacy hooks; Windows 11 24H2 додає перевірки захисту процесу і feature-flagged безпечніші шляхи. Вимкнення UIPI для всієї системи (`EnforceUIPI=0`) послаблює ці захисти.

## Слабкі місця в перевірці захищених директорій (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo приводить поданий шлях через `GetFinalPathNameByHandle`, а потім застосовує **строкові allow/deny перевірки** проти жорстко закодованих коренів/винятків. Від цієї примітивної валідації походять кілька класів обхідних шляхів:
- **Directory named streams**: Виключені директорії з правом запису (наприклад, `C:\Windows\tracing`) можна обійти за допомогою named stream на самій директорії, наприклад `C:\Windows\tracing:file.exe`. Строкові перевірки бачать `C:\Windows\` і пропускають виключений підшлях.
- **Файл/директорія з правом запису всередині дозволеного кореня**: `CreateProcessAsUser` **не вимагає `.exe` розширення**. Перезапис будь-якого записуваного файлу під дозволеним коренем виконуваним payload’ом працює, або копіювання підписаного EXE з `uiAccess="true"` у будь-яку записувану піддиректорію (наприклад, залишки оновлень як `Tasks_Migrated`, коли присутні) дозволяє пройти перевірку secure-path.
- **MSIX у `C:\Program Files\WindowsApps` (виправлено)**: Неадміні могли встановлювати підписані MSIX пакети, що потрапляли в `WindowsApps`, який не був виключений. Упакування UIAccess бінарника в MSIX і запуск його через `RAiLaunchAdminProcess` давав **безпомилковий High-IL UIAccess процес**. Microsoft пом’якшив це, виключивши цей шлях; можливість `uiAccess` для MSIX уже вимагала адмін-інсталяції.

## Сценарій атаки (High IL без prompt)
1. Отримати/зробити **signed UIAccess binary** (manifest `uiAccess="true"`).
2. Помістити його туди, куди AppInfo’s allowlist приймає (або зловживати уразливістю перевірки шляху/записуваним артефактом, як вище).
3. Викликати `RAiLaunchAdminProcess` для його **безшумного** запуску з UIAccess + підвищеним IL.
4. З цієї High-IL опори атакувати інший High-IL процес на робочому столі, використовуючи **window hooks/DLL injection** або інші примітиви same-IL, щоб повністю скомпрометувати адмін-контекст.

## Перерахунок кандидатів на записувані шляхи
Запустіть PowerShell helper, щоб знайти записувані/перезаписувані об’єкти всередині номінально захищених коренів з перспективи обраного токена:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Run as Administrator для ширшої видимості; встановіть `-ProcessId` на low-priv process, щоб відобразити доступ цього token.
- Фільтруйте вручну, щоб виключити відомі заборонені підкаталоги перед використанням кандидатів з `RAiLaunchAdminProcess`.

## Джерела
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
