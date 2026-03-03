# Admin Protection Bypasses via UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Огляд
- Windows AppInfo надає `RAiLaunchAdminProcess` для запуску UIAccess процесів (призначених для accessibility). UIAccess обминає більшість фільтрів User Interface Privilege Isolation (UIPI) для того, щоб accessibility софт міг керувати UI з вищим IL.
- Пряме увімкнення UIAccess вимагає `NtSetInformationToken(TokenUIAccess)` з **SeTcbPrivilege**, тому процеси з низькими привілеями покладаються на сервіс. Сервіс виконує три перевірки цільового бінарника перед встановленням UIAccess:
- Вбудований manifest містить `uiAccess="true"`.
- Підписаний будь-яким сертифікатом, довіреним Local Machine root store (без вимоги EKU/Microsoft).
- Розташований в директорії, доступній лише адміністраторам на системному диску (наприклад, `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, виключаючи конкретні підшляхи з правом запису).
- `RAiLaunchAdminProcess` не показує consent prompt для UIAccess запусків (інакше accessibility інструменти не могли б керувати prompt).

## Формування токену та рівні інтеґриті (Integrity Levels)
- Якщо перевірки проходять, AppInfo **копіює токен виклику**, вмикає UIAccess і піднімає Integrity Level (IL):
- Limited admin user (користувач в Administrators, але запуск з фільтрацією) ➜ **High IL**.
- Non-admin user ➜ IL збільшується на **+16 рівнів** до обмеження **High** (System IL ніколи не присвоюється).
- Якщо токен виклику вже має UIAccess, IL не змінюється.
- Трюк “Ratchet”: UIAccess процес може відключити UIAccess на собі, перезапуститися через `RAiLaunchAdminProcess` і отримати ще +16 IL. Medium➜High вимагає 255 перезапусків (шумно, але працює).

## Чому UIAccess дозволяє обхід Admin Protection
- UIAccess дозволяє процесу з нижчим IL надсилати window messages в вікна з вищим IL (обминаючи UIPI фільтри). На **рівних IL**, класичні UI примітиви як `SetWindowsHookEx` **дозволяють інжекцію коду/завантаження DLL** в будь-який процес, що володіє вікном (включно з **message-only windows**, які використовує COM).
- Admin Protection запускає UIAccess процес під особою обмеженого користувача, але на **High IL**, тихо. Як тільки довільний код виконується всередині цього High-IL UIAccess процесу, нападник може інжектити в інші High-IL процеси на десктопі (навіть ті, що належать іншим користувачам), порушуючи задуману ізоляцію.

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- На Windows 10 1803+ API перейшов у Win32k (`NtUserGetWindowProcessHandle`) і може відкрити process handle з використанням `DesiredAccess`, заданого викликачем. Шлях у kernel використовує `ObOpenObjectByPointer(..., KernelMode, ...)`, що обминає звичайні user-mode перевірки доступу.
- Передумови на практиці: цільове вікно має бути на тій самій десктоп-сесії, і UIPI перевірки повинні пройти. Історично викликач з UIAccess міг обійти UIPI відмову і все ще отримати kernel-mode handle (виправлено як CVE-2023-41772).
- Вплив: handle вікна стає **capability** для отримання потужного process handle (зазвичай `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`), який викликач зазвичай не зміг би відкрити. Це дозволяє доступ через сандбокси і може порушити Protected Process / PPL межі, якщо ціль відкриває будь-яке вікно (включно з message-only windows).
- Практичний сценарій зловживання: перелічити або знайти HWNDs (наприклад, `EnumWindows`/`FindWindowEx`), визначити PID власника (`GetWindowThreadProcessId`), викликати `GetProcessHandleFromHwnd`, потім використовувати повернений handle для читання/запису пам’яті або примітивів захоплення коду.
- Післяпатчеве поводження: UIAccess більше не дає kernel-mode відкриттів при UIPI-відмові, і дозволені права доступу обмежені до набору для legacy hook; Windows 11 24H2 додає перевірки захисту процесу і feature-flagged безпечніші шляхи. Вимкнення UIPI системно (`EnforceUIPI=0`) послаблює ці захисти.

## Слабкості перевірки безпечних директорій (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo отримує остаточний шлях через `GetFinalPathNameByHandle` і потім застосовує **рядкові allow/deny перевірки** проти хардкоджених коренів/винятків. Від цієї спрощеної валідації походять кілька класів обхідних шляхів:
- **Directory named streams**: Виключені директорії з правом запису (наприклад, `C:\Windows\tracing`) можна обійти за допомогою named stream на самій директорії, напр. `C:\Windows\tracing:file.exe`. Рядкові перевірки бачать `C:\Windows\` і пропускають пропуск підшляху.
- **Файл/директорія з правом запису всередині дозволеного кореня**: `CreateProcessAsUser` **не вимагає `.exe` розширення**. Перезапис будь-якого файлу з правом запису під дозволеним коренем виконуваним payload-ом працює, або копіювання підписаного EXE з `uiAccess="true"` у будь-який записуваний підкаталог (наприклад, залишки оновлень як `Tasks_Migrated`, коли присутні) дозволяє пройти secure-path перевірку.
- **MSIX у `C:\Program Files\WindowsApps` (запатчено)**: Non-admin могли встановлювати підписані MSIX пакети, що розміщувалися в `WindowsApps`, який не був виключений. Запаковування UIAccess бінарника в MSIX і запуск його через `RAiLaunchAdminProcess` давав **promptless High-IL UIAccess процес**. Microsoft пом’якшив шлях виключивши цей шлях; обмежена можливість `uiAccess` у MSIX сама по собі вже вимагає admin install.

## Сценарій атаки (High IL без prompt)
1. Отримати/згенерувати **підписаний UIAccess бінарник** (manifest `uiAccess="true"`).
2. Помістити його туди, куди AppInfo allowlist його приймає (або зловживати вразливістю в перевірці шляху/записуваним артефактом як вище).
3. Викликати `RAiLaunchAdminProcess` щоб запустити його **тихо** з UIAccess + підвищеним IL.
4. З цього High-IL плацдарму цілитися на інший High-IL процес на десктопі використовуючи **window hooks/DLL injection** або інші same-IL примітиви для повного компромету контексту адміністратора.

## Перелічення кандидатів на записувані шляхи
Запустіть PowerShell helper щоб знайти записувані/перезаписувані об’єкти в іменованих secure коренях з перспективи обраного токена:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Запустіть від імені Адміністратора для кращої видимості; встановіть `-ProcessId` на процес з низькими привілеями, щоб відтворити доступ цього токена.
- Фільтруйте вручну, щоб виключити відомі заборонені підкаталоги перед використанням кандидатів з `RAiLaunchAdminProcess`.

## Посилання
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
