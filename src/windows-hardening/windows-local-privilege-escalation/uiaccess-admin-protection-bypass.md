# Admin Protection Bypasses via UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Огляд
- Windows AppInfo exposes `RAiLaunchAdminProcess` to spawn UIAccess processes (intended for accessibility). UIAccess обходить більшість фільтрації повідомлень User Interface Privilege Isolation (UIPI), щоб програмне забезпечення доступності могло керувати інтерфейсом вищого IL.
- Пряме ввімкнення UIAccess вимагає виклику `NtSetInformationToken(TokenUIAccess)` з **SeTcbPrivilege**, тому процеси з низькими привілеями покладаються на сервіс. Сервіс виконує три перевірки цільового бінарника перед встановленням UIAccess:
- Вбудований манифест містить `uiAccess="true"`.
- Підписано сертифікатом, довіреним сховищем Local Machine root (без вимоги EKU/Microsoft).
- Розташовано в шляху, доступному лише адміністраторам на системному диску (наприклад, `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, за винятком певних записуваних підшляхів).
- `RAiLaunchAdminProcess` не показує запит згоди для запусків з UIAccess (в іншому випадку інструменти доступності не змогли б взаємодіяти з таким запитом).

## Формування токена та рівні цілісності
- Якщо перевірки проходять, AppInfo **копіює токен викликача**, вмикає UIAccess і підвищує Integrity Level (IL):
- Limited admin user (user is in Administrators but running filtered) ➜ **High IL**.
- Non-admin user ➜ IL підвищується на **+16 рівнів** до обмеження **High** (System IL ніколи не присвоюється).
- Якщо токен викликача вже має UIAccess, IL залишається без змін.
- “Ratchet” trick: процес з UIAccess може вимкнути UIAccess для себе, перезапуститися через `RAiLaunchAdminProcess` і отримати ще одне підвищення IL на +16. Medium➜High вимагає 255 перезапусків (шумно, але працює).

## Чому UIAccess дозволяє обійти Admin Protection
- UIAccess дозволяє процесу з нижчим IL надсилати віконні повідомлення вікнам з вищим IL (обходячи UIPI). За **рівних IL**, класичні UI-примітиви типу `SetWindowsHookEx` **дозволяють інжект коду/завантаження DLL** у будь-який процес, який володіє вікном (включно з **message-only windows**, які використовує COM).
- Admin Protection запускає UIAccess процес під **ідентичністю обмеженого користувача**, але на **High IL**, без повідомлення. Як тільки будь-який довільний код запуститься в цьому High-IL UIAccess процесі, нападник може інжектнути в інші High-IL процеси на робочому столі (навіть ті, що належать іншим користувачам), порушуючи передбачену ізоляцію.

## Слабкі місця перевірки захищених директорій (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo вирішує переданий шлях через `GetFinalPathNameByHandle`, а потім застосовує **рядкові allow/deny перевірки** проти захардкоджених коренів/винятків. Кілька класів обходу походять від такої спрощеної валідації:
- **Directory named streams**: Виключені записувані директорії (наприклад, `C:\Windows\tracing`) можна обійти за допомогою named stream на самій директорії, наприклад `C:\Windows\tracing:file.exe`. Рядкові перевірки бачать `C:\Windows\` і пропускають виключений підшлях.
- **Writable file/directory inside an allowed root**: `CreateProcessAsUser` **не вимагає розширення `.exe`**. Перезапис будь-якого записуваного файлу під дозволеним коренем виконуваним payload-ом працює, або копіювання підписаного EXE з `uiAccess="true"` у будь-яку записувану піддиректорію (наприклад, залишки оновлень такі як `Tasks_Migrated`, коли присутні) дозволяє пройти перевірку захищеного шляху.
- **MSIX into `C:\Program Files\WindowsApps` (fixed)**: Не-адміні могли встановлювати підписані MSIX пакети, що потрапляли в `WindowsApps`, який не був виключений. Упакування UIAccess бінарника всередині MSIX і його запуск через `RAiLaunchAdminProcess` призводило до **promptless High-IL UIAccess процесу**. Microsoft пом’якшила проблему, виключивши цей шлях; сам обмежений capability `uiAccess` для MSIX уже вимагає інсталяції з правами адміністратора.

## Сценарій атаки (High IL без запиту)
1. Отримати/збудувати **signed UIAccess binary** (манифест `uiAccess="true"`).
2. Помістити його туди, куди дозволяє allowlist AppInfo (або скористатися помилкою в перевірці шляху/доступним записуваним артефактом, як описано вище).
3. Викликати `RAiLaunchAdminProcess`, щоб запустити його **без повідомлення** з UIAccess + підвищеним IL.
4. З цієї High-IL опори цілитися в інший High-IL процес на робочому столі за допомогою **віконних хуків/DLL injection** або інших примітивів same-IL, щоб повністю скомпрометувати контекст адміністратора.

## Перерахунок кандидатних записуваних шляхів
Запустіть PowerShell helper, щоб виявити записувані/перезаписувані об’єкти всередині номінально захищених коренів з перспективи обраного токена:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Запустіть як Administrator для кращої видимості; встановіть `-ProcessId` на low-priv process, щоб віддзеркалити доступ цього токена.
- Фільтруйте вручну, щоб виключити відомі недозволені підкаталоги перед використанням кандидатів з `RAiLaunchAdminProcess`.

## Посилання
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
