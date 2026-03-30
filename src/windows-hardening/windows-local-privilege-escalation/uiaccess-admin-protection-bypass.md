# Обходи Admin Protection через UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Огляд
- Windows AppInfo надає `RAiLaunchAdminProcess` для запуску процесів UIAccess (призначено для accessibility). UIAccess обходить більшість UIPI-фільтрів повідомлень інтерфейсу, щоб програми доступності могли керувати UI з вищим IL.
- Увімкнення UIAccess напряму вимагає `NtSetInformationToken(TokenUIAccess)` з **SeTcbPrivilege**, тому викликачі з низькими привілеями покладаються на сервіс. Сервіс виконує три перевірки цільового бінарника перед встановленням UIAccess:
  - Вбудований manifest містить `uiAccess="true"`.
  - Підписаний будь-яким сертифікатом, якому довіряє Local Machine root store (без вимоги EKU/Microsoft).
  - Розташований у шляху доступному лише адміністраторам на системному диску (наприклад, `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, за винятком конкретних записуваних підшляхів).
- `RAiLaunchAdminProcess` не показує жодного consent prompt для запусків UIAccess (інакше інструменти доступності не могли б взаємодіяти з prompt).

## Формування токена та рівні цілісності
- Якщо перевірки пройдені, AppInfo **копіює токен виклику**, вмикає UIAccess і підвищує Integrity Level (IL):
  - Limited admin user (користувач входить до Administrators але запускається з фільтром) ➜ **High IL**.
  - Non-admin user ➜ IL підвищується на **+16 рівнів** до обмеження **High** (System IL ніколи не присвоюється).
- Якщо токен виклику вже має UIAccess, IL залишається незмінним.
- Трюк «Ratchet»: процес UIAccess може вимкнути UIAccess у себе, перезапуститися через `RAiLaunchAdminProcess` і отримати ще одне збільшення IL на +16. Medium➜High вимагає 255 перезапусків (шумно, але працює).

## Чому UIAccess дозволяє обхід Admin Protection
- UIAccess дозволяє процесу з нижчим IL відправляти віконні повідомлення вікнам з вищим IL (обхід UIPI-фільтрів). При **рівних IL** класичні UI-примітиви, як `SetWindowsHookEx`, **дозволяють інжекцію коду/завантаження DLL** в будь-який процес, що володіє вікном (включаючи **message-only windows**, які використовуються COM).
- Admin Protection запускає процес UIAccess під особою **limited user**, але на **High IL**, без індикації. Як тільки довільний код виконається всередині цього High-IL UIAccess процесу, атакуючий може інжектитися в інші High-IL процеси на робочому столі (навіть тих, що належать іншим користувачам), порушуючи передбачувану ізоляцію.

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- На Windows 10 1803+ API переміщено в Win32k (`NtUserGetWindowProcessHandle`) і може відкривати handle процеса, використовуючи бажаний `DesiredAccess`, наданий викликачем. Шлях в ядрі використовує `ObOpenObjectByPointer(..., KernelMode, ...)`, що обходить звичні user-mode перевірки доступу.
- Передумови на практиці: цільове вікно має бути на тому ж робочому столі, і UIPI-перевірки мають пройти. Історично викликач з UIAccess міг обійти UIPI-фейл і все одно отримати kernel-mode handle (виправлено як CVE-2023-41772).
- Вплив: дескриптор вікна стає **здатністю** отримати потужний handle процеса (зазвичай `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`), який викликач зазвичай не міг би відкрити. Це дозволяє доступ між сандбоксами і може порушити межі Protected Process / PPL, якщо ціль експонує будь-яке вікно (включаючи message-only windows).
- Практичний сценарій зловживання: перерахувати або знайти HWND (наприклад, `EnumWindows`/`FindWindowEx`), визначити PID власника (`GetWindowThreadProcessId`), викликати `GetProcessHandleFromHwnd`, а потім використовувати повернутий handle для читання/запису пам'яті або примітивів захоплення коду.
- Поведінка після виправлення: UIAccess більше не дає kernel-mode відкриттів при UIPI-фейлі, і дозволені права доступу обмежені до набору прав, необхідних для legacy hooks; Windows 11 24H2 додає перевірки захисту процесу і feature-flagged безпечні шляхи. Вимкнення UIPI для всієї системи (`EnforceUIPI=0`) послаблює ці захисти.

## Уразливості в перевірці захищених директорій (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo отримує остаточний шлях через `GetFinalPathNameByHandle` і потім застосовує **рядкові allow/deny перевірки** проти захардкоджених коренів/виключень. Від кількох спрощень у валідації походять такі обходи:
- **Directory named streams**: виключені записувані директорії (наприклад, `C:\Windows\tracing`) можна обійти за допомогою named stream на самій директорії, напр. `C:\Windows\tracing:file.exe`. Рядкові перевірки бачать `C:\Windows\` і пропускають виключений підшлях.
- **Записуваний файл/директорія всередині дозволеного кореня**: `CreateProcessAsUser` **не вимагає розширення `.exe`**. Перезапис будь-якого записуваного файлу під дозволеним коренем виконуваним payload-ом працює, або копіювання підписаного EXE з `uiAccess="true"` у будь-яку записувану піддиректорію (наприклад, залишки оновлення як `Tasks_Migrated`, коли вони присутні) дозволяє пройти перевірку secure-path.
- **MSIX into `C:\Program Files\WindowsApps` (fixed)**: non-admins могли інсталювати підписані MSIX пакети, які потрапляли в `WindowsApps`, що не було виключено. Запаковування UIAccess бінарника в MSIX і запуск його через `RAiLaunchAdminProcess` призводив до **promptless High-IL UIAccess процесу**. Microsoft виправили це, виключивши цей шлях; сама обмежена можливість `uiAccess` у MSIX вже вимагає admin install.

## Сценарій атаки (High IL без підказки)
1. Отримати/сконструювати **signed UIAccess binary** (manifest `uiAccess="true"`).
2. Помістити його туди, куди AppInfo дозволяє (або зловживати помилкою в валідації шляху/записуваним артефактом як вище).
3. Викликати `RAiLaunchAdminProcess`, щоб запустити його **безшумно** з UIAccess + підвищеним IL.
4. З цього High-IL плацдарму таргетувати інший High-IL процес на робочому столі за допомогою **window hooks/DLL injection** або інших same-IL примітивів, щоб повністю скомпрометувати контекст адміністратора.

## Перелік кандидатних записуваних шляхів
Запустіть helper на PowerShell, щоб виявити записувані/перезаписувані об’єкти всередині номінально secure roots з перспективи обраного токена:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Запускайте від імені Адміністратора для ширшої видимості; встановіть `-ProcessId` на процес з низькими привілеями, щоб відобразити доступ цього токена.
- Фільтруйте вручну, щоб виключити відомі заборонені підкаталоги перед використанням кандидатів з `RAiLaunchAdminProcess`.

## Пов'язані

Поширення запису реєстру доступності Secure Desktop — LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## Посилання
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
