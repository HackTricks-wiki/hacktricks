# Обхід захисту адміністратора через UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Огляд
- Windows AppInfo надає `RAiLaunchAdminProcess` для запуску UIAccess-процесів (призначених для accessibility). UIAccess обходить більшість фільтрів повідомлень User Interface Privilege Isolation (UIPI), щоб accessibility software могло керувати UI з вищим IL.
- Для прямого увімкнення UIAccess потрібен `NtSetInformationToken(TokenUIAccess)` із **SeTcbPrivilege**, тому callers із низькими привілеями покладаються на service. Перед встановленням UIAccess service виконує три перевірки цільового binary:
- Вбудований manifest містить `uiAccess="true"`.
- Підписаний будь-яким certificate, якому довіряє root store Local Machine (вимога EKU/Microsoft відсутня).
- Розташований у шляху, доступному лише адміністраторам, на системному диску (наприклад, `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`), за винятком певних writable subpaths.
- `RAiLaunchAdminProcess` не показує consent prompt для запусків UIAccess (інакше accessibility tooling не могло б керувати prompt).<sup>[[1]](#references)</sup>

## Формування token та рівні цілісності
- Якщо перевірки успішні, AppInfo **копіює token caller**, вмикає UIAccess і підвищує Integrity Level (IL):
- Limited admin user (користувач входить до Administrators, але працює з filtered token) ➜ **High IL**.
- Non-admin user ➜ IL збільшується на **+16 рівнів** до обмеження **High** (System IL ніколи не призначається).
- Якщо token caller уже має UIAccess, IL залишається без змін.
- Трюк із “ratchet”: UIAccess-процес може вимкнути UIAccess для себе, повторно запуститися через `RAiLaunchAdminProcess` і отримати ще одне збільшення IL на +16. Для переходу Medium➜High потрібно 255 повторних запусків (шумно, але працює).<sup>[[1]](#references)</sup>

## Чому UIAccess дає змогу обійти Admin Protection
- UIAccess дає змогу процесу з нижчим IL надсилати window messages до вікон із вищим IL (обходячи UIPI filters). За **однакового IL** класичні UI primitives, як-от `SetWindowsHookEx`, **дозволяють code injection/DLL loading** у будь-який process, що володіє вікном (зокрема **message-only windows**, які використовуються COM).
- Admin Protection запускає UIAccess process від імені **limited user**, але з **High IL**, без prompt. Щойно довільний code виконується всередині цього High-IL UIAccess process, attacker може виконати injection в інші High-IL processes на desktop (навіть такі, що належать іншим користувачам), руйнуючи задумане розділення.<sup>[[1]](#references)</sup>

## Примітив отримання handle process за HWND (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- У Windows 10 1803+ API було переміщено до Win32k (`NtUserGetWindowProcessHandle`) і може відкрити handle process, використовуючи переданий caller-ом `DesiredAccess`. Kernel path використовує `ObOpenObjectByPointer(..., KernelMode, ...)`, що обходить звичайні access checks у user mode.<sup>[[2]](#references)</sup>
- Практичні передумови: target window має бути на тому самому desktop, а UIPI checks мають пройти. Історично caller із UIAccess міг обійти помилку UIPI й усе одно отримати kernel-mode handle (виправлено в CVE-2023-41772).
- Вплив: window handle стає **capability** для отримання потужного process handle (зазвичай `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`), який caller зазвичай не міг відкрити. Це дає змогу отримати cross-sandbox access і може зруйнувати межі Protected Process / PPL, якщо target відкриває будь-яке вікно (зокрема message-only windows).
- Практичний flow abuse: перерахувати або знайти HWND (наприклад, через `EnumWindows`/`FindWindowEx`), визначити PID-власник (`GetWindowThreadProcessId`), викликати `GetProcessHandleFromHwnd`, а потім використати отриманий handle для memory read/write або code-hijack primitives.
- Поведінка після fix: UIAccess більше не надає kernel-mode opens у разі помилки UIPI, а дозволені access rights обмежено legacy hook set; Windows 11 24H2 додає process-protection checks і безпечніші paths, керовані feature flags. Загальносистемне вимкнення UIPI (`EnforceUIPI=0`) послаблює ці protections.<sup>[[2]](#references)</sup>

## Недоліки валідації secure directory (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo визначає supplied path через `GetFinalPathNameByHandle`, а потім застосовує **string allow/deny checks** до hardcoded roots/exclusions. Кілька класів bypass випливають із цієї спрощеної валідації:
- **Named streams директорій**: Excluded writable directories (наприклад, `C:\Windows\tracing`) можна обійти за допомогою named stream безпосередньо в директорії, наприклад `C:\Windows\tracing:file.exe`. String checks бачать `C:\Windows\` і пропускають excluded subpath.
- **Writable file/directory всередині дозволеного root**: `CreateProcessAsUser` **не вимагає розширення `.exe`**. Перезапис будь-якого writable file у дозволеному root executable payload-ом працює, або копіювання підписаного EXE з `uiAccess="true"` у будь-який writable subdirectory (наприклад, залишки update на кшталт `Tasks_Migrated`, якщо вони присутні) дає йому змогу пройти secure-path check.
- **MSIX у `C:\Program Files\WindowsApps` (виправлено)**: Non-admins могли встановлювати підписані MSIX packages, які потрапляли до `WindowsApps`, що не було виключено. Якщо упакувати UIAccess binary всередині MSIX, а потім запустити його через `RAiLaunchAdminProcess`, можна було отримати **High-IL UIAccess process без prompt**. Microsoft усунула проблему, виключивши цей path; сама restricted MSIX capability `uiAccess` уже вимагає встановлення адміністратором.<sup>[[1]](#references)</sup>

## Workflow атаки (High IL без prompt)
1. Отримати/зібрати **підписаний UIAccess binary** (manifest `uiAccess="true"`).
2. Розмістити його там, де AppInfo приймає його allowlist (або використати edge case валідації path/writable artifact, описаний вище).
3. Викликати `RAiLaunchAdminProcess`, щоб **безшумно** запустити його з UIAccess + elevated IL.
4. Із цього High-IL foothold атакувати інший High-IL process на desktop за допомогою **window hooks/DLL injection** або інших same-IL primitives, щоб повністю скомпрометувати admin context.<sup>[[1]](#references)</sup>

## Перелік потенційно writable paths
Запустіть PowerShell helper, щоб знайти writable/overwritable objects усередині номінально secure roots з perspective вибраного token:<sup>[[1]](#references)</sup>
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Запускайте від імені Administrator для ширшої видимості; задайте `-ProcessId` для процесу з низькими привілеями, щоб відтворити доступ цього токена.
- Вручну відфільтруйте відомі заборонені підкаталоги, перш ніж використовувати кандидатів із `RAiLaunchAdminProcess`.

## Пов’язані матеріали

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## Посилання

- [1] [Обхід Administrator Protection через зловживання UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [Поглиблений розбір GetProcessHandleFromHwnd (GPHFH)](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
