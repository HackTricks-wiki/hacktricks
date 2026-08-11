# Обхід Admin Protection через UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Огляд
- Windows AppInfo надає внутрішній шлях `RAiLaunchAdminProcess`, який використовується для запуску UIAccess applications для забезпечення доступності. UIAccess дозволяє вибраній взаємодії проходити через межі User Interface Privilege Isolation (UIPI); це не є загальним обходом усіх меж безпеки процесів.<sup>[[1]](#references)[[3]](#references)</sup>
- Безпосереднє ввімкнення UIAccess вимагає `NtSetInformationToken(TokenUIAccess)` із **SeTcbPrivilege**, тому low-priv callers покладаються на service. Service виконує три перевірки цільового binary перед встановленням UIAccess:
- Вбудований manifest містить `uiAccess="true"`.
- Підписаний будь-яким сертифікатом, якому довіряє Local Machine root store (без вимог щодо EKU/Microsoft).
- Розташований у шляху, доступному лише адміністраторам, на системному диску (наприклад, `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`), за винятком певних writable subpaths.
- `RAiLaunchAdminProcess` не показує consent prompt для запусків UIAccess (інакше accessibility tooling не могло б керувати prompt).<sup>[[1]](#references)</sup>

## Формування токена та рівні цілісності
- Якщо перевірки успішні, AppInfo **копіює caller token**, вмикає UIAccess і підвищує Integrity Level (IL):
- Limited admin user (user входить до Administrators, але працює у filtered режимі) ➜ **High IL**.
- Non-admin user ➜ IL збільшується на **+16 levels** до максимуму **High** (System IL ніколи не призначається).
- Якщо caller token уже має UIAccess, IL залишається без змін.
- Трюк із “ratchet”: UIAccess process може вимкнути UIAccess для себе, повторно запуститися через `RAiLaunchAdminProcess` і отримати ще одне збільшення IL на +16. Для переходу Medium➜High потрібно 255 relaunches (шумно, але працює).<sup>[[1]](#references)</sup>

## Чому UIAccess уможливлює escape з Admin Protection
- UIAccess дозволяє process із нижчим IL надсилати window messages до windows із вищим IL (обходячи UIPI filters). За **однакового IL** класичні UI primitives, як-от `SetWindowsHookEx`, **дозволяють code injection/DLL loading** у будь-який process, який володіє window (зокрема **message-only windows**, що використовуються COM).
- Admin Protection запускає UIAccess process від імені **limited user**, але з **High IL**, без prompt. Щойно arbitrary code виконується всередині цього High-IL UIAccess process, attacker може inject в інші High-IL processes на desktop (навіть якщо вони належать іншим users), руйнуючи заплановане розділення.<sup>[[1]](#references)</sup>

## Примітив handle від HWND до process (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- У Windows 10 1803+ API було переміщено до Win32k (`NtUserGetWindowProcessHandle`) і воно може відкрити process handle, використовуючи наданий caller-ом `DesiredAccess`. Kernel path використовує `ObOpenObjectByPointer(..., KernelMode, ...)`, що обходить звичайні user-mode access checks.<sup>[[2]](#references)</sup>
- Практичні передумови: target window має бути на тому самому desktop, а UIPI checks мають пройти. Історично caller із UIAccess міг обійти UIPI failure і все одно отримати kernel-mode handle (виправлено у CVE-2023-41772).
- Історичний вплив: window handle ставав **capability** для доступу до process, наприклад `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE` або `PROCESS_VM_OPERATION`, який caller зазвичай не міг отримати. До випуску документованих виправлень це могло долати межі sandbox і protected-process, якщо target відкривав window, зокрема message-only window.<sup>[[2]](#references)</sup>
- Практичний flow abuse: enumerate або locate HWNDs (наприклад, `EnumWindows`/`FindWindowEx`), визначити PID-власника (`GetWindowThreadProcessId`), викликати `GetProcessHandleFromHwnd`, а потім використати повернутий handle для memory read/write або code-hijack primitives.
- Поведінка після виправлення: UIAccess більше не надає kernel-mode opens у разі UIPI failure, а дозволені access rights обмежені legacy hook set; Windows 11 24H2 додає process-protection checks і safer paths, керовані feature flags. Вимкнення UIPI для всієї системи (`EnforceUIPI=0`) послаблює ці protections.<sup>[[2]](#references)</sup>

## Недоліки перевірки secure-directory (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo визначає supplied path через `GetFinalPathNameByHandle`, а потім застосовує **string allow/deny checks** до hardcoded roots/exclusions. Кілька класів bypass виникають через таку спрощену validation:
- **Directory named streams**: Excluded writable directories (наприклад, `C:\Windows\tracing`) можна обійти за допомогою named stream безпосередньо в directory, наприклад `C:\Windows\tracing:file.exe`. String checks бачать `C:\Windows\` і пропускають excluded subpath.
- **Writable file/directory всередині allowed root**: `CreateProcessAsUser` **не вимагає розширення `.exe`**. Перезапис будь-якого writable file всередині allowed root за допомогою executable payload працює, або копіювання signed `uiAccess="true"` EXE до будь-якого writable subdirectory (наприклад, update leftovers на кшталт `Tasks_Migrated`, якщо він присутній) дозволяє пройти secure-path check.
- **MSIX у `C:\Program Files\WindowsApps` (виправлено)**: Non-admins могли встановлювати signed MSIX packages, які потрапляли до `WindowsApps`, що не було виключено. Packaging UIAccess binary всередині MSIX із подальшим його запуском через `RAiLaunchAdminProcess` давав **promptless High-IL UIAccess process**. Microsoft усунула проблему, виключивши цей path; сама restricted MSIX capability `uiAccess` уже вимагає admin install.<sup>[[1]](#references)</sup>

## Attack workflow (High IL без prompt)
1. Отримати або зібрати **signed UIAccess binary** (manifest `uiAccess="true"`). Для реалістичної оцінки тестуйте з trust material і paths, явно authorized для lab; не додавайте attacker certificate до Local Machine root store production machine.
2. Розмістити його там, де AppInfo приймає його allowlist (або використати edge case перевірки path/writable artifact, як описано вище).
3. Викликати `RAiLaunchAdminProcess`, щоб **silently** запустити його з UIAccess + elevated IL.
4. Із цього High-IL foothold атакувати інший High-IL process на desktop, використовуючи **window hooks/DLL injection** або інші same-IL primitives, щоб повністю скомпрометувати admin context.<sup>[[1]](#references)</sup>

## Перелік потенційно writable paths
Запустіть PowerShell helper, щоб виявити writable/overwritable objects усередині nominally secure roots з perspective вибраного token:<sup>[[1]](#references)</sup>
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Запускайте від імені адміністратора для ширшої видимості; установіть `-ProcessId` для процесу з низькими привілеями, щоб відтворити доступ цього токена.
- Вручну відфільтруйте відомі заборонені підкаталоги, перш ніж використовувати знайдені кандидати з `RAiLaunchAdminProcess`.

## Пов'язані матеріали

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## References

- [1] [Обхід Administrator Protection через зловживання UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [Глибокий аналіз GetProcessHandleFromHwnd (GPHFH)](https://projectzero.google/2026/02/gphfh-deep-dive.html)
- [3] [Microsoft Learn — програми UIAccess](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works#uiaccess-applications)
{{#include ../../banners/hacktricks-training.md}}
