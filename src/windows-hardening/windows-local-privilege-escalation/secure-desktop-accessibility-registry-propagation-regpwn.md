# Secure Desktop Accessibility Registry Propagation LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## Огляд

Функції Accessibility зберігають конфігурацію користувача в HKCU і поширюють її до розташувань HKLM для окремих сесій. Під час переходу до **Secure Desktop** (екран блокування або запит UAC) компоненти **SYSTEM** повторно копіюють ці значення. Якщо **per-session HKLM key доступний для запису користувачу**, він стає привілейованою точкою запису, яку можна перенаправити за допомогою **registry symbolic links**, отримавши **довільний запис до реєстру від імені SYSTEM**.<sup>[[1]](#references)</sup>

Техніка RegPwn використовує цей ланцюжок поширення з невеликим вікном перегонів, стабілізованим за допомогою **opportunistic lock (oplock)** на файлі, який використовує `osk.exe`.<sup>[[1]](#references)</sup>

## Ланцюжок поширення реєстру (Accessibility -> Secure Desktop)

Приклад функції: **On-Screen Keyboard** (`osk`). Відповідні розташування:

- **Список функцій для всієї системи**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **Конфігурація користувача (доступна для запису користувачу)**:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **Конфігурація HKLM для окремої сесії (створюється `winlogon.exe`, доступна для запису користувачу)**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Secure desktop/default user hive (контекст SYSTEM)**:
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Поширення під час переходу до secure desktop (спрощено):

1. **User `atbroker.exe`** копіює `HKCU\...\ATConfig\osk` до `HKLM\...\Session<session id>\ATConfig\osk`.
2. **SYSTEM `atbroker.exe`** копіює `HKLM\...\Session<session id>\ATConfig\osk` до `HKU\.DEFAULT\...\ATConfig\osk`.
3. **SYSTEM `osk.exe`** копіює `HKU\.DEFAULT\...\ATConfig\osk` назад до `HKLM\...\Session<session id>\ATConfig\osk`.

Якщо subtree HKLM сесії доступне для запису користувачу, кроки 2/3 забезпечують запис від імені SYSTEM через розташування, яке користувач може замінити.<sup>[[1]](#references)</sup>

## Примітив: довільний запис до реєстру від імені SYSTEM через Registry Links

Замініть доступний для запису користувачу per-session key на **registry symbolic link**, що вказує на обране атакуючим призначення. Коли виконується копіювання від імені SYSTEM, воно переходить за посиланням і записує контрольовані атакуючим значення до довільного цільового ключа.

Ключова ідея:

- Ціль запису жертви (доступна для запису користувачу):
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- Атакуючий замінює цей ключ на **registry link** до будь-якого іншого ключа.
- SYSTEM виконує копіювання і записує дані до обраного атакуючим ключа з permissions SYSTEM.

Це забезпечує примітив **довільного запису до реєстру від імені SYSTEM**.<sup>[[1]](#references)</sup>

## Виграш вікна перегонів за допомогою Oplocks

Існує коротке часове вікно між запуском **SYSTEM `osk.exe`** і записом ключа для окремої сесії. Щоб зробити exploit надійним, він встановлює **oplock** на:
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
Коли спрацьовує oplock, attacker замінює per-session ключ HKLM на registry link, дозволяє запису SYSTEM завершитися, а потім видаляє link.<sup>[[1]](#references)</sup>

## Приклад Exploitation Flow (High Level)

1. Отримати поточний **ідентифікатор сесії** з access token.
2. Запустити прихований екземпляр `osk.exe` і ненадовго призупинити виконання (щоб забезпечити спрацювання oplock).
3. Записати контрольовані attacker значення до:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. Встановити **oplock** на `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`.
5. Запустити **Secure Desktop** (`LockWorkstation()`), що спричинить запуск `atbroker.exe` / `osk.exe` від імені SYSTEM.
6. Після спрацювання oplock замінити `HKLM\...\Session<session id>\ATConfig\osk` на **registry link**, що вказує на довільну ціль.
7. Ненадовго зачекати завершення копіювання від SYSTEM, а потім видалити link.<sup>[[1]](#references)</sup>

## Перетворення Primitive на виконання від імені SYSTEM

Один простий ланцюжок полягає в перезаписі значення **конфігурації service** (наприклад, `ImagePath`), а потім запуску service. RegPwn PoC перезаписує `ImagePath` для **`msiserver`** і запускає його шляхом створення екземпляра **MSI COM object**, що призводить до виконання коду від імені **SYSTEM**.<sup>[[1]](#references)[[2]](#references)</sup>

## Пов’язані матеріали

Інформацію про інші типи поведінки Secure Desktop / UIAccess див. у:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## Посилання

- [1] [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [2] [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)

{{#include ../../banners/hacktricks-training.md}}
