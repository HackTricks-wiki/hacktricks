# Secure Desktop Accessibility Registry Propagation LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## Огляд

Функції Windows Accessibility зберігають конфігурацію користувача в HKCU і поширюють її до розташувань HKLM для окремих сесій. Під час переходу до **Secure Desktop** (екран блокування або запит UAC) компоненти **SYSTEM** повторно копіюють ці значення. Якщо **per-session HKLM key** доступний для запису користувачу, він стає привілейованою точкою запису, яку можна перенаправити за допомогою **registry symbolic links**, отримавши **arbitrary SYSTEM registry write**.<sup>[[1]](#references)</sup>

Техніка RegPwn зловживає цим ланцюжком поширення за допомогою невеликого race window, стабілізованого через **opportunistic lock (oplock)** на файлі, який використовує `osk.exe`.<sup>[[1]](#references)</sup>

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

Поширення під час переходу до Secure Desktop (спрощено):

1. **User `atbroker.exe`** копіює `HKCU\...\ATConfig\osk` до `HKLM\...\Session<session id>\ATConfig\osk`.
2. **SYSTEM `atbroker.exe`** копіює `HKLM\...\Session<session id>\ATConfig\osk` до `HKU\.DEFAULT\...\ATConfig\osk`.
3. **SYSTEM `osk.exe`** копіює `HKU\.DEFAULT\...\ATConfig\osk` назад до `HKLM\...\Session<session id>\ATConfig\osk`.

Якщо subtree HKLM сесії доступний для запису користувачу, кроки 2/3 забезпечують запис SYSTEM через розташування, яке користувач може замінити.<sup>[[1]](#references)</sup>

## Примітив: Arbitrary SYSTEM Registry Write через Registry Links

Замініть доступний для запису користувачу ключ для окремої сесії на **registry symbolic link**, який вказує на обране attacker-ом призначення. Коли відбувається копіювання SYSTEM, воно переходить за link і записує контрольовані attacker-ом значення в довільний цільовий ключ.

Ключова ідея:

- Ціль запису victim-а (доступна для запису користувачу):
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- Attacker замінює цей ключ на **registry link** до будь-якого іншого ключа.
- SYSTEM виконує копіювання та записує дані в обраний attacker-ом ключ із дозволами SYSTEM.

Це забезпечує примітив **arbitrary SYSTEM registry write**.<sup>[[1]](#references)</sup>

## Виграш race window за допомогою Oplocks

Існує коротке timing window між запуском **SYSTEM `osk.exe`** і записом ключа для окремої сесії. Щоб зробити exploit надійним, він встановлює **oplock** на:
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
Коли спрацьовує oplock, attacker замінює per-session HKLM key на registry link, дозволяє запису SYSTEM відбутися, а потім видаляє link.<sup>[[1]](#references)</sup>

## Приклад перебігу Exploitation (на високому рівні)

1. Отримати поточний **session ID** з access token.
2. Запустити прихований екземпляр `osk.exe` і ненадовго призупинити виконання (щоб забезпечити спрацьовування oplock).
3. Записати контрольовані attacker-ом значення до:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. Встановити **oplock** на `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`.
5. Запустити **Secure Desktop** (`LockWorkstation()`), що спричинить запуск `atbroker.exe` / `osk.exe` від імені SYSTEM.
6. Після спрацьовування oplock замінити `HKLM\...\Session<session id>\ATConfig\osk` на **registry link**, що вказує на довільну ціль.
7. Ненадовго зачекати завершення копіювання від SYSTEM, а потім видалити link.<sup>[[1]](#references)</sup>

## Перетворення Primitive на виконання від імені SYSTEM

Один простий ланцюжок полягає в перезаписі значення **service configuration** (наприклад, `ImagePath`), а потім запуску service. RegPwn PoC перезаписує `ImagePath` служби **`msiserver`** і запускає її шляхом створення екземпляра **MSI COM object**, що призводить до виконання коду від імені **SYSTEM**.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

## Пов’язані матеріали

Щодо інших аспектів поведінки Secure Desktop / UIAccess дивіться:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## References

- [1] [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [2] [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)
{{#include ../../banners/hacktricks-training.md}}
