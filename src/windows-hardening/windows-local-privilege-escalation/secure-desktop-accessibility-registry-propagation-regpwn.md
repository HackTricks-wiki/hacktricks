# Secure Desktop Accessibility Registry Propagation LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## Огляд

Функції Accessibility у Windows зберігають конфігурацію користувача під HKCU і поширюють її в пер-сесійнi локації HKLM. Під час переходу на **Secure Desktop** (екран блокування або UAC prompt) компоненти **SYSTEM** повторно копіюють ці значення. Якщо **пер-сесійний ключ HKLM доступний для запису користувачем**, він стає привілейованим choke point для запису, який можна перенаправити за допомогою **registry symbolic links**, що дає можливість здійснити **довільний запис у реєстр від імені SYSTEM**.

Техніка RegPwn зловживає цим ланцюжком пропагації з невеликим вікном гонки, яке стабілізується за допомогою **opportunistic lock (oplock)** на файлі, що використовується `osk.exe`.

## Registry Propagation Chain (Accessibility -> Secure Desktop)

Приклад функції: **On-Screen Keyboard** (`osk`). Відповідні локації:

- **System-wide feature list**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **Per-user configuration (user-writable)**:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **Per-session HKLM config (created by `winlogon.exe`, user-writable)**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Secure desktop/default user hive (SYSTEM context)**:
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Поширення під час переходу на **Secure Desktop** (спрощено):

1. **User `atbroker.exe`** копіює `HKCU\...\ATConfig\osk` в `HKLM\...\Session<session id>\ATConfig\osk`.
2. **SYSTEM `atbroker.exe`** копіює `HKLM\...\Session<session id>\ATConfig\osk` в `HKU\.DEFAULT\...\ATConfig\osk`.
3. **SYSTEM `osk.exe`** копіює `HKU\.DEFAULT\...\ATConfig\osk` назад у `HKLM\...\Session<session id>\ATConfig\osk`.

Якщо піддерево сесії в HKLM доступне для запису користувачем, кроки 2/3 забезпечують запис від імені SYSTEM через локацію, яку користувач може замінити.

## Примітив: Arbitrary SYSTEM Registry Write via Registry Links

Замість пер-сесійного ключа, доступного для запису користувачем, встановлюють **registry symbolic link**, що вказує на довільну ціль, обрану атакуючим. Коли відбувається копіювання від SYSTEM, воно слідує по ланцюгу і записує керовані атакуючим значення в довільний цільовий ключ.

Ключова ідея:

- Victim write target (user-writable):
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- Attacker replaces that key with a **registry link** to any other key.
- SYSTEM performs the copy and writes into the attacker-chosen key with SYSTEM permissions.

Це дає примітив для **довільного запису в реєстр від імені SYSTEM**.

## Winning the Race Window with Oplocks

Існує коротке часове вікно між запуском **SYSTEM `osk.exe`** і записом пер-сесійного ключа. Щоб зробити це надійним, експлойт розміщує **oplock** на:
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
Коли **oplock** спрацьовує, атакувальник замінює per-session ключ HKLM на **registry link**, дозволяє SYSTEM виконати запис, а потім видаляє цей лінк.

## Example Exploitation Flow (High Level)

1. Отримайте поточний **session ID** з access token.
2. Запустіть прихований екземпляр `osk.exe` та ненадовго зробіть паузу (щоб гарантувати спрацьовування **oplock**).
3. Запишіть керовані атакером значення в:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. Встановіть **oplock** на `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`.
5. Ініціюйте **Secure Desktop** (`LockWorkstation()`), що спричинить запуск SYSTEM `atbroker.exe` / `osk.exe`.
6. При спрацьовуванні **oplock** замініть `HKLM\...\Session<session id>\ATConfig\osk` на **registry link** до довільної цілі.
7. Почекайте коротко, доки SYSTEM завершить копіювання, після чого видаліть лінк.

## Converting the Primitive to SYSTEM Execution

Одним із простих ланцюжків є перезапис значення **service configuration** (наприклад, `ImagePath`) з подальшим запуском служби. RegPwn PoC перезаписує `ImagePath` для **`msiserver`** і запускає її шляхом інстанціювання **MSI COM object**, що призводить до виконання коду від імені **SYSTEM**.

## Related

Для інших поведінок Secure Desktop / UIAccess див.:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## References

- [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)

{{#include ../../banners/hacktricks-training.md}}
