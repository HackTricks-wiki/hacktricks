# Захист облікових даних Windows

{{#include ../../banners/hacktricks-training.md}}

## WDigest

The [WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>) protocol, introduced with Windows XP, is designed for authentication via the HTTP Protocol and is **enabled by default on Windows XP through Windows 8.0 and Windows Server 2003 to Windows Server 2012**. This default setting results in **plain-text password storage in LSASS** (Local Security Authority Subsystem Service). An attacker can use Mimikatz to **extract these credentials** by executing:
```bash
sekurlsa::wdigest
```
Щоб **увімкнути або вимкнути цю функцію**, ключі реєстру _**UseLogonCredential**_ та _**Negotiate**_ у _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ мають бути встановлені на "1". Якщо ці ключі **відсутні або встановлені на "0"**, WDigest **відключено**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA Protection (PP & PPL protected processes)

**Protected Process (PP)** і **Protected Process Light (PPL)** — це **Windows kernel-level protections**, які призначені для запобігання несанкціонованому доступу до чутливих процесів, таких як **LSASS**. Запроваджені у **Windows Vista**, модель **PP** спочатку створювалася для забезпечення **DRM** і дозволяла захищати лише бінарники, підписані спеціальним медіа-сертифікатом. Процес, позначений як **PP**, може бути відкритий лише іншими процесами, які також є **PP** і мають **рівень захисту рівний або вищий**, і навіть тоді — **тільки з обмеженими правами доступу**, якщо інше явно не дозволено.

**PPL**, запроваджений у **Windows 8.1**, є більш гнучкою версією PP. Він дозволяє **ширші сценарії використання** (наприклад, LSASS, Defender) шляхом введення **"рівнів захисту"**, заснованих на полі EKU (Enhanced Key Usage) цифрового підпису. Рівень захисту зберігається в полі `EPROCESS.Protection`, яке є структурою `PS_PROTECTION` з:
- **Type** (`Protected` or `ProtectedLight`)
- **Signer** (наприклад, `WinTcb`, `Lsa`, `Antimalware` тощо)

Ця структура упакована в один байт і визначає **хто кого може доступати**:
- **Вищі значення signer можуть доступатися до нижчих**
- **PPLs не можуть доступатися до PPs**
- **Незахищені процеси не можуть доступатися до будь-яких PPL/PP**

### What you need to know from an offensive perspective

- Коли **LSASS запускається як PPL**, спроби відкрити його через `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` з нормального адміністративного контексту **завершуються помилкою `0x5 (Access Denied)`**, навіть якщо `SeDebugPrivilege` увімкнено.
- Ви можете **перевірити рівень захисту LSASS** за допомогою інструментів типу Process Hacker або програмно, читаючи значення `EPROCESS.Protection`.
- LSASS зазвичай матиме `PsProtectedSignerLsa-Light` (`0x41`), до якого можна отримати доступ **тільки з процесів, підписаних з вищим signer**, наприклад `WinTcb` (`0x61` або `0x62`).
- PPL — це **Userland-only restriction**; **kernel-level code може повністю його обійти**.
- Те, що LSASS є PPL, **не заважає зливу облікових даних**, якщо ви можете виконати kernel shellcode або **задіяти процес з високими привілеями та відповідним доступом**.
- **Установлення або зняття PPL** вимагає перезавантаження або змін у налаштуваннях Secure Boot/UEFI, які можуть зберегти налаштування PPL навіть після скасування змін у реєстрі.

### Create a PPL process at launch (documented API)

Windows надає документований спосіб запитати рівень Protected Process Light для дочірнього процесу під час створення, використовуючи розширений список атрибутів старту. Це не обходить вимоги до підпису — цільовий образ має бути підписаний для запитаної класи signer.

Мінімальний потік у C/C++:
```c
// Request a PPL protection level for the child process at creation time
// Requires Windows 8.1+ and a properly signed image for the selected level
#include <windows.h>

int wmain(int argc, wchar_t **argv) {
STARTUPINFOEXW si = {0};
PROCESS_INFORMATION pi = {0};
si.StartupInfo.cb = sizeof(si);

SIZE_T attrSize = 0;
InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
if (!si.lpAttributeList) return 1;

if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrSize)) return 1;

DWORD level = PROTECTION_LEVEL_ANTIMALWARE_LIGHT; // or WINDOWS_LIGHT/LSA_LIGHT/WINTCB_LIGHT
if (!UpdateProcThreadAttribute(
si.lpAttributeList, 0,
PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL,
&level, sizeof(level), NULL, NULL)) {
return 1;
}

DWORD flags = EXTENDED_STARTUPINFO_PRESENT;
if (!CreateProcessW(L"C\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE,
flags, NULL, NULL, &si.StartupInfo, &pi)) {
// If the image isn't signed appropriately for the requested level,
// CreateProcess will fail with ERROR_INVALID_IMAGE_HASH (577).
return 1;
}

// cleanup
DeleteProcThreadAttributeList(si.lpAttributeList);
HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
CloseHandle(pi.hThread);
CloseHandle(pi.hProcess);
return 0;
}
```
Примітки та обмеження:
- Використовуйте `STARTUPINFOEX` з `InitializeProcThreadAttributeList` та `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, ...)`, потім передайте `EXTENDED_STARTUPINFO_PRESENT` в `CreateProcess*`.
- Значення protection `DWORD` можна встановити в такі константи, як `PROTECTION_LEVEL_WINTCB_LIGHT`, `PROTECTION_LEVEL_WINDOWS`, `PROTECTION_LEVEL_WINDOWS_LIGHT`, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, або `PROTECTION_LEVEL_LSA_LIGHT`.
- Дочірній процес почне працювати як PPL лише якщо його образ підписаний для цього класу підписувача; в іншому випадку створення процесу не вдасться, зазвичай з `ERROR_INVALID_IMAGE_HASH (577)` / `STATUS_INVALID_IMAGE_HASH (0xC0000428)`.
- Це не bypass — це підтримуваний API, призначений для належним чином підписаних образів. Корисно для зміцнення інструментів або перевірки конфігурацій, захищених PPL.

Example CLI using a minimal loader:
- Antimalware signer: `CreateProcessAsPPL.exe 3 C:\Tools\agent.exe --svc`
- LSA-light signer: `CreateProcessAsPPL.exe 4 C:\Windows\System32\notepad.exe`

**Bypass PPL protections options:**

Якщо ви хочете dump LSASS незважаючи на PPL, у вас є 3 основні варіанти:
1. **Use a signed kernel driver (e.g., Mimikatz + mimidrv.sys)** щоб **видалити прапорець захисту LSASS**:

![](../../images/mimidrv.png)

2. **Bring Your Own Vulnerable Driver (BYOVD)** щоб виконувати власний код в ядрі та вимкнути захист. Інструменти на кшталт **PPLKiller**, **gdrv-loader**, або **kdmapper** роблять це можливим.
3. Вкрадіть існуючий дескриптор LSASS з іншого процесу, який має його відкритим (наприклад, AV процес), потім дуплікуйте його в ваш процес. Це основа техніки `pypykatz live lsa --method handledup`.
4. Зловживайте якимось привілейованим процесом, який дозволить завантажити довільний код у його адресний простір або всередину іншого привілейованого процесу, фактично обходячи обмеження PPL. Приклад можна подивитися в [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) або [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump).

**Check current status of LSA protection (PPL/PP) for LSASS**:
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
Коли ви запускаєте **`mimikatz privilege::debug sekurlsa::logonpasswords`**, це, найімовірніше, завершиться помилкою з кодом `0x00000005` через це.

- Для додаткової інформації про цю перевірку [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)


## Credential Guard

**Credential Guard**, функція, доступна лише в **Windows 10 (Enterprise та Education editions)**, підвищує безпеку облікових даних машини за допомогою **Virtual Secure Mode (VSM)** та **Virtualization Based Security (VBS)**. Воно використовує розширення віртуалізації CPU для ізоляції ключових процесів у захищеному просторі пам'яті, поза досяжністю основної операційної системи. Ця ізоляція гарантує, що навіть ядро не має доступу до пам'яті у VSM, ефективно захищаючи облікові дані від атак на кшталт **pass-the-hash**. **Local Security Authority (LSA)** працює в цьому захищеному середовищі як trustlet, тоді як процес **LSASS** в основній ОС виконує лише роль посередника для зв'язку з LSA у VSM.

За замовчуванням **Credential Guard** не активований і потребує ручного ввімкнення в організації. Воно критично для посилення захисту проти інструментів на кшталт **Mimikatz**, яким значно ускладнено можливість витягувати облікові дані. Проте вразливості все ще можуть бути використані шляхом додавання кастомних **Security Support Providers (SSP)** для перехоплення облікових даних у відкритому вигляді під час спроб входу.

Щоб перевірити стан активації **Credential Guard**, можна переглянути реєстровий ключ _**LsaCfgFlags**_ у _**HKLM\System\CurrentControlSet\Control\LSA**_. Значення "**1**" означає активацію з **UEFI lock**, "**2**" — без блокування, а "**0**" вказує, що він не увімкнений. Ця перевірка реєстру, хоча й є вагомим індикатором, не є єдиним кроком для увімкнення Credential Guard. Детальні інструкції та PowerShell-скрипт для увімкнення цієї функції доступні онлайн.
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Для повного розуміння та інструкцій щодо увімкнення **Credential Guard** у Windows 10 та його автоматичної активації в сумісних системах **Windows 11 Enterprise and Education (version 22H2)**, відвідайте [документацію Microsoft](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Детальніші відомості щодо реалізації custom SSPs для захоплення облікових даних наведено в [цьому посібнику](../active-directory-methodology/custom-ssp.md).

## RDP RestrictedAdmin Mode

**Windows 8.1 and Windows Server 2012 R2** запровадили кілька нових функцій безпеки, зокрема _**Restricted Admin mode for RDP**_. Цей режим створений для підвищення безпеки шляхом зменшення ризиків, пов'язаних із атаками [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/).

Традиційно, при підключенні до віддаленого комп'ютера через RDP ваші облікові дані зберігаються на цільовій машині. Це становить значний ризик для безпеки, особливо при використанні облікових записів з підвищеними привілеями. Однак із введенням _**Restricted Admin mode**_ цей ризик суттєво зменшується.

При ініціюванні RDP-з'єднання командою **mstsc.exe /RestrictedAdmin** автентифікація до віддаленого комп'ютера виконується без збереження ваших облікових даних на ньому. Такий підхід гарантує, що у разі зараження шкідливим ПЗ або якщо зловмисник отримає доступ до віддаленого сервера, ваші облікові дані не будуть скомпрометовані, оскільки вони не зберігаються на сервері.

Важливо зауважити, що в **Restricted Admin mode** спроби доступу до мережевих ресурсів із RDP-сесії не використовуватимуть ваші особисті облікові дані; натомість використовується **ідентичність машини**.

Ця функція є важливим кроком уперед у захисті віддалених робочих столів та захисті конфіденційної інформації від розкриття у разі порушення безпеки.

![](../../images/RAM.png)

Для детальнішої інформації перегляньте [цей ресурс](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Cached Credentials

Windows захищає **domain credentials** через **Local Security Authority (LSA)**, підтримуючи процеси входу з протоколами безпеки такими як **Kerberos** і **NTLM**. Важливою можливістю Windows є кешування **останніх десяти входів у домен**, щоб користувачі могли отримувати доступ до своїх комп'ютерів навіть якщо **domain controller** недоступний — корисно для ноутбуків, які часто знаходяться поза мережею компанії.

Кількість кешованих входів можна налаштувати через відповідний **registry key or group policy**. Щоб переглянути або змінити цей параметр, використовується наступна команда:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Доступ до цих кешованих облікових даних суворо контролюється: лише обліковий запис **SYSTEM** має необхідні дозволи для їх перегляду. Адміністратори, яким потрібно отримати цю інформацію, повинні робити це з привілеями користувача SYSTEM. Облікові дані зберігаються за адресою: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** можна використовувати для вилучення цих кешованих облікових даних за допомогою команди `lsadump::cache`.

Для детальнішої інформації оригінальне [source](http://juggernaut.wikidot.com/cached-credentials) містить повну інформацію.

## Protected Users

Членство в групі **Protected Users** додає кілька покращень безпеки для користувачів, забезпечуючи вищий рівень захисту від крадіжки та зловживання обліковими даними:

- **Credential Delegation (CredSSP)**: Навіть якщо налаштування Group Policy **Allow delegating default credentials** увімкнено, plain text облікові дані Protected Users не будуть кешовані.
- **Windows Digest**: Починаючи з **Windows 8.1 and Windows Server 2012 R2**, система не кешуватиме plain text облікові дані Protected Users, незалежно від стану Windows Digest.
- **NTLM**: Система не кешуватиме plain text облікові дані Protected Users або NT one-way functions (NTOWF).
- **Kerberos**: Для Protected Users аутентифікація Kerberos не генерує **DES** або **RC4 keys**, а також не кешуватиме plain text облікові дані чи довготривалі ключі поза початковим отриманням Ticket-Granting Ticket (TGT).
- **Offline Sign-In**: Для Protected Users не створюється кешований верифікатор під час входу або розблокування, отже offline sign-in для цих облікових записів не підтримується.

Ці захисти активуються з моменту, коли користувач, який є членом групи **Protected Users**, входить на пристрій. Це гарантує, що ключові заходи безпеки застосовуються для захисту від різних методів компрометації облікових даних.

Для детальнішої інформації зверніться до офіційної [documentation](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).

**Table from** [**the docs**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

## References

- [CreateProcessAsPPL – minimal PPL process launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [STARTUPINFOEX structure (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw)
- [InitializeProcThreadAttributeList (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist)
- [UpdateProcThreadAttribute (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [LSASS RunAsPPL – background and internals](https://itm4n.github.io/lsass-runasppl/)

{{#include ../../banners/hacktricks-training.md}}
