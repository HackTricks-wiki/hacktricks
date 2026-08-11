# Захист облікових даних Windows

{{#include ../../banners/hacktricks-training.md}}

## WDigest

Протокол [WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>), представлений у Windows XP, призначений для автентифікації через HTTP Protocol і **увімкнений за замовчуванням у Windows XP–Windows 8.0 та Windows Server 2003–Windows Server 2012**. Це налаштування за замовчуванням призводить до **зберігання паролів у відкритому тексті в LSASS** (підсистема локального органу безпеки). Зловмисник може використати Mimikatz, щоб **витягнути ці облікові дані**, виконавши:<sup>[[8]](#references)</sup>
```bash
sekurlsa::wdigest
```
Щоб **вимкнути або ввімкнути цю функцію**, ключі реєстру _**UseLogonCredential**_ і _**Negotiate**_ у _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ мають бути встановлені в значення "1". Якщо ці ключі **відсутні або мають значення "0"**, WDigest **вимкнено**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## Захист LSA (процеси із захистом PP і PPL)

**Protected Process (PP)** і **Protected Process Light (PPL)** — це **захисти на рівні ядра Windows**, призначені для запобігання несанкціонованому доступу до чутливих процесів, таких як **LSASS**. Представлена у **Windows Vista**, модель **PP** спочатку була створена для забезпечення **DRM** і дозволяла захищати лише бінарні файли, підписані **спеціальним медіасертифікатом**. Процес, позначений як **PP**, може бути доступний лише іншим процесам, які також є **PP** і мають **рівень захисту, що дорівнює або перевищує його**, і навіть тоді — **лише з обмеженими правами доступу**, якщо інше не дозволено явно.

**PPL**, представлений у **Windows 8.1**, є більш гнучкою версією PP. Він підтримує **ширший спектр сценаріїв використання** (наприклад, LSASS, Defender), запроваджуючи **«рівні захисту»**, засновані на полі **EKU (Enhanced Key Usage)** **цифрового підпису**. Рівень захисту зберігається в полі `EPROCESS.Protection`, яке є структурою `PS_PROTECTION` із такими полями:
- **Type** (`Protected` або `ProtectedLight`)
- **Signer** (наприклад, `WinTcb`, `Lsa`, `Antimalware` тощо)

Ця структура упаковується в один байт і визначає, **хто до кого може отримувати доступ**:
- **Signer із вищим значенням може отримувати доступ до Signer із нижчим значенням**
- **PPL не можуть отримувати доступ до PP**
- **Незахищені процеси не можуть отримувати доступ до PPL/PP**

### Що потрібно знати з offensive perspective

- Коли **LSASS працює як PPL**, спроби відкрити його за допомогою `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` зі звичайного контексту адміністратора **завершуються помилкою `0x5 (Access Denied)`**, навіть якщо `SeDebugPrivilege` увімкнено.
- Ви можете **перевірити рівень захисту LSASS** за допомогою таких інструментів, як Process Hacker, або програмно, зчитавши значення `EPROCESS.Protection`.
- Зазвичай LSASS має `PsProtectedSignerLsa-Light` (`0x41`), доступ до якого можуть отримувати **лише процеси, підписані Signer із вищим рівнем**, наприклад `WinTcb` (`0x61` або `0x62`).
- PPL є **обмеженням лише на рівні Userland**; **код на рівні ядра може повністю його обійти**.
- Те, що LSASS працює як PPL, **не запобігає credential dumping**, якщо ви можете виконати kernel shellcode або **використати високопривілейований процес із належним доступом**.
- **Встановлення або видалення PPL** потребує перезавантаження або налаштувань **Secure Boot/UEFI**; вони можуть зберігати налаштування PPL навіть після скасування змін у реєстрі.

### Створення процесу PPL під час запуску (documented API)

Windows надає документований спосіб запросити рівень Protected Process Light для дочірнього процесу під час його створення за допомогою списку розширених атрибутів запуску. Це не обходить вимоги до підпису — цільовий образ має бути підписаний для запитаного класу Signer.

Мінімальний flow мовою C/C++:
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
- Використовуйте `STARTUPINFOEX` разом із `InitializeProcThreadAttributeList` і `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, ...)`, а потім передавайте `EXTENDED_STARTUPINFO_PRESENT` до `CreateProcess*`.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- `DWORD` захисту можна встановити в такі константи, як `PROTECTION_LEVEL_WINTCB_LIGHT`, `PROTECTION_LEVEL_WINDOWS`, `PROTECTION_LEVEL_WINDOWS_LIGHT`, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` або `PROTECTION_LEVEL_LSA_LIGHT`.
- Дочірній процес запускається як PPL лише в тому випадку, якщо його image підписано для відповідного класу signer; інакше створення процесу завершується помилкою, зазвичай із `ERROR_INVALID_IMAGE_HASH (577)` / `STATUS_INVALID_IMAGE_HASH (0xC0000428)`.
- Це не bypass — це підтримуваний API, призначений для належним чином підписаних images. Корисно для hardening tools або перевірки конфігурацій, захищених PPL.

Приклад CLI із використанням мінімального loader:<sup>[[1]](#references)</sup>
- Antimalware signer: `CreateProcessAsPPL.exe 3 C:\Tools\agent.exe --svc`
- LSA-light signer: `CreateProcessAsPPL.exe 4 C:\Windows\System32\notepad.exe`

**Варіанти bypass захисту PPL:**

Якщо потрібно зробити dump LSASS попри PPL, є 3 основні варіанти:
1. **Використати підписаний kernel driver (наприклад, Mimikatz + mimidrv.sys)**, щоб **видалити прапорець захисту LSASS**:

![Вивід драйвера Mimikatz mimidrv, що демонструє взаємодію із захистом облікових даних](../../images/mimidrv.png)

2. **Bring Your Own Vulnerable Driver (BYOVD)**, щоб виконати власний kernel code і вимкнути захист. Такі tools, як **PPLKiller**, **gdrv-loader** або **kdmapper**, роблять це можливим.
3. **Викрасти наявний handle LSASS** з іншого процесу, який його відкрив (наприклад, процесу AV), а потім **продублювати його** у свій процес. На цьому базується technique `pypykatz live lsa --method handledup`.
4. **Зловжити деяким привілейованим процесом**, який дозволяє завантажити довільний code у свій address space або всередину іншого привілейованого процесу, фактично обходячи обмеження PPL. Приклад можна переглянути в [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) або [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump).

**Перевірка поточного статусу захисту LSA (PPL/PP) для LSASS**:
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
Під час виконання **`mimikatz privilege::debug sekurlsa::logonpasswords`** команда, імовірно, завершиться помилкою `0x00000005` через цей захист.

- Докладніше про цю перевірку: [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)<sup>[[5]](#references)</sup>


## Credential Guard

**Credential Guard** — функція, доступна лише у **Windows 10 (Enterprise та Education editions)**, яка підвищує безпеку облікових даних комп’ютера за допомогою **Virtual Secure Mode (VSM)** і **Virtualization Based Security (VBS)**. Вона використовує розширення віртуалізації CPU, щоб ізолювати ключові процеси в захищеному просторі пам’яті, недоступному для основної операційної системи. Така ізоляція гарантує, що навіть ядро не може отримати доступ до пам’яті у VSM, ефективно захищаючи облікові дані від атак на кшталт **pass-the-hash**. **Local Security Authority (LSA)** працює в цьому захищеному середовищі як trustlet, тоді як процес **LSASS** в основній ОС лише обмінюється даними з LSA у VSM.

За замовчуванням **Credential Guard** не активний і потребує ручного ввімкнення в організації. Він суттєво підвищує захист від таких інструментів, як **Mimikatz**, обмежуючи їхню здатність вилучати облікові дані. Однак уразливості все ще можна експлуатувати шляхом додавання власних **Security Support Providers (SSP)** для перехоплення облікових даних у відкритому вигляді під час спроб входу.

Щоб перевірити стан активації **Credential Guard**, можна переглянути ключ реєстру _**LsaCfgFlags**_ у _**HKLM\System\CurrentControlSet\Control\LSA**_. Значення "**1**" означає активацію з **UEFI lock**, "**2**" — активацію без блокування, а "**0**" означає, що функцію не ввімкнено. Ця перевірка реєстру є надійним індикатором, але не є єдиним кроком для ввімкнення Credential Guard. Докладні інструкції та PowerShell-скрипт для ввімкнення цієї функції доступні онлайн.
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Для повного розуміння та отримання інструкцій щодо ввімкнення **Credential Guard** у Windows 10 і його автоматичної активації у сумісних системах **Windows 11 Enterprise і Education (версія 22H2)** відвідайте [документацію Microsoft](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).<sup>[[9]](#references)</sup>

Докладніша інформація про реалізацію власних SSP для захоплення облікових даних наведена у [цьому посібнику](../active-directory-methodology/custom-ssp.md).

## Режим RestrictedAdmin для RDP

**Windows 8.1 і Windows Server 2012 R2** представили кілька нових функцій безпеки, зокрема _**режим Restricted Admin для RDP**_. Цей режим розроблено для підвищення безпеки шляхом зменшення ризиків, пов’язаних з атаками [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/).

Традиційно під час підключення до віддаленого комп’ютера через RDP ваші облікові дані зберігаються на цільовій машині. Це створює значний ризик для безпеки, особливо під час використання облікових записів із підвищеними привілеями. Однак із появою _**режиму Restricted Admin**_ цей ризик суттєво зменшується.

Під час встановлення RDP-з’єднання за допомогою команди **mstsc.exe /RestrictedAdmin** автентифікація на віддаленому комп’ютері виконується без збереження ваших облікових даних на ньому. Такий підхід гарантує, що в разі зараження malware або отримання зловмисником доступу до віддаленого сервера ваші облікові дані не буде скомпрометовано, оскільки вони не зберігаються на сервері.

Важливо зазначити, що в **режимі Restricted Admin** спроби доступу до мережевих ресурсів із сеансу RDP не використовуватимуть ваші особисті облікові дані; натомість використовуватиметься **ідентичність машини**.

Ця функція є важливим кроком уперед у захисті підключень до віддаленого робочого стола та конфіденційної інформації від розкриття в разі порушення безпеки.

![Діаграма оперативної пам’яті Windows у контексті вилучення облікових даних](../../images/RAM.png)

Докладнішу інформацію див. у [цьому ресурсі](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).<sup>[[6]](#references)</sup>

## Кешовані облікові дані

Windows захищає **облікові дані домену** за допомогою **Local Security Authority (LSA)**, підтримуючи процеси входу за допомогою протоколів безпеки, таких як **Kerberos** і **NTLM**. Важливою функцією Windows є можливість кешувати **останні десять входів до домену**, щоб користувачі й надалі могли отримувати доступ до своїх комп’ютерів, навіть якщо **контролер домену перебуває офлайн** — це особливо корисно для користувачів ноутбуків, які часто перебувають поза мережею своєї компанії.

Кількість кешованих входів можна налаштувати за допомогою певного **розділу реєстру або групової політики**. Для перегляду або зміни цього параметра використовується така команда:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Доступ до цих кешованих облікових даних суворо контролюється: лише обліковий запис **SYSTEM** має необхідні дозволи для їх перегляду. Адміністратори, яким потрібен доступ до цієї інформації, повинні виконувати його з привілеями користувача SYSTEM. Облікові дані зберігаються в: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** можна застосувати для вилучення цих кешованих облікових даних за допомогою команди `lsadump::cache`.

Докладнішу інформацію містить оригінальне [джерело](http://juggernaut.wikidot.com/cached-credentials).<sup>[[7]](#references)</sup>

## Protected Users

Членство в **Protected Users group** забезпечує кілька механізмів підвищення безпеки для користувачів, гарантуючи вищий рівень захисту від крадіжки та неправомірного використання облікових даних:

- **Credential Delegation (CredSSP)**: Навіть якщо параметр Group Policy **Allow delegating default credentials** увімкнено, облікові дані Protected Users у відкритому тексті не кешуватимуться.
- **Windows Digest**: Починаючи з **Windows 8.1 та Windows Server 2012 R2**, система не кешуватиме облікові дані Protected Users у відкритому тексті незалежно від стану Windows Digest.
- **NTLM**: Система не кешуватиме облікові дані Protected Users у відкритому тексті або односторонні функції NT (NTOWF).
- **Kerberos**: Для Protected Users автентифікація Kerberos не генеруватиме ключі **DES** або **RC4**, а також не кешуватиме облікові дані у відкритому тексті чи довгострокові ключі після початкового отримання Ticket-Granting Ticket (TGT).
- **Offline Sign-In**: Для Protected Users під час входу або розблокування не створюватиметься кешований verifier, тому offline sign-in для цих облікових записів не підтримується.

Ці засоби захисту активуються щойно користувач, який є членом **Protected Users group**, входить до пристрою. Це гарантує застосування важливих заходів безпеки для захисту від різних методів компрометації облікових даних.

Докладнішу інформацію дивіться в офіційній [документації](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).<sup>[[10]](#references)</sup>

**Таблиця з** [**документації**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**<sup>[[11]](#references)</sup>

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

- [1] [CreateProcessAsPPL – мінімальний запуск процесу PPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [2] [Структура STARTUPINFOEX (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw)
- [3] [InitializeProcThreadAttributeList (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist)
- [4] [UpdateProcThreadAttribute (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [5] [LSASS RunAsPPL – передумови та внутрішня реалізація](https://itm4n.github.io/lsass-runasppl/)
- [6] [Restricted Admin Mode для RDP](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/)
- [7] [Кешовані облікові дані - Juggernaut AppSec Wiki](http://juggernaut.wikidot.com/cached-credentials)
- [8] [Автентифікація WDigest (Microsoft TechNet)](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>)
- [9] [Керування Windows Defender Credential Guard (Microsoft Learn)](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)
- [10] [Група безпеки Protected Users (Microsoft Learn)](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [11] [Додаток C: Protected Accounts і Groups в Active Directory (Microsoft Learn)](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
{{#include ../../banners/hacktricks-training.md}}
