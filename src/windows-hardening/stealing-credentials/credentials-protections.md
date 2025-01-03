# Захист облікових даних Windows

## Захист облікових даних

{{#include ../../banners/hacktricks-training.md}}

## WDigest

Протокол [WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>), представлений з Windows XP, призначений для аутентифікації через HTTP-протокол і **включений за замовчуванням у Windows XP до Windows 8.0 та Windows Server 2003 до Windows Server 2012**. Це налаштування за замовчуванням призводить до **зберігання паролів у відкритому тексті в LSASS** (Служба підсистеми локальної безпеки). Зловмисник може використовувати Mimikatz для **витягування цих облікових даних**, виконавши:
```bash
sekurlsa::wdigest
```
Щоб **вимкнути або ввімкнути цю функцію**, реєстрові ключі _**UseLogonCredential**_ та _**Negotiate**_ в _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ повинні бути встановлені на "1". Якщо ці ключі **відсутні або встановлені на "0"**, WDigest є **вимкненим**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## Захист LSA

Починаючи з **Windows 8.1**, Microsoft покращила безпеку LSA, щоб **блокувати несанкціоновані зчитування пам'яті або ін'єкції коду ненадійними процесами**. Це покращення ускладнює звичайне функціонування команд, таких як `mimikatz.exe sekurlsa:logonpasswords`. Щоб **увімкнути цей покращений захист**, значення _**RunAsPPL**_ в _**HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ слід налаштувати на 1:
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Bypass

Можливо обійти цю захист за допомогою драйвера Mimikatz mimidrv.sys:

![](../../images/mimidrv.png)

## Credential Guard

**Credential Guard**, функція, що є ексклюзивною для **Windows 10 (Enterprise та Education editions)**, підвищує безпеку облікових даних машини за допомогою **Virtual Secure Mode (VSM)** та **Virtualization Based Security (VBS)**. Вона використовує розширення віртуалізації процесора для ізоляції ключових процесів у захищеному просторі пам'яті, подалі від основної операційної системи. Ця ізоляція забезпечує, що навіть ядро не може отримати доступ до пам'яті в VSM, ефективно захищаючи облікові дані від атак, таких як **pass-the-hash**. **Local Security Authority (LSA)** працює в цьому захищеному середовищі як trustlet, тоді як процес **LSASS** в основній ОС виконує лише роль комунікатора з LSA VSM.

За замовчуванням **Credential Guard** не активний і вимагає ручної активації в організації. Це критично важливо для підвищення безпеки проти інструментів, таких як **Mimikatz**, які обмежені у своїй здатності витягувати облікові дані. Однак вразливості все ще можуть бути використані через додавання користувацьких **Security Support Providers (SSP)** для захоплення облікових даних у відкритому тексті під час спроб входу.

Щоб перевірити статус активації **Credential Guard**, можна перевірити реєстровий ключ _**LsaCfgFlags**_ під _**HKLM\System\CurrentControlSet\Control\LSA**_. Значення "**1**" вказує на активацію з **UEFI lock**, "**2**" без замка, а "**0**" позначає, що він не активований. Ця перевірка реєстру, хоча і є сильним показником, не є єдиним кроком для активації Credential Guard. Докладні вказівки та скрипт PowerShell для активації цієї функції доступні онлайн.
```powershell
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Для всебічного розуміння та інструкцій щодо активації **Credential Guard** у Windows 10 та його автоматичної активації в сумісних системах **Windows 11 Enterprise та Education (версія 22H2)**, відвідайте [документацію Microsoft](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Додаткові відомості про реалізацію користувацьких SSP для захоплення облікових даних наведені в [цьому посібнику](../active-directory-methodology/custom-ssp.md).

## Режим обмеженого адміністратора RDP

**Windows 8.1 та Windows Server 2012 R2** представили кілька нових функцій безпеки, включаючи _**Режим обмеженого адміністратора для RDP**_. Цей режим був розроблений для підвищення безпеки шляхом зменшення ризиків, пов'язаних з [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/) атаками.

Традиційно, підключаючись до віддаленого комп'ютера через RDP, ваші облікові дані зберігаються на цільовій машині. Це становить значний ризик для безпеки, особливо при використанні облікових записів з підвищеними привілеями. Однак, з впровадженням _**Режиму обмеженого адміністратора**_, цей ризик суттєво зменшується.

При ініціюванні з'єднання RDP за допомогою команди **mstsc.exe /RestrictedAdmin**, автентифікація на віддаленому комп'ютері виконується без зберігання ваших облікових даних на ньому. Цей підхід забезпечує, що в разі зараження шкідливим ПЗ або якщо зловмисник отримує доступ до віддаленого сервера, ваші облікові дані не будуть скомпрометовані, оскільки вони не зберігаються на сервері.

Важливо зазначити, що в **Режимі обмеженого адміністратора** спроби доступу до мережевих ресурсів з RDP-сесії не використовуватимуть ваші особисті облікові дані; натомість використовується **ідентичність машини**.

Ця функція є значним кроком вперед у забезпеченні безпеки з'єднань віддаленого робочого столу та захисті чутливої інформації від витоку у разі порушення безпеки.

![](../../images/RAM.png)

Для отримання більш детальної інформації відвідайте [цей ресурс](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Кешовані облікові дані

Windows захищає **облікові дані домену** через **Local Security Authority (LSA)**, підтримуючи процеси входу з безпековими протоколами, такими як **Kerberos** та **NTLM**. Ключовою особливістю Windows є її здатність кешувати **останні десять входів до домену**, щоб забезпечити доступ користувачів до своїх комп'ютерів, навіть якщо **доменний контролер офлайн**—це перевага для користувачів ноутбуків, які часто перебувають поза мережею своєї компанії.

Кількість кешованих входів можна налаштувати за допомогою конкретного **реєстраційного ключа або групової політики**. Щоб переглянути або змінити цю настройку, використовується наступна команда:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Доступ до цих кешованих облікових даних суворо контролюється, лише обліковий запис **SYSTEM** має необхідні дозволи для їх перегляду. Адміністратори, які потребують доступу до цієї інформації, повинні робити це з привілеями користувача SYSTEM. Облікові дані зберігаються за адресою: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** може бути використаний для витягнення цих кешованих облікових даних за допомогою команди `lsadump::cache`.

Для отримання додаткової інформації оригінальне [джерело](http://juggernaut.wikidot.com/cached-credentials) надає всебічну інформацію.

## Захищені користувачі

Членство в групі **Захищені користувачі** вводить кілька покращень безпеки для користувачів, забезпечуючи вищі рівні захисту від крадіжки облікових даних та їх неналежного використання:

- **Делегування облікових даних (CredSSP)**: Навіть якщо налаштування групової політики для **Дозволити делегування стандартних облікових даних** увімкнено, облікові дані у відкритому тексті Захищених користувачів не будуть кешуватися.
- **Windows Digest**: Починаючи з **Windows 8.1 та Windows Server 2012 R2**, система не буде кешувати облікові дані у відкритому тексті Захищених користувачів, незалежно від статусу Windows Digest.
- **NTLM**: Система не буде кешувати облікові дані у відкритому тексті Захищених користувачів або односторонні функції NT (NTOWF).
- **Kerberos**: Для Захищених користувачів аутентифікація Kerberos не буде генерувати **DES** або **RC4 ключі**, а також не буде кешувати облікові дані у відкритому тексті або довгострокові ключі після початкового отримання квитка на отримання квитків (TGT).
- **Офлайн вхід**: У Захищених користувачів не буде створено кешований перевірник під час входу або розблокування, що означає, що офлайн вхід не підтримується для цих облікових записів.

Ці заходи захисту активуються в момент, коли користувач, який є членом групи **Захищені користувачі**, входить на пристрій. Це забезпечує наявність критичних заходів безпеки для захисту від різних методів компрометації облікових даних.

Для отримання більш детальної інформації зверніться до офіційної [документації](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).

**Таблиця з** [**документів**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

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

{{#include ../../banners/hacktricks-training.md}}
