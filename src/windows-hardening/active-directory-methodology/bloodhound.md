# BloodHound та інші інструменти перерахування Active Directory

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
adws-enumeration.md
{{#endref}}

> ПРИМІТКА: На цій сторінці зібрано деякі з найкорисніших утиліт для **перерахування** та **візуалізації** зв’язків Active Directory. Для збору даних через прихований канал **Active Directory Web Services (ADWS)** див. наведене вище посилання.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) — це розширений **засіб перегляду та редактор AD**, який дає змогу:

* Переглядати дерево каталогу через GUI
* Редагувати атрибути об’єктів і дескриптори безпеки
* Створювати та порівнювати Snapshot для офлайн-аналізу

### Швидке використання

1. Запустіть інструмент і підключіться до `dc01.corp.local` із будь-якими обліковими даними домену.
2. Створіть офлайн-Snapshot через `File ➜ Create Snapshot`.
3. Порівняйте два Snapshot за допомогою `File ➜ Compare`, щоб виявити зміни дозволів.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) витягує великий набір артефактів із домену (ACL, GPO, trust, шаблони CA …) і створює **звіт Excel**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (візуалізація графів)

[BloodHound](https://github.com/SpecterOps/BloodHound) використовує теорію графів, щоб виявляти приховані зв’язки привілеїв у локальній AD, Entra ID і будь-яких додаткових даних attack surface, які ви імпортуєте через OpenGraph.<sup>[[1]](#references)</sup>

### Розгортання (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Колектори

* `SharpHound.exe` / `Invoke-BloodHound` – нативний або PowerShell-варіант
* `RustHound-CE` – кросплатформний CE collector для Linux, macOS і Windows
* `NetExec --bloodhound` – швидкий збір даних через LDAP з Linux
* `AzureHound` – перелік об’єктів Entra ID
* **SoaPy + BOFHound** – збір даних через ADWS (див. посилання на початку)

> BloodHound CE `v8+` змінив формат виводу collector після появи OpenGraph. Після оновлення зі legacy BloodHound або старіших інсталяцій CE повторно виконайте discovery за допомогою актуальних collectors перед імпортом даних.<sup>[[1]](#references)</sup>

#### Поширені режими SharpHound
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
Збирачі генерують JSON, який імпортується через BloodHound GUI.

#### SharpHound із Windows host, не приєднаного до домену

Якщо ваша operator VM не приєднана до цільового домену, вкажіть DNS на DC, запустіть **network-only** shell, перевірте, що бачите `SYSVOL`/`NETLOGON` на DC, а потім виконайте збір даних у віддаленому домені:
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
Це корисно для одноразових jump box або робочих станцій оператора, які не повинні бути приєднані до домену.

#### Кросплатформний збір даних із Linux/macOS
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE` — хороший варіант за замовчуванням, коли потрібен сумісний із CE вивід із хоста не під керуванням Windows.<sup>[[2]](#references)</sup> `NetExec` зручний, якщо ви вже використовуєте його для LDAP validation або spraying і хочете швидко імпортувати граф. Для наборів даних, не пов’язаних з AD, BloodHound OpenGraph можна розширити за допомогою collectors, таких як [ShareHound](../../network-services-pentesting/pentesting-smb/README.md).<sup>[[1]](#references)</sup>

### ADPathFinder (пріоритизація шляхів OpenGraph)

[ADPathFinder](https://github.com/NetSPI/AD-PathFinder) працює поверх BloodHound CE/OpenGraph, коли граф надто великий для ручного pivoting. Замість того щоб лише перевіряти, чи може один principal отримати доступ до однієї цілі, він обчислює найкоротші шляхи від багатьох користувачів і комп’ютерів із низькими привілеями до цінних об’єктів, групує шляхи, які повторно використовують ті самі edges, і показує спільну choke point, яку слід усунути першою.<sup>[[4]](#references)</sup>
```bash
adpathfinder --setup-bloodhound-api
adpathfinder -i SharpHound.zip --ad
adpathfinder -i SharpHound.zip MSSQLHound.zip ConfigManBearPig.zip --ad --pwd Contoso,ContosoIT --ntds ntds.txt -p hashcat.potfile
```
Імпортовані дані `MSSQLHound` і `ConfigManBearPig` дають змогу одній знахідці охоплювати [AD CS](ad-certificates.md), [MSSQL AD abuse](abusing-ad-mssql.md) і [SCCM attack paths](sccm-management-point-relay-sql-policy-secrets.md), замість того щоб залишати їх як окремі напрямки.<sup>[[4]](#references)</sup> Приклад спільного шляху:
```text
J.REPORTER > MSSQL_HasLogin > j.reporter > MSSQL_ExecuteAs > ReportSvc >
MSSQL_Connect > lab-sql01.training.local > MSSQL_LinkedAsAdmin > sccmdb.training.local >
MSSQL_ExecuteOnHost (as DA@TRAINING.LOCAL) > SCCMDB.TRAINING.LOCAL >
SCCM_AssignAllPermissions > SCCM_Site(TRN)
```
- Відстежуйте **effective security context** на кожному ребрі. Шлях стає критичним для домену, щойно один із переходів виконується від імені привілейованої доменної ідентичності, навіть якщо він починався зі звичайного користувача.
- Згруповані результати ідеально підходять для **choke-point remediation**: видалення одного дозволу на SQL impersonation, довіри linked-server, шляху зловживання certificate-template або призначення SCCM може одночасно зруйнувати багато найкоротших шляхів.
- Повторно визначайте пріоритет "середніх" знахідок із урахуванням **graph context**. Вимкнений SMB signing, WebClient exposure, помилки delegation або SQL-сервери, доступні для NTLM-relay, заслуговують на вищий пріоритет, якщо скомпрометований вузол має подальші шляхи до Domain Admins, Domain Controllers, CA або SCCM site servers.
- Якщо у вас також є результат `NTDS.dit` і potfile hashcat, `--pwd` зіставляє cracked passwords із властивостями BloodHound, щоб швидко відокремити звичайне повторне використання паролів від cracked creds у привілейованих, Kerberoastable, AS-REP roastable або релевантних для шляхів облікових записах.

### Збір privilege та logon-right

Windows **token privileges** (наприклад, `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) можуть обходити перевірки DACL, тому їхнє загальнодоменне зіставлення виявляє локальні LPE-ребра, які не помітні на графах, що містять лише ACL. **Logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` і відповідні їм `SeDeny*`) застосовуються LSA ще до появи token, а заборони мають пріоритет, тому вони суттєво обмежують lateral movement (RDP/SMB/scheduled task/service logon).<sup>[[3]](#references)</sup>

**Запускайте collectors із підвищеними привілеями**, коли це можливо: UAC створює filtered token для інтерактивних адміністраторів (через `NtFilterToken`), видаляючи чутливі privileges і позначаючи admin SIDs як deny-only. Якщо перелічувати privileges із non-elevated shell, цінні privileges будуть невидимими, і BloodHound не імпортує ці ребра.<sup>[[3]](#references)</sup>

Тепер існують дві взаємодоповнювальні стратегії збору SharpHound:<sup>[[3]](#references)</sup>

- **Парсинг GPO/SYSVOL (stealthy, low-privilege):**
1. Перелічити GPO через LDAP (`(objectCategory=groupPolicyContainer)`) і прочитати `gPCFileSysPath` кожного з них.
2. Отримати `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` із SYSVOL і розібрати секцію `[Privilege Rights]`, яка зіставляє назви privilege/logon-right із SIDs.
3. Визначити зв’язки GPO через `gPLink` на OUs/sites/domains, перелічити комп’ютери у пов’язаних контейнерах і призначити ці rights відповідним машинам.
4. Перевага: працює зі звичайним користувачем і є тихим; недолік: бачить лише rights, застосовані через GPO (локальні зміни не враховуються).

- **Перелік через LSA RPC (noisy, accurate):**
- Із context, що має local admin на target, відкрити Local Security Policy і викликати `LsaEnumerateAccountsWithUserRight` для кожного privilege/logon right, щоб через RPC перелічити призначені principals.
- Перевага: охоплює rights, установлені локально або поза GPO; недолік: noisy network traffic і потреба в admin на кожному host.

**Приклад шляху зловживання, виявленого цими ребрами:** `CanRDP` ➜ host, де ваш user також має `SeBackupPrivilege` ➜ запустити elevated shell, щоб уникнути filtered tokens ➜ використати backup semantics для читання вуликів `SAM` і `SYSTEM`, попри restrictive DACLs ➜ exfiltrate їх і запустити `secretsdump.py` offline, щоб отримати local Administrator NT hash для lateral movement/privilege escalation.<sup>[[3]](#references)</sup>

### Визначення пріоритетів Kerberoasting за допомогою BloodHound

Використовуйте graph context, щоб зробити roasting цільовим:

1. Виконайте збір один раз за допомогою ADWS-compatible collector і працюйте offline:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. Імпортуйте ZIP, позначте скомпрометований principal як owned і запустіть вбудовані queries (*Kerberoastable Users*, *Shortest Paths to Domain Admins*), щоб виявити SPN accounts з admin/infra rights.
3. Визначайте пріоритет SPNs за blast radius; перед cracking перевірте `pwdLastSet`, `lastLogon` і дозволені типи encryption.
4. Запитуйте лише вибрані tickets, виконайте crack offline, а потім повторно запитайте BloodHound із новим доступом:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) перелічує **Group Policy Objects** і виділяє misconfigurations.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) виконує **перевірку стану** Active Directory та генерує HTML-звіт з оцінюванням ризиків.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Посилання

- [1] [BloodHound Community Edition v8 запускає OpenGraph: шляхи атак на ідентичності за межами Active Directory та Entra ID](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [2] [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [3] [Поза межами ACL: зіставлення шляхів підвищення привілеїв Windows за допомогою BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)
- [4] [ADPathFinder: зіставлення шляхів атак OpenGraph у BloodHound CE](https://www.netspi.com/blog/technical-blog/network-pentesting/adpathfinder-opengraph-attack-path-mapping-in-bloodhound-ce/)

{{#include ../../banners/hacktricks-training.md}}
