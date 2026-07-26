# BloodHound та інші інструменти перерахування Active Directory

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> ПРИМІТКА: На цій сторінці зібрано деякі з найкорисніших утиліт для **перерахування** та **візуалізації** зв’язків Active Directory. Для збору даних через прихований канал **Active Directory Web Services (ADWS)** див. наведене вище посилання.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) — це розширений **переглядач і редактор AD**, який дає змогу:

* Переглядати дерево каталогу через GUI
* Редагувати атрибути об’єктів і дескриптори безпеки
* Створювати та порівнювати snapshot для offline-аналізу

### Швидке використання

1. Запустіть інструмент і підключіться до `dc01.corp.local` за допомогою будь-яких облікових даних домену.
2. Створіть offline snapshot через `File ➜ Create Snapshot`.
3. Порівняйте два snapshot за допомогою `File ➜ Compare`, щоб виявити зміни дозволів.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) видобуває великий набір артефактів із домену (ACLs, GPOs, trusts, шаблони CA …) і створює **Excel-звіт**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (візуалізація графів)

[BloodHound](https://github.com/SpecterOps/BloodHound) використовує теорію графів для виявлення прихованих зв’язків привілеїв у локальному AD, Entra ID та будь-яких додаткових даних про поверхню атак, які ви додаєте через OpenGraph.

### Розгортання (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Збирачі

* `SharpHound.exe` / `Invoke-BloodHound` – нативний варіант або варіант для PowerShell
* `RustHound-CE` – кросплатформний CE-збирач для Linux, macOS і Windows
* `NetExec --bloodhound` – швидкий збір даних на основі LDAP із Linux
* `AzureHound` – enumeration Entra ID
* **SoaPy + BOFHound** – збір даних через ADWS (див. посилання вгорі)

> BloodHound CE `v8+` змінив формат виводу збирача після появи OpenGraph. Після оновлення зі legacy BloodHound або старих інсталяцій CE повторно виконайте discovery за допомогою актуальних збирачів перед імпортом даних.

#### Поширені режими SharpHound
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
Колектори генерують JSON, який імпортується через BloodHound GUI.

#### SharpHound з Windows-хоста, не приєднаного до домену

Якщо ваша operator VM не приєднана до цільового домену, вкажіть DNS на DC, запустіть **network-only** shell, переконайтеся, що бачите `SYSVOL`/`NETLOGON` на DC, а потім виконайте collect у віддаленому домені:
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
Це корисно для одноразових jump boxes або робочих станцій оператора, які не мають бути domain-joined.

#### Кросплатформний збір даних з Linux/macOS
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE` є хорошим варіантом за замовчуванням, коли потрібен сумісний із CE результат на хості не під керуванням Windows. `NetExec` зручний, якщо ви вже використовуєте його для перевірки LDAP або spraying і хочете швидко імпортувати граф. Для наборів даних, не пов'язаних з AD, BloodHound OpenGraph можна розширити за допомогою таких collectors, як [ShareHound](../../network-services-pentesting/pentesting-smb/README.md).

### ADPathFinder (пріоритизація шляхів OpenGraph)

[ADPathFinder](https://github.com/NetSPI/AD-PathFinder) працює поверх BloodHound CE/OpenGraph, коли граф надто великий для ручного pivoting. Замість того щоб лише визначати, чи може один principal досягти однієї цілі, він обчислює найкоротші шляхи від багатьох користувачів і комп'ютерів із низькими привілеями до цінних об'єктів, групує шляхи, що використовують одні й ті самі ребра, і показує спільне вузьке місце, яке слід усунути в першу чергу.
```bash
adpathfinder --setup-bloodhound-api
adpathfinder -i SharpHound.zip --ad
adpathfinder -i SharpHound.zip MSSQLHound.zip ConfigManBearPig.zip --ad --pwd Contoso,ContosoIT --ntds ntds.txt -p hashcat.potfile
```
З імпортованими даними `MSSQLHound` і `ConfigManBearPig` одна знахідка може охоплювати [AD CS](ad-certificates.md), [зловживання MSSQL AD](abusing-ad-mssql.md) і [шляхи атак SCCM](sccm-management-point-relay-sql-policy-secrets.md), а не залишати їх як окремі напрямки. Приклад спільного шляху:
```text
J.REPORTER > MSSQL_HasLogin > j.reporter > MSSQL_ExecuteAs > ReportSvc >
MSSQL_Connect > lab-sql01.training.local > MSSQL_LinkedAsAdmin > sccmdb.training.local >
MSSQL_ExecuteOnHost (as DA@TRAINING.LOCAL) > SCCMDB.TRAINING.LOCAL >
SCCM_AssignAllPermissions > SCCM_Site(TRN)
```
- Відстежуйте **effective security context** на кожному ребрі. Шлях стає критичним для домену, щойно один із переходів виконується від імені привілейованої доменної ідентичності, навіть якщо він починався зі звичайного користувача.
- Згруповані findings ідеально підходять для **choke-point remediation**: видалення одного дозволу SQL impersonation, довіри linked-server, шляху зловживання шаблоном сертифіката або призначення SCCM може одночасно зруйнувати багато найкоротших шляхів.
- Перепріоритизуйте "medium" findings з урахуванням **graph context**. Вимкнений SMB signing, WebClient exposure, помилки delegation або SQL-сервери, доступні для NTLM-relay, мають вищий пріоритет, якщо скомпрометований вузол має подальші шляхи до Domain Admins, Domain Controllers, CAs або SCCM site servers.
- Якщо у вас також є результат `NTDS.dit` і potfile hashcat, `--pwd` зіставляє cracked passwords із властивостями BloodHound, щоб швидко відокремити звичайне повторне використання паролів від cracked creds у привілейованих, Kerberoastable, AS-REP roastable або важливих для шляхів облікових записах.

### Збір privilege та logon-right

Windows **token privileges** (наприклад, `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) можуть обходити перевірки DACL, тому їхнє загальнодоменне зіставлення виявляє локальні LPE-ребра, які не відображаються в графах, що містять лише ACL. **Logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` і відповідні їм `SeDeny*`) застосовуються LSA ще до створення token, а заборони мають вищий пріоритет, тому вони суттєво обмежують lateral movement (RDP/SMB/scheduled task/service logon).

**Запускайте collectors з підвищеними привілеями**, коли це можливо: UAC створює filtered token для інтерактивних адміністраторів (через `NtFilterToken`), видаляючи чутливі privileges і позначаючи admin SID як deny-only. Якщо перелічувати privileges з non-elevated shell, важливі privileges будуть невидимими, і BloodHound не імпортує ці ребра.

Тепер існують дві взаємодоповнювальні стратегії збору SharpHound:

- **Парсинг GPO/SYSVOL (stealthy, low-privilege):**
1. Перелічити GPO через LDAP (`(objectCategory=groupPolicyContainer)`) і прочитати `gPCFileSysPath` кожного з них.
2. Отримати `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` із SYSVOL і розібрати секцію `[Privilege Rights]`, яка зіставляє назви privilege/logon-right із SID.
3. Визначити посилання GPO через `gPLink` на OU/sites/domains, перелічити computers у пов’язаних контейнерах і призначити ці rights відповідним machines.
4. Перевага: працює зі звичайним користувачем і є тихим; недолік: бачить лише rights, застосовані через GPO (локальні зміни не враховуються).

- **Перелік через LSA RPC (noisy, accurate):**
- Із context, що має local admin на target, відкрити Local Security Policy і викликати `LsaEnumerateAccountsWithUserRight` для кожного privilege/logon right, щоб через RPC перелічити призначені principals.
- Перевага: охоплює rights, задані локально або поза GPO; недолік: noisy network traffic і потреба в admin на кожному host.

**Приклад abuse path, виявленого цими ребрами:** `CanRDP` ➜ host, де ваш user також має `SeBackupPrivilege` ➜ запустити elevated shell, щоб уникнути filtered tokens ➜ використати backup semantics для читання hive `SAM` і `SYSTEM`, незважаючи на restrictive DACL ➜ exfiltrate їх і запустити `secretsdump.py` offline, щоб отримати локальний Administrator NT hash для lateral movement/privilege escalation.

### Пріоритизація Kerberoasting за допомогою BloodHound

Використовуйте graph context, щоб зробити roasting цільовим:

1. Виконайте збір один раз за допомогою ADWS-compatible collector і працюйте offline:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. Імпортуйте ZIP, позначте скомпрометований principal як owned і запустіть вбудовані queries (*Kerberoastable Users*, *Shortest Paths to Domain Admins*), щоб виявити SPN accounts з admin/infra rights.
3. Пріоритизуйте SPN за blast radius; перед cracking перевірте `pwdLastSet`, `lastLogon` і дозволені encryption types.
4. Запитуйте лише вибрані tickets, виконайте cracking offline, а потім повторно запитайте BloodHound із новим access:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) перелічує **Group Policy Objects** і виявляє misconfigurations.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) виконує **перевірку стану** Active Directory і генерує HTML-звіт з оцінюванням ризиків.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Посилання

- [BloodHound Community Edition v8 запускає OpenGraph: шляхи атак на ідентичності за межами Active Directory та Entra ID](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [За межами ACL: зіставлення шляхів підвищення привілеїв у Windows за допомогою BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)
- [ADPathFinder: зіставлення шляхів атак OpenGraph у BloodHound CE](https://www.netspi.com/blog/technical-blog/network-pentesting/adpathfinder-opengraph-attack-path-mapping-in-bloodhound-ce/)

{{#include ../../banners/hacktricks-training.md}}
