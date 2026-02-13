# BloodHound & Інші інструменти Enumeration Active Directory

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> ПРИМІТКА: Ця сторінка згруповує деякі з найкорисніших утиліт для **enumerate** та **visualise** відносин Active Directory. Для збору через stealthy канал **Active Directory Web Services (ADWS)** перевірте посилання вище.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) є просунутим **AD viewer & editor**, який дозволяє:

* GUI перегляд дерева каталогів
* Редагування атрибутів об'єктів & security descriptors
* Створення Snapshot / порівняння для офлайн-аналізу

### Quick usage

1. Запустіть інструмент і підключіться до `dc01.corp.local` за допомогою будь-яких облікових даних домену.
2. Створіть офлайн Snapshot через `File ➜ Create Snapshot`.
3. Порівняйте два Snapshot через `File ➜ Compare`, щоб виявити зміни в дозволах.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) витягує великий набір артефактів з домену (ACLs, GPOs, trusts, CA templates …) та генерує **Excel report**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (візуалізація графів)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) використовує теорію графів + Neo4j для виявлення прихованих відносин привілеїв у локальному AD (on-prem) та Azure AD.

### Розгортання (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Інструменти збору

* `SharpHound.exe` / `Invoke-BloodHound` – рідний або PowerShell-варіант
* `AzureHound` – Azure AD enumeration
* **SoaPy + BOFHound** – збір з ADWS (див. посилання вгорі)

#### Поширені режими SharpHound
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
The collectors generate JSON which is ingested via the BloodHound GUI.

### Збір привілеїв та прав входу

Windows **token privileges** (e.g., `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) можуть обходити перевірки DACL, тож їхнє відображення по всьому домену виявляє локальні LPE-ребра, які графи лише по ACL пропускають. **Logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` and their `SeDeny*` counterparts) застосовуються LSA ще до появи токена, і відмови мають пріоритет, тому вони істотно обмежують латеральний рух (RDP/SMB/завдання за розкладом/логін служби).

Запускайте колектори з підвищеними правами, коли можливо: UAC створює фільтрований токен для інтерактивних адміністраторів (через `NtFilterToken`), видаляючи чутливі привілеї й позначаючи admin SIDs як deny-only. Якщо ви перебираєте привілеї з неелевованого шелу, привілеї високої цінності будуть невидимі і BloodHound не імпортує відповідні ребра.

Тепер існують дві доповнювальні стратегії збору SharpHound:

- **GPO/SYSVOL parsing (stealthy, low-privilege):**
1. Перелікуйте GPO через LDAP (`(objectCategory=groupPolicyContainer)`) і зчитайте кожен `gPCFileSysPath`.
2. Отримайте `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` з SYSVOL і розберіть секцію `[Privilege Rights]`, яка відображає імена привілеїв/прав входу в SIDs.
3. Розв’язуйте посилання GPO через `gPLink` на OUs/sites/domains, перелікуйте комп’ютери в пов’язаних контейнерах і приписуйте права цим машинам.
4. Перевага: працює з нормальним користувачем і тихий; недолік: бачить лише права, поширені через GPO (локальні зміни пропускаються).

- **LSA RPC enumeration (noisy, accurate):**
- З контексту з локальним адміністратором на цілій машині відкрийте Local Security Policy і викличте `LsaEnumerateAccountsWithUserRight` для кожного привілею/права входу, щоб перелічити призначені суб’єкти через RPC.
- Перевага: ловить права, задані локально або поза GPO; недолік: шумний мережевий трафік і вимога адміністраторських прав на кожному хості.

**Приклад шляху зловживання, виявленого цими ребрами:** `CanRDP` ➜ хост, де ваш користувач також має `SeBackupPrivilege` ➜ запустити підвищений shell, щоб уникнути фільтрованих токенів ➜ використати механіку бекапу, щоб прочитати `SAM` і `SYSTEM` хіви попри обмежувальні DACL ➜ ексфільтрувати та запустити `secretsdump.py` офлайн, щоб відновити NT-хеш локального Administrator для латерального пересування/підвищення привілеїв.

### Пріоритизація Kerberoasting за допомогою BloodHound

Використовуйте контекст графа, щоб тримати Kerberoasting цілеспрямованим:

1. Зберіть один раз з ADWS-сумісним колектором і працюйте офлайн:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. Імпортуйте ZIP, позначте скомпрометований принципал як owned і запустіть вбудовані запити (*Kerberoastable Users*, *Shortest Paths to Domain Admins*), щоб виявити SPN-акаунти з правами admin/infra.
3. Пріоритетизуйте SPN за blast radius; перегляньте `pwdLastSet`, `lastLogon` та дозволені типи шифрування перед злому.
4. Запитуйте лише обрані квитки, ламајте офлайн, потім знову опитайте BloodHound з новим доступом:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) перелічує **Group Policy Objects** і виявляє помилки конфігурації.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) виконує **health-check** Active Directory та генерує HTML-звіт з оцінкою ризиків.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Посилання

- [HackTheBox Mirage: Ланцюгування NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, та Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [За межами ACLs: Мапування Windows Privilege Escalation Paths за допомогою BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)

{{#include ../../banners/hacktricks-training.md}}
