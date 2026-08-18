# Golden gMSA/dMSA Attack (Офлайн-виведення паролів Managed Service Account)

{{#include ../../banners/hacktricks-training.md}}

## Огляд

Windows Managed Service Accounts — це доменні облікові записи, призначені для запуску служб без необхідності адміністратору керувати довгостроковим паролем:

1. **gMSA** (group Managed Service Account) можна використовувати на комп'ютерах, авторизованих через `msDS-GroupMSAMembership` / `PrincipalsAllowedToRetrieveManagedPassword`.
2. **dMSA** (delegated Managed Service Account) було представлено у **Windows Server 2025**. Він пов'язує звичайну автентифікацію з авторизованими ідентифікаторами машин і може замінити застарілий service account у процесі міграції.

Не плутайте **Golden dMSA** з **BadSuccessor**. Для Golden dMSA потрібна компрометація матеріалу кореневого ключа KDS, після чого виводяться ключі managed account; [BadSuccessor](badsuccessor-dmsa-migration-abuse.md), натомість, зловживає контролем над об'єктом dMSA та його атрибутами міграції.

DC не зберігає незалежно згенерований пароль у відкритому вигляді для кожного gMSA. Він виводить пароль облікового запису з **кореневого ключа KDS**, індексованого за часом ключа Group Key Distribution Protocol (GKDI) і SID облікового запису. Об'єкти кореневих ключів — це об'єкти `msKds-ProvRootKey` у `CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,...`; конфіденційне значення — `msKds-RootKeyData`. `msDS-ManagedPasswordId` — **не GUID**: це двійковий ідентифікатор ключа, що містить GUID кореневого ключа KDS, індекси `L0`/`L1`/`L2` GKDI, а також метадані домену/лісу. DC застосовує KDF із міткою `GMSA PASSWORD` і двійковим SID як контекстом, після чого надає `MSDS-MANAGEDPASSWORD_BLOB` лише principals, авторизованим для отримання пароля gMSA.<sup>[[2]](#references)</sup>

Зазвичай dMSA операційно відрізняється: його секрет має залишатися на DC, а KDC видає credentials авторизованій машині. Однак dMSA повторно використовує базове виведення пароля KDS/GKDI. Golden dMSA безпосередньо відновлює цей секрет, обходячи передбачений процес прив'язки до машини та Credential Guard на service host.<sup>[[1]](#references)</sup>

## Golden gMSA / Golden dMSA Attack

Після вилучення кореневого ключа KDS attacker може виводити паролі облікових записів, пов'язаних із цим ключем, без читання `msDS-ManagedPassword`. Це обходить ACL отримання пароля для окремого облікового запису та переживає звичайні ротації managed password, доки скомпрометований кореневий ключ залишається в користуванні. Для gMSA доступний для читання `msDS-ManagedPasswordId` зазвичай надає точний ідентифікатор ключа. Для dMSA з обмеженим ACL Golden dMSA зменшує відсутній ідентифікатор лише до **1,024 варіантів**.<sup>[[1]](#references)[[2]](#references)</sup>

### Передумови

* Відповідний об'єкт кореневого ключа KDS, зазвичай отриманий із правами Enterprise Admin / Domain Admin у корені лісу, через `SYSTEM` на DC або з відкритої бази даних DC чи backup.<sup>[[1]](#references)[[2]](#references)</sup>
* SID цільового облікового запису, DNS-домен, ім'я лісу та `sAMAccountName`.<sup>[[1]](#references)[[2]](#references)</sup>
* Для прямого обчислення gMSA — закодований у base64 `msDS-ManagedPasswordId`; для Golden dMSA його можна натомість вгадати.<sup>[[1]](#references)[[2]](#references)</sup>
* x64 Windows host із .NET Framework 4.7.2 для [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA).<sup>[[3]](#references)</sup>

### Phase 1 - Extract the KDS root key

`GoldenDMSA` і [`GoldenGMSA`](https://github.com/Semperis/GoldenGMSA) експортують поля об'єкта кореневого ключа як blob у форматі base64. Без аргументу домену tools запитують корінь лісу та потребують відповідного привілейованого доступу до directory. З аргументом домену/лісу `SYSTEM` на DC може запитувати локальну репліку Configuration naming-context цього DC.<sup>[[1]](#references)[[2]](#references)</sup>
```cmd
:: GoldenDMSA: Enterprise Admin, or SYSTEM on a DC with --domain
GoldendMSA.exe kds
GoldendMSA.exe kds -g KDS_ROOT_KEY_GUID
GoldendMSA.exe kds --domain child.example.local

:: GoldenGMSA equivalents
GoldenGMSA.exe kdsinfo
GoldenGMSA.exe kdsinfo --guid KDS_ROOT_KEY_GUID
```
Збережіть ідентифікатор GUID root key та blob root key у форматі base64. Експорт hive `SECURITY`/`SYSTEM` реєстру сам по собі не є root key KDS: авторитетні дані містяться в розділі конфігурації AD.<sup>[[1]](#references)[[2]](#references)</sup>

### Phase 2 - Перелічення об’єктів gMSA / dMSA

Для gMSA отримайте `sAMAccountName`, `objectSid` і бінарний `msDS-ManagedPasswordId`. Останній зазвичай доступний для читання, навіть якщо caller не має дозволу отримувати `msDS-ManagedPassword`.<sup>[[2]](#references)</sup>
```powershell
Get-ADServiceAccount -Filter * -Properties objectSid,msDS-ManagedPasswordId |
Select-Object sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo --domain example.local
```
Стандартний ACL dMSA може перешкоджати LDAP enumeration для користувачів із низькими привілеями. `GoldenDMSA info` може або виконувати query LDAP, або перераховувати candidate RIDs і розв’язувати SIDs через `LsaLookupSids` через `\PIPE\lsarpc`, а потім відрізняти dMSAs від computer accounts і gMSAs.<sup>[[1]](#references)[[3]](#references)</sup>
```cmd
GoldendMSA.exe info -d example.local -m ldap
GoldendMSA.exe info -d example.local -m brute -u alice -p PASSWORD -o EXAMPLE -r 5000
```
### Фаза 3 — Відтворення або вгадування `msDS-ManagedPasswordId`

Ідентифікатор ключа містить `L0Index`, `L1Index` і `L2Index`, а не timestamp створення облікового запису, після якого йдуть випадкові біти. Semperis виявила, що шлях генерації пароля не використовує кандидат `L0Index`, тоді як `L1Index` і `L2Index` обмежені значеннями `0..31`. Отже, зловмисник, який знає GUID root key, домен, forest і SID, може створити всі `32 * 32 = 1,024` ідентифікатори-кандидати.<sup>[[1]](#references)</sup>
```cmd
:: Write 1,024 base64 ManagedPasswordId candidates to KDS_ROOT_KEY_GUID.txt
GoldendMSA.exe wordlist -s DMSA_SID -d example.local -f example.local -k KDS_ROOT_KEY_GUID

:: Derive and validate candidates; -t caches the successful TGT
GoldendMSA.exe bruteforce -s DMSA_SID -i KDS_ROOT_KEY_GUID -k KDS_ROOT_KEY_BASE64 -d example.local -u svc_dmsa$ -t
```
Виведення обчислюються offline, але визначення активного кандидата зазвичай потребує спроб автентифікації. Це може спричинити сплеск невдалих запитів попередньої автентифікації Kerberos або перевірки NTLM, перш ніж буде знайдено правильний ключ. Для ключів AES Kerberos сіль керованого облікового запису, яку використовує інструмент, має вигляд `UPPERCASE.DNS.DOMAIN` + `host` + UPN облікового запису в нижньому регістрі без кінцевого `$` (наприклад, `EXAMPLE.LOCALhostsvc_dmsa.example.local`).<sup>[[1]](#references)</sup>

### Фаза 4 — Обчислення та використання пароля

Якщо точний ідентифікатор відомий, обчисліть 256-байтовий буфер пароля та перетворіть його на матеріал NTLM/AES. Значення base64, надруковане цими інструментами, є закодованим буфером пароля, **а не самим LDAP `MSDS-MANAGEDPASSWORD_BLOB`**.<sup>[[2]](#references)[[3]](#references)</sup>
```cmd
GoldendMSA.exe compute -s ACCOUNT_SID -k KDS_ROOT_KEY_BASE64 -d example.local -m MANAGED_PASSWORD_ID_BASE64
GoldendMSA.exe convert -d example.local -u svc_account$ -p BASE64_PASSWORD

GoldenGMSA.exe compute --sid ACCOUNT_SID --kdskey KDS_ROOT_KEY_BASE64 --pwdid MANAGED_PASSWORD_ID_BASE64
```
Результат NTLM можна використовувати там, де приймається NTLM; ключ AES можна використовувати для overpass-the-hash / TGT-запитів, якщо керований обліковий запис працює лише з AES. Це надає привілеї, SPN, конфігурацію делегування та доступ до ресурсів скомпрометованого керованого сервісного облікового запису без додавання машини атакувальника до `PrincipalsAllowedToRetrieveManagedPassword`.<sup>[[1]](#references)[[2]](#references)</sup>

### Зловживання Configuration-partition у cross-domain середовищі

Об’єкти кореневого ключа KDS зберігаються в контексті іменування Configuration лісу, який реплікується на DC у дочірніх доменах. Отже, `SYSTEM` на DC дочірнього домену може прочитати матеріали KDS кореневого лісу з локальної репліки на дочірньому DC, навіть якщо Domain Admins дочірнього домену не можуть безпосередньо прочитати цей об’єкт із DC кореневого лісу. Якщо зловмисник також може прочитати `msDS-ManagedPasswordId` батьківського домену gMSA, GoldenGMSA може обчислити пароль цього батьківського облікового запису; фільтрація SID не запобігає цій криптографічній атаці.<sup>[[5]](#references)</sup>
```cmd
:: Run as SYSTEM on a child.example.local DC
GoldenGMSA.exe kdsinfo --forest child.example.local

:: Query target metadata in the parent, then combine both inputs
GoldenGMSA.exe gmsainfo --domain example.local
GoldenGMSA.exe compute --sid PARENT_GMSA_SID --domain example.local --forest child.example.local
```
## Виявлення, стримування та відновлення

* Налаштуйте SACL для контейнера **Master Root Keys**, успадкований об'єктами `msKds-ProvRootKey`, для успішного читання `msKds-RootKeyData`. Якщо ввімкнено аудит доступу до служб каталогів, online-вилучення створює подію безпеки **4662**; досліджуйте суб'єкти, які не є очікуваними DC або операторами Tier-0. Також аудіюйте зміни цих SACL і ACL об'єктів root key.<sup>[[1]](#references)[[2]](#references)[[4]](#references)</sup>
* Атака child-to-parent читає об'єкт KDS з локальної репліки скомпрометованого child DC, тому домен forest root може не зафіксувати це читання. У батьківському домені аудіюйте успішне читання `msDS-ManagedPasswordId` (schema GUID `0e78295a-c6d3-0a40-b491-d62251ffa0a6`) на об'єктах `msDS-GroupManagedServiceAccount` і досліджуйте читання, виконані principals з іншого домену.<sup>[[5]](#references)</sup>
* Співвідносіть доступ до об'єктів KDS з нетиповими logon для managed accounts і сплесками помилок Kerberos/NTLM для service accounts із суфіксом `$`. Offline-обчислення після попередньої крадіжки бази даних або backup не буде видимим для live DC.<sup>[[1]](#references)[[3]](#references)</sup>
* Звичайної ротації паролів недостатньо після розкриття root key. Поточна процедура recovery від Microsoft створює новий KDS root key, перезапускає KDS на всіх відповідних DC і переводить уражені accounts на цей key. Якщо масштаб або час розкриття невідомі, а очікування безпечної ротації неприйнятне, замініть кожен gMSA, який використовував скомпрометований key; якщо масштаб відомий, Microsoft документує workflow authoritative restore для примусової безпечної ротації. Перевірте новий GUID key у `msDS-ManagedPasswordId` перед видаленням старого key.<sup>[[4]](#references)</sup>
* Вважайте доступ до баз даних DC і backup, реплікацію Configuration-partition та адміністрування KDS root key ресурсами Tier-0. Зменшення `ManagedPasswordIntervalInDays` обмежує деякі вікна recovery, але не відкликає вже скомпрометований root key.<sup>[[4]](#references)</sup>

## Інструменти

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) - enumeration dMSA/gMSA, генерація ідентифікаторів, validation 1 024 кандидатів, обчислення паролів і конвертація NTLM/AES.<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) - enumeration gMSA/KDS та online-, offline- і cross-domain-обчислення паролів.<sup>[[2]](#references)</sup>
* [`Rubeus`](https://github.com/GhostPack/Rubeus) та [`Impacket`](https://github.com/fortra/impacket) - використовуйте або перевіряйте отримані NTLM/AES keys під час авторизованого тестування.



## References

- [1] [Golden dMSA - обхід автентифікації для делегованих Managed Service Accounts](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [Атаки gMSA в Active Directory](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Репозиторій Semperis/GoldenDMSA на GitHub](https://github.com/Semperis/GoldenDMSA)
- [4] [Microsoft - Як відновитися після атаки Golden gMSA](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/recover-from-golden-gmsa-attack)
- [5] [SID filter як межа безпеки між доменами? Частина 5 - trust attack Golden gMSA](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
{{#include ../../banners/hacktricks-training.md}}
