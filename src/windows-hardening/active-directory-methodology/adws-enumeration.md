# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## Що таке ADWS?

Active Directory Web Services (ADWS) увімкнено за замовчуванням на кожному Domain Controller починаючи з Windows Server 2008 R2 і слухає TCP 9389. Незважаючи на назву, HTTP не задіяно. Натомість сервіс експонує LDAP-style дані через стек пропрієтарних .NET framing протоколів:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Оскільки трафік інкапсульований у цих бінарних SOAP-фреймах і йде по нетиповому порту, перерахування через ADWS значно менше ймовірно буде інспектоване, відфільтроване або підписане, ніж класичний LDAP/389 & 636 трафік. Для операторів це означає:

* Stealthier recon – Blue teams часто зосереджуються на LDAP-запитах.
* Можливість збирати дані з non-Windows hosts (Linux, macOS), тунелювавши 9389/TCP через SOCKS proxy.
* Ті ж дані, які ви отримали б через LDAP (users, groups, ACLs, schema тощо), і можливість виконувати writes (наприклад `msDs-AllowedToActOnBehalfOfOtherIdentity` для RBCD).

Взаємодії ADWS реалізовані поверх WS-Enumeration: кожен запит починається з повідомлення `Enumerate`, яке визначає LDAP filter/attributes і повертає `EnumerationContext` GUID, після чого надсилається одне або декілька повідомлень `Pull`, які потоково повертають до серверно-визначеного вікна результатів. Contexts втрачають чинність приблизно через 30 хвилин, тож інструментам потрібно або розбивати результати на сторінки, або дробити фільтри (префіксні запити по CN), щоб не втратити стан. При запиті security descriptors вкажіть контрол `LDAP_SERVER_SD_FLAGS_OID`, щоб опустити SACLs, інакше ADWS просто опустить атрибут `nTSecurityDescriptor` зі свого SOAP-відповіді.

> NOTE: ADWS також використовується багатьма RSAT GUI/PowerShell інструментами, тож трафік може зливатися з легітимною адміністративною активністю.

## SoaPy – Нативний Python-клієнт

[SoaPy](https://github.com/logangoins/soapy) — це повна re-implementation стеку протоколів ADWS на чистому Python. Він формує NBFX/NBFSE/NNS/NMF фрейми байт у байт, дозволяючи збирати дані з Unix-подібних систем без звернення до .NET runtime.

### Ключові можливості

* Підтримка proxying через SOCKS (корисно з C2 implants).
* Дрібнозернисті search filters, ідентичні LDAP `-q '(objectClass=user)'`.
* Опціональні write операції (`--set` / `--delete`).
* BOFHound output mode для прямого імпорту в BloodHound.
* Прапорець `--parse` для приведення timestamp / `userAccountControl` у зручний для людини вигляд.

### Цільові прапори збору та операції запису

SoaPy постачається з куратованими switches, що відтворюють найбільш поширені LDAP hunting tasks через ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, плюс сирі `--query` / `--filter` ручки для кастомних pulls. Поєднуйте їх з write primitives, такими як `--rbcd <source>` (sets `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging для таргетованого Kerberoasting) та `--asrep` (переключає `DONT_REQ_PREAUTH` в `userAccountControl`).

Example targeted SPN hunt that only returns `samAccountName` and `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Використовуйте ті самі host/credentials, щоб негайно weaponise findings: dump RBCD-capable objects з допомогою `--rbcds`, потім застосуйте `--rbcd 'WEBSRV01$' --account 'FILE01$'` щоб підготувати Resource-Based Constrained Delegation chain (див. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) для повного шляху зловживання).

### Встановлення (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Sopa - практичний клієнт для ADWS на Golang

Подібно до soapy, [sopa](https://github.com/Macmod/sopa) реалізує стек протоколів ADWS (MS-NNS + MC-NMF + SOAP) на Golang і надає опції командного рядка для виконання викликів ADWS, таких як:

* **Пошук і отримання об'єктів** - `query` / `get`
* **Життєвий цикл об'єкта** - `create [user|computer|group|ou|container|custom]` and `delete`
* **Редагування атрибутів** - `attr [add|replace|delete]`
* **Керування обліковими записами** - `set-password` / `change-password`
* та інші, наприклад `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

## SOAPHound – масовий збір ADWS (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) — це .NET-колектор, який тримає всі LDAP-взаємодії всередині ADWS і видає JSON, сумісний з BloodHound v4. Він один раз будує повний кеш `objectSid`, `objectGUID`, `distinguishedName` та `objectClass` (`--buildcache`), а потім повторно використовує його для високопродуктивних проходів `--bhdump`, `--certdump` (ADCS) або `--dnsdump` (AD-integrated DNS), тож з DC виходить лише близько ~35 критичних атрибутів. AutoSplit (`--autosplit --threshold <N>`) автоматично розбиває запити по префіксу CN, щоб залишатися в межах 30-хвилинного таймауту EnumerationContext у великих лісах.

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
Експортовані JSON напряму інтегруються в SharpHound/BloodHound робочі процеси — див. [BloodHound methodology](bloodhound.md) для ідей щодо подальшої побудови графів. AutoSplit робить SOAPHound стійким у лісах з мільйонами об'єктів, одночасно знижуючи кількість запитів порівняно зі знімками в стилі ADExplorer.

## Стелс-робочий процес збору AD

Нижче наведено робочий процес, який показує, як перелічити **об'єкти домену та ADCS** через ADWS, конвертувати їх у BloodHound JSON та шукати шляхи атак на основі сертифікатів — усе з Linux:

1. **Tunnel 9389/TCP** з цільової мережі на вашу машину (наприклад через Chisel, Meterpreter, SSH dynamic port-forward тощо). Експортуйте `export HTTPS_PROXY=socks5://127.0.0.1:1080` або використайте параметри SoaPy `--proxyHost/--proxyPort`.

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
4. **Перетворити на BloodHound:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **Завантажте ZIP** у BloodHound GUI і виконайте cypher-запити, такі як `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c`, щоб виявити шляхи ескалації сертифікатів (ESC1, ESC8 тощо).

### Запис `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Поєднайте це з `s4u2proxy`/`Rubeus /getticket` для повного **Resource-Based Constrained Delegation** ланцюга (див. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Підсумок інструментів

| Призначення | Інструмент | Примітки |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Конвертує журнали SoaPy/ldapsearch |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Може бути проксований через той самий SOCKS |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | Універсальний клієнт для взаємодії з відомими ADWS endpoints — дозволяє enumeration, object creation, attribute modifications, and password changes |

## References

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
