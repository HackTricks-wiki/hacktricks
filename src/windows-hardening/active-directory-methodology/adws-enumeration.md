# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## What is ADWS?

Active Directory Web Services (ADWS) is **enabled by default on every Domain Controller since Windows Server 2008 R2** and listens on TCP **9389**.  Despite the name, **no HTTP is involved**.  Instead, the service exposes LDAP-style data through a stack of proprietary .NET framing protocols:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Оскільки трафік інкапсульований всередині цих бінарних SOAP-фреймів і передається через рідко використовуваний порт, **enumeration через ADWS значно рідше буде інспектуватися, фільтруватися або розпізнаватися за сигнатурами, ніж класичний LDAP/389 & 636 трафік**. Для операторів це означає:

* Stealthier recon – Blue teams often concentrate on LDAP queries.
* Можливість збирати дані з **non-Windows hosts (Linux, macOS)** шляхом тунелювання 9389/TCP через SOCKS proxy.
* Ті самі дані, які ви б отримали через LDAP (users, groups, ACLs, schema тощо) та можливість виконувати **writes** (наприклад `msDs-AllowedToActOnBehalfOfOtherIdentity` для **RBCD**).

ADWS interactions are implemented over WS-Enumeration: every query starts with an `Enumerate` message that defines the LDAP filter/attributes and returns an `EnumerationContext` GUID, followed by one or more `Pull` messages that stream up to the server-defined result window. Contexts age out after ~30 minutes, so tooling either needs to page results or split filters (prefix queries per CN) to avoid losing state. When asking for security descriptors, specify the `LDAP_SERVER_SD_FLAGS_OID` control to omit SACLs, otherwise ADWS simply drops the `nTSecurityDescriptor` attribute from its SOAP response.

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
Використайте той самий хост/облікові дані, щоб негайно використовувати знахідки: вивантажте RBCD-capable об'єкти за допомогою `--rbcds`, потім застосуйте `--rbcd 'WEBSRV01$' --account 'FILE01$'` для підготовки ланцюга Resource-Based Constrained Delegation (див. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) для повного шляху зловживання).

### Встановлення (хост оператора)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## SOAPHound – Збір великого обсягу ADWS (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) є .NET-колектором, який тримає всі LDAP-взаємодії всередині ADWS і генерує BloodHound v4-compatible JSON. Він створює повний кеш `objectSid`, `objectGUID`, `distinguishedName` та `objectClass` один раз (`--buildcache`), потім повторно використовує його для високопродуктивних проходів `--bhdump`, `--certdump` (ADCS) або `--dnsdump` (AD-integrated DNS), тож лише ~35 критичних атрибутів покидають DC. AutoSplit (`--autosplit --threshold <N>`) автоматично розбиває запити за префіксом CN, щоб не перевищувати 30‑хвилинний таймаут EnumerationContext у великих лісах.

Типовий робочий процес на VM оператора, приєднаного до домену:
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
Експортовані JSON-об'єкти безпосередньо у робочі процеси SharpHound/BloodHound — див. [BloodHound methodology](bloodhound.md) для ідей подальшої візуалізації графів. AutoSplit робить SOAPHound стійким у лісах з мільйонами об'єктів, одночасно знижуючи кількість запитів порівняно зі знімками в стилі ADExplorer.

## Прихований робочий процес збору AD

Наступний воркфлоу показує, як перелічити **доменні & ADCS об'єкти** через ADWS, конвертувати їх у BloodHound JSON та шукати шляхи атаки на основі сертифікатів — все це з Linux:

1. **Пробросити тунель 9389/TCP** з цільової мережі на вашу машину (наприклад через Chisel, Meterpreter, SSH dynamic port-forward тощо).  Експортуйте `export HTTPS_PROXY=socks5://127.0.0.1:1080` або використайте SoaPy’s `--proxyHost/--proxyPort`.

2. **Collect the root domain object:**
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
5. **Завантажте ZIP** у BloodHound GUI та виконайте cypher-запити, наприклад `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c`, щоб виявити шляхи ескалації сертифікатів (ESC1, ESC8 тощо).

### Запис `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Поєднайте це з `s4u2proxy`/`Rubeus /getticket` для повного ланцюга **Resource-Based Constrained Delegation** (див. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Короткий огляд інструментів

| Призначення | Інструмент | Примітки |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, читання/запис |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, орієнтований на кеш, режими BH/ADCS/DNS |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Перетворює SoaPy/ldapsearch логи |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Можна проксувати через той самий SOCKS |

## Посилання

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – специфікації MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Прихована інвентаризація Active Directory середовищ через ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
