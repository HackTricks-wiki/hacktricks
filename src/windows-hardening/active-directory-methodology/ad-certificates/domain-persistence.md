# AD CS Персистентність у домені

{{#include ../../../banners/hacktricks-training.md}}

**This is a summary of the domain persistence techniques shared in [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Check it for further details.

## Forging Certificates with Stolen CA Certificates - DPERSIST1

Як визначити, що сертифікат є CA сертифікатом?

Можна встановити, що сертифікат є CA сертифікатом, якщо виконані кілька умов:

- Сертифікат зберігається на CA сервері, а його приватний ключ захищений за допомогою DPAPI машини або апаратно (наприклад, TPM/HSM), якщо ОС це підтримує.
- Поля Issuer і Subject сертифіката збігаються з distinguished name самого CA.
- Розширення "CA Version" присутнє виключно в CA сертифікатах.
- У сертифіката відсутні поля Extended Key Usage (EKU).

Щоб витягти приватний ключ цього сертифіката, підтримуваний спосіб — використати інструмент `certsrv.msc` на CA сервері через вбудований GUI. Однак цей сертифікат не відрізняється від інших сертифікатів, що зберігаються в системі; тому для його витягання можна застосувати методи на кшталт [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2).

Сертифікат і приватний ключ також можна отримати за допомогою Certipy, виконавши наступну команду:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Після отримання сертифіката CA та його приватного ключа у форматі `.pfx`, такі інструменти, як [ForgeCert](https://github.com/GhostPack/ForgeCert), можна використати для генерації дійсних сертифікатів:
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
> Користувач, для якого фальсифікується сертифікат, має бути активним і здатним автентифікуватися в Active Directory для успіху процесу. Підробка сертифіката для спеціальних облікових записів, таких як krbtgt, неефективна.

Цей підроблений сертифікат буде **дійсним** до вказаної дати завершення та доти, поки дійсний кореневий сертифікат CA (зазвичай від 5 до **10+ років**). Він також дійсний для **машин**, тож у поєднанні з **S4U2Self** атакуючий може **підтримувати персистентність на будь-якій машині домену** стільки, скільки дійсний сертифікат CA.  
Крім того, **сертифікати, згенеровані** цим методом **не можна відкликати**, оскільки CA про них не знає.

### Робота під суворим застосуванням відображення сертифікатів (2025+)

З 11 лютого 2025 року (після розгортання KB5014754) контролери домену за замовчуванням перейшли у **Full Enforcement** для відображень сертифікатів. Практично це означає, що ваші підроблені сертифікати мають або:

- Містити міцне прив'язування до цільового облікового запису (наприклад, SID security extension), або
- Бути поєднаними з міцним, явним відображенням на атрибуті `altSecurityIdentities` цільового об'єкта.

Надійний підхід для персистентності — випустити підроблений сертифікат, зв'язаний з викраденим Enterprise CA, а потім додати сильне явне відображення до цільового principal:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Примітки
- Якщо ви можете створити підроблені сертифікати, що містять розширення безпеки SID, вони відобразяться імпліцитно навіть під Full Enforcement. В іншому випадку надавайте перевагу явним та строгим відповідностям. Див. [account-persistence](account-persistence.md) для детальнішої інформації про явні відповідності.
- Відкликання не допомагає захисникам у цьому випадку: підроблені сертифікати невідомі базі даних CA і тому не можуть бути відкликані.

## Trusting Rogue CA Certificates - DPERSIST2

The `NTAuthCertificates` object is defined to contain one or more **CA certificates** within its `cacertificate` attribute, which Active Directory (AD) utilizes. The verification process by the **domain controller** involves checking the `NTAuthCertificates` object for an entry matching the **CA specified** in the Issuer field of the authenticating **certificate**. Authentication proceeds if a match is found.

A self-signed CA certificate can be added to the `NTAuthCertificates` object by an attacker, provided they have control over this AD object. Normally, only members of the **Enterprise Admin** group, along with **Domain Admins** or **Administrators** in the **forest root’s domain**, are granted permission to modify this object. They can edit the `NTAuthCertificates` object using `certutil.exe` with the command `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, or by employing the [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

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
Ця можливість особливо актуальна при використанні разом із раніше описаним методом за участю ForgeCert для динамічної генерації сертифікатів.

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## Зловмисна неправильна конфігурація - DPERSIST3

Можливості для **персистенції** через **зміни дескрипторів безпеки компонентів AD CS** численні. Зміни, описані в розділі "[Domain Escalation](domain-escalation.md)", можуть бути зловмисно реалізовані атакуючим із підвищеними правами. Це включає додавання "control rights" (наприклад, WriteOwner/WriteDACL/etc.) до чутливих компонентів, таких як:

- Об'єкт **AD computer** сервера **CA**
- RPC/DCOM сервер **CA server’а**
- Будь-який **нащадковий об'єкт AD або контейнер** у **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (наприклад, контейнер Certificate Templates, контейнер Certification Authorities, об'єкт NTAuthCertificates тощо)
- **AD групи**, яким делеговано права контролю AD CS за замовчуванням або організацією (наприклад, вбудована група Cert Publishers та будь-які її члени)

Приклад шкідливої реалізації: атакуючий із **підвищеними правами** в домені додає право **`WriteOwner`** до шаблону сертифіката за замовчуванням **`User`**, призначаючи себе як принципала для цього права. Щоб скористатися цим, атакуючий спочатку змінює власника шаблону **`User`** на себе. Далі на шаблон встановлюється прапорець **mspki-certificate-name-flag** зі значенням **1** для ввімкнення **`ENROLLEE_SUPPLIES_SUBJECT`**, що дозволяє користувачу вказати Subject Alternative Name у запиті. Після цього атакуючий може **зареєструватися** за допомогою цього **шаблону**, обравши ім'я **domain administrator** як альтернативне ім'я, і використовувати отриманий сертифікат для автентифікації як DA.

Практичні параметри, які можуть встановити зловмисники для довгострокової стійкості в домені (див. {{#ref}}domain-escalation.md{{#endref}} для повних деталей та виявлення):

- Прапори політики CA, що дозволяють SAN від заявників (наприклад, увімкнення `EDITF_ATTRIBUTESUBJECTALTNAME2`). Це зберігає шляхи типу ESC1 експлуатованими.
- DACL або налаштування шаблону, які дозволяють випуск сертифікатів, придатних для автентифікації (наприклад, додавання EKU Client Authentication, ввімкнення `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Контроль над об'єктом `NTAuthCertificates` або контейнерами CA для постійного повторного введення зловмисних емітерів, якщо захисники намагаються очищувати середовище.

> [!TIP]
> У захищених середовищах після KB5014754 поєднання цих неправильних налаштувань із явними строгими відображеннями (`altSecurityIdentities`) забезпечує придатність ваших виданих або підроблених сертифікатів навіть коли DCs застосовують строгі відображення.



## References

- Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference and forge/auth usage. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
{{#include ../../../banners/hacktricks-training.md}}
