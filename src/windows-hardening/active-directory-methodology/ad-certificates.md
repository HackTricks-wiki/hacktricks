# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Introduction

### Components of a Certificate

- The **Subject** сертифіката позначає його власника.
- A **Public Key** парний із приватним ключем і зв’язує сертифікат з його законним власником.
- The **Validity Period**, визначений датами **NotBefore** та **NotAfter**, позначає період дії сертифіката.
- A unique **Serial Number**, наданий Certificate Authority (CA), ідентифікує кожен сертифікат.
- The **Issuer** відноситься до CA, який видав сертифікат.
- **SubjectAlternativeName** дозволяє додаткові імена для Subject, підвищуючи гнучкість ідентифікації.
- **Basic Constraints** вказують, чи є сертифікат для CA або кінцевого об’єкта, і визначають обмеження використання.
- **Extended Key Usages (EKUs)** описують конкретні призначення сертифіката, такі як code signing або email encryption, за допомогою Object Identifiers (OIDs).
- The **Signature Algorithm** визначає метод підписання сертифіката.
- The **Signature**, створений приватним ключем issuer, гарантує автентичність сертифіката.

### Special Considerations

- **Subject Alternative Names (SANs)** розширюють застосовність сертифіката на кілька ідентичностей, що критично для серверів з кількома доменами. Необхідні надійні процеси випуску, щоб уникнути ризиків підробки з боку атакувальників, які маніпулюють специфікацією SAN.

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS визнає CA certificates у AD forest через визначені контейнери, кожен з яких виконує унікальні ролі:

- **Certification Authorities** container містить довірені root CA certificates.
- **Enrolment Services** container містить інформацію про Enterprise CAs і їх certificate templates.
- **NTAuthCertificates** object включає CA certificates, уповноважені для AD authentication.
- **AIA (Authority Information Access)** container полегшує валідацію ланцюга сертифікатів за допомогою intermediate і cross CA certificates.

### Certificate Acquisition: Client Certificate Request Flow

1. Процес запиту починається з того, що клієнти знаходять Enterprise CA.
2. Створюється CSR, що містить public key та інші деталі, після генерації пари public-private ключів.
3. CA оцінює CSR відносно наявних certificate templates і видає сертифікат на основі прав, визначених у шаблоні.
4. Після затвердження CA підписує сертифікат своїм приватним ключем і повертає його клієнту.

### Certificate Templates

Визначені в AD, ці шаблони описують налаштування та дозволи для видачі сертифікатів, включаючи дозволені EKUs та права на enrollment або модифікацію, що є критичними для керування доступом до сертифікаційних сервісів.

**Template schema version matters.** Legacy **v1** templates (наприклад, вбудований **WebServer** template) не містять кількох сучасних механізмів примусового застосування. Дослідження **ESC15/EKUwu** показали, що на **v1 templates** запитувач може вбудувати **Application Policies/EKUs** у CSR, які будуть **предпочитані над** EKUs, сконфігурованими в шаблоні, що дозволяє отримати client-auth, enrollment agent або code-signing сертифікати лише з правами enrollment. Віддавайте перевагу **v2/v3 templates**, видаляйте або замінюйте v1 за замовчуванням і суворо обмежуйте EKUs до призначеної мети.

## Certificate Enrollment

Процес enrollment для сертифікатів ініціюється адміністратором, який **створює certificate template**, після чого Enterprise Certificate Authority (CA) **публікує** його. Це робить шаблон доступним для клієнтів для enrollment, що досягається додаванням імені шаблону до поля `certificatetemplates` об’єкта Active Directory.

Щоб клієнт міг запитати сертифікат, повинні бути надані **enrollment rights**. Ці права визначаються security descriptors на certificate template та на самому Enterprise CA. Дозволи мають бути надані в обох місцях, щоб запит був успішним.

### Template Enrollment Rights

Ці права вказуються через Access Control Entries (ACEs) і описують дозволи, такі як:

- **Certificate-Enrollment** та **Certificate-AutoEnrollment** права, кожне пов’язане з певними GUID.
- **ExtendedRights**, що дозволяє всі розширені дозволи.
- **FullControl/GenericAll**, що надає повний контроль над шаблоном.

### Enterprise CA Enrollment Rights

Права CA описані в його security descriptor, доступному через Certificate Authority management console. Деякі налаштування навіть дозволяють віддалений доступ низькопривілейованим користувачам, що може становити проблему для безпеки.

### Additional Issuance Controls

Можуть застосовуватися певні контролі, такі як:

- **Manager Approval**: поміщає запити в стан очікування до затвердження менеджером сертифікатів.
- **Enrolment Agents and Authorized Signatures**: визначають кількість необхідних підписів на CSR і необхідні Application Policy OIDs.

### Methods to Request Certificates

Сертифікати можна запитувати через:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), використовуючи DCOM interfaces.
2. **ICertPassage Remote Protocol** (MS-ICPR), через named pipes або TCP/IP.
3. **certificate enrollment web interface**, за умови інсталяції Certificate Authority Web Enrollment role.
4. **Certificate Enrollment Service** (CES), у поєднанні з Certificate Enrollment Policy (CEP) service.
5. **Network Device Enrollment Service** (NDES) для мережевих пристроїв, використовуючи Simple Certificate Enrollment Protocol (SCEP).

Користувачі Windows також можуть запитувати сертифікати через GUI (`certmgr.msc` або `certlm.msc`) або інструменти командного рядка (`certreq.exe` або PowerShell `Get-Certificate` command).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Аутентифікація за допомогою сертифікатів

Active Directory (AD) підтримує аутентифікацію за допомогою сертифікатів, переважно використовуючи протоколи **Kerberos** та **Secure Channel (Schannel)**.

### Процес аутентифікації Kerberos

У процесі аутентифікації Kerberos запит користувача на Ticket Granting Ticket (TGT) підписується за допомогою **private key** сертифіката користувача. Цей запит проходить кілька перевірок контролером домену, зокрема перевірку **validity**, **path** та **revocation status** сертифіката. Також перевіряють, що сертифікат походить із довіреного джерела, та підтверджують присутність видавця в **NTAUTH certificate store**. Після успішних перевірок видається TGT. Об'єкт **`NTAuthCertificates`** в AD, знайдений за адресою:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
є центральним елементом для встановлення довіри при автентифікації за допомогою сертифікатів.

### Аутентифікація Secure Channel (Schannel)

Schannel забезпечує захищені TLS/SSL-з'єднання, де під час handshake клієнт пред'являє сертифікат, який, якщо його успішно перевірено, надає авторизацію доступу. Відображення сертифіката на обліковий запис AD може включати функцію Kerberos **S4U2Self** або **Subject Alternative Name (SAN)** сертифіката, серед інших методів.

### Перерахування служб сертифікації AD

Служби сертифікації AD можна перерахувати за допомогою LDAP-запитів, що виявляють інформацію про **Enterprise Certificate Authorities (CAs)** та їхні конфігурації. Доступ до цього має будь-який користувач, автентифікований у домені, без спеціальних привілеїв. Інструменти, такі як **[Certify](https://github.com/GhostPack/Certify)** і **[Certipy](https://github.com/ly4k/Certipy)**, використовуються для перерахування та оцінки вразливостей у середовищах AD CS.

Команди для використання цих інструментів включають:
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy (>=4.0) for enumeration and identifying vulnerable templates
certipy find -vulnerable -dc-only -u john@corp.local -p Passw0rd -target dc.corp.local

# Request a certificate over the web enrollment interface (new in Certipy 4.x)
certipy req -web -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

---

## Останні вразливості та оновлення безпеки (2022-2025)

| Year | ID / Name | Impact | Key Take-aways |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Privilege escalation* by spoofing machine account certificates during PKINIT. | Patch is included in the **May 10 2022** security updates. Auditing & strong-mapping controls were introduced via **KB5014754**; environments should now be in *Full Enforcement* mode.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* in the AD CS Web Enrollment (certsrv) and CES roles. | Public PoCs are limited, but the vulnerable IIS components are often exposed internally. Patch as of **July 2023** Patch Tuesday.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | On **v1 templates**, a requester with enrollment rights can embed **Application Policies/EKUs** in the CSR that are preferred over the template EKUs, producing client-auth, enrollment agent, or code-signing certificates. | Patched as of **November 12, 2024**. Replace or supersede v1 templates (e.g., default WebServer), restrict EKUs to intent, and limit enrollment rights. |

### Microsoft hardening timeline (KB5014754)

Microsoft introduced a three-phase rollout (Compatibility → Audit → Enforcement) to move Kerberos certificate authentication away from weak implicit mappings. As of **February 11 2025**, domain controllers automatically switch to **Full Enforcement** if the `StrongCertificateBindingEnforcement` registry value is not set. Administrators should:

1. Patch all DCs & AD CS servers (May 2022 or later).
2. Monitor Event ID 39/41 for weak mappings during the *Audit* phase.
3. Re-issue client-auth certificates with the new **SID extension** or configure strong manual mappings before February 2025.

---

## Покращення виявлення та посилення захисту

* **Defender for Identity AD CS sensor (2023-2024)** now surfaces posture assessments for ESC1-ESC8/ESC11 and generates real-time alerts such as *“Domain-controller certificate issuance for a non-DC”* (ESC8) and *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Ensure sensors are deployed to all AD CS servers to benefit from these detections.
* Disable or tightly scope the **“Supply in the request”** option on all templates; prefer explicitly defined SAN/EKU values.
* Remove **Any Purpose** or **No EKU** from templates unless absolutely required (addresses ESC2 scenarios).
* Require **manager approval** or dedicated Enrollment Agent workflows for sensitive templates (e.g., WebServer / CodeSigning).
* Restrict web enrollment (`certsrv`) and CES/NDES endpoints to trusted networks or behind client-certificate authentication.
* Enforce RPC enrollment encryption (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) to mitigate ESC11 (RPC relay). The flag is **on by default**, but is often disabled for legacy clients, which re-opens relay risk.
* Secure **IIS-based enrollment endpoints** (CES/Certsrv): disable NTLM where possible or require HTTPS + Extended Protection to block ESC8 relays.

---



## Джерела

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/](https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/)
{{#include ../../banners/hacktricks-training.md}}
