# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Introduction

### Components of a Certificate

- **Subject** сертифіката позначає його власника.
- **Public Key** поєднаний із приватно збереженим ключем, щоб прив’язати сертифікат до його законного власника.
- **Validity Period**, визначений датами **NotBefore** і **NotAfter**, позначає строк дії сертифіката.
- Унікальний **Serial Number**, наданий Certificate Authority (CA), ідентифікує кожен сертифікат.
- **Issuer** означає CA, яка видала сертифікат.
- **SubjectAlternativeName** дозволяє додаткові імена для subject, підвищуючи гнучкість ідентифікації.
- **Basic Constraints** визначають, чи є сертифікат для CA або кінцевої сутності, і задають обмеження використання.
- **Extended Key Usages (EKUs)** окреслюють конкретні призначення сертифіката, як-от code signing або email encryption, через Object Identifiers (OIDs).
- **Signature Algorithm** визначає метод підписання сертифіката.
- **Signature**, створений із private key видавця, гарантує автентичність сертифіката.

### Special Considerations

- **Subject Alternative Names (SANs)** розширюють застосовність сертифіката до кількох ідентичностей, що критично для серверів із кількома доменами. Безпечні процеси видачі є життєво важливими, щоб уникнути ризиків impersonation з боку attackers, які маніпулюють SAN specification.

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS визнає CA certificates в AD forest через спеціальні контейнери, кожен із яких виконує унікальні ролі:

- Контейнер **Certification Authorities** містить довірені root CA certificates.
- Контейнер **Enrolment Services** містить відомості про Enterprise CAs та їхні certificate templates.
- Об’єкт **NTAuthCertificates** включає CA certificates, авторизовані для AD authentication.
- Контейнер **AIA (Authority Information Access)** полегшує validation certificate chain за допомогою intermediate і cross CA certificates.

### Certificate Acquisition: Client Certificate Request Flow

1. Процес request починається з того, що clients знаходять Enterprise CA.
2. Створюється CSR, який містить public key та інші дані, після генерації public-private key pair.
3. CA оцінює CSR відповідно до доступних certificate templates, видаючи сертифікат на основі permissions шаблону.
4. Після approval CA підписує сертифікат своїм private key і повертає його client.

### Certificate Templates

Визначені в AD, ці templates описують settings і permissions для видачі сертифікатів, включно з дозволеними EKUs та rights для enrollment або modification, що є критично важливим для керування доступом до certificate services.

**Template schema version matters.** Legacy **v1** templates (for example, the built-in **WebServer** template) lack several modern enforcement knobs. The **ESC15/EKUwu** research showed that on **v1 templates**, a requester can embed **Application Policies/EKUs** in the CSR that are **preferred over** the template's configured EKUs, enabling client-auth, enrollment agent, or code-signing certificates with only enrollment rights. Prefer **v2/v3 templates**, remove or supersede v1 defaults, and tightly scope EKUs to the intended purpose.

## Certificate Enrollment

Процес enrollment для сертифікатів ініціює administrator, який **creates a certificate template**, після чого його **published** Enterprise Certificate Authority (CA). Це робить шаблон доступним для client enrollment; цього досягають, додаючи ім’я шаблону до поля `certificatetemplates` об’єкта Active Directory.

Щоб client міг request сертифікат, мають бути надані **enrollment rights**. Ці rights визначаються security descriptors на certificate template та на самій Enterprise CA. Permissions мають бути надані в обох місцях, щоб request був успішним.

### Template Enrollment Rights

Ці rights задаються через Access Control Entries (ACEs), що описують permissions, як-от:

- **Certificate-Enrollment** і **Certificate-AutoEnrollment** rights, кожен із пов’язаними GUIDs.
- **ExtendedRights**, що дозволяє всі extended permissions.
- **FullControl/GenericAll**, що надає повний контроль над шаблоном.

### Enterprise CA Enrollment Rights

Rights CA описані в її security descriptor, доступному через Certificate Authority management console. Деякі settings навіть дозволяють low-privileged users remote access, що може бути проблемою безпеки.

### Additional Issuance Controls

Можуть застосовуватися певні controls, наприклад:

- **Manager Approval**: переводить requests у стан pending, доки їх не approve certificate manager.
- **Enrolment Agents and Authorized Signatures**: визначають кількість required signatures на CSR і необхідні Application Policy OIDs.

### Methods to Request Certificates

Certificates можна request через:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), використовуючи DCOM interfaces.
2. **ICertPassage Remote Protocol** (MS-ICPR), через named pipes або TCP/IP.
3. **certificate enrollment web interface**, якщо встановлено роль Certificate Authority Web Enrollment.
4. **Certificate Enrollment Service** (CES) у поєднанні з service Certificate Enrollment Policy (CEP).
5. **Network Device Enrollment Service** (NDES) для network devices, використовуючи Simple Certificate Enrollment Protocol (SCEP).

Windows users також можуть request certificates через GUI (`certmgr.msc` або `certlm.msc`) або command-line tools (`certreq.exe` чи команду PowerShell `Get-Certificate`).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Аутентифікація сертифікатом

Active Directory (AD) підтримує аутентифікацію сертифікатом, переважно використовуючи протоколи **Kerberos** і **Secure Channel (Schannel)**.

### Процес аутентифікації Kerberos

У процесі аутентифікації Kerberos запит користувача на Ticket Granting Ticket (TGT) підписується за допомогою **private key** сертифіката користувача. Цей запит проходить кілька перевірок доменним контролером, зокрема перевірку **validity**, **path** та статусу **revocation** сертифіката. Перевірки також включають підтвердження, що сертифікат походить із довіреного джерела, і підтвердження наявності видавця в **NTAUTH certificate store**. Успішні перевірки призводять до видачі TGT. Об'єкт **`NTAuthCertificates`** в AD, який знаходиться за адресою:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
є центральним для встановлення довіри для certificate authentication.

Since the **KB5014754** rollout, modern Kerberos certificate auth is mostly about **mapping strength**, not just EKUs. In hardened forests:

- A certificate that only carries a **UPN/DNS SAN** may no longer be enough for logon.
- The KDC prefers a **strong binding**, typically the **SID security extension** (`1.3.6.1.4.1.311.25.2`) or a strong explicit mapping in `altSecurityIdentities`.
- If the cert lacks a strong mapping, DCs log **Kdcsvc Event ID 39/41** in compatibility mode and deny auth in enforcement mode.
- In mixed attack paths, **ESC9/ESC16** matter because they strip the SID extension from issued certs; operators then rely on explicit mappings or SAN URL SID formats where the attack path supports them.

### Secure Channel (Schannel) Authentication

Schannel facilitates secure TLS/SSL connections, where during a handshake, the client presents a certificate that, if successfully validated, authorizes access. The mapping of a certificate to an AD account may involve Kerberos’s **S4U2Self** function or the certificate’s **Subject Alternative Name (SAN)**, among other methods.

Schannel is also the practical fallback when **PKINIT** is unavailable. For example, if a domain controller does not have a suitable **Smart Card Logon** certificate, `certipy auth`/PKINIT tooling may fail to get a TGT, but the same certificate can still be usable against **LDAPS** or **LDAP StartTLS** for authentication and LDAP operations.

### AD Certificate Services Enumeration

AD's certificate services can be enumerated through LDAP queries, revealing information about **Enterprise Certificate Authorities (CAs)** and their configurations. This is accessible by any domain-authenticated user without special privileges. Tools like **[Certify](https://github.com/GhostPack/Certify)** and **[Certipy](https://github.com/ly4k/Certipy)** are used for enumeration and vulnerability assessment in AD CS environments.

Commands for using these tools include:
```bash
# Enumerate trusted root CA certificates, Enterprise CAs, and web endpoints
Certify.exe cas

# Identify vulnerable templates and dump relevant permissions
Certify.exe find /vulnerable
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /showAdmins

# Certipy 5.x enumeration focused on enabled/vulnerable templates
certipy find -enabled -vulnerable -hide-admins -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Save JSON/CSV output for offline review or BloodHound correlation
certipy find -json -output corp_adcs -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Request a certificate over the Web Enrollment endpoint or DCOM/RPC
certipy req -web -ca corp-CA -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local
certipy req -ca corp-CA -target ca.corp.local -template User -upn administrator@corp.local -sid S-1-5-21-...-500

# Use the issued certificate either for PKINIT or directly for LDAP Schannel auth
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10 -ldap-shell

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

---

## Нещодавні вразливості та оновлення безпеки (2022-2025)

| Year | ID / Name | Impact | Key Take-aways |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Підвищення привілеїв* шляхом підробки сертифікатів машинного облікового запису під час PKINIT. | Патч включено в оновлення безпеки від **10 травня 2022**. Аудит і control сильного зіставлення були введені через **KB5014754**; середовища тепер мають бути в режимі *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Віддалене виконання коду* у ролях AD CS Web Enrollment (certsrv) та CES. | Публічні PoC обмежені, але вразливі компоненти IIS часто доступні всередині мережі. Патч станом на **липень 2023** Patch Tuesday.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | На **v1 templates**, запитувач із правами enrollment може вбудувати **Application Policies/EKUs** у CSR, які мають пріоритет над EKU шаблону, створюючи certificates для client-auth, enrollment agent або code-signing. | Виправлено станом на **12 листопада 2024**. Замініть або витісніть v1 templates (наприклад, стандартний WebServer), обмежте EKU відповідно до призначення та обмежте права enrollment. |

### Часова шкала hardening від Microsoft (KB5014754)

Microsoft запровадила трьохетапне розгортання (Compatibility → Audit → Enforcement), щоб перевести Kerberos certificate authentication від слабких implicit mappings. Станом на **11 лютого 2025**, domain controllers автоматично переходять у **Full Enforcement**, якщо значення реєстру `StrongCertificateBindingEnforcement` не встановлено. Пізніше Microsoft оновила часову шкалу, і повернення до compatibility mode залишається можливим до оновлення безпеки від **9 вересня 2025**. Administrators should:

1. Оновіть усі DCs і AD CS servers (травень 2022 або пізніше).
2. Відстежуйте Event ID 39/41 на предмет слабких mappings під час фази *Audit*.
3. Повторно видайте client-auth certificates з новим **SID extension** або налаштуйте strong manual mappings до того, як enforcement заблокує слабкі mappings.

### Примітки оператора для hardened forests

- **ESC1/ESC6 alone is no longer the whole story** у середовищах 2025+. Якщо ви запитуєте cert для іншого principal, зазвичай також потрібен strong mapping artifact, такий як SID extension або явне mapping.
- **ESC15 (EKUwu)** здебільшого корисний у незапатчених середовищах, тому що він перетворює нешкідливі **v1** templates, такі як **WebServer**, на certificates, здатні до authentication- або enrollment-agent-використання, шляхом інжекції **Application Policies**. Kerberos PKINIT і далі оцінює EKU, але **LDAP Schannel** також враховує Application Policies, що зберігає актуальність LDAP-based abuse.
- **ESC16** — це CA-wide knob: якщо CA глобально вимикає SID security extension, кожен виданий certificate повертається до слабшої поведінки mapping, якщо attack chain не інжектує SID в іншому підтримуваному форматі.

---

## Підсилення detection і hardening

* **Defender for Identity AD CS sensor (2023-2024)** тепер показує posture assessments для ESC1-ESC8/ESC11 і генерує real-time alerts, такі як *“Domain-controller certificate issuance for a non-DC”* (ESC8) та *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Переконайтеся, що sensors розгорнуті на всіх AD CS servers, щоб отримати переваги від цих detections.
* Вимкніть або жорстко обмежте опцію **“Supply in the request”** на всіх templates; надавайте перевагу явно визначеним значенням SAN/EKU.
* Видаліть **Any Purpose** або **No EKU** з templates, якщо це не є абсолютно необхідним (це покриває scenarios ESC2).
* Вимагайте **manager approval** або окремі Enrollment Agent workflows для чутливих templates (наприклад, WebServer / CodeSigning).
* Обмежте web enrollment (`certsrv`) і CES/NDES endpoints довіреними мережами або захистом через client-certificate authentication.
* Увімкніть RPC enrollment encryption (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) для пом’якшення ESC11 (RPC relay). Прапорець **увімкнений за замовчуванням**, але його часто вимикають для legacy clients, що знову відкриває ризик relay.
* Захистіть **IIS-based enrollment endpoints** (CES/Certsrv): вимикайте NTLM, де це можливо, або вимагайте HTTPS + Extended Protection, щоб блокувати ESC8 relays.

---

## References

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
