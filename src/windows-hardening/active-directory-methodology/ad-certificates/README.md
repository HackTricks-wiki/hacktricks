# AD Сертифікати

{{#include ../../../banners/hacktricks-training.md}}

## Вступ

### Компоненти сертифіката

- **Subject** сертифіката позначає його власника.
- **Public Key** пов'язаний з приватним ключем, що дозволяє пов'язати сертифікат з його законним власником.
- **Validity Period**, визначений датами **NotBefore** та **NotAfter**, позначає період дії сертифіката.
- Унікальний **Serial Number**, що присвоюється Certificate Authority (CA), ідентифікує кожний сертифікат.
- **Issuer** позначає CA, який видав сертифікат.
- **SubjectAlternativeName** дозволяє додавати додаткові імена для Subject, підвищуючи гнучкість ідентифікації.
- **Basic Constraints** вказують, чи є сертифікат для CA або кінцевого об'єкта, і визначають обмеження використання.
- **Extended Key Usages (EKUs)** визначають конкретні призначення сертифіката, наприклад code signing або email encryption, через Object Identifiers (OIDs).
- **Signature Algorithm** визначає метод підпису сертифіката.
- **Signature**, створена приватним ключем видавця, гарантує автентичність сертифіката.

### Особливі зауваження

- **Subject Alternative Names (SANs)** розширюють застосовність сертифіката на декілька ідентичностей, що критично для серверів із кількома доменами. Безпечні процеси видачі важливі, щоб уникнути ризику підроблення через маніпуляції атакувальників зі специфікацією SAN.

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS реєструє CA сертифікати в лісі AD через спеціальні контейнери, кожен з яких виконує певну роль:

- Контейнер **Certification Authorities** містить довірені root CA сертифікати.
- Контейнер **Enrolment Services** містить відомості про Enterprise CAs та їхні шаблони сертифікатів.
- Об'єкт **NTAuthCertificates** включає CA сертифікати, авторизовані для автентифікації в AD.
- Контейнер **AIA (Authority Information Access)** сприяє перевірці ланцюжка сертифікатів через проміжні та cross CA сертифікати.

### Отримання сертифіката: потік запиту клієнта

1. Процес запиту починається з пошуку клієнтом Enterprise CA.
2. Створюється CSR, який містить public key та інші дані, після генерації пари public-private ключів.
3. CA оцінює CSR щодо доступних шаблонів сертифікатів і видає сертифікат на основі дозволів шаблону.
4. Після погодження CA підписує сертифікат своїм приватним ключем і повертає його клієнту.

### Шаблони сертифікатів

Шаблони, визначені в AD, описують налаштування та дозволи для видачі сертифікатів, включно з дозволеними EKU та правами на enrollment або модифікацію, що критично для контролю доступу до сервісів сертифікації.

## Реєстрація сертифікатів

Процес реєстрації сертифікатів ініціюється адміністратором, який **створює шаблон сертифіката**, який потім **публікується** Enterprise Certificate Authority (CA). Це робить шаблон доступним для реєстрації клієнтами, що досягається додаванням імені шаблону до поля `certificatetemplates` об'єкта Active Directory.

Щоб клієнт міг запитати сертифікат, повинні бути надані **enrollment rights**. Ці права визначаються через security descriptors на шаблоні сертифіката та на самому Enterprise CA. Права мають бути надані в обох місцях для успішного виконання запиту.

### Права на реєстрацію шаблону

Ці права вказуються через Access Control Entries (ACEs) і деталізують дозволи, такі як:

- **Certificate-Enrollment** та **Certificate-AutoEnrollment** права, кожне з яких пов'язане зі специфічним GUID.
- **ExtendedRights**, що дозволяє всі розширені дозволи.
- **FullControl/GenericAll**, що надає повний контроль над шаблоном.

### Права реєстрації Enterprise CA

Права CA визначені в його security descriptor, доступному через консоль управління Certificate Authority. Деякі налаштування навіть дозволяють віддалений доступ користувачам з низькими привілеями, що може становити ризик безпеці.

### Додаткові обмеження при видачі

Можуть застосовуватись певні контролі, такі як:

- **Manager Approval**: ставить запити в очікуваний стан до затвердження менеджером сертифікатів.
- **Enrolment Agents and Authorized Signatures**: вказують кількість підписів, необхідних на CSR, та необхідні Application Policy OIDs.

### Методи запиту сертифікатів

Сертифікати можна запитувати через:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), використовуючи DCOM інтерфейси.
2. **ICertPassage Remote Protocol** (MS-ICPR), через named pipes або TCP/IP.
3. **certificate enrollment web interface**, при встановленій ролі Certificate Authority Web Enrollment.
4. **Certificate Enrollment Service** (CES) у поєднанні з Certificate Enrollment Policy (CEP) service.
5. **Network Device Enrollment Service** (NDES) для мережевих пристроїв, використовуючи Simple Certificate Enrollment Protocol (SCEP).

Користувачі Windows також можуть запитувати сертифікати через GUI (`certmgr.msc` або `certlm.msc`) або інструменти командного рядка (`certreq.exe` або PowerShell команду `Get-Certificate`).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Аутентифікація за сертифікатами

Active Directory (AD) підтримує автентифікацію за сертифікатами, здебільшого використовуючи протоколи **Kerberos** та **Secure Channel (Schannel)**.

### Процес автентифікації Kerberos

У процесі автентифікації Kerberos запит користувача на Ticket Granting Ticket (TGT) підписується за допомогою **приватного ключа** сертифіката користувача. Цей запит проходить кілька перевірок з боку доменного контролера, включаючи **дійсність**, **ланцюжок сертифікації (path)** та **статус відкликання** сертифіката. Перевірки також включають підтвердження того, що сертифікат походить із довіреного джерела, та підтвердження присутності видавця у **NTAUTH certificate store**. Успішні перевірки призводять до видачі TGT. Об'єкт **`NTAuthCertificates`** в AD, який знаходиться за адресою:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
є центральним для встановлення довіри при автентифікації за допомогою сертифікатів.

### Secure Channel (Schannel) Authentication

Schannel сприяє встановленню захищених TLS/SSL-з'єднань, де під час handshake клієнт пред'являє сертифікат, який у разі успішної валідації надає доступ. Відповідність сертифіката обліковому запису AD може залучати функцію **Kerberos’s S4U2Self** або поле сертифіката **Subject Alternative Name (SAN)**, серед інших методів.

### AD Certificate Services Enumeration

Служби сертифікації AD можна перелічити через LDAP-запити, що розкривають інформацію про **Enterprise Certificate Authorities (CAs)** та їхні конфігурації. До цього має доступ будь-який користувач, автентифікований у домені, без спеціальних привілеїв. Інструменти, такі як **[Certify](https://github.com/GhostPack/Certify)** та **[Certipy](https://github.com/ly4k/Certipy)**, використовуються для перелічення та оцінки вразливостей у середовищах AD CS.

Команди для використання цих інструментів включають:
```bash
# Enumerate trusted root CA certificates, Enterprise CAs and HTTP enrollment endpoints
# Useful flags: /domain, /path, /hideAdmins, /showAllPermissions, /skipWebServiceChecks
Certify.exe cas [/ca:SERVER\ca-name | /domain:domain.local | /path:CN=Configuration,DC=domain,DC=local] [/hideAdmins] [/showAllPermissions] [/skipWebServiceChecks]

# Identify vulnerable certificate templates and filter for common abuse cases
Certify.exe find
Certify.exe find /vulnerable [/currentuser]
Certify.exe find /enrolleeSuppliesSubject   # ESC1 candidates (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
Certify.exe find /clientauth                # templates with client-auth EKU
Certify.exe find /showAllPermissions        # include template ACLs in output
Certify.exe find /json /outfile:C:\Temp\adcs.json

# Enumerate PKI object ACLs (Enterprise PKI container, templates, OIDs) – useful for ESC4/ESC7 discovery
Certify.exe pkiobjects [/domain:domain.local] [/showAdmins]

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
## Посилання

- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
