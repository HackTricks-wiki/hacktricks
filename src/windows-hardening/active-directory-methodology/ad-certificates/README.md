# Сертифікати AD

{{#include ../../../banners/hacktricks-training.md}}

## Вступ

### Компоненти сертифіката

- **Subject** сертифіката позначає його власника.
- **Public Key** пов'язується з приватним ключем, що зберігається у власника, і таким чином підтверджує належність сертифіката його законному власнику.
- **Validity Period**, визначений датами **NotBefore** і **NotAfter**, позначає період дії сертифіката.
- Унікальний **Serial Number**, наданий Certificate Authority (CA), ідентифікує кожен сертифікат.
- **Issuer** — це CA, який видав сертифікат.
- **SubjectAlternativeName** дає змогу вказати додаткові імена суб'єкта, підвищуючи гнучкість ідентифікації.
- **Basic Constraints** визначають, чи призначений сертифікат для CA або кінцевого об'єкта, а також встановлюють обмеження використання.
- **Extended Key Usages (EKUs)** визначають конкретне призначення сертифіката, наприклад підписання коду або шифрування електронної пошти, за допомогою Object Identifiers (OIDs).
- **Signature Algorithm** визначає метод підписання сертифіката.
- **Signature**, створений за допомогою приватного ключа видавця, гарантує автентичність сертифіката.<sup>[[1]](#references)</sup>

### Особливі міркування

- **Subject Alternative Names (SANs)** розширюють застосовність сертифіката до кількох ідентичностей, що особливо важливо для серверів із кількома доменами. Безпечні процеси видачі мають критичне значення для запобігання ризикам імперсонації, коли зловмисники маніпулюють специфікацією SAN.<sup>[[1]](#references)</sup>

### Certificate Authorities (CAs) в Active Directory (AD)

AD CS розпізнає сертифікати CA у лісі AD через спеціальні контейнери, кожен із яких виконує окрему роль:<sup>[[1]](#references)</sup>

- Контейнер **Certification Authorities** містить довірені сертифікати кореневих CA.
- Контейнер **Enrolment Services** містить відомості про Enterprise CA та їхні шаблони сертифікатів.
- Об'єкт **NTAuthCertificates** містить сертифікати CA, авторизовані для автентифікації в AD.
- Контейнер **AIA (Authority Information Access)** сприяє перевірці ланцюжка сертифікатів за допомогою проміжних сертифікатів і сертифікатів перехресних CA.

### Отримання сертифіката: процес запиту клієнтського сертифіката

1. Процес запиту починається з пошуку клієнтами Enterprise CA.
2. Після створення пари відкритого та приватного ключів формується CSR, що містить відкритий ключ та інші відомості.
3. CA перевіряє CSR за доступними шаблонами сертифікатів і видає сертифікат на основі дозволів шаблону.
4. Після схвалення CA підписує сертифікат своїм приватним ключем і повертає його клієнту.<sup>[[1]](#references)</sup>

### Шаблони сертифікатів

Ці шаблони, визначені в AD, описують налаштування та дозволи для видачі сертифікатів, зокрема дозволені EKUs і права на реєстрацію або зміну, що має критичне значення для керування доступом до служб сертифікатів.<sup>[[1]](#references)</sup>

## Реєстрація сертифікатів

Процес реєстрації сертифікатів ініціюється адміністратором, який **створює шаблон сертифіката**, після чого **публікує** його Enterprise Certificate Authority (CA). Це робить шаблон доступним для реєстрації клієнтами; для цього ім'я шаблону додається до поля `certificatetemplates` об'єкта Active Directory.<sup>[[1]](#references)</sup>

Щоб клієнт міг запросити сертифікат, йому потрібно надати **права на реєстрацію**. Ці права визначаються дескрипторами безпеки шаблону сертифіката та самого Enterprise CA. Для успішного виконання запиту дозволи мають бути надані в обох місцях.<sup>[[1]](#references)</sup>

### Права на реєстрацію в шаблоні

Ці права визначаються за допомогою Access Control Entries (ACEs), які описують такі дозволи:<sup>[[1]](#references)</sup>

- Права **Certificate-Enrollment** і **Certificate-AutoEnrollment**, кожне з яких пов'язане з певними GUID.
- **ExtendedRights**, що надає всі розширені дозволи.
- **FullControl/GenericAll**, що забезпечує повний контроль над шаблоном.

### Права на реєстрацію в Enterprise CA

Права CA визначаються в його дескрипторі безпеки, доступному через консоль керування Certificate Authority. Деякі налаштування навіть дають користувачам із низькими привілеями віддалений доступ, що може становити загрозу безпеці.<sup>[[1]](#references)</sup>

### Додаткові елементи керування видачею

Можуть застосовуватися певні елементи керування, зокрема:<sup>[[1]](#references)</sup>

- **Manager Approval**: переводить запити в стан очікування до їх схвалення менеджером сертифікатів.
- **Enrolment Agents and Authorized Signatures**: визначають кількість необхідних підписів у CSR і необхідні Application Policy OIDs.

### Методи запиту сертифікатів

Сертифікати можна запитувати через:<sup>[[1]](#references)</sup>

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE) за допомогою інтерфейсів DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR) через іменовані канали або TCP/IP.
3. **вебінтерфейс реєстрації сертифікатів**, якщо встановлено роль Certificate Authority Web Enrollment.
4. **Certificate Enrollment Service** (CES) разом зі службою Certificate Enrollment Policy (CEP).
5. **Network Device Enrollment Service** (NDES) для мережевих пристроїв із використанням Simple Certificate Enrollment Protocol (SCEP).

Користувачі Windows також можуть запитувати сертифікати через GUI (`certmgr.msc` або `certlm.msc`) або інструменти командного рядка (`certreq.exe` чи команду PowerShell `Get-Certificate`).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Автентифікація за допомогою сертифіката

Active Directory (AD) підтримує автентифікацію за допомогою сертифікатів, переважно використовуючи протоколи **Kerberos** і **Secure Channel (Schannel)**.<sup>[[1]](#references)</sup>

### Процес автентифікації Kerberos

У процесі автентифікації Kerberos запит користувача на отримання Ticket Granting Ticket (TGT) підписується за допомогою **приватного ключа** сертифіката користувача. Цей запит проходить кілька перевірок на контролері домену, зокрема перевірку **чинності**, **ланцюжка сертифікації** та **статусу відкликання** сертифіката. Перевірки також включають підтвердження того, що сертифікат походить із довіреного джерела, а видавець присутній у **сховищі сертифікатів NTAUTH**. Успішне проходження перевірок призводить до видачі TGT. Об'єкт **`NTAuthCertificates`** в AD, розташований за адресою:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
є центральним для встановлення довіри під час автентифікації за сертифікатом.<sup>[[1]](#references)</sup>

### Автентифікація через Secure Channel (Schannel)

Schannel забезпечує захищені TLS/SSL-з'єднання, під час встановлення яких клієнт надає сертифікат, що в разі успішної перевірки авторизує доступ.<sup>[[2]](#references)</sup> Зіставлення сертифіката з обліковим записом AD може виконуватися за допомогою функції Kerberos **S4U2Self** або **Subject Alternative Name (SAN)** сертифіката, серед інших методів.<sup>[[1]](#references)</sup>

### Перерахування служб сертифікатів AD

Служби сертифікатів AD можна перераховувати за допомогою LDAP-запитів, отримуючи інформацію про **Enterprise Certificate Authorities (CAs)** та їхні конфігурації. Це доступно будь-якому автентифікованому в домені користувачу без спеціальних привілеїв.<sup>[[1]](#references)</sup> Такі інструменти, як **[Certify](https://github.com/GhostPack/Certify)** і **[Certipy](https://github.com/ly4k/Certipy)**, використовуються для перерахування та оцінювання вразливостей у середовищах AD CS.<sup>[[3]](#references)</sup>

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

- [1] [Certified Pre-Owned: Зловживання Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [2] [Що таке автентифікація клієнта SSL/TLS і як вона працює?](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [3] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
