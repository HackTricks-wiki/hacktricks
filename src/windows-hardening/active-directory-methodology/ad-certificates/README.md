# Сертифікати AD

{{#include ../../../banners/hacktricks-training.md}}

## Вступ

### Компоненти сертифіката

- **Subject** сертифіката позначає його власника.
- **Public Key** пов'язаний із приватним ключем, що зберігається у власника, для прив'язки сертифіката до його законного власника.
- **Validity Period**, визначений датами **NotBefore** і **NotAfter**, позначає період чинності сертифіката.
- Унікальний **Serial Number**, наданий Certificate Authority (CA), ідентифікує кожен сертифікат.
- **Issuer** — це CA, який видав сертифікат.
- **SubjectAlternativeName** дає змогу додавати додаткові імена для суб'єкта, підвищуючи гнучкість ідентифікації.
- **Basic Constraints** визначають, чи призначений сертифікат для CA або кінцевого об'єкта, а також встановлюють обмеження використання.
- **Extended Key Usages (EKUs)** визначають конкретне призначення сертифіката, наприклад підписування коду або шифрування електронної пошти, за допомогою Object Identifiers (OIDs).
- **Signature Algorithm** визначає метод підписування сертифіката.
- **Signature**, створений за допомогою приватного ключа видавця, гарантує автентичність сертифіката.<sup>[[1]](#references)</sup>

### Особливі міркування

- **Subject Alternative Names (SANs)** розширюють застосовність сертифіката на кілька ідентичностей, що особливо важливо для серверів із кількома доменами. Безпечні процеси видачі мають вирішальне значення для запобігання ризикам імперсонації з боку зловмисників, які маніпулюють специфікацією SAN.<sup>[[1]](#references)</sup>

### Certificate Authorities (CAs) в Active Directory (AD)

AD CS розпізнає сертифікати CA у лісі AD через спеціально призначені контейнери, кожен із яких виконує унікальну роль:<sup>[[1]](#references)</sup>

- Контейнер **Certification Authorities** містить довірені сертифікати кореневих CA.
- Контейнер **Enrolment Services** містить відомості про Enterprise CAs та їхні шаблони сертифікатів.
- Об'єкт **NTAuthCertificates** містить сертифікати CA, авторизовані для автентифікації AD.
- Контейнер **AIA (Authority Information Access)** забезпечує перевірку ланцюжка сертифікатів за допомогою проміжних сертифікатів і сертифікатів між CA.

### Отримання сертифіката: потік запиту клієнтського сертифіката

1. Процес запиту починається з пошуку клієнтами Enterprise CA.
2. Після створення пари відкритого та приватного ключів створюється CSR, що містить відкритий ключ та інші відомості.
3. CA перевіряє CSR за доступними шаблонами сертифікатів і видає сертифікат відповідно до дозволів шаблону.
4. Після схвалення CA підписує сертифікат своїм приватним ключем і повертає його клієнту.<sup>[[1]](#references)</sup>

### Шаблони сертифікатів

Визначені в AD шаблони описують налаштування та дозволи для видачі сертифікатів, зокрема дозволені EKUs і права на реєстрацію або зміну, що є критично важливим для керування доступом до служб сертифікатів.<sup>[[1]](#references)</sup>

## Реєстрація сертифікатів

Процес реєстрації сертифікатів ініціюється адміністратором, який **створює шаблон сертифіката**, після чого Enterprise Certificate Authority (CA) **публікує** його. Це робить шаблон доступним для реєстрації клієнтами; цього досягають додаванням імені шаблону до поля `certificatetemplates` об'єкта Active Directory.<sup>[[1]](#references)</sup>

Щоб клієнт міг запитати сертифікат, йому потрібно надати **права на реєстрацію**. Ці права визначаються дескрипторами безпеки на шаблоні сертифіката та самому Enterprise CA. Для успішного виконання запиту дозволи мають бути надані в обох місцях.<sup>[[1]](#references)</sup>

### Права на реєстрацію в шаблоні

Ці права визначаються за допомогою Access Control Entries (ACEs), які описують такі дозволи:<sup>[[1]](#references)</sup>

- Права **Certificate-Enrollment** і **Certificate-AutoEnrollment**, кожне з яких пов'язане з певними GUID.
- **ExtendedRights**, що дають змогу використовувати всі розширені дозволи.
- **FullControl/GenericAll**, що забезпечують повний контроль над шаблоном.

### Права на реєстрацію в Enterprise CA

Права CA визначені в його дескрипторі безпеки, доступному через консоль керування Certificate Authority. Деякі налаштування навіть дають користувачам із низьким рівнем привілеїв віддалений доступ, що може становити загрозу безпеці.<sup>[[1]](#references)</sup>

### Додаткові засоби керування видачею

Можуть застосовуватися певні засоби керування, зокрема:<sup>[[1]](#references)</sup>

- **Manager Approval**: переводить запити в стан очікування, доки їх не схвалить менеджер сертифікатів.
- **Enrolment Agents and Authorized Signatures**: визначають кількість підписів, необхідних для CSR, і потрібні Application Policy OIDs.

### Методи запиту сертифікатів

Сертифікати можна запитувати через:<sup>[[1]](#references)</sup>

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE) із використанням інтерфейсів DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR) через іменовані канали або TCP/IP.
3. **Вебінтерфейс реєстрації сертифікатів**, якщо інстальовано роль Certificate Authority Web Enrollment.
4. **Certificate Enrollment Service** (CES) у поєднанні зі службою Certificate Enrollment Policy (CEP).
5. **Network Device Enrollment Service** (NDES) для мережевих пристроїв із використанням Simple Certificate Enrollment Protocol (SCEP).

Користувачі Windows також можуть запитувати сертифікати через GUI (`certmgr.msc` або `certlm.msc`) або інструменти командного рядка (`certreq.exe` чи команду PowerShell `Get-Certificate`).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Автентифікація за сертифікатом

Active Directory (AD) підтримує автентифікацію за сертифікатами, переважно використовуючи протоколи **Kerberos** і **Secure Channel (Schannel)**.<sup>[[1]](#references)</sup>

### Процес автентифікації Kerberos

У процесі автентифікації Kerberos запит користувача на отримання Ticket Granting Ticket (TGT) підписується за допомогою **приватного ключа** сертифіката користувача. Цей запит проходить кілька перевірок на контролері домену, зокрема перевірку **чинності**, **ланцюжка** та статусу **відкликання** сертифіката. Перевірки також включають підтвердження того, що сертифікат походить із довіреного джерела, а також наявності видавця у **сховищі сертифікатів NTAUTH**. У разі успішного проходження перевірок видається TGT. Об’єкт **`NTAuthCertificates`** в AD, розташований за адресою:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
є центральним для встановлення довіри під час автентифікації за сертифікатами.<sup>[[1]](#references)</sup>

### Автентифікація через Secure Channel (Schannel)

Schannel забезпечує безпечні TLS/SSL-з’єднання, під час встановлення яких клієнт надає сертифікат, що в разі успішної перевірки авторизує доступ.<sup>[[2]](#references)</sup> Зіставлення сертифіката з обліковим записом AD може виконуватися за допомогою функції Kerberos **S4U2Self** або **Subject Alternative Name (SAN)** сертифіката, а також іншими методами.<sup>[[1]](#references)</sup>

### Перерахування служб сертифікатів AD

Служби сертифікатів AD можна перерахувати за допомогою LDAP-запитів, отримавши інформацію про **Enterprise Certificate Authorities (CAs)** та їхні конфігурації. Це доступно будь-якому автентифікованому в домені користувачу без спеціальних привілеїв.<sup>[[1]](#references)</sup> Такі інструменти, як **[Certify](https://github.com/GhostPack/Certify)** і **[Certipy](https://github.com/ly4k/Certipy)**, використовуються для перерахування та оцінювання вразливостей у середовищах AD CS.<sup>[[3]](#references)</sup>

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
Rubeus також може використовувати захищений паролем PFX-сертифікат для автентифікації PKINIT і запитувати TGT. Необов’язковий перемикач `/getcredentials` запитує сервісний квиток U2U та намагається відновити NT-хеш облікового запису:<sup>[[4]](#references)</sup>
```powershell
Rubeus.exe asktgt /user:<USER> /certificate:C:\temp\leaked.pfx /password:<PFX_PASSWORD> /getcredentials /ptt
```
## References

- [1] [Certified Pre-Owned: Зловживання службами сертифікатів Active Directory](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [2] [Що таке автентифікація клієнта SSL/TLS і як вона працює?](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [3] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
{{#include ../../../banners/hacktricks-training.md}}
