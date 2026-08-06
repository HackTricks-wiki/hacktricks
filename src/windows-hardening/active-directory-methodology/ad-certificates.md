# Сертифікати AD

{{#include ../../banners/hacktricks-training.md}}

## Вступ

### Компоненти сертифіката

- **Subject** сертифіката позначає його власника.
- **Public Key** пов'язаний із приватним ключем, який зберігається у власника, щоб пов'язати сертифікат із його законним власником.
- **Validity Period**, визначений датами **NotBefore** і **NotAfter**, позначає період чинності сертифіката.
- Унікальний **Serial Number**, наданий Certificate Authority (CA), ідентифікує кожен сертифікат.
- **Issuer** позначає CA, який видав сертифікат.
- **SubjectAlternativeName** дає змогу вказати додаткові імена суб'єкта, підвищуючи гнучкість ідентифікації.
- **Basic Constraints** визначають, чи призначений сертифікат для CA або кінцевого суб'єкта, а також встановлюють обмеження щодо використання.
- **Extended Key Usages (EKUs)** визначають конкретне призначення сертифіката, наприклад підписування коду або шифрування електронної пошти, за допомогою Object Identifiers (OIDs).
- **Signature Algorithm** визначає метод підписування сертифіката.
- **Signature**, створений за допомогою приватного ключа видавця, гарантує автентичність сертифіката.<sup>[[4]](#references)</sup>

### Особливі міркування

- **Subject Alternative Names (SANs)** розширюють застосовність сертифіката на кілька ідентичностей, що особливо важливо для серверів із кількома доменами. Безпечні процеси видачі мають критичне значення для запобігання ризикам імперсонації з боку зловмисників, які можуть маніпулювати специфікацією SAN.<sup>[[4]](#references)</sup>

### Certificate Authorities (CAs) в Active Directory (AD)

AD CS розпізнає сертифікати CA у лісі AD через спеціальні контейнери, кожен із яких виконує унікальну роль:<sup>[[4]](#references)</sup>

- Контейнер **Certification Authorities** містить довірені сертифікати кореневих CA.
- Контейнер **Enrolment Services** містить відомості про Enterprise CA та їхні шаблони сертифікатів.
- Об'єкт **NTAuthCertificates** містить сертифікати CA, авторизовані для автентифікації в AD.
- Контейнер **AIA (Authority Information Access)** забезпечує перевірку ланцюжка сертифікатів за допомогою проміжних сертифікатів і сертифікатів перехресних CA.

### Отримання сертифіката: процес запиту клієнтського сертифіката

1. Процес запиту починається з пошуку клієнтами Enterprise CA.
2. Після створення пари відкритого та приватного ключів створюється CSR, що містить відкритий ключ та інші відомості.
3. CA перевіряє CSR щодо доступних шаблонів сертифікатів і видає сертифікат на основі дозволів шаблону.
4. Після схвалення CA підписує сертифікат своїм приватним ключем і повертає його клієнту.<sup>[[4]](#references)</sup>

### Шаблони сертифікатів

Ці шаблони, визначені в AD, описують налаштування та дозволи для видачі сертифікатів, зокрема дозволені EKU, а також права на enrollment або зміну. Вони мають критичне значення для керування доступом до служб сертифікатів.<sup>[[4]](#references)</sup>

**Версія схеми шаблону має значення.** Застарілі шаблони **v1** (наприклад, вбудований шаблон **WebServer**) не мають кількох сучасних механізмів enforcement. Дослідження **ESC15/EKUwu** показало, що у **v1 templates** запитувач може вбудувати **Application Policies/EKUs** у CSR, і вони матимуть **перевагу над** EKU, налаштованими в шаблоні. Це дає змогу створювати сертифікати для client-auth, enrollment agent або code-signing, маючи лише права на enrollment. Надавайте перевагу шаблонам **v2/v3**, видаляйте шаблони v1 за замовчуванням або замінюйте їх і чітко обмежуйте EKU відповідно до призначення.<sup>[[1]](#references)</sup>

## Enrollment сертифікатів

Процес enrollment сертифікатів ініціює адміністратор, який **створює шаблон сертифіката**, після чого Enterprise Certificate Authority (CA) його **публікує**. Це робить шаблон доступним для enrollment клієнтів; крок виконується додаванням імені шаблону до поля `certificatetemplates` об'єкта Active Directory.<sup>[[4]](#references)</sup>

Щоб клієнт міг запитати сертифікат, йому потрібно надати **права на enrollment**. Ці права визначаються дескрипторами безпеки шаблону сертифіката та самої Enterprise CA. Для успішного виконання запиту дозволи мають бути надані в обох місцях.

### Права на enrollment шаблону

Ці права визначаються за допомогою Access Control Entries (ACEs), які описують такі дозволи:

- Права **Certificate-Enrollment** і **Certificate-AutoEnrollment**, кожне з яких пов'язане з певним GUID.
- **ExtendedRights**, що надають усі розширені дозволи.
- **FullControl/GenericAll**, що забезпечують повний контроль над шаблоном.

### Права на enrollment Enterprise CA

Права CA описані в її дескрипторі безпеки, доступному через консоль керування Certificate Authority. Деякі налаштування навіть дають low-privileged users віддалений доступ, що може становити загрозу безпеці.

### Додаткові засоби контролю видачі

Можуть застосовуватися певні засоби контролю, зокрема:

- **Manager Approval**: переводить запити в стан очікування, доки їх не схвалить certificate manager.
- **Enrolment Agents and Authorized Signatures**: визначають необхідну кількість підписів у CSR і потрібні Application Policy OIDs.

### Методи запиту сертифікатів

Сертифікати можна запитувати через:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE) з використанням інтерфейсів DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR) через named pipes або TCP/IP.
3. **Вебінтерфейс enrollment сертифікатів**, якщо встановлено роль Certificate Authority Web Enrollment.
4. **Certificate Enrollment Service** (CES) у поєднанні зі службою Certificate Enrollment Policy (CEP).
5. **Network Device Enrollment Service** (NDES) для мережевих пристроїв із використанням Simple Certificate Enrollment Protocol (SCEP).

Користувачі Windows також можуть запитувати сертифікати через GUI (`certmgr.msc` або `certlm.msc`) або інструменти командного рядка (`certreq.exe` чи команду PowerShell `Get-Certificate`).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Автентифікація за сертифікатом

Active Directory (AD) підтримує автентифікацію за сертифікатом, переважно використовуючи протоколи **Kerberos** і **Secure Channel (Schannel)**.

### Процес автентифікації Kerberos

У процесі автентифікації Kerberos запит користувача на отримання Ticket Granting Ticket (TGT) підписується за допомогою **приватного ключа** сертифіката користувача. Цей запит проходить кілька перевірок на контролері домену, зокрема перевірку **чинності**, **ланцюжка сертифікації** та **статусу відкликання** сертифіката. Перевірки також включають підтвердження того, що сертифікат походить із довіреного джерела, а видавець присутній у **сховищі сертифікатів NTAUTH**. У разі успішного проходження перевірок видається TGT. Об’єкт **`NTAuthCertificates`** в AD, розташований за адресою:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
є центральним елементом встановлення довіри для автентифікації за сертифікатом.<sup>[[4]](#references)</sup>

Після розгортання **KB5014754** сучасна автентифікація Kerberos за сертифікатом здебільшого стосується **сили зіставлення**, а не лише EKU.<sup>[[2]](#references)</sup> У захищених лісах:

- Сертифіката, що містить лише **UPN/DNS SAN**, може бути вже недостатньо для входу.
- KDC надає перевагу **сильному зв’язуванню**, зазвичай **розширенню безпеки SID** (`1.3.6.1.4.1.311.25.2`) або сильному явному зіставленню в `altSecurityIdentities`.
- Якщо сертифікат не має сильного зіставлення, DC записують **Kdcsvc Event ID 39/41** у режимі сумісності та забороняють автентифікацію в режимі примусового застосування.
- У змішаних attack paths **ESC9/ESC16** мають значення, оскільки вони видаляють розширення SID із виданих сертифікатів; після цього оператори покладаються на явні зіставлення або формати SAN URL SID, якщо це підтримується відповідним attack path.

### Автентифікація Secure Channel (Schannel)

Schannel забезпечує захищені TLS/SSL-з’єднання, під час встановлення яких клієнт надає сертифікат, що після успішної перевірки авторизує доступ. Зіставлення сертифіката з обліковим записом AD може виконуватися за допомогою функції Kerberos **S4U2Self** або **Subject Alternative Name (SAN)** сертифіката, серед інших методів.<sup>[[4]](#references)</sup>

Schannel також є практичним резервним варіантом, коли **PKINIT** недоступний. Наприклад, якщо контролер домену не має відповідного сертифіката **Smart Card Logon**, інструменти `certipy auth`/PKINIT можуть не отримати TGT, але той самий сертифікат усе одно може використовуватися проти **LDAPS** або **LDAP StartTLS** для автентифікації та операцій LDAP.

### Перелік AD Certificate Services

Certificate services в AD можна перелічити за допомогою LDAP-запитів, отримавши інформацію про **Enterprise Certificate Authorities (CAs)** та їхні конфігурації. Це доступно будь-якому автентифікованому в домені користувачу без спеціальних привілеїв. Такі інструменти, як **[Certify](https://github.com/GhostPack/Certify)** і **[Certipy](https://github.com/ly4k/Certipy)**, використовуються для переліку та оцінювання вразливостей у середовищах AD CS.

Команди для використання цих інструментів включають:
```bash
# Enumerate trusted root CA certificates, Enterprise CAs, and web endpoints
Certify.exe cas

# Identify vulnerable templates and dump relevant permissions
Certify.exe find /vulnerable
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /showAdmins

# Certipy 5.x enumeration focused on enabled/vulnerable templates
certipy find -enabled -vulnerable -hide-admins -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Save JSON/CSV output for offline review or BloodHound correlation
certipy find -json -output corp_adcs -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Request a certificate over the Web Enrollment endpoint or DCOM/RPC
certipy req -web -ca corp-CA -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local
certipy req -ca corp-CA -target ca.corp.local -template User -upn administrator@corp.local -sid S-1-5-21-...-500

# Use the issued certificate either for PKINIT or directly for LDAP Schannel auth
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10 -ldap-shell

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

---

## Останні вразливості та оновлення безпеки (2022-2025)

| Рік | ID / Назва | Вплив | Основні висновки |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Підвищення привілеїв* через підміну сертифікатів облікових записів комп'ютерів під час PKINIT. | Патч включено до оновлень безпеки від **10 травня 2022 року**. Засоби аудиту та контролі strong-mapping запроваджено через **KB5014754**; середовища тепер мають працювати в режимі *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Віддалене виконання коду* у AD CS Web Enrollment (certsrv) і ролях CES. | Публічні PoC обмежені, але вразливі компоненти IIS часто доступні у внутрішній мережі. Вразливість виправлено в оновленні Patch Tuesday за **липень 2023 року**.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | У шаблонах **v1** requester із правами enrollment може вбудувати **Application Policies/EKUs** у CSR, які матимуть пріоритет над EKU шаблону, створюючи сертифікати для client-auth, enrollment agent або code-signing. | Виправлено станом на **12 листопада 2024 року**. Замініть або зробіть supersede для шаблонів v1 (наприклад, стандартного WebServer), обмежте EKU відповідно до призначення та обмежте права enrollment. |

### Хронологія hardening від Microsoft (KB5014754)

Microsoft запровадила трифазне розгортання (Compatibility → Audit → Enforcement), щоб перевести автентифікацію Kerberos за сертифікатами з неявних слабких mappings. Станом на **11 лютого 2025 року** контролери домену автоматично перемикаються в режим **Full Enforcement**, якщо значення реєстру `StrongCertificateBindingEnforcement` не задано. Пізніше Microsoft оновила графік, залишивши можливість fallback до compatibility mode до оновлення безпеки від **9 вересня 2025 року**.<sup>[[2]](#references)</sup> Адміністраторам слід:

1. Встановити патчі на всі DC і сервери AD CS (травень 2022 року або новіші).
2. Відстежувати Event ID 39/41 щодо слабких mappings під час фази *Audit*.
3. Повторно видати client-auth сертифікати з новим **SID extension** або налаштувати strong manual mappings до того, як enforcement заблокує слабкі mappings.

### Примітки для операторів hardened forests

- **ESC1/ESC6 самі по собі більше не охоплюють усю проблему** у середовищах 2025+ років. Якщо ви запитуєте сертифікат для іншого principal, зазвичай також потрібен артефакт strong mapping, наприклад SID extension або явне mapping.
- **ESC15 (EKUwu)** переважно цінна у середовищах без патчів, оскільки перетворює нешкідливі шаблони **v1**, такі як **WebServer**, на сертифікати, здатні виконувати authentication або enrollment-agent, шляхом ін'єкції **Application Policies**. Kerberos PKINIT і надалі оцінює EKU, але **LDAP Schannel** також враховує Application Policies, завдяки чому abuse на основі LDAP залишається актуальним.<sup>[[1]](#references)</sup>
- **ESC16** — це параметр на рівні CA: якщо CA глобально вимикає SID security extension, кожен виданий сертифікат переходить до слабшої поведінки mapping, якщо attack chain не додає SID в іншому підтримуваному форматі.

---

## Покращення виявлення та hardening

* **Defender for Identity AD CS sensor (2023-2024)** тепер відображає оцінки стану безпеки для ESC1-ESC8/ESC11 і створює сповіщення в реальному часі, зокрема *“Domain-controller certificate issuance for a non-DC”* (ESC8) і *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Розгорніть sensors на всіх серверах AD CS, щоб скористатися цими засобами виявлення.<sup>[[3]](#references)</sup>
* Вимкніть або жорстко обмежте параметр **“Supply in the request”** у всіх шаблонах; надавайте перевагу явно визначеним значенням SAN/EKU.
* Видаліть **Any Purpose** або **No EKU** із шаблонів, якщо це не є абсолютно необхідним (усуває сценарії ESC2).
* Вимагайте **manager approval** або використовуйте спеціалізовані workflows Enrollment Agent для чутливих шаблонів (наприклад, WebServer / CodeSigning).
* Обмежте web enrollment (`certsrv`) і кінцеві точки CES/NDES довіреними мережами або розмістіть їх за автентифікацією за допомогою client-certificate.
* Увімкніть шифрування RPC enrollment (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) для протидії ESC11 (RPC relay). Прапорець **увімкнено за замовчуванням**, але його часто вимикають для legacy clients, що знову відкриває ризик relay.
* Захистіть **кінцеві точки enrollment на базі IIS** (CES/Certsrv): за можливості вимкніть NTLM або вимагайте HTTPS + Extended Protection, щоб блокувати ESC8 relays.

---

## References

- [1] [EKUwu: Not just another AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Certificates security posture assessments - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../banners/hacktricks-training.md}}
