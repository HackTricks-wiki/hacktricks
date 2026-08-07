# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**Щоб дізнатися більше про macOS MDM, дивіться:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)<sup>[[1]](#references)</sup>
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)<sup>[[2]](#references)</sup>

## Основи

### **Огляд MDM (Mobile Device Management)**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) використовується для керування різними кінцевими пристроями, такими як смартфони, ноутбуки та планшети. Зокрема, для платформ Apple (iOS, macOS, tvOS) він охоплює набір спеціалізованих функцій, API та практик. Робота MDM залежить від сумісного MDM-сервера, який може бути комерційним або open-source і повинен підтримувати [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Основні моменти:

- Централізований контроль над пристроями.
- Залежність від MDM-сервера, який дотримується MDM protocol.
- Можливість MDM-сервера надсилати різні команди на пристрої, наприклад віддалено стирати дані або встановлювати конфігурацію.

### **Основи DEP (Device Enrollment Program)**

[Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP), запропонована Apple, спрощує інтеграцію Mobile Device Management (MDM), забезпечуючи zero-touch конфігурацію пристроїв iOS, macOS і tvOS. DEP автоматизує процес enrollment, дозволяючи пристроям бути готовими до роботи одразу після розпакування, з мінімальним втручанням користувача або адміністратора. Основні аспекти:

- Дозволяє пристроям автоматично реєструватися на заздалегідь визначеному MDM-сервері під час першої активації.
- Переважно корисна для абсолютно нових пристроїв, але також застосовується до пристроїв, які проходять повторну конфігурацію.
- Забезпечує просте налаштування, завдяки чому пристрої швидко стають готовими до використання в організації.

### **Міркування щодо безпеки**

Важливо зазначити, що спрощений enrollment, який надає DEP, хоча й корисний, також може створювати ризики для безпеки. Якщо під час MDM enrollment недостатньо впроваджено захисні заходи, attackers можуть використати цей спрощений процес, щоб зареєструвати свій пристрій на MDM-сервері організації, видаючи його за корпоративний пристрій.<sup>[[2]](#references)</sup>

> [!CAUTION]
> **Попередження безпеки**: Спрощений DEP enrollment потенційно може дозволити неавторизовану реєстрацію пристрою на MDM-сервері організації, якщо належні засоби захисту відсутні.

### Основи: що таке SCEP (Simple Certificate Enrolment Protocol)?

- Відносно старий протокол, створений до широкого поширення TLS і HTTPS.
- Надає клієнтам стандартизований спосіб надсилання **Certificate Signing Request** (CSR) для отримання сертифіката. Клієнт просить сервер надати йому підписаний сертифікат.

### Що таке Configuration Profiles (також mobileconfigs)?

- Офіційний спосіб Apple **налаштовувати/застосовувати системну конфігурацію**.
- Формат файлу, який може містити кілька payloads.
- Базується на property lists (формат XML).
- «можуть бути підписані та зашифровані для перевірки їхнього походження, забезпечення цілісності та захисту вмісту». Basics — Page 70, iOS Security Guide, January 2018.

## Протоколи

### MDM

- Поєднання APNs (**серверів Apple**) + RESTful API (**серверів **vendor** MDM**)
- **Комунікація** відбувається між **пристроєм** і сервером, пов’язаним із **продуктом** **керування** **пристроями**
- **Команди** надсилаються з MDM на пристрій у вигляді **словників, закодованих у plist**
- Усе відбувається через **HTTPS**. MDM-сервери можуть використовувати (і зазвичай використовують) pinning.
- Apple надає vendor MDM **сертифікат APNs** для authentication

### DEP

- **3 API**: 1 для resellers, 1 для vendors MDM, 1 для ідентифікації пристрою (undocumented):
- Так званий [DEP "cloud service" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Він використовується MDM-серверами для пов’язування DEP profiles із конкретними пристроями.
- [DEP API, який використовують Apple Authorized Resellers](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html), для enrollment пристроїв, перевірки статусу enrollment і статусу транзакцій.
- Undocumented private DEP API. Він використовується Apple Devices для запиту їхнього DEP profile. У macOS за комунікацію через цей API відповідає binary `cloudconfigurationd`.
- Сучасніший і заснований на **JSON** (на відміну від plist)
- Apple надає vendor MDM **OAuth token**

**DEP "cloud service" API**

- RESTful
- синхронізує записи пристроїв від Apple до MDM-сервера
- синхронізує “DEP profiles” з MDM-сервера до Apple (пізніше Apple доставляє їх на пристрій)
- DEP “profile” містить:
- URL сервера vendor MDM
- Додаткові trusted certificates для URL сервера (optional pinning)
- Додаткові налаштування (наприклад, які екрани пропускати в Setup Assistant)

## Серійний номер

Пристрої Apple, виготовлені після 2010 року, зазвичай мають **12-символьні буквено-цифрові** серійні номери, де **перші три цифри позначають місце виробництва**, наступні **дві** — **рік** і **тиждень** виробництва, наступні **три** цифри — **унікальний** **ідентифікатор**, а **останні** **чотири** цифри позначають **номер моделі**.


{{#ref}}
macos-serial-number.md
{{#endref}}

## Етапи enrollment і керування

1. Створення запису пристрою (Reseller, Apple): створюється запис нового пристрою
2. Призначення запису пристрою (Customer): пристрій призначається MDM-серверу
3. Синхронізація запису пристрою (vendor MDM): MDM синхронізує записи пристроїв і надсилає DEP profiles до Apple
4. DEP check-in (Device): пристрій отримує свій DEP profile
5. Отримання profile (Device)
6. Встановлення profile (Device) a. включно з payloads MDM, SCEP і root CA
7. Надсилання команди MDM (Device)

![Серійний номер — Етапи enrollment і керування: 7. Надсилання команди MDM (Device)](<../../../images/image (694).png>)

Файл `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` експортує функції, які можна вважати **високорівневими «етапами»** процесу enrollment.

### Етап 4: DEP check-in — отримання Activation Record

Ця частина процесу відбувається, коли **користувач уперше завантажує Mac** (або після повного очищення)

![Етапи enrollment і керування — Етап 4: DEP check-in — отримання Activation Record: ця частина процесу відбувається, коли користувач уперше завантажує Mac (або після повного...](<../../../images/image (1044).png>)

або під час виконання `sudo profiles show -type enrollment`

- Визначення, **чи ввімкнено DEP для пристрою**
- Activation Record — внутрішня назва для **«profile» DEP**
- Починається одразу після підключення пристрою до Internet
- Керується **`CPFetchActivationRecord`**
- Реалізується **`cloudconfigurationd`** через XPC. **"Setup Assistant**" (коли пристрій завантажується вперше) або команда **`profiles`** зв’язується з цим daemon для отримання activation record.
- LaunchDaemon (завжди працює від root)

Щоб отримати Activation Record, **`MCTeslaConfigurationFetcher`** виконує кілька етапів. Цей процес використовує encryption під назвою **Absinthe**<sup>[[1]](#references)</sup>

1. Отримання **certificate**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Ініціалізація** state з certificate (**`NACInit`**)
1. Використовуються різні специфічні для пристрою дані (тобто **Serial Number через `IOKit`**)
3. Отримання **session key**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Встановлення session (**`NACKeyEstablishment`**)
5. Виконання request
1. POST на [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) із надсиланням даних `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. JSON payload зашифрований за допомогою Absinthe (**`NACSign`**)
3. Усі requests виконуються через HTTPs, використовуються вбудовані root certificates

![Етапи enrollment і керування — Етап 4: DEP check-in — отримання Activation Record: 3. Усі requests виконуються через HTTPs, використовуються вбудовані root certificates](<../../../images/image (566) (1).png>)

Відповідь — це JSON dictionary з важливими даними, такими як:

- **url**: URL host vendor MDM для activation profile
- **anchor-certs**: масив DER certificates, які використовуються як trusted anchors

### **Етап 5: отримання profile**

![Етап 4: DEP check-in — отримання Activation Record — Етап 5: отримання profile: Етап 5: отримання profile](<../../../images/image (444).png>)

- Request надсилається на **url, наданий у DEP profile**.
- **Anchor certificates** використовуються для **перевірки trust**, якщо вони надані.
- Нагадування: властивість **anchor_certs** DEP profile
- **Request — це простий .plist** з ідентифікаційними даними пристрою
- Приклади: **UDID, версія OS**.
- CMS-signed, DER-encoded
- Підписаний за допомогою **certificate ідентифікації пристрою (з APNS)**
- **Certificate chain** містить прострочений **Apple iPhone Device CA**

![Етап 4: DEP check-in — отримання Activation Record — Етап 5: отримання profile: підписаний за допомогою certificate ідентифікації пристрою (з APNS)](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Етап 6: встановлення profile

- Після отримання **profile зберігається в системі**
- Цей етап починається автоматично (якщо використовується **setup assistant**)
- Керується **`CPInstallActivationProfile`**
- Реалізується mdmclient через XPC
- LaunchDaemon (від root) або LaunchAgent (від user), залежно від контексту
- Configuration profiles мають кілька payloads для встановлення
- Framework має plugin-based architecture для встановлення profiles
- Кожен тип payload пов’язаний із plugin
- Це може бути XPC (у framework) або classic Cocoa (у ManagedClient.app)
- Приклад:
- Certificate Payloads використовують CertificateService.xpc

Зазвичай **activation profile**, наданий vendor MDM, **містить такі payloads**:

- `com.apple.mdm`: для **enroll** пристрою в MDM
- `com.apple.security.scep`: для безпечного надання пристрою **client certificate**.
- `com.apple.security.pem`: для **встановлення trusted CA certificates** у System Keychain пристрою.
- Встановлення MDM payload, еквівалентне **MDM check-in у документації**
- Payload **містить ключові властивості**:
- - URL MDM Check-In (**`CheckInURL`**)
- URL MDM Command Polling (**`ServerURL`**) + APNs topic для його trigger
- Для встановлення MDM payload request надсилається на **`CheckInURL`**
- Реалізується в **`mdmclient`**
- MDM payload може залежати від інших payloads
- Дозволяє **закріплювати requests за конкретними certificates**:
- Властивість: **`CheckInURLPinningCertificateUUIDs`**
- Властивість: **`ServerURLPinningCertificateUUIDs`**
- Доставляється через PEM payload
- Дозволяє пов’язати пристрій із identity certificate:
- Властивість: IdentityCertificateUUID
- Доставляється через SCEP payload

### **Етап 7: очікування команд MDM**

- Після завершення MDM check-in vendor може **надсилати push notifications за допомогою APNs**
- Після отримання вони обробляються **`mdmclient`**
- Для polling MDM commands request надсилається на ServerURL
- Використовується раніше встановлений MDM payload:
- **`ServerURLPinningCertificateUUIDs`** для pinning request
- **`IdentityCertificateUUID`** для TLS client certificate

## Атаки

### Enrollment пристроїв в інших організаціях

Як зазначалося раніше, щоб спробувати виконати enrollment пристрою в організації, **потрібен лише Serial Number, що належить цій організації**. Після enrollment кілька організацій встановлюють на новий пристрій sensitive data: certificates, applications, WiFi passwords, VPN configurations [і так далі](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Тому це може бути небезпечним entrypoint для attackers, якщо процес enrollment належним чином не захищений:<sup>[[2]](#references)</sup>


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

## References

- [1] [Глибокий аналіз macOS MDM (і як його можна скомпрометувати)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — "MDM Me Maybe?" (дослідження безпеки DEP/MDM enrollment)](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
