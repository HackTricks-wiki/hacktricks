# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**Щоб дізнатися більше про macOS MDM, перегляньте:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Основи

### **Огляд MDM (Mobile Device Management)**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) використовується для керування різними пристроями кінцевих користувачів, такими як смартфони, ноутбуки та планшети. Зокрема, для платформ Apple (iOS, macOS, tvOS) це охоплює набір спеціалізованих функцій, API та практик. Робота MDM залежить від сумісного MDM-сервера, який може бути комерційним або open-source, і повинен підтримувати [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Основні моменти:

- Централізований контроль над пристроями.
- Залежність від MDM-сервера, який дотримується протоколу MDM.
- Здатність MDM-сервера надсилати різні команди пристроям, наприклад для віддаленого стирання даних або встановлення конфігурації.

### **Основи DEP (Device Enrollment Program)**

[Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP), запропонована Apple, спрощує інтеграцію Mobile Device Management (MDM), забезпечуючи zero-touch конфігурацію пристроїв iOS, macOS і tvOS. DEP автоматизує процес enrollment, дозволяючи пристроям бути готовими до роботи одразу після розпакування з мінімальним втручанням користувача або адміністратора. Основні аспекти:

- Дозволяє пристроям автоматично реєструватися на заздалегідь визначеному MDM-сервері під час першої активації.
- Переважно призначена для нових пристроїв, але також застосовується до пристроїв, які проходять повторне налаштування.
- Забезпечує просте налаштування, завдяки чому пристрої швидко стають готовими до використання в організації.

### **Міркування щодо безпеки**

Важливо зазначити, що простота enrollment, яку забезпечує DEP, хоча й є корисною, також може створювати ризики безпеці. Якщо захисні заходи для MDM enrollment недостатньо посилені, attackers можуть скористатися цим спрощеним процесом, щоб зареєструвати свій пристрій на MDM-сервері організації, видаючи його за корпоративний пристрій.<sup>[2]</sup>

> [!CAUTION]
> **Попередження щодо безпеки**: Спрощений DEP enrollment потенційно може дозволити несанкціоновану реєстрацію пристрою на MDM-сервері організації, якщо належні засоби захисту не застосовуються.

### Основи. Що таке SCEP (Simple Certificate Enrolment Protocol)?

- Відносно старий протокол, створений до широкого поширення TLS і HTTPS.
- Надає клієнтам стандартизований спосіб надсилання **Certificate Signing Request** (CSR) з метою отримання сертифіката. Клієнт просить сервер надати йому підписаний сертифікат.

### Що таке Configuration Profiles (також mobileconfigs)?

- Офіційний спосіб Apple для **налаштування/примусового застосування системної конфігурації.**
- Формат файлу, який може містити кілька payload.
- Базується на property lists (у форматі XML).
- «можуть бути підписані та зашифровані для перевірки їхнього походження, забезпечення цілісності та захисту вмісту». Basics — сторінка 70, iOS Security Guide, January 2018.

## Протоколи

### MDM

- Поєднання APNs (**серверів Apple**) + RESTful API (**серверів vendor** **MDM**)
- **Комунікація** відбувається між **пристроєм** і сервером, пов’язаним із **продуктом** **керування** **пристроями**
- **Команди**, що надходять від MDM до пристрою, передаються у **словниках, закодованих у plist**
- Усе через **HTTPS**. MDM-сервери можуть використовувати (і зазвичай використовують) pinning.
- Apple надає vendor MDM **сертифікат APNs** для автентифікації

### DEP

- **3 API**: 1 для реселерів, 1 для vendor MDM, 1 для ідентифікації пристрою (недокументований):
- Так званий [DEP "cloud service" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Він використовується MDM-серверами для пов’язування DEP-профілів із конкретними пристроями.
- [DEP API, який використовують Apple Authorized Resellers](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) для enrollment пристроїв, перевірки статусу enrollment і перевірки статусу транзакцій.
- Недокументований приватний DEP API. Він використовується Apple Devices для запиту їхнього DEP-профілю. У macOS за комунікацію через цей API відповідає binary `cloudconfigurationd`.
- Більш сучасний і заснований на **JSON** (на відміну від **plist**)
- Apple надає vendor MDM **OAuth token**

**DEP "cloud service" API**

- RESTful
- синхронізує записи пристроїв з Apple на MDM-сервер
- синхронізує «DEP profiles» з MDM-сервера в Apple (пізніше Apple доставляє їх на пристрій)
- DEP «profile» містить:
- URL сервера vendor MDM
- Додаткові довірені сертифікати для URL сервера (опційний pinning)
- Додаткові налаштування (наприклад, які екрани пропускати в Setup Assistant)

## Серійний номер

Пристрої Apple, виготовлені після 2010 року, зазвичай мають **12-символьні буквено-цифрові** серійні номери: **перші три цифри позначають місце виробництва**, наступні **дві** — **рік** і **тиждень** виробництва, наступні **три** цифри є **унікальним** **ідентифікатором**, а **останні** **чотири** цифри позначають **номер моделі**.


{{#ref}}
macos-serial-number.md
{{#endref}}

## Етапи enrollment і керування

1. Створення запису пристрою (Reseller, Apple): створюється запис нового пристрою
2. Призначення запису пристрою (Customer): пристрій призначається MDM-серверу
3. Синхронізація запису пристрою (vendor MDM): MDM синхронізує записи пристроїв і передає DEP profiles до Apple
4. DEP check-in (Device): пристрій отримує свій DEP profile
5. Отримання profile (Device)
6. Встановлення profile (Device), включно з payload MDM, SCEP і root CA
7. Надсилання команд MDM (Device)

![Серійний номер - Етапи enrollment і керування: 7. Надсилання команд MDM (Device)](<../../../images/image (694).png>)

Файл `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` експортує функції, які можна вважати **високорівневими «етапами»** процесу enrollment.

### Етап 4: DEP check-in — отримання Activation Record

Ця частина процесу відбувається, коли **користувач уперше завантажує Mac** (або після повного стирання)

![Етапи enrollment і керування - Етап 4: DEP check-in - отримання Activation Record: Ця частина процесу відбувається, коли користувач уперше завантажує Mac або після повного...](<../../../images/image (1044).png>)

або під час виконання `sudo profiles show -type enrollment`

- Визначення, **чи ввімкнено DEP для пристрою**
- Activation Record — внутрішня назва **«profile» DEP**
- Починається одразу після підключення пристрою до Internet
- Керується **`CPFetchActivationRecord`**
- Реалізується **`cloudconfigurationd`** через XPC. **"Setup Assistant**" (коли пристрій завантажується вперше) або команда **`profiles`** звертається до **цього daemon**, щоб отримати activation record.
- LaunchDaemon (завжди працює від root)

Для отримання Activation Record виконується кілька кроків, за які відповідає **`MCTeslaConfigurationFetcher`**. Цей процес використовує шифрування під назвою **Absinthe**<sup>[1]</sup>

1. Отримання **сертифіката**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Ініціалізація** стану із сертифіката (**`NACInit`**)
1. Використовуються різні специфічні для пристрою дані (наприклад, **серійний номер через `IOKit`**)
3. Отримання **ключа сесії**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Встановлення сесії (**`NACKeyEstablishment`**)
5. Виконання запиту
1. POST до [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) з надсиланням даних `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. JSON payload шифрується за допомогою Absinthe (**`NACSign`**)
3. Усі запити виконуються через HTTPs, використовуються вбудовані root certificates

![Етапи enrollment і керування - Етап 4: DEP check-in - отримання Activation Record: 3. Усі запити виконуються через HTTPs, використовуються вбудовані root certificates](<../../../images/image (566) (1).png>)

Відповідь є JSON-словником із важливими даними, такими як:

- **url**: URL host vendor MDM для activation profile
- **anchor-certs**: масив DER-сертифікатів, що використовуються як довірені anchors

### **Етап 5: отримання Profile**

![Етап 4: DEP check-in - отримання Activation Record - Етап 5: отримання Profile: Етап 5: отримання Profile](<../../../images/image (444).png>)

- Запит надсилається на **url, указаний у DEP profile**.
- **Anchor certificates** використовуються для **оцінювання довіри**, якщо вони надані.
- Нагадування: властивість **anchor_certs** DEP profile
- **Запит є простим .plist** з ідентифікаційними даними пристрою
- Приклади: **UDID, версія OS**.
- CMS-підписаний, DER-кодований
- Підписаний за допомогою **сертифіката ідентифікації пристрою (з APNS)**
- **Ланцюжок сертифікатів** містить прострочений **Apple iPhone Device CA**

![Етап 4: DEP check-in - отримання Activation Record - Етап 5: отримання Profile: Підписаний за допомогою сертифіката ідентифікації пристрою (з APNS)](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Етап 6: встановлення Profile

- Після отримання **profile зберігається в системі**
- Цей етап починається автоматично (якщо запущено **setup assistant**)
- Керується **`CPInstallActivationProfile`**
- Реалізується mdmclient через XPC
- LaunchDaemon (від root) або LaunchAgent (від user), залежно від контексту
- Configuration profiles мають кілька payload для встановлення
- Framework має plugin-based architecture для встановлення profiles
- Кожен тип payload пов’язаний із plugin
- Це може бути XPC (у framework) або classic Cocoa (у ManagedClient.app)
- Приклад:
- Certificate Payloads використовують CertificateService.xpc

Зазвичай **activation profile**, наданий vendor MDM, **містить такі payload**:

- `com.apple.mdm`: для **enroll** пристрою в MDM
- `com.apple.security.scep`: для безпечного надання пристрою **client certificate**.
- `com.apple.security.pem`: для **встановлення trusted CA certificates** у System Keychain пристрою.
- Встановлення MDM payload, еквівалентне **MDM check-in у документації**
- Payload **містить ключові властивості**:
- - URL MDM Check-In (**`CheckInURL`**)
- URL опитування команд MDM (**`ServerURL`**) + topic APNs для його запуску
- Для встановлення MDM payload запит надсилається на **`CheckInURL`**
- Реалізується в **`mdmclient`**
- MDM payload може залежати від інших payload
- Дозволяє **закріплювати запити за певними сертифікатами**:
- Властивість: **`CheckInURLPinningCertificateUUIDs`**
- Властивість: **`ServerURLPinningCertificateUUIDs`**
- Доставляється через PEM payload
- Дозволяє призначити пристрою identity certificate:
- Властивість: IdentityCertificateUUID
- Доставляється через SCEP payload

### **Етап 7: прослуховування команд MDM**

- Після завершення MDM check-in vendor може **надсилати push notifications через APNs**
- Після отримання вони обробляються **`mdmclient`**
- Для опитування команд MDM запит надсилається на ServerURL
- Використовується раніше встановлений MDM payload:
- **`ServerURLPinningCertificateUUIDs`** для pinning запиту
- **`IdentityCertificateUUID`** для TLS client certificate

## Атаки

### Enrollment пристроїв в інших організаціях

Як уже зазначалося, для спроби enroll пристрою в організацію **потрібен лише серійний номер, що належить цій організації**. Після enrollment пристрою кілька організацій встановлюють на новий пристрій чутливі дані: сертифікати, applications, паролі WiFi, конфігурації VPN [і так далі](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Тому це може бути небезпечним entrypoint для attackers, якщо процес enrollment належним чином не захищено:<sup>[2]</sup>


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

## Посилання

- [1] [A Deep Dive into macOS MDM (and How it can be Compromised)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — "MDM Me Maybe?" (DEP/MDM enrollment security research)](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
