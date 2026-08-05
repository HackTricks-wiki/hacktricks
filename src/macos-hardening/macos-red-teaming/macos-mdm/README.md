# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**Щоб дізнатися більше про macOS MDM, перегляньте:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Основи

### **Огляд MDM (Mobile Device Management)**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) використовується для керування різними пристроями кінцевих користувачів, такими як смартфони, ноутбуки та планшети. Зокрема, для платформ Apple (iOS, macOS, tvOS) він включає набір спеціалізованих функцій, API та практик. Робота MDM залежить від сумісного MDM-сервера, який може бути комерційним або open-source, і має підтримувати [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Основні моменти:

- Централізований контроль над пристроями.
- Залежність від MDM-сервера, який відповідає протоколу MDM.
- Можливість MDM-сервера надсилати різні команди пристроям, наприклад для віддаленого видалення даних або встановлення конфігурацій.

### **Основи DEP (Device Enrollment Program)**

[Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP), запропонована Apple, спрощує інтеграцію Mobile Device Management (MDM), забезпечуючи zero-touch конфігурацію пристроїв iOS, macOS і tvOS. DEP автоматизує процес enrollment, завдяки чому пристрої готові до роботи одразу після розпакування, з мінімальним втручанням користувача або адміністратора. Основні аспекти:

- Дозволяє пристроям автоматично реєструватися на попередньо визначеному MDM-сервері під час першої активації.
- Переважно корисна для нових пристроїв, але також застосовна до пристроїв, що проходять повторну конфігурацію.
- Забезпечує просте налаштування, завдяки чому пристрої швидко стають готовими до використання в організації.

### **Міркування щодо безпеки**

Важливо зазначити, що спрощений enrollment, який забезпечує DEP, хоча й корисний, може створювати ризики безпеці. Якщо захисні заходи для MDM enrollment не застосовано належним чином, attackers можуть скористатися цим спрощеним процесом, щоб зареєструвати свій пристрій на MDM-сервері організації, видаючи його за корпоративний пристрій.<sup>[[2]](#references)</sup>

> [!CAUTION]
> **Попередження щодо безпеки**: спрощений DEP enrollment потенційно може дозволити несанкціоновану реєстрацію пристрою на MDM-сервері організації, якщо належні засоби захисту відсутні.

### Основи: що таке SCEP (Simple Certificate Enrolment Protocol)?

- Відносно старий протокол, створений до широкого поширення TLS і HTTPS.
- Надає клієнтам стандартизований спосіб надсилання **Certificate Signing Request** (CSR) для отримання сертифіката. Клієнт просить сервер надати йому підписаний сертифікат.

### Що таке Configuration Profiles (також відомі як mobileconfigs)?

- Офіційний спосіб Apple **налаштування/примусового застосування системної конфігурації.**
- Формат файлу, який може містити кілька payload.
- Базується на property lists (у форматі XML).
- «можуть бути підписані та зашифровані для перевірки їхнього походження, забезпечення цілісності та захисту їхнього вмісту». Basics — Page 70, iOS Security Guide, January 2018.

## Протоколи

### MDM

- Поєднання APNs (**сервери Apple**) + RESTful API (**сервери** **vendor** MDM)
- **Комунікація** відбувається між **пристроєм** і сервером, пов’язаним із **продуктом** **керування** **пристроями**
- **Команди** доставляються з MDM на пристрій у **словниках, закодованих у plist**
- Усе через **HTTPS**. MDM-сервери можуть використовувати (і зазвичай використовують) pinning.
- Apple надає vendor MDM **APNs-сертифікат** для автентифікації

### DEP

- **3 API**: 1 для реселерів, 1 для vendor MDM, 1 для ідентифікації пристрою (недокументований):
- Так званий [DEP "cloud service" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Він використовується MDM-серверами для пов’язування DEP-профілів із конкретними пристроями.
- [DEP API, який використовують Apple Authorized Resellers](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html), щоб реєструвати пристрої, перевіряти статус enrollment і статус транзакцій.
- Недокументований приватний DEP API. Він використовується Apple Devices для запиту свого DEP-профілю. У macOS за комунікацію через цей API відповідає бінарний файл `cloudconfigurationd`.
- Сучасніший і заснований на **JSON** (на відміну від **plist**)
- Apple надає vendor MDM **OAuth-токен**

**DEP "cloud service" API**

- RESTful
- синхронізує записи пристроїв з Apple на MDM-сервер
- синхронізує “DEP profiles” з MDM-сервера до Apple (пізніше вони доставляються Apple на пристрій)
- DEP “profile” містить:
- URL сервера vendor MDM
- Додаткові довірені сертифікати для URL сервера (необов’язковий pinning)
- Додаткові налаштування (наприклад, які екрани пропускати в Setup Assistant)

## Серійний номер

Пристрої Apple, виготовлені після 2010 року, зазвичай мають **12-символьні буквено-цифрові** серійні номери, де **перші три цифри позначають місце виробництва**, наступні **дві** — **рік** і **тиждень** виробництва, наступні **три** цифри є **унікальним** **ідентифікатором**, а **останні** **чотири** цифри позначають **номер моделі**.


{{#ref}}
macos-serial-number.md
{{#endref}}

## Етапи enrollment і керування

1. Створення запису пристрою (Reseller, Apple): створюється запис для нового пристрою
2. Призначення запису пристрою (Customer): пристрій призначається MDM-серверу
3. Синхронізація запису пристрою (vendor MDM): MDM синхронізує записи пристроїв і надсилає DEP-профілі до Apple
4. DEP check-in (Device): пристрій отримує свій DEP-профіль
5. Отримання профілю (Device)
6. Встановлення профілю (Device) a. включно з payload MDM, SCEP і root CA
7. Надсилання команд MDM (Device)

![Серійний номер — етапи enrollment і керування: 7. Надсилання команд MDM (Device)](<../../../images/image (694).png>)

Файл `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` експортує функції, які можна вважати **високорівневими «етапами»** процесу enrollment.

### Етап 4: DEP check-in — отримання Activation Record

Ця частина процесу відбувається, коли **користувач уперше завантажує Mac** (або після повного очищення)

![Етапи enrollment і керування — етап 4: DEP check-in — отримання Activation Record: ця частина процесу відбувається, коли користувач уперше завантажує Mac або після повного...](<../../../images/image (1044).png>)

або під час виконання `sudo profiles show -type enrollment`

- Визначення, **чи увімкнено DEP для пристрою**
- Activation Record — внутрішня назва **DEP “profile”**
- Починається одразу після підключення пристрою до Internet
- Керується **`CPFetchActivationRecord`**
- Реалізується **`cloudconfigurationd`** через XPC. **"Setup Assistant**" (під час першого завантаження пристрою) або команда **`profiles`** звертається до цього daemon для отримання activation record.
- LaunchDaemon (завжди працює від root)

Для отримання Activation Record виконується кілька етапів, які реалізує **`MCTeslaConfigurationFetcher`**. Цей процес використовує шифрування під назвою **Absinthe**<sup>[[1]](#references)</sup>

1. Отримання **сертифіката**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Ініціалізація** стану із сертифіката (**`NACInit`**)
1. Використовує різні специфічні для пристрою дані (тобто **Serial Number через `IOKit`**)
3. Отримання **ключа сесії**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Встановлення сесії (**`NACKeyEstablishment`**)
5. Виконання запиту
1. POST на [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) з надсиланням даних `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. JSON payload зашифрований за допомогою Absinthe (**`NACSign`**)
3. Усі запити виконуються через HTTPs, використовуються вбудовані root-сертифікати

![Етапи enrollment і керування — етап 4: DEP check-in — отримання Activation Record: 3. Усі запити виконуються через HTTPs, використовуються вбудовані root-сертифікати](<../../../images/image (566) (1).png>)

Відповідь є JSON-словником із такими важливими даними:

- **url**: URL хоста vendor MDM для activation profile
- **anchor-certs**: масив DER-сертифікатів, які використовуються як довірені anchors

### **Етап 5: отримання профілю**

![Етап 4: DEP check-in — отримання Activation Record — етап 5: отримання профілю: етап 5: отримання профілю](<../../../images/image (444).png>)

- Запит надсилається на **url, указаний у DEP profile**.
- **Anchor certificates** використовуються для **оцінювання довіри**, якщо вони надані.
- Нагадування: властивість **anchor_certs** DEP profile
- **Запит є простим .plist** з ідентифікаційними даними пристрою
- Приклади: **UDID, версія OS**.
- Підписаний CMS, закодований у DER
- Підписаний за допомогою **сертифіката ідентифікації пристрою (з APNS)**
- **Ланцюжок сертифікатів** містить прострочений **Apple iPhone Device CA**

![Етап 4: DEP check-in — отримання Activation Record — етап 5: отримання профілю: підписаний за допомогою сертифіката ідентифікації пристрою (з APNS)](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Етап 6: встановлення профілю

- Після отримання **profile зберігається в системі**
- Цей етап починається автоматично (якщо використовується **setup assistant**)
- Керується **`CPInstallActivationProfile`**
- Реалізується mdmclient через XPC
- LaunchDaemon (від root) або LaunchAgent (від user), залежно від контексту
- Configuration profiles мають кілька payload для встановлення
- Framework має plugin-based архітектуру для встановлення profiles
- Кожен тип payload пов’язаний із plugin
- Може бути XPC (у framework) або classic Cocoa (у ManagedClient.app)
- Приклад:
- Certificate Payloads використовують CertificateService.xpc

Зазвичай **activation profile**, наданий vendor MDM, **містить такі payload**:

- `com.apple.mdm`: для **enroll** пристрою в MDM
- `com.apple.security.scep`: для безпечного надання пристрою **client certificate**.
- `com.apple.security.pem`: для **встановлення довірених CA-сертифікатів** у System Keychain пристрою.
- Встановлення MDM payload є еквівалентом **MDM check-in у документації**
- Payload **містить ключові властивості**:
- - URL MDM Check-In (**`CheckInURL`**)
- URL MDM Command Polling (**`ServerURL`**) + topic APNs для його запуску
- Для встановлення MDM payload запит надсилається на **`CheckInURL`**
- Реалізується в **`mdmclient`**
- MDM payload може залежати від інших payload
- Дозволяє **закріплювати запити за конкретними сертифікатами**:
- Властивість: **`CheckInURLPinningCertificateUUIDs`**
- Властивість: **`ServerURLPinningCertificateUUIDs`**
- Доставляється через PEM payload
- Дозволяє призначити пристрою сертифікат ідентифікації:
- Властивість: IdentityCertificateUUID
- Доставляється через SCEP payload

### **Етап 7: прослуховування команд MDM**

- Після завершення MDM check-in vendor може **надсилати push notifications за допомогою APNs**
- Після отримання вони обробляються через **`mdmclient`**
- Для опитування щодо команд MDM запит надсилається на ServerURL
- Використовується раніше встановлений MDM payload:
- **`ServerURLPinningCertificateUUIDs`** для pinning запиту
- **`IdentityCertificateUUID`** для TLS client certificate

## Атаки

### Enrollment пристроїв в інших організаціях

Як зазначалося раніше, щоб спробувати enroll пристрій в організацію, **потрібен лише Serial Number, що належить цій організації**. Після enrollment деякі організації встановлюють на новий пристрій чутливі дані: сертифікати, застосунки, паролі WiFi, конфігурації VPN [і так далі](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Тому це може бути небезпечною точкою входу для attackers, якщо процес enrollment належним чином не захищено:<sup>[[2]](#references)</sup>


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

## Посилання

- [1] [A Deep Dive into macOS MDM (and How it can be Compromised)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — "MDM Me Maybe?" (DEP/MDM enrollment security research)](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
