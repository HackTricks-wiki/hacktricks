# Enrolling Devices in Other Organisations

{{#include ../../../banners/hacktricks-training.md}}

## Вступ

Як [**зазначалося раніше**](#what-is-mdm-mobile-device-management)**,** щоб спробувати зареєструвати пристрій в організації, **потрібен лише Serial Number, що належить цій організації**. Після реєстрації пристрою кілька організацій встановлять на новий пристрій чутливі дані: сертифікати, застосунки, паролі WiFi, конфігурації VPN [тощо](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Отже, це може бути небезпечною точкою входу для атакерів, якщо процес реєстрації належним чином не захищений.

**Нижче наведено підсумок дослідження [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Ознайомтеся з ним для отримання додаткових технічних деталей!**<sup>[[1]](#references)</sup>

## Огляд бінарного аналізу DEP і MDM

У цьому дослідженні розглядаються бінарні файли, пов’язані з Device Enrollment Program (DEP) і Mobile Device Management (MDM) у macOS. Основні компоненти:

- **`mdmclient`**: взаємодіє із серверами MDM і запускає DEP check-in у версіях macOS до 10.13.4.
- **`profiles`**: керує Configuration Profiles і запускає DEP check-in у версіях macOS 10.13.4 і новіших.
- **`cloudconfigurationd`**: керує взаємодією з DEP API та отримує Device Enrollment profiles.

Під час DEP check-in використовуються функції `CPFetchActivationRecord` і `CPGetActivationRecord` із приватного фреймворку Configuration Profiles для отримання Activation Record, при цьому `CPFetchActivationRecord` взаємодіє з `cloudconfigurationd` через XPC.<sup>[[1]](#references)</sup>

## Реверс-інжиніринг протоколу Tesla та схеми Absinthe

Під час DEP check-in `cloudconfigurationd` надсилає зашифрований і підписаний JSON payload до _iprofiles.apple.com/macProfile_. Payload містить Serial Number пристрою та дію "RequestProfileConfiguration". Використовувана схема шифрування всередині системи називається "Absinthe". Розкриття принципу роботи цієї схеми є складним і передбачає численні кроки, що призвело до пошуку альтернативних методів вставки довільних Serial Number у запит Activation Record.<sup>[[1]](#references)</sup>

## Проксування DEP-запитів

Спроби перехопити та змінити DEP-запити до _iprofiles.apple.com_ за допомогою інструментів на кшталт Charles Proxy ускладнювалися шифруванням payload і заходами безпеки SSL/TLS. Однак увімкнення конфігурації `MCCloudConfigAcceptAnyHTTPSCertificate` дозволяє обійти перевірку сертифіката сервера, хоча зашифрований характер payload усе ще не дає змоги змінити Serial Number без ключа розшифрування.<sup>[[1]](#references)</sup>

## Instrumenting системних бінарних файлів, що взаємодіють із DEP

Для Instrumenting системних бінарних файлів, таких як `cloudconfigurationd`, потрібно вимкнути System Integrity Protection (SIP) у macOS. Після вимкнення SIP такі інструменти, як LLDB, можна використовувати для підключення до системних процесів і потенційної зміни Serial Number, який використовується під час взаємодії з DEP API. Цей метод є кращим, оскільки дає змогу уникнути складнощів, пов’язаних із entitlements і code signing.<sup>[[1]](#references)</sup>

**Експлуатація Binary Instrumentation:**
Зміна DEP request payload перед серіалізацією JSON у `cloudconfigurationd` виявилася ефективною. Процес передбачав:

1. Підключення LLDB до `cloudconfigurationd`.
2. Пошук місця, де отримується системний Serial Number.
3. Вставку довільного Serial Number у пам’ять до шифрування та надсилання payload.

Цей метод дозволив отримувати повні DEP profiles для довільних Serial Number, демонструючи потенційну вразливість.<sup>[[1]](#references)</sup>

### Автоматизація Instrumentation за допомогою Python

Процес експлуатації було автоматизовано за допомогою Python та LLDB API, що зробило можливим програмну вставку довільних Serial Number і отримання відповідних DEP profiles.<sup>[[1]](#references)</sup>

### Потенційні наслідки вразливостей DEP і MDM

Дослідження виявило значні проблеми безпеки:

1. **Розкриття інформації**: надавши зареєстрований у DEP Serial Number, можна отримати чутливу інформацію організації, що міститься в DEP profile.<sup>[[1]](#references)</sup>

## Посилання

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
