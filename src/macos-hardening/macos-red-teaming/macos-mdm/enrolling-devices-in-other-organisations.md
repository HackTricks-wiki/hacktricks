# Зарахування пристроїв до інших організацій

{{#include ../../../banners/hacktricks-training.md}}

## Вступ

Як [**зазначалося раніше**](#what-is-mdm-mobile-device-management)**,** щоб спробувати зарахувати пристрій до організації, **потрібен лише Serial Number, що належить цій організації**. Після зарахування кілька організацій встановлюють на новий пристрій конфіденційні дані: сертифікати, застосунки, паролі WiFi, конфігурації VPN [тощо](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Отже, це може бути небезпечним entrypoint для attackers, якщо процес зарахування належним чином не захищений.

**Нижче наведено короткий виклад дослідження [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Ознайомтеся з ним для отримання додаткових технічних деталей!**<sup>[1]</sup>

## Огляд бінарного аналізу DEP і MDM

Це дослідження детально розглядає бінарні файли, пов’язані з Device Enrollment Program (DEP) і Mobile Device Management (MDM) у macOS. Основні компоненти:

- **`mdmclient`**: взаємодіє з MDM-серверами та запускає DEP check-ins у версіях macOS до 10.13.4.
- **`profiles`**: керує Configuration Profiles і запускає DEP check-ins у версіях macOS 10.13.4 і новіших.
- **`cloudconfigurationd`**: керує взаємодією з DEP API та отримує Device Enrollment profiles.

DEP check-ins використовують функції `CPFetchActivationRecord` і `CPGetActivationRecord` із приватного фреймворку Configuration Profiles для отримання Activation Record, причому `CPFetchActivationRecord` взаємодіє з `cloudconfigurationd` через XPC.<sup>[1]</sup>

## Reverse Engineering протоколу Tesla та схеми Absinthe

Під час DEP check-in `cloudconfigurationd` надсилає зашифрований, підписаний JSON payload до _iprofiles.apple.com/macProfile_. Payload містить Serial Number пристрою та action `"RequestProfileConfiguration"`. Використовувана схема шифрування внутрішньо називається "Absinthe". Розкриття принципу роботи цієї схеми є складним і потребує численних кроків, що призвело до пошуку альтернативних методів вставки довільних Serial Number у запит Activation Record.<sup>[1]</sup>

## Proxying DEP Requests

Спроби перехопити та змінити DEP requests до _iprofiles.apple.com_ за допомогою таких інструментів, як Charles Proxy, були ускладнені шифруванням payload і заходами безпеки SSL/TLS. Однак увімкнення конфігурації `MCCloudConfigAcceptAnyHTTPSCertificate` дає змогу обійти перевірку сертифіката сервера, хоча зашифрований характер payload усе одно не дозволяє змінити Serial Number без ключа розшифрування.<sup>[1]</sup>

## Інструментування системних бінарних файлів, що взаємодіють із DEP

Інструментування системних бінарних файлів, таких як `cloudconfigurationd`, потребує вимкнення System Integrity Protection (SIP) у macOS. Після вимкнення SIP такі інструменти, як LLDB, можна використовувати для підключення до системних процесів і потенційної зміни Serial Number, що використовується у взаємодіях із DEP API. Цей метод є кращим, оскільки дає змогу уникнути складнощів, пов’язаних із entitlements і code signing.

**Експлуатація інструментування бінарного файлу:**
Зміна DEP request payload перед серіалізацією JSON у `cloudconfigurationd` виявилася ефективною. Процес складався з таких етапів:

1. Підключення LLDB до `cloudconfigurationd`.
2. Визначення місця отримання системного Serial Number.
3. Вставка довільного Serial Number у пам’ять до шифрування та надсилання payload.

Цей метод дав змогу отримувати повні DEP profiles для довільних Serial Number, продемонструвавши потенційну вразливість.<sup>[1]</sup>

### Автоматизація інструментування за допомогою Python

Процес експлуатації було автоматизовано за допомогою Python та LLDB API, що зробило можливим програмну вставку довільних Serial Number і отримання відповідних DEP profiles.<sup>[1]</sup>

### Потенційні наслідки вразливостей DEP і MDM

Дослідження виявило значні проблеми безпеки:

1. **Розкриття інформації**: надавши зареєстрований у DEP Serial Number, можна отримати конфіденційну інформацію організації, що міститься у DEP profile.<sup>[1]</sup>

## Посилання

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
