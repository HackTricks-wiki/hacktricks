# Реєстрація пристроїв в інших організаціях

{{#include ../../../banners/hacktricks-training.md}}

## Вступ

Як [**зазначалося раніше**](#what-is-mdm-mobile-device-management)**,** щоб спробувати зареєструвати пристрій в організації, **потрібен лише Serial Number, що належить цій організації**. Після реєстрації пристрою декілька організацій встановлюють на новий пристрій конфіденційні дані: сертифікати, застосунки, паролі WiFi, конфігурації VPN [тощо](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Тому це може бути небезпечним entrypoint для атакувальників, якщо процес реєстрації належним чином не захищений.

**Нижче наведено стислий виклад дослідження [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Ознайомтеся з ним для отримання додаткових технічних деталей!**<sup>[[1]](#references)</sup>

## Огляд бінарних файлів DEP і MDM та їхній аналіз

Це дослідження розглядає бінарні файли, пов'язані з Device Enrollment Program (DEP) і Mobile Device Management (MDM) у macOS. Основні компоненти:

- **`mdmclient`**: обмінюється даними із серверами MDM і запускає DEP check-ins у версіях macOS до 10.13.4.
- **`profiles`**: керує Configuration Profiles і запускає DEP check-ins у версіях macOS 10.13.4 і новіших.
- **`cloudconfigurationd`**: керує взаємодією з API DEP і отримує Device Enrollment profiles.

DEP check-ins використовують функції `CPFetchActivationRecord` і `CPGetActivationRecord` із приватного фреймворку Configuration Profiles для отримання Activation Record, причому `CPFetchActivationRecord` взаємодіє з `cloudconfigurationd` через XPC.<sup>[[1]](#references)</sup>

## Зворотне проєктування протоколу Tesla та схеми Absinthe

Під час DEP check-in `cloudconfigurationd` надсилає зашифрований і підписаний JSON payload на _iprofiles.apple.com/macProfile_. Payload містить серійний номер пристрою та дію `"RequestProfileConfiguration"`. Використовувана схема шифрування всередині системи називається "Absinthe". Розкриття цієї схеми є складним і передбачає численні кроки, що призвело до дослідження альтернативних методів вставлення довільних серійних номерів у запит Activation Record.<sup>[[1]](#references)</sup>

## Проксування DEP-запитів

Спроби перехоплювати та змінювати DEP-запити до _iprofiles.apple.com_ за допомогою таких інструментів, як Charles Proxy, були ускладнені шифруванням payload і заходами безпеки SSL/TLS. Однак увімкнення конфігурації `MCCloudConfigAcceptAnyHTTPSCertificate` дає змогу обійти перевірку сертифіката сервера, хоча зашифрована природа payload усе ще не дозволяє змінити серійний номер без ключа розшифрування.<sup>[[1]](#references)</sup>

## Інструментування системних бінарних файлів, що взаємодіють із DEP

Інструментування системних бінарних файлів, таких як `cloudconfigurationd`, потребує вимкнення System Integrity Protection (SIP) у macOS. Після вимкнення SIP такі інструменти, як LLDB, можна використовувати для під'єднання до системних процесів і потенційної зміни серійного номера, що використовується у взаємодії з API DEP. Цей метод є кращим, оскільки дає змогу уникнути складнощів, пов'язаних із entitlements і code signing.

**Експлуатація інструментування бінарних файлів:**
Зміна DEP request payload перед серіалізацією JSON у `cloudconfigurationd` виявилася ефективною. Процес складався з таких кроків:

1. Під'єднання LLDB до `cloudconfigurationd`.
2. Пошук місця, де отримується системний серійний номер.
3. Вставлення довільного серійного номера в пам'ять до шифрування та надсилання payload.

Цей метод давав змогу отримувати повні DEP profiles для довільних серійних номерів, демонструючи потенційну вразливість.<sup>[[1]](#references)</sup>

### Автоматизація інструментування за допомогою Python

Процес експлуатації було автоматизовано за допомогою Python та LLDB API, що зробило можливим програмне вставлення довільних серійних номерів і отримання відповідних DEP profiles.<sup>[[1]](#references)</sup>

### Потенційні наслідки вразливостей DEP і MDM

Дослідження висвітлило значні проблеми безпеки:

1. **Розкриття інформації**: надавши зареєстрований у DEP серійний номер, можна отримати конфіденційну інформацію організації, що міститься у DEP profile.<sup>[[1]](#references)</sup>

## Посилання

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
