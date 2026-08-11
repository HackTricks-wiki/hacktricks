# Зарахування пристроїв до інших організацій

{{#include ../../../banners/hacktricks-training.md}}

## Вступ

Apple Automated Device Enrollment (раніше DEP) починається з ідентифікації пристрою, призначеного організації. Дослідження 2018 року, узагальнене тут, показало, що знання призначеного серійного номера було достатнім для отримання enrollment profiles деяких організацій, оскільки ці організації не вимагали належної додаткової автентифікації. Це історичний висновок, а не твердження про те, що до будь-якого сучасного MDM можна приєднатися лише за серійним номером. Profiles можуть містити сертифікати, застосунки, секрети Wi-Fi, налаштування VPN та іншу конфіденційну конфігурацію.<sup>[[1]](#references)[[2]](#references)</sup>

**Нижче наведено підсумок дослідження [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Ознайомтеся з ним для отримання додаткових технічних деталей!**<sup>[[1]](#references)</sup>

## Огляд бінарного аналізу DEP і MDM

У дослідженні аналізувалися бінарні файли, пов’язані з DEP і MDM, у версіях macOS, актуальних на той час. Назви компонентів і їхні функції можуть змінюватися в різних релізах:

- **`mdmclient`**: взаємодіє з MDM-серверами та запускає DEP check-ins у версіях macOS до 10.13.4.
- **`profiles`**: керує Configuration Profiles і запускає DEP check-ins у версіях macOS 10.13.4 і новіших.
- **`cloudconfigurationd`**: керує взаємодією з DEP API та отримує Device Enrollment profiles.

Під час DEP check-ins використовуються функції `CPFetchActivationRecord` і `CPGetActivationRecord` із приватного фреймворку Configuration Profiles для отримання Activation Record, причому `CPFetchActivationRecord` взаємодіє з `cloudconfigurationd` через XPC.<sup>[[1]](#references)</sup>

## Реверс-інжиніринг Tesla Protocol і Absinthe Scheme

Під час DEP check-in `cloudconfigurationd` надсилає зашифрований і підписаний JSON payload до _iprofiles.apple.com/macProfile_. Payload містить серійний номер пристрою та дію "RequestProfileConfiguration". Використовувана схема шифрування всередині системи називається "Absinthe". Розкриття цієї схеми є складним і передбачає численні кроки, що призвело до пошуку альтернативних методів вставлення довільних серійних номерів у запит Activation Record.<sup>[[1]](#references)</sup>

## Проксування DEP-запитів

Спроби перехоплювати та змінювати DEP-запити до _iprofiles.apple.com_ за допомогою таких інструментів, як Charles Proxy, ускладнювалися шифруванням payload і заходами безпеки SSL/TLS. Однак увімкнення конфігурації `MCCloudConfigAcceptAnyHTTPSCertificate` дає змогу обійти перевірку сертифіката сервера, хоча зашифрована природа payload усе ще не дозволяє змінити серійний номер без ключа розшифрування.<sup>[[1]](#references)</sup>

## Інструментування системних бінарних файлів, що взаємодіють із DEP

Для інструментування системних бінарних файлів, таких як `cloudconfigurationd`, у macOS потрібно вимкнути System Integrity Protection (SIP). Після вимкнення SIP такі інструменти, як LLDB, можна використовувати для підключення до системних процесів і потенційної зміни серійного номера, що використовується під час взаємодії з DEP API. Цей метод є кращим, оскільки дає змогу уникнути складнощів, пов’язаних із entitlements і code signing.<sup>[[1]](#references)</sup>

**Експлуатація бінарного інструментування:**
Зміна DEP request payload до серіалізації в JSON у `cloudconfigurationd` виявилася ефективною. Процес передбачав:

1. Підключення LLDB до `cloudconfigurationd`.
2. Пошук місця, де система отримує серійний номер.
3. Вставлення довільного серійного номера в пам’ять до шифрування та надсилання payload.

Цей метод дозволив дослідникам отримувати DEP profiles для наданих серійних номерів, призначених організаціям. Він не робив непризначений довільний серійний номер дійсним.<sup>[[1]](#references)</sup>

### Автоматизація інструментування за допомогою Python

Процес експлуатації було автоматизовано за допомогою Python і LLDB API, що зробило можливим програмне вставлення довільних серійних номерів та отримання відповідних DEP profiles.<sup>[[1]](#references)</sup>

### Потенційні наслідки вразливостей DEP і MDM

Дослідження висвітлило значні проблеми безпеки:

1. **Розкриття інформації**: надання серійного номера, зареєстрованого в DEP, дає змогу отримати конфіденційну інформацію організації, що міститься в DEP profile.<sup>[[1]](#references)</sup>

## References

- [1] [Duo Labs — Безпека програми Device Enrollment Program: MDM Me Maybe](https://duo.com/labs/research/mdm-me-maybe)
- [2] [Apple Platform Deployment — Автоматичне зарахування пристроїв](https://support.apple.com/guide/deployment/automated-device-enrollment-and-mdm-dep73069dd57/web)
{{#include ../../../banners/hacktricks-training.md}}
