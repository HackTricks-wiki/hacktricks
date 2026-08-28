# Реєстрація пристроїв в інших організаціях

{{#include ../../../banners/hacktricks-training.md}}

## Вступ

Apple Automated Device Enrollment (раніше DEP) починається з визначення пристрою, призначеного організації. Дослідження 2018 року, узагальнене тут, показало, що знання призначеного серійного номера було достатнім для отримання enrollment profiles деяких організацій, оскільки ці організації не вимагали належної додаткової автентифікації. Це історичний висновок, а не твердження, що до кожного сучасного MDM можна приєднатися лише за серійним номером. Профілі можуть містити сертифікати, застосунки, секрети Wi-Fi, налаштування VPN та інші конфіденційні конфігурації.<sup>[[1]](#references)[[2]](#references)</sup>

**Нижче наведено короткий виклад дослідження [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Перегляньте його для отримання додаткових технічних деталей!**<sup>[[1]](#references)</sup>

## Огляд бінарного аналізу DEP і MDM

У дослідженні аналізувалися бінарні файли, пов’язані з DEP і MDM, у версіях macOS, актуальних на той час. Назви компонентів і їхні функції можуть змінюватися в різних релізах:

- **`mdmclient`**: взаємодіє із серверами MDM і запускає DEP check-ins у версіях macOS до 10.13.4.
- **`profiles`**: керує Configuration Profiles і запускає DEP check-ins у версіях macOS 10.13.4 і новіших.
- **`cloudconfigurationd`**: керує взаємодією з DEP API та отримує Device Enrollment profiles.

DEP check-ins використовують функції `CPFetchActivationRecord` і `CPGetActivationRecord` із приватного фреймворку Configuration Profiles для отримання Activation Record, а `CPFetchActivationRecord` взаємодіє з `cloudconfigurationd` через XPC.<sup>[[1]](#references)</sup>

## Реверс-інжиніринг протоколу Tesla та схеми Absinthe

Під час DEP check-in `cloudconfigurationd` надсилає зашифрований JSON payload із цифровим підписом до _iprofiles.apple.com/macProfile_. Payload містить серійний номер пристрою та дію "RequestProfileConfiguration". Схема шифрування всередині системи називається "Absinthe". Розкриття принципу роботи цієї схеми є складним і передбачає численні кроки, тому дослідники почали шукати альтернативні методи вставлення довільних серійних номерів у запит Activation Record.<sup>[[1]](#references)</sup>

## Проксування DEP-запитів

Спроби перехоплювати й змінювати DEP-запити до _iprofiles.apple.com_ за допомогою таких інструментів, як Charles Proxy, ускладнювалися шифруванням payload і засобами безпеки SSL/TLS. Однак увімкнення конфігурації `MCCloudConfigAcceptAnyHTTPSCertificate` дає змогу обійти перевірку сертифіката сервера, хоча зашифрований характер payload усе одно не дозволяє змінити серійний номер без ключа розшифрування.<sup>[[1]](#references)</sup>

## Інструментування системних бінарних файлів, що взаємодіють із DEP

Інструментування системних бінарних файлів, таких як `cloudconfigurationd`, потребує вимкнення System Integrity Protection (SIP) у macOS. Коли SIP вимкнено, такі інструменти, як LLDB, можна використовувати для приєднання до системних процесів і потенційної зміни серійного номера, що використовується під час взаємодії з DEP API. Цей метод є кращим, оскільки дає змогу уникнути складнощів, пов’язаних із entitlements і code signing.<sup>[[1]](#references)</sup>

**Експлуатація бінарного інструментування:**
Зміна DEP request payload до серіалізації JSON у `cloudconfigurationd` виявилася ефективною. Процес передбачав:

1. Приєднання LLDB до `cloudconfigurationd`.
2. Пошук місця, де отримується системний серійний номер.
3. Вставлення довільного серійного номера в пам’ять до шифрування та надсилання payload.

Цей метод дав дослідникам змогу отримувати DEP profiles для переданих серійних номерів, призначених організаціям. Він не робив непризначений довільний серійний номер дійсним.<sup>[[1]](#references)</sup>

### Автоматизація інструментування за допомогою Python

Процес експлуатації автоматизували за допомогою Python і LLDB API, що зробило можливим програмне вставлення довільних серійних номерів і отримання відповідних DEP profiles.<sup>[[1]](#references)</sup>

## Повторне дослідження 2025 року: Rogue Enrollment із VM

Дослідження Black Hat Asia 2025 продемонструвало, що початкова проблема межі довіри все ще може мати значення на **рівні MDM**: замість patching `cloudconfigurationd` за допомогою LLDB дослідники запускали macOS під QEMU/KVM з OpenCore і передавали candidate identity через SMBIOS VM. Після цього незмінений enrollment stack macOS виконував зашифрований обмін з Apple. Тому publicly leaked serials і кандидати, що мають дійсний вигляд, можна тестувати без відповідного фізичного Mac; однак позитивний результат усе одно вимагає, щоб серійний номер був призначений організації, а enrollment path цієї організації мав недостатню автентифікацію.<sup>[[3]](#references)</sup>

Для авторизованого лабораторного пристрою відповідні значення OpenCore `PlatformInfo` включають модель продукту та серійний номер (у реальних розгортаннях ROM і UUID також мають залишатися внутрішньо узгодженими):<sup>[[3]](#references)</sup>
```xml
<key>SystemProductName</key>
<string>iMacPro1,1</string>
<key>SystemSerialNumber</key>
<string>AUTHORIZED_TEST_SERIAL</string>
```
Те саме дослідження виявило стан `CheckProfilesFetchRateLimit` у приватному файлі `/var/db/ConfigurationProfiles/Settings/.profilesDEPTimerCheck`. Оскільки перевірка виконувалася на клієнті, зміна збережених значень часу нівелювала її. Ці шляхи не задокументовані та залежать від версії, але вони корисні як reversing pivots під час оцінювання поточної збірки macOS:<sup>[[3]](#references)</sup>
```bash
sudo plutil -p /var/db/ConfigurationProfiles/Settings/.profilesDEPTimerCheck 2>/dev/null
sudo plutil -p /var/db/ConfigurationProfiles/Settings/.cloudConfigRecordFound 2>/dev/null
```
Другий артефакт може розкрити кешований запис активації, зокрема інформацію про те, чи використовує flow прямий `ConfigurationURL`, чи автентифікований `ConfigurationWebURL`. Протестуйте як заявлений flow, так і будь-які MDM-specific legacy endpoints enrollment: увімкнення SSO лише в основному web flow не захищає паралельний прямий endpoint. Повну послідовність протоколу див. в [огляді macOS MDM](README.md).<sup>[[3]](#references)</sup>

### Пошук секретів після enrollment

Rogue enrollment — лише точка входу. Після enrollment перевірте кожен доставлений profile, bootstrap policy, конфігурацію package-repository, script встановлення agent і self-service item. У дослідженні 2025 року були виявлені приклади облікових даних Wi-Fi, спільних паролів локального адміністратора, підписаних URL cloud-storage, URL webhook, даних активації security-agent та облікових даних MDM/API. Облікові дані tenant API у доставленому script можуть перетворити один rogue endpoint на контроль над іншими керованими пристроями, тому шукайте як у live filesystem, так і в завантаженому/кешованому вмісті policy.<sup>[[3]](#references)</sup>

Корисні цілі для перевірки:<sup>[[3]](#references)</sup>

- Встановлені payload `.mobileconfig` і база даних Configuration Profiles.
- PreStage/bootstrap scripts і packages, які створюють облікові записи або встановлюють EDR/VPN agents.
- Munki або інші URL package repository, особливо query strings, що містять підписи у стилі bearer/SAS.
- Self-service catalogs і відповідні їм policy APIs, включно з legacy routes, які можуть не застосовувати policy enrollment SSO.
- Shell history і кешований вивід policy для `password`, `token`, `secret`, `Authorization`, hostname webhook та vendor API endpoints.

### Посилення межі довіри

Розглядайте серійний номер як атрибут inventory/routing, **а не** як доказ володіння. Вимагайте user authentication для enrollment і self service, генеруйте унікальні паролі локального адміністратора для кожного пристрою та ніколи не вбудовуйте облікові дані tenant API або багаторазово використовувані infrastructure secrets у profiles чи scripts. Будь-який неминучий bootstrap token має бути короткоживучим і обмеженим однією дією та пристроєм, який provisioned.<sup>[[3]](#references)</sup>

На Mac з Apple silicon під керуванням macOS 14 або новішої версії Managed Device Attestation може криптографічно пов’язати ідентичність із Secure Enclave. Attestation, rooted в Apple, може містити свіжий nonce разом із серійним номером, UDID, версією ОС, станом SIP і станом secure boot; після цього ACME може видати hardware-bound client identity. Використовуйте цю ідентичність для захисту MDM channel і контролю доступу до high-value certificates, VPN та інших ресурсів, водночас зберігаючи окрему user authentication, оскільки device attestation підтверджує пристрій, а не оператора.<sup>[[4]](#references)</sup>

## Потенційні наслідки вразливостей DEP і MDM

Дослідження висвітлило значні проблеми безпеки:

1. **Розкриття інформації**: надавши серійний номер, зареєстрований у DEP, можна отримати конфіденційну інформацію організації, що міститься в DEP profile.<sup>[[1]](#references)</sup>



## References

- [1] [Duo Labs — Безпека Device Enrollment Program: MDM Me Maybe](https://duo.com/labs/research/mdm-me-maybe)
- [2] [Apple Platform Deployment — Automated Device Enrollment](https://support.apple.com/guide/deployment/automated-device-enrollment-and-mdm-dep73069dd57/web)
- [3] [Black Hat Asia 2025 — Impostor Syndrome: Hacking Apple MDMs Using Rogue Device Enrolments](https://i.blackhat.com/Asia-25/Asia-25-Molnar-Impostor-Syndrome-Hacking-Apple-MDMs.pdf)
- [4] [Apple Platform Security — Managed Device Attestation](https://support.apple.com/guide/security/managed-device-attestation-sec8a37b4cb2/web)
{{#include ../../../banners/hacktricks-training.md}}
