# Системні розширення macOS

{{#include ../../../banners/hacktricks-training.md}}

## Системні розширення / Endpoint Security Framework

На відміну від Kernel Extensions, **System Extensions працюють у user space**, а не в kernel space, що зменшує ризик аварійного завершення роботи системи через несправність розширення.

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Існує три типи системних розширень: розширення **DriverKit**, **Network** і **Endpoint Security**.

### **Розширення DriverKit**

DriverKit є заміною kernel extensions, які **забезпечують підтримку hardware**. Він дає змогу драйверам пристроїв (наприклад, USB, Serial, NIC і HID-драйверам) працювати в user space, а не в kernel space. Framework DriverKit містить **версії певних класів I/O Kit для user space**, а kernel пересилає звичайні події I/O Kit у user space, забезпечуючи безпечніше середовище для роботи цих драйверів.<sup>[2]</sup>

### **Network Extensions**

Network Extensions дають змогу налаштовувати мережеву поведінку. Існує кілька типів Network Extensions:

- **App Proxy**: використовується для створення VPN-клієнта, який реалізує flow-oriented custom VPN protocol. Це означає, що він обробляє мережевий трафік на основі з'єднань (або flows), а не окремих пакетів.
- **Packet Tunnel**: використовується для створення VPN-клієнта, який реалізує packet-oriented custom VPN protocol. Це означає, що він обробляє мережевий трафік на основі окремих пакетів.
- **Filter Data**: використовується для фільтрації мережевих "flows". Він може відстежувати або змінювати мережеві дані на рівні flow.
- **Filter Packet**: використовується для фільтрації окремих мережевих пакетів. Він може відстежувати або змінювати мережеві дані на рівні пакетів.
- **DNS Proxy**: використовується для створення custom DNS provider. Його можна використовувати для відстеження або зміни DNS-запитів і відповідей.<sup>[2]</sup>

## Endpoint Security Framework

Endpoint Security — це framework, наданий Apple у macOS, який містить набір API для безпеки системи. Він призначений для використання **security vendors і developers з метою створення продуктів, здатних відстежувати та контролювати активність системи**, щоб виявляти malicious activity і захищати від неї.

Цей framework надає **набір API для відстеження та контролю активності системи**, зокрема виконання процесів, подій файлової системи, мережевих і kernel-подій.

Основна частина цього framework реалізована в kernel як Kernel Extension (KEXT), розташована за шляхом **`/System/Library/Extensions/EndpointSecurity.kext`**.<sup>[2]</sup> Цей KEXT складається з кількох ключових компонентів:

- **EndpointSecurityDriver**: виконує роль "entry point" для kernel extension. Це основна точка взаємодії між OS і Endpoint Security framework.
- **EndpointSecurityEventManager**: цей компонент відповідає за реалізацію kernel hooks. Kernel hooks дають framework змогу відстежувати системні події шляхом перехоплення system calls.
- **EndpointSecurityClientManager**: керує комунікацією з клієнтами в user space, відстежуючи, які клієнти підключені та мають отримувати сповіщення про події.
- **EndpointSecurityMessageManager**: надсилає повідомлення та сповіщення про події клієнтам у user space.

Події, які може відстежувати Endpoint Security framework, поділяються на такі категорії:

- File events
- Process events
- Socket events
- Kernel events (наприклад, завантаження/вивантаження kernel extension або відкриття пристрою I/O Kit)

### Архітектура Endpoint Security Framework

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

**Комунікація з user space** через Endpoint Security framework відбувається за допомогою класу IOUserClient. Залежно від типу caller використовуються два різні subclass-и:

- **EndpointSecurityDriverClient**: вимагає entitlement `com.apple.private.endpoint-security.manager`, який має лише системний процес `endpointsecurityd`.
- **EndpointSecurityExternalClient**: вимагає entitlement `com.apple.developer.endpoint-security.client`. Зазвичай його використовує third-party security software, якому потрібно взаємодіяти з Endpoint Security framework.<sup>[1]</sup>

Endpoint Security Extensions:**`libEndpointSecurity.dylib`** — це C library, яку системні розширення використовують для комунікації з kernel. Ця library використовує I/O Kit (`IOKit`) для взаємодії з Endpoint Security KEXT.<sup>[2]</sup>

**`endpointsecurityd`** — ключовий системний daemon, залучений до керування та запуску endpoint security system extensions, особливо під час early boot process. **Лише system extensions**, позначені як **`NSEndpointSecurityEarlyBoot`** у файлі `Info.plist`, отримують таку обробку під час early boot.<sup>[2]</sup>

Інший системний daemon, **`sysextd`**, **перевіряє system extensions** і переміщує їх у відповідні системні locations. Після цього він просить відповідний daemon завантажити extension. За активацію та деактивацію system extensions відповідає **`SystemExtensions.framework`**.<sup>[2]</sup>

## Обхід ESF

ESF використовується security tools, які намагатимуться виявити red teamer, тому будь-яка інформація про те, як цього можна уникнути, є цікавою.

### CVE-2021-30965

Проблема полягає в тому, що security application має отримати **Full Disk Access permissions**. Тому якщо attacker зможе їх видалити, він зможе перешкодити роботі software:<sup>[3]</sup>
```bash
tccutil reset All
```
Для **більш детальної інформації** про цей bypass та пов’язані з ним bypass перевірте доповідь [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

Зрештою це виправили, надавши новий дозвіл **`kTCCServiceEndpointSecurityClient`** security app, яким керує **`tccd`**, щоб `tccutil` не очищав його дозволи, перешкоджаючи його запуску.<sup>[3]</sup>

## Посилання

- [1] [OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [2] [Knight.sc - System Extension Internals](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)
- [3] [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

{{#include ../../../banners/hacktricks-training.md}}
