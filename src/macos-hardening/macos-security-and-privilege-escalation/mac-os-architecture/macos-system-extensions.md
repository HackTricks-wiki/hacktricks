# System Extensions macOS

{{#include ../../../banners/hacktricks-training.md}}

## System Extensions / Endpoint Security Framework

На відміну від Kernel Extensions, **System Extensions працюють у user space**, а не в kernel space, що знижує ризик збою системи через несправність extension.

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Існує три типи system extensions: **DriverKit** Extensions, **Network** Extensions і **Endpoint Security** Extensions.

### **DriverKit Extensions**

DriverKit є заміною kernel extensions, які **забезпечують підтримку hardware**. Він дає змогу device drivers (наприклад, USB, Serial, NIC і HID drivers) працювати в user space, а не в kernel space. Framework DriverKit містить **версії певних класів I/O Kit для user space**, а kernel переспрямовує звичайні події I/O Kit у user space, забезпечуючи безпечніше середовище для роботи цих drivers.<sup>[[2]](#references)</sup>

### **Network Extensions**

Network Extensions дають змогу налаштовувати поведінку мережі. Існує кілька типів Network Extensions:

- **App Proxy**: використовується для створення VPN client, який реалізує flow-oriented custom VPN protocol. Це означає, що він обробляє мережевий трафік на основі з’єднань (або flows), а не окремих packet.
- **Packet Tunnel**: використовується для створення VPN client, який реалізує packet-oriented custom VPN protocol. Це означає, що він обробляє мережевий трафік на основі окремих packet.
- **Filter Data**: використовується для фільтрації мережевих "flows". Він може моніторити або змінювати мережеві дані на рівні flow.
- **Filter Packet**: використовується для фільтрації окремих мережевих packet. Він може моніторити або змінювати мережеві дані на рівні packet.
- **DNS Proxy**: використовується для створення custom DNS provider. Його можна використовувати для моніторингу або зміни DNS-запитів і відповідей.<sup>[[2]](#references)</sup>

## Endpoint Security Framework

Endpoint Security — це framework, наданий Apple у macOS, який містить набір API для безпеки системи. Він призначений для **security vendors і developers, щоб створювати продукти, здатні моніторити та контролювати активність системи** для виявлення malicious activity і захисту від неї.

Цей framework надає **набір API для моніторингу та контролю активності системи**, зокрема виконання process, подій file system, network і kernel events.

Основна частина цього framework реалізована в kernel як Kernel Extension (KEXT), розташований за адресою **`/System/Library/Extensions/EndpointSecurity.kext`**.<sup>[[2]](#references)</sup> Цей KEXT складається з кількох ключових компонентів:

- **EndpointSecurityDriver**: виконує роль "entry point" для kernel extension. Це основна точка взаємодії між OS і Endpoint Security framework.
- **EndpointSecurityEventManager**: цей компонент відповідає за реалізацію kernel hooks. Kernel hooks дають framework змогу моніторити системні події шляхом перехоплення system calls.
- **EndpointSecurityClientManager**: керує комунікацією з clients у user space, відстежуючи, які clients підключені та мають отримувати сповіщення про події.
- **EndpointSecurityMessageManager**: надсилає повідомлення та сповіщення про події clients у user space.

Події, які може моніторити Endpoint Security framework, поділяються на такі категорії:

- File events
- Process events
- Socket events
- Kernel events (наприклад, завантаження/вивантаження kernel extension або відкриття I/O Kit device)

### Архітектура Endpoint Security Framework

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

**Комунікація з user space** через Endpoint Security framework відбувається за допомогою класу IOUserClient. Залежно від типу caller використовуються два різні subclasses:

- **EndpointSecurityDriverClient**: вимагає entitlement `com.apple.private.endpoint-security.manager`, який належить лише системному process `endpointsecurityd`.
- **EndpointSecurityExternalClient**: вимагає entitlement `com.apple.developer.endpoint-security.client`. Зазвичай його використовує third-party security software, якому потрібно взаємодіяти з Endpoint Security framework.<sup>[[1]](#references)</sup>

Endpoint Security Extensions:**`libEndpointSecurity.dylib`** — це C library, яку system extensions використовують для комунікації з kernel. Ця library використовує I/O Kit (`IOKit`) для взаємодії з Endpoint Security KEXT.<sup>[[2]](#references)</sup>

**`endpointsecurityd`** — це важливий system daemon, залучений до керування та запуску endpoint security system extensions, особливо під час early boot process. **Лише system extensions**, позначені **`NSEndpointSecurityEarlyBoot`** у своєму файлі `Info.plist`, отримують таку обробку під час early boot.<sup>[[2]](#references)</sup>

Інший system daemon, **`sysextd`**, **перевіряє system extensions** і переміщує їх до належних системних розташувань. Потім він просить відповідний daemon завантажити extension. **`SystemExtensions.framework`** відповідає за активацію та деактивацію system extensions.<sup>[[2]](#references)</sup>

## Обхід ESF

ESF використовується security tools, які намагатимуться виявити red teamer, тому будь-яка інформація про те, як цього можна уникнути, є цікавою.

### CVE-2021-30965

Проблема полягає в тому, що security application має отримати **Full Disk Access permissions**. Тож якби attacker міг їх видалити, він міг би перешкодити роботі software:<sup>[[3]](#references)</sup>
```bash
tccutil reset All
```
Для **отримання додаткової інформації** про цей bypass та пов’язані з ним перевірте доповідь [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)<sup>[[3]](#references)</sup>

Зрештою це було виправлено шляхом надання нового дозволу **`kTCCServiceEndpointSecurityClient`** security app, якою керує **`tccd`**, щоб `tccutil` не видаляв її дозволи, не даючи їй запуститися.<sup>[[3]](#references)</sup>

## Посилання

- [1] [OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [2] [Knight.sc - System Extension Internals](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)
- [3] [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

{{#include ../../../banners/hacktricks-training.md}}
