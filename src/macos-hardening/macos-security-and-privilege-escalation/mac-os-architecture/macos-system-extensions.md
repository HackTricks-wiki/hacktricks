# System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## System Extensions / Endpoint Security Framework

На відміну від Kernel Extensions, **System Extensions працюють у user space**, а не в kernel space, зменшуючи ризик збою системи через несправність extension.

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Існує три типи system extensions: **DriverKit** Extensions, **Network** Extensions і **Endpoint Security** Extensions.

### **DriverKit Extensions**

DriverKit є заміною kernel extensions, які **забезпечують підтримку hardware**. Він дає змогу драйверам пристроїв (таким як USB, Serial, NIC і HID drivers) працювати в user space, а не в kernel space. Framework DriverKit містить **версії певних класів I/O Kit для user space**, а kernel переспрямовує звичайні події I/O Kit у user space, забезпечуючи безпечніше середовище для роботи цих drivers.<sup>[[2]](#references)</sup>

### **Network Extensions**

Network Extensions дають змогу налаштовувати мережеву поведінку. Існує кілька типів Network Extensions:

- **App Proxy**: використовується для створення VPN client, який реалізує flow-oriented custom VPN protocol. Це означає, що він обробляє network traffic на основі з'єднань (або flows), а не окремих пакетів.
- **Packet Tunnel**: використовується для створення VPN client, який реалізує packet-oriented custom VPN protocol. Це означає, що він обробляє network traffic на основі окремих пакетів.
- **Filter Data**: використовується для фільтрації network "flows". Він може monitor або modify network data на рівні flow.
- **Filter Packet**: використовується для фільтрації окремих network packets. Він може monitor або modify network data на рівні packet.
- **DNS Proxy**: використовується для створення custom DNS provider. Його можна використовувати для monitor або modify DNS requests і responses.<sup>[[2]](#references)</sup>

## Endpoint Security Framework

Endpoint Security — це framework, наданий Apple у macOS, який містить набір APIs для system security. Він призначений для використання **security vendors і developers, щоб створювати продукти, які можуть monitor і control system activity** для виявлення malicious activity та захисту від неї.

Цей framework надає **набір APIs для monitor і control system activity**, зокрема process executions, file system events, network events і kernel events.

Основна частина цього framework реалізована в kernel як Kernel Extension (KEXT), розташована за шляхом **`/System/Library/Extensions/EndpointSecurity.kext`**.<sup>[[2]](#references)</sup> Цей KEXT складається з кількох ключових компонентів:

- **EndpointSecurityDriver**: діє як "entry point" для kernel extension. Це основна точка взаємодії між OS і Endpoint Security framework.
- **EndpointSecurityEventManager**: цей компонент відповідає за реалізацію kernel hooks. Kernel hooks дають framework змогу monitor system events, перехоплюючи system calls.
- **EndpointSecurityClientManager**: керує communication із user space clients, відстежуючи, які clients підключені та мають отримувати event notifications.
- **EndpointSecurityMessageManager**: надсилає messages і event notifications у user space clients.

Events, які може monitor Endpoint Security framework, поділяються на такі категорії:

- File events
- Process events
- Socket events
- Kernel events (наприклад, loading/unloading kernel extension або opening I/O Kit device)

### Endpoint Security Framework Architecture

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

**User-space communication** з Endpoint Security framework відбувається через клас IOUserClient. Залежно від типу caller використовуються два різні subclasses:

- **EndpointSecurityDriverClient**: вимагає entitlement `com.apple.private.endpoint-security.manager`, який належить лише system process `endpointsecurityd`.
- **EndpointSecurityExternalClient**: вимагає entitlement `com.apple.developer.endpoint-security.client`. Зазвичай його використовує third-party security software, якому потрібно взаємодіяти з Endpoint Security framework.<sup>[[1]](#references)</sup>

Endpoint Security Extensions:**`libEndpointSecurity.dylib`** — це C library, яку system extensions використовують для communication із kernel. Ця library використовує I/O Kit (`IOKit`) для communication з Endpoint Security KEXT.<sup>[[2]](#references)</sup>

**`endpointsecurityd`** — це ключовий system daemon, залучений до керування та запуску endpoint security system extensions, особливо під час early boot process. **Лише system extensions**, позначені **`NSEndpointSecurityEarlyBoot`** у своєму файлі `Info.plist`, отримують таку обробку під час early boot.<sup>[[2]](#references)</sup>

Інший system daemon, **`sysextd`**, **перевіряє system extensions** і переміщує їх у відповідні system locations. Потім він просить відповідний daemon load extension. **`SystemExtensions.framework`** відповідає за activation і deactivation system extensions.<sup>[[2]](#references)</sup>

## Bypassing ESF

ESF використовують security tools, які намагатимуться detect red teamer, тому будь-яка інформація про те, як цього можна уникнути, звучить цікаво.

### CVE-2021-30965

Проблема полягає в тому, що security application має отримати **Full Disk Access permissions**. Отже, якби attacker зміг їх remove, він міг би prevent software from running:<sup>[[3]](#references)</sup>
```bash
tccutil reset All
```
Для отримання **додаткової інформації** про цей bypass та пов’язані з ним bypass перевірте доповідь [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

Зрештою це було виправлено шляхом надання нового дозволу **`kTCCServiceEndpointSecurityClient`** security app, якою керує **`tccd`**, щоб `tccutil` не очищав її дозволи, запобігаючи її запуску.<sup>[[3]](#references)</sup>

## References

- [1] [OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [2] [Knight.sc - System Extension Internals](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)
- [3] [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

{{#include ../../../banners/hacktricks-training.md}}
