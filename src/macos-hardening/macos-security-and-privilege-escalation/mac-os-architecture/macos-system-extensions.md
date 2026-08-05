# macOS System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## System Extensions / Endpoint Security Framework

Kernel Extensions'ın aksine, **System Extensions kernel space yerine user space'te çalışır**; bu da extension arızası nedeniyle sistem çökmesi riskini azaltır.

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Üç tür system extension vardır: **DriverKit** Extensions, **Network** Extensions ve **Endpoint Security** Extensions.

### **DriverKit Extensions**

DriverKit, **donanım desteği sağlayan** kernel extension'ların yerine kullanılan bir framework'tür. Device driver'ların (USB, Serial, NIC ve HID driver'ları gibi) kernel space yerine user space'te çalışmasını sağlar. DriverKit framework'ü, **belirli I/O Kit sınıflarının user space sürümlerini** içerir ve kernel, normal I/O Kit event'lerini user space'e ileterek bu driver'ların çalışması için daha güvenli bir ortam sunar.<sup>[2]</sup>

### **Network Extensions**

Network Extensions, network davranışlarını özelleştirme olanağı sağlar. Network Extensions'ın çeşitli türleri vardır:

- **App Proxy**: Flow-oriented, custom bir VPN protocol'ü uygulayan bir VPN client oluşturmak için kullanılır. Bu, network traffic'i tek tek packet'ler yerine connection'lara (veya flow'lara) göre işlediği anlamına gelir.
- **Packet Tunnel**: Packet-oriented, custom bir VPN protocol'ü uygulayan bir VPN client oluşturmak için kullanılır. Bu, network traffic'i tek tek packet'lere göre işlediği anlamına gelir.
- **Filter Data**: Network "flow"larını filtrelemek için kullanılır. Network data'sını flow seviyesinde monitor edebilir veya modify edebilir.
- **Filter Packet**: Tek tek network packet'lerini filtrelemek için kullanılır. Network data'sını packet seviyesinde monitor edebilir veya modify edebilir.
- **DNS Proxy**: Custom bir DNS provider oluşturmak için kullanılır. DNS request ve response'larını monitor etmek veya modify etmek için kullanılabilir.<sup>[2]</sup>

## Endpoint Security Framework

Endpoint Security, macOS'ta Apple tarafından sağlanan ve system security için bir API seti sunan bir framework'tür. **Security vendor'larının ve developer'ların malicious activity'yi tespit edip buna karşı koruma sağlamak amacıyla system activity'yi monitor ve control edebilen ürünler geliştirmesi** için tasarlanmıştır.

Bu framework; process execution'ları, file system event'leri, network ve kernel event'leri gibi **system activity'yi monitor ve control etmek için kullanılan bir API koleksiyonu** sağlar.

Bu framework'ün core'u kernel içinde, **`/System/Library/Extensions/EndpointSecurity.kext`** konumunda bulunan bir Kernel Extension (KEXT) olarak uygulanır.<sup>[2]</sup> Bu KEXT, birkaç temel component'ten oluşur:

- **EndpointSecurityDriver**: Bu, kernel extension için "entry point" görevi görür. OS ile Endpoint Security framework arasındaki temel interaction noktasıdır.
- **EndpointSecurityEventManager**: Bu component, kernel hook'larını uygulamaktan sorumludur. Kernel hook'ları, system call'ları intercept ederek framework'ün system event'lerini monitor etmesini sağlar.
- **EndpointSecurityClientManager**: User space client'larla iletişimi yönetir; hangi client'ların bağlı olduğunu ve event notification'ları alması gerektiğini takip eder.
- **EndpointSecurityMessageManager**: User space client'lara message ve event notification gönderir.

Endpoint Security framework'ünün monitor edebildiği event'ler şu kategorilere ayrılır:

- File event'leri
- Process event'leri
- Socket event'leri
- Kernel event'leri (kernel extension yükleme/unload etme veya bir I/O Kit device'ını açma gibi)

### Endpoint Security Framework Architecture

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

Endpoint Security framework ile **user-space communication**, IOUserClient sınıfı üzerinden gerçekleşir. Caller'ın türüne bağlı olarak iki farklı subclass kullanılır:

- **EndpointSecurityDriverClient**: Yalnızca system process'i olan `endpointsecurityd` tarafından sahip olunan `com.apple.private.endpoint-security.manager` entitlement'ını gerektirir.
- **EndpointSecurityExternalClient**: `com.apple.developer.endpoint-security.client` entitlement'ını gerektirir. Bu genellikle Endpoint Security framework ile etkileşime girmesi gereken third-party security software tarafından kullanılır.<sup>[1]</sup>

Endpoint Security Extensions:**`libEndpointSecurity.dylib`**, system extension'ların kernel ile communication kurmak için kullandığı C library'sidir. Bu library, Endpoint Security KEXT ile iletişim kurmak için I/O Kit (`IOKit`) kullanır.<sup>[2]</sup>

**`endpointsecurityd`**, endpoint security system extension'larını yönetme ve launch etme sürecinde, özellikle early boot process sırasında görev alan temel bir system daemon'dır. **Yalnızca** `Info.plist` dosyasında **`NSEndpointSecurityEarlyBoot`** ile işaretlenmiş system extension'lar bu early boot işlemine tabi tutulur.<sup>[2]</sup>

Başka bir system daemon olan **`sysextd`**, **system extension'ları validate eder** ve bunları uygun system location'larına taşır. Ardından ilgili daemon'dan extension'ı load etmesini ister. **`SystemExtensions.framework`**, system extension'ları activate ve deactivate etmekten sorumludur.<sup>[2]</sup>

## Bypassing ESF

ESF, bir red teamer'ı tespit etmeye çalışacak security tool'ları tarafından kullanılır; bu nedenle bunun nasıl önlenebileceğine dair her bilgi ilgi çekicidir.

### CVE-2021-30965

Sorun şu ki security application'ın **Full Disk Access permissions**'a sahip olması gerekir. Dolayısıyla bir attacker bunu kaldırabilirse software'in çalışmasını engelleyebilir:<sup>[3]</sup>
```bash
tccutil reset All
```
Bu bypass ve ilgili diğerleri hakkında **daha fazla bilgi** için [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI) konuşmasına bakın.

Sonunda bu, **`kTCCServiceEndpointSecurityClient`** yeni permission'ının **`tccd`** tarafından yönetilen security app'e verilmesiyle düzeltildi; böylece `tccutil` permission'larını temizleyemiyor ve uygulamanın çalışmasını engelleyemiyordu.<sup>[3]</sup>

## Referanslar

- [1] [OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [2] [Knight.sc - System Extension Internals](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)
- [3] [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

{{#include ../../../banners/hacktricks-training.md}}
