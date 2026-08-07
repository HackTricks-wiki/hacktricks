# macOS System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## System Extensions / Endpoint Security Framework

Kernel Extensions'ın aksine, **System Extensions kernel space yerine user space'te çalışır** ve extension arızası nedeniyle sistem çökmesi riskini azaltır.

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Üç tür system extension vardır: **DriverKit** Extensions, **Network** Extensions ve **Endpoint Security** Extensions.

### **DriverKit Extensions**

DriverKit, **hardware desteği sağlayan** kernel extensions'ın yerine kullanılan bir teknolojidir. Device driver'ların (USB, Serial, NIC ve HID driver'ları gibi) kernel space yerine user space'te çalışmasını sağlar. DriverKit framework'ü, **belirli I/O Kit sınıflarının user space sürümlerini** içerir ve kernel, normal I/O Kit event'lerini user space'e ileterek bu driver'ların çalışması için daha güvenli bir ortam sunar.<sup>[[2]](#references)</sup>

### **Network Extensions**

Network Extensions, network davranışlarını özelleştirme imkanı sağlar. Birkaç Network Extension türü vardır:

- **App Proxy**: Flow-oriented, custom bir VPN protocol'ü uygulayan bir VPN client oluşturmak için kullanılır. Bu, network traffic'ini tek tek packet'ler yerine connection'lara (veya flow'lara) göre işlediği anlamına gelir.
- **Packet Tunnel**: Packet-oriented, custom bir VPN protocol'ü uygulayan bir VPN client oluşturmak için kullanılır. Bu, network traffic'ini tek tek packet'lere göre işlediği anlamına gelir.
- **Filter Data**: Network "flow"larını filtrelemek için kullanılır. Network data'sını flow seviyesinde monitor edebilir veya değiştirebilir.
- **Filter Packet**: Tek tek network packet'lerini filtrelemek için kullanılır. Network data'sını packet seviyesinde monitor edebilir veya değiştirebilir.
- **DNS Proxy**: Custom bir DNS provider oluşturmak için kullanılır. DNS request ve response'larını monitor etmek veya değiştirmek için kullanılabilir.<sup>[[2]](#references)</sup>

## Endpoint Security Framework

Endpoint Security, macOS'ta Apple tarafından sağlanan ve system security için bir dizi API sunan bir framework'tür. **Security vendor'larının ve developer'ların system activity'yi monitor edip kontrol ederek malicious activity'yi tespit eden ve buna karşı koruma sağlayan ürünler geliştirmesi** için tasarlanmıştır.

Bu framework; process execution'ları, file system event'leri, network ve kernel event'leri gibi system activity'yi **monitor etmek ve kontrol etmek için bir API koleksiyonu** sunar.

Bu framework'ün çekirdeği, **`/System/Library/Extensions/EndpointSecurity.kext`** konumunda bulunan bir Kernel Extension (KEXT) olarak kernel'de uygulanır.<sup>[[2]](#references)</sup> Bu KEXT birkaç temel bileşenden oluşur:

- **EndpointSecurityDriver**: Kernel extension için "entry point" görevi görür. OS ile Endpoint Security framework arasındaki ana etkileşim noktasıdır.
- **EndpointSecurityEventManager**: Kernel hook'larını uygulamaktan sorumludur. Kernel hook'ları, system call'ları intercept ederek framework'ün system event'lerini monitor etmesini sağlar.
- **EndpointSecurityClientManager**: User space client'larıyla iletişimi yönetir; hangi client'ların bağlı olduğunu ve event notification'larını alması gerektiğini takip eder.
- **EndpointSecurityMessageManager**: User space client'larına message ve event notification'ları gönderir.

Endpoint Security framework'ünün monitor edebildiği event'ler şu kategorilere ayrılır:

- File event'leri
- Process event'leri
- Socket event'leri
- Kernel event'leri (kernel extension yükleme/kaldırma veya bir I/O Kit device'ı açma gibi)

### Endpoint Security Framework Architecture

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

Endpoint Security framework ile **user-space communication**, IOUserClient sınıfı üzerinden gerçekleşir. Caller türüne bağlı olarak iki farklı subclass kullanılır:

- **EndpointSecurityDriverClient**: Yalnızca system process'i olan `endpointsecurityd` tarafından sahip olunan `com.apple.private.endpoint-security.manager` entitlement'ını gerektirir.
- **EndpointSecurityExternalClient**: `com.apple.developer.endpoint-security.client` entitlement'ını gerektirir. Bu genellikle Endpoint Security framework ile etkileşim kurması gereken third-party security software tarafından kullanılır.<sup>[[1]](#references)</sup>

Endpoint Security Extensions:**`libEndpointSecurity.dylib`**, system extension'ların kernel ile iletişim kurmak için kullandığı C library'sidir. Bu library, Endpoint Security KEXT ile iletişim kurmak için I/O Kit (`IOKit`) kullanır.<sup>[[2]](#references)</sup>

**`endpointsecurityd`**, özellikle early boot process sırasında endpoint security system extension'larını yönetme ve başlatma görevinde yer alan önemli bir system daemon'dur. Yalnızca `Info.plist` dosyasında **`NSEndpointSecurityEarlyBoot`** ile işaretlenmiş **system extension**'lar bu early boot işlemine tabi tutulur.<sup>[[2]](#references)</sup>

Başka bir system daemon olan **`sysextd`**, **system extension'ları doğrular** ve uygun system location'larına taşır. Ardından ilgili daemon'dan extension'ı yüklemesini ister. **`SystemExtensions.framework`**, system extension'ların etkinleştirilmesinden ve devre dışı bırakılmasından sorumludur.<sup>[[2]](#references)</sup>

## Bypassing ESF

ESF, bir red teamer'ı tespit etmeye çalışacak security tool'ları tarafından kullanılır; bu nedenle bunun nasıl atlatılabileceğine dair her bilgi ilgi çekicidir.

### CVE-2021-30965

Sorun şu ki security application'ın **Full Disk Access permissions**'a sahip olması gerekir. Dolayısıyla bir attacker bunu kaldırabilirse software'in çalışmasını engelleyebilir:<sup>[[3]](#references)</sup>
```bash
tccutil reset All
```
**daha fazla bilgi** için bu bypass ve ilgili bypass'lar hakkında [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)<sup>[[3]](#references)</sup> konuşmasına bakın.

Sonunda bu durum, yeni **`kTCCServiceEndpointSecurityClient`** izninin **`tccd`** tarafından yönetilen security app'e verilmesiyle düzeltildi; böylece `tccutil` bu uygulamanın izinlerini temizleyemiyor ve uygulamanın çalışmasını engelleyemiyor.<sup>[[3]](#references)</sup>

## References

- [1] [OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [2] [Knight.sc - System Extension Internals](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)
- [3] [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

{{#include ../../../banners/hacktricks-training.md}}
