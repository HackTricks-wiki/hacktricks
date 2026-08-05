# macOS Kernel ve System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## XNU Kernel

**macOS'un çekirdeği XNU'dur**; bu ad "X is Not Unix" ifadesinin kısaltmasıdır. Bu kernel temelde **Mach microkernel** (daha sonra ele alınacaktır) **ve** Berkeley Software Distribution (**BSD**) bileşenlerinden oluşur. XNU ayrıca **I/O Kit adlı bir sistem aracılığıyla kernel driver'ları için** bir platform sağlar. XNU kernel'i Darwin open source projesinin bir parçasıdır; bu da **kaynak koduna herkesin ücretsiz olarak erişebildiği** anlamına gelir.

Bir security researcher veya Unix developer perspektifinden bakıldığında, **macOS**, zarif bir GUI'ye ve çok sayıda özel uygulamaya sahip bir **FreeBSD** sistemi gibi **oldukça benzer** görünebilir. BSD için geliştirilen uygulamaların çoğu, herhangi bir değişiklik gerektirmeden macOS'ta derlenip çalıştırılabilir; çünkü Unix kullanıcılarının aşina olduğu command-line araçlarının tümü macOS'ta mevcuttur. Ancak XNU kernel'i Mach'ı içerdiğinden, geleneksel Unix benzeri bir sistem ile macOS arasında bazı önemli farklar vardır ve bu farklar potansiyel sorunlara yol açabilir veya benzersiz avantajlar sağlayabilir.

Open source version of XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach, **UNIX-compatible** olacak şekilde tasarlanmış bir **microkernel**'dir. Temel tasarım ilkelerinden biri, **kernel** alanında çalışan **code** miktarını **en aza indirmek** ve bunun yerine file system, networking ve I/O gibi tipik kernel işlevlerinin çoğunun **user-level task'ler olarak çalışmasına** izin vermekti.

XNU'da Mach; processor scheduling, multitasking ve virtual memory management gibi bir kernel'in genellikle üstlendiği **kritik low-level işlemlerin çoğundan sorumludur**.

### BSD

XNU **kernel'i**, **FreeBSD** projesinden türetilen önemli miktarda code da **içerir**. Bu code, **Mach ile birlikte kernel'in bir parçası olarak**, aynı address space içinde çalışır. Ancak XNU içindeki FreeBSD code'u, Mach ile uyumluluğunu sağlamak için değişiklikler gerektiğinden, orijinal FreeBSD code'undan önemli ölçüde farklı olabilir. FreeBSD aşağıdakiler de dahil olmak üzere birçok kernel işlemine katkıda bulunur:

- Process management
- Signal handling
- User ve group management dahil temel security mekanizmaları
- System call altyapısı
- TCP/IP stack ve sockets
- Firewall ve packet filtering

Farklı kavramsal çerçeveleri nedeniyle BSD ile Mach arasındaki etkileşimi anlamak karmaşık olabilir. Örneğin BSD, temel execution unit olarak process'leri kullanırken Mach, thread'ler temelinde çalışır. Bu uyumsuzluk, XNU'da **her BSD process'inin tam olarak bir Mach thread'i içeren bir Mach task'i ile ilişkilendirilmesiyle** giderilir. BSD'nin fork() system call'u kullanıldığında, kernel içindeki BSD code'u bir task ve thread structure oluşturmak için Mach function'larını kullanır.

Ayrıca **Mach ve BSD farklı security model'lerini korur**: **Mach'ın** security modeli **port rights**'a dayanırken BSD'nin security modeli **process ownership** temelinde çalışır. Bu iki model arasındaki farklılıklar zaman zaman local privilege-escalation vulnerabilities ile sonuçlanmıştır. Tipik system call'ların yanı sıra, user-space programlarının kernel ile etkileşim kurmasına izin veren **Mach traps** de vardır. Bu farklı unsurlar birlikte macOS kernel'inin çok yönlü, hybrid architecture yapısını oluşturur.

### I/O Kit - Drivers

I/O Kit, XNU kernel'inde bulunan ve **dynamically loaded device driver'ları** yöneten open-source, object-oriented bir **device-driver framework**'üdür. Kernel'e anında modular code eklenmesini sağlayarak çeşitli donanımları destekler.


{{#ref}}
macos-iokit.md
{{#endref}}

### macOS Architecture'daki Coprocessor'lar

Apple platformları, latency'ye duyarlı işleri ana core'ların dışında tutmak ve security açısından kritik işlevleri izole etmek için çeşitli coprocessor'lara dayanır.

- **Secure Enclave Processor (SEP)**: Kendi microkernel'i ve secure boot chain'i olan, genellikle **EL3/secure world** üzerinde çalışan özel bir ARM core'udur. Etkileşim, macOS'ta EL1 seviyesindeki mailbox driver'ları aracılığıyla gerçekleşir.
- Attack surface: SEP firmware updates ve istekleri proxy'leyen user-space daemon'ları (`seputil`, `securityd`).
- Impact of compromise: Long-term key'leri leak etmek, biometric gating'i bypass etmek ve FileVault ya da Apple Pay protections'ı kırmak.
- **System Management Controller (SMC)**: ARM exception level'larının dışında bulunan bir microcontroller üzerinde proprietary firmware çalıştırır. macOS (EL1), I/O Kit user client'ları aracılığıyla buna erişir.
- Attack surface: USB-C power delivery mesajları, fan/battery management interface'leri ve firmware update path'leri.
- Impact of compromise: Thermal limit'leri override etmek, sahte sensor data enjekte etmek, gücü kesmek veya kalıcı NVRAM backdoor'ları yerleştirmek.
- **T1/T2 Security Chips**: Kendi ARM core'ları üzerinde, çoğunlukla EL1/EL3 seviyelerinde bridgeOS (watchOS-derived) çalıştırır. macOS, IOKit tarafından yönetilen PCIe/USB benzeri kanallar üzerinden iletişim kurar.
- Attack surface: DFU/restore path'leri, `tccd` gibi servislerin açığa çıkardığı IPC endpoint'leri ve T2'ye bridge edilen media pipeline'ları.
- Impact of compromise: Secure boot'u devre dışı bırakmak, SSD içeriğini decrypt etmek, camera/mic gating'i ele geçirmek veya stealth persistence için HID input'u taklit etmek.
- **Display Coprocessor (DCP)**: DART (Apple'ın IOMMU'su) tarafından korunan izole bir address space içinde EL1 seviyesinde firmware çalıştırır.
- Attack surface: `DCPAVService` interface'leri, paylaşılan descriptor buffer'ları ve firmware image parsing.
- Impact of compromise: Arbitrary frame'ler enjekte etmek, framebuffer'ları snoop etmek veya DoS için display pipeline'ını kullanılamaz hale getirmek.
- **Apple Neural Engine (ANE)**: Özel bir ML cluster'ında microcode çalıştırır (ARM EL level'ları yoktur). macOS, işleri `ANECompilerService` ve IOKit aracılığıyla schedule eder.
- Attack surface: Compiled model binary'leri (`.ane`), custom kernel'ları besleyen Core ML API'leri ve firmware loader'ları.
- Impact of compromise: ML model'lerini değiştirmek veya exfiltrate etmek, işlenen audio/vision data'sını leak etmek ya da on-device inference'ı sabote etmek.
- **AGX GPU**: Firmware, scheduler içeren custom GPU core'larında çalışır; EL0, Metal command'larını gönderir ve EL1 bunları validate eder.
- Attack surface: Metal shader compiler, shared buffer mapping API'leri ve `com.apple.AGXFirmware` ioctl interface'leri.
- Impact of compromise: System memory'ye DMA erişimi, GPU driver'ları üzerinden sandbox escape veya kalıcı firmware implant'ları.
- **Apple Video Encoder (AVE)**: Firmware, Media Engine üzerinde EL1 benzeri bir sandbox'ta çalışır. macOS, VideoToolbox ve `AppleAVE2` aracılığıyla etkileşim kurar.
- Attack surface: Codec bitstream'leri, parameter set'leri, user-supplied buffer'lar ve firmware update blob'ları.
- Impact of compromise: Uncompressed frame'leri leak etmek, DRM'yi bypass etmek veya DMA engine'lerine erişim sağlayan code execution elde etmek.
- **Image Signal Processor (ISP)**: Media Engine cluster'ında secure firmware çalıştırır; macOS camera driver'ları EL1 seviyesinde çalışır.
- Attack surface: Camera HAL'leri, RAW frame descriptor'ları, ISP configuration queue'ları ve firmware updates.
- Impact of compromise: Raw camera feed'lerini sessizce capture etmek, privacy indicator'larını devre dışı bırakmak veya sahte görüntüler enjekte etmek.
- **AMX Matrix core'ları**: Yeni instruction'lar aracılığıyla EL0/EL1 seviyelerinde expose edilen coprocessor unit'leri olarak çalışır.
- Attack surface: AMX state'in kernel virtualization'ı (`thread_set_state`, context switches) ve user-space code generation.
- Impact of compromise: Diğer process'lerin tile register'larını leak etmek, workload'ları fingerprint etmek veya kernel memory corruption üzerinden privilege escalation gerçekleştirmek.

Modern macOS, bu coprocessor'ları chain of trust içinde trusted component'ler olarak kabul eder. SEP, SMC ve T2 firmware'i Apple tarafından imzalanır ve handshake protocol'leri (genellikle mailbox'lar veya I/O Kit family'leri üzerinden uygulanır), yalnızca authenticated firmware'in isteklere hizmet verebilmesini sağlamak için challenge-response kontrolleri içerir.

### IPC - Inter Process Communication

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## macOS Kernel Extensions

macOS, code'un çalışacağı yüksek privilege'lar nedeniyle Kernel Extensions'ları (.kext) yükleme konusunda **son derece kısıtlayıcıdır**. Aslında varsayılan olarak bu işlem neredeyse imkansızdır (bir bypass bulunmadığı sürece).

Aşağıdaki sayfada macOS'un **kernelcache** içine yüklediği `.kext` dosyasını nasıl kurtarabileceğinizi de görebilirsiniz:

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### macOS System Extensions

macOS, Kernel Extensions kullanmak yerine System Extensions'ı oluşturmuştur; bunlar kernel ile etkileşim kurmak için user level API'ler sunar. Bu sayede developer'lar kernel extensions kullanmaktan kaçınabilir.

{{#ref}}
macos-system-extensions.md
{{#endref}}


### Cryptexes ve RSR (Rapid Security Response)

- **Cryptex**, **CRYPTographically-sealed EXtension** ifadesinin kısaltmasıdır. Apple'ın major OS update'leri arasında değişme olasılığı daha yüksek olan OS bölümlerini (framework'ler, shared library'ler, app'ler) barındırmak için kullandığı sealed disk image (container)'ıdır.
- macOS ve iOS'ta cryptex'lerin içine yerleştirilen component'ler, tüm system volume'u yeniden seal etmeye gerek kalmadan RSR aracılığıyla **patch edilebilir veya değiştirilebilir**.
- Cryptex'ler, boot firmware'in yanında **Preboot volume** üzerinde bulunur ve runtime sırasında OS file system'ine graft edilir.
- Cryptex içeriğinin yüklenmesi validation içerir: sistem file seal'lerini, manifest'leri ve root hash'leri kontrol eder, ardından cryptex içeriğini mount eder veya “graft” eder; böylece runtime sırasında app'ler mevcut olduklarında cryptex version'larını kullanır.
- Boot log'larında cryptex loading, kernel initialization'dan sonra ancak full system services başlamadan önce gerçekleşir.


#### Rapid Security Response (RSR)

- **RSR**, **regular OS update'leri arasında security patch'leri sunmak** için Apple'ın kullandığı mekanizmadır. Vulnerable bölümleri (ör. library'ler ve framework'ler) core system volume'a dokunmadan güncellemek için cryptex içeriğini hedefler.
- Bir RSR update uygulanırken cihaz, Apple'ın signing server'ından bir **Cryptex1 Image4 manifest** ister. Bu manifest, cihazla ve yeni cryptex içeriğiyle cryptographically bound durumdadır.
- Base system için mevcut AP boot ticket, **RSR tarafından değiştirilmez**. Patch, sealed base OS üzerinde additive olarak çalışır.
- macOS'ta belirli patched component'ler (ör. Safari), app yeniden başlatılır başlatılmaz aktif hale gelir; full system restart her zaman gerekli değildir.
- RSR'ler **removable**'dır: her biri hem bir patch hem de base OS version'a geri dönmeyi sağlayan bir “antipatch” ile birlikte gelir. Kaldırma sırasında cryptex içeriği geri alınır.
- RSR update'leri genellikle full OS update'lerinden çok daha küçüktür ve yüklenmeleri için daha düşük battery state gerekir.


## References

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
