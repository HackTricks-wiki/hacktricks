# macOS Kernel ve System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## XNU Kernel

**macOS'un çekirdeği XNU'dur** ve bu ad "X is Not Unix" ifadesinin kısaltmasıdır. Bu kernel temel olarak **Mach microkernel** (daha sonra ele alınacaktır) **ve** Berkeley Software Distribution (**BSD**) unsurlarından oluşur. XNU ayrıca **I/O Kit adı verilen bir sistem aracılığıyla kernel driver'ları** için bir platform sağlar. XNU kernel'i Darwin open source projesinin bir parçasıdır; bu da **kaynak koduna herkesin özgürce erişebileceği** anlamına gelir.

Bir security researcher veya Unix developer açısından **macOS**, şık bir GUI'ye ve çeşitli özel uygulamalara sahip bir **FreeBSD** sistemi gibi **oldukça benzer** görünebilir. BSD için geliştirilen uygulamaların çoğu, değişiklik yapılmasına gerek kalmadan macOS üzerinde derlenip çalıştırılabilir; çünkü Unix kullanıcılarının aşina olduğu command-line araçlarının tamamı macOS'ta bulunur. Ancak XNU kernel'i Mach'ı içerdiğinden, geleneksel Unix-benzeri bir sistem ile macOS arasında bazı önemli farklılıklar vardır ve bu farklılıklar potansiyel sorunlara yol açabilir veya benzersiz avantajlar sağlayabilir.

XNU'nun open source sürümü: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach, **UNIX-compatible** olacak şekilde tasarlanmış bir **microkernel**'dir. Temel tasarım ilkelerinden biri, **kernel** space'te çalışan **code** miktarını **azaltmak** ve bunun yerine file system, networking ve I/O gibi tipik kernel işlevlerinin çoğunun **user-level task'ler** olarak **çalışmasına** izin vermekti.

XNU'da Mach; processor scheduling, multitasking ve virtual memory management gibi bir kernel'in normalde yönettiği **kritik düşük seviyeli işlemlerin çoğundan sorumludur**.

### BSD

XNU **kernel'i**, **FreeBSD** projesinden türetilen önemli miktarda code da **içerir**. Bu code, Mach ile birlikte ve aynı address space içinde kernel'in bir parçası olarak **çalışır**. Ancak XNU içindeki FreeBSD code'u, Mach ile uyumluluğunu sağlamak için değişiklikler gerektiğinden orijinal FreeBSD code'undan önemli ölçüde farklı olabilir. FreeBSD, aşağıdakiler de dahil olmak üzere birçok kernel işlemine katkı sağlar:

- Process management
- Signal handling
- User ve group management dahil olmak üzere temel security mekanizmaları
- System call altyapısı
- TCP/IP stack ve sockets
- Firewall ve packet filtering

Farklı kavramsal çerçeveleri nedeniyle BSD ile Mach arasındaki etkileşimi anlamak karmaşık olabilir. Örneğin BSD, temel execution unit olarak process'leri kullanırken Mach, thread'ler temelinde çalışır. Bu uyumsuzluk XNU'da, her BSD process'inin tam olarak bir Mach thread içeren bir Mach task ile **ilişkilendirilmesiyle** giderilir. BSD'nin fork() system call'u kullanıldığında, kernel içindeki BSD code'u bir task ve thread structure oluşturmak için Mach function'larını kullanır.

Ayrıca **Mach ve BSD farklı security modellerini korur**: **Mach'ın** security modeli **port rights**'e dayanırken BSD'nin security modeli **process ownership** temelinde çalışır. Bu iki model arasındaki farklılıklar zaman zaman local privilege-escalation vulnerability'lerine yol açmıştır. Tipik system call'ların yanı sıra, user-space programlarının kernel ile etkileşim kurmasına izin veren **Mach traps** de vardır. Bu farklı unsurlar birlikte macOS kernel'inin çok yönlü, hybrid architecture yapısını oluşturur.<sup>[[1]](#references)</sup>

### I/O Kit - Drivers

I/O Kit, XNU kernel içindeki open-source, object-oriented bir **device-driver framework**'üdür ve **dynamically loaded device driver'ları** yönetir. Modular code'un kernel'e anlık olarak eklenmesine izin vererek çeşitli donanımları destekler.


{{#ref}}
macos-iokit.md
{{#endref}}

### macOS Architecture İçindeki Coprocessor'lar

Apple platformları, latency-sensitive işleri main core'ların üzerinden almak ve security-critical işlevleri izole etmek için çeşitli coprocessor'lara dayanır.

- **Secure Enclave Processor (SEP)**: Kendi microkernel'i ve secure boot chain'i bulunan özel bir ARM core'udur ve genellikle **EL3/secure world** üzerinde çalışır. Etkileşim, macOS'ta EL1 seviyesindeki mailbox driver'ları üzerinden gerçekleşir.
- Attack surface: SEP firmware update'leri ve istekleri proxy'leyen user-space daemon'ları (`seputil`, `securityd`).
- Impact of compromise: Uzun vadeli key'leri leak etmek, biometric gating'i bypass etmek ve FileVault veya Apple Pay protections'ı kırmak.
- **System Management Controller (SMC)**: ARM exception level'larının dışında bir microcontroller üzerinde proprietary firmware çalıştırır. macOS (EL1), ona I/O Kit user client'ları üzerinden erişir.
- Attack surface: USB-C power delivery message'ları, fan/battery management interface'leri ve firmware update path'leri.
- Impact of compromise: Thermal limit'leri değiştirmek, sahte sensor data enjekte etmek, gücü kesmek veya kalıcı NVRAM backdoor'ları yerleştirmek.
- **T1/T2 Security Chips**: Kendi ARM core'ları üzerinde, büyük ölçüde EL1/EL3 seviyelerinde bridgeOS (watchOS-derived) çalıştırır. macOS, IOKit tarafından yönetilen PCIe/USB-like channel'lar üzerinden iletişim kurar.
- Attack surface: DFU/restore path'leri, `tccd` gibi servisler tarafından sunulan IPC endpoint'leri ve T2'ye bridge edilen media pipeline'ları.
- Impact of compromise: Secure boot'u devre dışı bırakmak, SSD içeriğini decrypt etmek, camera/mic gating'i ele geçirmek veya stealth persistence için HID input'u taklit etmek.
- **Display Coprocessor (DCP)**: DART (Apple'ın IOMMU'su) tarafından korunan izole bir address space içinde EL1 seviyesinde firmware çalıştırır.
- Attack surface: `DCPAVService` interface'leri, paylaşılan descriptor buffer'ları ve firmware image parsing.
- Impact of compromise: Arbitrary frame'ler enjekte etmek, framebuffer'ları snoop etmek veya DoS için display pipeline'ını çalışamaz duruma getirmek.
- **Apple Neural Engine (ANE)**: Özel bir ML cluster üzerinde microcode çalıştırır (ARM EL level'ları yoktur). macOS, işleri `ANECompilerService` ve IOKit üzerinden schedule eder.
- Attack surface: Compiled model binary'leri (`.ane`), custom kernel'ları besleyen Core ML API'leri ve firmware loader'ları.
- Impact of compromise: ML model'lerini değiştirmek veya exfiltrate etmek, işlenmiş audio/vision data'sını leak etmek veya on-device inference'ı sabote etmek.
- **AGX GPU**: Firmware, scheduler içeren custom GPU core'ları üzerinde çalışır; EL0, Metal command'larını gönderir ve EL1 bunları validate eder.
- Attack surface: Metal shader compiler, shared buffer mapping API'leri ve `com.apple.AGXFirmware` ioctl interface'leri.
- Impact of compromise: System memory'ye DMA erişimi, GPU driver'ları üzerinden sandbox escape veya kalıcı firmware implant'ları.
- **Apple Video Encoder (AVE)**: Firmware, Media Engine üzerinde EL1-like bir sandbox içinde çalışır. macOS, VideoToolbox ve `AppleAVE2` üzerinden etkileşim kurar.
- Attack surface: Codec bitstream'leri, parameter set'leri, user-supplied buffer'lar ve firmware update blob'ları.
- Impact of compromise: Uncompressed frame'leri leak etmek, DRM'i bypass etmek veya DMA engine'lerine erişimi olan code execution elde etmek.
- **Image Signal Processor (ISP)**: Media Engine cluster içinde secure firmware çalıştırır; macOS camera driver'ları EL1 seviyesinde çalışır.
- Attack surface: Camera HAL'leri, RAW frame descriptor'ları, ISP configuration queue'ları ve firmware update'leri.
- Impact of compromise: Raw camera feed'lerini sessizce capture etmek, privacy indicator'larını devre dışı bırakmak veya sahte görüntüler enjekte etmek.
- **AMX Matrix core'ları**: Yeni instruction'lar aracılığıyla EL0/EL1 seviyelerinde sunulan coprocessor unit'leri olarak çalışır.
- Attack surface: AMX state'in kernel virtualization'ı (`thread_set_state`, context switch'leri) ve user-space code generation.
- Impact of compromise: Diğer process'lerin tile register'larını leak etmek, workload'ları fingerprint etmek veya kernel memory corruption üzerinden privilege escalation gerçekleştirmek.

Modern macOS, bu coprocessor'ları chain of trust içindeki trusted component'ler olarak ele alır. SEP, SMC ve T2 firmware'leri Apple tarafından sign edilir ve handshake protocol'leri (genellikle mailbox veya I/O Kit family'leri üzerinden uygulanır), yalnızca authenticated firmware'in isteklere hizmet verebilmesini sağlamak için challenge-response check'leri içerir.

### IPC - Inter Process Communication

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## macOS Kernel Extensions

macOS, code'un çalışacağı yüksek privilege'lar nedeniyle Kernel Extensions'ı (.kext) yükleme konusunda **son derece kısıtlayıcıdır**. Aslında default olarak, bir bypass bulunmadıkça, bunu yapmak neredeyse imkansızdır.

Aşağıdaki sayfada macOS'un **kernelcache** içine yüklediği `.kext` dosyasını nasıl kurtarabileceğinizi de görebilirsiniz:

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### macOS System Extensions

macOS, Kernel Extensions kullanmak yerine System Extensions'ı oluşturmuştur; bunlar kernel ile etkileşim kurmak için user level API'leri sunar. Bu sayede developer'lar kernel extension kullanmaktan kaçınabilir.

{{#ref}}
macos-system-extensions.md
{{#endref}}


### Cryptexes ve RSR (Rapid Security Response)

- **Cryptex**, **CRYPTographically-sealed EXtension** ifadesinin kısaltmasıdır. Apple'ın major OS update'leri arasında değişme ihtimali daha yüksek olan OS bölümlerini (framework'ler, shared library'ler, app'ler) barındırmak için kullandığı sealed disk image'dır (container).
- macOS ve iOS'ta cryptex'lerin içine yerleştirilen component'ler, tüm system volume yeniden seal edilmeden RSR aracılığıyla **patch edilebilir veya değiştirilebilir**.
- Cryptex'ler, boot firmware'in yanında **Preboot volume** üzerinde bulunur ve runtime sırasında OS file system'ına graft edilir.
- Cryptex içeriğinin yüklenmesi validation içerir: Sistem file seal'lerini, manifest'leri ve root hash'leri kontrol eder, ardından cryptex içeriğini mount eder veya "graft" eder; böylece runtime sırasında app'ler mevcut olduğunda cryptex sürümlerini kullanır.
- Boot log'larında cryptex loading, kernel initialization'dan sonra ancak full system service'leri başlamadan önce gerçekleşir.


#### Rapid Security Response (RSR)

- **RSR**, **normal OS update'leri arasındaki security patch'lerini** dağıtmak için Apple'ın kullandığı mekanizmadır. Vulnerable bölümleri (örneğin library'ler ve framework'ler) core system volume'a dokunmadan update etmek için cryptex içeriğini hedefler.
- Bir RSR update uygulanırken device, Apple'ın signing server'ından bir **Cryptex1 Image4 manifest** ister. Bu manifest, device'a ve yeni cryptex içeriğine cryptographic olarak bağlanır.
- Base system için mevcut AP boot ticket, RSR tarafından **değiştirilmez**. Patch, sealed base OS üzerinde additive olarak çalışır.
- macOS'ta belirli patched component'ler (örneğin Safari), app yeniden başlatılır başlatılmaz aktif hale gelir; her zaman full system restart gerekmez.
- RSR'ler **removable**'dır: Her biri hem bir patch hem de base OS version'a geri dönmeyi sağlayan bir "antipatch" ile birlikte gelir. Removal sırasında cryptex içeriği geri alınır.
- RSR update'leri genellikle full OS update'lerinden çok daha küçüktür ve yüklenmeleri için daha düşük battery state gerekir.


## References

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
