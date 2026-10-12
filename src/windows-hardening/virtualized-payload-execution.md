# Virtualized Payload Execution and Custom VM Evasion

{{#include ../banners/hacktricks-training.md}}

Payload virtualization, saldırgan mantığını bir guest komut kümesine derler ve yerel bir yorumlayıcıyla çalıştırır. Korunan yerel komutları eninde sonunda bellekte açığa çıkarması gereken bir packer’ın aksine, virtualized payload korunan mantığı tüm ömrü boyunca bytecode olarak tutabilir. Bu, belirli bir unpacking penceresini ortadan kaldırır; ancak syscall’lar, ağ etkinliği veya VM’den native koda çağrı sınırı gibi host tarafından görülebilen davranışları **gizlemez**.<sup>[[2]](#references)[[3]](#references)</sup>

## Execution model

Kompakt bir virtualized loader, yürütmeyi aşağıdaki katmanlara ayırabilir.<sup>[[3]](#references)</sup>

1. Freestanding C’yi, BOF kaynak kodunu veya runtime library’leri LLVM aracılığıyla özel bir bytecode ISA’ya derleyin.
2. Küçük bir native interpreter başlatın ve build’e özgü opcode eşlemesini başlatın.
3. PE linker-loader’ın kendisini bytecode olarak çalıştırın: başlıkları ayrıştırın, bölümleri eşleyin, relocation’ları uygulayın, import’ları çözümleyin ve IAT’yi doldurun.
4. Guest-to-guest çağrıları interpreter içinde tutun. Import edilmiş DLL işlevleri gibi bytecode bölgesinin dışındaki hedefleri native host-call thunk üzerinden yönlendirin.
5. HTTP framing, TLS ve C runtime’ın bazı bölümleri gibi destekleyici olanakları aynı yorumlama sınırının arkasına alın.

Bu model, her plugin için ayrı bir native code bölgesi ayırma gereksinimini ortadan kaldırır ve özgün payload’ın tanınabilir bir x86-64 komut akışı olarak görünmesini engeller. Yine de bu bir güvenlik sınırı değil, bir evasion/obfuscation sınırıdır: native interpreter ve her harici etki gözlemlenebilir durumda kalır.<sup>[[2]](#references)[[3]](#references)</sup>

## Shared-memory host bridge

Yalıtılmış bir VM, pointer’ları guest buffer içindeki offset’ler olarak temsil eder. Bu nedenle host API’sine yapılan her geçişte pointer çevirisi ve output parametreleri için özel işlem gerekir. Shared-memory VM ise guest adreslerini host process adresleri olarak geçerli kılar. Böylece okumalar ve yazmalar `memcpy` tarzı işlemlerle yapılabilir ve native allocation ECALL tarafından döndürülen bir pointer, bytecode tarafından doğrudan dereference edilebilir. RISC-Y Business, bu tasarımın bridge’i PEB’yi edinip keyfi host çağrıları yapmaya kadar indirebildiğini gösterdi.<sup>[[1]](#references)</sup>

Windows x64 için virtual register file ABI’yi taklit edebilir: ilk dört integer veya pointer argümanını `RCX`, `RDX`, `R8` ve `R9` içine, sonraki argümanları ve shadow space’i ise stack’e yerleştirin. Sanal bir `CALL`, bytecode aralığının dışındaki bir hedefe çözümlendiğinde universal thunk bu durumu native çağrıya uyarlar ve dönüş değerini VM’ye geri kopyalar. Böylece pointer fixup’ları olmadan IAT çağrıları, heap allocation ve socket işlemleri yapılabilir.<sup>[[2]](#references)[[3]](#references)</sup>

Bunun karşılığında yalıtım tamamen kaybolur. Guest belleğindeki bozulmalar host’u doğrudan etkileyebilir, native callee’ler guest pointer’larını saklayabilir veya değiştirebilir ve interpreter bytecode’u tamamen güvenilir kabul etmek zorundadır. Native-to-VM callback’ler de ters yönde bir bridge gerektirir; yalnızca dışarıya çağrı yapmayı destekleyen bir VM, `EnumWindows` gibi callback tabanlı API’leri doğrudan karşılayamaz.<sup>[[1]](#references)[[3]](#references)</sup>

## Per-build ISA polymorphism

Sabit genişlikli özel bir ISA; decoding, dispatch, relocation ve virtual-register eşlemesini basitleştirir. Centurion, 18 baytlık, x86-64’ten esinlenen bir instruction formatı kullanır. Bu yaklaşım, öngörülebilir parsing karşılığında code density’den ödün verir ve mevcut x86-64 artifact’lerini bytecode’a dönüştürmek için olası bir yol da sunar.<sup>[[3]](#references)</sup>

Her build için opcode-to-handler eşlemesini rastgeleleştirmek, aynı guest mantığının farklı byte sequence’ler üretmesini sağlar. Eşleme tablosunu şifreleyip yalnızca runtime’da geri elde etmek, diskteki sabit bir opcode sözlüğünü de ortadan kaldırır. Bu, sabit signature’ları ve yeniden kullanılabilir disassembly kurallarını zorlaştırır; ancak native dispatcher’ı, tablo çözme yordamını veya host-call sınırını otomatik olarak polymorph etmez.<sup>[[3]](#references)</sup>

## Bringing the execution environment into the VM

Host process, bellek, syscall ve socket primitive’lerine indirgenebilir; freestanding library’ler ise VM içinde daha üst düzey hizmetler sağlar. Örneğin FreeRTOS coreHTTP, HTTP framing’i; mbedTLS ise WinHTTP veya işletim sisteminin TLS API’sini çağırmadan TLS’yi uygulayabilir. Ardından `afd.sys` veya benzer bir arayüz üzerinden raw socket kullanımı, dar kapsamlı native networking sınırını oluşturur.<sup>[[3]](#references)</sup>

Bu **Bring Your Own Execution Environment (BYOEE)** tasarımı; PE loading’i, runtime desteğini ve bellekteki bir filesystem’ı da interpreter’ın arkasına alabilir. Telemetry’yi ortadan kaldırmak yerine tanınabilir native uygulamaları azaltır: raw socket işlemleri görünür kalır ve açık proxy’ler veya TLS interception gerektiren ortamlar networking tasarımının çalışmasını engelleyebilir.<sup>[[3]](#references)</sup>

## Selective native acceleration

Her instruction’ı yorumlamak, public-key cryptography işlemlerinde özellikle maliyetlidir. Uygulanabilir bir ayrımda, mbedTLS’in `MBEDTLS_ALT` hook’ları software-coprocessor arayüzü olarak kullanılır: TLS state’i, certificate parsing’i, negotiation’ı, allocation’ı ve üst düzey bignum kodunu bytecode içinde tutun; ancak `bignum_core.c` içindeki yoğun aritmetik kernel’lerini native ECALL’ler üzerinden çalıştırın. Centurion prototype’ında `bignum.c`, `bignum_mod.c` ve `bignum_mod_raw.c` virtualized kaldı; iç döngüler ise native çalıştırılarak ECDHE handshake süresi dakikalardan saniyelere indirildi.<sup>[[3]](#references)</sup>

Accelerator’ları isteğe bağlı yapın; böylece TLS gerektirmeyen payload’lar ek native entry point’leri dahil etmez. Bu yaklaşım her türlü interpreter iş yüküne uyarlanabilir: önce profiling yapın, sonra tüm bir subsystem’i VM dışına taşımak yerine mümkün olan en küçük native primitive’i açığa çıkarın.<sup>[[3]](#references)</sup>

Centurion, TLS 1.2 bind shell ile tüm zinciri doğruladı: bytecode loader PE’yi eşledi, socket çağrıları universal thunk üzerinden geçti, mbedTLS protokolü VM içinde işledi ve native ECALL’ler ECDHE aritmetiğini hızlandırdı. Böylece yaklaşık 18 KB’lık native interpreter, payload’ı native x86-64 kodu olarak bellekte oluşturmadan şifrelenmiş bir command channel’ı destekledi.<sup>[[3]](#references)</sup>

## Reversing and detection anchors

Aşağıdakiler, mimariden çıkarılan pratik analiz ipuçlarıdır; virtualization, analistlerin davranışı nerede gözlemlediğini değiştirir ancak davranışın kendisini ortadan kaldırmaz.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

- Fetch/decode/dispatch döngüsünü, virtual program counter’ı, register file’ı ve tekrarlanan sabit genişlikli instruction adımlarını belirleyin.
- Runtime’da şifresi çözüldükten sonra opcode tablosunu dump edin ve diskteki şifreli bytecode’u eşleştirmek yerine handler adreslerini anlamsal işlemlerle ilişkilendirin.
- Native hedefi, virtual argument register’larını, stack argümanlarını ve dönüş değerini kaydetmek için universal thunk’ta veya ECALL dispatcher’da duraklayın.
- Loader uygulamasının kendisi bytecode olsa bile PEB erişimini, export çözümlemesini, PE-header parsing’ini, relocation yazımlarını ve IAT doldurulmasını izleyin.
- Socket oluşturma ve `afd.sys` trafiğini, beklenen WinHTTP veya native TLS çağrılarının yokluğuyla ilişkilendirin; üst düzey import’ların eksikliği ipucudur, zararsız olduğunun kanıtı değildir.
- Native aritmetik accelerator’larını anlamsal darboğazlar olarak ele alın: çevredeki TLS state machine virtualized kalırken bunları çağıran kod, key exchange ve certificate-validation etkinliklerini ortaya çıkarabilir.

Özgün control-flow graph yerine dispatcher’dan başlayan analiz iş akışları için bkz. [malware-analysis guidance for virtualizing packers](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#virtualizing-packers-and-no-labels-obfuscation).

## Operational constraints

Virtualization, yorumlama maliyetini artırır, toolchain ve ABI karmaşıklığını yükseltir ve davranışsal tespiti çözmez. Shared memory tasarım gereği güvensizdir, raw-socket networking zorunlu proxy’lerin arkasında başarısız olabilir ve callback ağırlıklı Win32 API’leri native-to-VM trampoline’ler gerektirir. Interpreter, syscall bridge ve native accelerator’lar da savunucuların signature uygulayabileceği veya instrument edebileceği geleneksel bir native iz bırakır.<sup>[[2]](#references)[[3]](#references)</sup>

## Related pages

{{#ref}}
../reversing/common-api-used-in-malware.md
{{#endref}}

{{#ref}}
../generic-hacking/reverse-shells/README.md
{{#endref}}

## References

- [1] [RISC-Y Business: Payload Obfuscation için RISC-V Sanal Makinesi Oluşturma](https://secret.club/2023/12/24/riscy-business.html)
- [2] [Fox-IT: EDR Çağında Red Teaming — Malware Virtualisation ile Evasion](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/)
- [3] [Praetorian: Centurion — Kendi Execution Environment’ınızı Getirin](https://praetorian.com/blog/virtualized-loader-centurion/)
{{#include ../banners/hacktricks-training.md}}
