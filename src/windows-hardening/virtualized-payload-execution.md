# Sanallaştırılmış Payload Yürütme ve Özel VM Evasion

{{#include ../banners/hacktricks-training.md}}

Payload virtualization, saldırı mantığını bir guest instruction set'e derler ve yerel bir interpreter ile yürütür. Sonunda özgün yerel talimatları bellekte açığa çıkarması gereken bir packer'dan farklı olarak, virtualized payload korunan mantığı tüm ömrü boyunca bytecode olarak tutabilir. Bu, özel unpacking penceresini ortadan kaldırır; ancak syscall'lar, ağ etkinliği veya VM ile yerel kod arasındaki çağrı sınırı gibi host tarafından görülebilen davranışları **gizlemez**.<sup>[[2]](#references)[[3]](#references)</sup>

## Static-analysis evasion için WebAssembly'i yeniden host etme

İmza eşleşmesi yoğun bir Go aracını düzenlemek yerine, araç `wasip1` guest olarak derlenip ayrı bir yerel loader'a gömülebilir. Guest, `net.Dial`, `net.Listen`, `os/exec` ve `os.Pipe` gibi desteklenmeyen işlemlerin `//go:wasmimport` üzerinden yönlendirildiği yamalanmış bir GOROOT'a karşı derlenir; Wazero host module ise soketleri, process işlemlerini, Win32 çağrılarını ve macOS framework çağrılarını uygular. Böylece özgün projenin Go API kullanımı korunurken mantığının büyük bölümü, statik PE araçlarının anlayamayabileceği şifrelenmiş bir WASM module'üne taşınır.<sup>[[4]](#references)</sup>

### Linear memory ile native API'ler arasında köprü kurma

Guest pointer'ı, host virtual address değil, WASM linear memory içindeki 32 bitlik bir offset'tir. Native çağrıdan önce köprü, bir argümanı yalnızca local pointer olarak işaretlenmişse ve `0x10000 <= value < wasmMemorySize` aralığındaysa dönüştürerek `wasmMemoryBase + value` değerini elde edebilir. Alt sınır, küçük handle'ların, flag'lerin ve `nil` değerinin yeniden yazılmasını önler; `win32metadata` tarafından üretilen API başına maskeler, hatalı veya belirsiz metadata için geçersiz kılmalarla birlikte gerçek pointer'ları handle'lardan, boyutlardan ve remote-process adreslerinden ayırır.<sup>[[4]](#references)</sup>

Native API'ler, guest output buffer'ları üzerinden host pointer'ları da döndürebilir. Bir mirror table, bu nesnelere guest-memory karşılıkları atayıp özgün host adresine ters eşlemeyi saklayabilir. COM için hem interface'in hem de vtable'ının mirror edilmesi gerekir: data pointer'ları izlenip mirror edilebilirken, `MEM_IMAGE` bölgelerindeki çalıştırılabilir pointer'lar opak token'lar olarak kalmalıdır; çünkü WASM yerel talimatları çalıştıramaz. Bu model, `EnumWindows` veya `SetWindowsHookEx` gibi host-to-guest callback API'lerini doğrudan desteklemez.<sup>[[4]](#references)</sup>

### Build başına WASM VM polymorphism

Her build'de runtime ve payload birlikte dönüştürülebilir: opcode-to-handler tablosunu karıştırın, her guest opcode'u yeni eşlemeye göre yeniden yazın, section identifier'larını rastgeleleştirin, standart `\0asm` magic değerini build'e özel bir marker ile değiştirin ve runtime cache magic değerini değiştirin. Aynı kaynak böylece byte düzeyinde farklı module'ler üretir; analist host loader'daki özel eşleme ve framing'i çözene kadar standart WASM araçları payload'ı ayrıştıramaz.<sup>[[4]](#references)</sup>

Reverse engineering için yalnızca `\0asm` arayarak içerik çıkarmak yerine native host ile başlayın: derlenmiş marker'ı, module-decryption yolunu, opcode dispatch tablosunu ve `env` host-function kayıtlarını belirleyin; ardından standart bir module'ü yeniden oluşturun veya import sınırını instrument edin. Gömülü bytecode build'ler arasında değişse bile ağ iletişimi, process oluşturma, registry erişimi, dynamic loading ve genel Win32 dispatch çağrıları bu sınırdan geçtiği için köprü, davranışı gözlemlemek açısından kullanışlı bir kontrol noktası olmaya devam eder.<sup>[[4]](#references)</sup>

### Dış Go executable'ını kamufle etme

Yalnızca guest'i değiştirmek, tanınabilir bir loader bırakır. Gösterilen dış binary dönüşümleri, meşru Go projelerinden toplanan yoğun symbol profillerini `gopclntab` içine ekler, makul görünen az sayıdaki DLL import'u arasında dönüşümlü seçim yapar ve PE `VERSIONINFO` ile Authenticode identity string'lerini değiştirir. Bu dönüşümler container'ın statik ve machine-learning özelliklerini hedefler; host shim'lerinin açığa çıkardığı runtime davranışını ortadan kaldırmaz.<sup>[[4]](#references)</sup>

## Yürütme modeli

Kompakt bir virtualized loader, yürütmeyi aşağıdaki katmanlara ayırabilir.<sup>[[3]](#references)</sup>

1. Freestanding C, BOF source veya runtime library'lerini LLVM üzerinden özel bir bytecode ISA'ya derleyin.
2. Küçük bir native interpreter başlatıp build'e özel opcode eşlemesini başlatın.
3. PE linker-loader'ın kendisini bytecode olarak çalıştırın: header'ları ayrıştırın, section'ları map edin, relocation'ları uygulayın, import'ları çözümleyin ve IAT'yi doldurun.
4. Guest-to-guest çağrılarını interpreter içinde tutun. Import edilmiş DLL function'ları gibi bytecode bölgesinin dışındaki hedefleri native host-call thunk üzerinden yönlendirin.
5. HTTP framing, TLS ve C runtime'ın bazı bölümleri gibi destekleyici olanakları aynı interpretation sınırının arkasına taşıyın.

Bu model, her plugin için ayrı bir native code bölgesi ayırmayı önler ve özgün payload'ın tanınabilir bir x86-64 instruction stream olarak görünmesini engeller. Yine de bir güvenlik sınırı değil, bir evasion/obfuscation sınırıdır: native interpreter ve her dış etki gözlemlenebilir durumda kalır.<sup>[[2]](#references)[[3]](#references)</sup>

## Shared-memory host bridge

İzole bir VM, pointer'ları guest buffer içindeki offset'ler olarak temsil eder; bu nedenle host API sınırını geçen her işlem pointer çevirisi ve output parameter'ları için özel işlem gerektirir. Shared-memory VM ise guest adreslerini host process adresleri olarak kullanılabilir hale getirir. Böylece okuma ve yazma işlemleri `memcpy` benzeri işlemlerle yapılabilir ve yerel bir allocation ECALL tarafından döndürülen pointer, bytecode tarafından doğrudan dereference edilebilir. RISC-Y Business, bu tasarımın köprüyü PEB'yi almaya ve keyfi host çağrıları yapmaya indirgeyebileceğini gösterdi.<sup>[[1]](#references)</sup>

Windows x64 için virtual register file, ABI'yi yansıtabilir: ilk dört integer veya pointer argümanını `RCX`, `RDX`, `R8` ve `R9` içine yerleştirin; sonraki argümanları ve shadow space'i stack'e koyun. Bir virtual `CALL` bytecode aralığının dışındaki bir hedefe çözümlendiğinde, evrensel bir thunk bu durumu native çağrıya marshal eder ve dönüş değerini VM'ye geri kopyalar. Bu, pointer fixup'ları olmadan IAT çağrılarına, heap allocation'a ve socket işlemlerine olanak tanır.<sup>[[2]](#references)[[3]](#references)</sup>

Bunun karşılığında izolasyon tamamen kaybolur. Guest memory corruption doğrudan host'u etkileyebilir, native callee'ler guest pointer'larını saklayabilir veya değiştirebilir ve interpreter bytecode'u tamamen güvenilir kabul etmek zorundadır. Native-to-VM callback'ler de ters yönde bir köprü gerektirir; yalnızca dışa giden çağrıları destekleyen bir VM, `EnumWindows` gibi callback tabanlı API'leri doğrudan karşılayamaz.<sup>[[1]](#references)[[3]](#references)</sup>

## Build başına ISA polymorphism

Sabit genişlikli bir özel ISA; decoding, dispatch, relocation ve virtual-register mapping işlemlerini basitleştirir. Centurion, code density pahasına öngörülebilir parsing sağlayan ve mevcut x86-64 artifact'larını bytecode'a çevirmenin olası bir yolunu da sunan, x86-64'ten esinlenmiş 18 byte'lık bir instruction formatı kullanır.<sup>[[3]](#references)</sup>

Her build'de opcode-to-handler eşlemesini rastgeleleştirmek, aynı guest mantığının farklı byte sequence'leri üretmesini sağlar. Eşleme tablosunu şifreleyip yalnızca runtime'da geri elde etmek, diskteki sabit bir opcode dictionary'sini de ortadan kaldırır. Bu, sabit imzaları ve yeniden kullanılabilir disassembly kurallarını zorlaştırır; ancak native dispatcher'ı, tablo decryption rutinini veya host-call sınırını kendiliğinden polymorph etmez.<sup>[[3]](#references)</sup>

## Yürütme ortamını VM içine taşıma

Host process, bellek, syscall ve socket primitive'lerine indirgenebilir; freestanding library'ler ise daha üst düzey hizmetleri VM içinde sağlayabilir. Örneğin FreeRTOS coreHTTP, HTTP framing'i; mbedTLS ise WinHTTP veya işletim sistemi TLS API'sini çağırmadan TLS'yi uygulayabilir. `afd.sys` veya benzer bir interface üzerinden raw socket kullanımı, dar kapsamlı native networking sınırına dönüşür.<sup>[[3]](#references)</sup>

Bu **Bring Your Own Execution Environment (BYOEE)** tasarımı, PE loading'i, runtime desteğini ve in-memory filesystem'ı da interpreter arkasına yerleştirebilir. Tanınabilir native uygulamaları azaltır, ancak telemetry'yi ortadan kaldırmaz: raw socket işlemleri görünür olmaya devam eder ve açık proxy'ler veya TLS interception gerektiren ortamlarda networking tasarımı çalışmayabilir.<sup>[[3]](#references)</sup>

## Seçici native hızlandırma

Her instruction'ı yorumlamak, özellikle public-key cryptography işlemlerinde maliyetlidir. Pratik bir ayrım, mbedTLS'in `MBEDTLS_ALT` hook'larını software-coprocessor interface'i olarak kullanır: TLS state'ini, certificate parsing'i, negotiation'ı, allocation'ı ve üst düzey bignum kodunu bytecode'da tutar; ancak `bignum_core.c` içindeki yoğun aritmetik kernel'lerini native ECALL'ler üzerinden yönlendirir. Centurion prototype'ında `bignum.c`, `bignum_mod.c` ve `bignum_mod_raw.c` virtualized kalırken iç döngüler native olarak çalıştı ve ECDHE handshake süresi dakikalardan saniyelere indi.<sup>[[3]](#references)</sup>

Accelerator'ları isteğe bağlı yapın; böylece TLS gerektirmeyen payload'lar ek native entry point'leri içermez. Bu yaklaşım her türlü interpreter iş yüküne uyarlanabilir: önce profilleyin, ardından tüm bir subsystem'i VM dışına taşımak yerine mümkün olan en küçük native primitive'i açığa çıkarın.<sup>[[3]](#references)</sup>

Centurion, TLS 1.2 bind shell ile tüm zinciri doğruladı: bytecode loader PE'yi map etti, socket çağrıları evrensel thunk'tan geçti, mbedTLS protocol'ü VM içinde yönetti ve native ECALL'ler ECDHE aritmetiğini hızlandırdı. Böylece yaklaşık 18 KB'lık native interpreter, payload'ı native x86-64 kodu olarak bellekte oluşturmadan şifrelenmiş bir command channel'ı destekledi.<sup>[[3]](#references)</sup>

## Reverse engineering ve detection için odak noktaları

Aşağıdakiler, mimariden çıkarılmış pratik analiz odaklarıdır; virtualization, analistlerin davranışı gözlemlediği yeri değiştirir, ancak davranışın kendisini ortadan kaldırmaz.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

- Fetch/decode/dispatch döngüsünü, virtual program counter'ı, register file'ı ve sabit genişlikli instruction'ların tekrarlanan adımlarla işlenmesini belirleyin.
- Runtime decryption sonrasında opcode tablosunu dump edin ve diskteki şifreli bytecode'u eşleştirmek yerine handler adreslerini anlamsal işlemlerle ilişkilendirin.
- Native hedefi, virtual argüman register'larını, stack argümanlarını ve dönüş değerini kaydetmek için evrensel thunk veya ECALL dispatcher üzerinde breakpoint koyun.
- Loader uygulamasının kendisi bytecode olsa bile PEB erişimini, export resolution'ı, PE-header parsing'i, relocation yazımlarını ve IAT doldurmayı izleyin.
- Soket oluşturma ve `afd.sys` trafiğini, beklenen WinHTTP veya native TLS çağrılarının yokluğuyla ilişkilendirin; üst düzey import'ların eksikliği bir ipucudur, zararsız davranışın kanıtı değildir.
- Native aritmetik accelerator'larını anlamsal kontrol noktaları olarak değerlendirin: çevresindeki TLS state machine virtualized durumda kalırken, bunları çağıran kod key exchange ve certificate-validation etkinliğini açığa çıkarabilir.

Özgün control-flow graph yerine dispatcher'dan başlayan analiz iş akışları için [virtualizing packers hakkındaki malware-analysis rehberine](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#virtualizing-packers-and-no-labels-obfuscation) bakın.

## Operasyonel kısıtlamalar

Virtualization, interpretation overhead'i getirir, toolchain ve ABI karmaşıklığını artırır ve behavioral detection sorununu çözmez. Shared memory tasarım gereği güvensizdir, raw-socket networking zorunlu proxy'lerin arkasında başarısız olabilir ve callback ağırlıklı Win32 API'leri native-to-VM trampoline'leri gerektirir. Interpreter, syscall bridge ve native accelerator'lar da savunucuların imza oluşturabileceği veya instrument edebileceği geleneksel bir native footprint olarak kalır.<sup>[[2]](#references)[[3]](#references)</sup>

## İlgili sayfalar

VMProtect 3.x packing analizi için [emulated unpacking ve import repair](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#vmprotect-3x-emulated-unpacking-and-import-repair) sayfasına bakın.

{{#ref}}
../reversing/common-api-used-in-malware.md
{{#endref}}

{{#ref}}
../generic-hacking/reverse-shells/README.md
{{#endref}}

## References

- [1] [RISC-Y Business: Payload Obfuscation için RISC-V Virtual Machine Oluşturma](https://secret.club/2023/12/24/riscy-business.html)
- [2] [Fox-IT: EDR Çağında Red Teaming — Malware Virtualisation ile Evasion](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/)
- [3] [Praetorian: Centurion — Kendi Execution Environment'ınızı Getirin](https://praetorian.com/blog/virtualized-loader-centurion/)
- [4] [Praetorian - WasmForge'a Giriş: Sliver'ı WebAssembly'e Derleme](https://praetorian.com/blog/wasmforge-sliver-webassembly)
{{#include ../banners/hacktricks-training.md}}
