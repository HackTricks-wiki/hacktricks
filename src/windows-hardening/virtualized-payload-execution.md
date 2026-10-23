# वर्चुअलाइज़्ड Payload Execution और Custom VM Evasion

{{#include ../banners/hacktricks-training.md}}

Payload virtualization offensive logic को guest instruction set में compile करती है और उसे native interpreter से execute करती है। Packer के विपरीत, जिसे अंततः original native instructions को memory में उजागर करना पड़ता है, virtualized payload अपने पूरे lifetime में protected logic को bytecode के रूप में रख सकता है। इससे unpacking की वह खास window हट जाती है, लेकिन host-visible behavior जैसे syscalls, network activity या VM-to-native call boundary **छिपते नहीं हैं**।<sup>[[2]](#references)[[3]](#references)</sup>

## Static-analysis evasion के लिए WebAssembly re-hosting

भारी signatures वाले Go tool को edit करने के बजाय, उसे `wasip1` guest के रूप में compile करके एक अलग native loader में embed किया जा सकता है। Guest को patched GOROOT के विरुद्ध build किया जाता है, जिसमें `net.Dial`, `net.Listen`, `os/exec` और `os.Pipe` जैसे unsupported operations `//go:wasmimport` के ज़रिए delegate होते हैं; Wazero host module फिर sockets, process operations, Win32 calls और macOS framework calls implement करता है। इससे original project का Go API usage जस का तस रहता है, जबकि उसका अधिकांश logic एक encrypted WASM module में चला जाता है, जिसे static PE tooling शायद समझ न पाए।<sup>[[4]](#references)</sup>

### Linear memory को native APIs से जोड़ना

Guest pointer, WASM linear memory में 32-bit offset होता है, host virtual address नहीं। Native call से पहले bridge किसी argument को तभी translate कर सकता है, जब उसे local pointer के रूप में mark किया गया हो और वह `0x10000 <= value < wasmMemorySize` range में हो; इससे `wasmMemoryBase + value` बनता है। निचली सीमा छोटे handles, flags और `nil` को दोबारा लिखने से बचाती है; `win32metadata` से generate किए गए per-API masks वास्तविक pointers को handles, sizes और remote-process addresses से अलग करते हैं, और गलत या अस्पष्ट metadata के लिए overrides भी होते हैं।<sup>[[4]](#references)</sup>

Native APIs guest output buffers के ज़रिए host pointers भी लौटा सकते हैं। एक mirror table ऐसे objects को guest-memory representations दे सकती है और original host address की reverse mapping बनाए रख सकती है। COM के लिए interface और उसकी vtable, दोनों को mirror करना ज़रूरी है: data pointers को follow और mirror किया जा सकता है, जबकि `MEM_IMAGE` regions में executable pointers को opaque tokens ही रहना चाहिए, क्योंकि WASM native instructions execute नहीं कर सकता। यह model `EnumWindows` या `SetWindowsHookEx` जैसे host-to-guest callback APIs को सीधे support नहीं करता।<sup>[[4]](#references)</sup>

### हर build के लिए WASM VM polymorphism

हर build पर runtime और payload को साथ में transform किया जा सकता है: opcode-to-handler table को shuffle करें, हर guest opcode को नई mapping के अनुसार rewrite करें, section identifiers randomize करें, standard `\0asm` magic को build-specific marker से बदलें और runtime cache magic बदलें। इससे एक ही source से bytewise अलग modules बनते हैं, और analyst द्वारा host loader से custom mapping और framing recover करने तक सामान्य WASM tooling payload को parse नहीं कर सकती।<sup>[[4]](#references)</sup>

Reverse engineering के लिए, केवल `\0asm` पर carving करने के बजाय native host से शुरू करें: compiled marker, module-decryption path, opcode dispatch table और `env` host-function registrations पहचानें, फिर एक standard module reconstruct करें या import boundary को instrument करें। Bridge अब भी एक उपयोगी behavioral choke point है, क्योंकि embedded bytecode के हर build में बदलने पर भी networking, process creation, registry access, dynamic loading और generic Win32 dispatch की calls इसी से होकर गुजरती हैं।<sup>[[4]](#references)</sup>

### Outer Go executable को camouflage करना

केवल guest बदलने से पहचानने योग्य loader बना रहता है। दिखाए गए outer-binary transformations में legitimate Go projects से लिए गए dense symbol profiles को `gopclntab` में splice करना, DLL imports के एक छोटे plausible set को rotate करना, और PE `VERSIONINFO` तथा Authenticode identity strings को बदलना शामिल है। ये transformations container के static और machine-learning features को target करते हैं; host shims से उजागर होने वाला runtime behavior नहीं हटाते।<sup>[[4]](#references)</sup>

## Execution model

एक compact virtualized loader, execution को इन layers में बाँट सकता है।<sup>[[3]](#references)</sup>

1. Freestanding C, BOF source या runtime libraries को LLVM के ज़रिए custom bytecode ISA में compile करें।
2. एक छोटा native interpreter शुरू करें और build-specific opcode mapping initialize करें।
3. PE linker-loader को ही bytecode के रूप में चलाएँ: headers parse करें, sections map करें, relocations लागू करें, imports resolve करें और IAT populate करें।
4. Guest-to-guest calls को interpreter के भीतर रखें। Bytecode region के बाहर के targets, जैसे imported DLL functions, को native host-call thunk के ज़रिए route करें।
5. HTTP framing, TLS और C runtime के कुछ हिस्सों जैसी supporting facilities को भी इसी interpretation boundary के पीछे ले जाएँ।

यह model हर plugin के लिए अलग native code region allocate करने से बचाता है और original payload को पहचानने योग्य x86-64 instruction stream के रूप में दिखने से रोकता है। फिर भी यह security boundary नहीं, बल्कि evasion/obfuscation boundary है: native interpreter और हर external effect observable रहते हैं।<sup>[[2]](#references)[[3]](#references)</sup>

## Shared-memory host bridge

एक isolated VM pointers को guest buffer में offsets के रूप में दर्शाता है, इसलिए हर host API crossing पर pointer translation और output parameters की विशेष handling ज़रूरी होती है। इसके बजाय, shared-memory VM में guest addresses, host-process addresses के रूप में valid होते हैं। इसलिए reads और writes `memcpy`-style operations से किए जा सकते हैं, और native allocation ECALL से लौटाए गए pointer को bytecode सीधे dereference कर सकता है। RISC-Y Business ने दिखाया कि यह design bridge को PEB प्राप्त करने और arbitrary host calls जारी करने तक सीमित कर सकता है।<sup>[[1]](#references)</sup>

Windows x64 के लिए, virtual register file ABI को mirror कर सकता है: पहले चार integer या pointer arguments को `RCX`, `RDX`, `R8` और `R9` में रखें, और बाद के arguments तथा shadow space को stack पर रखें। जब कोई virtual `CALL`, bytecode range के बाहर resolve होता है, तो universal thunk उस state को native call के लिए marshal करता है और return value को VM में वापस copy करता है। इससे pointer fixups के बिना IAT calls, heap allocation और socket operations संभव होते हैं।<sup>[[2]](#references)[[3]](#references)</sup>

इसका tradeoff isolation का पूरी तरह खो जाना है। Guest memory corruption सीधे host को प्रभावित कर सकती है, native callees guest pointers को retain या modify कर सकते हैं, और interpreter को bytecode को पूरी तरह trusted मानना पड़ता है। Native-to-VM callbacks के लिए भी reverse bridge चाहिए; केवल outbound calls support करने वाला VM, `EnumWindows` जैसे callback-based APIs को सीधे पूरा नहीं कर सकता।<sup>[[1]](#references)[[3]](#references)</sup>

## हर build के लिए ISA polymorphism

एक fixed-width custom ISA decoding, dispatch, relocation और virtual-register mapping को सरल बनाता है। Centurion 18-byte, x86-64-inspired instruction format इस्तेमाल करता है, जो predictable parsing के बदले code density कम करता है और मौजूदा x86-64 artifacts को bytecode में translate करने का संभावित रास्ता भी देता है।<sup>[[3]](#references)</sup>

हर build के लिए opcode-to-handler mapping randomize करने से एक जैसा guest logic अलग-अलग byte sequences बनाता है। Mapping table को encrypt करके केवल runtime पर recover करने से disk पर मौजूद स्थिर opcode dictionary भी हट जाती है। इससे fixed signatures और reusable disassembly rules बाधित होते हैं, लेकिन native dispatcher, table-decryption routine या host-call boundary अपने-आप polymorphic नहीं होते।<sup>[[3]](#references)</sup>

## Execution environment को VM के भीतर लाना

Host process को memory, syscall और socket primitives तक सीमित किया जा सकता है, जबकि freestanding libraries VM के भीतर higher-level services उपलब्ध कराती हैं। उदाहरण के लिए, FreeRTOS coreHTTP HTTP framing implement कर सकता है और mbedTLS, WinHTTP या operating-system TLS API को call किए बिना TLS implement कर सकता है। `afd.sys` या किसी समान interface के ज़रिए raw sockets, फिर संकीर्ण native networking boundary बन जाते हैं।<sup>[[3]](#references)</sup>

यह **Bring Your Own Execution Environment (BYOEE)** design PE loading, runtime support और in-memory filesystem को भी interpreter के पीछे रख सकता है। यह पहचानने योग्य native implementations को कम करता है, telemetry को खत्म नहीं करता: raw socket operations दिखाई देते हैं, और जिन environments में explicit proxies या TLS interception ज़रूरी हैं, वहाँ networking design काम नहीं कर सकता।<sup>[[3]](#references)</sup>

## Selective native acceleration

हर instruction को interpret करना public-key cryptography में खास तौर पर महँगा पड़ता है। एक व्यावहारिक split, mbedTLS के `MBEDTLS_ALT` hooks को software-coprocessor interface के रूप में इस्तेमाल करता है: TLS state, certificate parsing, negotiation, allocation और high-level bignum code को bytecode में रखें, लेकिन `bignum_core.c` के hot arithmetic kernels को native ECALLs के ज़रिए dispatch करें। Centurion prototype में `bignum.c`, `bignum_mod.c` और `bignum_mod_raw.c` virtualized रहे, जबकि inner loops native रूप से चले; इससे ECDHE handshake का समय मिनटों से घटकर सेकंडों में आ गया।<sup>[[3]](#references)</sup>

Accelerators को optional रखें, ताकि जिन payloads को TLS की ज़रूरत नहीं है वे अतिरिक्त native entry points शामिल न करें। यह pattern किसी भी interpreter workload पर लागू होता है: पहले profile करें, फिर पूरे subsystem को VM से बाहर ले जाने के बजाय सबसे छोटा संभव native primitive expose करें।<sup>[[3]](#references)</sup>

Centurion ने TLS 1.2 bind shell के साथ पूरी chain को validate किया: bytecode loader ने PE map किया, socket calls universal thunk से गुज़रीं, mbedTLS ने VM के भीतर protocol संभाला और native ECALLs ने ECDHE arithmetic को accelerate किया। इस तरह लगभग 18 KB का native interpreter, payload को native x86-64 code के रूप में materialize किए बिना encrypted command channel support कर सका।<sup>[[3]](#references)</sup>

## Reversing और detection anchors

ये architecture से निकले व्यावहारिक analysis anchors हैं; virtualization यह बदलती है कि analysts behavior को कहाँ observe करते हैं, लेकिन behavior को हटाती नहीं है।<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

- Fetch/decode/dispatch loop, virtual program counter, register file और बार-बार होने वाले fixed-width instruction stepping की पहचान करें।
- Runtime decryption के बाद opcode table dump करें और disk पर encrypted bytecode से match करने के बजाय handler addresses को semantic operations से map करें।
- Universal thunk या ECALL dispatcher पर break करें, ताकि native target, virtual argument registers, stack arguments और return value record कर सकें।
- PEB access, export resolution, PE-header parsing, relocation writes और IAT population को trace करें, भले ही loader implementation स्वयं bytecode हो।
- Socket creation और `afd.sys` traffic को अपेक्षित WinHTTP या native TLS calls की अनुपस्थिति के साथ correlate करें; missing high-level imports एक clue हैं, benign behavior का प्रमाण नहीं।
- Native arithmetic accelerators को semantic chokepoints मानें: उनके callers key exchange और certificate-validation activity उजागर कर सकते हैं, जबकि आसपास की TLS state machine virtualized रहती है।

ऐसे analysis workflows के लिए, जो original control-flow graph के बजाय dispatcher से शुरू होते हैं, [virtualizing packers के लिए malware-analysis guidance](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#virtualizing-packers-and-no-labels-obfuscation) देखें।

## Operational constraints

Virtualization interpretation overhead बढ़ाती है, toolchain और ABI की complexity बढ़ाती है, और behavioral detection की समस्या हल नहीं करती। Shared memory design के अनुसार unsafe है, raw-socket networking mandatory proxies के पीछे fail हो सकती है, और callback-heavy Win32 APIs के लिए native-to-VM trampolines चाहिए। Interpreter, syscall bridge और कोई भी native accelerators भी एक पारंपरिक native footprint बने रहते हैं, जिन्हें defenders signature या instrument कर सकते हैं।<sup>[[2]](#references)[[3]](#references)</sup>

## Related pages

VMProtect 3.x packing के analysis के लिए, [emulated unpacking और import repair](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#vmprotect-3x-emulated-unpacking-and-import-repair) देखें।

{{#ref}}
../reversing/common-api-used-in-malware.md
{{#endref}}

{{#ref}}
../generic-hacking/reverse-shells/README.md
{{#endref}}

## References

- [1] [RISC-Y Business: Payload Obfuscation के लिए RISC-V Virtual Machine बनाना](https://secret.club/2023/12/24/riscy-business.html)
- [2] [Fox-IT: EDR के दौर में Red Teaming — Malware Virtualisation के ज़रिए Evasion](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/)
- [3] [Praetorian: Centurion — अपना Execution Environment लाएँ](https://praetorian.com/blog/virtualized-loader-centurion/)
- [4] [Praetorian - WasmForge में प्रवेश: Sliver को WebAssembly में Compile करना](https://praetorian.com/blog/wasmforge-sliver-webassembly)
{{#include ../banners/hacktricks-training.md}}
