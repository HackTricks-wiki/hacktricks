# Virtualized Payload Execution और Custom VM Evasion

{{#include ../banners/hacktricks-training.md}}

Payload virtualization, offensive logic को guest instruction set में compile करके native interpreter से execute करती है। Packer के विपरीत, जिसे अंततः original native instructions को memory में उजागर करना पड़ता है, virtualized payload अपनी protected logic को पूरे समय bytecode के रूप में रख सकती है। इससे unpacking की वह खास window हट जाती है, लेकिन host-visible behavior—जैसे syscalls, network activity या VM-to-native call boundary—नहीं छिपता।<sup>[[2]](#references)[[3]](#references)</sup>

## Execution model

एक compact virtualized loader, execution को निम्नलिखित layers में बाँट सकता है।<sup>[[3]](#references)</sup>

1. Freestanding C, BOF source या runtime libraries को LLVM के ज़रिए custom bytecode ISA में compile करें।
2. एक छोटा native interpreter शुरू करें और build-specific opcode mapping initialize करें।
3. PE linker-loader को स्वयं bytecode के रूप में चलाएँ: headers parse करें, sections map करें, relocations लागू करें, imports resolve करें और IAT populate करें।
4. Guest-to-guest calls को interpreter के अंदर रखें। Bytecode region के बाहर के targets, जैसे imported DLL functions, को native host-call thunk के ज़रिए route करें।
5. HTTP framing, TLS और C runtime के कुछ हिस्सों जैसी सहायक सुविधाओं को भी इसी interpretation boundary के पीछे रखें।

यह model हर plugin के लिए अलग native code region allocate करने से बचता है और original payload को पहचानने योग्य x86-64 instruction stream के रूप में सामने आने से रोकता है। फिर भी यह security boundary नहीं, बल्कि evasion/obfuscation boundary है: native interpreter और हर external effect देखे जा सकते हैं।<sup>[[2]](#references)[[3]](#references)</sup>

## Shared-memory host bridge

एक isolated VM, pointers को guest buffer के offsets के रूप में दर्शाता है, इसलिए हर host API crossing पर pointer translation और output parameters की विशेष handling ज़रूरी होती है। इसके बजाय shared-memory VM, guest addresses को host-process addresses के रूप में valid बनाता है। इसलिए reads और writes `memcpy`-style operations का उपयोग कर सकते हैं, और native allocation ECALL से मिले pointer को bytecode सीधे dereference कर सकता है। RISC-Y Business ने दिखाया कि यह design bridge को PEB प्राप्त करने और मनमाने host calls करने तक सीमित कर सकता है।<sup>[[1]](#references)</sup>

Windows x64 के लिए virtual register file, ABI की नकल कर सकती है: पहले चार integer या pointer arguments को `RCX`, `RDX`, `R8` और `R9` में रखें; बाद के arguments और shadow space stack पर रखें। जब कोई virtual `CALL`, bytecode range के बाहर resolve होता है, तो universal thunk उस state को native call के लिए marshal करता है और return value को VM में वापस copy करता है। इससे pointer fixups के बिना IAT calls, heap allocation और socket operations संभव होते हैं।<sup>[[2]](#references)[[3]](#references)</sup>

इसका tradeoff isolation का पूरी तरह खत्म होना है। Guest memory corruption सीधे host को प्रभावित कर सकती है, native callees guest pointers को अपने पास रख या उनमें बदलाव कर सकते हैं, और interpreter को bytecode को पूरी तरह trusted मानना पड़ता है। Native-to-VM callbacks के लिए भी reverse bridge चाहिए; केवल outbound calls support करने वाला VM, `EnumWindows` जैसे callback-based APIs को सीधे पूरा नहीं कर सकता।<sup>[[1]](#references)[[3]](#references)</sup>

## Per-build ISA polymorphism

Fixed-width custom ISA से decoding, dispatch, relocation और virtual-register mapping आसान हो जाती है। Centurion, 18-byte का x86-64-inspired instruction format इस्तेमाल करता है। इसमें predictable parsing के बदले code density कम होती है और मौजूदा x86-64 artifacts को bytecode में translate करने का संभावित रास्ता भी मिलता है।<sup>[[3]](#references)</sup>

हर build के लिए opcode-to-handler mapping को randomize करने से एक जैसी guest logic के byte sequences अलग-अलग बनते हैं। Mapping table को encrypt करना और उसे केवल runtime पर recover करना, disk पर मौजूद स्थिर opcode dictionary को भी हटा देता है। इससे fixed signatures और बार-बार इस्तेमाल किए जा सकने वाले disassembly rules बाधित होते हैं, लेकिन native dispatcher, table-decryption routine या host-call boundary अपने-आप polymorphic नहीं होते।<sup>[[3]](#references)</sup>

## Execution environment को VM के अंदर लाना

Host process को memory, syscall और socket primitives तक सीमित किया जा सकता है, जबकि freestanding libraries VM के अंदर higher-level services देती हैं। उदाहरण के लिए, FreeRTOS coreHTTP, HTTP framing लागू कर सकता है और mbedTLS, WinHTTP या operating-system TLS API को call किए बिना TLS लागू कर सकता है। इसके बाद `afd.sys` या इसी तरह के interface के ज़रिए raw sockets, native networking की संकरी boundary बन जाते हैं।<sup>[[3]](#references)</sup>

यह **Bring Your Own Execution Environment (BYOEE)** design, PE loading, runtime support और in-memory filesystem को भी interpreter के पीछे रख सकता है। इससे पहचाने जा सकने वाले native implementations कम होते हैं, telemetry खत्म नहीं होती: raw socket operations दिखते रहते हैं, और जिन environments में explicit proxies या TLS interception ज़रूरी हो, वहाँ networking design काम नहीं कर सकता।<sup>[[3]](#references)</sup>

## Selective native acceleration

हर instruction को interpret करना public-key cryptography में खास तौर पर महँगा पड़ता है। एक व्यावहारिक विभाजन में mbedTLS के `MBEDTLS_ALT` hooks को software-coprocessor interface की तरह इस्तेमाल किया जाता है: TLS state, certificate parsing, negotiation, allocation और high-level bignum code को bytecode में रखें, लेकिन `bignum_core.c` के hot arithmetic kernels को native ECALLs से dispatch करें। Centurion prototype में `bignum.c`, `bignum_mod.c` और `bignum_mod_raw.c` virtualized रहे, जबकि inner loops native रूप से चले। इससे ECDHE handshake का समय मिनटों से घटकर सेकंडों में आ गया।<sup>[[3]](#references)</sup>

Accelerators को optional रखें, ताकि जिन payloads को TLS की ज़रूरत नहीं है, वे अतिरिक्त native entry points को छोड़ सकें। यह तरीका किसी भी interpreter workload पर लागू होता है: पहले profile करें, फिर पूरे subsystem को VM के बाहर ले जाने के बजाय सबसे छोटी संभव native primitive उपलब्ध कराएँ।<sup>[[3]](#references)</sup>

Centurion ने TLS 1.2 bind shell के साथ पूरी chain validate की: bytecode loader ने PE map किया, socket calls universal thunk से गुज़रीं, mbedTLS ने VM के अंदर protocol संभाला और native ECALLs ने ECDHE arithmetic को तेज़ किया। इस तरह लगभग 18 KB का native interpreter, payload को native x86-64 code के रूप में materialize किए बिना encrypted command channel चला सका।<sup>[[3]](#references)</sup>

## Reversing और detection के संकेत

ये architecture से निकले व्यावहारिक analysis संकेत हैं; virtualization से analysts को behavior जहाँ दिखता है, वह बदलता है, लेकिन behavior स्वयं खत्म नहीं होता।<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

- Fetch/decode/dispatch loop, virtual program counter, register file और fixed-width instructions के बार-बार होने वाले stepping की पहचान करें।
- Runtime decryption के बाद opcode table dump करें और disk पर encrypted bytecode से match करने के बजाय handler addresses को semantic operations से map करें।
- Universal thunk या ECALL dispatcher पर break करें और native target, virtual argument registers, stack arguments तथा return value रिकॉर्ड करें।
- PEB access, export resolution, PE-header parsing, relocation writes और IAT population को trace करें—भले ही loader implementation स्वयं bytecode हो।
- Socket creation और `afd.sys` traffic को अपेक्षित WinHTTP या native TLS calls की अनुपस्थिति से correlate करें; high-level imports का न होना एक clue है, benign behavior का प्रमाण नहीं।
- Native arithmetic accelerators को semantic chokepoints मानें: उनके callers key exchange और certificate-validation activity दिखा सकते हैं, जबकि आसपास का TLS state machine virtualized रहता है।

Dispatcher से शुरू होने वाले analysis workflows के लिए, original control-flow graph से शुरू करने के बजाय, [virtualizing packers के लिए malware-analysis guidance](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#virtualizing-packers-and-no-labels-obfuscation) देखें।

## Operational constraints

Virtualization से interpretation overhead और toolchain तथा ABI की complexity बढ़ती है, और यह behavioral detection को हल नहीं करती। Shared memory design से ही unsafe है, raw-socket networking अनिवार्य proxies के पीछे विफल हो सकती है, और callback-heavy Win32 APIs के लिए native-to-VM trampolines चाहिए। Interpreter, syscall bridge और native accelerators भी conventional native footprint का हिस्सा रहते हैं, जिन्हें defenders signature या instrument कर सकते हैं।<sup>[[2]](#references)[[3]](#references)</sup>

## Related pages

{{#ref}}
../reversing/common-api-used-in-malware.md
{{#endref}}

{{#ref}}
../generic-hacking/reverse-shells/README.md
{{#endref}}

## References

- [1] [RISC-Y Business: Payload Obfuscation के लिए RISC-V Virtual Machine बनाना](https://secret.club/2023/12/24/riscy-business.html)
- [2] [Fox-IT: EDR के युग में Red Teaming — Malware Virtualisation के ज़रिए Evasion](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/)
- [3] [Praetorian: Centurion — अपना Execution Environment लाएँ](https://praetorian.com/blog/virtualized-loader-centurion/)
{{#include ../banners/hacktricks-training.md}}
