# macOS Kernel और System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## XNU Kernel

**macOS का core XNU है**, जिसका अर्थ "X is Not Unix" है। यह kernel मूल रूप से **Mach microkernel** (जिस पर बाद में चर्चा की जाएगी), **और** Berkeley Software Distribution (**BSD**) के elements से बना है। XNU **I/O Kit नामक system के माध्यम से kernel drivers** के लिए भी platform प्रदान करता है। XNU kernel Darwin open source project का हिस्सा है, जिसका अर्थ है कि **इसका source code freely accessible है**।

Security researcher या Unix developer के दृष्टिकोण से, **macOS** एक elegant GUI और कई custom applications वाले **FreeBSD** system के समान महसूस हो सकता है। BSD के लिए विकसित अधिकांश applications macOS पर बिना modifications के compile और run हो जाएंगी, क्योंकि Unix users से परिचित command-line tools macOS में मौजूद हैं। हालांकि, क्योंकि XNU kernel में Mach शामिल है, traditional Unix-like system और macOS के बीच कुछ महत्वपूर्ण differences हैं, और ये differences potential issues पैदा कर सकते हैं या unique advantages प्रदान कर सकते हैं।

XNU का open source version: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach एक **microkernel** है जिसे **UNIX-compatible** होने के लिए design किया गया है। इसके प्रमुख design principles में से एक था **kernel** space में चलने वाले **code** की मात्रा को **कम करना** और इसके बजाय file system, networking और I/O जैसे कई typical kernel functions को **user-level tasks के रूप में run** होने देना।

XNU में Mach कई critical low-level operations के लिए **responsible** है, जिन्हें आमतौर पर kernel handle करता है, जैसे processor scheduling, multitasking और virtual memory management।

### BSD

XNU **kernel** में **FreeBSD** project से derived काफी मात्रा में code भी **incorporate** किया गया है। यह code Mach के साथ kernel के हिस्से के रूप में, उसी address space में **run** होता है। हालांकि, XNU के भीतर मौजूद FreeBSD code मूल FreeBSD code से काफी अलग हो सकता है, क्योंकि Mach के साथ compatibility सुनिश्चित करने के लिए modifications आवश्यक थे। FreeBSD कई kernel operations में योगदान देता है, जिनमें शामिल हैं:

- Process management
- Signal handling
- Basic security mechanisms, जिसमें user और group management शामिल हैं
- System call infrastructure
- TCP/IP stack और sockets
- Firewall और packet filtering

BSD और Mach के interaction को समझना जटिल हो सकता है, क्योंकि उनके conceptual frameworks अलग हैं। उदाहरण के लिए, BSD processes को अपनी fundamental executing unit के रूप में use करता है, जबकि Mach threads पर आधारित operate करता है। XNU में इस discrepancy को **प्रत्येक BSD process को एक Mach task के साथ associate करके** resolve किया जाता है, जिसमें ठीक एक Mach thread होता है। BSD के `fork()` system call का उपयोग किए जाने पर, kernel के भीतर BSD code Mach functions का उपयोग करके एक task और thread structure create करता है।

इसके अलावा, **Mach और BSD दोनों अलग-अलग security models maintain करते हैं**: **Mach का** security model **port rights** पर आधारित है, जबकि BSD का security model **process ownership** पर operate करता है। इन दोनों models के बीच disparities ने कभी-कभी local privilege-escalation vulnerabilities को जन्म दिया है। Typical system calls के अलावा, **Mach traps भी मौजूद हैं, जो user-space programs को kernel के साथ interact करने देते हैं**। ये अलग-अलग elements मिलकर macOS kernel की multifaceted, hybrid architecture बनाते हैं।

### I/O Kit - Drivers

I/O Kit XNU kernel में एक open-source, object-oriented **device-driver framework** है, जो **dynamically loaded device drivers** को handle करता है। यह modular code को on-the-fly kernel में add करने की अनुमति देता है और diverse hardware को support करता है।


{{#ref}}
macos-iokit.md
{{#endref}}

### macOS Architecture में Coprocessors

Apple platforms latency-sensitive work को main cores से दूर रखने और security-critical functions को isolate करने के लिए कई coprocessors पर निर्भर करते हैं।

- **Secure Enclave Processor (SEP)**: अपना microkernel और secure boot chain वाला dedicated ARM core, जो आमतौर पर **EL3/secure world** में run होता है। Interaction macOS में EL1 पर मौजूद mailbox drivers के माध्यम से होता है।
- Attack surface: SEP firmware updates और user-space daemons (`seputil`, `securityd`) जो requests को proxy करते हैं।
- Impact of compromise: Long-term keys का leak, biometric gating को bypass करना और FileVault या Apple Pay protections को तोड़ना।
- **System Management Controller (SMC)**: ARM exception levels के बाहर एक microcontroller पर proprietary firmware run करता है। macOS (EL1) I/O Kit user clients के माध्यम से इस तक पहुंचता है।
- Attack surface: USB-C power delivery messages, fan/battery management interfaces और firmware update paths।
- Impact of compromise: Thermal limits को override करना, fake sensor data inject करना, power cut करना या persistent NVRAM backdoors implant करना।
- **T1/T2 Security Chips**: अपने ARM cores पर मुख्यतः EL1/EL3 में bridgeOS (watchOS-derived) run करते हैं। macOS IOKit द्वारा mediated PCIe/USB-like channels के माध्यम से communicate करता है।
- Attack surface: DFU/restore pathways, `tccd` जैसी services द्वारा exposed IPC endpoints और T2 से bridged media pipelines।
- Impact of compromise: Secure boot disable करना, SSD contents decrypt करना, camera/mic gating hijack करना या stealth persistence के लिए HID input emulate करना।
- **Display Coprocessor (DCP)**: DART (Apple का IOMMU) द्वारा protected isolated address space के अंदर EL1 पर firmware execute करता है।
- Attack surface: `DCPAVService` interfaces, shared descriptor buffers और firmware image parsing।
- Impact of compromise: Arbitrary frames inject करना, framebuffers snoop करना या DoS के लिए display pipeline को brick करना।
- **Apple Neural Engine (ANE)**: Dedicated ML cluster पर microcode run करता है (कोई ARM EL levels नहीं)। macOS `ANECompilerService` और IOKit के माध्यम से work schedule करता है।
- Attack surface: Compiled model binaries (`.ane`), custom kernels feed करने वाली Core ML APIs और firmware loaders।
- Impact of compromise: ML models को tamper या exfiltrate करना, processed audio/vision data का leak या on-device inference को sabotage करना।
- **AGX GPU**: Firmware custom GPU cores पर scheduler के साथ run होता है; EL0 Metal commands submit करता है, जिन्हें EL1 validate करता है।
- Attack surface: Metal shader compiler, shared buffer mapping APIs और `com.apple.AGXFirmware` ioctl interfaces।
- Impact of compromise: System memory तक DMA access, GPU drivers के माध्यम से sandbox escapes या persistent firmware implants।
- **Apple Video Encoder (AVE)**: Media Engine पर EL1-like sandbox में firmware execute करता है। macOS VideoToolbox और `AppleAVE2` के माध्यम से interact करता है।
- Attack surface: Codec bitstreams, parameter sets, user-supplied buffers और firmware update blobs।
- Impact of compromise: Uncompressed frames का leak, DRM bypass करना या DMA engines तक access के साथ code execution प्राप्त करना।
- **Image Signal Processor (ISP)**: Media Engine cluster में secure firmware run करता है; macOS camera drivers EL1 पर operate करते हैं।
- Attack surface: Camera HALs, RAW frame descriptors, ISP configuration queues और firmware updates।
- Impact of compromise: Raw camera feeds को silently capture करना, privacy indicators disable करना या fabricated imagery inject करना।
- **AMX Matrix cores**: New instructions के माध्यम से EL0/EL1 पर exposed coprocessor units के रूप में operate करते हैं।
- Attack surface: AMX state (`thread_set_state`, context switches) का kernel virtualization और user-space code generation।
- Impact of compromise: अन्य processes के tile registers का leak, workloads की fingerprinting या kernel memory corruption के माध्यम से escalation।

Modern macOS इन coprocessors को chain of trust में trusted components के रूप में treat करता है। SEP, SMC और T2 का firmware Apple द्वारा signed होता है, और handshake protocols (जो अक्सर mailboxes या I/O Kit families पर implemented होते हैं) में challenge-response checks शामिल होते हैं, ताकि केवल authenticated firmware ही requests service कर सके।

### IPC - Inter Process Communication

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## macOS Kernel Extensions

macOS **Kernel Extensions** (.kext) को load करने के लिए **बहुत restrictive** है, क्योंकि यह code high privileges के साथ run करेगा। वास्तव में, default रूप से यह virtually impossible है (जब तक कोई bypass न मिल जाए)।

अगले page पर आप यह भी देख सकते हैं कि macOS अपने **kernelcache** के अंदर load किए गए `.kext` को कैसे recover करता है:

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### macOS System Extensions

Kernel Extensions का उपयोग करने के बजाय macOS ने System Extensions create किए, जो kernel के साथ interact करने के लिए user level APIs प्रदान करते हैं। इस तरह developers kernel extensions का उपयोग करने से बच सकते हैं।

{{#ref}}
macos-system-extensions.md
{{#endref}}


### Cryptexes और RSR (Rapid Security Response)

- **Cryptex** का अर्थ **CRYPTographically-sealed EXtension** है। यह एक sealed disk image (container) है, जिसका उपयोग Apple OS के उन parts (frameworks, shared libraries, apps) को host करने के लिए करता है, जिनमें major OS updates के बीच बदलने की अधिक संभावना होती है।
- macOS और iOS पर, cryptexes के अंदर रखे गए components को पूरे system volume को फिर से seal किए बिना RSR के माध्यम से **patch या replace** किया जा सकता है।
- Cryptexes **Preboot volume** पर boot firmware के साथ reside करते हैं और runtime पर OS file system में graft किए जाते हैं।
- Cryptex content को load करने में validation शामिल होती है: system file seals, manifests और root hashes check करता है, फिर cryptex content को mount या “graft” करता है, ताकि runtime पर apps जहां उपलब्ध हों वहां cryptex versions का उपयोग करें।
- Boot logs में cryptex loading kernel initialization के बाद, लेकिन full system services के up होने से पहले होता है।


#### Rapid Security Response (RSR)

- **RSR** regular OS updates के बीच **security patches deliver करने का Apple का mechanism** है। यह vulnerable parts (जैसे libraries और frameworks) को update करने के लिए cryptex content को target करता है, core system volume को modify किए बिना।
- RSR update apply करते समय device Apple के signing server से एक **Cryptex1 Image4 manifest** request करता है। यह manifest device और नए cryptex content के साथ cryptographically bound होता है।
- Base system के लिए मौजूदा AP boot ticket **RSR द्वारा modify नहीं किया जाता**। Patch sealed base OS के ऊपर additive रूप से काम करता है।
- macOS पर कुछ patched components (जैसे Safari) app के relaunch होते ही active हो जाते हैं; full system restart हमेशा आवश्यक नहीं होता।
- RSRs **removable** होते हैं: प्रत्येक के साथ एक patch और “antipatch” ship होता है, जो base OS version पर rollback कर सकता है। Removal के बाद cryptex content revert हो जाता है।
- RSR updates आमतौर पर full OS updates से काफी छोटे होते हैं और install करने के लिए lower battery state की आवश्यकता होती है।


## References

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
