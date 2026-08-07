# macOS Kernel & System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## XNU Kernel

**macOS의 핵심은 XNU**이며, 이는 "X is Not Unix"를 의미합니다. 이 kernel은 기본적으로 **Mach microkernel**(이후 설명), 그리고 Berkeley Software Distribution(**BSD**)의 요소로 구성됩니다. XNU는 또한 **I/O Kit이라는 system을 통한 kernel drivers**를 위한 platform을 제공합니다. XNU kernel은 Darwin open source project의 일부이므로 **source code에 자유롭게 접근할 수 있습니다**.

Security researcher 또는 Unix developer의 관점에서 **macOS**는 세련된 GUI와 다양한 custom applications를 갖춘 **FreeBSD** system과 상당히 **유사하게** 느껴질 수 있습니다. BSD용으로 개발된 대부분의 application은 수정 없이 macOS에서 compile 및 실행할 수 있으며, Unix users에게 익숙한 command-line tools가 macOS에 모두 포함되어 있기 때문입니다. 그러나 XNU kernel은 Mach를 통합하고 있으므로 traditional Unix-like system과 macOS 사이에는 몇 가지 중요한 차이가 있으며, 이러한 차이는 잠재적인 문제를 일으키거나 고유한 이점을 제공할 수 있습니다.

Open source version of XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach는 **UNIX-compatible**하도록 설계된 **microkernel**입니다. 주요 설계 원칙 중 하나는 **kernel** space에서 실행되는 **code**의 양을 **최소화**하고, 대신 file system, networking, I/O와 같은 일반적인 kernel functions을 **user-level tasks로 실행**할 수 있도록 하는 것이었습니다.

XNU에서 Mach는 processor scheduling, multitasking, virtual memory management처럼 일반적으로 kernel이 처리하는 **많은 핵심 low-level operations를 담당**합니다.

### BSD

XNU **kernel**은 **FreeBSD** project에서 파생된 상당한 양의 code도 **통합**합니다. 이 code는 Mach와 함께 kernel의 일부로, 동일한 address space에서 **실행됩니다**. 그러나 XNU 내부의 FreeBSD code는 Mach와의 호환성을 보장하기 위해 수정이 필요했으므로 원본 FreeBSD code와 상당히 다를 수 있습니다. FreeBSD는 다음과 같은 많은 kernel operations에 기여합니다.

- Process management
- Signal handling
- User 및 group management를 포함한 기본 security mechanisms
- System call infrastructure
- TCP/IP stack 및 sockets
- Firewall 및 packet filtering

BSD와 Mach의 상호작용을 이해하는 것은 서로 다른 conceptual frameworks 때문에 복잡할 수 있습니다. 예를 들어 BSD는 process를 기본 execution unit으로 사용하는 반면, Mach는 thread를 기반으로 동작합니다. XNU에서는 **각 BSD process를 정확히 하나의 Mach thread를 포함하는 Mach task에 연결**하여 이러한 차이를 조정합니다. BSD의 fork() system call이 사용되면 kernel 내부의 BSD code는 Mach functions을 사용하여 task 및 thread structure를 생성합니다.

또한 **Mach와 BSD는 서로 다른 security models을 유지**합니다. **Mach의** security model은 **port rights**를 기반으로 하는 반면, BSD의 security model은 **process ownership**을 기반으로 동작합니다. 이 두 model 사이의 차이로 인해 때때로 local privilege-escalation vulnerabilities가 발생했습니다. 일반적인 system calls 외에도 **user-space programs가 kernel과 상호작용할 수 있도록 하는 Mach traps**도 존재합니다. 이러한 서로 다른 요소들이 함께 macOS kernel의 복합적인 hybrid architecture를 구성합니다.<sup>[[1]](#references)</sup>

### I/O Kit - Drivers

I/O Kit은 XNU kernel에 포함된 open-source, object-oriented **device-driver framework**로, **dynamically loaded device drivers를 처리**합니다. 이를 통해 kernel에 modular code를 즉시 추가할 수 있으며, 다양한 hardware를 지원합니다.


{{#ref}}
macos-iokit.md
{{#endref}}

### Coprocessors in macOS Architecture

Apple platforms는 latency-sensitive 작업을 main cores에서 분리하고 security-critical functions을 격리하기 위해 여러 coprocessors에 의존합니다.

- **Secure Enclave Processor (SEP)**: 자체 microkernel과 secure boot chain을 갖춘 전용 ARM core이며, 일반적으로 **EL3/secure world**에서 실행됩니다. macOS의 EL1에서는 mailbox drivers를 통해 상호작용합니다.
- Attack surface: SEP firmware updates 및 요청을 proxy하는 user-space daemons(`seputil`, `securityd`).
- Impact of compromise: 장기 keys를 **leak**하고, biometric gating을 우회하며, FileVault 또는 Apple Pay protections을 무력화할 수 있습니다.
- **System Management Controller (SMC)**: ARM exception levels 외부의 microcontroller에서 proprietary firmware를 실행합니다. macOS(EL1)는 I/O Kit user clients를 통해 접근합니다.
- Attack surface: USB-C power delivery messages, fan/battery management interfaces 및 firmware update paths.
- Impact of compromise: thermal limits를 override하고, fake sensor data를 inject하며, 전원을 차단하거나 persistent NVRAM backdoors를 implant할 수 있습니다.
- **T1/T2 Security Chips**: 자체 ARM cores에서 주로 EL1/EL3 수준으로 bridgeOS(watchOS-derived)를 실행합니다. macOS는 IOKit이 중개하는 PCIe/USB-like channels을 통해 통신합니다.
- Attack surface: DFU/restore pathways, `tccd`와 같은 services가 노출하는 IPC endpoints 및 T2로 bridge되는 media pipelines.
- Impact of compromise: secure boot을 disable하고, SSD contents를 decrypt하며, camera/mic gating을 hijack하거나, stealth persistence를 위해 HID input을 emulate할 수 있습니다.
- **Display Coprocessor (DCP)**: DART(Apple의 IOMMU)에 의해 보호되는 isolated address space 내부의 EL1에서 firmware를 실행합니다.
- Attack surface: `DCPAVService` interfaces, shared descriptor buffers 및 firmware image parsing.
- Impact of compromise: arbitrary frames를 inject하고, framebuffers를 snoop하거나, DoS를 위해 display pipeline을 brick할 수 있습니다.
- **Apple Neural Engine (ANE)**: 전용 ML cluster에서 microcode를 실행하며 ARM EL levels는 사용하지 않습니다. macOS는 `ANECompilerService` 및 IOKit을 통해 작업을 schedule합니다.
- Attack surface: compiled model binaries(`.ane`), custom kernels를 제공하는 Core ML APIs 및 firmware loaders.
- Impact of compromise: ML models를 tamper하거나 **exfiltrate**하고, 처리된 audio/vision data를 **leak**하거나, on-device inference를 sabotage할 수 있습니다.
- **AGX GPU**: scheduler가 있는 custom GPU cores에서 firmware가 실행됩니다. EL0는 Metal commands를 submit하고 EL1이 이를 validate합니다.
- Attack surface: Metal shader compiler, shared buffer mapping APIs 및 `com.apple.AGXFirmware` ioctl interfaces.
- Impact of compromise: system memory에 DMA access를 확보하고, GPU drivers를 통해 sandbox escapes를 수행하거나, persistent firmware implants를 설치할 수 있습니다.
- **Apple Video Encoder (AVE)**: EL1-like sandbox의 Media Engine에서 firmware를 실행합니다. macOS는 VideoToolbox 및 `AppleAVE2`를 통해 상호작용합니다.
- Attack surface: codec bitstreams, parameter sets, user-supplied buffers 및 firmware update blobs.
- Impact of compromise: uncompressed frames를 **leak**하고, DRM을 우회하거나, DMA engines에 access할 수 있는 code execution을 획득할 수 있습니다.
- **Image Signal Processor (ISP)**: Media Engine cluster에서 secure firmware를 실행하며, macOS camera drivers는 EL1에서 동작합니다.
- Attack surface: camera HALs, RAW frame descriptors, ISP configuration queues 및 firmware updates.
- Impact of compromise: raw camera feeds를 조용히 capture하고, privacy indicators를 disable하거나, fabricated imagery를 inject할 수 있습니다.
- **AMX Matrix cores**: new instructions를 통해 EL0/EL1에 노출되는 coprocessor units로 동작합니다.
- Attack surface: AMX state의 kernel virtualization(`thread_set_state`, context switches) 및 user-space code generation.
- Impact of compromise: 다른 processes의 tile registers를 **leak**하고, workloads를 fingerprint하거나, kernel memory corruption을 통해 escalate할 수 있습니다.

Modern macOS는 이러한 coprocessors를 chain of trust의 trusted components로 취급합니다. SEP, SMC 및 T2의 firmware는 Apple에 의해 signed되며, handshake protocols(대개 mailboxes 또는 I/O Kit families를 통해 구현됨)에는 challenge-response checks가 포함되어 있어 authenticated firmware만 requests를 처리할 수 있습니다.

### IPC - Inter Process Communication

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## macOS Kernel Extensions

macOS는 code가 실행될 높은 privileges 때문에 Kernel Extensions(.kext)를 **load하는 데 매우 restrictive**합니다. 실제로 기본 설정에서는 (bypass가 발견되지 않는 한) 사실상 불가능합니다.

다음 page에서는 macOS가 **kernelcache** 내부에 load하는 `.kext`를 recover하는 방법도 확인할 수 있습니다.

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### macOS System Extensions

Kernel Extensions를 사용하는 대신 macOS는 System Extensions를 만들었으며, 이는 kernel과 상호작용할 수 있는 user-level APIs를 제공합니다. 이러한 방식으로 developers는 kernel extensions를 사용하지 않아도 됩니다.

{{#ref}}
macos-system-extensions.md
{{#endref}}


### Cryptexes & RSR (Rapid Security Response)

- **Cryptex**는 **CRYPTographically-sealed EXtension**을 의미합니다. 이는 major OS updates 사이에 변경될 가능성이 높은 OS의 일부(frameworks, shared libraries, apps)를 호스팅하기 위해 Apple이 사용하는 sealed disk image(container)입니다.
- macOS 및 iOS에서 cryptexes 내부에 배치된 components는 전체 system volume을 다시 seal하지 않고도 RSR을 통해 **patch 또는 replace**할 수 있습니다.
- Cryptexes는 boot firmware와 함께 **Preboot volume**에 존재하며, runtime에 OS file system에 graft됩니다.
- cryptex content를 load할 때 validation이 수행됩니다. system은 file seals, manifests 및 root hashes를 확인한 후 cryptex content를 mount하거나 “graft”하여 runtime에 apps가 해당하는 경우 cryptex versions를 사용하도록 합니다.
- boot logs에서 cryptex loading은 kernel initialization 이후, full system services가 시작되기 전에 발생합니다.


#### Rapid Security Response (RSR)

- **RSR**은 **정기적인 OS updates 사이에 security patches를 제공하기 위한** Apple의 mechanism입니다. cryptex content를 대상으로 하여 core system volume을 건드리지 않고 취약한 parts(예: libraries, frameworks)를 update합니다.
- RSR update를 적용할 때 device는 Apple의 signing server에 **Cryptex1 Image4 manifest**를 요청합니다. 이 manifest는 device 및 새로운 cryptex content에 cryptographically bound됩니다.
- base system에 대한 기존 AP boot ticket은 **RSR에 의해 수정되지 않습니다**. patch는 sealed base OS 위에 additive 방식으로 적용됩니다.
- macOS에서는 특정 patched components(예: Safari)가 app을 relaunch하는 즉시 active 상태가 되므로, full system restart가 항상 필요한 것은 아닙니다.
- RSRs는 **removable**입니다. 각 RSR에는 patch와 base OS version으로 rollback할 수 있는 “antipatch”가 함께 제공됩니다. 제거하면 cryptex content가 revert됩니다.
- RSR updates는 일반적으로 full OS updates보다 훨씬 작으며, 설치를 위해 필요한 battery state도 더 낮습니다.


## References

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
