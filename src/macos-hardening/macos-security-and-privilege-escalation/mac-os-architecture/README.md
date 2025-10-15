# macOS Kernel & System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## XNU Kernel

The **core of macOS is XNU**, which stands for "X is Not Unix". This kernel is fundamentally composed of the **Mach microkerne**l (to be discussed later), **and** elements from Berkeley Software Distribution (**BSD**). XNU also provides a platform for **kernel drivers via a system called the I/O Kit**. The XNU kernel is part of the Darwin open source project, which means **its source code is freely accessible**.

From a perspective of a security researcher or a Unix developer, **macOS** can feel quite **similar** to a **FreeBSD** system with an elegant GUI and a host of custom applications. Most applications developed for BSD will compile and run on macOS without needing modifications, as the command-line tools familiar to Unix users are all present in macOS. However, because the XNU kernel incorporates Mach, there are some significant differences between a traditional Unix-like system and macOS, and these differences might cause potential issues or provide unique advantages.

Open source version of XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach is a **microkernel** designed to be **UNIX-compatible**. One of its key design principles was to **minimize** the amount of **code** running in the **kernel** space and instead allow many typical kernel functions, such as file system, networking, and I/O, to **run as user-level tasks**.

In XNU, Mach is **responsible for many of the critical low-level operations** a kernel typically handles, such as processor scheduling, multitasking, and virtual memory management.

### BSD

The XNU **kernel** also **incorporates** a significant amount of code derived from the **FreeBSD** project. This code **runs as part of the kernel along with Mach**, in the same address space. However, the FreeBSD code within XNU may differ substantially from the original FreeBSD code because modifications were required to ensure its compatibility with Mach. FreeBSD contributes to many kernel operations including:

- Process management
- Signal handling
- Basic security mechanisms, including user and group management
- System call infrastructure
- TCP/IP stack and sockets
- Firewall and packet filtering

Understanding the interaction between BSD and Mach can be complex, due to their different conceptual frameworks. For instance, BSD uses processes as its fundamental executing unit, while Mach operates based on threads. This discrepancy is reconciled in XNU by **associating each BSD process with a Mach task** that contains exactly one Mach thread. When BSD's fork() system call is used, the BSD code within the kernel uses Mach functions to create a task and a thread structure.

Moreover, **Mach and BSD each maintain different security models**: **Mach's** security model is based on **port rights**, whereas BSD's security model operates based on **process ownership**. Disparities between these two models have occasionally resulted in local privilege-escalation vulnerabilities. Apart from typical system calls, there are also **Mach traps that allow user-space programs to interact with the kernel**. These different elements together form the multifaceted, hybrid architecture of the macOS kernel.

### I/O Kit - Drivers

The I/O Kit is an open-source, object-oriented **device-driver framework** in the XNU kernel, handles **dynamically loaded device drivers**. It allows modular code to be added to the kernel on-the-fly, supporting diverse hardware.


{{#ref}}
macos-iokit.md
{{#endref}}

### Coprocessors in macOS Architecture

Apple platforms rely on several coprocessors to keep latency-sensitive work off the main cores and to isolate security-critical functions.

- **Secure Enclave Processor (SEP)**: A dedicated ARM core with its own microkernel and secure boot chain, typically running at **EL3/secure world**. Interaction happens through mailbox drivers in macOS at EL1.
  - Attack surface: SEP firmware updates and the user-space daemons (`seputil`, `securityd`) that proxy requests.
  - Impact of compromise: Leak long-term keys, bypass biometric gating, and break FileVault or Apple Pay protections.
- **System Management Controller (SMC)**: Runs proprietary firmware on a microcontroller outside the ARM exception levels. macOS (EL1) reaches it via I/O Kit user clients.
  - Attack surface: USB-C power delivery messages, fan/battery management interfaces, and firmware update paths.
  - Impact of compromise: Override thermal limits, inject fake sensor data, cut power, or implant persistent NVRAM backdoors.
- **T1/T2 Security Chips**: Run bridgeOS (watchOS-derived) largely at EL1/EL3 on their own ARM cores. macOS communicates over PCIe/USB-like channels mediated by IOKit.
  - Attack surface: DFU/restore pathways, IPC endpoints exposed by services like `tccd`, and media pipelines bridged to the T2.
  - Impact of compromise: Disable secure boot, decrypt SSD contents, hijack camera/mic gating, or emulate HID input for stealth persistence.
- **Display Coprocessor (DCP)**: Executes firmware at EL1 inside an isolated address space protected by DART (Apple’s IOMMU).
  - Attack surface: `DCPAVService` interfaces, shared descriptor buffers, and firmware image parsing.
  - Impact of compromise: Inject arbitrary frames, snoop framebuffers, or brick the display pipeline for DoS.
- **Apple Neural Engine (ANE)**: Runs microcode on a dedicated ML cluster (no ARM EL levels). macOS schedules work via `ANECompilerService` and IOKit.
  - Attack surface: Compiled model binaries (`.ane`), Core ML APIs feeding custom kernels, and firmware loaders.
  - Impact of compromise: Tamper or exfiltrate ML models, leak processed audio/vision data, or sabotage on-device inference.
- **AGX GPU**: Firmware runs on custom GPU cores with a scheduler; EL0 submits Metal commands that EL1 validates.
  - Attack surface: Metal shader compiler, shared buffer mapping APIs, and `com.apple.AGXFirmware` ioctl interfaces.
  - Impact of compromise: DMA access to system memory, sandbox escapes via GPU drivers, or persistent firmware implants.
- **Apple Video Encoder (AVE)**: Firmware executes on the Media Engine in an EL1-like sandbox. macOS interacts via VideoToolbox and `AppleAVE2`.
  - Attack surface: Codec bitstreams, parameter sets, user-supplied buffers, and firmware update blobs.
  - Impact of compromise: Leak uncompressed frames, bypass DRM, or gain code execution with access to DMA engines.
- **Image Signal Processor (ISP)**: Runs secure firmware in the Media Engine cluster; macOS camera drivers operate at EL1.
  - Attack surface: Camera HALs, RAW frame descriptors, ISP configuration queues, and firmware updates.
  - Impact of compromise: Capture raw camera feeds silently, disable privacy indicators, or inject fabricated imagery.
- **AMX Matrix cores**: Operate as coprocessor units exposed at EL0/EL1 via new instructions.
  - Attack surface: Kernel virtualization of AMX state (`thread_set_state`, context switches) and user-space code generation.
  - Impact of compromise: Leak other processes’ tile registers, fingerprint workloads, or escalate via kernel memory corruption.

Modern macOS treats these coprocessors as trusted components in the chain of trust. Firmware for SEP, SMC, and T2 is signed by Apple, and handshake protocols (often implemented over mailboxes or I/O Kit families) include challenge-response checks so that only authenticated firmware can service requests.

### IPC - Inter Process Communication

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## macOS Kernel Extensions

macOS is **super restrictive to load Kernel Extensions** (.kext) because of the high privileges that code will run with. Actually, by default is virtually impossible (unless a bypass is found).

In the following page you can also see how to recover the `.kext` that macOS loads inside its **kernelcache**:

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### macOS System Extensions

Instead of using Kernel Extensions macOS created the System Extensions, which offers in user level APIs to interact with the kernel. This way, developers can avoid to use kernel extensions.

{{#ref}}
macos-system-extensions.md
{{#endref}}


### Cryptexes & RSR (Rapid Security Response)

- **Cryptex** stands for **CRYPTographically-sealed EXtension**. It is a sealed disk image (container) used by Apple to host parts of the OS (frameworks, shared libraries, apps) that are more likely to change between major OS updates. 
- On macOS and iOS, components placed inside cryptexes can be **patched or replaced** via RSR without re-sealing the entire system volume. 
- Cryptexes reside on the **Preboot volume**, alongside boot firmware, and are grafted into the OS file system at runtime. 
- Loading cryptex content involves validation: the system checks file seals, manifests, and root hashes, then mounts or “grafts” the cryptex content so that at runtime apps use the cryptex versions where present. 
- In boot logs, cryptex loading happens after kernel initialization but before full system services are up. 


#### Rapid Security Response (RSR)

- **RSR** is Apple’s mechanism for delivering **security patches between regular OS updates**. It targets cryptex content to update vulnerable parts (e.g. libraries, frameworks) without touching the core system volume. 
- When applying an RSR update, the device requests from Apple’s signing server a **Cryptex1 Image4 manifest**. This manifest is cryptographically bound to the device and to the new cryptex content. 
- The existing AP boot ticket for the base system **is not modified** by RSR. The patch works additively over the sealed base OS. 
- On macOS, certain patched components (e.g. Safari) become active as soon as the app relaunches; a full system restart is not always required. 
- RSRs are **removable**: each ships both a patch and an “antipatch” that can roll back to the base OS version. On removal, cryptex content is reverted. 
- RSR updates are generally much smaller than full OS updates, and require lower battery state to install. 


## References

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
