# macOS Kernel & System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## XNU Kernel

The **core of macOS is XNU**, which stands for "X is Not Unix". It is a hybrid kernel that combines Mach, BSD components, and the C++ I/O Kit driver framework. Apple publishes the XNU source tree, including the `osfmk`, `bsd`, and `iokit` subsystems. <sup>[[1]](#references)</sup><sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

From a perspective of a security researcher or a Unix developer, **macOS** can feel quite **similar** to a **FreeBSD** system with an elegant GUI and a host of custom applications. Most applications developed for BSD will compile and run on macOS without needing modifications, as the command-line tools familiar to Unix users are all present in macOS. However, because the XNU kernel incorporates Mach, there are some significant differences between a traditional Unix-like system and macOS, and these differences might cause potential issues or provide unique advantages.

Open-source XNU releases are available from Apple's official distribution repository. <sup>[[1]](#references)</sup>

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

Moreover, **Mach and BSD maintain different security models**: Mach's security model is based on port rights, whereas BSD's model includes process credentials and ownership. Disparities at the boundary between these models have historically produced local privilege-escalation opportunities. User space interacts with these layers through Mach traps and BSD system calls. These elements form the hybrid architecture of the macOS kernel.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

### I/O Kit - Drivers

I/O Kit is XNU's open-source, object-oriented device-driver framework. Historically, kernel extensions used it to load modular driver code dynamically into the kernel; modern macOS increasingly moves supported drivers to DriverKit user-space extensions instead. I/O Kit also exposes user-client interfaces through which user processes communicate with drivers. The dedicated page covers its registry, matching model, user clients, and attack surface:<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup>


{{#ref}}
macos-iokit.md
{{#endref}}

### Coprocessors And Dedicated Security Hardware

Apple silicon and Macs with a T2 chip include a **Secure Enclave**, with its own Boot ROM and AES engine, that supports secure key generation and storage, biometric processing, and the key hierarchy used by data-protection features. Apple platforms also use other coprocessors to move latency-sensitive work away from the main CPU cores and to isolate security-critical functions. Their responsibilities and interfaces vary by model and OS release, so treat low-level firmware and mailbox details as implementation-specific unless they are confirmed for the exact target. <sup>[[2]](#references)</sup>

From a security-review perspective, the durable lesson is that the macOS attack surface extends beyond ordinary user processes and the XNU kernel. Drivers, firmware parsers, shared-memory interfaces, and I/O Kit or DriverKit user clients can mediate access to dedicated hardware. Validate the component, hardware generation, and trust boundary before drawing conclusions about exploit impact.

The following checklist preserves useful low-level leads while avoiding the assumption that every item applies unchanged to every Mac. Apple documents the Secure Enclave and hardware-security boundary; Asahi Linux and `m1n1` provide reverse-engineering references for Apple-silicon devices and coprocessor communication. <sup>[[2]](#references)</sup><sup>[[7]](#references)</sup><sup>[[8]](#references)</sup>

| Component | Architecture and attack-surface leads to validate on the target | Potential impact of a compromise |
| --- | --- | --- |
| **Secure Enclave Processor (SEP)** | Dedicated ARM processor with its own microkernel, Boot ROM, and secure-boot chain. It is commonly described as operating across a secure-world boundary; exact exception-level use is SoC-specific. Review SEP firmware updates, mailbox-facing drivers in macOS, and user-space brokers such as `seputil` and `securityd`. | Exposure of long-term key material, biometric-policy bypass, or weakening of FileVault and Apple Pay protections. |
| **System Management Controller (SMC)** | Proprietary firmware on a controller outside the application processor's normal ARM exception-level model. macOS reaches its services through platform and I/O Kit drivers. Review USB-C power-delivery input, fan/battery management, sensor interfaces, and firmware-update paths. | Thermal-limit override, power manipulation, false sensor data, denial of service, or firmware/NVRAM persistence. |
| **T1/T2 security chips** | Separate Apple SoCs that run bridgeOS, with their own ARM execution environments and secure-boot path. They communicate with macOS over device channels commonly described as PCIe/USB-like and mediated by I/O Kit drivers. Review DFU/restore paths, `tccd`-adjacent IPC, bridged media pipelines, and input services. | Secure-boot weakening, SSD-key exposure, camera/microphone-gating abuse, or emulated HID input. |
| **Display Coprocessor (DCP)** | Reverse engineering describes display firmware executing in an isolated environment, with shared descriptor buffers, DCP service interfaces, and DART IOMMU protection. Look for `DCPAVService`-related interfaces and firmware-image parsers; do not assume a specific exception level without confirming the SoC. | Arbitrary-frame injection, framebuffer disclosure, or display-pipeline denial of service. |
| **Apple Neural Engine (ANE)** | Dedicated ML cluster rather than a general-purpose ARM core. macOS reaches it through Core ML, compiler services such as `ANECompilerService`, compiled `.ane` models, I/O Kit interfaces, and firmware loaders. | Model or processed audio/vision-data disclosure, inference tampering, or escalation through a parser/driver flaw. |
| **AGX GPU** | Firmware executes on custom GPU cores with its own scheduler. EL0 applications submit Metal commands and shared buffers through kernel-validated interfaces, including AGX driver/firmware components such as `com.apple.AGXFirmware`. | DMA-backed memory exposure, sandbox escape through a GPU driver, or persistent firmware compromise. |
| **Apple Video Encoder / media engines** | Reverse-engineered descriptions place media firmware in an isolated, EL1-like execution environment. Codec bitstreams, parameter sets, user-controlled buffers, VideoToolbox, and driver families such as `AppleAVE2` are high-value parser surfaces. | Disclosure of uncompressed frames, DRM bypass, or code execution with access to DMA engines. |
| **Image Signal Processor (ISP)** | Secure camera-processing firmware is associated with the media-engine cluster while macOS camera drivers run on the application processor. Camera HALs, raw-frame descriptors, ISP configuration queues, I/O Kit interfaces, and firmware updates form the review surface. | Silent raw-camera capture, privacy-indicator bypass, fabricated imagery, or driver/firmware compromise. |
| **AMX matrix units** | Coprocessor-style matrix units are exposed through architecture-specific instructions usable by generated user and kernel code. Review kernel virtualization of AMX state, context switches, `thread_set_state`, and user-space code generation. | Cross-process tile-register leakage, workload fingerprinting, or escalation through kernel state-management corruption. |

These coprocessors participate in the platform's chain of trust. Apple documents separate secure-boot processes for the T2 chip and Secure Enclave, Apple-signed software-update authorization, and integrity protection for coprocessor firmware. Reverse-engineered components may additionally use authenticated mailbox or driver protocols; verify any claimed challenge-response handshake on the exact hardware and firmware rather than assuming one generic mechanism applies everywhere. <sup>[[2]](#references)</sup><sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

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

macOS provides system extensions and DriverKit so many security, networking, and driver components can run in user space rather than inside the kernel. Apple recommends these mechanisms whenever they cover the required functionality. <sup>[[3]](#references)</sup>

{{#ref}}
macos-system-extensions.md
{{#endref}}


### Cryptexes And Rapid Security Responses

A **cryptex** (cryptographically sealed extension) is a sealed disk image that lets Apple deliver and mount selected operating-system content separately from the sealed system volume. Rapid Security Responses used this mechanism to deliver important fixes between full software updates on supported OS versions. Exact cryptex layout, boot integration, and response availability are version-specific, so validate them on the target rather than relying on a single historical layout. <sup>[[4]](#references)</sup><sup>[[9]](#references)</sup>

Important implementation details documented for RSR-capable Apple operating systems include:

- Frameworks, shared libraries, and applications eligible for Rapid Security Response were moved into optimized, cryptographically sealed cryptex disk images on the Preboot volume.
- An RSR can patch the cryptex backing image without resealing the entire system volume.
- Cryptex content is bootstrapped after the kernel; its filesystem seals, measurements, and trust caches are represented in a separate Image4 ticket.
- At runtime, validated cryptex content is mounted or grafted into the operating-system namespace so applications resolve the cryptex-provided versions. Technical descriptions of the boot process also track manifest and root-hash validation before full system services are available.
- During RSR installation, the device requests a device-bound Cryptex1 Image4 manifest from Apple's signing service; the existing application-processor boot ticket is not replaced.
- On macOS, some patched application content, such as Safari components, can become active after relaunching the application rather than after a full reboot.
- Apple can remove a problematic response, and a user can remove and later reapply an RSR on supported versions.
- Technical descriptions of early RSR releases refer to the rollback component as an **antipatch**, which reverts cryptex content to the base OS representation.
- RSR downloads are generally smaller than full OS updates and historically used less restrictive installation prerequisites, such as lower battery thresholds, but those policy details can change.


## References

- [1] [Apple Open Source - XNU](https://github.com/apple-oss-distributions/xnu)
- [2] [Apple Platform Security - Hardware security overview](https://support.apple.com/guide/security/hardware-security-overview-secf020d1074/web)
- [3] [Apple Developer - System Extensions](https://developer.apple.com/documentation/systemextensions)
- [4] [Apple Support - Rapid Security Responses](https://support.apple.com/en-us/102657)
- [5] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/)
- [6] [The Art of Mac Malware, Vol. 1 - Analysis](https://taomm.org/)
- [7] [Asahi Linux - Apple-silicon platform documentation](https://asahilinux.org/docs/)
- [8] [Asahi Linux - `m1n1` Apple-silicon experimentation tools](https://github.com/AsahiLinux/m1n1)
- [9] [Apple Platform Security - Rapid Security Responses in Apple operating systems](https://support.apple.com/guide/security/sec87fc038c2/web)
- [10] [Apple Platform Security - Secure software updates](https://support.apple.com/guide/security/secure-software-updates-secf683e0b36/web)
- [11] [Apple Platform Security - Operating system integrity](https://support.apple.com/guide/security/sec8b776536b/web)

{{#include ../../../banners/hacktricks-training.md}}
