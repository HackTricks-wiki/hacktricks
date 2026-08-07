# macOS Kernel & System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## XNU Kernel

**macOSのコアはXNU**であり、これは「X is Not Unix」を意味します。このkernelは基本的に、**Mach microkernel**（後述）**と** Berkeley Software Distribution（**BSD**）の要素で構成されています。XNUは、**I/O Kitと呼ばれるシステムを介したkernel drivers**のためのプラットフォームも提供します。XNU kernelはDarwin open source projectの一部であるため、**そのsource codeは自由にアクセスできます**。

security researcherまたはUnix developerの観点から見ると、**macOS**は、洗練されたGUIと多数のcustom applicationsを備えた**FreeBSD** systemにかなり**似ている**ように感じられます。BSD向けに開発されたアプリケーションの多くは、変更なしでmacOS上でcompileおよび実行できます。これは、Unix usersが使い慣れたcommand-line toolsがmacOSにすべて存在するためです。しかし、XNU kernelにはMachが組み込まれているため、従来のUnix-like systemとmacOSの間には重要な相違点があり、これらの違いが潜在的な問題を引き起こしたり、独自の利点をもたらしたりする可能性があります。

Open source version of XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Machは**UNIX-compatible**に設計された**microkernel**です。その主要な設計原則の1つは、**kernel** spaceで実行される**code**の量を**最小化**し、file system、networking、I/Oなどの一般的なkernel functionsの多くを**user-level tasksとして実行**できるようにすることでした。

XNUでは、Machは通常kernelが処理するprocessor scheduling、multitasking、virtual memory managementなど、**多くの重要な低レベル処理を担当**します。

### BSD

XNU **kernel**には、**FreeBSD** project由来の大量のcodeも**組み込まれています**。このcodeはMachとともにkernelの一部として、同じaddress spaceで**実行されます**。ただし、XNU内のFreeBSD codeは、Machとの互換性を確保するために変更が必要だったため、元のFreeBSD codeとは大きく異なる場合があります。FreeBSDは、以下を含む多くのkernel operationsに貢献しています。

- Process management
- Signal handling
- Basic security mechanisms, including user and group management
- System call infrastructure
- TCP/IP stack and sockets
- Firewall and packet filtering

BSDとMachの相互作用を理解するのは、それぞれのconceptual frameworksが異なるため複雑です。たとえば、BSDはprocessを基本的な実行単位として使用する一方、Machはthreadを基盤として動作します。XNUでは、**各BSD processを、Mach threadを正確に1つ含むMach taskに関連付ける**ことで、この不一致を解消しています。BSDのfork() system callが使用されると、kernel内のBSD codeはMach functionsを使用してtaskおよびthread structureを作成します。

さらに、**MachとBSDはそれぞれ異なるsecurity modelsを維持しています**。**Machの**security modelは**port rights**に基づく一方、BSDのsecurity modelは**process ownership**に基づいて動作します。これら2つのmodelの相違により、過去にはlocal privilege-escalation vulnerabilitiesが発生することがありました。通常のsystem callsとは別に、**user-space programsがkernelとやり取りできるMach traps**も存在します。これらの異なる要素が合わさり、macOS kernelの多面的でhybridなarchitectureを形成しています。<sup>[[1]](#references)</sup>

### I/O Kit - Drivers

I/O KitはXNU kernelにおけるopen-sourceのobject-oriented **device-driver framework**であり、**dynamically loaded device drivers**を処理します。これにより、modular codeをon-the-flyでkernelに追加し、多様なhardwareをサポートできます。


{{#ref}}
macos-iokit.md
{{#endref}}

### Coprocessors in macOS Architecture

Apple platformsは、latency-sensitiveな処理をmain coresから切り離し、security-criticalなfunctionsを分離するために、複数のcoprocessorsに依存しています。

- **Secure Enclave Processor (SEP)**: 独自のmicrokernelとsecure boot chainを持つ専用ARM coreで、通常は**EL3/secure world**で実行されます。macOSのEL1とのinteractionはmailbox driversを介して行われます。
- Attack surface: SEP firmware updates、およびrequestをproxyするuser-space daemons（`seputil`、`securityd`）。
- Impact of compromise: 長期キーをLeakし、biometric gatingをbypassし、FileVaultまたはApple Payのprotectionsを破壊する。
- **System Management Controller (SMC)**: ARM exception levelsの外部にあるmicrocontroller上でproprietary firmwareを実行します。macOS（EL1）はI/O Kit user clientsを介してアクセスします。
- Attack surface: USB-C power delivery messages、fan/battery management interfaces、firmware update paths。
- Impact of compromise: thermal limitsのoverride、偽のsensor dataのinject、電源遮断、またはpersistent NVRAM backdoorsのimplant。
- **T1/T2 Security Chips**: 独自のARM cores上で、主にEL1/EL3でbridgeOS（watchOS-derived）を実行します。macOSはIOKitによって仲介されるPCIe/USB-like channelsを介して通信します。
- Attack surface: DFU/restore pathways、`tccd`などのservicesが公開するIPC endpoints、T2にbridgeされたmedia pipelines。
- Impact of compromise: secure bootのdisable、SSD contentsのdecrypt、camera/mic gatingのhijack、またはstealth persistenceのためのHID inputのemulate。
- **Display Coprocessor (DCP)**: DART（AppleのIOMMU）で保護されたisolated address space内でEL1 firmwareを実行します。
- Attack surface: `DCPAVService` interfaces、shared descriptor buffers、firmware image parsing。
- Impact of compromise: 任意のframesのinject、framebuffersのsnoop、またはDoSのためのdisplay pipelineのbrick。
- **Apple Neural Engine (ANE)**: 専用ML cluster上でmicrocodeを実行します（ARM EL levelsはありません）。macOSは`ANECompilerService`とIOKitを介してworkをscheduleします。
- Attack surface: compiled model binaries（`.ane`）、custom kernelsにdataをfeedするCore ML APIs、firmware loaders。
- Impact of compromise: ML modelsのtamperまたはexfiltrate、処理済みaudio/vision dataのLeak、またはon-device inferenceのsabotage。
- **AGX GPU**: schedulerを備えたcustom GPU cores上でfirmwareを実行します。EL0がMetal commandsをsubmitし、EL1がvalidateします。
- Attack surface: Metal shader compiler、shared buffer mapping APIs、`com.apple.AGXFirmware` ioctl interfaces。
- Impact of compromise: system memoryへのDMA access、GPU driversを介したsandbox escapes、またはpersistent firmware implants。
- **Apple Video Encoder (AVE)**: Media Engine上のEL1-like sandboxでfirmwareを実行します。macOSはVideoToolboxと`AppleAVE2`を介してinteractionします。
- Attack surface: codec bitstreams、parameter sets、user-supplied buffers、firmware update blobs。
- Impact of compromise: uncompressed framesのLeak、DRMのbypass、またはDMA enginesへのaccessを持つcode executionの獲得。
- **Image Signal Processor (ISP)**: Media Engine cluster内でsecure firmwareを実行し、macOS camera driversはEL1で動作します。
- Attack surface: camera HALs、RAW frame descriptors、ISP configuration queues、firmware updates。
- Impact of compromise: raw camera feedsのsecret capture、privacy indicatorsのdisable、またはfabricated imageryのinject。
- **AMX Matrix cores**: 新しいinstructionsを介してEL0/EL1に公開されるcoprocessor unitsとして動作します。
- Attack surface: AMX stateのkernel virtualization（`thread_set_state`、context switches）、およびuser-space code generation。
- Impact of compromise: 他のprocessesのtile registersのLeak、workloadsのfingerprint、またはkernel memory corruptionを介したescalation。

Modern macOSは、これらのcoprocessorsをchain of trustのtrusted componentsとして扱います。SEP、SMC、T2のfirmwareはAppleによってsignedされており、handshake protocols（多くの場合mailboxesまたはI/O Kit families上で実装される）にはchallenge-response checksが含まれているため、authenticated firmwareのみがrequestsをserviceできます。

### IPC - Inter Process Communication

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## macOS Kernel Extensions

macOSは、codeが実行するhigh privilegesのため、Kernel Extensions（.kext）のloadに対して**非常にrestrictive**です。実際、defaultでは（bypassが見つからない限り）事実上不可能です。

次のpageでは、macOSが**kernelcache**内にloadする`.kext`をrecoverする方法も確認できます。

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### macOS System Extensions

Kernel Extensionsを使用する代わりに、macOSはSystem Extensionsを作成しました。これはkernelとinteractionするためのuser level APIsを提供します。この方法により、developersはkernel extensionsの使用を避けられます。

{{#ref}}
macos-system-extensions.md
{{#endref}}


### Cryptexes & RSR (Rapid Security Response)

- **Cryptex**は**CRYPTographically-sealed EXtension**を意味します。これは、major OS updatesの間に変更される可能性が高いOSの一部（frameworks、shared libraries、apps）をhostするためにAppleが使用するsealed disk image（container）です。
- macOSとiOSでは、cryptexes内に配置されたcomponentsをRSRによって**patchまたはreplace**できます。system volume全体をre-sealする必要はありません。
- Cryptexesは、boot firmwareとともに**Preboot volume**に存在し、runtimeにOS file systemへgraftされます。
- Cryptex contentのloadingにはvalidationが伴います。systemはfile seals、manifests、root hashesをcheckし、cryptex contentをmountまたは“graft”します。これによりruntimeでは、存在する場合にappsがcryptex versionsを使用します。
- Boot logsでは、cryptex loadingはkernel initializationの後、full system servicesが起動する前に行われます。


#### Rapid Security Response (RSR)

- **RSR**は、**通常のOS updatesの間にsecurity patchesを提供する**Appleのmechanismです。cryptex contentを対象とし、core system volumeに触れることなく、脆弱なparts（libraries、frameworksなど）をupdateします。
- RSR updateの適用時、deviceはAppleのsigning serverから**Cryptex1 Image4 manifest**をrequestします。このmanifestはdeviceおよび新しいcryptex contentにcryptographically boundされています。
- base system用の既存のAP boot ticketは、RSRによって**変更されません**。patchはsealed base OS上にadditively適用されます。
- macOSでは、patched components（Safariなど）はappをrelaunchするとすぐにactiveになります。full system restartが常に必要とは限りません。
- RSRsは**removable**です。それぞれpatchと“antipatch”の両方を含み、base OS versionへrollbackできます。remove時には、cryptex contentがrevertされます。
- RSR updatesは通常、full OS updatesよりはるかに小さく、installに必要なbattery stateも低くなります。


## References

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
