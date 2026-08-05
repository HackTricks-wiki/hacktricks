# macOS Kernel & System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## XNU Kernel

**macOSの中核はXNU**であり、これは「X is Not Unix」を意味します。このkernelは基本的に、**Mach microkernel**（後述）と、Berkeley Software Distribution（**BSD**）に由来する要素で構成されています。XNUは、**I/O Kitと呼ばれるsystemを介したkernel driversのためのプラットフォーム**も提供します。XNU kernelはDarwin open source projectの一部であるため、**そのsource codeには誰でも自由にアクセスできます**。

security researcherやUnix developerの観点から見ると、**macOS**は、洗練されたGUIと多数のカスタムapplicationを備えた**FreeBSD** systemにかなり**似ている**ように感じられます。BSD向けに開発されたapplicationの多くは、変更なしでmacOS上でcompileおよび実行できます。これは、Unix userに馴染みのあるcommand-line toolsがmacOSにすべて存在するためです。ただし、XNU kernelにはMachが組み込まれているため、従来のUnix-like systemとmacOSの間にはいくつかの重要な違いがあります。これらの違いは、潜在的な問題を引き起こす場合もあれば、独自の利点をもたらす場合もあります。

Open source version of XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Machは**UNIX-compatible**な**microkernel**として設計されています。その主要な設計原則の1つは、**kernel** spaceで実行される**code**の量を**最小化**し、file system、networking、I/Oなど、一般的なkernel functionの多くを**user-level taskとして実行**できるようにすることでした。

XNUでは、Machは通常kernelが処理するprocessor scheduling、multitasking、virtual memory managementなど、**多くの重要な低レベル操作を担当**します。

### BSD

XNU **kernel**には、**FreeBSD** projectに由来する大量のcodeも**組み込まれています**。このcodeはMachとともにkernelの一部として、同じaddress spaceで実行されます。ただし、XNU内のFreeBSD codeは、Machとの互換性を確保するために変更が必要だったため、元のFreeBSD codeとは大きく異なる場合があります。FreeBSDは、以下を含む多くのkernel operationに貢献しています。

- Process management
- Signal handling
- Basic security mechanisms, including user and group management
- System call infrastructure
- TCP/IP stack and sockets
- Firewall and packet filtering

BSDとMachの相互作用を理解するのは、それぞれのconceptual frameworkが異なるため、複雑になる場合があります。例えば、BSDはprocessを基本的な実行単位として使用しますが、Machはthreadを基盤として動作します。この相違は、XNUにおいて、各BSD processを、Mach threadを正確に1つ含む**Mach taskに関連付ける**ことで調整されています。BSDのfork() system callが使用されると、kernel内のBSD codeはMach functionを使用してtaskとthread structureを作成します。

さらに、**MachとBSDはそれぞれ異なるsecurity modelを維持**しています。**Machの**security modelは**port rights**に基づいているのに対し、BSDのsecurity modelは**process ownership**に基づいて動作します。この2つのmodelの相違は、過去にlocal privilege-escalation vulnerabilityを引き起こしたことがあります。一般的なsystem callとは別に、user-space programがkernelとやり取りできる**Mach trap**も存在します。これらの要素が合わさることで、macOS kernelの多面的でhybridなarchitectureが形成されています。

### I/O Kit - Drivers

I/O Kitは、XNU kernel内のopen-sourceでobject-orientedな**device-driver framework**であり、**dynamically loaded device driver**を処理します。これにより、modular codeをon-the-flyでkernelに追加でき、多様なhardwareをサポートできます。


{{#ref}}
macos-iokit.md
{{#endref}}

### Coprocessors in macOS Architecture

Apple platformは、latency-sensitiveな処理をmain coreから切り離し、security-criticalなfunctionを分離するために、複数のcoprocessorに依存しています。

- **Secure Enclave Processor (SEP)**: 独自のmicrokernelとsecure boot chainを持つ専用ARM coreで、通常は**EL3/secure world**で動作します。macOSのEL1からはmailbox driverを介して通信します。
- Attack surface: SEP firmware updateと、requestをproxyするuser-space daemon（`seputil`、`securityd`）。
- Impact of compromise: 長期keyのLeak、biometric gatingのbypass、FileVaultまたはApple Pay protectionの破壊。
- **System Management Controller (SMC)**: ARM exception levelの外部にあるmicrocontroller上でproprietary firmwareを実行します。macOS（EL1）はI/O Kit user clientを介してアクセスします。
- Attack surface: USB-C power delivery message、fan/battery management interface、firmware update path。
- Impact of compromise: thermal limitのoverride、偽のsensor dataのinject、電源遮断、またはpersistent NVRAM backdoorのimplant。
- **T1/T2 Security Chips**: 独自のARM core上で、主にEL1/EL3としてbridgeOS（watchOS-derived）を実行します。macOSはIOKitによって仲介されるPCIe/USB-like channelを介して通信します。
- Attack surface: DFU/restore pathway、`tccd`などのserviceが公開するIPC endpoint、T2にbridgeされたmedia pipeline。
- Impact of compromise: secure bootのdisable、SSD contentのdecrypt、camera/mic gatingのhijack、またはstealth persistenceのためのHID inputのemulate。
- **Display Coprocessor (DCP)**: DART（AppleのIOMMU）によって保護されたisolated address space内で、EL1 firmwareを実行します。
- Attack surface: `DCPAVService` interface、shared descriptor buffer、firmware image parsing。
- Impact of compromise: arbitrary frameのinject、framebufferのsnoop、またはDoSを目的としたdisplay pipelineのbrick。
- **Apple Neural Engine (ANE)**: 専用ML cluster上でmicrocodeを実行します（ARM EL levelはありません）。macOSは`ANECompilerService`とIOKitを介して処理をscheduleします。
- Attack surface: compiled model binary（`.ane`）、custom kernelにdataを供給するCore ML API、firmware loader。
- Impact of compromise: ML modelのtamperまたはexfiltrate、処理済みaudio/vision dataのLeak、またはon-device inferenceのsabotage。
- **AGX GPU**: schedulerを備えたcustom GPU core上でfirmwareを実行します。EL0はMetal commandをsubmitし、EL1がvalidateします。
- Attack surface: Metal shader compiler、shared buffer mapping API、`com.apple.AGXFirmware` ioctl interface。
- Impact of compromise: system memoryへのDMA access、GPU driver経由のsandbox escape、またはpersistent firmware implant。
- **Apple Video Encoder (AVE)**: Media Engine上のEL1-like sandboxでfirmwareを実行します。macOSはVideoToolboxと`AppleAVE2`を介して通信します。
- Attack surface: codec bitstream、parameter set、user-supplied buffer、firmware update blob。
- Impact of compromise: uncompressed frameのLeak、DRMのbypass、またはDMA engineにアクセス可能なcode executionの取得。
- **Image Signal Processor (ISP)**: Media Engine cluster内でsecure firmwareを実行し、macOS camera driverはEL1で動作します。
- Attack surface: camera HAL、RAW frame descriptor、ISP configuration queue、firmware update。
- Impact of compromise: raw camera feedのsecret capture、privacy indicatorのdisable、または偽のimageのinject。
- **AMX Matrix cores**: 新しいinstructionを介してEL0/EL1に公開されるcoprocessor unitとして動作します。
- Attack surface: AMX stateのkernel virtualization（`thread_set_state`、context switch）、user-space code generation。
- Impact of compromise: 他のprocessのtile registerのLeak、workloadのfingerprint、またはkernel memory corruption経由のprivilege escalation。

Modern macOSは、これらのcoprocessorをchain of trust内のtrusted componentとして扱います。SEP、SMC、T2のfirmwareはAppleによって署名されており、handshake protocol（多くの場合mailboxまたはI/O Kit family上で実装される）にはchallenge-response checkが含まれ、認証済みfirmwareだけがrequestを処理できるようになっています。

### IPC - Inter Process Communication

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## macOS Kernel Extensions

macOSは、codeが実行する高いprivilegeのため、Kernel Extensions（.kext）のloadに対して**非常にrestrictive**です。実際、defaultでは（bypassが見つからない限り）事実上不可能です。

以下のpageでは、macOSが**kernelcache**内にloadする`.kext`をrecoverする方法も確認できます。

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### macOS System Extensions

Kernel Extensionsを使用する代わりに、macOSはSystem Extensionsを作成しました。これはkernelと対話するためのuser level APIを提供します。この方法により、developerはkernel extensionsを使用せずに済みます。

{{#ref}}
macos-system-extensions.md
{{#endref}}


### Cryptexes & RSR (Rapid Security Response)

- **Cryptex**は**CRYPTographically-sealed EXtension**の略です。これは、major OS update間で変更される可能性が高いOSの一部（framework、shared library、app）をAppleがhostするために使用するsealed disk image（container）です。
- macOSとiOSでは、cryptex内に配置されたcomponentをRSRによって、system volume全体をre-sealすることなく**patchまたはreplace**できます。
- Cryptexは、boot firmwareとともに**Preboot volume**に存在し、runtimeにOS file systemへgraftされます。
- Cryptex contentのload時にはvalidationが行われます。systemはfile seal、manifest、root hashをcheckし、その後cryptex contentをmountまたは「graft」します。これによりruntimeでは、存在する場合にappがcryptex versionを使用します。
- Boot logでは、cryptexのloadはkernel initialization後、full system serviceの起動前に行われます。


#### Rapid Security Response (RSR)

- **RSR**は、**通常のOS updateの間にsecurity patchを配信するためのAppleのmechanism**です。cryptex contentを対象とし、core system volumeに触れることなく、vulnerableな部分（library、frameworkなど）をupdateします。
- RSR updateを適用する際、deviceはAppleのsigning serverに対して**Cryptex1 Image4 manifest**をrequestします。このmanifestはdeviceおよび新しいcryptex contentにcryptographically boundされています。
- Base system用の既存のAP boot ticketは、RSRによって**変更されません**。patchはsealed base OS上にadditiveに適用されます。
- macOSでは、patchされた一部のcomponent（Safariなど）はappをrelaunchするとすぐにactiveになります。full system restartは必ずしも必要ありません。
- RSRは**removable**です。それぞれpatchと「antipatch」の両方を提供し、base OS versionへrollbackできます。removeすると、cryptex contentがrevertされます。
- RSR updateは通常、full OS updateよりはるかに小さく、installに必要なbattery stateも低くなります。


## References

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
