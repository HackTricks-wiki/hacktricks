# macOS Kernel & System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## XNU Kernel

Die **kern van macOS is XNU**, wat staan vir "X is Not Unix". Hierdie kernel bestaan fundamenteel uit die **Mach microkernel** (wat later bespreek sal word), **en** elemente van Berkeley Software Distribution (**BSD**). XNU verskaf ook 'n platform vir **kernel drivers via 'n stelsel genaamd die I/O Kit**. Die XNU kernel is deel van die Darwin open source-projek, wat beteken dat **die bronkode vrylik toeganklik is**.

Vanuit die perspektief van 'n security researcher of 'n Unix-ontwikkelaar kan **macOS** baie **soortgelyk** aan 'n **FreeBSD**-stelsel met 'n elegante GUI en 'n reeks pasgemaakte toepassings voel. Die meeste toepassings wat vir BSD ontwikkel is, sal op macOS compileer en loop sonder dat wysigings nodig is, aangesien die command-line tools waarmee Unix-gebruikers vertroud is, almal in macOS teenwoordig is. Omdat die XNU kernel egter Mach inkorporeer, is daar 'n paar beduidende verskille tussen 'n tradisionele Unix-agtige stelsel en macOS, en hierdie verskille kan potensiële probleme veroorsaak of unieke voordele bied.

Open source-weergawe van XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach is 'n **microkernel** wat ontwerp is om **UNIX-compatible** te wees. Een van sy belangrikste ontwerpbeginsels was om die hoeveelheid **code** wat in die **kernel**-ruimte loop, te **minimaliseer** en eerder toe te laat dat baie tipiese kernelfunksies, soos lêerstelsel-, networking- en I/O-funksies, **as user-level tasks** loop.

In XNU is Mach **verantwoordelik vir baie van die kritieke laevlakbewerkings** wat 'n kernel tipies hanteer, soos verwerkerskedulering, multitasking en virtuelegeheuebestuur.

### BSD

Die XNU **kernel** **inkorporeer** ook 'n beduidende hoeveelheid code wat van die **FreeBSD**-projek afgelei is. Hierdie code **loop as deel van die kernel saam met Mach**, in dieselfde address space. Die FreeBSD-code binne XNU kan egter aansienlik van die oorspronklike FreeBSD-code verskil, omdat wysigings nodig was om versoenbaarheid met Mach te verseker. FreeBSD dra by tot baie kernel-bewerkings, insluitend:

- Process management
- Signal handling
- Basiese security mechanisms, insluitend user- en group management
- System call infrastructure
- TCP/IP stack en sockets
- Firewall en packet filtering

Om die interaksie tussen BSD en Mach te verstaan, kan kompleks wees weens hul verskillende konseptuele raamwerke. BSD gebruik byvoorbeeld prosesse as sy fundamentele uitvoerende eenheid, terwyl Mach op threads werk. Hierdie verskil word in XNU versoen deur **elke BSD-proses met 'n Mach-task te assosieer** wat presies een Mach-thread bevat. Wanneer BSD se fork()-system call gebruik word, gebruik die BSD-code binne die kernel Mach-funksies om 'n task- en thread-struktuur te skep.

Verder handhaaf **Mach en BSD elk verskillende security models**: **Mach se** security model is gebaseer op **port rights**, terwyl BSD se security model op **process ownership** gebaseer is. Verskille tussen hierdie twee models het soms tot local privilege-escalation vulnerabilities gelei. Benewens tipiese system calls, is daar ook **Mach traps wat user-space-programme toelaat om met die kernel te kommunikeer**. Hierdie verskillende elemente vorm saam die veelvlakkige, hibriede architecture van die macOS kernel.

### I/O Kit - Drivers

Die I/O Kit is 'n open-source, object-oriented **device-driver framework** in die XNU kernel wat **dynamically loaded device drivers** hanteer. Dit laat toe dat modulêre code on-the-fly by die kernel gevoeg word, en ondersteun uiteenlopende hardware.


{{#ref}}
macos-iokit.md
{{#endref}}

### Coprocessors in macOS Architecture

Apple-platforms maak staat op verskeie coprocessors om latency-sensitive werk van die hoofkerne af weg te hou en security-critical funksies te isoleer.

- **Secure Enclave Processor (SEP)**: 'n Toegewyde ARM-core met sy eie microkernel en secure boot chain, wat tipies in **EL3/secure world** loop. Interaksie gebeur deur mailbox drivers in macOS by EL1.
- Attack surface: SEP-firmware-opdaterings en die user-space daemons (`seputil`, `securityd`) wat versoeke proxie.
- Impact of compromise: Lek langtermyn-sleutels, omseil biometric gating, en breek FileVault- of Apple Pay-beskerming.
- **System Management Controller (SMC)**: Loop proprietary firmware op 'n microcontroller buite die ARM exception levels. macOS (EL1) bereik dit deur I/O Kit user clients.
- Attack surface: USB-C power-delivery-boodskappe, fan/battery-management-interfaces en firmware-update paths.
- Impact of compromise: Oorskryf thermal limits, inject fake sensor data, sny krag af, of plant persistente NVRAM backdoors.
- **T1/T2 Security Chips**: Loop bridgeOS (watchOS-derived) hoofsaaklik by EL1/EL3 op hul eie ARM-cores. macOS kommunikeer oor PCIe/USB-like channels wat deur IOKit bemiddel word.
- Attack surface: DFU/restore pathways, IPC endpoints wat deur services soos `tccd` blootgestel word, en media pipelines wat na die T2 gebridge word.
- Impact of compromise: Disable secure boot, decrypt SSD-inhoud, hijack camera/mic gating, of emulate HID input vir stealth persistence.
- **Display Coprocessor (DCP)**: Voer firmware by EL1 binne 'n geïsoleerde address space uit wat deur DART (Apple se IOMMU) beskerm word.
- Attack surface: `DCPAVService`-interfaces, shared descriptor buffers en firmware-image parsing.
- Impact of compromise: Inject arbitrary frames, snoop framebuffers, of brick die display pipeline vir DoS.
- **Apple Neural Engine (ANE)**: Loop microcode op 'n toegewyde ML-cluster (geen ARM EL-levels nie). macOS scheduleer werk deur `ANECompilerService` en IOKit.
- Attack surface: Compiled model binaries (`.ane`), Core ML APIs wat custom kernels voer, en firmware loaders.
- Impact of compromise: Tamper met of exfiltrate ML-models, leak verwerkte audio/vision-data, of saboteer on-device inference.
- **AGX GPU**: Firmware loop op custom GPU-cores met 'n scheduler; EL0 submit Metal commands wat EL1 valideer.
- Attack surface: Metal shader compiler, shared buffer mapping APIs en `com.apple.AGXFirmware` ioctl interfaces.
- Impact of compromise: DMA access tot system memory, sandbox escapes deur GPU drivers, of persistente firmware implants.
- **Apple Video Encoder (AVE)**: Firmware execute op die Media Engine in 'n EL1-like sandbox. macOS interaksieer deur VideoToolbox en `AppleAVE2`.
- Attack surface: Codec bitstreams, parameter sets, user-supplied buffers en firmware-update blobs.
- Impact of compromise: Leak ongecomprimeerde frames, bypass DRM, of verkry code execution met toegang tot DMA engines.
- **Image Signal Processor (ISP)**: Loop secure firmware in die Media Engine-cluster; macOS camera drivers werk by EL1.
- Attack surface: Camera HALs, RAW frame descriptors, ISP configuration queues en firmware updates.
- Impact of compromise: Capture raw camera feeds silently, disable privacy indicators, of inject fabricated imagery.
- **AMX Matrix cores**: Funksioneer as coprocessor units wat by EL0/EL1 deur nuwe instruksies blootgestel word.
- Attack surface: Kernel-virtualisering van AMX-state (`thread_set_state`, context switches) en user-space code generation.
- Impact of compromise: Leak ander prosesse se tile registers, fingerprint workloads, of escalate deur kernel memory corruption.

Moderne macOS behandel hierdie coprocessors as trusted components in die chain of trust. Firmware vir SEP, SMC en T2 word deur Apple onderteken, en handshake-protokolle (dikwels geïmplementeer oor mailboxes of I/O Kit families) sluit challenge-response-kontroles in sodat slegs geauthentiseerde firmware versoeke kan diens.

### IPC - Inter Process Communication

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## macOS Kernel Extensions

macOS is **uiters beperkend wanneer Kernel Extensions** (.kext) gelaai word, weens die hoë privileges waarmee daardie code sal loop. Trouens, dit is by verstek feitlik onmoontlik (tensy 'n bypass gevind word).

Op die volgende bladsy kan jy ook sien hoe om die `.kext` te herstel wat macOS binne sy **kernelcache** laai:

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### macOS System Extensions

In plaas daarvan om Kernel Extensions te gebruik, het macOS System Extensions geskep, wat APIs op user-level bied om met die kernel te interaksieer. Op hierdie manier kan developers vermy om kernel extensions te gebruik.

{{#ref}}
macos-system-extensions.md
{{#endref}}


### Cryptexes & RSR (Rapid Security Response)

- **Cryptex** staan vir **CRYPTographically-sealed EXtension**. Dit is 'n sealed disk image (container) wat deur Apple gebruik word om dele van die OS (frameworks, shared libraries, apps) te huisves wat meer geneig is om tussen major OS-updates te verander.
- Op macOS en iOS kan komponente binne cryptexes deur RSR **gepatch of vervang** word sonder om die volledige system volume weer te seal.
- Cryptexes is op die **Preboot-volume**, langs boot firmware, en word tydens runtime in die OS file system ingesluit.
- Die laai van cryptex-inhoud behels validation: die stelsel kontroleer file seals, manifests en root hashes, en mount of “graft” dan die cryptex-inhoud sodat apps tydens runtime die cryptex-weergawes gebruik waar dit bestaan.
- In boot logs vind cryptex loading plaas ná kernel-initialisering, maar voordat volledige system services aktief is.


#### Rapid Security Response (RSR)

- **RSR** is Apple se meganisme om **security patches tussen gewone OS-updates** te lewer. Dit teiken cryptex-inhoud om kwesbare dele (bv. libraries, frameworks) op te dateer sonder om aan die core system volume te raak.
- Wanneer 'n RSR-update toegepas word, versoek die device 'n **Cryptex1 Image4 manifest** van Apple se signing server. Hierdie manifest is cryptographically gebind aan die device en aan die nuwe cryptex-inhoud.
- Die bestaande AP boot ticket vir die base system **word nie** deur RSR gewysig nie. Die patch werk additively bo-op die sealed base OS.
- Op macOS word sekere patched komponente (bv. Safari) aktief sodra die app herbegin; 'n volledige system restart word nie altyd vereis nie.
- RSRs is **verwyderbaar**: elkeen verskaf beide 'n patch en 'n “antipatch” wat na die base OS-weergawe kan terugrol. Wanneer dit verwyder word, word cryptex-inhoud teruggestel.
- RSR-updates is gewoonlik veel kleiner as volledige OS-updates en vereis 'n laer battery state om te installeer.


## References

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
