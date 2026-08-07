# macOS Kernel & System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## XNU Kernel

Die **kern van macOS is XNU**, wat staan vir "X is Not Unix". Hierdie kernel bestaan fundamenteel uit die **Mach-mikrokern** (wat later bespreek word), **en** elemente van Berkeley Software Distribution (**BSD**). XNU verskaf ook 'n platform vir **kernel drivers via 'n stelsel genaamd die I/O Kit**. Die XNU-kernel is deel van die Darwin open source-projek, wat beteken dat **die bronkode vrylik beskikbaar** is.

Vanuit die perspektief van 'n security researcher of 'n Unix-ontwikkelaar kan **macOS** baie **soortgelyk** aan 'n **FreeBSD**-stelsel met 'n elegante GUI en 'n groot aantal pasgemaakte toepassings voel. Die meeste toepassings wat vir BSD ontwikkel is, sal op macOS compileer en loop sonder dat wysigings nodig is, aangesien die command-line tools waarmee Unix-gebruikers vertroud is, almal in macOS teenwoordig is. Omdat die XNU-kernel egter Mach insluit, is daar beduidende verskille tussen 'n tradisionele Unix-agtige stelsel en macOS, en hierdie verskille kan potensiële probleme veroorsaak of unieke voordele bied.

Open source-weergawe van XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach is 'n **mikrokern** wat ontwerp is om **UNIX-versoenbaar** te wees. Een van sy belangrikste ontwerp-beginsels was om die hoeveelheid **kode** wat in die **kernel**-ruimte loop, te **minimaliseer** en eerder toe te laat dat baie tipiese kernel-funksies, soos lêerstelsel-, netwerk- en I/O-funksies, **as user-level tasks** loop.

In XNU is Mach **verantwoordelik vir baie van die kritieke laevlakbedrywighede** wat 'n kernel gewoonlik hanteer, soos verwerker-skedulering, multitasking en virtuelegeheuebestuur.

### BSD

Die XNU-**kernel** **sluit** ook 'n beduidende hoeveelheid kode in wat van die **FreeBSD**-projek afgelei is. Hierdie kode **loop as deel van die kernel saam met Mach**, in dieselfde adresruimte. Die FreeBSD-kode binne XNU kan egter aansienlik van die oorspronklike FreeBSD-kode verskil, omdat wysigings nodig was om versoenbaarheid met Mach te verseker. FreeBSD dra tot baie kernel-bedrywighede by, insluitend:

- Prosesbestuur
- Seinhantering
- Basiese sekuriteitsmeganismes, insluitend gebruiker- en groepbestuur
- Stelseloproep-infrastruktuur
- TCP/IP-stapel en sockets
- Firewall en packet filtering

Dit kan kompleks wees om die interaksie tussen BSD en Mach te verstaan weens hul verskillende konseptuele raamwerke. BSD gebruik byvoorbeeld prosesse as sy fundamentele uitvoeringseenheid, terwyl Mach op threads werk. Hierdie verskil word in XNU versoen deur **elke BSD-proses met 'n Mach-task te assosieer** wat presies een Mach-thread bevat. Wanneer BSD se fork()-stelseloproep gebruik word, gebruik die BSD-kode binne die kernel Mach-funksies om 'n task- en thread-struktuur te skep.

Verder handhaaf **Mach en BSD elk verskillende security models**: **Mach se** security model is gebaseer op **port rights**, terwyl BSD se security model op **proses-eienaarskap** gebaseer is. Verskille tussen hierdie twee modelle het soms tot local privilege-escalation vulnerabilities gelei. Benewens tipiese stelseloproepe is daar ook **Mach traps wat user-space-programme toelaat om met die kernel te kommunikeer**. Saam vorm hierdie verskillende elemente die veelvlakkige, hibriede argitektuur van die macOS-kernel.<sup>[[1]](#references)</sup>

### I/O Kit - Drivers

Die I/O Kit is 'n open-source, objekgeoriënteerde **device-driver framework** in die XNU-kernel wat **dynamies-gelaaide device drivers** hanteer. Dit laat modulêre kode toe om on-the-fly by die kernel gevoeg te word en ondersteun uiteenlopende hardeware.


{{#ref}}
macos-iokit.md
{{#endref}}

### Coprocessors in macOS Architecture

Apple-platforms maak op verskeie coprocessors staat om latency-sensitiewe werk van die hoofkerne af weg te hou en security-critical funksies te isoleer.

- **Secure Enclave Processor (SEP)**: 'n Toegewyde ARM-kern met sy eie mikrokern en secure boot chain, wat tipies by **EL3/secure world** loop. Interaksie vind plaas deur mailbox drivers in macOS by EL1.
- Attack surface: SEP-firmware-opdaterings en die user-space daemons (`seputil`, `securityd`) wat versoeke proxy.
- Impact of compromise: Leak langtermynsleutels, omseil biometric gating en breek FileVault- of Apple Pay-beskerming.
- **System Management Controller (SMC)**: Loop proprietary firmware op 'n mikrobeheerder buite die ARM exception levels. macOS (EL1) bereik dit via I/O Kit user clients.
- Attack surface: USB-C power delivery-boodskappe, koppelvlakke vir waaier-/batterybestuur en firmware update paths.
- Impact of compromise: Oorskryf thermal limits, inject vals sensordata, skakel krag af of plant persistente NVRAM backdoors.
- **T1/T2 Security Chips**: Loop bridgeOS (afgelei van watchOS) hoofsaaklik by EL1/EL3 op hul eie ARM-kerne. macOS kommunikeer oor PCIe/USB-agtige kanale wat deur IOKit bemiddel word.
- Attack surface: DFU/restore pathways, IPC endpoints wat deur dienste soos `tccd` blootgestel word, en media pipelines wat na die T2 oorbrug word.
- Impact of compromise: Deaktiveer secure boot, decrypt SSD-inhoud, kaap camera/mic gating of emuleer HID-input vir stealth persistence.
- **Display Coprocessor (DCP)**: Voer firmware by EL1 binne 'n geïsoleerde adresruimte uit wat deur DART (Apple se IOMMU) beskerm word.
- Attack surface: `DCPAVService`-koppelvlakke, gedeelde descriptor buffers en firmware image parsing.
- Impact of compromise: Inject arbitrêre frames, snoop framebuffers of brick die display pipeline vir DoS.
- **Apple Neural Engine (ANE)**: Loop microcode op 'n toegewyde ML-cluster (geen ARM EL-levels nie). macOS skeduleer werk via `ANECompilerService` en IOKit.
- Attack surface: Gecompileerde model binaries (`.ane`), Core ML APIs wat custom kernels voer, en firmware loaders.
- Impact of compromise: Tamper met of exfiltrate ML-modelle, leak verwerkte audio-/vision-data of saboteer on-device inference.
- **AGX GPU**: Firmware loop op custom GPU-kerne met 'n scheduler; EL0 dien Metal commands in wat EL1 valideer.
- Attack surface: Metal shader compiler, gedeelde buffer mapping APIs en `com.apple.AGXFirmware` ioctl interfaces.
- Impact of compromise: DMA-toegang tot stelselgeheue, sandbox escapes via GPU drivers of persistente firmware implants.
- **Apple Video Encoder (AVE)**: Firmware loop op die Media Engine in 'n EL1-agtige sandbox. macOS kommunikeer via VideoToolbox en `AppleAVE2`.
- Attack surface: Codec bitstreams, parameter sets, user-supplied buffers en firmware update blobs.
- Impact of compromise: Leak ongecomprimeerde frames, omseil DRM of verkry code execution met toegang tot DMA engines.
- **Image Signal Processor (ISP)**: Loop secure firmware in die Media Engine-cluster; macOS camera drivers werk by EL1.
- Attack surface: Camera HALs, RAW frame descriptors, ISP configuration queues en firmware updates.
- Impact of compromise: Capture stilweg raw camera feeds, deaktiveer privacy indicators of inject gefabriseerde beelde.
- **AMX Matrix cores**: Werk as coprocessor-eenhede wat via nuwe instruksies by EL0/EL1 blootgestel word.
- Attack surface: Kernel-virtualisering van AMX-state (`thread_set_state`, context switches) en user-space code generation.
- Impact of compromise: Leak ander prosesse se tile registers, fingerprint workloads of escalate via kernel memory corruption.

Moderne macOS behandel hierdie coprocessors as trusted components in die chain of trust. Firmware vir SEP, SMC en T2 word deur Apple onderteken, en handshake protocols (dikwels geïmplementeer oor mailboxes of I/O Kit families) sluit challenge-response checks in sodat slegs geauthentiseerde firmware versoeke kan diens.

### IPC - Inter Process Communication

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## macOS Kernel Extensions

macOS is **uiters beperkend met die laai van Kernel Extensions** (.kext), omdat die kode met hoë privileges sal loop. Trouens, dit is by verstek feitlik onmoontlik (tensy 'n bypass gevind word).

Op die volgende bladsy kan jy ook sien hoe om die `.kext` te herstel wat macOS binne sy **kernelcache** laai:

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### macOS System Extensions

In plaas daarvan om Kernel Extensions te gebruik, het macOS System Extensions geskep, wat user-level APIs bied om met die kernel te interaksie. Op hierdie manier kan ontwikkelaars die gebruik van kernel extensions vermy.

{{#ref}}
macos-system-extensions.md
{{#endref}}


### Cryptexes & RSR (Rapid Security Response)

- **Cryptex** staan vir **CRYPTographically-sealed EXtension**. Dit is 'n sealed disk image (container) wat Apple gebruik om dele van die OS (frameworks, shared libraries, apps) te huisves wat meer waarskynlik tussen groot OS-opdaterings sal verander.
- Op macOS en iOS kan komponente binne cryptexes deur RSR **gepatch of vervang** word sonder om die hele stelselvolume weer te seal.
- Cryptexes is op die **Preboot-volume** geleë, langs boot firmware, en word tydens runtime in die OS-lêerstelsel gegraft.
- Die laai van cryptex-inhoud behels validation: die stelsel kontroleer file seals, manifests en root hashes, en mount of “graft” dan die cryptex-inhoud sodat apps tydens runtime die cryptex-weergawes gebruik waar dit bestaan.
- In boot logs vind cryptex loading plaas ná kernel-initialisering, maar voordat volledige stelseldienste beskikbaar is.


#### Rapid Security Response (RSR)

- **RSR** is Apple se meganisme om **security patches tussen gewone OS-opdaterings** te lewer. Dit teiken cryptex-inhoud om kwesbare dele (bv. libraries, frameworks) op te dateer sonder om aan die kernstelselvolume te raak.
- Wanneer 'n RSR-opdatering toegepas word, versoek die device 'n **Cryptex1 Image4-manifest** van Apple se signing server. Hierdie manifest is kriptografies aan die device en die nuwe cryptex-inhoud gebind.
- Die bestaande AP boot ticket vir die basisstelsel **word nie** deur RSR gewysig nie. Die patch werk additively bo-op die sealed base OS.
- Op macOS word sekere gepatchte komponente (bv. Safari) aktief sodra die app herbegin word; 'n volledige stelselherbegin word nie altyd vereis nie.
- RSRs is **verwyderbaar**: elkeen lewer beide 'n patch en 'n “antipatch” wat na die base OS-weergawe kan terugrol. Wanneer dit verwyder word, word cryptex-inhoud teruggerol.
- RSR-opdaterings is gewoonlik baie kleiner as volledige OS-opdaterings en vereis 'n laer battery state om te installeer.


## References

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
