# macOS Kernel na System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## XNU Kernel

**Msingi wa macOS ni XNU**, ambayo inamaanisha "X is Not Unix". Kernel hii kimsingi imeundwa na **Mach microkernel** (itakayojadiliwa baadaye), **pamoja na** vipengele kutoka Berkeley Software Distribution (**BSD**). XNU pia hutoa jukwaa la **kernel drivers kupitia mfumo unaoitwa I/O Kit**. XNU kernel ni sehemu ya mradi wa open source wa Darwin, jambo linalomaanisha kuwa **source code yake inapatikana bila malipo**.

Kwa mtazamo wa security researcher au Unix developer, **macOS** inaweza kuhisi kuwa **sawa kabisa** na mfumo wa **FreeBSD** wenye GUI maridadi na mkusanyiko wa custom applications. Applications nyingi zilizotengenezwa kwa BSD zita-compile na ku-run kwenye macOS bila kuhitaji modifications, kwa kuwa command-line tools zinazofahamika kwa watumiaji wa Unix zinapatikana zote kwenye macOS. Hata hivyo, kwa sababu XNU kernel inajumuisha Mach, kuna tofauti kubwa kati ya mfumo wa kawaida wa Unix-like na macOS, na tofauti hizi zinaweza kusababisha matatizo yanayoweza kutokea au kutoa faida za kipekee.

Open source version of XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach ni **microkernel** iliyoundwa kuwa **UNIX-compatible**. Mojawapo ya kanuni zake kuu za muundo ilikuwa **kupunguza** kiasi cha **code** kinacho-run katika **kernel** space na badala yake kuruhusu functions nyingi za kawaida za kernel, kama vile file system, networking, na I/O, **ku-run kama user-level tasks**.

Katika XNU, Mach **inawajibika kwa operations nyingi muhimu za kiwango cha chini** ambazo kernel kwa kawaida hushughulikia, kama vile processor scheduling, multitasking, na virtual memory management.

### BSD

**Kernel** ya XNU pia **inajumuisha** kiasi kikubwa cha code iliyotokana na mradi wa **FreeBSD**. Code hii **hu-run kama sehemu ya kernel pamoja na Mach**, katika address space ileile. Hata hivyo, code ya FreeBSD iliyo ndani ya XNU inaweza kutofautiana sana na code ya awali ya FreeBSD kwa sababu modifications zilihitajika ili kuhakikisha compatibility yake na Mach. FreeBSD huchangia katika kernel operations nyingi, zikiwemo:

- Process management
- Signal handling
- Basic security mechanisms, ikiwemo user na group management
- System call infrastructure
- TCP/IP stack na sockets
- Firewall na packet filtering

Kuelewa interaction kati ya BSD na Mach kunaweza kuwa changamani, kutokana na conceptual frameworks zao tofauti. Kwa mfano, BSD hutumia processes kama executing unit yake ya msingi, wakati Mach hufanya kazi kwa kutegemea threads. Tofauti hii inapatanishwa katika XNU kwa **kuhusisha kila BSD process na Mach task** iliyo na Mach thread moja pekee. BSD's fork() system call inapotumiwa, BSD code iliyo ndani ya kernel hutumia Mach functions kuunda task na thread structure.

Aidha, **Mach na BSD kila moja hudumisha security model tofauti**: security model ya **Mach** inategemea **port rights**, wakati security model ya BSD inategemea **process ownership**. Tofauti kati ya models hizi wakati mwingine zimesababisha local privilege-escalation vulnerabilities. Mbali na system calls za kawaida, pia kuna **Mach traps zinazoruhusu user-space programs ku-interact na kernel**. Vipengele hivi tofauti kwa pamoja huunda hybrid architecture yenye sura nyingi ya macOS kernel.<sup>[[1]](#references)</sup>

### I/O Kit - Drivers

I/O Kit ni **device-driver framework** ya open-source na object-oriented ndani ya XNU kernel, inayoshughulikia **dynamically loaded device drivers**. Inaruhusu modular code kuongezwa kwenye kernel on-the-fly, na hivyo kusaidia hardware mbalimbali.


{{#ref}}
macos-iokit.md
{{#endref}}

### Coprocessors in macOS Architecture

Apple platforms hutegemea coprocessors kadhaa ili kuhamisha kazi zinazohitaji latency ndogo kutoka kwenye main cores na kutenga functions muhimu za security.

- **Secure Enclave Processor (SEP)**: ARM core maalum yenye microkernel yake na secure boot chain yake, kwa kawaida iki-run katika **EL3/secure world**. Interaction hufanyika kupitia mailbox drivers katika macOS kwenye EL1.
- Attack surface: SEP firmware updates na user-space daemons (`seputil`, `securityd`) zinazoproxy requests.
- Impact of compromise: Leak long-term keys, bypass biometric gating, na kuvunja FileVault au Apple Pay protections.
- **System Management Controller (SMC)**: Hu-run proprietary firmware kwenye microcontroller iliyo nje ya ARM exception levels. macOS (EL1) huifikia kupitia I/O Kit user clients.
- Attack surface: USB-C power delivery messages, fan/battery management interfaces, na firmware update paths.
- Impact of compromise: Override thermal limits, inject fake sensor data, kukata power, au ku-install persistent NVRAM backdoors.
- **T1/T2 Security Chips**: Hu-run bridgeOS (iliyotokana na watchOS) kwa kiasi kikubwa katika EL1/EL3 kwenye ARM cores zao. macOS huwasiliana kupitia channels zinazofanana na PCIe/USB, zinazosimamiwa na IOKit.
- Attack surface: DFU/restore pathways, IPC endpoints zinazowasilishwa na services kama `tccd`, na media pipelines zilizounganishwa na T2.
- Impact of compromise: Disable secure boot, decrypt SSD contents, hijack camera/mic gating, au ku-emulate HID input kwa stealth persistence.
- **Display Coprocessor (DCP)**: Hu-execute firmware katika EL1 ndani ya isolated address space inayolindwa na DART (Apple's IOMMU).
- Attack surface: `DCPAVService` interfaces, shared descriptor buffers, na firmware image parsing.
- Impact of compromise: Inject arbitrary frames, snoop framebuffers, au ku-brick display pipeline kwa DoS.
- **Apple Neural Engine (ANE)**: Hu-run microcode kwenye dedicated ML cluster (bila ARM EL levels). macOS hupanga kazi kupitia `ANECompilerService` na IOKit.
- Attack surface: Compiled model binaries (`.ane`), Core ML APIs zinazolisha custom kernels, na firmware loaders.
- Impact of compromise: Tamper au exfiltrate ML models, leak processed audio/vision data, au ku-sabotage on-device inference.
- **AGX GPU**: Firmware hu-run kwenye custom GPU cores zenye scheduler; EL0 hu-submit Metal commands ambazo EL1 huzivalidate.
- Attack surface: Metal shader compiler, shared buffer mapping APIs, na `com.apple.AGXFirmware` ioctl interfaces.
- Impact of compromise: DMA access kwenye system memory, sandbox escapes kupitia GPU drivers, au persistent firmware implants.
- **Apple Video Encoder (AVE)**: Firmware hu-execute kwenye Media Engine katika EL1-like sandbox. macOS hu-interact kupitia VideoToolbox na `AppleAVE2`.
- Attack surface: Codec bitstreams, parameter sets, user-supplied buffers, na firmware update blobs.
- Impact of compromise: Leak uncompressed frames, bypass DRM, au kupata code execution yenye access kwenye DMA engines.
- **Image Signal Processor (ISP)**: Hu-run secure firmware katika Media Engine cluster; macOS camera drivers hu-operate kwenye EL1.
- Attack surface: Camera HALs, RAW frame descriptors, ISP configuration queues, na firmware updates.
- Impact of compromise: Capture raw camera feeds kimya kimya, disable privacy indicators, au inject fabricated imagery.
- **AMX Matrix cores**: Hu-operate kama coprocessor units zinazo-exposewa kwenye EL0/EL1 kupitia new instructions.
- Attack surface: Kernel virtualization ya AMX state (`thread_set_state`, context switches) na user-space code generation.
- Impact of compromise: Leak tile registers za processes nyingine, fingerprint workloads, au escalate kupitia kernel memory corruption.

macOS ya kisasa huzichukulia coprocessors hizi kama trusted components katika chain of trust. Firmware ya SEP, SMC, na T2 husainiwa na Apple, na handshake protocols (mara nyingi hutekelezwa kupitia mailboxes au I/O Kit families) hujumuisha challenge-response checks ili firmware iliyo-authenticate pekee iweze kuhudumia requests.

### IPC - Inter Process Communication

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## macOS Kernel Extensions

macOS ina **vizuizi vikali sana vya ku-load Kernel Extensions** (.kext) kwa sababu ya privileges za juu ambazo code hiyo ita-run nazo. Kwa kweli, kwa default, hili haliwezekani karibu kabisa (isipokuwa bypass ipatikane).

Katika ukurasa unaofuata unaweza pia kuona jinsi ya kurecover `.kext` ambayo macOS hu-load ndani ya **kernelcache** yake:

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### macOS System Extensions

Badala ya kutumia Kernel Extensions, macOS iliunda System Extensions, ambazo hutoa APIs za user level za ku-interact na kernel. Kwa njia hii, developers wanaweza kuepuka kutumia kernel extensions.

{{#ref}}
macos-system-extensions.md
{{#endref}}


### Cryptexes & RSR (Rapid Security Response)

- **Cryptex** inasimama kwa **CRYPTographically-sealed EXtension**. Ni disk image (container) iliyofungwa ambayo Apple hutumia kuhifadhi sehemu za OS (frameworks, shared libraries, apps) ambazo zina uwezekano mkubwa wa kubadilika kati ya major OS updates.
- Kwenye macOS na iOS, components zilizowekwa ndani ya cryptexes zinaweza **kupatchiwa au kubadilishwa** kupitia RSR bila ku-seal upya system volume nzima.
- Cryptexes hukaa kwenye **Preboot volume**, pamoja na boot firmware, na hu-graftiwa kwenye OS file system wakati wa runtime.
- Ku-load cryptex content huhusisha validation: mfumo hukagua file seals, manifests, na root hashes, kisha hu-mount au “graft” cryptex content ili wakati wa runtime apps zitumie cryptex versions pale zinapopatikana.
- Katika boot logs, cryptex loading hutokea baada ya kernel initialization lakini kabla full system services hazijaanza.

#### Rapid Security Response (RSR)

- **RSR** ni mechanism ya Apple ya ku-deliver **security patches kati ya regular OS updates**. Hulenga cryptex content ili ku-update sehemu zilizo vulnerable (kwa mfano libraries, frameworks) bila kugusa core system volume.
- Wakati wa kutumia RSR update, device huomba kutoka kwa Apple signing server **Cryptex1 Image4 manifest**. Manifest hii hufungwa cryptographically na device pamoja na cryptex content mpya.
- AP boot ticket iliyopo ya base system **haibadilishwi** na RSR. Patch hufanya kazi additively juu ya sealed base OS.
- Kwenye macOS, patched components fulani (kwa mfano Safari) huanza kufanya kazi mara tu app inapo relaunch; full system restart haihitajiki kila wakati.
- RSRs **zinaweza kuondolewa**: kila moja husafirisha patch pamoja na “antipatch” inayoweza kurudisha mfumo kwenye base OS version. Wakati wa kuiondoa, cryptex content hurejeshwa.
- RSR updates kwa kawaida ni ndogo zaidi sana kuliko full OS updates, na zinahitaji battery state ya chini zaidi ili ku-install.


## References

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
