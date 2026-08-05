# macOS Kernel & System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## XNU Kernel

**Msingi wa macOS ni XNU**, jina linalomaanisha "X is Not Unix". Kernel hii kimsingi imeundwa na **Mach microkernel** (itakayojadiliwa baadaye), **na** vipengele kutoka Berkeley Software Distribution (**BSD**). Pia XNU hutoa jukwaa la **kernel drivers kupitia mfumo unaoitwa I/O Kit**. Kernel ya XNU ni sehemu ya open source project ya Darwin, kumaanisha kwamba **source code yake inapatikana kwa uhuru**.

Kwa mtazamo wa security researcher au Unix developer, **macOS** inaweza kuonekana **kufanana sana** na mfumo wa **FreeBSD** wenye GUI maridadi na mkusanyiko wa custom applications. Applications nyingi zilizotengenezwa kwa BSD zita-compile na kufanya kazi kwenye macOS bila kuhitaji marekebisho, kwa kuwa command-line tools zinazofahamika kwa watumiaji wa Unix zote zinapatikana kwenye macOS. Hata hivyo, kwa sababu kernel ya XNU inajumuisha Mach, kuna tofauti kubwa kati ya mfumo wa kawaida unaofanana na Unix na macOS, na tofauti hizi zinaweza kusababisha matatizo yanayoweza kutokea au kutoa faida za kipekee.

Open source version of XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach ni **microkernel** iliyoundwa kuwa **UNIX-compatible**. Mojawapo ya kanuni zake kuu za usanifu ilikuwa **kupunguza** kiasi cha **code** kinachoendesha katika nafasi ya **kernel**, na badala yake kuruhusu functions nyingi za kawaida za kernel, kama vile file system, networking, na I/O, **kuendesha kama user-level tasks**.

Katika XNU, Mach **inawajibika kwa shughuli nyingi muhimu za kiwango cha chini** ambazo kernel hushughulikia kwa kawaida, kama vile processor scheduling, multitasking, na virtual memory management.

### BSD

**Kernel** ya XNU pia **inajumuisha** kiasi kikubwa cha code iliyotokana na project ya **FreeBSD**. Code hii **huendesha kama sehemu ya kernel pamoja na Mach**, katika address space hiyo hiyo. Hata hivyo, code ya FreeBSD ndani ya XNU inaweza kutofautiana sana na code ya awali ya FreeBSD kwa sababu marekebisho yalihitajika ili kuhakikisha compatibility yake na Mach. FreeBSD huchangia katika kernel operations nyingi, zikiwemo:

- Process management
- Signal handling
- Basic security mechanisms, ikiwemo user na group management
- System call infrastructure
- TCP/IP stack na sockets
- Firewall na packet filtering

Kuelewa mwingiliano kati ya BSD na Mach kunaweza kuwa changamano, kwa sababu ya mifumo yao tofauti ya kimawazo. Kwa mfano, BSD hutumia processes kama executing unit yake ya msingi, huku Mach ikifanya kazi kwa kutegemea threads. Tofauti hii inatatuliwa katika XNU kwa **kuhusisha kila BSD process na Mach task** iliyo na Mach thread moja pekee. BSD's fork() system call inapotumika, code ya BSD ndani ya kernel hutumia Mach functions kuunda task na thread structure.

Zaidi ya hayo, **Mach na BSD kila moja hudumisha security model tofauti**: security model ya **Mach** inategemea **port rights**, ilhali security model ya BSD hufanya kazi kwa kutegemea **process ownership**. Tofauti kati ya models hizi mbili wakati mwingine zimesababisha local privilege-escalation vulnerabilities. Mbali na system calls za kawaida, pia kuna **Mach traps zinazoruhusu user-space programs kuwasiliana na kernel**. Vipengele hivi tofauti kwa pamoja huunda hybrid architecture yenye sura nyingi ya macOS kernel.

### I/O Kit - Drivers

I/O Kit ni **device-driver framework** ya open-source na object-oriented ndani ya XNU kernel, inayoshughulikia **dynamically loaded device drivers**. Huruhusu modular code kuongezwa kwenye kernel wakati wa utekelezaji, na kusaidia hardware mbalimbali.


{{#ref}}
macos-iokit.md
{{#endref}}

### Coprocessors in macOS Architecture

Apple platforms hutegemea coprocessors kadhaa ili kuondoa kazi zinazohitaji latency ndogo kutoka kwenye main cores na kutenga functions muhimu za security.

- **Secure Enclave Processor (SEP)**: ARM core maalum yenye microkernel yake na secure boot chain yake, kwa kawaida ikiendesha katika **EL3/secure world**. Mawasiliano hufanyika kupitia mailbox drivers katika macOS kwenye EL1.
- Attack surface: SEP firmware updates na user-space daemons (`seputil`, `securityd`) zinazofanya proxy ya requests.
- Impact of compromise: Leak long-term keys, bypass biometric gating, na kuvunja ulinzi wa FileVault au Apple Pay.
- **System Management Controller (SMC)**: Huendesha proprietary firmware kwenye microcontroller iliyo nje ya ARM exception levels. macOS (EL1) huifikia kupitia I/O Kit user clients.
- Attack surface: USB-C power delivery messages, fan/battery management interfaces, na firmware update paths.
- Impact of compromise: Override thermal limits, inject fake sensor data, kukata power, au kuweka persistent NVRAM backdoors.
- **T1/T2 Security Chips**: Huendesha bridgeOS (iliyotokana na watchOS) kwa kiasi kikubwa kwenye EL1/EL3 kwenye ARM cores zao. macOS huwasiliana kupitia channels zinazofanana na PCIe/USB zinazosimamiwa na IOKit.
- Attack surface: DFU/restore pathways, IPC endpoints zinazowasilishwa na services kama `tccd`, na media pipelines zilizounganishwa na T2.
- Impact of compromise: Disable secure boot, decrypt SSD contents, hijack camera/mic gating, au kuiga HID input kwa stealth persistence.
- **Display Coprocessor (DCP)**: Huendesha firmware kwenye EL1 ndani ya address space iliyotengwa na kulindwa na DART (Apple's IOMMU).
- Attack surface: `DCPAVService` interfaces, shared descriptor buffers, na firmware image parsing.
- Impact of compromise: Inject arbitrary frames, snoop framebuffers, au kuharibu display pipeline kwa DoS.
- **Apple Neural Engine (ANE)**: Huendesha microcode kwenye dedicated ML cluster (hakuna ARM EL levels). macOS hupanga kazi kupitia `ANECompilerService` na IOKit.
- Attack surface: Compiled model binaries (`.ane`), Core ML APIs zinazoingiza custom kernels, na firmware loaders.
- Impact of compromise: Tamper au exfiltrate ML models, leak processed audio/vision data, au kuharibu on-device inference.
- **AGX GPU**: Firmware huendesha kwenye custom GPU cores zenye scheduler; EL0 huwasilisha Metal commands ambazo EL1 huzihakiki.
- Attack surface: Metal shader compiler, shared buffer mapping APIs, na `com.apple.AGXFirmware` ioctl interfaces.
- Impact of compromise: DMA access kwenye system memory, sandbox escapes kupitia GPU drivers, au persistent firmware implants.
- **Apple Video Encoder (AVE)**: Firmware huendesha kwenye Media Engine ndani ya sandbox inayofanana na EL1. macOS huwasiliana kupitia VideoToolbox na `AppleAVE2`.
- Attack surface: Codec bitstreams, parameter sets, user-supplied buffers, na firmware update blobs.
- Impact of compromise: Leak uncompressed frames, bypass DRM, au kupata code execution yenye access kwa DMA engines.
- **Image Signal Processor (ISP)**: Huendesha secure firmware kwenye Media Engine cluster; macOS camera drivers huendesha kwenye EL1.
- Attack surface: Camera HALs, RAW frame descriptors, ISP configuration queues, na firmware updates.
- Impact of compromise: Capture raw camera feeds kwa siri, disable privacy indicators, au inject fabricated imagery.
- **AMX Matrix cores**: Hufanya kazi kama coprocessor units zinazoonekana kwenye EL0/EL1 kupitia instructions mpya.
- Attack surface: Kernel virtualization ya AMX state (`thread_set_state`, context switches) na user-space code generation.
- Impact of compromise: Leak tile registers za processes nyingine, fingerprint workloads, au escalate kupitia kernel memory corruption.

macOS ya kisasa huzichukulia coprocessors hizi kama trusted components katika chain of trust. Firmware ya SEP, SMC, na T2 imesainiwa na Apple, na handshake protocols (mara nyingi hutekelezwa kupitia mailboxes au I/O Kit families) hujumuisha challenge-response checks ili firmware iliyothibitishwa pekee iweze kushughulikia requests.

### IPC - Inter Process Communication

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## macOS Kernel Extensions

macOS ina **vizuizi vikali sana vya kupakia Kernel Extensions** (.kext) kwa sababu ya privileges za juu ambazo code hiyo itaendesha ikiwa nazo. Kwa kweli, kwa default ni jambo lisilowezekana kabisa (isipokuwa bypass ipatikane).

Katika ukurasa ufuatao unaweza pia kuona jinsi ya kurecover `.kext` ambayo macOS hupakia ndani ya **kernelcache** yake:

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### macOS System Extensions

Badala ya kutumia Kernel Extensions, macOS iliunda System Extensions, ambazo hutoa APIs za user level za kuwasiliana na kernel. Kwa njia hii, developers wanaweza kuepuka kutumia kernel extensions.

{{#ref}}
macos-system-extensions.md
{{#endref}}


### Cryptexes & RSR (Rapid Security Response)

- **Cryptex** ni kifupi cha **CRYPTographically-sealed EXtension**. Ni disk image (container) iliyofungwa inayotumiwa na Apple kuhifadhi sehemu za OS (frameworks, shared libraries, apps) ambazo zina uwezekano mkubwa wa kubadilika kati ya major OS updates.
- Kwenye macOS na iOS, components zilizowekwa ndani ya cryptexes zinaweza **kupatched au kubadilishwa** kupitia RSR bila ku-seal upya system volume yote.
- Cryptexes hukaa kwenye **Preboot volume**, pamoja na boot firmware, na huunganishwa kwenye OS file system wakati wa runtime.
- Kupakia cryptex content huhusisha validation: mfumo hukagua file seals, manifests, na root hashes, kisha hu-mount au “hu-graft” cryptex content ili apps wakati wa runtime zitumie cryptex versions zinapopatikana.
- Kwenye boot logs, cryptex loading hutokea baada ya kernel initialization lakini kabla full system services hazijaanza.

#### Rapid Security Response (RSR)

- **RSR** ni mechanism ya Apple ya kuwasilisha **security patches kati ya regular OS updates**. Hulenga cryptex content ili kusasisha sehemu zilizo vulnerable (kwa mfano libraries, frameworks) bila kugusa core system volume.
- Wakati wa kutumia RSR update, device huomba kutoka kwa Apple signing server **Cryptex1 Image4 manifest**. Manifest hii imefungwa cryptographically kwa device na cryptex content mpya.
- AP boot ticket iliyopo ya base system **haibadilishwi** na RSR. Patch hufanya kazi additively juu ya sealed base OS.
- Kwenye macOS, baadhi ya patched components (kwa mfano Safari) huanza kufanya kazi mara tu app inapoanzishwa tena; full system restart haihitajiki kila wakati.
- RSRs **zinaweza kuondolewa**: kila moja husafirisha patch na “antipatch” inayoweza kurudisha mfumo kwenye base OS version. Wakati wa kuondoa, cryptex content hurudishwa.
- RSR updates kwa kawaida ni ndogo zaidi kuliko full OS updates, na huhitaji battery state ya chini zaidi ili kusakinishwa.


## References

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
