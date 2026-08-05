# macOS Kernel i System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## XNU Kernel

**Osnovu macOS-a čini XNU**, što je skraćenica za „X is Not Unix“. Ovaj kernel je u osnovi sastavljen od **Mach microkernel-a** (o kome će biti reči kasnije) **i** elemenata iz Berkeley Software Distribution-a (**BSD**). XNU takođe obezbeđuje platformu za **kernel drivere putem sistema koji se naziva I/O Kit**. XNU kernel je deo open source projekta Darwin, što znači da je **njegov source code slobodno dostupan**.

Iz perspektive security researcher-a ili Unix developera, **macOS** može delovati prilično **slično** sistemu **FreeBSD**, sa elegantnim GUI-jem i velikim brojem prilagođenih aplikacija. Većina aplikacija razvijenih za BSD može se compile-ovati i pokretati na macOS-u bez izmena, jer su command-line alati poznati Unix korisnicima dostupni u macOS-u. Međutim, pošto XNU kernel uključuje Mach, postoje značajne razlike između tradicionalnog Unix-like sistema i macOS-a, a te razlike mogu izazvati potencijalne probleme ili pružiti jedinstvene prednosti.

Open source verzija XNU-a: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach je **microkernel** dizajniran tako da bude **UNIX-compatible**. Jedan od njegovih ključnih principa dizajna bio je da se **minimizuje** količina **code-a** koji se izvršava u **kernel** prostoru i da se umesto toga mnoge tipične kernel funkcije, kao što su file system, networking i I/O, **izvršavaju kao user-level tasks**.

U okviru XNU-a, Mach je **odgovoran za mnoge kritične low-level operacije** koje kernel obično obavlja, kao što su scheduling procesora, multitasking i upravljanje virtuelnom memorijom.

### BSD

XNU **kernel** takođe **uključuje** značajnu količinu code-a izvedenog iz projekta **FreeBSD**. Ovaj code **se izvršava kao deo kernela zajedno sa Mach-om**, u istom address space-u. Međutim, FreeBSD code unutar XNU-a može se značajno razlikovati od originalnog FreeBSD code-a, jer su bile potrebne izmene kako bi se obezbedila njegova kompatibilnost sa Mach-om. FreeBSD doprinosi mnogim kernel operacijama, uključujući:

- Upravljanje procesima
- Obradu signala
- Osnovne security mehanizme, uključujući upravljanje user-ima i grupama
- System call infrastrukturu
- TCP/IP stack i sockets
- Firewall i packet filtering

Razumevanje interakcije između BSD-a i Mach-a može biti kompleksno zbog njihovih različitih konceptualnih okvira. Na primer, BSD koristi procese kao osnovnu izvršnu jedinicu, dok Mach funkcioniše na osnovu thread-ova. Ova razlika se u XNU-u rešava tako što se **svaki BSD proces povezuje sa Mach task-om** koji sadrži tačno jedan Mach thread. Kada se koristi BSD-ov fork() system call, BSD code unutar kernela koristi Mach funkcije za kreiranje task-a i thread strukture.

Pored toga, **Mach i BSD održavaju različite security modele**: **Mach-ov** security model zasniva se na **port pravima**, dok se BSD-ov security model zasniva na **vlasništvu nad procesima**. Razlike između ova dva modela povremeno su dovele do local privilege-escalation vulnerabilities. Pored uobičajenih system call-ova, postoje i **Mach traps koji user-space programima omogućavaju interakciju sa kernelom**. Ovi različiti elementi zajedno čine višeslojnu, hibridnu arhitekturu macOS kernela.

### I/O Kit - Drivers

I/O Kit je open-source, object-oriented **device-driver framework** u okviru XNU kernela koji upravlja **dynamically loaded device drivers**. Omogućava modularnom code-u da se dodaje u kernel u hodu, pružajući podršku za raznovrstan hardware.


{{#ref}}
macos-iokit.md
{{#endref}}

### Coprocessors in macOS Architecture

Apple platforme se oslanjaju na nekoliko coprocessor-a kako bi se rad osetljiv na latency prebacio sa glavnih core-ova i izolovale security-critical funkcije.

- **Secure Enclave Processor (SEP)**: Poseban ARM core sa sopstvenim microkernel-om i secure boot chain-om, koji se obično izvršava u **EL3/secure world**. Interakcija se odvija putem mailbox driver-a u macOS-u na EL1.
- Attack surface: SEP firmware updates i user-space daemons (`seputil`, `securityd`) koji prosleđuju zahteve.
- Impact of compromise: Leak dugoročnih ključeva, zaobilaženje biometric gating-a i narušavanje FileVault ili Apple Pay zaštita.
- **System Management Controller (SMC)**: Pokreće proprietary firmware na microcontroller-u izvan ARM exception level-a. macOS (EL1) mu pristupa putem I/O Kit user client-a.
- Attack surface: USB-C power delivery poruke, interfejsi za upravljanje fan-om/baterijom i firmware update paths.
- Impact of compromise: Zaobilaženje thermal limits, ubacivanje lažnih podataka senzora, prekid napajanja ili postavljanje persistent NVRAM backdoor-a.
- **T1/T2 Security Chips**: Pokreću bridgeOS (zasnovan na watchOS-u), uglavnom na EL1/EL3, na sopstvenim ARM core-ovima. macOS komunicira putem PCIe/USB-like channel-a kojima upravlja IOKit.
- Attack surface: DFU/restore pathways, IPC endpoint-i koje izlažu servisi kao što je `tccd` i media pipeline-ovi povezani sa T2 čipom.
- Impact of compromise: Onemogućavanje secure boot-a, dešifrovanje sadržaja SSD-a, preuzimanje kontrole nad camera/mic gating-om ili emulacija HID input-a za stealth persistence.
- **Display Coprocessor (DCP)**: Izvršava firmware na EL1 unutar izolovanog address space-a zaštićenog pomoću DART-a (Apple-ov IOMMU).
- Attack surface: `DCPAVService` interfejsi, shared descriptor buffers i parsiranje firmware image-a.
- Impact of compromise: Ubacivanje proizvoljnih frame-ova, prisluškivanje framebuffer-a ili onesposobljavanje display pipeline-a radi DoS-a.
- **Apple Neural Engine (ANE)**: Pokreće microcode na posebnom ML cluster-u (bez ARM EL level-a). macOS schedule-uje rad putem `ANECompilerService` i IOKit-a.
- Attack surface: Compiled model binaries (`.ane`), Core ML APIs koji prosleđuju custom kernels i firmware loaders.
- Impact of compromise: Izmena ili exfiltration ML modela, leak obrađenih audio/vision podataka ili sabotiranje on-device inference-a.
- **AGX GPU**: Firmware se izvršava na custom GPU core-ovima sa scheduler-om; EL0 prosleđuje Metal commands koje EL1 validira.
- Attack surface: Metal shader compiler, shared buffer mapping APIs i `com.apple.AGXFirmware` ioctl interfejsi.
- Impact of compromise: DMA pristup system memory-ju, sandbox escapes putem GPU driver-a ili persistent firmware implants.
- **Apple Video Encoder (AVE)**: Firmware se izvršava na Media Engine-u u sandbox-u nalik EL1. macOS komunicira putem VideoToolbox-a i `AppleAVE2`.
- Attack surface: Codec bitstreams, parameter sets, user-supplied buffers i firmware update blobs.
- Impact of compromise: Leak nekompresovanih frame-ova, zaobilaženje DRM-a ili code execution sa pristupom DMA engine-ima.
- **Image Signal Processor (ISP)**: Pokreće secure firmware u Media Engine cluster-u; macOS camera driver-i rade na EL1.
- Attack surface: Camera HAL-ovi, RAW frame descriptors, ISP configuration queues i firmware updates.
- Impact of compromise: Tiho snimanje raw camera feed-ova, onemogućavanje privacy indikatora ili ubacivanje falsifikovanih slika.
- **AMX Matrix cores**: Funkcionišu kao coprocessor jedinice izložene na EL0/EL1 putem novih instructions.
- Attack surface: Kernel virtualization AMX state-a (`thread_set_state`, context switches) i user-space code generation.
- Impact of compromise: Leak tile register-a drugih procesa, fingerprint workloads-a ili privilege escalation putem kernel memory corruption-a.

Moderni macOS tretira ove coprocessor-e kao trusted components u chain of trust-u. Firmware za SEP, SMC i T2 potpisuje Apple, a handshake protokoli (često implementirani preko mailbox-a ili I/O Kit families) uključuju challenge-response provere kako bi samo authenticated firmware mogao da obrađuje zahteve.

### IPC - Inter Process Communication

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## macOS Kernel Extensions

macOS je **izuzetno restriktivan pri učitavanju Kernel Extensions** (.kext), zbog visokih privilegija sa kojima će se code izvršavati. Zapravo, po defaultu je to praktično nemoguće (osim ako se pronađe bypass).

Na sledećoj stranici možete videti i kako da povratite `.kext` koji macOS učitava unutar svog **kernelcache-a**:

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### macOS System Extensions

Umesto korišćenja Kernel Extensions, macOS je kreirao System Extensions, koje nude API-je na user level-u za interakciju sa kernelom. Na ovaj način developeri mogu izbeći korišćenje kernel extensions.

{{#ref}}
macos-system-extensions.md
{{#endref}}


### Cryptexes & RSR (Rapid Security Response)

- **Cryptex** je skraćenica za **CRYPTographically-sealed EXtension**. To je sealed disk image (container) koji Apple koristi za smeštanje delova OS-a (frameworks, shared libraries, apps) koji će se najverovatnije menjati između major OS updates.
- Na macOS-u i iOS-u, komponente smeštene unutar cryptex-a mogu se **patch-ovati ili zameniti** putem RSR-a bez ponovnog seal-ovanja čitavog system volume-a.
- Cryptex-i se nalaze na **Preboot volume-u**, zajedno sa boot firmware-om, i graft-uju se u OS file system tokom runtime-a.
- Učitavanje cryptex sadržaja uključuje validation: sistem proverava file seals, manifests i root hashes, a zatim mount-uje ili „graft-uje“ cryptex sadržaj tako da aplikacije tokom runtime-a koriste cryptex verzije tamo gde postoje.
- U boot log-ovima, učitavanje cryptex-a dešava se nakon kernel initialization-a, ali pre pokretanja full system services.

#### Rapid Security Response (RSR)

- **RSR** je Apple-ov mehanizam za isporuku **security patches između regularnih OS updates**. On cilja cryptex sadržaj kako bi ažurirao ranjive delove (npr. libraries, frameworks) bez izmene core system volume-a.
- Prilikom primene RSR update-a, uređaj od Apple-ovog signing server-a zahteva **Cryptex1 Image4 manifest**. Ovaj manifest je cryptographically bound za uređaj i novi cryptex sadržaj.
- Postojeći AP boot ticket za base system **ne menja se** putem RSR-a. Patch funkcioniše aditivno preko sealed base OS-a.
- Na macOS-u, određene patched komponente (npr. Safari) postaju aktivne čim se aplikacija ponovo pokrene; full system restart nije uvek potreban.
- RSR-ovi su **removable**: svaki isporučuje i patch i „antipatch“ koji može vratiti base OS version. Prilikom uklanjanja, cryptex sadržaj se vraća na prethodno stanje.
- RSR updates su uglavnom mnogo manji od full OS updates i zahtevaju niži nivo baterije za instalaciju.


## References

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
