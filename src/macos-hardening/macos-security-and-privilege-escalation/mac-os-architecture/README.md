# macOS Kernel & System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## XNU Kernel

**Jezgro macOS-a je XNU**, što je skraćenica za „X is Not Unix“. Ovo jezgro se u osnovi sastoji od **Mach microkernel-a** (o kome će biti reči kasnije), **i** elemenata iz Berkeley Software Distribution-a (**BSD**). XNU takođe obezbeđuje platformu za **kernel drivere preko sistema pod nazivom I/O Kit**. XNU kernel je deo open source projekta Darwin, što znači da je **njegov izvorni kod slobodno dostupan**.

Iz perspektive security istraživača ili Unix developera, **macOS** može delovati prilično **slično** **FreeBSD** sistemu sa elegantnim GUI-jem i mnoštvom prilagođenih aplikacija. Većina aplikacija razvijenih za BSD može da se kompajlira i pokrene na macOS-u bez izmena, pošto su command-line alati poznati Unix korisnicima prisutni u macOS-u. Međutim, pošto XNU kernel uključuje Mach, postoje značajne razlike između tradicionalnog Unix-like sistema i macOS-a, a te razlike mogu izazvati potencijalne probleme ili pružiti jedinstvene prednosti.

Open source verzija XNU-a: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach je **microkernel** dizajniran da bude **UNIX-kompatibilan**. Jedan od njegovih ključnih principa dizajna bio je da se **minimizuje** količina **koda** koji se izvršava u **kernel** prostoru i da se umesto toga mnoge tipične funkcije kernela, kao što su file system, networking i I/O, **izvršavaju kao user-level taskovi**.

U XNU-u, Mach je **odgovoran za mnoge kritične low-level operacije** koje kernel obično obavlja, kao što su raspoređivanje procesora, multitasking i upravljanje virtuelnom memorijom.

### BSD

XNU **kernel** takođe **uključuje** značajnu količinu koda izvedenog iz projekta **FreeBSD**. Ovaj kod **izvršava se kao deo kernela zajedno sa Mach-om**, u istom adresnom prostoru. Međutim, FreeBSD kod unutar XNU-a može se značajno razlikovati od originalnog FreeBSD koda, jer su bile potrebne izmene kako bi se obezbedila njegova kompatibilnost sa Mach-om. FreeBSD doprinosi mnogim kernel operacijama, uključujući:

- Upravljanje procesima
- Obradu signala
- Osnovne security mehanizme, uključujući upravljanje korisnicima i grupama
- Infrastrukturu za sistemske pozive
- TCP/IP stack i socket-e
- Firewall i filtriranje paketa

Razumevanje interakcije između BSD-a i Mach-a može biti složeno zbog njihovih različitih konceptualnih okvira. Na primer, BSD koristi procese kao osnovnu izvršnu jedinicu, dok Mach funkcioniše na osnovu thread-ova. Ova razlika se u XNU-u rešava tako što se **svaki BSD proces povezuje sa jednim Mach task-om** koji sadrži tačno jedan Mach thread. Kada se koristi BSD-ov fork() sistemski poziv, BSD kod unutar kernela koristi Mach funkcije za kreiranje task-a i thread strukture.

Pored toga, **Mach i BSD održavaju različite security modele**: **Mach-ov** security model zasniva se na **port pravima**, dok BSD-ov security model funkcioniše na osnovu **vlasništva nad procesima**. Razlike između ova dva modela povremeno su dovele do local privilege-escalation ranjivosti. Pored uobičajenih sistemskih poziva, postoje i **Mach traps** koji user-space programima omogućavaju interakciju sa kernelom. Ovi različiti elementi zajedno čine složenu, hibridnu arhitekturu macOS kernela.<sup>[[1]](#references)</sup>

### I/O Kit - Drivers

I/O Kit je open-source, object-oriented **framework za device drivere** u XNU kernelu i upravlja **dinamički učitanim device driverima**. Omogućava da se modularni kod dodaje kernelu tokom rada, pružajući podršku za različit hardware.


{{#ref}}
macos-iokit.md
{{#endref}}

### Coprocessors in macOS Architecture

Apple platforme se oslanjaju na nekoliko coprocessor-a kako bi se posao osetljiv na latency uklonio sa glavnih jezgara i izolovale security-kritične funkcije.

- **Secure Enclave Processor (SEP)**: Posvećeno ARM jezgro sa sopstvenim microkernel-om i secure boot chain-om, koje obično radi na **EL3/secure world**. Interakcija se odvija preko mailbox drivera u macOS-u na EL1.
- Attack surface: SEP firmware updates i user-space daemoni (`seputil`, `securityd`) koji prosleđuju zahteve.
- Impact of compromise: Leak dugoročnih ključeva, zaobilaženje biometric gating-a i razbijanje FileVault ili Apple Pay zaštita.
- **System Management Controller (SMC)**: Pokreće proprietary firmware na microcontroller-u izvan ARM exception level-a. macOS (EL1) mu pristupa preko I/O Kit user client-a.
- Attack surface: USB-C power delivery poruke, interfejsi za upravljanje ventilatorima i baterijom i putanje za firmware update.
- Impact of compromise: Zaobilaženje thermal ograničenja, ubacivanje lažnih podataka senzora, prekid napajanja ili postavljanje persistent NVRAM backdoor-a.
- **T1/T2 Security Chips**: Pokreću bridgeOS (izveden iz watchOS-a), uglavnom na EL1/EL3, na sopstvenim ARM jezgrima. macOS komunicira preko PCIe/USB-like kanala kojima upravlja IOKit.
- Attack surface: DFU/restore putanje, IPC endpoint-i koje izlažu servisi kao što je `tccd` i media pipeline-ovi povezani sa T2 čipom.
- Impact of compromise: Onemogućavanje secure boot-a, dešifrovanje SSD sadržaja, preuzimanje kontrole nad camera/mic gating-om ili emulacija HID input-a za stealth persistence.
- **Display Coprocessor (DCP)**: Izvršava firmware na EL1 unutar izolovanog adresnog prostora zaštićenog pomoću DART-a (Apple-ov IOMMU).
- Attack surface: `DCPAVService` interfejsi, deljeni descriptor buffer-i i parsiranje firmware image-a.
- Impact of compromise: Ubacivanje proizvoljnih frame-ova, prisluškivanje framebuffer-a ili onesposobljavanje display pipeline-a radi DoS-a.
- **Apple Neural Engine (ANE)**: Pokreće microcode na namenskom ML cluster-u (bez ARM EL nivoa). macOS raspoređuje posao preko `ANECompilerService` i IOKit-a.
- Attack surface: Kompajlirani model binari (`.ane`), Core ML API-ji koji prosleđuju custom kernel-e i firmware loader-i.
- Impact of compromise: Menjanje ili exfiltracija ML modela, leak obrađenih audio/vision podataka ili sabotiranje inference-a na uređaju.
- **AGX GPU**: Firmware radi na custom GPU jezgrima sa scheduler-om; EL0 šalje Metal komande koje EL1 validira.
- Attack surface: Metal shader compiler, API-ji za mapiranje deljenih buffer-a i `com.apple.AGXFirmware` ioctl interfejsi.
- Impact of compromise: DMA pristup sistemskoj memoriji, sandbox escape preko GPU drivera ili persistent firmware implant-i.
- **Apple Video Encoder (AVE)**: Firmware se izvršava na Media Engine-u u sandbox-u nalik EL1. macOS komunicira preko VideoToolbox-a i `AppleAVE2`.
- Attack surface: Codec bitstream-ovi, parameter set-ovi, buffer-i koje obezbeđuje korisnik i firmware update blob-ovi.
- Impact of compromise: Leak nekompresovanih frame-ova, zaobilaženje DRM-a ili dobijanje code execution-a sa pristupom DMA engine-ima.
- **Image Signal Processor (ISP)**: Pokreće secure firmware u Media Engine cluster-u; macOS camera driveri rade na EL1.
- Attack surface: Camera HAL-ovi, RAW frame descriptor-i, ISP configuration queue-ovi i firmware updates.
- Impact of compromise: Tiho snimanje raw camera feed-ova, onemogućavanje privacy indikatora ili ubacivanje lažnih slika.
- **AMX Matrix cores**: Funkcionišu kao coprocessor jedinice dostupne na EL0/EL1 preko novih instrukcija.
- Attack surface: Kernel virtualizacija AMX state-a (`thread_set_state`, context switches) i generisanje koda u user-space-u.
- Impact of compromise: Leak tile registara drugih procesa, fingerprinting workload-a ili escalation preko kernel memory corruption-a.

Moderni macOS tretira ove coprocessor-e kao trusted komponente u chain of trust-u. Firmware za SEP, SMC i T2 potpisuje Apple, a handshake protokoli (često implementirani preko mailbox-a ili I/O Kit family-ja) uključuju challenge-response provere kako bi samo authenticated firmware mogao da obrađuje zahteve.

### IPC - Inter Process Communication

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## macOS Kernel Extensions

macOS je **izuzetno restriktivan pri učitavanju Kernel Extensions** (.kext), jer se kod izvršava sa visokim privilegijama. Zapravo, po podrazumevanim podešavanjima to je praktično nemoguće (osim ako se pronađe bypass).

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

- **Cryptex** je skraćenica za **CRYPTographically-sealed EXtension**. To je sealed disk image (container) koji Apple koristi za smeštanje delova OS-a (framework-a, shared library-ja, aplikacija) za koje je verovatnije da će se menjati između velikih OS update-a.
- Na macOS-u i iOS-u, komponente smeštene unutar cryptex-a mogu se **patch-ovati ili zameniti** putem RSR-a bez ponovnog sealing-a čitavog system volume-a.
- Cryptex-i se nalaze na **Preboot volume-u**, pored boot firmware-a, i graft-uju se u OS file system tokom runtime-a.
- Učitavanje cryptex sadržaja uključuje validaciju: sistem proverava file seal-ove, manifest-e i root hash-eve, a zatim mount-uje ili „graft-uje“ cryptex sadržaj tako da aplikacije tokom runtime-a koriste cryptex verzije tamo gde postoje.
- U boot logovima, učitavanje cryptex-a dešava se nakon kernel inicijalizacije, ali pre potpunog pokretanja system servisa.


#### Rapid Security Response (RSR)

- **RSR** je Apple-ov mehanizam za isporučivanje **security patch-eva između redovnih OS update-a**. Usmeren je na cryptex sadržaj kako bi se ažurirali ranjivi delovi (npr. library-ji i framework-i), bez menjanja osnovnog system volume-a.
- Prilikom primene RSR update-a, uređaj od Apple-ovog signing servera zahteva **Cryptex1 Image4 manifest**. Ovaj manifest je kriptografski povezan sa uređajem i novim cryptex sadržajem.
- Postojeći AP boot ticket za osnovni sistem **ne menja se** tokom RSR-a. Patch se primenjuje aditivno preko sealed base OS-a.
- Na macOS-u, određene patch-ovane komponente (npr. Safari) postaju aktivne čim se aplikacija ponovo pokrene; potpuni restart sistema nije uvek potreban.
- RSR-ovi su **uklonjivi**: svaki uključuje i patch i „antipatch“ koji može da vrati sistem na base OS verziju. Prilikom uklanjanja, cryptex sadržaj se vraća na prethodno stanje.
- RSR update-i su uglavnom mnogo manji od potpunih OS update-a i zahtevaju niži nivo baterije za instalaciju.


## References

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
