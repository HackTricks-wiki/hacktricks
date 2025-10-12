# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

यह पृष्ठ कई MediaTek प्लेटफार्मों पर एक व्यावहारिक secure-boot ब्रेक का दस्तावेज़ प्रस्तुत करता है, जब डिवाइस बूटलोडर कॉन्फ़िगरेशन (seccfg) "unlocked" स्थिति में होता है तो सत्यापन अंतर का दुरुपयोग करके। यह दोष ARM EL3 पर एक patched bl2_ext चलाने की अनुमति देता है जो डाउनस्ट्रीम signature सत्यापन को अक्षम कर देता है, ट्रस्ट श्रृंखला को ध्वस्त कर देता है और arbitrary unsigned TEE/GZ/LK/Kernel लोडिंग सक्षम कर देता है।

> सावधान: शुरुआती-boot पर पैचिंग गलत offsets होने पर डिवाइस को स्थायी रूप से brick कर सकती है। हमेशा पूर्ण dumps और एक विश्वसनीय recovery path रखें।

## प्रभावित बूट प्रवाह (MediaTek)

- सामान्य पथ: BootROM → Preloader → bl2_ext (EL3, सत्यापित) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- कमजोर पथ: जब seccfg 'unlocked' पर सेट होता है, Preloader शायद bl2_ext का सत्यापन स्किप कर देता है। Preloader फिर भी EL3 पर bl2_ext में जंप करता है, इसलिए एक crafted bl2_ext उसके बाद असत्यापित कम्पोनेंट्स लोड कर सकता है।

प्रमुख ट्रस्ट सीमा:
- bl2_ext EL3 पर चलता है और TEE, GenieZone, LK/AEE और kernel को सत्यापित करने के लिए जिम्मेदार है। यदि bl2_ext स्वयं प्रमाणीकृत नहीं है, तो बाकी श्रृंखला सहजता से बाईपास हो जाती है।

## मूल कारण

प्रभावित डिवाइसों पर, जब seccfg "unlocked" दिखाता है तो Preloader bl2_ext पार्टीशन के प्रमाणिकरण को लागू नहीं करता। इससे एक attacker-controlled bl2_ext फ्लैश करना संभव होता है जो EL3 पर चलता है।

bl2_ext के अंदर, सत्यापन नीति फ़ंक्शन को पैच करके यह बिना शर्त रिपोर्ट कराया जा सकता है कि सत्यापन आवश्यक नहीं है। एक न्यूनतम वैचारिक पैच इस प्रकार है:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
इस परिवर्तन के साथ, patched bl2_ext जो EL3 पर चल रहा है द्वारा लोड किए जाने पर सभी बाद की images (TEE, GZ, LK/AEE, Kernel) cryptographic checks के बिना स्वीकार की जाती हैं।

## किसी लक्ष्य का मूल्यांकन कैसे करें (expdb logs)

bl2_ext लोड के आसपास boot logs (उदा., expdb) को dump/inspect करें। यदि img_auth_required = 0 और certificate verification time ≈ 0 ms है, तो enforcement संभवतः बंद है और डिवाइस exploitable है।

उदाहरण लॉग अंश:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
नोट: रिपोर्टों के अनुसार कुछ devices bl2_ext verification को skip कर देते हैं भले ही bootloader locked हो, जो प्रभाव को और बढ़ा देता है।

## व्यावहारिक exploitation workflow (Fenrir PoC)

Fenrir इस वर्ग की समस्या के लिए एक reference exploit/patching toolkit है। यह Nothing Phone (2a) (Pacman) को support करता है और CMF Phone 1 (Tetris) पर known working है (incompletely supported)। अन्य मॉडलों में port करने के लिए device-specific bl2_ext का reverse engineering करना आवश्यक है।

उच्च-स्तरीय प्रक्रिया:
- अपने target codename के लिए device bootloader image प्राप्त करें और इसे bin/<device>.bin के रूप में रखें
- एक patched image बनाएं जो bl2_ext verification policy को disable कर दे
- नतीजतन payload को device पर flash करें (helper script द्वारा fastboot मान लिया गया है)

Commands:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by helper script)
./flash.sh
```
यदि fastboot उपलब्ध नहीं है, तो आपको अपने प्लेटफ़ॉर्म के लिए उपयुक्त वैकल्पिक flashing method का उपयोग करना चाहिए।

## Runtime payload क्षमताएँ (EL3)

एक patched bl2_ext payload कर सकता है:
- कस्टम fastboot कमांड्स रजिस्टर कर सकता है
- boot mode को नियंत्रित/ओवरराइड कर सकता है
- runtime पर built‑in bootloader functions को डायनामिक रूप से कॉल कर सकता है
- वास्तव में unlocked होते हुए भी “lock state” को locked दिखाकर मजबूत integrity checks पास कर सकता है (कुछ वातावरण में अभी भी vbmeta/AVB समायोजन आवश्यक हो सकते हैं)

Limitation: वर्तमान PoCs में नोट है कि runtime memory modification MMU प्रतिबंधों के कारण fault कर सकती है; payloads आमतौर पर लाइव memory writes से तब तक बचते हैं जब तक यह समस्‍या हल न हो।

## पोर्टिंग टिप्स

- device-specific bl2_ext को reverse engineer करके verification policy logic ढूँढें (उदा., sec_get_vfy_policy)।
- policy return site या decision branch की पहचान करें और उसे “no verification required” (return 0 / unconditional allow) के लिए patch करें।
- Offsets को पूरी तरह device- और firmware-specific रखें; variants के बीच addresses को reuse न करें।
- पहले एक sacrificial unit पर validate करें। flash करने से पहले recovery plan तैयार रखें (उदा., EDL/BootROM loader/SoC-specific download mode)।

## सुरक्षा प्रभाव

- Preloader के बाद EL3 code execution और बाकी boot path के लिए पूरी chain-of-trust का पतन।
- unsigned TEE/GZ/LK/Kernel को boot करने की क्षमता, secure/verified boot अपेक्षाओं को bypass करते हुए और persistent compromise को सक्षम करना।

## Detection और hardening सुझाव

- सुनिश्चित करें कि Preloader seccfg state की परवाह किए बिना bl2_ext को verify करे।
- authentication results को enforce करें और audit evidence इकट्ठा करें (timings > 0 ms, mismatch पर strict errors)।
- Lock-state spoofing को attestation के लिए अप्रभावी बनाएं (lock state को AVB/vbmeta verification निर्णयों और fuse-backed state से जोड़ें)।

## Device notes

- पुष्ट रूप से समर्थित: Nothing Phone (2a) (Pacman)
- कार्यरत ज्ञात (अधूरा समर्थन): CMF Phone 1 (Tetris)
- प्रेक्षित: रिपोर्ट के अनुसार Vivo X80 Pro ने bl2_ext को verify नहीं किया, भले ही locked था

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)

{{#include ../../banners/hacktricks-training.md}}
