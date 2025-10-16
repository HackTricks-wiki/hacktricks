# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

यह पृष्ठ कई MediaTek प्लेटफ़ॉर्म्स पर एक व्यावहारिक secure-boot break का दस्तावेज़ प्रस्तुत करता है, जो तब होता है जब device bootloader configuration (seccfg) "unlocked" स्थिति में होने पर एक verification gap का दुरुपयोग किया जाता है। यह दोष patched bl2_ext को ARM EL3 पर चलाने की अनुमति देता है ताकि downstream signature verification को disable किया जा सके, जिससे chain of trust collapse हो जाती है और arbitrary unsigned TEE/GZ/LK/Kernel लोड करना संभव हो जाता है।

> सावधान: यदि offsets गलत हों तो early-boot patching डिवाइस को स्थायी रूप से ब्रिक कर सकता है। हमेशा full dumps और एक विश्वसनीय recovery path रखें।

## प्रभावित बूट फ़्लो (MediaTek)

- सामान्य मार्ग: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Vulnerable path: जब seccfg "unlocked" सेट होता है, तो Preloader bl2_ext की verification लागू नहीं कर सकता। Preloader तब भी EL3 पर bl2_ext में jump करता है, इसलिए एक crafted bl2_ext उसके बाद unverified components लोड कर सकता है।

प्रमुख trust सीमा:
- bl2_ext EL3 पर चलता है और TEE, GenieZone, LK/AEE और kernel की verification के लिए जिम्मेदार है। यदि bl2_ext स्वयं authenticated नहीं है, तो शेष chain आसानी से bypass हो जाती है।

## मूल कारण

प्रभावित डिवाइसों पर, जब seccfg "unlocked" संकेत करता है तो Preloader bl2_ext partition के authentication को लागू नहीं करता। इससे attacker-controlled bl2_ext को फ्लैश करने की अनुमति मिलती है जो EL3 पर चलता है।

bl2_ext के अंदर, verification policy function को patch करके यह अनिवार्य रूप से रिपोर्ट करने के लिए बदला जा सकता है कि verification आवश्यक नहीं है। एक न्यूनतम अवधारणात्मक patch है:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
इस परिवर्तन के साथ, बाद की सभी इमेज (TEE, GZ, LK/AEE, Kernel) patched bl2_ext द्वारा EL3 पर चलने पर लोड होने पर क्रिप्टोग्राफिक जांच के बिना स्वीकार कर ली जाती हैं।

## टार्गेट का ट्रायज कैसे करें (expdb logs)

Boot logs को dump/inspect करें (उदा., expdb) bl2_ext load के आसपास। यदि img_auth_required = 0 और certificate verification time लगभग 0 ms है, तो enforcement संभवतः बंद है और डिवाइस exploitable है।

उदाहरण लॉग अंश:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
नोट: कुछ डिवाइसों में रिपोर्ट किया गया है कि वे bl2_ext verification को स्किप कर देते हैं भले ही bootloader locked हो, जो प्रभाव को और बढ़ा देता है।

## व्यावहारिक exploitation कार्यप्रवाह (Fenrir PoC)

Fenrir इस श्रेणी के इश्यू के लिए एक reference exploit/patching toolkit है। यह Nothing Phone (2a) (Pacman) को सपोर्ट करता है और CMF Phone 1 (Tetris) पर (आंशिक रूप से समर्थित) काम करने के लिए जाना जाता है। अन्य मॉडलों पर पोर्ट करने के लिए device-specific bl2_ext का reverse engineering आवश्यक है।

उच्च-स्तरीय प्रक्रिया:
- अपने target codename के लिए device bootloader image प्राप्त करें और इसे bin/<device>.bin में रखें
- एक patched image बनाएं जो bl2_ext verification policy को disable कर दे
- नियत payload को device पर फ्लैश करें (helper script fastboot को मानकर चलता है)

कमांड्स:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by helper script)
./flash.sh
```
If fastboot is unavailable, you must use a suitable alternative flashing method for your platform.

## Runtime payload क्षमताएँ (EL3)

A patched bl2_ext payload can:
- कस्टम fastboot कमांड रजिस्टर करना
- boot mode को नियंत्रित/ओवरराइड करना
- रनटाइम पर built‑in bootloader functions को डायनामिक रूप से कॉल करना
- वास्तव में अनलॉक्ड होते हुए “lock state” को locked के रूप में spoof करना ताकि मजबूत integrity checks पास हो सकें (कुछ वातावरणों में फिर भी vbmeta/AVB समायोजन आवश्यक हो सकते हैं)

Limitation: Current PoCs note that runtime memory modification may fault due to MMU constraints; payloads generally avoid live memory writes until this is resolved.

## पोर्टिंग टिप्स

- डिवाइस-विशिष्ट bl2_ext को reverse engineer करें ताकि verification policy लॉजिक का पता लग सके (उदा., sec_get_vfy_policy).
- policy return साइट या decision branch की पहचान करें और इसे “no verification required” के रूप में patch करें (return 0 / unconditional allow).
- Offsets को पूरी तरह डिवाइस- और firmware-विशिष्ट रखें; variants के बीच addresses को पुनः उपयोग न करें।
- पहले किसी sacrificial unit पर validate करें। flash करने से पहले एक recovery plan तैयार रखें (उदा., EDL/BootROM loader/SoC-specific download mode)।

## सुरक्षा प्रभाव

- Preloader के बाद EL3 code का execution और बाकी boot path के लिए chain-of-trust का पूर्ण पतन।
- unsigned TEE/GZ/LK/Kernel को boot करने की क्षमता, जिससे secure/verified boot की अपेक्षाएँ bypass हो सकती हैं और persistent compromise सक्षम हो सकता है।

## डिटेक्शन और हार्डनिंग विचार

- सुनिश्चित करें कि Preloader bl2_ext को seccfg state की परवाह किए बिना verify करे।
- authentication results को enforce करें और audit evidence इकट्ठा करें (timings > 0 ms, mismatch पर strict errors)।
- Attestation के लिए lock-state spoofing को अप्रभावी बनाना चाहिए (lock state को AVB/vbmeta verification निर्णयों और fuse-backed state से जोड़ें)।

## डिवाइस नोट्स

- पुष्ट समर्थन: Nothing Phone (2a) (Pacman)
- रिपोर्ट किए गए कामकाज (अपूर्ण समर्थन): CMF Phone 1 (Tetris)
- देखा गया: रिपोर्ट है कि Vivo X80 Pro ने bl2_ext को verify नहीं किया, भले ही device locked हो

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)

{{#include ../../banners/hacktricks-training.md}}
