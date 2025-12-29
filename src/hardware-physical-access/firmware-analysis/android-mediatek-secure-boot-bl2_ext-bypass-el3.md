# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

यह पृष्ठ कई MediaTek प्लेटफॉर्म पर एक व्यावहारिक secure-boot ब्रेक का दस्तावेजीकरण करता है, जो तब होता है जब device bootloader configuration (seccfg) "unlocked" स्थिति में होने पर verification gap का दुरुपयोग किया जाता है। यह दोष patched bl2_ext को ARM EL3 पर चलाकर downstream signature verification को डिसेबल करने की अनुमति देता है, जिससे chain of trust collapse होता है और arbitrary unsigned TEE/GZ/LK/Kernel लोडिंग सक्षम हो जाती है।

> चेतावनी: Early-boot patching गलत offsets होने पर डिवाइस को स्थायी रूप से ब्रिक कर सकता है। हमेशा पूरी dumps और एक विश्वसनीय recovery path रखें।

## Affected boot flow (MediaTek)

- सामान्य पथ: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- कमजोर पथ: जब seccfg "unlocked" होता है, तो Preloader bl2_ext के verification को छोड़ सकता है। Preloader फिर भी EL3 पर bl2_ext में jump करता है, इसलिए एक crafted bl2_ext इसके बाद unverified components लोड कर सकता है।

कुंजी trust सीमा:
- bl2_ext EL3 पर execute करता है और TEE, GenieZone, LK/AEE तथा kernel की verification के लिए जिम्मेदार है। यदि bl2_ext स्वयं authenticated नहीं है, तो शेष chain आसानी से bypass हो जाती है।

## Root cause

प्रभावित डिवाइसों पर, जब seccfg "unlocked" संकेत करता है तो Preloader bl2_ext partition की authentication लागू नहीं करता। इससे attacker-controlled bl2_ext फ्लैश करने की अनुमति मिलती है जो EL3 पर चलता है।

bl2_ext के अंदर, verification policy function को patch करके यह बिना शर्त रिपोर्ट कराया जा सकता है कि verification आवश्यक नहीं है। एक न्यूनतम वैचारिक patch यह है:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
इस परिवर्तन के साथ, बाद की सभी images (TEE, GZ, LK/AEE, Kernel) patched bl2_ext द्वारा EL3 पर चलने पर लोड होने पर क्रिप्टोग्राफिक चेक्स के बिना स्वीकार कर ली जाती हैं।

## किसी लक्ष्य का triage कैसे करें (expdb logs)

Dump/inspect boot logs (e.g., expdb) bl2_ext लोड के आस-पास। यदि img_auth_required = 0 और certificate verification time ~0 ms है, तो enforcement संभवत: बंद है और डिवाइस exploitable है।

उदाहरण लॉग अंश:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Note: कुछ डिवाइसेज़ पर रिपोर्ट किया गया है कि वे bl2_ext verification को स्किप करते हैं, भले ही bootloader locked हो, जो प्रभाव को और बढ़ा देता है।

Devices that ship the lk2 secondary bootloader में भी वही logic gap देखा गया है, इसलिए porting का प्रयास करने से पहले यह पुष्टि करने के लिए कि कौन-सा path signatures लागू करता है, bl2_ext और lk2 दोनों partitions के expdb logs प्राप्त करें।

## Practical exploitation workflow (Fenrir PoC)

Fenrir is a reference exploit/patching toolkit इस क्लास की समस्या के लिए। यह Nothing Phone (2a) (Pacman) को support करता है और CMF Phone 1 (Tetris) पर known working (incompletely supported) है। अन्य मॉडलों पर porting के लिए device-specific bl2_ext का reverse engineering आवश्यक है।

High-level process:
- अपने target codename के लिए device bootloader image प्राप्त करें और उसे `bin/<device>.bin` के रूप में रखें
- एक patched image बनाएं जो bl2_ext verification policy को disable कर दे
- resulting payload को device पर flash करें (helper script द्वारा fastboot माना गया है)

Commands:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by the helper script)
./flash.sh
```
If fastboot उपलब्ध नहीं है, तो आपको अपने प्लेटफ़ॉर्म के लिए एक उपयुक्त वैकल्पिक flashing method का उपयोग करना होगा।

### Build automation & payload debugging

- `build.sh` अब पहले रन पर Arm GNU Toolchain 14.2 (aarch64-none-elf) को स्वतः डाउनलोड और export करता है, इसलिए आपको cross-compilers को मैन्युअली सम्हालने की आवश्यकता नहीं है।
- `build.sh` को invoke करने से पहले `DEBUG=1` export करें ताकि payloads verbose serial prints के साथ compile हों; यह जब आप EL3 कोड पाथ्स को blind-patch कर रहे होते हैं तब बहुत मदद करता है।
- सफल बिल्ड्स दोनों `lk.patched` और `<device>-fenrir.bin` ड्रॉप करते हैं; बाद वाले में payload पहले से inject किया हुआ होता है और यही आपको flash/boot-test करना चाहिए।

## Runtime payload capabilities (EL3)

A patched bl2_ext payload कर सकता है:
- कस्टम fastboot कमांड्स रजिस्टर
- boot mode को कंट्रोल/ओवरराइड
- runtime पर built‑in bootloader functions को डायनामिकली कॉल करना
- वास्तव में unlocked होते हुए भी “lock state” को locked के रूप में spoof करना ताकि मजबूत integrity checks पास हो सकें (कुछ एनवायरनमेंट्स में अभी भी vbmeta/AVB समायोजन की आवश्यकता हो सकती है)

Limitation: Current PoCs नोट करते हैं कि runtime memory modification MMU सीमाओं के कारण fault कर सकती है; जब तक यह हल नहीं होता payloads आमतौर पर live memory writes से बचते हैं।

## Payload staging patterns (EL3)

Fenrir अपने instrumentation को तीन compile-time stages में बाँटता है: stage1 `platform_init()` से पहले चलता है, stage2 LK के fastboot entry संकेत करने से पहले चलता है, और stage3 ठीक उसी क्षण execute होता है जब LK Linux लोड करने से पहले। प्रत्येक डिवाइस हेडर `payload/devices/` के अंतर्गत उन hooks के addresses और fastboot helper symbols प्रदान करता है, इसलिए उन offsets को अपने target build के साथ synchronized रखें।

Stage2 arbitrary `fastboot oem` verbs को रजिस्टर करने के लिए सुविधाजनक स्थान है:
```c
void cmd_r0rt1z2(const char *arg, void *data, unsigned int sz) {
video_printf("r0rt1z2 was here...\n");
fastboot_info("pwned by r0rt1z2");
fastboot_okay("");
}

__attribute__((section(".text.main"))) void main(void) {
fastboot_register("oem r0rt1z2", cmd_r0rt1z2, true, false);
notify_enter_fastboot();
}
```
Stage3 यह प्रदर्शित करता है कि कैसे अस्थायी रूप से page-table attributes को पलटकर immutable strings such as Android’s “Orange State” warning को patch किया जा सकता है बिना downstream kernel access की आवश्यकता के:
```c
set_pte_rwx(0xFFFF000050f9E3AE);
strcpy((char *)0xFFFF000050f9E3AE, "Patched by stage3");
```
क्योंकि stage1 प्लेटफ़ॉर्म bring-up से पहले चलता है, यह OEM पावर/रीसेट primitives को कॉल करने या verified boot chain टूटने से पहले अतिरिक्त integrity logging डालने के लिए सही स्थान है।

## पोर्टिंग टिप्स

- Reverse engineer डिवाइस-विशिष्ट bl2_ext ताकि verification policy logic (e.g., sec_get_vfy_policy) का स्थान पता चल सके।
- policy return site या decision branch की पहचान करें और इसे “no verification required” (return 0 / unconditional allow) में patch करें।
- Offsets को पूरी तरह डिवाइस- और firmware-विशिष्ट रखें; variants के बीच addresses को reuse न करें।
- पहले एक sacrificial unit पर validate करें। flash करने से पहले एक recovery plan तैयार करें (उदा., EDL/BootROM loader/SoC-specific download mode)।
- जो डिवाइस lk2 secondary bootloader का उपयोग करते हैं या bl2_ext के लिए लॉक्ड होने पर भी “img_auth_required = 0” रिपोर्ट करते हैं, उन्हें इस बग क्लास की संवेदनशील कॉपियों के रूप में माना जाना चाहिए; Vivo X80 Pro में पहले ही रिपोर्टेड लॉक स्टेट के बावजूद verification स्किप होते देखा गया है।
- locked और unlocked दोनों राज्यों के expdb logs की तुलना करें—यदि certificate timing relock करने पर 0 ms से non-zero मान पर कूदती है, तो संभव है कि आपने सही decision point को patch किया है पर फिर भी modification छिपाने के लिए lock-state spoofing को सशक्त करना आवश्यक है।

## सुरक्षा प्रभाव

- Preloader के बाद EL3 code execution और बाकी boot path के लिए पूरी chain-of-trust का collapse।
- unsigned TEE/GZ/LK/Kernel को boot करने की क्षमता, secure/verified boot अपेक्षाओं को bypass करते हुए और persistent compromise सक्षम करना।

## डिवाइस नोट्स

- पुष्टिकृत समर्थित: Nothing Phone (2a) (Pacman)
- ज्ञात कार्यशील (अपूर्ण समर्थन): CMF Phone 1 (Tetris)
- Observed: Vivo X80 Pro reportedly did not verify bl2_ext even when locked
- इंडस्ट्री कवरेज ने अतिरिक्त lk2-based vendors को उसी लॉजिक फॉल के साथ शिप करते हुए उजागर किया है, इसलिए 2024–2025 MTK releases में और ओवरलैप की उम्मीद रखें।

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)

{{#include ../../banners/hacktricks-training.md}}
