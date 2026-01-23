# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

यह पृष्ठ कई MediaTek प्लेटफ़ॉर्म पर एक व्यावहारिक secure-boot break का दस्तावेज़ है, जो उस सत्यापन अंतर का दुरुपयोग करके होता है जब डिवाइस bootloader configuration (seccfg) "unlocked" होता है। यह दोष ARM EL3 पर patched bl2_ext को चलाने की अनुमति देता है ताकि downstream signature verification को अक्षम किया जा सके, trust chain collapse हो जाए और arbitrary unsigned TEE/GZ/LK/Kernel लोड करना संभव हो जाए।

> सावधानी: Early-boot patching गलत offsets होने पर उपकरणों को स्थायी रूप से brick कर सकता है। हमेशा full dumps और एक भरोसेमंद recovery path रखें।

## प्रभावित बूट फ़्लो (MediaTek)

- सामान्य मार्ग: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- कमजोर मार्ग: जब seccfg "unlocked" पर सेट होता है, Preloader संभवतः bl2_ext के सत्यापन को छोड़ सकता है। Preloader फिर भी EL3 पर bl2_ext में jump करता है, इसलिए एक crafted bl2_ext उसके बाद unverified components लोड कर सकता है।

मुख्य ट्रस्ट सीमा:
- bl2_ext EL3 पर चलता है और TEE, GenieZone, LK/AEE और kernel के सत्यापन के लिए जिम्मेदार है। यदि bl2_ext स्वयं authenticated नहीं है, तो शेष chain आसानी से bypass किया जा सकता है।

## मूल कारण

प्रभावित उपकरणों पर, जब seccfg "unlocked" स्थिति दिखाता है तो Preloader bl2_ext partition की authentication को लागू नहीं करता। इससे attacker-controlled bl2_ext फ्लैश करने की अनुमति मिलती है जो EL3 पर चलता है।

bl2_ext के अंदर, verification policy फ़ंक्शन को पैच किया जा सकता है ताकि वह बिना शर्त रिपोर्ट करे कि verification आवश्यक नहीं है। एक न्यूनतम अवधारणात्मक पैच इस तरह है:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
इस बदलाव के साथ, बाद की सभी images (TEE, GZ, LK/AEE, Kernel) patched bl2_ext जो EL3 पर चल रहा है द्वारा लोड होने पर क्रिप्टोग्राफिक जाँचों के बिना स्वीकार कर ली जाती हैं।

## लक्ष्य का triage कैसे करें (expdb logs)

Dump/inspect boot logs (e.g., expdb) को bl2_ext load के आसपास देखें। यदि img_auth_required = 0 और certificate verification time ~0 ms है, तो enforcement संभवतः बंद है और डिवाइस exploitable है।

उदाहरण लॉग अंश:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
नोट: रिपोर्टों के अनुसार कुछ डिवाइस bl2_ext verification को स्किप कर देते हैं भले ही bootloader locked हो, जो प्रभाव को और बढ़ा देता है।

जो डिवाइस lk2 secondary bootloader के साथ शिप होते हैं, उनमें भी वही logic gap देखा गया है, इसलिए porting शुरू करने से पहले यह पुष्टि करने के लिए कि कौन सा path signatures लागू करता है, bl2_ext और lk2 दोनों partitions के expdb logs लें।

यदि किसी post-OTA Preloader ने bl2_ext के लिए img_auth_required = 1 लॉग किया है जबकि seccfg unlocked है, तो संभवतः vendor ने यह gap बंद कर दी है — नीचे दिए गए OTA persistence notes देखें।

## व्यावहारिक शोषण कार्यप्रणाली (Fenrir PoC)

Fenrir इस क्लास के मुद्दे के लिए एक reference exploit/patching toolkit है। यह Nothing Phone (2a) (Pacman) को सपोर्ट करता है और CMF Phone 1 (Tetris) पर काम करने के लिए जाना जाता है (incompletely supported)। अन्य मॉडल पर पोर्ट करने के लिए device-specific bl2_ext का reverse engineering करना आवश्यक है।

High-level process:
- अपने target codename के लिए device bootloader image प्राप्त करें और इसे `bin/<device>.bin` के रूप में रखें
- एक patched image बनाएं जो bl2_ext verification policy को disable कर दे
- बने हुए payload को डिवाइस पर फ्लैश करें (helper script द्वारा fastboot मान लिया गया है)

Commands:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by the helper script)
./flash.sh
```
यदि fastboot उपलब्ध नहीं है, तो आपको अपने प्लेटफ़ॉर्म के लिए एक उपयुक्त वैकल्पिक फ्लैशिंग विधि का उपयोग करना होगा।

### OTA-पैच्ड फर्मवेयर: bypass को जिंदा रखना (NothingOS 4, late 2025)

Nothing ने नवंबर 2025 में जारी NothingOS 4 stable OTA (build BP2A.250605.031.A3) में Preloader को पैच किया ताकि seccfg अनलॉक होने पर भी bl2_ext verification लागू हो सके। Fenrir `pacman-v2.0` फिर से काम करता है क्योंकि यह NOS 4 beta के vulnerable Preloader को stable LK payload के साथ मिला देता है:
```bash
# on Nothing Phone (2a), unlocked bootloader, in bootloader (not fastbootd)
fastboot flash preloader_a preloader_raw.img   # beta Preloader bundled with fenrir release
fastboot flash lk pacman-fenrir.bin            # patched LK containing stage hooks
fastboot reboot                                # factory reset may be needed
```
Important:
- दिए गए Preloader **only** उसी matching device/slot में फ़्लैश करें; गलत preloader तुरंत hard brick कर सकता है।
- फ़्लैश करने के बाद expdb चेक करें; img_auth_required को bl2_ext के लिए 0 पर वापस आ जाना चाहिए, जिससे पुष्टि होती है कि कमजोर Preloader आपके पैच किए गए LK से पहले execute कर रहा है।
- यदि भविष्य के OTAs Preloader और LK दोनों को पैच करते हैं, तो गैप को फिर से पैदा करने के लिए कमजोर Preloader की एक लोकल कॉपी रखें।

### Build automation & payload debugging

- `build.sh` अब पहली बार चलाने पर Arm GNU Toolchain 14.2 (aarch64-none-elf) को auto-download और export कर देता है, इसलिए आपको cross-compilers मैन्युअली संभालने की आवश्यकता नहीं है।
- `build.sh` invoke करने से पहले `DEBUG=1` export करें ताकि payloads verbose serial prints के साथ compile हों, जो blind-patching EL3 code paths करते समय बहुत मदद करते हैं।
- सफल builds दोनों `lk.patched` और `<device>-fenrir.bin` drop करते हैं; बाद वाला पहले से payload injected के साथ आता है और यही आपको flash/boot-test करना चाहिए।

## Runtime payload capabilities (EL3)

एक patched bl2_ext payload कर सकता है:
- कस्टम fastboot commands को रजिस्टर करना
- boot mode को कंट्रोल/ओवरराइड करना
- runtime पर built‑in bootloader functions को डायनामिकली कॉल करना
- मजबूत integrity checks पास करने के लिए "lock state" को locked के रूप में spoof करना जबकि वास्तव में unlocked हो (कुछ environments में अभी भी vbmeta/AVB adjustments की आवश्यकता हो सकती है)

Limitation: वर्तमान PoCs नोट करते हैं कि runtime memory modification MMU constraints के कारण fault कर सकती है; payloads आमतौर पर live memory writes से तब तक बचते हैं जब तक यह समस्या हल न हो जाए।

## Payload staging patterns (EL3)

Fenrir अपनी instrumentation को तीन compile-time stages में विभाजित करता है: stage1 `platform_init()` से पहले चलता है, stage2 तब चलता है जब LK fastboot entry signal करने से पहले होता है, और stage3 ठीक LK द्वारा Linux लोड करने से पहले execute होता है। `payload/devices/` के अंतर्गत प्रत्येक device header इन hooks के addresses और fastboot helper symbols प्रदान करता है, इसलिए उन offsets को अपने target build के साथ synchronized रखें।

Stage2 किसी भी arbitrary `fastboot oem` verbs को रजिस्टर करने के लिए एक सुविधाजनक स्थान है:
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
Stage3 यह दर्शाता है कि कैसे अस्थायी रूप से page-table attributes को flip करके immutable strings (जैसे Android’s “Orange State” warning) को patch किया जा सकता है, बिना downstream kernel access की आवश्यकता के:
```c
set_pte_rwx(0xFFFF000050f9E3AE);
strcpy((char *)0xFFFF000050f9E3AE, "Patched by stage3");
```
क्योंकि stage1 प्लेटफ़ॉर्म bring-up से पहले फायर होता है, यह OEM power/reset primitives को कॉल करने या verified boot chain को हटाने से पहले अतिरिक्त integrity logging डालने के लिए सही स्थान है।

## पोर्टिंग टिप्स

- डिवाइस-विशेष bl2_ext का Reverse engineer करके verification policy logic खोजें (उदा., sec_get_vfy_policy).
- policy return site या decision branch की पहचान करें और इसे “no verification required” (return 0 / unconditional allow) पर patch करें।
- offsets को पूरी तरह device- और firmware-specific रखें; variants के बीच addresses फिर से उपयोग न करें।
- पहले एक sacrificial unit पर validate करें। फ्लैश करने से पहले recovery plan तैयार रखें (उदा., EDL/BootROM loader/SoC-specific download mode)।
- जो डिवाइस lk2 secondary bootloader इस्तेमाल करते हैं या bl2_ext के लिए लॉक होने के बावजूद “img_auth_required = 0” रिपोर्ट करते हैं, उन्हें इस बग क्लास की vulnerable प्रतियों के रूप में माना जाना चाहिए; Vivo X80 Pro पर पहले ही रिपोर्टेड lock state के बावजूद verification skip होता देखा गया है।
- जब कोई OTA अनलॉक्ड स्टेट में bl2_ext signatures (img_auth_required = 1) लागू करना शुरू करे, तो जांचें कि क्या एक पुराना Preloader (अक्सर beta OTAs में उपलब्ध) फ्लैश करके गैप फिर से खोल सकता है, फिर नए LK के लिए updated offsets के साथ fenrir पुनः चलाएँ।

## Security impact

- Preloader के बाद EL3 code execution और बाकी boot path के लिए full chain-of-trust collapse।
- unsigned TEE/GZ/LK/Kernel को boot करने की क्षमता, secure/verified boot expectations को bypass करते हुए और persistent compromise को सक्षम करते हुए।

## Device notes

- पुष्टि हुआ समर्थित: Nothing Phone (2a) (Pacman)
- ज्ञात रूप से काम कर रहा (अपूर्ण सपोर्ट): CMF Phone 1 (Tetris)
- देखा गया: Vivo X80 Pro पर रिपोर्ट के अनुसार bl2_ext verification लॉक होने पर भी नहीं किया गया
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) ने bl2_ext verification को पुनः सक्षम किया; fenrir `pacman-v2.0` ऊपर दिखाए अनुसार beta Preloader और patched LK फ्लैश करके bypass पुनर्स्थापित करता है
- इंडस्ट्री कवरेज दर्शाती है कि अतिरिक्त lk2-based vendors वही logic flaw भेज रहे हैं, इसलिए 2024–2025 के MTK रिलीज़ में और ओवरलैप की उम्मीद रखें।

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [Fenrir pacman-v2.0 release (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [The Cyber Express – Fenrir PoC breaks secure boot on Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)

{{#include ../../banners/hacktricks-training.md}}
