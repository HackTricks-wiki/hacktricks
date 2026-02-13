# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

यह पृष्ठ कई MediaTek प्लेटफार्मों पर एक व्यावहारिक secure-boot ब्रेक का दस्तावेज़ीकरण करता है, जो तब होता है जब डिवाइस के bootloader कॉन्फ़िगरेशन (seccfg) को "unlocked" दर्शाया गया हो और verification में एक गैप का दुरुपयोग किया जाए। इस कमजोरियों से patched bl2_ext को ARM EL3 पर चलाकर downstream signature verification को डिसेबल किया जा सकता है, जिससे विश्वास की श्रृंखला ध्वस्त हो जाती है और arbitrary unsigned TEE/GZ/LK/Kernel लोडिंग संभव हो जाती है।

> सावधानी: Early-boot patching गलत offsets होने पर उपकरणों को स्थायी रूप से brick कर सकता है। हमेशा पूर्ण डंप और एक विश्वसनीय recovery path रखें।

## प्रभावित बूट फ्लो (MediaTek)

- सामान्य मार्ग: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- कमजोर मार्ग: जब seccfg "unlocked" सेट होता है, Preloader bl2_ext का प्रमाणीकरण स्किप कर सकता है। Preloader फिर भी EL3 पर bl2_ext में jump करता है, इसलिए एक crafted bl2_ext उसके बाद unverified components लोड कर सकता है।

मुख्य ट्रस्ट सीमा:
- bl2_ext EL3 पर execute होता है और TEE, GenieZone, LK/AEE और kernel के सत्यापन के लिए जिम्मेदार है। यदि bl2_ext स्वयं authenticated नहीं है, तो शेष चेन आसानी से बाइपास हो जाती है।

## मूल कारण

प्रभावित डिवाइसों पर, Preloader bl2_ext partition के authentication को लागू नहीं करता जब seccfg "unlocked" स्थिति दिखाता है। यह attacker-controlled bl2_ext को फ्लैश करने की अनुमति देता है जो EL3 पर चलता है।

bl2_ext के अंदर, verification policy फ़ंक्शन को पैच किया जा सकता है ताकि वह बिना शर्त रिपोर्ट करे कि verification आवश्यक नहीं है (या हमेशा सफल होता है), जिससे boot chain unsigned TEE/GZ/LK/Kernel images को स्वीकार करने के लिए मजबूर हो जाती है। चूंकि यह पैच EL3 पर चलता है, यह प्रभावी होता है भले ही downstream components अपनी खुद की जाँच लागू करते हों।

## Practical exploit chain

1. bootloader partitions (Preloader, bl2_ext, LK/AEE, आदि) OTA/firmware packages, EDL/DA readback, या hardware dumping के माध्यम से प्राप्त करें।
2. bl2_ext verification routine की पहचान करें और इसे हमेशा skip/accept करने के लिए पैच करें।
3. modified bl2_ext को fastboot, DA, या समान maintenance चैनलों का उपयोग करके फ्लैश करें जो unlocked डिवाइसों पर अभी भी अनुमति हैं।
4. रीबूट करें; Preloader patched bl2_ext पर EL3 में jump करता है जो फिर unsigned downstream images (patched TEE/GZ/LK/Kernel) लोड करता है और signature enforcement को डिसेबल कर देता है।

यदि डिवाइस locked (seccfg locked) के रूप में कॉन्फ़िगर किया गया है, तो Preloader से अपेक्षा की जाती है कि वह bl2_ext को verify करे। उस कॉन्फ़िगरेशन में, यह हमला तब विफल होगा जब तक कि कोई अन्य vulnerability unsigned bl2_ext लोड करने की अनुमति न दे।

## Triage (expdb boot logs)

- bl2_ext लोड के आसपास boot/expdb logs को dump करें। यदि `img_auth_required = 0` और certificate verification time लगभग `~0 ms` है, तो verification संभवतः स्किप किया गया है।

Example log excerpt:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
- कुछ डिवाइस bl2_ext verification को तब भी skip कर देते हैं जब डिवाइस locked होता है; lk2 secondary bootloader paths ने भी वही गैप दिखाया है। अगर किसी post-OTA Preloader ने bl2_ext के लिए `img_auth_required = 1` लॉग किया है जबकि डिवाइस unlocked है, तो enforcement संभवतः पुनर्स्थापित किया गया था।

## Verification logic locations

- संबंधित चेक आम तौर पर bl2_ext image के अंदर उन फ़ंक्शनों में रहता है जिनके नाम लगभग `verify_img` या `sec_img_auth` जैसे होते हैं।
- patched version फ़ंक्शन को success लौटाने के लिए मजबूर करता है या verification कॉल को पूरी तरह बाईपास कर देता है।

Example patch approach (conceptual):
- उस फ़ंक्शन का पता लगाएँ जो TEE, GZ, LK, और kernel images पर `sec_img_auth` को कॉल करता है।
- इसके body को एक stub से बदलें जो तुरंत success लौटाए, या verification failure को हैंडल करने वाली conditional branch को overwrite कर दें।

सुनिश्चित करें कि पैच stack/frame setup को बनाए रखे और callers को अपेक्षित status codes लौटाए।

## Fenrir PoC workflow (Nothing/CMF)

Fenrir इस समस्या के लिए एक reference patching toolkit है (Nothing Phone (2a) पूर्णतः supported; CMF Phone 1 आंशिक रूप से)। उच्च-स्तरीय:
- डिवाइस bootloader image को `bin/<device>.bin` के रूप में रखें।
- एक patched image बनाएं जो bl2_ext verification policy को disabled कर दे।
- निष्पन्न payload को flash करें (fastboot helper provided)।
```bash
./build.sh pacman                    # build from bin/pacman.bin
./build.sh pacman /path/to/boot.bin  # build from a custom bootloader path
./flash.sh                           # flash via fastboot
```
यदि fastboot उपलब्ध नहीं है तो कोई अन्य फ्लैशिंग चैनल उपयोग करें।

## EL3 पैचिंग नोट्स

- bl2_ext ARM EL3 में चलती है। यहां क्रैश होने पर डिवाइस तब तक ब्रिक हो सकता है जब तक इसे EDL/DA या test points के माध्यम से फिर से फ़्लैश न किया जाए।
- बोर्ड-विशेष logging/UART का उपयोग execution path को सत्यापित करने और क्रैश का निदान करने के लिए करें।
- सभी संशोधित की जा रही partitions का बैकअप रखें और पहले डिस्पोजेबल हार्डवेयर पर परीक्षण करें।

## निहितार्थ

- Preloader के बाद EL3 कोड निष्पादन और बाकी बूट पाथ के लिए chain-of-trust का पूरा पतन।
- unsigned TEE/GZ/LK/Kernel को बूट करने की क्षमता, secure/verified boot अपेक्षाओं को बाइपास करते हुए और persistent compromise को सक्षम बनाना।

## डिवाइस नोट्स

- पुष्ट समर्थन: Nothing Phone (2a) (Pacman)
- जानकारी में काम कर रहा (अपूर्ण समर्थन): CMF Phone 1 (Tetris)
- अवलोकन: बताया गया कि Vivo X80 Pro ने bl2_ext को सत्यापित नहीं किया, भले ही लॉक्ड हो
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) ने bl2_ext सत्यापन को फिर से सक्षम किया; fenrir `pacman-v2.0` बायपास को beta Preloader को patched LK के साथ मिलाकर बहाल करता है
- उद्योग कवरेज अतिरिक्त lk2-आधारित विक्रेताओं को उजागर करता है जो वही लॉजिक फ्लॉ भेज रहे हैं, इसलिए 2024–2025 MTK रिलीज़ में और अधिक ओवरलैप की उम्मीद रखें।

## MTK DA readback और seccfg manipulation with Penumbra

Penumbra एक Rust crate/CLI/TUI है जो MTK preloader/bootrom के साथ USB पर DA-mode ऑपरेशन्स के लिए इंटरैक्शन को स्वचालित करता है। भेद्य हैंडसेट तक physical access (DA extensions की अनुमति के साथ) होने पर यह MTK USB पोर्ट का पता लगा सकता है, एक Download Agent (DA) blob लोड कर सकता है, और seccfg lock flipping और partition readback जैसे विशेषाधिकार प्राप्त कमांड जारी कर सकता है।

- **Environment/driver setup**: Linux पर `libudev` इंस्टॉल करें, user को `dialout` group में जोड़ें, और udev rules बनाएं या device node inaccessible होने पर `sudo` के साथ चलाएँ। Windows समर्थन अविश्वसनीय है; कभी-कभी यह तभी काम करता है जब MTK driver को WinUSB से Zadig का उपयोग करके बदल दिया जाए (per project guidance)।
- **Workflow**: DA payload पढ़ें (उदाहरण: `std::fs::read("../DA_penangf.bin")`), `find_mtk_port()` से MTK पोर्ट के लिए poll करें, और `DeviceBuilder::with_mtk_port(...).with_da_data(...)` का उपयोग करके एक session बनाएं। `init()` हैंडशेक पूरा करने और device info एकत्र करने के बाद, `dev_info.target_config()` bitfields के माध्यम से protections जांचें (bit 0 set → SBC enabled)। DA mode में प्रवेश करें और `set_seccfg_lock_state(LockFlag::Unlock)` का प्रयास करें—यह केवल तभी सफल होता है जब device extensions स्वीकार करे। Partitions को offline analysis या patching के लिए `read_partition("lk_a", &mut progress_cb, &mut writer)` से dump किया जा सकता है।
- **Security impact**: सफल seccfg unlocking unsigned boot images के लिए flashing पाथ्स को फिर से खोल देता है, जिससे ऊपर वर्णित bl2_ext EL3 patching जैसी persistent compromises सक्षम होती हैं। Partition readback reverse engineering और modified images बनाने के लिए firmware artifacts प्रदान करता है।

<details>
<summary>Rust DA session + seccfg unlock + partition dump (Penumbra)</summary>
```rust
use tokio::fs::File;
use anyhow::Result;
use penumbra::{DeviceBuilder, LockFlag, find_mtk_port};
use tokio::io::{AsyncWriteExt, BufWriter};

#[tokio::main]
async fn main() -> Result<()> {
let da = std::fs::read("../DA_penangf.bin")?;
let mtk_port = loop {
if let Some(port) = find_mtk_port().await {
break port;
}
};

let mut dev = DeviceBuilder::default()
.with_mtk_port(mtk_port)
.with_da_data(da)
.build()?;

dev.init().await?;
let cfg = dev.dev_info.target_config().await;
println!("SBC: {}", (cfg & 0x1) != 0);

dev.set_seccfg_lock_state(LockFlag::Unlock).await?;

let mut progress = |_read: usize, _total: usize| {};
let mut writer = BufWriter::new(File::create("lk_a.bin")?);
dev.read_partition("lk_a", &mut progress, &mut writer).await?;
writer.flush().await?;
Ok(())
}
```
</details>

## संदर्भ

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [Fenrir pacman-v2.0 release (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [The Cyber Express – Fenrir PoC breaks secure boot on Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)
- [Penumbra – MTK DA flash/readback & seccfg tooling](https://github.com/shomykohai/penumbra)

{{#include ../../banners/hacktricks-training.md}}
