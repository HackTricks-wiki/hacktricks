# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

यह पेज कई MediaTek platforms पर practical secure-boot break को document करता है, जिसमें device bootloader configuration (seccfg) के "unlocked" होने पर verification gap का दुरुपयोग किया जाता है। यह flaw ARM EL3 पर patched bl2_ext चलाने की अनुमति देता है, जिससे downstream signature verification disable हो जाती है, trust chain collapse हो जाती है और arbitrary unsigned TEE/GZ/LK/Kernel loading सक्षम हो जाती है।<sup>[[1]](#references)</sup>

> सावधानी: Early-boot patching में offsets गलत होने पर devices स्थायी रूप से brick हो सकते हैं। हमेशा full dumps और reliable recovery path रखें।

## Affected boot flow (MediaTek)

- Normal path: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Vulnerable path: जब seccfg को unlocked पर सेट किया जाता है, तो Preloader bl2_ext को verify करना skip कर सकता है। Preloader फिर भी EL3 पर bl2_ext में jump करता है, इसलिए crafted bl2_ext इसके बाद unverified components को load कर सकता है।

Key trust boundary:
- bl2_ext EL3 पर execute होता है और TEE, GenieZone, LK/AEE तथा kernel को verify करने के लिए responsible है। यदि bl2_ext स्वयं authenticated नहीं है, तो बाकी chain को trivially bypass किया जा सकता है।<sup>[[1]](#references)</sup>

## Root cause

Affected devices पर, जब seccfg "unlocked" state दर्शाता है, तो Preloader bl2_ext partition की authentication enforce नहीं करता। इससे attacker-controlled bl2_ext को flash करना संभव हो जाता है, जो EL3 पर चलता है।

bl2_ext के अंदर verification policy function को patch करके उसे unconditionally report कराया जा सकता है कि verification required नहीं है (या यह हमेशा succeed होती है), जिससे boot chain unsigned TEE/GZ/LK/Kernel images को accept करने के लिए मजबूर हो जाती है। क्योंकि यह patch EL3 पर चलता है, इसलिए downstream components अपने स्वयं के checks implement करते हों तब भी यह effective रहता है।<sup>[[1]](#references)</sup>

## Practical exploit chain

1. OTA/firmware packages, EDL/DA readback या hardware dumping के माध्यम से bootloader partitions (Preloader, bl2_ext, LK/AEE आदि) प्राप्त करें।
2. bl2_ext verification routine identify करें और उसे हमेशा verification skip/accept करने के लिए patch करें।
3. Fastboot, DA या similar maintenance channels का उपयोग करके modified bl2_ext flash करें, जो unlocked devices पर अभी भी allowed हैं।
4. Reboot करें; Preloader EL3 पर patched bl2_ext में jump करता है, जो फिर unsigned downstream images (patched TEE/GZ/LK/Kernel) load करता है और signature enforcement disable कर देता है।<sup>[[1]](#references)</sup>

यदि device locked (seccfg locked) के रूप में configured है, तो Preloader से bl2_ext verify करने की अपेक्षा की जाती है। उस configuration में यह attack fail हो जाएगा, जब तक कोई अन्य vulnerability unsigned bl2_ext को load करने की अनुमति न दे।

## Triage (expdb boot logs)

- bl2_ext load के आसपास के boot/expdb logs dump करें। यदि `img_auth_required = 0` है और certificate verification time लगभग 0 ms है, तो verification संभवतः skip की गई है।<sup>[[1]](#references)</sup>

Example log excerpt:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
- कुछ devices locked होने पर भी bl2_ext verification को skip कर देते हैं; lk2 secondary bootloader paths में भी यही gap दिखाई दिया है। यदि unlocked स्थिति में post-OTA Preloader `img_auth_required = 1` for bl2_ext log करता है, तो enforcement संभवतः restore हो गया है।<sup>[[1]](#references)[[2]](#references)</sup>

## Verification logic locations

- Relevant check आमतौर पर bl2_ext image के अंदर `verify_img` या `sec_img_auth` जैसे नाम वाले functions में होता है।
- Patched version function को success return करने के लिए बाध्य करता है या verification call को पूरी तरह bypass कर देता है।<sup>[[1]](#references)</sup>

Example patch approach (conceptual):
- उस function को locate करें जो TEE, GZ, LK और kernel images पर `sec_img_auth` call करता है।
- इसके body को ऐसे stub से replace करें जो तुरंत success return करे, या verification failure को handle करने वाली conditional branch को overwrite करें।

सुनिश्चित करें कि patch stack/frame setup को preserve करता हो और callers को expected status codes return करता हो।<sup>[[1]](#references)</sup>

## Fenrir PoC workflow (Nothing/CMF)

Fenrir इस issue के लिए एक reference patching toolkit है (Nothing Phone (2a) पूरी तरह supported; CMF Phone 1 आंशिक रूप से supported)।<sup>[[1]](#references)</sup> High level:
- Device bootloader image को `bin/<device>.bin` के रूप में रखें।
- ऐसा patched image build करें जो bl2_ext verification policy को disable करे।
- Resulting payload को flash करें (fastboot helper उपलब्ध है)।
```bash
./build.sh pacman                    # build from bin/pacman.bin
./build.sh pacman /path/to/boot.bin  # build from a custom bootloader path
./flash.sh                           # flash via fastboot
```
यदि fastboot उपलब्ध न हो, तो किसी अन्य flashing channel का उपयोग करें।

## EL3 patching notes

- bl2_ext ARM EL3 में execute होता है। यहां होने वाले crashes device को brick कर सकते हैं, जब तक उसे EDL/DA या test points के माध्यम से फिर से reflash न किया जाए।
- Execution path को validate करने और crashes का diagnosis करने के लिए board-specific logging/UART का उपयोग करें।
- संशोधित किए जा रहे सभी partitions का backup रखें और पहले disposable hardware पर test करें।<sup>[[1]](#references)</sup>

## Implications

- Preloader के बाद EL3 code execution और boot path के शेष भाग के लिए पूरी chain-of-trust का collapse।
- Unsigned TEE/GZ/LK/Kernel को boot करने की क्षमता, जिससे secure/verified boot expectations bypass होती हैं और persistent compromise संभव होता है।<sup>[[1]](#references)</sup>

## Device notes

- Confirmed supported: Nothing Phone (2a) (Pacman)
- Known working (incomplete support): CMF Phone 1 (Tetris)
- Observed: Vivo X80 Pro ने reportedly locked होने पर भी bl2_ext को verify नहीं किया<sup>[[1]](#references)</sup>
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) ने bl2_ext verification को फिर से enable किया; fenrir `pacman-v2.0` beta Preloader को patched LK के साथ mix करके bypass restore करता है<sup>[[3]](#references)</sup>
- Industry coverage में समान logic flaw वाले अतिरिक्त lk2-based vendors के shipping का उल्लेख है, इसलिए 2024–2025 के MTK releases में आगे भी overlap की अपेक्षा करें।<sup>[[2]](#references)[[4]](#references)</sup>

## Penumbra के साथ MTK DA readback और seccfg manipulation

Penumbra एक Rust crate/CLI/TUI है, जो USB के माध्यम से MTK preloader/bootrom के साथ interaction को DA-mode operations के लिए automate करता है। Vulnerable handset तक physical access होने पर (DA extensions allowed), यह MTK USB port को discover कर सकता है, Download Agent (DA) blob load कर सकता है और seccfg lock flipping तथा partition readback जैसे privileged commands जारी कर सकता है।<sup>[[5]](#references)</sup>

- **Environment/driver setup**: Linux पर `libudev` install करें, user को `dialout` group में जोड़ें और udev rules बनाएं, या यदि device node accessible न हो तो `sudo` के साथ चलाएं। Windows support unreliable है; project guidance के अनुसार, कभी-कभी Zadig का उपयोग करके MTK driver को WinUSB से replace करने के बाद ही यह काम करता है।
- **Workflow**: DA payload पढ़ें (जैसे, `std::fs::read("../DA_penangf.bin")`), `find_mtk_port()` के साथ MTK port के लिए poll करें और `DeviceBuilder::with_mtk_port(...).with_da_data(...)` का उपयोग करके session बनाएं। `init()` handshake पूरा करके device info gather करने के बाद, `dev_info.target_config()` bitfields के माध्यम से protections check करें (bit 0 set → SBC enabled)। DA mode में enter करें और `set_seccfg_lock_state(LockFlag::Unlock)` का प्रयास करें—यह केवल तभी सफल होगा जब device extensions स्वीकार करे। Offline analysis या patching के लिए partitions को `read_partition("lk_a", &mut progress_cb, &mut writer)` से dump किया जा सकता है।
- **Security impact**: सफल seccfg unlocking unsigned boot images के लिए flashing paths को फिर से खोल देता है, जिससे ऊपर वर्णित bl2_ext EL3 patching जैसे persistent compromises संभव होते हैं। Partition readback reverse engineering और modified images तैयार करने के लिए firmware artifacts प्रदान करता है।

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

- [1] [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [2] [Cyber Security News – Nothing Phone Code Execution Vulnerability के लिए PoC Exploit जारी](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [3] [Fenrir pacman-v2.0 release (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [4] [The Cyber Express – Fenrir PoC ने Nothing Phone 2a/CMF1 पर secure boot को तोड़ा](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)
- [5] [Penumbra – MTK DA flash/readback & seccfg tooling](https://github.com/shomykohai/penumbra)

{{#include ../../banners/hacktricks-training.md}}
