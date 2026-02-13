# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unaelezea uvunjaji wa Secure-Boot wa vitendo katika majukwaa mbalimbali ya MediaTek kwa kuchukua faida ya pengo la uthibitishaji wakati usanidi wa bootloader (seccfg) umewekwa "unlocked". Hitilafu inaruhusu kuendesha bl2_ext iliyorekebishwa kwenye ARM EL3 ili kuzima downstream signature verification, kupunguza chain of trust na kuwezesha kupakia TEE/GZ/LK/Kernel zisizotiwa saini.

> Tahadhari: Urekebishaji mapema wa boot unaweza kuharibu kifaa kabisa ikiwa offsets sio sahihi. Daima hifadhi full dumps na njia thabiti ya recovery.

## Affected boot flow (MediaTek)

- Normal path: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Vulnerable path: When seccfg is set to unlocked, Preloader may skip verifying bl2_ext. Preloader still jumps into bl2_ext at EL3, so a crafted bl2_ext can load unverified components thereafter.

Key trust boundary:
- bl2_ext executes at EL3 and is responsible for verifying TEE, GenieZone, LK/AEE and the kernel. If bl2_ext itself is not authenticated, the rest of the chain is trivially bypassed.

## Root cause

Kwenye vifaa vilivyoathiriwa, Preloader haisisitizi authentication ya partition ya bl2_ext wakati seccfg inaonyesha hali ya "unlocked". Hii inaruhusu flashing ya bl2_ext inayodhibitiwa na mshambuliaji inayofanya kazi kwenye EL3.

Ndani ya bl2_ext, verification policy function inaweza ku-patch-ikiwa ili kuripoti bila masharti kwamba verification haitegemeeki (au kila wakati inafanikiwa), ikilazimisha boot chain kukubali picha za TEE/GZ/LK/Kernel zisizo na saini. Kwa sababu patch hii inafanya kazi kwenye EL3, ni yenye ufanisi hata kama vipengele vya downstream vinafanya ukaguzi wao wenyewe.

## Practical exploit chain

1. Obtain bootloader partitions (Preloader, bl2_ext, LK/AEE, etc.) via OTA/firmware packages, EDL/DA readback, or hardware dumping.
2. Identify bl2_ext verification routine and patch it to always skip/accept verification.
3. Flash modified bl2_ext using fastboot, DA, or similar maintenance channels that are still allowed on unlocked devices.
4. Reboot; Preloader jumps to patched bl2_ext at EL3 which then loads unsigned downstream images (patched TEE/GZ/LK/Kernel) and disables signature enforcement.

If the device is configured as locked (seccfg locked), the Preloader is expected to verify bl2_ext. In that configuration, this attack will fail unless another vulnerability permits loading an unsigned bl2_ext.

## Triage (expdb boot logs)

- Dump boot/expdb logs around the bl2_ext load. If `img_auth_required = 0` and certificate verification time is ~0 ms, verification is likely skipped.

Example log excerpt:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
- Vifaa vingine vinapita uhakiki wa bl2_ext hata vinapofungwa; njia za lk2 za bootloader ya sekondari zimeonyesha pengo sawa. Ikiwa Preloader baada ya OTA inaripoti `img_auth_required = 1` kwa bl2_ext wakati imefunguliwa, utekelezaji uwezekano ulirejeshwa.

## Verification logic locations

- Uhakiki husika kwa kawaida upo ndani ya picha ya bl2_ext katika funsi zenye majina yanayofanana na `verify_img` au `sec_img_auth`.
- Toleo lililorekebishwa linawalazimisha funsi kurudisha mafanikio au kuruka kabisa wito wa uhakiki.

Mfano wa patch (kimsingi):
- Tafuta funsi inayoitisha `sec_img_auth` kwa picha za TEE, GZ, LK, na kernel.
- Badilisha mwili wake na stub inayorudisha mara moja mafanikio, au andika juu tawi la masharti linaloshughulikia kushindwa kwa uhakiki.

Hakikisha patch inahifadhi mpangilio wa stack/frame na inarudisha status codes zinazotarajiwa kwa wawaitaji.

## Fenrir PoC workflow (Nothing/CMF)

Fenrir ni toolkit ya marejeo ya patching kwa tatizo hili (Nothing Phone (2a) inasaidiwa kikamilifu; CMF Phone 1 kwa sehemu). Kwa juu ya mchakato:
- Weka picha ya bootloader ya kifaa kama `bin/<device>.bin`.
- Jenga patched image inayozima sera ya uhakiki ya bl2_ext.
- Flash payload iliyotolewa (fastboot helper imetolewa).
```bash
./build.sh pacman                    # build from bin/pacman.bin
./build.sh pacman /path/to/boot.bin  # build from a custom bootloader path
./flash.sh                           # flash via fastboot
```
Tumia njia nyingine ya ku-flash ikiwa fastboot haipatikani.

## Vidokezo vya kurekebisha EL3

- bl2_ext inatekelezwa katika ARM EL3. Kuanguka hapa kunaweza kufanya kifaa kisifanye kazi hadi kirefleshwe kupitia EDL/DA au test points.
- Tumia logging/UART maalumu ya bodi kuthibitisha njia ya utekelezaji na kuchunguza kuanguka.
- Hifadhi chelezo za partitions zote zinazobadilishwa na jaribu kwanza kwenye hardware ya majaribio.

## Matokeo

- Utekelezaji wa nambari ya EL3 baada ya Preloader na kuanguka kabisa kwa chain-of-trust kwa sehemu iliyobaki ya boot.
- Uwezo wa kuboot unsigned TEE/GZ/LK/Kernel, ukivuka matarajio ya secure/verified boot na kuwezesha kuathirika kwa kudumu.

## Vidokezo kuhusu vifaa

- Imehakikiwa inaunga mkono: Nothing Phone (2a) (Pacman)
- Inajulikana kufanya kazi (msaada haujakamilika): CMF Phone 1 (Tetris)
- Imeonekana: Vivo X80 Pro inaripotiwa haikuthibitisha bl2_ext hata ilipokuwa imefungwa
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) iliwasha tena uhakiki wa bl2_ext; fenrir `pacman-v2.0` hurudisha bypass kwa kuchanganya Preloader ya beta na LK iliyorekebishwa
- Ripoti za tasnia zinaonyesha wauzaji wa lk2-based zaidi wanaosafirisha kasoro ya mantiki ile ile, hivyo tarajia msongamano zaidi katika utolewaji wa MTK 2024–2025.

## MTK DA readback na uendeshaji wa seccfg kwa kutumia Penumbra

Penumbra ni Rust crate/CLI/TUI inayojiripia mwingiliano na MTK preloader/bootrom kupitia USB kwa ajili ya shughuli za DA-mode. Ikiwa una upatikanaji wa kimwili wa handset iliyo na uharibifu (DA extensions zikiruhusiwa), inaweza kugundua port ya MTK USB, kupeleka Download Agent (DA) blob, na kutoa amri za cheo kama kubadilisha seccfg lock na partition readback.

- **Environment/driver setup**: Kwenye Linux install `libudev`, ongeza mtumiaji kwa kundi la `dialout`, na tengeneza udev rules au endesha kwa `sudo` ikiwa device node haipatikani. Msaada wa Windows sio thabiti; wakati mwingine hufanya kazi tu baada ya kubadilisha MTK driver na WinUSB kwa kutumia Zadig (kulingana na mwongozo wa project).
- **Workflow**: Soma DA payload (mfano, `std::fs::read("../DA_penangf.bin")`), dumu kwa port ya MTK na `find_mtk_port()`, na unda session kwa kutumia `DeviceBuilder::with_mtk_port(...).with_da_data(...)`. Baada `init()` inakamilisha handshake na kukusanya taarifa za kifaa, angalia ulinzi kupitia bitfields za `dev_info.target_config()` (bit 0 imewekwa → SBC imewezeshwa). Ingia DA mode na jaribu `set_seccfg_lock_state(LockFlag::Unlock)`—hii inafanikiwa tu ikiwa kifaa kinakubali extensions. Partitions zinaweza kuzuliwa kwa `read_partition("lk_a", &mut progress_cb, &mut writer)` kwa uchambuzi offline au patching.
- **Security impact**: Kufungua seccfg kwa mafanikio kunafungua tena njia za flashing kwa boot images zisizosainiwa, kuziwezesha kuathirika kwa kudumu kama EL3 bl2_ext patching iliyoelezewa hapo juu. Partition readback hutoa artifacts za firmware kwa ajili ya reverse engineering na kutengeneza images zilizorekebishwa.

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

## Marejeo

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Imetolewa kwa Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [Fenrir pacman-v2.0 toleo (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [The Cyber Express – Fenrir PoC inavunja secure boot kwenye Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)
- [Penumbra – MTK DA flash/readback & seccfg tooling](https://github.com/shomykohai/penumbra)

{{#include ../../banners/hacktricks-training.md}}
