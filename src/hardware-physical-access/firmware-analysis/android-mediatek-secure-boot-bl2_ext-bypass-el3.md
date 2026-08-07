# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unaandika kuvunjwa kwa vitendo kwa secure-boot kwenye majukwaa kadhaa ya MediaTek kwa kutumia pengo la verification wakati usanidi wa bootloader wa kifaa (seccfg) ukiwa "unlocked". Kasoro hii inaruhusu kuendesha bl2_ext iliyopachikwa kwenye ARM EL3 ili kuzima downstream signature verification, kuvunja chain of trust na kuwezesha upakiaji wa kiholela wa TEE/GZ/LK/Kernel ambazo hazijasainiwa.<sup>[[1]](#references)</sup>

> Tahadhari: Early-boot patching inaweza ku-brick vifaa kabisa ikiwa offsets si sahihi. Daima hifadhi full dumps na njia ya kuaminika ya recovery.

## Affected boot flow (MediaTek)

- Normal path: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Vulnerable path: Wakati seccfg imewekwa kuwa unlocked, Preloader inaweza kuruka verification ya bl2_ext. Preloader bado huruka kuingia kwenye bl2_ext katika EL3, hivyo bl2_ext iliyoundwa maalum inaweza kupakia components ambazo hazijathibitishwa baadaye.

Key trust boundary:
- bl2_ext huendesha katika EL3 na inawajibika kwa verification ya TEE, GenieZone, LK/AEE na kernel. Ikiwa bl2_ext yenyewe haija-authenticate, chain iliyobaki inaweza kubypass kwa urahisi.<sup>[[1]](#references)</sup>

## Root cause

Kwenye vifaa vilivyoathirika, Preloader hailazimishi authentication ya partition ya bl2_ext wakati seccfg inaonyesha hali ya "unlocked". Hii inaruhusu kuflash bl2_ext inayodhibitiwa na attacker na inayotekelezwa katika EL3.

Ndani ya bl2_ext, function ya verification policy inaweza kupatchiwa ili iripoti bila masharti kwamba verification haihitajiki (au kwamba inafanikiwa kila wakati), na hivyo kulazimisha boot chain kukubali TEE/GZ/LK/Kernel images ambazo hazijasainiwa. Kwa kuwa patch hii huendesha katika EL3, inafanya kazi hata kama downstream components zina checks zao wenyewe.<sup>[[1]](#references)</sup>

## Practical exploit chain

1. Pata bootloader partitions (Preloader, bl2_ext, LK/AEE, n.k.) kupitia OTA/firmware packages, EDL/DA readback, au hardware dumping.
2. Tambua bl2_ext verification routine na uipatch ili iruke au ikubali verification kila wakati.
3. Flash bl2_ext iliyobadilishwa kwa kutumia fastboot, DA, au maintenance channels zinazofanana ambazo bado zinaruhusiwa kwenye vifaa vilivyo unlocked.
4. Reboot; Preloader huruka kwenda kwenye bl2_ext iliyopatchiwa katika EL3, ambayo kisha hupakia downstream images ambazo hazijasainiwa (patched TEE/GZ/LK/Kernel) na kuzima signature enforcement.<sup>[[1]](#references)</sup>

Ikiwa kifaa kimewekwa kuwa locked (seccfg locked), Preloader inatarajiwa kufanya verification ya bl2_ext. Katika usanidi huo, attack hii itashindwa isipokuwa vulnerability nyingine iruhusu kupakia bl2_ext ambayo haijasainiwa.

## Triage (expdb boot logs)

- Dump boot/expdb logs zinazohusu upakiaji wa bl2_ext. Ikiwa `img_auth_required = 0` na certificate verification time ni takriban ~0 ms, inawezekana verification imerukwa.<sup>[[1]](#references)</sup>

Example log excerpt:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
- Baadhi ya vifaa huruka uthibitishaji wa bl2_ext hata vinapokuwa vimefungwa; lk2 secondary bootloader paths zimeonyesha pengo hilo pia. Ikiwa Preloader ya baada ya OTA itaandika `img_auth_required = 1` kwa bl2_ext wakati kifaa kikiwa unlocked, huenda enforcement imerejeshwa.<sup>[[1]](#references)[[2]](#references)</sup>

## Maeneo ya verification logic

- Check inayohusika kwa kawaida hupatikana ndani ya image ya bl2_ext, katika functions zenye majina yanayofanana na `verify_img` au `sec_img_auth`.
- Toleo lililopatchiwa hulazimisha function irejeshe success au huruka kabisa verification call.<sup>[[1]](#references)</sup>

Mfano wa patch approach (wa kimawazo):
- Tafuta function inayaita `sec_img_auth` kwenye TEE, GZ, LK, na kernel images.
- Badilisha body yake iwe stub inayorejesha success mara moja, au overwrite conditional branch inayoshughulikia verification failure.

Hakikisha patch inalinda stack/frame setup na inarejesha status codes zinazotarajiwa na callers.<sup>[[1]](#references)</sup>

## Fenrir PoC workflow (Nothing/CMF)

Fenrir ni reference patching toolkit ya suala hili (Nothing Phone (2a) inaungwa mkono kikamilifu; CMF Phone 1 inaungwa mkono kwa kiasi).<sup>[[1]](#references)</sup> Kwa muhtasari:
- Weka device bootloader image kama `bin/<device>.bin`.
- Build image iliyopatchiwa inayozima bl2_ext verification policy.
- Flash payload inayotokana (fastboot helper imetolewa).
```bash
./build.sh pacman                    # build from bin/pacman.bin
./build.sh pacman /path/to/boot.bin  # build from a custom bootloader path
./flash.sh                           # flash via fastboot
```
Tumia flashing channel nyingine ikiwa fastboot haipatikani.

## Maelezo ya EL3 patching

- bl2_ext hutekelezwa katika ARM EL3. Crashes hapa zinaweza ku-brick kifaa hadi kifanyiwe reflash kupitia EDL/DA au test points.
- Tumia logging/UART maalum ya board ili kuthibitisha execution path na kuchunguza crashes.
- Hifadhi backups za partitions zote zinazorekebishwa na ufanye majaribio kwenye hardware inayoweza kutupwa kwanza.<sup>[[1]](#references)</sup>

## Athari

- EL3 code execution baada ya Preloader na kuanguka kabisa kwa chain-of-trust kwa sehemu iliyobaki ya boot path.
- Uwezo wa ku-boot TEE/GZ/LK/Kernel zisizosainiwa, kupita matarajio ya secure/verified boot na kuwezesha persistent compromise.<sup>[[1]](#references)</sup>

## Maelezo ya kifaa

- Imethibitishwa kuwa supported: Nothing Phone (2a) (Pacman)
- Inajulikana kufanya kazi (support haijakamilika): CMF Phone 1 (Tetris)
- Imeonekana: Vivo X80 Pro iliripotiwa kutokuthibitisha bl2_ext hata ikiwa locked<sup>[[1]](#references)</sup>
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) iliwezesha tena bl2_ext verification; fenrir `pacman-v2.0` inarejesha bypass kwa kuchanganya beta Preloader na LK iliyopatched<sup>[[3]](#references)</sup>
- Industry coverage inaangazia vendors wengine wanaotumia lk2 na kusafirisha logic flaw hiyo hiyo, hivyo tarajia overlap zaidi katika MTK releases za 2024–2025.<sup>[[2]](#references)[[4]](#references)</sup>

## MTK DA readback na seccfg manipulation kwa Penumbra

Penumbra ni Rust crate/CLI/TUI inayoboresha interaction na MTK preloader/bootrom kupitia USB kwa operations za DA-mode. Kwa physical access kwenye handset iliyo vulnerable (DA extensions zimeruhusiwa), inaweza kugundua MTK USB port, kupakia Download Agent (DA) blob, na kutuma privileged commands kama kubadilisha seccfg lock na kufanya partition readback.<sup>[[5]](#references)</sup>

- **Environment/driver setup**: Kwenye Linux install `libudev`, ongeza user kwenye group ya `dialout`, na uunde udev rules au endesha kwa `sudo` ikiwa device node haipatikani. Windows support si ya kutegemewa; wakati mwingine hufanya kazi tu baada ya kubadilisha MTK driver na WinUSB kwa kutumia Zadig (kulingana na mwongozo wa project).
- **Workflow**: Soma DA payload (kwa mfano, `std::fs::read("../DA_penangf.bin")`), tafuta MTK port kwa `find_mtk_port()`, na tengeneza session kwa kutumia `DeviceBuilder::with_mtk_port(...).with_da_data(...)`. Baada ya `init()` kukamilisha handshake na kukusanya device info, kagua protections kupitia bitfields za `dev_info.target_config()` (bit 0 ikiwa set → SBC enabled). Ingia DA mode na ujaribu `set_seccfg_lock_state(LockFlag::Unlock)`—hii hufaulu tu ikiwa kifaa kinakubali extensions. Partitions zinaweza kudumpiwa kwa `read_partition("lk_a", &mut progress_cb, &mut writer)` kwa offline analysis au patching.
- **Security impact**: Seccfg unlocking ikifaulu hufungua tena flashing paths kwa unsigned boot images, na kuwezesha persistent compromises kama bl2_ext EL3 patching iliyoelezwa hapo juu. Partition readback hutoa firmware artifacts kwa reverse engineering na kutengeneza images zilizorekebishwa.

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

- [1] [Fenrir – MediaTek bl2_ext secure-boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [2] [Cyber Security News – PoC Exploit Imetolewa Kwa Vulnerability ya Code Execution kwenye Nothing Phone](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [3] [Fenrir pacman-v2.0 release (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [4] [The Cyber Express – Fenrir PoC inavunja secure boot kwenye Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)
- [5] [Penumbra – MTK DA flash/readback & seccfg tooling](https://github.com/shomykohai/penumbra)

{{#include ../../banners/hacktricks-training.md}}
