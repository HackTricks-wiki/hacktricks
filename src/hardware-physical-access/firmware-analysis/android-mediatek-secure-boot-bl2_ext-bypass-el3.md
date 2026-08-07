# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy dokumenteer 'n praktiese secure-boot-breuk op verskeie MediaTek-platforms deur 'n verifikasiegaping te misbruik wanneer die toestel se bootloader-konfigurasie (seccfg) "unlocked" is. Die fout laat toe dat 'n aangepaste bl2_ext by ARM EL3 uitgevoer word om daaropvolgende signature verification te deaktiveer, wat die chain of trust ineenstort en arbitrêre unsigned TEE/GZ/LK/Kernel-laaiing moontlik maak.<sup>[[1]](#references)</sup>

> Waarskuwing: Early-boot patching kan toestelle permanent brick indien offsets verkeerd is. Hou altyd volledige dumps en 'n betroubare recovery path.

## Geaffekteerde boot flow (MediaTek)

- Normale pad: BootROM → Preloader → bl2_ext (EL3, geverifieer) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Kwesbare pad: Wanneer seccfg op unlocked gestel is, kan Preloader die verifikasie van bl2_ext oorslaan. Preloader spring steeds na bl2_ext by EL3, dus kan 'n vervaardigde bl2_ext daarna ongeverifieerde komponente laai.

Belangrike trust boundary:
- bl2_ext voer by EL3 uit en is verantwoordelik vir die verifikasie van TEE, GenieZone, LK/AEE en die kernel. Indien bl2_ext self nie geauthentiseer is nie, word die res van die chain trivially omseil.<sup>[[1]](#references)</sup>

## Root cause

Op geaffekteerde toestelle dwing die Preloader nie authentication van die bl2_ext-partisie af wanneer seccfg 'n "unlocked"-toestand aandui nie. Dit laat toe dat 'n aanvaller-beheerde bl2_ext geflash word wat by EL3 uitvoer.

Binne bl2_ext kan die verification policy function gepatch word om onvoorwaardelik aan te dui dat verifikasie nie vereis word nie (of altyd slaag), wat die boot chain dwing om unsigned TEE/GZ/LK/Kernel-images te aanvaar. Omdat hierdie patch by EL3 uitvoer, is dit effektief selfs al implementeer downstream-komponente hul eie checks.<sup>[[1]](#references)</sup>

## Praktiese exploit chain

1. Verkry bootloader-partisies (Preloader, bl2_ext, LK/AEE, ens.) via OTA/firmware-pakkette, EDL/DA readback, of hardware dumping.
2. Identifiseer die bl2_ext-verification routine en patch dit om verifikasie altyd oor te slaan/te aanvaar.
3. Flash die gewysigde bl2_ext met fastboot, DA, of soortgelyke maintenance channels wat steeds op unlocked-toestelle toegelaat word.
4. Reboot; Preloader spring na die gepatchde bl2_ext by EL3, wat dan unsigned downstream-images (gepatchde TEE/GZ/LK/Kernel) laai en signature enforcement deaktiveer.<sup>[[1]](#references)</sup>

Indien die toestel as locked gekonfigureer is (seccfg locked), word daar van die Preloader verwag om bl2_ext te verifieer. In daardie konfigurasie sal hierdie aanval misluk, tensy 'n ander kwesbaarheid die laai van 'n unsigned bl2_ext moontlik maak.

## Triage (expdb boot logs)

- Dump boot/expdb-logs rondom die bl2_ext-laaiing. Indien `img_auth_required = 0` is en certificate verification time ongeveer 0 ms is, is dit waarskynlik dat verifikasie oorgeslaan word.<sup>[[1]](#references)</sup>

Voorbeeld van 'n log-uittreksel:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
- Sommige devices slaan bl2_ext-verifikasie oor selfs wanneer dit gesluit is; lk2 secondary bootloader paths het dieselfde gaping getoon. As ’n post-OTA Preloader `img_auth_required = 1` vir bl2_ext log terwyl dit ontsluit is, is enforcement waarskynlik herstel.<sup>[[1]](#references)[[2]](#references)</sup>

## Verification logic locations

- Die relevante check is gewoonlik binne die bl2_ext image in funksies met name soortgelyk aan `verify_img` of `sec_img_auth`.
- Die patched version dwing die funksie om success terug te gee of om die verification call heeltemal te omseil.<sup>[[1]](#references)</sup>

Example patch approach (conceptual):
- Locate die funksie wat `sec_img_auth` op TEE-, GZ-, LK- en kernel images call.
- Replace die body daarvan met ’n stub wat onmiddellik success return, of overwrite die conditional branch wat verification failure hanteer.

Maak seker die patch behou stack/frame setup en die verwagte status codes aan callers return.<sup>[[1]](#references)</sup>

## Fenrir PoC workflow (Nothing/CMF)

Fenrir is ’n reference patching toolkit vir hierdie issue (Nothing Phone (2a) word volledig ondersteun; CMF Phone 1 gedeeltelik).<sup>[[1]](#references)</sup> High level:
- Place die device bootloader image as `bin/<device>.bin`.
- Build ’n patched image wat die bl2_ext verification policy disable.
- Flash die resulting payload (fastboot helper provided).
```bash
./build.sh pacman                    # build from bin/pacman.bin
./build.sh pacman /path/to/boot.bin  # build from a custom bootloader path
./flash.sh                           # flash via fastboot
```
Gebruik nog ’n flashing-kanaal as fastboot nie beskikbaar is nie.

## EL3-patching-aantekeninge

- bl2_ext voer in ARM EL3 uit. Crashes hier kan ’n toestel brick totdat dit weer via EDL/DA of test points geflash word.
- Gebruik board-spesifieke logging/UART om die uitvoeringspad te valideer en crashes te diagnoseer.
- Hou backups van alle partisies wat gewysig word en toets eers op weggooibare hardware.<sup>[[1]](#references)</sup>

## Implikasies

- EL3-code-uitvoering ná Preloader en volledige chain-of-trust-ineenstorting vir die res van die boot-pad.
- Vermoë om unsigned TEE/GZ/LK/Kernel te boot, wat secure/verified boot-verwagtinge omseil en persistente compromise moontlik maak.<sup>[[1]](#references)</sup>

## Toestel-aantekeninge

- Bevestig ondersteun: Nothing Phone (2a) (Pacman)
- Bekend werkend (onvolledige ondersteuning): CMF Phone 1 (Tetris)
- Waargeneem: Vivo X80 Pro het na bewering nie bl2_ext geverifieer nie, selfs wanneer dit gesluit was<sup>[[1]](#references)</sup>
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) het bl2_ext-verifikasie heraktiveer; fenrir `pacman-v2.0` herstel die bypass deur die beta Preloader met ’n patched LK te meng<sup>[[3]](#references)</sup>
- Industry coverage beklemtoon addisionele lk2-gebaseerde vendors wat dieselfde logic flaw verskeep; verwag dus verdere oorvleueling oor 2024–2025 MTK-releases.<sup>[[2]](#references)[[4]](#references)</sup>

## MTK DA-readback en seccfg-manipulasie met Penumbra

Penumbra is ’n Rust crate/CLI/TUI wat interaksie met MTK preloader/bootrom oor USB vir DA-mode-operasies outomatiseer. Met physical access tot ’n vulnerable handset (DA extensions toegelaat), kan dit die MTK USB-port ontdek, ’n Download Agent (DA)-blob laai en privileged commands soos seccfg lock flipping en partition readback uitvoer.<sup>[[5]](#references)</sup>

- **Environment/driver-opstelling**: Installeer `libudev` op Linux, voeg die gebruiker by die `dialout`-groep en skep udev-reëls of voer dit met `sudo` uit indien die device node nie accessible is nie. Windows support is onbetroubaar; dit werk soms slegs nadat die MTK-driver met WinUSB deur Zadig vervang is (volgens die projek se guidance).
- **Workflow**: Lees ’n DA-payload (bv. `std::fs::read("../DA_penangf.bin")`), poll vir die MTK-port met `find_mtk_port()`, en bou ’n sessie met `DeviceBuilder::with_mtk_port(...).with_da_data(...)`. Nadat `init()` die handshake voltooi en device info versamel het, kontroleer protections via `dev_info.target_config()`-bitfields (bit 0 gestel → SBC enabled). Gaan DA-mode binne en probeer `set_seccfg_lock_state(LockFlag::Unlock)`—dit slaag slegs indien die toestel extensions aanvaar. Partisies kan met `read_partition("lk_a", &mut progress_cb, &mut writer)` gedump word vir offline analysis of patching.
- **Security impact**: Suksesvolle seccfg-unlocking heropen flashing paths vir unsigned boot images, wat persistente compromises moontlik maak, soos die bl2_ext EL3-patching wat hierbo beskryf word. Partition readback verskaf firmware artifacts vir reverse engineering en die skep van modified images.

<details>
<summary>Rust DA-sessie + seccfg-unlock + partition dump (Penumbra)</summary>
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

## Verwysings

- [1] [Fenrir – MediaTek bl2_ext secure-boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [2] [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [3] [Fenrir pacman-v2.0 release (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [4] [The Cyber Express – Fenrir PoC breaks secure boot on Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)
- [5] [Penumbra – MTK DA flash/readback & seccfg tooling](https://github.com/shomykohai/penumbra)

{{#include ../../banners/hacktricks-training.md}}
