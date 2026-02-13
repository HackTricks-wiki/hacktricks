# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Hierdie blad dokumenteer 'n praktiese secure-boot-breek op verskeie MediaTek-platforms deur misbruik van 'n verifikasiegaping wanneer die toestel se bootloader-konfigurasie (`seccfg`) "unlocked" is. Die fout maak dit moontlik om 'n gepatchede `bl2_ext` by ARM EL3 uit te voer om downstream-handtekeningverifikasie af te skakel, wat die trust-ketting laat inklap en arbitraire unsigned TEE/GZ/LK/Kernel-lading moontlik maak.

> Waarskuwing: Vroeë-boot patching kan toestelle permanent brick as offsets verkeerd is. Hou altyd volledige dumps en 'n betroubare recovery path.

## Geaffekteerde bootstroom (MediaTek)

- Normale pad: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Kwesbare pad: Wanneer `seccfg` op unlocked gestel is, mag Preloader verifikasie van bl2_ext oorslaan. Preloader spring nog steeds na bl2_ext by EL3, so 'n gekonstrueerde bl2_ext kan daarna ongeverifieerde komponente laai.

Belangrike vertrouensgrens:
- `bl2_ext` voer by EL3 uit en is verantwoordelik vir die verifikasie van TEE, GenieZone, LK/AEE en die kernel. As `bl2_ext` self nie geverifieer is nie, word die res van die ketting triviaal omseil.

## Oorsaak

Op geaffekteerde toestelle dwing die Preloader nie die verifikasie van die `bl2_ext`-partisie af wanneer `seccfg` 'n "unlocked" toestand aandui nie. Dit laat toe om 'n deur 'n aanvaller beheerde `bl2_ext` te flash wat by EL3 loop.

Binne `bl2_ext` kan die verifikasiebeleid-funksie gepatch word om onvoorwaardelik te rapporteer dat verifikasie nie benodig word nie (of altyd slaag), wat die boot-ketting dwing om unsigned TEE/GZ/LK/Kernel-beelde te aanvaar. Omdat hierdie patch by EL3 loop, is dit effektief selfs as downstream-komponente hul eie kontroles implementeer.

## Praktiese exploit-ketting

1. Verkry bootloader-partisies (Preloader, bl2_ext, LK/AEE, ens.) via OTA/firmware-pakkette, EDL/DA readback, of hardware dumps.
2. Identifiseer die bl2_ext verifikasie-roetine en patch dit om verifikasie altyd oor te slaan/te aanvaar.
3. Flash die aangepaste bl2_ext met behulp van fastboot, DA, of soortgelyke maintenance-kanale wat nog op unlocked toestelle toegelaat word.
4. Reboot; Preloader spring na die gepatchede bl2_ext by EL3 wat dan unsigned downstream-beelde (gepatchte TEE/GZ/LK/Kernel) laai en handtekeningsafdwinging deaktiveer.

As die toestel as locked gekonfigureer is (`seccfg locked`), verwag die Preloader om `bl2_ext` te verifieer. In daardie konfigurasie sal hierdie aanval misluk tensy 'n ander kwetsbaarheid toelaat dat 'n unsigned bl2_ext gelaai word.

## Triage (expdb boot logs)

- Dump boot/expdb logs rondom die bl2_ext-laai. As `img_auth_required = 0` en sertifikaatverifikasie tyd ~0 ms is, word verifikasie waarskynlik oorgeslaan.

Example log excerpt:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
- Sommige toestelle slaan bl2_ext-verifikasie oor selfs wanneer locked; lk2 sekondêre bootloader-paaie het dieselfde gaping getoon. As 'n post-OTA Preloader `img_auth_required = 1` vir bl2_ext log terwyl dit unlocked is, is afdwinging waarskynlik herstel.

## Plekke van verifikasie-logika

- Die relevante kontrole is tipies binne die bl2_ext-image en in funksies met name soortgelyk aan `verify_img` of `sec_img_auth`.
- Die gepatchte weergawe dwing die funksie om sukses terug te gee of om die verifikasie-oproep heeltemal te omseil.

Voorbeeld patch-benadering (konseptueel):
- Lokaliseer die funksie wat `sec_img_auth` op TEE, GZ, LK, en kernel-images aanroep.
- Vervang sy liggaam met 'n stub wat onmiddellik sukses teruggee, of oorskryf die voorwaardelike tak wat verifikasie-faling hanteer.

Verseker dat die patch die stack/frame-opstelling behou en die verwagte statuskodes aan roepers teruggee.

## Fenrir PoC-werkvloei (Nothing/CMF)

Fenrir is 'n verwysings patching-toolkit vir hierdie kwessie (Nothing Phone (2a) ten volle ondersteun; CMF Phone 1 gedeeltelik). Hoëvlak:
- Plaas die toestel se bootloader-image as `bin/<device>.bin`.
- Bou 'n gepatchte image wat die bl2_ext-verifikasiebeleid deaktiveer.
- Flash die resulterende payload (fastboot helper verskaf).
```bash
./build.sh pacman                    # build from bin/pacman.bin
./build.sh pacman /path/to/boot.bin  # build from a custom bootloader path
./flash.sh                           # flash via fastboot
```
Gebruik 'n ander flashing-kanaal as fastboot nie beskikbaar is nie.

## EL3 patching notes

- bl2_ext voer uit in ARM EL3. Crashes hier kan 'n toestel brick maak totdat dit weer geflasht word via EDL/DA of toetspunte.
- Gebruik bord-spesifieke logging/UART om die uitvoerpad te valideer en krakse te diagnoseer.
- Hou rugsteun van alle partisie wat gewysig word en toets eers op weggooihardware.

## Implikasies

- EL3-kode-uitvoering ná die Preloader en volledige ketting-van-vertroue-instorting vir die res van die boot-pad.
- Vermoë om unsigned TEE/GZ/LK/Kernel te boot, die secure/verified boot-verwachtinge te omseil en volhoubare kompromittering moontlik te maak.

## Toestelnotas

- Bevestig ondersteun: Nothing Phone (2a) (Pacman)
- Bekend werkend (onvolledige ondersteuning): CMF Phone 1 (Tetris)
- Waargeneem: daar is gerapporteer dat die Vivo X80 Pro bl2_ext nie geverifieer het nie, selfs toe dit gegrendel was
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) het bl2_ext-verifikasie heraktiveer; fenrir `pacman-v2.0` herstel die omseiling deur die beta Preloader met 'n gepatchte LK te meng
- Bedryfverslaggewing beklemtoon addisionele lk2-gebaseerde verskaffers wat dieselfde logika-fout lewer, so verwag verdere oorvleueling oor 2024–2025 MTK-vrystellings.

## MTK DA readback and seccfg manipulation with Penumbra

Penumbra is 'n Rust crate/CLI/TUI wat interaksie met MTK preloader/bootrom oor USB vir DA-mode operasies outomatiseer. Met fisiese toegang tot 'n kwesbare handset (DA-uitbreidings toegelaat), kan dit die MTK USB-poort ontdek, 'n Download Agent (DA) blob laai, en bevoorregte opdragte uitreik soos seccfg slot-omkeer en partisie-readback.

- **Environment/driver setup**: Op Linux installeer `libudev`, voeg die gebruiker by die `dialout` groep, en skep udev-reëls of voer met `sudo` as die toestel-node nie toeganklik is nie. Windows-ondersteuning is onbetroubaar; dit werk soms slegs nadat die MTK driver met WinUSB vervang is deur Zadig (volgens projek-riglyne).
- **Workflow**: Lees 'n DA payload (e.g., `std::fs::read("../DA_penangf.bin")`), peil na die MTK poort met `find_mtk_port()`, en bou 'n sessie met `DeviceBuilder::with_mtk_port(...).with_da_data(...)`. Nadat `init()` die handshake voltooi en toestel-inligting versamel het, kontroleer beskermings via `dev_info.target_config()` bitfields (bit 0 set → SBC enabled). Gaan DA-mode binne en probeer `set_seccfg_lock_state(LockFlag::Unlock)`—dit slaag slegs as die toestel uitbreidings aanvaar. Partisies kan gedump word met `read_partition("lk_a", &mut progress_cb, &mut writer)` vir offline-analise of patching.
- **Security impact**: Suksesvolle seccfg-ontsluiting heropen flashing-paaie vir unsigned boot images, wat volhoubare kompromitte moontlik maak soos die bl2_ext EL3 patching hierbo beskryf. Partisie-readback verskaf firmware-artefakte vir reverse engineering en die skep van gemodifiseerde images.

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

## Verwysings

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [Fenrir pacman-v2.0 release (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [The Cyber Express – Fenrir PoC breaks secure boot on Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)
- [Penumbra – MTK DA flash/readback & seccfg tooling](https://github.com/shomykohai/penumbra)

{{#include ../../banners/hacktricks-training.md}}
