# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Ova stranica dokumentuje praktičan prekid secure-boot-a na više MediaTek platformi zloupotrebom praznine u verifikaciji kada je konfiguracija bootloader-a (seccfg) "unlocked". Propust omogućava pokretanje patchovanog bl2_ext na ARM EL3 kako bi se onemogućila kasnija verifikacija potpisa, što urušava lanac poverenja i omogućava učitavanje proizvoljnih unsigned TEE/GZ/LK/Kernel slika.

> Upozorenje: Patchovanje u ranoj fazi boot-a može trajno oštetiti uređaje ako su offset-i pogrešni. Uvek čuvajte potpune dump-ove i pouzdanu putanju za oporavak.

## Affected boot flow (MediaTek)

- Normalan tok: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Ranljiv tok: Kada je seccfg podešen na unlocked, Preloader može preskočiti verifikaciju bl2_ext. Preloader i dalje skače u bl2_ext na EL3, pa crafted bl2_ext može potom učitati neverifikovane komponente.

Ključna granica poverenja:
- bl2_ext se izvršava na EL3 i odgovoran je za verifikaciju TEE, GenieZone, LK/AEE i kernel-a. Ako bl2_ext sam nije autentifikovan, ostatak lanca se trivijalno zaobilazi.

## Root cause

Na pogođenim uređajima, Preloader ne primenjuje autentifikaciju particije bl2_ext kada seccfg ukazuje na "unlocked" stanje. To omogućava flashovanje attacker-controlled bl2_ext koji se izvršava na EL3.

Unutar bl2_ext, funkcija politike verifikacije može se patch-ovati tako da bezuslovno prijavi da verifikacija nije potrebna (ili da uvek uspe), prisiljavajući boot lanac da prihvati unsigned TEE/GZ/LK/Kernel slike. Pošto se ovaj patch izvršava na EL3, efektivan je čak i ako downstream komponente imaju sopstvene provere.

## Practical exploit chain

1. Nabavite bootloader particije (Preloader, bl2_ext, LK/AEE, itd.) preko OTA/firmware paketa, EDL/DA readback-a, ili hardware dumping-a.
2. Identifikujte bl2_ext verification routine i patch-ujte je da uvek preskače/prihvata verifikaciju.
3. Flash-ujte modifikovani bl2_ext koristeći fastboot, DA, ili slične maintenance kanale koji su i dalje dozvoljeni na unlocked uređajima.
4. Reboot; Preloader skače u patch-ovani bl2_ext na EL3 koji zatim učitava unsigned downstream slike (patch-ovani TEE/GZ/LK/Kernel) i onemogućava enforcement potpisa.

Ako je uređaj podešen kao locked (seccfg locked), očekuje se da Preloader verifikuje bl2_ext. U toj konfiguraciji, ovaj napad će neuspeti osim ako neki drugi propust ne dozvoli učitavanje unsigned bl2_ext.

## Triage (expdb boot logs)

- Dump-ujte boot/expdb logove oko učitavanja bl2_ext. Ako je `img_auth_required = 0` i vreme verifikacije sertifikata je ~0 ms, verifikacija je verovatno preskočena.

Example log excerpt:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
- Neki uređaji preskaču verifikaciju bl2_ext čak i kada su zaključani; lk2 sekundarni bootloader putevi su pokazali istu rupu. Ako post-OTA Preloader prijavi `img_auth_required = 1` za bl2_ext dok je uređaj otključan, verovatno je sprovođenje ponovo uspostavljeno.

## Lokacije logike verifikacije

- Relevantna provera obično se nalazi unutar bl2_ext image u funkcijama koje se zovu slično kao `verify_img` ili `sec_img_auth`.
- Patchovana verzija prisiljava funkciju da vrati uspeh ili da potpuno zaobiđe poziv verifikacije.

Example patch approach (conceptual):
- Pronađite funkciju koja poziva `sec_img_auth` na TEE, GZ, LK i kernel images.
- Zamenite telo funkcije stub-om koji odmah vraća uspeh, ili prepišite uslovnu granu koja obrađuje neuspeh verifikacije.

Osigurajte da patch čuva podešavanje stack/frame i vraća očekivane status kodove pozivaocima.

## Fenrir PoC radni tok (Nothing/CMF)

Fenrir je referentni patching toolkit za ovaj problem (Nothing Phone (2a) u potpunosti podržan; CMF Phone 1 delimično). Opšti pregled:
- Postavite device bootloader image kao `bin/<device>.bin`.
- Sastavite patched image koji onemogućava bl2_ext verification policy.
- Flash-ujte nastali payload (fastboot helper obezbeđen).
```bash
./build.sh pacman                    # build from bin/pacman.bin
./build.sh pacman /path/to/boot.bin  # build from a custom bootloader path
./flash.sh                           # flash via fastboot
```
Koristite drugi flashing kanal ako fastboot nije dostupan.

## EL3 napomene o patchovanju

- bl2_ext izvršava se u ARM EL3. Padovi ovde mogu brick-ovati uređaj dok se ne reflashuje preko EDL/DA ili test points.
- Koristite board-specific logging/UART da potvrdite putanju izvršavanja i dijagnostikujete padove.
- Sačuvajte rezervne kopije svih particija koje menjate i prvo testirajte na disposable hardveru.

## Implikaсije

- Izvršavanje EL3 koda posle Preloader-a i potpuni kolaps chain-of-trust za ostatak boot puta.
- Mogućnost boot-ovanja unsigned TEE/GZ/LK/Kernel, zaobilaženjem secure/verified boot očekivanja i omogućavajući persistent compromise.

## Napomene o uređaju

- Potvrđeno podržano: Nothing Phone (2a) (Pacman)
- Poznato da radi (nepotpuna podrška): CMF Phone 1 (Tetris)
- Primećeno: Vivo X80 Pro navodno nije verifikovao bl2_ext čak i kada je zaključan
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) ponovo je omogućio verifikaciju bl2_ext; fenrir `pacman-v2.0` vraća bypass mešanjem beta Preloader-a sa patch-ovanim LK
- Izveštaji iz industrije ukazuju na dodatne lk2-based dobavljače koji isporučuju istu logičku grešku, pa očekujte dalje preklapanje u MTK izdanjima 2024–2025.

## MTK DA readback i manipulacija seccfg pomoću Penumbra

Penumbra je Rust crate/CLI/TUI koji automatizuje interakciju sa MTK preloader/bootrom preko USB za DA-mode operacije. Sa fizičkim pristupom ranjivom handsetu (ako su DA extensions dozvoljene), može otkriti MTK USB port, učitati Download Agent (DA) blob i izdati privilegovane komande kao što su flipanje seccfg lock-a i readback particija.

- **Environment/driver setup**: Na Linuxu instalirajte `libudev`, dodajte korisnika u `dialout` grupu, i napravite udev pravila ili pokrenite sa `sudo` ako device node nije dostupan. Windows support je nepouzdan; ponekad radi samo nakon zamene MTK driver-a sa WinUSB koristeći Zadig (prema smernicama projekta).
- **Workflow**: Pročitajte DA payload (npr. `std::fs::read("../DA_penangf.bin")`), poll-ujte za MTK port sa `find_mtk_port()`, i kreirajte sesiju koristeći `DeviceBuilder::with_mtk_port(...).with_da_data(...)`. Nakon što `init()` završi handshake i prikupi device info, proverite zaštite preko `dev_info.target_config()` bitfield-ova (bit 0 postavljen → SBC enabled). Uđite u DA mode i pokušajte `set_seccfg_lock_state(LockFlag::Unlock)`—ovo uspeva samo ako uređaj prihvata extensions. Particije se mogu dump-ovati koristeći `read_partition("lk_a", &mut progress_cb, &mut writer)` za offline analizu ili patching.
- **Security impact**: Uspešno otključavanje seccfg ponovo otvara flashing puteve za unsigned boot images, omogućavajući persistent compromises kao što je bl2_ext EL3 patching opisan gore. Readback particija daje firmware artefakte za reverse engineering i kreiranje modifikovanih image-a.

<details>
<summary>Rust DA sesija + seccfg unlock + dump particija (Penumbra)</summary>
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

## Izvori

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [Fenrir pacman-v2.0 release (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [The Cyber Express – Fenrir PoC breaks secure boot on Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)
- [Penumbra – MTK DA flash/readback & seccfg tooling](https://github.com/shomykohai/penumbra)

{{#include ../../banners/hacktricks-training.md}}
