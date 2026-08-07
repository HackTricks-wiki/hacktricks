# MediaTek bl2_ext Secure-Boot Bypass (Izvršavanje koda na EL3)

{{#include ../../banners/hacktricks-training.md}}

Ova stranica dokumentuje praktično zaobilaženje secure-boot zaštite na više MediaTek platformi zloupotrebom propusta u verifikaciji kada je konfiguracija bootloadera uređaja (seccfg) „otključana“. Propust omogućava pokretanje izmenjenog bl2_ext na ARM EL3 radi onemogućavanja naknadne verifikacije potpisa, čime se lanac poverenja urušava i omogućava učitavanje proizvoljnih nepotpisanih TEE/GZ/LK/Kernel komponenti.<sup>[[1]](#references)</sup>

> Oprez: Izmena koda u ranoj fazi pokretanja može trajno blokirati uređaje ako su offseti pogrešni. Uvek čuvajte kompletne dumpove i pouzdan način oporavka.

## Tok pokretanja (MediaTek)

- Uobičajeni put: BootROM → Preloader → bl2_ext (EL3, verifikovan) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Ranji put: Kada je seccfg podešen kao otključan, Preloader može preskočiti verifikaciju bl2_ext. Preloader i dalje skače u bl2_ext na EL3, pa posebno napravljen bl2_ext nakon toga može učitati neproverene komponente.

Ključna granica poverenja:
- bl2_ext se izvršava na EL3 i odgovoran je za verifikaciju komponenti TEE, GenieZone, LK/AEE i kernela. Ako sam bl2_ext nije autentifikovan, ostatak lanca se trivijalno zaobilazi.<sup>[[1]](#references)</sup>

## Osnovni uzrok

Na pogođenim uređajima Preloader ne zahteva autentifikaciju particije bl2_ext kada seccfg označava stanje „otključano“. To omogućava flešovanje bl2_ext-a pod kontrolom napadača, koji se izvršava na EL3.

Unutar bl2_ext-a, funkcija koja određuje pravila verifikacije može se izmeniti tako da bezuslovno prijavljuje da verifikacija nije potrebna (ili da je uvek uspešna), čime se lanac pokretanja primorava da prihvati nepotpisane TEE/GZ/LK/Kernel slike. Pošto se ova izmena izvršava na EL3, ona je delotvorna čak i ako naknadne komponente primenjuju sopstvene provere.<sup>[[1]](#references)</sup>

## Praktičan exploit chain

1. Nabavite bootloader particije (Preloader, bl2_ext, LK/AEE itd.) putem OTA/firmware paketa, EDL/DA readback-a ili hardverskog dumpovanja.
2. Identifikujte rutinu za verifikaciju bl2_ext-a i izmenite je tako da uvek preskače ili prihvata verifikaciju.
3. Flešujte izmenjeni bl2_ext koristeći fastboot, DA ili slične kanale za održavanje koji su i dalje dozvoljeni na otključanim uređajima.
4. Ponovo pokrenite uređaj; Preloader skače u izmenjeni bl2_ext na EL3, koji zatim učitava nepotpisane naknadne slike (izmenjene TEE/GZ/LK/Kernel komponente) i onemogućava proveru potpisa.<sup>[[1]](#references)</sup>

Ako je uređaj konfigurisan kao zaključan (seccfg locked), očekuje se da Preloader verifikuje bl2_ext. U toj konfiguraciji ovaj napad neće uspeti osim ako druga ranjivost ne omogući učitavanje nepotpisanog bl2_ext-a.

## Triage (expdb boot logs)

- Izbacite boot/expdb logove oko učitavanja bl2_ext-a. Ako je `img_auth_required = 0`, a vreme verifikacije sertifikata približno 0 ms, verifikacija je verovatno preskočena.<sup>[[1]](#references)</sup>

Primer dela loga:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
- Neki uređaji preskaču bl2_ext verifikaciju čak i kada su zaključani; lk2 putanje sekundarnog bootloader-a pokazale su isti propust. Ako post-OTA Preloader beleži `img_auth_required = 1` za bl2_ext dok je otključan, enforcement je verovatno vraćen.<sup>[[1]](#references)[[2]](#references)</sup>

## Lokacije logike verifikacije

- Relevantna provera se obično nalazi unutar bl2_ext image-a, u funkcijama sa nazivima sličnim `verify_img` ili `sec_img_auth`.
- Patched verzija primorava funkciju da vrati uspeh ili u potpunosti zaobilazi poziv verifikacije.<sup>[[1]](#references)</sup>

Primer pristupa patchovanju (konceptualno):
- Pronađite funkciju koja poziva `sec_img_auth` za TEE, GZ, LK i kernel images.
- Zamenite njeno telo stubom koji odmah vraća uspeh ili prepišite conditional branch koji obrađuje neuspeh verifikacije.

Uverite se da patch čuva podešavanje stack/frame-a i vraća očekivane statusne kodove pozivaocima.<sup>[[1]](#references)</sup>

## Fenrir PoC tok rada (Nothing/CMF)

Fenrir je referentni toolkit za patchovanje ovog problema (Nothing Phone (2a) je u potpunosti podržan; CMF Phone 1 delimično).<sup>[[1]](#references)</sup> Ukratko:
- Postavite image bootloader-a uređaja kao `bin/<device>.bin`.
- Napravite patched image koji onemogućava bl2_ext verification policy.
- Flashujte rezultujući payload (fastboot helper je obezbeđen).
```bash
./build.sh pacman                    # build from bin/pacman.bin
./build.sh pacman /path/to/boot.bin  # build from a custom bootloader path
./flash.sh                           # flash via fastboot
```
Koristite drugi flashing channel ako fastboot nije dostupan.

## Napomene o EL3 patching-u

- bl2_ext se izvršava u ARM EL3. Rušenja na ovom nivou mogu brick-ovati uređaj dok se ponovo ne flashuje putem EDL/DA ili test points.
- Koristite logging/UART specifičan za ploču da biste potvrdili putanju izvršavanja i dijagnostikovali rušenja.
- Napravite backup svih particija koje menjate i prvo testirajte na hardveru namenjenom za eksperimentisanje.<sup>[[1]](#references)</sup>

## Impikacije

- Izvršavanje EL3 koda nakon Preloader-a i potpunog urušavanja chain-of-trust-a za ostatak boot putanje.
- Mogućnost boot-ovanja unsigned TEE/GZ/LK/Kernel komponenti, zaobilaženje očekivanja secure/verified boot-a i omogućavanje persistent compromise-a.<sup>[[1]](#references)</sup>

## Napomene o uređajima

- Potvrđeno podržano: Nothing Phone (2a) (Pacman)
- Poznato da radi (nepotpuna podrška): CMF Phone 1 (Tetris)
- Uočeno: Vivo X80 Pro navodno nije verifikovao bl2_ext čak ni kada je bio zaključan<sup>[[1]](#references)</sup>
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) ponovo je uključio bl2_ext verifikaciju; fenrir `pacman-v2.0` vraća bypass kombinovanjem beta Preloader-a sa patch-ovanim LK-om<sup>[[3]](#references)</sup>
- Industry coverage ističe dodatne lk2-based vendore koji isporučuju istu logičku grešku, zato očekujte dodatno preklapanje među MTK izdanjima iz perioda 2024–2025.<sup>[[2]](#references)[[4]](#references)</sup>

## MTK DA readback i seccfg manipulation sa Penumbra

Penumbra je Rust crate/CLI/TUI koji automatizuje interakciju sa MTK preloader/bootrom-om preko USB-a za operacije u DA-mode-u. Uz physical access do ranjivog handset-a (uz dozvoljene DA extensions), može da otkrije MTK USB port, učita Download Agent (DA) blob i izda privilegovane komande, kao što su flipping seccfg lock-a i partition readback.<sup>[[5]](#references)</sup>

- **Podešavanje environment-a/driver-a**: Na Linux-u instalirajte `libudev`, dodajte korisnika u `dialout` grupu i kreirajte udev rules ili pokrenite sa `sudo` ako device node nije dostupan. Windows podrška je nepouzdana; ponekad radi samo nakon zamene MTK driver-a sa WinUSB-om pomoću Zadig-a (prema uputstvima projekta).
- **Workflow**: Učitajte DA payload (npr. `std::fs::read("../DA_penangf.bin")`), proveravajte MTK port pomoću `find_mtk_port()` i kreirajte session koristeći `DeviceBuilder::with_mtk_port(...).with_da_data(...)`. Nakon što `init()` završi handshake i prikupi informacije o uređaju, proverite protections putem bitfield-ova `dev_info.target_config()` (bit 0 set → SBC enabled). Uđite u DA mode i pokušajte `set_seccfg_lock_state(LockFlag::Unlock)` — ovo uspeva samo ako uređaj prihvata extensions. Particije se mogu dump-ovati pomoću `read_partition("lk_a", &mut progress_cb, &mut writer)` radi offline analysis-a ili patching-a.
- **Security impact**: Uspešan seccfg unlocking ponovo otvara flashing paths za unsigned boot images, omogućavajući persistent compromises kao što je bl2_ext EL3 patching opisan iznad. Partition readback obezbeđuje firmware artifacts za reverse engineering i izradu izmenjenih image-a.

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

## Reference

- [1] [Fenrir – MediaTek bl2_ext secure-boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [2] [Cyber Security News – Objavljen PoC exploit za ranjivost izvršavanja koda na Nothing telefonu](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [3] [Fenrir pacman-v2.0 release (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [4] [The Cyber Express – Fenrir PoC probija secure boot na Nothing Phone 2a/CMF1 uređajima](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)
- [5] [Penumbra – MTK DA flash/readback & seccfg tooling](https://github.com/shomykohai/penumbra)

{{#include ../../banners/hacktricks-training.md}}
