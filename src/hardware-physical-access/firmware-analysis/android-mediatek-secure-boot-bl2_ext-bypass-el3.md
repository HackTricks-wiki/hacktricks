# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Cette page documente une faille pratique du secure-boot sur plusieurs plateformes MediaTek en exploitant un vide de vérification lorsque la configuration du bootloader (seccfg) est « unlocked ». La vulnérabilité permet d’exécuter un bl2_ext patché à ARM EL3 pour désactiver la vérification des signatures en aval, casser la chaîne de confiance et permettre le chargement arbitraire d’images unsigned TEE/GZ/LK/Kernel.

> Attention : le patching en early-boot peut rendre les appareils irréversiblement inutilisables si les offsets sont incorrects. Conservez toujours des dumps complets et une procédure de récupération fiable.

## Affected boot flow (MediaTek)

- Normal path: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Vulnerable path: When seccfg is set to unlocked, Preloader may skip verifying bl2_ext. Preloader still jumps into bl2_ext at EL3, so a crafted bl2_ext can load unverified components thereafter.

Key trust boundary:
- bl2_ext executes at EL3 and is responsible for verifying TEE, GenieZone, LK/AEE and the kernel. If bl2_ext itself is not authenticated, the rest of the chain is trivially bypassed.

## Root cause

On affected devices, the Preloader does not enforce authentication of the bl2_ext partition when seccfg indicates an "unlocked" state. This allows flashing an attacker-controlled bl2_ext that runs at EL3.

Inside bl2_ext, the verification policy function can be patched to unconditionally report that verification is not required (or always succeeds), forcing the boot chain to accept unsigned TEE/GZ/LK/Kernel images. Because this patch runs at EL3, it is effective even if downstream components implement their own checks.

## Practical exploit chain

1. Obtain bootloader partitions (Preloader, bl2_ext, LK/AEE, etc.) via OTA/firmware packages, EDL/DA readback, or hardware dumping.
2. Identify bl2_ext verification routine and patch it to always skip/accept verification.
3. Flash modified bl2_ext using fastboot, DA, or similar maintenance channels that are still allowed on unlocked devices.
4. Reboot; Preloader jumps to patched bl2_ext at EL3 which then loads unsigned downstream images (patched TEE/GZ/LK/Kernel) and disables signature enforcement.

If the device is configured as locked (seccfg locked), the Preloader is expected to verify bl2_ext. In that configuration, this attack will fail unless another vulnerability permits loading an unsigned bl2_ext.

## Triage (expdb boot logs)

- Récupérez les logs boot/expdb autour du chargement de bl2_ext. Si `img_auth_required = 0` et le temps de vérification du certificat est ~0 ms, la vérification est probablement ignorée.

Example log excerpt:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
- Certains appareils sautent la vérification de bl2_ext même lorsqu'ils sont verrouillés ; les chemins de bootloader secondaires lk2 ont montré la même faille. Si un Preloader post-OTA enregistre `img_auth_required = 1` pour bl2_ext alors qu'il est déverrouillé, l'application de la vérification a probablement été rétablie.

## Verification logic locations

- La vérification pertinente se trouve généralement à l'intérieur de l'image bl2_ext dans des fonctions nommées de manière similaire à `verify_img` ou `sec_img_auth`.
- La version patchée force la fonction à renvoyer un succès ou à contourner complètement l'appel de vérification.

Example patch approach (conceptual):
- Localiser la fonction qui appelle `sec_img_auth` pour les images TEE, GZ, LK et kernel.
- Remplacer son corps par un stub qui retourne immédiatement un succès, ou écraser la branche conditionnelle qui gère l'échec de la vérification.

Veiller à ce que le patch préserve la configuration de la stack/frame et renvoie aux appelants les codes d'état attendus.

## Fenrir PoC workflow (Nothing/CMF)

Fenrir est un toolkit de patching de référence pour ce problème (Nothing Phone (2a) entièrement supporté ; CMF Phone 1 partiellement). Vue d'ensemble :
- Placer l'image du bootloader de l'appareil sous `bin/<device>.bin`.
- Construire une image patchée qui désactive la politique de vérification bl2_ext.
- Flasher le payload résultant (fastboot helper fourni).
```bash
./build.sh pacman                    # build from bin/pacman.bin
./build.sh pacman /path/to/boot.bin  # build from a custom bootloader path
./flash.sh                           # flash via fastboot
```
Utilisez un autre canal de flashing si fastboot n'est pas disponible.

## Notes sur le patch EL3

- bl2_ext s'exécute en ARM EL3. Les plantages à ce niveau peuvent bricker un appareil jusqu'à ce qu'il soit reflashé via EDL/DA ou des points de test.
- Utilisez la journalisation spécifique à la carte (UART) pour valider le chemin d'exécution et diagnostiquer les plantages.
- Conservez des sauvegardes de toutes les partitions modifiées et testez d'abord sur du matériel jetable.

## Conséquences

- Exécution de code en EL3 après le Preloader et effondrement complet de la chaîne de confiance pour le reste du chemin de boot.
- Possibilité de démarrer des TEE/GZ/LK/Kernel non signés, contournant les attentes du secure/verified boot et permettant une compromission persistante.

## Notes sur les appareils

- Supporté confirmé : Nothing Phone (2a) (Pacman)
- Fonctionne (support incomplet) : CMF Phone 1 (Tetris)
- Observé : il a été rapporté que le Vivo X80 Pro ne vérifiait pas bl2_ext même lorsque verrouillé
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) a réactivé la vérification de bl2_ext ; fenrir `pacman-v2.0` restaure le contournement en mélangeant le Preloader beta avec un LK patché
- La couverture industrielle souligne que d'autres vendors basés sur lk2 livrent la même faille logique, donc attendez-vous à un chevauchement supplémentaire sur les versions MTK 2024–2025.

## MTK DA readback and seccfg manipulation with Penumbra

Penumbra est une crate/CLI/TUI Rust qui automatise l'interaction avec le preloader/bootrom MTK via USB pour les opérations en mode DA. Avec un accès physique à un handset vulnérable (extensions DA autorisées), il peut détecter le port USB MTK, charger un blob Download Agent (DA) et émettre des commandes privilégiées comme le basculement du verrou seccfg et la lecture des partitions.

- **Environment/driver setup**: On Linux install `libudev`, add the user to the `dialout` group, and create udev rules or run with `sudo` if the device node is not accessible. Windows support is unreliable; it sometimes works only after replacing the MTK driver with WinUSB using Zadig (per project guidance).
- **Workflow**: Read a DA payload (e.g., `std::fs::read("../DA_penangf.bin")`), poll for the MTK port with `find_mtk_port()`, and build a session using `DeviceBuilder::with_mtk_port(...).with_da_data(...)`. After `init()` completes the handshake and gathers device info, check protections via `dev_info.target_config()` bitfields (bit 0 set → SBC enabled). Enter DA mode and attempt `set_seccfg_lock_state(LockFlag::Unlock)`—this only succeeds if the device accepts extensions. Partitions can be dumped with `read_partition("lk_a", &mut progress_cb, &mut writer)` for offline analysis or patching.
- **Security impact**: Successful seccfg unlocking reopens flashing paths for unsigned boot images, enabling persistent compromises such as the bl2_ext EL3 patching described above. Partition readback provides firmware artifacts for reverse engineering and crafting modified images.

<details>
<summary>Session DA Rust + déverrouillage seccfg + dump de partition (Penumbra)</summary>
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

## Références

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [Fenrir pacman-v2.0 release (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [The Cyber Express – Fenrir PoC breaks secure boot on Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)
- [Penumbra – MTK DA flash/readback & seccfg tooling](https://github.com/shomykohai/penumbra)

{{#include ../../banners/hacktricks-training.md}}
