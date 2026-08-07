# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Cette page documente une faille pratique du secure-boot sur plusieurs plateformes MediaTek, exploitant une faille de vérification lorsque la configuration du bootloader de l'appareil (seccfg) est « unlocked ». Cette faille permet d'exécuter un bl2_ext modifié au niveau ARM EL3 afin de désactiver la vérification des signatures en aval, de réduire à néant la chaîne de confiance et de permettre le chargement arbitraire de TEE/GZ/LK/Kernel non signés.<sup>[[1]](#references)</sup>

> Attention : le patching du démarrage précoce peut briquer définitivement les appareils si les offsets sont incorrects. Conservez toujours des dumps complets ainsi qu'une méthode de récupération fiable.

## Flux de démarrage affecté (MediaTek)

- Chemin normal : BootROM → Preloader → bl2_ext (EL3, vérifié) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Chemin vulnérable : lorsque seccfg est configuré sur unlocked, le Preloader peut ignorer la vérification de bl2_ext. Le Preloader saute tout de même vers bl2_ext au niveau EL3 ; un bl2_ext spécialement conçu peut donc charger ensuite des composants non vérifiés.

Limite de confiance principale :
- bl2_ext s'exécute au niveau EL3 et est chargé de vérifier TEE, GenieZone, LK/AEE et le kernel. Si bl2_ext lui-même n'est pas authentifié, le reste de la chaîne peut être trivialement contourné.<sup>[[1]](#references)</sup>

## Cause première

Sur les appareils concernés, le Preloader n'impose pas l'authentification de la partition bl2_ext lorsque seccfg indique un état « unlocked ». Cela permet de flasher un bl2_ext contrôlé par l'attaquant, qui s'exécute au niveau EL3.

Dans bl2_ext, la fonction de politique de vérification peut être patchée afin de signaler inconditionnellement que la vérification n'est pas requise (ou qu'elle réussit toujours), forçant ainsi la chaîne de démarrage à accepter des images TEE/GZ/LK/Kernel non signées. Comme ce patch s'exécute au niveau EL3, il reste efficace même si les composants en aval implémentent leurs propres contrôles.<sup>[[1]](#references)</sup>

## Chaîne d'exploitation pratique

1. Obtenir les partitions du bootloader (Preloader, bl2_ext, LK/AEE, etc.) via des packages OTA/firmware, un readback EDL/DA ou un dump matériel.
2. Identifier la routine de vérification de bl2_ext et la patcher afin qu'elle ignore ou accepte toujours la vérification.
3. Flasher le bl2_ext modifié avec fastboot, DA ou des canaux de maintenance similaires encore autorisés sur les appareils unlocked.
4. Redémarrer ; le Preloader saute vers le bl2_ext patché au niveau EL3, qui charge ensuite des images en aval non signées (TEE/GZ/LK/Kernel patchés) et désactive l'application des signatures.<sup>[[1]](#references)</sup>

Si l'appareil est configuré comme locked (seccfg locked), le Preloader est censé vérifier bl2_ext. Dans cette configuration, cette attaque échouera, sauf si une autre vulnérabilité permet de charger un bl2_ext non signé.

## Triage (logs de démarrage expdb)

- Dumper les logs de démarrage/expdb autour du chargement de bl2_ext. Si `img_auth_required = 0` et que le temps de vérification du certificat est d'environ 0 ms, la vérification est probablement ignorée.<sup>[[1]](#references)</sup>

Extrait de log exemple :
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
- Certains appareils ignorent la vérification de bl2_ext même lorsqu'ils sont verrouillés ; les chemins du lk2 secondary bootloader ont montré la même faille. Si un Preloader post-OTA journalise `img_auth_required = 1` pour bl2_ext alors qu'il est déverrouillé, l'application de la vérification a probablement été rétablie.<sup>[[1]](#references)[[2]](#references)</sup>

## Emplacements de la logique de vérification

- La vérification pertinente se trouve généralement dans l'image bl2_ext, au sein de fonctions nommées de manière similaire à `verify_img` ou `sec_img_auth`.
- La version patchée force la fonction à retourner un succès ou contourne entièrement l'appel de vérification.<sup>[[1]](#references)</sup>

Approche de patch d'exemple (conceptuelle) :
- Localiser la fonction qui appelle `sec_img_auth` sur les images TEE, GZ, LK et kernel.
- Remplacer son corps par un stub qui retourne immédiatement un succès, ou écraser la branche conditionnelle qui gère l'échec de la vérification.

S'assurer que le patch préserve la configuration de la stack/frame et retourne aux appelants les codes d'état attendus.<sup>[[1]](#references)</sup>

## Flux du Fenrir PoC (Nothing/CMF)

Fenrir est un toolkit de patch de référence pour ce problème (Nothing Phone (2a) entièrement pris en charge ; CMF Phone 1 partiellement).<sup>[[1]](#references)</sup> À un niveau élevé :
- Placer l'image du bootloader de l'appareil dans `bin/<device>.bin`.
- Construire une image patchée qui désactive la policy de vérification de bl2_ext.
- Flasher le payload obtenu (helper fastboot fourni).
```bash
./build.sh pacman                    # build from bin/pacman.bin
./build.sh pacman /path/to/boot.bin  # build from a custom bootloader path
./flash.sh                           # flash via fastboot
```
Utilisez un autre canal de flashing si fastboot est indisponible.

## Notes de patching EL3

- bl2_ext s’exécute dans ARM EL3. Les crashes à ce niveau peuvent briquer un appareil jusqu’à ce qu’il soit reflashed via EDL/DA ou des points de test.
- Utilisez la journalisation/UART spécifique à la carte pour valider le chemin d’exécution et diagnostiquer les crashes.
- Conservez des sauvegardes de toutes les partitions modifiées et testez d’abord sur du matériel destiné aux essais.<sup>[[1]](#references)</sup>

## Implications

- Exécution de code EL3 après Preloader et effondrement complet de la chaîne de confiance pour le reste du chemin de boot.
- Possibilité de booter un TEE/GZ/LK/Kernel non signé, contournant les attentes de secure/verified boot et permettant une compromission persistante.<sup>[[1]](#references)</sup>

## Notes sur les appareils

- Support confirmé : Nothing Phone (2a) (Pacman)
- Fonctionnel connu (support incomplet) : CMF Phone 1 (Tetris)
- Observé : le Vivo X80 Pro n’aurait apparemment pas vérifié bl2_ext, même lorsqu’il était verrouillé<sup>[[1]](#references)</sup>
- NothingOS 4 stable (BP2A.250605.031.A3, novembre 2025) a réactivé la vérification de bl2_ext ; fenrir `pacman-v2.0` restaure le bypass en mélangeant le Preloader beta avec un LK patché<sup>[[3]](#references)</sup>
- La couverture du secteur met en évidence d’autres vendors basés sur lk2 qui livrent la même faille logique ; attendez-vous donc à davantage de chevauchements entre les releases MTK de 2024–2025.<sup>[[2]](#references)[[4]](#references)</sup>

## Lecture DA MTK et manipulation de seccfg avec Penumbra

Penumbra est une crate/CLI/TUI Rust qui automatise l’interaction avec le preloader/bootrom MTK via USB pour les opérations en mode DA. Avec un accès physique à un handset vulnérable (extensions DA autorisées), il peut découvrir le port USB MTK, charger un blob Download Agent (DA) et envoyer des commandes privilégiées telles que le changement de l’état de verrouillage de seccfg et la lecture des partitions.<sup>[[5]](#references)</sup>

- **Configuration de l’environnement/des drivers** : sous Linux, installez `libudev`, ajoutez l’utilisateur au groupe `dialout` et créez des règles udev, ou exécutez avec `sudo` si le device node n’est pas accessible. Le support Windows est peu fiable ; il ne fonctionne parfois qu’après remplacement du driver MTK par WinUSB avec Zadig (selon les indications du projet).
- **Workflow** : lisez un payload DA (par exemple, `std::fs::read("../DA_penangf.bin")`), recherchez le port MTK avec `find_mtk_port()` et construisez une session avec `DeviceBuilder::with_mtk_port(...).with_da_data(...)`. Une fois que `init()` a terminé le handshake et récupéré les informations de l’appareil, vérifiez les protections via les bitfields de `dev_info.target_config()` (bit 0 défini → SBC activé). Entrez en mode DA et tentez `set_seccfg_lock_state(LockFlag::Unlock)` — cette opération ne réussit que si l’appareil accepte les extensions. Les partitions peuvent être dumpées avec `read_partition("lk_a", &mut progress_cb, &mut writer)` pour une analyse offline ou un patching.
- **Impact sur la sécurité** : le déverrouillage réussi de seccfg rouvre les chemins de flashing pour les boot images non signées, permettant des compromissions persistantes telles que le patching EL3 de bl2_ext décrit ci-dessus. La lecture des partitions fournit des artefacts firmware pour le reverse engineering et la création d’images modifiées.

<details>
<summary>Session Rust DA + déverrouillage seccfg + dump de partition (Penumbra)</summary>
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

- [1] [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [2] [Cyber Security News – Exploit PoC publié pour la vulnérabilité d’exécution de code du Nothing Phone](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [3] [Fenrir pacman-v2.0 release (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [4] [The Cyber Express – Le PoC Fenrir casse le secure boot sur Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)
- [5] [Penumbra – Outils MTK DA flash/readback & seccfg](https://github.com/shomykohai/penumbra)

{{#include ../../banners/hacktricks-training.md}}
