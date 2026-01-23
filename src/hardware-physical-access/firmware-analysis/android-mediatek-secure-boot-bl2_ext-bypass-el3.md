# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Cette page documente une faille pratique du secure-boot sur plusieurs plateformes MediaTek en abusant d'un écart de vérification lorsque la configuration du bootloader (seccfg) est "unlocked". La vulnérabilité permet d'exécuter un bl2_ext patché à ARM EL3 pour désactiver la vérification des signatures en aval, effondrant la chaîne de confiance et permettant le chargement arbitraire de TEE/GZ/LK/Kernel non signés.

> Attention : Le patching en tout début de boot peut briquer définitivement les appareils si les offsets sont incorrects. Conservez toujours des dumps complets et un chemin de récupération fiable.

## Flux de démarrage affecté (MediaTek)

- Chemin normal : BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Chemin vulnérable : Lorsque seccfg est en "unlocked", le Preloader peut ne pas vérifier bl2_ext. Le Preloader saute toujours vers bl2_ext en EL3, donc un bl2_ext conçu peut charger des composants non vérifiés par la suite.

Frontière de confiance clé :
- bl2_ext s'exécute en EL3 et est responsable de vérifier TEE, GenieZone, LK/AEE et le kernel. Si bl2_ext lui-même n'est pas authentifié, le reste de la chaîne est trivialement contourné.

## Cause racine

Sur les appareils affectés, le Preloader n'applique pas l'authentification de la partition bl2_ext lorsque seccfg indique un état "unlocked". Cela permet de flasher un bl2_ext contrôlé par un attaquant qui s'exécute en EL3.

Dans bl2_ext, la fonction de politique de vérification peut être patchée pour renvoyer inconditionnellement que la vérification n'est pas requise. Un patch conceptuel minimal est :
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Avec ce changement, toutes les images suivantes (TEE, GZ, LK/AEE, Kernel) sont acceptées sans vérifications cryptographiques lorsqu'elles sont chargées par le bl2_ext patché s'exécutant en EL3.

## Comment trier une cible (expdb logs)

Dump/inspect boot logs (e.g., expdb) autour du chargement du bl2_ext. Si img_auth_required = 0 et que certificate verification time est ~0 ms, l'enforcement est probablement désactivé et l'appareil est exploitable.

Exemple d'extrait de log :
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Note : Certains appareils sauteraient la vérification de bl2_ext même avec un bootloader verrouillé, ce qui aggrave l'impact.

Les appareils qui shipent le secondary bootloader lk2 ont été observés avec la même faille logique, donc récupérez les expdb logs pour les partitions bl2_ext et lk2 afin de confirmer si l'une ou l'autre voie applique des signatures avant d'essayer le porting.

Si un Preloader post-OTA enregistre maintenant img_auth_required = 1 pour bl2_ext même si seccfg est unlocked, le vendor a probablement colmaté la faille — voir les OTA persistence notes ci-dessous.

## Practical exploitation workflow (Fenrir PoC)

Fenrir est un toolkit de référence exploit/patching pour cette classe de problème. Il supporte Nothing Phone (2a) (Pacman) et fonctionne (avec support incomplet) sur CMF Phone 1 (Tetris). Le porting vers d'autres modèles nécessite du reverse engineering du bl2_ext spécifique à l'appareil.

High-level process:
- Obtenez l'image du bootloader de l'appareil pour votre codename cible et placez-la en tant que `bin/<device>.bin`
- Construisez une image patchée qui désactive la politique de vérification de bl2_ext
- Flashez le payload résultant sur l'appareil (fastboot présumé par le helper script)

Commands:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by the helper script)
./flash.sh
```
Si fastboot n'est pas disponible, vous devez utiliser une méthode de flashing alternative adaptée à votre plateforme.

### Firmware OTA corrigé : maintenir le contournement actif (NothingOS 4, fin 2025)

Nothing a corrigé le Preloader dans l'OTA stable NothingOS 4 de novembre 2025 (build BP2A.250605.031.A3) pour appliquer la vérification bl2_ext même lorsque seccfg est déverrouillé. Fenrir `pacman-v2.0` fonctionne à nouveau en mélangeant le Preloader vulnérable du beta NOS 4 avec le payload LK stable :
```bash
# on Nothing Phone (2a), unlocked bootloader, in bootloader (not fastbootd)
fastboot flash preloader_a preloader_raw.img   # beta Preloader bundled with fenrir release
fastboot flash lk pacman-fenrir.bin            # patched LK containing stage hooks
fastboot reboot                                # factory reset may be needed
```
Important :
- Flashez le Preloader fourni **uniquement** sur l'appareil/slot correspondant ; un Preloader incorrect provoque un hard brick instantané.
- Vérifiez expdb après le flash ; img_auth_required devrait repasser à 0 pour bl2_ext, confirmant que le Preloader vulnérable s'exécute avant votre LK patché.
- Si de futurs OTAs corrigent à la fois le Preloader et le LK, conservez une copie locale d'un Preloader vulnérable pour réintroduire la faille.

### Automatisation de la compilation et débogage des payloads

- `build.sh` télécharge et exporte automatiquement l'Arm GNU Toolchain 14.2 (aarch64-none-elf) la première fois que vous l'exécutez, vous évitant de jongler manuellement avec les cross-compilers.
- Exportez `DEBUG=1` avant d'invoquer `build.sh` pour compiler les payloads avec des serial prints verbeux, ce qui aide énormément lorsque vous faites du blind-patching sur des chemins de code EL3.
- Les builds réussis produisent `lk.patched` et `<device>-fenrir.bin` ; ce dernier contient déjà le payload injecté et c'est celui que vous devez flasher/tester au boot.

## Capacités des payloads à l'exécution (EL3)

Un payload bl2_ext patché peut :
- Enregistrer des commandes fastboot personnalisées
- Contrôler/override le boot mode
- Appeler dynamiquement des fonctions built‑in du bootloader à l'exécution
- Usurper l’« lock state » en affichant locked alors que c'est unlocked pour passer des vérifications d'intégrité plus strictes (certains environnements peuvent encore nécessiter des ajustements vbmeta/AVB)

Limitation : Les PoCs actuels notent que la modification mémoire à l'exécution peut faulter à cause des contraintes MMU ; les payloads évitent généralement les écritures mémoire en direct tant que cela n'est pas résolu.

## Modèles de staging des payloads (EL3)

Fenrir divise son instrumentation en trois étapes à la compilation : stage1 s'exécute avant `platform_init()`, stage2 s'exécute avant que LK signale l'entrée en fastboot, et stage3 s'exécute immédiatement avant que LK charge Linux. Chaque device header sous `payload/devices/` fournit les adresses pour ces hooks ainsi que les symboles d'assistance fastboot, donc gardez ces offsets synchronisés avec votre build cible.

Stage2 est un emplacement pratique pour enregistrer des verbes `fastboot oem` arbitraires :
```c
void cmd_r0rt1z2(const char *arg, void *data, unsigned int sz) {
video_printf("r0rt1z2 was here...\n");
fastboot_info("pwned by r0rt1z2");
fastboot_okay("");
}

__attribute__((section(".text.main"))) void main(void) {
fastboot_register("oem r0rt1z2", cmd_r0rt1z2, true, false);
notify_enter_fastboot();
}
```
Stage3 démontre comment basculer temporairement les attributs de page-table pour patcher des immutable strings, comme l'avertissement Android «Orange State», sans nécessiter d'accès kernel en aval:
```c
set_pte_rwx(0xFFFF000050f9E3AE);
strcpy((char *)0xFFFF000050f9E3AE, "Patched by stage3");
```
Parce que stage1 s'exécute prior to platform bring-up, c'est l'endroit approprié pour appeler les primitives power/reset OEM ou insérer une journalisation d'intégrité supplémentaire avant que la verified boot chain ne soit torn down.

## Porting tips

- Reverse engineer the device-specific bl2_ext to locate verification policy logic (e.g., sec_get_vfy_policy).
- Identify the policy return site or decision branch and patch it to “no verification required” (return 0 / unconditional allow).
- Keep offsets fully device- and firmware-specific; do not reuse addresses between variants.
- Validate on a sacrificial unit first. Prepare a recovery plan (e.g., EDL/BootROM loader/SoC-specific download mode) before you flash.
- Devices using the lk2 secondary bootloader or reporting “img_auth_required = 0” for bl2_ext even while locked should be treated as vulnerable copies of this bug class; Vivo X80 Pro has already been observed skipping verification despite a reported lock state.
- When an OTA begins enforcing bl2_ext signatures (img_auth_required = 1) in the unlocked state, check whether an older Preloader (often available in beta OTAs) can be flashed to re-open the gap, then re-run fenrir with updated offsets for the newer LK.

## Security impact

- EL3 code execution after Preloader and full chain-of-trust collapse for the rest of the boot path.
- Ability to boot unsigned TEE/GZ/LK/Kernel, bypassing secure/verified boot expectations and enabling persistent compromise.

## Device notes

- Confirmed supported: Nothing Phone (2a) (Pacman)
- Known working (incomplete support): CMF Phone 1 (Tetris)
- Observed: Vivo X80 Pro reportedly did not verify bl2_ext even when locked
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) re-enabled bl2_ext verification; fenrir `pacman-v2.0` restores the bypass by flashing the beta Preloader plus patched LK as shown above
- Industry coverage highlights additional lk2-based vendors shipping the same logic flaw, so expect further overlap across 2024–2025 MTK releases.

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [Fenrir pacman-v2.0 release (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [The Cyber Express – Fenrir PoC breaks secure boot on Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)

{{#include ../../banners/hacktricks-training.md}}
