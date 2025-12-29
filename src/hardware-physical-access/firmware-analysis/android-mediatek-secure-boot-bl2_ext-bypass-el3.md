# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Cette page documente une brèche pratique du secure-boot sur plusieurs plateformes MediaTek en abusant d'un trou de vérification lorsque la configuration du bootloader de l'appareil (seccfg) est « unlocked ». La vulnérabilité permet d'exécuter un bl2_ext patché à ARM EL3 pour désactiver la vérification des signatures en aval, effondrant la chaîne de confiance et permettant le chargement arbitraire de TEE/GZ/LK/Kernel non signés.

> Attention : le patching en early-boot peut briquer définitivement les appareils si les offsets sont incorrects. Conservez toujours des full dumps et un recovery path fiable.

## Affected boot flow (MediaTek)

- Chemin normal : BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Chemin vulnérable : Lorsque seccfg est réglé sur « unlocked », Preloader peut ne pas vérifier bl2_ext. Preloader saute néanmoins dans bl2_ext à EL3, donc un bl2_ext crafté peut charger par la suite des composants non vérifiés.

Key trust boundary:
- bl2_ext s'exécute à EL3 et est responsable de la vérification du TEE, de GenieZone, de LK/AEE et du kernel. Si bl2_ext lui-même n'est pas authentifié, le reste de la chaîne est trivialement contourné.

## Root cause

Sur les appareils affectés, le Preloader n'applique pas l'authentification de la partition bl2_ext lorsque seccfg indique un état « unlocked ». Cela permet de flasher un bl2_ext contrôlé par l'attaquant qui s'exécute à EL3.

À l'intérieur de bl2_ext, la fonction de politique de vérification peut être patchée pour indiquer inconditionnellement que la vérification n'est pas requise. Un patch conceptuel minimal est :
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Avec ce changement, toutes les images suivantes (TEE, GZ, LK/AEE, Kernel) sont acceptées sans vérifications cryptographiques lorsqu'elles sont chargées par le bl2_ext patché exécuté en EL3.

## Comment analyser une cible (expdb logs)

Dump/inspect les boot logs (e.g., expdb) autour du chargement de bl2_ext. Si img_auth_required = 0 et que le temps de vérification du certificat est d'environ 0 ms, l'enforcement est probablement désactivé et l'appareil est exploitable.

Exemple d'extrait de log:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Remarque : certains appareils sauteraient la vérification de bl2_ext même avec un bootloader verrouillé, ce qui aggrave l'impact.

Les appareils qui livrent le secondary bootloader lk2 ont été observés avec la même faille logique, donc récupérez les expdb logs pour les partitions bl2_ext et lk2 afin de confirmer si l’un des chemins applique des signatures avant d'essayer de porter.

## Flux d'exploitation pratique (Fenrir PoC)

Fenrir est un toolkit de référence pour exploit/patching pour cette classe de problèmes. Il prend en charge Nothing Phone (2a) (Pacman) et fonctionne (support incomplet) sur CMF Phone 1 (Tetris). Le portage vers d'autres modèles nécessite le reverse engineering du bl2_ext spécifique à l'appareil.

Processus à haut niveau :
- Obtenez l'image du bootloader de l'appareil pour votre nom de code cible et placez-la sous `bin/<device>.bin`
- Construisez une image patchée qui désactive la politique de vérification de bl2_ext
- Flashez le payload résultant sur l'appareil (fastboot est supposé par le helper script)

Commandes:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by the helper script)
./flash.sh
```
If fastboot is unavailable, you must use a suitable alternative flashing method for your platform.

### Automatisation de build et débogage du payload

- `build.sh` now auto-downloads and exports the Arm GNU Toolchain 14.2 (aarch64-none-elf) the first time you run it, so you do not have to juggle cross-compilers manually.
- Export `DEBUG=1` before invoking `build.sh` to compile payloads with verbose serial prints, which greatly helps when you are blind-patching EL3 code paths.
- Successful builds drop both `lk.patched` and `<device>-fenrir.bin`; the latter already has the payload injected and is what you should flash/boot-test.

## Capacités du payload à l'exécution (EL3)

A patched bl2_ext payload can:
- Enregistrer des commandes fastboot personnalisées
- Contrôler/remplacer le mode de démarrage
- Appeler dynamiquement des fonctions intégrées du bootloader à l'exécution
- Usurper l'état de verrouillage (lock state) en le présentant comme "locked" alors qu'il est "unlocked" pour passer des contrôles d'intégrité plus stricts (certains environnements peuvent néanmoins exiger des ajustements vbmeta/AVB)

Limitation : Les PoCs actuels notent que la modification de mémoire à l'exécution peut provoquer des faults en raison de contraintes MMU ; les payloads évitent généralement les écritures mémoire à chaud jusqu'à résolution de ce problème.

## Schémas de staging du payload (EL3)

Fenrir splits its instrumentation into three compile-time stages: stage1 runs before `platform_init()`, stage2 runs before LK signals fastboot entry, and stage3 executes immediately before LK loads Linux. Each device header under `payload/devices/` provides the addresses for these hooks plus fastboot helper symbols, so keep those offsets synchronized with your target build.

Stage2 is a convenient location to register arbitrary `fastboot oem` verbs:
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
Stage3 démontre comment basculer temporairement les attributs de la table des pages pour patcher des chaînes immuables telles que l’avertissement Android «Orange State» sans nécessiter d’un accès au kernel en aval :
```c
set_pte_rwx(0xFFFF000050f9E3AE);
strcpy((char *)0xFFFF000050f9E3AE, "Patched by stage3");
```
Parce que stage1 s'exécute prioritairement à la mise en route de la plateforme, c'est l'endroit approprié pour appeler les primitives d'alimentation/réinitialisation OEM ou pour insérer une journalisation d'intégrité supplémentaire avant que la chaîne de boot vérifiée ne soit démantelée.

## Conseils de portage

- Reverse engineer le bl2_ext spécifique à l'appareil pour localiser la logique de politique de vérification (e.g., sec_get_vfy_policy).
- Identifiez le site de retour de la politique ou la branche de décision et patch it to “no verification required” (return 0 / unconditional allow).
- Conservez les offsets entièrement spécifiques à l'appareil et au firmware ; ne réutilisez pas les adresses entre variantes.
- Validez d'abord sur une unité sacrificielle. Préparez un plan de récupération (e.g., EDL/BootROM loader/SoC-specific download mode) avant de flasher.
- Les appareils utilisant le secondary bootloader lk2 ou rapportant “img_auth_required = 0” pour bl2_ext même lorsqu'ils sont verrouillés doivent être traités comme des copies vulnérables de cette classe de bug ; Vivo X80 Pro a déjà été observé en train de sauter la vérification malgré un état verrouillé signalé.
- Comparez les logs expdb des états locked et unlocked — si le timing du certificat passe de 0 ms à une valeur non nulle une fois que vous re-lockez, vous avez probablement patché le bon point de décision mais devez encore durcir le spoofing de l'état de verrouillage pour masquer la modification.

## Impact sur la sécurité

- Exécution de code EL3 après le Preloader et effondrement complet de la chaîne de confiance pour le reste du chemin de boot.
- Possibilité de booter des TEE/GZ/LK/Kernel non signés, contournant les attentes de secure/verified boot et permettant une compromission persistante.

## Notes sur les appareils

- Prise en charge confirmée : Nothing Phone (2a) (Pacman)
- Fonctionnement connu (support incomplet) : CMF Phone 1 (Tetris)
- Observé : Vivo X80 Pro n'aurait apparemment pas vérifié bl2_ext même lorsqu'il était verrouillé
- La couverture industrielle met en évidence d'autres fabricants basés sur lk2 livrant le même défaut logique, donc attendez-vous à un chevauchement supplémentaire sur les releases MTK 2024–2025.

## Références

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)

{{#include ../../banners/hacktricks-training.md}}
