# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Cette page documente une compromission pratique du secure-boot sur plusieurs plateformes MediaTek en abusant d'une faille de vérification lorsque la configuration du bootloader (seccfg) est « unlocked ». La vulnérabilité permet d'exécuter un bl2_ext patché à ARM EL3 pour désactiver la vérification des signatures en aval, effondrant la chaîne de confiance et autorisant le chargement arbitraire de TEE/GZ/LK/Kernel non signés.

> Attention : Le patching en early-boot peut rendre les appareils définitivement inopérants si les offsets sont erronés. Conservez toujours des full dumps et un chemin de recovery fiable.

## Affected boot flow (MediaTek)

- Chemin normal : BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Chemin vulnérable : When seccfg is set to unlocked, Preloader may skip verifying bl2_ext. Preloader still jumps into bl2_ext at EL3, so a crafted bl2_ext can load unverified components thereafter.

Frontière de confiance clé :
- bl2_ext s'exécute à EL3 et est responsable de la vérification du TEE, de GenieZone, de LK/AEE et du kernel. Si bl2_ext lui-même n'est pas authentifié, le reste de la chaîne est trivialement contourné.

## Root cause

Sur les appareils affectés, le Preloader n'applique pas l'authentification de la partition bl2_ext lorsque seccfg indique l'état « unlocked ». Cela permet de flasher un bl2_ext contrôlé par un attaquant qui s'exécute à EL3.

Dans bl2_ext, la fonction de politique de vérification peut être patchée pour indiquer de manière inconditionnelle que la vérification n'est pas requise. Un patch conceptuel minimal est :
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Avec ce changement, toutes les images suivantes (TEE, GZ, LK/AEE, Kernel) sont acceptées sans vérifications cryptographiques lorsqu'elles sont chargées par le bl2_ext patché s'exécutant à EL3.

## Comment trier une cible (expdb logs)

Dump/inspect les boot logs (p.ex., expdb) autour du chargement du bl2_ext. Si img_auth_required = 0 et que le temps de vérification du certificat est ~0 ms, l'enforcement est probablement désactivé et l'appareil est exploitable.

Exemple d'extrait de log :
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Remarque : Certains appareils sauteraient la vérification bl2_ext même avec un bootloader verrouillé, ce qui aggrave l'impact.

## Flux d'exploitation pratique (Fenrir PoC)

Fenrir est un exploit/patching toolkit de référence pour cette classe de vulnérabilité. Il prend en charge Nothing Phone (2a) (Pacman) et fonctionne (de manière incomplète) sur CMF Phone 1 (Tetris). Le portage vers d'autres modèles nécessite du reverse engineering du bl2_ext spécifique à l'appareil.

Processus à haut niveau :
- Obtenez l'image du bootloader de l'appareil pour votre nom de code cible et placez-la en tant que bin/<device>.bin
- Construisez une image patchée qui désactive la politique de vérification bl2_ext
- Flashez le payload résultant sur l'appareil (fastboot supposé par le helper script)

Commandes:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by helper script)
./flash.sh
```
Si fastboot n'est pas disponible, vous devez utiliser une méthode de flashage alternative adaptée à votre plateforme.

## Capacités du payload à l'exécution (EL3)

Un payload bl2_ext patché peut :
- Enregistrer des commandes fastboot personnalisées
- Contrôler/outrepasser le mode de démarrage
- Appeler dynamiquement des fonctions intégrées du bootloader à l'exécution
- Usurper “lock state” en le faisant apparaître verrouillé alors qu'il est déverrouillé pour passer des contrôles d'intégrité plus stricts (certains environnements peuvent toujours nécessiter des ajustements vbmeta/AVB)

Limitation : Les PoCs actuels notent que la modification de la mémoire à l'exécution peut provoquer des faults en raison de contraintes MMU ; les payloads évitent généralement les écritures mémoire en direct tant que cela n'est pas résolu.

## Conseils de portage

- Reverse engineer le bl2_ext spécifique à l'appareil pour localiser la logique de la politique de vérification (par ex., sec_get_vfy_policy).
- Identifier le point de retour de la politique ou la branche de décision et le patcher pour « no verification required » (return 0 / unconditional allow).
- Conserver les offsets entièrement spécifiques à l'appareil et au firmware ; ne pas réutiliser les adresses entre variantes.
- Valider d'abord sur une unité sacrificielle. Préparer un plan de récupération (par ex., EDL/BootROM loader/mode de téléchargement spécifique SoC) avant de flasher.

## Impact sur la sécurité

- Exécution de code en EL3 après le Preloader et effondrement complet de la chaîne de confiance pour le reste du chemin de boot.
- Capacité à booter des TEE/GZ/LK/Kernel non signés, contournant les attentes de secure/verified boot et permettant une compromission persistante.

## Idées de détection et durcissement

- S'assurer que le Preloader vérifie bl2_ext indépendamment de l'état seccfg.
- Appliquer les résultats d'authentification et collecter des preuves d'audit (timings > 0 ms, erreurs strictes en cas de mismatch).
- Le spoofing du lock-state doit être rendu inefficace pour l'attestation (lier le lock state aux décisions de vérification AVB/vbmeta et à l'état lié aux fusibles).

## Notes sur les appareils

- Confirmed supported: Nothing Phone (2a) (Pacman)
- Known working (incomplete support): CMF Phone 1 (Tetris)
- Observed: Vivo X80 Pro reportedly did not verify bl2_ext even when locked

## Références

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)

{{#include ../../banners/hacktricks-training.md}}
