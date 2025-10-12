# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Cette page documente un contournement pratique de secure-boot sur plusieurs plateformes MediaTek en abusant d'une faille de vérification lorsque la configuration du bootloader de l'appareil (seccfg) est "unlocked". La faille permet d'exécuter un bl2_ext patché à ARM EL3 pour désactiver la vérification des signatures en aval, effondrer la chaîne de confiance et permettre le chargement arbitraire d'éléments non signés TEE/GZ/LK/Kernel.

> Caution: Early-boot patching can permanently brick devices if offsets are wrong. Always keep full dumps and a reliable recovery path.

## Affected boot flow (MediaTek)

- Normal path: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Vulnerable path: When seccfg is set to unlocked, Preloader may skip verifying bl2_ext. Preloader still jumps into bl2_ext at EL3, so a crafted bl2_ext can load unverified components thereafter.

Key trust boundary:
- bl2_ext executes at EL3 and is responsible for verifying TEE, GenieZone, LK/AEE and the kernel. If bl2_ext itself is not authenticated, the rest of the chain is trivially bypassed.

## Root cause

On affected devices, the Preloader does not enforce authentication of the bl2_ext partition when seccfg indicates an "unlocked" state. This allows flashing an attacker-controlled bl2_ext that runs at EL3.

Inside bl2_ext, the verification policy function can be patched to unconditionally report that verification is not required. A minimal conceptual patch is:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Avec ce changement, toutes les images suivantes (TEE, GZ, LK/AEE, Kernel) sont acceptées sans vérifications cryptographiques lorsqu'elles sont chargées par le bl2_ext patché s'exécutant en EL3.

## Comment trier une cible (expdb logs)

Dump/inspect boot logs (e.g., expdb) around the bl2_ext load. Si img_auth_required = 0 et que le temps de vérification du certificat est d'environ 0 ms, l'enforcement est probablement désactivé et l'appareil est exploitable.

Extrait de log (exemple):
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Remarque : d'après certains rapports, certains appareils sauteraient la vérification bl2_ext même avec un bootloader verrouillé, ce qui aggrave l'impact.

## Flux de travail d'exploitation pratique (Fenrir PoC)

Fenrir est un outil de référence d'exploit/patching pour cette classe de vulnérabilités. Il prend en charge Nothing Phone (2a) (Pacman) et fonctionne (avec support incomplet) sur CMF Phone 1 (Tetris). Le portage vers d'autres modèles nécessite le reverse engineering du bl2_ext spécifique à l'appareil.

Processus global :
- Obtenez l'image du bootloader de l'appareil pour votre nom de code cible et placez-la en bin/<device>.bin
- Construisez une image patchée qui désactive la politique de vérification bl2_ext
- Flashez le payload résultant sur l'appareil (fastboot présupposé par le script d'assistance)

Commandes:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by helper script)
./flash.sh
```
If fastboot n'est pas disponible, vous devez utiliser une méthode de flashage alternative adaptée à votre plateforme.

## Runtime payload capabilities (EL3)

Un payload bl2_ext patché peut :
- Enregistrer des commandes fastboot personnalisées
- Contrôler/écraser le mode de démarrage
- Appeler dynamiquement des fonctions intégrées du bootloader à l'exécution
- Usurper l'état de verrouillage (« lock state ») comme verrouillé alors qu'il est débloqué pour passer des vérifications d'intégrité plus strictes (certains environnements peuvent néanmoins exiger des ajustements vbmeta/AVB)

Limitation : Les PoC actuels notent que la modification mémoire à l'exécution peut provoquer des fautes à cause des contraintes MMU ; les payloads évitent généralement les écritures mémoire en direct tant que cela n'est pas résolu.

## Porting tips

- Faire de la rétro‑ingénierie du bl2_ext spécifique à l'appareil pour localiser la logique de politique de vérification (par ex., sec_get_vfy_policy).
- Identifier le site de retour de la politique ou la branche de décision et le patcher pour « no verification required » (return 0 / autorisation inconditionnelle).
- Conserver des offsets entièrement spécifiques au modèle et au firmware ; ne pas réutiliser d'adresses entre variantes.
- Valider d'abord sur une unité sacrificielle. Préparer un plan de récupération (par ex., EDL/BootROM loader/mode de téléchargement spécifique au SoC) avant de flasher.

## Security impact

- Exécution de code en EL3 après Preloader et effondrement complet de la chaîne de confiance pour le reste du chemin de démarrage.
- Possibilité de booter des TEE/GZ/LK/Kernel non signés, contournant les attentes de secure/verified boot et permettant une compromission persistante.

## Detection and hardening ideas

- S'assurer que Preloader vérifie bl2_ext indépendamment de l'état seccfg.
- Imposer les résultats d'authentification et collecter des preuves d'audit (timings > 0 ms, erreurs strictes en cas de mismatch).
- L'usurpation de lock-state doit être rendue inefficace pour l'attestation (lier l'état de verrouillage aux décisions de vérification AVB/vbmeta et à l'état protégé par fusible).

## Device notes

- Confirmed supported: Nothing Phone (2a) (Pacman)
- Known working (incomplete support): CMF Phone 1 (Tetris)
- Observed : il a été rapporté que le Vivo X80 Pro ne vérifiait pas bl2_ext même lorsqu'il était verrouillé

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)

{{#include ../../banners/hacktricks-training.md}}
