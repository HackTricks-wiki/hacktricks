# MediaTek XFlash Carbonara Contournement du hash DA2

{{#include ../../banners/hacktricks-training.md}}

## Résumé

"Carbonara" abuse le chemin de téléchargement XFlash de MediaTek pour exécuter un Download Agent stage 2 (DA2) modifié malgré les vérifications d'intégrité de DA1. DA1 stocke le SHA-256 attendu de DA2 en RAM et le compare avant de faire le branchement. Sur de nombreux loaders, l'hôte contrôle entièrement l'adresse de chargement/size de DA2, donnant un write mémoire non vérifié qui peut écraser ce hash en mémoire et rediriger l'exécution vers des payloads arbitraires (contexte pré-OS avec invalidation de cache gérée par DA).

## Frontière de confiance dans XFlash (DA1 → DA2)

- **DA1** est signé/chargé par BootROM/Preloader. Quand Download Agent Authorization (DAA) est activé, seul un DA1 signé devrait s'exécuter.
- **DA2** est envoyé via USB. DA1 reçoit **size**, **load address**, et **SHA-256** et hache le DA2 reçu, le comparant à un **hash attendu intégré dans DA1** (copié en RAM).
- **Faiblesse :** Sur les loaders non corrigés, DA1 ne valide pas le load address/size de DA2 et conserve le hash attendu modifiable en mémoire, permettant à l'hôte d'altérer la vérification.

## Flux Carbonara (astuce "two BOOT_TO")

1. **First `BOOT_TO`:** Entrer dans le flux de staging DA1→DA2 (DA1 alloue, prépare le DRAM, et expose le tampon du hash attendu en RAM).
2. **Hash-slot overwrite:** Envoyer un petit payload qui scanne la mémoire de DA1 pour trouver le hash attendu de DA2 et l'écrase avec le SHA-256 du DA2 modifié par l'attaquant. Cela exploite le chargement contrôlé par l'utilisateur pour placer le payload là où se trouve le hash.
3. **Second `BOOT_TO` + digest:** Déclencher un autre `BOOT_TO` avec les métadonnées DA2 patchées et envoyer le digest brut de 32 octets correspondant au DA2 modifié. DA1 recompute le SHA-256 sur le DA2 reçu, le compare au hash attendu désormais patché, et le saut vers le code de l'attaquant réussit.

Parce que le load address/size sont contrôlés par l'attaquant, la même primitive peut écrire n'importe où en mémoire (pas seulement dans le tampon du hash), permettant des implants au démarrage précoce, des aides au contournement de secure-boot, ou des rootkits malveillants.

## Patron PoC minimal (mtkclient-style)
```python
if self.xsend(self.Cmd.BOOT_TO):
payload = bytes.fromhex("a4de2200000000002000000000000000")
if self.xsend(payload) and self.status() == 0:
import hashlib
da_hash = hashlib.sha256(self.daconfig.da2).digest()
if self.xsend(da_hash):
self.status()
self.info("All good!")
```
- `payload` réplique le blob de l'outil payant qui patches le tampon expected-hash à l'intérieur de DA1.
- `sha256(...).digest()` envoie des octets bruts (pas hex) donc DA1 compare contre le tampon patched.
- DA2 peut être n'importe quelle image construite par l'attaquant ; le choix de load address/size permet un placement mémoire arbitraire, l'invalidation du cache étant gérée par DA.

## Notes pour le triage et le durcissement

- Les appareils où l'adresse/size de DA2 ne sont pas vérifiées et DA1 garde l'expected-hash modifiable sont vulnérables. Si un Preloader/DA ultérieur applique des limites d'adresse ou garde le hash immuable, Carbonara est atténué.
- Activer DAA et s'assurer que DA1/Preloader valident les paramètres BOOT_TO (bornes + authenticité de DA2) ferme la primitive. Fermer seulement le hash patch sans borner le load laisse toujours un risque d'écriture arbitraire.

## Références

- [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)

{{#include ../../banners/hacktricks-training.md}}
