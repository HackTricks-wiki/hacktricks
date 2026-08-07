# MediaTek XFlash Carbonara Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Résumé

« Carbonara » exploite le chemin de téléchargement XFlash de MediaTek afin d’exécuter une étape Download Agent stage 2 (DA2) modifiée malgré les contrôles d’intégrité de DA1. DA1 stocke en RAM le SHA-256 attendu de DA2 et le compare avant d’effectuer le branchement. Sur de nombreux loaders, l’hôte contrôle entièrement l’adresse et la taille de chargement de DA2, ce qui fournit une écriture mémoire non vérifiée permettant d’écraser ce hash en mémoire et de rediriger l’exécution vers des payloads arbitraires (contexte pré-OS, avec invalidation du cache gérée par DA).<sup>[[1]](#references)[[2]](#references)</sup>

## Frontière de confiance dans XFlash (DA1 → DA2)

- **DA1** est signé/chargé par BootROM/Preloader. Lorsque Download Agent Authorization (DAA) est activé, seul un DA1 signé devrait s’exécuter.
- **DA2** est envoyé via USB. DA1 reçoit la **taille**, l’**adresse de chargement** et le **SHA-256**, puis calcule le hash du DA2 reçu et le compare à un **hash attendu intégré à DA1** (copié en RAM).
- **Faiblesse :** sur les loaders non corrigés, DA1 ne nettoie pas l’adresse/la taille de chargement de DA2 et conserve le hash attendu dans une zone mémoire inscriptible, ce qui permet à l’hôte de modifier le contrôle.<sup>[[1]](#references)[[2]](#references)</sup>

## Flux Carbonara (astuce des « deux BOOT_TO »)

1. **Premier `BOOT_TO` :** entrer dans le flux de staging DA1→DA2 (DA1 alloue la mémoire, prépare la DRAM et expose le buffer du hash attendu en RAM).
2. **Écrasement du slot de hash :** envoyer un petit payload qui parcourt la mémoire de DA1 à la recherche du hash attendu de DA2 stocké, puis le remplace par le SHA-256 du DA2 modifié par l’attaquant. Cela exploite le chargement contrôlé par l’utilisateur pour placer le payload à l’emplacement du hash.
3. **Second `BOOT_TO` + digest :** déclencher un autre `BOOT_TO` avec les métadonnées DA2 modifiées et envoyer le digest brut de 32 octets correspondant au DA2 modifié. DA1 recalcule le SHA-256 sur le DA2 reçu, le compare au hash attendu désormais modifié, puis le saut aboutit vers le code de l’attaquant.

Comme l’adresse et la taille de chargement sont contrôlées par l’attaquant, la même primitive peut écrire n’importe où en mémoire (et pas uniquement dans le buffer du hash), permettant des implants précoces au démarrage, des helpers de bypass du secure boot ou des rootkits malveillants.<sup>[[1]](#references)[[2]](#references)</sup>

## Schéma de PoC minimal (style mtkclient)
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
- `payload` reproduit le blob de l'outil payant qui patche le buffer du hash attendu dans DA1.
- `sha256(...).digest()` envoie des octets bruts (et non de l'hexadécimal), afin que DA1 compare avec le buffer patché.
- DA2 peut être n'importe quelle image construite par l'attaquant ; le choix de l'adresse/la taille de chargement permet un placement arbitraire en mémoire, avec l'invalidation du cache gérée par DA.<sup>[[3]](#references)</sup>

## Paysage des correctifs (loaders renforcés)

- **Mitigation** : Les DA mis à jour codent en dur l'adresse de chargement de DA2 à `0x40000000` et ignorent l'adresse fournie par l'hôte ; les écritures ne peuvent donc pas atteindre le slot du hash de DA1 (environ `0x200000`). Le hash reste calculé, mais ne peut plus être modifié par l'attaquant.
- **Détection des DA patchés** : mtkclient/penumbra analysent DA1 à la recherche de patterns indiquant le renforcement de l'adresse ; s'ils en trouvent, Carbonara est ignoré. Les anciens DA exposent des slots de hash inscriptibles (généralement autour d'offsets comme `0x22dea4` dans DA1 V5) et restent exploitables.
- **V5 vs V6** : Certains loaders V6 (XML) acceptent encore les adresses fournies par l'utilisateur ; les binaires V6 plus récents imposent généralement l'adresse fixe et sont immunisés contre Carbonara, sauf en cas de downgrade.<sup>[[2]](#references)[[3]](#references)</sup>

## Note post-Carbonara (heapb8)

MediaTek a corrigé Carbonara ; une vulnérabilité plus récente, **heapb8**, cible le handler de téléchargement de fichiers USB de DA2 sur les loaders V6 patchés, permettant l'exécution de code même lorsque `boot_to` est renforcé. Elle exploite un heap overflow lors des transferts de fichiers en chunks afin de prendre le contrôle du flux d'exécution de DA2. L'exploit est public dans Penumbra/mtk-payloads et montre que les correctifs de Carbonara ne ferment pas toute la surface d'attaque de DA.<sup>[[4]](#references)</sup>

## Notes pour le triage et le renforcement

- Les appareils dont l'adresse/la taille de DA2 ne sont pas vérifiées et où DA1 conserve le hash attendu modifiable sont vulnérables. Si un Preloader/DA ultérieur impose des limites d'adresse ou conserve le hash immuable, Carbonara est mitigé.
- L'activation de DAA et la vérification par DA1/Preloader des paramètres BOOT_TO (limites + authenticité de DA2) ferment la primitive. Corriger uniquement le patch du hash sans limiter le chargement laisse toujours un risque d'écriture arbitraire.

## Références

- [1] [Carbonara : l'exploit MediaTek que personne n'a servi](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [2] [Documentation de l'exploit Carbonara](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [3] [Code source de Carbonara dans Penumbra](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [4] [heapb8 : exploitation des Download Agents V6 patchés](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)

{{#include ../../banners/hacktricks-training.md}}
