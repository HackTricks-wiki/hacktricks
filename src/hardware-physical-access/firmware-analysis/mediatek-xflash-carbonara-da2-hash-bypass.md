# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Résumé

"Carbonara" abuse le chemin de téléchargement XFlash de MediaTek pour exécuter un Download Agent stage 2 (DA2) modifié malgré les contrôles d'intégrité de DA1. DA1 stocke le SHA-256 attendu de DA2 en RAM et le compare avant de faire le branchement. Sur de nombreux loaders, l'hôte contrôle entièrement l'address/size de chargement de DA2, ce qui permet une écriture mémoire non vérifiée pouvant écraser ce hash en mémoire et rediriger l'exécution vers des payloads arbitraires (contexte pré-OS avec invalidation de cache gérée par DA).

## Frontière de confiance dans XFlash (DA1 → DA2)

- **DA1** est signé/chargé par BootROM/Preloader. Lorsque Download Agent Authorization (DAA) est activé, seul DA1 signé devrait s'exécuter.
- **DA2** est envoyé via USB. DA1 reçoit **size**, **load address**, et **SHA-256** et calcule le hash du DA2 reçu, le comparant à un **expected hash embedded in DA1** (copié en RAM).
- **Faiblesse :** Sur des loaders non patchés, DA1 ne sanitize pas le DA2 load address/size et garde l'expected hash modifiable en mémoire, permettant à l'hôte de falsifier la vérification.

## Carbonara flow ("two BOOT_TO" trick)

1. **First `BOOT_TO`:** Entrer dans le flux de staging DA1→DA2 (DA1 allocates, prepares DRAM, and exposes the expected-hash buffer in RAM).
2. **Hash-slot overwrite:** Envoyer un petit payload qui scan la mémoire de DA1 pour le DA2-expected hash stocké et l'écrase avec le SHA-256 du DA2 modifié par l'attaquant. Cela exploite le load contrôlé par l'utilisateur pour positionner le payload là où le hash réside.
3. **Second `BOOT_TO` + digest:** Déclencher un autre `BOOT_TO` avec les metadata DA2 patchés et envoyer le digest brut de 32 octets correspondant au DA2 modifié. DA1 recalculera le SHA-256 sur le DA2 reçu, le compare à l'expected hash désormais patché, et le saut réussit vers le code de l'attaquant.

Parce que load address/size sont contrôlés par l'attaquant, la même primitive peut écrire n'importe où en mémoire (pas seulement le buffer de hash), permettant des implants au démarrage précoce, des aides au contournement de secure-boot, ou des rootkits malveillants.

## Minimal PoC pattern (mtkclient-style)
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
- `payload` reproduit le blob de l'outil payant qui patch le buffer expected-hash à l'intérieur de DA1.
- `sha256(...).digest()` envoie des octets bruts (pas de hex) donc DA1 compare contre le buffer patché.
- DA2 peut être n'importe quelle image construite par l'attaquant ; choisir l'adresse/taile de chargement permet le placement arbitraire en mémoire avec l'invalidation du cache gérée par DA.

## Paysage des patchs (loaders durcis)

- **Atténuation** : Les DAs mis à jour codent en dur l'adresse de chargement DA2 à `0x40000000` et ignorent l'adresse fournie par l'hôte, donc les écritures ne peuvent pas atteindre la slot de hash DA1 (~plage 0x200000). Le hash reste calculé mais n'est plus modifiable par l'attaquant.
- **Détection des DAs patchés** : mtkclient/penumbra scannent DA1 à la recherche de motifs indiquant le durcissement des adresses ; si trouvé, Carbonara est ignoré. Les anciens DAs exposent des slots de hash modifiables (typiquement autour des offsets comme `0x22dea4` dans V5 DA1) et restent exploitables.
- **V5 vs V6** : Certains loaders V6 (XML) acceptent encore des adresses fournies par l'utilisateur ; les binaires V6 plus récents imposent généralement l'adresse fixe et sont immunisés contre Carbonara sauf en cas de downgrade.

## Remarque post-Carbonara (heapb8)

MediaTek a patché Carbonara ; une vulnérabilité plus récente, **heapb8**, cible le gestionnaire de téléchargement de fichiers USB DA2 sur les loaders V6 patchés, offrant une exécution de code même lorsque `boot_to` est durci. Elle abuse d'un débordement de heap lors de transferts de fichiers fragmentés pour prendre le contrôle du flot d'exécution de DA2. L'exploit est public dans Penumbra/mtk-payloads et montre que les correctifs de Carbonara ne ferment pas toute la surface d'attaque des DA.

## Notes pour le triage et le durcissement

- Les appareils où l'adresse/taille de DA2 ne sont pas vérifiées et DA1 garde le hash attendu modifiable sont vulnérables. Si un Preloader/DA ultérieur impose des bornes d'adresse ou rend le hash immuable, Carbonara est atténuée.
- Activer DAA et s'assurer que DA1/Preloader valident les paramètres BOOT_TO (bornes + authenticité de DA2) ferme la primitive. Fermer uniquement le patch du hash sans borner le chargement laisse toujours un risque d'écriture arbitraire.

## References

- [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [heapb8: exploiting patched V6 Download Agents](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)

{{#include ../../banners/hacktricks-training.md}}
