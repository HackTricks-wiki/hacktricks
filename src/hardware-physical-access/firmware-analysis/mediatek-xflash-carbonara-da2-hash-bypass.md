# MediaTek XFlash Carbonara - Bypass du hash DA2

{{#include ../../banners/hacktricks-training.md}}

## Résumé

"Carbonara" exploite le chemin de téléchargement XFlash de MediaTek pour exécuter une étape Download Agent stage 2 (DA2) modifiée malgré les contrôles d'intégrité de DA1. DA1 stocke dans la RAM le SHA-256 attendu de DA2 et le compare avant d'effectuer le branchement. Sur de nombreux loaders, l'hôte contrôle entièrement l'adresse et la taille de chargement de DA2, ce qui fournit une écriture mémoire non vérifiée capable d'écraser le hash présent en mémoire et de rediriger l'exécution vers des payloads arbitraires (dans le contexte pre-OS, avec l'invalidation du cache gérée par DA).<sup>[[1]](#references)[[2]](#references)</sup>

## Frontière de confiance dans XFlash (DA1 → DA2)

- **DA1** est signé/chargé par le BootROM/Preloader. Lorsque Download Agent Authorization (DAA) est activé, seul un DA1 signé devrait être exécuté.
- **DA2** est envoyé via USB. DA1 reçoit la **taille**, l'**adresse de chargement** et le **SHA-256**, puis calcule le hash du DA2 reçu et le compare à un **hash attendu intégré à DA1** (copié dans la RAM).
- **Faiblesse :** sur les loaders non patchés, DA1 ne nettoie pas l'adresse/la taille de chargement de DA2 et conserve le hash attendu dans une zone mémoire inscriptible, ce qui permet à l'hôte de falsifier le contrôle.<sup>[[1]](#references)[[2]](#references)</sup>

## Déroulement de Carbonara (astuce des « deux BOOT_TO »)

1. **Premier `BOOT_TO` :** entrer dans le flux de staging DA1→DA2 (DA1 alloue les ressources, prépare la DRAM et expose le buffer du hash attendu en RAM).
2. **Écrasement de l'emplacement du hash :** envoyer un petit payload qui parcourt la mémoire de DA1 à la recherche du hash attendu de DA2 stocké, puis le remplace par le SHA-256 du DA2 modifié par l'attaquant. Cela exploite le chargement contrôlé par l'utilisateur pour placer le payload à l'emplacement du hash.
3. **Second `BOOT_TO` + digest :** déclencher un autre `BOOT_TO` avec les métadonnées de DA2 patchées et envoyer le digest brut de 32 octets correspondant au DA2 modifié. DA1 recalcule le SHA-256 du DA2 reçu, le compare au hash attendu désormais patché, puis le saut aboutit vers le code de l'attaquant.

Sur les loaders affectés, l'adresse et la taille non vérifiées peuvent fournir à l'attaquant une primitive d'écriture mémoire pre-OS choisie par l'attaquant, allant au-delà de l'emplacement du hash. Selon la memory map du SoC et les étapes de vérification ultérieures, cela peut permettre des implants early-boot, des helpers de secure-boot-bypass ou des payloads de type rootkit. L'exécution de code DA seule ne fournit pas automatiquement de persistance ni un secure-boot bypass complet ; un mécanisme de persistance distinct et une chaîne de vérification compatible restent nécessaires.<sup>[[1]](#references)[[2]](#references)</sup>

## Schéma minimal de PoC (style mtkclient)
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
- Le `payload` de 16 octets reproduit le blob observé dans le workflow de l’outil payant et utilisé par l’implémentation publiée pour patcher le buffer de hash attendu. Il est spécifique au loader et ne constitue pas un patch de hash-slot portable pour chaque SoC ou DA.<sup>[[1]](#references)[[2]](#references)</sup>
- `sha256(...).digest()` envoie des octets bruts (et non de l’hexadécimal) afin que DA1 compare avec le buffer patché.
- Avec un loader vulnérable et correspondant, DA2 peut être une image construite par l’attaquant, et les métadonnées de chargement choisies contrôlent son placement en mémoire. Validez la combinaison DA/SoC avant la transmission, car des adresses incorrectes peuvent bloquer ou endommager la cible.<sup>[[3]](#references)</sup>

## Paysage des patchs (loaders renforcés)

- **Mitigation observée** : Les DA renforcés examinés par les chercheurs forcent l’adresse de chargement de DA2 à `0x40000000` et ignorent l’adresse fournie par l’hôte, empêchant les écritures dans la région de hash de DA1 observée, située près de `0x200000`. Considérez ces deux adresses comme spécifiques à l’implémentation et non comme des constantes architecturales.
- **Détection des DA patchés** : mtkclient/penumbra analysent DA1 à la recherche de patterns indiquant le renforcement de l’adresse ; s’ils sont trouvés, Carbonara est ignoré. Les anciens DA exposent des hash slots inscriptibles (généralement autour d’offsets tels que `0x22dea4` dans DA1 V5) et restent exploitables.
- **V5 vs V6** : Certains loaders V6 (XML) acceptent encore les adresses fournies par l’utilisateur ; les binaires V6 plus récents imposent généralement l’adresse fixe et sont immunisés contre Carbonara, sauf en cas de downgrade.<sup>[[2]](#references)[[3]](#references)</sup>

## Note post-Carbonara (heapb8)

MediaTek a patché Carbonara ; une vulnérabilité plus récente, **heapb8**, cible le handler de téléchargement de fichiers USB de DA2 sur les loaders V6 patchés, permettant l’exécution de code même lorsque `boot_to` est renforcé. Elle exploite un heap overflow pendant les transferts de fichiers par chunks afin de prendre le contrôle du flux d’exécution de DA2. L’exploit est public dans Penumbra/mtk-payloads et montre que les correctifs de Carbonara ne ferment pas toute la surface d’attaque des DA.<sup>[[4]](#references)</sup>

## Notes pour le triage et le renforcement

- Les appareils pour lesquels l’adresse/la taille de DA2 ne sont pas vérifiées et où DA1 conserve le hash attendu inscriptible sont vulnérables. Si un Preloader/DA ultérieur impose des limites d’adresse ou maintient le hash immuable, Carbonara est mitigé.
- L’activation de DAA et la vérification par DA1/Preloader des paramètres BOOT_TO (limites + authenticité de DA2) ferment la primitive. Fermer uniquement le patch du hash sans limiter le chargement laisse toujours un risque d’écriture arbitraire.

## References

- [1] [Carbonara : l’exploit MediaTek que personne n’a servi](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [2] [Documentation de l’exploit Carbonara](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [3] [Code source de Penumbra Carbonara](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [4] [heapb8 : exploitation des Download Agents V6 patchés](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)
{{#include ../../banners/hacktricks-training.md}}
