# Modification des paramètres de sécurité UEFI IFR et NVRAM

{{#include ../../banners/hacktricks-training.md}}

Un mot de passe de configuration protège l'interface utilisateur du firmware, mais il n'authentifie pas nécessairement les octets de configuration stockés dans la SPI flash. Avec un accès physique en écriture, un évaluateur peut faire correspondre un paramètre UEFI masqué ou verrouillé de la **Human Interface Infrastructure (HII) Internal Forms Representation (IFR)** à la variable NVRAM correspondante, modifier cette valeur hors ligne, puis la reflasher. Sur un système Dell concerné, cela a modifié l'état de l'IOMMU avant le démarrage, alors que l'interface graphique de configuration indiquait toujours que la protection DMA était activée.<sup>[[3]](#references)</sup>

> [!CAUTION]
> Les écritures dans le firmware peuvent rendre la cible définitivement inutilisable. Travaillez sur un appareil de test autorisé et récupérable ; conservez l'image originale et obtenez au moins trois lectures indépendantes dont les hachages cryptographiques correspondent avant toute modification.<sup>[[3]](#references)</sup>

## Acquisition de l'image du firmware

Lisez uniquement la région BIOS lorsque le flash descriptor Intel autorise l'accès de l'hôte, ou utilisez un programmateur externe avec une tension appropriée et une pince in-circuit. Un programmateur externe est généralement nécessaire pour restaurer une machine qui ne démarre plus.<sup>[[3]](#references)[[9]](#references)</sup>
```bash
flashrom -p internal -r dump.bin --ifd -i bios
sha256sum dump*.bin
```
Ne supposez pas qu’une capsule de mise à jour du vendor soit équivalente au contenu de la puce : elle peut omettre la NVRAM, contenir une encapsulation ou être chiffrée. [UEFITool](https://github.com/LongSoft/UEFITool) peut analyser une image UEFI brute en volumes de firmware, fichiers et sections.<sup>[[7]](#references)</sup>

## Mapper une question IFR à la NVRAM

[IFRExtractor-RS](https://github.com/LongSoft/IFRExtractor-RS) convertit les packages de formulaires HII en texte et expose les paramètres qu’une GUI du vendor masque, renomme ou supprime. Sa sortie peut identifier la question, le variable store, l’offset d’octet, la largeur de stockage, les valeurs valides et la visibilité conditionnelle.<sup>[[8]](#references)</sup>

1. Ouvrez le dump dans UEFITool, recherchez le firmware file nommé `Setup`, développez-le jusqu’à la section d’image PE32, puis utilisez **Extract body**.
2. Exécutez IFRExtractor-RS sur le corps EFI/PE32 extrait, puis recherchez dans le texte généré des contrôles tels que `DMA`, `IOMMU`, `VT-d`, `Secure Boot` ou le label visible par l’utilisateur.
3. Notez `VarStoreId`, `VarOffset`, `Size`, les options valides et l’ID de la question. N’inférez pas la sémantique de la valeur à partir de `Flags` uniquement.
4. Trouvez la déclaration `VarStore`/`VarStoreEfi` correspondante et associez l’ID numérique du store à son **nom et GUID**.
5. Recherchez ce GUID dans UEFITool jusqu’à atteindre l’objet NVRAM correspondant. Ouvrez **Body hex view** et naviguez jusqu’à `VarOffset` relativement au corps de la variable, et non à l’ensemble de l’image flash.<sup>[[3]](#references)</sup>
```bash
./ifrextractor Section_PE32_image_Setup_body.efi
rg -i 'dma|iommu|vt-d|secure boot' *.ifr.txt
```
Par exemple, une image Dell décrivait la question concernée comme `Control Iommu Pre-boot Behavior`, avec `VarStoreId: 0x1`, `VarOffset: 0x975` et un champ de 8 bits. Le Store `0x1` correspondait à la variable `Setup` et au GUID `EC87D643-EBA4-4BB5-A1E5-3F3E36B20DA9` ; des dumps différentiels ont établi que `01` signifiait activé et `00` désactivé sur ce firmware.<sup>[[3]](#references)</sup>

> [!WARNING]
> Les GUID, offsets, layouts de structure, instances de variables dupliquées et encodages des valeurs peuvent changer selon les modèles et les versions du firmware. Ne réutilisez jamais l'offset d'exemple comme valeur Dell universelle.

## Validate with differential dumps

Lorsque l'interface de configuration est disponible sur une unité de test équivalente, créez un dump avec l'option activée et un autre avec l'option désactivée. Comparez le corps de la variable dérivé de l'IFR et confirmez que seul le champ attendu change. Cela détermine l'encodage réel et permet de distinguer une variable active des copies obsolètes, par défaut ou de récupération. Patchez une copie de l'image originale vérifiée, rouvrez-la dans UEFITool et confirmez que la modification se trouve en dehors des plages de code authentifiées ou mesurées avant le reflash.<sup>[[3]](#references)[[4]](#references)</sup>

Une modification ciblée peut avoir moins d'effets secondaires que l'effacement d'un firmware password, qui peut entraîner un état d'usine, nécessiter la saisie de nouvelles données spécifiques à l'appareil ou modifier les mesures PCR du TPM. Cependant, une modification offline ciblée peut également créer une dangereuse **divergence entre l'état affiché et l'état effectif** : l'interface utilisateur et les outils de gestion peuvent afficher l'ancienne valeur tandis que le firmware précoce utilise l'octet patché. La modification démontrée n'a pas demandé de récupération BitLocker et a persisté après une mise à jour du BIOS du fournisseur, car la mise à jour a conservé l'état NVRAM modifié.<sup>[[3]](#references)</sup>

Le [Dell UEFI Patcher](https://github.com/craigsblackie/Dell_UEFI_Patcher) de l'auteur illustre un patcher spécifique à un modèle qui détecte les plages Intel Boot Guard Initial Boot Block et refuse les écritures normales à l'intérieur de celles-ci. Utilisez son mode d'analyse avant `--apply`, examinez chaque correspondance potentielle et considérez ses valeurs par défaut comme des exemples plutôt que comme des offsets réutilisables.<sup>[[4]](#references)</sup>
```bash
python3 dell_bios_patcher.py bios_dump.bin
python3 dell_bios_patcher.py bios_dump.bin patched.bin --apply
```
## Automatiser la cartographie avec NVRAMap

[NVRAMap](https://github.com/PN-Tester/NVRAMap) automatise l'extraction IFR, associe le `VarStoreId` d'une question au GUID/nom NVRAM, affiche les valeurs actuelles des options et peut modifier le champ sélectionné. Il peut fonctionner à partir d'un dump complet du firmware ou de blobs EFI et NVRAM extraits séparément.<sup>[[5]](#references)</sup>
```bash
# EFI question -> backing NVRAM value
python3 NVRAMap.py -mode 1 -firmware dump.bin -terms DMA,IOMMU --dump-ifr ifr.txt

# Interactive editor after reviewing the mapping
python3 NVRAMap.py -mode 1 -firmware dump.bin -terms DMA,IOMMU --modify
```
L’automatisation ne supprime pas la nécessité de disposer de dumps correspondants, de matériel de récupération, de vérifications de l’intégrité des régions ou d’une validation post-flash.

## Enchaînement d’un downgrade de l’IOMMU en pre-boot pour obtenir un accès DMA à Windows

Si la valeur patchée autorise le DMA PCIe avant ExitBootServices, [DMAReaper](https://github.com/PN-Tester/DMAReaper) peut parcourir l’EFI System Table via les tables racines ACPI, localiser la table `DMAR` et l’écraser avant que Windows ne l’analyse. Sans données DMAR utilisables, Windows peut échouer à initialiser la Kernel DMA Protection basée sur l’IOMMU. DMAReaper ne désactive pas VBS/HVCI à lui seul.<sup>[[1]](#references)</sup>

Dans la chaîne présentée, la cible a ensuite été démarrée en Mode sans échec afin de supprimer la barrière VBS restante, puis [PCILeech](https://github.com/ufrisk/pcileech) a patché la mémoire physique avec une signature Sticky Keys :<sup>[[2]](#references)[[3]](#references)</sup>
```bash
sudo ./pcileech patch -sig stickykeys_cmd_win
```
Après un patch compatible avec la build réussi, l’activation de Sticky Keys sur l’écran de connexion Windows lançait une invite de commandes en tant que `NT AUTHORITY\SYSTEM`. Les signatures et les plages de mémoire accessibles dépendent de la cible, de la build et du matériel ; une correspondance détectée ne prouve pas que toutes les versions de Windows sont exploitables.<sup>[[2]](#references)[[3]](#references)</sup>

Ne faites pas confiance au menu du firmware pour valider le résultat. Vérifiez **System Information (`msinfo32.exe`) → Kernel DMA Protection**, vérifiez VBS séparément, déterminez si l’OS a reçu une table DMAR valide et testez l’accessibilité DMA réelle. Windows indique Kernel DMA Protection uniquement lorsque la plateforme et le firmware prennent en charge la configuration IOMMU requise.<sup>[[6]](#references)</sup>

## References

- [1] [DMAReaper - Désactiver Kernel DMA Protection via un écrasement DMAR au pré-démarrage](https://github.com/PN-Tester/DMAReaper)
- [2] [PCILeech - Logiciel d’attaque Direct Memory Access](https://github.com/ufrisk/pcileech)
- [3] [MDSec - Désactivation des fonctionnalités de sécurité dans un BIOS verrouillé](https://mdsec.co.uk/2026/03/disabling-security-features-in-a-locked-bios)
- [4] [Dell UEFI Patcher - Patching NVRAM prenant en compte IBB](https://github.com/craigsblackie/Dell_UEFI_Patcher)
- [5] [NVRAMap - Mapper les paramètres EFI vers les valeurs NVRAM](https://github.com/PN-Tester/NVRAMap)
- [6] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [7] [UEFITool - Visionneuse et parseur d’images de firmware UEFI](https://github.com/LongSoft/UEFITool)
- [8] [IFRExtractor-RS - Extraire l’IFR UEFI dans un texte lisible](https://github.com/LongSoft/IFRExtractor-RS)
- [9] [Manuel de flashrom - Programmeurs et opérations de lecture/écriture](https://flashrom.org/classic_cli_manpage.html)
{{#include ../../banners/hacktricks-training.md}}
