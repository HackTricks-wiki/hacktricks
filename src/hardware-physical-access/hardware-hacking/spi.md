# SPI

{{#include ../../banners/hacktricks-training.md}}

## Informations de base

SPI (Serial Peripheral Interface) est un bus série synchrone couramment utilisé pour les communications à courte distance entre circuits intégrés. Un contrôleur fournit l’horloge et sélectionne un périphérique, tel qu’une EEPROM, un capteur ou un dispositif de contrôle, au moyen d’un signal de sélection de puce.<sup>[[1]](#references)</sup>

Plusieurs périphériques peuvent partager les lignes d’horloge et de données, avec généralement une ligne de sélection de puce distincte pour chacun. Le contrôleur orchestre les transferts ; les périphériques ne communiquent normalement pas directement entre eux sur le bus SPI. La polarité et le timing de la sélection de puce dépendent du périphérique ; une sélection active à l’état bas est courante, mais pas universelle. SPI ne définit ni la découverte, ni l’adressage, ni les commandes, ni une longueur maximale unique de transfert ; consultez donc toujours la fiche technique du composant ciblé.<sup>[[1]](#references)</sup>

MOSI/COPI transporte les données du contrôleur vers le périphérique et MISO/CIPO transporte les données du périphérique vers le contrôleur. Les deux directions peuvent décaler des données simultanément. La relation entre une commande, une adresse, des cycles fictifs et les données renvoyées est définie par le périphérique — et non par SPI — et dépend de la polarité et de la phase de l’horloge (modes 0 à 3). Ne partez pas du principe que la sortie commence exactement un cycle d’horloge après la fin de l’entrée.<sup>[[1]](#references)</sup>

## Extraction du firmware des EEPROM

L’extraction du firmware peut être utile pour l’analyser et y trouver des vulnérabilités. Il se peut que l’image correcte ne soit pas disponible en ligne ou qu’elle diffère selon le modèle, la révision matérielle ou la version. L’extraire directement de l’appareil physique fournit donc une cible d’évaluation exacte.

Une console série peut être utile, mais son système de fichiers peut être en lecture seule et la cible peut ne pas disposer d’outils d’analyse, notamment des utilitaires nécessaires pour envoyer/recevoir du trafic de test ou extraire facilement des binaires. Une image hors ligne préserve l’intégralité de la disposition de la mémoire flash et permet l’extraction du système de fichiers ainsi que la rétro-ingénierie sans modifier la cible en fonctionnement.

Lors d’une évaluation physique autorisée, une extraction vérifiée peut aussi servir à effectuer des tests contrôlés de modification et de reflashage. Cela inclut la modification de fichiers ou l’injection d’une charge utile de test/d’une backdoor pour démontrer la persistance au niveau du firmware. Conservez plusieurs lectures concordantes et l’image d’origine avant toute écriture : une tension, une sélection de puce, une disposition ou une image incorrecte peut rendre l’appareil inutilisable.

### Programmeur et lecteur d’EEPROM CH341A

Cet outil USB peu coûteux permet d’extraire et de reflasher des EEPROM série et des mémoires flash SPI compatibles. Il est couramment utilisé avec les puces de mémoire flash SPI NOR qui stockent le firmware PC BIOS/UEFI et est pratique lorsque l’accès physique est limité dans le temps.

![drawing](../../images/board_image_ch341a.jpg)

Connectez la mémoire flash au CH341A, puis branchez le programmeur à l’ordinateur. Si le programmeur lui-même n’est pas détecté, vérifiez le câble USB, les autorisations du système d’exploitation et le pilote CH341A approprié avant de diagnostiquer la puce ciblée. Vérifiez la tension de la puce, la broche 1, le câblage de l’adaptateur et la sortie du programmeur à l’aide des fiches techniques ou d’un multimètre — ne vous fiez **pas** à une règle telle que placer VCC à l’opposé du connecteur USB. Une orientation incorrecte ou l’application de 5 V à un composant de 3,3/1,8 V peut le détruire. Les lectures en circuit peuvent également échouer, car le reste de la carte charge le bus ou l’alimente.<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Utilisez un logiciel tel que `flashrom` ou G-Flash pour lire la puce. G-Flash est une interface graphique minimale qui peut détecter automatiquement les périphériques compatibles, ce qui peut être pratique lors d’une acquisition rapide, mais vérifiez vous-même le modèle détecté et la tension. Indiquez le programmeur exact et, si nécessaire, le modèle exact de la puce ; effectuez au moins deux lectures et comparez leurs empreintes de hachage avant de considérer une extraction comme fiable.<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

Après l’extraction du firmware, l’analyse peut être effectuée sur les fichiers binaires. Des outils comme strings, hexdump, xxd, binwalk, etc. permettent d’extraire de nombreuses informations sur le firmware ainsi que sur l’ensemble du système de fichiers.

Pour un tri initial, Binwalk peut rechercher des signatures connues et extraire le contenu intégré pris en charge :

```
binwalk -e <filename>
```

Le fichier de sortie peut utiliser l’extension `.bin`, `.rom` ou une autre ; l’extension ne permet pas de déterminer le format.

> [!CAUTION]
> Notez que l’extraction du firmware est un processus délicat qui demande beaucoup de patience. Toute mauvaise manipulation risque de corrompre le firmware, voire de l’effacer complètement et de rendre l’appareil inutilisable. Il est recommandé d’étudier l’appareil concerné avant de tenter d’extraire le firmware.

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom : Bus Pirate + flashrom](<../../images/image (910).png>)

Certaines fiches techniques désignent les broches cibles par `DI` et `DO` : pour une connexion flash conventionnelle à une seule ligne de données, le **MOSI/COPI** du contrôleur se connecte à `DI`, et son **MISO/CIPO` à `DO`. Vérifiez la fiche technique du composant cible, car les composants à double ou quadruple E/S réutilisent les broches dans d’autres modes.

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom : notez que même si le brochage du Bus Pirate indique des broches MOSI et MISO à connecter au SPI, certains SPI peuvent...](<../../images/image (360).png>)

Sous Windows ou Linux, vous pouvez utiliser le programme [**`flashrom`**](https://www.flashrom.org/Flashrom) pour extraire le contenu de la mémoire flash en exécutant une commande semblable à :

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

La documentation récente de Bus Pirate mentionne également les paramètres facultatifs `serialspeed` et `spispeed`. Commencez prudemment si des fils longs ou la charge du circuit rendent les lectures instables.<sup>[[3]](#references)</sup>

### Lectures en circuit lorsque le contrôleur partage le bus flash

Une pince SOIC peut alimenter le reste du PCB via l’alimentation de la flash. Si le MCU est alors alimenté et accède à la même puce, ses transferts SPI peuvent entrer en conflit avec ceux du programmateur externe. Un résultat `No EEPROM/flash device found` ne prouve donc pas que la flash est absente ou non prise en charge. Vérifiez d’abord le brochage, la tension et le contact, puis déterminez si le contrôleur intégré est également actif.<sup>[[4]](#references)</sup>

Si un pad de test de reset est disponible, vérifiez sa polarité et sa tension avec un multimètre avant de l’activer. Maintenir le MCU en reset peut laisser la flash accessible tout en arrêtant le contrôleur SPI concurrent. Il est également possible de dessouder la puce ou d’enregistrer passivement les lectures du MCU ; cette dernière méthode ne permet pas d’accéder aux zones non lues ni d’écrire sur la puce, et un câblage de sonde supplémentaire peut perturber un bus rapide. Une intervention sur l’oscillateur ou le mode de démarrage dépend de la cible et ne remplace pas la vérification du schéma et des signaux.<sup>[[4]](#references)</sup>

Lorsque le MCU est maintenu inactif, un Raspberry Pi doté d’une interface `spidev` activée peut lire la flash à l’aide du programmateur `linux_spi` de flashrom. Modifiez `-p` pour utiliser un autre adaptateur. Répétez la lecture et comparez les hashes avant de vous y fier ; l’autodétection SFDP et une lecture réussie **ne prouvent pas** que les opérations d’effacement, d’écriture ou de protection contre l’écriture fonctionnent sur une puce qui n’est pas prise en charge.<sup>[[4]](#references)[[2]](#references)</sup>

```bash
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-1.bin
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-2.bin
sha256sum flash-1.bin flash-2.bin
```

### Reconstruire les lectures de mémoire flash SPI avec un analyseur logique

Lorsqu’une lecture active est impossible, capturez le signal de sélection de puce, l’horloge, les données du contrôleur vers la mémoire flash et celles de la mémoire flash vers le contrôleur pendant le démarrage ou une action choisie dans l’interface utilisateur. Dans PulseView, identifiez d’abord l’intervalle actif du signal de sélection de puce et l’horloge, puis configurez les canaux de données du décodeur SPI à l’aide du brochage de la mémoire flash et vérifiez qu’une commande et une adresse plausibles sont suivies d’octets renvoyés. Exportez les octets **MISO/sortie de la mémoire flash** avec Binary Decoder Output View et conservez les adresses de lecture décodées afin de placer chaque réponse à l’offset correspondant dans la mémoire flash. Une capture des seules lectures déclenchées par les menus ne donne que les régions demandées, et non une image complète de la mémoire flash ; ne concaténez pas les réponses comme si elles étaient contiguës sans vérifier les adresses.<sup>[[4]](#references)</sup>

Si un dump semble contenir des graphismes plutôt que du code exécutable, poursuivez avec le [triage des ressources graphiques brutes](../firmware-analysis/#raw-display-assets-in-external-flash).<sup>[[4]](#references)</sup>

## References

- [1] [Analog Devices — Introduction à l’interface SPI](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [Manuel de flashrom — programmateur SPI CH341A et options de lecture/écriture](https://flashrom.org/classic_cli_manpage.html)
- [3] [Documentation de Bus Pirate — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
- [4] [VoidStar Security — Réviser le hacking matériel, partie 2](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
