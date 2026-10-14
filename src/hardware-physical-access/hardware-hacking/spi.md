# SPI

{{#include ../../banners/hacktricks-training.md}}

## Informations de base

SPI (Serial Peripheral Interface) est un bus série synchrone couramment utilisé pour les communications à courte distance entre circuits intégrés. Un contrôleur fournit l’horloge et sélectionne un périphérique, comme une EEPROM, un capteur ou un dispositif de commande, à l’aide d’un signal de sélection de puce.<sup>[[1]](#references)</sup>

Plusieurs périphériques peuvent partager les lignes d’horloge et de données, généralement avec une ligne de sélection de puce distincte pour chaque périphérique. Le contrôleur orchestre les transferts ; les périphériques ne communiquent normalement pas directement entre eux via le bus SPI. La polarité et la synchronisation du signal de sélection de puce dépendent du périphérique ; une sélection active à l’état bas est courante, mais pas universelle. SPI ne définit ni découverte, ni adressage, ni commandes, ni longueur maximale unique de transfert. Consultez donc toujours la fiche technique du périphérique cible.<sup>[[1]](#references)</sup>

MOSI/COPI transporte les données du contrôleur vers le périphérique, et MISO/CIPO celles du périphérique vers le contrôleur. Les deux sens peuvent transmettre simultanément. La relation entre une commande, une adresse, les cycles factices et les données renvoyées est définie par le périphérique, pas par SPI, et dépend de la polarité et de la phase de l’horloge (modes 0 à 3). Ne supposez pas que la sortie commence exactement un cycle d’horloge après la fin de l’entrée.<sup>[[1]](#references)</sup>

## Extraction du firmware des EEPROM

L’extraction du firmware peut être utile pour l’analyser et rechercher des vulnérabilités. L’image correcte peut être indisponible en ligne ou différer selon le modèle, la révision matérielle ou la version. L’extraire directement de l’appareil physique permet donc d’obtenir une cible d’évaluation exacte.

Une console série peut être utile, mais son système de fichiers peut être en lecture seule et la cible peut ne pas disposer d’outils d’analyse, notamment d’utilitaires pour envoyer/recevoir du trafic de test ou extraire facilement des binaires. Une image hors ligne conserve la disposition complète de la mémoire flash et permet d’extraire le système de fichiers et de procéder à la rétro-ingénierie sans modifier la cible en cours d’exécution.

Lors d’une évaluation physique autorisée, une extraction vérifiée peut aussi permettre des tests contrôlés de modification et de reprogrammation. Cela comprend la modification de fichiers ou l’injection d’un payload/deadback pour démontrer la persistance au niveau du firmware. Conservez plusieurs lectures identiques ainsi que l’image d’origine avant toute écriture : une tension, une sélection de puce, une disposition ou une image incorrecte peut rendre l’appareil inutilisable.

### Programmeur et lecteur d’EEPROM CH341A

Cet outil USB peu coûteux peut extraire et reprogrammer les EEPROM série et les mémoires flash SPI compatibles. Il est souvent utilisé avec les puces de mémoire flash SPI NOR qui stockent le firmware BIOS/UEFI des PC, et se révèle pratique lorsque l’accès physique est limité dans le temps.

![illustration](../../images/board_image_ch341a.jpg)

Connectez la mémoire flash au CH341A, puis branchez le programmeur à l’ordinateur. Si le programmeur n’est pas détecté, vérifiez le câble USB, les autorisations du système d’exploitation et le pilote CH341A approprié avant de diagnostiquer la puce cible. Vérifiez la tension de la puce, la broche 1, le câblage de l’adaptateur et la sortie du programmeur à l’aide des fiches techniques ou d’un multimètre — ne vous fiez **pas** à une règle telle que placer VCC à l’opposé du connecteur USB. Une orientation incorrecte ou l’application de 5 V à un composant de 3,3/1,8 V peut le détruire. Les lectures en circuit peuvent également échouer, car le reste de la carte charge le bus ou l’alimente.<sup>[[2]](#references)</sup>

![illustration](../../images/connect_wires_ch341a.jpg) ![illustration](../../images/eeprom_plugged_ch341a.jpg)

Utilisez un logiciel comme `flashrom` ou G-Flash pour lire la puce. G-Flash est une interface graphique minimale qui peut détecter automatiquement les périphériques compatibles, ce qui peut être pratique lors d’une acquisition rapide, mais vérifiez vous-même le modèle détecté et la tension. Indiquez le programmeur exact et, si nécessaire, le modèle exact de la puce ; effectuez au moins deux lectures et comparez leurs empreintes de hachage avant de considérer une extraction comme fiable.<sup>[[2]](#references)</sup>

![illustration](../../images/connected_status_ch341a.jpg)

Après l’extraction du firmware, l’analyse peut être effectuée sur les fichiers binaires. Des outils comme strings, hexdump, xxd, binwalk, etc. permettent d’extraire de nombreuses informations sur le firmware ainsi que sur l’ensemble du système de fichiers.

Pour un tri initial, Binwalk peut rechercher des signatures connues et extraire le contenu intégré pris en charge :

```
binwalk -e <filename>
```

Le fichier de sortie peut utiliser l’extension `.bin`, `.rom` ou une autre extension ; celle-ci ne détermine pas le format.

> [!CAUTION]
> Notez que l’extraction du firmware est un processus délicat qui demande beaucoup de patience. Toute mauvaise manipulation risque de corrompre le firmware, voire de l’effacer complètement et de rendre l’appareil inutilisable. Il est recommandé d’étudier l’appareil concerné avant de tenter d’extraire le firmware.

### Bus Pirate + flashrom

![Programmeur et lecteur EEPROM CH341A - Bus Pirate + flashrom : Bus Pirate + flashrom](<../../images/image (910).png>)

Certaines fiches techniques désignent les broches cibles par `DI` et `DO` : pour une connexion flash classique à une seule ligne de données, **MOSI/COPI du contrôleur se connecte à DI** et **MISO/CIPO du contrôleur se connecte à DO**. Vérifiez la fiche technique de la cible, car les composants à E/S duales ou quadruples réutilisent les broches dans d’autres modes.

![Programmeur et lecteur EEPROM CH341A - Bus Pirate + flashrom : Notez que, même si le brochage du Bus Pirate indique des broches MOSI et MISO à connecter au SPI, certains SPI peuvent...](<../../images/image (360).png>)

Sous Windows ou Linux, vous pouvez utiliser le programme [**`flashrom`**](https://www.flashrom.org/Flashrom) pour extraire le contenu de la mémoire flash en exécutant une commande de ce type :

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

La documentation récente de Bus Pirate indique également les paramètres facultatifs `serialspeed` et `spispeed`. Commencez prudemment si des fils longs ou la charge du circuit rendent les lectures instables.<sup>[[3]](#references)</sup>

## References

- [1] [Analog Devices — Introduction à l’interface SPI](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [Manuel de flashrom — programmateur SPI CH341A et options de lecture/écriture](https://flashrom.org/classic_cli_manpage.html)
- [3] [Documentation de Bus Pirate — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
{{#include ../../banners/hacktricks-training.md}}
