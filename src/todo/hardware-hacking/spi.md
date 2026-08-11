# SPI

{{#include ../../banners/hacktricks-training.md}}

## Informations de base

SPI (Serial Peripheral Interface) est un bus série synchrone couramment utilisé pour les communications à courte distance entre circuits intégrés. Un contrôleur fournit l'horloge et sélectionne un périphérique, tel qu'une EEPROM, un capteur ou un dispositif de contrôle, à l'aide d'un signal de sélection de puce.<sup>[[1]](#references)</sup>

Plusieurs périphériques peuvent partager les lignes d'horloge et de données, généralement avec une ligne de sélection de puce distincte pour chaque périphérique. Le contrôleur orchestre les transferts ; les périphériques ne communiquent normalement pas directement entre eux sur le bus SPI. La polarité et le timing de la sélection de puce dépendent du périphérique ; une sélection active à l'état bas est courante, mais pas universelle. SPI ne définit ni découverte, ni adressage, ni commandes, ni longueur maximale unique de transfert. Consultez donc toujours la fiche technique de la cible.<sup>[[1]](#references)</sup>

MOSI/COPI transporte les données du contrôleur vers le périphérique, tandis que MISO/CIPO transporte les données du périphérique vers le contrôleur. Les deux directions peuvent être décalées simultanément. La relation entre une commande, une adresse, les cycles fictifs et les données renvoyées est définie par le périphérique, et non par SPI ; elle dépend de la polarité et de la phase de l'horloge (modes 0 à 3). Ne supposez pas que la sortie commence exactement un cycle d'horloge après la fin de l'entrée.<sup>[[1]](#references)</sup>

## Extraction du firmware des EEPROM

L'extraction du firmware peut être utile pour l'analyser et rechercher des vulnérabilités. L'image correcte peut être indisponible en ligne ou différer selon le modèle, la révision matérielle ou la version. L'extraire directement du périphérique physique fournit donc une cible d'évaluation exacte.

Une console série peut être utile, mais son système de fichiers peut être en lecture seule et la cible peut ne pas disposer d'outils d'analyse, notamment des utilitaires nécessaires pour envoyer ou recevoir du trafic de test ou extraire facilement des binaires. Une image hors ligne préserve la disposition complète de la mémoire flash et permet l'extraction du système de fichiers ainsi que la rétro-ingénierie sans modifier la cible en fonctionnement.

Lors d'une évaluation physique autorisée, un dump vérifié peut également permettre des tests contrôlés de modification et de reflashing. Cela inclut la modification de fichiers ou l'injection d'une charge utile de test/backdoor afin de démontrer une persistance au niveau du firmware. Conservez plusieurs lectures correspondantes ainsi que l'image originale avant toute écriture : une tension, une sélection de puce, une disposition ou une image incorrecte peut rendre le périphérique inutilisable.

### CH341A EEPROM Programmer and Reader

Cet outil USB peu coûteux peut extraire et reflasher des EEPROM série et des périphériques flash SPI compatibles. Il est couramment utilisé avec les puces flash SPI NOR qui stockent le firmware PC BIOS/UEFI et se révèle pratique lors d'un accès physique limité dans le temps.

![schéma](../../images/board_image_ch341a.jpg)

Connectez la mémoire flash au CH341A, puis connectez le programmer à l'ordinateur. Si le programmer lui-même n'est pas détecté, vérifiez le câble USB, les permissions de l'OS et le driver CH341A approprié avant de dépanner la puce cible. Vérifiez la tension de la puce, la broche 1, le câblage de l'adaptateur et la sortie du programmer à l'aide des fiches techniques ou d'un multimètre — ne vous fiez **pas** à une règle telle que placer VCC à l'opposé du connecteur USB. Une orientation incorrecte ou l'application de 5 V à un composant de 3,3/1,8 V peut le détruire. Les lectures in-circuit peuvent également échouer, car le reste de la carte charge ou alimente le bus.<sup>[[2]](#references)</sup>

![schéma](../../images/connect_wires_ch341a.jpg) ![schéma](../../images/eeprom_plugged_ch341a.jpg)

Utilisez un logiciel tel que `flashrom` ou G-Flash pour lire la puce. G-Flash est une GUI minimale qui peut détecter automatiquement les périphériques compatibles, ce qui peut être pratique lors d'une acquisition rapide, mais vérifiez vous-même le modèle et la tension détectés. Indiquez le programmer exact et, si nécessaire, le modèle exact de la puce ; effectuez au moins deux lectures et comparez leurs hashes avant de considérer un dump comme fiable.<sup>[[2]](#references)</sup>

![schéma](../../images/connected_status_ch341a.jpg)

Après l'extraction du firmware, l'analyse peut être effectuée sur les fichiers binaires. Des outils comme strings, hexdump, xxd, binwalk, etc. peuvent être utilisés pour extraire de nombreuses informations sur le firmware ainsi que sur l'ensemble du système de fichiers.

Pour le triage initial, Binwalk peut rechercher des signatures connues et extraire le contenu embarqué pris en charge :
```
binwalk -e <filename>
```
L’extension du fichier de sortie peut être `.bin`, `.rom` ou une autre extension ; l’extension ne définit pas le format.

> [!CAUTION]
> Notez que l’extraction du firmware est un processus délicat qui demande beaucoup de patience. Toute mauvaise manipulation peut potentiellement corrompre le firmware, voire l’effacer complètement et rendre l’appareil inutilisable. Il est recommandé d’étudier l’appareil concerné avant de tenter d’extraire le firmware.

### Bus Pirate + flashrom

![Programmateur et lecteur EEPROM CH341A - Bus Pirate + flashrom : Bus Pirate + flashrom](<../../images/image (910).png>)

Certaines fiches techniques désignent les broches cibles par `DI` et `DO` : pour une connexion flash conventionnelle à ligne de données unique, **MOSI/COPI du contrôleur se connecte à DI** et **MISO/CIPO du contrôleur se connecte à DO**. Vérifiez la fiche technique de la cible, car les composants à E/S duales/quadruples réutilisent les broches dans d’autres modes.

![Programmateur et lecteur EEPROM CH341A - Bus Pirate + flashrom : notez que, même si le PINOUT du Bus Pirate indique des broches MOSI et MISO à connecter au SPI, certains SPI peuvent...](<../../images/image (360).png>)

Sous Windows ou Linux, vous pouvez utiliser le programme [**`flashrom`**](https://www.flashrom.org/Flashrom) pour extraire le contenu de la mémoire flash en exécutant quelque chose comme :
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
La documentation récente de Bus Pirate présente également les paramètres optionnels `serialspeed` et `spispeed`. Commencez prudemment si de longs câbles ou la charge du circuit rendent les lectures instables.<sup>[[3]](#references)</sup>

## References

- [1] [Analog Devices — Introduction à l’interface SPI](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [Manuel de flashrom — programmeur SPI CH341A et options de lecture/écriture](https://flashrom.org/classic_cli_manpage.html)
- [3] [Documentation de Bus Pirate — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
{{#include ../../banners/hacktricks-training.md}}
