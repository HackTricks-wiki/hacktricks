# SPI

{{#include ../../banners/hacktricks-training.md}}

## Informations de base

SPI (Serial Peripheral Interface) est un protocole de communication série synchrone utilisé dans les systèmes embarqués pour les communications à courte distance entre circuits intégrés (IC, Integrated Circuits). Le protocole de communication SPI repose sur une architecture maître-esclave orchestrée par les signaux d'horloge et de sélection de circuit (Chip Select). Une architecture maître-esclave se compose d'un maître (généralement un microprocesseur) qui gère des périphériques externes comme des EEPROM, des capteurs, des dispositifs de contrôle, etc., considérés comme les esclaves.

Plusieurs esclaves peuvent être connectés à un maître, mais les esclaves ne peuvent pas communiquer entre eux. Les esclaves sont administrés par deux broches : l'horloge et la sélection de circuit. Comme SPI est un protocole de communication synchrone, les broches d'entrée et de sortie suivent les signaux d'horloge. La sélection de circuit est utilisée par le maître pour sélectionner un esclave et interagir avec lui. Lorsque la sélection de circuit est à l'état haut, l'esclave n'est pas sélectionné, tandis que lorsqu'elle est à l'état bas, la puce est sélectionnée et le maître interagit avec l'esclave.

Les broches MOSI (Master Out, Slave In) et MISO (Master In, Slave Out) sont responsables de l'envoi et de la réception des données. Les données sont envoyées à l'esclave via la broche MOSI lorsque la sélection de circuit est maintenue à l'état bas. Les données d'entrée contiennent des instructions, des adresses mémoire ou des données, conformément à la datasheet du fabricant de l'esclave. Lorsqu'une entrée valide est reçue, la broche MISO transmet les données au maître. Les données de sortie sont envoyées exactement au cycle d'horloge suivant la fin de l'entrée. Les broches MISO transmettent les données jusqu'à ce qu'elles soient entièrement transmises ou que le maître place la broche de sélection de circuit à l'état haut (dans ce cas, l'esclave cesse de transmettre et le maître n'écoute plus après ce cycle d'horloge).

## Dumping du firmware depuis des EEPROM

Le dumping du firmware peut être utile pour analyser le firmware et y trouver des vulnérabilités. Souvent, le firmware n'est pas disponible sur Internet ou n'est pas pertinent en raison de variations liées à des facteurs comme le numéro de modèle, la version, etc. Par conséquent, extraire directement le firmware depuis le dispositif physique peut être utile pour rechercher précisément les menaces.

Obtenir une console série peut être utile, mais il arrive souvent que les fichiers soient en lecture seule. Cela limite l'analyse pour diverses raisons. Par exemple, les outils nécessaires pour envoyer et recevoir des paquets ne seraient pas présents dans le firmware. Il n'est donc pas possible d'extraire les binaires pour les reverse engineer. Disposer de l'ensemble du firmware dumpé sur le système et en extraire les binaires pour les analyser peut donc être très utile.

De plus, lors d'opérations de red teaming et après avoir obtenu un accès physique aux dispositifs, dumper le firmware peut permettre de modifier les fichiers ou d'injecter des fichiers malveillants, puis de les reflasher dans la mémoire, ce qui peut être utile pour implanter une backdoor dans le dispositif. Le dumping du firmware permet donc d'envisager de nombreuses possibilités.

### CH341A EEPROM Programmer and Reader

Ce dispositif est un outil peu coûteux permettant de dumper des firmwares depuis des EEPROM et de les reflasher avec des fichiers de firmware. Il est très utilisé pour travailler avec les puces BIOS des ordinateurs (qui sont simplement des EEPROM). Ce dispositif se connecte via USB et nécessite peu d'outils pour commencer. De plus, il effectue généralement la tâche rapidement, ce qui peut également être utile lors d'un accès physique à un dispositif.

![schéma](../../images/board_image_ch341a.jpg)

Connectez la mémoire EEPROM au CH341A Programmer et branchez le dispositif à l'ordinateur. Si le dispositif n'est pas détecté, essayez d'installer les drivers sur l'ordinateur. Assurez-vous également que l'EEPROM est connectée dans la bonne orientation (généralement, placez la broche VCC dans le sens opposé au connecteur USB), sinon le software ne pourra pas détecter la puce. Consultez le schéma si nécessaire :

![schéma](../../images/connect_wires_ch341a.jpg) ![schéma](../../images/eeprom_plugged_ch341a.jpg)

Enfin, utilisez des softwares comme flashrom, G-Flash (GUI), etc. pour dumper le firmware. G-Flash est un outil GUI minimaliste et rapide qui détecte automatiquement l'EEPROM. Cela peut être utile lorsque le firmware doit être extrait rapidement, sans avoir à trop consulter la documentation.

![schéma](../../images/connected_status_ch341a.jpg)

Après avoir dumpé le firmware, l'analyse peut être effectuée sur les fichiers binaires. Des outils comme strings, hexdump, xxd, binwalk, etc. peuvent être utilisés pour extraire de nombreuses informations du firmware ainsi que de l'ensemble du système de fichiers.

Pour extraire le contenu du firmware, binwalk peut être utilisé. Binwalk analyse les signatures hexadécimales, identifie les fichiers dans le fichier binaire et est capable de les extraire.
```
binwalk -e <filename>
```
Cela peut être au format .bin ou .rom selon les outils et les configurations utilisés.

> [!CAUTION]
> Notez que l’extraction du firmware est un processus délicat qui demande beaucoup de patience. Toute mauvaise manipulation peut potentiellement corrompre le firmware, voire l’effacer complètement et rendre l’appareil inutilisable. Il est recommandé d’étudier l’appareil concerné avant de tenter d’extraire le firmware.

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom : Bus Pirate + flashrom](<../../images/image (910).png>)

Notez que même si le PINOUT du Bus Pirate indique des broches **MOSI** et **MISO** pour la connexion au SPI, certains SPI peuvent indiquer des broches DI et DO. **MOSI -> DI, MISO -> DO**

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom : Notez que même si le PINOUT du Bus Pirate indique des broches MOSI et MISO pour la connexion au SPI, certains SPI peuvent...](<../../images/image (360).png>)

Sous Windows ou Linux, vous pouvez utiliser le programme [**`flashrom`**](https://www.flashrom.org/Flashrom) pour extraire le contenu de la mémoire flash en exécutant une commande similaire à :
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
{{#include ../../banners/hacktricks-training.md}}
