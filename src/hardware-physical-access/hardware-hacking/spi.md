# SPI

{{#include ../../banners/hacktricks-training.md}}

## Informations de base

SPI (Serial Peripheral Interface) est un bus série synchrone couramment utilisé pour la communication à courte distance entre circuits intégrés. Un contrôleur fournit l’horloge et sélectionne un périphérique, comme une EEPROM, un capteur ou un dispositif de contrôle, à l’aide d’un signal de sélection de puce.<sup>[[1]](#references)</sup>

Plusieurs périphériques peuvent partager les lignes d’horloge et de données, généralement avec un signal de sélection de puce distinct pour chaque périphérique. Le contrôleur orchestre les transferts ; les périphériques ne communiquent normalement pas directement entre eux via le bus SPI. La polarité et le timing du signal de sélection de puce dépendent du périphérique ; une sélection active à l’état bas est courante, mais pas universelle. SPI ne définit ni la découverte, ni l’adressage, ni les commandes, ni une longueur de transfert maximale unique : consultez toujours la fiche technique du périphérique cible.<sup>[[1]](#references)</sup>

MOSI/COPI transporte les données du contrôleur vers le périphérique et MISO/CIPO transporte les données du périphérique vers le contrôleur. Les deux directions peuvent transmettre des bits simultanément. La relation entre une commande, une adresse, les cycles factices et les données renvoyées est définie par le périphérique, et non par SPI, et dépend de la polarité et de la phase de l’horloge (modes 0–3). Ne supposez pas que la sortie commence exactement un cycle d’horloge après la fin de l’entrée.<sup>[[1]](#references)</sup>

## Extraction du firmware des EEPROM

L’extraction du firmware peut être utile pour l’analyser et trouver des vulnérabilités. L’image appropriée peut être indisponible en ligne ou différer selon le modèle, la révision matérielle ou la version. L’extraire directement du périphérique physique fournit donc une cible d’évaluation exacte.

Une console série peut être utile, mais son système de fichiers peut être en lecture seule et la cible peut ne pas disposer d’outils d’analyse, y compris des utilitaires nécessaires pour envoyer/recevoir du trafic de test ou extraire facilement des binaires. Une image hors ligne conserve la disposition complète de la flash et permet l’extraction du système de fichiers ainsi que la rétro-ingénierie sans modifier la cible en fonctionnement.

Lors d’une évaluation physique autorisée, une extraction vérifiée peut également permettre des tests contrôlés de modification et de reflashage. Cela inclut la modification de fichiers ou l’injection d’une charge utile de test/d’une backdoor pour démontrer une persistance au niveau du firmware. Conservez plusieurs lectures concordantes ainsi que l’image d’origine avant toute écriture : une tension, une sélection de puce, une disposition ou une image incorrecte peut rendre le périphérique inutilisable.

### Programmeur et lecteur EEPROM CH341A

Cet outil USB peu coûteux peut extraire et reflasher les EEPROM série et les puces flash SPI compatibles. Il est couramment utilisé avec les puces flash SPI NOR qui stockent le firmware BIOS/UEFI des PC et se révèle pratique lorsque l’accès physique est limité dans le temps.

![drawing](../../images/board_image_ch341a.jpg)

Connectez la mémoire flash au CH341A, puis branchez le programmeur à l’ordinateur. Si le programmeur n’est pas détecté, vérifiez le câble USB, les permissions du système d’exploitation et le pilote CH341A approprié avant de dépanner la puce cible. Vérifiez la tension de la puce, la broche 1, le câblage de l’adaptateur et la sortie du programmeur à l’aide des fiches techniques ou d’un multimètre — ne vous fiez **pas** à une règle telle que placer VCC à l’opposé du connecteur USB. Une orientation incorrecte ou l’application de 5 V à un composant de 3,3/1,8 V peut le détruire. Les lectures en circuit peuvent également échouer si le reste de la carte charge le bus ou l’alimente.<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Utilisez un logiciel comme `flashrom` ou G-Flash pour lire la puce. G-Flash est une interface graphique minimale qui peut détecter automatiquement les périphériques compatibles, ce qui peut être pratique lors d’une acquisition rapide, mais vérifiez vous-même le modèle détecté et la tension. Indiquez le programmeur exact et, si nécessaire, le modèle exact de la puce ; effectuez au moins deux lectures et comparez leurs hashes avant de considérer une extraction comme fiable.<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

Après l’extraction du firmware, l’analyse peut être effectuée sur les fichiers binaires. Des outils comme strings, hexdump, xxd, binwalk, etc. peuvent servir à extraire de nombreuses informations sur le firmware ainsi que sur l’ensemble du système de fichiers.

Pour le triage initial, Binwalk peut rechercher des signatures connues et extraire le contenu embarqué pris en charge :

```
binwalk -e <filename>
```

Le fichier de sortie peut utiliser l’extension `.bin`, `.rom` ou une autre extension ; l’extension ne permet pas d’établir le format.

> [!CAUTION]
> Notez que l’extraction du firmware est un processus délicat qui demande beaucoup de patience. Toute mauvaise manipulation peut corrompre le firmware, voire l’effacer complètement et rendre l’appareil inutilisable. Il est recommandé d’étudier l’appareil concerné avant de tenter d’en extraire le firmware.

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom : Bus Pirate + flashrom](<../../images/image (910).png>)

Certaines fiches techniques désignent les broches cibles par `DI` et `DO` : pour une connexion flash conventionnelle à une seule ligne de données, la broche **MOSI/COPI** du contrôleur se connecte à `DI` et la broche **MISO/CIPO** du contrôleur se connecte à `DO`. Vérifiez la fiche technique de la cible, car les composants à E/S doubles ou quadruples réutilisent les broches dans d’autres modes.

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom : Notez que même si le brochage du Bus Pirate indique des broches MOSI et MISO à connecter au SPI, certains SPI peuvent...](<../../images/image (360).png>)

Sous Windows ou Linux, vous pouvez utiliser le programme [**`flashrom`**](https://www.flashrom.org/Flashrom) pour extraire le contenu de la mémoire flash en exécutant une commande de ce type :

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

La documentation récente de Bus Pirate présente également les paramètres facultatifs `serialspeed` et `spispeed`. Commencez prudemment si des fils longs ou la charge du circuit rendent les lectures instables.<sup>[[3]](#references)</sup>

### Lectures en circuit lorsque le contrôleur partage le bus flash

Une pince SOIC peut alimenter le reste du PCB via l’alimentation de la flash. Si le MCU est alors alimenté et accède à la même puce, ses transferts SPI peuvent entrer en collision avec ceux du programmateur externe. Un résultat `No EEPROM/flash device found` ne prouve donc pas que la flash est absente ou non prise en charge. Vérifiez d’abord le brochage, la tension et le contact, puis déterminez si le contrôleur intégré à la carte est également actif.<sup>[[4]](#references)</sup>

Si un point de test de réinitialisation est disponible, vérifiez sa polarité et sa tension avec un multimètre avant de l’activer. Maintenir le MCU en réinitialisation peut laisser la flash accessible tout en arrêtant le contrôleur SPI concurrent. Il est également possible de dessouder la puce ou d’enregistrer passivement les lectures du MCU ; cette dernière méthode ne permet pas d’accéder aux régions non lues ni d’écrire sur la puce, et des fils de sonde supplémentaires peuvent perturber un bus rapide. Une intervention sur l’oscillateur ou le mode de démarrage dépend de la cible et ne remplace pas la vérification du schéma et des signaux.<sup>[[4]](#references)</sup>

Lorsque le MCU est maintenu inactif, un Raspberry Pi doté d’une interface `spidev` activée peut lire la flash avec le programmateur `linux_spi` de flashrom. Modifiez `-p` pour utiliser un autre adaptateur. Répétez la lecture et comparez les hachages avant de vous fier au résultat ; la détection automatique via SFDP et une lecture réussie ne prouvent **pas** que les opérations d’effacement, d’écriture ou de protection en écriture fonctionnent sur une puce non prise en charge par ailleurs.<sup>[[4]](#references)[[2]](#references)</sup>

```bash
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-1.bin
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-2.bin
sha256sum flash-1.bin flash-2.bin
```

### Reconstruire les lectures de flash SPI avec un analyseur logique

Quand la lecture active est impossible, capturez chip select, l’horloge, les données du contrôleur vers la flash et celles de la flash vers le contrôleur pendant le démarrage ou une action d’interface choisie. Dans PulseView, repérez d’abord l’intervalle actif de chip select et l’horloge, puis configurez les canaux de données du décodeur SPI à partir du brochage de la flash et vérifiez qu’une commande/adresse plausible est suivie d’octets retournés. Exportez les octets **MISO/sortie de la flash** avec Binary Decoder Output View et conservez les adresses de lecture décodées pour placer chaque réponse à l’offset correspondant dans la flash. Une capture limitée aux lectures déclenchées par les menus ne fournit que les régions demandées, pas une image complète de la flash ; ne concaténez pas les réponses comme si elles étaient contiguës sans vérifier les adresses.<sup>[[4]](#references)</sup>

Si le dump semble contenir des graphiques plutôt que du code exécutable, poursuivez avec le [triage des ressources d’affichage brutes](../firmware-analysis/#raw-display-assets-in-external-flash).<sup>[[4]](#references)</sup>

#### Scapy et captures SPI/QSPI mixtes

Pour les sondes non étiquetées, distinguez MOSI de MISO en repérant la ligne qui transporte l’opcode avant les données de réponse, puis vérifiez la commande dans la fiche technique de la flash. Les impulsions plus courtes qu’une période d’horloge peuvent être du bruit de sonde plutôt que des bits échantillonnés, et les câbles supplémentaires des pinces peuvent rendre les captures à haute vitesse peu fiables.<sup>[[5]](#references)</sup>

L’export CSV SPI de Saleae utilise `enable` et `disable` pour délimiter un intervalle de chip select, avec les octets MOSI/MISO dans les lignes `result`. Regroupez les octets par intervalle avant le décodage ; concaténer toutes les données MISO fait perdre les adresses des transactions.<sup>[[5]](#references)</sup> Un `Packet` Scapy peut modéliser l’en-tête MOSI avec un opcode `ByteEnumField` et des champs conditionnels pour l’adresse et les octets dummy. Pour les lectures NOR sur 24 bits, `0x03` comporte un opcode et trois octets d’adresse, tandis que `0x0B` ajoute un octet dummy. `len(req.self_build())` donne la longueur de l’en-tête modélisé : pour une lecture sur une seule ligne, `miso[header_length:]` correspond à la réponse de la flash, tandis que MOSI après l’en-tête contient des données sans importance côté contrôleur.<sup>[[5]](#references)</sup> Placez les réponses à leurs adresses décodées dans une image remplie de `0xFF` et suivez séparément les offsets couverts. Un octet non observé ne prouve pas que la flash contenait `0xFF` à cet endroit.<sup>[[5]](#references)[[6]](#references)</sup>

Une lecture `0x6B` (1-1-4) de type W25Q utilise une ligne pour l’opcode et l’adresse, mais IO0–IO3 pour les données de réponse. L’activité sur les anciennes broches `/WP` et `/HOLD` constitue un indice plus solide d’un passage en mode quad qu’une simple augmentation de la fréquence d’horloge ; un analyseur sur une seule ligne peut mal décoder la réponse quad.<sup>[[5]](#references)</sup> Exportez cette phase avec un analyseur QSPI configuré selon la largeur des lignes et les cycles dummy de la commande, puis fusionnez les lectures sur une seule ligne et sur quatre lignes en fonction de l’adresse de la flash.<sup>[[5]](#references)[[7]](#references)</sup> `spidump` détecte automatiquement les deux formats d’export, écarte les lectures décodées avec une largeur de ligne incorrecte et indique la couverture des lectures.<sup>[[6]](#references)</sup> Depuis son dépôt, après avoir installé ses dépendances, fusionnez les captures avec :<sup>[[6]](#references)</sup>

```bash
python main.py single_lane_boot.csv --merge quad_boot.txt -o recovered_flash.bin -v
```

Le résultat reste une observation partielle, et non une image complète de la puce.<sup>[[5]](#references)[[6]](#references)</sup> Pour examiner séparément les écritures, corrélez `0x06` (activation de l’écriture), les interrogations d’état `0x05`, les opcodes d’effacement et les commandes de programmation de page `0x02`. Les données de programmation de page suivent l’adresse sur MOSI et ne sont pas incluses dans une reconstruction en lecture seule.<sup>[[5]](#references)</sup> Analysez l’image obtenue avec l’[analyse de firmware](../firmware-analysis/), tout en conservant les informations de couverture de lecture.

## References

- [1] [Analog Devices — Introduction à l’interface SPI](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [Manuel de flashrom — programmeur SPI CH341A et options de lecture/écriture](https://flashrom.org/classic_cli_manpage.html)
- [3] [Documentation de Bus Pirate — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
- [4] [VoidStar Security — Révision du hardware hacking, partie 2](https://voidstarsec.com/blog/brushing-up-part-2)
- [5] [VoidStar Security — Étendre Scapy pour la rétro-ingénierie matérielle](https://voidstarsec.com/blog/scapy-spi-reconstruction)
- [6] [spidump — capture et reconstruction de traces SPI/QSPI](https://github.com/wrongbaud/spidump)
- [7] [Analyseur QSPI pour Saleae Logic/KingstVIS](https://github.com/AddioElectronics/QSPI-Analyzer)
{{#include ../../banners/hacktricks-training.md}}
