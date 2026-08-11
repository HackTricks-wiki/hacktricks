# UART

{{#include ../../banners/hacktricks-training.md}}

## Informations de base

UART est une interface série asynchrone qui transfère un flux de bits encadré sans horloge partagée. Il ne faut pas confondre l'UART de niveau logique avec le RS-232 : le RS-232 utilise des niveaux de tension différents, souvent négatifs, et nécessite un transceiver.<sup>[[1]](#references)[[3]](#references)</sup>

En général, la ligne est maintenue à l'état haut (valeur logique 1) lorsque l'UART est au repos. Ensuite, pour signaler le début d'un transfert de données, l'émetteur envoie un bit de départ au récepteur, pendant lequel le signal est maintenu à l'état bas (valeur logique 0). L'émetteur envoie ensuite cinq à huit bits de données contenant le message réel, suivis d'un bit de parité facultatif et d'un ou deux bits d'arrêt (avec une valeur logique 1), selon la configuration. Le bit de parité, utilisé pour la vérification des erreurs, est rarement observé en pratique. Le ou les bits d'arrêt signalent la fin de la transmission.

La configuration la plus courante est 8N1 : huit bits de données, aucune parité et un bit d'arrêt. L'UART envoie d'abord le bit de données de poids faible, donc le caractère ASCII `C` (`0x43`) est transmis ainsi : start `0` ; données `1, 1, 0, 0, 0, 0, 1, 0` ; stop `1`.<sup>[[1]](#references)</sup>

![UART : la configuration la plus courante est appelée 8N1 : huit bits de données, aucune parité et un bit d'arrêt. Par exemple, pour envoyer le caractère C, ou 0x43 en ASCII, dans un UART 8N1](<../../images/image (764).png>)

Outils matériels pour communiquer avec un UART :

- Adaptateur USB-série
- Adaptateurs équipés des puces CP2102 ou PL2303
- Outil polyvalent tel que : Bus Pirate, l'Adafruit FT232H, le Shikra ou l'Attify Badge

### Identification des ports UART

Un header de debug typique expose **TX**, **RX** et **GND** ; il peut également exposer une broche **Vcc/Vref**, le reset ou des broches de contrôle de flux. Vcc n'est pas un signal UART et doit normalement être utilisé uniquement comme référence de tension, et non connecté comme source d'alimentation, sauf si le schéma de la carte et les besoins en courant sont connus.<sup>[[2]](#references)[[3]](#references)</sup>

Commencez avec l'appareil **éteint** et déconnecté :

- Identifiez **GND** en mode continuité par rapport à un plan de masse connu, au blindage d'un connecteur ou à la masse de l'alimentation. N'utilisez jamais le mode continuité/résistance sur une carte sous tension.
- Passez en mode tension continue avant de mettre la cible sous tension. Mesurez les broches candidates par rapport à la masse afin d'identifier la tension logique. Un rail stable peut être Vcc/Vref ; ne supposez pas qu'il est possible de le connecter sans danger.
- Observez les broches candidates avec un analyseur logique ou un oscilloscope pendant le démarrage. **TX** est généralement au repos à l'état haut et présente des rafales de données encadrées. Un multimètre peut afficher une fluctuation moyenne, mais ne peut pas valider le framing ou le baud rate.
- **RX** peut rester au repos et ne peut pas être identifié sans danger simplement parce qu'il est adjacent à TX. Suivez les pistes du PCB, consultez la fiche technique du SoC ou utilisez un analyseur à haute impédance avant de le piloter.

L'inversion de TX et RX ne produit normalement aucune communication ; confondre l'alimentation, la masse ou les niveaux de signal peut endommager définitivement la cible ou l'adaptateur. Connectez d'abord la masse et commencez en **réception uniquement** (TX de la cible vers RX de l'adaptateur).

Les fabricants peuvent supprimer le header, laisser des résistances série non installées, désactiver la console dans le firmware ou n'exposer que TX. Suivez les test pads et les empreintes de résistances proches jusqu'au SoC et ajoutez une connexion temporaire à haute impédance uniquement après avoir confirmé le niveau électrique. La présence d'une garantie n'implique pas qu'un UART accessible existe nécessairement.

### Identification du baud rate de l'UART

La manière la plus simple d'identifier le baud rate correct consiste à examiner la sortie de la **broche TX et à essayer de lire les données**. Si les données reçues ne sont pas lisibles, passez au baud rate possible suivant jusqu'à ce qu'elles deviennent lisibles. Vous pouvez utiliser un adaptateur USB-série ou un outil polyvalent comme Bus Pirate pour cela, associé à un script d'aide tel que [baudrate.py](https://github.com/devttys0/baudrate/). Les baud rates les plus courants sont 9600, 38400, 19200, 57600 et 115200.

> [!CAUTION]
> Il est important de noter que, dans ce protocole, vous devez connecter le TX d'un appareil au RX de l'autre !

## Adaptateur CP210X UART vers TTY

Les bridges USB-vers-UART CP210x sont présents sur de nombreuses cartes de prototypage et de nombreux adaptateurs bon marché. Les modules courants exposent des broches d'alimentation לצד de GND, RXD et TXD, mais leurs headers et leurs niveaux d'E/S varient. Confirmez la tension réelle à partir de la conception de la carte ou de sa fiche technique. En général, connectez uniquement GND, RX de l'adaptateur à TX de la cible et, après validation en réception uniquement, TX de l'adaptateur à RX de la cible. Ne connectez pas la broche d'alimentation 5 V/3,3 V de l'adaptateur, sauf si vous alimentez volontairement une cible dont la compatibilité est connue.<sup>[[3]](#references)</sup>

Si l'adaptateur n'est pas détecté, vérifiez que les drivers CP210X sont installés sur le système hôte. Une fois l'adaptateur détecté et connecté, des outils comme picocom, minicom ou screen peuvent être utilisés.

Pour lister les appareils connectés aux systèmes Linux/MacOS :
```
ls /dev/
```
Pour une interaction de base avec l’interface UART, utilisez la commande suivante :
```
picocom /dev/<adapter> --baud <baudrate>
```
Pour minicom, utilisez la commande suivante pour le configurer :
```
minicom -s
```
Configurez les paramètres tels que le baudrate et le nom du périphérique dans l’option `Serial port setup`.

Après la configuration, exécutez `minicom` pour ouvrir la console UART.

## UART via Arduino UNO R3 (cartes équipées d’une puce Atmel 328p amovible)

Si aucun adaptateur UART Serial vers USB n’est disponible, un Arduino UNO R3 peut être utilisé avec un quick hack. Comme l’Arduino UNO R3 est généralement disponible partout, cela peut faire gagner beaucoup de temps.

L’Arduino UNO R3 possède un adaptateur USB vers Serial intégré directement sur la carte. Pour obtenir une connexion UART, retirez simplement la puce microcontrôleur Atmel 328p de la carte. Ce hack fonctionne avec les variantes de l’Arduino UNO R3 dont l’Atmel 328p n’est pas soudé sur la carte (la version SMD est utilisée). Connectez la broche RX de l’Arduino (broche numérique 0) à la broche TX de l’interface UART, et la broche TX de l’Arduino (broche numérique 1) à la broche RX de l’interface UART.

Utilisez le **Serial Monitor** de l’Arduino IDE ou un terminal dédié avec le baudrate cible. Les signaux Serial classiques de l’Uno R3 utilisent une logique de 5 V ; utilisez donc un level shifter ou un diviseur de tension avant de les connecter à une cible en 3,3 V ou avec une tension inférieure.

## Bus Pirate

La transcription suivante utilise l’interface du firmware legacy de Bus Pirate pour surveiller la sortie UART. Les versions plus récentes du firmware Bus Pirate utilisent des commandes telles que `m uart`, `{`/`}`, `monitor` ou `bridge` ; consultez la documentation correspondant à la version installée.<sup>[[2]](#references)</sup>
```bash
# Check the modes
UART>m
1. HiZ
2. 1-WIRE
3. UART
4. I2C
5. SPI
6. 2WIRE
7. 3WIRE
8. KEYB
9. LCD
10. PIC
11. DIO
x. exit(without change)

# Select UART
(1)>3
Set serial port speed: (bps)
1. 300
2. 1200
3. 2400
4. 4800
5. 9600
6. 19200
7. 38400
8. 57600
9. 115200
10. BRG raw value

# Select the speed the communication is occurring on (you BF all this until you find readable things)
# Or you could later use the macro (4) to try to find the speed
(1)>5
Data bits and parity:
1. 8, NONE *default
2. 8, EVEN
3. 8, ODD
4. 9, NONE

# From now on pulse enter for default
(1)>
Stop bits:
1. 1 *default
2. 2
(1)>
Receive polarity:
1. Idle 1 *default
2. Idle 0
(1)>
Select output type:
1. Open drain (H=Hi-Z, L=GND)
2. Normal (H=3.3V, L=GND)

(1)>
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Start
UART>W
POWER SUPPLIES ON
Clutch engaged!!!

# Use macro (2) to read the data of the bus (live monitor)
UART>(2)
Raw UART input
Any key to exit
Escritura inicial completada:
AAA Hi Dreg! AAA
waiting a few secs to repeat....
```
## Dump de firmware avec une console UART

Une console UART fournit un accès en temps réel aux journaux de démarrage et, parfois, à un bootloader ou à un shell du système d’exploitation. Même une console en lecture seule révèle les cartes mémoire, les drivers flash, les arguments de démarrage, la disposition des partitions et les versions du firmware. Le firmware peut se trouver dans une SPI NOR/NAND, une eMMC ou un autre périphérique ; il n’est généralement pas exécuté depuis une EEPROM, et les fichiers écrits sur un système de fichiers persistant monté ne disparaissent pas nécessairement lors d’un redémarrage.

Il existe plusieurs méthodes d’acquisition, et la section SPI couvre les lectures directes depuis une mémoire flash externe. L’acquisition assistée par console peut être moins intrusive lorsque le bootloader fournit déjà une commande de lecture sûre, mais toute interruption du démarrage ou commande flash peut affecter la disponibilité. Il faut donc consigner l’état d’origine et éviter les opérations d’écriture ou d’effacement.

Le dump de firmware assisté par console commence souvent par l’interruption d’un bootloader. De nombreux appareils Linux embarqués utilisent **Das U-Boot**, mais d’autres utilisent des bootloaders propriétaires ou désactivent la console interactive.

Pour tester la présence d’un bootloader interactif, connectez la ligne de réception UART et le terminal lorsque la cible est hors tension, commencez l’enregistrement, puis mettez-la sous tension. Suivez l’invite d’autoboot affichée ; selon le build, l’interruption peut nécessiter une touche, une courte séquence, ou être entièrement désactivée.

Si l’interruption réussit, utilisez `help`, `printenv` et des commandes de découverte en lecture seule pour comprendre la disposition de la mémoire et du stockage propre à ce vendor avant d’accéder aux adresses.

Dans U-Boot, `md` affiche la **mémoire adressable**, et non automatiquement « l’EEPROM ». Utilisez d’abord des commandes spécifiques à la carte telles que `mtd list`, `sf probe`, `mmc info`, `part list`, les variables d’environnement et les journaux de démarrage afin d’identifier l’adresse mappée correcte ou de charger une région flash en RAM. Affichez ensuite une plage connue octet par octet :<sup>[[4]](#references)</sup>
```
md.b <address> <byte_count>
```
Enregistrez la sortie série avant de commencer. La sortie de `md.b` contient des adresses et une colonne ASCII ; il s’agit donc d’une représentation textuelle plutôt que d’une image ROM brute.

Supprimez les colonnes d’adresses et ASCII, concaténez uniquement les champs d’octets hexadécimaux, puis décodez-les en binaire (par exemple avec `xxd -r -p`). Vérifiez le nombre d’octets attendu et consignez un hash avant l’analyse :
```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```
Binwalk identifie ensuite les signatures connues dans le binaire reconstruit. Une lecture directe de la flash via l’interface SPI/eMMC/NAND appropriée est généralement plus rapide et moins sujette aux erreurs lorsque la console ne peut pas transférer les données de manière fiable.

U-Boot peut désactiver l’interruption, exiger une séquence de touches spécifique au fabricant ou verrouiller les commandes de mémoire/flash. Suivez l’invite d’autoboot et le boot log plutôt que de transmettre des caractères sans vérifier. Si la console ne peut pas être interrompue, conservez le boot log et passez à une méthode non invasive d’acquisition du firmware.

## References

- [1] [Manuel de référence de la famille Microchip PIC32 - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Documentation de Bus Pirate - mode UART et limites électriques](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - fiche technique du CP2102C](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [Documentation U-Boot - commande `md` d’affichage de la mémoire](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
{{#include ../../banners/hacktricks-training.md}}
