# UART

{{#include ../../banners/hacktricks-training.md}}

## Informations de base

UART est une interface série asynchrone qui transmet un flux de bits encadré sans horloge partagée. Ne confondez pas UART au niveau logique et RS-232 : RS-232 utilise des niveaux de tension différents, souvent négatifs, et nécessite un transceiver.<sup>[[1]](#references)[[3]](#references)</sup>

En général, la ligne est maintenue à l’état haut (valeur logique 1) lorsque UART est au repos. Pour signaler le début d’un transfert de données, l’émetteur envoie ensuite un bit de départ au récepteur, pendant lequel le signal est maintenu à l’état bas (valeur logique 0). L’émetteur envoie ensuite cinq à huit bits de données contenant le message proprement dit, suivis d’un bit de parité facultatif et d’un ou deux bits d’arrêt (valeur logique 1), selon la configuration. Le bit de parité, utilisé pour vérifier les erreurs, est rarement employé en pratique. Le ou les bits d’arrêt signalent la fin de la transmission.

La configuration la plus courante est 8N1 : huit bits de données, aucune parité et un bit d’arrêt. UART envoie d’abord le bit de données de poids faible : le caractère ASCII `C` (`0x43`) est donc transmis ainsi : départ `0` ; données `1, 1, 0, 0, 0, 0, 1, 0` ; arrêt `1`.<sup>[[1]](#references)</sup>

![UART : La configuration la plus courante est 8N1 : huit bits de données, aucune parité et un bit d’arrêt. Par exemple, pour envoyer le caractère C, ou 0x43 en ASCII, avec UART en 8N1](<../../images/image (764).png>)

Outils matériels pour communiquer avec UART :

- Adaptateur USB-série
- Adaptateurs avec les puces CP2102 ou PL2303
- Outil multifonction comme : Bus Pirate, Adafruit FT232H, Shikra ou Attify Badge

### Identification des ports UART

Un connecteur de debug typique expose **TX**, **RX** et **GND** ; il peut également exposer une broche **Vcc/Vref**, une broche de réinitialisation ou des broches de contrôle de flux. Vcc n’est pas un signal UART et ne doit normalement servir que de référence de tension — et non être connectée comme source d’alimentation — sauf si le schéma de la carte et les besoins en courant sont connus.<sup>[[2]](#references)[[3]](#references)</sup>

Commencez avec l’appareil **éteint** et déconnecté :

- Identifiez **GND** en mode continuité, par rapport à un plan de masse connu, au blindage d’un connecteur ou à la masse de l’alimentation. N’utilisez jamais le mode continuité/résistance sur une carte sous tension.
- Passez en mode tension continue avant de mettre la cible sous tension. Mesurez les broches candidates par rapport à la masse pour déterminer la tension logique. Une tension stable peut correspondre à Vcc/Vref ; ne supposez pas qu’il est sûr de s’y connecter.
- Observez les broches candidates avec un analyseur logique ou un oscilloscope pendant le démarrage. **TX** est généralement au repos à l’état haut et présente des salves de données encadrées. Un multimètre peut afficher une variation moyenne, mais ne permet pas de vérifier le cadrage ni le débit en bauds.
- **RX** peut rester au repos ; sa proximité avec TX ne suffit pas à l’identifier sans risque. Suivez les pistes du PCB, consultez la fiche technique du SoC ou utilisez un analyseur à haute impédance avant de lui envoyer un signal.

Inverser TX et RX n’entraîne généralement aucune communication ; confondre l’alimentation, la masse ou les niveaux de signal peut endommager définitivement la cible ou l’adaptateur. Connectez d’abord la masse et commencez en mode **réception seule** (TX de la cible vers RX de l’adaptateur).

Les fabricants peuvent omettre le connecteur, ne pas installer les résistances en série, désactiver la console dans le firmware ou n’exposer que TX. Suivez les pistes des points de test et des empreintes de résistances proches jusqu’au SoC, et n’ajoutez une connexion temporaire à haute impédance qu’après avoir confirmé le niveau électrique. La présence d’une garantie ne signifie pas qu’un UART accessible doit exister.

### Identification du débit en bauds UART

La méthode la plus simple pour identifier le débit en bauds correct consiste à observer la sortie de la **broche TX et à essayer de lire les données**. Si les données reçues sont illisibles, essayez le débit en bauds possible suivant jusqu’à ce que les données deviennent lisibles. Vous pouvez utiliser un adaptateur USB-série ou un appareil multifonction comme Bus Pirate, avec un script utilitaire tel que [baudrate.py](https://github.com/devttys0/baudrate/). Les débits en bauds les plus courants sont 9600, 38400, 19200, 57600 et 115200.

> [!CAUTION]
> Il est important de noter que, dans ce protocole, vous devez connecter le TX d’un appareil au RX de l’autre !

## Adaptateur CP210X UART vers TTY

Les ponts USB-vers-UART CP210x équipent de nombreuses cartes de prototypage et de nombreux adaptateurs bon marché. Les modules courants exposent des broches d’alimentation aux côtés de GND, RXD et TXD, mais leurs connecteurs et leurs niveaux d’E/S varient. Vérifiez la tension réelle à partir de la conception de la carte ou de sa fiche technique. En général, connectez uniquement GND et RX de l’adaptateur à TX de la cible ; après validation en réception seule, connectez également TX de l’adaptateur à RX de la cible. Ne connectez pas la broche d’alimentation 5 V/3,3 V de l’adaptateur, sauf si vous souhaitez alimenter une cible dont la tolérance à cette tension est connue.<sup>[[3]](#references)</sup>

Si l’adaptateur n’est pas détecté, vérifiez que les pilotes CP210X sont installés sur le système hôte. Une fois l’adaptateur détecté et connecté, vous pouvez utiliser des outils comme picocom, minicom ou screen.

Pour afficher la liste des appareils connectés aux systèmes Linux/MacOS :

```
ls /dev/
```

Pour interagir de manière basique avec l’interface UART, utilisez la commande suivante :

```
picocom /dev/<adapter> --baud <baudrate>
```

Pour minicom, utilisez la commande suivante pour le configurer :

```
minicom -s
```

Configurez les paramètres tels que le débit en bauds et le nom du périphérique dans l’option `Serial port setup`.

Une fois la configuration terminée, lancez `minicom` pour ouvrir la console UART.

## UART via Arduino UNO R3 (cartes avec puce Atmel 328p amovible)

Si aucun adaptateur série-USB UART n’est disponible, vous pouvez utiliser un Arduino UNO R3 avec un hack rapide. Comme l’Arduino UNO R3 est généralement disponible partout, cela peut vous faire gagner beaucoup de temps.

L’Arduino UNO R3 intègre un adaptateur USB-série. Pour établir une connexion UART, retirez simplement la puce microcontrôleur Atmel 328p de la carte. Ce hack fonctionne avec les variantes de l’Arduino UNO R3 dont la puce Atmel 328p n’est pas soudée à la carte (une version SMD est utilisée). Connectez la broche RX de l’Arduino (broche numérique 0) à la broche TX de l’interface UART, et la broche TX de l’Arduino (broche numérique 1) à la broche RX de l’interface UART.

Utilisez le **Moniteur série** de l’IDE Arduino ou un terminal dédié avec le débit en bauds cible. Les signaux série de l’Uno R3 classique utilisent une logique de 5 V : utilisez donc un convertisseur de niveau ou un diviseur de tension avant de les connecter à une cible en 3,3 V ou à une tension inférieure.

## Bus Pirate

La transcription suivante utilise l’interface du firmware Bus Pirate héritée pour surveiller la sortie UART. Les versions plus récentes du firmware Bus Pirate utilisent des commandes telles que `m uart`, `{`/`}`, `monitor` ou `bridge` ; consultez la documentation correspondant à la version installée.<sup>[[2]](#references)</sup>

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

## Extraction du firmware avec la console UART

Une console UART fournit un accès à l’exécution aux journaux de démarrage et, parfois, à un shell de bootloader ou de système d’exploitation. Même en lecture seule, une console révèle les cartes mémoire, les pilotes flash, les arguments de démarrage, les dispositions des partitions et les versions du firmware. Le firmware peut se trouver sur une mémoire SPI NOR/NAND, eMMC ou un autre périphérique ; il n’est généralement pas exécuté depuis une EEPROM, et les fichiers écrits sur un système de fichiers persistant monté ne disparaissent pas nécessairement au redémarrage.

Il existe plusieurs méthodes d’acquisition ; la section SPI couvre les lectures directes de la mémoire flash externe. L’acquisition assistée par console peut être moins intrusive lorsque le bootloader fournit déjà une commande de lecture sûre, mais toute interruption du démarrage ou commande flash peut affecter la disponibilité. Il faut donc consigner l’état initial et éviter les opérations d’écriture ou d’effacement.

L’extraction du firmware assistée par console commence souvent par l’interruption d’un bootloader. De nombreux appareils Linux embarqués utilisent **Das U-Boot**, mais d’autres utilisent des bootloaders propriétaires ou désactivent la console interactive.

Pour vérifier la présence d’un bootloader interactif, connectez le chemin de réception UART et le terminal alors que la cible est hors tension, démarrez la journalisation, puis mettez-la sous tension. Suivez l’invite d’autoboot affichée ; selon la version, l’interruption peut nécessiter une touche, une courte séquence, ou être entièrement désactivée.

Si l’interruption réussit, utilisez `help`, `printenv` et les commandes de découverte en lecture seule pour comprendre la disposition de la mémoire et du stockage propre au fabricant avant d’accéder à des adresses.

Dans U-Boot, `md` affiche la **mémoire adressable**, et non automatiquement « l’EEPROM ». Commencez par utiliser des commandes propres à la carte, telles que `mtd list`, `sf probe`, `mmc info`, `part list`, les variables d’environnement et les journaux de démarrage, afin d’identifier l’adresse mappée appropriée ou de charger une région flash en RAM. Affichez ensuite une plage connue octet par octet :<sup>[[4]](#references)</sup>

```
md.b <address> <byte_count>
```

Consignez la sortie série avant de commencer. La sortie `md.b` contient des adresses et une colonne ASCII : il s’agit donc d’une représentation textuelle, et non d’une image ROM brute.

Supprimez les colonnes d’adresse et ASCII, concaténez uniquement les champs d’octets hexadécimaux, puis décodez-les en binaire (par exemple avec `xxd -r -p`). Vérifiez le nombre d’octets attendu et consignez une empreinte avant l’analyse :

```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```

Binwalk identifie ensuite les signatures connues dans le binaire reconstruit. Une lecture directe de la mémoire flash via l’interface SPI/eMMC/NAND appropriée est généralement plus rapide et moins sujette aux erreurs lorsque la console ne peut pas transférer les données de manière fiable.

U-Boot peut désactiver l’interruption, exiger une séquence de touches spécifique au fournisseur ou verrouiller les commandes mémoire/flash. Suivez l’invite d’autoboot et le journal de démarrage au lieu d’envoyer des caractères à l’aveugle. Si la console ne peut pas être interrompue, conservez le journal de démarrage et utilisez une méthode non invasive d’acquisition du firmware.

## References

- [1] [Manuel de référence de la famille Microchip PIC32 - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Documentation Bus Pirate - mode UART et limites électriques](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - fiche technique CP2102C](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [Documentation U-Boot - commande d’affichage de la mémoire `md`](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
{{#include ../../banners/hacktricks-training.md}}
