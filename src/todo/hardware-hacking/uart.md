# UART

{{#include ../../banners/hacktricks-training.md}}

## Informations de base

UART est un protocole série, ce qui signifie qu'il transfère des données entre les composants un bit à la fois. En revanche, les protocoles de communication parallèle transmettent des données simultanément par plusieurs canaux. Les protocoles série courants incluent RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express et USB.

En général, la ligne est maintenue à un niveau élevé (à une valeur logique de 1) pendant que l'UART est dans l'état inactif. Ensuite, pour signaler le début d'un transfert de données, l'émetteur envoie un bit de départ au récepteur, pendant lequel le signal est maintenu à un niveau bas (à une valeur logique de 0). Ensuite, l'émetteur envoie de cinq à huit bits de données contenant le message réel, suivis d'un bit de parité optionnel et d'un ou deux bits d'arrêt (avec une valeur logique de 1), selon la configuration. Le bit de parité, utilisé pour la vérification des erreurs, est rarement vu en pratique. Le bit d'arrêt (ou les bits) signale la fin de la transmission.

Nous appelons la configuration la plus courante 8N1 : huit bits de données, pas de parité et un bit d'arrêt. Par exemple, si nous voulions envoyer le caractère C, ou 0x43 en ASCII, dans une configuration UART 8N1, nous enverrions les bits suivants : 0 (le bit de départ) ; 0, 1, 0, 0, 0, 0, 1, 1 (la valeur de 0x43 en binaire), et 0 (le bit d'arrêt).

![](<../../images/image (764).png>)

Outils matériels pour communiquer avec l'UART :

- Adaptateur USB-série
- Adaptateurs avec les puces CP2102 ou PL2303
- Outil polyvalent tel que : Bus Pirate, l'Adafruit FT232H, le Shikra ou le Badge Attify

### Identification des ports UART

L'UART a 4 ports : **TX**(Transmettre), **RX**(Recevoir), **Vcc**(Tension), et **GND**(Masse). Vous pourriez être en mesure de trouver 4 ports avec les lettres **`TX`** et **`RX`** **écrites** sur le PCB. Mais s'il n'y a aucune indication, vous devrez peut-être essayer de les trouver vous-même en utilisant un **multimètre** ou un **analyseur logique**.

Avec un **multimètre** et l'appareil éteint :

- Pour identifier la broche **GND**, utilisez le mode **Test de continuité**, placez la sonde noire sur la masse et testez avec la rouge jusqu'à ce que vous entendiez un son du multimètre. Plusieurs broches GND peuvent être trouvées sur le PCB, donc vous avez peut-être trouvé ou non celle appartenant à l'UART.
- Pour identifier le port **VCC**, réglez le mode **tension DC** et configurez-le à 20 V de tension. Sonde noire sur la masse et sonde rouge sur la broche. Allumez l'appareil. Si le multimètre mesure une tension constante de 3,3 V ou 5 V, vous avez trouvé la broche Vcc. Si vous obtenez d'autres tensions, réessayez avec d'autres ports.
- Pour identifier le port **TX**, mode **tension DC** jusqu'à 20 V de tension, sonde noire sur la masse, et sonde rouge sur la broche, puis allumez l'appareil. Si vous constatez que la tension fluctue pendant quelques secondes puis se stabilise à la valeur Vcc, vous avez probablement trouvé le port TX. Cela est dû au fait qu'à l'allumage, il envoie des données de débogage.
- Le port **RX** serait le plus proche des autres 3, il a la fluctuation de tension la plus faible et la valeur globale la plus basse de toutes les broches UART.

Vous pouvez confondre les ports TX et RX et rien ne se passerait, mais si vous confondez le port GND et le port VCC, vous pourriez endommager le circuit.

Dans certains appareils cibles, le port UART est désactivé par le fabricant en désactivant RX ou TX ou même les deux. Dans ce cas, il peut être utile de tracer les connexions sur le circuit imprimé et de trouver un point de rupture. Un indice fort pour confirmer l'absence de détection de l'UART et la rupture du circuit est de vérifier la garantie de l'appareil. Si l'appareil a été expédié avec une garantie, le fabricant laisse des interfaces de débogage (dans ce cas, UART) et donc, doit avoir déconnecté l'UART et le reconnectera lors du débogage. Ces broches de rupture peuvent être connectées par soudure ou fils de cavalier.

### Identification du débit en bauds UART

Le moyen le plus simple d'identifier le bon débit en bauds est de regarder la **sortie de la broche TX et d'essayer de lire les données**. Si les données que vous recevez ne sont pas lisibles, passez au débit en bauds suivant possible jusqu'à ce que les données deviennent lisibles. Vous pouvez utiliser un adaptateur USB-série ou un appareil polyvalent comme Bus Pirate pour cela, associé à un script d'aide, tel que [baudrate.py](https://github.com/devttys0/baudrate/). Les débits en bauds les plus courants sont 9600, 38400, 19200, 57600 et 115200.

> [!CAUTION]
> Il est important de noter que dans ce protocole, vous devez connecter le TX d'un appareil au RX de l'autre !

## Adaptateur CP210X UART à TTY

La puce CP210X est utilisée dans de nombreuses cartes de prototypage comme NodeMCU (avec esp8266) pour la communication série. Ces adaptateurs sont relativement peu coûteux et peuvent être utilisés pour se connecter à l'interface UART de la cible. L'appareil a 5 broches : 5V, GND, RXD, TXD, 3.3V. Assurez-vous de connecter la tension comme supportée par la cible pour éviter tout dommage. Enfin, connectez la broche RXD de l'adaptateur à TXD de la cible et la broche TXD de l'adaptateur à RXD de la cible.

En cas de non-détection de l'adaptateur, assurez-vous que les pilotes CP210X sont installés sur le système hôte. Une fois l'adaptateur détecté et connecté, des outils comme picocom, minicom ou screen peuvent être utilisés.

Pour lister les appareils connectés aux systèmes Linux/MacOS :
```
ls /dev/
```
Pour une interaction de base avec l'interface UART, utilisez la commande suivante :
```
picocom /dev/<adapter> --baud <baudrate>
```
Pour minicom, utilisez la commande suivante pour le configurer :
```
minicom -s
```
Configurez les paramètres tels que le baudrate et le nom de l'appareil dans l'option `Serial port setup`.

Après la configuration, utilisez la commande `minicom` pour démarrer la console UART.

## UART Via Arduino UNO R3 (Cartes à puce Atmel 328p amovibles)

Dans le cas où des adaptateurs UART Serial vers USB ne sont pas disponibles, l'Arduino UNO R3 peut être utilisé avec un hack rapide. Étant donné que l'Arduino UNO R3 est généralement disponible partout, cela peut faire gagner beaucoup de temps.

L'Arduino UNO R3 dispose d'un adaptateur USB vers Serial intégré sur la carte elle-même. Pour obtenir une connexion UART, il suffit de retirer la puce microcontrôleur Atmel 328p de la carte. Ce hack fonctionne sur les variantes de l'Arduino UNO R3 ayant l'Atmel 328p non soudé sur la carte (la version SMD est utilisée). Connectez la broche RX de l'Arduino (broche numérique 0) à la broche TX de l'interface UART et la broche TX de l'Arduino (broche numérique 1) à la broche RX de l'interface UART.

Enfin, il est recommandé d'utiliser l'IDE Arduino pour obtenir la console série. Dans la section `tools` du menu, sélectionnez l'option `Serial Console` et définissez le baud rate selon l'interface UART.

## Bus Pirate

Dans ce scénario, nous allons sniffer la communication UART de l'Arduino qui envoie toutes les impressions du programme au Moniteur Série.
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
## Dumping Firmware with UART Console

Le UART Console offre un excellent moyen de travailler avec le firmware sous-jacent dans un environnement d'exécution. Mais lorsque l'accès au UART Console est en lecture seule, cela peut introduire de nombreuses contraintes. Dans de nombreux dispositifs embarqués, le firmware est stocké dans des EEPROM et exécuté dans des processeurs ayant une mémoire volatile. Par conséquent, le firmware est maintenu en lecture seule puisque le firmware original lors de la fabrication se trouve à l'intérieur de l'EEPROM lui-même et tout nouveau fichier serait perdu en raison de la mémoire volatile. Ainsi, le dumping du firmware est un effort précieux lors du travail avec des firmwares embarqués.

Il existe de nombreuses façons de le faire et la section SPI couvre des méthodes pour extraire le firmware directement de l'EEPROM avec divers dispositifs. Cependant, il est recommandé d'essayer d'abord de dumper le firmware avec UART, car le dumping du firmware avec des dispositifs physiques et des interactions externes peut être risqué.

Dumper le firmware depuis le UART Console nécessite d'abord d'accéder aux bootloaders. De nombreux fournisseurs populaires utilisent uboot (Universal Bootloader) comme leur bootloader pour charger Linux. Par conséquent, obtenir l'accès à uboot est nécessaire.

Pour accéder au bootloader, connectez le port UART à l'ordinateur et utilisez l'un des outils de console série tout en maintenant l'alimentation de l'appareil déconnectée. Une fois la configuration prête, appuyez sur la touche Entrée et maintenez-la enfoncée. Enfin, connectez l'alimentation à l'appareil et laissez-le démarrer.

Faire cela interrompra le chargement de uboot et fournira un menu. Il est recommandé de comprendre les commandes uboot et d'utiliser le menu d'aide pour les lister. Cela pourrait être la commande `help`. Étant donné que différents fournisseurs utilisent différentes configurations, il est nécessaire de comprendre chacune d'elles séparément.

En général, la commande pour dumper le firmware est :
```
md
```
qui signifie "vidage de mémoire". Cela affichera le contenu de la mémoire (contenu EEPROM) à l'écran. Il est recommandé de consigner la sortie de la console série avant de commencer la procédure pour capturer le vidage de mémoire.

Enfin, il suffit de supprimer toutes les données inutiles du fichier journal et de stocker le fichier sous le nom `filename.rom` et d'utiliser binwalk pour extraire le contenu :
```
binwalk -e <filename.rom>
```
Cela listera les contenus possibles de l'EEPROM selon les signatures trouvées dans le fichier hex.

Cependant, il est nécessaire de noter qu'il n'est pas toujours vrai que le uboot est déverrouillé même s'il est utilisé. Si la touche Entrée ne fait rien, vérifiez d'autres touches comme la touche Espace, etc. Si le bootloader est verrouillé et n'est pas interrompu, cette méthode ne fonctionnera pas. Pour vérifier si uboot est le bootloader de l'appareil, vérifiez la sortie sur la console UART pendant le démarrage de l'appareil. Il pourrait mentionner uboot pendant le démarrage.

{{#include ../../banners/hacktricks-training.md}}
