# UART

{{#include ../../banners/hacktricks-training.md}}

## Informations de base

UART est un protocole série, ce qui signifie qu’il transfère les données entre les composants un bit à la fois. À l’inverse, les protocoles de communication parallèles transmettent les données simultanément via plusieurs canaux. Les protocoles série courants incluent RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express et USB.

Généralement, la ligne est maintenue à l’état haut (avec une valeur logique de 1) lorsque UART est au repos. Ensuite, pour signaler le début d’un transfert de données, l’émetteur envoie un bit de départ au récepteur, pendant lequel le signal est maintenu à l’état bas (avec une valeur logique de 0). L’émetteur envoie ensuite cinq à huit bits de données contenant le message réel, suivis d’un bit de parité facultatif et d’un ou deux bits d’arrêt (avec une valeur logique de 1), selon la configuration. Le bit de parité, utilisé pour la vérification des erreurs, est rarement observé en pratique. Le bit d’arrêt (ou les bits d’arrêt) signale la fin de la transmission.

Nous appelons la configuration la plus courante 8N1 : huit bits de données, aucune parité et un bit d’arrêt. Par exemple, si nous voulions envoyer le caractère C, ou 0x43 en ASCII, dans une configuration UART 8N1, nous enverrions les bits suivants : 0 (le bit de départ) ; 0, 1, 0, 0, 0, 0, 1, 1 (la valeur de 0x43 en binaire), puis 0 (le bit d’arrêt).

![UART : nous appelons la configuration la plus courante 8N1 : huit bits de données, aucune parité et un bit d’arrêt. Par exemple, si nous voulions envoyer le caractère C, ou 0x43 en ASCII, dans une configuration UART 8N1](<../../images/image (764).png>)

Outils matériels pour communiquer avec UART :

- Adaptateur USB-série
- Adaptateurs équipés des puces CP2102 ou PL2303
- Outil polyvalent tel que : Bus Pirate, l’Adafruit FT232H, le Shikra ou l’Attify Badge

### Identification des ports UART

UART possède 4 ports : **TX** (Transmission), **RX** (Réception), **Vcc** (Tension) et **GND** (Masse). Vous pourrez peut-être trouver 4 ports avec les lettres **`TX`** et **`RX`** **inscrites** sur le PCB. Mais s’il n’y a aucune indication, vous devrez peut-être les identifier vous-même à l’aide d’un **multimètre** ou d’un **analyseur logique**.

Avec un **multimètre** et l’appareil éteint :

- Pour identifier la broche **GND**, utilisez le mode **test de continuité**, placez la pointe noire sur la masse et testez avec la pointe rouge jusqu’à ce que le multimètre émette un son. Plusieurs broches GND peuvent être présentes sur le PCB ; vous avez donc peut-être trouvé, ou non, celle appartenant à UART.
- Pour identifier le **port VCC**, sélectionnez le **mode tension continue** et réglez-le sur 20 V. Placez la sonde noire sur la masse et la sonde rouge sur la broche. Mettez l’appareil sous tension. Si le multimètre mesure une tension constante de 3,3 V ou 5 V, vous avez trouvé la broche Vcc. Si vous obtenez d’autres tensions, recommencez avec les autres ports.
- Pour identifier le **port TX**, sélectionnez le **mode tension continue** jusqu’à 20 V, placez la sonde noire sur la masse et la sonde rouge sur la broche, puis mettez l’appareil sous tension. Si vous constatez que la tension fluctue pendant quelques secondes avant de se stabiliser à la valeur Vcc, vous avez très probablement trouvé le port TX. En effet, lors de la mise sous tension, il envoie des données de debug.
- Le **port RX** est généralement le plus proche des trois autres ; il présente la plus faible fluctuation de tension et la plus faible valeur globale de toutes les broches UART.

Vous pouvez confondre les ports TX et RX sans que rien ne se produise, mais si vous confondez les ports GND et VCC, vous risquez de griller le circuit.

Sur certains appareils cibles, le port UART est désactivé par le fabricant en désactivant RX ou TX, voire les deux. Dans ce cas, il peut être utile de suivre les connexions sur la carte de circuit et de trouver un point de connexion. Pour confirmer l’absence de détection d’UART et la rupture du circuit, vérifiez la garantie de l’appareil. Si l’appareil a été livré avec une garantie, le fabricant laisse certaines interfaces de debug (dans ce cas, UART) et doit donc avoir déconnecté UART, puis le reconnecter pendant le debug. Ces broches de connexion peuvent être reliées par soudure ou à l’aide de fils de connexion.

### Identification du débit UART

La manière la plus simple d’identifier le débit correct consiste à observer la **sortie de la broche TX et à essayer de lire les données**. Si les données reçues ne sont pas lisibles, passez au débit possible suivant jusqu’à ce que les données deviennent lisibles. Vous pouvez utiliser un adaptateur USB-série ou un appareil polyvalent comme Bus Pirate pour cela, associé à un script auxiliaire tel que [baudrate.py](https://github.com/devttys0/baudrate/). Les débits les plus courants sont 9600, 38400, 19200, 57600 et 115200.

> [!CAUTION]
> Il est important de noter que dans ce protocole, vous devez connecter le TX d’un appareil au RX de l’autre !

## Adaptateur CP210X UART vers TTY

La puce CP210X est utilisée dans de nombreuses cartes de prototypage, comme NodeMCU (avec esp8266), pour la communication série. Ces adaptateurs sont relativement peu coûteux et peuvent être utilisés pour se connecter à l’interface UART de la cible. L’appareil possède 5 broches : 5V, GND, RXD, TXD et 3.3V. Veillez à connecter une tension compatible avec la cible afin d’éviter tout dommage. Connectez ensuite la broche RXD de l’adaptateur à TXD de la cible et la broche TXD de l’adaptateur à RXD de la cible.

Si l’adaptateur n’est pas détecté, vérifiez que les pilotes CP210X sont installés sur le système hôte. Une fois l’adaptateur détecté et connecté, des outils comme picocom, minicom ou screen peuvent être utilisés.

Pour lister les appareils connectés aux systèmes Linux/MacOS :
```
ls /dev/
```
Pour une interaction basique avec l’interface UART, utilisez la commande suivante :
```
picocom /dev/<adapter> --baud <baudrate>
```
Pour minicom, utilisez la commande suivante pour le configurer :
```
minicom -s
```
Configurez les paramètres tels que le baudrate et le nom du périphérique dans l’option `Serial port setup`.

Après la configuration, utilisez la commande `minicom` pour démarrer la UART Console.

## UART Via Arduino UNO R3 (Removable Atmel 328p Chip Boards)

Si les adaptateurs UART Serial to USB ne sont pas disponibles, Arduino UNO R3 peut être utilisé avec un quick hack. Comme Arduino UNO R3 est généralement disponible partout, cela peut faire gagner beaucoup de temps.

Arduino UNO R3 dispose d’un adaptateur USB to Serial intégré directement sur la carte. Pour obtenir une connexion UART, il suffit de retirer la puce microcontrôleur Atmel 328p de la carte. Ce hack fonctionne avec les variantes d’Arduino UNO R3 dont l’Atmel 328p n’est pas soudé sur la carte (la version SMD est utilisée dans ce modèle). Connectez la broche RX de l’Arduino (Digital Pin 0) à la broche TX de l’interface UART, et la broche TX de l’Arduino (Digital Pin 1) à la broche RX de l’interface UART.

Enfin, il est recommandé d’utiliser Arduino IDE pour accéder à la Serial Console. Dans la section `tools` du menu, sélectionnez l’option `Serial Console` et définissez le baud rate correspondant à l’interface UART.

## Bus Pirate

Dans ce scénario, nous allons sniffer la communication UART de l’Arduino, qui envoie toutes les sorties du programme vers le Serial Monitor.
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
## Dumping du Firmware avec UART Console

UART Console fournit un excellent moyen d’interagir avec le firmware sous-jacent dans l’environnement d’exécution. Cependant, lorsque l’accès à la UART Console est en lecture seule, cela peut imposer de nombreuses contraintes. Dans de nombreux appareils embarqués, le firmware est stocké dans des EEPROM et exécuté par des processeurs disposant d’une mémoire volatile. Le firmware reste donc en lecture seule, puisque le firmware d’origine installé lors de la fabrication se trouve dans l’EEPROM elle-même et que tout nouveau fichier serait perdu en raison de la mémoire volatile. Ainsi, le dumping du firmware constitue une opération précieuse lors du travail sur des firmwares embarqués.

Il existe de nombreuses façons de procéder, et la section SPI couvre les méthodes permettant d’extraire directement le firmware de l’EEPROM avec différents appareils. Toutefois, il est recommandé d’essayer d’abord de dumper le firmware avec UART, car le dumping du firmware à l’aide d’appareils physiques et d’interactions externes peut être risqué.

Le dumping du firmware depuis la UART Console nécessite d’abord d’obtenir un accès aux bootloaders. De nombreux fournisseurs utilisent uboot (Universal Bootloader) comme bootloader pour charger Linux. Il est donc nécessaire d’obtenir un accès à uboot.

Pour accéder au bootloader, connectez le port UART à l’ordinateur et utilisez l’un des outils de Serial Console, tout en laissant l’alimentation de l’appareil déconnectée. Une fois la configuration prête, appuyez sur la touche Entrée et maintenez-la enfoncée. Enfin, connectez l’alimentation à l’appareil et laissez-le démarrer.

Cette opération interrompra le chargement de uboot et affichera un menu. Il est recommandé de comprendre les commandes uboot et d’utiliser le menu help pour les lister. Il peut s’agir de la commande `help`. Comme les différents fournisseurs utilisent des configurations différentes, il est nécessaire de comprendre chacune d’elles séparément.

Généralement, la commande permettant de dumper le firmware est la suivante :
```
md
```
qui signifie « memory dump ». Cela affichera la mémoire (contenu de l’EEPROM) à l’écran. Il est recommandé d’enregistrer la sortie de la Serial Console avant de commencer la procédure afin de capturer le memory dump.

Enfin, supprimez simplement toutes les données inutiles du fichier journal, enregistrez le fichier sous le nom `filename.rom`, puis utilisez binwalk pour en extraire le contenu :
```
binwalk -e <filename.rom>
```
Cela listsera le contenu possible de l’EEPROM selon les signatures trouvées dans le fichier hexadécimal.

Cependant, il est nécessaire de noter que uboot n’est pas toujours déverrouillé, même s’il est utilisé. Si la touche Entrée ne fait rien, essayez d’autres touches comme la barre d’espace, etc. Si le bootloader est verrouillé et ne peut pas être interrompu, cette méthode ne fonctionnera pas. Pour vérifier si uboot est le bootloader de l’appareil, vérifiez la sortie sur la UART Console pendant le démarrage de l’appareil. Elle peut mentionner uboot lors du démarrage.

{{#include ../../banners/hacktricks-training.md}}
