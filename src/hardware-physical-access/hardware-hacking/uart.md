# UART

{{#include ../../banners/hacktricks-training.md}}

## Informations de base

UART est une interface série asynchrone qui transfère un flux de bits encadrés sans horloge partagée. Ne confondez pas UART au niveau logique et RS-232 : RS-232 utilise des niveaux de tension différents, souvent négatifs, et nécessite un transceiver.<sup>[[1]](#references)[[3]](#references)</sup>

En général, la ligne est maintenue à l’état haut (valeur logique 1) lorsque UART est au repos. Pour signaler le début d’un transfert de données, l’émetteur envoie ensuite un bit de départ au récepteur, pendant lequel le signal est maintenu à l’état bas (valeur logique 0). L’émetteur transmet alors cinq à huit bits de données contenant le message proprement dit, suivis d’un bit de parité facultatif et d’un ou deux bits d’arrêt (valeur logique 1), selon la configuration. Le bit de parité, utilisé pour la détection d’erreurs, est rarement utilisé en pratique. Le ou les bits d’arrêt indiquent la fin de la transmission.

La configuration la plus courante est 8N1 : huit bits de données, aucune parité et un bit d’arrêt. UART envoie d’abord le bit de données de poids faible. Ainsi, le caractère ASCII `C` (`0x43`) est transmis comme suit : départ `0` ; données `1, 1, 0, 0, 0, 0, 1, 0` ; arrêt `1`.<sup>[[1]](#references)</sup>

![UART : la configuration la plus courante est 8N1 : huit bits de données, aucune parité et un bit d’arrêt. Par exemple, pour envoyer le caractère C, soit 0x43 en ASCII, avec UART 8N1](<../../images/image (764).png>)

Outils matériels pour communiquer avec UART :

- Adaptateur USB-série
- Adaptateurs équipés de puces CP2102 ou PL2303
- Outil polyvalent tel que Bus Pirate, Adafruit FT232H, Shikra ou Attify Badge

### Repérer les ports UART

Un connecteur de debug typique expose **TX**, **RX** et **GND** ; il peut également exposer une broche **Vcc/Vref**, une broche de réinitialisation ou des broches de contrôle de flux. Vcc n’est pas un signal UART et ne doit normalement servir que de référence de tension — et non de source d’alimentation — sauf si le schéma de la carte et les besoins en courant sont connus.<sup>[[2]](#references)[[3]](#references)</sup>

Commencez par éteindre et déconnecter l’appareil :

- Repérez **GND** en mode continuité, en le comparant à un plan de masse connu, au blindage d’un connecteur ou à la masse de l’alimentation. N’utilisez jamais le mode continuité/résistance sur une carte sous tension.
- Passez en mode tension continue avant de mettre la cible sous tension. Mesurez les broches candidates par rapport à la masse pour déterminer la tension logique. Une tension stable peut correspondre à Vcc/Vref ; ne supposez pas qu’il est sûr de s’y connecter.
- Observez les broches candidates avec un analyseur logique ou un oscilloscope pendant le démarrage. **TX** est généralement au repos à l’état haut et présente des rafales de données encadrées. Un multimètre peut afficher une fluctuation moyenne, mais ne permet pas de vérifier le cadrage ni le débit en bauds.
- **RX** peut rester au repos ; sa proximité avec TX ne suffit pas pour l’identifier sans risque. Suivez les pistes du PCB, consultez la fiche technique du SoC ou utilisez un analyseur à haute impédance avant de lui appliquer un signal.

Inverser TX et RX n’empêche généralement que la communication ; confondre l’alimentation, la masse ou les niveaux des signaux peut endommager définitivement la cible ou l’adaptateur. Connectez d’abord la masse et commencez en **réception seule** (TX de la cible vers RX de l’adaptateur).

Les fabricants peuvent omettre le connecteur, ne pas monter les résistances série, désactiver la console dans le firmware ou n’exposer que TX. Suivez les pistes de test et les empreintes de résistances proches jusqu’au SoC, et n’ajoutez une connexion temporaire à haute impédance qu’après avoir confirmé le niveau électrique. La présence d’une garantie n’implique pas qu’un UART accessible existe.

### Déterminer le débit en bauds UART

La méthode la plus simple pour déterminer le débit en bauds consiste à observer la sortie de la broche **TX** et à essayer de lire les données. Si les données reçues sont illisibles, passez au débit en bauds possible suivant jusqu’à ce qu’elles deviennent lisibles. Pour cela, vous pouvez utiliser un adaptateur USB-série ou un appareil polyvalent comme Bus Pirate, avec un script auxiliaire tel que [baudrate.py](https://github.com/devttys0/baudrate/). Les débits en bauds les plus courants sont 9600, 38400, 19200, 57600 et 115200.

> [!CAUTION]
> Il est important de noter que, dans ce protocole, vous devez connecter le TX d’un appareil au RX de l’autre !

### Automatiser la capture UART au démarrage avec SCPI

Si la sortie au démarrage est brève ou si la pastille TX n’a pas encore été repérée, automatisez plusieurs démarrages au lieu de manipuler l’alimentation et l’oscilloscope manuellement. Connectez une alimentation programmable avec limitation de courant à l’entrée d’alimentation vérifiée de la cible. Sondez chaque pastille TX candidate avec une entrée d’oscilloscope à haute impédance et une masse commune ; n’appliquez aucun signal à la pastille.<sup>[[5]](#references)</sup>

VISA ouvre des sessions d’instruments série ou Ethernet, tandis que SCPI contrôle la sortie, le déclenchement et la lecture des formes d’onde.<sup>[[5]](#references)[[6]](#references)</sup> Installez `pyvisa` et `pyvisa-py` (ainsi que `pyserial` pour les ressources VISA série) ; `ResourceManager('@py')` sélectionne explicitement le backend Python.<sup>[[5]](#references)[[7]](#references)</sup> Remplacez les chaînes de ressources et les commandes par celles prises en charge par les instruments utilisés.<sup>[[5]](#references)</sup>

Dans l’exemple du Rigol MSO5000, activez un déclenchement unique sur front descendant avant de mettre la carte sous tension : la broche TX UART, au repos à l’état haut, passe d’abord à l’état bas pour le bit de départ.<sup>[[5]](#references)</sup> Réglez le seuil de déclenchement entre les niveaux haut au repos et bas mesurés, et réglez la base de temps pour couvrir l’intervalle de démarrage qui vous intéresse.<sup>[[5]](#references)[[6]](#references)</sup> `:TRIG:HOLD` peut supprimer les fronts répétés lors de captures continues, mais ne remplace pas la vérification qu’une capture unique est bien terminée.<sup>[[5]](#references)</sup> Le code suivant capture un démarrage et enregistre les échantillons sous forme d’octets non signés ainsi que leurs métadonnées de mise à l’échelle ; en cas de délai d’attente, il éteint la cible au lieu d’attendre indéfiniment.<sup>[[5]](#references)[[6]](#references)</sup>

<details>
<summary>Capture d’une forme d’onde UART au démarrage avec PyVISA et déclenchement unique</summary>

```python
import time
from pathlib import Path
import pyvisa

rm = pyvisa.ResourceManager('@py')
psu = rm.open_resource('ASRL/dev/ttyUSB0::INSTR')
scope = rm.open_resource('TCPIP::192.0.2.10::INSTR')
psu.baud_rate = 115200
scope.timeout = 5000
try:
    print(psu.query('*IDN?').strip(), scope.query('*IDN?').strip())
    psu.write('OUTP OFF')
    psu.write('SOUR:VOLT 3.3')
    psu.write('SOUR:CURR 0.5')
    for cmd in (':CHAN1:DISP ON', ':CHAN1:SCAL 0.5',
                ':TIM:MAIN:SCAL 0.05', ':TRIG:MODE EDGE',
                ':TRIG:EDGE:SOUR CHAN1', ':TRIG:EDGE:LEV 1.5',
                ':TRIG:EDGE:SLOP NEG'):
        scope.write(cmd)
    scope.write(':SING')
    psu.write('OUTP ON')
    deadline = time.monotonic() + 30
    while scope.query(':TRIG:STAT?').strip() != 'STOP':
        if time.monotonic() >= deadline:
            raise TimeoutError('No single-shot trigger')
        time.sleep(0.5)
    scope.write(':WAV:SOUR CHAN1')
    scope.write(':WAV:MODE RAW')
    scope.write(':WAV:FORM BYTE')
    preamble = scope.query(':WAV:PRE?').strip()
    points = int(preamble.split(',')[2])
    scope.write(f':WAV:POIN {points}')
    scope.write(':WAV:STAR 1')
    scope.write(f':WAV:STOP {points}')
    scope.timeout = 120000
    raw = scope.query_binary_values(':WAV:DATA?', datatype='B', container=bytes)
    if len(raw) != points:
        raise ValueError('Incomplete waveform; use instrument-specific batch reads')
    Path('capture.bin').write_bytes(raw)
    Path('capture_preamble.txt').write_text(preamble + '\n')
finally:
    psu.write('OUTP OFF')
    scope.close()
    psu.close()
    rm.close()
```

</details>

Pour une inspection des pastilles, répétez la capture unique après avoir déplacé la sonde, ou laissez la session d’alimentation ouverte et faites basculer sa sortie en alternant un délai de démarrage et une période hors tension. Réarmez l’oscilloscope avant chaque mise sous tension afin que chaque fichier corresponde à un démarrage et à une pastille.<sup>[[5]](#references)</sup>

Le préambule Rigol est `<format>,<type>,<points>,<count>,<xincrement>,...`.<sup>[[6]](#references)</sup> La **troisième** valeur indique le nombre de points, et non la fréquence d’échantillonnage comme indiqué dans l’article.<sup>[[5]](#references)[[6]](#references)</sup> Dans son exemple, `25,000,000` points et `xincrement = 2e-8` secondes impliquent `1 / xincrement = 50,000,000` échantillons/seconde, et non 25 MSa/s.<sup>[[5]](#references)[[6]](#references)</sup> Conservez le préambule avec le fichier binaire et vérifiez que la longueur des données lues correspond à `<points>` ; le guide décrit les lectures segmentées/par lots pour les enregistrements volumineux.<sup>[[6]](#references)</sup>

Pour décoder le signal capturé, importez `capture.bin` dans PulseView en tant que **Raw Analog Data Without Header**, choisissez des valeurs non signées sur 8 bits (`U8`) et indiquez la fréquence d’échantillonnage calculée à partir de `xincrement`.<sup>[[5]](#references)[[6]](#references)</sup> Appliquez **Logic via Threshold** au canal analogique en choisissant un seuil entre les valeurs d’échantillon basses et hautes.<sup>[[5]](#references)</sup> Mesurez la largeur d’un bit de démarrage net pour estimer le débit en bauds (environ 17.36 µs pour 57,600 bauds), puis appliquez le décodeur UART de PulseView et vérifiez que plusieurs trames sont décodées de manière cohérente.<sup>[[5]](#references)</sup> Un seul front descendant ne prouve pas qu’une pastille est une UART.

## Adaptateur CP210X UART vers TTY

Les ponts USB-vers-UART CP210x équipent de nombreuses cartes de prototypage et des adaptateurs peu coûteux. Les modules courants exposent des broches d’alimentation ainsi que GND, RXD et TXD, mais leurs connecteurs et leurs niveaux d’E/S varient. Vérifiez la tension réelle dans la conception de la carte ou la fiche technique. En général, connectez uniquement GND, RX de l’adaptateur à TX de la cible et, après validation en réception seule, TX de l’adaptateur à RX de la cible. Ne connectez pas la broche d’alimentation 5 V/3.3 V de l’adaptateur, sauf si vous souhaitez alimenter une cible dont la tolérance à cette tension est connue.<sup>[[3]](#references)</sup>

Si l’adaptateur n’est pas détecté, vérifiez que les pilotes CP210X sont installés sur le système hôte. Une fois l’adaptateur détecté et connecté, vous pouvez utiliser des outils comme picocom, minicom ou screen.

Pour répertorier les périphériques connectés aux systèmes Linux/MacOS :

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

Configurez les paramètres tels que le baudrate et le nom de l’appareil dans l’option `Serial port setup`.

Une fois la configuration terminée, lancez `minicom` pour ouvrir la console UART.

## UART via Arduino UNO R3 (cartes avec puce Atmel 328p amovible)

Si aucun adaptateur série-USB UART n’est disponible, vous pouvez utiliser un Arduino UNO R3 avec une petite astuce. Comme l’Arduino UNO R3 est généralement disponible partout, cela peut vous faire gagner beaucoup de temps.

L’Arduino UNO R3 intègre un adaptateur USB-série. Pour établir une connexion UART, retirez simplement la puce microcontrôleur Atmel 328p de la carte. Cette astuce fonctionne avec les variantes de l’Arduino UNO R3 dont l’Atmel 328p n’est pas soudé à la carte (elles utilisent la version SMD). Reliez la broche RX de l’Arduino (broche numérique 0) à la broche TX de l’interface UART, puis la broche TX de l’Arduino (broche numérique 1) à la broche RX de l’interface UART.

Utilisez le **Serial Monitor** de l’Arduino IDE ou un terminal dédié réglé sur le baudrate cible. Les signaux série des Uno R3 classiques utilisent une logique 5 V ; utilisez donc un convertisseur de niveau ou un diviseur de tension avant de les connecter à une cible 3,3 V ou de tension inférieure.

## Bus Pirate

La transcription suivante utilise l’interface du firmware Bus Pirate historique pour surveiller la sortie UART. Les versions plus récentes du firmware Bus Pirate utilisent des commandes telles que `m uart`, `{`/`}`, `monitor` ou `bridge` ; consultez la documentation correspondant à la version installée.<sup>[[2]](#references)</sup>

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

## Dump du firmware avec une console UART

Une console UART donne accès, pendant l’exécution, aux journaux de démarrage et parfois à un bootloader ou à un shell du système d’exploitation. Même une console en lecture seule révèle les cartes mémoire, les pilotes flash, les arguments de démarrage, la disposition des partitions et les versions du firmware. Le firmware peut se trouver dans une mémoire SPI NOR/NAND, une eMMC ou un autre périphérique ; il n’est généralement pas exécuté depuis une EEPROM, et les fichiers écrits sur un système de fichiers persistant monté ne disparaissent pas forcément au redémarrage.

Il existe plusieurs méthodes d’acquisition ; la section SPI traite des lectures directes depuis la mémoire flash externe. L’acquisition assistée par console peut être moins invasive si le bootloader propose déjà une commande de lecture sûre. Toutefois, toute interruption du démarrage ou commande flash peut affecter la disponibilité : consignez l’état initial et évitez les opérations d’écriture ou d’effacement.

L’extraction du firmware assistée par console commence souvent par l’interruption d’un bootloader. De nombreux appareils Linux embarqués utilisent **Das U-Boot**, mais d’autres utilisent des bootloaders propriétaires ou désactivent la console interactive.

Pour vérifier si un bootloader interactif est disponible, connectez la ligne de réception UART et le terminal lorsque la cible est hors tension, démarrez l’enregistrement, puis mettez-la sous tension. Suivez l’invite d’autoboot affichée ; selon la version, l’interruption peut nécessiter une touche, une courte séquence, ou être entièrement désactivée.

Si l’interruption réussit, utilisez `help`, `printenv` et des commandes de découverte en lecture seule pour comprendre la disposition mémoire et le stockage propres au fabricant avant d’accéder à des adresses.

Dans U-Boot, `md` affiche la **mémoire adressable**, et non automatiquement « l’EEPROM ». Commencez par utiliser des commandes propres à la carte, comme `mtd list`, `sf probe`, `mmc info`, `part list`, ainsi que les variables d’environnement et les journaux de démarrage, pour identifier la bonne adresse mappée ou charger une région flash en RAM. Affichez ensuite une plage connue octet par octet :<sup>[[4]](#references)</sup>

```
md.b <address> <byte_count>
```

Enregistrez la sortie série avant de commencer. La sortie de `md.b` contient des adresses et une colonne ASCII : il s’agit donc d’une représentation textuelle, et non d’une image ROM brute.

Supprimez les colonnes d’adresses et ASCII, concaténez uniquement les champs d’octets hexadécimaux, puis décodez-les en binaire (par exemple avec `xxd -r -p`). Vérifiez le nombre d’octets attendu et consignez une empreinte avant l’analyse :

```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```

Binwalk identifie ensuite les signatures connues dans le binaire reconstruit. Une lecture directe de la flash via l’interface SPI/eMMC/NAND appropriée est généralement plus rapide et moins sujette aux erreurs lorsque la console ne peut pas transférer les données de manière fiable.

U-Boot peut désactiver l’interruption, exiger une séquence de touches propre au fournisseur ou verrouiller les commandes mémoire/flash. Suivez l’invite d’autoboot et le journal de démarrage plutôt que d’envoyer des caractères à l’aveugle. Si la console ne peut pas être interrompue, conservez le journal de démarrage et passez à une méthode non invasive d’acquisition du firmware.

## References

- [1] [Manuel de référence de la famille PIC32 Microchip - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Documentation Bus Pirate - mode UART et limites électriques](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - fiche technique CP2102C](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [Documentation U-Boot - commande d’affichage mémoire `md`](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
- [5] [VoidStar Security — SCPI et instrumentation matérielle pour ingénieurs en rétro-ingénierie, partie 1](https://voidstarsec.com/blog/scpi-and-hardware-instrumentation-for-reverse-engineers-part-1)
- [6] [Guide de programmation Rigol MSO5000](https://www.batronix.com/files/Rigol/Oszilloskope/MSO5000/MSO5000_ProgrammingGuide_EN-V2.0.pdf)
- [7] [PyVISA — Configuration du backend](https://pyvisa.readthedocs.io/en/latest/introduction/configuring.html)
{{#include ../../banners/hacktricks-training.md}}
