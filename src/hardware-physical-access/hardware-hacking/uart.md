# UART

{{#include ../../banners/hacktricks-training.md}}

## Informations de base

UART est une interface série asynchrone qui transfère un flux de bits encadrés sans horloge partagée. Ne confondez pas UART à niveau logique et RS-232 : RS-232 utilise des niveaux de tension différents, souvent négatifs, et nécessite un transceiver.<sup>[[1]](#references)[[3]](#references)</sup>

En général, la ligne est maintenue à l’état haut (valeur logique 1) lorsque UART est au repos. Pour signaler le début d’un transfert de données, l’émetteur envoie ensuite un bit de start au récepteur, pendant lequel le signal est maintenu à l’état bas (valeur logique 0). L’émetteur envoie ensuite cinq à huit bits de données contenant le message proprement dit, suivis d’un bit de parité facultatif et d’un ou deux bits de stop (valeur logique 1), selon la configuration. Le bit de parité, utilisé pour la détection d’erreurs, est rarement utilisé en pratique. Le ou les bits de stop indiquent la fin de la transmission.

La configuration la plus courante est 8N1 : huit bits de données, aucune parité et un bit de stop. UART envoie d’abord le bit de données de poids faible. Ainsi, le caractère ASCII `C` (`0x43`) est transmis sous la forme : start `0` ; données `1, 1, 0, 0, 0, 0, 1, 0` ; stop `1`.<sup>[[1]](#references)</sup>

![UART : la configuration la plus courante est appelée 8N1 : huit bits de données, aucune parité et un bit de stop. Par exemple, pour envoyer le caractère C, soit 0x43 en ASCII, avec UART 8N1](<../../images/image (764).png>)

Outils matériels pour communiquer avec UART :

- Adaptateur USB-série
- Adaptateurs dotés de puces CP2102 ou PL2303
- Outil polyvalent tel que Bus Pirate, Adafruit FT232H, Shikra ou Attify Badge

### Identifier les ports UART

Un connecteur de debug typique expose **TX**, **RX** et **GND** ; il peut aussi exposer une broche **Vcc/Vref**, une broche de reset ou des broches de contrôle de flux. Vcc n’est pas un signal UART et ne doit normalement servir que de référence de tension — et non être raccordée comme source d’alimentation — sauf si le schéma de la carte et les besoins en courant sont connus.<sup>[[2]](#references)[[3]](#references)</sup>

Commencez avec l’appareil **éteint** et déconnecté :

- Identifiez **GND** en mode continuité, par rapport à un plan de masse connu, au blindage d’un connecteur ou à la masse de l’alimentation. N’utilisez jamais le mode continuité/résistance sur une carte sous tension.
- Passez en mode tension continue avant de mettre la cible sous tension. Mesurez les broches candidates par rapport à la masse afin d’identifier la tension logique. Un rail stable peut être Vcc/Vref ; ne supposez pas qu’il est sûr de s’y connecter.
- Observez les broches candidates avec un analyseur logique ou un oscilloscope pendant le démarrage. **TX** est généralement au repos à l’état haut et présente des salves de données encadrées. Un multimètre peut afficher une fluctuation moyenne, mais ne permet pas de vérifier l’encadrement ni le baud rate.
- **RX** peut rester au repos et ne peut pas être identifié de manière sûre simplement parce qu’il est adjacent à TX. Suivez les pistes du PCB, consultez la datasheet du SoC ou utilisez un analyseur à haute impédance avant de le piloter.

Inverser TX et RX ne permet généralement pas de communiquer ; confondre l’alimentation, la masse ou les niveaux de signal peut endommager définitivement la cible ou l’adaptateur. Connectez d’abord la masse et commencez en **réception uniquement** (TX de la cible vers RX de l’adaptateur).

Les fabricants peuvent omettre le connecteur, ne pas monter les résistances série, désactiver la console dans le firmware ou n’exposer que TX. Suivez les pistes des pastilles de test et des empreintes de résistances voisines jusqu’au SoC, et n’ajoutez une connexion temporaire à haute impédance qu’après avoir confirmé le niveau électrique. La présence d’une garantie ne signifie pas qu’un UART accessible doit nécessairement être présent.

### Récupérer une pastille TX qui semble à l’état bas

Une pastille TX étiquetée qui reste à l’état bas lors d’une première capture à l’oscilloscope ne suffit pas à exclure la présence d’UART. Après avoir confirmé la tension logique de la cible et établi une masse commune, essayez une faible résistance de pull-up (l’exemple documenté utilisait **10 kΩ vers 3,3 V**) et répétez la capture en appuyant sur des boutons ou en démarrant l’appareil. Utilisez uniquement le rail logique vérifié de la cible ; ne connectez pas de résistance de pull-up à un signal inconnu ou piloté activement. Si des transitions encadrées apparaissent, mesurez la période de bit propre la plus courte pour estimer le baud rate avant de connecter la pastille en réception uniquement à un adaptateur série. Dans l’exemple, cette méthode a permis de récupérer des journaux d’événements de boutons à 115200 bauds, mais pas d’obtenir un dump du firmware.<sup>[[8]](#references)</sup>

### Identifier le baud rate UART

La manière la plus simple d’identifier le bon baud rate consiste à observer la sortie de la broche **TX** et à essayer de lire les données. Si les données reçues ne sont pas lisibles, essayez le baud rate suivant jusqu’à ce qu’elles le deviennent. Vous pouvez utiliser un adaptateur USB-série ou un appareil polyvalent comme Bus Pirate, avec un script utilitaire tel que [baudrate.py](https://github.com/devttys0/baudrate/). Les baud rates les plus courants sont 9600, 38400, 19200, 57600 et 115200.

> [!CAUTION]
> Il est important de noter que, dans ce protocole, vous devez connecter le TX d’un appareil au RX de l’autre !

### Automatiser la capture UART au démarrage avec SCPI

Si la sortie au démarrage est brève ou si la pastille TX n’est pas encore identifiée, automatisez les démarrages répétés au lieu de manipuler manuellement l’alimentation et l’oscilloscope. Connectez une alimentation programmable limitée en courant à l’entrée d’alimentation vérifiée de la cible. Sondez chaque pastille TX candidate avec une entrée d’oscilloscope à haute impédance et une masse commune ; ne pilotez pas la pastille.<sup>[[5]](#references)</sup>

VISA ouvre des sessions d’instruments série ou Ethernet, tandis que SCPI contrôle la sortie, le déclenchement et la lecture de la forme d’onde.<sup>[[5]](#references)[[6]](#references)</sup> Installez `pyvisa` et `pyvisa-py` (ainsi que `pyserial` pour les ressources VISA série) ; `ResourceManager('@py')` sélectionne explicitement le backend Python.<sup>[[5]](#references)[[7]](#references)</sup> Remplacez les chaînes de ressources et les commandes par celles prises en charge par les instruments utilisés.<sup>[[5]](#references)</sup>

Dans l’exemple du Rigol MSO5000, armez un déclenchement unique sur front descendant avant de mettre la carte sous tension : le TX UART, au repos à l’état haut, passe d’abord à l’état bas pour le bit de start.<sup>[[5]](#references)</sup> Réglez le seuil de déclenchement entre les niveaux mesurés à l’état de repos et à l’état bas, puis réglez la base de temps pour couvrir l’intervalle de démarrage voulu.<sup>[[5]](#references)[[6]](#references)</sup> `:TRIG:HOLD` peut supprimer les fronts répétés lors de captures continues, mais ne remplace pas la vérification qu’une capture unique est bien terminée.<sup>[[5]](#references)</sup> Le code suivant capture un démarrage et enregistre à la fois les échantillons en octets non signés et leurs métadonnées de mise à l’échelle ; en cas de délai d’attente dépassé, la cible est mise hors tension au lieu d’attendre indéfiniment.<sup>[[5]](#references)[[6]](#references)</sup>

<details>
<summary>Mise sous tension avec PyVISA et capture de la forme d’onde UART en acquisition unique</summary>

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

Pour relever les pads, répétez la capture single-shot après avoir déplacé la sonde, ou laissez la session d’alimentation ouverte et faites commuter sa sortie en respectant un délai de démarrage et un intervalle hors tension. Réarmez l’oscilloscope avant chaque mise sous tension afin que chaque fichier corresponde à un démarrage et à un pad.<sup>[[5]](#references)</sup>

Le préambule Rigol est `<format>,<type>,<points>,<count>,<xincrement>,...`.<sup>[[6]](#references)</sup> La **troisième** valeur correspond au nombre de points, et non à la fréquence d’échantillonnage comme indiqué dans l’article.<sup>[[5]](#references)[[6]](#references)</sup> Dans l’exemple, `25,000,000` points et `xincrement = 2e-8` secondes impliquent `1 / xincrement = 50,000,000` échantillons/seconde, et non 25 MSa/s.<sup>[[5]](#references)[[6]](#references)</sup> Conservez le préambule avec le fichier binaire et vérifiez que la longueur lue correspond à `<points>` ; le guide décrit des lectures segmentées/par lots pour les enregistrements volumineux.<sup>[[6]](#references)</sup>

Pour décoder le signal capturé, importez `capture.bin` dans PulseView en tant que **Raw Analog Data Without Header**, sélectionnez des valeurs non signées sur 8 bits (`U8`) et indiquez la fréquence d’échantillonnage calculée à partir de `xincrement`.<sup>[[5]](#references)[[6]](#references)</sup> Appliquez **Logic via Threshold** au canal analogique en choisissant un seuil entre les valeurs d’échantillon basses et hautes.<sup>[[5]](#references)</sup> Mesurez la largeur d’un bit de départ net pour estimer le débit en bauds (environ 17,36 µs pour 57 600 bauds), puis appliquez le décodeur UART de PulseView et vérifiez que plusieurs trames sont décodées de manière cohérente.<sup>[[5]](#references)</sup> Un seul front descendant ne suffit pas à prouver qu’un pad est UART.

## Adaptateur CP210X UART vers TTY

Les ponts USB-vers-UART CP210x sont présents sur de nombreuses cartes de prototypage et dans des adaptateurs bon marché. Les modules courants exposent des broches d’alimentation en plus de GND, RXD et TXD, mais la disposition des broches et les niveaux d’E/S varient. Vérifiez la tension réelle à partir du schéma de la carte ou de la fiche technique. En général, connectez uniquement GND et l’entrée RX de l’adaptateur à TX de la cible ; après validation en réception seule, connectez également TX de l’adaptateur à RX de la cible. Ne connectez pas la broche d’alimentation 5 V/3,3 V de l’adaptateur, sauf si vous souhaitez alimenter une cible dont la compatibilité est confirmée.<sup>[[3]](#references)</sup>

Si l’adaptateur n’est pas détecté, vérifiez que les pilotes CP210X sont installés sur le système hôte. Une fois l’adaptateur détecté et connecté, vous pouvez utiliser des outils comme picocom, minicom ou screen.

Pour lister les appareils connectés aux systèmes Linux/MacOS :

```
ls /dev/
```

Pour interagir avec l’interface UART, utilisez la commande suivante :

```
picocom /dev/<adapter> --baud <baudrate>
```

Pour minicom, utilisez la commande suivante pour le configurer :

```
minicom -s
```

Configurez les paramètres tels que le débit en bauds et le nom du périphérique dans l’option `Serial port setup`.

Après la configuration, lancez `minicom` pour ouvrir la console UART.

## UART via Arduino UNO R3 (cartes avec puce Atmel 328p amovible)

Si aucun adaptateur UART Serial vers USB n’est disponible, vous pouvez utiliser un Arduino UNO R3 avec une astuce rapide. Comme l’Arduino UNO R3 est généralement disponible partout, cela peut vous faire gagner beaucoup de temps.

L’Arduino UNO R3 intègre un adaptateur USB vers Serial. Pour établir une connexion UART, retirez simplement la puce du microcontrôleur Atmel 328p de la carte. Cette astuce fonctionne avec les variantes de l’Arduino UNO R3 dont l’Atmel 328p n’est pas soudé à la carte (la version SMD est utilisée dans ce cas). Connectez la broche RX de l’Arduino (broche numérique 0) à la broche TX de l’interface UART, et la broche TX de l’Arduino (broche numérique 1) à la broche RX de l’interface UART.

Utilisez le **Serial Monitor** de l’Arduino IDE ou un terminal dédié configuré au débit en bauds de la cible. Les signaux Serial classiques de l’Uno R3 utilisent une logique 5 V : utilisez donc un convertisseur de niveau ou un diviseur de tension avant de les connecter à une cible 3,3 V ou à tension inférieure.

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

## Extraction du firmware avec la console UART

Une console UART permet d’accéder aux journaux de démarrage et, parfois, à un shell de bootloader ou de système d’exploitation pendant l’exécution. Même en lecture seule, une console révèle les cartes mémoire, les pilotes flash, les arguments de démarrage, la disposition des partitions et les versions du firmware. Le firmware peut se trouver dans une mémoire SPI NOR/NAND, une eMMC ou un autre périphérique ; il n’est généralement pas exécuté depuis une EEPROM, et les fichiers écrits sur un système de fichiers persistant monté ne disparaissent pas nécessairement au redémarrage.

Il existe plusieurs méthodes d’acquisition ; la section SPI couvre les lectures directes depuis une mémoire flash externe. L’acquisition assistée par console peut être moins invasive si le bootloader fournit déjà une commande de lecture sûre, mais toute interruption du démarrage ou commande flash peut affecter la disponibilité. Il faut donc consigner l’état initial et éviter les opérations d’écriture ou d’effacement.

L’extraction du firmware assistée par console commence souvent par l’interruption d’un bootloader. De nombreux appareils Linux embarqués utilisent **Das U-Boot**, mais d’autres utilisent des bootloaders propriétaires ou désactivent la console interactive.

Pour tester la présence d’un bootloader interactif, connectez la ligne de réception UART et le terminal alors que la cible est hors tension, démarrez la journalisation, puis mettez-la sous tension. Suivez l’invite d’autoboot affichée ; selon la version, l’interruption peut nécessiter une touche, une courte séquence, ou être entièrement désactivée.

Si l’interruption réussit, utilisez `help`, `printenv` et des commandes de découverte en lecture seule pour comprendre la disposition de la mémoire et du stockage propre au fabricant avant d’accéder aux adresses.

Dans U-Boot, `md` affiche la **mémoire adressable**, et non automatiquement « l’EEPROM ». Commencez par utiliser des commandes spécifiques à la carte, comme `mtd list`, `sf probe`, `mmc info`, `part list`, les variables d’environnement et les journaux de démarrage, afin d’identifier l’adresse mappée correcte ou de charger une région flash en RAM. Affichez ensuite une plage connue octet par octet :<sup>[[4]](#references)</sup>

```
md.b <address> <byte_count>
```

Consignez la sortie série avant de commencer. La sortie `md.b` contient des adresses et une colonne ASCII ; il s’agit donc d’une représentation textuelle, et non d’une image ROM brute.

Supprimez les colonnes d’adresse et ASCII, concaténez uniquement les champs d’octets hexadécimaux et décodez-les en binaire (par exemple avec `xxd -r -p`). Vérifiez le nombre d’octets attendu et consignez une empreinte avant l’analyse :

```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```

Binwalk identifie ensuite les signatures connues dans le binaire reconstitué. Une lecture directe de la flash via l’interface SPI/eMMC/NAND appropriée est généralement plus rapide et moins sujette aux erreurs lorsque la console ne peut pas transférer les données de manière fiable.

U-Boot peut désactiver l’interruption, exiger une séquence de touches spécifique au fabricant ou verrouiller les commandes mémoire/flash. Suivez l’invite d’autoboot et le journal de démarrage au lieu de transmettre des caractères à l’aveugle. Si la console ne peut pas être interrompue, conservez le journal de démarrage et utilisez une méthode non invasive d’acquisition du firmware.

## References

- [1] [Manuel de référence de la famille Microchip PIC32 - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Documentation Bus Pirate - mode UART et limites électriques](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - fiche technique du CP2102C](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [Documentation U-Boot - commande `md` d’affichage de la mémoire](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
- [5] [VoidStar Security — SCPI et instrumentation matérielle pour les ingénieurs en rétro-ingénierie, partie 1](https://voidstarsec.com/blog/scpi-and-hardware-instrumentation-for-reverse-engineers-part-1)
- [6] [Guide de programmation Rigol MSO5000](https://www.batronix.com/files/Rigol/Oszilloskope/MSO5000/MSO5000_ProgrammingGuide_EN-V2.0.pdf)
- [7] [PyVISA — Configuration du backend](https://pyvisa.readthedocs.io/en/latest/introduction/configuring.html)
- [8] [VoidStar Security — Réviser le hardware hacking, partie 2](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
