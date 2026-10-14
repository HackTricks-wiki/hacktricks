# I2C

{{#include ../../banners/hacktricks-training.md}}

## Bus Pirate

> [!CAUTION]
> Vérifiez la tension cible, le brochage, la configuration des résistances de pull-up et la mise à la masse commune avant de connecter un Bus Pirate. N’activez pas les alimentations du Bus Pirate sur un bus alimenté par la cible simplement pour l’espionner : les deux alimentations peuvent entrer en conflit et endommager le matériel. La transcription ci-dessous est un exemple spécifique à un appareil, utilisant un Bus Pirate v3 et un firmware communautaire ; ce n’est pas un schéma de câblage universel.<sup>[[1]](#references)[[2]](#references)</sup>

Pour vérifier que le Bus Pirate fonctionne, connectez le +5V à VPU et le 3,3V à ADC, puis accédez au Bus Pirate (en utilisant Tera Term, par exemple) et saisissez la commande `~` :

```bash
# Use command
HiZ>~
Disconnect any devices
Connect (Vpu to +5V) and (ADC to +3.3V)
Space to continue
# Press space
Ctrl
AUX OK
MODE LED OK
PULLUP H OK
PULLUP L OK
VREG OK
ADC and supply
5V(4.96) OK
VPU(4.96) OK
3.3V(3.26) OK
ADC(3.27) OK
Bus high
MOSI OK
CLK OK
MISO OK
CS OK
Bus Hi-Z 0
MOSI OK
CLK OK
MISO OK
CS OK
Bus Hi-Z 1
MOSI OK
CLK OK
MISO OK
CS OK
MODE and VREG LEDs should be on!
Any key to exit
#Press space
Found 0 errors.
```

Comme vous pouvez le voir dans la ligne de commande précédente, elle indique qu’elle a trouvé 0 erreur. C’est très utile pour vérifier que l’appareil fonctionne après l’avoir acheté ou après avoir flashé un firmware.

Pour vous connecter au Bus Pirate, vous pouvez suivre la documentation :

![Utilisez la commande - Appuyez sur espace : pour vous connecter au Bus Pirate, vous pouvez suivre la documentation](<../../images/image (484).png>)

Dans ce cas, la cible est une EEPROM I²C de la famille 24C256. Vérifiez le suffixe exact et la fiche technique, car la tension d’alimentation prise en charge varie selon le composant.<sup>[[3]](#references)</sup>

![Utilisez la commande - Appuyez sur espace : dans ce cas, je vais me connecter à une EPROM : ATMEL901 24C256 PU27](<../../images/image (964).png>)

Pour communiquer avec le Bus Pirate, j’ai utilisé Tera Term, connecté au port COM du Bus Pirate avec la vitesse réglée sur 115200 dans Setup --> Serial Port --> Speed.\
La communication suivante montre comment préparer le Bus Pirate pour communiquer en I2C et comment écrire dans la mémoire et la lire (les commentaires commencent par « # » ; ne vous attendez pas à trouver cette partie dans la communication) :

```bash
# Check communication with buspirate
i
Bus Pirate v3.5
Community Firmware v7.1 - goo.gl/gCzQnW [HiZ 1-WIRE UART I2C SPI 2WIRE 3WIRE KEYB LCD PIC DIO] Bootloader v4.5
DEVID:0x0447 REVID:0x3046 (24FJ64GA00 2 B8)
http://dangerousprototypes.com

# Check voltages
I2C>v
Pinstates:
1.(BR)  2.(RD)  3.(OR)  4.(YW)  5.(GN)  6.(BL)  7.(PU)  8.(GR)  9.(WT)  0.(Blk)
GND     3.3V    5.0V    ADC     VPU     AUX     SCL     SDA     -       -
P       P       P       I       I       I       I       I       I       I
GND     3.27V   4.96V   0.00V   4.96V   L       H       H       L       L

# This particular setup used 5 V pull-ups; do not generalize it to every 24C256 variant or board

# Get mode options
HiZ>m
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

# Select I2C
(1)>4
I2C mode:
 1. Software
 2. Hardware

# Select Software mode
(1)>1
Set speed:
 1. ~5kHz
 2. ~50kHz
 3. ~100kHz
 4. ~240kHz

# Select communication speed
(1)> 2
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Start communication
I2C>W
POWER SUPPLIES ON
Clutch engaged!!!

# Get macros
I2C>(0)
 0.Macro menu
 1.7bit address search
 2.I2C sniffer

#Get addresses of slaves connected
I2C>(1)
Searching I2C address space. Found devices at:
0xA0(0x50 W) 0xA1(0x50 R)

# Bus Pirate displays the 8-bit address bytes 0xA0 (write) and 0xA1 (read)
# Both correspond to the same 7-bit I2C target address, 0x50

# Write "BBB" in address 0x69
I2C>[0xA0 0x00 0x69 0x42 0x42 0x42]
I2C START BIT
WRITE: 0xA0 ACK
WRITE: 0x00 ACK
WRITE: 0x69 ACK
WRITE: 0x42 ACK
WRITE: 0x42 ACK
WRITE: 0x42 ACK
I2C STOP BIT

# Prepare to read from address 0x69
I2C>[0xA0 0x00 0x69]
I2C START BIT
WRITE: 0xA0 ACK
WRITE: 0x00 ACK
WRITE: 0x69 ACK
I2C STOP BIT

# Read 20B from address 0x69 configured before
I2C>[0xA1 r:20]
I2C START BIT
WRITE: 0xA1 ACK
READ: 0x42  ACK 0x42  ACK 0x42  ACK 0x20  ACK 0x48  ACK 0x69  ACK 0x20  ACK 0x44  ACK 0x72  ACK 0x65  ACK 0x67  ACK 0x21  ACK 0x20  ACK 0x41  ACK 0x41  ACK 0x41  ACK 0x00  ACK 0xFF  ACK 0xFF  ACK 0xFF
NACK
```

### Sniffer

Dans ce scénario, nous allons écouter la communication I2C entre l’Arduino et l’EPROM précédente. Il suffit de faire communiquer les deux appareils, puis de connecter le Bus Pirate aux broches SCL, SDA et GND :

![Lire 20 octets à l’adresse 0x69 configurée précédemment - Sniffer : dans ce scénario, nous allons écouter la communication I2C entre l’Arduino et l’EPROM précédente. Il suffit de...](<../../images/image (166).png>)

```bash
I2C>m
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

(1)>4
I2C mode:
 1. Software
 2. Hardware

(1)>1
Set speed:
 1. ~5kHz
 2. ~50kHz
 3. ~100kHz
 4. ~240kHz

(1)>1
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Historical transcript powered this bench setup. On a live target-powered bus, leave Bus Pirate power OFF.

I2C>W
POWER SUPPLIES ON
Clutch engaged!!!

# Start sniffing, you can see we sniffed a write command

I2C>(2)
Sniffer
Any key to exit
[0xA0+0x00+0x69+0x41+0x41+0x41+0x20+0x48+0x69+0x20+0x44+0x72+0x65+0x67+0x21+0x20+0x41+0x41+0x41+0x00+]
```

## Reconstruction du protocole I2C en boîte noire

### Identifier le bus à partir des broches actives

Lorsque le périphérique n’a ni brochage ni fiche technique, commencez par une analyse passive avec un analyseur logique à haute impédance pendant que l’hôte d’origine fonctionne. Après avoir établi une masse commune et un niveau logique sûr, classez les broches constantes comme des rails d’alimentation probables, des masses ou des signaux tirés vers le haut, puis comparez les lignes actives aux bus courants : l’UART a des lignes TX/RX asynchrones et dirigées indépendamment ; le SPI conventionnel expose normalement une horloge, une sélection de puce et des lignes de données distinctes selon le sens ; l’I2C a une horloge régulière et une seule ligne de données bidirectionnelle. Un décodage I2C devrait alors révéler les adresses cibles sur 7 bits, le sens lecture/écriture, les ACK/NACK et les charges utiles récurrentes.<sup>[[2]](#references)[[4]](#references)</sup>

Capturez plusieurs échanges légitimes et conservez à la fois les octets décodés et la synchronisation brute. Les trames répétées sont des tests utiles avec réponse connue pour les sérialiseurs utilisés ultérieurement, tandis que les changements entre les requêtes peuvent révéler des champs probables d’opcode, d’index, de décalage, de longueur, de séquence ou de somme de contrôle.<sup>[[4]](#references)</sup>

### Retrouver le format des trames à partir du firmware de l’hôte

Si le firmware du périphérique est inaccessible, extrayez le firmware de l’**hôte** et trouvez le composant qui ouvre le périphérique I2C. Recherchez des chaînes et des symboles correspondant au nom du périphérique, à `/dev/i2c-`, aux constructeurs de commandes, aux analyseurs de réponses, aux routines de réinitialisation/initialisation et aux fonctions de somme de contrôle. Pour chaque constructeur, consignez les décalages exacts des champs, les constantes, les tailles d’arguments acceptées, la longueur de la charge utile, les données couvertes par la somme de contrôle, l’ordre des octets de cette somme et la longueur de la trame retournée, plutôt que de déduire le format du nom des fonctions.<sup>[[4]](#references)</sup>

Une fonction de somme de contrôle nommée `crc16_ccitt` ne suffit pas à choisir un préréglage. Déterminez le sens du décalage, l’octet utilisé comme index de table, le polynôme représenté par la table, le registre initial, la réflexion des entrées/sorties, le XOR/inversion final et l’ordre des octets sur le bus utilisé par le sérialiseur. Par exemple, une table d’octets faibles à décalage vers la droite basée sur le polynôme inversé `0x8408`, initialisée à `0xFFFF` et complémentée à la fin, identifie **CRC-16/X-25 (IBM-SDLC)**. Une somme de contrôle correcte est souvent nécessaire pour que les cas de test passent la validation d’intégrité et atteignent l’analyseur de commandes.<sup>[[4]](#references)</sup>

Après avoir reconstitué le format, recherchez des noms de symboles et des constantes distinctifs dans le code public. Dans le cas de MJA1, un wrapper SDK trouvé indépendamment a confirmé les ID de commande, la validation des arguments, les définitions des réponses et l’implémentation miroir du CRC ; utilisez ce type de source comme validation, et non comme substitut à la vérification du binaire cible exact et de l’ordre des octets sur le bus.<sup>[[4]](#references)[[5]](#references)</sup>

### Envoyer des trames depuis un hôte Linux rooté

Un hôte Linux embarqué compromis peut interagir avec le périphérique sans ajouter un autre contrôleur de bus. Ouvrez l’adaptateur concerné, sélectionnez l’adresse sur 7 bits avec `I2C_SLAVE` et envoyez une trame produite par un sérialiseur dédié ; conservez un mode trame brute pour la mutation et le fuzzing.<sup>[[4]](#references)</sup>

```c
int fd = open("/dev/i2c-0", O_RDWR);
if (fd < 0 || ioctl(fd, I2C_SLAVE, target_addr) < 0)
    err(1, "I2C setup");
if (write(fd, cmd, cmd_len) != cmd_len)
    err(1, "I2C write");
ssize_t n = read(fd, resp, resp_size);
if (n < 0)
    err(1, "I2C read");
```

Compilez de manière croisée avec une toolchain compatible avec le CPU et la libc de la cible, puis comparez les traces de l’analyseur du client de test au trafic légitime. Les limites des transactions, l’ordre des écritures et des lectures, les délais et l’état du périphérique peuvent avoir de l’importance, même si les octets visibles sont identiques.<sup>[[4]](#references)</sup>

### Énumération des opcodes guidée par les réponses

Une fois la trame valide la plus courte et la somme de contrôle connues, énumérez toute la largeur d’opcode et utilisez la réponse explicite du protocole **commande non prise en charge** comme référence négative. Un résultat différent — par exemple des arguments invalides, un état invalide ou un statut non documenté — suggère que le décodage a atteint un gestionnaire implémenté ou partiellement implémenté. Cela ne prouve **pas** qu’il est exploitable ; donnez la priorité à ce candidat pour des tests fuzzing structurés portant sur la longueur, les arguments, l’état et les séquences de commandes.<sup>[[4]](#references)</sup>

Si un test bloque le périphérique, automatisez un cas isolé par démarrage depuis un contrôleur externe : connectez-vous en SSH, exécutez le cas, enregistrez la requête et la réponse brutes ainsi que leur chronométrage, redémarrez ou coupez puis rétablissez l’alimentation, attendez que les contrôles d’état soient de nouveau opérationnels, puis continuez. Le déplacement du composant vers un banc de test contrôlé par microcontrôleur peut ensuite permettre des réinitialisations déterministes, un contrôle direct de l’alimentation et un fuzzing plus rapide.<sup>[[4]](#references)</sup>

## References

- [1] [Documentation de Bus Pirate — I²C](https://docs.buspirate.com/docs/devices/i2c-eeprom/)
- [2] [NXP — Spécification du bus I²C et manuel utilisateur](https://www.nxp.com/docs/en/user-guide/UM10204.pdf)
- [3] [Microchip — Fiche technique de l’EEPROM série AT24C256C compatible I²C](https://ww1.microchip.com/downloads/en/DeviceDoc/AT24C256C-I2C-Compatible-Two-Wire-Serial-EEPROM-256-Kbit-32,768-x-8-20005915A.pdf)
- [4] [Quarkslab — Analyse par sondage en boîte noire : analyse de sécurité de la puce sécurisée MJA1 de Xiaomi](https://blog.quarkslab.com/black-box-probing-a-security-analysis-of-xiaomis-mja1-secure-chip.html)
- [5] [Wrapper de cryptographie MJA1 du SDK Mijia BLE](https://github.com/iomonad/handshow-firmware/tree/master/components/vendor/common/mijia_ble/libs/cryptography/mja1)
{{#include ../../banners/hacktricks-training.md}}
