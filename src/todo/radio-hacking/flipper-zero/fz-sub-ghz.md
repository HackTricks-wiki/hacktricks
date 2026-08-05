# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Introduction <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero peut **recevoir et transmettre des fréquences radio dans la plage de 300 à 928 MHz** grâce à son module intégré, qui peut lire, enregistrer et émuler des télécommandes. Ces télécommandes sont utilisées pour interagir avec des portails, des barrières, des serrures radio, des interrupteurs commandés à distance, des sonnettes sans fil, des éclairages intelligents, et bien plus encore. Flipper Zero peut vous aider à déterminer si votre sécurité est compromise.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Matériel Sub-GHz <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero dispose d’un module sub-1 GHz intégré basé sur une [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[puce CC1101](https://www.ti.com/lit/ds/symlink/cc1101.pdf) et une antenne radio (la portée maximale est de 50 mètres). La puce CC1101 et l’antenne sont conçues pour fonctionner dans les bandes de fréquences 300-348 MHz, 387-464 MHz et 779-928 MHz.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Actions

### Frequency Analyzer

> [!TIP]
> Comment trouver la fréquence utilisée par la télécommande

Lors de l’analyse, Flipper Zero analyse la puissance des signaux (RSSI) sur toutes les fréquences disponibles dans la configuration des fréquences. Flipper Zero affiche la fréquence ayant la valeur RSSI la plus élevée, avec une puissance du signal supérieure à -90 [dBm](https://en.wikipedia.org/wiki/DBm).<sup>[[1]](#references)</sup>

Pour déterminer la fréquence de la télécommande, procédez comme suit :

1. Placez la télécommande très près, à gauche de Flipper Zero.
2. Accédez à **Main Menu** **→ Sub-GHz**.
3. Sélectionnez **Frequency Analyzer**, puis maintenez enfoncé le bouton de la télécommande que vous souhaitez analyser.
4. Consultez la valeur de la fréquence à l’écran.

### Read

> [!TIP]
> Trouver des informations sur la fréquence utilisée (une autre façon de trouver la fréquence utilisée)

L’option **Read** **écoute sur la fréquence configurée** avec la modulation indiquée : 433.92 AM par défaut. Si **quelque chose est détecté** pendant la lecture, **des informations sont affichées** à l’écran. Ces informations peuvent être utilisées pour reproduire le signal ultérieurement.<sup>[[1]](#references)</sup>

Pendant l’utilisation de Read, il est possible d’appuyer sur le **bouton gauche** et de **le configurer**.\
À ce stade, il dispose de **4 modulations** (AM270, AM650, FM328 et FM476), ainsi que de **plusieurs fréquences pertinentes** enregistrées :

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

Vous pouvez définir **celle qui vous intéresse**, mais si vous **n’êtes pas certain de la fréquence** utilisée par votre télécommande, **activez Hopping** (désactivé par défaut), puis appuyez plusieurs fois sur le bouton jusqu’à ce que Flipper la capture et vous fournisse les informations nécessaires pour définir la fréquence.

> [!CAUTION]
> Le changement de fréquence prend un certain temps ; les signaux transmis au moment du changement peuvent donc être manqués. Pour une meilleure réception du signal, définissez une fréquence fixe déterminée avec Frequency Analyzer.

### **Read Raw**

> [!TIP]
> Voler (et rejouer) un signal sur la fréquence configurée

L’option **Read Raw** **enregistre les signaux** envoyés sur la fréquence d’écoute. Elle peut être utilisée pour **voler** un signal et le **répéter**.

Par défaut, **Read Raw est également réglé sur 433.92 en AM650**, mais si l’option Read vous a permis de constater que le signal qui vous intéresse utilise une **fréquence/modulation différente, vous pouvez également la modifier** en appuyant sur le bouton gauche (dans l’option Read Raw).

### Brute-Force

Si vous connaissez le protocole utilisé, par exemple, par la porte de garage, il est possible de **générer tous les codes et de les envoyer avec Flipper Zero.** Voici un exemple prenant en charge les types courants de portes de garage : [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Add Manually

> [!TIP]
> Ajouter des signaux à partir d’une liste configurée de protocoles

#### Liste des [protocoles pris en charge](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton_433 (fonctionne avec la majorité des systèmes à code statique) | 433.92 | Statique |
| -------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit_433                                             | 433.92 | Statique |
| Nice Flo 24bit_433                                             | 433.92 | Statique |
| CAME 12bit_433                                                 | 433.92 | Statique |
| CAME 24bit_433                                                 | 433.92 | Statique |
| Linear_300                                                     | 300.00 | Statique |
| CAME TWEE                                                      | 433.92 | Statique |
| Gate TX_433                                                    | 433.92 | Statique |
| DoorHan_315                                                    | 315.00 | Dynamique |
| DoorHan_433                                                    | 433.92 | Dynamique |
| LiftMaster_315                                                 | 315.00 | Dynamique |
| LiftMaster_390                                                 | 390.00 | Dynamique |
| Security+2.0_310                                               | 310.00 | Dynamique |
| Security+2.0_315                                               | 315.00 | Dynamique |
| Security+2.0_390                                               | 390.00 | Dynamique |

### Fournisseurs Sub-GHz pris en charge

Consultez la liste sur [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Fréquences prises en charge par région

Consultez la liste sur [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Test

> [!TIP]
> Obtenir les dBm des fréquences enregistrées

## Références

- [1] [Flipper Zero Sub-GHz documentation](https://docs.flipperzero.one/sub-ghz)

{{#include ../../../banners/hacktricks-training.md}}
