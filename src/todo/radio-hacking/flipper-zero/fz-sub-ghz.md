# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero peut **recevoir et transmettre des fréquences radio dans la plage de 300 à 928 MHz** grâce à son module intégré, qui peut lire, enregistrer et émuler des télécommandes. Ces télécommandes sont utilisées pour interagir avec des portails, des barrières, des serrures radio, des interrupteurs télécommandés, des sonnettes sans fil, des éclairages intelligents, et bien plus encore. Flipper Zero peut vous aider à déterminer si votre sécurité est compromise.

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Matériel Sub-GHz <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero possède un module intégré sub-1 GHz basé sur une [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[puce CC1101](https://www.ti.com/lit/ds/symlink/cc1101.pdf) et une antenne radio (la portée maximale est de 50 mètres). La puce CC1101 et l’antenne sont toutes deux conçues pour fonctionner dans les bandes de fréquences 300-348 MHz, 387-464 MHz et 779-928 MHz.

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Actions

### Frequency Analyser

> [!TIP]
> Comment trouver la fréquence utilisée par la télécommande

Lors de l’analyse, Flipper Zero analyse la puissance des signaux (RSSI) sur toutes les fréquences disponibles dans la configuration des fréquences. Flipper Zero affiche la fréquence ayant la valeur RSSI la plus élevée, avec une puissance de signal supérieure à -90 [dBm](https://en.wikipedia.org/wiki/DBm).<sup>[[1]](#references)</sup>

Pour déterminer la fréquence de la télécommande, procédez comme suit :

1. Placez la télécommande très près de la partie gauche de Flipper Zero.
2. Allez dans **Main Menu** **→ Sub-GHz**.
3. Sélectionnez **Frequency Analyzer**, puis maintenez enfoncé le bouton de la télécommande que vous souhaitez analyser.
4. Consultez la valeur de la fréquence à l’écran.

### Read

> [!TIP]
> Trouver des informations sur la fréquence utilisée (également une autre façon de trouver la fréquence utilisée)

L’option **Read** **écoute sur la fréquence configurée** avec la modulation indiquée : 433.92 AM par défaut. Si **quelque chose est détecté** lors de la lecture, des **informations sont affichées** à l’écran. Ces informations peuvent être utilisées pour répliquer le signal ultérieurement.<sup>[[1]](#references)</sup>

Lorsque Read est utilisé, il est possible d’appuyer sur le **bouton gauche** et de **le configurer**.\
Il dispose actuellement de **4 modulations** (AM270, AM650, FM328 et FM476), ainsi que de **plusieurs fréquences pertinentes** enregistrées :

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

Vous pouvez définir **celle qui vous intéresse**, cependant, si vous **n’êtes pas certain de la fréquence** utilisée par votre télécommande, **activez Hopping** (désactivé par défaut), puis appuyez plusieurs fois sur le bouton jusqu’à ce que Flipper la capture et vous fournisse les informations nécessaires pour configurer la fréquence.

> [!CAUTION]
> Le changement de fréquence prend un certain temps ; les signaux transmis pendant ce changement peuvent donc être manqués. Pour une meilleure réception du signal, définissez une fréquence fixe déterminée avec Frequency Analyzer.

### **Read Raw**

> [!TIP]
> Voler (et rejouer) un signal sur la fréquence configurée

L’option **Read Raw** **enregistre les signaux** envoyés sur la fréquence d’écoute. Elle peut être utilisée pour **voler** un signal et le **répéter**.<sup>[[1]](#references)</sup>

Par défaut, **Read Raw est également configuré sur 433.92 en AM650**, mais si l’option Read vous a permis de constater que le signal qui vous intéresse utilise une **fréquence/modulation différente, vous pouvez également la modifier** en appuyant sur le bouton gauche (dans l’option Read Raw).

### Brute-Force

Si vous connaissez le protocole utilisé, par exemple, par la porte de garage, il est possible de **générer tous les codes et de les envoyer avec Flipper Zero.** Voici un exemple prenant en charge les types courants de portes de garage : [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Add Manually

> [!TIP]
> Ajouter des signaux à partir d’une liste configurée de protocoles

#### Liste des [protocoles pris en charge](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton_433 (works with the majority of static code systems) | 433.92 | Static  |
| -------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit_433                                             | 433.92 | Static  |
| Nice Flo 24bit_433                                             | 433.92 | Static  |
| CAME 12bit_433                                                 | 433.92 | Static  |
| CAME 24bit_433                                                 | 433.92 | Static  |
| Linear_300                                                     | 300.00 | Static  |
| CAME TWEE                                                      | 433.92 | Static  |
| Gate TX_433                                                    | 433.92 | Static  |
| DoorHan_315                                                    | 315.00 | Dynamic |
| DoorHan_433                                                    | 433.92 | Dynamic |
| LiftMaster_315                                                 | 315.00 | Dynamic |
| LiftMaster_390                                                 | 390.00 | Dynamic |
| Security+2.0_310                                               | 310.00 | Dynamic |
| Security+2.0_315                                               | 315.00 | Dynamic |
| Security+2.0_390                                               | 390.00 | Dynamic |

### Fournisseurs Sub-GHz pris en charge

Consultez la liste sur [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Fréquences prises en charge par région

Consultez la liste sur [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Test

> [!TIP]
> Obtenir les dBm des fréquences enregistrées

## Références

- [1] [Sub-GHz - Flipper Zero User Documentation](https://docs.flipperzero.one/sub-ghz)

{{#include ../../../banners/hacktricks-training.md}}
