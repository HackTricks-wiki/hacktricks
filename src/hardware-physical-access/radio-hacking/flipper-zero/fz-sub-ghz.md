# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Introduction <a href="#introduction" id="introduction"></a>

Flipper Zero peut **recevoir et transmettre des fréquences radio dans la plage de 300 à 928 MHz** grâce à son module intégré, sous réserve des restrictions de fréquence applicables à la région configurée. Il peut lire, enregistrer et émuler des télécommandes compatibles utilisées pour les portails, barrières, serrures radio, interrupteurs, sonnettes sans fil, éclairages intelligents et autres appareils.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Matériel Sub-GHz <a href="#sub-ghz-hardware" id="sub-ghz-hardware"></a>

Flipper Zero possède un module sub-1 GHz intégré, basé sur un émetteur-récepteur CC1101 et une antenne radio. La portée réelle dépend de la fréquence, de l’antenne, de l’environnement et de l’émetteur ; Flipper indique une portée allant jusqu’à environ 50 mètres dans des conditions favorables. Le matériel couvre les plages 300-348 MHz, 387-464 MHz et 779-928 MHz, tandis que le firmware et les règles régionales imposent des restrictions supplémentaires à la transmission.<sup>[[1]](#references)[[2]](#references)</sup>

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Actions

### Frequency Analyser

> [!TIP]
> Comment trouver la fréquence utilisée par la télécommande

Lors de l’analyse, Flipper Zero parcourt la puissance des signaux (RSSI) sur toutes les fréquences disponibles dans la configuration des fréquences. Flipper Zero affiche la fréquence dont la valeur RSSI est la plus élevée, avec une puissance de signal supérieure à -90 [dBm](https://en.wikipedia.org/wiki/DBm).<sup>[[1]](#references)</sup>

Pour déterminer la fréquence de la télécommande, procédez comme suit :

1. Placez la télécommande tout près, à gauche de Flipper Zero.
2. Allez dans **Main Menu** **→ Sub-GHz**.
3. Sélectionnez **Frequency Analyzer**, puis maintenez enfoncé le bouton de la télécommande que vous souhaitez analyser.
4. Consultez la valeur de fréquence affichée à l’écran.

### Read

> [!TIP]
> Trouver des informations sur la fréquence utilisée (une autre façon de déterminer la fréquence utilisée)

L’option **Read** écoute sur la fréquence et la modulation configurées (433,92 MHz AM par défaut). Lorsqu’un signal compatible est détecté, des informations s’affichent à l’écran et peuvent être enregistrées pour être rejouées ultérieurement.<sup>[[1]](#references)</sup>

Pendant l’utilisation de Read, vous pouvez appuyer sur le **bouton gauche** pour **configurer les paramètres**.\
Il existe actuellement **4 modulations** (AM270, AM650, FM328 et FM476) et **plusieurs fréquences pertinentes** sont enregistrées :

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

Vous pouvez sélectionner toute fréquence autorisée. Si vous ne savez pas quelle fréquence utilise la télécommande, activez **Hopping** (désactivé par défaut), puis appuyez plusieurs fois sur le bouton de la télécommande jusqu’à ce que Flipper capture le signal et indique sa fréquence.

> [!CAUTION]
> Le changement de fréquence prend un certain temps ; les signaux transmis pendant ce changement risquent donc d’être manqués. Pour une meilleure réception, définissez une fréquence fixe déterminée avec Frequency Analyzer.

### **Read Raw**

> [!TIP]
> Capturer (et rejouer) un signal sur la fréquence configurée

L’option **Read Raw** enregistre les signaux transmis sur la fréquence sélectionnée. Elle peut servir à capturer et rejouer un signal lors de tests autorisés.<sup>[[1]](#references)</sup>

Par défaut, **Read Raw utilise également 433,92 MHz avec AM650**. Si l’option Read a détecté un signal sur une autre fréquence ou modulation, appuyez sur Left dans Read Raw pour modifier ces paramètres.

### Brute-Force

Si vous connaissez le protocole utilisé par un appareil comme une porte de garage, il peut être possible de **générer des codes candidats et de les transmettre avec Flipper Zero**. Le projet `flipperzero-bruteforce` prend en charge plusieurs protocoles courants à code statique.<sup>[[3]](#references)</sup>

### Add Manually

> [!TIP]
> Ajouter des signaux à partir d’une liste de protocoles configurés

#### Liste des protocoles pris en charge <a href="#id-3iglu" id="id-3iglu"></a>

Le menu Add Manually propose les préréglages de protocoles documentés par Flipper Zero.<sup>[[4]](#references)</sup>

| Princeton_433 (fonctionne avec la majorité des systèmes à code statique) | 433.92 | Static  |
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

### Fabricants Sub-GHz pris en charge

Consultez la liste des fabricants pris en charge par Flipper Zero.<sup>[[5]](#references)</sup>

### Fréquences prises en charge par région

Consultez la liste officielle des fréquences régionales avant toute transmission.<sup>[[6]](#references)</sup>

### Test

> [!TIP]
> Obtenir les valeurs en dBm des fréquences enregistrées

## References

- [1] [Sub-GHz - Documentation utilisateur Flipper Zero](https://docs.flipperzero.one/sub-ghz)
- [2] [Fiche technique Texas Instruments CC1101](https://www.ti.com/lit/ds/symlink/cc1101.pdf)
- [3] [tobiabocchi/flipperzero-bruteforce](https://github.com/tobiabocchi/flipperzero-bruteforce)
- [4] [Flipper Zero - Ajouter une télécommande créée manuellement](https://docs.flipperzero.one/sub-ghz/add-new-remote)
- [5] [Flipper Zero - Fabricants Sub-GHz pris en charge](https://docs.flipperzero.one/sub-ghz/supported-vendors)
- [6] [Flipper Zero - Fréquences Sub-GHz régionales](https://docs.flipperzero.one/sub-ghz/frequencies)
{{#include ../../../banners/hacktricks-training.md}}
