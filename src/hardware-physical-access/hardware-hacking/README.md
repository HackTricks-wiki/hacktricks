# Piratage matériel

{{#include ../../banners/hacktricks-training.md}}

Pour un appareil auquel vous avez physiquement accès, commencez par examiner les interfaces exposées par sa carte ou ses signaux : [consoles série UART](uart.md), [accès de débogage JTAG/SWD](jtag.md), bus [I²C](i2c.md) et [mémoire flash SPI](spi.md). L’[analyse des canaux auxiliaires](side_channel_analysis.md) et l’[injection de fautes](fault_injection_attacks.md) servent à effectuer d’autres types de mesures et de glitching ; l’[analyse des signaux radio](radio.md) couvre les points d’entrée sans fil. Pour les procédures spécifiques à la cible concernant RFID/NFC, les fréquences sub-GHz, l’infrarouge, BLE, LoRaWAN et iButton, consultez [Radio Hacking and Proximity Interfaces](../radio-hacking/README.md). Vérifiez les niveaux électriques de la cible et les restrictions décrites dans le chapitre correspondant avant de connecter vos outils.

## JTAG

JTAG (IEEE 1149.1) permet d’effectuer des tests boundary-scan à l’aide de cellules placées autour des broches d’E/S d’un appareil. De nombreux processeurs exposent également des fonctions de débogage spécifiques au fabricant par le même Test Access Port (TAP) ; le boundary scan et le débogage du processeur sont deux usages connexes de JTAG, mais pas des synonymes.<sup>[[1]](#references)</sup>

La norme JTAG définit **des commandes spécifiques pour effectuer des boundary scans**, notamment :

- **BYPASS** sélectionne un registre de contournement d’un bit, afin d’accéder aux autres appareils d’une chaîne de scan avec un minimum de surcharge.
- **SAMPLE/PRELOAD** capture les valeurs des broches en fonctionnement normal et peut précharger le registre boundary-scan avant une autre instruction.
- **EXTEST** définit et lit l’état des broches.

Elle peut également prendre en charge d’autres commandes, telles que :

- **IDCODE** pour identifier un appareil
- **INTEST** pour les tests internes de l’appareil

Vous pouvez rencontrer ces instructions en utilisant un outil comme le JTAGulator.

### Le Test Access Port

Le **Test Access Port (TAP)** donne accès à la logique de test JTAG d’un composant. Quatre signaux sont nécessaires ; `TRST` est facultatif :<sup>[[1]](#references)</sup>

- Entrée d’horloge de test (**TCK**) TCK est l’**horloge** qui définit la fréquence à laquelle le contrôleur TAP effectue une action (autrement dit, passe à l’état suivant de la machine à états).
- Entrée de sélection du mode de test (**TMS**) TMS contrôle la **machine à états finis**. À chaque cycle d’horloge, le contrôleur JTAG TAP de l’appareil vérifie la tension sur la broche TMS. Si la tension est inférieure à un certain seuil, le signal est considéré comme bas et interprété comme 0 ; si elle dépasse ce seuil, le signal est considéré comme haut et interprété comme 1.
- Entrée de données de test (**TDI**) TDI fait entrer en série des instructions ou des données de test dans le registre TAP sélectionné. IEEE 1149.1 définit le fonctionnement des transferts TAP, tandis que les fabricants définissent les instructions facultatives et les registres de débogage.
- Sortie de données de test (**TDO**) TDO est la broche qui envoie les **données hors de la puce**.
- Entrée de réinitialisation de test (**TRST**) L’entrée TRST facultative réinitialise la machine à états finis **dans un état connu et valide**. Autrement, maintenir TMS à 1 pendant cinq cycles d’horloge consécutifs déclenche une réinitialisation, comme le ferait la broche TRST, ce qui explique pourquoi TRST est facultative.

Il est parfois possible de repérer ces broches sur la carte électronique. Dans d’autres cas, vous devrez les **identifier**.

### Identification des broches JTAG

Le **JTAGulator** est une option rapide, conçue spécifiquement pour détecter les ports JTAG, mais relativement coûteuse ; il peut également identifier le brochage UART.<sup>[[2]](#references)</sup>

Il dispose de **24 canaux** qui peuvent être connectés aux points de test de la carte. Il énumère les combinaisons de broches possibles à l’aide de scans **IDCODE** et **BYPASS**, puis indique les canaux correspondant aux signaux JTAG détectés.

Une méthode moins coûteuse, mais beaucoup plus lente, pour identifier le brochage JTAG consiste à utiliser [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) sur un microcontrôleur compatible Arduino.

Avec **JTAGenum**, commencez par définir les broches du microcontrôleur de sondage utilisées pour l’énumération. Consultez son brochage, puis connectez ces broches aux points de test potentiels de la carte cible.<sup>[[3]](#references)</sup>

Une **troisième méthode** pour identifier les broches JTAG consiste à **examiner la carte électronique** afin d’y repérer une empreinte connue. Certaines cartes exposent une empreinte **Tag-Connect**, mais Tag-Connect est un système de connecteurs pouvant transporter JTAG, SWD, UART ou une autre interface : sa présence ne prouve pas à elle seule que les broches sont JTAG. Les fiches techniques des composants et les mesures de continuité permettent ensuite d’identifier les signaux réels.<sup>[[5]](#references)</sup>

## SDW

SWD est l’interface de débogage d’Arm, à deux broches et basée sur des paquets.<sup>[[4]](#references)</sup>

L’interface utilise **SWDIO** bidirectionnel pour les données et **SWCLK** pour l’horloge. De nombreux appareils implémentent un **Serial Wire/JTAG Debug Port (SWJ-DP)** qui permet de choisir entre SWD et JTAG sur des broches partagées.<sup>[[4]](#references)</sup>

## References

- [1] [Groupe de travail IEEE 1149.1 — JTAG et boundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [Documentation JTAGulator](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — Énumération des broches JTAG avec Arduino](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Interfaces de débogage à faible nombre de broches pour les systèmes multi-appareils](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — Empreintes de câbles de débogage et de programmation](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
