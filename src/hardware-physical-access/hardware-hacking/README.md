# Piratage matériel

{{#include ../../banners/hacktricks-training.md}}

Pour un appareil auquel vous avez un accès physique, commencez par examiner les interfaces exposées par sa carte ou ses signaux : [consoles série UART](uart.md), [accès de débogage JTAG/SWD](jtag.md), [traçage d’instructions CoreSight](arm-coresight-instruction-tracing.md), les bus [I²C](i2c.md) et [flash SPI](spi.md). L’[analyse side-channel](side_channel_analysis.md) et l’[injection de fautes](fault_injection_attacks.md) répondent à d’autres besoins de mesure et de glitching ; l’[analyse des signaux radio](radio.md) couvre les points d’entrée sans fil. Pour les procédures propres à une cible concernant RFID/NFC, les fréquences sub-GHz, l’infrarouge, BLE, LoRaWAN et iButton, consultez [Radio Hacking and Proximity Interfaces](../radio-hacking/README.md). Vérifiez les niveaux électriques de la cible et les limitations indiquées dans le chapitre correspondant avant de connecter des outils.

## JTAG

JTAG (IEEE 1149.1) permet de réaliser des tests boundary-scan à l’aide de cellules placées autour des broches d’E/S d’un appareil. De nombreux processeurs exposent également des fonctions de débogage propres au fabricant via le même Test Access Port (TAP) ; le boundary scan et le débogage du CPU sont des utilisations liées de JTAG, mais ne sont pas synonymes.<sup>[[1]](#references)</sup>

La norme JTAG définit des **commandes spécifiques pour effectuer des boundary scans**, notamment :

- **BYPASS** sélectionne un registre de contournement d’un bit afin d’accéder aux autres appareils de la chaîne de scan avec un minimum de surcharge.
- **SAMPLE/PRELOAD** capture les valeurs des broches pendant le fonctionnement normal et peut précharger le registre boundary-scan avant une autre instruction.
- **EXTEST** définit et lit l’état des broches.

Elle peut également prendre en charge d’autres commandes, telles que :

- **IDCODE** pour identifier un appareil
- **INTEST** pour tester l’appareil en interne

Vous pourriez rencontrer ces instructions en utilisant un outil comme le JTAGulator.

### Le Test Access Port

Le **Test Access Port (TAP)** donne accès à la logique de test JTAG d’un composant. Quatre signaux sont nécessaires et `TRST` est facultatif :<sup>[[1]](#references)</sup>

- Entrée d’horloge de test (**TCK**) TCK est l’**horloge** qui détermine la fréquence à laquelle le contrôleur TAP effectue une action (autrement dit, passe à l’état suivant de la machine à états).
- Entrée de sélection du mode de test (**TMS**) TMS contrôle la **machine à états finis**. À chaque impulsion d’horloge, le contrôleur JTAG TAP de l’appareil vérifie la tension sur la broche TMS. Si la tension est inférieure à un certain seuil, le signal est considéré comme bas et interprété comme 0 ; si elle est supérieure à un certain seuil, le signal est considéré comme haut et interprété comme 1.
- Entrée de données de test (**TDI**) TDI décale des instructions série ou des données de test vers le registre TAP sélectionné. IEEE 1149.1 définit le fonctionnement des transferts TAP, tandis que les fabricants définissent les instructions facultatives et les registres de débogage.
- Sortie de données de test (**TDO**) TDO est la broche qui transmet les **données hors de la puce**.
- Entrée de réinitialisation de test (**TRST**) L’entrée TRST facultative réinitialise la machine à états finis **dans un état connu et valide**. Sinon, maintenir TMS à 1 pendant cinq cycles d’horloge consécutifs déclenche une réinitialisation, comme le ferait la broche TRST ; c’est pourquoi TRST est facultative.

Il est parfois possible de repérer ces broches indiquées sur le PCB. Dans d’autres cas, vous devrez les **identifier**.

### Identifier les broches JTAG

Une option rapide, spécialement conçue à cet effet, mais relativement coûteuse pour détecter les ports JTAG est le **JTAGulator**, qui peut également identifier les brochages UART.<sup>[[2]](#references)</sup>

Il dispose de **24 canaux** pouvant être connectés aux points de test de la carte. Il énumère les combinaisons de broches possibles au moyen de scans **IDCODE** et **BYPASS**, puis indique les canaux correspondant aux signaux JTAG détectés.

Une méthode moins coûteuse, mais beaucoup plus lente, pour identifier les brochages JTAG consiste à utiliser [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) sur un microcontrôleur compatible Arduino.

Avec **JTAGenum**, commencez par définir les broches du microcontrôleur de sondage utilisées pour l’énumération. Consultez son brochage, puis connectez ces broches aux points de test possibles sur la carte cible.<sup>[[3]](#references)</sup>

Une **troisième méthode** pour identifier les broches JTAG consiste à **inspecter le PCB** à la recherche d’une empreinte connue. Certaines cartes exposent une empreinte **Tag-Connect**, mais Tag-Connect est un système de connecteurs pouvant transporter JTAG, SWD, UART ou une autre interface ; sa présence ne prouve donc pas à elle seule que les broches sont des broches JTAG. Les fiches techniques des composants et des mesures de continuité permettent ensuite d’identifier les signaux réels.<sup>[[5]](#references)</sup>

## SDW

SWD est l’interface de débogage d’Arm à deux broches et à paquets.<sup>[[4]](#references)</sup>

L’interface utilise **SWDIO**, bidirectionnel, pour les données et **SWCLK** pour l’horloge. De nombreux appareils implémentent un **Serial Wire/JTAG Debug Port (SWJ-DP)** qui permet de choisir entre SWD et JTAG sur des broches partagées.<sup>[[4]](#references)</sup>

## References

- [1] [Groupe de travail IEEE 1149.1 — JTAG et boundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [Documentation du JTAGulator](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — Énumération des broches JTAG sur Arduino](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Interfaces de débogage à faible nombre de broches pour les systèmes multi-appareils](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — Empreintes pour câbles de débogage et de programmation](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
