# Hacking matériel

{{#include ../../banners/hacktricks-training.md}}

Pour un appareil auquel vous avez physiquement accès, commencez par examiner les interfaces exposées par sa carte ou ses signaux : [consoles série UART](uart.md), [accès de débogage JTAG/SWD](jtag.md), bus [I²C](i2c.md) et [flash SPI](spi.md). L’[analyse des canaux auxiliaires](side_channel_analysis.md) et l’[injection de fautes](fault_injection_attacks.md) répondent à d’autres tâches de mesure et de glitching ; l’[analyse des signaux radio](radio.md) couvre un point d’entrée sans fil. Vérifiez les niveaux électriques de la cible et les limites indiquées dans le chapitre correspondant avant de connecter des outils.

## JTAG

JTAG (IEEE 1149.1) permet les tests boundary-scan au moyen de cellules placées autour des broches d’E/S d’un appareil. De nombreux processeurs exposent également des fonctions de débogage spécifiques au fabricant via le même Test Access Port (TAP) ; le boundary-scan et le débogage du processeur sont des usages liés de JTAG, mais ne sont pas synonymes.<sup>[[1]](#references)</sup>

La norme JTAG définit des **commandes spécifiques pour effectuer des boundary scans**, notamment :

- **BYPASS** sélectionne un registre de contournement d’un bit afin d’accéder aux autres appareils d’une chaîne de scan avec un minimum de surcharge.
- **SAMPLE/PRELOAD** capture les valeurs des broches pendant le fonctionnement normal et peut précharger le registre boundary-scan avant une autre instruction.
- **EXTEST** définit et lit l’état des broches.

JTAG peut également prendre en charge d’autres commandes, telles que :

- **IDCODE** pour identifier un appareil
- **INTEST** pour tester l’appareil en interne

Vous pouvez rencontrer ces instructions lorsque vous utilisez un outil comme le JTAGulator.

### Le Test Access Port

Le **Test Access Port (TAP)** donne accès à la logique de test JTAG d’un composant. Quatre signaux sont requis et `TRST` est facultatif :<sup>[[1]](#references)</sup>

- Entrée d’horloge de test (**TCK**) TCK est l’**horloge** qui détermine la fréquence à laquelle le contrôleur TAP effectue une action (autrement dit, passe à l’état suivant de la machine à états).
- Entrée de sélection du mode de test (**TMS**) TMS contrôle la **machine à états finis**. À chaque cycle d’horloge, le contrôleur JTAG TAP de l’appareil vérifie la tension sur la broche TMS. Si la tension est inférieure à un certain seuil, le signal est considéré comme bas et interprété comme 0 ; si elle est supérieure à ce seuil, le signal est considéré comme haut et interprété comme 1.
- Entrée de données de test (**TDI**) TDI décale une instruction série ou des données de test vers le registre TAP sélectionné. IEEE 1149.1 définit le comportement de transfert du TAP, tandis que les fabricants définissent les instructions facultatives et les registres de débogage.
- Sortie de données de test (**TDO**) TDO est la broche qui envoie les **données hors de la puce**.
- Entrée de réinitialisation de test (**TRST**) L’entrée TRST facultative réinitialise la machine à états finis **dans un état connu et valide**. Autrement, si TMS est maintenu à 1 pendant cinq cycles d’horloge consécutifs, cela déclenche une réinitialisation, comme le ferait la broche TRST ; c’est pourquoi TRST est facultatif.

Parfois, ces broches sont indiquées sur le PCB. Dans d’autres cas, vous devrez les **repérer**.

### Identifier les broches JTAG

Le **JTAGulator** est une option rapide et conçue spécialement pour détecter les ports JTAG, mais relativement coûteuse. Il peut également identifier le brochage UART.<sup>[[2]](#references)</sup>

Il dispose de **24 canaux** qui peuvent être connectés aux points de test de la carte. Il énumère les combinaisons possibles de broches à l’aide de scans **IDCODE** et **BYPASS**, puis indique les canaux correspondant aux signaux JTAG détectés.

Une méthode moins coûteuse, mais beaucoup plus lente, pour identifier le brochage JTAG consiste à utiliser [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) sur un microcontrôleur compatible Arduino.

Avec **JTAGenum**, commencez par définir les broches du microcontrôleur de sondage utilisées pour l’énumération. Consultez son brochage, puis connectez ces broches aux points de test possibles de la carte cible.<sup>[[3]](#references)</sup>

Une **troisième méthode** pour identifier les broches JTAG consiste à **examiner le PCB** afin d’y repérer une empreinte connue. Certaines cartes exposent une empreinte **Tag-Connect**, mais Tag-Connect est un système de connexion pouvant transporter JTAG, SWD, UART ou une autre interface : sa présence ne prouve pas à elle seule que les broches sont des broches JTAG. Les fiches techniques des composants et les mesures de continuité permettent ensuite d’identifier les signaux réels.<sup>[[5]](#references)</sup>

## SDW

SWD est l’interface de débogage à deux broches et à paquets d’Arm.<sup>[[4]](#references)</sup>

L’interface utilise **SWDIO**, bidirectionnelle, pour les données et **SWCLK** pour l’horloge. De nombreux appareils implémentent un **Serial Wire/JTAG Debug Port (SWJ-DP)** qui permet de choisir entre SWD et JTAG sur des broches partagées.<sup>[[4]](#references)</sup>

## References

- [1] [Groupe de travail IEEE 1149.1 — JTAG et boundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [Documentation du JTAGulator](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — Énumération des broches JTAG sur Arduino](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Interfaces de débogage à faible nombre de broches pour les systèmes multi-appareils](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — Empreintes pour câbles de débogage et de programmation](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
