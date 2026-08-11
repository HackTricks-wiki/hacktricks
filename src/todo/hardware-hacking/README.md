# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

## JTAG

JTAG (IEEE 1149.1) prend en charge les tests boundary-scan au moyen de cellules placées autour des broches d'E/S d'un composant. De nombreux processeurs exposent également des fonctions de debug propres au fabricant via le même Test Access Port (TAP) ; le boundary scan et le debug du CPU sont des utilisations liées de JTAG, mais ne sont pas synonymes.<sup>[[1]](#references)</sup>

Le standard JTAG définit des **commandes spécifiques pour effectuer des boundary scans**, notamment les suivantes :

- **BYPASS** sélectionne un registre de bypass d'un bit afin que les autres composants d'une chaîne de scan puissent être atteints avec un surcoût minimal.
- **SAMPLE/PRELOAD** capture les valeurs des broches pendant le fonctionnement normal et peut précharger le registre boundary-scan avant une autre instruction.
- **EXTEST** définit et lit l'état des broches.

Il prend également en charge d'autres commandes, telles que :

- **IDCODE** pour identifier un composant
- **INTEST** pour effectuer les tests internes du composant

Vous pouvez rencontrer ces instructions lorsque vous utilisez un outil comme le JTAGulator.

### Le Test Access Port

Le **Test Access Port (TAP)** permet d'accéder à la logique de test JTAG d'un composant. Quatre signaux sont requis et `TRST` est optionnel :<sup>[[1]](#references)</sup>

- Entrée d'horloge de test (**TCK**) TCK est l'**horloge** qui définit la fréquence à laquelle le contrôleur TAP effectue une action unique (autrement dit, passe à l'état suivant de la machine à états).
- Entrée de sélection du mode de test (**TMS**) TMS contrôle la **machine à états finis**. À chaque cycle d'horloge, le contrôleur JTAG TAP du composant vérifie la tension sur la broche TMS. Si la tension est inférieure à un certain seuil, le signal est considéré comme bas et interprété comme 0 ; si la tension est supérieure à un certain seuil, le signal est considéré comme haut et interprété comme 1.
- Entrée de données de test (**TDI**) TDI décale les instructions série ou les données de test dans le registre TAP sélectionné. IEEE 1149.1 définit le comportement du transfert TAP, tandis que les fabricants définissent les instructions optionnelles et les registres de debug.
- Sortie de données de test (**TDO**) TDO est la broche qui envoie les **données hors de la puce**.
- Entrée de réinitialisation de test (**TRST**) L'entrée TRST optionnelle réinitialise la machine à états finis **dans un état connu et fonctionnel**. Alternativement, si TMS est maintenu à 1 pendant cinq cycles d'horloge consécutifs, une réinitialisation est déclenchée, de la même manière qu'avec la broche TRST, ce qui explique pourquoi TRST est optionnel.

Il est parfois possible de trouver ces broches marquées sur le PCB. Dans d'autres cas, vous devrez les **identifier**.

### Identification des broches JTAG

Une option rapide et conçue spécifiquement à cet effet, mais relativement coûteuse, pour détecter les ports JTAG est le **JTAGulator**, qui peut également identifier les brochages UART.<sup>[[2]](#references)</sup>

Il dispose de **24 canaux** pouvant être connectés aux points de test de la carte. Il énumère les combinaisons de broches candidates à l'aide de scans **IDCODE** et **BYPASS**, puis indique les canaux correspondant aux signaux JTAG détectés.

Une méthode moins coûteuse, mais beaucoup plus lente, pour identifier les brochages JTAG consiste à utiliser [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) chargé sur un microcontrôleur compatible Arduino.

Avec **JTAGenum**, commencez par définir les broches du microcontrôleur de sondage utilisées pour l'énumération. Consultez son brochage, puis connectez ces broches aux points de test candidats de la carte cible.<sup>[[3]](#references)</sup>

Une **troisième méthode** pour identifier les broches JTAG consiste à **inspecter le PCB** à la recherche d'une empreinte connue. Certaines cartes exposent une empreinte **Tag-Connect**, bien que Tag-Connect soit un système de connecteurs pouvant transporter du JTAG, du SWD, de l'UART ou une autre interface : cela ne prouve pas à lui seul que les broches sont JTAG. Les fiches techniques des composants et les mesures de continuité peuvent ensuite permettre d'identifier les signaux réels.<sup>[[5]](#references)</sup>

## SDW

SWD est l'interface de debug à deux broches et basée sur des paquets d'Arm.<sup>[[4]](#references)</sup>

L'interface utilise **SWDIO** bidirectionnel pour les données et **SWCLK** pour l'horloge. De nombreux composants implémentent un **Serial Wire/JTAG Debug Port (SWJ-DP)** qui permet de sélectionner SWD ou JTAG sur des broches partagées.<sup>[[4]](#references)</sup>

## References

- [1] [Groupe de travail IEEE 1149.1 — JTAG et boundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [Documentation de JTAGulator](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — Énumération des broches JTAG avec Arduino](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Interfaces de debug à faible nombre de broches pour les systèmes multi-composants](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — Empreintes pour câbles de debug et de programmation](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
