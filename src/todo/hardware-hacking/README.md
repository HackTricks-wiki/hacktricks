# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

## JTAG

JTAG permet d’effectuer un boundary scan. Le boundary scan analyse certains circuits, notamment les boundary-scan cells et les registres associés à chaque broche.

Le standard JTAG définit des **commandes spécifiques pour effectuer des boundary scans**, notamment les suivantes :

- **BYPASS** permet de tester une puce spécifique sans subir la surcharge liée au passage par les autres puces.
- **SAMPLE/PRELOAD** capture un échantillon des données entrant dans le composant et en sortant lorsqu’il fonctionne normalement.
- **EXTEST** définit et lit l’état des broches.

Il peut également prendre en charge d’autres commandes, telles que :

- **IDCODE** pour identifier un composant
- **INTEST** pour effectuer un test interne du composant

Vous pouvez rencontrer ces instructions lorsque vous utilisez un outil comme le JTAGulator.

### The Test Access Port

Les boundary scans incluent des tests du **Test Access Port (TAP)** à quatre fils, un port polyvalent qui fournit un **accès aux fonctions de support des tests JTAG** intégrées à un composant. Le TAP utilise les cinq signaux suivants :

- Entrée d’horloge de test (**TCK**) Le TCK est l’**horloge** qui définit la fréquence à laquelle le contrôleur TAP effectue une action unique (autrement dit, passe à l’état suivant de la machine à états).
- Entrée de sélection du mode de test (**TMS**) Le TMS contrôle la **machine à états finis**. À chaque cycle d’horloge, le contrôleur JTAG TAP du composant vérifie la tension sur la broche TMS. Si la tension est inférieure à un certain seuil, le signal est considéré comme bas et interprété comme 0 ; si elle est supérieure à un certain seuil, le signal est considéré comme haut et interprété comme 1.
- Entrée de données de test (**TDI**) Le TDI est la broche qui envoie les **données dans la puce via les scan cells**. Chaque fabricant est responsable de la définition du protocole de communication utilisé sur cette broche, car JTAG ne le définit pas.
- Sortie de données de test (**TDO**) Le TDO est la broche qui envoie les **données hors de la puce**.
- Entrée de réinitialisation de test (**TRST**) La TRST, facultative, réinitialise la machine à états finis **dans un état connu et fiable**. Sinon, si le TMS est maintenu à 1 pendant cinq cycles d’horloge consécutifs, une réinitialisation est déclenchée de la même manière que par la broche TRST, ce qui explique pourquoi TRST est facultative.

Il est parfois possible de trouver ces broches marquées sur le PCB. Dans d’autres cas, vous devrez les **trouver**.

### Identifying JTAG pins

La manière la plus rapide, mais aussi la plus coûteuse, de détecter les ports JTAG consiste à utiliser le **JTAGulator**, un appareil créé spécifiquement à cette fin (bien qu’il puisse **également détecter les pinouts UART**).

Il possède **24 canaux** que vous pouvez connecter aux broches de la carte. Il effectue ensuite une **attaque BF** sur toutes les combinaisons possibles en envoyant les commandes de boundary scan **IDCODE** et **BYPASS**. S’il reçoit une réponse, il affiche le canal correspondant à chaque signal JTAG.

Une manière moins coûteuse, mais beaucoup plus lente, d’identifier les pinouts JTAG consiste à utiliser [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) chargé sur un microcontrôleur compatible Arduino.

Avec **JTAGenum**, vous devez d’abord **définir les broches du dispositif de probing** que vous utiliserez pour l’énumération. Vous devez consulter le schéma de brochage du dispositif, puis connecter ces broches aux points de test de votre dispositif cible.

Une **troisième manière** d’identifier les broches JTAG consiste à **inspecter le PCB** pour trouver l’un des pinouts. Dans certains cas, les PCB peuvent fournir de manière pratique l’**interface Tag-Connect**, ce qui indique clairement que la carte possède également un connecteur JTAG. Vous pouvez voir à quoi ressemble cette interface à l’adresse [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). En outre, l’inspection des **datasheets des chipsets du PCB** peut révéler des schémas de brochage indiquant la présence d’interfaces JTAG.

## SDW

SWD est un protocole spécifique à ARM conçu pour le debugging.

L’interface SWD nécessite **deux broches** : un signal bidirectionnel **SWDIO**, qui équivaut aux **broches TDI et TDO de JTAG ainsi qu’à une horloge**, et **SWCLK**, qui équivaut à **TCK** dans JTAG. De nombreux composants prennent en charge le **Serial Wire or JTAG Debug Port (SWJ-DP)**, une interface combinant JTAG et SWD qui permet de connecter au dispositif cible une sonde SWD ou JTAG.

{{#include ../../banners/hacktricks-training.md}}
