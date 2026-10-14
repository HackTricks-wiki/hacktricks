# Radio

{{#include ../../banners/hacktricks-training.md}}

Pour les tests propres à chaque protocole après l’identification du signal, consultez [RFID/NFC, sub-GHz, infrarouge, BLE et LoRaWAN](../radio-hacking/README.md).

## SigDigger

[**SigDigger**](https://github.com/BatchDrake/SigDigger) est un analyseur gratuit de signaux numériques pour GNU/Linux et macOS, conçu pour extraire des informations de signaux radio inconnus. Il prend en charge les appareils SDR via SoapySDR et fournit des outils de démodulation et d’analyse en temps réel pour FSK, PSK, ASK, la vidéo analogique, les signaux en rafales et les canaux vocaux analogiques.<sup>[[1]](#references)</sup>

### Configuration de base

Après l’installation, quelques paramètres peuvent être configurés.\
Dans les paramètres (deuxième onglet), sélectionnez un **appareil SDR** ou un fichier d’entrée, la fréquence à régler et la fréquence d’échantillonnage. Une fréquence pouvant atteindre 2.56 Msps peut être adaptée si l’hôte la prend en charge.

![Paramètres de SigDigger affichant les options d’appareil SDR, de fichier d’entrée, de fréquence et de fréquence d’échantillonnage](<../../images/image (245).png>)

Dans le comportement de l’interface graphique, il est recommandé d’activer quelques options si votre PC les prend en charge :

![SigDigger - Configuration de base : dans le comportement de l’interface graphique, il est recommandé d’activer quelques options si votre PC les prend en charge](<../../images/image (472).png>)

> [!TIP]
> Si vous constatez que votre PC ne capture rien, essayez de désactiver OpenGL et de réduire la fréquence d’échantillonnage.

### Utilisations

- Pour **capturer un signal pendant un certain temps et l’analyser**, maintenez le bouton « Push to capture » enfoncé aussi longtemps que nécessaire.

![Configuration de base - Utilisations : pour capturer un signal pendant un certain temps et l’analyser, maintenez le bouton « Push to capture » enfoncé aussi longtemps que nécessaire](<../../images/image (960).png>)

- Le **Tuner** de SigDigger aide à **mieux capturer les signaux** (mais peut aussi les dégrader). L’idéal est de commencer à 0 et de **l’augmenter progressivement jusqu’à ce que** le **bruit** introduit soit **supérieur** à l’**amélioration du signal** recherchée.

![Commande du tuner de SigDigger réglée pour améliorer le signal radio capturé](<../../images/image (1099).png>)

### Synchronisation avec un canal radio

Avec [**SigDigger** ](https://github.com/BatchDrake/SigDigger), synchronisez-vous avec le canal que vous voulez écouter, configurez l’option « Baseband audio preview », réglez la largeur de bande pour obtenir toutes les informations transmises, puis réglez le Tuner au niveau juste avant que le bruit ne commence à augmenter fortement :<sup>[[1]](#references)</sup>

![Canal radio synchronisé dans SigDigger, avec l’aperçu audio en bande de base et la largeur de bande configurés](<../../images/image (585).png>)

## Astuces intéressantes

- Lorsqu’un appareil transmet des rafales d’informations, **la première partie est généralement un préambule**. Vous n’avez donc **pas à vous inquiéter** si vous **n’y trouvez aucune information** ou s’il **contient des erreurs**.
- Dans les trames d’informations, vous devriez généralement **trouver différentes trames bien alignées entre elles** :

![Synchronisation avec un canal radio - Astuces intéressantes : dans les trames d’informations, vous devriez généralement trouver différentes trames bien alignées entre elles](<../../images/image (1076).png>)

![Synchronisation avec un canal radio - Astuces intéressantes : dans les trames d’informations, vous devriez généralement trouver différentes trames bien alignées entre elles](<../../images/image (597).png>)

- **Après avoir récupéré les transitions de niveau, vous devrez peut-être les décoder.** Pour le codage Manchester, un sens de transition représente `0` et le sens opposé représente `1` ; la polarité exacte dépend de la convention utilisée.
- Un préambule peut contenir une série de niveaux échantillonnés identiques, même si la charge utile utilise le codage Manchester. Identifiez donc le début de la trame avant le décodage.

### Déterminer le type de modulation avec IQ

Il existe 3 façons de coder des informations dans les signaux : moduler l’**amplitude**, la **fréquence** ou la **phase**.\
Pour analyser un signal, il existe différentes façons de déterminer comment l’information est codée (voir d’autres méthodes ci-dessous), mais une bonne méthode consiste à examiner le graphique IQ.

![Graphique IQ de SigDigger utilisé pour déterminer si un signal utilise une modulation d’amplitude, de fréquence ou de phase](<../../images/image (788).png>)

- **Détection de l’AM** : si le graphique IQ montre, par exemple, **2 cercles** (probablement l’un en 0 et l’autre à une amplitude différente), il peut s’agir d’un signal AM. En effet, sur le graphique IQ, la distance entre le point 0 et le cercle correspond à l’amplitude du signal : il est donc facile de visualiser les différentes amplitudes utilisées.
- **Détection de la PM** : comme dans l’image précédente, si vous trouvez de petits cercles sans lien entre eux, une modulation de phase est probablement utilisée. En effet, sur le graphique IQ, l’angle entre le point et le point 0,0 correspond à la phase du signal, ce qui signifie que 4 phases différentes sont utilisées.
  - Notez que si l’information réside dans le changement de phase et non dans la phase elle-même, vous ne verrez pas de phases clairement distinctes.
- **Détection de la FM** : IQ ne comporte pas de champ permettant d’identifier les fréquences (la distance au centre correspond à l’amplitude et l’angle à la phase).\
  Par conséquent, pour identifier la FM, vous devriez **voir essentiellement un cercle** sur ce graphique.\
  De plus, un décalage de fréquence modifie la vitesse de rotation autour du cercle IQ. Dans SigDigger, un changement de vitesse ou de sens de rotation peut donc indiquer une FM.

## Exemple AM

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Déterminer l’AM

#### Examiner l’enveloppe

Lors de l’inspection de données AM avec [**SigDigger**](https://github.com/BatchDrake/SigDigger), l’**enveloppe** du signal peut révéler des niveaux d’amplitude distincts. Le signal d’exemple transmet des informations sous forme d’impulsions modulées en amplitude ; une impulsion ressemble à ceci :<sup>[[1]](#references)</sup>

![Enveloppe du signal AM dans SigDigger, avec des niveaux d’amplitude d’impulsion clairement visibles](<../../images/image (590).png>)

Voici à quoi ressemble une partie du symbole dans la forme d’onde :

![Déterminer l’AM - Examiner l’enveloppe : voici à quoi ressemble une partie du symbole dans la forme d’onde](<../../images/image (734).png>)

#### Examiner l’histogramme

Vous pouvez **sélectionner toute la portion du signal** où se trouve l’information, choisir le mode **Amplitude** et **Selection**, puis cliquer sur **Histogram.** Vous pouvez constater qu’on ne trouve que 2 niveaux distincts.

![Histogramme d’amplitude de SigDigger montrant deux niveaux distincts pour le signal AM sélectionné](<../../images/image (264).png>)

Par exemple, si vous sélectionnez Frequency au lieu d’Amplitude dans ce signal AM, vous ne trouverez qu’une seule fréquence (il est impossible qu’une information modulée en fréquence n’utilise qu’une seule fréquence).

![Histogramme de fréquence de SigDigger pour le signal AM, montrant une seule fréquence](<../../images/image (732).png>)

Si vous trouvez de nombreuses fréquences, il ne s’agit probablement pas de FM ; la fréquence du signal a sans doute simplement été modifiée par le canal.

#### Avec IQ

Dans cet exemple, vous pouvez voir un **grand cercle**, mais aussi **de nombreux points au centre**.

![Examiner l’histogramme - Avec IQ : dans cet exemple, on voit un grand cercle ainsi que de nombreux points au centre](<../../images/image (222).png>)

### Déterminer le débit symbole

#### Avec un symbole

Sélectionnez le plus petit intervalle contenant clairement un symbole, puis vérifiez **Selection freq**. Dans cet exemple, la valeur est de 1.013 kHz, soit environ 1 kHz.

![Déterminer le débit symbole - Avec un symbole : sélectionnez le plus petit intervalle qui contient clairement un seul symbole, puis vérifiez « Selection freq ». Dans cet exemple, la valeur est de 1.013 kHz, soit 1 kHz.](<../../images/image (78).png>)

#### Avec un groupe de symboles

Vous pouvez également indiquer le nombre de symboles à sélectionner ; SigDigger calculera alors la fréquence d’un symbole (plus le nombre de symboles sélectionnés est grand, plus le résultat est probablement précis). Dans cet exemple, j’ai sélectionné 10 symboles et « Selection freq » indique 1.004 Khz :

![Calcul du débit symbole dans SigDigger à partir d’un groupe sélectionné de dix symboles](<../../images/image (1008).png>)

### Extraire les bits

Après avoir identifié l’AM et estimé le **débit symbole**, sélectionnez la portion du signal, configurez l’échantillonnage de l’amplitude et les niveaux de décision, choisissez **Gardner clock recovery**, puis cliquez sur **Sample** :

![Panneau Get Bits de SigDigger configuré pour l’échantillonnage AM, le débit symbole et Gardner clock recovery](<../../images/image (965).png>)

- **Sync to selection intervals** signifie que si vous avez précédemment sélectionné des intervalles pour trouver le débit symbole, ce débit sera utilisé.
- **Manual** signifie que le débit symbole indiqué sera utilisé.
- Dans **Fixed interval selection**, vous indiquez le nombre d’intervalles à sélectionner ; le débit symbole est alors calculé à partir de ce nombre.
- **Gardner clock recovery** est un bon réglage par défaut, mais il nécessite tout de même un débit symbole approximatif.

Après avoir cliqué sur Sample, voici ce qui apparaît :

![Avec un groupe de symboles - Extraire les bits : voici ce qui apparaît après avoir cliqué sur Sample](<../../images/image (644).png>)

Pour que SigDigger comprenne **où se trouve la plage** des niveaux qui portent l’information, cliquez sur le **niveau inférieur** et maintenez le clic jusqu’au niveau le plus élevé :

![Sélection de la plage de niveaux dans SigDigger, de l’amplitude la plus faible à la plus élevée](<../../images/image (439).png>)

S’il y avait, par exemple, **4 niveaux d’amplitude différents**, vous devriez configurer **Bits per symbol** sur 2 et sélectionner la plage allant du niveau le plus faible au plus élevé.

Enfin, en **augmentant** le **Zoom** et en **modifiant Row size**, vous pouvez voir les bits (vous pouvez tout sélectionner et copier pour récupérer tous les bits) :

![Avec un groupe de symboles - Extraire les bits : en augmentant le Zoom et en modifiant Row size, vous pouvez voir les bits et tous les sélectionner et les copier](<../../images/image (276).png>)

Si le signal comporte plus d’un bit par symbole (par exemple 2), SigDigger ne peut **pas savoir quel symbole correspond à** 00, 01, 10 ou 11. Il utilise donc différentes **nuances de gris** pour les représenter (et, si vous copiez les bits, il utilise des **nombres de 0 à 3**, qu’il faudra interpréter).

Pour les codages de ligne tels que **Manchester**, convertissez chaque paire de transitions valide (`01` ou `10`) en bit de données selon la convention utilisée par le protocole.

## Exemple FM

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Déterminer la FM

#### Examiner les fréquences et la forme d’onde

Exemple de signal transmettant des informations modulées en FM :

![Déterminer la FM - Examiner les fréquences et la forme d’onde : exemple de signal transmettant des informations modulées en FM](<../../images/image (725).png>)

Le spectre montre clairement **deux fréquences**, même si elles peuvent être difficiles à distinguer dans la forme d’onde temporelle :

![Forme d’onde FM dans SigDigger, où les deux fréquences sont difficiles à distinguer directement](<../../images/image (717).png>)

Cela se produit parce que la capture est centrée entre les deux fréquences ; leurs décalages de fréquence sont donc approximativement opposés :

![Capture FM dans SigDigger montrant les deux fréquences comme des valeurs approximativement opposées](<../../images/image (942).png>)

Si la fréquence de synchronisation est **plus proche d’une fréquence que de l’autre**, vous pouvez facilement voir les 2 fréquences distinctes :

![Déterminer la FM - Examiner les fréquences et la forme d’onde : si la fréquence de synchronisation est plus proche d’une fréquence que de l’autre, vous pouvez facilement voir les 2 fréquences distinctes](<../../images/image (422).png>)

![Déterminer la FM - Examiner les fréquences et la forme d’onde : si la fréquence de synchronisation est plus proche d’une fréquence que de l’autre, vous pouvez facilement voir les 2 fréquences distinctes](<../../images/image (488).png>)

#### Examiner l’histogramme

En examinant l’histogramme des fréquences du signal contenant l’information, vous pouvez facilement voir 2 signaux distincts :

![Examiner les fréquences et la forme d’onde - Examiner l’histogramme : l’histogramme des fréquences du signal contenant l’information montre clairement 2 signaux distincts](<../../images/image (871).png>)

Dans ce cas, si vous examinez l’**histogramme d’amplitude**, vous ne trouverez **qu’une seule amplitude** ; il **ne peut donc pas s’agir d’AM** (si vous trouvez de nombreuses amplitudes, cela peut être dû à une perte de puissance du signal dans le canal) :

![Histogramme d’amplitude de SigDigger pour un signal FM, montrant un seul niveau d’amplitude](<../../images/image (817).png>)

Voici l’histogramme de phase, qui montre clairement que le signal n’est pas modulé en phase :

![Examiner les fréquences et la forme d’onde - Examiner l’histogramme : histogramme de phase montrant clairement que le signal n’est pas modulé en phase](<../../images/image (996).png>)

#### Avec IQ

IQ ne comporte pas de champ permettant d’identifier les fréquences (la distance au centre correspond à l’amplitude et l’angle à la phase).\
Par conséquent, pour identifier la FM, vous devriez **voir essentiellement un cercle** sur ce graphique.\
De plus, un décalage de fréquence modifie la vitesse de rotation autour du cercle IQ. Dans SigDigger, un changement de vitesse ou de sens de rotation peut donc indiquer une FM :

![Graphique IQ de SigDigger où la FM apparaît sous forme de changements d’accélération autour du cercle](<../../images/image (81).png>)

### Déterminer le débit symbole

Vous pouvez utiliser **la même méthode que dans l’exemple AM** pour déterminer le débit symbole une fois que vous avez trouvé les fréquences qui portent les symboles.

### Extraire les bits

Vous pouvez utiliser **la même méthode que dans l’exemple AM** pour extraire les bits une fois que vous avez **déterminé que le signal est modulé en fréquence** et trouvé le **débit symbole**.

## References

- [1] [SigDigger - Analyseur gratuit de signaux numériques pour GNU/Linux et macOS](https://github.com/BatchDrake/SigDigger)
{{#include ../../banners/hacktricks-training.md}}
