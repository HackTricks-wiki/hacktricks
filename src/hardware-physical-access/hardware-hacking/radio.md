# Radio

{{#include ../../banners/hacktricks-training.md}}

## SigDigger

[**SigDigger**](https://github.com/BatchDrake/SigDigger) est un analyseur de signaux numériques gratuit pour GNU/Linux et macOS, conçu pour extraire des informations de signaux radio inconnus. Il prend en charge les appareils SDR via SoapySDR et fournit des outils de démodulation et d'analyse en temps réel pour les signaux FSK, PSK, ASK, la vidéo analogique, les signaux en rafales et les canaux vocaux analogiques.<sup>[[1]](#references)</sup>

### Configuration de base

Après l’installation, vous pouvez envisager de configurer quelques éléments.\
Dans les paramètres (le deuxième bouton d’onglet), sélectionnez un **appareil SDR** ou un fichier d’entrée, la fréquence à syntoniser et la fréquence d’échantillonnage. Une fréquence pouvant atteindre 2.56 Msps peut être pratique si l’ordinateur hôte le permet.

![Paramètres de SigDigger affichant les options d’appareil SDR, de fichier d’entrée, de fréquence et de fréquence d’échantillonnage](<../../images/image (245).png>)

Dans le comportement de l’interface graphique, il est recommandé d’activer quelques options si votre PC les prend en charge :

![SigDigger - Configuration de base : dans le comportement de l’interface graphique, il est recommandé d’activer quelques options si votre PC les prend en charge](<../../images/image (472).png>)

> [!TIP]
> Si vous constatez que votre PC ne capture rien, essayez de désactiver OpenGL et de réduire la fréquence d’échantillonnage.

### Utilisations

- Pour **capturer un signal pendant un certain temps et l’analyser**, maintenez simplement le bouton « Push to capture » enfoncé aussi longtemps que nécessaire.

![Configuration de base - Utilisations : pour capturer un signal pendant un certain temps et l’analyser, maintenez simplement le bouton « Push to capture » enfoncé aussi longtemps que nécessaire](<../../images/image (960).png>)

- Le **Tuner** de SigDigger aide à **mieux capturer les signaux** (mais peut aussi les dégrader). Idéalement, commencez à 0 et **augmentez progressivement** jusqu’à ce que le **bruit** introduit soit **plus important** que l’amélioration du signal recherchée.

![Commande Tuner de SigDigger réglée pour améliorer le signal radio capturé](<../../images/image (1099).png>)

### Synchronisation avec un canal radio

Avec [**SigDigger** ](https://github.com/BatchDrake/SigDigger), synchronisez-vous avec le canal que vous souhaitez écouter, configurez l’option « Baseband audio preview », réglez la largeur de bande pour obtenir toutes les informations transmises, puis réglez le Tuner au niveau précédant l’augmentation marquée du bruit :<sup>[[1]](#references)</sup>

![Canal radio synchronisé dans SigDigger, avec l’aperçu audio en bande de base et la largeur de bande configurés](<../../images/image (585).png>)

## Astuces intéressantes

- Lorsqu’un appareil transmet des rafales d’informations, **la première partie est généralement un préambule**. Vous n’avez donc **pas** à vous **inquiéter** si vous n’y trouvez **aucune information** ou si vous y observez **des erreurs**.
- Dans les trames d’informations, vous devriez généralement **trouver différentes trames bien alignées entre elles** :

![Synchronisation avec un canal radio - Astuces intéressantes : dans les trames d’informations, vous devriez généralement trouver différentes trames bien alignées entre elles](<../../images/image (1076).png>)

![Synchronisation avec un canal radio - Astuces intéressantes : dans les trames d’informations, vous devriez généralement trouver différentes trames bien alignées entre elles](<../../images/image (597).png>)

- **Après avoir récupéré les transitions de niveau, vous devrez peut-être les décoder.** En codage Manchester, une direction de transition représente `0` et la direction opposée représente `1` ; la polarité exacte dépend de la convention utilisée.
- Un préambule peut contenir une suite de niveaux échantillonnés identiques, même si la charge utile utilise un codage Manchester. Repérez donc le début de la trame avant de la décoder.

### Déterminer le type de modulation avec IQ

Il existe 3 façons de stocker des informations dans des signaux : moduler l’**amplitude**, la **fréquence** ou la **phase**.\
Pour déterminer ce qui est utilisé pour stocker les informations d’un signal, il existe plusieurs méthodes (d’autres sont présentées ci-dessous), mais consulter le graphique IQ est une bonne approche.

![Graphique IQ de SigDigger utilisé pour déterminer si un signal utilise une modulation d’amplitude, de fréquence ou de phase](<../../images/image (788).png>)

- **Détection de l’AM** : si le graphique IQ affiche, par exemple, **2 cercles** (probablement l’un en 0 et l’autre à une amplitude différente), il pourrait s’agir d’un signal AM. En effet, sur le graphique IQ, la distance entre le point 0 et le cercle correspond à l’amplitude du signal ; il est donc facile de visualiser les différentes amplitudes utilisées.
- **Détection de la PM** : comme dans l’image précédente, si vous trouvez de petits cercles qui ne sont pas liés entre eux, une modulation de phase est probablement utilisée. Sur le graphique IQ, l’angle entre le point et le point 0,0 correspond à la phase du signal ; cela signifie donc que 4 phases différentes sont utilisées.
  - Notez que si l’information réside dans le changement de phase, et non dans la phase elle-même, vous ne verrez pas de phases nettement différenciées.
- **Détection de la FM** : IQ ne comporte pas de champ permettant d’identifier les fréquences (la distance au centre correspond à l’amplitude et l’angle à la phase).\
  Par conséquent, pour identifier la FM, vous devriez **essentiellement voir un cercle** sur ce graphique.\
  De plus, un décalage de fréquence modifie la vitesse de rotation autour du cercle IQ. Dans SigDigger, un changement de vitesse ou de direction de rotation peut donc indiquer une FM.

## Exemple AM

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Déterminer l’AM

#### Examiner l’enveloppe

Lors de l’inspection de données AM avec [**SigDigger**](https://github.com/BatchDrake/SigDigger), l’**enveloppe** du signal peut révéler des niveaux d’amplitude distincts. Le signal d’exemple transmet des informations sous forme d’impulsions modulées en amplitude ; voici à quoi ressemble une impulsion :<sup>[[1]](#references)</sup>

![Enveloppe du signal AM dans SigDigger, avec des niveaux d’amplitude d’impulsion clairement définis](<../../images/image (590).png>)

Voici à quoi ressemble une partie du symbole avec la forme d’onde :

![Déterminer l’AM - Examiner l’enveloppe : voici à quoi ressemble une partie du symbole avec la forme d’onde](<../../images/image (734).png>)

#### Examiner l’histogramme

Vous pouvez **sélectionner toute la partie du signal** qui contient des informations, choisir le mode **Amplitude** et **Selection**, puis cliquer sur **Histogram**. Vous pouvez observer que seuls 2 niveaux distincts apparaissent.

![Histogramme d’amplitude de SigDigger montrant deux niveaux distincts pour le signal AM sélectionné](<../../images/image (264).png>)

Par exemple, si vous sélectionnez Frequency au lieu d’Amplitude pour ce signal AM, vous ne trouverez qu’une seule fréquence (une information modulée en fréquence ne peut pas utiliser une seule fréquence).

![Histogramme de fréquence de SigDigger pour le signal AM, montrant une seule fréquence](<../../images/image (732).png>)

Si vous trouvez de nombreuses fréquences, il ne s’agit probablement pas de FM ; la fréquence du signal a probablement simplement été modifiée par le canal.

#### Avec IQ

Dans cet exemple, vous pouvez voir un **grand cercle**, mais aussi **de nombreux points au centre**.

![Examiner l’histogramme - Avec IQ : dans cet exemple, on voit un grand cercle, mais aussi de nombreux points au centre](<../../images/image (222).png>)

### Déterminer le débit de symboles

#### Avec un seul symbole

Sélectionnez le plus petit intervalle contenant clairement un seul symbole, puis consultez **Selection freq**. Dans cet exemple, la valeur est de 1.013 kHz, soit environ 1 kHz.

![Déterminer le débit de symboles - Avec un seul symbole : sélectionnez le plus petit symbole identifiable (pour être sûr qu’il n’y en a qu’un) et consultez « Selection freq ». Ici, la valeur est de 1.013 kHz (soit 1 kHz).](<../../images/image (78).png>)

#### Avec un groupe de symboles

Vous pouvez également indiquer le nombre de symboles à sélectionner ; SigDigger calculera alors la fréquence d’un symbole (plus le nombre de symboles sélectionnés est élevé, plus le résultat sera probablement précis). Dans cet exemple, j’ai sélectionné 10 symboles et la valeur de « Selection freq » est de 1.004 kHz :

![Calcul du débit de symboles dans SigDigger à partir d’un groupe sélectionné de dix symboles](<../../images/image (1008).png>)

### Récupérer les bits

Après avoir identifié l’AM et estimé le **débit de symboles**, sélectionnez la région du signal, configurez l’échantillonnage d’amplitude et les niveaux de décision, choisissez **Gardner clock recovery**, puis cliquez sur **Sample** :

![Panneau Get Bits de SigDigger configuré pour l’échantillonnage AM, le débit de symboles et la récupération d’horloge Gardner](<../../images/image (965).png>)

- **Sync to selection intervals** signifie que si vous avez précédemment sélectionné des intervalles pour déterminer le débit de symboles, ce débit sera utilisé.
- **Manual** signifie que le débit de symboles indiqué sera utilisé.
- Dans **Fixed interval selection**, vous indiquez le nombre d’intervalles à sélectionner ; le débit de symboles sera calculé à partir de ce nombre.
- **Gardner clock recovery** est une option par défaut utile, mais elle nécessite tout de même un débit de symboles approximatif.

Après avoir cliqué sur Sample, voici ce qui apparaît :

![Avec un groupe de symboles - Récupérer les bits : voici ce qui apparaît après avoir cliqué sur Sample](<../../images/image (644).png>)

Maintenant, pour indiquer à SigDigger **où se trouve la plage** de niveaux contenant des informations, cliquez sur le **niveau inférieur** et gardez le bouton enfoncé jusqu’au niveau le plus élevé :

![Sélection de la plage de niveaux dans SigDigger, du niveau d’amplitude inférieur au niveau supérieur](<../../images/image (439).png>)

S’il y avait eu, par exemple, **4 niveaux d’amplitude différents**, il aurait fallu configurer **Bits per symbol** sur 2 et sélectionner la plage allant du niveau le plus bas au niveau le plus élevé.

Enfin, en **augmentant** le **Zoom** et en **modifiant la Row size**, vous pouvez voir les bits (vous pouvez tout sélectionner et copier pour récupérer tous les bits) :

![Avec un groupe de symboles - Récupérer les bits : enfin, en augmentant le Zoom et en modifiant la Row size, vous pouvez voir les bits (vous pouvez tout sélectionner et copier pour récupérer tous les bits)](<../../images/image (276).png>)

Si le signal contient plus d’un bit par symbole (par exemple, 2), SigDigger ne peut **pas savoir quel symbole correspond à** 00, 01, 10 ou 11. Il utilise donc différentes **nuances de gris** pour les représenter (et, si vous copiez les bits, il utilise des **chiffres de 0 à 3** qu’il vous faudra traiter).

Pour les codages de ligne comme **Manchester**, convertissez chaque paire de transitions valide (`01` ou `10`) en un bit de données selon la convention utilisée par le protocole.

## Exemple FM

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Déterminer la FM

#### Examiner les fréquences et la forme d’onde

Exemple de signal transmettant des informations modulées en FM :

![Déterminer la FM - Examiner les fréquences et la forme d’onde : exemple de signal transmettant des informations modulées en FM](<../../images/image (725).png>)

Le spectre montre clairement **deux fréquences**, même s’il peut être difficile de les distinguer sur la forme d’onde dans le domaine temporel :

![Forme d’onde FM dans SigDigger où les deux fréquences sont difficiles à distinguer directement](<../../images/image (717).png>)

Cela s’explique par le fait que la capture est centrée entre les deux fréquences ; leurs décalages de fréquence sont donc approximativement opposés :

![Capture FM dans SigDigger montrant les deux fréquences avec des décalages approximativement opposés](<../../images/image (942).png>)

Si la fréquence de synchronisation est **plus proche d’une fréquence que de l’autre**, vous pouvez facilement voir les 2 fréquences différentes :

![Déterminer la FM - Examiner les fréquences et la forme d’onde : si la fréquence de synchronisation est plus proche d’une fréquence que de l’autre, vous pouvez facilement voir les 2 fréquences différentes](<../../images/image (422).png>)

![Déterminer la FM - Examiner les fréquences et la forme d’onde : si la fréquence de synchronisation est plus proche d’une fréquence que de l’autre, vous pouvez facilement voir les 2 fréquences différentes](<../../images/image (488).png>)

#### Examiner l’histogramme

En examinant l’histogramme des fréquences du signal contenant des informations, vous pouvez facilement voir 2 signaux différents :

![Examiner les fréquences et la forme d’onde - Examiner l’histogramme : en examinant l’histogramme des fréquences du signal contenant des informations, vous pouvez facilement voir 2 signaux différents](<../../images/image (871).png>)

Dans ce cas, si vous examinez l’**histogramme d’amplitude**, vous ne trouverez **qu’une seule amplitude** ; il **ne peut donc pas s’agir d’AM** (si vous trouvez de nombreuses amplitudes, cela peut être dû à une perte de puissance du signal dans le canal) :

![Histogramme d’amplitude du signal FM dans SigDigger, montrant un seul niveau d’amplitude](<../../images/image (817).png>)

Voici l’histogramme de phase, qui montre clairement que le signal n’est pas modulé en phase :

![Examiner les fréquences et la forme d’onde - Examiner l’histogramme : voici l’histogramme de phase, qui montre clairement que le signal n’est pas modulé en phase](<../../images/image (996).png>)

#### Avec IQ

IQ ne comporte pas de champ permettant d’identifier les fréquences (la distance au centre correspond à l’amplitude et l’angle à la phase).\
Par conséquent, pour identifier la FM, vous devriez **essentiellement voir un cercle** sur ce graphique.\
De plus, un décalage de fréquence modifie la vitesse de rotation autour du cercle IQ. Dans SigDigger, un changement de vitesse ou de direction de rotation peut donc indiquer une FM :

![Graphique IQ de SigDigger où la FM apparaît sous la forme de changements de vitesse de rotation autour du cercle](<../../images/image (81).png>)

### Déterminer le débit de symboles

Une fois que vous avez trouvé les fréquences portant les symboles, vous pouvez utiliser **la même technique que dans l’exemple AM** pour déterminer le débit de symboles.

### Récupérer les bits

Une fois que vous avez **déterminé que le signal est modulé en fréquence** et identifié le **débit de symboles**, vous pouvez utiliser **la même technique que dans l’exemple AM** pour récupérer les bits.

## References

- [1] [SigDigger - Analyseur de signaux numériques gratuit pour GNU/Linux et macOS](https://github.com/BatchDrake/SigDigger)
{{#include ../../banners/hacktricks-training.md}}
