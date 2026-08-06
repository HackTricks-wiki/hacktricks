# Radio

{{#include ../../banners/hacktricks-training.md}}

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)est un analyseur de signaux numériques gratuit pour GNU/Linux et macOS, conçu pour extraire des informations de signaux radio inconnus. Il prend en charge divers appareils SDR via SoapySDR et permet la démodulation réglable des signaux FSK, PSK et ASK, le décodage de vidéos analogiques, l'analyse de signaux en rafales et l'écoute de canaux vocaux analogiques (le tout en temps réel).<sup>[[1]](#references)</sup>

### Basic Config

Après l'installation, quelques éléments peuvent être configurés.\
Dans les paramètres (le deuxième bouton d'onglet), vous pouvez sélectionner le **SDR device** ou **select a file** à lire, ainsi que la fréquence à syntoniser et le taux d'échantillonnage (il est recommandé d'utiliser jusqu'à 2.56Msps si votre PC le permet).

![Paramètres de SigDigger affichant les options de l'appareil SDR, du fichier d'entrée, de la fréquence et du taux d'échantillonnage](<../../images/image (245).png>)

Dans le comportement de l'interface graphique, il est recommandé d'activer quelques options si votre PC le permet :

![SigDigger - Basic Config : dans le comportement de l'interface graphique, il est recommandé d'activer quelques options si votre PC le permet](<../../images/image (472).png>)

> [!TIP]
> Si vous constatez que votre PC ne capture rien, essayez de désactiver OpenGL et de réduire le taux d'échantillonnage.

### Uses

- Pour **capturer un signal pendant un certain temps et l'analyser**, maintenez simplement le bouton "Push to capture" enfoncé aussi longtemps que nécessaire.

![Basic Config - Uses : pour capturer un signal pendant un certain temps et l'analyser, maintenez simplement le bouton "Push to capture" enfoncé aussi longtemps que nécessaire](<../../images/image (960).png>)

- Le **Tuner** de SigDigger aide à **mieux capturer les signaux** (mais peut également les dégrader). Idéalement, commencez à 0 et continuez à **augmenter la valeur jusqu'à** ce que le **bruit** introduit soit **supérieur à l'amélioration du signal** recherchée.

![Contrôle du tuner de SigDigger réglé pour améliorer le signal radio capturé](<../../images/image (1099).png>)

### Synchronize with radio channel

Avec [**SigDigger** ](https://github.com/BatchDrake/SigDigger), synchronisez-vous avec le canal que vous souhaitez écouter, configurez l'option "Baseband audio preview", configurez la bande passante pour obtenir toutes les informations transmises, puis réglez le Tuner juste avant que le bruit ne commence réellement à augmenter :<sup>[[1]](#references)</sup>

![Canal radio synchronisé dans SigDigger, avec aperçu audio de la bande de base et bande passante configurée](<../../images/image (585).png>)

## Interesting tricks

- Lorsqu'un appareil envoie des rafales d'informations, la **première partie est généralement un préambule**. Vous n'avez donc **pas besoin de vous inquiéter** si vous n'y **trouvez aucune information** ou si **quelques erreurs** y apparaissent.
- Dans les trames d'informations, vous devriez généralement **trouver différentes trames bien alignées entre elles** :

![Synchronize with radio channel - Interesting tricks : dans les trames d'informations, vous devriez généralement trouver différentes trames bien alignées entre elles](<../../images/image (1076).png>)

![Synchronize with radio channel - Interesting tricks : dans les trames d'informations, vous devriez généralement trouver différentes trames bien alignées entre elles](<../../images/image (597).png>)

- **Après avoir récupéré les bits, vous devrez peut-être les traiter d'une certaine manière**. Par exemple, dans le codage Manchester, une montée+descente correspondra à un 1 ou un 0, et une descente+montée correspondra à l'autre valeur. Ainsi, les paires de 1 et de 0 (montées et descentes) correspondront à un véritable 1 ou à un véritable 0.
- Même si un signal utilise le codage Manchester (il est impossible de trouver plus de deux 0 ou 1 consécutifs), vous pouvez **trouver plusieurs 1 ou 0 consécutifs dans le préambule** !

### Uncovering modulation type with IQ

Il existe trois façons de stocker des informations dans les signaux : moduler **l'amplitude**, la **fréquence** ou la **phase**.\
Si vous examinez un signal, il existe différentes façons d'essayer de déterminer ce qui est utilisé pour stocker les informations (voir d'autres méthodes ci-dessous), mais une bonne approche consiste à examiner le graphique IQ.

![Graphique IQ de SigDigger utilisé pour déterminer si un signal utilise une modulation d'amplitude, de fréquence ou de phase](<../../images/image (788).png>)

- **Détecter l'AM** : si le graphique IQ affiche par exemple **2 cercles** (probablement un en 0 et l'autre à une amplitude différente), cela peut signifier qu'il s'agit d'un signal AM. En effet, sur le graphique IQ, la distance entre le point 0 et le cercle correspond à l'amplitude du signal ; il est donc facile de visualiser les différentes amplitudes utilisées.
- **Détecter la PM** : comme dans l'image précédente, si vous trouvez de petits cercles qui ne sont pas liés entre eux, cela signifie probablement qu'une modulation de phase est utilisée. En effet, sur le graphique IQ, l'angle entre le point et le point 0,0 correspond à la phase du signal, ce qui signifie que 4 phases différentes sont utilisées.
- Notez que si l'information est cachée dans le fait qu'une phase change et non dans la phase elle-même, vous ne verrez pas clairement les différentes phases.
- **Détecter la FM** : IQ ne dispose pas de champ permettant d'identifier les fréquences (la distance au centre correspond à l'amplitude et l'angle à la phase).\
Par conséquent, pour identifier la FM, vous devriez **voir essentiellement un seul cercle** sur ce graphique.\
De plus, une fréquence différente est « représentée » sur le graphique IQ par une **accélération de la vitesse le long du cercle** (ainsi, dans SysDigger, lorsque le signal est sélectionné, le graphique IQ est rempli ; si vous trouvez une accélération ou un changement de direction dans le cercle créé, cela peut indiquer qu'il s'agit de FM) :

## AM Example

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Uncovering AM

#### Checking the envelope

Pour examiner les informations AM avec [**SigDigger** ](https://github.com/BatchDrake/SigDigger), il suffit d'observer l'**enveloppe** pour voir différents niveaux d'amplitude clairement définis. Le signal utilisé envoie des impulsions contenant des informations en AM. Voici à quoi ressemble une impulsion :<sup>[[1]](#references)</sup>

![Enveloppe du signal AM dans SigDigger, avec des niveaux d'amplitude d'impulsion clairement définis](<../../images/image (590).png>)

Voici à quoi ressemble une partie du symbole avec la forme d'onde :

![Uncovering AM - Checking the envelope : voici à quoi ressemble une partie du symbole avec la forme d'onde](<../../images/image (734).png>)

#### Checking the Histogram

Vous pouvez **sélectionner l'intégralité du signal** contenant les informations, sélectionner le mode **Amplitude**, puis **Selection**, et cliquer sur **Histogram.** Vous pouvez observer que seuls 2 niveaux clairement définis sont présents.

![Histogramme d'amplitude de SigDigger affichant deux niveaux clairement définis pour le signal AM sélectionné](<../../images/image (264).png>)

Par exemple, si vous sélectionnez Frequency au lieu de Amplitude dans ce signal AM, vous ne trouverez qu'une seule fréquence (il est impossible qu'une information modulée en fréquence n'utilise qu'une seule fréquence).

![Histogramme de fréquence de SigDigger pour le signal AM, affichant une seule fréquence](<../../images/image (732).png>)

Si vous trouvez beaucoup de fréquences, il ne s'agit potentiellement pas de FM ; la fréquence du signal a probablement simplement été modifiée par le canal.

#### With IQ

Dans cet exemple, vous pouvez voir un **grand cercle**, mais également **beaucoup de points au centre**.

![Checking the Histogram - With IQ : dans cet exemple, vous pouvez voir un grand cercle, mais également beaucoup de points au centre](<../../images/image (222).png>)

### Get Symbol Rate

#### With one symbol

Sélectionnez le plus petit symbole que vous pouvez trouver (afin d'être certain qu'il ne s'agit que d'un seul symbole) et vérifiez la "Selection freq". Dans ce cas, elle serait de 1.013 kHz (donc 1 kHz).

![Get Symbol Rate - With one symbol : sélectionnez le plus petit symbole que vous pouvez trouver (afin d'être certain qu'il ne s'agit que d'un seul symbole) et vérifiez la "Selection freq". Dans ce cas, elle serait de 1.013 kHz (donc 1 kHz)](<../../images/image (78).png>)

#### With a group of symbols

Vous pouvez également indiquer le nombre de symboles que vous allez sélectionner, et SigDigger calculera la fréquence d'un symbole (plus le nombre de symboles sélectionnés est élevé, meilleur sera probablement le résultat). Dans ce scénario, j'ai sélectionné 10 symboles et la "Selection freq" est de 1.004 kHz :

![Calcul du débit de symboles par SigDigger à partir d'un groupe sélectionné de dix symboles](<../../images/image (1008).png>)

### Get Bits

Après avoir déterminé qu'il s'agit d'un signal **modulé en AM** et trouvé le **débit de symboles** (et sachant que, dans ce cas, une montée correspond à 1 et une descente à 0), il est très facile d'**obtenir les bits** encodés dans le signal. Sélectionnez donc le signal contenant les informations, configurez l'échantillonnage et la décision, puis appuyez sur sample (vérifiez que **Amplitude** est sélectionné, que le **Symbol rate** découvert est configuré et que **Gadner clock recovery** est sélectionné) :

![Panneau Get Bits de SigDigger configuré pour l'échantillonnage AM, le débit de symboles et la récupération d'horloge Gardner](<../../images/image (965).png>)

- **Sync to selection intervals** signifie que si vous avez précédemment sélectionné des intervalles pour trouver le débit de symboles, ce débit sera utilisé.
- **Manual** signifie que le débit de symboles indiqué sera utilisé.
- Dans **Fixed interval selection**, vous indiquez le nombre d'intervalles à sélectionner et le débit de symboles est calculé à partir de cette valeur.
- **Gadner clock recovery** est généralement la meilleure option, mais vous devez tout de même indiquer un débit de symboles approximatif.

Après avoir appuyé sur sample, ceci apparaît :

![With a group of symbols - Get Bits : ceci apparaît après avoir appuyé sur sample](<../../images/image (644).png>)

Maintenant, pour que SigDigger comprenne **où se trouve la plage** du niveau contenant les informations, vous devez cliquer sur le **niveau inférieur** et maintenir le bouton enfoncé jusqu'au niveau le plus élevé :

![Sélection de la plage de niveaux de SigDigger, du niveau d'amplitude inférieur au niveau supérieur](<../../images/image (439).png>)

S'il y avait eu, par exemple, **4 niveaux d'amplitude différents**, vous auriez dû configurer **Bits per symbol sur 2** et effectuer une sélection du niveau le plus faible au niveau le plus élevé.

Enfin, en **augmentant** le **Zoom** et en **modifiant la Row size**, vous pouvez voir les bits (et tout sélectionner puis copier pour obtenir tous les bits) :

![With a group of symbols - Get Bits : enfin, en augmentant le Zoom et en modifiant la Row size, vous pouvez voir les bits (et tout sélectionner puis copier pour obtenir tous les bits)](<../../images/image (276).png>)

Si le signal contient plus d'un bit par symbole (par exemple 2), SigDigger ne peut pas savoir quel symbole correspond à 00, 01, 10 ou 11. Il utilisera donc différentes **échelles de gris** pour représenter chacun d'eux (et, si vous copiez les bits, il utilisera des **nombres de 0 à 3** ; vous devrez les traiter).

Utilisez également des **codages** tels que **Manchester** : une montée+descente peut correspondre à 1 ou 0, et une descente+montée peut correspondre à 1 ou 0. Dans ces cas, vous devez **traiter les montées (1) et les descentes (0)** obtenues afin de remplacer les paires 01 ou 10 par des 0 ou des 1.

## FM Example

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Uncovering FM

#### Checking the frequencies and waveform

Exemple de signal envoyant des informations modulées en FM :

![Uncovering FM - Checking the frequencies and waveform : exemple de signal envoyant des informations modulées en FM](<../../images/image (725).png>)

Dans l'image précédente, vous pouvez constater assez clairement que **2 fréquences sont utilisées**, mais si vous **observez** la **forme d'onde**, vous ne pourrez peut-être **pas identifier correctement les 2 fréquences différentes** :

![Forme d'onde FM de SigDigger, où les deux fréquences sont difficiles à distinguer directement](<../../images/image (717).png>)

Cela s'explique par le fait que j'ai capturé le signal sur les deux fréquences ; l'une est donc approximativement l'opposée de l'autre :

![Capture FM de SigDigger montrant les deux fréquences comme approximativement opposées l'une à l'autre](<../../images/image (942).png>)

Si la fréquence synchronisée est **plus proche d'une fréquence que de l'autre**, vous pouvez facilement voir les 2 fréquences différentes :

![Uncovering FM - Checking the frequencies and waveform : si la fréquence synchronisée est plus proche d'une fréquence que de l'autre, vous pouvez facilement voir les 2 fréquences différentes](<../../images/image (422).png>)

![Uncovering FM - Checking the frequencies and waveform : si la fréquence synchronisée est plus proche d'une fréquence que de l'autre, vous pouvez facilement voir les 2 fréquences différentes](<../../images/image (488).png>)

#### Checking the histogram

En examinant l'histogramme des fréquences du signal contenant les informations, vous pouvez facilement voir 2 signaux différents :

![Checking the frequencies and waveform - Checking the histogram : en examinant l'histogramme des fréquences du signal contenant les informations, vous pouvez facilement voir 2 signaux différents](<../../images/image (871).png>)

Dans ce cas, si vous examinez l'**histogramme d'amplitude**, vous ne trouverez **qu'une seule amplitude** ; il **ne peut donc pas s'agir d'AM** (si vous trouvez beaucoup d'amplitudes, cela peut être dû au fait que le signal a perdu de la puissance le long du canal) :

![Histogramme d'amplitude de SigDigger pour un signal FM, affichant un seul niveau d'amplitude](<../../images/image (817).png>)

Voici l'histogramme de phase (qui montre très clairement que le signal n'est pas modulé en phase) :

![Checking the frequencies and waveform - Checking the histogram : histogramme de phase montrant très clairement que le signal n'est pas modulé en phase](<../../images/image (996).png>)

#### With IQ

IQ ne dispose pas de champ permettant d'identifier les fréquences (la distance au centre correspond à l'amplitude et l'angle à la phase).\
Par conséquent, pour identifier la FM, vous devriez **voir essentiellement un seul cercle** sur ce graphique.\
De plus, une fréquence différente est « représentée » sur le graphique IQ par une **accélération de la vitesse le long du cercle** (ainsi, dans SysDigger, lorsque le signal est sélectionné, le graphique IQ est rempli ; si vous trouvez une accélération ou un changement de direction dans le cercle créé, cela peut indiquer qu'il s'agit de FM) :

![Graphique IQ de SigDigger où la FM apparaît comme des changements d'accélération autour du cercle](<../../images/image (81).png>)

### Get Symbol Rate

Vous pouvez utiliser **la même technique que celle utilisée dans l'exemple AM** pour obtenir le débit de symboles une fois que vous avez trouvé les fréquences transportant les symboles.

### Get Bits

Vous pouvez utiliser **la même technique que celle utilisée dans l'exemple AM** pour obtenir les bits une fois que vous avez **déterminé que le signal est modulé en fréquence** et trouvé le **débit de symboles**.

## References

- [1] [SigDigger - Free digital signal analyzer for GNU/Linux and macOS](https://github.com/BatchDrake/SigDigger)

{{#include ../../banners/hacktricks-training.md}}
