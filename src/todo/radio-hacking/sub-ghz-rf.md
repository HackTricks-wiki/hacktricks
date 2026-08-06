# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Portes de garage

Les ouvre-portes de garage fonctionnent généralement sur des fréquences comprises entre 190 et 300 MHz, les fréquences les plus courantes étant 300 MHz, 310 MHz, 315 MHz et 390 MHz. Cette plage de fréquences est couramment utilisée pour les ouvre-portes de garage, car elle est moins encombrée que d'autres bandes de fréquences et est moins susceptible de subir des interférences provenant d'autres appareils.

## Portes de voiture

La plupart des télécommandes de voiture fonctionnent soit à **315 MHz, soit à 433 MHz**. Il s'agit dans les deux cas de radiofréquences utilisées dans diverses applications. La principale différence entre ces deux fréquences est que 433 MHz offre une portée supérieure à 315 MHz. Cela signifie que 433 MHz est mieux adaptée aux applications nécessitant une portée plus importante, comme l'accès sans clé à distance.\
En Europe, 433,92 MHz est couramment utilisée, tandis qu'aux États-Unis et au Japon, c'est la fréquence de 315 MHz.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

Au lieu d'envoyer chaque code 5 fois (il est envoyé ainsi pour s'assurer que le récepteur le reçoit), si vous l'envoyez une seule fois, le temps est réduit à 6 minutes :

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

et si vous **supprimez la période d'attente de 2 ms** entre les signaux, vous pouvez **réduire le temps à 3 minutes.**

De plus, en utilisant la séquence de De Bruijn (une méthode permettant de réduire le nombre de bits nécessaires pour envoyer tous les nombres binaires potentiels à bruteforce), ce **temps est réduit à seulement 8 secondes** :<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

Un exemple de cette attaque a été implémenté dans [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

L'exigence d'un **préambule empêchera l'optimisation par séquence de De Bruijn**, et les **rolling codes empêcheront cette attaque** (à condition que le code soit suffisamment long pour ne pas être bruteforceable).

## Sub-GHz Attack

Pour attaquer ces signaux avec Flipper Zero, consultez :


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Protection par Rolling Codes

Les ouvre-portes de garage automatiques utilisent généralement une télécommande sans fil pour ouvrir et fermer la porte du garage. La télécommande **envoie un signal radiofréquence (RF)** à l'ouvre-porte de garage, qui active le moteur pour ouvrir ou fermer la porte.

Il est possible qu'une personne utilise un appareil appelé code grabber pour intercepter le signal RF et l'enregistrer afin de le réutiliser ultérieurement. C'est ce que l'on appelle une **replay attack**. Pour empêcher ce type d'attaque, de nombreux ouvre-portes de garage modernes utilisent une méthode de chiffrement plus sécurisée, connue sous le nom de système à **rolling code**.

Le **signal RF est généralement transmis à l'aide d'un rolling code**, ce qui signifie que le code change à chaque utilisation. Il devient ainsi **difficile** pour une personne d'**intercepter** le signal et de l'**utiliser** pour obtenir un accès **non autorisé** au garage.

Dans un système à rolling code, la télécommande et l'ouvre-porte de garage possèdent un **algorithme partagé** qui **génère un nouveau code** chaque fois que la télécommande est utilisée. L'ouvre-porte de garage ne répondra qu'au **code correct**, ce qui rend beaucoup plus difficile l'obtention d'un accès non autorisé au garage par la simple capture d'un code.

### **Missing Link Attack**

En résumé, vous écoutez l'appui sur le bouton et **capturez le signal alors que la télécommande est hors de portée** de l'appareil (par exemple la voiture ou le garage). Vous vous déplacez ensuite jusqu'à l'appareil et **utilisez le code capturé pour l'ouvrir**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

Un attaquant peut **brouiller le signal à proximité du véhicule ou du récepteu**r afin que le **récepteur ne puisse pas réellement « entendre » le code**. Une fois cela fait, il peut simplement **capturer et rejouer** le code après avoir cessé le brouillage.<sup>[[2]](#references)</sup>

À un moment donné, la victime utilisera les **clés pour verrouiller la voiture**, mais l'attaque aura alors **enregistré suffisamment de codes de « fermeture de porte »** pour pouvoir, avec un peu de chance, les renvoyer afin d'ouvrir la porte (un **changement de fréquence peut être nécessaire**, car certaines voitures utilisent les mêmes codes pour ouvrir et fermer, mais écoutent les deux commandes sur des fréquences différentes).

> [!WARNING]
> Le **brouillage fonctionne**, mais il est détectable : si la **personne qui verrouille la voiture teste simplement les portes** pour s'assurer qu'elles sont verrouillées, elle remarquera que la voiture est déverrouillée. De plus, si elle est informée de l'existence de telles attaques, elle peut remarquer que les portes n'ont jamais émis le **son** du verrouillage ou que les **feux** de la voiture n'ont jamais clignoté lorsqu'elle a appuyé sur le bouton « verrouiller ».

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Il s'agit d'une **technique de Jamming plus furtive**. L'attaquant brouille le signal, de sorte que lorsque la victime essaie de verrouiller la porte, cela ne fonctionne pas, mais l'attaquant **enregistre ce code**. La victime essaie alors **à nouveau de verrouiller la voiture** en appuyant sur le bouton, et la voiture **enregistre ce second code**.<sup>[[2]](#references)[[4]](#references)</sup>\
Immédiatement après, l'**attaquant peut envoyer le premier code** et la **voiture se verrouillera** (la victime pensera que la seconde pression a verrouillé la voiture). L'attaquant pourra ensuite **envoyer le second code volé pour ouvrir** la voiture (en supposant qu'un **code de « fermeture de la voiture » puisse également être utilisé pour l'ouvrir**). Un changement de fréquence peut être nécessaire (car certaines voitures utilisent les mêmes codes pour ouvrir et fermer, mais écoutent les deux commandes sur des fréquences différentes).

L'attaquant peut **brouiller le récepteur de la voiture sans brouiller son propre récepteur**, car si le récepteur de la voiture écoute, par exemple, une bande large de 1 MHz, l'attaquant ne **brouillera** pas la fréquence exacte utilisée par la télécommande, mais **une fréquence proche dans ce spectre**, tandis que le **récepteur de l'attaquant écoutera une plage plus étroite**, dans laquelle il pourra écouter le signal de la télécommande **sans le signal de brouillage**.

> [!WARNING]
> D'autres implémentations décrites dans des spécifications montrent que le **rolling code ne constitue qu'une partie** du code total envoyé. Par exemple, le code envoyé est une **clé de 24 bits** dont les premiers **12 bits sont le rolling code**, les **8 suivants correspondent à la commande** (verrouillage ou déverrouillage, par exemple) et les 4 derniers constituent la **checksum**. Les véhicules qui implémentent ce type de système sont également naturellement vulnérables, car l'attaquant doit simplement remplacer le segment du rolling code pour pouvoir **utiliser n'importe quel rolling code sur les deux fréquences**.

> [!CAUTION]
> Notez que si la victime envoie un troisième code pendant que l'attaquant envoie le premier, les premier et deuxième codes seront invalidés.

### Alarm Sounding Jamming Attack

Lors de tests effectués sur un système à rolling code installé ultérieurement sur une voiture, **l'envoi immédiat du même code deux fois** a **activé l'alarme** et l'antidémarrage, offrant une opportunité unique de **denial of service**. Ironiquement, le moyen de **désactiver l'alarme** et l'antidémarrage consistait à **appuyer** sur la **télécommande**, ce qui permettait à un attaquant d'effectuer continuellement une **attaque DoS**. Il est également possible de combiner cette attaque avec la **précédente afin d'obtenir davantage de codes**, car la victime voudra mettre fin à l'attaque le plus rapidement possible.<sup>[[2]](#references)</sup>

## Références

- [1] [What Radio Frequency Does Car Key Fobs Run On?](https://www.americanradioarchives.com/what-radio-frequency-do-car-key-fobs-run-on/)
- [2] [Bypassing Rolling Code Systems - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23: Drive It Like You Hacked It (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [How To Hack A Car - RollJam recreation with YARD Stick One / RTL-SDR](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{{#include ../../banners/hacktricks-training.md}}
