# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Portes de garage

Les ouvre-portes de garage fonctionnent généralement sur des fréquences comprises entre 190 et 300 MHz, les fréquences les plus courantes étant 300 MHz, 310 MHz, 315 MHz et 390 MHz. Cette plage de fréquences est couramment utilisée pour les ouvre-portes de garage, car elle est moins encombrée que d'autres bandes de fréquences et est moins susceptible de subir des interférences provenant d'autres appareils.

## Portes de voiture

La plupart des télécommandes de clés de voiture fonctionnent soit à **315 MHz, soit à 433 MHz**. Ce sont toutes deux des fréquences radio utilisées dans diverses applications. La principale différence entre ces deux fréquences est que 433 MHz offre une portée supérieure à 315 MHz. Cela signifie que 433 MHz est plus adaptée aux applications nécessitant une plus grande portée, comme l'ouverture sans clé à distance.\
En Europe, la fréquence 433,92 MHz est couramment utilisée, tandis qu'aux États-Unis et au Japon, c'est la fréquence 315 MHz.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

Au lieu d'envoyer chaque code 5 fois (ce qui est fait pour s'assurer que le récepteur le reçoit), si on l'envoie une seule fois, le temps est réduit à 6 minutes :

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

et si vous **supprimez la période d'attente de 2 ms** entre les signaux, vous pouvez **réduire la durée à 3 minutes.**

De plus, en utilisant la De Bruijn Sequence (une méthode permettant de réduire le nombre de bits nécessaires pour envoyer tous les nombres binaires potentiels afin d'effectuer un brute-force), ce **temps est réduit à seulement 8 secondes** :

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

Un exemple de cette attaque a été implémenté dans [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)<sup>[[3]](#references)</sup>

L'utilisation obligatoire d'un **préambule empêchera l'optimisation par De Bruijn Sequence** et les **rolling codes empêcheront cette attaque** (en supposant que le code soit suffisamment long pour ne pas pouvoir être bruteforcé).

## Attaque Sub-GHz

Pour attaquer ces signaux avec Flipper Zero, consultez :


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Protection par Rolling Codes

Les ouvre-portes de garage automatiques utilisent généralement une télécommande sans fil pour ouvrir et fermer la porte du garage. La télécommande **envoie un signal de radiofréquence (RF)** à l'ouvre-porte de garage, qui active le moteur pour ouvrir ou fermer la porte.

Il est possible qu'une personne utilise un appareil appelé code grabber pour intercepter le signal RF et l'enregistrer afin de le réutiliser ultérieurement. C'est ce qu'on appelle une **replay attack**. Pour empêcher ce type d'attaque, de nombreux ouvre-portes de garage modernes utilisent une méthode de chiffrement plus sécurisée appelée système de **rolling code**.

Le **signal RF est généralement transmis à l'aide d'un rolling code**, ce qui signifie que le code change à chaque utilisation. Il devient ainsi **difficile** pour quelqu'un d'**intercepter** le signal et de l'**utiliser** pour obtenir un accès **non autorisé** au garage.

Dans un système de rolling code, la télécommande et l'ouvre-porte de garage possèdent un **algorithme partagé** qui **génère un nouveau code** chaque fois que la télécommande est utilisée. L'ouvre-porte de garage ne répondra qu'au **code correct**, ce qui rend beaucoup plus difficile l'accès non autorisé au garage par simple capture d'un code.

### **Missing Link Attack**

En résumé, vous écoutez l'appui sur le bouton et **capturez le signal alors que la télécommande est hors de portée** de l'appareil (par exemple, la voiture ou le garage). Vous vous rendez ensuite auprès de l'appareil et **utilisez le code capturé pour l'ouvrir**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

Un attaquant pourrait **brouiller le signal à proximité du véhicule ou du récepteu**r afin que le **récepteur ne puisse effectivement pas « entendre » le code**. Une fois cela fait, il peut simplement **capturer et rejouer** le code après avoir cessé le brouillage.

À un moment donné, la victime utilisera les **clés pour verrouiller la voiture**, mais l'attaquant aura alors **enregistré suffisamment de codes de « fermeture de porte »** pour pouvoir, avec un peu de chance, les renvoyer afin d'ouvrir la porte (un **changement de fréquence peut être nécessaire**, car certaines voitures utilisent les mêmes codes pour ouvrir et fermer, mais écoutent les deux commandes sur des fréquences différentes).

> [!WARNING]
> **Le brouillage fonctionne**, mais il est visible : si la **personne qui verrouille la voiture vérifie simplement les portes** pour s'assurer qu'elles sont verrouillées, elle remarquera que la voiture est déverrouillée. De plus, si elle connaissait ce type d'attaque, elle pourrait même remarquer que les portes n'ont jamais émis le **son** de verrouillage ou que les **feux** de la voiture n'ont jamais clignoté lorsqu'elle a appuyé sur le bouton « verrouiller ».

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Il s'agit d'une **technique de Jamming plus furtive**. L'attaquant brouille le signal : lorsque la victime essaie de verrouiller la porte, cela ne fonctionne pas, mais l'attaquant **enregistre ce code**. La victime essaie ensuite **à nouveau de verrouiller la voiture** en appuyant sur le bouton, et la voiture **enregistre ce second code**.\
Immédiatement après, l'**attaquant peut envoyer le premier code** et la **voiture se verrouille** (la victime pensera que la seconde pression a permis de la verrouiller). L'attaquant pourra ensuite **envoyer le second code volé pour ouvrir** la voiture (en supposant qu'un **code de « fermeture de voiture » puisse également être utilisé pour l'ouvrir**). Un changement de fréquence peut être nécessaire (car certaines voitures utilisent les mêmes codes pour ouvrir et fermer, mais écoutent les deux commandes sur des fréquences différentes).<sup>[[3]](#references)[[2]](#references)</sup>

L'attaquant peut **brouiller le récepteur de la voiture, mais pas son propre récepteur**, car si le récepteur de la voiture écoute, par exemple, une bande large de 1 MHz, l'attaquant ne **brouillera** pas la fréquence exacte utilisée par la télécommande, mais **une fréquence proche dans ce spectre**, tandis que le **récepteur de l'attaquant écoutera une plage plus étroite** dans laquelle il pourra écouter le signal de la télécommande **sans le signal de brouillage**.

> [!WARNING]
> D'autres implémentations observées dans les spécifications montrent que le **rolling code ne constitue qu'une portion** du code total envoyé. Par exemple, le code envoyé est une **clé de 24 bits** dont les premiers **12 bits constituent le rolling code**, les **8 suivants la commande** (telle que verrouiller ou déverrouiller) et les 4 derniers le **checksum**. Les véhicules implémentant ce type de système sont également naturellement vulnérables, car l'attaquant doit simplement remplacer le segment du rolling code pour pouvoir **utiliser n'importe quel rolling code sur les deux fréquences**.

> [!CAUTION]
> Notez que si la victime envoie un troisième code pendant que l'attaquant envoie le premier, les premier et deuxième codes seront invalidés.

### Alarm Sounding Jamming Attack

Lors d'un test sur un système de rolling code installé après-vente sur une voiture, **envoyer deux fois le même code** a immédiatement **activé l'alarme** et l'antidémarrage, offrant une opportunité unique de **denial of service**. Ironiquement, le moyen de **désactiver l'alarme** et l'antidémarrage consistait à **appuyer** sur la **télécommande**, ce qui permettait à un attaquant d'effectuer **continuellement une attaque DoS**. Il est également possible de combiner cette attaque avec la **précédente afin d'obtenir davantage de codes**, car la victime cherchera à arrêter l'attaque au plus vite.<sup>[[2]](#references)</sup>

## Références

- [1] [What Radio Frequency Does Car Key Fobs Run On?](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
- [2] [Bypassing Rolling Code Systems](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Drive It Like You Hacked It (DEF CON 23) - OpenSesame / RollJam](https://samy.pl/defcon2015/)
- [4] [How to hack a car (RollJam recreation)](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{{#include ../../banners/hacktricks-training.md}}
