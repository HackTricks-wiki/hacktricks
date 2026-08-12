# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Garage Doors

Les télécommandes de portes de garage utilisent plusieurs allocations sub-GHz spécifiques à chaque région et produit. Des fréquences telles que 300, 310, 315, 390 et 433,92 MHz sont utilisées, mais il n'existe pas de bande universelle « 300–190 MHz » pour les portes de garage. Identifiez l'étiquette de la cible, la région réglementaire et le signal observé avant toute transmission.<sup>[[1]](#references)</sup>

## Car Doors

De nombreux porte-clés de voiture utilisent **315 MHz ou 433,92 MHz**, les réglementations régionales et la conception du véhicule influençant le choix. La fréquence seule ne rend pas le 433 MHz plus longue portée que le 315 MHz : la puissance d'émission, l'efficacité de l'antenne, la modulation, la sensibilité du récepteur, la propagation et les réglementations locales sont également déterminantes. L'Europe utilise couramment 433,92 MHz, tandis que le 315 MHz est courant en Amérique du Nord et au Japon.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

Dans le système à code fixe présenté, envoyer chaque code une seule fois au lieu de cinq réduit le temps estimé à six minutes :

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

Supprimer l'attente de 2 ms entre les signaux réduit cette démonstration à environ trois minutes.

L'utilisation d'une séquence de De Bruijn pour faire se chevaucher les chaînes de bits candidates réduit l'attaque présentée à environ huit secondes lorsque le récepteur accepte la séquence continue sans préambule requis ni réinitialisation de trame.<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

OpenSesame implémente cette attaque contre les systèmes à code fixe compatibles.<sup>[[5]](#references)</sup>

Exiger **un préambule évitera l'optimisation De Bruijn Sequence** et **les rolling codes empêcheront cette attaque** (en supposant que le code soit suffisamment long pour ne pas être bruteforceable).

## Sub-GHz Attack

Pour attaquer ces signaux avec Flipper Zero, consultez :


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Codes Protection

Les ouvre-portes de garage automatiques utilisent généralement une télécommande sans fil pour ouvrir et fermer la porte du garage. La télécommande **envoie un signal de radiofréquence (RF)** à l'ouvre-porte de garage, qui active le moteur pour ouvrir ou fermer la porte.

Il est possible d'utiliser un appareil appelé code grabber pour intercepter le signal RF et l'enregistrer afin de le réutiliser ultérieurement. C'est ce que l'on appelle une **replay attack**. Pour empêcher ce type d'attaque, de nombreux ouvre-portes de garage modernes utilisent une méthode de chiffrement plus sécurisée appelée système à **rolling code**.

Le **signal RF est généralement transmis avec un rolling code**, ce qui signifie que le code change à chaque utilisation. Cela rend **difficile** pour quelqu'un d'**intercepter** le signal et de l'**utiliser** pour obtenir un accès **non autorisé** au garage.

Dans un système à rolling code, la télécommande et l'ouvre-porte de garage disposent d'un **algorithme partagé** qui **génère un nouveau code** chaque fois que la télécommande est utilisée. L'ouvre-porte de garage ne répondra qu'au **code correct**, ce qui rend beaucoup plus difficile l'obtention d'un accès non autorisé au garage par la simple capture d'un code.

### **Missing Link Attack**

En résumé, vous écoutez l'appui sur le bouton et **capturez le signal alors que la télécommande est hors de portée** de l'appareil (par exemple la voiture ou le garage). Vous vous déplacez ensuite jusqu'à l'appareil et **utilisez le code capturé pour l'ouvrir**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

> [!CAUTION]
> Les interférences RF intentionnelles sont illégales dans de nombreuses juridictions et peuvent perturber des systèmes critiques pour la sécurité. N'effectuez des tests de jamming que dans un laboratoire autorisé et blindé, conformément aux réglementations radio applicables.<sup>[[6]](#references)</sup>

Un attaquant pourrait **brouiller le signal à proximité du véhicule ou du récepteur** afin que le récepteur ne puisse pas décoder le code, capturer séparément la transmission bloquée, arrêter le brouillage, puis rejouer le code capturé.<sup>[[2]](#references)</sup>

La victime finira par utiliser les **clés pour verrouiller la voiture**, mais l'attaque aura alors **enregistré suffisamment de codes de « fermeture de porte »** qui pourront, espérons-le, être renvoyés pour ouvrir la porte (un **changement de fréquence peut être nécessaire**, car certaines voitures utilisent les mêmes codes pour ouvrir et fermer, mais écoutent les deux commandes sur des fréquences différentes).

> [!WARNING]
> **Le jamming fonctionne**, mais il est visible : si la **personne qui verrouille la voiture vérifie simplement les portes** pour s'assurer qu'elles sont verrouillées, elle remarquera que la voiture est déverrouillée. De plus, si elle connaît ce type d'attaque, elle pourrait remarquer que les portes n'ont jamais émis le **son de verrouillage** ou que les **feux de la voiture** n'ont jamais clignoté lorsqu'elle a appuyé sur le bouton « lock ».

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Il s'agit d'une **technique de jamming plus furtive**. L'attaquant brouille le signal : lorsque la victime essaie de verrouiller la porte, cela ne fonctionne pas, mais l'attaquant **enregistre ce code**. La victime essaie ensuite **de verrouiller à nouveau la voiture** en appuyant sur le bouton, et la voiture **enregistre ce deuxième code**.<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>\
Immédiatement après, l'**attaquant peut envoyer le premier code** et la **voiture se verrouillera** (la victime pensera que la deuxième pression l'a verrouillée). L'attaquant pourra ensuite **envoyer le deuxième code volé pour ouvrir** la voiture (en supposant qu'un **code de « fermeture de la voiture » puisse également être utilisé pour l'ouvrir**). Un changement de fréquence peut être nécessaire (car certaines voitures utilisent les mêmes codes pour ouvrir et fermer, mais écoutent les deux commandes sur des fréquences différentes).

Une implémentation de RollJam exploite la largeur de bande du récepteur : le jammer émet suffisamment près de la porteuse de la télécommande pour désensibiliser le récepteur plus large du véhicule, tandis que le récepteur plus étroit de l'attaquant reste centré sur la télécommande et peut toujours l'enregistrer. Le décalage et la largeur de bande exacts dépendent du matériel ciblé.<sup>[[2]](#references)</sup>

> [!WARNING]
> D'autres implémentations observées dans des spécifications montrent que le **rolling code ne constitue qu'une partie** du code total envoyé. Par exemple, le code envoyé est une **clé de 24 bits** dont les premiers **12 bits constituent le rolling code**, les **8 suivants la commande** (telle que lock ou unlock) et les 4 derniers le **checksum**. Les véhicules qui implémentent ce type de système sont également naturellement vulnérables, car l'attaquant doit simplement remplacer le segment du rolling code pour pouvoir **utiliser n'importe quel rolling code sur les deux fréquences**.

> [!CAUTION]
> Notez que si la victime envoie un troisième code pendant que l'attaquant envoie le premier, les premier et deuxième codes seront invalidés.

### Alarm Sounding Jamming Attack

Lors de tests effectués sur un système à rolling code installé après-vente sur une voiture, **envoyer deux fois le même code** a immédiatement **activé l'alarme** et l'antidémarrage, offrant une possibilité unique de **denial of service**. Ironiquement, le moyen de **désactiver l'alarme** et l'antidémarrage consistait à **appuyer** sur la **télécommande**, donnant à un attaquant la possibilité d'effectuer **continuellement une attaque DoS**. Il est également possible de combiner cette attaque avec la **précédente pour obtenir davantage de codes**, car la victime cherchera à arrêter l'attaque au plus vite.<sup>[[2]](#references)</sup>

## References

- [1] [Documentation Flipper Zero - fréquences Sub-GHz régionales](https://docs.flipper.net/zero/sub-ghz/frequencies)
- [2] [Contourner les systèmes à rolling code - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23 : Drive It Like You Hacked It (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [Comment hacker une voiture - Reproduction de RollJam avec YARD Stick One / RTL-SDR](https://hackaday.io/project/164566-how-to-hack-a-car/details)
- [5] [Code source d'OpenSesame](https://github.com/samyk/opensesame)
- [6] [Avis d'application de la FCC - Application concernant les jammers](https://www.fcc.gov/document/jammer-enforcement)
{{#include ../../banners/hacktricks-training.md}}
