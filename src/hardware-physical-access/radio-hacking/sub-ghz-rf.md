# RF sub-GHz

{{#include ../../banners/hacktricks-training.md}}

## Portes de garage

Les télécommandes de portes de garage utilisent différentes bandes sub-GHz selon la région et le produit. On rencontre notamment les fréquences 300, 310, 315, 390 et 433,92 MHz, mais il n’existe pas de bande universelle « 300–190 MHz » pour les portes de garage. Avant toute émission, identifiez l’étiquette de la cible, la région réglementaire et le signal observé.<sup>[[1]](#references)</sup>

## Portes de voiture

De nombreuses clés électroniques de voiture utilisent **315 MHz ou 433,92 MHz** ; le choix dépend des règles régionales et de la conception du véhicule. La fréquence seule ne suffit pas à rendre le 433 MHz plus longue portée que le 315 MHz : la puissance d’émission, l’efficacité de l’antenne, la modulation, la sensibilité du récepteur, la propagation et les réglementations locales comptent également. En Europe, le 433,92 MHz est courant, tandis que le 315 MHz est fréquent en Amérique du Nord et au Japon.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

Dans le système à code fixe présenté, envoyer chaque code une seule fois au lieu de cinq réduit le temps estimé à six minutes :

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

La suppression de l’attente de 2 ms entre les signaux réduit cette démonstration à environ trois minutes.

L’utilisation d’une séquence de De Bruijn, qui fait se chevaucher les chaînes de bits candidates, ramène l’attaque présentée à environ huit secondes lorsque le récepteur accepte la séquence continue sans préambule requis ni réinitialisation de trame.<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

OpenSesame implémente cette attaque contre les systèmes à code fixe compatibles.<sup>[[5]](#references)</sup>

Un **préambule empêche l’optimisation par séquence de De Bruijn**, et les **rolling codes empêchent cette attaque** (à condition que le code soit suffisamment long pour ne pas pouvoir être bruteforcé).

## Attaque Sub-GHz

Pour attaquer ces signaux avec Flipper Zero, consultez :


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Protection par rolling codes

Les ouvre-portes de garage automatiques utilisent généralement une télécommande sans fil pour ouvrir et fermer la porte. La télécommande **envoie un signal radiofréquence (RF)** à l’ouvre-porte, qui active le moteur pour ouvrir ou fermer la porte.

Une personne peut utiliser un appareil appelé code grabber pour intercepter le signal RF et l’enregistrer en vue d’une utilisation ultérieure. C’est ce qu’on appelle une **replay attack**. Pour contrer ce type d’attaque, de nombreux ouvre-portes modernes utilisent une méthode de chiffrement plus sûre, appelée système à **rolling code**.

Le **signal RF est généralement transmis au moyen d’un rolling code**, ce qui signifie que le code change à chaque utilisation. Il devient ainsi **difficile** pour quelqu’un d’**intercepter** le signal et de l’**utiliser** pour obtenir un accès **non autorisé** au garage.

Dans un système à rolling code, la télécommande et l’ouvre-porte partagent un **algorithme** qui **génère un nouveau code** à chaque utilisation de la télécommande. L’ouvre-porte ne répondra qu’au **code correct**, ce qui rend beaucoup plus difficile l’accès non autorisé au garage par simple capture d’un code.

### **Missing Link Attack**

En gros, on écoute l’appui sur le bouton et on **capture le signal alors que la télécommande est hors de portée** de l’appareil (par exemple, la voiture ou le garage). On se rapproche ensuite de l’appareil et on **utilise le code capturé pour l’ouvrir**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

> [!CAUTION]
> Le brouillage RF intentionnel est illégal dans de nombreuses juridictions et peut perturber des systèmes essentiels à la sécurité. N’effectuez des tests de brouillage que dans un laboratoire blindé et autorisé, conformément à la réglementation radio applicable.<sup>[[6]](#references)</sup>

Un attaquant pourrait **brouiller le signal à proximité du véhicule ou du récepteur**, afin que celui-ci ne puisse pas décoder le code, capturer séparément la transmission bloquée, arrêter le brouillage, puis rejouer le code capturé.<sup>[[2]](#references)</sup>

À un moment donné, la victime utilisera ses **clés pour verrouiller la voiture**, mais l’attaque aura alors **enregistré suffisamment de codes de « fermeture »** pour pouvoir éventuellement les renvoyer afin d’ouvrir la porte (un **changement de fréquence peut être nécessaire**, car certaines voitures utilisent les mêmes codes pour ouvrir et fermer, mais écoutent les deux commandes sur des fréquences différentes).

> [!WARNING]
> **Le brouillage fonctionne**, mais il se remarque : si la **personne qui verrouille la voiture vérifie simplement les portes**, elle constatera que la voiture est déverrouillée. De plus, si elle connaît ce type d’attaque, elle pourrait remarquer que les portes n’ont jamais émis le **son** de verrouillage ou que les **feux** de la voiture n’ont pas clignoté lorsqu’elle a appuyé sur le bouton « verrouiller ».

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Il s’agit d’une **technique de brouillage plus furtive**. L’attaquant brouille le signal ; lorsque la victime essaie de verrouiller la porte, cela échoue, mais l’attaquant **enregistre ce code**. La victime **essaie alors de verrouiller à nouveau la voiture** en appuyant sur le bouton, et la voiture **enregistre ce deuxième code**.<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>\
Juste après, **l’attaquant peut envoyer le premier code** et la **voiture se verrouille** (la victime pensera que c’est le deuxième appui qui l’a verrouillée). L’attaquant pourra ensuite **envoyer le deuxième code volé pour ouvrir** la voiture (à condition qu’un code de **« fermeture de la voiture » puisse aussi servir à l’ouvrir**). Un changement de fréquence peut être nécessaire (car certaines voitures utilisent les mêmes codes pour ouvrir et fermer, mais écoutent les deux commandes sur des fréquences différentes).

Une implémentation de RollJam exploite la bande passante du récepteur : le brouilleur émet suffisamment près de la porteuse de la télécommande pour désensibiliser le récepteur plus large du véhicule, tandis que le récepteur plus étroit de l’attaquant reste centré sur la télécommande et peut toujours l’enregistrer. Le décalage exact et la bande passante dépendent du matériel ciblé.<sup>[[2]](#references)</sup>

> [!WARNING]
> D’autres implémentations décrites dans des spécifications montrent que le **rolling code ne constitue qu’une partie** du code total transmis. Par exemple, le code envoyé est une **clé de 24 bits**, dont les **12 premiers bits forment le rolling code**, les **8 suivants indiquent la commande** (verrouiller ou déverrouiller, par exemple) et les 4 derniers constituent la **somme de contrôle**. Les véhicules qui utilisent ce type de système sont également vulnérables : l’attaquant n’a qu’à remplacer le segment du rolling code pour pouvoir **utiliser n’importe quel rolling code sur les deux fréquences**.

> [!CAUTION]
> Notez que si la victime envoie un troisième code pendant que l’attaquant transmet le premier, les premier et deuxième codes seront invalidés.

### Alarm Sounding Jamming Attack

Lors de tests sur un système à rolling code installé après-vente sur une voiture, **l’envoi deux fois du même code** a immédiatement **déclenché l’alarme et l’antidémarrage**, créant une occasion unique de **denial of service**. Ironiquement, pour **désactiver l’alarme** et l’antidémarrage, il suffisait d’**appuyer** sur la **télécommande**, ce qui permettait à l’attaquant de **répéter continuellement l’attaque DoS**. Il est également possible de combiner cette attaque avec la **précédente pour obtenir davantage de codes**, puisque la victime voudra mettre fin à l’attaque au plus vite.<sup>[[2]](#references)</sup>

## References

- [1] [Documentation de Flipper Zero - fréquences Sub-GHz régionales](https://docs.flipper.net/zero/sub-ghz/frequencies)
- [2] [Contournement des systèmes à rolling code - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23 : Conduisez comme si vous l’aviez piratée (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [Comment pirater une voiture - reproduction de RollJam avec YARD Stick One / RTL-SDR](https://hackaday.io/project/164566-how-to-hack-a-car/details)
- [5] [Code source d’OpenSesame](https://github.com/samyk/opensesame)
- [6] [Avis d’application de la FCC - application de la réglementation sur les brouilleurs](https://www.fcc.gov/document/jammer-enforcement)
{{#include ../../banners/hacktricks-training.md}}
