# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Portes de garage

Les ouvre-portes de garage fonctionnent généralement à des fréquences dans la plage de 300-190 MHz, les fréquences les plus courantes étant 300 MHz, 310 MHz, 315 MHz et 390 MHz. Cette plage de fréquences est couramment utilisée pour les ouvre-portes de garage car elle est moins encombrée que d'autres bandes de fréquence et est moins susceptible de subir des interférences d'autres appareils.

## Portes de voiture

La plupart des télécommandes de voiture fonctionnent soit à **315 MHz soit à 433 MHz**. Ce sont toutes deux des fréquences radio, et elles sont utilisées dans une variété d'applications différentes. La principale différence entre les deux fréquences est que 433 MHz a une portée plus longue que 315 MHz. Cela signifie que 433 MHz est mieux adapté aux applications nécessitant une portée plus longue, comme l'entrée sans clé à distance.\
En Europe, 433,92 MHz est couramment utilisé et aux États-Unis et au Japon, c'est 315 MHz.

## **Attaque par force brute**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

Si au lieu d'envoyer chaque code 5 fois (envoyé de cette manière pour s'assurer que le récepteur le reçoit) vous l'envoyez juste une fois, le temps est réduit à 6 minutes :

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

et si vous **supprimez la période d'attente de 2 ms** entre les signaux, vous pouvez **réduire le temps à 3 minutes.**

De plus, en utilisant la séquence de De Bruijn (une méthode pour réduire le nombre de bits nécessaires pour envoyer tous les nombres binaires potentiels à brute-forcer), ce **temps est réduit à seulement 8 secondes** :

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

Un exemple de cette attaque a été implémenté dans [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

Exiger **un préambule évitera l'optimisation de la séquence de De Bruijn** et **les codes roulants empêcheront cette attaque** (supposant que le code est suffisamment long pour ne pas être brute-forcé).

## Attaque Sub-GHz

Pour attaquer ces signaux avec Flipper Zero, vérifiez :

{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Protection par codes roulants

Les ouvre-portes de garage automatiques utilisent généralement une télécommande sans fil pour ouvrir et fermer la porte du garage. La télécommande **envoie un signal de fréquence radio (RF)** à l'ouvre-porte de garage, qui active le moteur pour ouvrir ou fermer la porte.

Il est possible que quelqu'un utilise un appareil connu sous le nom de code grabber pour intercepter le signal RF et l'enregistrer pour une utilisation ultérieure. Cela s'appelle une **attaque par répétition**. Pour prévenir ce type d'attaque, de nombreux ouvre-portes de garage modernes utilisent une méthode de cryptage plus sécurisée connue sous le nom de système de **code roulant**.

Le **signal RF est généralement transmis en utilisant un code roulant**, ce qui signifie que le code change à chaque utilisation. Cela rend **difficile** pour quelqu'un d'**intercepter** le signal et de **l'utiliser** pour obtenir un accès **non autorisé** au garage.

Dans un système de code roulant, la télécommande et l'ouvre-porte de garage ont un **algorithme partagé** qui **génère un nouveau code** chaque fois que la télécommande est utilisée. L'ouvre-porte de garage ne répondra qu'au **code correct**, rendant beaucoup plus difficile pour quelqu'un d'obtenir un accès non autorisé au garage simplement en capturant un code.

### **Attaque par lien manquant**

En gros, vous écoutez le bouton et **capturez le signal pendant que la télécommande est hors de portée** de l'appareil (disons la voiture ou le garage). Vous vous déplacez ensuite vers l'appareil et **utilisez le code capturé pour l'ouvrir**.

### Attaque par brouillage de lien complet

Un attaquant pourrait **brouiller le signal près du véhicule ou du récepteur** afin que le **récepteur ne puisse pas réellement ‘entendre’ le code**, et une fois que cela se produit, vous pouvez simplement **capturer et rejouer** le code lorsque vous avez arrêté le brouillage.

La victime à un moment donné utilisera les **clés pour verrouiller la voiture**, mais ensuite l'attaque aura **enregistré suffisamment de "codes de fermeture"** qui, espérons-le, pourraient être renvoyés pour ouvrir la porte (un **changement de fréquence pourrait être nécessaire** car il y a des voitures qui utilisent les mêmes codes pour ouvrir et fermer mais écoutent les deux commandes à des fréquences différentes).

> [!WARNING]
> **Le brouillage fonctionne**, mais c'est perceptible car si la **personne verrouillant la voiture teste simplement les portes** pour s'assurer qu'elles sont verrouillées, elle remarquerait que la voiture est déverrouillée. De plus, si elle était consciente de telles attaques, elle pourrait même écouter le fait que les portes n'ont jamais fait le **bruit** de verrouillage ou que les **lumières** de la voiture n'ont jamais clignoté lorsqu'elle a appuyé sur le bouton ‘verrouiller’.

### **Attaque de capture de code (alias ‘RollJam’)**

C'est une technique de **brouillage furtif**. L'attaquant va brouiller le signal, donc lorsque la victime essaie de verrouiller la porte, cela ne fonctionnera pas, mais l'attaquant va **enregistrer ce code**. Ensuite, la victime va **essayer de verrouiller la voiture à nouveau** en appuyant sur le bouton et la voiture va **enregistrer ce deuxième code**.\
Instantanément après cela, l'**attaquant peut envoyer le premier code** et la **voiture se verrouillera** (la victime pensera que la deuxième pression l'a fermée). Ensuite, l'attaquant pourra **envoyer le deuxième code volé pour ouvrir** la voiture (supposant qu'un **code "fermer la voiture" peut également être utilisé pour l'ouvrir**). Un changement de fréquence pourrait être nécessaire (car il y a des voitures qui utilisent les mêmes codes pour ouvrir et fermer mais écoutent les deux commandes à des fréquences différentes).

L'attaquant peut **brouiller le récepteur de la voiture et non son récepteur** car si le récepteur de la voiture écoute par exemple une bande large de 1 MHz, l'attaquant ne **brouillera** pas la fréquence exacte utilisée par la télécommande mais **une proche dans ce spectre** tandis que le **récepteur de l'attaquant écoutera dans une plage plus petite** où il peut écouter le signal de la télécommande **sans le signal de brouillage**.

> [!WARNING]
> D'autres implémentations vues dans les spécifications montrent que le **code roulant est une portion** du code total envoyé. Par exemple, le code envoyé est une **clé de 24 bits** où les premiers **12 sont le code roulant**, les **8 suivants sont la commande** (comme verrouiller ou déverrouiller) et les 4 derniers sont le **checksum**. Les véhicules mettant en œuvre ce type sont également naturellement susceptibles car l'attaquant doit simplement remplacer le segment de code roulant pour pouvoir **utiliser n'importe quel code roulant sur les deux fréquences**.

> [!CAUTION]
> Notez que si la victime envoie un troisième code pendant que l'attaquant envoie le premier, le premier et le deuxième code seront invalidés.

### Attaque de brouillage de son d'alarme

En testant un système de code roulant après-vente installé sur une voiture, **l'envoi du même code deux fois** a immédiatement **activé l'alarme** et l'immobilisateur, offrant une opportunité unique de **refus de service**. Ironiquement, le moyen de **désactiver l'alarme** et l'immobilisateur était de **presser** la **télécommande**, offrant à un attaquant la possibilité de **réaliser continuellement une attaque DoS**. Ou de mélanger cette attaque avec la **précédente pour obtenir plus de codes** car la victime aimerait arrêter l'attaque le plus rapidement possible.

## Références

- [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
- [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
- [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{{#include ../../banners/hacktricks-training.md}}
