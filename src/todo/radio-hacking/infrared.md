# Infrared

{{#include ../../banners/hacktricks-training.md}}

## Comment fonctionne l'infrarouge <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**La lumière infrarouge est invisible pour les humains**. La longueur d'onde IR va de **0,7 à 1000 microns**. Les télécommandes domestiques utilisent un signal IR pour la transmission de données et fonctionnent dans la plage de longueur d'onde de 0,75 à 1,4 microns. Un microcontrôleur dans la télécommande fait clignoter une LED infrarouge à une fréquence spécifique, transformant le signal numérique en un signal IR.

Pour recevoir les signaux IR, un **photodétecteur** est utilisé. Il **convertit la lumière IR en impulsions de tension**, qui sont déjà des **signaux numériques**. En général, il y a un **filtre de lumière sombre à l'intérieur du récepteur**, qui laisse **passer uniquement la longueur d'onde souhaitée** et élimine le bruit.

### Variété de protocoles IR <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Les protocoles IR diffèrent par 3 facteurs :

- codage des bits
- structure des données
- fréquence porteuse — souvent dans la plage de 36 à 38 kHz

#### Méthodes de codage des bits <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Codage par distance d'impulsion**

Les bits sont codés en modulant la durée de l'espace entre les impulsions. La largeur de l'impulsion elle-même est constante.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Codage par largeur d'impulsion**

Les bits sont codés par modulation de la largeur de l'impulsion. La largeur de l'espace après l'impulsion est constante.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Codage de phase**

Il est également connu sous le nom de codage Manchester. La valeur logique est définie par la polarité de la transition entre l'impulsion et l'espace. "Espace à impulsion" désigne la logique "0", "impulsion à espace" désigne la logique "1".

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Combinaison des précédents et autres exotiques**

> [!NOTE]
> Il existe des protocoles IR qui **essaient de devenir universels** pour plusieurs types d'appareils. Les plus connus sont RC5 et NEC. Malheureusement, le plus connu **ne signifie pas le plus courant**. Dans mon environnement, j'ai rencontré seulement deux télécommandes NEC et aucune RC5.
>
> Les fabricants aiment utiliser leurs propres protocoles IR uniques, même au sein de la même gamme d'appareils (par exemple, les décodeurs TV). Par conséquent, les télécommandes de différentes entreprises et parfois de différents modèles de la même entreprise, ne peuvent pas fonctionner avec d'autres appareils du même type.

### Exploration d'un signal IR

Le moyen le plus fiable de voir à quoi ressemble le signal IR de la télécommande est d'utiliser un oscilloscope. Il ne démodule pas ou n'inverse pas le signal reçu, il est simplement affiché "tel quel". Cela est utile pour les tests et le débogage. Je vais montrer le signal attendu à l'exemple du protocole IR NEC.

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

En général, il y a un préambule au début d'un paquet codé. Cela permet au récepteur de déterminer le niveau de gain et de fond. Il existe également des protocoles sans préambule, par exemple, Sharp.

Ensuite, les données sont transmises. La structure, le préambule et la méthode de codage des bits sont déterminés par le protocole spécifique.

Le **protocole IR NEC** contient une courte commande et un code de répétition, qui est envoyé tant que le bouton est enfoncé. La commande et le code de répétition ont tous deux le même préambule au début.

La **commande NEC**, en plus du préambule, se compose d'un octet d'adresse et d'un octet de numéro de commande, par lesquels l'appareil comprend ce qui doit être effectué. Les octets d'adresse et de numéro de commande sont dupliqués avec des valeurs inverses, pour vérifier l'intégrité de la transmission. Il y a un bit d'arrêt supplémentaire à la fin de la commande.

Le **code de répétition** a un "1" après le préambule, qui est un bit d'arrêt.

Pour **la logique "0" et "1"**, NEC utilise le codage par distance d'impulsion : d'abord, une impulsion est transmise après laquelle il y a une pause, sa longueur détermine la valeur du bit.

### Climatisations

Contrairement à d'autres télécommandes, **les climatiseurs ne transmettent pas seulement le code du bouton enfoncé**. Ils **transmettent également toutes les informations** lorsqu'un bouton est enfoncé pour s'assurer que la **machine à air conditionné et la télécommande sont synchronisées**.\
Cela évitera qu'une machine réglée à 20ºC soit augmentée à 21ºC avec une télécommande, et ensuite, lorsqu'une autre télécommande, qui a toujours la température à 20ºC, est utilisée pour augmenter encore la température, elle "l'augmentera" à 21ºC (et non à 22ºC en pensant qu'elle est à 21ºC).

### Attaques

Vous pouvez attaquer l'infrarouge avec Flipper Zero :

{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

## Références

- [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

{{#include ../../banners/hacktricks-training.md}}
