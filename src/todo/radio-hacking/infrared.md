# Infrared

{{#include ../../banners/hacktricks-training.md}}

## Comment fonctionne l'infrarouge <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**La lumière infrarouge est invisible pour les humains**. La longueur d'onde IR va de **0,7 à 1000 microns**. Les télécommandes domestiques utilisent un signal IR pour la transmission de données et fonctionnent dans la plage de longueur d'onde de 0,75 à 1,4 microns. Un microcontrôleur dans la télécommande fait clignoter une LED infrarouge à une fréquence spécifique, transformant le signal numérique en un signal IR.

Pour recevoir des signaux IR, un **photodétecteur** est utilisé. Il **convertit la lumière IR en impulsions de tension**, qui sont déjà des **signaux numériques**. En général, il y a un **filtre de lumière sombre à l'intérieur du récepteur**, qui laisse **passer uniquement la longueur d'onde souhaitée** et élimine le bruit.

### Variété de protocoles IR <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Les protocoles IR diffèrent par 3 facteurs :

- encodage des bits
- structure des données
- fréquence porteuse — souvent dans la plage de 36 à 38 kHz

#### Méthodes d'encodage des bits <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Encodage par distance d'impulsion**

Les bits sont encodés en modulant la durée de l'espace entre les impulsions. La largeur de l'impulsion elle-même est constante.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Encodage par largeur d'impulsion**

Les bits sont encodés par modulation de la largeur de l'impulsion. La largeur de l'espace après l'explosion d'impulsion est constante.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Encodage de phase**

Il est également connu sous le nom d'encodage Manchester. La valeur logique est définie par la polarité de la transition entre l'explosion d'impulsion et l'espace. "Espace à explosion d'impulsion" désigne la logique "0", "explosion d'impulsion à espace" désigne la logique "1".

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Combinaison des précédents et autres exotiques**

> [!TIP]
> Il existe des protocoles IR qui **essaient de devenir universels** pour plusieurs types d'appareils. Les plus connus sont RC5 et NEC. Malheureusement, le plus connu **ne signifie pas le plus courant**. Dans mon environnement, j'ai rencontré seulement deux télécommandes NEC et aucune RC5.
>
> Les fabricants aiment utiliser leurs propres protocoles IR uniques, même au sein de la même gamme d'appareils (par exemple, les décodeurs TV). Par conséquent, les télécommandes de différentes entreprises et parfois de différents modèles de la même entreprise, ne peuvent pas fonctionner avec d'autres appareils du même type.

### Exploration d'un signal IR

Le moyen le plus fiable de voir à quoi ressemble le signal IR de la télécommande est d'utiliser un oscilloscope. Il ne démodule ni n'inverse le signal reçu, il est simplement affiché "tel quel". Cela est utile pour les tests et le débogage. Je vais montrer le signal attendu à l'exemple du protocole IR NEC.

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

En général, il y a un préambule au début d'un paquet encodé. Cela permet au récepteur de déterminer le niveau de gain et de fond. Il existe également des protocoles sans préambule, par exemple, Sharp.

Ensuite, les données sont transmises. La structure, le préambule et la méthode d'encodage des bits sont déterminés par le protocole spécifique.

Le **protocole IR NEC** contient une courte commande et un code de répétition, qui est envoyé pendant que le bouton est enfoncé. La commande et le code de répétition ont tous deux le même préambule au début.

La **commande NEC**, en plus du préambule, se compose d'un octet d'adresse et d'un octet de numéro de commande, par lesquels l'appareil comprend ce qui doit être effectué. Les octets d'adresse et de numéro de commande sont dupliqués avec des valeurs inverses, pour vérifier l'intégrité de la transmission. Il y a un bit d'arrêt supplémentaire à la fin de la commande.

Le **code de répétition** a un "1" après le préambule, qui est un bit d'arrêt.

Pour **la logique "0" et "1"**, NEC utilise l'encodage par distance d'impulsion : d'abord, une explosion d'impulsion est transmise après laquelle il y a une pause, sa longueur détermine la valeur du bit.

### Climatisations

Contrairement à d'autres télécommandes, **les climatiseurs ne transmettent pas seulement le code du bouton enfoncé**. Ils **transmettent également toutes les informations** lorsqu'un bouton est enfoncé pour s'assurer que la **machine à air conditionné et la télécommande sont synchronisées**.\
Cela évitera qu'une machine réglée à 20ºC soit augmentée à 21ºC avec une télécommande, et ensuite, lorsqu'une autre télécommande, qui a toujours la température à 20ºC, est utilisée pour augmenter encore la température, elle "l'augmentera" à 21ºC (et non à 22ºC en pensant qu'elle est à 21ºC).

---

## Attaques & Recherche Offensive <a href="#attacks" id="attacks"></a>

Vous pouvez attaquer l'infrarouge avec Flipper Zero :

{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Prise de contrôle de Smart-TV / Set-top Box (EvilScreen)

Des travaux académiques récents (EvilScreen, 2022) ont démontré que **les télécommandes multi-canaux qui combinent l'infrarouge avec Bluetooth ou Wi-Fi peuvent être abusées pour prendre complètement le contrôle des smart-TVs modernes**. L'attaque enchaîne des codes de service IR à privilèges élevés avec des paquets Bluetooth authentifiés, contournant l'isolation des canaux et permettant le lancement d'applications arbitraires, l'activation du microphone ou la réinitialisation d'usine sans accès physique. Huit téléviseurs grand public de différents fournisseurs — y compris un modèle Samsung prétendant être conforme à la norme ISO/IEC 27001 — ont été confirmés vulnérables. L'atténuation nécessite des correctifs de firmware du fournisseur ou la désactivation complète des récepteurs IR inutilisés.

### Exfiltration de données air-gapped via des LED IR (famille aIR-Jumper)

Les caméras de sécurité, les routeurs ou même les clés USB malveillantes incluent souvent des **LED IR de vision nocturne**. Des recherches montrent que des logiciels malveillants peuvent moduler ces LED (<10–20 kbit/s avec OOK simple) pour **exfiltrer des secrets à travers les murs et les fenêtres** vers une caméra externe placée à des dizaines de mètres. Comme la lumière est en dehors du spectre visible, les opérateurs remarquent rarement. Contre-mesures :

* Protéger physiquement ou retirer les LED IR dans les zones sensibles
* Surveiller le cycle de service des LED de la caméra et l'intégrité du firmware
* Déployer des filtres IR-cut sur les fenêtres et les caméras de surveillance

Un attaquant peut également utiliser de puissants projecteurs IR pour **infiltrer** des commandes dans le réseau en flashant des données vers des caméras non sécurisées.

### Brute-Force à Longue Portée & Protocoles Étendus avec Flipper Zero 1.0

Le firmware 1.0 (septembre 2024) a ajouté **des dizaines de protocoles IR supplémentaires et des modules amplificateurs externes optionnels**. Combiné avec le mode brute-force de télécommande universelle, un Flipper peut désactiver ou reconfigurer la plupart des téléviseurs/climatiseurs publics jusqu'à 30 m en utilisant une diode haute puissance.

---

## Outils & Exemples Pratiques <a href="#tooling" id="tooling"></a>

### Matériel

* **Flipper Zero** – transceiver portable avec modes d'apprentissage, de répétition et de brute-force par dictionnaire (voir ci-dessus).
* **Arduino / ESP32** + LED IR / récepteur TSOP38xx – analyseur/transmetteur DIY bon marché. Combinez avec la bibliothèque `Arduino-IRremote` (v4.x prend en charge >40 protocoles).
* **Analyseurs logiques** (Saleae/FX2) – capturer les temps bruts lorsque le protocole est inconnu.
* **Smartphones avec IR-blaster** (par exemple, Xiaomi) – test rapide sur le terrain mais portée limitée.

### Logiciel

* **`Arduino-IRremote`** – bibliothèque C++ activement maintenue :
```cpp
#include <IRremote.hpp>
IRsend sender;
void setup(){ sender.begin(); }
void loop(){
sender.sendNEC(0x20DF10EF, 32); // Samsung TV Power
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** – décodeurs GUI qui importent des captures brutes et identifient automatiquement le protocole + génèrent du code Pronto/Arduino.
* **LIRC / ir-keytable (Linux)** – recevoir et injecter IR depuis la ligne de commande :
```bash
sudo ir-keytable -p nec,rc5 -t   # dump en direct des codes scannés décodés
irsend SEND_ONCE samsung KEY_POWER
```

---

## Mesures Défensives <a href="#defense" id="defense"></a>

* Désactiver ou couvrir les récepteurs IR sur les appareils déployés dans des espaces publics lorsqu'ils ne sont pas nécessaires.
* Appliquer des vérifications de *couplage* ou cryptographiques entre les smart-TVs et les télécommandes ; isoler les codes de "service" privilégiés.
* Déployer des filtres IR-cut ou des détecteurs d'ondes continues autour des zones classifiées pour briser les canaux optiques cachés.
* Surveiller l'intégrité du firmware des caméras/appareils IoT qui exposent des LED IR contrôlables.

## Références

- [Flipper Zero Infrared blog post](https://blog.flipperzero.one/infrared/)
- EvilScreen : détournement de Smart TV via imitation de télécommande (arXiv 2210.03014)

{{#include ../../banners/hacktricks-training.md}}
