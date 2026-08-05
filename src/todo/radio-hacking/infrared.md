# Infrarouge

{{#include ../../banners/hacktricks-training.md}}

## Fonctionnement de l'infrarouge <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**La lumière infrarouge est invisible pour les humains**. La longueur d'onde IR va de **0,7 à 1000 microns**. Les télécommandes domestiques utilisent un signal IR pour la transmission de données et fonctionnent dans la plage de longueurs d'onde de 0,75..1,4 micron. Un microcontrôleur dans la télécommande fait clignoter une LED infrarouge à une fréquence spécifique, transformant le signal numérique en signal IR.<sup>[[1]](#references)</sup>

Pour recevoir les signaux IR, on utilise un **phot récepteur**. Il **convertit la lumière IR en impulsions de tension**, qui sont déjà des **signaux numériques**. Généralement, un **filtre de lumière sombre** se trouve à l'intérieur du récepteur. Il ne laisse passer **que la longueur d'onde souhaitée** et élimine les parasites.

### Variété des protocoles IR <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Les protocoles IR diffèrent selon 3 facteurs :

- l'encodage des bits
- la structure des données
- la fréquence porteuse — souvent comprise entre 36 et 38 kHz

#### Méthodes d'encodage des bits <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulse Distance Encoding**

Les bits sont encodés en modulant la durée de l'espace entre les impulsions. La largeur de l'impulsion elle-même est constante.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulse Width Encoding**

Les bits sont encodés par modulation de la largeur de l'impulsion. La largeur de l'espace après la salve d'impulsions est constante.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phase Encoding**

Cette méthode est également connue sous le nom d'encodage Manchester. La valeur logique est définie par la polarité de la transition entre la salve d'impulsions et l'espace. « Espace vers salve d'impulsions » représente la logique « 0 », tandis que « salve d'impulsions vers espace » représente la logique « 1 ».

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Combinaison des précédentes et autres méthodes exotiques**

> [!TIP]
> Certains protocoles IR **tentent de devenir universels** pour plusieurs types d'appareils. Les plus célèbres sont RC5 et NEC. Malheureusement, être le plus célèbre **ne signifie pas être le plus courant**. Dans mon environnement, je n'ai rencontré que deux télécommandes NEC et aucune télécommande RC5.
>
> Les fabricants aiment utiliser leurs propres protocoles IR uniques, même au sein d'une même gamme d'appareils (par exemple, les box TV). Par conséquent, les télécommandes de sociétés différentes, et parfois de modèles différents d'une même société, sont incapables de fonctionner avec d'autres appareils du même type.

### Exploration d'un signal IR

La manière la plus fiable d'observer l'apparence du signal IR d'une télécommande consiste à utiliser un oscilloscope. Celui-ci ne démodule ni n'inverse le signal reçu ; il l'affiche simplement « tel quel ». Cela est utile pour les tests et le debugging. Je vais présenter le signal attendu en prenant l'exemple du protocole IR NEC.

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Généralement, un préambule se trouve au début d'un paquet encodé. Il permet au récepteur de déterminer le niveau de gain et le bruit de fond. Certains protocoles ne possèdent toutefois pas de préambule, comme Sharp.

Les données sont ensuite transmises. La structure, le préambule et la méthode d'encodage des bits sont déterminés par le protocole spécifique.

Le **protocole IR NEC** contient une commande courte et un code de répétition, envoyé tant que le bouton est pressé. La commande et le code de répétition possèdent tous deux le même préambule au début.

La **commande** NEC, en plus du préambule, se compose d'un octet d'adresse et d'un octet de numéro de commande, qui indiquent à l'appareil ce qui doit être exécuté. Les octets d'adresse et de numéro de commande sont dupliqués avec des valeurs inversées afin de vérifier l'intégrité de la transmission. Un bit d'arrêt supplémentaire se trouve à la fin de la commande.

Le **code de répétition** contient un « 1 » après le préambule, qui constitue un bit d'arrêt.

Pour les **logiques « 0 » et « 1 »**, NEC utilise le Pulse Distance Encoding : une salve d'impulsions est d'abord transmise, suivie d'une pause dont la longueur définit la valeur du bit.

### Climatiseurs

Contrairement aux autres télécommandes, **les climatiseurs ne transmettent pas uniquement le code du bouton pressé**. Ils **transmettent également toutes les informations** lors de l'appui sur un bouton afin de garantir que **le climatiseur et la télécommande sont synchronisés**.\
Cela évite qu'un appareil réglé à 20 °C soit augmenté à 21 °C avec une télécommande, puis que, lorsqu'une autre télécommande indiquant toujours 20 °C est utilisée pour augmenter davantage la température, celle-ci soit « augmentée » à 21 °C (et non à 22 °C, en pensant qu'elle est à 21 °C).

---

## Attaques et recherche offensive <a href="#attacks" id="attacks"></a>

Vous pouvez attaquer l'infrarouge avec Flipper Zero :


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Prise de contrôle des Smart-TV / Set-top Box (EvilScreen)

Des travaux universitaires récents (EvilScreen, 2022) ont démontré que **les télécommandes multicanaux combinant l'infrarouge avec le Bluetooth ou le Wi-Fi peuvent être utilisées pour détourner complètement les Smart-TV modernes**. L'attaque associe des codes de service IR à privilèges élevés à des paquets Bluetooth authentifiés, contournant l'isolation des canaux et permettant de lancer arbitrairement des applications, d'activer le microphone ou d'effectuer une réinitialisation d'usine sans accès physique. Huit téléviseurs courants de différents fabricants — dont un modèle Samsung revendiquant une conformité à la norme ISO/IEC 27001 — se sont révélés vulnérables. La mitigation nécessite des correctifs firmware du fabricant ou la désactivation complète des récepteurs IR inutilisés.<sup>[[2]](#references)</sup>

### Exfiltration de données depuis un réseau isolé via des LED IR (famille aIR-Jumper)

Les caméras de sécurité, les routeurs et même les clés USB malveillantes intègrent souvent des **LED IR de vision nocturne**. Des recherches montrent que les malwares peuvent moduler ces LED (<10–20 kbit/s avec un OOK simple) afin d'**exfiltrer des secrets à travers les murs et les fenêtres** vers une caméra externe située à plusieurs dizaines de mètres. Comme la lumière se trouve en dehors du spectre visible, les opérateurs le remarquent rarement. Contre-mesures :

* Protéger physiquement ou retirer les LED IR dans les zones sensibles
* Surveiller le duty-cycle des LED des caméras et l'intégrité du firmware
* Déployer des filtres IR-cut sur les fenêtres et les caméras de surveillance

Un attaquant peut également utiliser de puissants projecteurs IR pour **injecter** des commandes dans le réseau en envoyant des données par flash vers des caméras vulnérables.

### Brute-force longue portée et protocoles étendus avec Flipper Zero 1.0

Le firmware 1.0 (septembre 2024) a ajouté **des dizaines de protocoles IR supplémentaires et des modules d'amplification externes optionnels**. Combiné au mode de brute-force de télécommande universelle, un Flipper peut désactiver ou reconfigurer la plupart des téléviseurs/climatiseurs publics jusqu'à 30 m à l'aide d'une diode haute puissance.

---

## Outils et exemples pratiques <a href="#tooling" id="tooling"></a>

### Matériel

* **Flipper Zero** – émetteur-récepteur portable proposant des modes d'apprentissage, de replay et de dictionary-bruteforce (voir ci-dessus).
* **Arduino / ESP32** + LED IR / récepteur TSOP38xx – analyseur/émetteur DIY bon marché. À combiner avec la bibliothèque `Arduino-IRremote` (v4.x prend en charge >40 protocoles).
* **Analyseurs logiques** (Saleae/FX2) – capturent les timings bruts lorsque le protocole est inconnu.
* **Smartphones équipés d'un IR-blaster** (par exemple, Xiaomi) – test rapide sur le terrain, mais portée limitée.

### Logiciels

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
* **IRscrutinizer / AnalysIR** – décodeurs GUI qui importent les captures brutes, identifient automatiquement le protocole et génèrent du code Pronto/Arduino.
* **LIRC / ir-keytable (Linux)** – réception et injection d'IR depuis la ligne de commande :
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Mesures défensives <a href="#defense" id="defense"></a>

* Désactiver ou couvrir les récepteurs IR des appareils déployés dans les espaces publics lorsqu'ils ne sont pas nécessaires.
* Imposer un *pairing* ou des vérifications cryptographiques entre les Smart-TV et les télécommandes ; isoler les codes de « service » à privilèges élevés.
* Déployer des filtres IR-cut ou des détecteurs à onde continue autour des zones classifiées afin de couper les covert channels optiques.
* Surveiller l'intégrité du firmware des caméras/appareils IoT qui exposent des LED IR contrôlables.

## Références

- [1] [Article de blog Flipper Zero sur l'infrarouge](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen : détournement de Smart-TV via l'imitation d'une télécommande](https://arxiv.org/abs/2210.03014)

{{#include ../../banners/hacktricks-training.md}}
