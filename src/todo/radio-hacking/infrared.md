# Infrarouge

{{#include ../../banners/hacktricks-training.md}}

## Fonctionnement de l'infrarouge <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**La lumière infrarouge est invisible pour les humains**. La longueur d'onde IR est comprise entre **0,7 et 1000 microns**. Les télécommandes domestiques utilisent un signal IR pour la transmission de données et fonctionnent dans une plage de longueurs d'onde comprise entre 0,75 et 1,4 micron. Un microcontrôleur présent dans la télécommande fait clignoter une LED infrarouge à une fréquence spécifique, transformant le signal numérique en signal IR.

Pour recevoir les signaux IR, on utilise un **photodétecteur**. Il **convertit la lumière IR en impulsions de tension**, qui sont déjà des **signaux numériques**. Généralement, un **filtre de lumière sombre** est présent à l'intérieur du récepteur. Il ne laisse passer **que la longueur d'onde souhaitée** et élimine le bruit.<sup>[[1]](#references)</sup>

### Variété des protocoles IR <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Les protocoles IR diffèrent selon 3 facteurs :<sup>[[1]](#references)</sup>

- encodage des bits
- structure des données
- fréquence porteuse — souvent comprise entre 36 et 38 kHz

#### Méthodes d'encodage des bits <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulse Distance Encoding**

Les bits sont encodés en modulant la durée de l'espace entre les impulsions. La largeur de l'impulsion elle-même est constante.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulse Width Encoding**

Les bits sont encodés par modulation de la largeur de l'impulsion. La largeur de l'espace après la salve d'impulsions est constante.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phase Encoding**

Cette méthode est également appelée encodage Manchester. La valeur logique est définie par la polarité de la transition entre la salve d'impulsions et l'espace. « espace vers salve d'impulsions » représente la logique « 0 », tandis que « salve d'impulsions vers espace » représente la logique « 1 ».

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Combinaison des précédentes et autres méthodes exotiques**

> [!TIP]
> Certains protocoles IR **tentent de devenir universels** pour plusieurs types d'appareils. Les plus célèbres sont RC5 et NEC. Malheureusement, **le plus célèbre ne signifie pas le plus courant**. Dans mon environnement, je n'ai rencontré que deux télécommandes NEC et aucune télécommande RC5.
>
> Les fabricants aiment utiliser leurs propres protocoles IR uniques, même au sein d'une même gamme d'appareils (par exemple, les box TV). Par conséquent, les télécommandes de sociétés différentes, et parfois de modèles différents d'une même société, sont incapables de fonctionner avec d'autres appareils du même type.

### Exploration d'un signal IR

La manière la plus fiable d'observer l'apparence du signal IR d'une télécommande consiste à utiliser un oscilloscope. Celui-ci ne démodule ni n'inverse le signal reçu ; il l'affiche simplement « tel quel ». Cela est utile pour les tests et le débogage. Je vais présenter le signal attendu en prenant comme exemple le protocole IR NEC.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Généralement, un préambule se trouve au début d'un paquet encodé. Cela permet au récepteur de déterminer le niveau de gain et le bruit de fond. Il existe également des protocoles sans préambule, comme Sharp.

Les données sont ensuite transmises. La structure, le préambule et la méthode d'encodage des bits sont déterminés par le protocole spécifique.

Le **protocole IR NEC** contient une commande courte et un code de répétition, envoyé tant que le bouton est maintenu enfoncé. La commande et le code de répétition possèdent tous deux le même préambule au début.

La **commande** NEC, en plus du préambule, se compose d'un octet d'adresse et d'un octet de numéro de commande, qui permettent à l'appareil de comprendre ce qui doit être exécuté. Les octets d'adresse et de numéro de commande sont dupliqués avec leurs valeurs inversées afin de vérifier l'intégrité de la transmission. Un bit d'arrêt supplémentaire se trouve à la fin de la commande.

Le **code de répétition** contient un « 1 » après le préambule, qui correspond à un bit d'arrêt.

Pour la **logique « 0 » et « 1 »**, NEC utilise le Pulse Distance Encoding : une salve d'impulsions est d'abord transmise, suivie d'une pause dont la durée définit la valeur du bit.

### Climatiseurs

Contrairement aux autres télécommandes, **les climatiseurs ne transmettent pas uniquement le code du bouton pressé**. Ils **transmettent également toutes les informations** lors de l'appui sur un bouton afin de garantir que **le climatiseur et la télécommande sont synchronisés**.\
Cela évite qu'une machine réglée à 20 °C soit augmentée à 21 °C avec une télécommande, puis que, lorsqu'une autre télécommande indiquant toujours une température de 20 °C est utilisée pour augmenter davantage la température, celle-ci soit « augmentée » à 21 °C (et non à 22 °C, puisqu'elle pense être réglée à 21 °C).<sup>[[1]](#references)</sup>

---

## Attaques et recherche offensive <a href="#attacks" id="attacks"></a>

Vous pouvez attaquer l'infrarouge avec Flipper Zero :


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Prise de contrôle de Smart-TV / Set-top Box (EvilScreen)

Des travaux universitaires récents (EvilScreen, 2022) ont démontré que **les télécommandes multicanaux combinant l'infrarouge avec le Bluetooth ou le Wi-Fi peuvent être utilisées pour détourner complètement les Smart-TV modernes**. L'attaque enchaîne des codes de service IR à privilèges élevés avec des paquets Bluetooth authentifiés, contourne l'isolation des canaux et permet de lancer arbitrairement des applications, d'activer le microphone ou de rétablir les paramètres d'usine sans accès physique. Huit téléviseurs grand public de différents fabricants — dont un modèle Samsung revendiquant la conformité à la norme ISO/IEC 27001 — se sont révélés vulnérables. La mitigation nécessite des correctifs firmware fournis par les fabricants ou la désactivation complète des récepteurs IR inutilisés.<sup>[[2]](#references)</sup>

### Exfiltration de données depuis un réseau isolé via des LED IR (famille aIR-Jumper)

Les caméras de sécurité incluent généralement des **LED IR de vision nocturne**. Le prototype aIR-Jumper a montré qu'un malware contrôlant ces LED pouvait **exfiltrer des secrets à travers des fenêtres** vers une caméra externe, jusqu'à **20 bit/s par caméra de surveillance** sur plusieurs dizaines de mètres. Dans la direction inverse, les chercheurs ont démontré une infiltration à plus de **100 bit/s** sur des distances allant de plusieurs centaines de mètres à plusieurs kilomètres.<sup>[[3]](#references)</sup> Comme la lumière se situe en dehors du spectre visible, les opérateurs peuvent ne pas la remarquer. Les contre-mesures comprennent :

* Protéger physiquement ou retirer les LED IR dans les zones sensibles
* Surveiller le duty-cycle des LED des caméras et l'intégrité du firmware
* Déployer des filtres IR-cut sur les fenêtres et les caméras de surveillance

Un attaquant peut également utiliser de puissants projecteurs IR pour **infiltrer** des commandes dans le réseau en envoyant des données par flash vers des caméras non sécurisées.

### Brute-Force à longue portée et protocoles étendus avec Flipper Zero 1.0

Le firmware 1.0 (septembre 2024) a étendu la bibliothèque de télécommandes universelles et ajouté le chargement dynamique de fichiers d'assets infrarouges depuis une carte microSD.<sup>[[4]](#references)</sup> Ses fonctions d'apprentissage et de télécommande universelle peuvent rejouer ou essayer des commandes connues contre des téléviseurs et des climatiseurs proches. La portée dépend fortement de l'émetteur, de l'optique, de la lumière ambiante et du récepteur ; du matériel IR externe peut l'étendre, mais il ne faut pas supposer une distance fixe.

---

## Outils et exemples pratiques <a href="#tooling" id="tooling"></a>

### Matériel

* **Flipper Zero** – émetteur-récepteur portable avec des modes d'apprentissage, de rejeu et de dictionary-bruteforce (voir ci-dessus).
* **Arduino / ESP32** + LED IR / récepteur TSOP38xx – analyseur/émetteur DIY peu coûteux. À combiner avec la bibliothèque `Arduino-IRremote` (v4.x prend en charge plus de 40 protocoles).
* **Analyseurs logiques** (Saleae/FX2) – capturent les timings bruts lorsque le protocole est inconnu.
* **Smartphones avec IR-blaster** (par exemple, Xiaomi) – test rapide sur le terrain, mais portée limitée.

### Logiciels

* **`Arduino-IRremote`** – bibliothèque C++ activement maintenue :<sup>[[5]](#references)</sup>
```cpp
#include <IRremote.hpp>
void setup(){ IrSender.begin(3); }
void loop(){
IrSender.sendNEC(0x00, 0x10, 0); // address, command, repeats
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** – décodeurs GUI qui importent des captures brutes, identifient automatiquement le protocole et génèrent du code Pronto/Arduino.
* **LIRC / ir-keytable (Linux)** – réception et injection d'IR depuis la ligne de commande :
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Mesures défensives <a href="#defense" id="defense"></a>

* Désactiver ou couvrir les récepteurs IR des appareils déployés dans les espaces publics lorsqu'ils ne sont pas nécessaires.
* Imposer un *pairing* ou des vérifications cryptographiques entre les Smart-TV et les télécommandes ; isoler les codes de « service » privilégiés.
* Déployer des filtres IR-cut ou des détecteurs à onde continue autour des zones classifiées afin de perturber les covert channels optiques.
* Surveiller l'intégrité du firmware des caméras/appareils IoT qui exposent des LED IR contrôlables.

## References

- [1] [Flipper Zero Infrared blog post](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen Attack: Smart TV Hijacking via Multi-channel Remote Control Mimicry (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: Covert Air-Gap Exfiltration/Infiltration via Security Cameras & Infrared (IR) (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)
- [4] [Flipper Zero Blog - Firmware 1.0 Released](https://blog.flipper.net/released-firmware-1/)
- [5] [Arduino-IRremote - usage and protocol documentation](https://github.com/Arduino-IRremote/Arduino-IRremote)
{{#include ../../banners/hacktricks-training.md}}
