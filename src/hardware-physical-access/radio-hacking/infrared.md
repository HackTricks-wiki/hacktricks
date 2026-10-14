# Infrarouge

{{#include ../../banners/hacktricks-training.md}}

## Fonctionnement de l’infrarouge <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**La lumière infrarouge est invisible pour les humains**. La longueur d’onde IR s’étend de **0,7 à 1 000 microns**. Les télécommandes domestiques utilisent un signal IR pour transmettre des données et fonctionnent dans la plage de longueurs d’onde de 0,75 à 1,4 micron. Un microcontrôleur dans la télécommande fait clignoter une LED infrarouge à une fréquence spécifique, convertissant ainsi le signal numérique en signal IR.

Pour recevoir les signaux IR, on utilise un **photorécepteur**. Il **convertit la lumière IR en impulsions de tension**, qui sont déjà des **signaux numériques**. En général, le récepteur contient un **filtre optique sombre**, qui ne laisse passer **que la longueur d’onde souhaitée** et élimine le bruit.<sup>[[1]](#references)</sup>

### Variété des protocoles IR <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Les protocoles IR diffèrent selon 3 facteurs :<sup>[[1]](#references)</sup>

- le codage des bits
- la structure des données
- la fréquence porteuse — souvent comprise entre 36 et 38 kHz

#### Méthodes de codage des bits <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Codage par distance d’impulsion**

Les bits sont codés en modulant la durée de l’espace entre les impulsions. La largeur de l’impulsion elle-même reste constante.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Codage par largeur d’impulsion**

Les bits sont codés en modulant la largeur de l’impulsion. La durée de l’espace après la salve d’impulsions reste constante.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Codage de phase**

Il est également appelé codage Manchester. La valeur logique est définie par la polarité de la transition entre la salve d’impulsions et l’espace. « De l’espace à la salve d’impulsions » désigne la valeur logique « 0 », et « de la salve d’impulsions à l’espace » désigne la valeur logique « 1 ».

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Combinaison des méthodes précédentes et d’autres méthodes exotiques**

> [!TIP]
> Certains protocoles IR **tentent de devenir universels** pour plusieurs types d’appareils. Les plus connus sont RC5 et NEC. Malheureusement, **le plus connu n’est pas forcément le plus répandu**. Dans mon entourage, je n’ai rencontré que deux télécommandes NEC et aucune RC5.
>
> Les fabricants aiment utiliser leurs propres protocoles IR, même pour une même catégorie d’appareils (par exemple, les boîtiers TV). Par conséquent, les télécommandes de fabricants différents, et parfois celles de modèles différents d’un même fabricant, ne peuvent pas fonctionner avec d’autres appareils du même type.

### Examiner un signal IR

La méthode la plus fiable pour observer un signal IR de télécommande consiste à utiliser un oscilloscope. Il ne démodule ni n’inverse le signal reçu : il l’affiche simplement « tel quel ». C’est utile pour les tests et le débogage. Je vais montrer le signal attendu en prenant l’exemple du protocole IR NEC.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

En général, un préambule se trouve au début d’un paquet encodé. Il permet au récepteur de déterminer le niveau de gain et le bruit de fond. Certains protocoles n’ont pas de préambule, comme Sharp.

Les données sont ensuite transmises. La structure, le préambule et la méthode de codage des bits sont déterminés par le protocole utilisé.

Le **protocole IR NEC** contient une commande courte et un code de répétition, envoyé tant que le bouton est maintenu enfoncé. La commande et le code de répétition ont tous deux le même préambule au début.

La **commande** NEC comprend, en plus du préambule, un octet d’adresse et un octet de numéro de commande, qui indique à l’appareil l’action à effectuer. Les octets d’adresse et de numéro de commande sont dupliqués avec leurs valeurs inversées afin de vérifier l’intégrité de la transmission. Un bit d’arrêt supplémentaire se trouve à la fin de la commande.

Le **code de répétition** contient un « 1 » après le préambule, qui correspond à un bit d’arrêt.

Pour les valeurs **logiques « 0 » et « 1 »**, NEC utilise le codage par distance d’impulsion : une salve d’impulsions est d’abord transmise, puis une pause dont la durée détermine la valeur du bit.

### Climatiseurs

Contrairement aux autres télécommandes, **les télécommandes de climatiseur ne transmettent pas uniquement le code du bouton enfoncé**. Elles **transmettent également toutes les informations** lorsqu’on appuie sur un bouton, afin que **le climatiseur et la télécommande restent synchronisés**.\
Cela évite qu’un climatiseur réglé sur 20 °C passe à 21 °C avec une télécommande, puis qu’une autre télécommande, dont le réglage est toujours à 20 °C, le fasse passer à 21 °C (au lieu de 22 °C, puisqu’elle pense qu’il est réglé sur 21 °C).<sup>[[1]](#references)</sup>

---

## Attaques et recherche offensive <a href="#attacks" id="attacks"></a>

Vous pouvez attaquer l’infrarouge avec Flipper Zero :


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Prise de contrôle d’une Smart TV / d’un décodeur (EvilScreen)

Des travaux universitaires récents (EvilScreen, 2022) ont montré que **les télécommandes multicanaux combinant l’infrarouge au Bluetooth ou au Wi-Fi peuvent être exploitées pour prendre entièrement le contrôle des Smart TV modernes**. L’attaque enchaîne des codes IR de service à privilèges élevés avec des paquets Bluetooth authentifiés, contourne l’isolation des canaux et permet de lancer n’importe quelle application, d’activer le microphone ou de réinitialiser l’appareil aux paramètres d’usine, sans accès physique. Huit téléviseurs courants de différents fabricants — dont un modèle Samsung déclarant être conforme à la norme ISO/IEC 27001 — ont été confirmés vulnérables. Pour atténuer le risque, il faut installer des correctifs de firmware fournis par le fabricant ou désactiver complètement les récepteurs IR inutilisés.<sup>[[2]](#references)</sup>

### Exfiltration de données par LED IR depuis un environnement isolé (famille aIR-Jumper)

Les caméras de sécurité comportent couramment des **LED IR pour la vision nocturne**. Le prototype aIR-Jumper a montré qu’un malware contrôlant ces LED pouvait **exfiltrer des secrets à travers des fenêtres** vers une caméra externe, à une vitesse pouvant atteindre **20 bit/s par caméra de surveillance**, sur plusieurs dizaines de mètres. En sens inverse, les chercheurs ont démontré une infiltration à plus de **100 bit/s**, sur des distances allant de plusieurs centaines de mètres à plusieurs kilomètres.<sup>[[3]](#references)</sup> Comme cette lumière se situe hors du spectre visible, les opérateurs peuvent ne pas la remarquer. Les contre-mesures comprennent :

* Protéger physiquement les LED IR ou les retirer des zones sensibles
* Surveiller le cycle d’activité des LED des caméras et l’intégrité de leur firmware
* Installer des filtres anti-IR sur les fenêtres et les caméras de surveillance

Un attaquant peut également utiliser de puissants projecteurs IR pour **infiltrer** des commandes dans le réseau en envoyant des données par flash à des caméras non sécurisées.

### Force brute à longue portée et protocoles étendus avec Flipper Zero 1.0

Le firmware 1.0 (septembre 2024) a élargi la bibliothèque de télécommandes universelles et ajouté le chargement dynamique de fichiers de ressources infrarouges depuis une carte microSD.<sup>[[4]](#references)</sup> Ses fonctions d’apprentissage et de télécommande universelle peuvent rejouer des commandes connues ou les tester contre des téléviseurs et des climatiseurs à proximité. La portée dépend fortement de l’émetteur, de l’optique, de la lumière ambiante et du récepteur ; du matériel IR externe peut l’augmenter, mais il ne faut pas supposer une distance fixe.

---

## Outils et exemples pratiques <a href="#tooling" id="tooling"></a>

### Matériel

* **Flipper Zero** – émetteur-récepteur portable doté de modes d’apprentissage, de rejeu et de force brute par dictionnaire (voir ci-dessus).
* **Arduino / ESP32** + LED IR / récepteur TSOP38xx – analyseur/émetteur DIY économique. À combiner avec la bibliothèque `Arduino-IRremote` (la v4.x prend en charge plus de 40 protocoles).
* **Analyseurs logiques** (Saleae/FX2) – capturent les temporisations brutes lorsque le protocole est inconnu.
* **Smartphones avec émetteur infrarouge** (par ex., Xiaomi) – utiles pour un test rapide sur le terrain, mais de portée limitée.

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
* **IRscrutinizer / AnalysIR** – décodeurs avec interface graphique qui importent des captures brutes, identifient automatiquement le protocole et génèrent du code Pronto/Arduino.
* **LIRC / ir-keytable (Linux)** – recevoir et injecter des signaux IR depuis la ligne de commande :
  ```bash
  sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
  irsend SEND_ONCE samsung KEY_POWER
  ```

---

## Mesures défensives <a href="#defense" id="defense"></a>

* Désactivez ou couvrez les récepteurs IR des appareils installés dans des espaces publics lorsqu’ils ne sont pas nécessaires.
* Imposez un *appairage* ou des contrôles cryptographiques entre les téléviseurs connectés et leurs télécommandes ; isolez les codes de « service » privilégiés.
* Déployez des filtres anti-IR ou des détecteurs d’onde continue autour des zones classifiées afin de neutraliser les canaux de communication optiques clandestins.
* Surveillez l’intégrité du firmware des caméras et appareils IoT qui exposent des LED IR contrôlables.

## References

- [1] [Article de blog de Flipper Zero sur l’infrarouge](https://blog.flipperzero.one/infrared/)
- [2] [Attaque EvilScreen : piratage de téléviseurs connectés par imitation de télécommande multicanal (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper : exfiltration/infiltration clandestine à travers un air gap via des caméras de sécurité et l’infrarouge (IR) (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)
- [4] [Blog Flipper Zero - Sortie du firmware 1.0](https://blog.flipper.net/released-firmware-1/)
- [5] [Arduino-IRremote - documentation sur l’utilisation et les protocoles](https://github.com/Arduino-IRremote/Arduino-IRremote)
{{#include ../../banners/hacktricks-training.md}}
