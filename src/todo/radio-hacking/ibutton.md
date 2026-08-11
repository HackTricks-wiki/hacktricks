# iButton

{{#include ../../banners/hacktricks-training.md}}

## Introduction

iButton est un nom générique désignant une clé d'identification électronique encapsulée dans un **boîtier métallique en forme de pièce**. Elle est également appelée mémoire **Dallas Touch** ou mémoire à contact. Bien qu'elle soit souvent désignée à tort comme une clé « magnétique », elle ne contient **rien de magnétique**. En réalité, une véritable **puce électronique** fonctionnant avec un protocole numérique est dissimulée à l'intérieur.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### Qu'est-ce qu'un iButton ? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Le nom iButton décrit le boîtier durable en forme de pièce ainsi que la disposition des contacts. Les supports comprennent des porte-clés en plastique, des bagues et des pendentifs.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Lorsque les deux contacts touchent le lecteur, l'appareil reçoit de l'énergie et échange des données. Si la géométrie en retrait des contacts empêche les contacts de masse extérieurs de se rejoindre, incliner la clé contre la paroi du lecteur peut rétablir le contact.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **Protocole 1-Wire** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Les clés Dallas/Maxim utilisent le protocole 1-Wire : un contact de données transporte le trafic bidirectionnel et peut également fournir une alimentation parasite, tandis que le boîtier métallique constitue le contact de retour. Le contrôleur initie les transactions et l'appareil répond.<sup>[[2]](#references)</sup>

Lorsque la clé (Slave) entre en contact avec l'interphone (Master), la puce située à l'intérieur de la clé s'allume, alimentée par l'interphone, et la clé est initialisée. Ensuite, l'interphone demande l'identifiant de la clé. Nous allons maintenant examiner ce processus plus en détail.

Flipper peut agir comme contrôleur lors de la lecture d'une clé et comme appareil émulé lorsqu'il présente un identifiant enregistré à un lecteur.<sup>[[1]](#references)</sup>

### Clés Dallas, Cyfral & Metakom

Pour savoir comment fonctionnent ces clés, consultez la page [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Attaques

Les iButtons peuvent être attaqués avec Flipper Zero :


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## References

- [1] [Maîtriser iButton avec Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Analog Devices — Communication 1-Wire par logiciel](https://www.analog.com/en/resources/technical-articles/1wire-communication-through-software.html)
{{#include ../../banners/hacktricks-training.md}}
