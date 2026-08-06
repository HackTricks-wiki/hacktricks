# iButton

{{#include ../../banners/hacktricks-training.md}}

## Introduction

iButton est un nom générique désignant une clé d’identification électronique enfermée dans un **boîtier métallique en forme de pièce**. Elle est également appelée mémoire **Dallas Touch** ou mémoire à contact. Bien qu’elle soit souvent appelée à tort clé « magnétique », elle ne contient **rien de magnétique**. En réalité, une véritable **puce électronique** fonctionnant avec un protocole numérique est dissimulée à l’intérieur.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### Qu’est-ce qu’un iButton ? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Habituellement, iButton désigne la forme physique de la clé et du lecteur : une pièce ronde avec deux contacts. En ce qui concerne la monture qui l’entoure, il existe de nombreuses variantes, allant du support en plastique le plus courant avec un trou aux bagues, pendentifs, etc.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Lorsque la clé atteint le lecteur, les **contacts se touchent** et la clé est alimentée afin de **transmettre** son identifiant. Parfois, la clé n’est **pas lue** immédiatement, car le **PSD de contact d’un interphone est plus grand** qu’il ne devrait l’être. Les contours extérieurs de la clé et du lecteur ne pouvaient donc pas se toucher. Dans ce cas, vous devrez appuyer la clé contre l’une des parois du lecteur.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **Protocole 1-Wire** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Les clés Dallas échangent des données à l’aide du protocole 1-wire, avec un seul contact pour le transfert de données (!!) dans les deux directions, du Master vers le Slave et inversement. Le protocole 1-wire fonctionne selon le modèle Master-Slave. Dans cette topologie, le Master initie toujours la communication et le Slave suit ses instructions.

Lorsque la clé (Slave) entre en contact avec l’interphone (Master), la puce située à l’intérieur de la clé s’allume, alimentée par l’interphone, et la clé est initialisée. Ensuite, l’interphone demande l’identifiant de la clé. Nous allons examiner ce processus plus en détail.

Flipper peut fonctionner en mode Master et en mode Slave. En mode lecture de clé, Flipper agit comme un lecteur, c’est-à-dire qu’il fonctionne en tant que Master. En mode émulation de clé, Flipper se fait passer pour une clé et fonctionne en mode Slave.<sup>[[1]](#references)</sup>

### Clés Dallas, Cyfral et Metakom

Pour plus d’informations sur le fonctionnement de ces clés, consultez la page [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Attaques

Les iButtons peuvent être attaqués avec Flipper Zero :


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## Références

- [1] [Taming iButton with Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../banners/hacktricks-training.md}}
