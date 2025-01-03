# iButton

{{#include ../../banners/hacktricks-training.md}}

## Intro

iButton est un nom générique pour une clé d'identification électronique emballée dans un **conteneur métallique en forme de pièce**. Elle est également appelée **Dallas Touch** Memory ou mémoire de contact. Bien qu'elle soit souvent mal appelée clé « magnétique », il n'y a **rien de magnétique** à l'intérieur. En fait, un **microchip** complet fonctionnant sur un protocole numérique est caché à l'intérieur.

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### Qu'est-ce que l'iButton ? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

En général, l'iButton implique la forme physique de la clé et du lecteur - une pièce ronde avec deux contacts. Pour le cadre qui l'entoure, il existe de nombreuses variations, du support en plastique le plus courant avec un trou aux anneaux, pendentifs, etc.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Lorsque la clé atteint le lecteur, les **contacts se touchent** et la clé est alimentée pour **transmettre** son ID. Parfois, la clé n'est **pas lue** immédiatement car le **PSD de contact d'un interphone est plus grand** qu'il ne devrait l'être. Ainsi, les contours extérieurs de la clé et du lecteur ne pouvaient pas se toucher. Si c'est le cas, vous devrez appuyer la clé contre l'un des murs du lecteur.

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **Protocole 1-Wire** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Les clés Dallas échangent des données en utilisant le protocole 1-wire. Avec un seul contact pour le transfert de données (!!) dans les deux sens, du maître à l'esclave et vice versa. Le protocole 1-wire fonctionne selon le modèle Maître-Esclave. Dans cette topologie, le Maître initie toujours la communication et l'Esclave suit ses instructions.

Lorsque la clé (Esclave) entre en contact avec l'interphone (Maître), la puce à l'intérieur de la clé s'allume, alimentée par l'interphone, et la clé est initialisée. Ensuite, l'interphone demande l'ID de la clé. Nous examinerons ce processus plus en détail.

Flipper peut fonctionner à la fois en modes Maître et Esclave. En mode de lecture de clé, Flipper agit comme un lecteur, c'est-à-dire qu'il fonctionne comme un Maître. Et en mode d'émulation de clé, le flipper fait semblant d'être une clé, il est en mode Esclave.

### Clés Dallas, Cyfral & Metakom

Pour des informations sur le fonctionnement de ces clés, consultez la page [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### Attaques

Les iButtons peuvent être attaqués avec Flipper Zero :

{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## Références

- [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../banners/hacktricks-training.md}}
