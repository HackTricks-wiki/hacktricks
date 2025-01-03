# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#id-9wrzi" id="id-9wrzi"></a>

Pour des informations sur RFID et NFC, consultez la page suivante :

{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Cartes NFC prises en charge <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> En plus des cartes NFC, Flipper Zero prend en charge **d'autres types de cartes à haute fréquence** telles que plusieurs **Mifare** Classic et Ultralight et **NTAG**.

De nouveaux types de cartes NFC seront ajoutés à la liste des cartes prises en charge. Flipper Zero prend en charge les **cartes NFC de type A** (ISO 14443A) suivantes :

- **Cartes bancaires (EMV)** — uniquement lecture de l'UID, SAK et ATQA sans sauvegarde.
- **Cartes inconnues** — lire (UID, SAK, ATQA) et émuler un UID.

Pour les **cartes NFC de type B, type F et type V**, Flipper Zero peut lire un UID sans le sauvegarder.

### Cartes NFC de type A <a href="#uvusf" id="uvusf"></a>

#### Carte bancaire (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero ne peut lire qu'un UID, SAK, ATQA et les données stockées sur les cartes bancaires **sans sauvegarde**.

Écran de lecture de carte bancairePour les cartes bancaires, Flipper Zero ne peut lire les données **sans sauvegarde et émulation**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### Cartes inconnues <a href="#id-37eo8" id="id-37eo8"></a>

Lorsque Flipper Zero est **incapable de déterminer le type de carte NFC**, alors seul un **UID, SAK et ATQA** peut être **lu et sauvegardé**.

Écran de lecture de carte inconnuePour les cartes NFC inconnues, Flipper Zero peut émuler uniquement un UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### Cartes NFC de types B, F et V <a href="#wyg51" id="wyg51"></a>

Pour les **cartes NFC de types B, F et V**, Flipper Zero peut uniquement **lire et afficher un UID** sans le sauvegarder.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## Actions

Pour une introduction sur NFC [**lisez cette page**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Lire

Flipper Zero peut **lire des cartes NFC**, cependant, il **ne comprend pas tous les protocoles** qui sont basés sur ISO 14443. Cependant, puisque **l'UID est un attribut de bas niveau**, vous pourriez vous retrouver dans une situation où **l'UID est déjà lu, mais le protocole de transfert de données de haut niveau est encore inconnu**. Vous pouvez lire, émuler et saisir manuellement l'UID en utilisant Flipper pour les lecteurs primitifs qui utilisent l'UID pour l'autorisation.

#### Lecture de l'UID VS Lecture des données internes <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

Dans Flipper, la lecture des étiquettes à 13,56 MHz peut être divisée en deux parties :

- **Lecture de bas niveau** — lit uniquement l'UID, SAK et ATQA. Flipper essaie de deviner le protocole de haut niveau basé sur ces données lues à partir de la carte. Vous ne pouvez pas être sûr à 100 % de cela, car c'est juste une supposition basée sur certains facteurs.
- **Lecture de haut niveau** — lit les données de la mémoire de la carte en utilisant un protocole de haut niveau spécifique. Cela consisterait à lire les données sur un Mifare Ultralight, lire les secteurs d'un Mifare Classic, ou lire les attributs de la carte depuis PayPass/Apple Pay.

### Lire Spécifique

Dans le cas où Flipper Zero n'est pas capable de trouver le type de carte à partir des données de bas niveau, dans `Actions Supplémentaires`, vous pouvez sélectionner `Lire un Type de Carte Spécifique` et **indiquer manuellement** **le type de carte que vous souhaitez lire**.

#### Cartes Bancaires EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

En plus de simplement lire l'UID, vous pouvez extraire beaucoup plus de données d'une carte bancaire. Il est possible d'**obtenir le numéro de carte complet** (les 16 chiffres à l'avant de la carte), **date de validité**, et dans certains cas même le **nom du propriétaire** ainsi qu'une liste des **transactions les plus récentes**.\
Cependant, vous **ne pouvez pas lire le CVV de cette manière** (les 3 chiffres au dos de la carte). De plus, **les cartes bancaires sont protégées contre les attaques de rejeu**, donc les copier avec Flipper et ensuite essayer de l'émuler pour payer quelque chose ne fonctionnera pas.

## Références

- [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

{{#include ../../../banners/hacktricks-training.md}}
