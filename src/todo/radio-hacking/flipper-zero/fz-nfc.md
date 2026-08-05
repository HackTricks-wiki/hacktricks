# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#id-9wrzi" id="id-9wrzi"></a>

Pour plus d'informations sur RFID et NFC, consultez la page suivante :


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Cartes NFC supportées <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> En plus des cartes NFC, Flipper Zero prend en charge **d'autres types de cartes haute fréquence**, notamment plusieurs cartes **Mifare** Classic et Ultralight ainsi que des **NTAG**.

De nouveaux types de cartes NFC seront ajoutés à la liste des cartes supportées. Flipper Zero prend en charge les **cartes NFC de type A** (ISO 14443A) suivantes :

- **Cartes bancaires (EMV)** — lecture uniquement de l'UID, du SAK et de l'ATQA, sans sauvegarde.
- **Cartes inconnues** — lecture (UID, SAK, ATQA) et émulation d'un UID.

Pour les **cartes NFC de type B, de type F et de type V**, Flipper Zero peut lire un UID sans le sauvegarder.

### Cartes NFC de type A <a href="#uvusf" id="uvusf"></a>

#### Carte bancaire (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero peut uniquement lire un UID, un SAK, une ATQA et les données stockées sur les cartes bancaires **sans les sauvegarder**.

Écran de lecture d'une carte bancairePour les cartes bancaires, Flipper Zero peut uniquement lire les données **sans les sauvegarder ni les émuler**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Cartes inconnues <a href="#id-37eo8" id="id-37eo8"></a>

Lorsque Flipper Zero est **incapable de déterminer le type de la carte NFC**, seul un **UID, un SAK et une ATQA** peuvent être **lus et sauvegardés**.

Écran de lecture d'une carte inconnuePour les cartes NFC inconnues, Flipper Zero peut uniquement émuler un UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### Cartes NFC de types B, F et V <a href="#wyg51" id="wyg51"></a>

Pour les **cartes NFC de types B, F et V**, Flipper Zero peut uniquement **lire et afficher un UID** sans le sauvegarder.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Actions

Pour une introduction au NFC, [**consultez cette page**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Lecture

Flipper Zero peut **lire les cartes NFC**, mais il **ne comprend pas tous les protocoles** basés sur ISO 14443. Cependant, comme **l'UID est un attribut de bas niveau**, vous pouvez vous retrouver dans une situation où **l'UID a déjà été lu, mais où le protocole de transfert de données de haut niveau reste inconnu**. Vous pouvez lire, émuler et saisir manuellement l'UID avec Flipper pour les lecteurs primitifs qui utilisent l'UID à des fins d'autorisation.<sup>[[1]](#references)</sup>

#### Lecture de l'UID VS lecture des données internes <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

Dans Flipper, la lecture des tags 13.56 MHz peut être divisée en deux parties :<sup>[[1]](#references)</sup>

- **Lecture de bas niveau** — lit uniquement l'UID, le SAK et l'ATQA. Flipper tente de deviner le protocole de haut niveau à partir de ces données lues sur la carte. Vous ne pouvez pas en être certain à 100 %, car il s'agit simplement d'une hypothèse basée sur certains facteurs.
- **Lecture de haut niveau** — lit les données de la mémoire de la carte à l'aide d'un protocole de haut niveau spécifique. Il peut s'agir de lire les données d'une Mifare Ultralight, de lire les secteurs d'une Mifare Classic ou de lire les attributs de la carte avec PayPass/Apple Pay.

### Lecture spécifique

Si Flipper Zero n'est pas capable de trouver le type de carte à partir des données de bas niveau, vous pouvez sélectionner `Read Specific Card Type` dans `Extra Actions` et **indiquer** **manuellement le type de carte que vous souhaitez lire**.

#### Cartes bancaires EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

En plus de simplement lire l'UID, vous pouvez extraire beaucoup plus de données d'une carte bancaire. Il est possible d'**obtenir le numéro complet de la carte** (les 16 chiffres sur le devant de la carte), la **date d'expiration** et, dans certains cas, même le **nom du titulaire** ainsi qu'une liste des **transactions les plus récentes**.\
Cependant, vous **ne pouvez pas lire le CVV de cette manière** (les 3 chiffres au dos de la carte). De plus, **les cartes bancaires sont protégées contre les attaques par rejeu** : les copier avec Flipper, puis tenter de les émuler pour payer quelque chose, ne fonctionnera pas.<sup>[[1]](#references)</sup>

## Références

- [1] [Diving into RFID Protocols with Flipper Zero](https://blog.flipperzero.one/rfid/)

{{#include ../../../banners/hacktricks-training.md}}
