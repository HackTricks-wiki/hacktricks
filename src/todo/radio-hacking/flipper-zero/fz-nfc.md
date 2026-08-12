# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Introduction <a href="#id-9wrzi" id="id-9wrzi"></a>

Pour plus d'informations sur le RFID et le NFC, consultez la page suivante :


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Cartes NFC prises en charge <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> En plus des cartes NFC, Flipper Zero prend en charge **d'autres types de cartes haute fréquence**, notamment plusieurs cartes **Mifare** Classic et Ultralight ainsi que des cartes **NTAG**.

La liste des capacités ci-dessous décrit le firmware documenté par l'article original et ne doit pas être considérée comme la matrice exhaustive actuelle des cartes prises en charge. Le firmware de Flipper a ajouté des protocoles et modifié le comportement NFC au fil du temps ; consultez la documentation officielle actuelle correspondant au firmware installé.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Cartes bancaires (EMV)** — lecture uniquement de l'UID, du SAK et de l'ATQA, sans sauvegarde.
- **Cartes inconnues** — lecture de l'UID, du SAK et de l'ATQA, et émulation d'un UID.

Pour les **types de cartes NFC B, F et V**, le firmware documenté pouvait lire un UID sans le sauvegarder.

### Cartes NFC de type A <a href="#uvusf" id="uvusf"></a>

#### Carte bancaire (EMV) <a href="#kzmrp" id="kzmrp"></a>

Le firmware documenté pouvait lire l'UID, le SAK, l'ATQA et les données d'application disponibles d'une carte bancaire **sans les sauvegarder**.

Pour ces cartes bancaires, le firmware affichait les données sans sauvegarder ni émuler la carte.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Cartes inconnues <a href="#id-37eo8" id="id-37eo8"></a>

Lorsque Flipper Zero est **incapable de déterminer le type de carte NFC**, seul un **UID, un SAK et une ATQA** peuvent être **lus et sauvegardés**.

Pour une carte NFC inconnue, ce mode peut uniquement émuler son UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### Cartes NFC de types B, F et V <a href="#wyg51" id="wyg51"></a>

Dans le firmware documenté par l'article original, l'identifiant des cartes NFC de types B, F et V pouvait uniquement être lu et affiché sans être sauvegardé.<sup>[[1]](#references)</sup>

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Actions

Pour une introduction au NFC, [**consultez cette page**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Lecture

Flipper Zero peut lire les cartes NFC, mais n'implémente pas tous les protocoles de niveau supérieur fondés sur ISO 14443. Il peut donc récupérer l'UID, le SAK et l'ATQA de bas niveau tout en laissant le protocole applicatif inconnu. Pour les systèmes d'accès primitifs qui autorisent uniquement par UID, l'outil peut lire, saisir manuellement et émuler cet identifiant ; les systèmes utilisant une authentification cryptographique nécessitent davantage qu'un UID copié.<sup>[[1]](#references)</sup>

#### Lecture de l'UID VS Lecture des données internes <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

Dans Flipper, la lecture des tags 13,56 MHz peut être divisée en deux parties :<sup>[[1]](#references)</sup>

- **Lecture de bas niveau** — lit uniquement l'UID, le SAK et l'ATQA. Flipper essaie de deviner le protocole de haut niveau à partir de ces données lues sur la carte. Il n'est pas possible d'en être certain à 100 %, car il ne s'agit que d'une supposition fondée sur certains facteurs.
- **Lecture de haut niveau** — lit les données de la mémoire de la carte à l'aide d'un protocole de haut niveau spécifique. Il peut s'agir de lire les données d'une Mifare Ultralight, de lire les secteurs d'une Mifare Classic ou de lire les attributs de la carte avec PayPass/Apple Pay.

### Lecture spécifique

Si Flipper Zero n'est pas capable de trouver le type de carte à partir des données de bas niveau, vous pouvez sélectionner `Read Specific Card Type` dans `Extra Actions` et **indiquer** **manuellement le type de carte que vous souhaitez lire**.

#### Cartes bancaires EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Les anciens firmwares de Flipper et les cartes EMV compatibles pouvaient exposer davantage que l'UID, notamment le PAN, la date d'expiration, le nom du titulaire ou l'historique des transactions lorsque ces enregistrements étaient disponibles sur la carte. La disponibilité varie selon la carte, l'application et le firmware. Le CVV de la piste magnétique imprimé sur la carte n'est pas exposé de cette manière, et la lecture de ces enregistrements ne clone pas la capacité cryptographique de transaction nécessaire pour effectuer un paiement sans contact.<sup>[[1]](#references)</sup>

## References

- [1] [Plongée dans les protocoles RFID avec Flipper Zero](https://blog.flipperzero.one/rfid/)
- [2] [Documentation de Flipper Zero - NFC](https://docs.flipper.net/zero/nfc)
{{#include ../../../banners/hacktricks-training.md}}
