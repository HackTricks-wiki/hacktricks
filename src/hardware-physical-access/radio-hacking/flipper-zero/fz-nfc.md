# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Introduction <a href="#id-9wrzi" id="id-9wrzi"></a>

Pour en savoir plus sur la RFID et le NFC, consultez la page suivante :


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Cartes NFC prises en charge <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> En plus des cartes NFC, Flipper Zero prend en charge **d’autres types de cartes haute fréquence**, notamment plusieurs cartes **Mifare** Classic et Ultralight et **NTAG**.

La liste des capacités ci-dessous décrit le firmware documenté dans l’article d’origine et ne doit pas être considérée comme une matrice exhaustive des compatibilités actuelles. Le firmware de Flipper a ajouté des protocoles et son comportement NFC a évolué au fil du temps ; consultez la documentation officielle actuelle correspondant au firmware installé.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Cartes bancaires (EMV)** — lecture de l’UID, du SAK et de l’ATQA uniquement, sans enregistrement.
- **Cartes inconnues** — lecture de l’UID, du SAK et de l’ATQA, et émulation d’un UID.

Pour les **types de cartes NFC B, F et V**, le firmware documenté pouvait lire un UID sans l’enregistrer.

### Cartes NFC de type A <a href="#uvusf" id="uvusf"></a>

#### Carte bancaire (EMV) <a href="#kzmrp" id="kzmrp"></a>

Le firmware documenté pouvait lire l’UID, le SAK, l’ATQA et les données d’application disponibles d’une carte bancaire **sans les enregistrer**.

Pour ces cartes bancaires, le firmware affichait les données sans enregistrer ni émuler la carte.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Cartes inconnues <a href="#id-37eo8" id="id-37eo8"></a>

Lorsque Flipper Zero **ne parvient pas à déterminer le type de carte NFC**, seul un **UID, un SAK et un ATQA** peuvent être **lus et enregistrés**.

Pour une carte NFC inconnue, ce mode ne peut émuler que son UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### Cartes NFC de types B, F et V <a href="#wyg51" id="wyg51"></a>

Dans le firmware documenté par l’article d’origine, les cartes NFC de types B, F et V permettaient uniquement de lire et d’afficher un identifiant, sans l’enregistrer.<sup>[[1]](#references)</sup>

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Actions

Pour une introduction au NFC, [**consultez cette page**](../pentesting-rfid.md#high-frequency-rfid-tags-1356-mhz-1).

### Lecture

Flipper Zero peut lire les cartes NFC, mais n’implémente pas tous les protocoles de niveau supérieur basés sur ISO 14443. Il peut donc récupérer l’UID, le SAK et l’ATQA de bas niveau, sans identifier le protocole applicatif. Pour les systèmes de contrôle d’accès rudimentaires qui autorisent uniquement sur la base de l’UID, l’outil peut lire, saisir manuellement et émuler cet identifiant ; les systèmes reposant sur une authentification cryptographique nécessitent davantage qu’un UID copié.<sup>[[1]](#references)</sup>

#### Lecture de l’UID VS lecture des données internes <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

Dans Flipper, la lecture des tags 13,56 MHz peut être divisée en deux parties :<sup>[[1]](#references)</sup>

- **Lecture de bas niveau** — lit uniquement l’UID, le SAK et l’ATQA. Flipper essaie de deviner le protocole de niveau supérieur à partir de ces données lues sur la carte. Le résultat n’est pas fiable à 100 %, puisqu’il s’agit d’une simple supposition fondée sur certains facteurs.
- **Lecture de haut niveau** — lit les données de la mémoire de la carte à l’aide d’un protocole spécifique de haut niveau. Il peut s’agir de lire les données d’une Mifare Ultralight, les secteurs d’une Mifare Classic ou les attributs de la carte dans PayPass/Apple Pay.

### Lecture spécifique

Si Flipper Zero ne parvient pas à déterminer le type de carte à partir des données de bas niveau, vous pouvez sélectionner `Read Specific Card Type` dans `Extra Actions` et **indiquer manuellement le type de carte que vous souhaitez lire**.

#### Cartes bancaires EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Les anciens firmwares Flipper et les cartes EMV compatibles pouvaient exposer davantage que l’UID, notamment le PAN, la date d’expiration, le nom du titulaire ou l’historique des transactions lorsque ces informations étaient disponibles sur la carte. Leur disponibilité varie selon la carte, l’application et le firmware. Le CVV de la piste magnétique imprimé sur la carte n’est pas exposé de cette manière, et la lecture de ces données ne clone pas la capacité cryptographique de transaction nécessaire pour effectuer un paiement sans contact.<sup>[[1]](#references)</sup>

## References

- [1] [Plongée dans les protocoles RFID avec Flipper Zero](https://blog.flipperzero.one/rfid/)
- [2] [Documentation Flipper Zero - NFC](https://docs.flipper.net/zero/nfc)
{{#include ../../../banners/hacktricks-training.md}}
