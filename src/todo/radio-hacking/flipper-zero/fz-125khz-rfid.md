# FZ - RFID 125 kHz

{{#include ../../../banners/hacktricks-training.md}}


## Introduction

Pour plus d'informations sur le fonctionnement des tags 125 kHz, consultez :


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Actions

Pour plus d'informations sur ces types de tags, [**lisez cette introduction**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Lire

Tente de **lire** les informations de la carte. Il est ensuite possible de les **émuler**.<sup>[[1]](#references)</sup>

> [!WARNING]
> Notez que certains interphones tentent de se protéger contre la duplication des clés en envoyant une commande d'écriture avant la lecture. Si l'écriture réussit, le tag est considéré comme faux. Lorsque Flipper émule un RFID, il n'existe aucun moyen pour le lecteur de le distinguer de l'original, ce qui évite donc ce type de problème.

### Ajouter manuellement

Vous pouvez créer de **fausses cartes dans Flipper Zero en indiquant les données** manuellement, puis les émuler.

#### Identifiants sur les cartes

Parfois, lorsque vous obtenez une carte, vous trouverez son identifiant (ou une partie de celui-ci) inscrit et visible sur la carte.

- **EM Marin**

Par exemple, sur cette carte EM-Marin, il est possible de **lire clairement les 3 derniers octets sur les 5** présents sur la carte physique.\
Les 2 autres peuvent être **brute-forced** si vous ne pouvez pas les lire sur la carte.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Il en va de même pour cette carte HID, où seuls 2 des 3 octets peuvent être trouvés imprimés sur la carte.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Émuler/écrire

Après avoir **copié** une carte ou **saisi** son identifiant **manuellement**, il est possible de l'**émuler** avec Flipper Zero ou de l'**écrire** sur une carte réelle.<sup>[[1]](#references)</sup>

## Références

- [1] [Diving into RFID Protocols with Flipper Zero](https://blog.flipperzero.one/rfid/)


{{#include ../../../banners/hacktricks-training.md}}
