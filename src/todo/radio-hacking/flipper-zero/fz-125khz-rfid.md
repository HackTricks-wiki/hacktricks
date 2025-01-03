# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}


## Intro

Pour plus d'informations sur le fonctionnement des tags 125kHz, consultez :

{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Actions

Pour plus d'informations sur ces types de tags [**lisez cette introduction**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Read

Essaye de **lire** les informations de la carte. Ensuite, il peut **émuler** celles-ci.

> [!WARNING]
> Notez que certains interphones essaient de se protéger contre la duplication de clés en envoyant une commande d'écriture avant de lire. Si l'écriture réussit, ce tag est considéré comme faux. Lorsque Flipper émule RFID, il n'y a aucun moyen pour le lecteur de le distinguer de l'original, donc aucun problème de ce type ne se produit.

### Add Manually

Vous pouvez créer des **cartes fausses dans Flipper Zero en indiquant les données** manuellement, puis les émuler.

#### IDs on cards

Parfois, lorsque vous obtenez une carte, vous trouverez l'ID (ou une partie) écrit sur la carte de manière visible.

- **EM Marin**

Par exemple, dans cette carte EM-Marin, il est possible de **lire les 3 derniers des 5 octets en clair**.\
Les 2 autres peuvent être brute-forcés si vous ne pouvez pas les lire depuis la carte.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Il en va de même pour cette carte HID où seulement 2 des 3 octets peuvent être trouvés imprimés sur la carte.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emulate/Write

Après avoir **copié** une carte ou **saisi** l'ID **manuellement**, il est possible de **l'émuler** avec Flipper Zero ou de **l'écrire** sur une carte réelle.

## References

- [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)


{{#include ../../../banners/hacktricks-training.md}}
