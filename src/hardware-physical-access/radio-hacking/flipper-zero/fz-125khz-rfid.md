# FZ - RFID 125 kHz

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

Pour en savoir plus sur le fonctionnement des tags 125 kHz, consultez :

{{#ref}}
../pentesting-rfid.md
{{#endref}}

[L’introduction aux RFID basse fréquence](../pentesting-rfid.md#low-frequency-rfid-tags-125khz) présente les familles de tags courantes et leurs formats de données.

## Actions

### Lire

Utilisez **Lire** pour capturer les données du tag. Après une lecture réussie, Flipper Zero peut émuler le tag enregistré.<sup>[[1]](#references)</sup>

> [!WARNING]
> Certains lecteurs d’interphone tentent de détecter les tags dupliqués inscriptibles en envoyant une commande d’écriture avant la lecture. L’émulation de Flipper Zero ne permet pas d’accéder à la mémoire inscriptible du tag de la même manière.<sup>[[1]](#references)</sup>

### Ajouter manuellement

Vous pouvez saisir manuellement les données du tag dans Flipper Zero, les enregistrer, puis les émuler.<sup>[[1]](#references)</sup>

#### Identifiants sur les cartes

Il arrive qu’une partie ou la totalité de l’identifiant d’une carte soit imprimée sur sa surface.

- **EM Marin**

Par exemple, la carte EM-Marin illustrée affiche les trois derniers des cinq octets de son identifiant. Si le tag ne peut pas être lu, les deux octets manquants peuvent être retrouvés par brute-force.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

De même, la carte HID illustrée n’affiche que deux des trois octets de son identifiant.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Émuler/écrire

Après avoir lu un tag ou saisi son identifiant manuellement, Flipper Zero peut émuler l’identifiant enregistré. Pour les tags inscriptibles compatibles, il peut également écrire les données enregistrées sur une carte compatible.<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero : exploration des protocoles RFID](https://blog.flipperzero.one/rfid/)
{{#include ../../../banners/hacktricks-training.md}}
