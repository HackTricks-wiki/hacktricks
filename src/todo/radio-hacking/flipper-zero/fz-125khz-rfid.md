# FZ - RFID 125 kHz

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

Pour comprendre le fonctionnement des tags 125 kHz, consultez :

{{#ref}}
../pentesting-rfid.md
{{#endref}}

L'[introduction aux tags RFID basse fréquence](../pentesting-rfid.md#low-frequency-rfid-tags-125khz) présente les familles de tags courantes et leurs formats de données.

## Actions

### Lire

Utilisez **Lire** pour capturer les données du tag. Après une lecture réussie, Flipper Zero peut émuler le tag enregistré.<sup>[[1]](#references)</sup>

> [!WARNING]
> Certains lecteurs d'interphone tentent de détecter les tags duplicata inscriptibles en envoyant une commande d'écriture avant la lecture. Une émulation Flipper Zero n'expose pas la mémoire inscriptible du tag de la même manière.<sup>[[1]](#references)</sup>

### Ajouter manuellement

Vous pouvez saisir manuellement les données du tag dans Flipper Zero, les enregistrer, puis les émuler.<sup>[[1]](#references)</sup>

#### IDs sur les cartes

Parfois, une carte comporte tout ou partie de son ID imprimé sur sa face extérieure.

- **EM Marin**

Par exemple, la carte EM-Marin illustrée expose les trois derniers de ses cinq octets d'ID. Si le tag ne peut pas être lu, les deux octets manquants peuvent être brute-forcés.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

De même, la carte HID illustrée n'imprime que deux de ses trois octets d'ID.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Émuler/Écrire

Après avoir lu un tag ou saisi manuellement son ID, Flipper Zero peut émuler l'identifiant enregistré. Pour les tags inscriptibles pris en charge, il peut également écrire les données enregistrées sur une carte compatible.<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero : Plongée dans les protocoles RFID](https://blog.flipperzero.one/rfid/)
{{#include ../../../banners/hacktricks-training.md}}
