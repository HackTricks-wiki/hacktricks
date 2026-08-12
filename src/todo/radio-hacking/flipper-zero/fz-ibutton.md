# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

Pour obtenir des informations générales sur la technologie iButton, consultez :

{{#ref}}
../ibutton.md
{{#endref}}

## Design

Dans l’image suivante, la zone **bleue** montre comment placer un iButton physique contre les contacts du Flipper Zero pour le lire. La zone **verte** montre quels contacts doivent toucher un lecteur pendant l’émulation.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Actions

### Lire

En mode Lecture, le Flipper Zero attend qu’une clé touche ses contacts, détecte le protocole et affiche le protocole au-dessus de l’identifiant de la clé. L’application intégrée prend en charge les clés de contrôle d’accès Dallas, Cyfral et Metakom.<sup>[[2]](#references)</sup>

### Ajouter manuellement

Vous pouvez saisir manuellement les données de clé pour les protocoles Dallas, Cyfral et Metakom.<sup>[[2]](#references)</sup>

### Émuler

Vous pouvez émuler une clé enregistrée, qu’elle ait été lue depuis une clé physique ou saisie manuellement.<sup>[[2]](#references)</sup>

> [!TIP]
> Si les contacts intégrés ne peuvent pas atteindre le lecteur, connectez les contacts de données et de masse via les broches GPIO.<sup>[[2]](#references)</sup>

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Maîtriser les clés iButton avec Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Documentation Flipper Zero - Lecture des clés iButton](https://docs.flipper.net/zero/ibutton/read)
{{#include ../../../banners/hacktricks-training.md}}
