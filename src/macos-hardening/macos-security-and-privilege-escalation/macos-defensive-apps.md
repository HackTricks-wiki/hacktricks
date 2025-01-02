# Applications Défensives macOS

{{#include ../../banners/hacktricks-training.md}}

## Pare-feux

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html) : Il surveillera chaque connexion établie par chaque processus. Selon le mode (autoriser silencieusement les connexions, refuser silencieusement la connexion et alerter), il **vous montrera une alerte** chaque fois qu'une nouvelle connexion est établie. Il dispose également d'une très belle interface graphique pour voir toutes ces informations.
- [**LuLu**](https://objective-see.org/products/lulu.html) : Pare-feu d'Objective-See. C'est un pare-feu de base qui vous alertera pour des connexions suspectes (il a une interface graphique mais elle n'est pas aussi sophistiquée que celle de Little Snitch).

## Détection de persistance

- [**KnockKnock**](https://objective-see.org/products/knockknock.html) : Application d'Objective-See qui recherchera à plusieurs endroits où **le malware pourrait persister** (c'est un outil ponctuel, pas un service de surveillance).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html) : Comme KnockKnock, en surveillant les processus qui génèrent de la persistance.

## Détection de keyloggers

- [**ReiKey**](https://objective-see.org/products/reikey.html) : Application d'Objective-See pour trouver des **keyloggers** qui installent des "event taps" de clavier&#x20;

{{#include ../../banners/hacktricks-training.md}}
