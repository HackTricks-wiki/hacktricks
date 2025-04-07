# Weaponizing Distroless

{{#include ../../../banners/hacktricks-training.md}}

## Qu'est-ce que Distroless

Un conteneur distroless est un type de conteneur qui **contient uniquement les dépendances nécessaires pour exécuter une application spécifique**, sans aucun logiciel ou outil supplémentaire qui n'est pas requis. Ces conteneurs sont conçus pour être aussi **légers** et **sécurisés** que possible, et ils visent à **minimiser la surface d'attaque** en supprimant les composants inutiles.

Les conteneurs distroless sont souvent utilisés dans des **environnements de production où la sécurité et la fiabilité sont primordiales**.

Quelques **exemples** de **conteneurs distroless** sont :

- Fournis par **Google** : [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
- Fournis par **Chainguard** : [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Weaponizing Distroless

L'objectif de l'armement d'un conteneur distroless est de pouvoir **exécuter des binaires et des charges utiles arbitraires même avec les limitations** imposées par **distroless** (absence de binaires communs dans le système) et également des protections couramment trouvées dans les conteneurs telles que **lecture seule** ou **non-exécution** dans `/dev/shm`.

### À travers la mémoire

Arrivant à un moment donné de 2023...

### Via des binaires existants

#### openssl

\***\*[**Dans cet article,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) il est expliqué que le binaire **`openssl`** se trouve fréquemment dans ces conteneurs, potentiellement parce qu'il est **nécessaire** pour le logiciel qui va s'exécuter à l'intérieur du conteneur.

{{#include ../../../banners/hacktricks-training.md}}
