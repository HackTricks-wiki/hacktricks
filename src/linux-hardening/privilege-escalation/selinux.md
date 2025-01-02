{{#include ../../banners/hacktricks-training.md}}

# SELinux dans les conteneurs

[Introduction et exemple des docs redhat](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux) est un **système de labellisation**. Chaque **processus** et chaque objet de système de fichiers a un **label**. Les politiques SELinux définissent des règles sur ce qu'un **label de processus est autorisé à faire avec tous les autres labels** sur le système.

Les moteurs de conteneurs lancent des **processus de conteneur avec un seul label SELinux confiné**, généralement `container_t`, puis définissent le conteneur à l'intérieur du conteneur pour être labellisé `container_file_t`. Les règles de politique SELinux disent essentiellement que les **processus `container_t` ne peuvent lire/écrire/exécuter que des fichiers labellisés `container_file_t`**. Si un processus de conteneur s'échappe du conteneur et tente d'écrire sur le contenu de l'hôte, le noyau Linux refuse l'accès et ne permet au processus de conteneur d'écrire que sur le contenu labellisé `container_file_t`.
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
# Utilisateurs SELinux

Il existe des utilisateurs SELinux en plus des utilisateurs Linux réguliers. Les utilisateurs SELinux font partie d'une politique SELinux. Chaque utilisateur Linux est mappé à un utilisateur SELinux dans le cadre de la politique. Cela permet aux utilisateurs Linux d'hériter des restrictions et des règles de sécurité et des mécanismes imposés aux utilisateurs SELinux.

{{#include ../../banners/hacktricks-training.md}}
