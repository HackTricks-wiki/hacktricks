# Fichiers intéressants et permissions

{{#include ../../banners/hacktricks-training.md}}

La propriété des fichiers, les droits d’écriture, les options de montage et les privilèges d’exécution peuvent modifier les capacités effectives d’un utilisateur local. Commencez par identifier le fichier ou le chemin d’exécution ciblé, puis consultez la page pertinente :

- [SUID, SGID, ACLs et fichiers sensibles](suid-sgid-and-acl-triage.md) propose une première méthode pour examiner les privilèges d’exécution et les droits d’accès cachés.
- [Écriture arbitraire de fichiers en tant que root](write-to-root.md) décrit comment exploiter l’écriture dans des chemins privilégiés pour obtenir une élévation de privilèges.
- [Capacités Linux](linux-capabilities.md) explique les capacités par processus et par fichier.
- [Abus des bibliothèques partagées SUID et de l’éditeur de liens](suid-shared-library-and-linker-abuse.md) traite du chargement dynamique autour des binaires privilégiés.
- [Exemple d’élévation de privilèges avec `ld.so`](ld.so.conf-example.md) présente un cas lié à la configuration de l’éditeur de liens.
- [Mauvaise configuration NFS `no_root_squash` et `no_all_squash`](nfs-no_root_squash-misconfiguration-pe.md) traite du mappage des identités sur les systèmes de fichiers distants.
- [Wildcard spare tricks](wildcards-spare-tricks.md) traite de l’expansion des arguments dans les commandes privilégiées.
- [SELinux](selinux.md) explique l’application des politiques et les étapes d’investigation pertinentes.
{{#include ../../banners/hacktricks-training.md}}
