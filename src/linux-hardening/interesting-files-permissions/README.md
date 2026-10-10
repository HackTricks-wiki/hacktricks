# Fichiers intéressants et permissions

{{#include ../../banners/hacktricks-training.md}}

La propriété des fichiers, les droits d’écriture, les options de montage et les privilèges d’exécution peuvent modifier les accès effectifs d’un utilisateur local. Commencez par identifier le fichier ou le chemin d’exécution ciblé, puis consultez la page correspondante :

- [SUID, SGID, ACL et fichiers sensibles](suid-sgid-and-acl-triage.md) propose une méthode de départ pour examiner les privilèges d’exécution et les droits d’accès cachés.
- [Écriture arbitraire dans les fichiers de root](write-to-root.md) décrit comment des écritures dans des chemins privilégiés peuvent être exploitées pour obtenir une élévation de privilèges.
- [Capacités Linux](linux-capabilities.md) explique les capacités par processus et par fichier.
- [Abus des bibliothèques partagées et de l’éditeur de liens avec SUID](suid-shared-library-and-linker-abuse.md) traite du chargement dynamique autour des binaires privilégiés.
- [Exemple d’élévation de privilèges avec `ld.so`](ld.so.conf-example.md) présente un cas de configuration de l’éditeur de liens.
- [Mauvaise configuration NFS avec `no_root_squash` et `no_all_squash`](nfs-no_root_squash-misconfiguration-pe.md) traite du mappage des identités sur les systèmes de fichiers distants.
- [Astuces avec les caractères génériques](wildcards-spare-tricks.md) traite de l’expansion des arguments dans les commandes privilégiées.
- [SELinux](selinux.md) explique l’application des politiques et les étapes d’investigation pertinentes.
{{#include ../../banners/hacktricks-training.md}}
