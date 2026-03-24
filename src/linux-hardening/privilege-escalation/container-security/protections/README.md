# Aperçu des protections des conteneurs

{{#include ../../../../banners/hacktricks-training.md}}

L'idée la plus importante pour le hardening des conteneurs est qu'il n'existe pas un contrôle unique appelé "container security". Ce que les gens appellent isolation des conteneurs est en réalité le résultat de plusieurs mécanismes Linux de sécurité et de gestion des ressources qui fonctionnent ensemble. Si la documentation ne décrit qu'un seul de ces mécanismes, les lecteurs ont tendance à surestimer sa portée. Si la documentation en liste plusieurs sans expliquer leur interaction, les lecteurs obtiennent un catalogue de noms mais pas de modèle réel. Cette section essaie d'éviter ces deux erreurs.

Au centre du modèle se trouvent **namespaces**, qui isolent ce que la charge de travail peut voir. Ils donnent au processus une vue privée ou partiellement privée des points de montage du système de fichiers, des PIDs, du réseau, des objets IPC, des hostnames, des mappages user/group, des chemins cgroup, et de certains clocks. Mais les namespaces seuls ne déterminent pas ce qu'un processus est autorisé à faire. C'est là que les couches suivantes interviennent.

**cgroups** gouvernent l'utilisation des ressources. Ce ne sont pas principalement une frontière d'isolation au même titre que les mount ou PID namespaces, mais elles sont cruciales opérationnellement parce qu'elles contraignent la mémoire, le CPU, les PIDs, l'I/O et l'accès aux devices. Elles ont aussi une pertinence en sécurité car des techniques d'évasion historiques ont abusé de fonctionnalités cgroup inscriptibles, surtout dans des environnements cgroup v1.

**Capabilities** divisent l'ancien modèle root tout-puissant en unités de privilèges plus petites. C'est fondamental pour les conteneurs car de nombreuses charges de travail tournent encore en UID 0 à l'intérieur du conteneur. La question n'est donc pas seulement "le processus est-il root ?", mais plutôt "quelles capabilities ont survécu, à l'intérieur de quels namespaces, sous quelles restrictions seccomp et MAC ?" C'est pourquoi un processus root dans un conteneur peut être relativement contraint alors qu'un root dans un autre conteneur peut en pratique être presque indiscernable du root de l'hôte.

**seccomp** filtre les syscalls et réduit la surface d'attaque du noyau exposée à la charge de travail. C'est souvent le mécanisme qui bloque des appels manifestement dangereux comme `unshare`, `mount`, `keyctl`, ou d'autres syscalls utilisés dans des chaînes d'évasion. Même si un processus possède une capability qui autoriserait autrement une opération, seccomp peut encore bloquer le chemin syscall avant que le noyau ne le traite complètement.

**AppArmor** et **SELinux** ajoutent un Mandatory Access Control par-dessus les vérifications normales de fichiers et de privilèges. Ceux-ci sont particulièrement importants car ils continuent d'avoir de l'importance même lorsqu'un conteneur a plus de capabilities qu'il ne devrait. Une charge de travail peut théoriquement posséder le privilège pour tenter une action mais être quand même empêchée de l'exécuter parce que son label ou son profil interdit l'accès au chemin, à l'objet ou à l'opération concernés.

Enfin, il existe des couches de durcissement supplémentaires qui reçoivent moins d'attention mais qui comptent régulièrement dans de vraies attaques : `no_new_privs`, des chemins procfs masqués, des chemins système en lecture seule, des systèmes de fichiers root en lecture seule, et des defaults d'exécution soigneusement choisis. Ces mécanismes arrêtent souvent le "dernier kilomètre" d'une compromission, surtout lorsqu'un attaquant tente de transformer une exécution de code en un gain de privilèges plus large.

Le reste de ce dossier explique chacun de ces mécanismes en détail, y compris ce que la primitive du noyau fait réellement, comment l'observer localement, comment les runtimes courants l'utilisent, et comment les opérateurs l'affaiblissent accidentellement.

## À lire ensuite

{{#ref}}
namespaces/
{{#endref}}

{{#ref}}
cgroups.md
{{#endref}}

{{#ref}}
capabilities.md
{{#endref}}

{{#ref}}
seccomp.md
{{#endref}}

{{#ref}}
apparmor.md
{{#endref}}

{{#ref}}
selinux.md
{{#endref}}

{{#ref}}
no-new-privileges.md
{{#endref}}

{{#ref}}
masked-paths.md
{{#endref}}

{{#ref}}
read-only-paths.md
{{#endref}}

De nombreuses vraies évasions dépendent aussi du contenu de l'hôte qui a été monté dans la charge de travail, donc après avoir lu les protections de base il est utile de continuer avec :

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
{{#include ../../../../banners/hacktricks-training.md}}
