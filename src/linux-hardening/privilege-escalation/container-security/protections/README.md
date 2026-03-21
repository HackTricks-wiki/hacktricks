# Aperçu des protections des containers

{{#include ../../../../banners/hacktricks-training.md}}

L'idée la plus importante dans le durcissement des containers est qu'il n'existe pas un contrôle unique appelé "container security". Ce que l'on appelle container isolation est en réalité le résultat de plusieurs mécanismes Linux de sécurité et de gestion des ressources qui fonctionnent ensemble. Si la documentation décrit un seul de ces mécanismes, les lecteurs ont tendance à surestimer sa portée. Si la documentation énumère tous les mécanismes sans expliquer comment ils interagissent, les lecteurs obtiennent un catalogue de noms mais pas de modèle réel. Cette section essaie d'éviter ces deux erreurs.

Au centre du modèle se trouvent **namespaces**, qui isolent ce que la charge de travail peut voir. Ils offrent au processus une vue privée ou partiellement privée des montages du système de fichiers, des PIDs, du réseau, des objets IPC, des noms d'hôte, des mappages utilisateur/groupe, des chemins cgroup et de certaines horloges. Mais les namespaces seuls ne déterminent pas ce qu'un processus est autorisé à faire. C'est là que les couches suivantes entrent en jeu.

**cgroups** régissent l'utilisation des ressources. Ils ne constituent pas principalement une frontière d'isolation au même titre que les mount ou PID namespaces, mais ils sont cruciaux opérationnellement car ils contraignent la mémoire, le CPU, les PIDs, les entrées/sorties et l'accès aux périphériques. Ils ont aussi une pertinence en matière de sécurité parce que des techniques historiques d'évasion ont abusé de fonctionnalités cgroup modifiables, notamment dans les environnements cgroup v1.

**Capabilities** divisent l'ancien modèle root tout-puissant en unités de privilèges plus petites. C'est fondamental pour les containers car beaucoup de charges de travail tournent encore en UID 0 à l'intérieur du container. La question n'est donc pas simplement « le processus est-il root ? », mais plutôt « quelles capabilities ont survécu, dans quels namespaces, sous quelles restrictions seccomp et MAC ? » C'est pourquoi un processus root dans un container peut être relativement contraint tandis qu'un processus root dans un autre container peut, en pratique, être presque indiscernable du root de l'hôte.

**seccomp** filtre les appels système et réduit la surface d'attaque du kernel exposée à la charge de travail. C'est souvent le mécanisme qui bloque des appels manifestement dangereux tels que `unshare`, `mount`, `keyctl`, ou d'autres syscalls utilisés dans des chaînes d'évasion. Même si un processus possède une capability qui permettrait autrement une opération, seccomp peut quand même bloquer la voie d'appel système avant que le kernel ne la traite complètement.

**AppArmor** et **SELinux** ajoutent un contrôle d'accès obligatoire (Mandatory Access Control) au-dessus des vérifications normales du système de fichiers et des privilèges. Ceux-ci sont particulièrement importants car ils continuent d'avoir un effet même lorsqu'un container possède plus de capabilities qu'il ne devrait. Une charge de travail peut théoriquement avoir le privilège d'essayer une action mais être empêchée de l'exécuter parce que son label ou son profil interdit l'accès au chemin, à l'objet ou à l'opération concernés.

Enfin, il existe d'autres couches de durcissement qui reçoivent moins d'attention mais qui importent régulièrement dans les attaques réelles : `no_new_privs`, chemins procfs masqués, chemins système en lecture seule, systèmes de fichiers root en lecture seule, et des valeurs par défaut d'exécution prudentes. Ces mécanismes arrêtent souvent la « dernière étape » d'une compromission, surtout lorsqu'un attaquant tente de transformer une exécution de code en un gain de privilèges plus large.

Le reste de ce dossier explique chacun de ces mécanismes en plus de détails, y compris ce que le primitif du kernel fait réellement, comment l'observer localement, comment les runtimes courants l'utilisent, et comment les opérateurs l'affaiblissent accidentellement.

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

Many real escapes also depend on what host content was mounted into the workload, so after reading the core protections it is useful to continue with:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
