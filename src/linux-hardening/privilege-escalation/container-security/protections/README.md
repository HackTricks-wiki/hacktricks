# Vue d'ensemble des protections des conteneurs

{{#include ../../../../banners/hacktricks-training.md}}

L'idée la plus importante dans le durcissement des conteneurs est qu'il n'existe pas un contrôle unique appelé "container security". Ce que l'on appelle isolation des conteneurs est en réalité le résultat de plusieurs mécanismes Linux de sécurité et de gestion des ressources qui fonctionnent ensemble. Si la documentation décrit un seul de ces mécanismes, les lecteurs ont tendance à surestimer sa portée. Si la documentation énumère tous les mécanismes sans expliquer comment ils interagissent, les lecteurs obtiennent un catalogue de noms mais pas de modèle réel. Cette section tente d'éviter ces deux erreurs.

Au centre du modèle se trouvent **namespaces**, qui isolent ce que la charge de travail peut voir. Ils donnent au processus une vue privée ou partiellement privée des montages de systèmes de fichiers, des PIDs, du réseau, des objets IPC, des hostnames, des mappings utilisateur/groupe, des chemins cgroup, et de certains horloges. Mais les namespaces seuls ne déterminent pas ce qu'un processus est autorisé à faire. C'est là que les couches suivantes interviennent.

Les **cgroups** régissent l'utilisation des ressources. Ils ne constituent pas principalement une frontière d'isolation au même titre que les mount ou PID namespaces, mais ils sont cruciaux sur le plan opérationnel parce qu'ils contraignent la mémoire, le CPU, les PIDs, l'I/O et l'accès aux périphériques. Ils ont aussi une pertinence en matière de sécurité parce que des techniques historiques d'évasion ont abusé de fonctionnalités cgroup modifiables, en particulier dans des environnements cgroup v1.

Les **Capabilities** divisent l'ancien modèle root tout-puissant en unités de privilèges plus petites. C'est fondamental pour les conteneurs parce que de nombreuses charges de travail tournent encore en UID 0 à l'intérieur du conteneur. La question n'est donc pas simplement "le processus est-il root ?", mais plutôt "quelles capabilities ont survécu, à l'intérieur de quels namespaces, sous quelles restrictions seccomp et MAC ?" C'est pour cela qu'un processus root dans un conteneur peut être relativement contraint tandis qu'un processus root dans un autre conteneur peut, en pratique, être presque indiscernable du root de l'hôte.

**seccomp** filtre les appels système et réduit la surface d'attaque du kernel exposée à la charge de travail. C'est souvent le mécanisme qui bloque des appels manifestement dangereux comme `unshare`, `mount`, `keyctl`, ou d'autres syscalls utilisés dans des chaînes d'évasion. Même si un processus dispose d'une capability qui permettrait autrement une opération, seccomp peut quand même bloquer le chemin de l'appel système avant que le kernel ne le traite complètement.

**AppArmor** et **SELinux** ajoutent un Mandatory Access Control au-dessus des vérifications normales de système de fichiers et de privilèges. Ils sont particulièrement importants parce qu'ils continuent à avoir un effet même lorsqu'un conteneur possède plus de capabilities qu'il ne devrait. Une charge de travail peut théoriquement posséder le privilège d'essayer une action mais être empêchée de l'exécuter parce que son label ou son profil interdit l'accès au chemin, à l'objet ou à l'opération concernés.

Enfin, il existe des couches de durcissement supplémentaires qui reçoivent moins d'attention mais qui comptent régulièrement dans de vraies attaques : `no_new_privs`, des chemins procfs masqués, des chemins système en lecture seule, des root filesystems en lecture seule, et des valeurs par défaut runtime prudentes. Ces mécanismes arrêtent souvent le "dernier kilomètre" d'une compromission, en particulier lorsqu'un attaquant tente de transformer une exécution de code en un gain de privilèges plus large.

Le reste de ce dossier explique chacun de ces mécanismes plus en détail, y compris ce que le primitive kernel fait réellement, comment l'observer localement, comment les runtimes courants l'utilisent, et comment les opérateurs l'affaiblissent accidentellement.

## Lire ensuite

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

De nombreuses échappées réelles dépendent aussi du contenu hôte monté dans la charge de travail, donc après avoir lu les protections de base il est utile de continuer avec :

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
{{#include ../../../../banners/hacktricks-training.md}}
