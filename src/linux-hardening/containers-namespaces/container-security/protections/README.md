# Vue d’ensemble des protections des containers

{{#include ../../../../banners/hacktricks-training.md}}

L’idée la plus importante du hardening des containers est qu’il n’existe pas de contrôle unique appelé « container security ». Ce que l’on appelle l’isolation des containers est en réalité le résultat de plusieurs mécanismes Linux de sécurité et de gestion des ressources qui fonctionnent ensemble. Si la documentation ne décrit qu’un seul d’entre eux, les lecteurs ont tendance à surestimer sa robustesse. Si elle les énumère tous sans expliquer leurs interactions, les lecteurs obtiennent un catalogue de noms, mais aucun modèle réel. Cette section tente d’éviter ces deux erreurs.

Au centre du modèle se trouvent les **namespaces**, qui isolent ce que le workload peut voir. Ils donnent au processus une vue privée ou partiellement privée des mounts du filesystem, des PIDs, du networking, des objets IPC, des hostnames, des mappings utilisateur/groupe, des chemins de cgroups et de certaines horloges. Mais les namespaces seuls ne déterminent pas ce qu’un processus est autorisé à faire. C’est là qu’interviennent les couches suivantes.

Les **cgroups** régissent l’utilisation des ressources. Ils ne constituent pas principalement une frontière d’isolation au même sens que les namespaces de mount ou de PID, mais ils sont essentiels sur le plan opérationnel, car ils limitent la mémoire, le CPU, les PIDs, les I/O et l’accès aux devices. Ils ont également une importance en matière de sécurité, car des techniques historiques de breakout ont exploité des fonctionnalités de cgroups accessibles en écriture, en particulier dans les environnements cgroup v1.

Les **Capabilities** divisent l’ancien modèle de root tout-puissant en unités de privilèges plus petites. C’est fondamental pour les containers, car de nombreux workloads s’exécutent toujours avec l’UID 0 à l’intérieur du container. La question n’est donc pas simplement « le processus est-il root ? », mais plutôt « quelles capabilities ont été conservées, dans quels namespaces, et sous quelles restrictions seccomp et MAC ? » C’est pourquoi un processus root dans un container peut être relativement limité, tandis qu’un processus root dans un autre container peut être presque impossible à distinguer de root sur l’host en pratique.

**seccomp** filtre les syscalls et réduit la surface d’attaque du kernel exposée au workload. Il s’agit souvent du mécanisme qui bloque les appels manifestement dangereux tels que `unshare`, `mount`, `keyctl` ou d’autres syscalls utilisés dans les chaînes de breakout. Même si un processus possède une capability qui permettrait autrement une opération, seccomp peut tout de même bloquer le chemin du syscall avant que le kernel ne le traite entièrement.

**AppArmor** et **SELinux** ajoutent un Mandatory Access Control par-dessus les vérifications normales du filesystem et des privilèges. Ces mécanismes sont particulièrement importants, car ils continuent de jouer un rôle même lorsqu’un container possède plus de capabilities qu’il ne devrait. Un workload peut disposer du privilège théorique nécessaire pour tenter une action, tout en étant empêché de l’exécuter parce que son label ou son profile interdit l’accès au chemin, à l’objet ou à l’opération concerné.

Enfin, d’autres couches de hardening reçoivent moins d’attention, mais jouent régulièrement un rôle dans les attaques réelles : `no_new_privs`, les chemins procfs masqués, les chemins système en lecture seule, les root filesystems en lecture seule et des valeurs par défaut soigneusement configurées pour le runtime. Ces mécanismes empêchent souvent la « dernière étape » d’une compromission, en particulier lorsqu’un attaquant tente de transformer une exécution de code en élévation de privilèges plus large.

Le reste de ce dossier explique chacun de ces mécanismes plus en détail, notamment ce que fait réellement la primitive du kernel, comment l’observer localement, comment les runtimes courants l’utilisent et comment les operators l’affaiblissent accidentellement.

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

De nombreux escapes réels dépendent également du contenu de l’host qui a été monté dans le workload. Après avoir lu les protections principales, il est donc utile de poursuivre avec :

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
{{#include ../../../../banners/hacktricks-training.md}}
