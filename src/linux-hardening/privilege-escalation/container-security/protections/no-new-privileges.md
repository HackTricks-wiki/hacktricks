# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` est une fonctionnalité de durcissement du kernel qui empêche un processus d'acquérir davantage de privilèges via `execve()`. En termes pratiques, une fois le flag activé, l'exécution d'un binaire setuid, d'un binaire setgid, ou d'un fichier avec des Linux file capabilities n'accorde pas de privilèges supplémentaires au-delà de ceux que le processus possédait déjà. Dans les environnements containerisés, c'est important car de nombreuses chaînes d'escalade de privilèges reposent sur la découverte d'un exécutable dans l'image qui change les privilèges lorsqu'il est lancé.

D'un point de vue défensif, `no_new_privs` ne remplace pas les namespaces, seccomp, ou le dropping des capabilities. C'est une couche de renforcement. Il bloque une classe spécifique d'escalades secondaires après qu'une exécution de code ait déjà été obtenue. Cela le rend particulièrement précieux dans des environnements où les images contiennent des helper binaries, des package-manager artifacts, ou des legacy tools qui seraient autrement dangereux combinés à une compromission partielle.

## Operation

Le flag kernel derrière ce comportement est `PR_SET_NO_NEW_PRIVS`. Une fois qu'il est défini pour un processus, les appels `execve()` ultérieurs ne peuvent pas augmenter les privilèges. Le détail important est que le processus peut toujours exécuter des binaires ; il ne peut simplement pas utiliser ces binaires pour franchir une frontière de privilèges que le kernel respecterait autrement.

Dans les environnements orientés Kubernetes, `allowPrivilegeEscalation: false` correspond à ce comportement pour le processus du container. Dans les runtimes de type Docker et Podman, l'équivalent est généralement activé explicitement via une option de sécurité.

## Lab

Inspectez l'état du processus courant :
```bash
grep NoNewPrivs /proc/self/status
```
Comparez cela avec un container où le runtime active le flag :
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Sur une charge de travail durcie, le résultat devrait afficher `NoNewPrivs: 1`.

## Impact sur la sécurité

Si `no_new_privs` est absent, une position établie à l'intérieur du conteneur peut encore être élevée via des helpers setuid ou des binaires avec file capabilities. S'il est présent, ces changements de privilèges post-exec sont interrompus. L'effet est particulièrement pertinent dans les images de base larges qui contiennent de nombreux utilitaires dont l'application n'avait jamais besoin.

## Mauvaises configurations

Le problème le plus courant est de ne tout simplement pas activer ce contrôle dans les environnements où il serait compatible. Dans Kubernetes, laisser `allowPrivilegeEscalation` activé est souvent l'erreur opérationnelle par défaut. Dans Docker et Podman, omettre l'option de sécurité pertinente a le même effet. Un autre mode d'échec récurrent est de supposer que parce qu'un conteneur est "not privileged", les transitions de privilèges au moment de l'exec sont automatiquement sans importance.

## Abus

Si `no_new_privs` n'est pas défini, la première question est de savoir si l'image contient des binaires qui peuvent encore élever les privilèges :
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Résultats intéressants incluent :

- `NoNewPrivs: 0`
- setuid helpers tels que `su`, `mount`, `passwd`, ou des outils d'administration spécifiques à la distribution
- binaires avec des file capabilities qui accordent des privilèges réseau ou sur le système de fichiers

Dans une évaluation réelle, ces découvertes ne prouvent pas à elles seules une escalation fonctionnelle, mais elles identifient exactement les binaires à tester ensuite.

### Exemple complet : In-Container Privilege Escalation Through setuid

Ce contrôle empêche généralement **in-container privilege escalation** plutôt qu'une évasion vers l'hôte directe. Si `NoNewPrivs` est `0` et qu'un setuid helper existe, testez-le explicitement :
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Si un binaire setuid connu est présent et fonctionnel, essayez de le lancer d'une manière qui préserve la transition de privilèges :
```bash
/bin/su -c id 2>/dev/null
```
Cela ne permet pas, en soi, d'escape the container, mais cela peut convertir un low-privilege foothold à l'intérieur du container en container-root, ce qui devient souvent le prérequis pour un host escape ultérieur via des mounts, des runtime sockets ou des kernel-facing interfaces.

## Vérifications

Le but de ces vérifications est d'établir si l'exec-time privilege gain est bloqué et si l'image contient encore des helpers qui importeraient si ce n'est pas le cas.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```
Ce qui est intéressant ici :

- `NoNewPrivs: 1` est généralement le résultat le plus sûr.
- `NoNewPrivs: 0` signifie que les voies d'escalade basées sur setuid et file-cap restent pertinentes.
- Une image minimale contenant peu ou aucun binaire setuid/file-cap offre à un attaquant moins d'options de post-exploitation, même lorsque `no_new_privs` est absent.

## Paramètres d'exécution par défaut

| Runtime / platform | État par défaut | Comportement par défaut | Affaiblissement manuel courant |
| --- | --- | --- | --- |
| Docker Engine | Non activé par défaut | Activé explicitement avec `--security-opt no-new-privileges=true` | omettant le flag, `--privileged` |
| Podman | Non activé par défaut | Activé explicitement avec `--security-opt no-new-privileges` ou une configuration de sécurité équivalente | omettant l'option, `--privileged` |
| Kubernetes | Contrôlé par la politique de workload | `allowPrivilegeEscalation: false` active l'effet ; de nombreux workloads le laissent encore activé | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Suit les paramètres des workloads Kubernetes | Généralement hérité du contexte de sécurité du Pod | identique à la ligne Kubernetes |

Cette protection est souvent absente simplement parce que personne ne l'a activée, et non pas parce que le runtime ne la prend pas en charge.
