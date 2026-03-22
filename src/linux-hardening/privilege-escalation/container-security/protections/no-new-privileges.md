# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` est une fonctionnalité de durcissement du kernel qui empêche un processus d'obtenir davantage de privilèges lors d'un `execve()`. Concrètement, une fois le flag activé, l'exécution d'un binaire setuid, d'un binaire setgid, ou d'un fichier avec Linux file capabilities n'accorde pas de privilèges supplémentaires au-delà de ceux que le processus possédait déjà. Dans les environnements conteneurisés, cela est important car de nombreuses chaînes d'escalade de privilèges dépendent de la présence d'un exécutable dans l'image qui modifie les privilèges lorsqu'il est lancé.

D'un point de vue défensif, `no_new_privs` ne remplace pas namespaces, seccomp, ni la suppression des capabilities. C'est une couche de renforcement. Elle bloque une catégorie spécifique d'escalades complémentaires après qu'une exécution de code ait déjà été obtenue. Cela la rend particulièrement utile dans les environnements où les images contiennent des binaires d'assistance, des artefacts de gestionnaire de paquets, ou des outils hérités qui seraient autrement dangereux lorsqu'ils sont combinés avec une compromission partielle.

## Operation

Le flag du kernel responsable de ce comportement est `PR_SET_NO_NEW_PRIVS`. Une fois qu'il est défini pour un processus, les appels `execve()` ultérieurs ne peuvent pas augmenter les privilèges. Le détail important est que le processus peut toujours exécuter des binaires ; il ne peut simplement pas utiliser ces binaires pour franchir une frontière de privilèges que le kernel honorerait autrement.

Dans les environnements orientés Kubernetes, `allowPrivilegeEscalation: false` correspond à ce comportement pour le processus du conteneur. Dans les runtimes de type Docker et Podman, l'équivalent est généralement activé explicitement via une option de sécurité.

## Lab

Inspectez l'état actuel du processus :
```bash
grep NoNewPrivs /proc/self/status
```
Comparez cela avec un container où le runtime active le flag :
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Sur une charge de travail durcie, le résultat doit afficher `NoNewPrivs: 1`.

## Impact sur la sécurité

Si `no_new_privs` est absent, un point d'appui à l'intérieur du conteneur peut encore être élevé via des helpers setuid ou des binaires avec file capabilities. S'il est présent, ces changements de privilèges post-exec sont coupés. L'effet est particulièrement pertinent dans les images de base larges qui incluent de nombreux utilitaires dont l'application n'avait jamais besoin à l'origine.

## Mauvaises configurations

Le problème le plus courant est simplement de ne pas activer le contrôle dans des environnements où il serait compatible. Dans Kubernetes, laisser `allowPrivilegeEscalation` activé est souvent l'erreur opérationnelle par défaut. Dans Docker et Podman, omettre l'option de sécurité pertinente a le même effet. Un autre mode d'échec récurrent est de supposer que parce qu'un conteneur est "not privileged", les transitions de privilèges au moment de l'exec sont automatiquement sans importance.

## Abus

Si `no_new_privs` n'est pas défini, la première question est de savoir si l'image contient des binaires pouvant encore élever les privilèges :
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Résultats intéressants incluent:

- `NoNewPrivs: 0`
- setuid helpers tels que `su`, `mount`, `passwd` ou des outils d'administration spécifiques à la distribution
- binaires présentant des file capabilities qui accordent des privilèges réseau ou système de fichiers

Lors d'une évaluation réelle, ces découvertes ne prouvent pas à elles seules qu'une escalation fonctionne, mais elles identifient exactement les binaires qu'il convient de tester ensuite.

### Exemple complet : In-Container Privilege Escalation Through setuid

Ce contrôle empêche généralement **in-container privilege escalation** plutôt que l'évasion directe de l'hôte. Si `NoNewPrivs` est `0` et qu'un setuid helper existe, testez-le explicitement:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
S'il existe un binaire setuid connu et fonctionnel, essayez de le lancer d'une manière qui préserve la transition de privilèges :
```bash
/bin/su -c id 2>/dev/null
```
Cela n'entraîne pas à lui seul une sortie du conteneur, mais peut transformer une implantation à faibles privilèges à l'intérieur du conteneur en container-root, ce qui devient souvent le prérequis pour une host escape ultérieure via des mounts, des runtime sockets ou des interfaces exposées au kernel.

## Vérifications

L'objectif de ces vérifications est de déterminer si l'obtention de privilèges au moment de l'exécution (exec-time privilege gain) est bloquée et si l'image contient encore des helpers qui importeraient si ce n'est pas le cas.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```
Qu'est-ce qui est intéressant ici :

- `NoNewPrivs: 1` est généralement le résultat le plus sûr.
- `NoNewPrivs: 0` signifie que les voies d'escalade basées sur setuid et file-cap restent pertinentes.
- Une image minimale avec peu ou pas de binaires setuid/file-cap offre à un attaquant moins d'options de post-exploitation même lorsque `no_new_privs` est absent.

## Paramètres d'exécution par défaut

| Runtime / plateforme | État par défaut | Comportement par défaut | Affaiblissement manuel courant |
| --- | --- | --- | --- |
| Docker Engine | Non activé par défaut | Activé explicitement avec `--security-opt no-new-privileges=true` | ne pas spécifier le flag, `--privileged` |
| Podman | Non activé par défaut | Activé explicitement avec `--security-opt no-new-privileges` ou une configuration de sécurité équivalente | ne pas spécifier l'option, `--privileged` |
| Kubernetes | Contrôlé par la politique de la charge de travail | `allowPrivilegeEscalation: false` active l'effet ; de nombreuses charges de travail le laissent encore activé | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Suit les paramètres de charge de travail Kubernetes | Généralement hérité du contexte de sécurité du Pod | identique à la ligne Kubernetes |

Cette protection est souvent absente simplement parce que personne ne l'a activée, et non parce que le runtime ne la prend pas en charge.
{{#include ../../../../banners/hacktricks-training.md}}
