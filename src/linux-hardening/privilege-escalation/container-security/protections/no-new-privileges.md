# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` est une fonctionnalité de durcissement du kernel qui empêche un processus d'obtenir plus de privilèges via `execve()`. En pratique, une fois le flag activé, l'exécution d'un binaire setuid, d'un binaire setgid, ou d'un fichier avec Linux file capabilities n'accorde pas de privilèges supplémentaires au-delà de ceux que possédait déjà le processus. Dans les environnements containerisés, cela importe car de nombreuses chaînes de privilege-escalation reposent sur la présence d'un exécutable dans l'image qui change les privilèges lorsqu'il est lancé.

Du point de vue défensif, `no_new_privs` ne remplace pas namespaces, seccomp, ou capability dropping. C'est une couche de renforcement. Il bloque une classe spécifique d'escalade de suivi après que l'exécution de code ait déjà été obtenue. Cela le rend particulièrement précieux dans les environnements où les images contiennent des helper binaries, des package-manager artifacts, ou des legacy tools qui seraient autrement dangereux lorsqu'ils sont combinés à une compromission partielle.

## Fonctionnement

Le flag kernel derrière ce comportement est `PR_SET_NO_NEW_PRIVS`. Une fois qu'il est défini pour un processus, les appels `execve()` ultérieurs ne peuvent pas augmenter les privilèges. Le détail important est que le processus peut toujours exécuter des binaires ; il ne peut simplement pas utiliser ces binaires pour franchir une privilege boundary que le kernel honorerait autrement.

Dans les environnements orientés Kubernetes, `allowPrivilegeEscalation: false` correspond à ce comportement pour le processus du conteneur. Dans les runtimes de type Docker et Podman, l'équivalent est généralement activé explicitement via une option de sécurité.

## Lab

Inspecter l'état du processus courant :
```bash
grep NoNewPrivs /proc/self/status
```
Comparez cela avec un conteneur où le runtime active le flag:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
On a hardened workload, the result should show `NoNewPrivs: 1`.

## Impact sur la sécurité

Si `no_new_privs` est absent, une position à l'intérieur du conteneur peut encore être escaladée via des helpers setuid ou des binaires avec file capabilities. S'il est présent, ces changements de privilèges post-exec sont interrompus. L'effet est particulièrement pertinent dans des images de base générales qui embarquent de nombreux utilitaires dont l'application n'avait pas besoin à l'origine.

## Mauvaises configurations

Le problème le plus courant est simplement de ne pas activer le contrôle dans des environnements où il serait compatible. Dans Kubernetes, laisser `allowPrivilegeEscalation` activé est souvent l'erreur opérationnelle par défaut. Dans Docker et Podman, omettre l'option de sécurité pertinente produit le même effet. Un autre mode d'échec récurrent est de supposer que parce qu'un conteneur est "pas privilégié", les transitions de privilèges au moment de l'exec sont automatiquement sans importance.

## Abus

Si `no_new_privs` n'est pas défini, la première question est de savoir si l'image contient des binaires pouvant toujours élever les privilèges :
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Interesting results include:

- `NoNewPrivs: 0`
- binaires setuid tels que `su`, `mount`, `passwd`, ou des outils d'administration spécifiques à la distribution
- binaires avec des file capabilities qui accordent des privilèges réseau ou sur le système de fichiers

Dans une évaluation réelle, ces constats ne prouvent pas à eux seuls qu'une escalade fonctionne, mais ils identifient précisément les binaires qu'il convient de tester ensuite.

### Exemple complet : Escalade de privilèges dans le conteneur via setuid

Ce contrôle empêche généralement une **escalade de privilèges dans le conteneur** plutôt que l'évasion vers l'hôte. Si `NoNewPrivs` est `0` et qu'un helper setuid existe, testez-le explicitement:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Si un binaire setuid connu est présent et fonctionnel, essayez de le lancer d'une manière qui préserve la transition de privilèges :
```bash
/bin/su -c id 2>/dev/null
```
Ce mécanisme n'échappe pas au conteneur en soi, mais il peut convertir un accès initial à faibles privilèges à l'intérieur du conteneur en root du conteneur, ce qui devient souvent le prérequis pour une évasion ultérieure vers l'hôte via des points de montage, des sockets runtime ou des interfaces exposées au noyau.

## Vérifications

L'objectif de ces vérifications est de déterminer si la montée de privilèges au moment de l'exécution (exec-time) est bloquée et si l'image contient encore des helpers qui seraient pertinents si ce n'était pas le cas.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```
Ce qui est intéressant ici :

- `NoNewPrivs: 1` est généralement le résultat le plus sûr.
- `NoNewPrivs: 0` signifie que les voies d'escalade basées sur setuid et file-cap restent pertinentes.
- Une image minimale avec peu ou pas de setuid/file-cap binaries offre à un attaquant moins d'options de post-exploitation même lorsque `no_new_privs` est absent.

## Valeurs par défaut à l'exécution

| Runtime / plateforme | État par défaut | Comportement par défaut | Affaiblissement manuel courant |
| --- | --- | --- | --- |
| Docker Engine | Pas activé par défaut | Activé explicitement avec `--security-opt no-new-privileges=true` | en omettant le flag, `--privileged` |
| Podman | Pas activé par défaut | Activé explicitement avec `--security-opt no-new-privileges` ou une configuration de sécurité équivalente | en omettant l'option, `--privileged` |
| Kubernetes | Contrôlé par la politique de la charge de travail | `allowPrivilegeEscalation: false` enables the effect; many workloads still leave it enabled | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Suit les paramètres de charge de travail de Kubernetes | Généralement hérité du Pod security context | identique à la ligne Kubernetes |

Cette protection est souvent absente simplement parce que personne ne l'a activée, et non parce que le runtime ne la prend pas en charge.
{{#include ../../../../banners/hacktricks-training.md}}
