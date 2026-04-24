# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` est une fonctionnalité de renforcement du kernel qui empêche un processus d’obtenir plus de privilege lors d’un `execve()`. En pratique, une fois le flag défini, l’exécution d’un binaire setuid, d’un binaire setgid, ou d’un fichier avec Linux file capabilities n’accorde pas de privilege supplémentaire au-delà de ce que le processus avait déjà. Dans les environnements containerized, c’est important car de nombreuses chaînes de privilege-escalation reposent sur la recherche d’un exécutable dans l’image qui change de privilege au lancement.

D’un point de vue défensif, `no_new_privs` ne remplace pas les namespaces, seccomp, ni la suppression des capabilities. C’est une couche de renforcement. Elle bloque une classe précise d’escalade de suivi après que l’exécution de code a déjà été obtenue. Cela la rend particulièrement utile dans les environnements où les images contiennent des binaires utilitaires, des artefacts de package-manager, ou des outils legacy qui seraient autrement dangereux combinés à une compromission partielle.

## Operation

Le flag du kernel derrière ce comportement est `PR_SET_NO_NEW_PRIVS`. Une fois défini pour un processus, les appels `execve()` suivants ne peuvent pas augmenter le privilege. Le détail important est que le processus peut toujours exécuter des binaires ; il ne peut simplement pas utiliser ces binaires pour franchir une frontière de privilege que le kernel aurait autrement respectée.

Le comportement du kernel est aussi **hérité et irréversible** : une fois qu’une tâche définit `no_new_privs`, le bit est hérité à travers `fork()`, `clone()`, et `execve()`, et ne peut pas être désactivé ensuite. C’est utile lors d’analyses car un seul `NoNewPrivs: 1` sur le processus du container signifie généralement que les descendants doivent aussi rester dans ce mode, sauf si vous regardez un arbre de processus complètement différent.

Dans les environnements orientés Kubernetes, `allowPrivilegeEscalation: false` correspond à ce comportement pour le processus du container. Dans les runtimes de type Docker et Podman, l’équivalent est généralement activé explicitement via une option de sécurité. Au niveau OCI, le même concept apparaît comme `process.noNewPrivileges`.

## Important Nuances

`no_new_privs` bloque l’augmentation de privilege **au moment de l’exec**, pas tous les changements de privilege. En particulier :

- les transitions setuid et setgid cessent de fonctionner à travers `execve()`
- les file capabilities n’ajoutent pas au set permis sur `execve()`
- les LSMs comme AppArmor ou SELinux ne relâchent pas les contraintes après `execve()`
- un privilege déjà détenu reste un privilege déjà détenu

Ce dernier point est important sur le plan opérationnel. Si le processus s’exécute déjà en root, possède déjà une capability dangereuse, ou a déjà accès à une API runtime puissante ou à un montage hôte inscriptible, définir `no_new_privs` ne neutralise pas ces expositions. Cela retire seulement une **étape suivante** fréquente dans une chaîne de privilege-escalation.

Notez aussi que le flag ne bloque pas les changements de privilege qui ne dépendent pas de `execve()`. Par exemple, une tâche déjà suffisamment privilégiée peut encore appeler directement `setuid(2)` ou recevoir un descripteur de fichier privilégié via un Unix socket. C’est pourquoi `no_new_privs` doit être lu avec [seccomp](seccomp.md), les capability sets, et l’exposition des namespaces, plutôt que comme une réponse autonome.

## Lab

Inspect the current process state:
```bash
grep NoNewPrivs /proc/self/status
```
Comparez cela avec un container où le runtime active le flag :
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Sur une workload durcie, le résultat devrait afficher `NoNewPrivs: 1`.

Vous pouvez aussi démontrer l’effet réel sur un binaire setuid :
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
Le point de la comparaison n’est pas que `su` soit universellement exploitable. Il s’agit du fait que la même image peut se comporter très différemment selon que `execve()` est encore autorisé à franchir une boundary de privilège.

## Security Impact

Si `no_new_privs` est absent, une foothold à l’intérieur du container peut encore être élevée via des helpers setuid ou des binaries avec des file capabilities. S’il est présent, ces changements de privilège post-`exec` sont bloqués. L’effet est particulièrement important dans les images de base larges qui embarquent de nombreux utilitaires dont l’application n’avait pas besoin au départ.

Il existe aussi une interaction importante avec seccomp. Les tâches non privilégiées ont généralement besoin que `no_new_privs` soit activé avant de pouvoir installer un filtre seccomp en mode filter. C’est l’une des raisons pour lesquelles les containers durcis affichent souvent à la fois `Seccomp` et `NoNewPrivs` activés ensemble. Du point de vue d’un attaquant, voir les deux signifie généralement que l’environnement a été configuré délibérément plutôt que par accident.

## Misconfigurations

Le problème le plus courant est simplement de ne pas activer le contrôle dans des environnements où il serait compatible. Dans Kubernetes, laisser `allowPrivilegeEscalation` activé est souvent l’erreur opérationnelle par défaut. Dans Docker et Podman, omettre l’option de sécurité pertinente produit le même effet. Un autre mode d’échec récurrent consiste à supposer que, parce qu’un container n’est pas "privileged", les transitions de privilège au moment de l’exec sont automatiquement sans importance.

Un écueil Kubernetes plus subtil est que `allowPrivilegeEscalation: false` n’est **pas** appliqué comme les gens s’y attendent lorsque le container est `privileged` ou lorsqu’il possède `CAP_SYS_ADMIN`. L’API Kubernetes documente que `allowPrivilegeEscalation` est en pratique toujours true dans ces cas. En pratique, cela signifie que le champ doit être traité comme un signal parmi d’autres dans la posture finale, et non comme une garantie que le runtime a fini avec `NoNewPrivs: 1`.

## Abuse

Si `no_new_privs` n’est pas défini, la première question est de savoir si l’image contient des binaries qui peuvent encore élever le privilège:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Résultats intéressants incluent :

- `NoNewPrivs: 0`
- des helpers setuid tels que `su`, `mount`, `passwd`, ou des outils d’administration spécifiques à la distribution
- des binaires avec des file capabilities qui accordent des privilèges réseau ou filesystem

Dans une évaluation réelle, ces findings ne prouvent pas à eux seuls une escalade fonctionnelle, mais ils identifient précisément les binaires à tester ensuite.

Dans Kubernetes, vérifiez aussi que l’intention du YAML correspond à la réalité du kernel :
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
Combinaisons intéressantes incluent :

- `allowPrivilegeEscalation: false` dans le Pod spec mais `NoNewPrivs: 0` dans le container
- `cap_sys_admin` présent, ce qui rend le champ Kubernetes bien moins fiable
- `Seccomp: 0` et `NoNewPrivs: 0`, ce qui indique généralement une posture runtime largement affaiblie plutôt qu’une seule erreur isolée

### Full Example: In-Container Privilege Escalation Through setuid

Ce contrôle empêche généralement l’**in-container privilege escalation** plutôt qu’un escape direct du host. Si `NoNewPrivs` est `0` et qu’un helper setuid existe, testez-le explicitement :
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Si un binaire setuid connu est présent et fonctionnel, essayez de le lancer d’une manière qui préserve la transition de privilèges :
```bash
/bin/su -c id 2>/dev/null
```
Cela, à lui seul, ne permet pas de s’échapper du container, mais cela peut transformer un point d’appui à faibles privilèges à l’intérieur du container en container-root, ce qui devient souvent le prérequis pour une future évasion de l’hôte via des mounts, des runtime sockets, ou des interfaces exposées au kernel.

## Checks

Le but de ces checks est de déterminer si l’élévation de privilèges au moment de l’exécution est bloquée et si l’image contient encore des helpers qui compteraient si ce n’est pas le cas.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
grep -E 'Seccomp|NoNewPrivs' /proc/self/status   # Whether seccomp and no_new_privs are both active
setpriv --dump 2>/dev/null | grep -i no-new-privs   # util-linux view if available
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt' 2>/dev/null   # Docker runtime options
kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}' 2>/dev/null
```
Ce qui est intéressant ici :

- `NoNewPrivs: 1` est généralement le résultat le plus sûr.
- `NoNewPrivs: 0` signifie que les chemins d'escalade basés sur setuid et file-cap restent pertinents.
- `NoNewPrivs: 1` avec `Seccomp: 2` est un signe courant d'une posture de hardening plus intentionnelle.
- Un manifest Kubernetes qui indique `allowPrivilegeEscalation: false` est utile, mais l'état du kernel est la source de vérité.
- Une image minimale avec peu ou pas de binaires setuid/file-cap donne à un attaquant moins d'options de post-exploitation même lorsque `no_new_privs` est absent.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Not enabled by default | Enabled explicitly with `--security-opt no-new-privileges=true`; daemon-wide default also exists via `dockerd --no-new-privileges` | omitting the flag, `--privileged` |
| Podman | Not enabled by default | Enabled explicitly with `--security-opt no-new-privileges` or equivalent security configuration | omitting the option, `--privileged` |
| Kubernetes | Controlled by workload policy | `allowPrivilegeEscalation: false` requests the effect, but `privileged: true` and `CAP_SYS_ADMIN` keep it effectively true | `allowPrivilegeEscalation: true`, `privileged: true`, adding `CAP_SYS_ADMIN` |
| containerd / CRI-O under Kubernetes | Follows Kubernetes workload settings / OCI `process.noNewPrivileges` | Usually inherited from the Pod security context and translated into OCI runtime config | same as Kubernetes row |

Cette protection est souvent absente simplement parce que personne ne l'a activée, et non parce que le runtime ne la prend pas en charge.

## References

- [Linux kernel documentation: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
{{#include ../../../../banners/hacktricks-training.md}}
