# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` est une fonctionnalité de hardening du kernel qui empêche un processus d'obtenir davantage de privilèges via `execve()`. En pratique, une fois le flag défini, l'exécution d'un binaire setuid, d'un binaire setgid ou d'un fichier doté de Linux file capabilities n'accorde aucun privilège supplémentaire au-delà de ceux que le processus possédait déjà. Dans les environnements containerisés, c'est important, car de nombreuses chaînes d'escalade de privilèges reposent sur la découverte, dans l'image, d'un exécutable qui modifie les privilèges au lancement.

D'un point de vue défensif, `no_new_privs` ne remplace pas les namespaces, seccomp ou la suppression de capabilities. C'est une couche de renforcement supplémentaire. Elle bloque une classe spécifique d'escalade ultérieure après l'obtention initiale d'une exécution de code. Cela la rend particulièrement utile dans les environnements où les images contiennent des binaires auxiliaires, des artefacts de package managers ou des outils legacy qui seraient autrement dangereux s'ils étaient combinés à une compromission partielle.

## Fonctionnement

Le flag du kernel à l'origine de ce comportement est `PR_SET_NO_NEW_PRIVS`. Une fois défini pour un processus, les appels ultérieurs à `execve()` ne peuvent pas augmenter les privilèges. Le point important est que le processus peut toujours exécuter des binaires ; il ne peut simplement pas utiliser ces binaires pour franchir une frontière de privilèges que le kernel aurait autrement respectée.

Le comportement du kernel est également **hérité et irréversible** : une fois qu'une task définit `no_new_privs`, le bit est hérité à travers `fork()`, `clone()` et `execve()`, et ne peut plus être désactivé. C'est utile lors des assessments, car un `NoNewPrivs: 1` sur le processus du container signifie généralement que ses descendants devraient eux aussi rester dans ce mode, sauf si vous examinez un arbre de processus complètement différent.

Dans les environnements orientés Kubernetes, `allowPrivilegeEscalation: false` correspond à ce comportement pour le processus du container. Dans les runtimes de type Docker et Podman, l'équivalent est généralement activé explicitement via une security option. Au niveau OCI, le même concept apparaît sous la forme `process.noNewPrivileges`.

## Nuances importantes

`no_new_privs` bloque l'augmentation de privilèges **au moment de l'exécution**, et non chaque changement de privilèges. En particulier :

- les transitions setuid et setgid cessent de fonctionner via `execve()`
- les file capabilities n'ajoutent rien à l'ensemble permitted lors de `execve()`
- les LSM tels qu'AppArmor ou SELinux n'assouplissent pas leurs contraintes après `execve()`
- les privilèges déjà détenus restent des privilèges déjà détenus

Ce dernier point est important sur le plan opérationnel. Si le processus s'exécute déjà en tant que root, possède déjà une capability dangereuse ou a déjà accès à une API de runtime puissante ou à un host mount inscriptible, la définition de `no_new_privs` ne neutralise pas ces expositions. Elle supprime uniquement une **étape suivante** courante d'une chaîne d'escalade de privilèges.

Notez également que le flag ne bloque pas les changements de privilèges qui ne dépendent pas de `execve()`. Par exemple, une task disposant déjà de privilèges suffisants peut toujours appeler directement `setuid(2)` ou recevoir un descripteur de fichier privilégié via un socket Unix. C'est pourquoi `no_new_privs` doit être examiné conjointement avec [seccomp](seccomp.md), les capability sets et l'exposition des namespaces, plutôt que comme une réponse autonome.

## Lab

Inspectez l'état du processus actuel :
```bash
grep NoNewPrivs /proc/self/status
```
Comparez cela avec un container où le runtime active le flag :
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Sur une workload renforcée, le résultat devrait afficher `NoNewPrivs: 1`.

Vous pouvez également démontrer l'effet réel sur un binaire setuid :
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
Le but de la comparaison n’est pas que `su` soit universellement exploitable. Il est que la même image puisse se comporter très différemment selon que `execve()` est toujours autorisé à franchir une frontière de privilèges.

## Impact sur la sécurité

Si `no_new_privs` est absent, un foothold à l’intérieur du container peut encore être élevé via des helpers setuid ou des binaries dotés de file capabilities. S’il est présent, ces changements de privilèges post-exec sont bloqués. Cet effet est particulièrement pertinent dans les images de base larges qui fournissent de nombreux utilitaires dont l’application n’avait jamais besoin.

Il existe également une interaction importante avec seccomp. Les tâches non privilégiées doivent généralement définir `no_new_privs` avant de pouvoir installer un filtre seccomp en mode filter. C’est l’une des raisons pour lesquelles les containers durcis affichent souvent `Seccomp` et `NoNewPrivs` activés simultanément. Du point de vue de l’attaquant, la présence des deux indique généralement que l’environnement a été configuré délibérément plutôt que par accident.

## Mauvaises configurations

Le problème le plus courant consiste simplement à ne pas activer ce contrôle dans les environnements où il serait compatible. Dans Kubernetes, laisser `allowPrivilegeEscalation` activé constitue souvent l’erreur opérationnelle par défaut. Dans Docker et Podman, omettre l’option de sécurité correspondante produit le même effet. Une autre erreur récurrente consiste à supposer que, parce qu’un container n’est « pas privilégié », les transitions de privilèges au moment de l’exec sont automatiquement sans importance.

Un piège Kubernetes plus subtil est que `allowPrivilegeEscalation: false` n’est **pas** respecté comme les utilisateurs s’y attendent lorsque le container est `privileged` ou possède `CAP_SYS_ADMIN`. L’API Kubernetes précise que `allowPrivilegeEscalation` est effectivement toujours défini sur true dans ces cas. En pratique, cela signifie que ce champ doit être considéré comme un indicateur parmi d’autres dans la posture finale, et non comme une garantie que le runtime a finalement configuré `NoNewPrivs: 1`.

## Abuse

Si `no_new_privs` n’est pas défini, la première question est de savoir si l’image contient des binaries capables d’élever les privilèges :
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Les résultats intéressants incluent :

- `NoNewPrivs: 0`
- des helpers setuid tels que `su`, `mount`, `passwd` ou des outils d’administration spécifiques à la distribution
- des binaires dotés de file capabilities accordant des privilèges réseau ou sur le système de fichiers

Lors d’une évaluation réelle, ces résultats ne prouvent pas à eux seuls l’existence d’une escalation fonctionnelle, mais ils identifient précisément les binaires à tester ensuite.

Dans Kubernetes, vérifiez également que l’intention du fichier YAML correspond à la réalité du kernel :
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
Les combinaisons intéressantes comprennent :

- `allowPrivilegeEscalation: false` dans la spécification du Pod, mais `NoNewPrivs: 0` dans le conteneur
- `cap_sys_admin` présent, ce qui rend le champ Kubernetes bien moins fiable
- `Seccomp: 0` et `NoNewPrivs: 0`, ce qui indique généralement une posture d'exécution largement affaiblie plutôt qu'une seule erreur isolée

### Exemple complet : In-Container Privilege Escalation via setuid

Ce contrôle empêche généralement l'**in-container privilege escalation** plutôt qu'un host escape direct. Si `NoNewPrivs` vaut `0` et qu'un helper setuid existe, testez-le explicitement :
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Si un binaire setuid connu est présent et fonctionnel, essayez de le lancer d’une manière qui préserve la transition de privilèges :
```bash
/bin/su -c id 2>/dev/null
```
Cela ne permet pas à lui seul de s’échapper du container, mais peut transformer un foothold à faibles privilèges à l’intérieur du container en container-root, ce qui devient souvent un prérequis pour un host escape ultérieur via des mounts, des runtime sockets ou des interfaces exposées au kernel.

## Checks

L’objectif de ces checks est de déterminer si l’élévation de privilèges au moment de l’exécution est bloquée et si l’image contient encore des helpers qui seraient importants dans le cas contraire.
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
- `NoNewPrivs: 1` associé à `Seccomp: 2` est un signe courant d'une posture de hardening plus intentionnelle.
- Un manifeste Kubernetes indiquant `allowPrivilegeEscalation: false` est utile, mais l'état du kernel est la source de vérité.
- Une image minimale contenant peu ou pas de binaires setuid/file-cap offre moins d'options de post-exploitation à un attaquant, même lorsque `no_new_privs` est absent.

## Valeurs par défaut du runtime

| Runtime / plateforme | État par défaut | Comportement par défaut | Affaiblissement manuel courant |
| --- | --- | --- | --- |
| Docker Engine | Non activé par défaut | Activé explicitement avec `--security-opt no-new-privileges=true` ; une valeur par défaut à l'échelle du daemon existe également via `dockerd --no-new-privileges` | omission du flag, `--privileged` |
| Podman | Non activé par défaut | Activé explicitement avec `--security-opt no-new-privileges` ou une configuration de sécurité équivalente | omission de l'option, `--privileged` |
| Kubernetes | Contrôlé par la policy du workload | `allowPrivilegeEscalation: false` demande cet effet, mais `privileged: true` et `CAP_SYS_ADMIN` le maintiennent effectivement à true | `allowPrivilegeEscalation: true`, `privileged: true`, ajout de `CAP_SYS_ADMIN` |
| containerd / CRI-O sous Kubernetes | Suit les paramètres du workload Kubernetes / `OCI process.noNewPrivileges` | Généralement hérité du security context du Pod et traduit dans la configuration du runtime OCI | identique à la ligne Kubernetes |

Cette protection est souvent absente simplement parce que personne ne l'a activée, et non parce que le runtime ne la prend pas en charge.

## Références

- [Documentation du kernel Linux : No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [Kubernetes : Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
{{#include ../../../../banners/hacktricks-training.md}}
