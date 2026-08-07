# Évaluation et durcissement

{{#include ../../../banners/hacktricks-training.md}}

## Vue d’ensemble

Une bonne évaluation de conteneur doit répondre à deux questions parallèles. Premièrement, que peut faire un attaquant depuis la workload actuelle ? Deuxièmement, quels choix de l’opérateur ont rendu cela possible ? Les outils d’énumération aident à répondre à la première question, tandis que les recommandations de durcissement aident à répondre à la seconde. Regrouper les deux sur une même page rend cette section plus utile comme référence de terrain, plutôt que comme simple catalogue de techniques d’escape.

Une mise à jour pratique pour les environnements modernes est que de nombreux anciens writeups sur les conteneurs supposent implicitement un **runtime rootful**, aucune isolation par user namespace, et souvent **cgroup v1**. Ces hypothèses ne sont plus sûres. Avant de consacrer du temps aux anciennes primitives d’escape, vérifiez d’abord si la workload est rootless ou userns-remapped, si l’hôte utilise cgroup v2, et si Kubernetes ou le runtime applique désormais des profils seccomp et AppArmor par défaut. Ces détails déterminent souvent si un breakout connu reste applicable.

## Outils d’énumération

Un certain nombre d’outils restent utiles pour caractériser rapidement un environnement de conteneurs :

- `linpeas` peut identifier de nombreux indicateurs de conteneurs, les sockets montés, les ensembles de capabilities, les filesystems dangereux et les indices de breakout.
- `CDK` se concentre spécifiquement sur les environnements de conteneurs et inclut de l’énumération ainsi que certains contrôles automatisés d’escape.
- `amicontained` est léger et utile pour identifier les restrictions des conteneurs, les capabilities, l’exposition des namespaces et les classes de breakout probables.
- `deepce` est un autre outil d’énumération orienté conteneurs, avec des contrôles axés sur les breakouts.
- `grype` est utile lorsque l’évaluation inclut l’analyse des vulnérabilités des packages d’image, plutôt qu’une analyse limitée à l’escape au runtime.
- `Tracee` est utile lorsque vous avez besoin de **preuves au runtime** plutôt que d’une simple posture statique, notamment pour l’exécution de processus suspects, l’accès aux fichiers et la collecte d’événements tenant compte des conteneurs.
- `Inspektor Gadget` est utile dans les investigations Kubernetes et Linux lorsque vous avez besoin d’une visibilité basée sur eBPF, corrélée aux pods, conteneurs, namespaces et autres concepts de plus haut niveau.

La valeur de ces outils réside dans leur rapidité et leur couverture, pas dans leur certitude. Ils permettent de révéler rapidement la posture générale, mais les résultats intéressants nécessitent toujours une interprétation manuelle en fonction du runtime réel et du modèle des namespaces, des capabilities et des mounts.

## Priorités de durcissement

Les principes de durcissement les plus importants sont conceptuellement simples, même si leur mise en œuvre varie selon la plateforme. Évitez les conteneurs privilégiés. Évitez les sockets de runtime montés. N’accordez pas aux conteneurs l’accès en écriture à des chemins de l’hôte, sauf raison très spécifique. Utilisez les user namespaces ou une exécution rootless lorsque cela est possible. Supprimez toutes les capabilities et ne réajoutez que celles dont la workload a réellement besoin. Maintenez seccomp, AppArmor et SELinux activés au lieu de les désactiver pour résoudre des problèmes de compatibilité applicative. Limitez les ressources afin qu’un conteneur compromis ne puisse pas facilement provoquer un déni de service sur l’hôte.

L’hygiène des images et des builds est tout aussi importante que la posture au runtime. Utilisez des images minimales, reconstruisez-les fréquemment, scannez-les, exigez une provenance lorsque cela est possible et gardez les secrets hors des layers. Un conteneur exécuté en non-root, avec une petite image et une surface limitée au niveau des syscalls et des capabilities, est beaucoup plus facile à défendre qu’une grande image pratique exécutée avec un root équivalent à celui de l’hôte et contenant déjà des outils de debug.

Pour Kubernetes, les baselines de durcissement actuelles sont plus prescriptives que ne le supposent encore de nombreux opérateurs. Les **Pod Security Standards** intégrés considèrent `restricted` comme le profil correspondant aux "meilleures pratiques actuelles" : `allowPrivilegeEscalation` doit être défini sur `false`, les workloads doivent s’exécuter en non-root, seccomp doit être explicitement défini sur `RuntimeDefault` ou `Localhost`, et les ensembles de capabilities doivent être supprimés de manière stricte. Lors de l’évaluation, cela est important, car un cluster qui utilise uniquement des labels `warn` ou `audit` peut sembler durci sur le papier tout en autorisant concrètement des pods risqués.<sup>[[1]](#references)</sup>

## Questions de triage modernes

Avant d’aborder les pages spécifiques aux escapes, répondez à ces questions rapides :

1. La workload est-elle **rootful**, **rootless** ou **userns-remapped** ?
2. Le nœud utilise-t-il **cgroup v1** ou **cgroup v2** ?
3. **seccomp** et **AppArmor/SELinux** sont-ils configurés explicitement, ou simplement hérités lorsqu’ils sont disponibles ?
4. Dans Kubernetes, le namespace applique-t-il réellement `baseline` ou `restricted`, ou se contente-t-il d’émettre des avertissements ou d’effectuer des audits ?

Vérifications utiles :
```bash
id
cat /proc/self/uid_map 2>/dev/null
cat /proc/self/gid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/1/attr/current 2>/dev/null
find /var/run/secrets -maxdepth 3 -type f 2>/dev/null | head
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get ns "$NS" -o jsonpath='{.metadata.labels}' 2>/dev/null
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.securityContext.supplementalGroupsPolicy}{"\n"}' 2>/dev/null
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.securityContext.seccompProfile.type}{"\n"}{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.capabilities.drop}{"\n"}' 2>/dev/null
```
Ce qui est intéressant ici :

- Si `/proc/self/uid_map` indique que le root du container est mappé vers une **plage d’UID hôte élevés**, de nombreux anciens writeups sur l’écriture en tant que root sur l’hôte deviennent moins pertinents, car le root dans le container n’est plus l’équivalent du root sur l’hôte.
- Si `/sys/fs/cgroup` est `cgroup2fs`, les anciens writeups spécifiques à **cgroup v1**, comme l’abus de `release_agent`, ne devraient plus être votre première hypothèse.
- Si seccomp et AppArmor sont uniquement hérités implicitement, la portabilité peut être plus faible que ce que les défenseurs attendent. Dans Kubernetes, définir explicitement `RuntimeDefault` est souvent plus robuste que de s’appuyer silencieusement sur les valeurs par défaut du node.
- Si `supplementalGroupsPolicy` est défini sur `Strict`, le pod devrait éviter d’hériter silencieusement de memberships de groupes supplémentaires depuis `/etc/group` dans l’image, ce qui rend le comportement d’accès aux volumes et aux fichiers basé sur les groupes plus prévisible.
- Les labels de namespace tels que `pod-security.kubernetes.io/enforce=restricted` méritent d’être vérifiés directement. `warn` et `audit` sont utiles, mais ils n’empêchent pas la création d’un pod risqué.

## Triage de la baseline du runtime

Une baseline du runtime est la vérification rapide qui permet de déterminer si un container ressemble à un workload isolé ordinaire ou à un foothold de control plane ayant un impact sur l’hôte. Elle doit collecter suffisamment d’informations pour prioriser la prochaine page à consulter : abus du runtime socket, mounts de l’hôte, namespaces, cgroups, capabilities ou review des secrets de l’image.

Vérifications utiles depuis l’intérieur d’un workload :
```bash
id
hostname
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/uid_map 2>/dev/null
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
stat -fc %T /sys/fs/cgroup 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
readlink /proc/self/ns/{pid,mnt,net,ipc,cgroup,user} 2>/dev/null
mount
find /run /var/run -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Interprétation :

- L’absence de limites ou des valeurs illimitées pour `memory.max` / `pids.max` indiquent des contrôles de blast radius faibles, même sans escape propre.
- Un root shell avec `NoNewPrivs: 0`, des capabilities étendues et un seccomp permissif est bien plus intéressant qu’un workload non-root limité.
- Les runtime sockets et les writable host mounts sont généralement prioritaires par rapport aux kernel exploits, car ils exposent déjà un chemin de contrôle de la gestion ou du filesystem.
- Les namespaces PID, réseau, IPC ou cgroup partagés ne constituent pas toujours à eux seuls des full escapes, mais ils facilitent la découverte de l’étape suivante.

## Exemples d’épuisement des ressources

Les resource controls ne sont pas glamour, mais ils font partie de la container security, car ils limitent le blast radius d’une compromission. Sans limites de mémoire, de CPU ou de PID, un simple shell peut suffire à dégrader l’host ou les workloads voisins.

Exemples de tests ayant un impact sur l’host :
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Ces exemples sont utiles, car ils montrent que les conséquences dangereuses d'un container ne constituent pas toujours un « escape » propre. Des limites cgroup faibles peuvent tout de même transformer une exécution de code en un impact opérationnel réel.

Dans les environnements adossés à Kubernetes, vérifiez également si des contrôles des ressources existent, avant de considérer le DoS comme théorique :
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Outils de hardening

Pour les environnements centrés sur Docker, `docker-bench-security` reste une base d’audit utile côté hôte, car il vérifie les problèmes de configuration courants par rapport à des recommandations de référence largement reconnues :
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
L'outil ne remplace pas le threat modeling, mais il reste utile pour détecter les valeurs par défaut négligentes des daemon, mount, network et runtime qui s'accumulent au fil du temps.

Pour Kubernetes et les environnements fortement dépendants du runtime, associez les vérifications statiques à une visibilité runtime :

- `Tracee` est utile pour la détection runtime consciente des containers et la forensics rapide lorsque vous devez confirmer ce qu'un workload compromis a réellement touché.
- `Inspektor Gadget` est utile lorsque l'évaluation nécessite une télémétrie au niveau du kernel, mise en correspondance avec les pods, les containers, l'activité DNS, l'exécution de fichiers ou le comportement réseau.

## Vérifications

Utilisez-les comme commandes rapides de première passe pendant l'évaluation :
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Ce qui est intéressant ici :

- Un processus root doté de capacités étendues et avec `Seccomp: 0` mérite une attention immédiate.
- Un processus root qui possède également une **1:1 UID map** est bien plus intéressant que le « root » à l'intérieur d'un user namespace correctement isolé.
- `cgroup2fs` signifie généralement que de nombreuses chaînes d'escape reposant sur **cgroup v1** ne constituent pas le meilleur point de départ, tandis que l'absence de `memory.max` ou de `pids.max` indique toujours des contrôles faibles de la portée de l'impact.
- Les mounts suspects et les runtime sockets offrent souvent un chemin plus rapide vers un impact que n'importe quel exploit du kernel.
- La combinaison d'une posture runtime faible et de limites de ressources faibles indique généralement un environnement de containers permissif dans son ensemble, plutôt qu'une seule erreur isolée.

## Références

- [1] [Standards de sécurité des Pods Kubernetes](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [2] [Avis de sécurité Docker : plusieurs vulnérabilités dans runc, BuildKit et Moby](https://docs.docker.com/security/security-announcements/)

{{#include ../../../banners/hacktricks-training.md}}
