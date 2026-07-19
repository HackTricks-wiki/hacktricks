# Évaluation et durcissement

{{#include ../../../banners/hacktricks-training.md}}

## Vue d’ensemble

Une bonne évaluation d’un conteneur doit répondre à deux questions en parallèle. Premièrement, que peut faire un attaquant depuis la workload actuelle ? Deuxièmement, quels choix de l’opérateur ont rendu cela possible ? Les outils d’énumération aident à répondre à la première question, tandis que les recommandations de durcissement aident à répondre à la seconde. Regrouper les deux sur une même page rend cette section plus utile comme référence de terrain, plutôt que comme simple catalogue de techniques d’escape.

Une mise à jour pratique pour les environnements modernes est que de nombreux writeups anciens sur les conteneurs supposent implicitement un **rootful runtime**, l’absence d’isolation par user namespace et souvent **cgroup v1**. Ces hypothèses ne sont plus sûres. Avant de consacrer du temps aux anciennes primitives d’escape, vérifiez d’abord si la workload est rootless ou userns-remapped, si l’hôte utilise cgroup v2 et si Kubernetes ou le runtime applique désormais les profils seccomp et AppArmor par défaut. Ces détails déterminent souvent si un breakout connu reste applicable.

## Outils d’énumération

Plusieurs outils restent utiles pour caractériser rapidement un environnement de conteneurs :

- `linpeas` peut identifier de nombreux indicateurs de conteneurs, les sockets montés, les ensembles de capabilities, les filesystems dangereux et les indices de breakout.
- `CDK` se concentre spécifiquement sur les environnements de conteneurs et inclut l’énumération ainsi que certains checks automatisés d’escape.
- `amicontained` est léger et utile pour identifier les restrictions des conteneurs, les capabilities, l’exposition des namespaces et les classes de breakout probables.
- `deepce` est un autre outil d’énumération spécialisé dans les conteneurs, avec des checks orientés breakout.
- `grype` est utile lorsque l’évaluation inclut l’analyse des vulnérabilités des packages d’une image, plutôt que l’analyse exclusive de l’escape au runtime.
- `Tracee` est utile lorsque vous avez besoin de **runtime evidence** plutôt que d’une simple posture statique, notamment pour l’exécution de processus suspects, l’accès aux fichiers et la collecte d’événements prenant en compte les conteneurs.
- `Inspektor Gadget` est utile dans les investigations Kubernetes et Linux-host lorsque vous avez besoin d’une visibilité basée sur eBPF, reliée aux pods, conteneurs, namespaces et autres concepts de plus haut niveau.

La valeur de ces outils réside dans leur rapidité et leur couverture, pas dans leur certitude. Ils permettent de révéler rapidement la posture générale, mais les résultats intéressants doivent toujours être interprétés manuellement en fonction du runtime réel et du modèle des namespaces, capabilities et mounts.

## Priorités de durcissement

Les principes de durcissement les plus importants sont conceptuellement simples, même si leur implémentation varie selon la plateforme. Évitez les conteneurs privilégiés. Évitez de monter des runtime sockets. N’accordez pas aux conteneurs l’accès en écriture à des chemins de l’hôte, sauf raison très précise. Utilisez les user namespaces ou une exécution rootless lorsque cela est possible. Supprimez toutes les capabilities et ne rajoutez que celles dont la workload a réellement besoin. Maintenez seccomp, AppArmor et SELinux activés au lieu de les désactiver pour résoudre des problèmes de compatibilité applicative. Limitez les ressources afin qu’un conteneur compromis ne puisse pas provoquer trivialement un déni de service sur l’hôte.

L’hygiène des images et des builds est tout aussi importante que la posture au runtime. Utilisez des images minimales, reconstruisez-les fréquemment, scannez-les, exigez une provenance lorsque cela est possible et gardez les secrets hors des layers. Un conteneur exécuté en tant que non-root, utilisant une petite image et une surface réduite de syscalls et de capabilities, est beaucoup plus facile à défendre qu’une grosse image pratique exécutée avec un root équivalent à celui de l’hôte et contenant des outils de debugging préinstallés.

Pour Kubernetes, les baselines de durcissement actuelles sont plus directives que ne le supposent encore de nombreux opérateurs. Les **Pod Security Standards** intégrés considèrent `restricted` comme le profil correspondant aux « meilleures pratiques actuelles » : `allowPrivilegeEscalation` devrait être défini sur `false`, les workloads devraient s’exécuter en tant que non-root, seccomp devrait être explicitement défini sur `RuntimeDefault` ou `Localhost`, et les ensembles de capabilities devraient être supprimés de manière agressive. Lors de l’évaluation, cela est important, car un cluster qui utilise uniquement des labels `warn` ou `audit` peut sembler durci sur le papier tout en autorisant réellement des pods risqués.

## Questions de triage modernes

Avant de consulter les pages spécifiques à l’escape, répondez à ces questions rapides :

1. La workload est-elle **rootful**, **rootless** ou **userns-remapped** ?
2. Le node utilise-t-il **cgroup v1** ou **cgroup v2** ?
3. **seccomp** et **AppArmor/SELinux** sont-ils configurés explicitement, ou simplement hérités lorsqu’ils sont disponibles ?
4. Dans Kubernetes, le namespace applique-t-il réellement `baseline` ou `restricted`, ou se contente-t-il d’émettre des avertissements ou de réaliser un audit ?

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

- Si `/proc/self/uid_map` montre que le root du container est mappé vers une **high host UID range**, de nombreux writeups plus anciens sur le host-root sont moins pertinents, car le root du container n'est plus équivalent au root du host.
- Si `/sys/fs/cgroup` est `cgroup2fs`, les anciens writeups spécifiques à **cgroup v1**, comme l'abus de `release_agent`, ne devraient plus être votre première hypothèse.
- Si seccomp et AppArmor sont uniquement hérités implicitement, la portabilité peut être plus faible que ce que les defenders imaginent. Dans Kubernetes, définir explicitement `RuntimeDefault` est souvent plus sûr que de dépendre silencieusement des defaults du node.
- Si `supplementalGroupsPolicy` est défini sur `Strict`, le pod devrait éviter d'hériter silencieusement de memberships de groupes supplémentaires depuis `/etc/group` dans l'image, ce qui rend le comportement d'accès aux volumes et aux fichiers basé sur les groupes plus prévisible.
- Les labels de namespace tels que `pod-security.kubernetes.io/enforce=restricted` méritent d'être vérifiés directement. `warn` et `audit` sont utiles, mais ils n'empêchent pas la création d'un pod risqué.

## Triage de la baseline du runtime

Une baseline du runtime est le quick pass qui permet de déterminer si un container ressemble à un workload isolé ordinaire ou à un foothold de control plane ayant un impact sur le host. Elle doit collecter suffisamment d'informations pour prioriser la prochaine page à consulter : abus du runtime socket, mounts du host, namespaces, cgroups, capabilities ou review des secrets de l'image.

Vérifications utiles depuis l'intérieur d'un workload :
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

- L’absence de `memory.max` / `pids.max`, ou des limites illimitées, indique des contrôles faibles du blast radius, même sans escape propre.
- Un shell root avec `NoNewPrivs: 0`, de nombreuses capabilities et un seccomp permissif est bien plus intéressant qu’un workload non-root aux privilèges limités.
- Les runtime sockets et les mounts hôte inscriptibles sont généralement prioritaires par rapport aux kernel exploits, car ils exposent déjà un chemin de contrôle de la gestion ou du système de fichiers.
- Les namespaces PID, réseau, IPC ou cgroup partagés ne constituent pas toujours à eux seuls des full escapes, mais ils facilitent la recherche de l’étape suivante.

## Exemples d’épuisement des ressources

Les contrôles des ressources ne sont pas très glamour, mais ils font partie de la container security, car ils limitent le blast radius d’une compromission. Sans limites de mémoire, de CPU ou de PID, un simple shell peut suffire à dégrader l’hôte ou les workloads voisins.

Exemples de tests ayant un impact sur l’hôte :
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Ces exemples sont utiles, car ils montrent que toutes les conséquences dangereuses d’un container ne constituent pas un « escape » propre. Des limites cgroup faibles peuvent tout de même transformer une exécution de code en un véritable impact opérationnel.

Dans les environnements s’appuyant sur Kubernetes, vérifiez également si des contrôles de ressources existent réellement avant de considérer le DoS comme théorique :
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Outils de hardening

Pour les environnements centrés sur Docker, `docker-bench-security` reste une base d’audit utile côté hôte, car il vérifie les problèmes de configuration courants par rapport aux recommandations de référence largement reconnues :
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
L’outil ne remplace pas la modélisation des menaces, mais il reste utile pour détecter les configurations par défaut négligées des daemon, des mount, du réseau et du runtime qui s’accumulent au fil du temps.

Pour Kubernetes et les environnements fortement axés sur le runtime, associez les contrôles statiques à une visibilité runtime :

- `Tracee` est utile pour la détection runtime adaptée aux conteneurs et l’analyse forensique rapide lorsque vous devez confirmer ce qu’un workload compromis a réellement touché.
- `Inspektor Gadget` est utile lorsque l’assessment nécessite une télémétrie au niveau du kernel, reliée aux pods, aux conteneurs, à l’activité DNS, à l’exécution de fichiers ou au comportement réseau.

## Contrôles

Utilisez-les comme commandes rapides de première passe pendant l’assessment :
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
- Un processus root qui possède également une **1:1 UID map** est bien plus intéressant que du « root » dans un user namespace correctement isolé.
- `cgroup2fs` signifie généralement que de nombreuses chaînes d'escape **cgroup v1** plus anciennes ne constituent pas le meilleur point de départ, tandis que l'absence de `memory.max` ou de `pids.max` indique toujours des contrôles faibles du rayon d'impact.
- Les mounts suspects et les runtime sockets offrent souvent un chemin plus rapide vers l'impact que n'importe quel kernel exploit.
- La combinaison d'une posture runtime faible et de limites de ressources faibles indique généralement un environnement de containers permissif dans son ensemble, plutôt qu'une seule erreur isolée.

## Références

- [Standards de sécurité des Pods Kubernetes](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Avis de sécurité Docker : plusieurs vulnérabilités dans runc, BuildKit et Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
