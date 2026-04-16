# Assessment And Hardening

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Une bonne évaluation de container doit répondre à deux questions parallèles. D’abord, que peut faire un attaquant depuis le workload actuel ? Ensuite, quels choix de l’opérateur ont rendu cela possible ? Les outils d’énumération aident pour la première question, et les recommandations de hardening aident pour la seconde. Garder les deux sur la même page rend cette section plus utile comme référence terrain plutôt que comme simple catalogue de techniques d’évasion.

Une mise à jour pratique pour les environnements modernes est que beaucoup d’anciens writeups sur les containers supposent discrètement un **runtime rootful**, **aucune isolation user namespace**, et souvent **cgroup v1**. Ces hypothèses ne sont plus sûres. Avant de perdre du temps sur d’anciennes primitives d’évasion, vérifiez d’abord si le workload est rootless ou userns-remapped, si l’hôte utilise cgroup v2, et si Kubernetes ou le runtime applique maintenant les profils seccomp et AppArmor par défaut. Ces détails décident souvent si un breakout célèbre s’applique encore.

## Enumeration Tools

Un certain nombre d’outils restent utiles pour caractériser rapidement un environnement container :

- `linpeas` peut identifier de nombreux indicateurs de container, des sockets montés, des ensembles de capabilities, des filesystem dangereux et des indices de breakout.
- `CDK` se concentre spécifiquement sur les environnements container et inclut l’énumération ainsi que कुछ vérifications automatisées d’évasion.
- `amicontained` est léger et utile pour identifier les restrictions du container, les capabilities, l’exposition des namespaces et les classes probables de breakout.
- `deepce` est un autre énumérateur orienté container avec des vérifications centrées sur les breakout.
- `grype` est utile lorsque l’évaluation inclut une revue des vulnérabilités des images et packages plutôt qu’une seule analyse d’évasion runtime.
- `Tracee` est utile lorsque vous avez besoin de **preuves runtime** plutôt que d’une simple posture statique, en particulier pour l’exécution de processus suspects, l’accès aux fichiers et la collecte d’événements aware des containers.
- `Inspektor Gadget` est utile dans Kubernetes et les investigations Linux de l’hôte lorsque vous avez besoin d’une visibilité basée sur eBPF reliée aux pods, containers, namespaces et autres concepts de niveau supérieur.

La valeur de ces outils est la vitesse et la couverture, pas la certitude. Ils aident à révéler rapidement la posture générale, mais les résultats intéressants nécessitent encore une interprétation manuelle en fonction du runtime réel, du namespace, des capabilities et du modèle de mount.

## Hardening Priorities

Les principes de hardening les plus importants sont conceptuellement simples même si leur mise en œuvre varie selon la plateforme. Évitez les containers privilégiés. Évitez les runtime sockets montés. Ne donnez pas aux containers des chemins hôte inscriptibles sauf raison très précise. Utilisez les user namespaces ou une exécution rootless lorsque c’est possible. Retirez toutes les capabilities et ne rajoutez que celles dont le workload a réellement besoin. Gardez seccomp, AppArmor et SELinux activés plutôt que de les désactiver pour résoudre des problèmes de compatibilité applicative. Limitez les ressources pour qu’un container compromis ne puisse pas facilement provoquer un déni de service sur l’hôte.

L’hygiène des images et de la build est aussi importante que la posture runtime. Utilisez des images minimales, reconstruisez fréquemment, scannez-les, exigez la provenance quand c’est possible, et gardez les secrets hors des layers. Un container exécuté en non-root avec une petite image et une surface syscall et capabilities réduite est beaucoup plus facile à défendre qu’une grande image de confort exécutée en root équivalent à l’hôte avec des outils de debug préinstallés.

Pour Kubernetes, les baselines actuelles de hardening sont plus opinionated que beaucoup d’opérateurs ne le supposent encore. Les **Pod Security Standards** intégrés considèrent `restricted` comme le profil de "current best practice" : `allowPrivilegeEscalation` devrait être `false`, les workloads devraient s’exécuter en non-root, seccomp devrait être défini explicitement sur `RuntimeDefault` ou `Localhost`, et les ensembles de capabilities devraient être retirés agressivement. Pendant l’évaluation, cela compte parce qu’un cluster qui utilise seulement les labels `warn` ou `audit` peut sembler durci sur le papier tout en acceptant en pratique des pods risqués.

## Modern Triage Questions

Avant de plonger dans les pages spécifiques aux escapes, répondez à ces questions rapides :

1. Le workload est-il **rootful**, **rootless**, ou **userns-remapped** ?
2. Le node utilise-t-il **cgroup v1** ou **cgroup v2** ?
3. **seccomp** et **AppArmor/SELinux** sont-ils configurés explicitement, ou seulement hérités quand ils sont disponibles ?
4. Dans Kubernetes, le namespace applique-t-il réellement `baseline` ou `restricted`, ou seulement le warning/l’audit ?

Useful checks:
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

- Si `/proc/self/uid_map` montre que root du conteneur est mappé vers une **plage élevée de UID host**, beaucoup d’anciens writeups sur host-root deviennent moins pertinents, car root dans le conteneur n’est plus équivalent à host-root.
- Si `/sys/fs/cgroup` est `cgroup2fs`, les anciens writeups spécifiques à **cgroup v1** comme l’abus de `release_agent` ne devraient plus être votre premier réflexe.
- Si seccomp et AppArmor ne sont hérités qu’implicement, la portabilité peut être plus faible que les defenders ne l’anticipent. Dans Kubernetes, définir explicitement `RuntimeDefault` est souvent plus robuste que de s’appuyer silencieusement sur les valeurs par défaut du node.
- Si `supplementalGroupsPolicy` est défini sur `Strict`, le pod devrait éviter d’hériter silencieusement de memberships de groupes supplémentaires depuis `/etc/group` à l’intérieur de l’image, ce qui rend le comportement des accès aux volumes et aux fichiers basé sur les groupes plus prévisible.
- Les labels de namespace tels que `pod-security.kubernetes.io/enforce=restricted` méritent d’être vérifiés directement. `warn` et `audit` sont utiles, mais ils n’empêchent pas la création d’un pod risqué.

## Exemples d’épuisement des ressources

Les contrôles de ressources ne sont pas glamour, mais ils font partie de la sécurité des conteneurs parce qu’ils limitent le rayon d’impact d’une compromission. Sans limites de mémoire, de CPU ou de PID, un simple shell peut suffire à dégrader l’hôte ou les workloads voisins.

Exemples de tests ayant un impact sur l’hôte :
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Ces exemples sont utiles car ils montrent que tous les résultats dangereux d’un container ne sont pas un « escape » propre. Des limites cgroup faibles peuvent quand même transformer une exécution de code en impact opérationnel réel.

Dans les environnements basés sur Kubernetes, vérifiez aussi si des contrôles de ressources existent réellement avant de considérer le DoS comme purement théorique :
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Outils de durcissement

Pour les environnements centrés sur Docker, `docker-bench-security` reste une base d’audit utile côté hôte, car il vérifie les problèmes de configuration courants par rapport à des recommandations de benchmark largement reconnues :
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
L'outil ne remplace pas la threat modeling, mais il reste utile pour détecter des valeurs par défaut négligentes de daemon, mount, network et runtime qui s'accumulent au fil du temps.

Pour Kubernetes et les environnements fortement orientés runtime, associez les vérifications statiques à la visibilité runtime :

- `Tracee` est utile pour la détection runtime aware des containers et la quick forensics lorsque vous devez confirmer ce qu'un workload compromis a réellement touché.
- `Inspektor Gadget` est utile lorsque l'assessment nécessite une télémétrie au niveau kernel reliée aux pods, containers, à l'activité DNS, à l'exécution de fichiers ou au comportement réseau.

## Checks

Utilisez-les comme commandes rapides de premier passage pendant l'assessment :
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

- Un processus root avec des capacités larges et `Seccomp: 0` mérite une attention immédiate.
- Un processus root qui a aussi une **map UID 1:1** est bien plus intéressant que "root" dans un user namespace correctement isolé.
- `cgroup2fs` signifie généralement que de nombreuses anciennes chaînes d’évasion **cgroup v1** ne sont pas votre meilleur point de départ, tandis que l’absence de `memory.max` ou `pids.max` indique toujours des contrôles faibles de blast-radius.
- Des mounts suspects et des sockets d’exécution fournissent souvent un chemin plus rapide vers un impact que n’importe quel exploit du kernel.
- La combinaison d’une posture d’exécution faible et de limites de ressources faibles indique généralement un environnement de container globalement permissif plutôt qu’une seule erreur isolée.

## References

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
