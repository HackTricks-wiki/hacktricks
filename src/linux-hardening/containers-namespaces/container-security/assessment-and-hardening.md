# Évaluation et renforcement de la sécurité

{{#include ../../../banners/hacktricks-training.md}}

## Présentation

Une bonne évaluation de conteneur devrait répondre à deux questions en parallèle. Premièrement, que peut faire un attaquant depuis la charge de travail actuelle ? Deuxièmement, quels choix de l’opérateur ont rendu cela possible ? Les outils d’énumération aident à répondre à la première question, et les conseils de renforcement de la sécurité à la seconde. Regrouper les deux sur une même page en fait une référence de terrain plus utile qu’un simple catalogue de techniques d’évasion.

Une mise à jour pratique pour les environnements modernes : de nombreux anciens articles sur les conteneurs supposent implicitement un **runtime rootful**, **aucune isolation par user namespace**, et souvent **cgroup v1**. Ces hypothèses ne sont plus sûres. Avant de consacrer du temps aux anciennes primitives d’évasion, vérifiez d’abord si la charge de travail est rootless ou utilise le remappage des user namespaces, si l’hôte utilise cgroup v2, et si Kubernetes ou le runtime applique désormais des profils seccomp et AppArmor par défaut. Ces détails déterminent souvent si une technique de breakout bien connue s’applique encore.

## Outils d’énumération

Plusieurs outils restent utiles pour caractériser rapidement un environnement de conteneurs :

- `linpeas` peut identifier de nombreux indicateurs de conteneur, sockets montés, ensembles de capabilities, systèmes de fichiers dangereux et indices de breakout.
- `CDK` cible spécifiquement les environnements de conteneurs et inclut des fonctions d’énumération ainsi que quelques vérifications automatisées d’évasion.
- `amicontained` est léger et utile pour identifier les restrictions des conteneurs, les capabilities, l’exposition des namespaces et les catégories de breakout probables.
- `deepce` est un autre outil d’énumération ciblant les conteneurs, avec des vérifications axées sur le breakout.
- `grype` est utile lorsque l’évaluation comprend l’analyse des vulnérabilités des paquets d’image, et pas seulement l’analyse des évasions au runtime.
- `Tracee` est utile lorsque vous avez besoin de **preuves d’exécution** plutôt que d’une simple évaluation statique de la posture, notamment pour surveiller l’exécution de processus suspects, l’accès aux fichiers et la collecte d’événements tenant compte des conteneurs.
- `Inspektor Gadget` est utile dans les enquêtes sur Kubernetes et les hôtes Linux lorsque vous avez besoin d’une visibilité reposant sur eBPF, reliée aux pods, conteneurs, namespaces et autres concepts de plus haut niveau.

Ces outils sont précieux pour leur rapidité et leur couverture, pas pour leur certitude. Ils aident à révéler rapidement la posture générale, mais les résultats intéressants doivent toujours être interprétés manuellement en fonction du runtime réel et des modèles de namespace, de capabilities et de montage.

## Priorités de renforcement

Les principes les plus importants de renforcement de la sécurité sont simples dans leur concept, même si leur mise en œuvre varie selon la plateforme. Évitez les conteneurs privilégiés. Évitez les sockets de runtime montés. Ne donnez pas aux conteneurs des chemins de l’hôte accessibles en écriture, sauf raison très précise. Utilisez les user namespaces ou une exécution rootless lorsque c’est possible. Supprimez toutes les capabilities et ne réactivez que celles dont la charge de travail a réellement besoin. Laissez seccomp, AppArmor et SELinux activés au lieu de les désactiver pour résoudre des problèmes de compatibilité applicative. Limitez les ressources afin qu’un conteneur compromis ne puisse pas facilement provoquer un déni de service sur l’hôte.

L’hygiène des images et des builds compte autant que la posture au runtime. Utilisez des images minimales, reconstruisez-les fréquemment, analysez-les, exigez une provenance lorsque c’est possible et ne stockez pas de secrets dans les couches. Un conteneur exécuté sans privilèges, avec une petite image et une surface d’appels système et de capabilities réduite, est bien plus facile à défendre qu’une grosse image pratique exécutée en tant que root avec des privilèges équivalents à ceux de l’hôte et des outils de débogage préinstallés.

Pour Kubernetes, les référentiels de renforcement actuels sont plus prescriptifs que ne le pensent encore de nombreux opérateurs. Les **Pod Security Standards** intégrées considèrent `restricted` comme le profil correspondant aux « bonnes pratiques actuelles » : `allowPrivilegeEscalation` devrait être défini sur `false`, les charges de travail devraient s’exécuter sans privilèges root, seccomp devrait être explicitement défini sur `RuntimeDefault` ou `Localhost`, et les ensembles de capabilities devraient être supprimés de manière agressive. Lors d’une évaluation, c’est important, car un cluster qui utilise uniquement des labels `warn` ou `audit` peut sembler sécurisé sur le papier tout en acceptant, en pratique, des pods à risque.<sup>[[1]](#references)</sup>

Lorsqu’un Pod a un token de service-account monté, évaluez ses permissions **pour chaque namespace cible**. Une règle listant les Pods dans un namespace ne confère pas de permissions dans un autre ; un token monté dans un autre Pod peut avoir des droits différents. Utilisez `kubectl auth can-i list pods -n <target-namespace>` et `kubectl auth can-i list secrets -n <target-namespace>` avec l’identité réellement évaluée. Une vérification autorisant l’énumération des Secrets constitue une piste sérieuse, car la réponse à une requête de liste peut inclure le contenu des Secrets, mais elle ne prouve pas la présence d’un token privilégié. L’accès à l’hôte nécessite également un droit utilisable de création de charges de travail, l’autorisation par les règles d’admission du montage `hostPath` proposé, ainsi qu’un contexte de sécurité de nœud/pod permettant l’opération souhaitée sur les fichiers. Consultez les [vérifications d’autorisation](https://kubernetes.io/docs/reference/access-authn-authz/authorization/) et les [conseils de Kubernetes sur l’escalade de privilèges RBAC](https://kubernetes.io/docs/concepts/security/rbac-good-practices/).

## Questions de triage modernes

Avant d’examiner les pages consacrées aux techniques d’évasion, répondez à ces questions rapides :

1. La charge de travail est-elle **rootful**, **rootless** ou utilise-t-elle le **remappage des user namespaces** ?
2. Le nœud utilise-t-il **cgroup v1** ou **cgroup v2** ?
3. **seccomp** et **AppArmor/SELinux** sont-ils explicitement configurés ou simplement hérités lorsqu’ils sont disponibles ?
4. Dans Kubernetes, le namespace **applique-t-il** réellement `baseline` ou `restricted`, ou se contente-t-il d’émettre des avertissements ou de réaliser des audits ?

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

- Si `/proc/self/uid_map` indique que le root du conteneur est associé à une **plage élevée d’UID hôte**, de nombreux anciens articles sur l’écriture avec les privilèges root sur l’hôte sont moins pertinents, car le root du conteneur n’est plus équivalent au root de l’hôte.
- Si `/sys/fs/cgroup` est `cgroup2fs`, les anciens articles spécifiques à **cgroup v1**, comme l’abus de `release_agent`, ne devraient plus être votre première piste.
- Si seccomp et AppArmor sont hérités implicitement, la portabilité peut être moins bonne que ne le pensent les défenseurs. Dans Kubernetes, définir explicitement `RuntimeDefault` est souvent plus sûr que de se fier silencieusement aux paramètres par défaut du nœud.
- Si `supplementalGroupsPolicy` est défini sur `Strict`, le pod devrait éviter d’hériter silencieusement de groupes supplémentaires depuis `/etc/group` dans l’image, ce qui rend le comportement d’accès aux volumes et aux fichiers basé sur les groupes plus prévisible.
- Les labels de namespace tels que `pod-security.kubernetes.io/enforce=restricted` méritent d’être vérifiés directement. `warn` et `audit` sont utiles, mais ils n’empêchent pas la création d’un pod risqué.

## Triage de référence du runtime

Une référence du runtime est une vérification rapide qui indique si un conteneur ressemble à une charge de travail isolée ordinaire ou à un point d’appui dans le plan de contrôle susceptible d’avoir un impact sur l’hôte. Elle doit recueillir suffisamment d’informations pour déterminer quelle page consulter ensuite : abus du socket du runtime, montages de l’hôte, namespaces, cgroups, capabilities ou vérification des secrets de l’image.

Vérifications utiles depuis une charge de travail :

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

- L’absence de limite ou une limite illimitée pour `memory.max` / `pids.max` indique des contrôles faibles du rayon d’impact, même sans évasion complète.
- Un shell root avec `NoNewPrivs: 0`, des capacités étendues et un seccomp permissif est bien plus intéressant qu’une charge de travail restreinte exécutée sans privilèges.
- Les sockets du runtime et les montages hôte accessibles en écriture sont généralement prioritaires par rapport aux exploits du kernel, car ils exposent déjà un chemin de contrôle de la gestion ou du système de fichiers.
- Les namespaces PID, réseau, IPC ou cgroup partagés ne permettent pas toujours à eux seuls une évasion complète, mais ils facilitent la découverte de l’étape suivante.

## Exemples d’épuisement des ressources

Les contrôles des ressources ne sont pas très glamour, mais ils font partie de la sécurité des conteneurs, car ils limitent le rayon d’impact d’une compromission. Sans limites de mémoire, de CPU ou de PID, un simple shell peut suffire à dégrader l’hôte ou les charges de travail voisines.

Exemples de tests ayant un impact sur l’hôte :

```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```

Ces exemples sont utiles, car ils montrent que les conséquences dangereuses d’un conteneur ne se résument pas à une « escape » propre. Des limites cgroup trop faibles peuvent quand même transformer une exécution de code en véritable impact opérationnel.

Dans les environnements reposant sur Kubernetes, vérifiez également si des contrôles de ressources existent avant de considérer le DoS comme théorique :

```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```

## Outils de durcissement

Dans les environnements centrés sur Docker, `docker-bench-security` reste une référence utile pour l’audit côté hôte, car il vérifie les problèmes de configuration courants au regard de recommandations de référence largement reconnues. Les avis de sécurité concernant le runtime doivent être examinés séparément, car un benchmark de configuration ne peut pas détecter si le runtime installé est concerné par une vulnérabilité récemment divulguée. <sup>[[2]](#references)</sup>

```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```

L’outil ne remplace pas la modélisation des menaces, mais il reste utile pour repérer les paramètres par défaut négligés des daemons, des montages, du réseau et de l’environnement d’exécution, qui s’accumulent au fil du temps.

Pour Kubernetes et les environnements fortement axés sur l’environnement d’exécution, associez les vérifications statiques à une visibilité à l’exécution :

- `Tracee` est utile pour la détection à l’exécution tenant compte des conteneurs et pour les investigations rapides lorsque vous devez confirmer ce qu’une charge de travail compromise a réellement touché.
- `Inspektor Gadget` est utile lorsque l’évaluation nécessite une télémétrie au niveau du noyau reliée aux pods, aux conteneurs, à l’activité DNS, à l’exécution de fichiers ou au comportement réseau.

## Vérifications

Utilisez ces commandes comme premières vérifications rapides pendant l’évaluation :

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

- Un processus root doté de nombreuses capabilities et avec `Seccomp: 0` mérite une attention immédiate.
- Un processus root qui possède aussi un **mappage UID 1:1** est bien plus intéressant que du « root » dans un namespace utilisateur correctement isolé.
- `cgroup2fs` signifie généralement que de nombreuses anciennes chaînes d’évasion **cgroup v1** ne constituent pas le meilleur point de départ, tandis que l’absence de `memory.max` ou de `pids.max` indique toujours des contrôles de limitation de l’impact insuffisants.
- Les mounts suspects et les sockets du runtime offrent souvent un moyen plus rapide d’obtenir un impact qu’un exploit noyau.
- La combinaison d’une configuration du runtime peu sécurisée et de limites de ressources faibles indique généralement un environnement de conteneurs permissif dans son ensemble, plutôt qu’une erreur isolée.

## References

- [1] [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [2] [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
