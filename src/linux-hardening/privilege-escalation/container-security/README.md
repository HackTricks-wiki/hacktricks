# Sécurité des conteneurs

{{#include ../../../banners/hacktricks-training.md}}

## Ce qu'est réellement un conteneur

Une façon pratique de définir un conteneur est la suivante : un conteneur est un **arbre de processus Linux ordinaire** qui a été démarré selon une configuration de type OCI de sorte qu'il voit un système de fichiers contrôlé, un ensemble contrôlé de ressources du noyau, et un modèle de privilèges restreint. Le processus peut croire qu'il est PID 1, peut croire qu'il possède sa propre pile réseau, peut croire qu'il possède son propre hostname et ses ressources IPC, et peut même s'exécuter en root à l'intérieur de son propre espace de noms utilisateur. Mais sous le capot, c'est toujours un processus hôte que le noyau planifie comme n'importe quel autre.

C'est pourquoi la sécurité des conteneurs est en réalité l'étude de la manière dont cette illusion est construite et comment elle échoue. Si le mount namespace est faible, le processus peut voir le système de fichiers hôte. Si l'espace de noms utilisateur est absent ou désactivé, le root à l'intérieur du conteneur peut se mapper trop étroitement au root de l'hôte. Si seccomp n'est pas confiné et que l'ensemble de capabilities est trop large, le processus peut atteindre des syscalls et des fonctionnalités privilégiées du noyau qui auraient dû rester hors de portée. Si le runtime socket est monté à l'intérieur du conteneur, le conteneur peut ne pas avoir besoin d'une breakout du noyau du tout car il peut simplement demander au runtime de lancer un conteneur frère plus puissant ou de monter directement le système de fichiers racine de l'hôte.

## Comment les conteneurs diffèrent des machines virtuelles

Une VM transporte normalement son propre noyau et sa propre frontière d'abstraction matérielle. Cela signifie que le noyau invité peut planter, faire un panic ou être exploité sans impliquer automatiquement un contrôle direct du noyau hôte. Dans les conteneurs, la charge de travail n'obtient pas un noyau séparé. À la place, elle obtient une vue soigneusement filtrée et namespaced du même noyau que celui utilisé par l'hôte. En conséquence, les conteneurs sont généralement plus légers, démarrent plus vite, sont plus faciles à empaqueter densément sur une machine, et mieux adaptés aux déploiements d'applications de courte durée. Le prix à payer est que la frontière d'isolation dépend beaucoup plus directement d'une configuration correcte de l'hôte et du runtime.

Cela ne signifie pas que les conteneurs sont « insecure » et que les VMs sont « secure ». Cela signifie que le modèle de sécurité est différent. Une pile de conteneurs bien configurée avec exécution rootless, espaces de noms utilisateur, seccomp par défaut, un ensemble strict de capabilities, aucun partage de namespace hôte, et un renforcement fort par SELinux ou AppArmor peut être très robuste. À l'inverse, un conteneur démarré avec `--privileged`, partage de PID/network avec l'hôte, le socket Docker monté à l'intérieur, et un bind mount en écriture de `/` est fonctionnellement beaucoup plus proche d'un accès root sur l'hôte que d'un bac à sable d'application isolé en toute sécurité. La différence vient des couches qui ont été activées ou désactivées.

Il existe aussi un terrain intermédiaire que les lecteurs doivent comprendre car il apparaît de plus en plus souvent dans les environnements réels. Les runtimes de conteneurs sandboxés tels que gVisor et Kata Containers renforcent intentionnellement la frontière au-delà d'un conteneur `runc` classique. gVisor place une couche de noyau en espace utilisateur entre la charge de travail et de nombreuses interfaces du noyau hôte, tandis que Kata lance la charge de travail à l'intérieur d'une machine virtuelle légère. Ils sont toujours utilisés via les écosystèmes de conteneurs et les workflows d'orchestration, mais leurs propriétés de sécurité diffèrent des runtimes OCI simples et ne doivent pas être mentalement regroupés avec les « normal Docker containers » comme si tout se comportait de la même façon.

## La pile des conteneurs : plusieurs couches, pas une seule

Quand quelqu'un dit « ce conteneur est insecure », la question de suivi utile est : **quelle couche l'a rendu insecure ?** Une charge de travail conteneurisée est généralement le résultat de plusieurs composants travaillant ensemble.

En haut, il y a souvent une **couche de build d'image** telle que BuildKit, Buildah, ou Kaniko, qui crée l'image OCI et les métadonnées. Au-dessus du runtime bas niveau, il peut y avoir un **engine ou manager** tel que Docker Engine, Podman, containerd, CRI-O, Incus, ou systemd-nspawn. Dans les environnements de cluster, il peut aussi y avoir un **orchestrateur** tel que Kubernetes décidant de la posture de sécurité demandée via la configuration de la charge de travail. Enfin, le **noyau** est ce qui applique réellement les namespaces, cgroups, seccomp, et la politique MAC.

Ce modèle en couches est important pour comprendre les valeurs par défaut. Une restriction peut être demandée par Kubernetes, traduite via CRI par containerd ou CRI-O, convertie en spec OCI par le wrapper runtime, et seulement alors appliquée par `runc`, `crun`, `runsc`, ou un autre runtime contre le noyau. Lorsque les valeurs par défaut diffèrent entre les environnements, c'est souvent parce qu'une de ces couches a modifié la configuration finale. Le même mécanisme peut donc apparaître dans Docker ou Podman comme un flag CLI, dans Kubernetes comme un champ Pod ou `securityContext`, et dans des stacks runtime de bas niveau comme une configuration OCI générée pour la charge de travail. Pour cette raison, les exemples CLI de cette section doivent être lus comme une **syntaxe spécifique au runtime pour un concept général de conteneur**, et non comme des flags universels supportés par chaque outil.

## La véritable frontière de sécurité des conteneurs

En pratique, la sécurité des conteneurs vient d'**un recouvrement de contrôles**, pas d'un contrôle unique parfait. Les namespaces isolent la visibilité. Les cgroups gouvernent et limitent l'utilisation des ressources. Les capabilities réduisent ce qu'un processus apparemment privilégié peut réellement faire. seccomp bloque les syscalls dangereux avant qu'ils n'atteignent le noyau. AppArmor et SELinux ajoutent du Mandatory Access Control par-dessus les contrôles DAC normaux. `no_new_privs`, les chemins procfs masqués, et les chemins système en lecture seule rendent les chaînes d'abus de privilèges et de proc/sys courantes plus difficiles. Le runtime lui-même compte aussi car il décide comment les mounts, sockets, labels, et les joins de namespaces sont créés.

C'est pourquoi beaucoup de documentation sur la sécurité des conteneurs semble répétitive. La même chaîne d'évasion dépend souvent de plusieurs mécanismes à la fois. Par exemple, un bind mount hôte en écriture est mauvais, mais il devient bien pire si le conteneur s'exécute aussi en vrai root sur l'hôte, a `CAP_SYS_ADMIN`, n'est pas confiné par seccomp, et n'est pas restreint par SELinux ou AppArmor. De même, le partage de PID avec l'hôte est une exposition sérieuse, mais il devient énormément plus utile pour un attaquant lorsqu'il est combiné avec `CAP_SYS_PTRACE`, des protections procfs faibles, ou des outils d'entrée de namespace tels que `nsenter`. La bonne façon de documenter le sujet n'est donc pas de répéter la même attaque sur chaque page, mais d'expliquer ce que chaque couche apporte à la frontière finale.

## Comment lire cette section

La section est organisée des concepts les plus généraux aux plus spécifiques.

Commencez par la vue d'ensemble du runtime et de l'écosystème :

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Puis passez en revue les plans de contrôle et les surfaces de la supply-chain qui décident fréquemment si un attaquant a même besoin d'une évasion du noyau :

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
authorization-plugins.md
{{#endref}}

{{#ref}}
image-security-and-secrets.md
{{#endref}}

{{#ref}}
assessment-and-hardening.md
{{#endref}}

Ensuite, entrez dans le modèle de protection :

{{#ref}}
protections/
{{#endref}}

Les pages sur les namespaces expliquent individuellement les primitives d'isolation du noyau :

{{#ref}}
protections/namespaces/
{{#endref}}

Les pages sur les cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, les chemins masqués, et les chemins en lecture seule expliquent les mécanismes qui sont habituellement superposés aux namespaces :

{{#ref}}
protections/cgroups.md
{{#endref}}

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/seccomp.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

{{#ref}}
protections/no-new-privileges.md
{{#endref}}

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

{{#ref}}
distroless.md
{{#endref}}

{{#ref}}
privileged-containers.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Une bonne démarche d'énumération

Lors de l'évaluation d'une cible conteneurisée, il est bien plus utile de poser un petit ensemble de questions techniques précises que de sauter immédiatement sur des PoC d'évasion célèbres. Identifiez d'abord la **stack** : Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer, ou quelque chose de plus spécialisé. Ensuite identifiez le **runtime** : `runc`, `crun`, `runsc`, `kata-runtime`, ou une autre implémentation compatible OCI. Après cela, vérifiez si l'environnement est **rootful ou rootless**, si les **user namespaces** sont actifs, si des **host namespaces** sont partagés, quelles **capabilities** restent, si **seccomp** est activé, si une **politique MAC** applique réellement, si des **mounts ou sockets dangereux** sont présents, et si le processus peut interagir avec l'API du container runtime.

Ces réponses vous apprennent bien plus sur la posture de sécurité réelle que le nom de l'image de base ne le fera jamais. Dans de nombreuses évaluations, vous pouvez prédire la famille d'évasion probable avant même de lire un seul fichier applicatif, simplement en comprenant la configuration finale du conteneur.

## Portée

Cette section couvre le vieux contenu centré sur Docker sous une organisation orientée conteneur : exposition du runtime et du daemon, authorization plugins, trust des images et secrets de build, mounts sensibles de l'hôte, workloads distroless, containers privilégiés, et les protections du noyau normalement superposées autour de l'exécution de conteneurs.
{{#include ../../../banners/hacktricks-training.md}}
