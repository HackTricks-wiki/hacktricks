# Sécurité des conteneurs

{{#include ../../../banners/hacktricks-training.md}}

## Ce Qu'est Réellement Un Conteneur

Une manière pratique de définir un conteneur est la suivante : un conteneur est un **arbre de processus Linux normal** démarré avec une configuration de type OCI spécifique, afin qu'il voie un système de fichiers contrôlé, un ensemble contrôlé de ressources du kernel et un modèle de privilèges restreint. Le processus peut croire qu'il est le PID 1, peut croire qu'il possède sa propre pile réseau, peut croire qu'il possède son propre hostname et ses propres ressources IPC, et peut même s'exécuter en tant que root dans son propre user namespace. Mais en réalité, il reste un processus de l'hôte que le kernel planifie comme n'importe quel autre.

C'est pourquoi la sécurité des conteneurs consiste réellement à étudier la manière dont cette illusion est construite et comment elle échoue. Si le mount namespace est faible, le processus peut voir le système de fichiers de l'hôte. Si le user namespace est absent ou désactivé, root dans le conteneur peut être mappé trop directement sur root sur l'hôte. Si seccomp est unconfined et que l'ensemble des capabilities est trop large, le processus peut accéder à des syscalls et à des fonctionnalités privilégiées du kernel qui auraient dû rester inaccessibles. Si le socket du runtime est monté dans le conteneur, celui-ci peut ne pas avoir besoin d'un kernel breakout, car il peut simplement demander au runtime de lancer un conteneur sibling plus puissant ou de monter directement le système de fichiers root de l'hôte.

## Différences Entre Les Conteneurs Et Les Machines Virtuelles

Une VM possède normalement son propre kernel et sa propre frontière d'abstraction matérielle. Cela signifie que le kernel guest peut se crasher, paniquer ou être exploité sans impliquer automatiquement un contrôle direct du kernel host. Dans les conteneurs, la workload n'a pas de kernel séparé. Elle obtient plutôt une vue soigneusement filtrée et organisée en namespaces du même kernel que celui utilisé par l'hôte. Par conséquent, les conteneurs sont généralement plus légers, démarrent plus rapidement, sont plus faciles à déployer en grand nombre sur une machine et sont mieux adaptés au déploiement d'applications de courte durée. En contrepartie, la frontière d'isolation dépend beaucoup plus directement d'une configuration correcte de l'hôte et du runtime.

Cela ne signifie pas que les conteneurs sont « insecure » et que les VM sont « secure ». Cela signifie que le modèle de sécurité est différent. Une stack de conteneurs correctement configurée, avec une exécution rootless, des user namespaces, le seccomp par défaut, un ensemble strict de capabilities, aucun partage de host namespace et une application stricte de SELinux ou AppArmor peut être très robuste. À l'inverse, un conteneur démarré avec `--privileged`, un partage du host PID/network, le socket Docker monté à l'intérieur et un bind mount inscriptible de `/` est fonctionnellement beaucoup plus proche d'un accès root à l'hôte que d'une sandbox d'application correctement isolée. La différence vient des couches qui ont été activées ou désactivées.

Il existe également un juste milieu que les lecteurs doivent comprendre, car il apparaît de plus en plus souvent dans les environnements réels. Les **sandboxed container runtimes** tels que **gVisor** et **Kata Containers** renforcent intentionnellement la frontière au-delà d'un conteneur `runc` classique. gVisor place une couche de kernel en userspace entre la workload et de nombreuses interfaces du kernel host, tandis que Kata lance la workload dans une machine virtuelle légère. Ils sont toujours utilisés via des écosystèmes de conteneurs et des workflows d'orchestration, mais leurs propriétés de sécurité diffèrent de celles des runtimes OCI classiques et ils ne doivent pas être mentalement regroupés avec les « conteneurs Docker normaux », comme si tout fonctionnait de la même manière.

## La Stack De Conteneurs : Plusieurs Couches, Pas Une Seule

Lorsqu'une personne dit « ce conteneur est insecure », la question utile à poser ensuite est : **quelle couche l'a rendu insecure ?** Une workload conteneurisée est généralement le résultat de plusieurs composants qui fonctionnent ensemble.

Au sommet, on trouve souvent une **couche de build d'image** telle que BuildKit, Buildah ou Kaniko, qui crée l'image OCI et ses métadonnées. Au-dessus du runtime bas niveau, il peut y avoir un **engine ou manager** tel que Docker Engine, Podman, containerd, CRI-O, Incus ou systemd-nspawn. Dans les environnements en cluster, un **orchestrator** tel que Kubernetes peut également décider de la posture de sécurité demandée via la configuration de la workload. Enfin, le **kernel** est ce qui applique réellement les namespaces, les cgroups, seccomp et la politique MAC.

Ce modèle en couches est important pour comprendre les valeurs par défaut. Une restriction peut être demandée par Kubernetes, traduite via CRI par containerd ou CRI-O, convertie en spec OCI par le runtime wrapper, puis seulement appliquée par `runc`, `crun`, `runsc` ou un autre runtime au niveau du kernel. Lorsque les valeurs par défaut diffèrent entre les environnements, c'est souvent parce que l'une de ces couches a modifié la configuration finale. Le même mécanisme peut donc apparaître dans Docker ou Podman comme un flag CLI, dans Kubernetes comme un champ Pod ou `securityContext`, et dans les stacks de runtime bas niveau comme une configuration OCI générée pour la workload. Pour cette raison, les exemples CLI de cette section doivent être lus comme une **syntaxe spécifique au runtime pour un concept général de conteneur**, et non comme des flags universels pris en charge par tous les outils.

## La Véritable Frontière De Sécurité Des Conteneurs

En pratique, la sécurité des conteneurs repose sur des **contrôles qui se chevauchent**, et non sur un contrôle parfait unique. Les namespaces isolent la visibilité. Les cgroups régulent et limitent l'utilisation des ressources. Les capabilities réduisent ce qu'un processus qui semble privilégié peut réellement faire. seccomp bloque les syscalls dangereux avant qu'ils n'atteignent le kernel. AppArmor et SELinux ajoutent un Mandatory Access Control par-dessus les vérifications DAC normales. `no_new_privs`, les chemins procfs masqués et les chemins système en lecture seule rendent plus difficiles les chaînes d'abus courantes de privilèges et de proc/sys. Le runtime lui-même est également important, car il décide de la manière dont les mounts, sockets, labels et joins de namespaces sont créés.

C'est pourquoi de nombreux documents sur la sécurité des conteneurs semblent répétitifs. Une même chaîne d'escape dépend souvent de plusieurs mécanismes à la fois. Par exemple, un host bind mount inscriptible est dangereux, mais il devient bien plus grave si le conteneur s'exécute également en tant que root réel sur l'hôte, possède `CAP_SYS_ADMIN`, n'est pas restreint par seccomp et n'est pas limité par SELinux ou AppArmor. De même, le partage du host PID constitue une exposition sérieuse, mais il devient beaucoup plus utile à un attaquant lorsqu'il est combiné à `CAP_SYS_PTRACE`, à de faibles protections procfs ou à des outils d'entrée dans les namespaces tels que `nsenter`. La bonne manière de documenter ce sujet n'est donc pas de répéter la même attaque sur chaque page, mais d'expliquer ce que chaque couche apporte à la frontière finale.

## Comment Lire Cette Section

La section est organisée des concepts les plus généraux aux plus spécifiques.

Commencez par la vue d'ensemble des runtimes et de l'écosystème :

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Examinez ensuite les control planes et les surfaces de supply chain qui déterminent souvent si un attaquant a réellement besoin d'un kernel escape :

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

Passez ensuite au modèle de protection :

{{#ref}}
protections/
{{#endref}}

Les pages consacrées aux namespaces expliquent individuellement les primitives d'isolation du kernel :

{{#ref}}
protections/namespaces/
{{#endref}}

Les pages consacrées aux cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, aux chemins masqués et aux chemins système en lecture seule expliquent les mécanismes généralement superposés aux namespaces :

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

## Une Bonne Méthode Pour Commencer L'énumération

Lors de l'évaluation d'une cible conteneurisée, il est beaucoup plus utile de poser un petit ensemble de questions techniques précises que de se précipiter immédiatement vers des PoC d'escape connus. Commencez par identifier la **stack** : Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer ou quelque chose de plus spécialisé. Identifiez ensuite le **runtime** : `runc`, `crun`, `runsc`, `kata-runtime` ou une autre implémentation compatible OCI. Vérifiez ensuite si l'environnement est **rootful ou rootless**, si les **user namespaces** sont actifs, si des **host namespaces** sont partagés, quelles **capabilities** sont conservées, si **seccomp** est activé, si une **politique MAC** est réellement appliquée, si des **mounts ou sockets dangereux** sont présents et si le processus peut interagir avec l'API du runtime de conteneurs.

Ces réponses vous en apprendront beaucoup plus sur la posture de sécurité réelle que le nom de l'image de base. Dans de nombreuses évaluations, il est possible de prévoir la famille d'escape probable avant même de lire un seul fichier de l'application, simplement en comprenant la configuration finale du conteneur.

## Couverture

Cette section couvre l'ancien contenu centré sur Docker, réorganisé autour des conteneurs : exposition du runtime et du daemon, authorization plugins, confiance des images et build secrets, mounts sensibles de l'hôte, workloads distroless, conteneurs privilégiés et protections du kernel normalement superposées à l'exécution des conteneurs.
{{#include ../../../banners/hacktricks-training.md}}
