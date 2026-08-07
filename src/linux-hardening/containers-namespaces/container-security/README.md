# Sécurité des conteneurs

{{#include ../../../banners/hacktricks-training.md}}

## Ce Qu'Est Réellement Un Conteneur

Une manière pratique de définir un conteneur est la suivante : un conteneur est un **arbre de processus Linux classique** démarré avec une configuration spécifique de type OCI, de sorte qu'il voit un système de fichiers contrôlé, un ensemble contrôlé de ressources du kernel et un modèle de privilèges restreint. Le processus peut croire qu'il est le PID 1, peut croire qu'il possède sa propre stack réseau, peut croire qu'il gère son propre hostname et ses propres ressources IPC, et peut même s'exécuter en tant que root dans son propre user namespace. Mais en interne, il reste un processus de l'hôte que le kernel planifie comme n'importe quel autre.

C'est pourquoi la sécurité des conteneurs consiste réellement à étudier comment cette illusion est construite et comment elle échoue. Si le mount namespace est faible, le processus peut voir le système de fichiers de l'hôte. Si le user namespace est absent ou désactivé, root dans le conteneur peut être mappé de trop près sur root de l'hôte. Si seccomp est unconfined et que l'ensemble des capabilities est trop large, le processus peut accéder à des syscalls et à des fonctionnalités privilégiées du kernel qui auraient dû rester inaccessibles. Si le socket du runtime est monté dans le conteneur, celui-ci peut ne pas avoir besoin d'un kernel breakout, car il peut simplement demander au runtime de lancer un conteneur sibling plus puissant ou de monter directement le système de fichiers root de l'hôte.

## Différences Entre Les Conteneurs Et Les Machines Virtuelles

Une VM possède normalement son propre kernel et sa propre boundary d'abstraction matérielle. Cela signifie que le kernel guest peut crasher, paniquer ou être exploité sans que cela implique automatiquement un contrôle direct du kernel host. Dans les conteneurs, le workload n'obtient pas de kernel séparé. Il reçoit plutôt une vue soigneusement filtrée et namespacée du même kernel que celui utilisé par l'hôte. Par conséquent, les conteneurs sont généralement plus légers, démarrent plus rapidement, sont plus faciles à déployer en grande densité sur une machine et conviennent mieux au déploiement d'applications de courte durée. En contrepartie, la boundary d'isolation dépend beaucoup plus directement d'une configuration correcte de l'hôte et du runtime.

Cela ne signifie pas que les conteneurs sont « insecure » et que les VM sont « secure ». Cela signifie que le modèle de sécurité est différent. Une stack de conteneurs correctement configurée, avec une exécution rootless, des user namespaces, le seccomp par défaut, un ensemble strict de capabilities, aucun partage de host namespace et une enforcement stricte de SELinux ou AppArmor, peut être très robuste. À l'inverse, un conteneur démarré avec `--privileged`, le partage des host PID/network namespaces, le socket Docker monté à l'intérieur et un bind mount inscriptible de `/` est fonctionnellement beaucoup plus proche d'un accès root à l'hôte que d'une application correctement isolée dans une sandbox. La différence vient des couches activées ou désactivées.

Il existe également une situation intermédiaire que les lecteurs doivent comprendre, car elle apparaît de plus en plus souvent dans les environnements réels. Les **sandboxed container runtimes** tels que **gVisor** et **Kata Containers** renforcent volontairement la boundary au-delà d'un conteneur `runc` classique. gVisor place une couche de kernel en userspace entre le workload et de nombreuses interfaces du kernel host, tandis que Kata lance le workload dans une machine virtuelle légère. Ils sont toujours utilisés via des écosystèmes de conteneurs et des workflows d'orchestration, mais leurs propriétés de sécurité diffèrent de celles des runtimes OCI classiques et ils ne doivent pas être mentalement regroupés avec les « normal Docker containers », comme si tout fonctionnait de la même manière.

## La Stack Des Conteneurs : Plusieurs Couches, Pas Une Seule

Lorsqu'une personne dit « ce conteneur est insecure », la question utile à poser ensuite est : **quelle couche l'a rendu insecure ?** Un workload conteneurisé est généralement le résultat de plusieurs composants qui fonctionnent ensemble.

Au sommet, on trouve souvent une **image build layer** telle que BuildKit, Buildah ou Kaniko, qui crée l'image OCI et ses métadonnées. Au-dessus du low-level runtime, il peut y avoir un **engine ou manager** tel que Docker Engine, Podman, containerd, CRI-O, Incus ou systemd-nspawn. Dans les environnements cluster, il peut également y avoir un **orchestrator** tel que Kubernetes, qui décide de la security posture demandée via la configuration du workload. Enfin, c'est le **kernel** qui applique réellement les namespaces, les cgroups, seccomp et la MAC policy.

Ce modèle en couches est important pour comprendre les defaults. Une restriction peut être demandée par Kubernetes, traduite via CRI par containerd ou CRI-O, convertie en OCI spec par le runtime wrapper, puis seulement appliquée par `runc`, `crun`, `runsc` ou un autre runtime au niveau du kernel. Lorsque les defaults diffèrent entre les environnements, c'est souvent parce que l'une de ces couches a modifié la configuration finale. Le même mécanisme peut donc apparaître dans Docker ou Podman sous la forme d'un CLI flag, dans Kubernetes comme un champ de Pod ou de `securityContext`, et dans les runtime stacks de bas niveau comme une configuration OCI générée pour le workload. Pour cette raison, les exemples CLI de cette section doivent être lus comme une **syntaxe spécifique au runtime pour un concept général de conteneur**, et non comme des flags universels pris en charge par tous les outils.

## La Véritable Boundary De Sécurité D'un Conteneur

En pratique, la sécurité des conteneurs provient de **contrôles qui se chevauchent**, et non d'un contrôle unique et parfait. Les namespaces isolent la visibilité. Les cgroups gouvernent et limitent l'utilisation des ressources. Les capabilities réduisent ce qu'un processus d'apparence privilégiée peut réellement faire. seccomp bloque les syscalls dangereux avant qu'ils n'atteignent le kernel. AppArmor et SELinux ajoutent un Mandatory Access Control par-dessus les vérifications DAC normales. `no_new_privs`, les chemins procfs masqués et les chemins système en lecture seule rendent les chaînes courantes d'abus de privilèges et de proc/sys plus difficiles. Le runtime lui-même est également important, car il décide de la manière dont les mounts, sockets, labels et namespace joins sont créés.

C'est pourquoi une grande partie de la documentation sur la sécurité des conteneurs semble répétitive. La même chaîne d'escape dépend souvent de plusieurs mécanismes à la fois. Par exemple, un host bind mount inscriptible est dangereux, mais il devient bien plus grave si le conteneur s'exécute également en tant que root réel sur l'hôte, possède `CAP_SYS_ADMIN`, n'est pas restreint par seccomp et n'est pas limité par SELinux ou AppArmor. De même, le partage du host PID est une exposition sérieuse, mais il devient nettement plus utile à un attacker lorsqu'il est combiné avec `CAP_SYS_PTRACE`, de faibles protections procfs ou des outils d'entrée dans les namespaces tels que `nsenter`. La bonne manière de documenter ce sujet n'est donc pas de répéter la même attaque sur chaque page, mais d'expliquer ce que chaque couche apporte à la boundary finale.

## Comment Lire Cette Section

La section est organisée des concepts les plus généraux aux concepts les plus spécifiques.

Commencez par la présentation du runtime et de l'écosystème :

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Examinez ensuite les control planes et les supply-chain surfaces qui déterminent fréquemment si un attacker doit même effectuer un kernel escape :

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

## Un Bon État D'Esprit Pour La Première Énumération

Lors de l'assessment d'une cible conteneurisée, il est beaucoup plus utile de poser un petit ensemble de questions techniques précises que de passer immédiatement aux célèbres PoC d'escape. Commencez par identifier la **stack** : Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer ou quelque chose de plus spécialisé. Identifiez ensuite le **runtime** : `runc`, `crun`, `runsc`, `kata-runtime` ou une autre implémentation compatible OCI. Vérifiez ensuite si l'environnement est **rootful ou rootless**, si les **user namespaces** sont actifs, si des **host namespaces** sont partagés, quelles **capabilities** sont conservées, si **seccomp** est activé, si une **MAC policy** est réellement en enforcement, si des **mounts ou sockets dangereux** sont présents et si le processus peut interagir avec l'API du container runtime.

Ces réponses vous en disent beaucoup plus sur la security posture réelle que le nom de la base image. Dans de nombreux assessments, vous pouvez prévoir la famille de breakout probable avant même de lire un seul fichier applicatif, simplement en comprenant la configuration finale du conteneur.

## Couverture

Cette section couvre l'ancien contenu centré sur Docker, réorganisé autour des conteneurs : exposition du runtime et du daemon, authorization plugins, confiance accordée aux images et build secrets, mounts sensibles de l'hôte, workloads distroless, conteneurs privilégiés et protections du kernel habituellement superposées à l'exécution des conteneurs.

{{#include ../../../banners/hacktricks-training.md}}
