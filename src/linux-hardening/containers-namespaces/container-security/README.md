# Sécurité des conteneurs

## Ce qu'est réellement un conteneur

Une manière pratique de définir un conteneur est la suivante : un conteneur est un **arbre de processus Linux ordinaire** démarré avec une configuration spécifique de type OCI, de sorte qu'il voit un système de fichiers contrôlé, un ensemble contrôlé de ressources du kernel et un modèle de privilèges restreint. Le processus peut croire qu'il est le PID 1, qu'il possède sa propre pile réseau, son propre hostname et ses propres ressources IPC, et peut même s'exécuter en tant que root dans son propre user namespace. Mais sous le capot, il reste un processus de l'hôte que le kernel ordonnance comme n'importe quel autre.

C'est pourquoi la container security consiste réellement à étudier la manière dont cette illusion est construite et comment elle échoue. Si le mount namespace est faible, le processus peut voir le système de fichiers de l'hôte. Si le user namespace est absent ou désactivé, root dans le conteneur peut correspondre trop directement à root sur l'hôte. Si seccomp est unconfined et que l'ensemble des capabilities est trop large, le processus peut accéder à des syscalls et à des fonctionnalités privilégiées du kernel qui auraient dû rester inaccessibles. Si le socket du runtime est monté dans le conteneur, celui-ci peut ne pas avoir besoin d'un kernel breakout, car il peut simplement demander au runtime de lancer un conteneur sibling plus puissant ou de monter directement le système de fichiers root de l'hôte.

## Différences entre les conteneurs et les machines virtuelles

Une VM possède normalement son propre kernel et sa propre frontière d'abstraction matérielle. Cela signifie que le kernel guest peut planter, déclencher un panic ou être exploité sans que cela implique automatiquement un contrôle direct du kernel host. Dans les conteneurs, la workload n'obtient pas de kernel séparé. Elle reçoit à la place une vue soigneusement filtrée et organisée en namespaces du même kernel que celui utilisé par l'hôte. Par conséquent, les conteneurs sont généralement plus légers, démarrent plus rapidement, sont plus faciles à déployer en grande densité sur une machine et conviennent mieux au déploiement d'applications à courte durée de vie. Le prix à payer est que la frontière d'isolation dépend beaucoup plus directement de la configuration correcte de l'hôte et du runtime.

Cela ne signifie pas que les conteneurs sont « insecure » et que les VM sont « secure ». Cela signifie que le security model est différent. Une stack de conteneurs correctement configurée avec une exécution rootless, des user namespaces, le seccomp par défaut, un ensemble strict de capabilities, aucun partage de host namespace et une enforcement forte de SELinux ou AppArmor peut être très robuste. À l'inverse, un conteneur démarré avec `--privileged`, un partage des host PID/network namespaces, le socket Docker monté à l'intérieur et un bind mount inscriptible de `/` est fonctionnellement beaucoup plus proche d'un accès root à l'hôte que d'une application isolée dans un sandbox sécurisé. La différence vient des couches qui ont été activées ou désactivées.

Il existe également une situation intermédiaire que les lecteurs doivent comprendre, car elle apparaît de plus en plus souvent dans les environnements réels. Les **sandboxed container runtimes** tels que **gVisor** et **Kata Containers** renforcent intentionnellement la frontière au-delà d'un conteneur `runc` classique. gVisor place une couche de kernel en userspace entre la workload et de nombreuses interfaces du kernel host, tandis que Kata lance la workload dans une machine virtuelle légère. Ils sont toujours utilisés via des ecosystems de conteneurs et des workflows d'orchestration, mais leurs propriétés de sécurité diffèrent de celles des runtimes OCI classiques et ne doivent pas être mentalement regroupées avec les « conteneurs Docker normaux », comme si tout fonctionnait de la même manière.

## La stack des conteneurs : plusieurs couches, pas une seule

Lorsqu'une personne dit « ce conteneur est insecure », la question utile à poser ensuite est : **quelle couche l'a rendu insecure ?** Une workload conteneurisée est généralement le résultat de plusieurs composants qui fonctionnent ensemble.

Au sommet, on trouve souvent une **couche de build d'image** telle que BuildKit, Buildah ou Kaniko, qui crée l'image OCI et ses métadonnées. Au-dessus du runtime de bas niveau, il peut y avoir un **engine ou manager** tel que Docker Engine, Podman, containerd, CRI-O, Incus ou systemd-nspawn. Dans les environnements en cluster, un **orchestrator** tel que Kubernetes peut également décider de la security posture demandée via la configuration de la workload. Enfin, le **kernel** est ce qui applique réellement les namespaces, les cgroups, seccomp et la MAC policy.

Ce modèle en couches est important pour comprendre les valeurs par défaut. Une restriction peut être demandée par Kubernetes, traduite via CRI par containerd ou CRI-O, convertie en OCI spec par le runtime wrapper, puis appliquée par `runc`, `crun`, `runsc` ou un autre runtime au niveau du kernel. Lorsque les valeurs par défaut diffèrent entre les environnements, c'est souvent parce que l'une de ces couches a modifié la configuration finale. Le même mécanisme peut donc apparaître dans Docker ou Podman sous la forme d'un CLI flag, dans Kubernetes sous la forme d'un champ Pod ou `securityContext`, et dans les runtime stacks de bas niveau sous la forme d'une configuration OCI générée pour la workload. Pour cette raison, les exemples de CLI de cette section doivent être lus comme une **syntaxe spécifique au runtime pour un concept général de conteneur**, et non comme des flags universels pris en charge par tous les outils.

## La véritable frontière de sécurité des conteneurs

En pratique, la container security repose sur des **contrôles qui se chevauchent**, et non sur un contrôle unique et parfait. Les namespaces isolent la visibilité. Les cgroups régissent et limitent l'utilisation des ressources. Les capabilities réduisent ce qu'un processus ayant une apparence privilégiée peut réellement faire. seccomp bloque les syscalls dangereux avant qu'ils n'atteignent le kernel. AppArmor et SELinux ajoutent une Mandatory Access Control par-dessus les contrôles DAC normaux. `no_new_privs`, les chemins procfs masqués et les chemins système en lecture seule rendent plus difficiles les chaînes courantes d'abus de privilèges et de proc/sys. Le runtime lui-même est également important, car il décide de la manière dont les mounts, les sockets, les labels et les joins de namespaces sont créés.

C'est pourquoi de nombreux documents sur la container security semblent répétitifs. Une même chaîne d'escape dépend souvent de plusieurs mécanismes à la fois. Par exemple, un bind mount inscriptible de l'hôte est dangereux, mais il devient bien plus grave si le conteneur s'exécute également en tant que root réel sur l'hôte, possède `CAP_SYS_ADMIN`, est unconfined par seccomp et n'est pas restreint par SELinux ou AppArmor. De même, le partage du host PID namespace constitue une exposition sérieuse, mais il devient considérablement plus utile à un attaquant lorsqu'il est combiné à `CAP_SYS_PTRACE`, à de faibles protections procfs ou à des outils d'entrée dans les namespaces tels que `nsenter`. La bonne manière de documenter ce sujet n'est donc pas de répéter la même attaque sur chaque page, mais d'expliquer la contribution de chaque couche à la frontière finale.

## Comment lire cette section

La section est organisée des concepts les plus généraux aux concepts les plus spécifiques.

Commencez par la présentation du runtime et de l'ecosystem :

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Examinez ensuite les control planes et les supply-chain surfaces qui déterminent souvent si un attaquant a réellement besoin d'un kernel escape :

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

Les pages consacrées aux cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, aux masked paths et aux read-only system paths expliquent les mécanismes généralement ajoutés par-dessus les namespaces :

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

## Une bonne approche initiale de l'énumération

Lors de l'évaluation d'une cible conteneurisée, il est beaucoup plus utile de poser un petit ensemble de questions techniques précises que de se précipiter immédiatement sur de célèbres PoC d'escape. Commencez par identifier la **stack** : Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer ou quelque chose de plus spécialisé. Identifiez ensuite le **runtime** : `runc`, `crun`, `runsc`, `kata-runtime` ou une autre implémentation compatible OCI. Vérifiez ensuite si l'environnement est **rootful ou rootless**, si les **user namespaces** sont actifs, si des **host namespaces** sont partagés, quelles **capabilities** sont conservées, si **seccomp** est activé, si une **MAC policy** est réellement enforced, si des **mounts ou sockets dangereux** sont présents et si le processus peut interagir avec l'API du runtime de conteneurs.

Ces réponses en disent beaucoup plus sur la security posture réelle que le nom de l'image de base. Dans de nombreuses évaluations, il est possible de prévoir la famille d'escape probable avant même de lire un seul fichier de l'application, simplement en comprenant la configuration finale du conteneur.

## Couverture

Cette section couvre l'ancien contenu centré sur Docker, réorganisé autour des conteneurs : exposition du runtime et du daemon, authorization plugins, confiance dans les images et build secrets, mounts sensibles de l'hôte, workloads distroless, conteneurs privilégiés et protections du kernel généralement ajoutées autour de l'exécution des conteneurs.

{{#include ../../../banners/hacktricks-training.md}}
