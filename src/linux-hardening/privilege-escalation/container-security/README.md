# Sécurité des conteneurs

{{#include ../../../banners/hacktricks-training.md}}

## Ce qu'est réellement un container

Une façon pratique de définir un container est la suivante : un container est un **arbre de processus Linux ordinaire** qui a été démarré sous une configuration de type OCI de sorte qu'il voit un système de fichiers contrôlé, un ensemble contrôlé de ressources du kernel et un modèle de privilèges restreint. Le processus peut croire qu'il est PID 1, qu'il possède sa propre pile réseau, qu'il possède son propre hostname et ressources IPC, et peut même s'exécuter en tant que root à l'intérieur de son propre espace de noms utilisateur. Mais sous le capot, c'est toujours un processus de l'hôte que le kernel ordonne comme n'importe quel autre.

C'est pourquoi la sécurité des containers consiste vraiment à étudier comment cette illusion est construite et comment elle peut échouer. Si le mount namespace est faible, le processus peut voir le système de fichiers de l'hôte. Si l'espace de noms utilisateur est absent ou désactivé, root à l'intérieur du container peut se mapper trop étroitement sur root de l'hôte. Si seccomp n'est pas confiné et que l'ensemble des capabilities est trop large, le processus peut atteindre des syscalls et des fonctionnalités privilégiées du kernel qui auraient dû rester hors de portée. Si le runtime socket est monté à l'intérieur du container, le container peut ne pas avoir besoin d'une breakout du kernel du tout puisqu'il peut simplement demander au runtime de lancer un container frère plus puissant ou de monter directement le filesystem racine de l'hôte.

## En quoi les containers diffèrent des machines virtuelles

Une VM transporte normalement son propre kernel et une frontière d'abstraction matérielle. Cela signifie que le kernel invité peut planter, faire un panic ou être exploité sans impliquer automatiquement un contrôle direct du kernel de l'hôte. Dans les containers, la charge de travail n'obtient pas un kernel séparé. À la place, elle reçoit une vue filtrée et namespaced du même kernel que celui utilisé par l'hôte. Par conséquent, les containers sont généralement plus légers, plus rapides à démarrer, plus faciles à empaqueter densément sur une machine et mieux adaptés au déploiement d'applications de courte durée. Le prix à payer est que la frontière d'isolation dépend beaucoup plus directement d'une configuration correcte de l'hôte et du runtime.

Cela ne veut pas dire que les containers sont « insecure » et que les VMs sont « secure ». Cela signifie que le modèle de sécurité est différent. Une pile de containers bien configurée avec exécution rootless, des espaces de noms utilisateur, seccomp par défaut, un ensemble strict de capabilities, pas de partage de namespace avec l'hôte et une forte application de SELinux ou AppArmor peut être très robuste. À l'inverse, un container démarré avec `--privileged`, partage PID/network avec l'hôte, le socket Docker monté à l'intérieur, et un bind mount writable de `/` est fonctionnellement beaucoup plus proche d'un accès root host que d'un sandbox d'application correctement isolé. La différence provient des couches qui ont été activées ou désactivées.

Il existe aussi un terrain intermédiaire que les lecteurs doivent comprendre car il apparaît de plus en plus souvent dans les environnements réels. Les runtimes de containers sandboxés tels que gVisor et Kata Containers renforcent intentionnellement la frontière au-delà d'un container `runc` classique. gVisor place une couche de kernel en espace utilisateur entre la charge de travail et de nombreuses interfaces du kernel de l'hôte, tandis que Kata lance la charge de travail à l'intérieur d'une machine virtuelle légère. Ceux-ci sont toujours utilisés via les écosystèmes de containers et les workflows d'orchestration, mais leurs propriétés de sécurité diffèrent des runtimes OCI classiques et ne doivent pas être mentalement regroupés avec les « normal Docker containers » comme si tout se comportait de la même manière.

## La pile des containers : plusieurs couches, pas une seule

Quand quelqu'un dit « ce container est insecure », la question utile suivante est : **quelle couche l'a rendu insecure ?** Une charge de travail containerisée est généralement le résultat de plusieurs composants fonctionnant ensemble.

En haut, il y a souvent une **couche de build d'image** comme BuildKit, Buildah ou Kaniko, qui crée l'image OCI et les métadonnées. Au-dessus du runtime bas niveau, il peut y avoir un **engine ou manager** comme Docker Engine, Podman, containerd, CRI-O, Incus ou systemd-nspawn. Dans les environnements de cluster, il peut aussi y avoir un **orchestrator** comme Kubernetes qui décide de la posture de sécurité demandée via la configuration de la charge de travail. Enfin, le **kernel** est ce qui applique réellement les namespaces, cgroups, seccomp et la politique MAC.

Ce modèle en couches est important pour comprendre les valeurs par défaut. Une restriction peut être demandée par Kubernetes, traduite via CRI par containerd ou CRI-O, convertie en spec OCI par le wrapper runtime, et seulement alors appliquée par `runc`, `crun`, `runsc` ou un autre runtime contre le kernel. Lorsque les valeurs par défaut diffèrent entre environnements, c'est souvent parce que l'une de ces couches a modifié la configuration finale. Le même mécanisme peut donc apparaître dans Docker ou Podman comme un flag CLI, dans Kubernetes comme un Pod ou un champ `securityContext`, et dans des stacks runtime de bas niveau comme une configuration OCI générée pour la charge de travail. Pour cette raison, les exemples CLI de cette section doivent être lus comme une **syntaxe runtime-spécifique pour un concept général de container**, et non comme des flags universels supportés par chaque outil.

## La véritable frontière de sécurité des containers

En pratique, la sécurité des containers provient d'**contrôles qui se chevauchent**, pas d'un seul contrôle parfait. Les namespaces isolent la visibilité. Les cgroups gouvernent et limitent l'utilisation des ressources. Les capabilities réduisent ce qu'un processus semblant privilégié peut réellement faire. seccomp bloque les syscalls dangereux avant qu'ils n'atteignent le kernel. AppArmor et SELinux ajoutent un Mandatory Access Control par-dessus les contrôles DAC normaux. `no_new_privs`, les chemins procfs masqués et les chemins système en lecture seule rendent les chaînes communes d'abus de privilèges et de proc/sys plus difficiles. Le runtime lui-même compte aussi car il décide comment les mounts, sockets, labels et jointures de namespaces sont créés.

C'est pourquoi beaucoup de documentation sur la sécurité des containers semble répétitive. La même chaîne d'évasion dépend souvent de plusieurs mécanismes en même temps. Par exemple, un bind mount en écriture de l'hôte est mauvais, mais il devient bien pire si le container s'exécute aussi en tant que vrai root sur l'hôte, possède `CAP_SYS_ADMIN`, n'est pas confiné par seccomp et n'est pas restreint par SELinux ou AppArmor. De même, le partage PID avec l'hôte est une exposition sérieuse, mais il devient dramatiquement plus utile pour un attaquant lorsqu'il est combiné avec `CAP_SYS_PTRACE`, des protections procfs faibles, ou des outils d'entrée dans les namespaces comme `nsenter`. La bonne façon de documenter le sujet n'est donc pas de répéter la même attaque sur chaque page, mais d'expliquer ce que chaque couche apporte à la frontière finale.

## Comment lire cette section

La section est organisée des concepts les plus généraux aux plus spécifiques.

Commencez par la vue d'ensemble du runtime et de l'écosystème :

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Ensuite, passez en revue les plans de contrôle et les surfaces de la supply-chain qui décident fréquemment si un attaquant a même besoin d'une breakout du kernel :

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

Puis passez au modèle de protection :

{{#ref}}
protections/
{{#endref}}

Les pages sur les namespaces expliquent individuellement les primitives d'isolation du kernel :

{{#ref}}
protections/namespaces/
{{#endref}}

Les pages sur cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, les chemins masqués et les chemins système en lecture seule expliquent les mécanismes qui sont généralement superposés aux namespaces :

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

## Un bon état d'esprit pour l'énumération initiale

Lors de l'évaluation d'une cible containerisée, il est beaucoup plus utile de poser un petit ensemble de questions techniques précises que de sauter immédiatement sur des PoC d'évasion célèbres. D'abord, identifiez la **stack** : Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer, ou quelque chose de plus spécialisé. Ensuite identifiez le **runtime** : `runc`, `crun`, `runsc`, `kata-runtime` ou une autre implémentation compatible OCI. Après cela, vérifiez si l'environnement est **rootful ou rootless**, si les **espaces de noms utilisateur** sont actifs, si des **namespaces de l'hôte** sont partagés, quelles **capabilities** restent, si **seccomp** est activé, si une politique **MAC** applique réellement, si des **mounts ou sockets dangereux** sont présents, et si le processus peut interagir avec l'API du runtime du container.

Ces réponses vous informent bien plus sur la posture réelle de sécurité que le nom de l'image de base ne le fera jamais. Dans de nombreuses évaluations, vous pouvez prédire la famille d'évasions probable avant même de lire un seul fichier d'application simplement en comprenant la configuration finale du container.

## Couverture

Cette section couvre le vieux matériel centré sur Docker sous une organisation orientée container : exposition du runtime et du daemon, authorization plugins, trust d'image et secrets de build, mounts sensibles de l'hôte, workloads distroless, containers privilégiés, et les protections du kernel normalement superposées à l'exécution des containers.
