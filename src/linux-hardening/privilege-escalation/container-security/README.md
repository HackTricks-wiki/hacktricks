# Sécurité des conteneurs

{{#include ../../../banners/hacktricks-training.md}}

## Ce qu'est réellement un conteneur

Une façon pratique de définir un conteneur est la suivante : un conteneur est un **arbre de processus Linux régulier** qui a été lancé sous une configuration de type OCI particulière de sorte qu'il voit un système de fichiers contrôlé, un ensemble contrôlé de ressources du kernel et un modèle de privilèges restreint. Le processus peut croire qu'il est PID 1, peut croire qu'il a sa propre pile réseau, peut croire qu'il possède son propre hostname et ses ressources IPC, et peut même s'exécuter en tant que root à l'intérieur de son propre user namespace. Mais sous le capot, il reste un processus de l'hôte que le kernel ordonne comme n'importe quel autre.

C'est pourquoi la sécurité des conteneurs est vraiment l'étude de la façon dont cette illusion est construite et de la façon dont elle échoue. Si le mount namespace est mal isolé, le processus peut voir le système de fichiers de l'hôte. Si le user namespace est absent ou désactivé, root à l'intérieur du conteneur peut se mapper trop étroitement à root sur l'hôte. Si seccomp n'est pas confiné et que le capability set est trop large, le processus peut atteindre des syscalls et des fonctionnalités privilégiées du kernel qui auraient dû rester hors de portée. Si le runtime socket est monté à l'intérieur du conteneur, le conteneur peut ne pas avoir besoin d'une breakout kernel du tout car il peut simplement demander au runtime de lancer un conteneur frère plus puissant ou de monter directement le système de fichiers racine de l'hôte.

## En quoi les conteneurs diffèrent des machines virtuelles

Une VM porte normalement son propre kernel et une frontière d'abstraction matérielle. Cela signifie que le guest kernel peut planter, faire un panic, ou être exploité sans impliquer automatiquement le contrôle direct du kernel de l'hôte. Dans les conteneurs, la charge de travail n'obtient pas un noyau séparé. À la place, elle obtient une vue soigneusement filtrée et namespaced du même kernel que celui utilisé par l'hôte. En conséquence, les conteneurs sont généralement plus légers, démarrent plus rapidement, sont plus faciles à densifier sur une machine, et mieux adaptés au déploiement d'applications éphémères. Le prix à payer est que la frontière d'isolation dépend beaucoup plus directement d'une configuration correcte de l'hôte et du runtime.

Cela ne veut pas dire que les conteneurs sont «insécurisés» et que les VM sont «sécurisées». Cela signifie que le modèle de sécurité est différent. Une pile de conteneurs bien configurée avec exécution rootless, user namespaces, seccomp par défaut, un capability set strict, pas de partage de namespace avec l'hôte, et une forte application de SELinux ou AppArmor peut être très robuste. À l'inverse, un conteneur démarré avec `--privileged`, partage PID/network avec l'hôte, le Docker socket monté à l'intérieur, et un bind mount inscriptible de `/` est fonctionnellement beaucoup plus proche d'un accès root de l'hôte que d'un sandbox d'application correctement isolé. La différence vient des couches qui ont été activées ou désactivées.

Il existe aussi un terrain intermédiaire que les lecteurs doivent comprendre car il apparaît de plus en plus souvent dans des environnements réels. Les runtimes de conteneurs sandboxés tels que gVisor et Kata Containers durcissent intentionnellement la frontière au-delà d'un conteneur `runc` classique. gVisor place une couche de kernel en espace utilisateur entre la charge de travail et de nombreuses interfaces du kernel de l'hôte, tandis que Kata lance la charge de travail à l'intérieur d'une machine virtuelle légère. Ceux-ci sont toujours utilisés via les écosystèmes de conteneurs et les workflows d'orchestration, mais leurs propriétés de sécurité diffèrent des runtimes OCI nus et ne devraient pas être mentalement regroupés avec les «normal Docker containers» comme si tout fonctionnait de la même manière.

## La pile des conteneurs : plusieurs couches, pas une seule

Quand quelqu'un dit «ce conteneur est insecure», la question utile à poser ensuite est : **quelle couche l'a rendu insecure ?** Une charge de travail containerisée est généralement le résultat de plusieurs composants travaillant ensemble.

En haut, il y a souvent une **couche de build d'image** telle que BuildKit, Buildah, ou Kaniko, qui crée l'image OCI et les metadata. Au-dessus du runtime de bas niveau, il peut y avoir un **engine ou manager** comme Docker Engine, Podman, containerd, CRI-O, Incus, ou systemd-nspawn. Dans les environnements de cluster, il peut aussi y avoir un **orchestrator** comme Kubernetes décidant de la posture de sécurité demandée via la configuration de la charge de travail. Enfin, le **kernel** est ce qui applique effectivement les namespaces, cgroups, seccomp, et la politique MAC.

Ce modèle en couches est important pour comprendre les valeurs par défaut. Une restriction peut être demandée par Kubernetes, traduite via CRI par containerd ou CRI-O, convertie en spec OCI par le wrapper runtime, puis seulement appliquée par `runc`, `crun`, `runsc`, ou un autre runtime contre le kernel. Quand les valeurs par défaut diffèrent entre environnements, c'est souvent parce qu'une de ces couches a changé la configuration finale. Le même mécanisme peut donc apparaître dans Docker ou Podman comme un flag CLI, dans Kubernetes comme un champ Pod ou `securityContext`, et dans des stacks runtime de bas niveau comme une configuration OCI générée pour la charge de travail. Pour cette raison, les exemples CLI de cette section doivent être lus comme une **syntaxe spécifique au runtime pour un concept général de conteneur**, et non comme des flags universels supportés par tous les outils.

## La véritable frontière de sécurité des conteneurs

En pratique, la sécurité des conteneurs provient d'**un chevauchement de contrôles**, pas d'un seul contrôle parfait. Les namespaces isolent la visibilité. Les cgroups gouvernent et limitent l'utilisation des ressources. Les capabilities réduisent ce qu'un processus apparemment privilégié peut réellement faire. Seccomp bloque les syscalls dangereux avant qu'ils n'atteignent le kernel. AppArmor et SELinux ajoutent du Mandatory Access Control en plus des contrôles DAC normaux. `no_new_privs`, les chemins procfs masqués, et les chemins système en lecture seule rendent les chaînes d'abus de privilèges et de proc/sys courantes plus difficiles. Le runtime lui-même compte aussi car il décide comment les mounts, sockets, labels, et jointures de namespaces sont créés.

C'est pourquoi beaucoup de documentation sur la sécurité des conteneurs semble répétitive. La même chaîne d'évasion dépend souvent de plusieurs mécanismes à la fois. Par exemple, un bind mount inscriptible depuis l'hôte est mauvais, mais il devient bien pire si le conteneur s'exécute aussi en tant que véritable root sur l'hôte, dispose de `CAP_SYS_ADMIN`, n'est pas confiné par seccomp, et n'est pas restreint par SELinux ou AppArmor. De même, le partage PID de l'hôte est une exposition sérieuse, mais il devient dramatiquement plus utile pour un attaquant quand il est combiné avec `CAP_SYS_PTRACE`, des protections procfs faibles, ou des outils d'entrée dans les namespaces tels que `nsenter`. La bonne façon de documenter le sujet n'est donc pas de répéter la même attaque sur chaque page, mais d'expliquer ce que chaque couche apporte à la frontière finale.

## Comment lire cette section

La section est organisée des concepts les plus généraux aux plus spécifiques.

Commencez par l'aperçu du runtime et de l'écosystème :

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Puis passez en revue les plans de contrôle et les surfaces de la supply-chain qui décident fréquemment si un attaquant a même besoin d'une évasion kernel :

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

Les pages sur les namespaces expliquent individuellement les primitives d'isolation du kernel :

{{#ref}}
protections/namespaces/
{{#endref}}

Les pages sur cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, les chemins masqués, et les chemins en lecture seule expliquent les mécanismes qui sont généralement empilés au-dessus des namespaces :

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

## Une bonne méthode d'énumération initiale

Lors de l'évaluation d'une cible containerisée, il est beaucoup plus utile de poser un petit ensemble de questions techniques précises que de sauter immédiatement sur des PoC d'évasion célèbres. D'abord, identifiez la **stack** : Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer, ou quelque chose de plus spécialisé. Puis identifiez le **runtime** : `runc`, `crun`, `runsc`, `kata-runtime`, ou une autre implémentation compatible OCI. Après cela, vérifiez si l'environnement est **rootful ou rootless**, si les **user namespaces** sont actifs, si des **host namespaces** sont partagés, quelles **capabilities** restent, si **seccomp** est activé, si une **politique MAC** applique réellement, si des **mounts ou sockets dangereux** sont présents, et si le processus peut interagir avec l'API du container runtime.

Ces réponses vous en diront bien plus sur la posture réelle de sécurité que le nom de l'image de base. Dans de nombreuses évaluations, vous pouvez prédire la famille d'évasion probable avant d'avoir lu un seul fichier d'application simplement en comprenant la configuration finale du conteneur.

## Couverture

Cette section couvre l'ancien matériau centré sur Docker sous une organisation orientée conteneur : exposition du runtime et du daemon, authorization plugins, confiance des images et secrets de build, mounts sensibles de l'hôte, workloads distroless, conteneurs privilégiés, et les protections du kernel normalement empilées autour de l'exécution des conteneurs.
{{#include ../../../banners/hacktricks-training.md}}
