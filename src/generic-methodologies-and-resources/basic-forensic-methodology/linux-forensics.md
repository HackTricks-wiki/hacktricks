# Analyse forensique Linux

{{#include ../../banners/hacktricks-training.md}}

## Collecte initiale d'informations

### Informations de base

Tout d'abord, il est recommandé d'avoir une **clé USB** contenant de **bons binaires et bibliothèques connus** (vous pouvez simplement récupérer ubuntu et copier les dossiers _/bin_, _/sbin_, _/lib,_ et _/lib64_), puis de monter la clé USB et de modifier les variables d'environnement afin d'utiliser ces binaires :
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Une fois que vous avez configuré le système pour utiliser des binaires fiables et connus, vous pouvez commencer à **extraire quelques informations de base** :
```bash
date #Date and time (Clock may be skewed, Might be at a different timezone)
uname -a #OS info
ifconfig -a || ip a #Network interfaces (promiscuous mode?)
ps -ef #Running processes
netstat -anp #Proccess and ports
lsof -V #Open files
netstat -rn; route #Routing table
df; mount #Free space and mounted devices
free #Meam and swap space
w #Who is connected
last -Faiwx #Logins
lsmod #What is loaded
cat /etc/passwd #Unexpected data?
cat /etc/shadow #Unexpected data?
find /directory -type f -mtime -1 -print #Find modified files during the last minute in the directory
```
#### Informations suspectes

Lors de l'obtention des informations de base, vous devriez rechercher des éléments inhabituels comme :

- Les **processus root** s'exécutent généralement avec des PIDS faibles ; si vous trouvez donc un processus root avec un PID élevé, vous pouvez avoir des soupçons
- Vérifiez les **connexions enregistrées** d'utilisateurs sans shell dans `/etc/passwd`
- Vérifiez la présence de **hashes de mots de passe** dans `/etc/shadow` pour les utilisateurs sans shell

### Memory Dump

Pour obtenir la mémoire du système en cours d'exécution, il est recommandé d'utiliser [**LiME**](https://github.com/504ensicsLabs/LiME).\
Pour le **compiler**, vous devez utiliser le **même kernel** que celui utilisé par la machine victime.

> [!TIP]
> Souvenez-vous que vous **ne pouvez pas installer LiME ni aucun autre élément** sur la machine victime, car cela y apportera plusieurs modifications

Ainsi, si vous disposez d'une version identique d'Ubuntu, vous pouvez utiliser `apt-get install lime-forensics-dkms`\
Dans les autres cas, vous devez télécharger [**LiME**](https://github.com/504ensicsLabs/LiME) depuis github et le compiler avec les headers du kernel appropriés. Pour **obtenir les headers exacts du kernel** de la machine victime, vous pouvez simplement **copier le répertoire** `/lib/modules/<kernel version>` sur votre machine, puis **compiler** LiME en les utilisant :
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME prend en charge 3 **formats** :

- Raw (tous les segments concaténés)
- Padded (identique à raw, mais avec des zéros dans les bits de droite)
- Lime (format recommandé avec des métadonnées

LiME peut également être utilisé pour **envoyer le dump via le réseau** au lieu de le stocker sur le système, en utilisant quelque chose comme : `path=tcp:4444`

### Imagerie du disque

#### Arrêt

Tout d'abord, vous devrez **arrêter le système**. Ce n'est pas toujours possible, car il peut parfois s'agir d'un serveur de production que l'entreprise ne peut pas se permettre d'arrêter.\
Il existe **2 façons** d'arrêter le système : un **arrêt normal** et un **arrêt par débranchement**. Le premier permettra aux **processus de se terminer normalement** et au **système de fichiers** d'être **synchronisé**, mais il permettra également au **malware** éventuel de **détruire les preuves**. L'approche consistant à **débrancher la prise** peut entraîner **une certaine perte d'informations** (peu d'informations seront perdues, car nous avons déjà effectué une image de la mémoire) et le **malware n'aura aucune possibilité** d'intervenir. Par conséquent, si vous **soupçonnez** la présence d'un **malware**, exécutez simplement la **commande** **`sync`** sur le système, puis débranchez la prise.

#### Création d'une image du disque

Il est important de noter qu'**avant de connecter votre ordinateur à quoi que ce soit lié à l'affaire**, vous devez vous assurer qu'il sera **monté en lecture seule**, afin d'éviter de modifier toute information.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Pré-analyse de l'image disque

Création d'une image disque sans davantage de données.
```bash
#Find out if it's a disk image using "file" command
file disk.img
disk.img: Linux rev 1.0 ext4 filesystem data, UUID=59e7a736-9c90-4fab-ae35-1d6a28e5de27 (extents) (64bit) (large files) (huge files)

#Check which type of disk image it's
img_stat -t evidence.img
raw
#You can list supported types with
img_stat -i list
Supported image format types:
raw (Single or split raw file (dd))
aff (Advanced Forensic Format)
afd (AFF Multiple File)
afm (AFF with external metadata)
afflib (All AFFLIB image formats (including beta ones))
ewf (Expert Witness Format (EnCase))

#Data of the image
fsstat -i raw -f ext4 disk.img
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: Ext4
Volume Name:
Volume ID: 162850f203fd75afab4f1e4736a7e776

Last Written at: 2020-02-06 06:22:48 (UTC)
Last Checked at: 2020-02-06 06:15:09 (UTC)

Last Mounted at: 2020-02-06 06:15:18 (UTC)
Unmounted properly
Last mounted on: /mnt/disk0

Source OS: Linux
[...]

#ls inside the image
fls -i raw -f ext4 disk.img
d/d 11: lost+found
d/d 12: Documents
d/d 8193:       folder1
d/d 8194:       folder2
V/V 65537:      $OrphanFiles

#ls inside folder
fls -i raw -f ext4 disk.img 12
r/r 16: secret.txt

#cat file inside image
icat -i raw -f ext4 disk.img 16
ThisisTheMasterSecret
```
## Rechercher les malwares connus

### Fichiers système modifiés

Linux propose des outils permettant de vérifier l’intégrité des composants système, ce qui est essentiel pour repérer les fichiers potentiellement problématiques.<sup>[[1]](#references)</sup>

- **Systèmes basés sur RedHat** : utilisez `rpm -Va` pour effectuer une vérification complète.
- **Systèmes basés sur Debian** : utilisez `dpkg --verify` pour une première vérification, puis `debsums | grep -v "OK$"` (après avoir installé `debsums` avec `apt-get install debsums`) afin d’identifier les problèmes éventuels.

### Détecteurs de malware/rootkit

Consultez la page suivante pour découvrir les outils pouvant être utiles pour trouver des malwares :


{{#ref}}
malware-analysis.md
{{#endref}}

## Rechercher les programmes installés

Pour rechercher efficacement les programmes installés sur les systèmes Debian et RedHat, utilisez les journaux et les bases de données système, en complément de vérifications manuelles dans les répertoires courants.<sup>[[1]](#references)</sup>

- Pour Debian, examinez _**`/var/lib/dpkg/status`**_ et _**`/var/log/dpkg.log`**_ afin d’obtenir des informations sur les installations de paquets, en utilisant `grep` pour filtrer les informations spécifiques.
- Les utilisateurs de RedHat peuvent interroger la base de données RPM avec `rpm -qa --root=/mntpath/var/lib/rpm` afin de lister les paquets installés.

Pour détecter les logiciels installés manuellement ou en dehors de ces gestionnaires de paquets, explorez des répertoires tels que _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_ et _**`/sbin`**_. Combinez les listes de répertoires avec des commandes spécifiques au système afin d’identifier les exécutables qui ne sont associés à aucun paquet connu, ce qui permet d’améliorer votre recherche de tous les programmes installés.
```bash
# Debian package and log details
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
# RedHat RPM database query
rpm -qa --root=/mntpath/var/lib/rpm
# Listing directories for manual installations
ls /usr/sbin /usr/bin /bin /sbin
# Identifying non-package executables (Debian)
find /sbin/ -exec dpkg -S {} \; | grep "no path found"
# Identifying non-package executables (RedHat)
find /sbin/ –exec rpm -qf {} \; | grep "is not"
# Find exacuable files
find / -type f -executable | grep <something>
```
## Récupérer des binaires exécutés supprimés

Imaginez un processus qui a été exécuté depuis /tmp/exec, puis supprimé. Il est possible de l’extraire.
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Triage des appels système avec SQLite et FTS5

Lorsqu’un processus est toujours en cours d’exécution ou peut être réexécuté dans un lab, **`strace`** peut fournir rapidement une trace comportementale sans nécessiter de modules du kernel ni de télémétrie EDR complète. Pour les traces volumineuses, évitez de lire directement le log brut ou de le coller dans un LLM : stockez-le dans une base de données **SQLite** et n’interrogez que le sous-ensemble minimal dont vous avez besoin.<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

> [!WARNING]
> Attacher `strace` modifie le timing du processus et peut affecter les conditions de course ou d’autres bugs fragiles. Préférez reproduire le problème sur une copie ou un système de lab lorsque c’est possible.

### Capture

Pour un nouveau processus :
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log <command>
```
Pour un processus en cours d’exécution :
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log -p <PID>
```
Options utiles :

- `-ff` : suivre les forks/threads et conserver des sorties par processus
- `-ttt` : horodatages epoch pour faciliter la corrélation de la timeline
- `-yy` : résoudre les descripteurs de fichiers en chemins/sockets sous-jacents lorsque possible
- `-s 4096` : conserver les chemins longs et les arguments de buffer sans troncature

### Normaliser

Un schéma pratique consiste à utiliser une ligne par syscall et par argument :
```sql
CREATE TABLE syscalls (
id        INTEGER PRIMARY KEY,
pid       INTEGER NOT NULL,
timestamp REAL    NOT NULL,
name      TEXT    NOT NULL,
ret_val   INTEGER,
errno     TEXT
);

CREATE TABLE syscall_args (
id         INTEGER PRIMARY KEY,
syscall_id INTEGER NOT NULL REFERENCES syscalls(id),
position   INTEGER NOT NULL,
raw        TEXT    NOT NULL,
type       INTEGER NOT NULL
);
```
Cela évite d’essayer d’aplatir des lignes d’appels système hétérogènes en une seule table très large et garantit des jointures prévisibles pendant le triage.

### Indexer les arguments riches en texte avec FTS5

La recherche naïve de chemins avec `LIKE "%...%"` devient très lente sur les traces volumineuses. Créez un index FTS5 pour le texte des arguments et effectuez plutôt la recherche dans cet index :
```sql
CREATE VIRTUAL TABLE syscall_args_fts
USING fts5(raw, content='syscall_args', content_rowid='id');

INSERT INTO syscall_args_fts(rowid, raw)
SELECT id, raw FROM syscall_args;
```
Exemple : retrouver l’activité des fichiers sous `/tmp` sans analyser chaque ligne :
```sql
SELECT s.timestamp, s.pid, s.name, a.position, a.raw
FROM syscall_args_fts f
JOIN syscall_args a ON a.id = f.rowid
JOIN syscalls s ON s.id = a.syscall_id
WHERE syscall_args_fts MATCH 'tmp'
AND s.name IN ('openat', 'stat', 'lstat', 'rename', 'unlink', 'execve')
ORDER BY s.timestamp;
```
### Investigations à signaux élevés

- **PATH hijacking / fake sudo** : recherchez les écritures ainsi que les activités `chmod`/`rename` sous `~/.local/bin/`, puis corrélez-les avec les appels ultérieurs à `execve` visant des noms évoquant des privilèges, tels que `sudo`.
- **TOCTOU on temporary files** : faites pivoter l’analyse autour du même chemin `/tmp/...` dans `stat`, `access`, `openat`, `rename`, `unlink`, `link`, `symlink` et `execve` afin d’identifier les écarts entre la vérification et l’utilisation.
- **Crash root cause** : corrélez le `mmap` d’un fichier avec les écritures ou la troncature du même inode/chemin par un autre processus, puis examinez la séquence du signal/de la sortie pour détecter `SIGBUS`.
- **Network destination recovery** : filtrez `connect`, `sendto`, `sendmsg`, `recvfrom` ainsi que les arguments liés aux sockets afin d’extraire les IP et ports pairs.

### Analyse de traces assistée par LLM

Si vous souhaitez qu’un LLM vous assiste, exposez-lui une connexion SQLite **en lecture seule** et fournissez-lui le schéma complet. Laissez-le exécuter du SQL brut au lieu de placer la base de données derrière des fonctions d’assistance limitées. Cela fonctionne généralement mieux pour les jointures, la corrélation temporelle et les recherches FTS.

Règles pratiques :

- Gardez la base de données en lecture seule, par exemple avec `sqlite3 'file:trace.db?mode=ro'`.
- Donnez au modèle des exemples de requêtes `JOIN` et `FTS5 MATCH` valides.
- Ne collez **pas** de logs `strace` bruts de plusieurs Go dans le prompt.
- Posez des questions ciblées telles que :
- « Liste les fichiers persistants écrits par ce programme. »
- « A-t-il créé ou remplacé des exécutables dans des répertoires du PATH contrôlés par l’utilisateur ? »
- « Explique pourquoi cette trace se termine par SIGBUS. »

## Inspecter les emplacements de démarrage automatique

### Tâches planifiées
```bash
cat /var/spool/cron/crontabs/*  \
/var/spool/cron/atjobs \
/var/spool/anacron \
/etc/cron* \
/etc/at* \
/etc/anacrontab \
/etc/incron.d/* \
/var/spool/incron/* \

#MacOS
ls -l /usr/lib/cron/tabs/ /Library/LaunchAgents/ /Library/LaunchDaemons/ ~/Library/LaunchAgents/
```
#### Recherche : abus de Cron/Anacron via 0anacron et stubs suspects
Les attaquants modifient souvent le stub 0anacron présent dans chaque répertoire /etc/cron.*/ afin de garantir une exécution périodique.<sup>[[4]](#references)</sup>
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Hunt: rollback du hardening SSH et shells de backdoor
Les modifications apportées à sshd_config et aux shells des comptes système sont courantes après une post-exploitation pour préserver l’accès.<sup>[[4]](#references)</sup>
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Chasse : marqueurs de Cloud C2 (Dropbox/Cloudflare Tunnel)
- Les beacons de l’API Dropbox utilisent généralement api.dropboxapi.com ou content.dropboxapi.com via HTTPS, avec des tokens Authorization: Bearer.
- Recherchez dans le proxy/Zeek/NetFlow les connexions Dropbox sortantes inattendues depuis les serveurs.
- Cloudflare Tunnel (`cloudflared`) fournit un C2 de secours via le port 443 sortant.<sup>[[4]](#references)</sup>
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Services

Chemins où un malware peut être installé en tant que service :

- **/etc/inittab** : Appelle des scripts d'initialisation comme rc.sysinit, qui redirigent ensuite vers les scripts de démarrage.
- **/etc/rc.d/** et **/etc/rc.boot/** : Contiennent les scripts de démarrage des services, ce dernier étant présent dans les anciennes versions de Linux.
- **/etc/init.d/** : Utilisé dans certaines versions de Linux, comme Debian, pour stocker les scripts de démarrage.
- Les services peuvent également être activés via **/etc/inetd.conf** ou **/etc/xinetd/**, selon la variante de Linux.
- **/etc/systemd/system** : Répertoire contenant les scripts du gestionnaire du système et des services.
- **/etc/systemd/system/multi-user.target.wants/** : Contient des liens vers les services qui doivent être démarrés dans un runlevel multi-utilisateur.
- **/usr/local/etc/rc.d/** : Destiné aux services personnalisés ou tiers.
- **\~/.config/autostart/** : Destiné aux applications à démarrage automatique spécifiques à un utilisateur ; peut servir de cachette à un malware ciblant les utilisateurs.
- **/lib/systemd/system/** : Contient les fichiers d'unités par défaut à l'échelle du système, fournis par les packages installés.

#### Recherche : systemd timers et transient units

La persistence avec systemd ne se limite pas aux fichiers `.service`. Examinez les unités `.timer`, les unités de niveau utilisateur et les **transient units** créées au moment de l'exécution.
```bash
# Enumerate timers and inspect referenced services
systemctl list-timers --all
systemctl cat <name>.timer
systemctl cat <name>.service

# Search common system and user paths
find /etc/systemd/system /run/systemd/system /usr/lib/systemd/system -maxdepth 3 \( -name '*.service' -o -name '*.timer' \) -ls
find /home -path '*/.config/systemd/user/*' -type f \( -name '*.service' -o -name '*.timer' \) -ls

# Transient units created via systemd-run often land here
find /run/systemd/transient -maxdepth 2 -type f -ls 2>/dev/null

# Pull execution history for a suspicious unit
journalctl -u <name>.service
journalctl _SYSTEMD_UNIT=<name>.service
```
Les unités transitoires sont faciles à manquer, car `/run/systemd/transient/` est **non persistant**. Si vous collectez une image en direct, récupérez-le avant l'arrêt.

### Kernel Modules

Les modules du noyau Linux, souvent utilisés par les malwares comme composants de rootkit, sont chargés au démarrage du système. Les répertoires et fichiers essentiels pour ces modules incluent :

- **/lib/modules/$(uname -r)** : Contient les modules correspondant à la version du noyau en cours d'exécution.
- **/etc/modprobe.d** : Contient les fichiers de configuration permettant de contrôler le chargement des modules.
- **/etc/modprobe** et **/etc/modprobe.conf** : Fichiers contenant les paramètres globaux des modules.

### Other Autostart Locations

Linux utilise divers fichiers pour exécuter automatiquement des programmes lors de la connexion d'un utilisateur, lesquels peuvent potentiellement héberger des malwares :

- **/etc/profile.d/**\*, **/etc/profile** et **/etc/bash.bashrc** : Exécutés lors de la connexion de tout utilisateur.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile** et **~/.config/autostart** : Fichiers propres à l'utilisateur, exécutés lors de sa connexion.
- **/etc/rc.local** : S'exécute après le démarrage de tous les services système, marquant la fin de la transition vers un environnement multiutilisateur.

## Examine Logs

Les systèmes Linux suivent les activités des utilisateurs et les événements système au moyen de divers fichiers journaux. Ces journaux sont essentiels pour identifier les accès non autorisés, les infections par des malwares et autres incidents de sécurité.<sup>[[2]](#references)</sup> Les principaux fichiers journaux incluent :

- **/var/log/syslog** (Debian) ou **/var/log/messages** (RedHat) : Enregistrent les messages et activités à l'échelle du système.
- **/var/log/auth.log** (Debian) ou **/var/log/secure** (RedHat) : Enregistrent les tentatives d'authentification ainsi que les connexions réussies et échouées.
- Utilisez `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` pour filtrer les événements d'authentification pertinents.
- **/var/log/boot.log** : Contient les messages de démarrage du système.
- **/var/log/maillog** ou **/var/log/mail.log** : Enregistre les activités du serveur de messagerie, ce qui est utile pour suivre les services liés aux e-mails.
- **/var/log/kern.log** : Stocke les messages du noyau, notamment les erreurs et les avertissements.
- **/var/log/dmesg** : Contient les messages des pilotes de périphériques.
- **/var/log/faillog** : Enregistre les tentatives de connexion échouées, ce qui facilite les investigations concernant les compromissions de sécurité.
- **/var/log/cron** : Enregistre l'exécution des tâches cron.
- **/var/log/daemon.log** : Suit les activités des services en arrière-plan.
- **/var/log/btmp** : Documente les tentatives de connexion échouées.
- **/var/log/httpd/** : Contient les journaux d'erreurs et d'accès d'Apache HTTPD.
- **/var/log/mysqld.log** ou **/var/log/mysql.log** : Enregistre les activités des bases de données MySQL.
- **/var/log/xferlog** : Enregistre les transferts de fichiers FTP.
- **/var/log/** : Vérifiez toujours la présence de journaux inattendus à cet emplacement.

> [!TIP]
> Les journaux système Linux et les sous-systèmes d'audit peuvent être désactivés ou supprimés lors d'une intrusion ou d'un incident lié à un malware. Comme les systèmes Linux contiennent généralement dans leurs journaux certaines des informations les plus utiles sur les activités malveillantes, les intrus les suppriment régulièrement. Par conséquent, lors de l'examen des fichiers journaux disponibles, il est important de rechercher les lacunes ou les entrées dans le désordre, qui peuvent indiquer une suppression ou une altération.

### Journald triage (`journalctl`)

Sur les hôtes Linux modernes, le **journal systemd** constitue généralement la source la plus utile pour l'**exécution des services**, les **événements d'authentification**, les **opérations sur les paquets** et les **messages du noyau et de l'espace utilisateur**. Lors d'une réponse en direct, essayez de préserver à la fois le journal **persistant** (`/var/log/journal/`) et le journal **d'exécution** (`/run/log/journal/`), car l'activité de courte durée d'un attaquant peut n'exister que dans ce dernier.<sup>[[5]](#references)</sup>
```bash
# List available boots and pivot around the suspicious one
journalctl --list-boots
journalctl -b -1

# Review a mounted image or copied journal directory offline
journalctl --directory /mnt/image/var/log/journal --list-boots
journalctl --directory /mnt/image/var/log/journal -b -1

# Inspect a single journal file and check integrity/corruption
journalctl --file system.journal --header
journalctl --file system.journal --verify

# High-signal filters
journalctl -u ssh.service
journalctl _SYSTEMD_UNIT=cron.service
journalctl _UID=0
journalctl _EXE=/usr/sbin/useradd
```
Les champs du journal utiles pour le triage comprennent `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID` et `MESSAGE`. Si journald a été configuré sans stockage persistant, attendez-vous à ne trouver que des données récentes sous `/run/log/journal/`.

### Triage du framework d’audit (`auditd`)

Si `auditd` est activé, privilégiez-le chaque fois que vous avez besoin d’une **attribution des processus** pour les modifications de fichiers, l’exécution de commandes, l’activité de connexion ou l’installation de packages.<sup>[[6]](#references)</sup>
```bash
# Fast summaries
aureport --start today --summary -i
aureport --start today --login --failed -i
aureport --start today --executable -i

# Search raw events
ausearch --start today -m EXECVE -i
ausearch --start today -ua 1000 -m USER_CMD,EXECVE -i
ausearch --start today -m SERVICE_START,SERVICE_STOP -i

# Software installation/update events (especially useful on RHEL-like systems)
ausearch -m SOFTWARE_UPDATE -i
```
Lorsque des règles ont été déployées avec des clés, pivotez à partir de celles-ci au lieu de grep les logs bruts :
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Linux conserve un historique des commandes pour chaque utilisateur**, stocké dans :

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

De plus, la commande `last -Faiwx` fournit une liste des connexions des utilisateurs. Vérifiez-la pour repérer les connexions inconnues ou inattendues.

Vérifiez les fichiers pouvant accorder des privilèges supplémentaires :

- Examinez `/etc/sudoers` pour détecter les privilèges inattendus qui pourraient avoir été accordés à des utilisateurs.
- Examinez `/etc/sudoers.d/` pour détecter les privilèges inattendus qui pourraient avoir été accordés à des utilisateurs.
- Examinez `/etc/groups` pour identifier les appartenances à des groupes ou les permissions inhabituelles.
- Examinez `/etc/passwd` pour identifier les appartenances à des groupes ou les permissions inhabituelles.

Certaines applications génèrent également leurs propres journaux :

- **SSH** : Examinez _\~/.ssh/authorized_keys_ et _\~/.ssh/known_hosts_ pour détecter les connexions distantes non autorisées.
- **Gnome Desktop** : Consultez _\~/.recently-used.xbel_ pour voir les fichiers récemment consultés via les applications Gnome.
- **Firefox/Chrome** : Vérifiez l’historique et les téléchargements du navigateur dans _\~/.mozilla/firefox_ ou _\~/.config/google-chrome_ pour repérer les activités suspectes.
- **VIM** : Examinez _\~/.viminfo_ pour obtenir des informations d’utilisation, telles que les chemins des fichiers consultés et l’historique des recherches.
- **Open Office** : Vérifiez les accès récents aux documents, qui pourraient indiquer la présence de fichiers compromis.
- **FTP/SFTP** : Examinez les journaux dans _\~/.ftp_history_ ou _\~/.sftp_history_ pour repérer les transferts de fichiers potentiellement non autorisés.
- **MySQL** : Analysez _\~/.mysql_history_ pour examiner les requêtes MySQL exécutées, qui peuvent révéler des activités non autorisées sur les bases de données.
- **Less** : Analysez _\~/.lesshst_ pour consulter l’historique d’utilisation, notamment les fichiers affichés et les commandes exécutées.
- **Git** : Examinez _\~/.gitconfig_ et _.git/logs_ des projets pour détecter les modifications apportées aux repositories.

### Journaux USB

[**usbrip**](https://github.com/snovvcrash/usbrip) est un petit logiciel écrit en Python 3 pur qui analyse les fichiers journaux Linux (`/var/log/syslog*` ou `/var/log/messages*`, selon la distribution) afin de générer des tableaux d’historique des événements USB.

Il est intéressant de **connaître tous les périphériques USB qui ont été utilisés**. Cela sera encore plus utile si vous disposez d’une liste autorisée de périphériques USB afin de détecter les « événements de violation » (l’utilisation de périphériques USB qui ne figurent pas dans cette liste).

### Installation
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### Exemples
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
Plus d'exemples et d'informations sur le github : [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Examiner les comptes utilisateur et les activités de connexion

Examinez _**/etc/passwd**_, _**/etc/shadow**_ et les **journaux de sécurité** à la recherche de noms ou de comptes inhabituels créés ou utilisés à proximité d'événements non autorisés connus. Vérifiez également les éventuelles attaques de brute-force contre sudo.\
Examinez en outre des fichiers tels que _**/etc/sudoers**_ et _**/etc/groups**_ pour détecter les privilèges inattendus accordés aux utilisateurs.\
Enfin, recherchez les comptes **sans mot de passe** ou utilisant des mots de passe **faciles à deviner**.<sup>[[1]](#references)</sup>

## Examiner le système de fichiers

### Analyser les structures du système de fichiers lors d'une investigation de malware

Lors de l'investigation d'incidents liés à des malware, la structure du système de fichiers constitue une source d'informations essentielle, car elle révèle à la fois la séquence des événements et le contenu du malware. Cependant, les auteurs de malware développent des techniques visant à entraver cette analyse, comme la modification des horodatages des fichiers ou l'évitement du système de fichiers pour le stockage des données.<sup>[[1]](#references)</sup>

Pour contrer ces méthodes anti-forensics, il est essentiel de :

- **Effectuer une analyse approfondie de la timeline** à l'aide d'outils comme **Autopsy** pour visualiser les timelines des événements ou `mactime` de **Sleuth Kit** pour obtenir des données détaillées.
- **Examiner les scripts inattendus** présents dans le $PATH du système, qui peuvent inclure des scripts shell ou PHP utilisés par des attackers.
- **Examiner `/dev` à la recherche de fichiers atypiques**, car ce répertoire contient traditionnellement des fichiers spéciaux, mais peut également héberger des fichiers liés à un malware.
- **Rechercher les fichiers ou répertoires cachés** portant des noms tels que ".. " (deux points suivis d'un espace) ou "..^G" (deux points suivis d'un control-G), qui peuvent dissimuler du contenu malveillant.
- **Identifier les fichiers setuid root** à l'aide de la commande : `find / -user root -perm -04000 -print` Cette commande recherche les fichiers disposant de privilèges élevés, qui pourraient être exploités par des attackers.
- **Examiner les horodatages de suppression** dans les tables d'inodes afin de détecter les suppressions massives de fichiers, ce qui peut indiquer la présence de rootkits ou de trojans.
- **Inspecter les inodes consécutifs** à la recherche de fichiers malveillants proches après en avoir identifié un, car ils peuvent avoir été placés ensemble.
- **Vérifier les répertoires binaires courants** (_/bin_, _/sbin_) à la recherche de fichiers récemment modifiés, car ceux-ci peuvent avoir été altérés par un malware.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> Notez qu’un **attaquant** peut **modifier** l’**heure** pour faire **paraître** les **fichiers** **légitimes**, mais il ne peut pas modifier l’**inode**. Si vous constatez qu’un **fichier** indique avoir été créé et modifié en même temps que les autres fichiers du même dossier, mais que l’**inode** est **étonnamment plus grand**, alors les **horodatages de ce fichier ont été modifiés**.

### Triage rapide axé sur les inodes

Si vous suspectez de l’anti-forensics, exécutez rapidement ces vérifications axées sur les inodes :
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
Lorsqu’un inode suspect se trouve sur une image ou un périphérique de système de fichiers EXT, inspectez directement les métadonnées de l’inode :
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
Champs utiles :
- **Links** : si `0`, aucune entrée de répertoire ne référence actuellement l’inode.
- **dtime** : horodatage de suppression défini lorsque l’inode a été unlink.
- **ctime/mtime** : aide à corréler les changements de métadonnées/contenu avec la chronologie de l’incident.

### Capabilities, xattrs et userland rootkits basés sur preload

La persistence Linux moderne évite souvent les binaires `setuid` évidents et abuse plutôt des **file capabilities**, des **extended attributes** et du dynamic loader.
```bash
# Enumerate file capabilities (think cap_setuid, cap_sys_admin, cap_dac_override)
getcap -r / 2>/dev/null

# Inspect extended attributes on suspicious binaries and libraries
getfattr -d -m - /path/to/suspicious/file 2>/dev/null

# Global preload hook affecting every dynamically linked binary
cat /etc/ld.so.preload 2>/dev/null
stat /etc/ld.so.preload 2>/dev/null

# If a suspicious library is referenced, inspect its metadata and links
ls -lah /lib /lib64 /usr/lib /usr/lib64 /usr/local/lib 2>/dev/null | grep -E '\\.so(\\.|$)'
ldd /bin/ls
```
Accordez une attention particulière aux bibliothèques référencées depuis des chemins **writable** tels que `/tmp`, `/dev/shm`, `/var/tmp` ou des emplacements inhabituels sous `/usr/local/lib`. Vérifiez également les binaires dotés de capacités en dehors de la propriété normale des paquets et corrélez-les avec les résultats de la vérification des paquets (`rpm -Va`, `dpkg --verify`, `debsums`).

## Comparer les fichiers de différentes versions du système de fichiers

### Résumé de la comparaison des versions du système de fichiers

Pour comparer les versions du système de fichiers et identifier précisément les changements, nous utilisons des commandes `git diff` simplifiées :<sup>[[3]](#references)</sup>

- **Pour trouver les nouveaux fichiers**, comparez deux répertoires :
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Pour le contenu modifié**, listez les changements en ignorant certaines lignes :
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Pour détecter les fichiers supprimés**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Les options de filtrage** (`--diff-filter`) permettent de limiter les résultats à des modifications spécifiques, comme les fichiers ajoutés (`A`), supprimés (`D`) ou modifiés (`M`).
- `A` : Fichiers ajoutés
- `C` : Fichiers copiés
- `D` : Fichiers supprimés
- `M` : Fichiers modifiés
- `R` : Fichiers renommés
- `T` : Changements de type (par exemple, fichier vers lien symbolique)
- `U` : Fichiers non fusionnés
- `X` : Fichiers inconnus
- `B` : Fichiers corrompus

## Références

- [1] [Guide de terrain de Malware Forensics pour les systèmes Linux : Digital Forensics Field Guides – Chapitre 3](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [2] [Les logs Linux expliqués](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [3] [Documentation de `git diff` – option `--diff-filter`](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- [4] [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [5] [Analyse forensique des journaux Linux](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [6] [Red Hat Enterprise Linux 9 - Auditing the system](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)
- [7] [Say hi to Pike!](https://www.synacktiv.com/en/publications/say-hi-to-pike.html)
- [8] [strace](https://strace.io/)
- [9] [SQLite FTS5 Extension](https://www.sqlite.org/fts5.html)

{{#include ../../banners/hacktricks-training.md}}
