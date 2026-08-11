# Analyse forensique Linux

{{#include ../../banners/hacktricks-training.md}}

## Collecte initiale d’informations

### Informations de base

Tout d’abord, il est recommandé d’avoir une **clé USB** contenant des **binaires et bibliothèques fiables et connus** (vous pouvez simplement récupérer Ubuntu et copier les dossiers _/bin_, _/sbin_, _/lib,_ et _/lib64_), puis de monter la clé USB et de modifier les variables d’environnement afin d’utiliser ces binaires :
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

Lors de l'obtention des informations de base, vous devez vérifier la présence d'éléments inhabituels tels que :

- Les processus **root** s'exécutent généralement avec des PID faibles ; si vous trouvez un processus **root** avec un PID élevé, cela peut être suspect
- Vérifiez les **connexions enregistrées** des utilisateurs sans shell dans `/etc/passwd`
- Vérifiez la présence de **hashes de mots de passe** dans `/etc/shadow` pour les utilisateurs sans shell

### Memory Dump

Pour obtenir la mémoire du système en cours d'exécution, il est recommandé d'utiliser [**LiME**](https://github.com/504ensicsLabs/LiME).\
Pour le **compiler**, vous devez utiliser le **même kernel** que celui utilisé par la machine victime.

> [!TIP]
> N'oubliez pas que vous **ne pouvez pas installer LiME ni quoi que ce soit d'autre** sur la machine victime, car cela y entraînerait plusieurs modifications

Ainsi, si vous disposez d'une version identique d'Ubuntu, vous pouvez utiliser `apt-get install lime-forensics-dkms`\
Dans les autres cas, vous devez télécharger [**LiME**](https://github.com/504ensicsLabs/LiME) depuis github et le compiler avec les headers du kernel appropriés. Pour **obtenir les headers exacts du kernel** de la machine victime, il vous suffit de **copier le répertoire** `/lib/modules/<kernel version>` sur votre machine, puis de **compiler** LiME en les utilisant :
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME prend en charge 3 **formats** :

- Raw (chaque segment concaténé)
- Padded (identique à raw, mais avec des zéros dans les bits de droite)
- Lime (format recommandé avec des métadonnées

LiME peut également être utilisé pour **envoyer le dump via le réseau** au lieu de le stocker sur le système, en utilisant quelque chose comme : `path=tcp:4444`

### Imaging du disque

#### Arrêt

Tout d'abord, vous devrez **arrêter le système**. Ce n'est pas toujours une option, car il peut parfois s'agir d'un serveur de production que l'entreprise ne peut pas se permettre d'arrêter.\
Il existe **2 façons** d'arrêter le système : un **arrêt normal** et un **arrêt en « retirant la prise »**. Le premier permettra aux **processus de se terminer normalement** et au **système de fichiers** d'être **synchronisé**, mais il permettra également au **malware** éventuel de **détruire les preuves**. L'approche consistant à « retirer la prise » peut entraîner **une certaine perte d'informations** (une grande partie des informations ne sera pas perdue, car nous avons déjà effectué une image de la mémoire) et le **malware n'aura aucune possibilité** d'agir. Par conséquent, si vous **suspectez** la présence d'un **malware**, exécutez simplement la **commande** **`sync`** sur le système, puis retirez la prise.

#### Création d'une image du disque

Il est important de noter qu'**avant de connecter votre ordinateur à tout élément lié à l'affaire**, vous devez vous assurer qu'il sera **monté en lecture seule** afin d'éviter de modifier toute information.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Pré-analyse de l’image disque

Création d’une image disque ne contenant pas davantage de données.
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
## Rechercher les Malware connus

### Fichiers système modifiés

Linux propose des outils permettant de vérifier l’intégrité des composants système, ce qui est essentiel pour repérer les fichiers potentiellement problématiques.<sup>[[1]](#references)</sup>

- **Systèmes basés sur RedHat** : utilisez `rpm -Va` pour effectuer une vérification complète.
- **Systèmes basés sur Debian** : utilisez `dpkg --verify` pour une première vérification, puis `debsums | grep -v "OK$"` (après avoir installé `debsums` avec `apt-get install debsums`) afin d’identifier les problèmes éventuels.

### Détecteurs de Malware/Rootkit

Consultez la page suivante pour découvrir les outils qui peuvent être utiles pour trouver des Malware :


{{#ref}}
malware-analysis.md
{{#endref}}

## Rechercher les programmes installés

Pour rechercher efficacement les programmes installés sur les systèmes Debian et RedHat, envisagez d’exploiter les journaux et les bases de données système, en complément de vérifications manuelles dans les répertoires courants.<sup>[[1]](#references)</sup>

- Pour Debian, examinez _**`/var/lib/dpkg/status`**_ et _**`/var/log/dpkg.log`**_ afin d’obtenir les détails sur les installations de packages, en utilisant `grep` pour filtrer les informations spécifiques.
- Les utilisateurs de RedHat peuvent interroger la base de données RPM avec `rpm -qa --root=/mntpath/var/lib/rpm` pour lister les packages installés.

Pour repérer les logiciels installés manuellement ou en dehors de ces gestionnaires de packages, explorez des répertoires tels que _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_ et _**`/sbin`**_. Combinez les listes de répertoires avec des commandes spécifiques au système afin d’identifier les exécutables qui ne sont associés à aucun package connu, ce qui améliore votre recherche de tous les programmes installés.
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
## Récupérer des binaires en cours d’exécution supprimés

Imaginez un processus qui a été exécuté depuis `/tmp/exec`, puis supprimé. Il est possible de l’extraire
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Triage des traces d’appels système avec SQLite et FTS5

Lorsqu’un processus est toujours en cours d’exécution ou peut être réexécuté dans un lab, **`strace`** peut fournir rapidement une trace comportementale sans nécessiter de modules du kernel ni une télémétrie EDR complète. Pour les traces volumineuses, évitez de lire directement le journal brut ou de le coller dans un LLM : stockez-le dans une base de données **SQLite** et n’interrogez que le sous-ensemble minimal dont vous avez besoin.<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

> [!WARNING]
> L’attachement de `strace` modifie le timing du processus et peut affecter les race conditions ou d’autres bugs fragiles. Privilégiez si possible la reproduction sur une copie ou un système de lab.

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
- `-ttt` : horodatages epoch pour faciliter la corrélation chronologique
- `-yy` : résoudre les descripteurs de fichiers en chemins/sockets sous-jacents lorsque cela est possible
- `-s 4096` : empêcher la troncature des arguments contenant des chemins et des buffers longs

### Normaliser

Un schéma pratique consiste à utiliser une ligne par appel système et une ligne par argument :
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
Cela évite d’essayer d’aplatir des lignes de syscall hétérogènes dans une seule table très large et garantit que les jointures restent prévisibles pendant le triage.

### Indexer les arguments riches en texte avec FTS5

La recherche naïve de chemins avec `LIKE "%...%"` devient très lente sur les traces volumineuses. Créez un index FTS5 pour le texte des arguments et effectuez plutôt les recherches dessus :
```sql
CREATE VIRTUAL TABLE syscall_args_fts
USING fts5(raw, content='syscall_args', content_rowid='id');

INSERT INTO syscall_args_fts(rowid, raw)
SELECT id, raw FROM syscall_args;
```
Exemple : récupérer l’activité des fichiers sous `/tmp` sans analyser chaque ligne :
```sql
SELECT s.timestamp, s.pid, s.name, a.position, a.raw
FROM syscall_args_fts f
JOIN syscall_args a ON a.id = f.rowid
JOIN syscalls s ON s.id = a.syscall_id
WHERE syscall_args_fts MATCH 'tmp'
AND s.name IN ('openat', 'stat', 'lstat', 'rename', 'unlink', 'execve')
ORDER BY s.timestamp;
```
### Investigations à signal élevé

- **PATH hijacking / fake sudo** : rechercher les écritures ainsi que les activités `chmod`/`rename` sous `~/.local/bin/`, puis les corréler avec les appels `execve` ultérieurs de noms évoquant des privilèges, tels que `sudo`.
- **TOCTOU sur les fichiers temporaires** : suivre le même chemin `/tmp/...` à travers `stat`, `access`, `openat`, `rename`, `unlink`, `link`, `symlink` et `execve` afin d’identifier les écarts entre la vérification et l’utilisation.
- **Cause racine d’un crash** : corréler le `mmap` d’un fichier avec les écritures ou la troncature du même inode/chemin par un autre processus, puis examiner la séquence du signal/de la sortie pour détecter `SIGBUS`.
- **Récupération de la destination réseau** : filtrer `connect`, `sendto`, `sendmsg`, `recvfrom` ainsi que les arguments liés aux sockets afin d’extraire les IP et ports pairs.

### Analyse de traces assistée par LLM

Si vous souhaitez qu’un LLM vous assiste, exposez une handle SQLite en **lecture seule** et fournissez-lui le schéma complet. Laissez-le exécuter du SQL brut au lieu de masquer la base de données derrière des fonctions d’aide limitées. Cette approche fonctionne généralement mieux pour les jointures, la corrélation temporelle et les recherches FTS.

Règles pratiques :

- Conservez la base de données en lecture seule, par exemple avec `sqlite3 'file:trace.db?mode=ro'`.
- Donnez au modèle des exemples de requêtes `JOIN` et `FTS5 MATCH` valides.
- Ne collez **pas** de logs `strace` bruts de plusieurs Go dans le prompt.
- Posez des questions ciblées telles que :
- « Liste les fichiers persistants écrits par ce programme. »
- « A-t-il créé ou remplacé des exécutables dans des répertoires PATH contrôlés par l’utilisateur ? »
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
#### Chasse : abus de Cron/Anacron via 0anacron et stubs suspects
Les attaquants modifient souvent le stub 0anacron présent dans chaque répertoire /etc/cron.*/ afin de garantir une exécution périodique.<sup>[[4]](#references)</sup>
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Hunt: rollback du hardening SSH et shells backdoor
Les modifications apportées à sshd_config et aux shells des comptes système sont courantes après une post-exploitation pour conserver l’accès.<sup>[[4]](#references)</sup>
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Chasse : marqueurs de Cloud C2 (Dropbox/Cloudflare Tunnel)
- Les beacons de l’API Dropbox utilisent généralement api.dropboxapi.com ou content.dropboxapi.com via HTTPS avec des tokens Authorization: Bearer.
- Recherchez dans les proxy/Zeek/NetFlow un trafic sortant Dropbox inattendu depuis les serveurs.
- Cloudflare Tunnel (`cloudflared`) fournit un C2 de secours via le port 443 sortant.<sup>[[4]](#references)</sup>
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Services

Chemins où un malware peut être installé en tant que service :

- **/etc/inittab** : Appelle des scripts d'initialisation comme rc.sysinit, qui redirige ensuite vers les scripts de démarrage.
- **/etc/rc.d/** et **/etc/rc.boot/** : Contiennent des scripts de démarrage des services, ce dernier étant présent dans les anciennes versions de Linux.
- **/etc/init.d/** : Utilisé dans certaines versions de Linux comme Debian pour stocker les scripts de démarrage.
- Les services peuvent également être activés via **/etc/inetd.conf** ou **/etc/xinetd/**, selon la variante de Linux.
- **/etc/systemd/system** : Un répertoire contenant les scripts du gestionnaire système et des services.
- **/etc/systemd/system/multi-user.target.wants/** : Contient des liens vers les services qui doivent être démarrés dans un runlevel multi-utilisateur.
- **/usr/local/etc/rc.d/** : Pour les services personnalisés ou tiers.
- **\~/.config/autostart/** : Pour les applications à démarrage automatique spécifiques à l'utilisateur, ce qui peut constituer un emplacement de dissimulation pour un malware ciblant l'utilisateur.
- **/lib/systemd/system/** : Fichiers unités par défaut à l'échelle du système, fournis par les packages installés.

#### Recherche : systemd timers et unités transitoires

La persistence de Systemd ne se limite pas aux fichiers `.service`. Examinez les unités `.timer`, les unités de niveau utilisateur et les **unités transitoires** créées au runtime.
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
Les unités transitoires sont faciles à manquer, car `/run/systemd/transient/` est **non persistant**. Si vous collectez une image live, récupérez-la avant l'arrêt.

### Modules du noyau

Les modules du noyau Linux, souvent utilisés par les malwares comme composants de rootkit, sont chargés au démarrage du système. Les répertoires et fichiers essentiels pour ces modules incluent :

- **/lib/modules/$(uname -r)** : Contient les modules correspondant à la version du noyau en cours d'exécution.
- **/etc/modprobe.d** : Contient les fichiers de configuration permettant de contrôler le chargement des modules.
- **/etc/modprobe** et **/etc/modprobe.conf** : Fichiers contenant les paramètres globaux des modules.

### Autres emplacements d'autostart

Linux utilise différents fichiers pour exécuter automatiquement des programmes lors de la connexion d'un utilisateur, lesquels peuvent potentiellement abriter des malwares :

- **/etc/profile.d/**\*, **/etc/profile** et **/etc/bash.bashrc** : Exécutés lors de la connexion de tout utilisateur.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile** et **\~/.config/autostart** : Fichiers spécifiques à l'utilisateur exécutés lors de sa connexion.
- **/etc/rc.local** : S'exécute après le démarrage de tous les services système, marquant la fin de la transition vers un environnement multiutilisateur.

## Examiner les journaux

Les systèmes Linux suivent les activités des utilisateurs et les événements système au moyen de différents fichiers journaux. Ces journaux sont essentiels pour identifier les accès non autorisés, les infections par des malwares et les autres incidents de sécurité.<sup>[[2]](#references)</sup> Les principaux fichiers journaux incluent :

- **/var/log/syslog** (Debian) ou **/var/log/messages** (RedHat) : Enregistrent les messages et activités à l'échelle du système.
- **/var/log/auth.log** (Debian) ou **/var/log/secure** (RedHat) : Enregistrent les tentatives d'authentification ainsi que les connexions réussies et échouées.
- Utilisez `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` pour filtrer les événements d'authentification pertinents.
- **/var/log/boot.log** : Contient les messages de démarrage du système.
- **/var/log/maillog** ou **/var/log/mail.log** : Enregistre les activités du serveur de messagerie, ce qui est utile pour suivre les services liés aux e-mails.
- **/var/log/kern.log** : Stocke les messages du noyau, notamment les erreurs et les avertissements.
- **/var/log/dmesg** : Contient les messages des pilotes de périphériques.
- **/var/log/faillog** : Enregistre les tentatives de connexion échouées, ce qui facilite les investigations liées aux failles de sécurité.
- **/var/log/cron** : Enregistre les exécutions des tâches cron.
- **/var/log/daemon.log** : Suit les activités des services en arrière-plan.
- **/var/log/btmp** : Documente les tentatives de connexion échouées.
- **/var/log/httpd/** : Contient les journaux d'erreurs et d'accès d'Apache HTTPD.
- **/var/log/mysqld.log** ou **/var/log/mysql.log** : Enregistre les activités de la base de données MySQL.
- **/var/log/xferlog** : Enregistre les transferts de fichiers FTP.
- **/var/log/** : Vérifiez toujours la présence de journaux inattendus à cet emplacement.

> [!TIP]
> Les journaux système Linux et les sous-systèmes d'audit peuvent être désactivés ou supprimés lors d'une intrusion ou d'un incident lié à un malware. Comme les journaux des systèmes Linux contiennent généralement certaines des informations les plus utiles sur les activités malveillantes, les intrus les suppriment régulièrement. Par conséquent, lors de l'examen des fichiers journaux disponibles, il est important de rechercher des lacunes ou des entrées dans le désordre qui pourraient indiquer une suppression ou une falsification.

### Triage de Journald (`journalctl`)

Sur les hôtes Linux modernes, le **journal systemd** est généralement la source la plus précieuse pour l'**exécution des services**, les **événements d'authentification**, les **opérations sur les paquets** et les **messages du noyau et de l'espace utilisateur**. Lors d'une réponse live, essayez de préserver à la fois le journal **persistant** (`/var/log/journal/`) et le journal **d'exécution** (`/run/log/journal/`), car l'activité de courte durée d'un attaquant peut n'exister que dans ce dernier.<sup>[[5]](#references)</sup>
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
Les champs utiles du journal pour le triage incluent `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID` et `MESSAGE`. Si journald a été configuré sans stockage persistant, attendez-vous à ne trouver que des données récentes sous `/run/log/journal/`.

### Triage de l’audit framework (`auditd`)

Si `auditd` est activé, privilégiez-le lorsque vous avez besoin de l’**attribution des processus** pour les modifications de fichiers, l’exécution de commandes, l’activité de connexion ou l’installation de packages.<sup>[[6]](#references)</sup>
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
Lorsque des règles ont été déployées avec des clés, pivotez à partir de celles-ci au lieu de rechercher dans les logs bruts :
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

De plus, la commande `last -Faiwx` fournit une liste des connexions des utilisateurs. Vérifiez-la pour détecter les connexions inconnues ou inattendues.

Vérifiez les fichiers susceptibles d'accorder des privilèges supplémentaires :

- Examinez `/etc/sudoers` pour repérer les privilèges inattendus qui auraient pu être accordés à des utilisateurs.
- Examinez `/etc/sudoers.d/` pour repérer les privilèges inattendus qui auraient pu être accordés à des utilisateurs.
- Examinez `/etc/groups` afin d'identifier les appartenances à des groupes ou les permissions inhabituelles.
- Examinez `/etc/passwd` afin d'identifier les appartenances à des groupes ou les permissions inhabituelles.

Certaines applications génèrent également leurs propres logs :

- **SSH** : Examinez _\~/.ssh/authorized_keys_ et _\~/.ssh/known_hosts_ à la recherche de connexions distantes non autorisées.
- **Gnome Desktop** : Consultez _\~/.recently-used.xbel_ pour connaître les fichiers récemment consultés via les applications Gnome.
- **Firefox/Chrome** : Vérifiez l'historique et les téléchargements des navigateurs dans _\~/.mozilla/firefox_ ou _\~/.config/google-chrome_ à la recherche d'activités suspectes.
- **VIM** : Examinez _\~/.viminfo_ pour obtenir des détails sur l'utilisation, tels que les chemins des fichiers consultés et l'historique des recherches.
- **Open Office** : Vérifiez les accès récents aux documents, qui pourraient indiquer la présence de fichiers compromis.
- **FTP/SFTP** : Examinez les logs dans _\~/.ftp_history_ ou _\~/.sftp_history_ pour repérer les transferts de fichiers potentiellement non autorisés.
- **MySQL** : Analysez _\~/.mysql_history_ pour examiner les requêtes MySQL exécutées, qui pourraient révéler des activités non autorisées sur les bases de données.
- **Less** : Analysez _\~/.lesshst_ pour consulter l'historique d'utilisation, notamment les fichiers affichés et les commandes exécutées.
- **Git** : Examinez _\~/.gitconfig_ et les fichiers _.git/logs_ des projets pour détecter les modifications apportées aux repositories.

### Journaux USB

[**usbrip**](https://github.com/snovvcrash/usbrip) est un petit logiciel écrit en Python 3 pur qui analyse les fichiers de logs Linux (`/var/log/syslog*` ou `/var/log/messages*`, selon la distribution) afin de générer des tableaux d'historique des événements USB.

Il est intéressant de **connaître tous les périphériques USB qui ont été utilisés**. Cela sera encore plus utile si vous disposez d'une liste autorisée de périphériques USB pour détecter les « événements de violation » (l'utilisation de périphériques USB qui ne figurent pas dans cette liste).

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
Plus d'exemples et d'informations dans le github : [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Examiner les comptes utilisateur et les activités de connexion

Examinez _**/etc/passwd**_, _**/etc/shadow**_ et les **security logs** à la recherche de noms inhabituels ou de comptes créés et/ou utilisés peu avant ou après des événements non autorisés connus. Vérifiez également les éventuelles attaques de brute-force contre sudo.\
En outre, vérifiez des fichiers tels que _**/etc/sudoers**_ et _**/etc/groups**_ afin d'identifier les privilèges inattendus accordés aux utilisateurs.\
Enfin, recherchez les comptes **sans mot de passe** ou dotés de mots de passe **facilement devinables**.<sup>[[1]](#references)</sup>

## Examiner le système de fichiers

### Analyser les structures du système de fichiers lors d'une investigation de malware

Lors de l'investigation d'incidents liés à des malwares, la structure du système de fichiers constitue une source d'informations cruciale, révélant à la fois la séquence des événements et le contenu du malware. Cependant, les auteurs de malwares développent des techniques visant à entraver cette analyse, comme la modification des horodatages des fichiers ou l'évitement du système de fichiers pour le stockage des données.<sup>[[1]](#references)</sup>

Pour contrer ces méthodes anti-forensic, il est essentiel de :

- **Effectuer une analyse approfondie de la timeline** à l'aide d'outils tels qu'**Autopsy** pour visualiser les timelines d'événements ou `mactime` de **Sleuth Kit** pour obtenir des données détaillées sur la timeline.
- **Rechercher les scripts inattendus** dans le $PATH du système, qui peuvent inclure des scripts shell ou PHP utilisés par les attaquants.
- **Examiner `/dev` à la recherche de fichiers atypiques**, car ce répertoire contient traditionnellement des fichiers spéciaux, mais peut également héberger des fichiers liés à des malwares.
- **Rechercher les fichiers ou répertoires cachés** portant des noms tels que ".. " (deux points suivis d'un espace) ou "..^G" (deux points suivis d'un contrôle-G), qui pourraient dissimuler du contenu malveillant.
- **Identifier les fichiers setuid root** à l'aide de la commande : `find / -user root -perm -04000 -print` Cette commande trouve les fichiers dotés de permissions élevées, qui pourraient être exploitées par des attaquants.
- **Examiner les horodatages de suppression** dans les tables d'inodes afin de détecter les suppressions massives de fichiers, pouvant indiquer la présence de rootkits ou de trojans.
- **Inspecter les inodes consécutifs** à la recherche de fichiers malveillants situés à proximité après en avoir identifié un, car ils peuvent avoir été placés ensemble.
- **Vérifier les répertoires binaires courants** (_/bin_, _/sbin_) à la recherche de fichiers récemment modifiés, car ceux-ci pourraient avoir été altérés par un malware.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> Notez qu’un **attacker** peut **modifier** l’**heure** pour faire **paraître les fichiers** **légitimes**, mais il ne peut pas modifier l’**inode**. Si vous constatez qu’un **fichier** indique qu’il a été créé et modifié au **même moment** que le reste des fichiers du même dossier, mais que l’**inode** est **inattenduement plus grand**, alors les **horodatages de ce fichier ont été modifiés**.

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
Lorsqu’un inode suspect se trouve sur une image ou un périphérique de système de fichiers EXT, examinez directement les métadonnées de l’inode :
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
Champs utiles :
- **Links** : si `0`, aucune entrée de répertoire ne référence actuellement l’inode.
- **dtime** : horodatage de suppression défini lorsque l’inode a été désalloué.
- **ctime/mtime** : aide à corréler les modifications des métadonnées et du contenu avec la chronologie de l’incident.

### Capabilities, xattrs et userland rootkits basés sur preload

La persistance Linux moderne évite souvent les binaires `setuid` évidents et abuse plutôt des **file capabilities**, des **extended attributes** et du dynamic loader.
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
Accordez une attention particulière aux libraries référencées depuis des chemins **writable** tels que `/tmp`, `/dev/shm`, `/var/tmp` ou des emplacements inhabituels sous `/usr/local/lib`. Vérifiez également les binaires dotés de capabilities situés en dehors de la propriété habituelle des packages, et mettez-les en corrélation avec les résultats de vérification des packages (`rpm -Va`, `dpkg --verify`, `debsums`).

## Compare files of different filesystem versions

### Résumé de la comparaison des versions du filesystem

Pour comparer des versions du filesystem et identifier précisément les modifications, nous utilisons des commandes `git diff` simplifiées :<sup>[[3]](#references)</sup>

- **Pour trouver les nouveaux fichiers**, comparez deux répertoires :
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Pour le contenu modifié**, listez les changements en ignorant les lignes spécifiques :
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Pour détecter les fichiers supprimés**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Les options de filtrage** (`--diff-filter`) permettent de limiter les résultats à des changements spécifiques, comme les fichiers ajoutés (`A`), supprimés (`D`) ou modifiés (`M`).
- `A` : Fichiers ajoutés
- `C` : Fichiers copiés
- `D` : Fichiers supprimés
- `M` : Fichiers modifiés
- `R` : Fichiers renommés
- `T` : Changements de type (par exemple, fichier vers lien symbolique)
- `U` : Fichiers non fusionnés
- `X` : Fichiers inconnus
- `B` : Fichiers endommagés

## References

- [1] [Guide de terrain de la forensique des malwares pour les systèmes Linux : guides de terrain de la forensique numérique – chapitre 3](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [2] [Les logs Linux expliqués](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [3] [Documentation de git diff – option --diff-filter](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- [4] [Red Canary – Patcher pour assurer la persistence : comment le malware Linux DripDropper se déplace dans le cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [5] [Analyse forensique des journaux Linux](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [6] [Red Hat Enterprise Linux 9 - Auditer le système](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)
- [7] [Dites bonjour à Pike !](https://www.synacktiv.com/en/publications/say-hi-to-pike.html)
- [8] [strace](https://strace.io/)
- [9] [Extension SQLite FTS5](https://www.sqlite.org/fts5.html)
{{#include ../../banners/hacktricks-training.md}}
