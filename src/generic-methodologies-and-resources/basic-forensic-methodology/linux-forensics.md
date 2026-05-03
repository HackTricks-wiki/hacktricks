# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## Collecte d’informations initiale

### Informations de base

Tout d’abord, il est recommandé d’avoir une **USB** avec des **binaires et bibliothèques de bonne réputation** dessus (vous pouvez simplement prendre Ubuntu et copier les dossiers _/bin_, _/sbin_, _/lib,_ et _/lib64_), puis monter l’USB et modifier les variables d’environnement pour utiliser ces binaires :
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

Lors de l’obtention des informations de base, vous devez vérifier des choses étranges comme :

- Les **processus root** s’exécutent généralement avec des PIDs faibles, donc si vous trouvez un processus root avec un gros PID, cela peut éveiller des soupçons
- Vérifiez les **connexions enregistrées** des utilisateurs sans shell dans `/etc/passwd`
- Vérifiez la présence de **hashes de mots de passe** dans `/etc/shadow` pour les utilisateurs sans shell

### Memory Dump

Pour obtenir la mémoire du système en cours d’exécution, il est recommandé d’utiliser [**LiME**](https://github.com/504ensicsLabs/LiME).\
Pour le **compiler**, vous devez utiliser le **même kernel** que celui utilisé par la machine victime.

> [!TIP]
> N’oubliez pas que vous **ne pouvez pas installer LiME ni quoi que ce soit d’autre** sur la machine victime, car cela y apporterait plusieurs modifications

Donc, si vous avez une version identique d’Ubuntu, vous pouvez utiliser `apt-get install lime-forensics-dkms`\
Dans les autres cas, vous devez télécharger [**LiME**](https://github.com/504ensicsLabs/LiME) depuis github et le compiler avec les bons en-têtes du kernel. Pour **obtenir les en-têtes exacts du kernel** de la machine victime, vous pouvez simplement **copier le répertoire** `/lib/modules/<kernel version>` sur votre machine, puis **compiler** LiME en les utilisant :
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME supporte 3 **formats** :

- Raw (tous les segments concaténés ensemble)
- Padded (comme raw, mais avec des zéros dans les bits de droite)
- Lime (format recommandé avec des métadonnées)

LiME peut aussi être utilisé pour **envoyer le dump via network** au lieu de le stocker sur le système en utilisant quelque chose comme : `path=tcp:4444`

### Disk Imaging

#### Shutting down

Tout d'abord, vous devrez **éteindre le système**. Ce n'est pas toujours une option, car parfois le système sera un serveur de production que l'entreprise ne peut pas se permettre d'arrêter.\
Il existe **2 façons** d'éteindre le système : un **arrêt normal** et un **arrêt "plug the plug"**. La première permettra aux **processes** de se terminer normalement et au **filesystem** d'être **synchronisé**, mais elle permettra aussi à un éventuel **malware** de **détruire des preuves**. L'approche "pull the plug" peut entraîner **une certaine perte d'information** (pas beaucoup d'informations ne seront perdues puisque nous avons déjà pris une image de la mémoire) et le **malware n'aura aucune opportunité** de faire quoi que ce soit à ce sujet. Par conséquent, si vous **soupçonnez** qu'il pourrait y avoir un **malware**, exécutez simplement la **commande** **`sync`** sur le système et débranchez-le.

#### Taking an image of the disk

Il est important de noter qu'**avant de connecter votre ordinateur à quoi que ce soit lié à l'affaire**, vous devez vous assurer qu'il va être **monté en lecture seule** afin d'éviter de modifier toute information.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Pré-analyse d'une image disque

Imager une image disque sans plus de données.
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
## Rechercher des Malware connus

### Fichiers système modifiés

Linux offre des outils pour garantir l'intégrité des composants système, essentiels pour repérer des fichiers potentiellement problématiques.

- **Systèmes basés sur RedHat** : Utilisez `rpm -Va` pour une vérification complète.
- **Systèmes basés sur Debian** : `dpkg --verify` pour une vérification initiale, suivi de `debsums | grep -v "OK$"` (après installation de `debsums` avec `apt-get install debsums`) pour identifier d'éventuels problèmes.

### Détecteurs de Malware/Rootkit

Lisez la page suivante pour apprendre quels outils peuvent être utiles pour trouver du malware :


{{#ref}}
malware-analysis.md
{{#endref}}

## Rechercher les programmes installés

Pour rechercher efficacement les programmes installés sur les systèmes Debian et RedHat, pensez à exploiter les journaux système et les bases de données, en plus des vérifications manuelles dans les répertoires courants.

- Pour Debian, inspectez _**`/var/lib/dpkg/status`**_ et _**`/var/log/dpkg.log`**_ pour obtenir des détails sur les installations de paquets, en utilisant `grep` pour filtrer des informations spécifiques.
- Les utilisateurs RedHat peuvent interroger la base de données RPM avec `rpm -qa --root=/mntpath/var/lib/rpm` pour lister les paquets installés.

Pour découvrir des logiciels installés manuellement ou en dehors de ces gestionnaires de paquets, explorez des répertoires comme _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_ et _**`/sbin`**_. Combinez les listes de répertoires avec des commandes spécifiques au système pour identifier les exécutables non associés à des paquets connus, afin d'améliorer votre recherche de tous les programmes installés.
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

Imaginez un processus qui a été exécuté depuis /tmp/exec puis supprimé. Il est possible de l’extraire
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Syscall Trace Triage with SQLite and FTS5

Quand un processus est encore en cours d’exécution ou peut être relancé dans un lab, **`strace`** peut fournir une trace comportementale rapide sans avoir besoin de modules kernel ou d’une télémétrie EDR complète. Pour les grandes traces, évitez de lire directement le journal brut ou de le coller dans un LLM : stockez-le dans une base de données **SQLite** et interrogez uniquement le sous-ensemble minimal dont vous avez besoin.

> [!WARNING]
> Attacher `strace` modifie le timing du processus et peut affecter les race conditions ou d’autres bugs fragiles. Préférez la reproduction sur une copie/un système de lab lorsque c’est possible.

### Capture

Pour un nouveau processus :
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log <command>
```
Pour un processus en cours :
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log -p <PID>
```
Options utiles :

- `-ff` : suivre les forks/threads et conserver les sorties par processus
- `-ttt` : horodatages epoch pour faciliter la corrélation chronologique
- `-yy` : résoudre les descripteurs de fichiers vers les chemins/sockets de support lorsque possible
- `-s 4096` : éviter que les longs chemins et arguments de buffer soient tronqués

### Normaliser

Un schéma pratique consiste en une ligne par syscall et une ligne par argument :
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
Cela évite d’essayer d’aplatir des lignes de syscall hétérogènes en un seul tableau large et garde les jointures prévisibles pendant le triage.

### Index text-heavy arguments with FTS5

La chasse naïve aux chemins avec `LIKE "%...%"` devient très lente sur de grandes traces. Créez plutôt un index FTS5 pour le texte des arguments et effectuez la recherche dessus :
```sql
CREATE VIRTUAL TABLE syscall_args_fts
USING fts5(raw, content='syscall_args', content_rowid='id');

INSERT INTO syscall_args_fts(rowid, raw)
SELECT id, raw FROM syscall_args;
```
Exemple : récupérer l’activité des fichiers sous `/tmp` sans scanner chaque ligne :
```sql
SELECT s.timestamp, s.pid, s.name, a.position, a.raw
FROM syscall_args_fts f
JOIN syscall_args a ON a.id = f.rowid
JOIN syscalls s ON s.id = a.syscall_id
WHERE syscall_args_fts MATCH 'tmp'
AND s.name IN ('openat', 'stat', 'lstat', 'rename', 'unlink', 'execve')
ORDER BY s.timestamp;
```
### Investigations à fort signal

- **PATH hijacking / fake sudo** : recherchez les écritures et l’activité `chmod`/`rename` sous `~/.local/bin/`, puis corrélez avec des `execve` ultérieurs de noms à l’apparence privilégiée comme `sudo`.
- **TOCTOU sur les fichiers temporaires** : pivotez sur le même chemin `/tmp/...` à travers `stat`, `access`, `openat`, `rename`, `unlink`, `link`, `symlink`, et `execve` pour identifier les écarts check/use.
- **Cause racine d’un crash** : corrélez le `mmap` d’un fichier avec des écritures ou la troncation du même inode/chemin par un autre processus, puis inspectez la séquence de signal/sortie pour `SIGBUS`.
- **Récupération de la destination réseau** : filtrez `connect`, `sendto`, `sendmsg`, `recvfrom`, et les arguments liés aux sockets pour extraire les IP et ports pairs.

### Analyse de trace assistée par LLM

Si vous voulez qu’un LLM aide, exposez un handle SQLite en **lecture seule** et donnez-lui le schéma complet. Laissez-le émettre du SQL brut au lieu d’envelopper la base de données derrière des fonctions helper étroites. Cela fonctionne généralement mieux pour les jointures, la corrélation temporelle et les recherches FTS.

Règles pratiques :

- Gardez la base de données en lecture seule, par exemple avec `sqlite3 'file:trace.db?mode=ro'`.
- Donnez au modèle des exemples de requêtes `JOIN` et `FTS5 MATCH` valides.
- Ne collez pas de logs `strace` bruts de plusieurs Go dans le prompt.
- Posez des questions ciblées telles que :
- "Listez les fichiers persistants écrits par ce programme."
- "A-t-il créé ou remplacé des exécutables dans des répertoires PATH contrôlés par l’utilisateur ?"
- "Expliquez pourquoi cette trace se termine par un `SIGBUS`."

## Inspecter les emplacements d’Autostart

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
#### Hunt: Cron/Anacron abuse via 0anacron and suspicious stubs
Les attaquants modifient souvent le stub 0anacron présent dans chaque répertoire /etc/cron.*/ pour garantir une exécution périodique.
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Hunt: annulation du durcissement SSH et shells backdoor
Les modifications de sshd_config et des shells des comptes système sont courantes après une exploitation pour préserver l'accès.
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Chasse : indicateurs Cloud C2 (Dropbox/Cloudflare Tunnel)
- Les beacons de l'API Dropbox utilisent typiquement api.dropboxapi.com ou content.dropboxapi.com en HTTPS avec des tokens Authorization: Bearer.
- Recherchez dans proxy/Zeek/NetFlow un trafic egress Dropbox inattendu depuis des serveurs.
- Cloudflare Tunnel (`cloudflared`) fournit un C2 de secours via le trafic sortant 443.
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Services

Chemins où un malware pourrait être installé en tant que service :

- **/etc/inittab** : Appelle des scripts d'initialisation comme rc.sysinit, en dirigeant ensuite vers d'autres scripts de démarrage.
- **/etc/rc.d/** et **/etc/rc.boot/** : Contiennent des scripts pour le démarrage des services, ce dernier se trouvant dans les anciennes versions de Linux.
- **/etc/init.d/** : Utilisé dans certaines versions de Linux comme Debian pour stocker les scripts de démarrage.
- Les services peuvent aussi être activés via **/etc/inetd.conf** ou **/etc/xinetd/**, selon la variante de Linux.
- **/etc/systemd/system** : Un répertoire pour les scripts du gestionnaire système et de services.
- **/etc/systemd/system/multi-user.target.wants/** : Contient des liens vers les services qui doivent être démarrés dans un runlevel multi-utilisateur.
- **/usr/local/etc/rc.d/** : Pour les services personnalisés ou tiers.
- **\~/.config/autostart/** : Pour les applications de démarrage automatique spécifiques à l'utilisateur, ce qui peut servir de cachette à un malware ciblant un utilisateur.
- **/lib/systemd/system/** : Fichiers d’unité par défaut à l’échelle du système fournis par les paquets installés.

#### Hunt: systemd timers and transient units

La persistance systemd ne se limite pas aux fichiers `.service`. Examinez les unités `.timer`, les unités au niveau utilisateur, et les **transient units** créées à l’exécution.
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
Les unités temporaires sont faciles à manquer parce que `/run/systemd/transient/` est **non persistant**. Si vous collectez une image live, récupérez-la avant l'arrêt.

### Kernel Modules

Les modules du noyau Linux, souvent utilisés par des malwares comme composants de rootkit, sont chargés au démarrage du système. Les répertoires et fichiers critiques pour ces modules incluent :

- **/lib/modules/$(uname -r)** : Contient les modules pour la version du kernel en cours d’exécution.
- **/etc/modprobe.d** : Contient les fichiers de configuration pour contrôler le chargement des modules.
- **/etc/modprobe** et **/etc/modprobe.conf** : Fichiers pour les paramètres globaux des modules.

### Other Autostart Locations

Linux utilise divers fichiers pour exécuter automatiquement des programmes lors de la connexion d’un utilisateur, pouvant potentiellement héberger des malwares :

- **/etc/profile.d/**\*, **/etc/profile**, et **/etc/bash.bashrc** : Exécutés pour toute connexion utilisateur.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, et **\~/.config/autostart** : Fichiers spécifiques à l’utilisateur qui s’exécutent lors de sa connexion.
- **/etc/rc.local** : S’exécute après le démarrage de tous les services système, marquant la fin de la transition vers un environnement multiutilisateur.

## Examine Logs

Les systèmes Linux suivent les activités des utilisateurs et les événements système via divers fichiers de log. Ces logs sont essentiels pour identifier les accès non autorisés, les infections par malware et autres incidents de sécurité. Les principaux fichiers de log incluent :

- **/var/log/syslog** (Debian) ou **/var/log/messages** (RedHat) : Capturent les messages et activités à l’échelle du système.
- **/var/log/auth.log** (Debian) ou **/var/log/secure** (RedHat) : Enregistrent les tentatives d’authentification, les connexions réussies et échouées.
- Utilisez `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` pour filtrer les événements d’authentification pertinents.
- **/var/log/boot.log** : Contient les messages de démarrage du système.
- **/var/log/maillog** ou **/var/log/mail.log** : Journalise les activités du serveur de messagerie, utile pour suivre les services liés aux e-mails.
- **/var/log/kern.log** : Stocke les messages du kernel, y compris les erreurs et avertissements.
- **/var/log/dmesg** : Contient les messages des pilotes de périphériques.
- **/var/log/faillog** : Enregistre les tentatives de connexion échouées, aidant aux enquêtes sur les violations de sécurité.
- **/var/log/cron** : Journalise les exécutions des tâches cron.
- **/var/log/daemon.log** : Suit les activités des services en arrière-plan.
- **/var/log/btmp** : Documente les tentatives de connexion échouées.
- **/var/log/httpd/** : Contient les logs d’erreur et d’accès Apache HTTPD.
- **/var/log/mysqld.log** ou **/var/log/mysql.log** : Journalise les activités de la base de données MySQL.
- **/var/log/xferlog** : Enregistre les transferts de fichiers FTP.
- **/var/log/** : Vérifiez toujours s’il y a des logs inattendus ici.

> [!TIP]
> Les logs système Linux et les sous-systèmes d’audit peuvent être désactivés ou supprimés lors d’une intrusion ou d’un incident de malware. Comme les logs sur les systèmes Linux contiennent généralement certaines des informations les plus utiles sur les activités malveillantes, les intrus les suppriment régulièrement. Par conséquent, lors de l’examen des fichiers de log disponibles, il est important de rechercher des lacunes ou des entrées hors ordre qui pourraient indiquer une suppression ou une falsification.

### Journald triage (`journalctl`)

Sur les hôtes Linux modernes, le **journal systemd** est généralement la source de plus grande valeur pour **l’exécution des services**, les **événements d’authentification**, les **opérations de paquets** et les **messages kernel/user-space**. Pendant une réponse live, essayez de préserver à la fois le journal **persistant** (`/var/log/journal/`) et le journal **runtime** (`/run/log/journal/`) car l’activité de l’attaquant de courte durée peut n’exister que dans ce dernier.
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
Les champs de journal utiles pour le triage incluent `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID` et `MESSAGE`. Si journald a été configuré sans stockage persistant, attendez-vous à ne trouver que les données récentes sous `/run/log/journal/`.

### Tri du framework d’audit (`auditd`)

Si `auditd` est activé, privilégiez-le chaque fois que vous avez besoin de **process attribution** pour les modifications de fichiers, l’exécution de commandes, l’activité de connexion ou l’installation de packages.
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
Lorsque les règles ont été déployées avec des clés, pivotez à partir d’elles au lieu de faire des grep dans les logs bruts :
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Linux maintient un historique des commandes pour chaque utilisateur**, stocké dans :

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

De plus, la commande `last -Faiwx` fournit une liste des connexions utilisateur. Vérifiez-la pour détecter des connexions inconnues ou inattendues.

Vérifiez les fichiers qui peuvent accorder des rprivileges supplémentaires :

- Passez en revue `/etc/sudoers` pour repérer des privilèges utilisateur inattendus qui auraient pu être accordés.
- Passez en revue `/etc/sudoers.d/` pour repérer des privilèges utilisateur inattendus qui auraient pu être accordés.
- Examinez `/etc/groups` pour identifier des appartenances à des groupes ou des permissions inhabituelles.
- Examinez `/etc/passwd` pour identifier des appartenances à des groupes ou des permissions inhabituelles.

Certaines apps génèrent aussi leurs propres logs :

- **SSH** : Examinez _\~/.ssh/authorized_keys_ et _\~/.ssh/known_hosts_ pour détecter des connexions distantes non autorisées.
- **Gnome Desktop** : Consultez _\~/.recently-used.xbel_ pour les fichiers récemment accessibles via des applications Gnome.
- **Firefox/Chrome** : Vérifiez l’historique du navigateur et les téléchargements dans _\~/.mozilla/firefox_ ou _\~/.config/google-chrome_ pour des activités suspectes.
- **VIM** : Passez en revue _\~/.viminfo_ pour les détails d’utilisation, tels que les chemins des fichiers consultés et l’historique de recherche.
- **Open Office** : Vérifiez les accès récents aux documents qui pourraient indiquer des fichiers compromis.
- **FTP/SFTP** : Passez en revue les logs dans _\~/.ftp_history_ ou _\~/.sftp_history_ pour des transferts de fichiers potentiellement non autorisés.
- **MySQL** : Analysez _\~/.mysql_history_ pour les requêtes MySQL exécutées, pouvant révéler des activités de base de données non autorisées.
- **Less** : Analysez _\~/.lesshst_ pour l’historique d’utilisation, y compris les fichiers consultés et les commandes exécutées.
- **Git** : Examinez _\~/.gitconfig_ et les _.git/logs_ des projets pour détecter des changements dans les dépôts.

### USB Logs

[**usbrip**](https://github.com/snovvcrash/usbrip) est un petit logiciel écrit en pur Python 3 qui analyse les fichiers de logs Linux (`/var/log/syslog*` ou `/var/log/messages*` selon la distro) pour construire des tableaux d’historique des événements USB.

Il est intéressant de **connaître toutes les USB qui ont été utilisées** et ce sera plus utile si vous disposez d’une liste autorisée d’USB afin de détecter des "violation events" (l’utilisation d’USB qui ne figurent pas dans cette liste).

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
More examples and info inside the github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Examiner les comptes utilisateurs et les activités de connexion

Examinez les _**/etc/passwd**_, _**/etc/shadow**_ et les **security logs** pour repérer des noms inhabituels ou des comptes créés et/ou utilisés à proximité d’événements non autorisés connus. Vérifiez également d’éventuelles attaques par force brute sudo.\
De plus, vérifiez des fichiers comme _**/etc/sudoers**_ et _**/etc/groups**_ pour des privilèges inattendus accordés aux utilisateurs.\
Enfin, recherchez des comptes avec **no passwords** ou des mots de passe **facilement devinables**.

## Examiner le système de fichiers

### Analyse des structures du système de fichiers dans une enquête malware

Lors d’une enquête sur des incidents malware, la structure du système de fichiers est une source d’information cruciale, révélant à la fois la séquence des événements et le contenu du malware. Cependant, les auteurs de malware développent des techniques pour gêner cette analyse, comme la modification des horodatages des fichiers ou l’évitement du système de fichiers pour le stockage des données.

Pour contrer ces méthodes anti-forensiques, il est essentiel de :

- **Réaliser une analyse approfondie de la timeline** à l’aide d’outils comme **Autopsy** pour visualiser les timelines d’événements ou **Sleuth Kit's** `mactime` pour des données de timeline détaillées.
- **Inspecter les scripts inattendus** dans le $PATH du système, qui peuvent inclure des scripts shell ou PHP utilisés par les attaquants.
- **Examiner `/dev` à la recherche de fichiers atypiques**, car il contient traditionnellement des fichiers spéciaux, mais peut aussi héberger des fichiers liés à un malware.
- **Rechercher des fichiers ou répertoires cachés** avec des noms comme ".. " (dot dot space) ou "..^G" (dot dot control-G), qui peuvent dissimuler du contenu malveillant.
- **Identifier les fichiers setuid root** à l’aide de la commande : `find / -user root -perm -04000 -print` Cela trouve les fichiers avec des permissions élevées, qui peuvent être exploités par des attaquants.
- **Vérifier les horodatages de suppression** dans les tables d’inodes pour repérer des suppressions massives de fichiers, indiquant possiblement la présence de rootkits ou de trojans.
- **Inspecter les inodes consécutifs** à la recherche de fichiers malveillants proches après en avoir identifié un, car ils peuvent avoir été placés ensemble.
- **Vérifier les répertoires binaires courants** (_/bin_, _/sbin_) pour des fichiers récemment modifiés, car ceux-ci peuvent avoir été altérés par un malware.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> Note that an **attacker** can **modify** the **time** to make **files appear** **legitimate**, but he **cannot** modify the **inode**. If you find that a **file** indicates that it was created and modified at the **same time** as the rest of the files in the same folder, but the **inode** is **unexpectedly bigger**, then the **timestamps of that file were modified**.

### Tri rapide centré sur l'inode

Si vous soupçonnez de l'anti-forensics, exécutez ces vérifications centrées sur l'inode tôt :
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
Lorsqu’un inode suspect se trouve sur une image/périphérique du système de fichiers EXT, inspectez directement les métadonnées de l’inode :
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
Champs utiles :
- **Links** : si `0`, aucune entrée de répertoire ne référence actuellement l'inode.
- **dtime** : horodatage de suppression défini lorsque l'inode a été unlink.
- **ctime/mtime** : aide à corréler les changements de métadonnées/contenu avec la timeline de l'incident.

### Capabilities, xattrs, and preload-based userland rootkits

La persistance moderne sous Linux évite souvent les binaires **setuid** évidents et abuse plutôt des **file capabilities**, des **extended attributes**, et du chargeur dynamique.
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
Accordez une attention particulière aux bibliothèques référencées depuis des chemins **writable** tels que `/tmp`, `/dev/shm`, `/var/tmp`, ou des emplacements inhabituels sous `/usr/local/lib`. Vérifiez également les binaires avec capabilities en dehors de la propriété normale des paquets et corrélez-les avec les résultats de vérification des paquets (`rpm -Va`, `dpkg --verify`, `debsums`).

## Compare files of different filesystem versions

### Filesystem Version Comparison Summary

Pour comparer des versions du filesystem et repérer les changements, nous utilisons des commandes `git diff` simplifiées :

- **Pour trouver de nouveaux fichiers**, comparez deux répertoires :
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
- **Filter options** (`--diff-filter`) aident à limiter aux changements spécifiques comme les fichiers ajoutés (`A`), supprimés (`D`) ou modifiés (`M`).
- `A`: Fichiers ajoutés
- `C`: Fichiers copiés
- `D`: Fichiers supprimés
- `M`: Fichiers modifiés
- `R`: Fichiers renommés
- `T`: Changements de type (par ex., fichier vers symlink)
- `U`: Fichiers non fusionnés
- `X`: Fichiers inconnus
- `B`: Fichiers cassés

## References

- [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- **Book: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

- [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [Forensic Analysis of Linux Journals](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [Red Hat Enterprise Linux 9 - Auditing the system](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)
- [Say hi to Pike!](https://www.synacktiv.com/en/publications/say-hi-to-pike.html)
- [strace](https://strace.io/)
- [SQLite FTS5 Extension](https://www.sqlite.org/fts5.html)

{{#include ../../banners/hacktricks-training.md}}
