# Forensics Linux

## Collecte initiale d’informations

### Informations de base

Tout d’abord, il est recommandé d’avoir une clé **USB** contenant des **binaires et bibliothèques fiables** (vous pouvez simplement récupérer Ubuntu et copier les dossiers _/bin_, _/sbin_, _/lib,_ et _/lib64_), puis de monter la clé USB et de modifier les variables d’environnement afin d’utiliser ces binaires :
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Une fois que vous avez configuré le système pour utiliser des binaires fiables et connus, vous pouvez commencer à **extraire des informations de base** :
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

Lors de l’obtention des informations de base, vous devez rechercher les éléments inhabituels suivants :

- Les processus **root** s’exécutent généralement avec des PIDS faibles. Si vous trouvez donc un processus **root** avec un PID élevé, vous pouvez avoir des soupçons.
- Vérifiez les **connexions enregistrées** des utilisateurs sans shell dans `/etc/passwd`
- Vérifiez la présence de **hashes de mots de passe** dans `/etc/shadow` pour les utilisateurs sans shell

### Dump mémoire

Pour obtenir la mémoire du système en cours d’exécution, il est recommandé d’utiliser [**LiME**](https://github.com/504ensicsLabs/LiME).\
Pour le **compiler**, vous devez utiliser le **même kernel** que celui utilisé par la machine victime.

> [!TIP]
> N’oubliez pas que vous **ne pouvez pas installer LiME ni quoi que ce soit d’autre** sur la machine victime, car cela y apportera plusieurs modifications.

Ainsi, si vous disposez d’une version identique d’Ubuntu, vous pouvez utiliser `apt-get install lime-forensics-dkms`\
Dans les autres cas, vous devez télécharger [**LiME**](https://github.com/504ensicsLabs/LiME) depuis github et le compiler avec les headers du kernel appropriés. Pour **obtenir les headers exacts du kernel** de la machine victime, vous pouvez simplement **copier le répertoire** `/lib/modules/<kernel version>` sur votre machine, puis **compiler** LiME en les utilisant :
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME prend en charge 3 **formats** :

- Raw (chaque segment concaténé)
- Padded (identique à raw, mais avec des zéros dans les bits de droite)
- Lime (format recommandé avec des métadonnées

LiME peut également être utilisé pour **envoyer le dump via le réseau** au lieu de le stocker sur le système, en utilisant quelque chose comme : `path=tcp:4444`

### Disk Imaging

#### Shutting down

Tout d'abord, vous devrez **arrêter le système**. Ce n'est pas toujours une option, car il peut parfois s'agir d'un serveur de production que l'entreprise ne peut pas se permettre d'arrêter.\
Il existe **2 façons** d'arrêter le système : un **arrêt normal** et un **arrêt par "débranchement de la prise"**. La première méthode permettra aux **processus de se terminer comme d'habitude** et au **système de fichiers** d'être **synchronisé**, mais elle permettra également au **malware** éventuel de **détruire les preuves**. L'approche consistant à **débrancher la prise** peut entraîner **une certaine perte d'informations** (une grande partie des informations ne sera pas perdue, car nous avons déjà effectué une image de la mémoire) et le **malware n'aura aucune possibilité** d'intervenir. Par conséquent, si vous **suspectez** la présence d'un **malware**, exécutez simplement la **commande** **`sync`** sur le système, puis débranchez la prise.

#### Taking an image of the disk

Il est important de noter qu'**avant de connecter votre ordinateur à tout élément lié à l'affaire**, vous devez vous assurer qu'il sera **monté en lecture seule** afin d'éviter de modifier des informations.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Pré-analyse de l'image disque

Création d'une image disque sans données supplémentaires.
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

Linux fournit des outils permettant de vérifier l’intégrité des composants système, ce qui est essentiel pour repérer les fichiers potentiellement problématiques.<sup>[[1]](#references)</sup>

- **Systèmes basés sur RedHat** : utilisez `rpm -Va` pour effectuer une vérification complète.
- **Systèmes basés sur Debian** : utilisez d’abord `dpkg --verify`, puis `debsums | grep -v "OK$"` (après avoir installé `debsums` avec `apt-get install debsums`) afin d’identifier les problèmes éventuels.

### Détecteurs de Malware/Rootkit

Consultez la page suivante pour découvrir les outils qui peuvent être utiles pour trouver des Malware :

{{#ref}}
malware-analysis.md
{{#endref}}

## Rechercher les programmes installés

Pour rechercher efficacement les programmes installés sur les systèmes Debian et RedHat, utilisez les journaux et les bases de données système en complément de vérifications manuelles dans les répertoires courants.<sup>[[1]](#references)</sup>

- Pour Debian, examinez _**`/var/lib/dpkg/status`**_ et _**`/var/log/dpkg.log`**_ afin d’obtenir des informations sur les installations de paquets, en utilisant `grep` pour filtrer les informations spécifiques.
- Les utilisateurs de RedHat peuvent interroger la base de données RPM avec `rpm -qa --root=/mntpath/var/lib/rpm` pour lister les paquets installés.

Pour découvrir les logiciels installés manuellement ou en dehors de ces gestionnaires de paquets, explorez les répertoires tels que _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_ et _**`/sbin`**_. Combinez les listes de répertoires avec des commandes spécifiques au système afin d’identifier les exécutables qui ne sont associés à aucun paquet connu, ce qui améliore votre recherche de tous les programmes installés.
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
## Récupérer des binaires supprimés en cours d’exécution

Imaginez un processus exécuté depuis /tmp/exec, puis supprimé. Il est possible de l’extraire.
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Triage des syscalls avec SQLite et FTS5

Lorsqu’un processus est toujours en cours d’exécution ou peut être réexécuté dans un lab, **`strace`** peut fournir rapidement une trace comportementale sans nécessiter de modules du kernel ni de télémétrie EDR complète. Pour les traces volumineuses, évitez de lire directement le log brut ou de le coller dans un LLM : stockez-le dans une base de données **SQLite** et n’interrogez que le sous-ensemble minimal dont vous avez besoin.<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

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

- `-ff` : suivre les forks/threads et conserver les sorties par processus
- `-ttt` : timestamps epoch pour faciliter la corrélation temporelle
- `-yy` : résoudre les descripteurs de fichiers en chemins de fichiers/sockets sous-jacents lorsque cela est possible
- `-s 4096` : éviter la troncature des chemins et des arguments de buffer longs

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
Cela évite d’essayer d’aplatir des lignes de syscall hétérogènes en une seule table très large et rend les jointures prévisibles pendant le triage.

### Indexez les arguments riches en texte avec FTS5

La recherche naïve de chemins avec `LIKE "%...%"` devient très lente sur les traces volumineuses. Créez un index FTS5 pour le texte des arguments et effectuez plutôt la recherche dedans :
```sql
CREATE VIRTUAL TABLE syscall_args_fts
USING fts5(raw, content='syscall_args', content_rowid='id');

INSERT INTO syscall_args_fts(rowid, raw)
SELECT id, raw FROM syscall_args;
```
Exemple : reconstituer l’activité des fichiers sous `/tmp` sans analyser chaque ligne :
```sql
SELECT s.timestamp, s.pid, s.name, a.position, a.raw
FROM syscall_args_fts f
JOIN syscall_args a ON a.id = f.rowid
JOIN syscalls s ON s.id = a.syscall_id
WHERE syscall_args_fts MATCH 'tmp'
AND s.name IN ('openat', 'stat', 'lstat', 'rename', 'unlink', 'execve')
ORDER BY s.timestamp;
```
### Investigations à signaux forts

- **PATH hijacking / fake sudo** : recherchez les écritures et les activités de `chmod`/`rename` sous `~/.local/bin/`, puis corrélez-les avec des `execve` ultérieurs de noms ressemblant à des commandes privilégiées, comme `sudo`.
- **TOCTOU on temporary files** : effectuez un pivot sur le même chemin `/tmp/...` à travers `stat`, `access`, `openat`, `rename`, `unlink`, `link`, `symlink` et `execve` afin d’identifier les écarts entre la vérification et l’utilisation.
- **Crash root cause** : corrélez le `mmap` d’un fichier avec les écritures ou la troncature du même inode/chemin par un autre processus, puis examinez la séquence du signal/de la sortie pour détecter `SIGBUS`.
- **Network destination recovery** : filtrez `connect`, `sendto`, `sendmsg`, `recvfrom` et les arguments liés aux sockets afin d’extraire les IP et ports pairs.

### Analyse de traces assistée par LLM

Si vous souhaitez qu’un LLM vous assiste, exposez une interface SQLite **en lecture seule** et fournissez-lui le schéma complet. Laissez-le exécuter du SQL brut plutôt que de dissimuler la base de données derrière des fonctions d’assistance limitées. Cela fonctionne généralement mieux pour les jointures, la corrélation temporelle et les recherches FTS.

Règles pratiques :

- Gardez la base de données en lecture seule, par exemple avec `sqlite3 'file:trace.db?mode=ro'`.
- Fournissez au modèle des exemples de requêtes `JOIN` et `FTS5 MATCH` valides.
- **Ne** collez **pas** de logs `strace` bruts de plusieurs Go dans le prompt.
- Posez des questions ciblées comme :
- "List persistent files written by this program."
- "Did it create or replace executables in user-controlled PATH directories?"
- "Explain why this trace ends in SIGBUS."

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
#### Recherche : abuse de Cron/Anacron via 0anacron et stubs suspects
Les attaquants modifient souvent le stub 0anacron présent dans chaque répertoire /etc/cron.*/ afin de garantir une exécution périodique.<sup>[[4]](#references)</sup>
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Recherche : annulation du durcissement de SSH et shells backdoor
Les modifications apportées à sshd_config et aux shells des comptes système sont courantes après une exploitation pour conserver l’accès.<sup>[[4]](#references)</sup>
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Recherche : indicateurs de C2 Cloud (Dropbox/Cloudflare Tunnel)
- Les beacons de l’API Dropbox utilisent généralement api.dropboxapi.com ou content.dropboxapi.com via HTTPS avec des jetons Authorization: Bearer.
- Recherchez dans proxy/Zeek/NetFlow des connexions sortantes Dropbox inattendues depuis les serveurs.
- Cloudflare Tunnel (`cloudflared`) fournit un C2 de secours via le port 443 sortant.<sup>[[4]](#references)</sup>
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Services

Chemins où un malware peut être installé en tant que service :

- **/etc/inittab** : Appelle des scripts d'initialisation comme rc.sysinit, qui redirige ensuite vers les scripts de démarrage.
- **/etc/rc.d/** et **/etc/rc.boot/** : Contiennent des scripts de démarrage des services, ce dernier étant présent dans les anciennes versions de Linux.
- **/etc/init.d/** : Utilisé dans certaines versions de Linux, comme Debian, pour stocker les scripts de démarrage.
- Les services peuvent également être activés via **/etc/inetd.conf** ou **/etc/xinetd/**, selon la variante de Linux.
- **/etc/systemd/system** : Un répertoire contenant les scripts du gestionnaire du système et des services.
- **/etc/systemd/system/multi-user.target.wants/** : Contient des liens vers les services qui doivent être démarrés dans un runlevel multi-utilisateur.
- **/usr/local/etc/rc.d/** : Pour les services personnalisés ou tiers.
- **\~/.config/autostart/** : Pour les applications démarrées automatiquement et spécifiques à l'utilisateur, ce qui peut constituer un emplacement de dissimulation pour un malware ciblant un utilisateur.
- **/lib/systemd/system/** : Fichiers d'unités par défaut à l'échelle du système, fournis par les packages installés.

#### Recherche : timers systemd et unités transitoires

La persistence de systemd ne se limite pas aux fichiers `.service`. Examinez les unités `.timer`, les unités au niveau utilisateur et les **unités transitoires** créées au moment de l'exécution.
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
Les unités transitoires sont faciles à manquer, car `/run/systemd/transient/` est **non persistant**. Si vous collectez une image live, récupérez-la avant l’arrêt.

### Modules du noyau

Les modules du noyau Linux, souvent utilisés par les malware comme composants de rootkit, sont chargés au démarrage du système. Les répertoires et fichiers essentiels pour ces modules incluent :

- **/lib/modules/$(uname -r)** : Contient les modules correspondant à la version du noyau en cours d’exécution.
- **/etc/modprobe.d** : Contient les fichiers de configuration permettant de contrôler le chargement des modules.
- **/etc/modprobe** et **/etc/modprobe.conf** : Fichiers contenant les paramètres globaux des modules.

### Autres emplacements d’autostart

Linux utilise différents fichiers pour exécuter automatiquement des programmes lors de la connexion d’un utilisateur, lesquels peuvent potentiellement abriter des malware :

- **/etc/profile.d/**\*, **/etc/profile** et **/etc/bash.bashrc** : Exécutés lors de la connexion de n’importe quel utilisateur.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile** et **\~/.config/autostart** : Fichiers spécifiques à l’utilisateur, exécutés lors de sa connexion.
- **/etc/rc.local** : S’exécute après le démarrage de tous les services système, marquant la fin de la transition vers un environnement multiutilisateur.

## Examiner les logs

Les systèmes Linux suivent les activités des utilisateurs et les événements système au moyen de différents fichiers de logs. Ces logs sont essentiels pour identifier les accès non autorisés, les infections par malware et autres incidents de sécurité.<sup>[[2]](#references)</sup> Les principaux fichiers de logs incluent :

- **/var/log/syslog** (Debian) ou **/var/log/messages** (RedHat) : Enregistrent les messages et activités à l’échelle du système.
- **/var/log/auth.log** (Debian) ou **/var/log/secure** (RedHat) : Enregistrent les tentatives d’authentification ainsi que les connexions réussies et échouées.
- Utilisez `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` pour filtrer les événements d’authentification pertinents.
- **/var/log/boot.log** : Contient les messages de démarrage du système.
- **/var/log/maillog** ou **/var/log/mail.log** : Enregistrent les activités du serveur de messagerie, ce qui est utile pour suivre les services liés aux e-mails.
- **/var/log/kern.log** : Stocke les messages du noyau, notamment les erreurs et les avertissements.
- **/var/log/dmesg** : Contient les messages des pilotes de périphériques.
- **/var/log/faillog** : Enregistre les tentatives de connexion échouées, ce qui aide à enquêter sur les compromissions de sécurité.
- **/var/log/cron** : Enregistre les exécutions des tâches cron.
- **/var/log/daemon.log** : Suit les activités des services en arrière-plan.
- **/var/log/btmp** : Documente les tentatives de connexion échouées.
- **/var/log/httpd/** : Contient les logs d’erreur et d’accès d’Apache HTTPD.
- **/var/log/mysqld.log** ou **/var/log/mysql.log** : Enregistre les activités des bases de données MySQL.
- **/var/log/xferlog** : Enregistre les transferts de fichiers FTP.
- **/var/log/** : Vérifiez toujours la présence de logs inattendus ici.

> [!TIP]
> Les logs système Linux et les sous-systèmes d’audit peuvent être désactivés ou supprimés lors d’une intrusion ou d’un incident lié à un malware. Comme les logs des systèmes Linux contiennent généralement certaines des informations les plus utiles sur les activités malveillantes, les intrus les suppriment régulièrement. Par conséquent, lors de l’examen des fichiers de logs disponibles, il est important de rechercher des lacunes ou des entrées dans le désordre, qui pourraient indiquer une suppression ou une altération.

### Triage de Journald (`journalctl`)

Sur les hôtes Linux modernes, le **journal systemd** est généralement la source la plus utile pour l’**exécution des services**, les **événements d’authentification**, les **opérations sur les paquets** et les **messages du noyau et de l’espace utilisateur**. Lors d’une réponse live, essayez de préserver à la fois le journal **persistant** (`/var/log/journal/`) et le journal **d’exécution** (`/run/log/journal/`), car l’activité de courte durée d’un attaquant peut n’exister que dans ce dernier.<sup>[[5]](#references)</sup>
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
Les champs de journal utiles pour le triage incluent `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID` et `MESSAGE`. Si journald a été configuré sans stockage persistant, attendez-vous à ne trouver que des données récentes sous `/run/log/journal/`.

### Triage du framework Audit (`auditd`)

Si `auditd` est activé, privilégiez-le chaque fois que vous avez besoin d’attribuer des modifications de fichiers, une exécution de commandes, une activité de connexion ou une installation de packages à un processus.<sup>[[6]](#references)</sup>
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
Lorsque des règles ont été déployées avec des keys, pivotez à partir de celles-ci au lieu de grepper les raw logs :
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

Vérifiez les fichiers susceptibles d'accorder des privilèges supplémentaires :

- Examinez `/etc/sudoers` afin d'identifier les privilèges inattendus qui auraient pu être accordés à des utilisateurs.
- Examinez `/etc/sudoers.d/` afin d'identifier les privilèges inattendus qui auraient pu être accordés à des utilisateurs.
- Examinez `/etc/groups` afin d'identifier les appartenances à des groupes ou les permissions inhabituelles.
- Examinez `/etc/passwd` afin d'identifier les appartenances à des groupes ou les permissions inhabituelles.

Certaines applications génèrent également leurs propres logs :

- **SSH** : Examinez _\~/.ssh/authorized_keys_ et _\~/.ssh/known_hosts_ pour repérer les connexions distantes non autorisées.
- **Gnome Desktop** : Consultez _\~/.recently-used.xbel_ pour connaître les fichiers récemment ouverts via les applications Gnome.
- **Firefox/Chrome** : Vérifiez l'historique de navigation et les téléchargements dans _\~/.mozilla/firefox_ ou _\~/.config/google-chrome_ afin de repérer les activités suspectes.
- **VIM** : Examinez _\~/.viminfo_ pour obtenir des informations sur l'utilisation, comme les chemins des fichiers consultés et l'historique des recherches.
- **Open Office** : Vérifiez les accès récents aux documents, qui pourraient indiquer la présence de fichiers compromis.
- **FTP/SFTP** : Examinez les logs dans _\~/.ftp_history_ ou _\~/.sftp_history_ pour repérer les transferts de fichiers potentiellement non autorisés.
- **MySQL** : Examinez _\~/.mysql_history_ pour identifier les requêtes MySQL exécutées, qui pourraient révéler des activités non autorisées sur les bases de données.
- **Less** : Analysez _\~/.lesshst_ pour consulter l'historique d'utilisation, notamment les fichiers affichés et les commandes exécutées.
- **Git** : Examinez _\~/.gitconfig_ et les fichiers _.git/logs_ des projets pour repérer les modifications apportées aux repositories.

### Logs USB

[**usbrip**](https://github.com/snovvcrash/usbrip) est un petit logiciel écrit en Python 3 pur qui analyse les fichiers de log Linux (`/var/log/syslog*` ou `/var/log/messages*` selon la distribution) afin de construire des tableaux d'historique des événements USB.

Il est intéressant de **connaître tous les périphériques USB qui ont été utilisés**. Cela sera encore plus utile si vous disposez d'une liste autorisée de périphériques USB afin d'identifier les « événements de violation » (l'utilisation de périphériques USB qui ne figurent pas dans cette liste).

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
Plus d'exemples et d'informations sur github : [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Examiner les comptes utilisateurs et les activités de connexion

Examinez _**/etc/passwd**_, _**/etc/shadow**_ et les **journaux de sécurité** à la recherche de noms ou de comptes inhabituels créés et/ou utilisés à proximité d'événements non autorisés connus. Vérifiez également les éventuelles attaques sudo par brute-force.\
En outre, vérifiez des fichiers comme _**/etc/sudoers**_ et _**/etc/groups**_ pour détecter les privilèges inattendus accordés aux utilisateurs.\
Enfin, recherchez les comptes **sans mots de passe** ou avec des mots de passe **facilement devinables**.<sup>[[1]](#references)</sup>

## Examiner le système de fichiers

### Analyser les structures du système de fichiers lors d'une investigation de malware

Lors de l'investigation d'incidents liés à des malwares, la structure du système de fichiers constitue une source d'informations cruciale, révélant à la fois la séquence des événements et le contenu du malware. Cependant, les auteurs de malwares développent des techniques visant à entraver cette analyse, comme la modification des timestamps des fichiers ou l'évitement du système de fichiers pour le stockage des données.<sup>[[1]](#references)</sup>

Pour contrer ces méthodes anti-forensics, il est essentiel de :

- **Effectuer une analyse approfondie de la timeline** à l'aide d'outils comme **Autopsy** pour visualiser les timelines d'événements ou `mactime` de **Sleuth Kit** pour obtenir des données détaillées sur la timeline.
- **Rechercher les scripts inattendus** dans le $PATH du système, qui peuvent inclure des scripts shell ou PHP utilisés par les attaquants.
- **Examiner `/dev` à la recherche de fichiers atypiques**, car ce répertoire contient traditionnellement des fichiers spéciaux, mais peut également héberger des fichiers liés à des malwares.
- **Rechercher les fichiers ou répertoires cachés** portant des noms comme ".. " (deux points espace) ou "..^G" (deux points control-G), qui pourraient dissimuler du contenu malveillant.
- **Identifier les fichiers setuid root** à l'aide de la commande : `find / -user root -perm -04000 -print` Cette commande recherche les fichiers disposant de permissions élevées, qui pourraient être exploités par des attaquants.
- **Examiner les timestamps de suppression** dans les tables d'inodes afin de repérer les suppressions massives de fichiers, ce qui peut indiquer la présence de rootkits ou de trojans.
- **Inspecter les inodes consécutifs** à la recherche de fichiers malveillants proches après en avoir identifié un, car ils peuvent avoir été placés ensemble.
- **Vérifier les répertoires binaires courants** (_/bin_, _/sbin_) à la recherche de fichiers récemment modifiés, car ceux-ci pourraient avoir été altérés par un malware.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> Notez qu'un **attacker** peut **modifier** l'**heure** pour faire **paraître** les **fichiers** **légitimes**, mais il ne peut pas modifier l'**inode**. Si vous constatez qu'un **fichier** indique avoir été créé et modifié au **même moment** que le reste des fichiers du même dossier, mais que l'**inode** est **étonnamment plus grand**, alors les **horodatages de ce fichier ont été modifiés**.

### Triage rapide axé sur l'inode

Si vous suspectez de l'anti-forensics, exécutez rapidement ces vérifications axées sur l'inode :
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
- **dtime** : horodatage de suppression défini lorsque l’inode n’est plus lié.
- **ctime/mtime** : aide à corréler les modifications des métadonnées/du contenu avec la chronologie de l’incident.

### Capabilities, xattrs et rootkits userland basés sur preload

La persistance moderne sous Linux évite souvent les binaires **setuid** évidents et exploite plutôt les **file capabilities**, les **extended attributes** et le chargeur dynamique.
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
Accordez une attention particulière aux libraries référencées depuis des chemins **writable** tels que `/tmp`, `/dev/shm`, `/var/tmp` ou des emplacements inhabituels sous `/usr/local/lib`. Vérifiez également les binaires dotés de capabilities situés en dehors des chemins d’appartenance habituels des packages et corrélez-les avec les résultats de vérification des packages (`rpm -Va`, `dpkg --verify`, `debsums`).

## Comparer des fichiers de différentes versions du filesystem

### Résumé de la comparaison des versions du filesystem

Pour comparer les versions du filesystem et identifier précisément les changements, nous utilisons des commandes `git diff` simplifiées :<sup>[[3]](#references)</sup>

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

- [1] [Guide pratique de la malware forensics pour les systèmes Linux : guides pratiques de la forensique numérique – chapitre 3](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [2] [Les logs Linux expliqués](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [3] [Documentation de git diff – option --diff-filter](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- [4] [Red Canary – Patching for persistence : comment le malware Linux DripDropper se déplace dans le cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [5] [Analyse forensique des journaux Linux](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [6] [Red Hat Enterprise Linux 9 - Auditer le système](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)
- [7] [Dites bonjour à Pike !](https://www.synacktiv.com/en/publications/say-hi-to-pike.html)
- [8] [strace](https://strace.io/)
- [9] [Extension SQLite FTS5](https://www.sqlite.org/fts5.html)
{{#include ../../banners/hacktricks-training.md}}
